import Foundation
import CryptoKit
import Darwin

// Darwin 模块里 struct stat 与 func stat 同名，Swift 名称解析始终选中结构体，
// 因此通过 dlsym 取 libSystem 里真正的 C 函数指针。
typealias StatBuf = stat
typealias StatFunc = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<StatBuf>) -> Int32

// RTLD_DEFAULT 在 Darwin 上的值为 -2（Swift 未导出该宏）
private let rtldDefault = UnsafeMutableRawPointer(bitPattern: UInt(bitPattern: -2))

private let cStat: StatFunc = {
    let sym = dlsym(rtldDefault, "stat")!
    return unsafeBitCast(sym, to: StatFunc.self)
}()

private let cLstat: StatFunc = {
    let sym = dlsym(rtldDefault, "lstat")!
    return unsafeBitCast(sym, to: StatFunc.self)
}()

// MARK: - 文件元数据 / 类型识别 / 路径工具
enum FS {

    /// lstat：不跟随符号链接
    static func lstatInfo(_ path: String) -> StatBuf? {
        var st = StatBuf()
        guard cLstat(path, &st) == 0 else { return nil }
        return st
    }

    static func statInfo(_ path: String) -> StatBuf? {
        var st = StatBuf()
        guard cStat(path, &st) == 0 else { return nil }
        return st
    }

    static func exists(_ path: String) -> Bool {
        statInfo(path) != nil
    }

    static func isSymlink(_ path: String) -> Bool {
        guard let st = lstatInfo(path) else { return false }
        return (st.st_mode & S_IFMT) == S_IFLNK
    }

    static func isDirectory(_ path: String) -> Bool {
        guard let st = statInfo(path) else { return false }
        return (st.st_mode & S_IFMT) == S_IFDIR
    }

    static func symlinkTarget(_ path: String) -> String? {
        guard isSymlink(path) else { return nil }
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let count = readlink(path, buf, Int(MAXPATHLEN))
        guard count > 0 else { return nil }
        return String(cString: buf)
    }

    static func resolveSymlinks(_ path: String) -> String {
        // 标准化 + 完全解析符号链接；路径不存在时返回标准化结果
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        return URL(fileURLWithPath: standardized).resolvingSymlinksInPath().path
    }

    static func sha256(of path: String) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: path)) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk = handle.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// 完整元数据（跟随符号链接后的真实文件 + 链接自身信息）
    static func metadata(_ path: String) -> FileMeta {
        var meta = FileMeta()
        meta.isSymlink = isSymlink(path)
        if meta.isSymlink {
            meta.symlinkTarget = symlinkTarget(path)
        }
        guard let st = statInfo(path) else {
            meta.exists = false
            return meta
        }
        meta.exists = true
        meta.size = Int(st.st_size)
        meta.owner = name(pw: getpwuid(st.st_uid))
        meta.group = name(gr: getgrgid(st.st_gid))
        meta.posixPermissions = permissionString(st.st_mode)
        meta.worldWritable = (st.st_mode & S_IWOTH) != 0
        meta.groupWritable = (st.st_mode & S_IWGRP) != 0
        // 属主不是 root 但属主有写权限 —— 任何拿到该账号的人都能改
        meta.ownerWritableByNonRoot = (st.st_mode & S_IWUSR) != 0 && st.st_uid != 0
        if isRegularFile(st.st_mode), let hash = sha256(of: path) {
            meta.sha256 = hash
        }
        return meta
    }

    static func isWritableByNonRoot(_ meta: FileMeta) -> Bool {
        meta.worldWritable || meta.groupWritable || meta.ownerWritableByNonRoot
    }

    // MARK: 文件类型识别（魔数）

    enum DetectedType {
        case machO
        case script(shebang: String?)
        case appBundle(executable: String?)
        case plist
        case text
        case other
    }

    static func detectType(_ path: String) -> DetectedType {
        // .app 包
        if path.hasSuffix(".app") && isDirectory(path) {
            return .appBundle(executable: appExecutable(path))
        }
        guard let st = statInfo(path), isRegularFile(st.st_mode) else {
            return .other
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            // 无读取权限（如 /usr/sbin 下 r-x------ 的系统守护进程）：
            // 有执行位且无脚本扩展名时，按 Mach-O 走签名检查；签名 API 不受读权限限制
            if let st = statInfo(path), (st.st_mode & S_IXUSR) != 0 {
                let scriptExts = [".sh", ".zsh", ".bash", ".py", ".pl", ".rb", ".conf", ".plist"]
                if !scriptExts.contains(where: { path.lowercased().hasSuffix($0) }) {
                    return .machO
                }
            }
            return .other
        }

        // Mach-O 魔数：0xFEEDFACE / 0xFEEDFACF（含 32/64、大小端、fat 0xCAFEBABE）
        if let magic = data.uint32(at: 0) {
            let magics: Set<UInt32> = [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca]
            if magics.contains(magic) {
                return .machO
            }
        }

        // plist（二进制 bplist 或 XML）
        if data.starts(with: [0x62, 0x70, 0x6c, 0x69, 0x73, 0x74]) { // "bplist"
            return .plist
        }
        if let head = String(data: data.prefix(512), encoding: .utf8),
           head.contains("<plist") || head.contains("<?xml") {
            // XML plist 与普通 XML 配置都按配置类处理
            return head.contains("<plist") ? .plist : .text
        }

        // 脚本 shebang
        if data.first == 0x23, data.count > 1, data[1] == 0x21 { // #!
            let lineEnd = data.firstIndex(of: 0x0a) ?? data.count
            let shebang = String(data: data[2..<lineEnd], encoding: .utf8)?
                .trimmingCharacters(in: .whitespaces)
            return .script(shebang: shebang)
        }

        // 无 shebang 但扩展名/内容表明是脚本
        let lower = path.lowercased()
        let scriptExts = [".sh", ".zsh", ".bash", ".py", ".pl", ".rb", ".applescript", ".js", ".command"]
        if scriptExts.contains(where: { lower.hasSuffix($0) }) {
            return .script(shebang: nil)
        }

        // 无 shebang 的文本：尝试 UTF-8 解码小样本
        if let sample = String(data: data.prefix(4096), encoding: .utf8),
           sample.rangeOfCharacter(from: CharacterSet.controlCharacters.subtracting(CharacterSet(charactersIn: "\r\n\t"))) == nil {
            return .text
        }
        return .other
    }

    static func appExecutable(_ appPath: String) -> String? {
        let infoPlist = appPath + "/Contents/Info.plist"
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: infoPlist)),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            // 兜底：Contents/MacOS 下找可执行文件
            let macos = appPath + "/Contents/MacOS"
            if let entries = try? FileManager.default.contentsOfDirectory(atPath: macos), let first = entries.first {
                return macos + "/" + first
            }
            return nil
        }
        if let exec = plist["CFBundleExecutable"] as? String {
            return appPath + "/Contents/MacOS/" + exec
        }
        return nil
    }

    // MARK: 权限/属主

    private static func isRegularFile(_ mode: mode_t) -> Bool {
        (mode & S_IFMT) == S_IFREG
    }

    private static func name(pw: UnsafeMutablePointer<passwd>?) -> String? {
        guard let pw else { return nil }
        return String(cString: pw.pointee.pw_name)
    }

    private static func name(gr: UnsafeMutablePointer<group>?) -> String? {
        guard let gr else { return nil }
        return String(cString: gr.pointee.gr_name)
    }

    private static func permissionString(_ mode: mode_t) -> String {
        let chars: [Character] = ["r", "w", "x"]
        var s = ""
        let sets: [mode_t] = [S_IRUSR, S_IWUSR, S_IXUSR,
                              S_IRGRP, S_IWGRP, S_IXGRP,
                              S_IROTH, S_IWOTH, S_IXOTH]
        let type: Character
        switch mode & S_IFMT {
        case S_IFDIR: type = "d"
        case S_IFLNK: type = "l"
        default: type = "-"
        }
        s.append(type)
        for (i, bit) in sets.enumerated() {
            s.append((mode & bit) != 0 ? chars[i % 3] : "-")
        }
        return s
    }
}

private extension Data {
    func uint32(at offset: Int) -> UInt32? {
        guard count >= offset + 4 else { return nil }
        return withUnsafeBytes { $0.load(fromByteOffset: offset, as: UInt32.self) }
    }
}
