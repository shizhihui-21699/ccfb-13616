import Foundation

// MARK: - 执行链追踪引擎
// 从自动启动项登记的 argv 出发，逐层解析符号链接、app 包、脚本、配置，
// 直到抵达最终 Mach-O 代码或无法继续为止。每个 Tracer 实例服务一个审计项，
// 用 inode 集合做环路防护，depth 做深度兜底。
final class Tracer {

    let maxDepth = 12
    private var visitedInodes: Set<UInt64> = []
    private var indexCounter = 0
    private let env: [String: String]
    private let customPath: [String]
    private let defaultPath: [String]

    static let systemInterpreters: Set<String> = [
        "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "perl", "ruby",
        "node", "php", "osascript", "env", "open", "curl", "wget", "jsc", "ruby"
    ]

    // 系统自身使用的 DYLD 行为开关（非注入路径变量）
    static let dyldBehaviorFlags: Set<String> = [
        "DYLD_PAGEIN_LINKING", "DYLD_PRINT_LIBRARIES", "DYLD_PRINT_ENV",
        "DYLD_PRINT_STATISTICS", "DYLD_PRINT_OPTS", "DYLD_PRINT_RPATHS",
        "DYLD_PRINT_WARNINGS", "DYLD_PRINT_APIS", "DYLD_PRINT_SEGMENTS",
        "DYLD_PRINT_INITIALIZERS", "DYLD_PRINT_BINDINGS", "DYLD_PRINT_CODE_SIGNATURES",
        "DYLD_PRINT_WEAK_IMPORTS", "DYLD_PRINT_DOFS", "DYLD_USE_CLOSURES",
        "DYLD_SHARED_REGION", "DYLD_SHARED_CACHE_DONT_VALIDATE",
        "DYLD_DISABLE_DOFS", "DYLD_IGNORE_PREBOUND", "DYLD_BIND_AT_LAUNCH",
        "DYLD_NO_FIX_PREBOUND", "DYLD_PRINT_INTERPOSING", "DYLD_PRINT_LIBRARIES_POST_LAUNCH"
    ]

    init(env: [String: String]) {
        self.env = env
        self.defaultPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin",
                            "/usr/local/bin", "/opt/homebrew/bin"]
        if let path = env["PATH"] {
            self.customPath = path.components(separatedBy: ":").filter { !$0.isEmpty }
        } else {
            self.customPath = []
        }
    }

    // MARK: 入口：从 argv 建链

    func trace(argv: [String], kindName: String) -> [Hop] {
        guard let first = argv.first else { return [] }
        let resolved = resolveCommand(first)
        let hop = inspectCommand(
            path: resolved ?? first,
            displayName: first,
            args: Array(argv.dropFirst()),
            env: env,
            depth: 0,
            originNote: kindName
        )
        return [hop]
    }

    // MARK: 命令路径解析（PATH 查找）

    /// 当前生效的搜索路径：环境变量里的 PATH 覆盖优先，其次启动项声明的 PATH
    private func effectiveSearchPath(_ extraEnv: [String: String]? = nil) -> [String] {
        if let p = extraEnv?["PATH"] ?? env["PATH"], !p.isEmpty {
            return p.components(separatedBy: ":").filter { !$0.isEmpty }
        }
        return customPath.isEmpty ? defaultPath : customPath
    }

    private func resolveCommand(_ name: String, extraEnv: [String: String]? = nil) -> String? {
        if name.hasPrefix("/") || name.hasPrefix("./") || name.hasPrefix("../") {
            return FS.exists(name) ? FS.resolveSymlinks(name) : name
        }
        let dirs = effectiveSearchPath(extraEnv)
        for dir in dirs {
            let candidate = dir + "/" + name
            if FS.exists(candidate) {
                return FS.resolveSymlinks(candidate)
            }
        }
        return nil
    }

    /// 解析脚本参数：存在返回真实路径；不存在返回 nil 并由调用方建 missing 跳
    private func resolveScriptArg(_ arg: String, extraEnv: [String: String]? = nil) -> String? {
        if arg.hasPrefix("/") || arg.hasPrefix("./") || arg.hasPrefix("../") {
            return FS.exists(arg) ? arg : nil
        }
        for dir in effectiveSearchPath(extraEnv) {
            let candidate = dir + "/" + arg
            if FS.exists(candidate) { return candidate }
        }
        return nil
    }

    // MARK: 通用节点检查（符号链接/缺失/分发）

    private func inspectPath(_ path: String, depth: Int, displayName: String? = nil,
                             argv: [String] = [], env: [String: String] = [:],
                             inlineSnippet: String? = nil) -> Hop {
        indexCounter += 1
        let index = indexCounter
        let name = displayName ?? path.lastPathComponent

        // 缺失
        guard FS.exists(path) else {
            return Hop(index: index, kind: .missing, path: path, displayName: name, depth: depth,
                       trust: HopTrust(verdict: .suspicious,
                                       reasons: ["引用的文件或命令不存在（可能是清除残留或等待投放）"],
                                       techniques: ["T10"]),
                       file: FileMeta(exists: false))
        }

        // 符号链接：先记录链接本身，再追目标
        if FS.isSymlink(path) {
            let meta = FS.metadata(path)
            var hop = Hop(index: index, kind: .symlink, path: path, displayName: name, depth: depth,
                          trust: HopTrust(verdict: .unknown, reasons: [], techniques: []),
                          file: meta,
                          note: "符号链接 -> \(meta.symlinkTarget ?? "?")")
            let target = FS.resolveSymlinks(path)
            if target != path {
                let targetHop = inspectPath(target, depth: depth + 1)
                hop.children = [targetHop]
                hop.trust = HopTrust(verdict: targetHop.trust.verdict,
                                     reasons: ["链接目标判定: \(targetHop.trust.verdict.rawValue)"],
                                     techniques: unionTech(["T09"], targetHop.trust.techniques))
            }
            return hop
        }

        // 目录
        if FS.isDirectory(path) {
            if path.hasSuffix(".app") {
                return inspectAppBundle(path, depth: depth, index: index, displayName: name)
            }
            return Hop(index: index, kind: .directory, path: path, displayName: name, depth: depth,
                       trust: HopTrust(verdict: .unknown, reasons: ["执行链引用了目录而非可执行文件"]),
                       file: FS.metadata(path))
        }

        return inspectRegularFile(path, depth: depth, index: index, displayName: name,
                                  argv: argv, env: env, inlineSnippet: inlineSnippet)
    }

    // MARK: .app 包

    private func inspectAppBundle(_ path: String, depth: Int, index: Int, displayName: String) -> Hop {
        let meta = FS.metadata(path)
        var hop = Hop(index: index, kind: .directory, path: path, displayName: displayName, depth: depth,
                      trust: HopTrust(verdict: .unknown),
                      file: meta,
                      note: "应用程序包 (.app)")
        guard let exec = FS.appExecutable(path) else {
            hop.trust = HopTrust(verdict: .suspicious,
                                 reasons: ["应用包缺少 CFBundleExecutable，结构异常"],
                                 techniques: ["T03"])
            return hop
        }
        let execHop = inspectPath(exec, depth: depth + 1, displayName: exec.lastPathComponent)
        hop.children = [execHop]
        hop.trust = execHop.trust
        return hop
    }

    // MARK: 普通文件按类型分发

    private func inspectRegularFile(_ path: String, depth: Int, index: Int, displayName: String,
                                    argv: [String], env: [String: String], inlineSnippet: String?) -> Hop {
        // 环路防护：同一 inode 不重复深入
        if let st = FS.statInfo(path), visitedInodes.contains(st.st_ino) {
            return Hop(index: index, kind: .unknown, path: path, displayName: displayName, depth: depth,
                       trust: HopTrust(verdict: .unknown, reasons: ["检测到引用环路，停止深入"]),
                       file: FS.metadata(path))
        }
        if let st = FS.statInfo(path) { visitedInodes.insert(st.st_ino) }

        switch FS.detectType(path) {
        case .machO:
            return inspectMachO(path, depth: depth, index: index, displayName: displayName,
                                argv: argv, env: env)
        case .appBundle:
            return inspectAppBundle(path, depth: depth, index: index, displayName: displayName)
        case .script(let shebang):
            return inspectScript(path, depth: depth, index: index, displayName: displayName,
                                 shebang: shebang, argv: argv, env: env)
        case .plist:
            return inspectConfig(path, depth: depth, index: index, displayName: displayName, isPlist: true)
        case .text:
            return inspectConfig(path, depth: depth, index: index, displayName: displayName, isPlist: false)
        case .other:
            var hop = Hop(index: index, kind: .unknown, path: path, displayName: displayName, depth: depth,
                          trust: HopTrust(verdict: .unknown, reasons: ["无法识别的文件类型，无法继续静态追踪"]),
                          file: FS.metadata(path))
            return hop
        }
    }

    // MARK: Mach-O

    private func inspectMachO(_ path: String, depth: Int, index: Int, displayName: String,
                              argv: [String], env: [String: String]) -> Hop {
        let meta = FS.metadata(path)
        let signing = CodeSigning.assess(path: path)
        var techniques: [String] = []
        var reasons: [String] = []
        var children: [Hop] = []

        // 可写性检查（签名二进制被篡改风险）
        // 家目录内、仅属主可写的已签名程序是正常的用户级安装模式（如 Google/微软自动更新器），
        // 不按篡改风险处理；全局/组可写，或系统位置内属主可写才是真实风险。
        let inHome = path.hasPrefix(NSHomeDirectory() + "/")
        let dangerousWritable = meta.worldWritable || meta.groupWritable
            || (meta.ownerWritableByNonRoot && !inHome)
        let writable = FS.isWritableByNonRoot(meta)
        if dangerousWritable {
            techniques.append("T07")
            reasons.append("签名二进制存在过宽写权限(\(meta.posixPermissions ?? "?") \(meta.owner ?? "?"):\(meta.group ?? "?"))，可被非授权用户替换")
        } else if writable && !inHome {
            reasons.append("属主可写(\(meta.posixPermissions ?? "?"))：签名有效时风险有限，建议关注文件哈希变化")
        }

        // DYLD 注入（系统自身的行为开关变量不算注入）
        let dyldBehaviorFlags = Self.dyldBehaviorFlags

        let dyldEntries = env.filter { $0.key.hasPrefix("DYLD_") }
        for (key, value) in dyldEntries where !Self.dyldBehaviorFlags.contains(key) {
            techniques.append("T02")
            reasons.append("环境变量 \(key)=\(value) 可注入动态库")
            // 追注入的库路径（冒号分隔）；数字/开关等非路径值不建链
            for lib in value.components(separatedBy: ":") where lib.hasPrefix("/") {
                let libPath = lib.hasPrefix("/") ? lib : path.deletingLastPathComponent + "/" + lib
                children.append(inspectPath(libPath, depth: depth + 1, displayName: "注入库: \(lib)"))
            }
        }

        let verdict: HopVerdict
        if !signing.signed {
            if let err = signing.assessmentError, err.contains("Permission denied") {
                // 权限不足无法评估（如 root 专属守护进程）：不下恶意结论
                verdict = .unknown
                reasons.append("当前权限无法读取该系统二进制，签名未能评估（建议以 root 重跑）")
            } else {
                verdict = .malicious
                reasons.append("未签名 Mach-O：\(signing.assessmentError ?? "无签名信息")")
                techniques.append("T07")
            }
        } else if !signing.valid {
            verdict = .malicious
            reasons.append("签名校验未通过（二进制可能被篡改）：\(signing.assessmentError ?? "未知错误")")
            techniques.append("T07")
        } else if signing.isAppleAnchored || signing.isPlatformBinary {
            // Apple 第一方优先于 ad-hoc 判断：平台二进制走独立信任链，没有常规证书链
            verdict = .trusted
            reasons.append("Apple 平台签名（identifier: \(signing.identifier ?? "?")）")
        } else if signing.isAdHoc {
            verdict = .malicious
            reasons.append("仅 ad-hoc 签名（无开发者身份背书，任何人可自行生成，常见于本地编译的投放载荷）")
            techniques.append("T07")
        } else if writable {
            verdict = .suspicious
        } else if signing.notarized {
            verdict = .trusted
            reasons.append("有效开发者签名且已公证（team: \(signing.teamID ?? "?")）")
        } else {
            verdict = .suspicious
            reasons.append("有开发者签名但未公证（team: \(signing.teamID ?? "?")）")
        }

        return Hop(index: index, kind: .machO, path: path, displayName: displayName, depth: depth,
                   trust: HopTrust(verdict: verdict, reasons: reasons,
                                   techniques: Array(NSOrderedSet(array: techniques)) as? [String] ?? []),
                   signing: signing, file: meta, argv: argv, env: env,
                   children: children)
    }

    // MARK: 脚本

    private func inspectScript(_ path: String, depth: Int, index: Int, displayName: String,
                               shebang: String?, argv: [String], env: [String: String]) -> Hop {
        let meta = FS.metadata(path)
        let pathDirs = (customPath.isEmpty ? defaultPath : customPath)
        let parser = ScriptParser(path: path, env: env, inheritedPath: pathDirs)
        let analysis = parser.analyzeFile(path)

        var techniques = analysis.techniques
        var reasons = analysis.indicators
        var children: [Hop] = []

        // 1) shebang 解释器；无 shebang 时按扩展名推断默认解释器
        if let effectiveShebang = shebang ?? Self.defaultShebang(for: path),
           let interp = parseShebang(effectiveShebang) {
            let interpHop = inspectCommand(path: interp.path, displayName: interp.path.lastPathComponent,
                                           args: interp.args + argv, env: env, depth: depth + 1,
                                           originNote: "shebang")
            children.append(interpHop)
            // 合法解释器借用识别：可信签名二进制加载非系统位置脚本
            if interpHop.kind == .machO,
               (interpHop.trust.verdict == .trusted || interpHop.trust.verdict == .borrowed),
               !isSystemLocation(path) {
                techniques.append("T01")
                reasons.append("合法签名解释器 \(interp.path.lastPathComponent) 被借用来加载非系统位置的脚本")
            }
        }

        // 2) 多层包装：脚本 source 另一个脚本 / 引用其他文件
        for ref in analysis.referencedPaths where ref != path {
            let child = inspectPath(ref, depth: depth + 1)
            // 包装链：非系统位置脚本继续引用其他可执行脚本，才按藏匿手法计分
            if (child.kind == .script || child.kind == .inlineScript), !isSystemLocation(path) {
                techniques.append("T04")
                reasons.append("多层包装：脚本继续引用 \(ref.lastPathComponent)，载荷藏在链路深处")
            }
            children.append(child)
        }

        // 3) 内联 -c/-e 片段：作为虚拟节点继续解析
        for snippet in analysis.inlineSnippets {
            children.append(inspectInline(snippet, depth: depth + 1, env: env,
                                          baseDir: path.deletingLastPathComponent))
        }

        // 4) 可写脚本 = 配置替换风险
        if FS.isWritableByNonRoot(meta) {
            techniques.append("T03")
            reasons.append("脚本对非 root 用户可写(\(meta.posixPermissions ?? "?") \(meta.owner ?? "?"))，内容可被替换")
        }

        let verdict = TrustEngine.verdictForScript(children: children, techniques: techniques)
        return Hop(index: index, kind: .script, path: path, displayName: displayName, depth: depth,
                   trust: HopTrust(verdict: verdict,
                                   reasons: reasons,
                                   techniques: Array(NSOrderedSet(array: techniques)) as? [String] ?? []),
                   file: meta, argv: argv, env: env,
                   note: analysis.note,
                   children: children)
    }

    // MARK: 配置 / 文本数据文件

    private func inspectConfig(_ path: String, depth: Int, index: Int, displayName: String, isPlist: Bool) -> Hop {
        let meta = FS.metadata(path)
        var techniques: [String] = []
        var reasons: [String] = []
        var children: [Hop] = []

        if FS.isWritableByNonRoot(meta) {
            techniques.append("T03")
            reasons.append("配置文件对非 root 用户可写，可被替换为恶意内容")
        }

        // plist 里的 ProgramArguments / 文本里出现的本地路径
        let refs = extractReferencedPaths(from: path, isPlist: isPlist)
        for ref in refs where ref != path {
            children.append(inspectPath(ref, depth: depth + 1))
        }

        let verdict: HopVerdict
        if children.contains(where: { $0.trust.verdict == .malicious }) {
            verdict = .malicious
        } else if !techniques.isEmpty || children.contains(where: { $0.trust.verdict == .suspicious || $0.trust.verdict == .borrowed }) {
            verdict = .suspicious
        } else {
            verdict = .trusted
        }

        return Hop(index: index, kind: .config, path: path, displayName: displayName, depth: depth,
                   trust: HopTrust(verdict: verdict, reasons: reasons,
                                   techniques: Array(NSOrderedSet(array: techniques)) as? [String] ?? []),
                   file: meta, children: children)
    }

    private func extractReferencedPaths(from path: String, isPlist: Bool) -> [String] {
        var found: [String] = []
        if isPlist, let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
           let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
            if let program = plist["Program"] as? String { found.append(program) }
            if let args = plist["ProgramArguments"] as? [String], let first = args.first { found.append(first) }
        }
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return found }
        let ns = text as NSString
        if let re = try? NSRegularExpression(pattern: #"(/[A-Za-z0-9_.\-/ ]+)"#) {
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let p = ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
                if FS.exists(p) { found.append(p) }
            }
        }
        return Array(NSOrderedSet(array: found)) as? [String] ?? []
    }

    // MARK: 内联命令（解释器 -c 的虚拟节点）

    private func inspectInline(_ snippet: String, depth: Int, env: [String: String], baseDir: String) -> Hop {
        indexCounter += 1
        let index = indexCounter
        let display = snippet.count > 60 ? String(snippet.prefix(60)) + "…" : snippet

        // 内联片段复用 shell 解析器（路径解析基准设为父脚本目录）
        let parser = ScriptParser(path: baseDir + "/<inline>.sh", env: env,
                                  inheritedPath: customPath.isEmpty ? defaultPath : customPath)
        let analysis = parser.analyzeText(snippet)

        var techniques = unionTech(["T12"], analysis.techniques)
        var reasons = analysis.indicators
        var children: [Hop] = []
        for ref in analysis.referencedPaths {
            children.append(inspectPath(ref, depth: depth + 1))
        }
        for nested in analysis.inlineSnippets where nested != snippet {
            children.append(inspectInline(nested, depth: depth + 1, env: env, baseDir: baseDir))
        }

        let verdict: HopVerdict
        if children.contains(where: { $0.trust.verdict == .malicious }) { verdict = .malicious }
        else if !analysis.techniques.isEmpty || children.contains(where: { $0.trust.verdict != .trusted }) {
            verdict = .suspicious
        } else {
            verdict = .borrowed   // 纯内联执行本身就是"解释器借用"形态
        }

        return Hop(index: index, kind: .inlineScript,
                   path: "<inline: \(display)>", displayName: display, depth: depth,
                   trust: HopTrust(verdict: verdict, reasons: reasons, techniques: techniques),
                   note: "内联代码（无独立载荷文件）",
                   children: children)
    }

    // MARK: 命令检查（带参数的入口，处理 env/解释器/open 等）

    private func inspectCommand(path: String, displayName: String, args: [String],
                                env: [String: String], depth: Int, originNote: String) -> Hop {
        let resolved = path.hasPrefix("/") ? FS.resolveSymlinks(path) : (resolveCommand(path) ?? path)
        let base = resolved.lastPathComponent

        // env: 剥掉 env 选项和前置赋值，追真正的命令
        if base == "env" {
            var idx = 0
            var innerEnv = env
            while idx < args.count {
                let a = args[idx]
                if a.hasPrefix("-") { idx += 1; continue }
                if a.contains("="), a.range(of: #"^[A-Za-z_][A-Za-z0-9_]*="#, options: .regularExpression) != nil {
                    let parts = a.split(separator: "=", maxSplits: 1).map(String.init)
                    innerEnv[parts[0]] = parts.count > 1 ? parts[1] : ""
                    idx += 1
                    continue
                }
                break
            }
            let rest = Array(args[idx...])
            guard let real = rest.first else {
                return inspectPath(resolved, depth: depth, displayName: displayName, argv: args, env: env)
            }
            let realPath = resolveCommand(real, extraEnv: innerEnv) ?? real
            let child = inspectCommand(path: realPath, displayName: real,
                                       args: Array(rest.dropFirst()), env: innerEnv,
                                       depth: depth + 1, originNote: "env")
            var hop = Hop(index: 0, kind: .machO, path: resolved, displayName: "env", depth: depth,
                          trust: HopTrust(verdict: .borrowed,
                                          reasons: ["env 包装器转交给 \(real) 执行"],
                                          techniques: unionTech(["T01"], child.trust.techniques)),
                          file: FS.metadata(resolved), argv: args, env: env, children: [child])
            indexCounter += 1
            hop.index = indexCounter
            return hop
        }

        // 解释器类：自身签名节点 + 参数中的脚本/内联
        let interpreters = Set(["sh", "bash", "zsh", "dash", "ksh"])
        if interpreters.contains(base) {
            return inspectInterpreter(resolved: resolved, displayName: displayName, args: args,
                                      env: env, depth: depth, originNote: originNote,
                                      inlineFlag: "-c")
        }
        let pyInterpreters = Set(["python", "python3", "perl", "ruby", "node", "php"])
        if pyInterpreters.contains(base) {
            return inspectInterpreter(resolved: resolved, displayName: displayName, args: args,
                                      env: env, depth: depth, originNote: originNote,
                                      inlineFlag: "-e")
        }

        // osascript
        if base == "osascript" {
            return inspectOsascript(resolved: resolved, args: args, env: env, depth: depth)
        }

        // open
        if base == "open" {
            return inspectOpen(resolved: resolved, args: args, env: env, depth: depth)
        }

        // 下载工具
        if base == "curl" || base == "wget" {
            indexCounter += 1
            let urls = args.filter { $0.hasPrefix("http") }
            return Hop(index: indexCounter, kind: .machO, path: resolved, displayName: base, depth: depth,
                       trust: HopTrust(verdict: .suspicious,
                                       reasons: ["下载工具出现在持久化执行链中\(urls.isEmpty ? "" : "，目标: \(urls.joined(separator: ", "))")"],
                                       techniques: ["T06"]),
                       file: FS.metadata(resolved), argv: args, env: env)
        }

        // 普通二进制 / 脚本路径
        var hop = inspectPath(resolved, depth: depth, displayName: displayName, argv: args, env: env)
        hop.argv = args
        hop.env = env
        return hop
    }

    private func inspectInterpreter(resolved: String, displayName: String, args: [String],
                                    env: [String: String], depth: Int, originNote: String,
                                    inlineFlag: String) -> Hop {
        indexCounter += 1
        let index = indexCounter
        let selfHop = inspectPath(resolved, depth: depth, displayName: displayName, argv: args, env: env)
        var children: [Hop] = []
        var techniques: [String] = []
        var reasons: [String] = []

        // 内联代码
        if let flagIdx = args.firstIndex(where: { $0 == inlineFlag || (inlineFlag == "-e" && $0 == "-c") }),
           flagIdx + 1 < args.count {
            techniques.append("T12")
            reasons.append("通过 \(args[flagIdx]) 执行内联脚本，载荷不以文件形式存在")
            children.append(inspectInline(args[flagIdx + 1], depth: depth + 1, env: env,
                                          baseDir: FS.resolveSymlinks(resolved).deletingLastPathComponent))
        }

        // 脚本文件参数（跳过选项及其取值）
        var skip = 0
        for (i, arg) in args.enumerated() {
            if skip > 0 { skip -= 1; continue }
            if arg == inlineFlag || arg == "-c" { skip = 1; continue }
            if arg.hasPrefix("-") { continue }
            if let scriptPath = resolveScriptArg(arg, extraEnv: env) {
                let child = inspectPath(scriptPath, depth: depth + 1, displayName: arg.lastPathComponent)
                children.append(child)
                if selfHop.kind == .machO, selfHop.trust.verdict == .trusted, !isSystemLocation(scriptPath) {
                    techniques.append("T01")
                    reasons.append("合法签名解释器 \(resolved.lastPathComponent) 被借用来执行外部脚本 \(arg)")
                }
            } else if arg.hasPrefix("/") || arg.contains("/") || !arg.hasPrefix("-") {
                // 引用的脚本不存在 —— 执行链断裂（可能已被清除）
                let child = inspectPath(arg, depth: depth + 1, displayName: arg.lastPathComponent)
                children.append(child)
                reasons.append("解释器参数引用的脚本不存在: \(arg)")
            }
            break
        }

        let verdict: HopVerdict
        if children.contains(where: { $0.trust.verdict == .malicious }) { verdict = .malicious }
        else if children.contains(where: { $0.trust.verdict == .suspicious }) { verdict = .suspicious }
        else if !children.isEmpty || !techniques.isEmpty { verdict = .borrowed }
        else { verdict = selfHop.trust.verdict }

        return Hop(index: index, kind: selfHop.kind, path: resolved, displayName: displayName, depth: depth,
                   trust: HopTrust(verdict: verdict,
                                   reasons: unionReasons(reasons, selfHop.trust.reasons),
                                   techniques: unionTech(techniques, selfHop.trust.techniques)),
                   signing: selfHop.signing, file: selfHop.file, argv: args, env: env,
                   children: children)
    }

    private func inspectOsascript(resolved: String, args: [String], env: [String: String], depth: Int) -> Hop {
        indexCounter += 1
        let index = indexCounter
        let selfHop = inspectPath(resolved, depth: depth, displayName: "osascript", argv: args, env: env)
        var children: [Hop] = []
        var techniques = ["T01"]
        var reasons: [String] = []

        if let eIdx = args.firstIndex(of: "-e"), eIdx + 1 < args.count {
            techniques.append("T12")
            reasons.append("osascript -e 内联 AppleScript/JavaScript")
            children.append(inspectInline(args[eIdx + 1], depth: depth + 1, env: env, baseDir: "/tmp"))
        }
        for arg in args where !arg.hasPrefix("-") {
            if let p = resolveScriptArg(arg, extraEnv: env) {
                children.append(inspectPath(p, depth: depth + 1))
                break
            }
        }
        let verdict: HopVerdict = children.contains(where: { $0.trust.verdict == .malicious }) ? .malicious
            : children.contains(where: { $0.trust.verdict == .suspicious }) ? .suspicious : .borrowed
        return Hop(index: index, kind: selfHop.kind, path: resolved, displayName: "osascript", depth: depth,
                   trust: HopTrust(verdict: verdict, reasons: reasons,
                                   techniques: Array(NSOrderedSet(array: techniques)) as? [String] ?? []),
                   signing: selfHop.signing, file: selfHop.file, argv: args, env: env, children: children)
    }

    private func inspectOpen(resolved: String, args: [String], env: [String: String], depth: Int) -> Hop {
        indexCounter += 1
        let index = indexCounter
        var techniques = ["T01"]
        let reasons = ["open 被用作执行包装，真实程序由 LaunchServices 决定"]
        var children: [Hop] = []
        var target: String?
        if let aIdx = args.firstIndex(of: "-a"), aIdx + 1 < args.count {
            target = resolveCommand(args[aIdx + 1]) ?? args[aIdx + 1]
        } else {
            target = args.first { !$0.hasPrefix("-") }
        }
        if let t = target {
            let p = t.hasPrefix("/") ? t : resolveCommand(t) ?? t
            children.append(inspectPath(p, depth: depth + 1))
        }
        let verdict: HopVerdict = children.contains(where: { $0.trust.verdict == .malicious }) ? .malicious
            : children.contains(where: { $0.trust.verdict == .suspicious }) ? .suspicious : .borrowed
        return Hop(index: index, kind: .machO, path: resolved, displayName: "open", depth: depth,
                   trust: HopTrust(verdict: verdict, reasons: reasons,
                                   techniques: Array(NSOrderedSet(array: techniques)) as? [String] ?? []),
                   file: FS.metadata(resolved), argv: args, env: env, children: children)
    }

    // MARK: 辅助

    /// 无 shebang 脚本的默认解释器推断
    private static func defaultShebang(for path: String) -> String? {
        let lower = path.lowercased()
        if lower.hasSuffix(".py") { return "/usr/bin/env python3" }
        if lower.hasSuffix(".pl") { return "/usr/bin/env perl" }
        if lower.hasSuffix(".rb") { return "/usr/bin/env ruby" }
        if lower.hasSuffix(".sh") || lower.hasSuffix(".zsh") || lower.hasSuffix(".bash") || lower.hasSuffix(".command") {
            return "/bin/sh"
        }
        return nil
    }

    private func parseShebang(_ shebang: String) -> (path: String, args: [String])? {
        let parts = shebang.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard let first = parts.first else { return nil }
        // #!/usr/bin/env python3 形式
        if first.hasSuffix("/env") {
            guard let tool = parts.dropFirst().first else { return nil }
            let resolved = resolveCommand(tool) ?? ("/usr/bin/" + tool)
            return (resolved, Array(parts.dropFirst(2)))
        }
        return (first, Array(parts.dropFirst()))
    }

    private func isSystemLocation(_ path: String) -> Bool {
        path.hasPrefix("/System/") || path.hasPrefix("/usr/") || path.hasPrefix("/bin/")
            || path.hasPrefix("/sbin/") || path.hasPrefix("/Library/Apple/")
    }

    private func unionTech(_ a: [String], _ b: [String]) -> [String] {
        Array(NSOrderedSet(array: a + b)) as? [String] ?? a + b
    }

    private func unionReasons(_ a: [String], _ b: [String]) -> [String] {
        Array(NSOrderedSet(array: a + b)) as? [String] ?? a + b
    }
}
