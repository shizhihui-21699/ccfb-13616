import Foundation
import CryptoKit

// MARK: - 自动启动项采集
struct PersistenceCollector {

    let root: String           // 测试时可重定向到假根目录；真机审计为 "/"
    var notes: [String] = []

    private var r: String { root == "/" ? "" : root }

    mutating func collectAll() -> [AuditItem] {
        var items: [AuditItem] = []
        items.append(contentsOf: collectLaunchd())
        items.append(contentsOf: collectCron())
        items.append(contentsOf: collectShellInit())
        items.append(contentsOf: collectBTM())
        return items
    }

    // MARK: launchd plist

    private func launchdDirs() -> [(path: String, kind: PersistenceKind)] {
        [
            (r + "/System/Library/LaunchAgents", .launchAgent),
            (r + "/Library/LaunchAgents", .launchAgent),
            (r + NSHomeDirectory() + "/Library/LaunchAgents", .launchAgent),
            (r + "/System/Library/LaunchDaemons", .launchDaemon),
            (r + "/Library/LaunchDaemons", .launchDaemon)
        ]
    }

    mutating func collectLaunchd() -> [AuditItem] {
        var items: [AuditItem] = []
        for (dir, kind) in launchdDirs() {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".plist") {
                let plistPath = dir + "/" + entry
                guard let item = parseLaunchPlist(plistPath, kind: kind) else { continue }
                items.append(item)
            }
        }
        return items
    }

    private mutating func parseLaunchPlist(_ plistPath: String, kind: PersistenceKind) -> AuditItem? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: plistPath)),
              let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            notes.append("无法解析 plist: \(plistPath)")
            return nil
        }

        var argv: [String] = []
        if let args = plist["ProgramArguments"] as? [String] {
            argv = args.filter { !$0.isEmpty }
        } else if let program = plist["Program"] as? String, !program.isEmpty {
            argv = [program]
        }
        // 没有可执行入口的 plist（纯配置/Watch 触发器/空登记）跳过
        guard !argv.isEmpty else {
            notes.append("plist 缺少有效 ProgramArguments，已跳过: \(plistPath)")
            return nil
        }

        let label = (plist["Label"] as? String) ?? plistPath.lastPathComponent
        let env = (plist["EnvironmentVariables"] as? [String: String]) ?? [:]

        var item = AuditItem(
            id: stableID("launchd:" + plistPath),
            kind: kind,
            source: kind == .launchAgent ? "LaunchAgent 注册项" : "LaunchDaemon 注册项",
            label: label,
            plistPath: plistPath,
            programArguments: argv,
            environmentVariables: env,
            runAtLoad: plist["RunAtLoad"] as? Bool
        )

        let tracer = Tracer(env: env)
        item.chain = tracer.trace(argv: argv, kindName: item.source)
        TrustEngine.finalize(item: &item)
        return item
    }

    // MARK: cron

    func collectCron() -> [AuditItem] {
        var items: [AuditItem] = []
        let cronFiles = [
            r + "/etc/crontab",
            r + "/etc/periodic"
        ]
        for path in cronFiles {
            if FS.isDirectory(path), let entries = try? FileManager.default.contentsOfDirectory(atPath: path) {
                for e in entries {
                    items.append(contentsOf: parseCronFile(path + "/" + e))
                }
            } else {
                items.append(contentsOf: parseCronFile(path))
            }
        }
        // 用户 crontab 假根：/var/at/tabs/<user>（macOS cron 假脱机目录）
        let tabs = r + "/var/at/tabs"
        if let users = try? FileManager.default.contentsOfDirectory(atPath: tabs) {
            for user in users {
                items.append(contentsOf: parseCronFile(tabs + "/" + user, owner: user))
            }
        }
        return items
    }

    private func parseCronFile(_ path: String, owner: String? = nil) -> [AuditItem] {        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return [] }
        var items: [AuditItem] = []
        for (lineNo, rawLine) in text.components(separatedBy: "\n").enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            // 标准五字段 crontab：分 时 日 月 周 命令；@reboot 等 @ 形式单独处理
            let command: String
            if line.hasPrefix("@") {
                let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
                guard parts.count == 2 else { continue }
                command = parts[1]
            } else {
                let parts = line.split(separator: " ", maxSplits: 5).map(String.init)
                guard parts.count == 6 else { continue }
                command = parts[5]
            }

            // 经 /bin/sh -c 执行 —— 这正是 cron 隐藏手法的关键一环
            let argv = ["/bin/sh", "-c", command]
            let id = stableID("cron:\(path):\(lineNo + 1)")
            var item = AuditItem(
                id: id,
                kind: .cron,
                source: "cron 计划任务\(owner.map { "（用户 \($0)）" } ?? "")",
                label: "\(path.lastPathComponent):\(lineNo + 1)",
                programArguments: argv,
                rawLine: line
            )
            let tracer = Tracer(env: [:])
            item.chain = tracer.trace(argv: argv, kindName: item.source)
            // cron 持久化本身记 T08
            item.techniques.append("T08")
            TrustEngine.finalize(item: &item)
            if !item.techniques.contains("T08") { item.techniques.insert("T08", at: 0) }
            items.append(item)
        }
        return items
    }

    // MARK: shell 初始化文件

    func collectShellInit() -> [AuditItem] {
        let home = r == "" ? NSHomeDirectory() : r + NSHomeDirectory()
        let candidates = [".zshrc", ".zprofile", ".zshenv", ".bashrc",
                          ".bash_profile", ".profile"].map { home + "/" + $0 }
        var items: [AuditItem] = []
        for path in candidates {
            guard FS.exists(path) else { continue }
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }

            // 只把非注释、非空的有效行作为审计内容；逐行建模，每行经 zsh -c 解释
            let activeLines = text.components(separatedBy: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            guard !activeLines.isEmpty else { continue }

            // 合并为一个审计项（一个初始化文件 = 一个持久化点），逐行进链
            var item = AuditItem(
                id: stableID("shellinit:" + path),
                kind: .shellInit,
                source: "Shell 初始化文件（交互式终端启动时执行）",
                label: path.lastPathComponent,
                plistPath: path,
                programArguments: ["/bin/zsh", "-c", activeLines.joined(separator: "; ")]
            )
            let tracer = Tracer(env: [:])
            item.chain = tracer.trace(argv: item.programArguments, kindName: item.source)
            item.techniques.append("T11")
            TrustEngine.finalize(item: &item)
            if !item.techniques.contains("T11") { item.techniques.insert("T11", at: 0) }
            items.append(item)
        }
        return items
    }

    // MARK: Background Task Management（login items，带超时）

    mutating func collectBTM() -> [AuditItem] {
        // 真机 root 才采集；假根环境下 sfltool 看不到测试数据，直接跳过
        guard root == "/" else { return [] }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sfltool")
        process.arguments = ["dumpbtm"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
        } catch {
            notes.append("sfltool dumpbtm 启动失败: \(error.localizedDescription)")
            return []
        }
        // sfltool dumpbtm 在部分系统版本上会长时间不返回，10 秒兜底
        let deadline = DispatchTime.now() + .seconds(10)
        while process.isRunning && DispatchTime.now() < deadline {
            usleep(200_000)
        }
        if process.isRunning {
            process.terminate()
            notes.append("sfltool dumpbtm 超时（10s），已跳过 BTM 登录项采集")
            return []
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8) else { return [] }
        return parseBTMOutput(text)
    }

    /// 解析 sfltool dumpbtm 的段落式输出（键: 值 缩进结构）
    private func parseBTMOutput(_ text: String) -> [AuditItem] {
        var items: [AuditItem] = []
        // 以 "Name:" 起始的条目分段
        let blocks = text.components(separatedBy: "\n")
        var current: [String] = []
        var blocksToParse: [[String]] = []
        for line in blocks {
            if line.hasPrefix("Name:") && !current.isEmpty {
                blocksToParse.append(current)
                current = [line]
            } else {
                current.append(line)
            }
        }
        if !current.isEmpty { blocksToParse.append(current) }

        for block in blocksToParse {
            var name: String?, path: String?, args: [String]?
            for line in block {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("Name:"), name == nil {
                    name = trimmed.replacingOccurrences(of: "Name:", with: "").trimmingCharacters(in: .whitespaces)
                }
                if trimmed.hasPrefix("Path:"), path == nil {
                    path = trimmed.replacingOccurrences(of: "Path:", with: "").trimmingCharacters(in: .whitespaces)
                }
                if trimmed.hasPrefix("Arguments:") {
                    let raw = trimmed.replacingOccurrences(of: "Arguments:", with: "").trimmingCharacters(in: .whitespaces)
                    args = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                }
            }
            guard let execPath = path, FS.exists(execPath) else { continue }
            let argv = (args?.isEmpty == false) ? ([execPath] + args!) : [execPath]
            var item = AuditItem(
                id: stableID("btm:" + execPath),
                kind: .btmLoginItem,
                source: "后台任务管理(BTM) 登录项",
                label: name ?? execPath.lastPathComponent,
                programArguments: argv
            )
            let tracer = Tracer(env: [:])
            item.chain = tracer.trace(argv: argv, kindName: item.source)
            TrustEngine.finalize(item: &item)
            items.append(item)
        }
        return items
    }

    // MARK: 工具

    private func stableID(_ raw: String) -> String {
        let data = raw.data(using: .utf8)!
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined().prefix(16).description
    }
}
