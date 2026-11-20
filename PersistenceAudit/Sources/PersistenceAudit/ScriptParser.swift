import Foundation

// MARK: - 脚本静态分析
// 启发式解析（非完整 shell 语法实现）：提取脚本真正引用的可执行文件、源文件、
// 内联命令、下载执行与混淆特征。所有结论都是"可疑指示"，由 TrustEngine 汇总。

struct ScriptCommand {
    var argv: [String]
    var rawLine: String
    var envAssignments: [String: String] = [:]   // FOO=bar cmd ... 形式
    var isPipelineWithDownload: Bool = false
    var pipelineCommands: [[String]] = []
}

struct ScriptAnalysis {
    var commands: [ScriptCommand] = []
    var referencedPaths: [String] = []           // 脚本中出现且真实存在的本地路径
    var urlStrings: [String] = []
    var inlineSnippets: [String] = []            // 传给解释器 -c 的内联代码
    var techniques: [String] = []
    var indicators: [String] = []                // 人类可读的可疑指示
    var sourcedFiles: [String] = []
    var note: String?
}

enum ScriptKind {
    case shell, python, perl, ruby, osascript, unknown
}

struct ScriptParser {

    let kind: ScriptKind
    let scriptPath: String
    let searchPaths: [String]                   // 脚本所在目录 + 继承的 PATH
    var variables: [String: String]

    // POSIX shell 内建命令：不是外部可执行文件，不应进入执行链
    static let shellBuiltins: Set<String> = [
        "cd", "echo", "printf", "pwd", "export", "unset", "readonly", "shift",
        "set", "unset", "alias", "unalias", "source", "eval", "exec", "exit",
        "return", "break", "continue", "wait", "trap", "umask", "times", "getopts",
        "hash", "help", "history", "jobs", "kill", "let", "local", "mapfile",
        "read", "readarray", "type", "typeset", "ulimit", "command", "builtin",
        "test", "[", "true", "false", "fc", "bg", "fg", "disown", "suspend",
        "caller", "compgen", "complete", "compopt", "declare", "dirs", "enable",
        "popd", "pushd", "shopt", "logout", "bind", "do", "done", "if", "then",
        "else", "elif", "fi", "for", "while", "case", "esac", "function", "in"
    ]

    init(path: String, env: [String: String] = [:], inheritedPath: [String]) {
        self.kind = ScriptParser.classify(path)
        self.scriptPath = path
        self.searchPaths = [path.deletingLastPathComponent] + inheritedPath
        self.variables = env
    }

    static func classify(_ path: String) -> ScriptKind {
        let lower = path.lowercased()
        if lower.hasSuffix(".sh") || lower.hasSuffix(".zsh") || lower.hasSuffix(".bash") { return .shell }
        if lower.hasSuffix(".py") { return .python }
        if lower.hasSuffix(".pl") { return .perl }
        if lower.hasSuffix(".rb") { return .ruby }
        if lower.hasSuffix(".scpt") || lower.hasSuffix(".applescript") || lower.hasSuffix(".js") { return .osascript }
        return .unknown
    }

    // MARK: 入口

    func analyzeFile(_ path: String) -> ScriptAnalysis {
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else {
            var a = ScriptAnalysis()
            a.note = "无法以 UTF-8 读取脚本内容"
            return a
        }
        return analyzeText(content)
    }

    func analyzeText(_ content: String) -> ScriptAnalysis {
        switch kind {
        case .shell, .unknown:
            return analyzeShell(content)
        default:
            return analyzeGenericScript(content)
        }
    }

    // MARK: Shell 类脚本

    private func analyzeShell(_ content: String) -> ScriptAnalysis {
        var analysis = ScriptAnalysis()
        var vars = variables
        let lines = preprocess(content)

        for raw in lines {
            let trimmed = raw.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            // 管道两侧都要解析；下载|执行 的组合在管道级别标记
            let segments = splitPipeline(trimmed)
            var parsedCommands: [[String]] = []
            for segment in segments {
                let (env, cmd) = splitEnvAssignments(tokenize(segment, vars: vars))
                if cmd.isEmpty {
                    // 纯赋值语句 FOO=bar
                    for (k, v) in env { vars[k] = v }
                    continue
                }
                var sc = ScriptCommand(argv: cmd, rawLine: trimmed, envAssignments: env)
                analysis.commands.append(sc)
                parsedCommands.append(cmd)
                handleCommand(cmd, raw: trimmed, analysis: &analysis, vars: vars)
            }
            if parsedCommands.count > 1, isDownloadPipeline(parsedCommands) {
                analysis.techniques.append("T06")
                analysis.indicators.append("下载工具与解释器通过管道串联（下载即执行）: \(trimmed)")
                if let idx = analysis.commands.indices.last {
                    analysis.commands[idx].isPipelineWithDownload = true
                    analysis.commands[idx].pipelineCommands = parsedCommands
                }
            }
        }
        analysis.techniques = Array(NSOrderedSet(array: analysis.techniques)) as? [String] ?? analysis.techniques
        return analysis
    }

    // MARK: 非 shell 脚本（python/perl/ruby/applescript）
    // 不做完整语法解析：提取字符串字面量中的路径/URL，以及 eval/exec/urllib 等动态特征

    private func analyzeGenericScript(_ content: String) -> ScriptAnalysis {
        var analysis = ScriptAnalysis()

        // 字符串里的绝对路径（引号或空白分隔）
        let pathPattern = #"(?:"|'|\s|=)(/[^\s"'\\;|&<>()]+)"#
        if let re = try? NSRegularExpression(pattern: pathPattern) {
            let ns = content as NSString
            for m in re.matches(in: content, range: NSRange(location: 0, length: ns.length)) {
                let p = ns.substring(with: m.range(at: 1))
                if FS.exists(p) { analysis.referencedPaths.append(p) }
            }
        }

        let lower = content.lowercased()
        let dynamicMarkers: [(String, String, String)] = [
            ("eval(", "T05", "运行时 eval 动态执行"),
            ("exec(", "T05", "运行时 exec 动态执行"),
            ("base64", "T05", "base64 编解码（可能用于还原载荷）"),
            ("urllib", "T06", "网络请求能力（脚本可运行时拉取载荷）"),
            ("requests.get", "T06", "网络请求能力（脚本可运行时拉取载荷）"),
            ("subprocess", "T01", "调用子进程执行外部程序"),
            ("os.system", "T01", "调用系统命令"),
            ("popen", "T01", "管道方式调用外部程序")
        ]
        for (marker, tech, desc) in dynamicMarkers where lower.contains(marker) {
            analysis.techniques.append(tech)
            analysis.indicators.append(desc + ": \(marker)")
        }
        analysis.referencedPaths = Array(NSOrderedSet(array: analysis.referencedPaths)) as? [String] ?? []
        analysis.techniques = Array(NSOrderedSet(array: analysis.techniques)) as? [String] ?? []
        return analysis
    }

    // MARK: 单条命令的语义处理

    private func handleCommand(_ cmd: [String], raw: String, analysis: inout ScriptAnalysis, vars: [String: String]) {
        guard let first = cmd.first else { return }
        let base = first.lastPathComponent
        let args = Array(cmd.dropFirst())

        // 1) source / . 加载其他脚本 —— 包装链向下走
        if base == "source" || (base == "." && first == ".") {
            for arg in args where !arg.hasPrefix("-") {
                if let resolved = resolvePath(arg, vars: vars) {
                    analysis.sourcedFiles.append(resolved)
                    analysis.referencedPaths.append(resolved)
                }
            }
            return
        }

        // 2) eval / 混淆执行
        if base == "eval" {
            analysis.indicators.append("eval 动态求值: \(raw)")
            if !isSystemPath(scriptPath) { analysis.techniques.append("T05") }
            // eval 里如果是命令替换产生的命令，继续抽出其中可见的命令名
            analysis.inlineSnippets.append(args.joined(separator: " "))
            return
        }
        if base == "base64" && args.contains(where: { $0 == "-d" || $0 == "--decode" || $0 == "-D" }) {
            analysis.indicators.append("base64 解码（常见载荷还原手法）: \(raw)")
            if !isSystemPath(scriptPath) { analysis.techniques.append("T05") }
            return
        }

        // 3) 解释器 -c 内联
        let interpreters = Set(["sh", "bash", "zsh", "dash", "ksh", "python", "python3",
                                "perl", "ruby", "node", "php", "osascript"])
        if interpreters.contains(base) {
            if let cIndex = args.firstIndex(where: { $0 == "-c" || $0 == "-e" }), cIndex + 1 < args.count {
                analysis.techniques.append("T12")
                analysis.inlineSnippets.append(args[cIndex + 1])
            }
            // 解释器后跟脚本文件路径
            for arg in args where !arg.hasPrefix("-") {
                if let resolved = resolvePath(arg, vars: vars) {
                    analysis.referencedPaths.append(resolved)
                    break
                }
            }
        }

        // 4) osascript
        if base == "osascript" {
            if let eIndex = args.firstIndex(of: "-e"), eIndex + 1 < args.count {
                analysis.techniques.append("T12")
                analysis.inlineSnippets.append(args[eIndex + 1])
            }
            for arg in args where !arg.hasPrefix("-") {
                if let resolved = resolvePath(arg, vars: vars) {
                    analysis.referencedPaths.append(resolved)
                    break
                }
            }
        }

        // 5) env：跳过选项，第一个非选项是真正的命令；-i/S 等也一并容忍
        if base == "env" {
            if let real = args.first(where: { !$0.hasPrefix("-") }) {
                if let resolved = resolvePath(real, vars: vars) {
                    analysis.referencedPaths.append(resolved)
                }
            }
        }

        // 6) open -a / 文件参数
        if base == "open" {
            if let aIdx = args.firstIndex(of: "-a"), aIdx + 1 < args.count {
                collectCandidate(args[aIdx + 1], analysis: &analysis, vars: vars)
            }
            for arg in args where !arg.hasPrefix("-") {
                collectCandidate(arg, analysis: &analysis, vars: vars)
            }
        }

        // 7) 下载工具单独出现（没有管道也记录能力）
        if base == "curl" || base == "wget" {
            for arg in args where arg.hasPrefix("http") {
                analysis.urlStrings.append(arg)
            }
            if args.contains("-o") || args.contains("--output") || args.contains("-O") {
                analysis.indicators.append("下载工具带落地参数，注意后续是否执行该文件: \(raw)")
            }
        }

        // 8) 命令替换 $(...) 或反引号
        // 系统位置脚本里这是常规 shell 用法，只记录指示不打手法分；非系统位置才视为混淆信号
        if raw.contains("$(") || raw.contains("`") {
            analysis.indicators.append("使用命令替换动态构造命令: \(raw)")
            if !isSystemPath(scriptPath) {
                analysis.techniques.append("T05")
            }
        }

        // 9) 普通可执行文件 / 脚本参数中的路径
        if first.hasPrefix("/") {
            collectCandidate(first, analysis: &analysis, vars: vars)
        } else if !interpreters.contains(base) && !Self.shellBuiltins.contains(base)
                    && !["launchctl", "defaults", "chmod", "chown", "xattr", "mkdir",
                         "rm", "cp", "mv", "ln", "sudo", "sleep",
                         "touch", "tee", "logger"].contains(base) {
            // 裸命令名：尝试 PATH 解析
            if let resolved = resolvePath(first, vars: vars) {
                analysis.referencedPaths.append(resolved)
            }
        }

        // 10) DYLD 变量出现在脚本里
        for key in ["DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_LIBRARY_PATH"] {
            if raw.contains(key) {
                analysis.techniques.append("T02")
                analysis.indicators.append("脚本内设置 \(key) 注入环境: \(raw)")
            }
        }

        analysis.referencedPaths = Array(NSOrderedSet(array: analysis.referencedPaths)) as? [String] ?? []
        analysis.techniques = Array(NSOrderedSet(array: analysis.techniques)) as? [String] ?? []
    }

    private func collectCandidate(_ candidate: String, analysis: inout ScriptAnalysis, vars: [String: String]) {
        if let resolved = resolvePath(candidate, vars: vars) {
            analysis.referencedPaths.append(resolved)
        }
    }

    private func isDownloadPipeline(_ cmds: [[String]]) -> Bool {
        let names = cmds.compactMap { $0.first?.lastPathComponent }
        let download = names.contains("curl") || names.contains("wget")
        let interpreter = names.contains { ["sh", "bash", "zsh", "python", "python3", "perl", "ruby", "node"].contains($0) }
        return download && interpreter
    }

    private func isSystemPath(_ command: String) -> Bool {
        command.hasPrefix("/System/") || command.hasPrefix("/usr/") || command.hasPrefix("/bin/")
            || command.hasPrefix("/sbin/") || command.hasPrefix("/Library/Apple/")
    }

    // MARK: 路径解析

    private func resolvePath(_ raw: String, vars: [String: String]) -> String? {
        var p = raw
        // 去掉引号
        p = p.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if p.isEmpty { return nil }

        // 变量展开（只处理整体就是 $VAR 的常见情形，复杂表达式保守跳过）
        if p.hasPrefix("$") {
            let key = String(p.dropFirst())
            if let v = vars[key] { p = v } else { return nil }
        }
        // ~ 展开
        if p == "~" { p = NSHomeDirectory() }
        else if p.hasPrefix("~/") { p = NSHomeDirectory() + String(p.dropFirst(1)) }

        if p.hasPrefix("/") {
            return FS.exists(p) ? p : nil
        }
        // 相对路径：先看脚本目录，再看 PATH
        for dir in searchPaths {
            let candidate = dir + "/" + p
            if FS.exists(candidate) { return candidate }
        }
        return nil
    }

    // MARK: 词法处理

    /// 续行合并、去注释、处理 here-doc
    private func preprocess(_ content: String) -> [String] {
        let rawLines = content.components(separatedBy: "\n")
        var output: [String] = []
        var buffer = ""
        var inHeredoc = false
        var heredocMarker: String?

        for line in rawLines {
            if inHeredoc {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed == heredocMarker { inHeredoc = false; heredocMarker = nil }
                // here-doc 内容本身不解析为命令
                continue
            }
            // here-doc 起始：cmd <<EOF / <<-EOF
            if let range = line.range(of: #"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)"#, options: .regularExpression) {
                heredocMarker = String(line[range].split(separator: " ").last ?? "")
                inHeredoc = true
                continue
            }

            let noComment = stripComment(line)
            if buffer.isEmpty { buffer = noComment } else { buffer += " " + noComment.trimmingCharacters(in: .whitespaces) }

            if buffer.hasSuffix("\\") {
                buffer.removeLast()
                continue
            }
            let trimmed = buffer.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty { output.append(trimmed) }
            buffer = ""
        }
        if !buffer.trimmingCharacters(in: .whitespaces).isEmpty {
            output.append(buffer)
        }
        return output
    }

    /// 去掉 # 注释（不碰引号内的 #）
    private func stripComment(_ line: String) -> String {
        var inSingle = false, inDouble = false
        for (idx, ch) in line.enumerated() {
            if ch == "'" && !inDouble { inSingle.toggle() }
            if ch == "\"" && !inSingle { inDouble.toggle() }
            if ch == "#" && !inSingle && !inDouble {
                return String(line[line.startIndex..<line.index(line.startIndex, offsetBy: idx)])
            }
        }
        return line
    }

    private func splitPipeline(_ line: String) -> [String] {
        // 仅按未被引号包裹的 | 拆分；|| 与函数体内管道的极端情形保守容忍
        var segments: [String] = []
        var current = ""
        var inSingle = false, inDouble = false
        var prev: Character?
        for ch in line {
            if ch == "'" && !inDouble { inSingle.toggle() }
            if ch == "\"" && !inSingle { inDouble.toggle() }
            if ch == "|" && !inSingle && !inDouble && prev != "|" {
                segments.append(current)
                current = ""
            } else {
                current.append(ch)
            }
            prev = ch
        }
        segments.append(current)
        return segments.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// 简单词法拆分：支持单双引号、反斜杠转义、重定向剥离、$VAR 展开
    private func tokenize(_ line: String, vars: [String: String]) -> [String] {
        var tokens: [String] = []
        var current = ""
        var inSingle = false, inDouble = false
        var chars = Array(line)
        var i = 0
        var skipNextRedirect = false

        while i < chars.count {
            let ch = chars[i]
            if skipNextRedirect {
                if ch.isWhitespace { skipNextRedirect = false }
                i += 1
                continue
            }
            if ch == "'" && !inDouble {
                inSingle.toggle(); i += 1; continue
            }
            if ch == "\"" && !inSingle {
                inDouble.toggle(); i += 1; continue
            }
            if ch == "\\" && i + 1 < chars.count && !inSingle {
                current.append(chars[i + 1]); i += 2; continue
            }
            if ch.isWhitespace && !inSingle && !inDouble {
                if !current.isEmpty { tokens.append(expand(current, vars: vars)); current = "" }
                i += 1; continue
            }
            // 重定向符 < > 及其后面的目标整体跳过
            if (ch == ">" || ch == "<") && !inSingle && !inDouble {
                if !current.isEmpty { tokens.append(expand(current, vars: vars)); current = "" }
                skipNextRedirect = true
                // 处理 >> 2> 等
                i += 1
                while i < chars.count, chars[i] == ">" || chars[i] == "<" || chars[i].isNumber { i += 1 }
                continue
            }
            if ch == ";" && !inSingle && !inDouble {
                if !current.isEmpty { tokens.append(expand(current, vars: vars)); current = "" }
                i += 1; continue
            }
            current.append(ch)
            i += 1
        }
        if !current.isEmpty { tokens.append(expand(current, vars: vars)) }
        return tokens
    }

    private func expand(_ token: String, vars: [String: String]) -> String {
        guard token.hasPrefix("$") else { return token }
        let key = String(token.dropFirst())
        return vars[key] ?? ProcessInfo.processInfo.environment[key] ?? ""
    }

    private func splitEnvAssignments(_ tokens: [String]) -> ([String: String], [String]) {
        var env: [String: String] = [:]
        var cmd = tokens
        while let t = cmd.first, t.contains("="), !t.hasPrefix("="),
              t.range(of: #"^[A-Za-z_][A-Za-z0-9_]*="#, options: .regularExpression) != nil {
            let parts = t.split(separator: "=", maxSplits: 1).map(String.init)
            env[parts[0]] = parts.count > 1 ? parts[1] : ""
            cmd.removeFirst()
        }
        return (env, cmd)
    }
}
