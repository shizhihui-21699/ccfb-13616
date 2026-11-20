import Foundation

// MARK: - 命令行入口
// 用法:
//   PersistenceAudit scan  [--root /] [--baseline path] [--snapshot-out path] [--report path]
//   PersistenceAudit baseline --snapshot path          将某快照登记为基线
//   PersistenceAudit diff --baseline path --snapshot path [--report path]

struct CLI {
    var command: String = "scan"
    var root: String = "/"
    var baselinePath: String = "~/.persistence-audit/baseline.json"
    var snapshotOut: String = "~/.persistence-audit/latest.json"
    var reportPath: String = "~/.persistence-audit/report.html"
    var snapshotPath: String = ""
}

@main
struct Main {
    static func main() {
        let args = CommandLine.arguments
        let cli = parse(args)

        switch cli.command {
        case "scan":
            runScan(cli)
        case "baseline":
            runBaseline(cli)
        case "diff":
            runDiff(cli)
        default:
            printUsage()
            exit(2)
        }
    }

    // MARK: scan

    private static func runScan(_ cli: CLI) {
        let baselinePath = expand(cli.baselinePath)
        let snapshotOut = expand(cli.snapshotOut)
        let reportPath = expand(cli.reportPath)

        var collector = PersistenceCollector(root: cli.root)
        let items = collector.collectAll()

        var snapshot = AuditSnapshot(
            hostname: hostname(),
            auditTime: Date(),
            scanRoot: cli.root,
            notes: collector.notes,
            items: items,
            stats: SnapshotStats()
        )
        snapshot.stats = TrustEngine.stats(of: snapshot)

        // 对比基线
        let baseline = try? SnapshotStore.load(baselinePath)
        let diff = DiffEngine.compare(baseline: baseline, current: snapshot)

        // 输出
        try? FileManager.default.createDirectory(atPath: snapshotOut.deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        do {
            try SnapshotStore.save(snapshot, to: snapshotOut)
        } catch {
            fputs("快照写入失败: \(error)\n", stderr)
            exit(1)
        }
        let html = ReportHTML.generate(snapshot: snapshot, diff: diff)
        do {
            try html.write(toFile: reportPath, atomically: true, encoding: .utf8)
        } catch {
            fputs("报告写入失败: \(error)\n", stderr)
            exit(1)
        }

        printSummary(snapshot: snapshot, diff: diff)
        print("""

        快照: \(snapshotOut)
        报告: \(reportPath)
        基线: \(baseline == nil ? "（不存在，本次为首次审计）" : baselinePath)
        """)
    }

    // MARK: baseline

    private static func runBaseline(_ cli: CLI) {
        let src = expand(cli.snapshotPath.isEmpty ? cli.snapshotOut : cli.snapshotPath)
        let dst = expand(cli.baselinePath)
        do {
            try FileManager.default.createDirectory(atPath: dst.deletingLastPathComponent,
                                                    withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: dst) {
                try FileManager.default.removeItem(atPath: dst)
            }
            try FileManager.default.copyItem(atPath: src, toPath: dst)
            print("已登记基线: \(dst)（来源 \(src)）")
        } catch {
            fputs("登记基线失败: \(error)\n", stderr)
            exit(1)
        }
    }

    // MARK: diff

    private static func runDiff(_ cli: CLI) {
        let baselinePath = expand(cli.baselinePath)
        let snapshotPath = expand(cli.snapshotPath)
        let reportPath = expand(cli.reportPath)
        do {
            let baseline = try SnapshotStore.load(baselinePath)
            let current = try SnapshotStore.load(snapshotPath)
            let diff = DiffEngine.compare(baseline: baseline, current: current)
            let html = ReportHTML.generate(snapshot: current, diff: diff)
            try html.write(toFile: reportPath, atomically: true, encoding: .utf8)
            printSummary(snapshot: current, diff: diff)
            print("\n对比报告: \(reportPath)")
        } catch {
            fputs("对比失败: \(error)\n", stderr)
            exit(1)
        }
    }

    // MARK: 输出与工具

    private static func printSummary(snapshot: AuditSnapshot, diff: AuditDiff) {
        let s = snapshot.stats
        print("=== 持久化执行链审计 ===")
        print("主机: \(snapshot.hostname)   时间: \(ISO8601DateFormatter().string(from: snapshot.auditTime))")
        print("审计项: \(s.totalItems)  执行链跳数: \(s.totalHops)  最大深度: \(s.maxDepth)")
        print("判定: 恶意 \(s.malicious)  可疑 \(s.suspicious)  签名借用 \(s.borrowed)  可信 \(s.trusted)  未知 \(s.unknown)")
        if let b = diff.baselineTime {
            print("对比基线 \(ISO8601DateFormatter().string(from: b)): " +
                  "新增 \(diff.summary["new"] ?? 0)  变更 \(diff.summary["changed"] ?? 0)  " +
                  "消失 \(diff.summary["removed"] ?? 0)  未变化 \(diff.summary["unchanged"] ?? 0)")
        } else {
            print("对比: 无历史基线（首次审计）")
        }
        let flagged = snapshot.items
            .filter { $0.verdict == .malicious || $0.verdict == .suspicious }
            .sorted { $0.score > $1.score }
        if !flagged.isEmpty {
            print("\n--- 重点关注（按评分排序）---")
            for it in flagged {
                print("[\(it.score)] \(it.verdict.rawValue.uppercased())  \(it.label)  手法: \(it.techniques.joined(separator: ","))")
                print("       \(it.programArguments.joined(separator: " "))")
            }
        }
    }

    private static func parse(_ args: [String]) -> CLI {
        var cli = CLI()
        var positional: [String] = []
        var i = 1
        while i < args.count {
            let a = args[i]
            switch a {
            case "--root": cli.root = args[i + 1]; i += 2
            case "--baseline": cli.baselinePath = args[i + 1]; i += 2
            case "--snapshot-out": cli.snapshotOut = args[i + 1]; i += 2
            case "--snapshot": cli.snapshotPath = args[i + 1]; i += 2
            case "--report": cli.reportPath = args[i + 1]; i += 2
            default:
                if !a.hasPrefix("-") { positional.append(a) }
                i += 1
            }
        }
        if let cmd = positional.first { cli.command = cmd }
        return cli
    }

    private static func expand(_ path: String) -> String {
        if path.hasPrefix("~") {
            return NSHomeDirectory() + String(path.dropFirst(1))
        }
        return path
    }

    private static func hostname() -> String {
        var buf = [CChar](repeating: 0, count: Int(MAXHOSTNAMELEN) + 1)
        gethostname(&buf, buf.count)
        return String(cString: buf)
    }

    private static func printUsage() {
        print("""
        PersistenceAudit — macOS 持久化执行链审计工具

        用法:
          PersistenceAudit scan [--root /] [--baseline path] [--snapshot-out path] [--report path]
          PersistenceAudit baseline --snapshot path [--baseline path]
          PersistenceAudit diff --baseline path --snapshot path [--report path]

        默认路径:
          基线     ~/.persistence-audit/baseline.json
          最新快照 ~/.persistence-audit/latest.json
          报告     ~/.persistence-audit/report.html
        """)
    }
}
