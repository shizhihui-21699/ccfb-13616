import Foundation

// MARK: - 快照读写
enum SnapshotStore {

    static func save(_ snapshot: AuditSnapshot, to path: String) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(snapshot)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
    }

    static func load(_ path: String) throws -> AuditSnapshot {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(AuditSnapshot.self, from: data)
    }
}

// MARK: - 两次审计对比
enum DiffEngine {

    static func compare(baseline: AuditSnapshot?, current: AuditSnapshot) -> AuditDiff {
        var diffs: [ItemDiff] = []
        var summary = ["new": 0, "removed": 0, "changed": 0, "unchanged": 0]

        guard let baseline else {
            for item in current.items {
                diffs.append(ItemDiff(status: .new, item: item, changes: ["无历史基线，首次记录"]))
                summary["new"]! += 1
            }
            return AuditDiff(baselineTime: nil, currentTime: current.auditTime,
                             hostname: current.hostname, items: diffs, summary: summary)
        }

        let oldByID = Dictionary(baseline.items.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let newByID = Dictionary(current.items.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

        for (id, newItem) in newByID {
            guard let oldItem = oldByID[id] else {
                diffs.append(ItemDiff(status: .new, item: newItem,
                                      changes: ["新出现的持久化项: \(newItem.label)"]))
                summary["new"]! += 1
                continue
            }
            if oldItem.chainFingerprint == newItem.chainFingerprint
                && oldItem.verdict == newItem.verdict
                && oldItem.programArguments == newItem.programArguments {
                diffs.append(ItemDiff(status: .unchanged, item: newItem, previous: oldItem))
                summary["unchanged"]! += 1
            } else {
                let changes = describeChanges(old: oldItem, new: newItem)
                diffs.append(ItemDiff(status: .changed, item: newItem, previous: oldItem, changes: changes))
                summary["changed"]! += 1
            }
        }
        for (id, oldItem) in oldByID where newByID[id] == nil {
            diffs.append(ItemDiff(status: .removed, item: oldItem,
                                  changes: ["持久化项已消失: \(oldItem.label)"]))
            summary["removed"]! += 1
        }

        diffs.sort { rank($0.status) < rank($1.status) }
        return AuditDiff(baselineTime: baseline.auditTime, currentTime: current.auditTime,
                         hostname: current.hostname, items: diffs, summary: summary)
    }

    private static func describeChanges(old: AuditItem, new: AuditItem) -> [String] {
        var changes: [String] = []
        if old.programArguments != new.programArguments {
            changes.append("启动命令改变: \(old.programArguments.joined(separator: " ")) → \(new.programArguments.joined(separator: " "))")
        }
        if old.verdict != new.verdict {
            changes.append("信任判定变化: \(old.verdict.rawValue) → \(new.verdict.rawValue)")
        }
        if old.score != new.score {
            changes.append("风险评分变化: \(old.score) → \(new.score)")
        }
        if old.chainFingerprint != new.chainFingerprint {
            let oldHops = TrustEngine.flatten(old.chain)
            let newHops = TrustEngine.flatten(new.chain)
            if oldHops.count != newHops.count {
                changes.append("执行链长度变化: \(oldHops.count) 跳 → \(newHops.count) 跳")
            }
            // 找出哈希变化的具体文件
            let oldHashes = Dictionary(oldHops.compactMap { h in h.file?.sha256.map { (h.path, $0) } },
                                       uniquingKeysWith: { a, _ in a })
            let newHashes = Dictionary(newHops.compactMap { h in h.file?.sha256.map { (h.path, $0) } },
                                       uniquingKeysWith: { a, _ in a })
            for (path, newHash) in newHashes where oldHashes[path] != nil && oldHashes[path] != newHash {
                changes.append("文件内容被替换: \(path)")
            }
            let oldPaths = Set(oldHops.map(\.path))
            let newPaths = Set(newHops.map(\.path))
            for p in newPaths.subtracting(oldPaths) where !p.hasPrefix("<inline:") {
                changes.append("执行链新增环节: \(p)")
            }
            for p in oldPaths.subtracting(newPaths) where !p.hasPrefix("<inline:") {
                changes.append("执行链移除环节: \(p)")
            }
        }
        if changes.isEmpty { changes.append("执行链指纹发生变化") }
        return changes
    }

    private static func rank(_ s: DiffStatus) -> Int {
        switch s {
        case .new: return 0
        case .changed: return 1
        case .removed: return 2
        case .unchanged: return 3
        }
    }
}
