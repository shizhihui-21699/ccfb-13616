import Foundation
import CryptoKit

// MARK: - 信任汇总与评分
enum TrustEngine {

    // 脚本节点自身的判定（结合子链）
    static func verdictForScript(children: [Hop], techniques: [String]) -> HopVerdict {
        if children.contains(where: { $0.trust.verdict == .malicious }) { return .malicious }
        if children.contains(where: { $0.trust.verdict == .suspicious }) { return .suspicious }
        if children.contains(where: { $0.trust.verdict == .borrowed }) { return .borrowed }
        if techniques.contains("T05") || techniques.contains("T06") { return .suspicious }
        if !children.isEmpty { return .borrowed }
        return .unknown
    }

    // 整个持久化项的判定与评分
    static func finalize(item: inout AuditItem) {
        let hops = flatten(item.chain)
        var allTechniques: Set<String> = []
        var allReasons: [String] = []
        var worst = HopVerdict.trusted

        for hop in hops {
            for t in hop.trust.techniques { allTechniques.insert(t) }
            allReasons.append(contentsOf: hop.trust.reasons)
            worst = worse(worst, hop.trust.verdict)
        }

        // 评分：手法权重 + 签名状态加权
        var score = 0
        let weights: [String: Int] = [
            "T01": 15, "T02": 30, "T03": 20, "T04": 10, "T05": 25,
            "T06": 30, "T07": 35, "T08": 8, "T09": 18, "T10": 10,
            "T11": 20, "T12": 12
        ]
        for t in allTechniques { score += weights[t] ?? 5 }

        if hops.contains(where: { $0.kind == .machO && $0.signing?.signed == false }) { score += 25 }
        if hops.contains(where: { $0.kind == .machO && $0.signing?.isAdHoc == true }) { score += 15 }
        if hops.contains(where: { $0.kind == .machO && $0.signing?.valid == false && $0.signing?.signed == true }) { score += 20 }
        score = min(100, score)

        // 最终判定
        let finalVerdict: HopVerdict
        if worst == .malicious || score >= 70 {
            finalVerdict = .malicious
        } else if worst == .suspicious || score >= 30 {
            finalVerdict = .suspicious
        } else if worst == .borrowed || allTechniques.contains("T01") {
            finalVerdict = .borrowed
        } else if worst == .unknown {
            finalVerdict = .unknown
        } else {
            finalVerdict = .trusted
        }

        item.verdict = finalVerdict
        item.score = score
        item.techniques = allTechniques.sorted()
        item.reasons = Array(NSOrderedSet(array: allReasons)) as? [String] ?? allReasons
        item.chainFingerprint = fingerprint(of: item)
    }

    static func flatten(_ hops: [Hop]) -> [Hop] {
        var out: [Hop] = []
        for h in hops {
            out.append(h)
            out.append(contentsOf: flatten(h.children))
        }
        return out
    }

    static func maxDepth(_ hops: [Hop]) -> Int {
        (flatten(hops).map(\.depth).max() ?? 0) + 1
    }

    // 链指纹：结构 + 路径 + 哈希 + 签名标识，任何一环变化都会改变
    static func fingerprint(of item: AuditItem) -> String {
        var rows: [String] = [item.id, item.programArguments.joined(separator: "\u{1f}")]
        for hop in flatten(item.chain) {
            var row = "\(hop.kind.rawValue)|\(hop.path)|\(hop.trust.verdict.rawValue)|\(hop.argv.joined(separator: " "))"
            if let sha = hop.file?.sha256 { row += "|\(sha)" }
            if let id = hop.signing?.identifier { row += "|sig:\(id)" }
            rows.append(row)
        }
        let data = rows.joined(separator: "\u{1e}").data(using: .utf8)!
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func stats(of snapshot: AuditSnapshot) -> SnapshotStats {
        var s = SnapshotStats()
        s.totalItems = snapshot.items.count
        for item in snapshot.items {
            switch item.verdict {
            case .trusted: s.trusted += 1
            case .borrowed: s.borrowed += 1
            case .suspicious: s.suspicious += 1
            case .malicious: s.malicious += 1
            case .unknown: s.unknown += 1
            }
        }
        s.totalHops = snapshot.items.reduce(0) { $0 + flatten($1.chain).count }
        s.maxDepth = snapshot.items.map { maxDepth($0.chain) }.max() ?? 0
        return s
    }

    private static func worse(_ a: HopVerdict, _ b: HopVerdict) -> HopVerdict {
        let order: [HopVerdict] = [.trusted, .borrowed, .unknown, .suspicious, .malicious]
        return (order.firstIndex(of: a) ?? 0) >= (order.firstIndex(of: b) ?? 0) ? a : b
    }
}
