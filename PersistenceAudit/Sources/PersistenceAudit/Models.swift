import Foundation

// MARK: - 技术手法目录
// 编号含义：审计报告里每项风险都会引用其中一个或多个编号，对应已知的持久化藏匿手法。
struct Technique: Codable {
    let id: String
    let name: String
    let detail: String
}

enum TechniqueCatalog {
    static let all: [String: Technique] = [
        "T01": Technique(id: "T01", name: "启动参数/合法解释器借用 (LOLbin)",
                         detail: "由带合法签名的系统解释器或常见工具(bash/python/osascript/env 等)加载外部脚本或 -c 内联命令，真正的载荷不在签名二进制内。"),
        "T02": Technique(id: "T02", name: "DYLD 环境变量注入",
                         detail: "通过 DYLD_INSERT_LIBRARIES / DYLD_FRAMEWORK_PATH 等环境变量让合法二进制加载非系统动态库。"),
        "T03": Technique(id: "T03", name: "被替换/可写的配置或脚本",
                         detail: "执行链引用的配置文件、脚本或 plist 位于普通用户可写位置，内容可被静默替换。"),
        "T04": Technique(id: "T04", name: "多层包装脚本",
                         detail: "载荷经过多层 wrapper/launcher 间接执行，真正的代码藏在链路深处。"),
        "T05": Technique(id: "T05", name: "混淆/动态求值 (base64/eval/命令替换)",
                         detail: "脚本中出现 base64 解码、eval、命令替换等运行时还原载荷的写法。"),
        "T06": Technique(id: "T06", name: "网络下载即执行",
                         detail: "curl/wget 拉取内容通过管道直接交给 shell 等解释器执行，载荷不落盘或运行时才落地。"),
        "T07": Technique(id: "T07", name: "未签名/ad-hoc/可篡改的可执行文件",
                         detail: "最终载荷是未签名、仅 ad-hoc 签名或签名失效的 Mach-O，或二进制存在过宽写权限可被静默替换。"),
        "T08": Technique(id: "T08", name: "cron/计划任务持久化",
                         detail: "通过 crontab 而不是 launchd 登记自启动，常规排查容易漏掉。"),
        "T09": Technique(id: "T09", name: "PATH 劫持 / 符号链接伪装",
                         detail: "自定义 PATH 指向可写目录，或通过符号链接把执行流导向另一个文件。"),
        "T10": Technique(id: "T10", name: "执行链断裂 / 载荷缺失",
                         detail: "链上引用的文件不存在 —— 可能是清除残留，也可能是等待投放的占位。"),
        "T11": Technique(id: "T11", name: "Shell 初始化文件注入",
                         detail: "在 .zshrc/.bash_profile 等交互式 shell 启动文件中植入命令，每次开终端即执行。"),
        "T12": Technique(id: "T12", name: "内联脚本载荷 (无文件落地)",
                         detail: "命令以 -c/-e 内联形式直接执行，磁盘上没有独立载荷文件。")
    ]
}

// MARK: - 执行链上的一跳
enum HopKind: String, Codable {
    case launchItem     // 自动启动项登记点（plist 里的 ProgramArguments / cron 行 / shell 配置行）
    case machO          // Mach-O 二进制 / app 主可执行文件
    case script         // 脚本文件（shell/python/applescript…）
    case inlineScript   // -c/-e 内联代码（虚拟节点，无对应文件）
    case config         // 配置/plist/数据文件
    case symlink        // 符号链接
    case directory      // 目录（通常是 .app 包）
    case missing        // 引用的文件不存在
    case unknown
}

enum HopVerdict: String, Codable {
    case trusted        // 可信：Apple 平台二进制，或有效公证的第三方签名
    case borrowed       // 签名本身合法，但被借用来执行外部/内联载荷
    case suspicious     // 可疑：可写、混淆、下载执行等
    case malicious      // 恶意：未签名/无效签名的可执行文件，或高置信藏匿手法
    case unknown
}

struct SigningInfo: Codable {
    var signed: Bool = false
    var valid: Bool = false
    var isAdHoc: Bool = false
    var isAppleAnchored: Bool = false
    var isPlatformBinary: Bool = false
    var hardenedRuntime: Bool = false
    var notarized: Bool = false
    var identifier: String?
    var teamID: String?
    var authorityChain: [String] = []
    var flags: [String] = []
    var assessmentError: String?   // SecStaticCodeCheckValidity 的错误描述
}

struct FileMeta: Codable {
    var exists: Bool = false
    var isSymlink: Bool = false
    var symlinkTarget: String?
    var owner: String?
    var group: String?
    var posixPermissions: String?  // 例如 -rwxr-xr-x
    var worldWritable: Bool = false
    var groupWritable: Bool = false
    var ownerWritableByNonRoot: Bool = false
    var sha256: String?
    var size: Int?
}

struct HopTrust: Codable {
    var verdict: HopVerdict
    var reasons: [String] = []        // 判定理由（人话）
    var techniques: [String] = []     // 命中的手法编号
}

struct Hop: Codable {
    var index: Int
    var kind: HopKind
    var path: String                 // 虚拟节点用描述性路径（<inline:…>）
    var displayName: String
    var depth: Int
    var trust: HopTrust
    var signing: SigningInfo?
    var file: FileMeta?
    var argv: [String] = []          // 这一跳实际使用的参数
    var env: [String: String] = [:]  // 这一跳的环境变量（仅展示持久化项里显式声明的）
    var note: String?
    var children: [Hop] = []
}

// MARK: - 一个自动启动项
enum PersistenceKind: String, Codable {
    case launchAgent
    case launchDaemon
    case cron
    case shellInit
    case btmLoginItem
}

struct AuditItem: Codable, Identifiable {
    var id: String                   // 稳定标识：来源+路径，供跨次对比
    var kind: PersistenceKind
    var source: String               // 采集来源描述
    var label: String                // plist Label / cron 描述 / 配置文件名
    var plistPath: String?
    var programArguments: [String] = []
    var environmentVariables: [String: String] = [:]
    var runAtLoad: Bool?
    var rawLine: String?
    var chain: [Hop] = []
    var verdict: HopVerdict = .unknown
    var score: Int = 0
    var techniques: [String] = []
    var reasons: [String] = []
    var chainFingerprint: String?    // 整条链的指纹，变更对比用
}

// MARK: - 一次审计的完整快照
struct SnapshotStats: Codable {
    var totalItems: Int = 0
    var trusted: Int = 0
    var borrowed: Int = 0
    var suspicious: Int = 0
    var malicious: Int = 0
    var unknown: Int = 0
    var totalHops: Int = 0
    var maxDepth: Int = 0
}

struct AuditSnapshot: Codable {
    var schemaVersion: Int = 1
    var hostname: String
    var auditTime: Date
    var scanRoot: String
    var notes: [String] = []
    var items: [AuditItem]
    var stats: SnapshotStats
}

// MARK: - 两次快照对比
enum DiffStatus: String, Codable {
    case new, removed, changed, unchanged
}

struct ItemDiff: Codable {
    var status: DiffStatus
    var item: AuditItem
    var previous: AuditItem?
    var changes: [String] = []       // 变更点描述
}

struct AuditDiff: Codable {
    var baselineTime: Date?
    var currentTime: Date
    var hostname: String
    var items: [ItemDiff]
    var summary: [String: Int]
}
