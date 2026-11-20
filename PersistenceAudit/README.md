# PersistenceAudit — macOS 持久化执行链审计工具

对 Mac 上每一个自动启动项，把**整条执行链一路追到最终真正执行的代码**，逐跳判定可信度，
识别"合法签名被借用"的藏匿手法，并与上一次审计结果对比，输出单文件网页报告。

## 解决的问题

成熟恶意软件很少直接登记一个可疑程序，而是让带合法签名的系统解释器/常见工具去加载脚本，
通过启动参数、环境变量注入、被替换的配置或多层包装隐藏真实载荷。本工具针对这些手法：

| 编号 | 手法 | 识别方式 |
|---|---|---|
| T01 | 合法解释器/LOLbin 借用 | 可信签名 Mach-O（bash/python/osascript/env/open…）加载非系统位置脚本或内联命令 |
| T02 | DYLD 环境变量注入 | 解析 `DYLD_INSERT_LIBRARIES` 等变量并追注入库；系统行为开关白名单降噪 |
| T03 | 被替换/可写的配置或脚本 | 链上文件的 POSIX 属主/权限分析，非 root 可写即标记 |
| T04 | 多层包装脚本 | 脚本 source/引用其他脚本的嵌套链 |
| T05 | 混淆/动态求值 | eval、base64 -d、命令替换（系统位置脚本自动降噪） |
| T06 | 网络下载即执行 | curl/wget 与解释器管道串联、脚本内 urllib/requests 特征 |
| T07 | 未签名/ad-hoc/可篡改载荷 | SecStaticCode 验签 + 权限分析 |
| T08 | cron 持久化 | /etc/crontab、/etc/periodic、/var/at/tabs 用户 crontab |
| T09 | PATH 劫持/符号链接伪装 | env 内 PATH 覆盖解析、符号链接逐跳追踪 |
| T10 | 执行链断裂/载荷缺失 | 引用文件不存在（清除残留或等待投放） |
| T11 | Shell 初始化文件注入 | .zshrc/.zprofile/.bash_profile 等 |
| T12 | 内联无文件载荷 | -c/-e 参数作为虚拟节点继续解析 |

## 架构

```
PersistenceCollector   采集 LaunchAgents/LaunchDaemons、cron、shell init、BTM（sfltool 带 10s 超时）
└── Tracer             执行链引擎（深度上限 12，inode 集合防环路）
    ├── FileSystem     魔数识别 Mach-O/脚本/plist、lstat/stat（dlsym 规避同名遮蔽）、SHA256
    ├── CodeSigning    SecStaticCode：有效性、Apple 锚点、公证、ad-hoc、hardened runtime、证书链
    └── ScriptParser   启发式 shell/python 静态分析（管道、source、eval、变量展开、内建命令过滤）
TrustEngine            逐跳汇总 → 5 级判定（trusted/borrowed/suspicious/malicious/unknown）+ 0-100 评分
DiffEngine             稳定 ID + 链指纹（结构/路径/SHA256/签名标识）对比，输出新增/变更/消失
ReportHTML             单文件 HTML，暗色模式、筛选搜索、可折叠执行链、差异视图
```

追踪终止条件（"追多深算完"）：抵达 Mach-O 且无可追的 DYLD 库/参数；链上文件缺失；
文件类型无法识别；深度达到 12；或 inode 环路。

## 使用

```bash
swift build -c release

# 审计（首次自动建基线）
.build/release/PersistenceAudit scan

# 确认当前状态无误后登记为基线
.build/release/PersistenceAudit baseline

# 之后再次 scan 即自动与基线对比
.build/release/PersistenceAudit scan

# 针对离线镜像/测试假根
.build/release/PersistenceAudit scan --root /path/to/fakeroot \
  --baseline /tmp/baseline.json --snapshot-out /tmp/run.json --report /tmp/report.html
```

默认产物在 `~/.persistence-audit/`：`baseline.json`、`latest.json`、`report.html`。
建议以 root 运行，否则部分 root 专属守护进程（如 cupsd）签名无法评估，会标记为 unknown 而非漏报。

## 判定原则

- **trusted**：Apple 平台签名（anchor apple / platform binary），或有效 Developer ID + 公证
- **borrowed**：签名本身合法，但被借用来执行外部/内联载荷（LOLbin 的核心特征）
- **suspicious**：可写脚本/配置、混淆、下载执行、链断裂等
- **malicious**：未签名/ad-hoc/签名失效的最终载荷，或评分 ≥70
- **unknown**：权限不足或类型无法识别，报告中保留而非静默忽略

## 测试夹具

`fixtures/make_fixtures.zsh` 在独立假根目录构造 8 类藏匿手法 + 1 个干净对照组，
全部为本地静态文件（无真实网络请求）。复现：

```bash
zsh fixtures/make_fixtures.zsh /tmp/fakeroot
.build/release/PersistenceAudit scan --root /tmp/fakeroot \
  --baseline /tmp/b.json --snapshot-out /tmp/r.json --report /tmp/r.html
```

## 局限

- 静态分析，不执行任何目标程序；运行时才解密/下载的载荷只能识别到混淆指示，看不到明文
- shell 解析是启发式的，极端语法（动态拼接变量名、复杂 eval 嵌套）可能漏报
- BTM 登录项依赖 `sfltool dumpbtm`，该命令在部分系统版本会长时间挂起，10 秒超时后跳过并在备注说明
- 公证检查需要网络或本地票据缓存；离线时以 flag 位为准
