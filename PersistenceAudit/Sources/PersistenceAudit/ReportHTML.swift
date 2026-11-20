import Foundation

// MARK: - 单文件 HTML 报告
enum ReportHTML {

    static func generate(snapshot: AuditSnapshot, diff: AuditDiff?) -> String {
        let payload = ReportPayload(snapshot: snapshot, diff: diff)
        let json = encodeJSON(payload)
        return templateHTML
            .replacingOccurrences(of: "__PAYLOAD__", with: json)
            .replacingOccurrences(of: "__GENERATED_AT__", with: Self.escape(isoDate(snapshot.auditTime)))
            .replacingOccurrences(of: "__HOST__", with: Self.escape(snapshot.hostname))
    }

    private static func isoDate(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: d)
    }

    static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    private static func encodeJSON(_ payload: ReportPayload) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try! encoder.encode(payload)
        // 防止 </script> 注入破坏页面
        return String(data: data, encoding: .utf8)!
            .replacingOccurrences(of: "<", with: "\\u003c")
            .replacingOccurrences(of: ">", with: "\\u003e")
            .replacingOccurrences(of: " ", with: "\\u2028")
            .replacingOccurrences(of: " ", with: "\\u2029")
    }

    // 与前端共享的数据形状
    struct ReportPayload: Codable {
        let generatedAt: Date
        let hostname: String
        let scanRoot: String
        let notes: [String]
        let stats: SnapshotStats
        let techniques: [String: Technique]
        let items: [AuditItem]
        let diff: AuditDiff?

        init(snapshot: AuditSnapshot, diff: AuditDiff?) {
            self.generatedAt = snapshot.auditTime
            self.hostname = snapshot.hostname
            self.scanRoot = snapshot.scanRoot
            self.notes = snapshot.notes
            self.stats = snapshot.stats
            self.techniques = TechniqueCatalog.all
            self.items = snapshot.items
            self.diff = diff
        }
    }
}

private extension ReportHTML {

    static let templateHTML = #"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>macOS 持久化执行链审计报告</title>
<style>
:root {
  --bg: #f6f7f9; --fg: #1c2128; --muted: #656d76; --card: #ffffff;
  --border: #d8dee4; --accent: #0969da;
  --malicious: #cf222e; --suspicious: #bf8700; --borrowed: #8250df;
  --trusted: #1a7f37; --unknown: #6e7781;
  --code-bg: #f0f1f3;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --card: #161b22;
    --border: #30363d; --accent: #4493f8;
    --malicious: #ff7b72; --suspicious: #d29922; --borrowed: #d2a8ff;
    --trusted: #3fb950; --unknown: #9198a1;
    --code-bg: #1c2128;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.6 -apple-system, BlinkMacSystemFont, "SF Pro Text", "PingFang SC", sans-serif;
}
.wrap { max-width: 1180px; margin: 0 auto; padding: 28px 20px 60px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 17px; margin: 32px 0 12px; }
.sub { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card {
  background: var(--card); border: 1px solid var(--border); border-radius: 10px;
  padding: 14px 16px;
}
.card .num { font-size: 26px; font-weight: 700; }
.card .lbl { color: var(--muted); font-size: 12px; }
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-size: 12px; font-weight: 600; border: 1px solid transparent; white-space: nowrap;
}
.badge.malicious { color: #fff; background: var(--malicious); }
.badge.suspicious { color: #fff; background: var(--suspicious); }
.badge.borrowed { color: #fff; background: var(--borrowed); }
.badge.trusted { color: #fff; background: var(--trusted); }
.badge.unknown { color: var(--fg); background: transparent; border-color: var(--border); }
.badge.diff-new { color: #fff; background: var(--malicious); }
.badge.diff-changed { color: #fff; background: var(--suspicious); }
.badge.diff-removed { color: #fff; background: var(--unknown); }
.badge.diff-unchanged { color: var(--muted); background: transparent; border-color: var(--border); }
.tech {
  display: inline-block; padding: 1px 7px; margin: 2px 3px 2px 0;
  border-radius: 6px; font-size: 11px; font-weight: 600;
  background: var(--code-bg); border: 1px solid var(--border); color: var(--fg);
  cursor: help;
}
.controls { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0; align-items: center; }
.controls input, .controls select {
  background: var(--card); color: var(--fg); border: 1px solid var(--border);
  border-radius: 8px; padding: 7px 10px; font-size: 13px;
}
.controls input[type=search] { flex: 1; min-width: 220px; }
.item {
  background: var(--card); border: 1px solid var(--border); border-radius: 12px;
  margin-bottom: 14px; overflow: hidden;
}
.item-head {
  width: 100%; display: flex; gap: 12px; align-items: center; text-align: left;
  padding: 14px 16px; background: none; border: 0; color: inherit;
  font: inherit; cursor: pointer;
}
.item-head:hover { background: color-mix(in srgb, var(--accent) 6%, transparent); }
.item-title { flex: 1; min-width: 0; }
.item-title .name { font-weight: 650; word-break: break-all; }
.item-title .meta { color: var(--muted); font-size: 12px; margin-top: 2px; word-break: break-all; }
.score { font-variant-numeric: tabular-nums; font-weight: 700; }
.item-body { padding: 0 16px 16px; display: none; }
.item.open .item-body { display: block; }
.chain { margin-top: 8px; border-left: 2px solid var(--border); padding-left: 14px; }
.hop { position: relative; margin: 10px 0; }
.hop::before {
  content: "→"; position: absolute; left: -22px; top: 0; color: var(--muted);
}
.hop.chain-root::before { content: "▶"; }
.hop-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.hop-path { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; word-break: break-all; }
.hop-kind { color: var(--muted); font-size: 11px; border: 1px solid var(--border); padding: 0 6px; border-radius: 5px; }
.hop-detail { margin: 6px 0 0; font-size: 12.5px; color: var(--muted); }
.hop-detail ul { margin: 4px 0; padding-left: 18px; }
.kv { font-family: ui-monospace, Menlo, monospace; font-size: 12px; color: var(--muted); }
.kv b { color: var(--fg); font-weight: 600; }
.sigbox {
  background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 8px 10px; margin-top: 6px; font-size: 12px;
}
.sigbox .row { display: flex; gap: 8px; margin: 2px 0; }
.sigbox .k { color: var(--muted); min-width: 86px; }
.children { margin-left: 16px; border-left: 2px dashed var(--border); padding-left: 14px; }
.reasons { font-size: 12.5px; }
.reasons li { margin: 2px 0; }
.diffbox {
  border-left: 3px solid var(--suspicious); background: var(--code-bg);
  border-radius: 0 8px 8px 0; padding: 8px 12px; margin: 8px 0; font-size: 12.5px;
}
.legend { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0; }
.notes { font-size: 12.5px; color: var(--muted); }
.notes li { margin: 3px 0; }
details.techdict summary { cursor: pointer; color: var(--accent); font-size: 13px; }
.techdict table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 12.5px; }
.techdict th, .techdict td { border: 1px solid var(--border); padding: 6px 9px; text-align: left; vertical-align: top; }
.techdict th { background: var(--code-bg); }
.empty { color: var(--muted); padding: 20px; text-align: center; }
@media (max-width: 640px) {
  .wrap { padding: 18px 12px 40px; }
  .item-head { padding: 12px; }
}
</style>
</head>
<body>
<div class="wrap">
  <h1>macOS 持久化执行链审计报告</h1>
  <div class="sub">主机 <b id="host"></b> · 生成时间 <span id="generated"></span> · 扫描根 <span id="root"></span></div>

  <div class="cards" id="summary"></div>

  <div id="diffsection"></div>

  <h2>自动启动项明细</h2>
  <div class="controls">
    <input type="search" id="q" placeholder="搜索名称、路径、手法…">
    <select id="verdictFilter">
      <option value="">全部判定</option>
      <option value="malicious">恶意</option>
      <option value="suspicious">可疑</option>
      <option value="borrowed">签名借用</option>
      <option value="trusted">可信</option>
      <option value="unknown">未知</option>
    </select>
    <select id="kindFilter">
      <option value="">全部来源</option>
      <option value="launchAgent">LaunchAgent</option>
      <option value="launchDaemon">LaunchDaemon</option>
      <option value="cron">cron</option>
      <option value="shellInit">Shell 初始化</option>
      <option value="btmLoginItem">BTM 登录项</option>
    </select>
  </div>
  <div id="items"></div>

  <h2>手法说明</h2>
  <details class="techdict">
    <summary>展开技术手法编号字典</summary>
    <table><thead><tr><th>编号</th><th>手法</th><th>说明</th></tr></thead>
    <tbody id="techdict"></tbody></table>
  </details>

  <h2>审计备注</h2>
  <ul class="notes" id="notes"></ul>
</div>

<script>
const PAYLOAD = __PAYLOAD__;
const VERDICT_TEXT = {trusted:"可信", borrowed:"签名借用", suspicious:"可疑", malicious:"恶意", unknown:"未知"};
const KIND_TEXT = {launchAgent:"LaunchAgent", launchDaemon:"LaunchDaemon", cron:"cron 计划任务",
  shellInit:"Shell 初始化", btmLoginItem:"BTM 登录项"};
const DIFF_TEXT = {new:"新增", changed:"已变更", removed:"已消失", unchanged:"未变化"};

const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const verdictLabel = v => `<span class="badge ${v}">${VERDICT_TEXT[v] || v}</span>`;

function renderHeader() {
  document.getElementById("host").textContent = PAYLOAD.hostname;
  document.getElementById("generated").textContent = new Date(PAYLOAD.generatedAt).toLocaleString("zh-CN");
  document.getElementById("root").textContent = PAYLOAD.scanRoot;
  const s = PAYLOAD.stats;
  const cards = [
    ["审计项总数", s.totalItems, ""], ["执行链总跳数", s.totalHops, ""],
    ["最大追踪深度", s.maxDepth, ""],
    ["恶意", s.malicious, "malicious"], ["可疑", s.suspicious, "suspicious"],
    ["签名借用", s.borrowed, "borrowed"], ["可信", s.trusted, "trusted"],
    ["未知", s.unknown, "unknown"]
  ];
  document.getElementById("summary").innerHTML = cards.map(([l,n,c]) =>
    `<div class="card"><div class="num"${c?` style="color:var(--${c})"`:""}>${n}</div><div class="lbl">${l}</div></div>`
  ).join("");
  document.getElementById("notes").innerHTML =
    (PAYLOAD.notes.length ? PAYLOAD.notes : ["（无）"]).map(n => `<li>${esc(n)}</li>`).join("");
  document.getElementById("techdict").innerHTML =
    Object.values(PAYLOAD.techniques).map(t =>
      `<tr><td><b>${t.id}</b></td><td>${esc(t.name)}</td><td>${esc(t.detail)}</td></tr>`).join("");
}

function renderDiff() {
  const d = PAYLOAD.diff;
  const el = document.getElementById("diffsection");
  if (!d) { el.innerHTML = ""; return; }
  const base = d.baselineTime ? new Date(d.baselineTime).toLocaleString("zh-CN") : "无基线（首次审计）";
  el.innerHTML = `<h2>与上次审计对比</h2>
    <div class="sub">基线时间: ${esc(base)} · 本次: ${new Date(d.currentTime).toLocaleString("zh-CN")}</div>
    <div class="legend">
      <span class="badge diff-new">新增 ${d.summary.new ?? 0}</span>
      <span class="badge diff-changed">变更 ${d.summary.changed ?? 0}</span>
      <span class="badge diff-removed">消失 ${d.summary.removed ?? 0}</span>
      <span class="badge diff-unchanged">未变化 ${d.summary.unchanged ?? 0}</span>
    </div>`;
}

function sigBlock(hop) {
  const sg = hop.signing; if (!sg) return "";
  const row = (k, v) => v ? `<div class="row"><span class="k">${k}</span><span>${esc(v)}</span></div>` : "";
  return `<div class="sigbox">
    ${row("签名状态", sg.signed ? (sg.valid ? "有效" : "无效/被篡改") : "未签名")}
    ${row("签名形式", sg.isAdHoc ? "ad-hoc（无身份背书）" : null)}
    ${row("Apple 锚点", sg.isAppleAnchored ? "是（Apple 第一方）" : null)}
    ${row("平台二进制", sg.isPlatformBinary ? "是" : null)}
    ${row("公证", sg.notarized ? "已公证" : (sg.signed ? "未公证" : null))}
    ${row("Identifier", sg.identifier)}
    ${row("Team ID", sg.teamID)}
    ${row("签名 flags", sg.flags.length ? sg.flags.join(", ") : null)}
    ${row("证书链", sg.authorityChain.length ? sg.authorityChain.map(esc).join(" ← ") : null)}
    ${row("校验错误", sg.assessmentError)}
  </div>`;
}

function fileBlock(hop) {
  const f = hop.file; if (!f || !f.exists) return "";
  const bits = [];
  if (f.posixPermissions) bits.push(`<b>权限</b> ${esc(f.posixPermissions)}`);
  if (f.owner) bits.push(`<b>属主</b> ${esc(f.owner)}:${esc(f.group ?? "")}`);
  if (f.sha256) bits.push(`<b>SHA256</b> <span style="word-break:break-all">${esc(f.sha256)}</span>`);
  if (f.worldWritable || f.groupWritable || f.ownerWritableByNonRoot)
    bits.push(`<b style="color:var(--malicious)">非 root 可写</b>`);
  return bits.length ? `<div class="kv" style="margin-top:4px">${bits.join(" · ")}</div>` : "";
}

function renderHop(hop, isRoot) {
  const techs = (hop.trust.techniques || []).map(t => {
    const def = PAYLOAD.techniques[t];
    return `<span class="tech" title="${esc(def ? def.detail : "")}">${t}</span>`;
  }).join("");
  const reasons = (hop.trust.reasons || []).length
    ? `<div class="hop-detail"><ul class="reasons">${hop.trust.reasons.map(r => `<li>${esc(r)}</li>`).join("")}</ul></div>` : "";
  const env = Object.keys(hop.env || {}).length
    ? `<div class="kv" style="margin-top:4px"><b>env:</b> ${esc(Object.entries(hop.env).map(([k,v]) => k+"="+v).join(" "))}</div>` : "";
  const argv = (hop.argv || []).length
    ? `<div class="kv" style="margin-top:4px"><b>argv:</b> ${esc(hop.argv.join(" "))}</div>` : "";
  const note = hop.note ? `<div class="hop-detail">${esc(hop.note)}</div>` : "";
  const children = (hop.children || []).map(c => `<div class="children">${renderHop(c, false)}</div>`).join("");
  return `<div class="hop ${isRoot ? "chain-root" : ""}">
    <div class="hop-head">
      ${verdictLabel(hop.trust.verdict)}
      <span class="hop-kind">${hop.kind}</span>
      <span class="hop-path">${esc(hop.displayName || hop.path)}</span>
      ${techs}
    </div>
    ${hop.kind !== hop.displayName && hop.path !== hop.displayName ? `<div class="kv" style="margin-top:2px">${esc(hop.path)}</div>` : ""}
    ${argv}${env}${fileBlock(hop)}${sigBlock(hop)}${reasons}${note}
    ${children}
  </div>`;
}

const diffMap = {};
function renderItems() {
  const q = document.getElementById("q").value.toLowerCase();
  const vf = document.getElementById("verdictFilter").value;
  const kf = document.getElementById("kindFilter").value;
  const shown = PAYLOAD.items.filter(it => {
    if (vf && it.verdict !== vf) return false;
    if (kf && it.kind !== kf) return false;
    if (!q) return true;
    const hay = JSON.stringify(it).toLowerCase();
    return hay.includes(q);
  });
  const el = document.getElementById("items");
  if (!shown.length) { el.innerHTML = `<div class="empty">没有匹配的审计项</div>`; return; }
  el.innerHTML = shown.map((it, i) => {
    const df = diffMap[it.id];
    const diffBadge = df && df.status !== "unchanged"
      ? `<span class="badge diff-${df.status}">${DIFF_TEXT[df.status]}</span>` : "";
    const techs = it.techniques.map(t => `<span class="tech">${t}</span>`).join("");
    const diffBox = df && df.changes && df.status !== "unchanged"
      ? `<div class="diffbox"><b>变更点：</b><ul style="margin:4px 0;padding-left:18px">
          ${df.changes.map(c => `<li>${esc(c)}</li>`).join("")}</ul></div>` : "";
    return `<div class="item" data-i="${i}">
      <button class="item-head" onclick="this.parentElement.classList.toggle('open')">
        <span class="item-title">
          <div class="name">${esc(it.label)} ${diffBadge}</div>
          <div class="meta">${KIND_TEXT[it.kind] || it.kind} · ${esc(it.plistPath || it.source)} · ${techs}</div>
        </span>
        <span class="score" style="color:${it.score>=70?"var(--malicious)":it.score>=30?"var(--suspicious)":"var(--muted)"}">${it.score}</span>
        ${verdictLabel(it.verdict)}
      </button>
      <div class="item-body">
        ${diffBox}
        <div class="kv"><b>ProgramArguments:</b> ${esc(it.programArguments.join(" "))}</div>
        ${Object.keys(it.environmentVariables||{}).length ? `<div class="kv"><b>EnvironmentVariables:</b> ${esc(Object.entries(it.environmentVariables).map(([k,v])=>k+"="+v).join(" "))}</div>` : ""}
        ${it.rawLine ? `<div class="kv"><b>原始行:</b> ${esc(it.rawLine)}</div>` : ""}
        ${it.reasons.length ? `<div class="hop-detail"><ul class="reasons">${it.reasons.map(r=>`<li>${esc(r)}</li>`).join("")}</ul></div>` : ""}
        <div class="chain">${it.chain.map(h => renderHop(h, true)).join("")}</div>
      </div>
    </div>`;
  }).join("");
}

function init() {
  renderHeader(); renderDiff();
  if (PAYLOAD.diff) {
    for (const d of PAYLOAD.diff.items) diffMap[d.item.id] = d;
  }
  ["q","verdictFilter","kindFilter"].forEach(id =>
    document.getElementById(id).addEventListener("input", renderItems));
  renderItems();
}
init();
</script>
</body>
</html>
"""#
}
