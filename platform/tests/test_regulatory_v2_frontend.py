from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess


WEB_ROOT = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "mineguard"
    / "regulatory_web"
)


def _run_regulatory_frontend_probe(body: str) -> None:
    script_path = WEB_ROOT / "app.js"
    harness = """
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(__SCRIPT_PATH__, "utf8")
  + `
globalThis.__testSurface = {
  renderOverview,
  renderActivity,
  selectLeaderActivities,
  findingCard,
  humanizeBusinessText,
  solverDisplay,
  refreshAll,
  switchView,
  renderTrace,
  traceEndpoint,
  traceWindowForPreset,
  setTraceRangePreset,
  applyTraceFilters,
  loadTrace,
  checkTraceUpdates,
  state,
};`;
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      innerHTML: "",
      textContent: "",
      value: "",
      disabled: false,
      clientWidth: 1200,
      dataset: {},
      classList: {add() {}, remove() {}, toggle() {}},
      title: "",
      setAttribute() {},
      querySelectorAll() { return []; },
    });
  }
  return elements.get(id);
}
const sandbox = {
  document: {
    getElementById: element,
    addEventListener() {},
    querySelector(selector) { return selector === "#app" ? element("app") : null; },
    querySelectorAll() { return []; },
  },
  window: {setInterval() { return 0; }},
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
""".replace("__SCRIPT_PATH__", json.dumps(str(script_path)))
    subprocess.run(
        ["node", "-e", harness + body],
        check=True,
        capture_output=True,
        text=True,
    )


def test_regulatory_frontend_is_a_read_only_business_surface() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "政府只读监管端" in index
    assert "单矿五量研判" in index
    assert "五量时序（火工品分项）" in index
    assert "风险台账" in index
    assert "交换留痕" in index
    assert "/v2/regulatory/overview" in script
    assert "/v2/regulatory/mines" in script
    assert "/v2/regulatory/findings" in script
    assert "/v2/regulatory/exchanges" in script
    for label in ("风量", "电量", "火工品量", "入井人员量", "产量"):
        assert label in script
    assert "火工品量·雷管" in script
    assert "火工品量·炸药" in script
    assert 'showNotice(overview.notice || "")' not in script
    # The production CSP deliberately disallows inline styles. All dynamic
    # colours and progress fills must use CSS classes or SVG attributes.
    assert "style=" not in script

    # Login/logout are session management, not a regulator business mutation.
    assert 'api("/v2/auth/login", {method:"POST"' in script
    assert 'api("/v2/auth/logout", {method:"POST"' in script
    for forbidden in (
        "/v1/ingest/",
        "/v1/analyze/",
        "/v1/cases/",
        "submit_conclusion",
        "approve_case",
        "deleteFinding",
    ):
        assert forbidden not in script


def test_regulatory_frontend_uses_the_official_mineguard_brand_name() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")

    assert "<title>MineGuard · 矿安智察 · 煤矿智能辅助监管系统</title>" in index
    assert "<h1>MineGuard · 矿安智察</h1>" in index
    assert "煤矿智能辅助监管系统 · 政府只读监管端" in index
    assert "登录煤矿智能辅助监管系统" in index
    assert "五量智能监管驾驶舱" not in index
    assert "进入监管驾驶舱" not in index


def test_leader_overview_has_plain_language_sections_and_dom_contract() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    overview = index.split('<section id="overviewView"', maxsplit=1)[1].split(
        '<section id="mineView"', maxsplit=1
    )[0]

    for element_id in (
        "attentionTotal",
        "attentionStatus",
        "riskGuidance",
        "openFindingsButton",
    ):
        assert f'id="{element_id}"' in overview
    for label in ("辖区待关注事项", "当前先看什么", "辖区最新动态"):
        assert label in overview

    assert "风险等级分布" not in overview
    assert "最高风险" not in overview
    for pseudo_grade in ("重大", "高", "中", "低"):
        assert f">{pseudo_grade}<" not in overview
    assert "全部事项类型" in index
    assert "全部等级" not in index
    assert '<option value="risk">风险线索</option>' in index
    assert '<option value="data_insufficient">数据待补</option>' in index


def test_mine_detail_discloses_demo_workbook_origin_without_raw_payload() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    assert 'id="mineSourceNotice"' in index
    for required in (
        "source_disclosure",
        "bundled_workbook_values",
        "ET样表原值",
        "空白未补数、日期未平移",
        "单位与身份待核验",
    ):
        assert required in script
    assert ".mine-source-notice" in styles


def test_leader_attention_progress_is_svg_exact_and_zero_safe() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {renderOverview, state} = sandbox.__testSurface;
state.trace = [];
renderOverview({
  counts: {
    configured_mines: 12,
    reporting_mines: 10,
    normal_candidate: 7,
    risk: 2,
    insufficient_data: 1,
    awaiting_response: 3,
    overdue: 1,
  },
  attention_counts: {
    risk_findings: 8,
    data_to_complete: 1,
    awaiting_enterprise_response: 3,
    enterprise_responded_unresolved: 2,
    cleared_by_reanalysis: 4,
  },
  // Legacy severity input must not recreate a fabricated major/high/medium/low chart.
  severity_counts: {critical: 99, high: 98, medium: 97, low: 96},
  as_of: "2026-08-01T08:00:00Z",
  latest_events: [],
});
let bars = element("severityBars").innerHTML;
if (element("metricHighest").textContent !== "待核事项 9 项") process.exit(2);
if (element("attentionTotal").textContent !== "当前 9 项未解除") process.exit(3);
if (!bars.includes('aria-label="风险线索 8 项，占 88.9%"')) process.exit(4);
if (!bars.includes('aria-label="数据待补 1 项，占 11.1%"')) process.exit(5);
if (!bars.includes('width="88.89"') || !bars.includes('width="11.11"')) process.exit(6);
if (bars.includes("style=") || bars.includes("NaN") || bars.includes("Infinity")) process.exit(7);
for (const grade of [">重大<", ">高<", ">中<", ">低<"]) {
  if (bars.includes(grade)) process.exit(8);
}
if (!element("attentionStatus").innerHTML.includes("企业已回复<br>风险未解除")) process.exit(9);
if (!element("riskGuidance").textContent.includes("8 项风险线索、1 项数据待补")) process.exit(10);

renderOverview({
  counts: {
    configured_mines: 0,
    reporting_mines: 0,
    normal_candidate: 0,
    risk: 0,
    insufficient_data: 0,
    awaiting_response: 0,
    overdue: 0,
  },
  attention_counts: {
    risk_findings: 0,
    data_to_complete: 0,
    awaiting_enterprise_response: 0,
    enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 0,
  },
  latest_events: [],
});
bars = element("severityBars").innerHTML;
if (element("metricCoverage").textContent !== "覆盖率 0.0%") process.exit(11);
if (element("attentionTotal").textContent !== "当前无未解除事项") process.exit(12);
if ((bars.match(/width="0.00"/g) || []).length !== 2) process.exit(13);
if (!bars.includes("风险线索 0 项，占 0.0%") || !bars.includes("数据待补 0 项，占 0.0%")) process.exit(14);
if (bars.includes("style=") || bars.includes("NaN") || bars.includes("Infinity")) process.exit(15);
"""
    )


def test_leader_activity_is_grouped_translated_escaped_and_filters_technical_events() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {renderActivity, selectLeaderActivities, state} = sandbox.__testSurface;
state.mines = [{
  mine_id: "M-QY-01",
  mine_name: "沁源一号煤矿<script>alert(1)</script>",
}];
const workflowEvents = [
  {
    event_type: "analysis_report_automatically_issued",
    status: "risk",
    correlation_id: "corr-one-workflow",
    mine_id: "M-QY-01",
    summary: "analysis_report_automatically_issued risk",
    occurred_at: "2026-08-01T08:03:00Z",
  },
  {
    event_type: "analysis_report_delivery_acknowledged",
    status: "risk",
    correlation_id: "corr-one-workflow",
    mine_id: "M-QY-01",
    occurred_at: "2026-08-01T08:02:00Z",
  },
  {
    event_type: "enterprise_response_batch_recorded",
    status: "explanation_recorded",
    correlation_id: "corr-one-workflow",
    mine_id: "M-QY-01",
    occurred_at: "2026-08-01T08:01:00Z",
  },
  {
    event_type: "hash_chain_checkpoint_written",
    correlation_id: "technical-only",
    mine_id: "M-QY-01",
    summary: "database_transaction_committed",
    occurred_at: "2026-08-01T08:00:00Z",
  },
];
const selected = selectLeaderActivities(workflowEvents);
if (selected.length !== 1 || selected[0].correlation_id !== "corr-one-workflow") process.exit(2);
renderActivity(workflowEvents);
let html = element("activityList").innerHTML;
if ((html.match(/<li\b/g) || []).length !== 1) process.exit(3);
if (!html.includes("沁源一号煤矿&lt;script&gt;alert(1)&lt;/script&gt;")) process.exit(4);
if (html.includes("<script>") || html.includes("alert(1)</script>")) process.exit(5);
if (!html.includes("本期五量核验发现风险线索")) process.exit(6);
const visibleText = html.replace(/<[^>]*>/g, " ");
for (const rawCode of [
  "analysis_report_automatically_issued",
  "analysis_report_delivery_acknowledged",
  "enterprise_response_batch_recorded",
  "explanation_recorded",
  "hash_chain_checkpoint_written",
  "database_transaction_committed",
]) {
  if (visibleText.includes(rawCode)) process.exit(7);
}

const technicalEvents = [{
  event_type: "outbox_delivery_attempt_recorded",
  correlation_id: "technical-two",
  mine_id: "M-QY-01",
  summary: "signature_verification_completed",
  occurred_at: "2026-08-01T09:00:00Z",
}];
if (selectLeaderActivities(technicalEvents).length !== 0) process.exit(8);
renderActivity(technicalEvents);
html = element("activityList").innerHTML;
if (!html.includes("暂无新的监管动态")) process.exit(9);
if (html.includes("outbox_delivery_attempt_recorded") || html.includes("signature_verification_completed")) process.exit(10);
"""
    )


def test_overview_prefers_backend_business_projection_over_raw_trace() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {renderOverview, state} = sandbox.__testSurface;
state.trace = [{
  event_type: "analysis_report_automatically_issued",
  status: "normal_candidate",
  correlation_id: "revision-002",
  mine_id: "M-QY-01",
  summary: "状态：normal_candidate",
  occurred_at: "2026-08-01T08:01:00Z",
}];
renderOverview({
  counts: {configured_mines: 1, reporting_mines: 1, normal_candidate: 1,
    risk: 0, insufficient_data: 0, awaiting_response: 0, overdue: 0},
  attention_counts: {risk_findings: 0, data_to_complete: 0,
    awaiting_enterprise_response: 0, enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 2},
  latest_events: [{
    event_type: "finding_resolved_by_revision_reanalysis",
    event_label: "风险已解除",
    status: "cleared_by_reanalysis",
    correlation_id: "revision-002",
    mine_id: "M-QY-01",
    mine_name: "沁源一号煤矿",
    summary: "修订数据经同一算法重新分析通过，2 项相关风险已解除。",
    occurred_at: "2026-08-01T08:01:00Z",
  }],
});
const html = element("activityList").innerHTML;
if (!html.includes("风险已解除") || !html.includes("2 项相关风险已解除")) process.exit(2);
if (html.includes("normal_candidate") || html.includes("研判完成")) process.exit(3);
"""
    )


def test_finding_cards_use_business_types_not_fabricated_grades() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {findingCard} = sandbox.__testSurface;
const risk = findingCard({
  finding_type: "risk",
  severity: "high",
  category: "relationship_consistency",
  title: "五量关系待核",
  summary: "关系偏离",
  state: "open",
});
const incomplete = findingCard({
  finding_type: "data_insufficient",
  severity: "medium",
  category: "data_completeness",
  title: "数据待补",
  state: "explanation_recorded",
});
if (!risk.includes("风险线索") || !risk.includes("五量关系")) process.exit(2);
if (!incomplete.includes("数据待补") || !incomplete.includes("数据完整性")) process.exit(3);
const visible = `${risk} ${incomplete}`.replace(/<[^>]*>/g, " ");
if (visible.includes("relationship_consistency") || visible.includes("data_completeness")) process.exit(4);
for (const grade of [">重大<", ">高<", ">中<", ">低<"]) {
  if (`${risk}${incomplete}`.includes(grade)) process.exit(5);
}
"""
    )


def test_finding_summary_and_evidence_translate_business_codes_without_damaging_content() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {findingCard} = sandbox.__testSurface;
const card = findingCard({
  finding_type: "risk",
  category: "temporal_pattern",
  title: "五量时序变化风险",
  state: "open",
  summary: "2026-07-01 electricity_per_production偏离anonymous_peer稳健基线；已有中文说明，偏离42.75%。CUSUM、EWMA、Page-Hinkley、median/MAD均未触发。记录编号 FINDING_QY_20260705_001，摘要哈希 a3f91c9e72b4；unmapped_ratio_signal待核。",
  evidence: [
    "2026-07-05 ventilation_m3_min 为 3000.50 m³/min，现场记录完整。",
    {description: "2026-07-05 electricity_kwh 为 12345.67 kWh，数值经人工复核。"},
    {description: "2026-07-05 detonators_count 为 18 发；mystery_sensor_delta=7，原始凭证已留存。"},
  ],
});
const summaryMatch = card.match(/<header>[\s\S]*?<\/header><p>([\s\S]*?)<\/p><div class="finding-meta">/);
const evidenceMatch = card.match(/<div class="finding-evidence">([\s\S]*?)<\/div>/);
if (!summaryMatch || !evidenceMatch) process.exit(2);
const summary = summaryMatch[1].replace(/<[^>]*>/g, " ");
const evidence = evidenceMatch[1].replace(/<[^>]*>/g, " ");

for (const [rawCode, businessLabel] of [
  ["electricity_per_production", "单位产量电耗"],
  ["anonymous_peer", "匿名同类矿"],
]) {
  if (summary.includes(rawCode) || !summary.includes(businessLabel)) process.exit(3);
}
for (const [rawCode, businessLabel] of [
  ["ventilation_m3_min", "风量"],
  ["electricity_kwh", "电量"],
  ["detonators_count", "火工品量（雷管）"],
]) {
  if (evidence.includes(rawCode) || !evidence.includes(businessLabel)) process.exit(4);
}

// An unknown implementation token may be replaced by a safe generic label or
// omitted, but it must never leak verbatim into leader-facing prose.
if (summary.includes("unmapped_ratio_signal")) process.exit(5);
if (evidence.includes("mystery_sensor_delta")) process.exit(6);

// Humanisation is a token-level presentation transform. Dates, measurements,
// existing Chinese prose and opaque identifiers/hashes must remain intact.
for (const expected of [
  "2026-07-01", "42.75%", "已有中文说明",
  "持续累积偏移", "近期均值越界", "均值变化检测", "历史稳健范围",
  "FINDING_QY_20260705_001", "a3f91c9e72b4",
]) {
  if (!summary.includes(expected)) process.exit(7);
}
for (const expected of [
  "2026-07-05", "3000.50", "m³/min", "现场记录完整",
  "12345.67", "kWh", "数值经人工复核", "18 发", "原始凭证已留存",
]) {
  if (!evidence.includes(expected)) process.exit(8);
}
"""
    )


def test_finding_card_groups_repeated_daily_machine_summary() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {findingCard} = sandbox.__testSurface;
const card = findingCard({
  finding_type: "risk",
  category: "temporal_pattern",
  title: "五量时序变化风险",
  state: "open",
  summary: "2026-07-01 electricity_per_production偏离anonymous_peer稳健基线；2026-07-02 electricity_per_production偏离anonymous_peer稳健基线；2026-07-03 electricity_per_production偏离anonymous_peer稳健基线；2026-07-04 electricity_per_production偏离anonymous_peer稳健基线",
});
const visible = card.replace(/<[^>]*>/g, " ");
if (!visible.includes("多日出现：单位产量电耗偏离匿名同类矿稳健基线")) process.exit(2);
if (!visible.includes("逐日证据见下方")) process.exit(3);
if (visible.includes("electricity_per_production") || visible.includes("anonymous_peer")) process.exit(4);
if (visible.includes("2026-07-01") || visible.includes("2026-07-04")) process.exit(5);

const relationship = findingCard({
  finding_type: "risk",
  category: "relationship_consistency",
  title: "五量关系协调风险",
  state: "open",
  summary: "2026-07-01 electricity_per_production 超出anonymous_peer软参考区间；2026-07-01 的日报、班次或软参考带无法同时成立；2026-07-02 electricity_per_production 超出anonymous_peer软参考区间；2026-07-02 的日报、班次或软参考带无法同时成立",
}).replace(/<[^>]*>/g, " ");
if (!relationship.includes("多日出现：日报、班次或软参考带无法同时成立")) process.exit(6);
if (relationship.includes("：的日报") || relationship.includes("电耗 超出")) process.exit(7);
"""
    )


def test_solver_and_unknown_status_codes_are_presented_without_internal_names() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {humanizeBusinessText, solverDisplay} = sandbox.__testSurface;
const solver = solverDisplay("iteration_or_time_limit · highs-ipm · MCS 2 组");
for (const expected of ["达到迭代或时间上限", "HiGHS", "最小冲突集 2 组"]) {
  if (!solver.includes(expected)) process.exit(2);
}
if (solver.includes("iteration_or_time_limit")) process.exit(3);
const unknown = humanizeBusinessText("temporal_unknown_state 需要复核");
if (unknown.includes("temporal_unknown_state") || !unknown.includes("其他业务项")) process.exit(4);
const opaqueId = humanizeBusinessText("FINDING_QY_20260705_001");
if (opaqueId !== "FINDING_QY_20260705_001") process.exit(5);
const natural = humanizeBusinessText("正向 CUSUM 累积偏移超过持续漂移阈值；EWMA 水平超过控制限；Page-Hinkley 检测到均值变点；滚动 median/MAD 基线发生偏离");
for (const expected of ["正向持续累积偏移值", "近期加权均值", "均值变化检测发现", "滚动历史稳健基线"]) {
  if (!natural.includes(expected)) process.exit(6);
}
for (const awkward of ["累积偏移 累积偏移", "均值越界 水平", "变化检测 检测到", "稳健范围 基线"]) {
  if (natural.includes(awkward)) process.exit(7);
}
"""
    )


def test_periodic_refresh_never_forces_navigation_back_to_mine_view() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {refreshAll, switchView, state} = sandbox.__testSurface;
const fetches = [];
const overview = {
  counts: {configured_mines: 1, reporting_mines: 1, normal_candidate: 1,
    risk: 0, insufficient_data: 0, awaiting_response: 0, overdue: 0},
  attention_counts: {risk_findings: 0, data_to_complete: 0,
    awaiting_enterprise_response: 0, enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 0},
  latest_events: [],
};
const mineDetail = {
  mine: {mine_id: "M-QY-01", mine_name: "沁源一号煤矿", status: "normal_candidate"},
  latest_submission: {},
  latest_analysis: {},
  response_summary: {},
  daily_series: [],
  findings: [],
  responses: [],
  timeline: [],
};
sandbox.fetch = async (path) => {
  fetches.push(String(path));
  let payload;
  if (path === "/v2/regulatory/overview") payload = overview;
  else if (path === "/v2/regulatory/mines") payload = {items: [{
    mine_id: "M-QY-01", mine_name: "沁源一号煤矿", status: "normal_candidate",
    trend: [],
  }]};
  else if (path.startsWith("/v2/regulatory/findings")) payload = {items: []};
  else if (path.startsWith("/v2/regulatory/exchanges")) payload = {items: []};
  else if (path === "/v2/regulatory/mines/M-QY-01") payload = mineDetail;
  else throw new Error(`unexpected request ${path}`);
  return {
    ok: true,
    status: 200,
    headers: {get() { return "application/json"; }},
    async json() { return payload; },
  };
};

(async () => {
  state.principal = {username: "admin"};
  // Simulate a mine opened earlier, followed by the user returning to overview.
  state.selectedMine = mineDetail;
  switchView("overview");
  await refreshAll();
  if (state.activeView !== "overview") process.exit(2);
  if (fetches.includes("/v2/regulatory/mines/M-QY-01")) process.exit(3);

  // While the user remains on the mine page, its data may refresh silently.
  fetches.length = 0;
  switchView("mine");
  await refreshAll();
  if (state.activeView !== "mine") process.exit(4);
  if (fetches.filter((path) => path === "/v2/regulatory/mines/M-QY-01").length !== 1) process.exit(5);
})().catch((error) => { console.error(error); process.exit(6); });
"""
    )


def test_regulatory_frontend_javascript_parses_on_supported_baseline() -> None:
    subprocess.run(
        ["node", "--check", str(WEB_ROOT / "app.js")],
        check=True,
        capture_output=True,
        text=True,
    )


def test_regulatory_frontend_dom_contract_and_missing_trend_are_safe() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script_path = WEB_ROOT / "app.js"
    script = script_path.read_text(encoding="utf-8")
    html_ids = set(re.findall(r'\bid="([^"]+)"', index))
    referenced_ids = set(re.findall(r'\$\("([^"]+)"\)', script))
    assert referenced_ids <= html_ids

    probe = f"""
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync({json.dumps(str(script_path))}, "utf8")
  + "\\nglobalThis.__sparkline = sparkline;";
const sandbox = {{
  document: {{
    getElementById() {{ return {{}}; }},
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
  }},
  window: {{ setInterval() {{ return 0; }} }},
}};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const rendered = sandbox.__sparkline([100, null, 110, {{value: null}}, 120], "#fff");
if (!rendered.includes("<svg") || rendered.includes("NaN")) process.exit(2);
"""
    subprocess.run(
        ["node", "-e", probe],
        check=True,
        capture_output=True,
        text=True,
    )


def test_regulatory_frontend_has_responsive_and_reduced_motion_styles() -> None:
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    assert "@media (max-width: 760px)" in styles
    assert "prefers-reduced-motion" in styles
    assert ".status-pill" in styles
    assert ".series-chart" in styles


def test_trace_panel_has_content_inset_and_contains_narrow_screen_overflow() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    trace = index.split('<section id="traceView"', maxsplit=1)[1].split(
        "</section>", maxsplit=1
    )[0]

    assert '<article class="panel trace-panel">' in trace
    assert ".trace-panel { min-width: 0; overflow: hidden; padding: 18px 0 0; }" in styles
    assert ".trace-panel > .panel-header, .trace-panel > .trace-explainer" in styles
    assert "padding-inline: 18px" in styles
    assert ".trace-table { min-width: 1120px; table-layout: auto; }" in styles
    assert "flex:0 0 auto;white-space:nowrap" in styles
    assert ".trace-table thead { display: none; }" in styles
    assert 'content: attr(data-label)' in styles


def test_trace_workbench_exposes_server_filters_paging_integrity_and_export() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    trace = index.split('<section id="traceView"', maxsplit=1)[1].split(
        "</section>", maxsplit=1
    )[0]

    for element_id in (
        "traceIntegrity",
        "traceExportButton",
        "traceRangePresets",
        "traceCustomRange",
        "traceFrom",
        "traceTo",
        "traceMineFilter",
        "traceEventGroup",
        "traceViewMode",
        "traceApplyButton",
        "traceClearButton",
        "traceNewRecords",
        "traceResultCount",
        "traceDataAsOf",
        "traceTableBody",
        "traceLoadMoreButton",
    ):
        assert f'id="{element_id}"' in trace
    for label in ("近24小时", "近7天", "近30天", "本月", "自定义"):
        assert label in trace
    for value in (
        "submission",
        "analysis",
        "finding",
        "delivery",
        "response",
        "reanalysis",
        "security",
    ):
        assert f'<option value="{value}">' in trace
    assert '<option value="business">业务关键节点</option>' in trace
    assert '<option value="technical">完整技术留痕</option>' in trace
    assert "导出当前筛选" in trace
    assert "完整留痕链待校验" in trace
    assert "<th>留痕序号</th>" in trace
    assert "<th>链校验</th>" not in trace


def test_trace_query_builder_reuses_exact_filters_and_omits_paging_on_export() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {traceEndpoint, traceWindowForPreset} = sandbox.__testSurface;
const filters = {
  from: "2026-07-25T09:30:00.000Z",
  to: "2026-08-01T09:30:00.000Z",
  mineId: "M-QY-01",
  eventGroup: "response",
  view: "technical",
};
const pageUrl = traceEndpoint("/v2/regulatory/exchanges", filters, {limit:20, cursor:"snapshot:20"});
const exportUrl = traceEndpoint("/v2/regulatory/exchanges/export.csv", filters);
for (const expected of [
  "from=2026-07-25T09%3A30%3A00.000Z",
  "to=2026-08-01T09%3A30%3A00.000Z",
  "mine_id=M-QY-01",
  "event_group=response",
  "view=technical",
]) {
  if (!pageUrl.includes(expected) || !exportUrl.includes(expected)) process.exit(2);
}
if (!pageUrl.includes("limit=20") || !pageUrl.includes("cursor=snapshot%3A20")) process.exit(3);
if (exportUrl.includes("limit=") || exportUrl.includes("cursor=")) process.exit(4);
const day = traceWindowForPreset("24h", new Date("2026-08-01T09:30:00.000Z"));
if (day.from !== "2026-07-31T09:30:00.000Z" || day.to !== "2026-08-01T09:30:00.000Z") process.exit(5);
"""
    )


def test_trace_server_paging_and_polling_preserve_the_table_until_user_accepts() -> None:
    _run_regulatory_frontend_probe(
        r"""
const {loadTrace, checkTraceUpdates, state} = sandbox.__testSurface;
state.principal = {username:"leader"};
state.activeView = "trace";
state.tracePage.initialized = true;
state.tracePage.appliedFilters = {
  rangePreset: "custom",
  from: "2026-07-01T00:00:00.000Z",
  to: "2026-08-02T00:00:00.000Z",
  mineId: "M-QY-01",
  eventGroup: "",
  view: "business",
};
const calls = [];
const event = (sequence, label) => ({
  sequence,
  event_id: `EVENT-${sequence}`,
  mine_id: "M-QY-01",
  mine_name: "沁源一号煤矿",
  event_group: sequence === 1 ? "submission" : "analysis",
  event_label: label,
  summary: `${label}已追加留痕`,
  correlation_id: `CORR-${sequence}`,
  occurred_at: `2026-08-01T0${sequence}:00:00Z`,
});
sandbox.fetch = async (path) => {
  calls.push(String(path));
  let payload;
  if (String(path).includes("cursor=page-2")) {
    payload = {items:[event(1, "企业报送已接收")], matched_count:3,
      has_more:false, next_cursor:null, as_of:"2026-08-02T00:00:00Z",
      integrity:{valid:true, checked_at:"2026-08-02T00:00:01Z"}};
  } else if (String(path).includes("limit=1")) {
    payload = {items:[event(4, "政府研判已完成")], matched_count:4,
      has_more:true, next_cursor:"newer", as_of:"2026-08-02T00:00:10Z",
      integrity:{valid:true, checked_at:"2026-08-02T00:00:11Z"}};
  } else {
    payload = {items:[event(3, "政府研判已完成"), event(2, "政府研判已启动")],
      matched_count:3, has_more:true, next_cursor:"page-2",
      as_of:"2026-08-02T00:00:00Z",
      integrity:{valid:true, checked_at:"2026-08-02T00:00:01Z"}};
  }
  return {ok:true, status:200, headers:{get() { return "application/json"; }},
    async json() { return payload; }};
};
(async () => {
  await loadTrace({reset:true});
  if (state.trace.length !== 2 || state.tracePage.matchedCount !== 3) process.exit(2);
  if (!state.tracePage.hasMore || state.tracePage.nextCursor !== "page-2") process.exit(3);
  if (!element("traceResultCount").textContent.includes("当前显示 2 / 共 3 条")) process.exit(4);
  if (element("traceIntegrity").textContent !== "完整留痕链校验通过") process.exit(5);
  let visible = element("traceTableBody").innerHTML.replace(/<[^>]*>/g, " ");
  if (!visible.includes("政府研判") || visible.includes("校验通过")) process.exit(6);

  await loadTrace();
  if (state.trace.length !== 3 || state.tracePage.hasMore) process.exit(7);
  if (!calls.some((path) => path.includes("cursor=page-2"))) process.exit(8);
  const tableBeforePoll = element("traceTableBody").innerHTML;
  await checkTraceUpdates();
  if (state.trace.length !== 3 || element("traceTableBody").innerHTML !== tableBeforePoll) process.exit(9);
  if (state.tracePage.pendingCount !== 1) process.exit(10);
  if (!element("traceNewRecords").textContent.includes("有 1 条新的交换留痕，点击查看")) process.exit(11);
})().catch((error) => { console.error(error); process.exit(12); });
"""
    )


def test_finding_ledger_panel_has_the_same_top_inset_as_other_main_panels() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    findings = index.split('<section id="findingsView"', maxsplit=1)[1].split(
        "</section>", maxsplit=1
    )[0]

    assert '<article class="panel finding-ledger-panel">' in findings
    assert (
        ".finding-ledger-panel { min-width: 0; overflow: hidden; "
        "padding: 18px 0 0; }"
    ) in styles


def test_five_quantity_legend_has_equal_groups_and_visible_series_lines() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    assert 'class="series-legend" role="list"' in index
    assert 'class="series-legend-item"' in script
    assert 'class="series-legend-swatch"' in script
    assert 'code: "blasting_materials"' in script
    assert "const FIVE_QUANTITY_GROUPS" in script
    assert "fire-material-legend" not in script
    assert "grid-template-columns: repeat(5, minmax(132px, 1fr))" in styles
    assert 'viewBox="0 0 30 10"' in script
    assert 'style="--series-color:' not in script
    assert "width: 30px" in styles
    for color in ("#45d7ff", "#ffbd59", "#ff7864", "#f1a1ff", "#ae80ff", "#36dfa1"):
        assert color in script


def test_five_quantity_legend_matches_all_chart_series_colors() -> None:
    script_path = WEB_ROOT / "app.js"
    probe = f"""
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync({json.dumps(str(script_path))}, "utf8")
  + "\\nglobalThis.__renderSeries = renderSeries;";
const elements = new Map();
function element(id) {{
  if (!elements.has(id)) {{
    elements.set(id, {{
      innerHTML: "",
      textContent: "",
      classList: {{ add() {{}}, remove() {{}} }},
    }});
  }}
  return elements.get(id);
}}
const sandbox = {{
  document: {{
    getElementById: element,
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
  }},
  window: {{ setInterval() {{ return 0; }} }},
}};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
sandbox.__renderSeries([
  {{date:"2026-07-01", ventilation_m3_min:100, electricity_kwh:200,
    detonators_count:3, explosives_kg:4, mine_entry_persons:5, production_t:6}},
  {{date:"2026-07-02", ventilation_m3_min:110, electricity_kwh:220,
    detonators_count:4, explosives_kg:5, mine_entry_persons:6, production_t:7}},
]);
const legend = element("seriesLegend").innerHTML;
const chart = element("seriesChart").innerHTML;
const groups = [...legend.matchAll(/data-quantity-group="([^"]+)"/g)]
  .map((item) => item[1]);
const legendColors = [...legend.matchAll(/<line [^>]*stroke="(#[0-9a-f]{{6}})"/g)]
  .map((item) => item[1]);
const chartColors = [...chart.matchAll(
  /<polyline class="series-line[^\"]*"[^>]*stroke="(#[0-9a-f]{{6}})"/g,
)].map((item) => item[1]);
const expectedGroups = [
  "airflow", "electricity", "blasting_materials",
  "mine_entry_personnel", "production",
];
if (JSON.stringify(groups) !== JSON.stringify(expectedGroups)) process.exit(2);
if ((legend.match(/class="series-legend-swatch"/g) || []).length !== 6) process.exit(3);
if (JSON.stringify(legendColors.sort()) !== JSON.stringify(chartColors.sort())) process.exit(4);
"""
    subprocess.run(
        ["node", "-e", probe],
        check=True,
        capture_output=True,
        text=True,
    )


def test_five_quantity_series_are_six_gap_safe_independent_tracks() -> None:
    script_path = WEB_ROOT / "app.js"
    probe = f"""
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync({json.dumps(str(script_path))}, "utf8")
  + "\\nglobalThis.__renderSeries = renderSeries;";
const elements = new Map();
function element(id) {{
  if (!elements.has(id)) elements.set(id, {{innerHTML: "", clientWidth: 1984}});
  return elements.get(id);
}}
const sandbox = {{
  document: {{
    getElementById: element,
    addEventListener() {{}},
    querySelectorAll() {{ return []; }},
  }},
  window: {{ setInterval() {{ return 0; }} }},
}};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const metricCodes = [
  "ventilation_m3_min", "electricity_kwh", "detonators_count",
  "explosives_kg", "mine_entry_persons", "production_t",
];
function rowsFor(values) {{
  return values.map((factor, index) => ({{
    date: `2026-07-0${{index + 1}}`,
    ventilation_m3_min: factor,
    electricity_kwh: factor === null ? null : factor * 10,
    detonators_count: factor === null ? null : factor * 20,
    explosives_kg: factor === null ? null : factor * 30,
    mine_entry_persons: factor === null ? null : factor * 40,
    production_t: factor === null ? null : factor * 50,
  }}));
}}
function tracks(chart) {{
  return [...chart.matchAll(
    /<g class="series-track" data-series-code="([^\"]+)" data-track-index="(\\d+)">([\\s\\S]*?)<\\/g>/g,
  )];
}}

// Even perfectly proportional inputs must occupy six visibly separate tracks.
sandbox.__renderSeries(rowsFor([1, 2, 3]));
let chart = element("seriesChart").innerHTML;
let foundTracks = tracks(chart);
if (foundTracks.length !== 6 || chart.includes("NaN")) process.exit(2);
if (!chart.includes('viewBox="0 0 1984 458"')) process.exit(11);
if (JSON.stringify(foundTracks.map((item) => item[1])) !== JSON.stringify(metricCodes)) process.exit(3);
const firstPointY = foundTracks.map((item) => {{
  const match = item[3].match(/<circle [^>]*cy="([0-9.]+)"/);
  return match && Number(match[1]);
}});
if (new Set(firstPointY).size !== 6) process.exit(4);

// A constant window belongs on the middle of each track and is labelled clearly.
sandbox.__renderSeries(rowsFor([7, 7, 7]));
chart = element("seriesChart").innerHTML;
foundTracks = tracks(chart);
if (foundTracks.length !== 6 || chart.includes("NaN")) process.exit(5);
for (const item of foundTracks) {{
  const body = item[3];
  const rect = body.match(/<rect [^>]*y="([0-9.]+)"[^>]*height="([0-9.]+)"/);
  const pointYs = [...body.matchAll(/<circle [^>]*cy="([0-9.]+)"/g)].map((match) => Number(match[1]));
  const middle = Number(rect[1]) + Number(rect[2]) / 2;
  if (!body.includes("恒定") || !body.includes('data-constant="true"')) process.exit(6);
  if (pointYs.length !== 3 || pointYs.some((value) => value !== middle)) process.exit(7);
}}

// A single valid sample must also use the safe middle position, never divide by zero.
sandbox.__renderSeries(rowsFor([null, 7, null]));
chart = element("seriesChart").innerHTML;
foundTracks = tracks(chart);
if (foundTracks.length !== 6 || chart.includes("NaN")) process.exit(12);
for (const item of foundTracks) {{
  const body = item[3];
  const rect = body.match(/<rect [^>]*y="([0-9.]+)"[^>]*height="([0-9.]+)"/);
  const point = body.match(/<circle [^>]*cy="([0-9.]+)"/);
  const middle = Number(rect[1]) + Number(rect[2]) / 2;
  if (!body.includes("恒定") || !point || Number(point[1]) !== middle) process.exit(13);
}}

// A null day splits a series into segments; no line may bridge that gap.
const gapRows = rowsFor([1, 2, 3, 4, 5]);
gapRows[2].ventilation_m3_min = null;
sandbox.__renderSeries(gapRows);
chart = element("seriesChart").innerHTML;
const airflow = tracks(chart).find((item) => item[1] === "ventilation_m3_min")[3];
const segments = [...airflow.matchAll(/<polyline class="series-line[^\"]*"[^>]*points="([^\"]+)"/g)];
if (segments.length !== 2) process.exit(8);
if (segments.some((item) => item[1].trim().split(/\\s+/).length !== 2)) process.exit(9);
if (chart.includes("NaN")) process.exit(10);
"""
    subprocess.run(
        ["node", "-e", probe],
        check=True,
        capture_output=True,
        text=True,
    )


def test_five_quantity_chart_explains_tracks_and_busts_static_cache() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")

    assert "按五量分轨展示；火工品量分为雷管、炸药两个子项" in index
    assert "恒定值位于轨道中线" in index
    assert 'aria-label="五量分轨时序图；火工品包含雷管和炸药子项"' in index
    assert "SIX TRACKS" not in index
    assert "六条原子序列" not in index
    assert "/assets/styles.css?v=2.8.0" in index
    assert "/assets/app.js?v=2.8.0" in index
