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


def _asset(name: str) -> str:
    return (WEB_ROOT / name).read_text(encoding="utf-8")


def _wallboard_markup(index: str) -> str:
    start = index.index('<section id="wallboardView"')
    return index[start : index.index("</main>", start)]


def _run_core_probe(body: str) -> None:
    script_path = WEB_ROOT / "app.js"
    probe = r'''
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(__SCRIPT_PATH__, "utf8") + `
globalThis.__wallboardCoreSurface = {
  renderWallboardCore,
  renderWallboardFocus,
  rotateWallboard,
  wallboardEffectiveStatus,
  state,
};`;

function makeClassList(initial = []) {
  const values = new Set(initial);
  return {
    add(...names) { names.forEach((name) => values.add(name)); },
    remove(...names) { names.forEach((name) => values.delete(name)); },
    contains(name) { return values.has(name); },
    toggle(name, force) {
      const enabled = force === undefined ? !values.has(name) : Boolean(force);
      if (enabled) values.add(name); else values.delete(name);
      return enabled;
    },
  };
}

const elements = new Map();
const writes = new Map();
function element(id) {
  if (!elements.has(id)) {
    let html = "";
    const value = {
      textContent: "", title: "", value: "", disabled: false,
      dataset: {}, offsetWidth: 1200, clientWidth: 1200,
      classList: makeClassList(),
      setAttribute() {}, addEventListener() {}, querySelectorAll() { return []; },
    };
    Object.defineProperty(value, "innerHTML", {
      get() { return html; },
      set(next) {
        html = String(next);
        writes.set(id, (writes.get(id) || 0) + 1);
      },
    });
    elements.set(id, value);
  }
  return elements.get(id);
}

const sandbox = {
  URL, URLSearchParams,
  document: {
    body: element("body"),
    documentElement: {requestFullscreen() { return Promise.resolve(); }},
    fullscreenElement: null,
    getElementById: element,
    addEventListener() {},
    querySelector(selector) { return selector === "#app" ? element("app") : null; },
    querySelectorAll() { return []; },
    exitFullscreen() { return Promise.resolve(); },
  },
  window: {
    location: {pathname: "/wallboard", search: "", hash: "", href: "http://mineguard.local/wallboard"},
    history: {pushState() {}},
    setInterval() { return 0; }, clearInterval() {}, setTimeout() { return 0; },
    addEventListener() {},
  },
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const surface = sandbox.__wallboardCoreSurface;
'''.replace("__SCRIPT_PATH__", json.dumps(str(script_path)))
    completed = subprocess.run(
        ["node", "-e", probe + body],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_wallboard_middle_contains_an_intelligent_five_quantity_core() -> None:
    wallboard = _wallboard_markup(_asset("index.html"))

    assert 'id="wallboardCorePanel"' in wallboard
    assert 'id="wallboardCoreBody"' in wallboard
    assert "智能研判核心" in wallboard
    assert "五量联动核验" in wallboard

    # The core is the visual centre between the jurisdiction summary and live
    # updates, rather than another strip appended below the screen fold.
    situation = wallboard.index("wallboard-situation-panel")
    core = wallboard.index('id="wallboardCorePanel"')
    activity = wallboard.index("wallboard-activity-panel")
    assert situation < core < activity


def test_core_names_all_five_quantities_and_keeps_explosives_as_one_quantity() -> None:
    combined = _asset("index.html") + _asset("app.js")

    for quantity in ("风量", "电量", "火工品量", "入井人员量", "产量"):
        assert quantity in combined

    # 火工品是五量之一，雷管与炸药只是同一量下面的两个业务分项。
    assert re.search(r"火工品量[^\n]{0,80}雷管", combined)
    assert re.search(r"火工品量[^\n]{0,120}炸药", combined)
    assert "雷管（发）" in combined
    assert "炸药（kg）" in combined
    for wrong in ("六量", "雷管量", "炸药量"):
        assert wrong not in _wallboard_markup(_asset("index.html"))


def test_core_explains_all_four_independent_algorithm_evidence_layers() -> None:
    combined = _wallboard_markup(_asset("index.html")) + _asset("app.js")

    assert "关系约束" in combined or "物理关系" in combined
    for layer in ("历史基线", "同类参照", "时序漂移"):
        assert layer in combined


def test_core_uses_effective_mine_status_without_inventing_quantity_values() -> None:
    _run_core_probe(
        r'''
const {renderWallboardFocus, wallboardEffectiveStatus, state} = surface;
state.wallboard.active = true;
state.wallboard.rotationIndex = 0;
const current = {
  mine_id: "CORE-RISK-01",
  mine_name: "核心风险矿",
  status: "normal_candidate",
  open_finding_count: 2,
  completeness_rate: 1,
};
if (wallboardEffectiveStatus(current) !== "risk") process.exit(2);
renderWallboardFocus([current]);
const html = element("wallboardCoreBody").innerHTML;

// The status at the centre follows effective status. A normal latest run must
// not turn an unresolved supervision loop green.
if (!html.includes("status-risk")) process.exit(3);
if (!html.includes("存在风险")) process.exit(4);

for (const label of ["风量", "电量", "火工品量", "入井人员量", "产量",
                     "雷管（发）", "炸药（kg）"]) {
  if (!html.includes(label)) process.exit(5);
}
if (!html.includes("关系约束") && !html.includes("物理关系")) process.exit(6);
for (const layer of ["历史基线", "同类参照", "时序漂移"]) {
  if (!html.includes(layer)) process.exit(6);
}

// /v2/regulatory/mines does not supply per-quantity measurements. The visual
// may show their role in the linkage, but must not fabricate plausible values.
const visible = html.replace(/<[^>]*>/g, " ");
if (/\d+(?:\.\d+)?\s*(?:(?:m³\/min|kWh|kg|t)\b|(?:发|人次|吨)(?![\u3400-\u9fff]))/i.test(visible)) process.exit(7);
'''
    )


def test_core_maps_risk_insufficient_and_normal_to_plain_language_center_tones() -> None:
    _run_core_probe(
        r'''
const {renderWallboardFocus, state} = surface;
state.wallboard.active = true;
state.wallboard.rotationIndex = 0;
const cases = [
  [{mine_id:"STATUS-RISK", mine_name:"风险矿", status:"normal_candidate", open_finding_count:1},
   "status-risk", "存在风险"],
  [{mine_id:"STATUS-INSUFFICIENT", mine_name:"数据不足矿", status:"insufficient_data", open_finding_count:0},
   "status-warning", "数据不足"],
  [{mine_id:"STATUS-NORMAL", mine_name:"正常矿", status:"normal_candidate", open_finding_count:0},
   "status-positive", "暂未发现异常"],
];
for (const entry of cases) {
  state.wallboard.rotationIndex = 0;
  renderWallboardFocus([entry[0]]);
  const html = element("wallboardCoreBody").innerHTML;
  if (!html.includes(entry[1]) || !html.includes(entry[2])) process.exit(2);
}
'''
    )


def test_quantity_nodes_only_show_inclusion_not_fake_individual_statuses() -> None:
    _run_core_probe(
        r'''
const {renderWallboardFocus, state} = surface;
state.wallboard.active = true;
state.wallboard.rotationIndex = 0;
renderWallboardFocus([{
  mine_id:"NODE-SCOPE-01", mine_name:"节点口径矿",
  status:"risk", open_finding_count:3,
}]);
const html = element("wallboardCoreBody").innerHTML;
const nodes = (html.match(/<[^>]+>/g) || []).filter((tag) => {
  const matched = tag.match(/\bclass="([^"]*)"/);
  return matched && matched[1].split(/\s+/).includes("wallboard-core-quantity");
});
if (nodes.length !== 5) process.exit(2);
for (const node of nodes) {
  if (/\bstatus-(?:risk|positive|warning|info|neutral)\b/.test(node)) process.exit(3);
}
'''
    )


def test_core_status_tone_and_visuals_use_classes_not_inline_style_writes() -> None:
    script = _asset("app.js")
    styles = _asset("styles.css")

    assert "style=" not in script
    assert re.search(r"\.style(?:\s*=|\.|\[)", script) is None
    assert re.search(r"status-\$\{[^}]*tone[^}]*\}", script, re.IGNORECASE)

    for tone in ("positive", "risk", "warning", "neutral", "info"):
        assert f"status-{tone}" in styles


def test_core_has_css_motion_and_respects_reduced_motion_preference() -> None:
    styles = _asset("styles.css")

    assert re.search(r"@keyframes\s+wallboard-core-[\w-]+", styles)
    assert re.search(r"\.wallboard-core-[^{]+\{[^}]*animation\s*:", styles, re.DOTALL)
    reduced = re.search(
        r"@media\s*\(prefers-reduced-motion:\s*reduce\)\s*\{([\s\S]*)\}\s*$",
        styles,
    )
    assert reduced is not None
    assert "animation:none!important" in re.sub(r"\s+", "", reduced.group(1))


def test_rotate_wallboard_rerenders_core_for_the_new_current_mine() -> None:
    _run_core_probe(
        r'''
const {renderWallboardFocus, rotateWallboard, state} = surface;
state.wallboard.active = true;
state.mines = [
  {mine_id:"ROTATE-RISK", mine_name:"轮播风险矿", status:"risk", open_finding_count:1},
  {mine_id:"ROTATE-NORMAL", mine_name:"轮播正常矿", status:"normal_candidate", open_finding_count:0},
];
state.wallboard.rotationIndex = 0;
renderWallboardFocus();
const firstHtml = element("wallboardCoreBody").innerHTML;
const firstWrites = writes.get("wallboardCoreBody") || 0;
if (!firstHtml.includes("status-risk")) process.exit(2);

rotateWallboard();
const secondHtml = element("wallboardCoreBody").innerHTML;
const secondWrites = writes.get("wallboardCoreBody") || 0;
if (state.wallboard.rotationIndex !== 1) process.exit(3);
if (secondWrites <= firstWrites || secondHtml === firstHtml) process.exit(4);
if (!secondHtml.includes("status-positive")) process.exit(5);
if (!secondHtml.includes("暂未发现异常")) process.exit(6);
'''
    )


def test_core_release_has_layout_rules_and_new_cache_version() -> None:
    index = _asset("index.html")
    styles = _asset("styles.css")

    assert ".wallboard-core-panel" in styles
    assert ".wallboard-core-body" in styles
    assert re.search(r"\.wallboard-core-(?:body|stage)[^{]*\{[^}]*(?:display:\s*grid|position:\s*relative)", styles)

    stylesheet = re.search(r'/assets/styles\.css\?v=([0-9]+(?:\.[0-9]+)+)', index)
    application = re.search(r'/assets/app\.js\?v=([0-9]+(?:\.[0-9]+)+)', index)
    assert stylesheet is not None
    assert application is not None
    assert stylesheet.group(1) == application.group(1)
    assert tuple(map(int, stylesheet.group(1).split("."))) > (2, 7, 0)

    # Keep compatibility with the project's existing Node runtime baseline.
    assert ".at(" not in _asset("app.js")
