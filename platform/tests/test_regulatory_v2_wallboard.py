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
    marker = '<section id="wallboardView"'
    assert marker in index, "the wallboard must be an independent page section"
    # The wallboard is the final application section. Slicing to </main> also
    # guards against accidentally placing ordinary dashboard controls inside it.
    return index[index.index(marker) : index.index("</main>", index.index(marker))]


def test_wallboard_entry_is_immediately_right_of_fullscreen() -> None:
    index = _asset("index.html")

    fullscreen = index.index('id="fullscreenButton"')
    wallboard = index.index('id="wallboardButton"')
    logout = index.index('id="logoutButton"')

    assert fullscreen < wallboard < logout
    assert re.search(
        r'<button\s+id="wallboardButton"[^>]*type="button"[^>]*>'
        r"\s*大屏展示\s*</button>",
        index,
    )


def test_wallboard_is_an_independent_read_only_single_page() -> None:
    index = _asset("index.html")
    wallboard = _wallboard_markup(index)

    assert 'id="wallboardExitButton"' in wallboard
    assert "返回监管端" in wallboard or "退出大屏" in wallboard

    # A wall display must not expose the ordinary dashboard's filters, edits,
    # exports or navigation. The unobtrusive exit control is the sole exception.
    button_ids = re.findall(r'<button\b[^>]*\bid="([^"]+)"', wallboard)
    assert button_ids == ["wallboardExitButton"]
    for interactive_tag in ("<input", "<select", "<textarea", "<form"):
        assert interactive_tag not in wallboard
    for ordinary_control in (
        "refreshButton",
        "traceExportButton",
        "traceApplyButton",
        "traceClearButton",
        "mineSearch",
        "mineSelector",
        "view-tabs",
    ):
        assert ordinary_control not in wallboard

    # The unattended page still has to communicate the essential supervision
    # picture without requiring the viewer to drill down.
    for business_topic in ("辖区", "风险", "煤矿", "最新动态"):
        assert business_topic in wallboard


def test_wallboard_supports_direct_url_and_keeps_normal_mode_conditional() -> None:
    script = _asset("app.js")
    styles = _asset("styles.css")

    assert re.search(r"URLSearchParams\s*\(\s*window\.location\.search\s*\)", script)
    assert re.search(r"\.get\(\s*[\"']mode[\"']\s*\)", script)
    assert "wallboard" in script
    assert "wallboardButton" in script
    assert "wallboardExitButton" in script
    assert "wallboard-mode" in script
    assert "wallboard-mode" in styles
    for ordinary_surface in (".topbar", ".view-tabs", "#notice", ".view"):
        assert f"body.wallboard-mode {ordinary_surface}" in styles

    # Entering via the normal button and leaving the single-page display both
    # need explicit handlers; merely styling a static section is insufficient.
    assert re.search(
        r'\$\(\s*["\']wallboardButton["\']\s*\)\.addEventListener\('
        r'\s*["\']click["\']',
        script,
    )
    assert re.search(
        r'\$\(\s*["\']wallboardExitButton["\']\s*\)\.addEventListener\('
        r'\s*["\']click["\']',
        script,
    )
    assert "if (isWallboardRequested()) enterWallboard({updateUrl:false})" in script

    # The class is applied at runtime only. Without ?mode=wallboard the existing
    # four-tab dashboard remains the initial HTML surface.
    index = _asset("index.html")
    body_opening_tag = re.search(r"<body[^>]*>", index)
    assert body_opening_tag is not None
    assert "wallboard-mode" not in body_opening_tag.group(0)
    for view in ("overview", "mine", "findings", "trace"):
        assert f'data-view="{view}"' in index


def test_wallboard_url_entry_exit_and_rotation_behave_as_a_separate_mode() -> None:
    script_path = WEB_ROOT / "app.js"
    probe = r'''
const fs = require("fs");
const vm = require("vm");
const source = fs.readFileSync(__SCRIPT_PATH__, "utf8") + `
globalThis.__wallboardSurface = {
  isWallboardRequested, enterWallboard, exitWallboard, rotateWallboard, state,
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
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      innerHTML: "", textContent: "", title: "", value: "", disabled: false,
      dataset: {}, offsetWidth: 1200,
      classList: makeClassList(id === "wallboardView" ? ["hidden"] : []),
      setAttribute() {}, addEventListener() {}, querySelectorAll() { return []; },
    });
  }
  return elements.get(id);
}

const intervals = new Set();
const cleared = [];
const historyEntries = [];
let nextInterval = 1;
const location = {
  pathname: "/", search: "?mode=wallboard", hash: "",
  href: "http://mineguard.local/?mode=wallboard",
};
const sandbox = {
  URL, URLSearchParams,
  document: {
    body: element("body"),
    documentElement: {requestFullscreen() { return Promise.resolve(); }},
    fullscreenElement: null,
    getElementById: element, addEventListener() {},
    querySelector(selector) { return selector === "#app" ? element("app") : null; },
    querySelectorAll() { return []; },
    exitFullscreen() { return Promise.resolve(); },
  },
  window: {
    location,
    history: {pushState(_state, _title, url) { historyEntries.push(url); }},
    setInterval() { const id = nextInterval++; intervals.add(id); return id; },
    clearInterval(id) { intervals.delete(id); cleared.push(id); },
    setTimeout() { return 0; }, addEventListener() {},
  },
};
vm.createContext(sandbox);
vm.runInContext(source, sandbox);
const {isWallboardRequested, enterWallboard, exitWallboard, rotateWallboard, state} = sandbox.__wallboardSurface;

if (!isWallboardRequested()) process.exit(2);
location.search = "";
location.href = "http://mineguard.local/";
if (isWallboardRequested()) process.exit(3);
location.pathname = "/wallboard";
location.href = "http://mineguard.local/wallboard";
if (!isWallboardRequested()) process.exit(4);

location.pathname = "/";
location.href = "http://mineguard.local/";
state.overview = {
  counts: {configured_mines: 2, reporting_mines: 2, normal_candidate: 1,
    risk: 1, insufficient_data: 0, awaiting_response: 1, overdue: 0},
  attention_counts: {risk_findings: 1, data_to_complete: 0,
    awaiting_enterprise_response: 1, enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 0},
  latest_events: [],
};
state.mines = [];
enterWallboard({updateUrl:true});
if (!state.wallboard.active) process.exit(5);
if (!element("body").classList.contains("wallboard-mode")) process.exit(6);
if (element("wallboardView").classList.contains("hidden")) process.exit(7);
if (historyEntries[historyEntries.length - 1] !== "/?mode=wallboard") process.exit(8);
if (intervals.size !== 2) process.exit(9);

state.mines = [
  {mine_id:"M-01", mine_name:"一号矿", status:"risk", open_finding_count:1},
  {mine_id:"M-02", mine_name:"二号矿", status:"normal_candidate", open_finding_count:0},
];
state.wallboard.rotationIndex = 0;
rotateWallboard();
if (state.wallboard.rotationIndex !== 1) process.exit(10);

exitWallboard();
if (state.wallboard.active) process.exit(11);
if (element("body").classList.contains("wallboard-mode")) process.exit(12);
if (!element("wallboardView").classList.contains("hidden")) process.exit(13);
if (intervals.size !== 0 || cleared.length !== 2) process.exit(14);
if (historyEntries[historyEntries.length - 1] !== "/") process.exit(15);
'''.replace("__SCRIPT_PATH__", json.dumps(str(script_path)))
    completed = subprocess.run(
        ["node", "-e", probe],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_wallboard_refreshes_and_rotates_without_operator_input() -> None:
    script = _asset("app.js")

    # The normal ten-second refresh remains the source of live data. Wallboard
    # rendering must participate in that refresh path and have a separate timed
    # rotation mechanism for content that does not fit on one physical screen.
    assert 'refreshAll({automatic:true})' in script
    assert re.search(r"renderWallboard\s*\(", script)
    assert re.search(r"(?:rotateWallboard|advanceWallboard|wallboardRotation)", script)
    assert len(re.findall(r"(?:window\.)?setInterval\s*\(", script)) >= 2

    # The wallboard must be populated from the same read-only government data,
    # rather than introducing a second mutable workflow.
    for endpoint in (
        "/v2/regulatory/overview",
        "/v2/regulatory/mines",
        "/v2/regulatory/findings",
    ):
        assert endpoint in script
    for mutation in ("submit_conclusion", "approve_case", "deleteFinding"):
        assert mutation not in script


def test_wallboard_refresh_does_not_load_exchange_trace_workbench() -> None:
    script = _asset("app.js")
    refresh = script.split("async function refreshAll", maxsplit=1)[1].split(
        "function bindEvents", maxsplit=1
    )[0]

    # Exchange trace has its own filters and paging and is not core wallboard
    # data. It must remain lazy: unattended refreshes fetch only overview, mines
    # and findings unless the operator is actually on the trace workbench.
    trace_guard = refresh.index('state.activeView === "trace"')
    trace_initialization = refresh.index("initializeTrace()")
    assert trace_guard < trace_initialization


def test_wallboard_release_bumps_both_static_asset_versions_together() -> None:
    index = _asset("index.html")

    stylesheet = re.search(r'/assets/styles\.css\?v=([0-9]+(?:\.[0-9]+)+)', index)
    application = re.search(r'/assets/app\.js\?v=([0-9]+(?:\.[0-9]+)+)', index)
    assert stylesheet is not None
    assert application is not None
    assert stylesheet.group(1) == application.group(1)
    assert tuple(map(int, stylesheet.group(1).split("."))) > (2, 6, 0)
