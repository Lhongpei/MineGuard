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


def test_regulatory_frontend_is_a_read_only_business_surface() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "政府只读监管平台" in index
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


def test_five_quantity_legend_has_equal_groups_and_visible_series_lines() -> None:
    index = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    assert 'class="series-legend" role="list"' in index
    assert 'class="series-legend-item"' in script
    assert 'class="series-legend-swatch"' in script
    assert 'code: "blasting_materials"' in script
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
  /<polyline class="series-line" stroke="(#[0-9a-f]{{6}})"/g,
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
