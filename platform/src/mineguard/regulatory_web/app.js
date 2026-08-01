"use strict";

const state = {
  csrf: null,
  principal: null,
  overview: null,
  mines: [],
  findings: [],
  trace: [],
  selectedMine: null,
  refreshTimer: null,
};

const $ = (id) => {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`页面组件缺失（${id}），请强制刷新以加载同一版本的前端资源`);
  }
  return element;
};
const firstDefined = (...values) => values.find((value) => value !== null && value !== undefined);
const escapeHtml = (value) => String(firstDefined(value, "")).replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const number = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
const formatNumber = (value, digits = 0) => Number.isFinite(Number(value)) ? Number(value).toLocaleString("zh-CN", {maximumFractionDigits: digits}) : "—";
const metricLabel = (code) => ({
  ventilation_m3_min: "风量",
  wind_m3_min: "风量",
  electricity_kwh: "电量",
  detonators_count: "火工品量（雷管）",
  explosives_kg: "火工品量（炸药）",
  mine_entry_persons: "入井人员量",
  // Old persisted demo records are normalised to the current business label.
  // The compatibility key must never become a second user-visible quantity.
  labor_persons: "入井人员量",
  production_t: "产量",
}[code] || code || "");
const formatTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("zh-CN", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false}).format(date);
};

const statusInfo = (status) => ({
  normal_candidate: ["正常候选", "#36dfa1"],
  risk: ["存在风险", "#ff6474"],
  insufficient_data: ["数据不足", "#ffbd59"],
  analyzing: ["分析中", "#45d7ff"],
  not_reported: ["未报送", "#71889a"],
  open: ["待回复", "#ff6474"],
  explanation_recorded: ["已解释", "#ae80ff"],
  risk_persists: ["风险持续", "#ff6474"],
  cleared_by_reanalysis: ["重算解除", "#36dfa1"],
}[status] || [status || "未知", "#8fa9ba"]);

const severityInfo = (severity) => ({
  critical: ["重大", "#ff4157"], high: ["高", "#ff7864"], medium: ["中", "#ffbd59"], low: ["低", "#45d7ff"], information: ["提示", "#8fa9ba"],
}[severity] || [severity || "未分级", "#8fa9ba"]);

async function api(path, options = {}) {
  const headers = {Accept: "application/json", ...(options.headers || {})};
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (state.csrf && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (response.status === 401) {
    state.principal = null;
    showLogin();
    throw new Error("请重新登录");
  }
  if (!response.ok) throw new Error((payload && payload.error && payload.error.message) || (payload && payload.message) || `请求失败（${response.status}）`);
  return payload;
}

function showNotice(message, kind = "warning") {
  const notice = $("notice");
  if (!message) return notice.classList.add("hidden");
  notice.textContent = message;
  notice.dataset.kind = kind;
  notice.classList.remove("hidden");
}

function showLogin() {
  $("logoutButton").classList.add("hidden");
  const dialog = $("loginDialog");
  if (!dialog.open) dialog.showModal();
  $("password").focus();
}

function hideLogin() {
  const dialog = $("loginDialog");
  if (dialog.open) dialog.close();
  $("logoutButton").classList.remove("hidden");
}

async function recoverSession() {
  try {
    const me = await api("/v2/auth/me");
    state.principal = me.principal || me;
    const csrf = await api("/v2/auth/csrf");
    state.csrf = csrf.csrf_token;
    hideLogin();
    return true;
  } catch (_) {
    showLogin();
    return false;
  }
}

async function login(event) {
  event.preventDefault();
  $("loginError").textContent = "";
  try {
    const payload = await api("/v2/auth/login", {method:"POST", body:JSON.stringify({username:$("username").value, password:$("password").value})});
    state.principal = payload.principal;
    state.csrf = payload.csrf_token;
    $("password").value = "";
    hideLogin();
    await refreshAll();
  } catch (error) {
    $("loginError").textContent = error.message;
  }
}

async function logout() {
  try { await api("/v2/auth/logout", {method:"POST", body:"{}"}); } catch (_) {}
  state.csrf = null; state.principal = null; showLogin();
}

function pickCounts(payload) {
  const c = (payload && payload.counts) || (payload && payload.summary) || {};
  return {
    expected: number(firstDefined(c.configured_mines, c.expected_mines, c.total_mines)),
    reported: number(firstDefined(c.reporting_mines, c.reported_mines)),
    normal: number(firstDefined(c.normal_candidate, c.normal)),
    risk: number(firstDefined(c.risk, c.risk_mines)),
    insufficient: number(firstDefined(c.insufficient_data, c.insufficient)),
    awaiting: number(firstDefined(c.awaiting_response, c.open_findings)),
    overdue: number(firstDefined(c.overdue, c.overdue_responses)),
  };
}

function renderOverview(payload) {
  const counts = pickCounts(payload);
  $("metricExpected").textContent = formatNumber(counts.expected);
  $("metricReported").textContent = formatNumber(counts.reported);
  $("metricCoverage").textContent = `覆盖率 ${counts.expected ? (counts.reported / counts.expected * 100).toFixed(1) : "0.0"}%`;
  $("metricNormal").textContent = formatNumber(counts.normal);
  $("metricRisk").textContent = formatNumber(counts.risk);
  $("metricInsufficient").textContent = formatNumber(counts.insufficient);
  $("metricAwaiting").textContent = formatNumber(counts.awaiting);
  $("metricOverdue").textContent = `超时 ${formatNumber(counts.overdue)}`;
  const severityCounts = (payload && payload.severity_counts) || {};
  const highest = (payload && payload.highest_severity) || (number(severityCounts.critical) ? "critical" : number(severityCounts.high) ? "high" : null);
  $("metricHighest").textContent = `最高风险 ${severityInfo(highest)[0]}`;
  $("asOf").textContent = formatTime((payload && payload.as_of) || (payload && payload.updated_at) || new Date().toISOString());

  const legend = [
    ["正常候选", counts.normal, "#36dfa1"], ["存在风险", counts.risk, "#ff6474"], ["数据不足", counts.insufficient, "#ffbd59"], ["未报送", Math.max(0, counts.expected - counts.reported), "#71889a"],
  ];
  $("statusLegend").innerHTML = legend.map(([label, value, color]) => `<div class="legend-row" style="--legend-color:${color}"><i></i><span>${label}</span><strong>${formatNumber(value)}</strong></div>`).join("");

  const severity = (payload && payload.severity_counts) || (payload && payload.risk_severity) || {};
  const rows = [["重大",number(severity.critical),"#ff4157"],["高",number(severity.high),"#ff7864"],["中",number(severity.medium),"#ffbd59"],["低",number(severity.low),"#45d7ff"]];
  const max = Math.max(1, ...rows.map((row) => row[1]));
  $("severityBars").innerHTML = rows.map(([label,value,color]) => `<div class="severity-row"><span>${label}</span><div class="severity-track"><i style="--width:${value/max*100}%;--bar:${color}"></i></div><strong>${value}</strong></div>`).join("");

  renderActivity((payload && payload.latest_events) || (payload && payload.events) || []);
}

function renderActivity(items) {
  $("activityList").innerHTML = items.length ? items.slice(0, 8).map((item) => {
    const [, color] = statusInfo(item.status || item.result_status);
    return `<li class="activity-item" style="--event-color:${color}"><strong>${escapeHtml(item.mine_name || item.mine_id || "系统")} · ${escapeHtml(item.title || item.event_type || item.type || "状态更新")}</strong><p>${escapeHtml(item.summary || item.description || "")}</p><time>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</time></li>`;
  }).join("") : `<li class="activity-item"><strong>暂无交换记录</strong><p>企业完成首次报送后将在这里显示。</p></li>`;
}

function sparkline(values, color) {
  const samples = (Array.isArray(values) ? values : []).map((item) => {
    if (item === null || item === undefined) return null;
    const raw = typeof item === "object"
      ? firstDefined(item.value, item.production_t)
      : item;
    if (raw === null || raw === undefined || raw === "") return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  });
  const finite = samples.filter((value) => value !== null);
  if (finite.length < 2) return "—";
  const min = Math.min(...finite), max = Math.max(...finite), span = max - min || 1;
  const segments = [];
  let current = [];
  samples.forEach((value, index) => {
    if (value === null) {
      if (current.length) segments.push(current);
      current = [];
      return;
    }
    current.push(`${(index/Math.max(1,samples.length-1)*80+1).toFixed(1)},${(24-(value-min)/span*20).toFixed(1)}`);
  });
  if (current.length) segments.push(current);
  const paths = segments
    .filter((segment) => segment.length >= 2)
    .map((segment) => `<polyline points="${segment.join(" ")}" fill="none" stroke="${color}" stroke-width="1.5"/>`)
    .join("");
  return `<svg class="sparkline" viewBox="0 0 82 26" aria-hidden="true">${paths}<line x1="1" y1="24.5" x2="81" y2="24.5" stroke="rgba(139,191,226,.12)"/></svg>`;
}

function renderMines() {
  const query = $("mineSearch").value.trim().toLowerCase();
  const filtered = state.mines.filter((mine) => !query || `${mine.mine_name || ""} ${mine.mine_id || ""}`.toLowerCase().includes(query));
  $("mineTableBody").innerHTML = filtered.length ? filtered.map((mine) => {
    const status = mine.status || mine.analysis_status || "not_reported";
    const [label,color] = statusInfo(status);
    const reply = statusInfo(mine.response_status || (mine.open_finding_count ? "open" : "—"));
    const rawCompleteness = number(firstDefined(mine.completeness_rate, mine.completeness, 0));
    const completeness = Math.max(0, Math.min(100, rawCompleteness * (rawCompleteness <= 1 ? 100 : 1)));
    return `<tr data-mine-id="${escapeHtml(mine.mine_id)}"><td class="mine-cell"><strong>${escapeHtml(mine.mine_name || mine.mine_id)}</strong><small>${escapeHtml(mine.mine_id)}</small></td><td>${escapeHtml(mine.report_month || mine.latest_report_month || "未报")}</td><td><div class="completeness"><div class="mini-track"><i style="width:${completeness}%"></i></div><span>${completeness.toFixed(0)}%</span></div></td><td><span class="status-pill" style="--status-color:${color}">${label}</span></td><td>${formatNumber(firstDefined(mine.finding_count, mine.open_finding_count, 0))}</td><td><span class="status-pill" style="--status-color:${reply[1]}">${escapeHtml(reply[0])}</span></td><td>${escapeHtml(mine.freshness_label || formatTime(mine.data_as_of || mine.updated_at))}</td><td>${sparkline(mine.trend || mine.production_trend || [], color)}</td></tr>`;
  }).join("") : `<tr><td colspan="8">暂无匹配的煤矿记录</td></tr>`;
  $("mineTableBody").querySelectorAll("tr[data-mine-id]").forEach((row) => row.addEventListener("click", () => openMine(row.dataset.mineId)));
}

function renderMineSelector() {
  const current = $("mineSelector").value;
  $("mineSelector").innerHTML = `<option value="">请选择</option>` + state.mines.map((mine) => `<option value="${escapeHtml(mine.mine_id)}">${escapeHtml(mine.mine_name || mine.mine_id)}</option>`).join("");
  if (state.mines.some((mine) => mine.mine_id === current)) $("mineSelector").value = current;
}

function switchView(name) {
  document.querySelectorAll(".view-tab").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === name));
}

async function openMine(mineId) {
  if (!mineId) return;
  switchView("mine");
  $("mineSelector").value = mineId;
  $("mineEmpty").classList.add("hidden");
  $("mineDetail").classList.remove("hidden");
  try {
    const detail = await api(`/v2/regulatory/mines/${encodeURIComponent(mineId)}`);
    state.selectedMine = detail;
    renderMineDetail(detail);
  } catch (error) { showNotice(error.message); }
}

function renderMineDetail(detail) {
  const mine = detail.mine || detail;
  const analysis = detail.latest_analysis || detail.analysis || {};
  const status = statusInfo(analysis.status || mine.status);
  $("mineName").textContent = mine.mine_name || mine.mine_id || "—";
  const latestSubmission = detail.latest_submission || {};
  $("mineMeta").textContent = `${mine.mine_id || "—"} · 报表期 ${latestSubmission.report_month || mine.report_month || "—"} · 截至 ${formatTime(latestSubmission.data_as_of || mine.data_as_of)}`;
  $("mineStatus").innerHTML = `<span class="status-pill" style="--status-color:${status[1]}">${escapeHtml(status[0])}</span>`;
  $("algorithmMeta").innerHTML = `<dt>算法版本</dt><dd>${escapeHtml(analysis.algorithm_version || "—")}</dd><dt>配置指纹</dt><dd title="${escapeHtml(analysis.configuration_sha256 || "")}">${escapeHtml((analysis.configuration_sha256 || "—").slice(0,16))}</dd><dt>L1/MCS</dt><dd>${escapeHtml(analysis.solver_status || "—")}</dd><dt>时序证据</dt><dd>${escapeHtml(analysis.temporal_status || (analysis.temporal && analysis.temporal.status) || "—")}</dd><dt>同类矿样本</dt><dd>${formatNumber(analysis.peer_sample_count)}</dd><dt>参考候选</dt><dd>${analysis.baseline_reference_candidate === true ? "是" : analysis.baseline_reference_candidate === false ? "否" : "—"}</dd><dt>进入历史基线</dt><dd>${analysis.baseline_eligible === true ? "是" : analysis.baseline_eligible === false ? "否（结论仍独立留痕）" : "—"}</dd>`;
  const response = detail.response_summary || {};
  const findings = detail.findings || [];
  const responses = detail.responses || [];
  $("responseMeta").innerHTML = `<dt>开放风险</dt><dd>${formatNumber(firstDefined(response.open, findings.filter((x) => !["cleared_by_reanalysis"].includes(x.state)).length))}</dd><dt>已送达</dt><dd>${formatNumber(response.delivered)}</dd><dt>已回复</dt><dd>${formatNumber(firstDefined(response.replied, responses.length))}</dd><dt>最后回复</dt><dd>${escapeHtml(formatTime(response.last_response_at))}</dd>`;
  renderSeries(detail.daily_series || detail.series || []);
  renderMineFindings(detail.findings || []);
  renderTimeline(detail.timeline || detail.audit_events || []);
}

function renderSeries(rows) {
  const groups = [
    {
      code: "airflow",
      label: "风量",
      series: [{keys:["ventilation_m3_min","wind_m3_min"], label:"风量", legend:"m³/min", color:"#45d7ff"}],
    },
    {
      code: "electricity",
      label: "电量",
      series: [{keys:["electricity_kwh"], label:"电量", legend:"kWh", color:"#ffbd59"}],
    },
    {
      code: "blasting_materials",
      label: "火工品量",
      series: [
        {keys:["detonators_count"], label:"火工品量·雷管（发）", legend:"雷管（发）", color:"#ff7864"},
        {keys:["explosives_kg"], label:"火工品量·炸药（kg）", legend:"炸药（kg）", color:"#f1a1ff"},
      ],
    },
    {
      code: "mine_entry_personnel",
      label: "入井人员量",
      series: [{keys:["mine_entry_persons","labor_persons"], label:"入井人员量", legend:"人次", color:"#ae80ff"}],
    },
    {
      code: "production",
      label: "产量",
      series: [{keys:["production_t"], label:"产量", legend:"吨（t）", color:"#36dfa1"}],
    },
  ];
  const definitions = groups.flatMap((group) => group.series);
  $("seriesLegend").innerHTML = groups.map((group) => `
    <span class="series-legend-item" data-quantity-group="${group.code}" role="listitem">
      <strong>${group.label}</strong>
      <span class="series-legend-keys">
        ${group.series.map((series) => `
          <span class="series-legend-key" aria-label="${series.label}">
            <svg class="series-legend-swatch" viewBox="0 0 30 10" aria-hidden="true" focusable="false">
              <line x1="1" y1="5" x2="29" y2="5" stroke="${series.color}" stroke-width="3" stroke-linecap="round"></line>
              <circle cx="15" cy="5" r="3.5" fill="${series.color}" stroke="#0a1b2d" stroke-width="1"></circle>
            </svg>
            <small>${series.legend}</small>
          </span>`).join("")}
      </span>
    </span>`).join("");
  if (!rows.length) { $("seriesChart").innerHTML = `<div class="empty-state">暂无逐日五量数据</div>`; return; }
  const width = 1000, height = 270, left = 42, right = 12, top = 12, bottom = 32;
  const x = (index) => left + index / Math.max(1, rows.length - 1) * (width-left-right);
  let svg = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">`;
  for (let i=0;i<=4;i+=1) { const y = top + i/4*(height-top-bottom); svg += `<line class="grid" x1="${left}" y1="${y}" x2="${width-right}" y2="${y}"/><text class="axis-label" x="4" y="${y+3}">${100-i*25}%</text>`; }
  definitions.forEach(({keys,label,color}) => {
    const rawValue = (row) => firstDefined(
      ...keys.map((key) => firstDefined(row[key], row.metrics && row.metrics[key])),
    );
    const values = rows.map((row) => Number(rawValue(row))).filter(Number.isFinite);
    if (!values.length) return;
    const min = Math.min(...values), max = Math.max(...values), span = max-min || Math.max(Math.abs(max),1);
    const points = rows.map((row,index) => { const value = Number(rawValue(row)); if (!Number.isFinite(value)) return null; return {x:x(index),y:top+(1-(value-min)/span)*(height-top-bottom),value,date:row.date}; }).filter(Boolean);
    svg += `<polyline class="series-line" stroke="${color}" points="${points.map((p)=>`${p.x},${p.y}`).join(" ")}"/>`;
    svg += points.map((p) => `<circle class="point" cx="${p.x}" cy="${p.y}" r="2.4" fill="${color}"><title>${escapeHtml(p.date || "")} ${label}: ${formatNumber(p.value,2)}</title></circle>`).join("");
  });
  const labelIndexes = [...new Set([0, Math.floor((rows.length-1)/2), rows.length-1])];
  svg += labelIndexes.map((index) => `<text class="axis-label" x="${x(index)}" y="${height-8}" text-anchor="middle">${escapeHtml((rows[index] && rows[index].date) || "")}</text>`).join("") + `</svg>`;
  $("seriesChart").innerHTML = svg;
}

function findingCard(item) {
  const [severityLabel,color] = severityInfo(item.severity);
  const stateLabel = statusInfo(item.state || item.status);
  const evidence = item.evidence || item.facts || [];
  return `<article class="finding-card" style="--severity-color:${color}" data-severity="${escapeHtml(item.severity)}" data-state="${escapeHtml(item.state || item.status)}"><header><h3>${escapeHtml(item.title || item.code || "风险线索")}</h3><span class="status-pill" style="--status-color:${color}">${severityLabel}</span></header><p>${escapeHtml(item.summary || item.description || "")}</p><div class="finding-meta"><span>${escapeHtml(item.mine_name || item.mine_id || "")}</span><span>${escapeHtml(item.category || "")}</span><span>${escapeHtml(formatTime(item.issued_at || item.created_at))}</span><span style="color:${stateLabel[1]}">${escapeHtml(stateLabel[0])}</span></div>${evidence.length ? `<div class="finding-evidence">${evidence.slice(0,3).map((fact) => `<p>• ${escapeHtml(typeof fact === "string" ? fact : fact.description || metricLabel(fact.metric) || JSON.stringify(fact))}</p>`).join("")}</div>` : ""}</article>`;
}

function renderMineFindings(items) { $("mineFindings").innerHTML = items.length ? items.map(findingCard).join("") : `<div class="empty-state">当前没有风险线索</div>`; }
function renderTimeline(items) { $("mineTimeline").innerHTML = items.length ? items.map((item) => `<li><strong>${escapeHtml(item.title || item.event_type || item.type || "状态更新")}</strong><p>${escapeHtml(item.summary || item.description || "")}</p><time>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</time></li>`).join("") : `<li><strong>暂无时间线记录</strong></li>`; }

function renderFindings() {
  const severity = $("findingSeverity").value, findingState = $("findingState").value;
  const filtered = state.findings.filter((item) => (!severity || item.severity === severity) && (!findingState || (item.state || item.status) === findingState));
  $("findingLedger").innerHTML = filtered.length ? filtered.map(findingCard).join("") : `<div class="empty-state">没有符合筛选条件的风险记录</div>`;
}

function renderTrace() {
  $("traceTableBody").innerHTML = state.trace.length ? state.trace.map((item) => `<tr><td>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</td><td class="mine-cell"><strong>${escapeHtml(item.mine_name || item.mine_id || "—")}</strong><small>${escapeHtml(item.mine_id || "")}</small></td><td>${escapeHtml(item.event_type || item.type || "—")}</td><td title="${escapeHtml(item.correlation_id || item.message_id || "")}">${escapeHtml((item.correlation_id || item.message_id || "—").slice(0,20))}</td><td>${escapeHtml(item.summary || item.description || "")}</td><td><span class="status-pill" style="--status-color:${item.integrity_valid === false ? "#ff6474" : "#36dfa1"}">${item.integrity_valid === false ? "异常" : "有效"}</span></td></tr>`).join("") : `<tr><td colspan="6">暂无交换留痕</td></tr>`;
}

async function refreshAll() {
  if (!state.principal) return;
  $("refreshButton").disabled = true;
  try {
    const [overview, mines, findings, trace] = await Promise.all([
      api("/v2/regulatory/overview"), api("/v2/regulatory/mines"), api("/v2/regulatory/findings?limit=200"), api("/v2/regulatory/exchanges?limit=200"),
    ]);
    state.overview = overview;
    state.mines = mines.items || mines.mines || [];
    state.findings = findings.items || findings.findings || [];
    state.trace = trace.items || trace.events || [];
    renderOverview(overview); renderMines(); renderMineSelector(); renderFindings(); renderTrace();
    if (state.selectedMine && state.selectedMine.mine && state.selectedMine.mine.mine_id) await openMine(state.selectedMine.mine.mine_id);
    showNotice("");
  } catch (error) { showNotice(error.message); }
  finally { $("refreshButton").disabled = false; document.querySelector("#app").setAttribute("aria-busy", "false"); }
}

function bindEvents() {
  $("loginForm").addEventListener("submit", login);
  $("logoutButton").addEventListener("click", logout);
  $("refreshButton").addEventListener("click", refreshAll);
  $("fullscreenButton").addEventListener("click", () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen());
  $("mineSearch").addEventListener("input", renderMines);
  $("mineSelector").addEventListener("change", (event) => openMine(event.target.value));
  $("findingSeverity").addEventListener("change", renderFindings);
  $("findingState").addEventListener("change", renderFindings);
  document.querySelectorAll(".view-tab").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  if (await recoverSession()) await refreshAll();
  state.refreshTimer = window.setInterval(refreshAll, 10000);
});
