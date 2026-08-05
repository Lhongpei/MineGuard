"use strict";

const state = {
  csrf: null,
  principal: null,
  overview: null,
  mines: [],
  findings: [],
  trace: [],
  tracePage: {
    initialized: false,
    loading: false,
    exporting: false,
    rangePreset: "7d",
    appliedFilters: null,
    matchedCount: 0,
    hasMore: false,
    nextCursor: null,
    asOf: null,
    integrity: null,
    pendingCount: 0,
    newestIdentity: null,
    requestSerial: 0,
  },
  selectedMine: null,
  activeView: "overview",
  refreshTimer: null,
  refreshing: false,
  wallboard: {
    active: false,
    rotationIndex: 0,
    rotationTimer: null,
    clockTimer: null,
    updateFailed: false,
    lastError: null,
  },
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

// Government-facing text must never expose storage/algorithm enum names.
// Exact codes remain unchanged in source records and audit hashes; this map is
// presentation-only and therefore cannot affect calculation or traceability.
const BUSINESS_TERM_LABELS = Object.freeze({
  ventilation_m3_min: "风量",
  wind_m3_min: "风量",
  electricity_kwh: "电量",
  detonators_count: "火工品量（雷管）",
  explosives_kg: "火工品量（炸药）",
  mine_entry_persons: "入井人员量",
  labor_persons: "入井人员量",
  production_t: "产量",
  ventilation_per_production: "单位产量风量",
  electricity_per_production: "单位产量电耗",
  detonators_per_production: "单位产量雷管用量",
  explosives_per_production: "单位产量炸药用量",
  mine_entry_persons_per_production: "单位产量入井人员量",
  labor_per_production: "单位产量入井人员量",
  anonymous_peer: "匿名同类矿",
  same_mine_history: "本矿历史",
  within_submission: "本期数据",
  wire_quality_flags: "报送质量标记",
  required_metric_completeness: "五量完整性规则",
  declared_vs_inferred_operating_state: "申报与推断工况",
  weighted_l1: "加权偏差协调",
  median_mad: "稳健中位数基线",
  robust_half_window_median_drift: "窗口中位数漂移",
  sse_bic_step_vs_linear: "变化点与趋势比较",
  strict_profile_mcs_diagnostic_not_causation: "最小冲突集诊断",
  state_aware_context_rule_not_physical_violation: "工况上下文规则",
  qualified_measurement_requires_review: "测量值需复核",
  incomplete_five_quantity_days: "五量日数据不完整",
  soft_reference_interval_exceeded: "超出软参考区间",
  robust_temporal_outlier: "稳健时序偏离",
  strict_counterfactual_conflict_set: "最小放宽组合",
  normal_candidate: "暂未发现异常",
  insufficient_data: "数据不足",
  risk_persists: "风险仍存在",
  cleared_by_reanalysis: "修订复核已解除",
  explanation_recorded: "企业已回复、风险未解除",
  not_reported: "尚未报送",
  iteration_or_time_limit: "达到迭代或时间上限",
  numerical_failure: "数值计算失败",
  solver_error: "求解器异常",
});
const SNAKE_CASE_TOKEN = /(^|[^A-Za-z0-9_])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?=$|[^A-Za-z0-9_])/g;

function humanizeBusinessText(value) {
  return String(firstDefined(value, ""))
    .replace(
      SNAKE_CASE_TOKEN,
      (_match, prefix, token) => `${prefix}${BUSINESS_TERM_LABELS[token] || "其他业务项"}`,
    )
    .replace(/CUSUM\s+累积偏移/g, "持续累积偏移值")
    .replace(/EWMA\s+水平/g, "近期加权均值")
    .replace(/Page-Hinkley\s+检测到/gi, "均值变化检测发现")
    .replace(/median\/MAD\s+基线/gi, "历史稳健基线")
    .replace(/\bCUSUM\b/g, "持续累积偏移")
    .replace(/\bEWMA\b/g, "近期均值越界")
    .replace(/\bPage-Hinkley\b/gi, "均值变化检测")
    .replace(/\bmedian\/MAD\b/gi, "历史稳健范围")
    .replace(/([\u3400-\u9fff])\s+(?=[\u3400-\u9fff])/g, "$1");
}

function findingSummaryForDisplay(value) {
  const rendered = humanizeBusinessText(value);
  const clauses = rendered.split("；").map((item) => item.trim()).filter(Boolean);
  const dated = clauses.map((clause) => {
    const matched = clause.match(/^(\d{4}-\d{2}-\d{2})\s*(.+)$/);
    return matched ? {date:matched[1], body:matched[2].trim().replace(/^的(?=[\u3400-\u9fff])/, "")} : null;
  });
  if (clauses.length < 3 || dated.some((item) => item === null)) return rendered;
  const groups = new Map();
  dated.forEach((item) => {
    if (!groups.has(item.body)) groups.set(item.body, {count:0, firstDate:item.date});
    groups.get(item.body).count += 1;
  });
  if (groups.size > 3) return rendered;
  const summary = [...groups.entries()].map(([body, group]) => group.count > 1
    ? `多日出现：${body}`
    : `${group.firstDate} ${body}`);
  return `${summary.join("；")}。逐日证据见下方。`;
}

const metricLabel = (code) => BUSINESS_TERM_LABELS[code] || humanizeBusinessText(code);

function solverDisplay(value) {
  return humanizeBusinessText(value)
    .replace(/\boptimal\b/gi, "求解成功")
    .replace(/\binfeasible\b/gi, "约束不可同时满足")
    .replace(/\bunbounded\b/gi, "求解边界异常")
    .replace(/\bhighs(?:-[a-z]+)?\b/gi, "HiGHS")
    .replace(/\bMCS\b/g, "最小冲突集");
}
const formatTime = (value) => {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : new Intl.DateTimeFormat("zh-CN", {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false}).format(date);
};

const statusInfo = (status) => ({
  normal_candidate: ["暂未发现异常", "#36dfa1", "positive"],
  risk: ["存在风险", "#ff6474", "risk"],
  insufficient_data: ["数据不足", "#ffbd59", "warning"],
  analyzing: ["正在分析", "#45d7ff", "info"],
  not_reported: ["尚未报送", "#71889a", "neutral"],
  open: ["待企业回复", "#ff6474", "risk"],
  explanation_recorded: ["企业已回复、风险未解除", "#ae80ff", "response"],
  risk_persists: ["复核后风险仍存在", "#ff6474", "risk"],
  cleared_by_reanalysis: ["修订复核已解除", "#36dfa1", "positive"],
}[status] || ["状态待确认", "#8fa9ba", "neutral"]);

const findingType = (item) => item.finding_type || (item.severity === "medium" ? "data_insufficient" : "risk");
const findingTypeInfo = (type) => type === "data_insufficient"
  ? ["数据待补", "warning"]
  : ["风险线索", "risk"];
const findingCategoryLabel = (category) => ({
  data_quality: "数据质量",
  relationship_consistency: "五量关系",
  temporal_pattern: "时序变化",
  data_completeness: "数据完整性",
}[category] || "其他待核事项");

const TRACE_EVENT_GROUP_LABELS = Object.freeze({
  submission: "企业报送",
  analysis: "政府研判",
  finding: "风险形成",
  delivery: "结果送达",
  response: "企业回复",
  reanalysis: "修订重算",
  security: "接入与安全拦截",
  technical: "技术留痕",
  system: "系统记录",
});
const TRACE_PAGE_SIZE = 20;
const TRACE_RANGE_DURATIONS = Object.freeze({
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
});
const WALLBOARD_ROTATION_MS = 8000;
const WALLBOARD_MINE_PAGE_SIZE = 8;

function traceEventGroupLabel(item) {
  return firstDefined(
    item.event_group_label,
    TRACE_EVENT_GROUP_LABELS[item.event_group],
    "其他业务环节",
  );
}

function traceIdentity(item) {
  return String(firstDefined(
    item.event_id,
    item.audit_event_id,
    item.message_id,
    item.sequence,
    item.trace_sequence,
    `${item.mine_id || "system"}:${item.occurred_at || item.created_at || ""}:${item.event_type || ""}`,
  ));
}

const LEADER_ACTIVITY_EVENT_TYPES = new Set([
  "submission_received",
  "analysis_report_automatically_issued",
  "analysis_report_delivery_acknowledged",
  "enterprise_response_batch_recorded",
  "enterprise_explanation_recorded",
  "explanation_recorded",
  "finding_resolved_by_revision_reanalysis",
  "inbox_idempotency_conflict_rejected",
]);

function decisionFromActivity(item) {
  const explicit = firstDefined(item.status, item.result_status, item.decision, item.outcome);
  if (explicit) return String(explicit);
  const source = `${item.summary || ""} ${item.description || ""}`;
  return ["normal_candidate", "insufficient_data", "risk"].find((code) => source.includes(code)) || null;
}

function mineNameForActivity(item) {
  if (item.mine_name) return item.mine_name;
  const mine = state.mines.find((candidate) => candidate.mine_id === item.mine_id);
  return (mine && mine.mine_name) || item.mine_id || "辖区系统";
}

function activityPresentation(item) {
  const eventType = item.event_type || item.type || "";
  const decision = decisionFromActivity(item);
  const mineName = mineNameForActivity(item);
  let title = "业务状态已更新";
  let summary = "系统已记录一项业务变化，详细信息可在交换留痕中查看。";
  let tone = "info";
  if (eventType === "submission_received" || eventType === "exchange_inbound_recorded") {
    title = "本期五量数据已收到";
    summary = "数据已通过基本验收，并进入统一监管算法分析。";
  } else if (eventType === "analysis_completed" || eventType === "analysis_report_automatically_issued") {
    if (decision === "risk") {
      title = "本期五量核验发现风险线索";
      summary = "风险报告已发送企业，等待企业说明原因或修订数据。";
      tone = "risk";
    } else if (decision === "insufficient_data") {
      title = "本期五量数据不足，暂不能形成判断";
      summary = "已通知企业补充或核对缺失数据。";
      tone = "warning";
    } else {
      title = "本期五量核验完成：暂未发现异常";
      summary = "本期自动核验已完成，继续按期观察后续数据。";
      tone = "positive";
    }
  } else if (eventType === "finding_automatically_issued") {
    title = "已生成风险提醒";
    summary = "请在风险台账中查看涉及指标、算法依据和待核事项。";
    tone = "risk";
  } else if (eventType === "baseline_candidate_admitted") {
    title = "本期数据已纳入历史参考";
    summary = "该期数据符合基线准入条件，可用于后续同矿历史比较。";
    tone = "positive";
  } else if (eventType === "baseline_candidate_rejected") {
    title = "本期数据暂不作为历史参考";
    summary = "本次结果仍完整留痕，但不会影响后续基线。";
    tone = "warning";
  } else if (eventType === "analysis_report_delivery_acknowledged") {
    title = "企业已确认收到分析结果";
    summary = "监管结果已送达企业端，需回复的事项继续计入待办。";
    tone = "positive";
  } else if (["enterprise_response_batch_recorded", "enterprise_explanation_recorded", "explanation_recorded"].includes(eventType)) {
    title = "企业回复已收到";
    summary = "企业说明和证据索引已追加留痕，可在风险台账中查看。";
    tone = "response";
  } else if (eventType === "finding_resolved_by_revision_reanalysis") {
    title = "修订数据重新分析后，风险已解除";
    summary = "企业提交了修订数据，同一算法重算后未再出现原风险。";
    tone = "positive";
  } else if (eventType === "inbox_idempotency_conflict_rejected") {
    title = "异常重复报送已拦截";
    summary = "同一业务编号出现不同内容，系统已拒绝写入并保留审计记录。";
    tone = "risk";
  } else if (eventType === "agent_mine_bound") {
    title = "企业智能体已完成接入";
    summary = "该智能体已与本矿井身份固定绑定。";
  }
  return {mineName, title, summary, tone};
}

function activitySummaryForDisplay(item, presentation) {
  return humanizeBusinessText(firstDefined(
    item.summary_human,
    item.business_summary,
    item.summary,
    item.description,
    presentation.summary,
  ));
}

function selectLeaderActivities(items) {
  const source = Array.isArray(items) ? items : [];
  const candidates = source.filter((item) => LEADER_ACTIVITY_EVENT_TYPES.has(item.event_type || item.type));
  const seen = new Set();
  const selected = [];
  for (const item of candidates) {
    const correlation = item.correlation_id || item.message_id || item.event_id || `${item.mine_id || "system"}:${item.occurred_at || item.created_at || ""}`;
    if (seen.has(correlation)) continue;
    seen.add(correlation);
    selected.push(item);
    if (selected.length === 8) break;
  }
  return selected;
}

// 五个业务量、六个不可混加的原子序列共用这一份展示定义。
// 图例和轨道均直接读取这里的色值，避免两处配置漂移。
const FIVE_QUANTITY_GROUPS = [
  {
    code: "airflow",
    label: "风量",
    series: [{code:"ventilation_m3_min", keys:["ventilation_m3_min","wind_m3_min"], label:"风量", trackLabel:"风量", legend:"m³/min", color:"#45d7ff"}],
  },
  {
    code: "electricity",
    label: "电量",
    series: [{code:"electricity_kwh", keys:["electricity_kwh"], label:"电量", trackLabel:"电量", legend:"kWh", color:"#ffbd59"}],
  },
  {
    code: "blasting_materials",
    label: "火工品量",
    series: [
      {code:"detonators_count", keys:["detonators_count"], label:"火工品量·雷管（发）", trackLabel:"雷管（火工品）", legend:"雷管（发）", unit:"发", color:"#ff7864"},
      {code:"explosives_kg", keys:["explosives_kg"], label:"火工品量·炸药（kg）", trackLabel:"炸药（火工品）", legend:"炸药（kg）", unit:"kg", color:"#f1a1ff"},
    ],
  },
  {
    code: "mine_entry_personnel",
    label: "入井人员量",
    series: [{code:"mine_entry_persons", keys:["mine_entry_persons","labor_persons"], label:"入井人员量", trackLabel:"入井人员量", legend:"人次", color:"#ae80ff"}],
  },
  {
    code: "production",
    label: "产量",
    series: [{code:"production_t", keys:["production_t"], label:"产量", trackLabel:"产量", legend:"吨（t）", unit:"t", color:"#36dfa1"}],
  },
];

async function api(path, options = {}) {
  const headers = {Accept: "application/json", ...(options.headers || {})};
  if (options.body && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
  if (state.csrf && !["GET", "HEAD"].includes((options.method || "GET").toUpperCase())) headers["X-CSRF-Token"] = state.csrf;
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (response.status === 401) {
    state.principal = null;
    resetTraceSessionState();
    showLogin();
    throw new Error("请重新登录");
  }
  if (!response.ok) throw new Error((payload && payload.error && payload.error.message) || (payload && payload.message) || `请求失败（${response.status}）`);
  return payload;
}

function resetTraceSessionState() {
  state.trace = [];
  Object.assign(state.tracePage, {
    initialized: false,
    loading: false,
    exporting: false,
    rangePreset: "7d",
    appliedFilters: null,
    matchedCount: 0,
    hasMore: false,
    nextCursor: null,
    asOf: null,
    integrity: null,
    pendingCount: 0,
    newestIdentity: null,
    requestSerial: state.tracePage.requestSerial + 1,
  });
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
  state.csrf = null;
  state.principal = null;
  resetTraceSessionState();
  showLogin();
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
  const legacySeverity = (payload && payload.severity_counts) || {};
  const attention = (payload && payload.attention_counts) || {
    risk_findings: number(legacySeverity.high),
    data_to_complete: number(legacySeverity.medium),
    awaiting_enterprise_response: counts.awaiting,
    enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 0,
  };
  const riskFindings = number(attention.risk_findings);
  const dataToComplete = number(attention.data_to_complete);
  const unresolved = riskFindings + dataToComplete;
  $("metricHighest").textContent = `待核事项 ${formatNumber(unresolved)} 项`;
  $("asOf").textContent = formatTime((payload && payload.as_of) || (payload && payload.updated_at) || new Date().toISOString());

  const legend = [
    ["暂未发现风险", counts.normal, "positive"], ["存在风险", counts.risk, "risk"], ["数据不足", counts.insufficient, "warning"], ["未报送", Math.max(0, counts.expected - counts.reported), "neutral"],
  ];
  $("statusLegend").innerHTML = legend.map(([label, value, tone]) => `<div class="legend-row legend-${tone}"><i></i><span>${label}</span><strong>${formatNumber(value)}</strong></div>`).join("");

  const attentionRows = [
    ["风险线索", riskFindings, "#ff6474"],
    ["数据待补", dataToComplete, "#ffbd59"],
  ];
  const attentionTotal = attentionRows.reduce((sum, row) => sum + row[1], 0);
  $("attentionTotal").textContent = attentionTotal ? `当前 ${formatNumber(attentionTotal)} 项未解除` : "当前无未解除事项";
  $("severityBars").innerHTML = attentionRows.map(([label,value,color]) => {
    const share = attentionTotal ? value / attentionTotal * 100 : 0;
    return `<div class="severity-row"><span>${label}</span><svg class="severity-track" viewBox="0 0 100 8" preserveAspectRatio="none" role="img" aria-label="${label} ${value} 项，占 ${share.toFixed(1)}%"><rect class="severity-track-bg" x="0" y="0" width="100" height="8" rx="4"></rect><rect x="0" y="0" width="${share.toFixed(2)}" height="8" rx="4" fill="${color}"></rect></svg><strong>${formatNumber(value)} 项<small>${share.toFixed(1)}%</small></strong></div>`;
  }).join("");
  const awaiting = number(attention.awaiting_enterprise_response);
  const responded = number(firstDefined(attention.enterprise_responded_unresolved, attention.explanation_recorded));
  const cleared = number(attention.cleared_by_reanalysis);
  $("attentionStatus").innerHTML = `<div><span>待企业回复</span><strong>${formatNumber(awaiting)}</strong></div><div><span>企业已回复<br>风险未解除</span><strong>${formatNumber(responded)}</strong></div><div><span>修订数据复核<br>已解除</span><strong>${formatNumber(cleared)}</strong></div>`;
  if (unresolved) {
    const responseText = awaiting ? `；其中 ${formatNumber(awaiting)} 项等待企业回复` : responded ? `；${formatNumber(responded)} 项已收到企业回复` : "";
    $("riskGuidance").textContent = `辖区当前共 ${formatNumber(unresolved)} 项待关注事项：${formatNumber(riskFindings)} 项风险线索、${formatNumber(dataToComplete)} 项数据待补${responseText}。`;
  } else {
    $("riskGuidance").textContent = "当前没有未解除的风险线索或待补数据，请继续关注未报送和新产生的异常。";
  }

  const latest = (payload && payload.latest_events) || (payload && payload.events) || [];
  const hasBusinessProjection = latest.some((item) => item && item.event_label);
  renderActivity(hasBusinessProjection ? latest : state.trace.length ? state.trace : latest);
}

function renderActivity(items) {
  const selected = selectLeaderActivities(items);
  $("activityList").innerHTML = selected.length ? selected.map((item) => {
    const presentation = activityPresentation(item);
    return `<li class="activity-item activity-${presentation.tone}"><strong>${escapeHtml(presentation.mineName)}</strong><h3>${escapeHtml(humanizeBusinessText(item.event_label || presentation.title))}</h3><p>${escapeHtml(activitySummaryForDisplay(item, presentation))}</p><time>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</time></li>`;
  }).join("") : `<li class="activity-item activity-info"><strong>辖区动态</strong><h3>暂无新的监管动态</h3><p>企业完成报送或风险状态发生变化后，将在这里显示。</p></li>`;
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
    const [label,color,tone] = statusInfo(status);
    const reply = statusInfo(mine.response_status || (mine.open_finding_count ? "open" : "—"));
    const rawCompleteness = number(firstDefined(mine.completeness_rate, mine.completeness, 0));
    const completeness = Math.max(0, Math.min(100, rawCompleteness * (rawCompleteness <= 1 ? 100 : 1)));
    return `<tr data-mine-id="${escapeHtml(mine.mine_id)}"><td class="mine-cell"><strong>${escapeHtml(mine.mine_name || mine.mine_id)}</strong><small>${escapeHtml(mine.mine_id)}</small></td><td>${escapeHtml(mine.report_month || mine.latest_report_month || "未报")}</td><td><div class="completeness"><svg class="mini-track" viewBox="0 0 100 5" preserveAspectRatio="none" role="img" aria-label="数据完整率 ${completeness.toFixed(0)}%"><rect class="mini-track-bg" x="0" y="0" width="100" height="5" rx="2.5"></rect><rect class="mini-track-fill" x="0" y="0" width="${completeness.toFixed(2)}" height="5" rx="2.5"></rect></svg><span>${completeness.toFixed(0)}%</span></div></td><td><span class="status-pill status-${tone}">${escapeHtml(label)}</span></td><td>${formatNumber(firstDefined(mine.finding_count, mine.open_finding_count, 0))}</td><td><span class="status-pill status-${reply[2]}">${escapeHtml(reply[0])}</span></td><td>${escapeHtml(humanizeBusinessText(mine.freshness_label || formatTime(mine.data_as_of || mine.updated_at)))}</td><td>${sparkline(mine.trend || mine.production_trend || [], color)}</td></tr>`;
  }).join("") : `<tr><td colspan="8">暂无匹配的煤矿记录</td></tr>`;
  $("mineTableBody").querySelectorAll("tr[data-mine-id]").forEach((row) => row.addEventListener("click", () => openMine(row.dataset.mineId)));
}

function renderMineSelector() {
  const current = $("mineSelector").value;
  $("mineSelector").innerHTML = `<option value="">请选择</option>` + state.mines.map((mine) => `<option value="${escapeHtml(mine.mine_id)}">${escapeHtml(mine.mine_name || mine.mine_id)}</option>`).join("");
  if (state.mines.some((mine) => mine.mine_id === current)) $("mineSelector").value = current;
}

function isWallboardRequested() {
  const cleanPath = window.location.pathname.replace(/\/+$/, "") || "/";
  return cleanPath === "/wallboard" || new URLSearchParams(window.location.search).get("mode") === "wallboard";
}

function wallboardEffectiveStatus(mine) {
  const openFindings = number(mine && mine.open_finding_count);
  const reportedStatus = firstDefined(mine && mine.status, mine && mine.analysis_status, "not_reported");
  // An unresolved item remains visible as attention even when the newest report
  // itself is normal; this avoids turning an open supervision loop pure green.
  if (openFindings > 0) return reportedStatus === "insufficient_data" ? "insufficient_data" : "risk";
  return reportedStatus;
}

function wallboardOrderedMines() {
  const statusPriority = {risk:0, insufficient_data:1, not_reported:2, analyzing:3, normal_candidate:4};
  return [...state.mines].sort((left, right) => {
    const leftOpen = number(left.open_finding_count);
    const rightOpen = number(right.open_finding_count);
    if ((leftOpen > 0) !== (rightOpen > 0)) return leftOpen > 0 ? -1 : 1;
    if (leftOpen !== rightOpen) return rightOpen - leftOpen;
    const leftPriority = firstDefined(statusPriority[wallboardEffectiveStatus(left)], 9);
    const rightPriority = firstDefined(statusPriority[wallboardEffectiveStatus(right)], 9);
    const statusDelta = leftPriority - rightPriority;
    if (statusDelta) return statusDelta;
    return String(left.mine_name || left.mine_id || "").localeCompare(String(right.mine_name || right.mine_id || ""), "zh-CN");
  });
}

function updateWallboardClock() {
  if (!state.wallboard.active) return;
  $("wallboardClock").textContent = new Intl.DateTimeFormat("zh-CN", {
    year:"numeric", month:"2-digit", day:"2-digit", weekday:"short",
    hour:"2-digit", minute:"2-digit", second:"2-digit", hour12:false,
  }).format(new Date());
}

function renderWallboardHealth() {
  if (!state.wallboard.active) return;
  const element = $("wallboardAsOf");
  const asOf = firstDefined(state.overview && state.overview.as_of, state.overview && state.overview.updated_at);
  element.classList.toggle("is-error", state.wallboard.updateFailed);
  element.textContent = state.wallboard.updateFailed
    ? `更新异常，继续展示 ${asOf ? formatTraceTime(asOf) : "最近一次"} 页面`
    : asOf ? `页面更新于 ${formatTraceTime(asOf)}` : "页面尚未加载";
  element.title = state.wallboard.updateFailed ? humanizeBusinessText(state.wallboard.lastError || "后台更新暂时失败") : "";
}

function renderWallboardCore(mine) {
  const effectiveStatus = wallboardEffectiveStatus(mine);
  const [statusLabel, _statusColor, statusTone] = statusInfo(effectiveStatus);
  const openFindings = number(mine && mine.open_finding_count);
  const reportPeriod = firstDefined(
    mine && mine.report_month,
    mine && mine.latest_report_month,
    "尚未形成报表期",
  );
  const findingText = openFindings > 0
    ? `${formatNumber(openFindings)} 项未解除事项`
    : "当前无未解除事项";
  $("wallboardCoreBody").innerHTML = `
    <div class="wallboard-core-stage status-${statusTone}" role="img" aria-label="五量统一交叉核验；当前结论：${escapeHtml(statusLabel)}">
      <div class="wallboard-core-grid" aria-hidden="true"></div>
      <svg class="wallboard-core-network" viewBox="0 0 520 300" preserveAspectRatio="xMidYMid meet" aria-hidden="true" focusable="false">
        <circle class="wallboard-core-orbit orbit-outer" cx="260" cy="150" r="125"></circle>
        <circle class="wallboard-core-orbit orbit-inner" cx="260" cy="150" r="78"></circle>
        <polygon class="wallboard-core-pentagon" points="260,25 379,111 334,251 186,251 141,111"></polygon>
        <g class="wallboard-core-links">
          <path d="M260 150 L260 25"></path>
          <path d="M260 150 L379 111"></path>
          <path d="M260 150 L334 251"></path>
          <path d="M260 150 L186 251"></path>
          <path d="M260 150 L141 111"></path>
        </g>
        <g class="wallboard-core-scan">
          <path d="M260 150 L260 25 A125 125 0 0 1 379 111 Z"></path>
        </g>
        <circle class="wallboard-core-pulse" cx="260" cy="150" r="53"></circle>
      </svg>
      <div class="wallboard-core-center">
        <span>统一监管引擎</span>
        <strong>${escapeHtml(statusLabel)}</strong>
        <small>${escapeHtml(findingText)} · ${escapeHtml(reportPeriod)}</small>
      </div>
      <div class="wallboard-core-quantity quantity-ventilation"><strong>风量</strong><span>已纳入核验</span></div>
      <div class="wallboard-core-quantity quantity-electricity"><strong>电量</strong><span>已纳入核验</span></div>
      <div class="wallboard-core-quantity quantity-production"><strong>产量</strong><span>已纳入核验</span></div>
      <div class="wallboard-core-quantity quantity-personnel"><strong>入井人员量</strong><span>已纳入核验</span></div>
      <div class="wallboard-core-quantity quantity-explosives"><strong>火工品量</strong><span>雷管（发） · 炸药（kg）</span></div>
    </div>
    <div class="wallboard-core-layers" aria-label="交叉核验依据">
      <span><i aria-hidden="true"></i>物理关系 · 关系约束</span>
      <span><i aria-hidden="true"></i>本矿历史基线</span>
      <span><i aria-hidden="true"></i>匿名同类参照</span>
      <span><i aria-hidden="true"></i>时序漂移识别</span>
    </div>
    <p class="wallboard-core-note">星环表示五量核验链路与当前整体结论，不代表各指标数值大小。</p>`;
}

function renderWallboardFocus(orderedMines = wallboardOrderedMines()) {
  const total = orderedMines.length;
  if (!total) {
    $("wallboardFocusProgress").textContent = "暂无煤矿";
    $("wallboardFocusBody").innerHTML = `<div class="wallboard-focus-empty">辖区尚无可展示的煤矿数据</div>`;
    $("wallboardMinePage").textContent = "暂无煤矿";
    $("wallboardMineRail").innerHTML = `<div class="wallboard-focus-empty">暂无煤矿状态</div>`;
    return;
  }
  state.wallboard.rotationIndex %= total;
  const index = state.wallboard.rotationIndex;
  const mine = orderedMines[index];
  const effectiveStatus = wallboardEffectiveStatus(mine);
  const [statusLabel, statusColor, statusTone] = statusInfo(effectiveStatus);
  const openFindings = number(mine.open_finding_count);
  const rawCompleteness = number(firstDefined(mine.completeness_rate, mine.completeness, 0));
  const completeness = Math.max(0, Math.min(100, rawCompleteness * (rawCompleteness <= 1 ? 100 : 1)));
  const responseLabel = openFindings > 0
    ? statusInfo(firstDefined(mine.response_status, "open"))[0]
    : "当前无需企业回复";
  const freshness = humanizeBusinessText(firstDefined(mine.freshness_label, formatTime(mine.data_as_of || mine.updated_at), "—"));
  const focusBody = $("wallboardFocusBody");
  focusBody.innerHTML = `<div class="wallboard-focus-name"><div><h3>${escapeHtml(mine.mine_name || mine.mine_id || "未命名煤矿")}</h3><p>${escapeHtml(mine.mine_id || "—")} · ${escapeHtml(mine.report_month || mine.latest_report_month || "尚未报送")}</p></div><span class="status-pill status-${statusTone}">${escapeHtml(statusLabel)}</span></div><div class="wallboard-focus-score"><div><span>未解除事项</span><strong>${formatNumber(openFindings)} 项</strong></div><div><span>企业回复状态</span><strong>${escapeHtml(responseLabel)}</strong></div><div><span>数据新鲜度</span><strong>${escapeHtml(freshness)}</strong></div></div><section class="wallboard-core-visual" aria-label="五量智能研判核心"><div id="wallboardCoreBody" class="wallboard-core-body"></div></section><div class="wallboard-completeness"><div><span>五量数据完整率</span><strong>${completeness.toFixed(0)}%</strong></div><svg class="wallboard-completeness-track" viewBox="0 0 100 7" preserveAspectRatio="none" aria-hidden="true"><rect class="track" x="0" y="0" width="100" height="7" rx="3.5"></rect><rect class="value" x="0" y="0" width="${completeness.toFixed(2)}" height="7" rx="3.5"></rect></svg></div><div class="wallboard-focus-trend" aria-label="产量近期趋势">${sparkline(mine.trend || mine.production_trend || [], statusColor)}</div>`;
  renderWallboardCore(mine);
  focusBody.classList.remove("is-rotating");
  void focusBody.offsetWidth;
  focusBody.classList.add("is-rotating");
  $("wallboardFocusProgress").textContent = `${index + 1} / ${total} · 8 秒切换`;

  const pageStart = Math.floor(index / WALLBOARD_MINE_PAGE_SIZE) * WALLBOARD_MINE_PAGE_SIZE;
  const pageItems = orderedMines.slice(pageStart, pageStart + WALLBOARD_MINE_PAGE_SIZE);
  $("wallboardMinePage").textContent = `显示 ${pageStart + 1}—${pageStart + pageItems.length} / 共 ${total} 座`;
  $("wallboardMineRail").innerHTML = pageItems.map((item, offset) => {
    const itemStatus = wallboardEffectiveStatus(item);
    const [label, _color, tone] = statusInfo(itemStatus);
    const itemOpen = number(item.open_finding_count);
    const detail = itemOpen > 0 ? `${formatNumber(itemOpen)} 项未解除` : label;
    return `<div class="wallboard-mine-chip status-${tone} ${pageStart + offset === index ? "is-current" : ""}"><div><strong>${escapeHtml(item.mine_name || item.mine_id || "未命名煤矿")}</strong><i aria-hidden="true"></i></div><span>${escapeHtml(detail)}</span></div>`;
  }).join("");
}

function renderWallboard() {
  if (!state.wallboard.active) return;
  updateWallboardClock();
  renderWallboardHealth();
  const payload = state.overview || {};
  const counts = pickCounts(payload);
  const coverage = counts.expected ? Math.max(0, Math.min(100, counts.reported / counts.expected * 100)) : 0;
  $("wallboardMetricExpected").textContent = formatNumber(counts.expected);
  $("wallboardMetricReported").textContent = formatNumber(counts.reported);
  $("wallboardMetricCoverage").textContent = `覆盖率 ${coverage.toFixed(1)}%`;
  $("wallboardMetricNormal").textContent = formatNumber(counts.normal);
  const attentionMineCount = state.mines.filter((mine) => number(mine.open_finding_count) > 0 || wallboardEffectiveStatus(mine) === "risk").length;
  $("wallboardMetricRisk").textContent = formatNumber(attentionMineCount);
  $("wallboardMetricInsufficient").textContent = formatNumber(counts.insufficient);
  $("wallboardMetricAwaiting").textContent = formatNumber(counts.awaiting);
  $("wallboardCoverageValue").textContent = `${coverage.toFixed(1)}%`;
  $("wallboardCoverageArc").setAttribute("stroke-dasharray", `${coverage.toFixed(2)} 100`);

  const legacySeverity = payload.severity_counts || {};
  const attention = payload.attention_counts || {
    risk_findings: number(legacySeverity.high),
    data_to_complete: number(legacySeverity.medium),
    awaiting_enterprise_response: counts.awaiting,
    enterprise_responded_unresolved: 0,
    cleared_by_reanalysis: 0,
  };
  const riskFindings = number(attention.risk_findings);
  const dataToComplete = number(attention.data_to_complete);
  $("wallboardMetricRiskItems").textContent = `待核事项 ${formatNumber(riskFindings + dataToComplete)} 项`;
  $("wallboardRiskFindings").textContent = formatNumber(riskFindings);
  $("wallboardDataToComplete").textContent = formatNumber(dataToComplete);
  $("wallboardResponded").textContent = formatNumber(firstDefined(attention.enterprise_responded_unresolved, attention.explanation_recorded, 0));
  $("wallboardCleared").textContent = formatNumber(attention.cleared_by_reanalysis);
  const unreported = Math.max(0, counts.expected - counts.reported);
  $("wallboardStatusLegend").innerHTML = [
    ["暂未发现风险", counts.normal, "positive"],
    ["存在风险", counts.risk, "risk"],
    ["数据不足", counts.insufficient, "warning"],
    ["尚未报送", unreported, "neutral"],
  ].map(([label, value, tone]) => `<div class="wallboard-status-row status-${tone}"><i aria-hidden="true"></i><span>${label}</span><strong>${formatNumber(value)}</strong></div>`).join("");

  renderWallboardFocus();
  const latest = payload.latest_events || payload.events || [];
  const hasBusinessProjection = latest.some((item) => item && item.event_label);
  const activities = selectLeaderActivities(hasBusinessProjection ? latest : state.trace.length ? state.trace : latest).slice(0, 6);
  $("wallboardActivityList").innerHTML = activities.length ? activities.map((item) => {
    const presentation = activityPresentation(item);
    return `<li class="wallboard-activity-item activity-${presentation.tone}"><div><strong>${escapeHtml(presentation.mineName)}</strong><time>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</time></div><h3>${escapeHtml(humanizeBusinessText(item.event_label || presentation.title))}</h3><p>${escapeHtml(activitySummaryForDisplay(item, presentation))}</p></li>`;
  }).join("") : `<li class="wallboard-activity-item"><div><strong>辖区动态</strong></div><h3>暂无新的监管动态</h3><p>企业完成报送或风险状态发生变化后，将自动显示。</p></li>`;
}

function rotateWallboard() {
  if (!state.wallboard.active) return;
  const total = state.mines.length;
  state.wallboard.rotationIndex = total ? (state.wallboard.rotationIndex + 1) % total : 0;
  renderWallboardFocus();
}

function startWallboardTimers() {
  if (!state.wallboard.rotationTimer) state.wallboard.rotationTimer = window.setInterval(rotateWallboard, WALLBOARD_ROTATION_MS);
  if (!state.wallboard.clockTimer) state.wallboard.clockTimer = window.setInterval(updateWallboardClock, 1000);
}

function stopWallboardTimers() {
  if (state.wallboard.rotationTimer) window.clearInterval(state.wallboard.rotationTimer);
  if (state.wallboard.clockTimer) window.clearInterval(state.wallboard.clockTimer);
  state.wallboard.rotationTimer = null;
  state.wallboard.clockTimer = null;
}

function enterWallboard({updateUrl = true, requestFullscreen = false} = {}) {
  if (updateUrl) {
    const url = new URL(window.location.href);
    url.pathname = "/";
    url.searchParams.set("mode", "wallboard");
    window.history.pushState({}, "", `${url.pathname}${url.search}${url.hash}`);
  }
  state.wallboard.active = true;
  document.body.classList.add("wallboard-mode");
  $("wallboardView").classList.remove("hidden");
  renderWallboard();
  startWallboardTimers();
  if (requestFullscreen && !document.fullscreenElement && document.documentElement.requestFullscreen) {
    const request = document.documentElement.requestFullscreen();
    if (request && request.catch) request.catch(() => {});
  }
}

function exitWallboard({updateUrl = true, exitFullscreen = true} = {}) {
  state.wallboard.active = false;
  stopWallboardTimers();
  document.body.classList.remove("wallboard-mode");
  $("wallboardView").classList.add("hidden");
  if (updateUrl) window.history.pushState({}, "", "/");
  if (exitFullscreen && document.fullscreenElement && document.exitFullscreen) {
    const request = document.exitFullscreen();
    if (request && request.catch) request.catch(() => {});
  }
}

function switchView(name) {
  state.activeView = name;
  document.querySelectorAll(".view-tab").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  document.querySelectorAll("[data-view-panel]").forEach((panel) => panel.classList.toggle("active", panel.dataset.viewPanel === name));
  if (name === "trace" && state.principal) {
    if (!state.tracePage.initialized) initializeTrace();
    else if (!state.tracePage.asOf && !state.tracePage.loading) refreshAppliedTrace();
  }
}

async function refreshMineDetail(mineId) {
  const detail = await api(`/v2/regulatory/mines/${encodeURIComponent(mineId)}`);
  state.selectedMine = detail;
  renderMineDetail(detail);
}

async function openMine(mineId) {
  if (!mineId) return;
  switchView("mine");
  $("mineSelector").value = mineId;
  $("mineEmpty").classList.add("hidden");
  $("mineDetail").classList.remove("hidden");
  try {
    await refreshMineDetail(mineId);
  } catch (error) { showNotice(error.message); }
}

function renderMineDetail(detail) {
  const mine = detail.mine || detail;
  const analysis = detail.latest_analysis || detail.analysis || {};
  const status = statusInfo(analysis.status || mine.status);
  $("mineName").textContent = mine.mine_name || mine.mine_id || "—";
  const latestSubmission = detail.latest_submission || {};
  $("mineMeta").textContent = `${mine.mine_id || "—"} · 报表期 ${latestSubmission.report_month || mine.report_month || "—"} · 截至 ${formatTime(latestSubmission.data_as_of || mine.data_as_of)}`;
  const source = latestSubmission.source_disclosure || {};
  const sourceNotice = $("mineSourceNotice");
  if (source.demo) {
    const sourceHash = String(source.source_sha256 || "");
    const detailText = source.data_origin === "bundled_workbook_values"
      ? `${source.label || "ET样表原值"} · 空白未补数、日期未平移 · 单位与身份待核验${sourceHash ? ` · SHA ${sourceHash.slice(0, 12)}…` : ""}`
      : (source.label || "程序合成教学场景");
    sourceNotice.textContent = detailText;
    sourceNotice.classList.remove("hidden");
  } else {
    sourceNotice.textContent = "";
    sourceNotice.classList.add("hidden");
  }
  $("mineStatus").innerHTML = `<span class="status-pill status-${status[2]}">${escapeHtml(status[0])}</span>`;
  $("algorithmMeta").innerHTML = `<dt>算法版本</dt><dd>${escapeHtml(analysis.algorithm_version || "—")}</dd><dt>配置指纹</dt><dd title="${escapeHtml(analysis.configuration_sha256 || "")}">${escapeHtml((analysis.configuration_sha256 || "—").slice(0,16))}</dd><dt>协调求解</dt><dd>${escapeHtml(solverDisplay(analysis.solver_status || "—"))}</dd><dt>时序证据</dt><dd>${escapeHtml(humanizeBusinessText(analysis.temporal_status || (analysis.temporal && analysis.temporal.status) || "—"))}</dd><dt>同类矿样本</dt><dd>${formatNumber(analysis.peer_sample_count)}</dd><dt>参考候选</dt><dd>${analysis.baseline_reference_candidate === true ? "是" : analysis.baseline_reference_candidate === false ? "否" : "—"}</dd><dt>进入历史基线</dt><dd>${analysis.baseline_eligible === true ? "是" : analysis.baseline_eligible === false ? "否（结论仍独立留痕）" : "—"}</dd>`;
  const response = detail.response_summary || {};
  const findings = detail.findings || [];
  const responses = detail.responses || [];
  $("responseMeta").innerHTML = `<dt>开放风险</dt><dd>${formatNumber(firstDefined(response.open, findings.filter((x) => !["cleared_by_reanalysis"].includes(x.state)).length))}</dd><dt>已送达</dt><dd>${formatNumber(response.delivered)}</dd><dt>已回复</dt><dd>${formatNumber(firstDefined(response.replied, responses.length))}</dd><dt>最后回复</dt><dd>${escapeHtml(formatTime(response.last_response_at))}</dd>`;
  renderSeries(detail.daily_series || detail.series || []);
  renderMineFindings(detail.findings || []);
  renderTimeline(detail.timeline || detail.audit_events || []);
}

function renderSeries(rows) {
  const definitions = FIVE_QUANTITY_GROUPS.flatMap((group) => group.series);
  $("seriesLegend").innerHTML = FIVE_QUANTITY_GROUPS.map((group) => `
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
  const chartElement = $("seriesChart");
  if (!rows.length) { chartElement.innerHTML = `<div class="empty-state">暂无逐日五量数据</div>`; return; }
  const measuredWidth = Number(chartElement.clientWidth);
  const width = Math.max(760, Number.isFinite(measuredWidth) && measuredWidth > 0 ? Math.round(measuredWidth) : 1100);
  const left = 132, right = 78, top = 8, bottom = 38;
  const trackHeight = 62, trackGap = 8;
  const height = top + definitions.length * trackHeight + (definitions.length - 1) * trackGap + bottom;
  const plotWidth = width - left - right;
  const x = (index) => left + index / Math.max(1, rows.length - 1) * plotWidth;
  const own = (object, key) => object && Object.prototype.hasOwnProperty.call(object, key);
  const rawValue = (row, keys) => {
    for (const key of keys) {
      if (own(row, key)) return row[key];
      if (own(row && row.metrics, key)) return row.metrics[key];
    }
    return null;
  };
  const numericValue = (row, keys) => {
    const raw = rawValue(row, keys);
    if (raw === null || raw === undefined || raw === "") return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  };
  const trackBottom = top + definitions.length * trackHeight + (definitions.length - 1) * trackGap;
  let svg = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-labelledby="seriesChartTitle seriesChartDescription">`;
  svg += `<title id="seriesChartTitle">五量分轨趋势图</title><desc id="seriesChartDescription">五量分别展示走势；火工品量分为雷管和炸药两个子项，各轨道共用日期轴并按当前窗口缩放。</desc>`;
  const labelIndexes = [...new Set([0, Math.floor((rows.length-1)/2), rows.length-1])];
  svg += labelIndexes.map((index) => `<line class="date-grid" x1="${x(index)}" y1="${top}" x2="${x(index)}" y2="${trackBottom}"/>`).join("");
  definitions.forEach((definition, trackIndex) => {
    const {code, keys, label, trackLabel, legend, unit, color} = definition;
    const yTop = top + trackIndex * (trackHeight + trackGap);
    const yBottom = yTop + trackHeight;
    const yMiddle = (yTop + yBottom) / 2;
    const innerTop = yTop + 9;
    const innerBottom = yBottom - 9;
    const samples = rows.map((row) => numericValue(row, keys));
    const values = samples.filter((value) => value !== null);
    const min = values.length ? Math.min(...values) : null;
    const max = values.length ? Math.max(...values) : null;
    const constant = values.length > 0 && min === max;
    const y = (value) => constant ? yMiddle : innerBottom - (value-min)/(max-min)*(innerBottom-innerTop);
    svg += `<g class="series-track" data-series-code="${code}" data-track-index="${trackIndex}">`;
    svg += `<rect class="track-band" x="0" y="${yTop}" width="${width}" height="${trackHeight}" rx="6"/>`;
    svg += `<line class="track-midline" x1="${left}" y1="${yMiddle}" x2="${width-right}" y2="${yMiddle}"/>`;
    svg += `<line x1="${left-12}" y1="${yMiddle}" x2="${left-3}" y2="${yMiddle}" stroke="${color}" stroke-width="3" stroke-linecap="round"/>`;
    svg += `<text class="track-label" x="12" y="${yMiddle-2}">${escapeHtml(trackLabel || label)}</text>`;
    svg += `<text class="track-unit" x="12" y="${yMiddle+13}">${escapeHtml(unit || legend)}</text>`;
    if (!values.length) {
      svg += `<text class="track-state" x="${left+plotWidth/2}" y="${yMiddle+3}" text-anchor="middle">暂无数据</text></g>`;
      return;
    }
    if (constant) {
      svg += `<text class="track-range is-constant" x="${width-right+8}" y="${yMiddle+3}">恒定 ${formatNumber(min,2)}</text>`;
    } else {
      svg += `<text class="track-range" x="${width-right+8}" y="${innerTop+3}">${formatNumber(max,2)}</text>`;
      svg += `<text class="track-range" x="${width-right+8}" y="${innerBottom+3}">${formatNumber(min,2)}</text>`;
    }
    const segments = [];
    let segment = [];
    samples.forEach((value, index) => {
      if (value === null) {
        if (segment.length) segments.push(segment);
        segment = [];
        return;
      }
      segment.push({x:x(index), y:y(value), value, date:rows[index].date});
    });
    if (segment.length) segments.push(segment);
    segments.forEach((points, segmentIndex) => {
      if (points.length >= 2) {
        svg += `<polyline class="series-line${constant ? " is-constant" : ""}" data-series-code="${code}" data-segment-index="${segmentIndex}" data-constant="${constant}" stroke="${color}"${constant ? ' stroke-dasharray="7 4"' : ""} points="${points.map((point)=>`${point.x},${point.y}`).join(" ")}"/>`;
      }
      svg += points.map((point) => `<circle class="point" data-series-code="${code}" cx="${point.x}" cy="${point.y}" r="2.8" fill="${color}"><title>${escapeHtml(point.date || "")} ${label}: ${formatNumber(point.value,2)} ${escapeHtml(unit || legend)}</title></circle>`).join("");
    });
    svg += `</g>`;
  });
  svg += labelIndexes.map((index, position) => `<text class="axis-label" x="${x(index)}" y="${height-10}" text-anchor="${position === 0 ? "start" : position === labelIndexes.length-1 ? "end" : "middle"}">${escapeHtml((rows[index] && rows[index].date) || "")}</text>`).join("") + `</svg>`;
  chartElement.innerHTML = svg;
}

function findingCard(item) {
  const type = findingType(item);
  const [typeLabel,typeTone] = findingTypeInfo(type);
  const stateLabel = statusInfo(item.state || item.status);
  const evidence = item.evidence || item.facts || [];
  const evidenceText = (fact) => humanizeBusinessText(
    typeof fact === "string"
      ? fact
      : firstDefined(fact.description, fact.message, metricLabel(fact.metric), "相关业务证据"),
  );
  return `<article class="finding-card finding-type-${typeTone}" data-finding-type="${escapeHtml(type)}" data-state="${escapeHtml(item.state || item.status)}"><header><h3>${escapeHtml(humanizeBusinessText(item.title || item.code || "风险线索"))}</h3><span class="status-pill status-${typeTone}">${escapeHtml(typeLabel)}</span></header><p>${escapeHtml(findingSummaryForDisplay(item.summary || item.description || ""))}</p><div class="finding-meta"><span>${escapeHtml(item.mine_name || item.mine_id || "")}</span><span>${escapeHtml(findingCategoryLabel(item.category))}</span><span>${escapeHtml(formatTime(item.issued_at || item.created_at))}</span><span class="status-text-${stateLabel[2]}">${escapeHtml(stateLabel[0])}</span></div>${evidence.length ? `<div class="finding-evidence">${evidence.slice(0,3).map((fact) => `<p>• ${escapeHtml(evidenceText(fact))}</p>`).join("")}</div>` : ""}</article>`;
}

function renderMineFindings(items) { $("mineFindings").innerHTML = items.length ? items.map(findingCard).join("") : `<div class="empty-state">当前没有风险线索</div>`; }
function renderTimeline(items) { $("mineTimeline").innerHTML = items.length ? items.map((item) => { const presentation = activityPresentation(item); return `<li><strong>${escapeHtml(humanizeBusinessText(item.event_label || item.title || presentation.title))}</strong><p>${escapeHtml(activitySummaryForDisplay(item, presentation))}</p><time>${escapeHtml(formatTime(item.occurred_at || item.created_at))}</time></li>`; }).join("") : `<li><strong>暂无时间线记录</strong></li>`; }

function renderFindings() {
  const type = $("findingSeverity").value, findingState = $("findingState").value;
  const filtered = state.findings.filter((item) => (!type || findingType(item) === type) && (!findingState || (item.state || item.status) === findingState));
  $("findingLedger").innerHTML = filtered.length ? filtered.map(findingCard).join("") : `<div class="empty-state">没有符合筛选条件的风险记录</div>`;
}

function traceWindowForPreset(preset, now = new Date()) {
  const end = new Date(now);
  if (preset === "month") {
    const start = new Date(end.getFullYear(), end.getMonth(), 1, 0, 0, 0, 0);
    return {from:start.toISOString(), to:end.toISOString()};
  }
  const duration = TRACE_RANGE_DURATIONS[preset] || TRACE_RANGE_DURATIONS["7d"];
  return {from:new Date(end.getTime() - duration).toISOString(), to:end.toISOString()};
}

function localDateTimeInputValue(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60 * 1000);
  return local.toISOString().slice(0, 16);
}

function setTraceRangePreset(preset) {
  state.tracePage.rangePreset = preset;
  document.querySelectorAll("[data-trace-range]").forEach((button) => {
    button.classList.toggle("active", button.dataset.traceRange === preset);
  });
  $("traceCustomRange").classList.toggle("hidden", preset !== "custom");
  if (preset === "custom" && (!$("traceFrom").value || !$("traceTo").value)) {
    const windowRange = traceWindowForPreset("7d");
    $("traceFrom").value = localDateTimeInputValue(windowRange.from);
    $("traceTo").value = localDateTimeInputValue(windowRange.to);
  }
}

function readTraceFilters() {
  const preset = state.tracePage.rangePreset;
  let windowRange;
  if (preset === "custom") {
    const from = new Date($("traceFrom").value);
    const to = new Date($("traceTo").value);
    if (!$("traceFrom").value || !$("traceTo").value || Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
      throw new Error("请选择完整的自定义开始和结束时间");
    }
    if (from >= to) throw new Error("自定义结束时间必须晚于开始时间");
    windowRange = {from:from.toISOString(), to:to.toISOString()};
  } else {
    windowRange = traceWindowForPreset(preset);
  }
  return {
    rangePreset: preset,
    from: windowRange.from,
    to: windowRange.to,
    mineId: $("traceMineFilter").value,
    eventGroup: $("traceEventGroup").value,
    view: $("traceViewMode").value || "business",
  };
}

function rollingTraceFilters(filters) {
  if (!filters || filters.rangePreset === "custom") return filters;
  return {...filters, ...traceWindowForPreset(filters.rangePreset)};
}

function traceEndpoint(path, filters, options = {}) {
  const pairs = [
    ["from", filters.from],
    ["to", filters.to],
    ["mine_id", filters.mineId],
    ["event_group", filters.eventGroup],
    ["view", filters.view || "business"],
  ];
  if (options.limit !== undefined) pairs.push(["limit", String(options.limit)]);
  if (options.cursor !== undefined && options.cursor !== null && options.cursor !== "") pairs.push(["cursor", String(options.cursor)]);
  const query = pairs
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
  return `${path}?${query}`;
}

function renderTraceMineOptions() {
  const select = $("traceMineFilter");
  const current = select.value;
  select.innerHTML = `<option value="">全部可见煤矿</option>` + state.mines.map((mine) =>
    `<option value="${escapeHtml(mine.mine_id)}">${escapeHtml(mine.mine_name || mine.mine_id)}</option>`,
  ).join("");
  if (state.mines.some((mine) => mine.mine_id === current)) select.value = current;
}

function formatTraceTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("zh-CN", {
    year:"numeric", month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit", hour12:false,
  }).format(date);
}

function renderTraceNewRecordsNotice() {
  const page = state.tracePage;
  const newRecords = $("traceNewRecords");
  newRecords.classList.toggle("hidden", page.pendingCount < 1);
  newRecords.textContent = page.pendingCount > 0
    ? `有 ${formatNumber(page.pendingCount)} 条新的交换留痕，点击查看`
    : "";
}

function renderTrace() {
  const page = state.tracePage;
  if (page.loading && !state.trace.length) {
    $("traceTableBody").innerHTML = `<tr><td class="trace-empty-cell" colspan="7">正在读取交换留痕…</td></tr>`;
  } else {
    $("traceTableBody").innerHTML = state.trace.length ? state.trace.map((item) => {
      const presentation = activityPresentation(item);
      const correlation = String(firstDefined(item.correlation_id, item.message_id, "—"));
      const sequence = firstDefined(item.sequence, item.trace_sequence, item.audit_sequence, "—");
      return `<tr data-trace-id="${escapeHtml(traceIdentity(item))}"><td data-label="时间">${escapeHtml(formatTraceTime(item.occurred_at || item.created_at))}</td><td data-label="煤矿" class="mine-cell"><strong>${escapeHtml(item.mine_name || presentation.mineName || "—")}</strong><small>${escapeHtml(item.mine_id || "")}</small></td><td data-label="业务环节">${escapeHtml(traceEventGroupLabel(item))}</td><td data-label="事件">${escapeHtml(humanizeBusinessText(item.event_label || presentation.title))}</td><td data-label="关联编号" class="trace-correlation" title="${escapeHtml(correlation)}">${escapeHtml(correlation)}</td><td data-label="摘要" class="trace-summary-cell">${escapeHtml(activitySummaryForDisplay(item, presentation))}</td><td data-label="留痕序号" class="trace-sequence">${escapeHtml(sequence)}</td></tr>`;
    }).join("") : `<tr><td class="trace-empty-cell" colspan="7">当前筛选范围内暂无交换留痕</td></tr>`;
  }

  $("traceResultCount").textContent = `当前显示 ${formatNumber(state.trace.length)} / 共 ${formatNumber(page.matchedCount)} 条`;
  $("traceDataAsOf").textContent = page.asOf ? `数据截至 ${formatTraceTime(page.asOf)}` : "尚未加载";
  const integrity = $("traceIntegrity");
  const integrityValid = page.integrity && page.integrity.valid;
  integrity.className = `status-pill status-${integrityValid === true ? "positive" : integrityValid === false ? "risk" : "neutral"}`;
  integrity.textContent = integrityValid === true
    ? "完整留痕链校验通过"
    : integrityValid === false ? "完整留痕链校验异常" : "完整留痕链待校验";
  if (page.integrity && page.integrity.checked_at) {
    integrity.title = `校验时间 ${formatTraceTime(page.integrity.checked_at)}`;
  } else {
    integrity.title = "";
  }

  const loadMore = $("traceLoadMoreButton");
  loadMore.classList.toggle("hidden", !page.hasMore);
  loadMore.disabled = page.loading;
  loadMore.textContent = page.loading && state.trace.length ? "正在加载…" : "加载更早 20 条";
  renderTraceNewRecordsNotice();
}

async function loadTrace({reset = false} = {}) {
  const page = state.tracePage;
  if (!page.appliedFilters || (page.loading && !reset)) return;
  const requestSerial = ++page.requestSerial;
  page.loading = true;
  if (reset) {
    state.trace = [];
    page.matchedCount = 0;
    page.hasMore = false;
    page.nextCursor = null;
  }
  renderTrace();
  try {
    const endpoint = traceEndpoint("/v2/regulatory/exchanges", page.appliedFilters, {
      limit: TRACE_PAGE_SIZE,
      cursor: reset ? null : page.nextCursor,
    });
    const payload = await api(endpoint);
    if (requestSerial !== page.requestSerial) return;
    const incoming = payload.items || payload.events || [];
    if (reset) {
      state.trace = incoming;
    } else {
      const seen = new Set(state.trace.map(traceIdentity));
      state.trace = state.trace.concat(incoming.filter((item) => !seen.has(traceIdentity(item))));
    }
    page.matchedCount = number(firstDefined(payload.matched_count, payload.total, state.trace.length));
    page.hasMore = payload.has_more === true;
    page.nextCursor = firstDefined(payload.next_cursor, null);
    page.asOf = firstDefined(payload.as_of, page.asOf);
    page.integrity = firstDefined(payload.integrity, page.integrity);
    page.newestIdentity = state.trace.length ? traceIdentity(state.trace[0]) : null;
    if (reset) page.pendingCount = 0;
  } catch (error) {
    showNotice(error.message);
  } finally {
    if (requestSerial === page.requestSerial) page.loading = false;
    renderTrace();
  }
}

async function applyTraceFilters() {
  try {
    state.tracePage.appliedFilters = readTraceFilters();
    state.tracePage.pendingCount = 0;
    await loadTrace({reset:true});
  } catch (error) {
    showNotice(error.message);
  }
}

async function refreshAppliedTrace() {
  if (!state.tracePage.appliedFilters) return;
  state.tracePage.appliedFilters = rollingTraceFilters(state.tracePage.appliedFilters);
  await loadTrace({reset:true});
}

async function checkTraceUpdates() {
  const page = state.tracePage;
  if (state.activeView !== "trace" || !page.initialized || !page.appliedFilters || page.loading) return;
  try {
    const filters = rollingTraceFilters(page.appliedFilters);
    const payload = await api(traceEndpoint("/v2/regulatory/exchanges", filters, {limit:1}));
    const incoming = payload.items || payload.events || [];
    const newest = incoming.length ? traceIdentity(incoming[0]) : null;
    const matchedCount = number(firstDefined(payload.matched_count, payload.total, incoming.length));
    const currentContainsNewest = newest && state.trace.some((item) => traceIdentity(item) === newest);
    if (newest && !currentContainsNewest) {
      page.pendingCount = Math.max(1, matchedCount - page.matchedCount);
      // Only reveal the notice; do not replace rows, scroll position or selection.
      renderTraceNewRecordsNotice();
    }
  } catch (_) {
    // Background polling must not replace the current table or interrupt reading.
  }
}

async function resetTraceFilters() {
  $("traceMineFilter").value = "";
  $("traceEventGroup").value = "";
  $("traceViewMode").value = "business";
  $("traceFrom").value = "";
  $("traceTo").value = "";
  setTraceRangePreset("7d");
  await applyTraceFilters();
}

async function initializeTrace() {
  if (state.tracePage.initialized) return;
  state.tracePage.initialized = true;
  renderTraceMineOptions();
  setTraceRangePreset("7d");
  await applyTraceFilters();
}

function traceExportFilename(response) {
  const disposition = response.headers.get("content-disposition") || "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (encoded) {
    try { return decodeURIComponent(encoded[1].replace(/^"|"$/g, "")); } catch (_) {}
  }
  const plain = disposition.match(/filename="?([^";]+)"?/i);
  if (plain) return plain[1];
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return `MineGuard_双系统交换留痕_${stamp}.csv`;
}

async function exportTrace() {
  const page = state.tracePage;
  if (!page.appliedFilters || page.exporting) return;
  const button = $("traceExportButton");
  page.exporting = true;
  button.disabled = true;
  button.textContent = "正在生成导出文件…";
  try {
    const response = await fetch(
      traceEndpoint("/v2/regulatory/exchanges/export.csv", page.appliedFilters),
      {headers:{Accept:"text/csv"}, credentials:"same-origin"},
    );
    if (response.status === 401) {
      state.principal = null;
      resetTraceSessionState();
      showLogin();
      throw new Error("请重新登录");
    }
    if (!response.ok) {
      const contentType = response.headers.get("content-type") || "";
      const payload = contentType.includes("application/json") ? await response.json() : null;
      throw new Error((payload && payload.error && payload.error.message) || (payload && payload.message) || `导出失败（${response.status}）`);
    }
    const blob = await response.blob();
    const downloadUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = downloadUrl;
    anchor.download = traceExportFilename(response);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
  } catch (error) {
    showNotice(error.message);
  } finally {
    page.exporting = false;
    button.disabled = false;
    button.textContent = "导出当前筛选";
  }
}

async function refreshAll({automatic = false} = {}) {
  if (!state.principal || state.refreshing) return;
  state.refreshing = true;
  $("refreshButton").disabled = true;
  try {
    const [overview, mines, findings] = await Promise.all([
      api("/v2/regulatory/overview"), api("/v2/regulatory/mines"), api("/v2/regulatory/findings?limit=200"),
    ]);
    state.overview = overview;
    state.mines = mines.items || mines.mines || [];
    state.findings = findings.items || findings.findings || [];
    renderOverview(overview); renderMines(); renderMineSelector(); renderFindings();
    renderTraceMineOptions();
    if (state.activeView === "trace") {
      if (!state.tracePage.initialized) await initializeTrace();
      else if (automatic) await checkTraceUpdates();
      else await refreshAppliedTrace();
    }
    const selectedMineId = state.selectedMine && state.selectedMine.mine && state.selectedMine.mine.mine_id;
    if (state.activeView === "mine" && selectedMineId) await refreshMineDetail(selectedMineId);
    state.wallboard.updateFailed = false;
    state.wallboard.lastError = null;
    renderWallboard();
    showNotice("");
  } catch (error) {
    state.wallboard.updateFailed = true;
    state.wallboard.lastError = error.message;
    renderWallboardHealth();
    showNotice(error.message);
  }
  finally {
    state.refreshing = false;
    $("refreshButton").disabled = false;
    document.querySelector("#app").setAttribute("aria-busy", "false");
  }
}

function bindEvents() {
  $("loginForm").addEventListener("submit", login);
  $("logoutButton").addEventListener("click", logout);
  $("refreshButton").addEventListener("click", () => refreshAll());
  $("fullscreenButton").addEventListener("click", () => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen());
  $("wallboardButton").addEventListener("click", () => enterWallboard({requestFullscreen:true}));
  $("wallboardExitButton").addEventListener("click", () => exitWallboard());
  $("mineSearch").addEventListener("input", renderMines);
  $("mineSelector").addEventListener("change", (event) => openMine(event.target.value));
  $("findingSeverity").addEventListener("change", renderFindings);
  $("findingState").addEventListener("change", renderFindings);
  $("traceRangePresets").querySelectorAll("[data-trace-range]").forEach((button) => {
    button.addEventListener("click", () => setTraceRangePreset(button.dataset.traceRange));
  });
  $("traceApplyButton").addEventListener("click", applyTraceFilters);
  $("traceClearButton").addEventListener("click", resetTraceFilters);
  $("traceLoadMoreButton").addEventListener("click", () => loadTrace());
  $("traceNewRecords").addEventListener("click", refreshAppliedTrace);
  $("traceExportButton").addEventListener("click", exportTrace);
  $("openFindingsButton").addEventListener("click", () => switchView("findings"));
  document.querySelectorAll(".view-tab").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.wallboard.active) exitWallboard();
  });
  window.addEventListener("popstate", () => {
    if (isWallboardRequested()) enterWallboard({updateUrl:false});
    else if (state.wallboard.active) exitWallboard({updateUrl:false});
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  if (isWallboardRequested()) enterWallboard({updateUrl:false});
  if (await recoverSession()) await refreshAll();
  state.refreshTimer = window.setInterval(() => refreshAll({automatic:true}), 10000);
});
