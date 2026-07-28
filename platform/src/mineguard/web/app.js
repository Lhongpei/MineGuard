"use strict";

const API_PATHS = {
  production: "/v1/analyze/production",
  personnel: "/v1/analyze/personnel",
};

const SUPERVISION_API_PATHS = {
  csrf: "/v1/auth/csrf",
  login: "/v1/auth/login",
  logout: "/v1/auth/logout",
  overview: "/v1/dashboard/overview",
  trends: "/v1/dashboard/trends?days=30",
  temporal: "/v1/dashboard/temporal?days=90",
  batchProduction: "/v1/analyze/production/batch",
  batches: "/v1/analysis-batches",
  isolatePilotBatches: "/v1/admin/analysis-batches/isolate-pilots",
  cases: "/v1/cases",
  jobs: "/v1/analysis-jobs",
  users: "/v1/admin/users",
  readiness: "/ready",
  backups: "/v1/admin/backups",
  legitimateScenarios: "/v1/admin/legitimate-scenarios",
};

const WORKSPACE_NAMES = ["overview", "cases", "jobs", "tools", "admin"];

const ROLE_LABELS = {
  admin: "系统管理员",
  supervisor: "监管负责人",
  reviewer: "复核人员",
  viewer: "查阅人员",
};

const JOB_STATUS_LABELS = {
  queued: "排队中",
  running: "运行中",
  succeeded: "全部完成",
  partial_failed: "部分窗口失败",
  failed: "任务失败",
  cancelled: "已取消",
};

const READINESS_STATUS_LABELS = {
  ready: "系统可用",
  degraded: "部分能力受影响",
  not_ready: "系统尚未就绪",
};

const REFERENCE_LABEL_LABELS = {
  verified_normal: "已核实为正常",
  legitimate_exception: "已核实为合法例外",
  confirmed_data_error: "确认存在数据错误",
  confirmed_technical_anomaly: "确认存在技术异常",
  adjudicated_violation: "已依法认定违规",
  unresolved: "尚未解决 / 继续核查",
};

const FUSION_AGREEMENT_LABELS = {
  corroborated: "多路证据相互印证",
  physical_only: "仅物理关系提示",
  historical_only: "仅辅助证据提示",
  no_signal: "各路均未提示异常",
  insufficient: "证据不足，不能判断",
};

const FUSION_REASON_LABELS = {
  data_quality_blocked: "数据质量存在阻断项，必须先补数。",
  data_quality_degraded: "数据质量下降，辅助排序需谨慎使用。",
  physical_diagnostics_incomplete: "物理诊断尚不完整，不能支持最高优先级。",
  historical_evidence_insufficient: "可比且经人工核实的历史样本不足。",
  historical_observation_within_baseline: "当前特征落在同条件历史基线范围内。",
  historical_rarity_explained_by_legitimate_scenario:
    "历史罕见性可由已登记合法情景解释，但物理冲突仍保留。",
  historical_observation_rare: "当前特征相对同条件历史记录较罕见。",
  temporal_evidence_insufficient: "时序历史不足，尚不能判断长期变化。",
  temporal_observation_normal: "时序监测未提示显著变化。",
  temporal_observation_anomalous: "时序监测提示持续或突变异常。",
  independent_secondary_signal_corroborates_conflict:
    "独立的历史或时序信号对物理冲突形成印证。",
  physical_conflict_not_independently_corroborated:
    "当前冲突来自物理关系，尚无独立辅助信号印证。",
  secondary_signal_requires_shadow_review:
    "辅助信号建议进入影子复核队列，不直接改变正式结论。",
  no_unexplained_review_signal: "当前没有未解释的辅助复核信号。",
  evidence_insufficient_for_agreement_assessment:
    "证据不足，无法判断各路证据是否一致。",
  original_physically_authorised_p1_preserved:
    "原有 P1 有完整物理证据支撑，予以保留。",
  p1_rejected_by_physical_safeguards:
    "物理证据条件不足，影子排序不采用 P1。",
  original_data_priority_preserved: "原有补数优先级保持不变。",
  physical_conflict_applies_p2_priority_floor:
    "存在物理冲突时，影子排序至少为一般复核。",
  secondary_signal_does_not_promote_p2_to_p1:
    "辅助信号只能印证，不能把 P2 自动提升为 P1。",
};

const METRIC_LABELS = {
  "coal.reported_output_t": "上报原煤产量",
  "coal.main_transport_t": "主运输皮带量",
  "wash.feed_t": "入洗原煤量",
  "sales.raw_shipped_t": "原煤外销量",
  "inventory.raw_change_t": "原煤库存变化",
};

const SOURCE_LABELS = {
  production_report: "生产上报",
  main_belt: "主运输皮带",
  wash_meter: "洗煤计量",
  sales_ledger: "销售台账",
  stock_survey: "库存盘点",
};

const BLOCKING_FLAG_LABELS = {
  clock_unsynchronized: "设备时钟不同步",
  missing_raw_data: "缺少原始数据",
  duplicate_record: "存在重复记录",
  device_fault: "设备状态异常",
  calibration_expired: "检定或校准已过期",
  lineage_missing: "数据来源链不完整",
};

const PRODUCTION_RISK_SAMPLE = {
  mine_id: "M001",
  window_start: "2026-07-20T00:00:00+08:00",
  window_end: "2026-07-21T00:00:00+08:00",
  observations: [
    {
      observation_id: "production-report-20260720",
      metric_code: "coal.reported_output_t",
      value: 5000,
      tolerance_abs: 100,
      source_group: "production_report",
      source_reliability: 0.6,
    },
    {
      observation_id: "main-belt-20260720",
      metric_code: "coal.main_transport_t",
      value: 7100,
      tolerance_abs: 106.5,
      source_group: "main_belt",
      source_reliability: 1,
    },
    {
      observation_id: "wash-feed-20260720",
      metric_code: "wash.feed_t",
      value: 6800,
      tolerance_abs: 136,
      source_group: "wash_meter",
      source_reliability: 1,
    },
    {
      observation_id: "raw-sales-20260720",
      metric_code: "sales.raw_shipped_t",
      value: 0,
      tolerance_abs: 1,
      source_group: "sales_ledger",
      source_reliability: 1,
    },
    {
      observation_id: "raw-stock-change-20260720",
      metric_code: "inventory.raw_change_t",
      value: 250,
      tolerance_abs: 100,
      source_group: "stock_survey",
      source_reliability: 1,
    },
  ],
  parameters: {
    transport_balance_tolerance: 0,
    stock_balance_tolerance: 0,
    transport_slack_penalty: 100,
    stock_slack_penalty: 100,
    max_mcs: 5,
    max_relaxed_groups: 3,
    quality_gate: 60,
  },
};

const PRODUCTION_NORMAL_SAMPLE = {
  mine_id: "M002",
  window_start: "2026-07-20T00:00:00+08:00",
  window_end: "2026-07-21T00:00:00+08:00",
  observations: [
    {
      observation_id: "production-report",
      metric_code: "coal.reported_output_t",
      value: 7050,
      tolerance_abs: 100,
      source_group: "production_report",
    },
    {
      observation_id: "main-belt",
      metric_code: "coal.main_transport_t",
      value: 7100,
      tolerance_abs: 106.5,
      source_group: "main_belt",
    },
    {
      observation_id: "wash-feed",
      metric_code: "wash.feed_t",
      value: 6800,
      tolerance_abs: 136,
      source_group: "wash_meter",
    },
    {
      observation_id: "raw-sales",
      metric_code: "sales.raw_shipped_t",
      value: 0,
      tolerance_abs: 1,
      source_group: "sales_ledger",
    },
    {
      observation_id: "raw-stock-change",
      metric_code: "inventory.raw_change_t",
      value: 250,
      tolerance_abs: 100,
      source_group: "stock_survey",
    },
  ],
};

const PERSONNEL_RISK_SAMPLE = {
  session_id: "GATE-A-entry-20260720T080000",
  faces: [
    {
      face_track_id: "face-001",
      event_time: "2026-07-20T08:00:01+08:00",
      candidate_person_id: "P001",
      match_probability: 0.97,
      direction: "entry",
    },
    {
      face_track_id: "face-002",
      event_time: "2026-07-20T08:00:06+08:00",
      candidate_person_id: "P009",
      match_probability: 0.94,
      direction: "entry",
    },
    {
      face_track_id: "face-003",
      event_time: "2026-07-20T08:00:12+08:00",
      candidate_person_id: "P003",
      match_probability: 0.91,
      direction: "entry",
    },
  ],
  cards: [
    {
      card_event_id: "card-event-001",
      card_id: "CARD-001",
      bound_person_id: "P001",
      event_time: "2026-07-20T08:00:02+08:00",
      direction: "entry",
    },
    {
      card_event_id: "card-event-002",
      card_id: "CARD-002",
      bound_person_id: "P002",
      event_time: "2026-07-20T08:00:07+08:00",
      direction: "entry",
    },
  ],
  max_time_delta_seconds: 30,
  unmatched_face_cost: 1.1,
  unmatched_card_cost: 1.1,
  mismatch_penalty: 1,
};

const PERSONNEL_NORMAL_SAMPLE = {
  session_id: "GATE-A-entry-20260720T090000",
  faces: [
    {
      face_track_id: "face-101",
      event_time: "2026-07-20T09:00:01+08:00",
      candidate_person_id: "P101",
      match_probability: 0.98,
      direction: "entry",
    },
    {
      face_track_id: "face-102",
      event_time: "2026-07-20T09:00:05+08:00",
      candidate_person_id: "P102",
      match_probability: 0.96,
      direction: "entry",
    },
  ],
  cards: [
    {
      card_event_id: "card-event-101",
      card_id: "CARD-101",
      bound_person_id: "P101",
      event_time: "2026-07-20T09:00:02+08:00",
      direction: "entry",
    },
    {
      card_event_id: "card-event-102",
      card_id: "CARD-102",
      bound_person_id: "P102",
      event_time: "2026-07-20T09:00:06+08:00",
      direction: "entry",
    },
  ],
  max_time_delta_seconds: 30,
  unmatched_face_cost: 1.1,
  unmatched_card_cost: 1.1,
  mismatch_penalty: 1,
};

const state = {
  authInitialized: false,
  authEnabled: false,
  principal: null,
  csrfToken: null,
  workspace: "overview",
  mode: "production",
  datasetName: "",
  currentInput: null,
  lastResult: null,
  lastResultMode: null,
  isRunning: false,
  overviewLoading: false,
  overviewLoaded: false,
  overview: null,
  overviewItems: [],
  trendsLoading: false,
  trendsLoaded: false,
  analytics: null,
  temporalLoading: false,
  temporalLoaded: false,
  temporalDashboard: null,
  casesLoading: false,
  casesLoaded: false,
  showArchivedCases: false,
  cases: [],
  currentCaseId: null,
  currentCaseVersion: null,
  currentCaseDetail: null,
  currentCaseResponse: null,
  currentReferenceLabels: null,
  currentReferenceLabelsError: null,
  referenceLabelRunning: false,
  overviewReferenceLabelRunId: null,
  overviewReferenceLabelItem: null,
  overviewReferenceLabels: null,
  overviewReferenceLabelError: null,
  overviewReferenceLabelRunning: false,
  caseActionRunning: false,
  currentEvidenceBundle: null,
  evidenceRunning: false,
  jobsLoading: false,
  jobsLoaded: false,
  showArchivedJobs: false,
  jobs: [],
  currentJob: null,
  jobPollTimer: null,
  usersLoading: false,
  usersLoaded: false,
  users: [],
  editingUsername: null,
  batchesLoading: false,
  batchesLoaded: false,
  showInvalidatedBatches: false,
  batches: [],
  operationsLoading: false,
  operationsLoaded: false,
  readiness: null,
  backups: [],
  legitimateScenariosLoading: false,
  legitimateScenariosLoaded: false,
  legitimateScenarios: [],
};

const elements = {};
let pendingConfirmation = null;

document.addEventListener("DOMContentLoaded", () => {
  cacheElements();
  bindEvents();
  setMode("production");
  setWorkspace("overview", false);
  checkService();
  initializeAuthentication();
});

function cacheElements() {
  [
    "service-dot",
    "service-text",
    "auth-gate",
    "auth-checking",
    "login-panel",
    "login-form",
    "login-username",
    "login-password",
    "login-status",
    "login-submit",
    "scope-summary",
    "principal-summary",
    "principal-name",
    "principal-role",
    "principal-scopes",
    "logout-button",
    "overview-workspace-tab",
    "cases-workspace-tab",
    "jobs-workspace-tab",
    "tools-workspace-tab",
    "admin-workspace-tab",
    "overview-workspace",
    "cases-workspace",
    "jobs-workspace",
    "tools-workspace",
    "admin-workspace",
    "nav-open-case-count",
    "nav-running-job-count",
    "refresh-overview",
    "overview-status",
    "overview-empty",
    "overview-empty-message",
    "load-pilot-overview",
    "retry-overview",
    "overview-content",
    "overview-portfolio-name",
    "overview-batch-id",
    "overview-generated-at",
    "overview-trial-badge",
    "overview-kpi-grid",
    "coverage-callout",
    "coverage-title",
    "coverage-explanation",
    "coverage-meter-fill",
    "refresh-trends",
    "trends-status",
    "trends-content",
    "trends-empty",
    "trend-executive-summary",
    "trend-kpi-grid",
    "daily-trend-chart",
    "mine-risk-ranking",
    "mine-ranking-empty",
    "repeated-anomaly-list",
    "analytics-quality-list",
    "temporal-health-card",
    "temporal-status-badge",
    "temporal-status",
    "temporal-content",
    "temporal-summary",
    "temporal-kpi-grid",
    "temporal-episode-list",
    "temporal-episode-empty",
    "view-all-cases",
    "overview-search",
    "overview-focus-filter",
    "overview-priority-body",
    "overview-queue-empty",
    "case-list-view",
    "refresh-cases",
    "case-search",
    "case-priority-filter",
    "case-technical-filter",
    "case-workflow-filter",
    "show-archived-cases",
    "cases-status",
    "cases-empty",
    "cases-empty-message",
    "retry-cases",
    "cases-table-content",
    "case-table-body",
    "cases-filter-empty",
    "case-detail-view",
    "back-to-cases",
    "download-case",
    "print-case",
    "case-detail-loading",
    "case-detail-content",
    "case-detail-id",
    "case-detail-title",
    "case-detail-period",
    "case-priority-badge",
    "case-technical-badge",
    "case-workflow-badge",
    "case-plain-summary",
    "case-facts",
    "case-recommended-checks",
    "case-evidence-list",
    "case-evidence-empty",
    "case-event-count",
    "case-timeline",
    "case-evidence-grade",
    "case-evidence-grade-note",
    "case-hash-status",
    "case-trace-fields",
    "case-historical-panel",
    "case-historical-status",
    "case-historical-summary",
    "case-historical-facts",
    "case-historical-scenarios",
    "case-fusion-panel",
    "case-fusion-agreement",
    "case-fusion-summary",
    "case-fusion-facts",
    "case-fusion-reasons",
    "evidence-bundle-card",
    "generate-evidence",
    "evidence-bundle-status",
    "evidence-bundle-result",
    "evidence-verification",
    "evidence-bundle-fields",
    "evidence-bundle-actions",
    "reference-label-card",
    "reference-label-status",
    "reference-label-current",
    "reference-label-history-details",
    "reference-label-history",
    "reference-label-form",
    "reference-label-expected-sequence",
    "reference-label-value",
    "reference-label-scenario-wrap",
    "reference-label-scenario",
    "reference-label-note",
    "submit-reference-label",
    "reference-label-readonly-note",
    "case-action-card",
    "case-action-form",
    "case-action",
    "case-assignee",
    "case-disposition",
    "case-action-note",
    "case-action-status",
    "submit-case-action",
    "submit-pilot-job",
    "submit-pilot-job-empty",
    "refresh-jobs",
    "show-archived-jobs",
    "retry-jobs",
    "jobs-status",
    "jobs-empty",
    "jobs-empty-message",
    "jobs-content",
    "jobs-summary-grid",
    "jobs-table-body",
    "job-detail",
    "back-to-jobs",
    "refresh-job-detail",
    "job-detail-id",
    "job-detail-title",
    "job-detail-meta",
    "job-detail-status",
    "job-progress-title",
    "job-progress-counts",
    "job-progress-bar",
    "job-progress-fill",
    "job-detail-actions",
    "job-window-body",
    "refresh-users",
    "refresh-admin",
    "refresh-batches",
    "show-invalidated-batches",
    "isolate-pilot-batches",
    "batches-status",
    "batches-table-wrap",
    "batches-table-body",
    "batches-empty",
    "refresh-operations",
    "operations-status",
    "readiness-overall",
    "readiness-summary",
    "readiness-checks",
    "backup-create-form",
    "backup-id",
    "create-backup-submit",
    "backup-action-status",
    "backups-table-body",
    "refresh-legitimate-scenarios",
    "legitimate-scenarios-status",
    "legitimate-scenarios-table-wrap",
    "legitimate-scenarios-table-body",
    "legitimate-scenarios-empty",
    "legitimate-scenario-form",
    "scenario-id",
    "scenario-version",
    "scenario-name",
    "scenario-description",
    "scenario-mine-ids",
    "scenario-regime",
    "scenario-shift",
    "scenario-season",
    "scenario-maintenance",
    "scenario-event-codes",
    "scenario-required-tags",
    "scenario-feature-bounds",
    "scenario-active",
    "legitimate-scenario-form-status",
    "submit-legitimate-scenario",
    "overview-reference-label-dialog",
    "overview-reference-label-title",
    "overview-reference-label-context",
    "close-overview-reference-label",
    "overview-reference-label-status",
    "overview-reference-label-current",
    "overview-reference-label-history-details",
    "overview-reference-label-history",
    "overview-reference-label-form",
    "overview-reference-label-expected-sequence",
    "overview-reference-label-value",
    "overview-reference-label-scenario-wrap",
    "overview-reference-label-scenario",
    "overview-reference-label-note",
    "submit-overview-reference-label",
    "overview-reference-label-readonly-note",
    "users-status",
    "users-table-wrap",
    "users-table-body",
    "users-empty",
    "user-create-form",
    "new-user-username",
    "new-user-password",
    "new-user-role",
    "new-user-scopes",
    "user-create-status",
    "create-user-submit",
    "user-username-wrap",
    "user-password-wrap",
    "cancel-user-edit",
    "action-confirm-dialog",
    "action-confirm-form",
    "action-confirm-title",
    "action-confirm-message",
    "action-confirm-input-wrap",
    "action-confirm-input-label",
    "action-confirm-input",
    "action-confirm-input-help",
    "action-confirm-error",
    "action-confirm-cancel",
    "action-confirm-submit",
    "production-tab",
    "personnel-tab",
    "input-panel",
    "mode-description",
    "load-risk-sample",
    "load-normal-sample",
    "upload-button",
    "clear-analysis",
    "file-input",
    "dataset-card",
    "dataset-name",
    "dataset-summary",
    "dataset-state",
    "json-editor",
    "request-status",
    "analyze-button",
    "analyze-button-text",
    "empty-state",
    "result-section",
    "result-title",
    "result-time",
    "download-button",
    "print-button",
    "decision-banner",
    "decision-symbol",
    "decision-level",
    "decision-title",
    "decision-summary",
    "priority-text",
    "kpi-grid",
    "finding-list",
    "action-list",
    "evidence-card",
    "source-list",
    "evidence-explanation",
    "metric-section",
    "metric-table-body",
    "conflict-section",
    "conflict-table-body",
    "personnel-detail-section",
    "personnel-table-body",
    "assumption-section",
    "assumption-list",
    "raw-output",
  ].forEach((id) => {
    elements[id] = document.getElementById(id);
  });
}

function bindEvents() {
  elements["login-form"].addEventListener("submit", submitLogin);
  elements["logout-button"].addEventListener("click", logout);
  WORKSPACE_NAMES.forEach((workspace) => {
    const tab = elements[`${workspace}-workspace-tab`];
    tab.addEventListener("click", () => setWorkspace(workspace));
    tab.addEventListener("keydown", handleWorkspaceKeydown);
  });
  elements["refresh-overview"].addEventListener("click", loadOverview);
  elements["refresh-trends"].addEventListener("click", refreshTrendWorkspace);
  elements["retry-overview"].addEventListener("click", loadOverview);
  elements["load-pilot-overview"].addEventListener("click", loadPilotOverview);
  elements["view-all-cases"].addEventListener("click", () => setWorkspace("cases"));
  elements["overview-search"].addEventListener("input", renderOverviewQueue);
  elements["overview-focus-filter"].addEventListener(
    "change",
    renderOverviewQueue,
  );
  elements["refresh-cases"].addEventListener("click", loadCases);
  elements["retry-cases"].addEventListener("click", loadCases);
  elements["show-archived-cases"].addEventListener("change", () => {
    state.showArchivedCases = elements["show-archived-cases"].checked;
    state.casesLoaded = false;
    loadCases();
  });
  [
    "case-search",
    "case-priority-filter",
    "case-technical-filter",
    "case-workflow-filter",
  ].forEach((id) => {
    elements[id].addEventListener(
      id === "case-search" ? "input" : "change",
      renderCaseTable,
    );
  });
  elements["back-to-cases"].addEventListener("click", showCaseList);
  elements["download-case"].addEventListener("click", downloadCurrentCase);
  elements["print-case"].addEventListener("click", () => printView("case"));
  elements["generate-evidence"].addEventListener(
    "click",
    generateEvidenceBundle,
  );
  elements["reference-label-form"].addEventListener(
    "submit",
    submitReferenceLabel,
  );
  elements["reference-label-value"].addEventListener(
    "change",
    configureReferenceLabelFields,
  );
  elements["case-action-form"].addEventListener("submit", submitCaseAction);
  elements["case-action"].addEventListener("change", configureCaseActionFields);
  elements["refresh-jobs"].addEventListener("click", loadJobs);
  elements["retry-jobs"].addEventListener("click", loadJobs);
  elements["show-archived-jobs"].addEventListener("change", () => {
    state.showArchivedJobs = elements["show-archived-jobs"].checked;
    state.jobsLoaded = false;
    loadJobs();
  });
  elements["submit-pilot-job"].addEventListener("click", submitPilotJob);
  elements["submit-pilot-job-empty"].addEventListener(
    "click",
    submitPilotJob,
  );
  elements["back-to-jobs"].addEventListener("click", showJobList);
  elements["refresh-job-detail"].addEventListener("click", () => {
    if (state.currentJob) {
      openJob(state.currentJob.job_id, false);
    }
  });
  elements["refresh-users"].addEventListener("click", loadUsers);
  elements["refresh-admin"].addEventListener("click", refreshAdmin);
  elements["refresh-batches"].addEventListener("click", loadBatches);
  elements["show-invalidated-batches"].addEventListener("change", () => {
    state.showInvalidatedBatches =
      elements["show-invalidated-batches"].checked;
    state.batchesLoaded = false;
    loadBatches();
  });
  elements["isolate-pilot-batches"].addEventListener(
    "click",
    isolatePilotBatches,
  );
  elements["refresh-operations"].addEventListener("click", loadOperations);
  elements["backup-create-form"].addEventListener("submit", createBackup);
  elements["refresh-legitimate-scenarios"].addEventListener(
    "click",
    loadLegitimateScenarios,
  );
  elements["legitimate-scenario-form"].addEventListener(
    "submit",
    createLegitimateScenario,
  );
  elements["overview-reference-label-form"].addEventListener(
    "submit",
    submitOverviewReferenceLabel,
  );
  elements["overview-reference-label-value"].addEventListener(
    "change",
    configureOverviewReferenceLabelFields,
  );
  elements["close-overview-reference-label"].addEventListener(
    "click",
    closeOverviewReferenceLabelDialog,
  );
  elements["overview-reference-label-dialog"].addEventListener(
    "cancel",
    closeOverviewReferenceLabelDialog,
  );
  elements["user-create-form"].addEventListener("submit", createUser);
  elements["cancel-user-edit"].addEventListener("click", resetUserForm);
  elements["action-confirm-form"].addEventListener(
    "submit",
    submitActionConfirmation,
  );
  elements["action-confirm-cancel"].addEventListener(
    "click",
    cancelActionConfirmation,
  );
  elements["action-confirm-dialog"].addEventListener(
    "cancel",
    cancelActionConfirmation,
  );

  elements["production-tab"].addEventListener("click", () => setMode("production"));
  elements["personnel-tab"].addEventListener("click", () => setMode("personnel"));
  [elements["production-tab"], elements["personnel-tab"]].forEach((tab) => {
    tab.addEventListener("keydown", handleTabKeydown);
  });

  elements["load-risk-sample"].addEventListener("click", () => {
    const sample =
      state.mode === "production" ? PRODUCTION_RISK_SAMPLE : PERSONNEL_RISK_SAMPLE;
    const name =
      state.mode === "production" ? "产量冲突示例" : "人卡异常示例";
    loadDataset(sample, name);
  });

  elements["load-normal-sample"].addEventListener("click", () => {
    const sample =
      state.mode === "production"
        ? PRODUCTION_NORMAL_SAMPLE
        : PERSONNEL_NORMAL_SAMPLE;
    const name =
      state.mode === "production" ? "产量正常示例" : "人员通行正常示例";
    loadDataset(sample, name);
  });

  elements["file-input"].addEventListener("change", handleFile);
  elements["upload-button"].addEventListener("click", () => {
    elements["file-input"].click();
  });
  elements["clear-analysis"].addEventListener(
    "click",
    clearCurrentAnalysis,
  );

  elements["json-editor"].addEventListener("input", () => {
    if (!elements["json-editor"].value.trim()) {
      clearDataset();
      return;
    }
    state.currentInput = null;
    state.datasetName = state.datasetName || "手工录入数据";
    elements["dataset-card"].classList.remove("is-empty");
    elements["dataset-name"].textContent = state.datasetName;
    elements["dataset-summary"].textContent = "内容已修改，将在分析前重新校验";
    elements["dataset-state"].textContent = "待校验";
    setRequestStatus("数据已修改，可以开始分析");
    elements["analyze-button"].disabled = false;
    elements["clear-analysis"].disabled = false;
  });

  elements["analyze-button"].addEventListener("click", runAnalysis);
  elements["download-button"].addEventListener("click", downloadResult);
  elements["print-button"].addEventListener("click", () => printView("analysis"));
}

function requestActionConfirmation({
  title,
  message,
  confirmLabel = "确认",
  danger = false,
  inputLabel = "",
  inputHelp = "",
  inputType = "text",
  inputPlaceholder = "",
  inputMinLength = 0,
  inputRequired = false,
  trimInput = true,
} = {}) {
  if (pendingConfirmation) {
    return Promise.resolve({ confirmed: false, value: "" });
  }
  const dialog = elements["action-confirm-dialog"];
  if (!dialog || typeof dialog.showModal !== "function") {
    setRequestStatus("当前浏览器不支持安全确认窗口，请升级浏览器后重试。", "error");
    return Promise.resolve({ confirmed: false, value: "" });
  }
  elements["action-confirm-title"].textContent =
    displayText(title, "确认操作");
  elements["action-confirm-message"].textContent =
    displayText(message, "请确认是否继续。");
  elements["action-confirm-submit"].textContent = confirmLabel;
  elements["action-confirm-submit"].className =
    `button ${danger ? "danger" : "primary"} compact`;
  const hasInput = Boolean(inputLabel);
  elements["action-confirm-input-wrap"].hidden = !hasInput;
  elements["action-confirm-input-label"].textContent = inputLabel;
  elements["action-confirm-input-help"].textContent = inputHelp;
  elements["action-confirm-input"].type = inputType;
  elements["action-confirm-input"].placeholder = inputPlaceholder;
  elements["action-confirm-input"].required = inputRequired;
  elements["action-confirm-input"].minLength = inputMinLength;
  elements["action-confirm-input"].value = "";
  elements["action-confirm-error"].hidden = true;
  elements["action-confirm-error"].textContent = "";

  return new Promise((resolve) => {
    pendingConfirmation = {
      resolve,
      trigger: document.activeElement,
      hasInput,
      inputMinLength,
      inputRequired,
      trimInput,
    };
    dialog.showModal();
    window.setTimeout(() => elements["action-confirm-cancel"].focus(), 0);
  });
}

function submitActionConfirmation(event) {
  event.preventDefault();
  if (!pendingConfirmation) {
    return;
  }
  const rawValue = elements["action-confirm-input"].value;
  const value = pendingConfirmation.trimInput ? rawValue.trim() : rawValue;
  if (
    pendingConfirmation.hasInput &&
    pendingConfirmation.inputRequired &&
    !value
  ) {
    elements["action-confirm-error"].textContent = "请填写后再确认。";
    elements["action-confirm-error"].hidden = false;
    elements["action-confirm-input"].focus();
    return;
  }
  if (
    pendingConfirmation.hasInput &&
    value.length < pendingConfirmation.inputMinLength
  ) {
    elements["action-confirm-error"].textContent =
      `至少需要 ${pendingConfirmation.inputMinLength} 个字符。`;
    elements["action-confirm-error"].hidden = false;
    elements["action-confirm-input"].focus();
    return;
  }
  finishActionConfirmation({ confirmed: true, value });
}

function cancelActionConfirmation(event) {
  if (event) {
    event.preventDefault();
  }
  finishActionConfirmation({ confirmed: false, value: "" });
}

function finishActionConfirmation(result) {
  if (!pendingConfirmation) {
    return;
  }
  const current = pendingConfirmation;
  pendingConfirmation = null;
  elements["action-confirm-dialog"].close();
  elements["action-confirm-input"].value = "";
  current.resolve(result);
  if (current.trigger && typeof current.trigger.focus === "function") {
    window.setTimeout(() => current.trigger.focus(), 0);
  }
}

async function initializeAuthentication() {
  elements["auth-gate"].hidden = false;
  elements["auth-checking"].hidden = false;
  elements["login-panel"].hidden = true;
  document.body.classList.add("is-auth-pending");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.csrf, {
      skipAuthHandling: true,
    });
    establishSession(body);
    unlockApplication();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      showLogin("请登录后进入监管工作台。");
    } else {
      showLogin("暂时无法确认访问身份，请检查内网服务后重试登录。", "error");
    }
  }
}

function establishSession(body) {
  const principal = objectOrNull(body && body.principal);
  if (!principal) {
    throw new Error("身份服务未返回当前用户");
  }
  state.principal = principal;
  state.csrfToken = nullableText(body.csrf_token);
  state.authEnabled = state.csrfToken !== null;
  state.authInitialized = true;
  renderPrincipal();
}

function unlockApplication() {
  document.body.classList.remove("is-auth-pending");
  elements["auth-gate"].hidden = true;
  elements["auth-checking"].hidden = true;
  elements["login-panel"].hidden = true;
  state.overviewLoaded = false;
  state.trendsLoaded = false;
  state.temporalLoaded = false;
  setWorkspace("overview", false);
  loadOverview();
  refreshTrendWorkspace();
}

function showLogin(message, tone = "") {
  state.authInitialized = false;
  state.authEnabled = true;
  state.principal = null;
  state.csrfToken = null;
  clearJobPoll();
  document.body.classList.add("is-auth-pending");
  elements["auth-gate"].hidden = false;
  elements["auth-checking"].hidden = true;
  elements["login-panel"].hidden = false;
  elements["login-status"].textContent = message;
  elements["login-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
  elements["login-password"].value = "";
  requestAnimationFrame(() => elements["login-username"].focus());
}

async function submitLogin(event) {
  event.preventDefault();
  const username = elements["login-username"].value.trim();
  const password = elements["login-password"].value;
  if (!username || !password) {
    setLoginStatus("请输入用户名和密码。", "error");
    return;
  }
  elements["login-submit"].disabled = true;
  setLoginStatus("正在核验账号和授权范围…");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.login, {
      method: "POST",
      body: JSON.stringify({ username, password }),
      skipAuthHandling: true,
    });
    establishSession(body);
    elements["login-password"].value = "";
    setLoginStatus("");
    unlockApplication();
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      setLoginStatus("用户名或密码不正确，请重新输入。", "error");
    } else if (error instanceof ApiError && error.status === 429) {
      setLoginStatus("连续登录失败次数过多，请稍后再试。", "error");
    } else {
      setLoginStatus(
        explainAccessError(error, "登录"),
        "error",
      );
    }
  } finally {
    elements["login-submit"].disabled = false;
  }
}

async function logout() {
  elements["logout-button"].disabled = true;
  try {
    await requestJson(SUPERVISION_API_PATHS.logout, { method: "POST" });
  } catch (error) {
    if (!(error instanceof ApiError && error.status === 401)) {
      elements["service-dot"].classList.remove("is-online");
      elements["service-dot"].classList.add("is-offline");
      elements["service-text"].textContent =
        explainAccessError(error, "退出登录");
      elements["logout-button"].disabled = false;
      return;
    }
  }
  resetProtectedState();
  showLogin("已安全退出，请重新登录。");
  elements["logout-button"].disabled = false;
}

function resetProtectedState() {
  state.principal = null;
  state.csrfToken = null;
  state.overviewLoaded = false;
  state.overview = null;
  state.overviewItems = [];
  state.trendsLoaded = false;
  state.analytics = null;
  state.temporalLoaded = false;
  state.temporalDashboard = null;
  state.casesLoaded = false;
  state.showArchivedCases = false;
  state.cases = [];
  state.currentCaseDetail = null;
  state.currentCaseResponse = null;
  state.currentReferenceLabels = null;
  state.currentReferenceLabelsError = null;
  state.referenceLabelRunning = false;
  state.overviewReferenceLabelRunId = null;
  state.overviewReferenceLabelItem = null;
  state.overviewReferenceLabels = null;
  state.overviewReferenceLabelError = null;
  state.overviewReferenceLabelRunning = false;
  state.jobsLoaded = false;
  state.showArchivedJobs = false;
  state.jobs = [];
  state.currentJob = null;
  state.usersLoaded = false;
  state.users = [];
  state.editingUsername = null;
  state.batchesLoaded = false;
  state.showInvalidatedBatches = false;
  state.batches = [];
  state.operationsLoaded = false;
  state.readiness = null;
  state.backups = [];
  state.legitimateScenariosLoading = false;
  state.legitimateScenariosLoaded = false;
  state.legitimateScenarios = [];
  if (
    elements["overview-reference-label-dialog"] &&
    elements["overview-reference-label-dialog"].open
  ) {
    elements["overview-reference-label-dialog"].close();
  }
  elements["show-archived-cases"].checked = false;
  elements["show-archived-jobs"].checked = false;
  elements["show-invalidated-batches"].checked = false;
  resetUserForm();
  clearJobPoll();
}

function setLoginStatus(message, tone = "") {
  elements["login-status"].textContent = message;
  elements["login-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

function renderPrincipal() {
  const principal = state.principal;
  if (!principal) {
    elements["principal-summary"].hidden = true;
    return;
  }
  const role = String(principal.role || "viewer");
  const scopes = arrayOrNull(principal.mine_scopes) || [];
  elements["principal-name"].textContent = displayText(
    principal.username,
    "当前用户",
  );
  elements["principal-role"].textContent =
    `${ROLE_LABELS[role] || role}${state.authEnabled ? "" : " · 本地免登录模式"}`;
  elements["principal-scopes"].textContent =
    role === "admin"
      ? "矿山范围：全部"
      : scopes.length
        ? `矿山范围：${scopes.join("、")}`
        : "矿山范围：未分配";
  elements["principal-summary"].hidden = false;
  elements["logout-button"].hidden = !state.authEnabled;
  const isAdmin = role === "admin";
  elements["admin-workspace-tab"].hidden = !isAdmin;
  document.body.classList.toggle("is-admin", isAdmin);
  updatePermissionControls();
}

function updatePermissionControls() {
  const canRunSandbox = userCan("directRun");
  elements["submit-pilot-job"].hidden = !canRunSandbox;
  elements["submit-pilot-job-empty"].hidden = !canRunSandbox;
  elements["load-pilot-overview"].hidden =
    state.authEnabled && !isAdminUser();
}

function isAdminUser() {
  return Boolean(state.principal && state.principal.role === "admin");
}

function userCan(capability) {
  const role = state.principal ? state.principal.role : null;
  const allowed = {
    directRun: ["admin"],
    cancelJob: ["admin", "supervisor"],
    assign: ["admin", "supervisor"],
    review: ["admin", "supervisor", "reviewer"],
    approve: ["admin", "supervisor"],
    evidence: ["admin", "supervisor", "reviewer"],
    referenceLabel: ["admin", "supervisor"],
    scenarios: ["admin"],
    users: ["admin"],
  };
  return Boolean(role && (allowed[capability] || []).includes(role));
}

function availableWorkspaces() {
  return WORKSPACE_NAMES.filter(
    (name) => !elements[`${name}-workspace-tab`].hidden,
  );
}

function handleWorkspaceKeydown(event) {
  if (
    !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
  ) {
    return;
  }
  event.preventDefault();
  const workspaces = availableWorkspaces();
  const current = workspaces.indexOf(event.currentTarget.dataset.workspace);
  let next = current;
  if (event.key === "Home") {
    next = 0;
  } else if (event.key === "End") {
    next = workspaces.length - 1;
  } else if (event.key === "ArrowLeft") {
    next = (current - 1 + workspaces.length) % workspaces.length;
  } else {
    next = (current + 1) % workspaces.length;
  }
  const workspace = workspaces[next];
  setWorkspace(workspace);
  elements[`${workspace}-workspace-tab`].focus();
}

function setWorkspace(workspace, shouldLoad = true) {
  if (
    !WORKSPACE_NAMES.includes(workspace) ||
    elements[`${workspace}-workspace-tab`].hidden
  ) {
    return;
  }
  state.workspace = workspace;
  WORKSPACE_NAMES.forEach((name) => {
    const isActive = name === workspace;
    const tab = elements[`${name}-workspace-tab`];
    const panel = elements[`${name}-workspace`];
    tab.classList.toggle("is-active", isActive);
    tab.setAttribute("aria-selected", String(isActive));
    tab.tabIndex = isActive ? 0 : -1;
    panel.hidden = !isActive;
  });

  if (workspace !== "jobs") {
    clearJobPoll();
  }

  if (workspace === "cases") {
    showCaseList(false);
    if (
      shouldLoad &&
      state.authInitialized &&
      !state.casesLoaded &&
      !state.casesLoading
    ) {
      loadCases();
    }
  } else if (workspace === "jobs") {
    showJobList(false);
    if (
      shouldLoad &&
      state.authInitialized &&
      !state.jobsLoaded &&
      !state.jobsLoading
    ) {
      loadJobs();
    } else if (state.jobsLoaded) {
      scheduleJobPoll();
    }
  } else if (
    workspace === "admin" &&
    shouldLoad &&
    state.authInitialized &&
    isAdminUser()
  ) {
    if (!state.usersLoaded && !state.usersLoading) {
      loadUsers();
    }
    if (!state.operationsLoaded && !state.operationsLoading) {
      loadOperations();
    }
    if (!state.batchesLoaded && !state.batchesLoading) {
      loadBatches();
    }
    if (
      !state.legitimateScenariosLoaded &&
      !state.legitimateScenariosLoading
    ) {
      loadLegitimateScenarios();
    }
  } else if (
    workspace === "overview" &&
    shouldLoad &&
    state.authInitialized &&
    !state.overviewLoaded &&
    !state.overviewLoading
  ) {
    loadOverview();
    if (!state.trendsLoaded && !state.trendsLoading) {
      loadTrends();
    }
    if (!state.temporalLoaded && !state.temporalLoading) {
      loadTemporalDashboard();
    }
  }
}

async function requestJson(path, options = {}) {
  const {
    skipAuthHandling = false,
    headers: customHeaders = {},
    ...fetchOptions
  } = options;
  const method = String(fetchOptions.method || "GET").toUpperCase();
  const headers = {
    Accept: "application/json",
    ...(fetchOptions.body ? { "Content-Type": "application/json" } : {}),
    ...customHeaders,
  };
  if (
    !["GET", "HEAD", "OPTIONS"].includes(method) &&
    state.csrfToken
  ) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    ...fetchOptions,
    headers,
  });
  const body = await readJsonResponse(response);
  if (!response.ok) {
    const error = new ApiError(response.status, body);
    if (response.status === 401 && !skipAuthHandling) {
      resetProtectedState();
      showLogin("会话已失效或已超时，请重新登录。", "error");
    }
    throw error;
  }
  return body;
}

async function loadOverview() {
  if (state.overviewLoading) {
    return;
  }
  state.overviewLoading = true;
  elements["refresh-overview"].disabled = true;
  setLoadStatus(
    elements["overview-status"],
    "正在读取辖区数据接收和研判情况…",
    "loading",
  );

  try {
    const body = await requestJson(SUPERVISION_API_PATHS.overview);
    const overview = normalizeOverview(body);
    if (!overview.hasBatch) {
      state.overviewLoaded = true;
      state.overview = overview;
      state.overviewItems = [];
      showOverviewEmpty(
        "当前还没有辖区批次。可载入脱敏试点数据，先体验总览、排序和核查闭环。",
      );
      setLoadStatus(elements["overview-status"], "尚无辖区汇总批次");
      return;
    }
    state.overviewLoaded = true;
    renderOverview(overview);
  } catch (error) {
    state.overviewLoaded = false;
    showOverviewEmpty(
      "暂时无法读取辖区汇总。服务恢复后可重新读取；这不表示当前辖区没有异常或缺报。",
      true,
    );
    setLoadStatus(
      elements["overview-status"],
      explainSupervisionError(error, "辖区汇总"),
      "error",
    );
  } finally {
    state.overviewLoading = false;
    elements["refresh-overview"].disabled = false;
  }
}

async function loadPilotOverview() {
  if (state.overviewLoading) {
    return;
  }
  state.overviewLoading = true;
  const button = elements["load-pilot-overview"];
  const previousLabel = button.textContent;
  button.disabled = true;
  elements["retry-overview"].disabled = true;
  button.textContent = "正在载入脱敏数据…";
  setLoadStatus(
    elements["overview-status"],
    "正在生成脱敏试点辖区的交叉核验汇总…",
    "loading",
  );

  try {
    const payload = buildPilotBatchPayload();
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.batchProduction}?preview=1`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    const overview = normalizeOverview({
      batch: body,
      generated_at: new Date().toISOString(),
      local_trial: true,
    });
    if (!overview.hasBatch) {
      throw new Error("批次接口未返回可展示的汇总");
    }
    overview.localTrial = true;
    state.overviewLoaded = true;
    renderOverview(overview);
    elements["overview-trial-badge"].textContent =
      "脱敏试点预览 · 不保存";
    elements["scope-summary"].textContent =
      `临时预览 · ${overview.portfolioName}（不入库）`;
    setLoadStatus(
      elements["overview-status"],
      "脱敏试点临时预览：未保存批次，不生成案件、算法特征或正式趋势。",
    );
  } catch (error) {
    showOverviewEmpty(
      "脱敏试点数据暂时无法载入。请确认批次分析服务已启动后重试。",
      true,
    );
    setLoadStatus(
      elements["overview-status"],
      explainSupervisionError(error, "脱敏试点数据"),
      "error",
    );
  } finally {
    state.overviewLoading = false;
    button.disabled = false;
    elements["retry-overview"].disabled = false;
    button.textContent = previousLabel;
  }
}

function buildPilotBatchPayload() {
  const stamp = fileTimestamp();
  return {
    batch_id: `pilot-${stamp}`,
    portfolio_name: "脱敏试点辖区",
    expected_mine_ids: ["M001", "M002", "M003"],
    analyses: [
      JSON.parse(JSON.stringify(PRODUCTION_RISK_SAMPLE)),
      JSON.parse(JSON.stringify(PRODUCTION_NORMAL_SAMPLE)),
    ],
  };
}

function showOverviewEmpty(message, isError = false) {
  elements["overview-content"].hidden = true;
  elements["overview-empty"].hidden = false;
  elements["overview-empty-message"].textContent = message;
  elements["overview-empty"].classList.toggle("is-error", isError);
  elements["scope-summary"].textContent = "工作范围 · 待载入";
}

function normalizeOverview(raw) {
  const response = raw && typeof raw === "object" ? raw : {};
  let batch;
  if (Object.prototype.hasOwnProperty.call(response, "batch")) {
    batch = response.batch;
  } else {
    batch = pickFirst(response, "dashboard", "overview");
    if (typeof batch === "undefined") {
      batch = response;
    }
  }
  if (!batch || typeof batch !== "object" || Array.isArray(batch)) {
    return {
      hasBatch: false,
      generatedAt: pickFirst(response, "generated_at", "updated_at"),
      localTrial: Boolean(response.local_trial),
    };
  }

  const rawItems =
    arrayOrNull(
      pickFirst(batch, "items", "results", "analyses", "priority_items"),
    ) || [];
  const expectedIds = arrayOrNull(
    pickFirst(batch, "expected_mine_ids", "expected_ids"),
  );
  const receivedIds = arrayOrNull(
    pickFirst(batch, "received_mine_ids", "received_ids"),
  );
  const missingIds = arrayOrNull(
    pickFirst(batch, "missing_mine_ids", "missing_ids"),
  );
  const normalizedItems = rawItems.map(normalizeOverviewItem);

  if (missingIds) {
    missingIds.forEach((mineId) => {
      const exists = normalizedItems.some(
        (item) => String(item.mineId) === String(mineId),
      );
      if (!exists) {
        normalizedItems.push(
          normalizeOverviewItem({
            mine_id: mineId,
            technical_status: "missing",
            priority_level: "supplement",
            plain_summary:
              "预期收到该矿数据，但本批次尚未收到；缺报不按零值处理。",
          }),
        );
      }
    });
  }

  const expectedCount = firstNumber(
    pickFirst(
      batch,
      "expected_mine_count",
      "expected_count",
      "total_expected",
    ),
    expectedIds ? expectedIds.length : undefined,
  );
  const receivedCount = firstNumber(
    pickFirst(
      batch,
      "received_mine_count",
      "received_count",
      "analyzed_count",
    ),
    receivedIds ? receivedIds.length : undefined,
    expectedCount !== null && missingIds
      ? expectedCount - missingIds.length
      : undefined,
  );
  const missingCount = firstNumber(
    pickFirst(batch, "missing_mine_count", "missing_count"),
    missingIds ? missingIds.length : undefined,
    expectedCount !== null && receivedCount !== null
      ? Math.max(expectedCount - receivedCount, 0)
      : undefined,
  );
  const statusCounts =
    pickFirst(batch, "status_counts", "technical_status_counts", "counts") || {};
  const inconsistentCount = firstNumber(
    pickFirst(
      batch,
      "inconsistent_count",
      "technical_inconsistent_count",
    ),
    pickFirst(statusCounts, "inconsistent", "technical_inconsistent"),
    countStatuses(normalizedItems, ["inconsistent"]),
  );
  const statusInconclusiveCount = firstNumber(
    pickFirst(statusCounts, "inconclusive", "data_insufficient"),
  );
  const statusSolverErrorCount = firstNumber(
    pickFirst(statusCounts, "solver_error", "analysis_failed"),
  );
  const statusIncompleteCount =
    statusInconclusiveCount === null && statusSolverErrorCount === null
      ? undefined
      : (statusInconclusiveCount === null ? 0 : statusInconclusiveCount) +
        (statusSolverErrorCount === null ? 0 : statusSolverErrorCount);
  const inconclusiveCount = firstNumber(
    pickFirst(batch, "inconclusive_count", "data_insufficient_count"),
    statusIncompleteCount,
    countStatuses(normalizedItems, ["inconclusive", "solver_error"]),
  );
  const consistentCount = firstNumber(
    pickFirst(batch, "consistent_count"),
    pickFirst(statusCounts, "consistent"),
    countStatuses(normalizedItems, ["consistent"]),
  );
  const ratioValue = firstNumber(
    pickFirst(batch, "coverage_ratio", "coverage_rate"),
    expectedCount !== null && expectedCount > 0 && receivedCount !== null
      ? receivedCount / expectedCount
      : undefined,
  );

  return {
    hasBatch: true,
    batchId: displayText(pickFirst(batch, "batch_id", "id")),
    portfolioName: displayText(
      pickFirst(batch, "portfolio_name", "scope_name", "region_name"),
      "未命名辖区",
    ),
    generatedAt: pickFirst(
      response,
      "generated_at",
      "last_data_refresh_at",
      "updated_at",
      "batch.generated_at",
    ),
    localTrial: Boolean(
      pickFirst(response, "local_trial", "is_trial", "batch.local_trial"),
    ),
    expectedIds,
    receivedIds,
    missingIds,
    expectedCount,
    receivedCount,
    missingCount,
    coverageRatio: normalizeRatio(ratioValue),
    inconsistentCount,
    inconclusiveCount,
    consistentCount,
    openCaseCount: firstNumber(
      pickFirst(
        response,
        "open_case_count",
        "pending_case_count",
        "batch.open_case_count",
      ),
    ),
    items: normalizedItems,
    raw: response,
  };
}

function renderOverview(overview) {
  state.overview = overview;
  state.overviewItems = overview.items;
  elements["overview-empty"].hidden = true;
  elements["overview-content"].hidden = false;
  elements["overview-portfolio-name"].textContent = overview.portfolioName;
  elements["overview-batch-id"].textContent = overview.batchId;
  elements["overview-generated-at"].textContent = formatDateTime(
    overview.generatedAt,
  );
  elements["overview-trial-badge"].hidden = !overview.localTrial;
  elements["scope-summary"].textContent =
    `工作范围 · ${overview.portfolioName}`;
  updateOpenCaseCount(overview.openCaseCount);
  renderOverviewKpis(overview);
  renderCoverage(overview);
  renderOverviewQueue();
  setLoadStatus(
    elements["overview-status"],
    overview.generatedAt
      ? `总览已更新：${formatDateTime(overview.generatedAt)}`
      : "辖区汇总已读取",
  );
}

function renderOverviewKpis(overview) {
  clearNode(elements["overview-kpi-grid"]);
  const coverageText =
    overview.coverageRatio === null
      ? "覆盖率未返回"
      : `覆盖率 ${formatPercent(overview.coverageRatio)}`;
  const missingNote =
    overview.missingIds && overview.missingIds.length
      ? `未收到：${overview.missingIds.slice(0, 3).join("、")}${overview.missingIds.length > 3 ? "等" : ""}`
      : "缺报不按零值或正常数据处理";
  const cards = [
    {
      label: "预期报送矿山",
      value: formatCount(overview.expectedCount),
      note: "本批次应纳入的监管对象",
    },
    {
      label: "已收到数据",
      value: formatCount(overview.receivedCount),
      note: coverageText,
      tone:
        overview.receivedCount !== null &&
        overview.expectedCount !== null &&
        overview.receivedCount === overview.expectedCount
          ? "success"
          : "",
    },
    {
      label: "缺报",
      value: formatCount(overview.missingCount),
      note: missingNote,
      tone:
        overview.missingCount === null
          ? ""
          : overview.missingCount > 0
            ? "warning"
            : "success",
    },
    {
      label: "技术不一致",
      value: formatCount(overview.inconsistentCount),
      note: "多源数据暂不能在容差内同时成立",
      tone:
        overview.inconsistentCount === null
          ? ""
          : overview.inconsistentCount > 0
            ? "review"
            : "success",
    },
    {
      label: "数据不足",
      value: formatCount(overview.inconclusiveCount),
      note: "需补齐阻断项后再形成技术判断",
      tone:
        overview.inconclusiveCount === null
          ? ""
          : overview.inconclusiveCount > 0
            ? "warning"
            : "success",
    },
    {
      label: "开放事项",
      value: formatCount(overview.openCaseCount),
      note: "待阅、已交办、补数或复核中的事项",
      tone:
        overview.openCaseCount === null
          ? ""
          : overview.openCaseCount > 0
            ? "review"
            : "success",
    },
  ];
  cards.forEach((item) => {
    const card = document.createElement("article");
    card.className = `overview-stat${item.tone ? ` is-${item.tone}` : ""}`;
    const label = document.createElement("p");
    label.className = "overview-stat-label";
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.className = "overview-stat-value";
    value.textContent = item.value;
    const note = document.createElement("span");
    note.className = "overview-stat-note";
    note.textContent = item.note;
    card.append(label, value, note);
    elements["overview-kpi-grid"].appendChild(card);
  });
}

function renderCoverage(overview) {
  const ratio = overview.coverageRatio;
  if (ratio === null) {
    elements["coverage-title"].textContent = "数据接收覆盖率尚未返回";
    elements["coverage-explanation"].textContent =
      "请先核对预期报送对象和实际收到数据；缺报不按零值处理。";
    elements["coverage-meter-fill"].style.width = "0%";
    return;
  }
  const percentage = formatPercent(ratio);
  elements["coverage-title"].textContent =
    `本批次数据接收覆盖率 ${percentage}`;
  elements["coverage-explanation"].textContent =
    ratio < 1
      ? "仍有数据未收到。缺报矿山单独列出，不进入“当前数据可协调”统计。"
      : "预期对象已全部收到数据，仍需分别查看技术状态和办理状态。";
  elements["coverage-meter-fill"].style.width =
    `${Math.max(0, Math.min(ratio, 1)) * 100}%`;
}

async function loadTrends() {
  if (state.trendsLoading || !state.authInitialized) {
    return;
  }
  state.trendsLoading = true;
  updateTrendRefreshButton();
  setLoadStatus(elements["trends-status"], "正在计算近 30 日趋势…", "loading");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.trends);
    const analytics = normalizeAnalytics(body);
    state.analytics = analytics;
    state.trendsLoaded = true;
    renderAnalytics(analytics);
    setLoadStatus(
      elements["trends-status"],
      `统计截至 ${formatDateTime(analytics.asOf)}，按授权矿山范围计算。`,
    );
  } catch (error) {
    state.trendsLoaded = false;
    state.analytics = null;
    elements["trends-content"].hidden = true;
    elements["trends-empty"].hidden = false;
    setLoadStatus(
      elements["trends-status"],
      explainSupervisionError(error, "近 30 日趋势"),
      "error",
    );
  } finally {
    state.trendsLoading = false;
    updateTrendRefreshButton();
  }
}

async function refreshTrendWorkspace() {
  await Promise.allSettled([loadTrends(), loadTemporalDashboard()]);
}

function updateTrendRefreshButton() {
  elements["refresh-trends"].disabled =
    state.trendsLoading || state.temporalLoading;
}

async function loadTemporalDashboard() {
  if (state.temporalLoading || !state.authInitialized) {
    return;
  }
  state.temporalLoading = true;
  updateTrendRefreshButton();
  setLoadStatus(
    elements["temporal-status"],
    "正在读取近 90 日时序异常与数据质量…",
    "loading",
  );
  setTemporalStatusBadge("正在读取", "loading");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.temporal);
    const dashboard = normalizeTemporalDashboard(body);
    state.temporalDashboard = dashboard;
    state.temporalLoaded = true;
    renderTemporalDashboard(dashboard);
    setLoadStatus(
      elements["temporal-status"],
      dashboard.generatedAt
        ? `时序观察更新于 ${formatDateTime(dashboard.generatedAt)}，范围仅限当前账号授权矿山。`
        : "近 90 日时序观察已读取，范围仅限当前账号授权矿山。",
    );
  } catch (error) {
    state.temporalLoaded = false;
    state.temporalDashboard = null;
    elements["temporal-content"].hidden = true;
    setTemporalStatusBadge("读取失败", "error");
    setLoadStatus(
      elements["temporal-status"],
      `${explainSupervisionError(error, "时序异常与数据质量")} 未读取不代表无异常。`,
      "error",
    );
  } finally {
    state.temporalLoading = false;
    updateTrendRefreshButton();
  }
}

function normalizeTemporalDashboard(rawResponse) {
  const response = objectOrNull(rawResponse) || {};
  const nested = objectOrNull(
    pickFirst(response, "temporal", "dashboard", "result"),
  );
  const raw = nested || response;
  const health = objectOrNull(raw.health) || {};
  const series = arrayOrNull(raw.series) || [];
  let episodes = arrayOrNull(raw.episodes) || [];
  if (!episodes.length) {
    episodes = series.flatMap((rawSeries) => {
      const seriesItem = objectOrNull(rawSeries) || {};
      return (arrayOrNull(seriesItem.episodes) || []).map((episode) => ({
        ...(objectOrNull(episode) || {}),
        mine_id: seriesItem.mine_id,
        source_id: seriesItem.source_id,
        metric_code: seriesItem.metric_code,
      }));
    });
  }
  const normalizedEpisodes = episodes.map((rawEpisode, index) => {
    const episode = objectOrNull(rawEpisode) || {};
    return {
      number: firstNumber(episode.episode_number, index + 1),
      mineId: nullableText(episode.mine_id),
      sourceId: nullableText(episode.source_id),
      metricCode: nullableText(episode.metric_code),
      start: pickFirst(episode, "start", "start_at", "started_at"),
      end: pickFirst(episode, "end", "end_at", "ended_at"),
      anomalyPoints: firstNumber(
        episode.anomaly_point_count,
        episode.point_count,
      ),
      spannedPoints: firstNumber(episode.spanned_point_count),
      detectors: arrayOrNull(episode.detectors) || [],
      directions: arrayOrNull(episode.directions) || [],
      maximumContribution: firstNumber(
        episode.maximum_contribution,
        episode.max_contribution,
      ),
      explanation: nullableText(episode.explanation),
    };
  });
  const explicitStatus = String(raw.status || "").trim().toLowerCase();
  const reason = String(raw.reason || "").trim().toLowerCase();
  const inferredStatus = normalizedEpisodes.length
    ? "anomalous"
    : firstNumber(raw.insufficient_history_series_count) > 0
      ? "insufficient_history"
      : "normal";
  const status = [
    "anomalous",
    "normal",
    "insufficient_history",
  ].includes(explicitStatus)
    ? explicitStatus
    : inferredStatus;
  return {
    status,
    reason: reason || null,
    generatedAt: pickFirst(raw, "generated_at", "as_of", "updated_at"),
    seriesCount: firstNumber(raw.series_count, health.series_count),
    anomalousSeriesCount: firstNumber(raw.anomalous_series_count),
    insufficientHistorySeriesCount: firstNumber(
      raw.insufficient_history_series_count,
    ),
    episodes: normalizedEpisodes,
    health: {
      status: nullableText(health.status),
      pointCount: firstNumber(health.point_count),
      acceptedCount: firstNumber(health.baseline_accepted_count),
      missingCount: firstNumber(health.missing_count),
      lateCount: firstNumber(health.late_count),
      revisedCount: firstNumber(health.revised_count),
      lowQualityCount: firstNumber(health.low_quality_count),
      rejectedFeatureCount: firstNumber(
        health.rejected_feature_row_count,
      ),
      featureLimitReached: Boolean(health.feature_limit_reached),
    },
  };
}

function renderTemporalDashboard(dashboard) {
  elements["temporal-content"].hidden = false;
  const isColdStart = dashboard.status === "insufficient_history";
  const hasWarnings = dashboard.status === "anomalous";
  const dataIncomplete =
    dashboard.reason === "data_truncated" ||
    dashboard.health.featureLimitReached;
  const healthIssueCount = [
    dashboard.health.missingCount,
    dashboard.health.lateCount,
    dashboard.health.revisedCount,
    dashboard.health.lowQualityCount,
    dashboard.health.rejectedFeatureCount,
  ].reduce((total, value) => total + (value === null ? 0 : value), 0);
  const dataQualityNeedsAttention =
    dataIncomplete ||
    healthIssueCount > 0 ||
    dashboard.health.status === "degraded";

  if (hasWarnings) {
    setTemporalStatusBadge("发现预警", "review");
    elements["temporal-summary"].textContent =
      `近 90 日检测到 ${dashboard.episodes.length} 个时序预警事件。它们只提示“哪里值得先查”，必须结合原始台账、设备状态和业务口径人工复核，不能作为定案。${dataIncomplete ? " 同时，本次数据未完整，未覆盖部分不能判断正常。" : ""}`;
  } else if (dataIncomplete) {
    setTemporalStatusBadge("数据未完整", "warning");
    elements["temporal-summary"].textContent =
      "本次时序数据读取达到上限或被截断，数据未完整，不能判断正常。请缩小范围、补充分页处理或由技术人员完成全量复核。";
  } else if (isColdStart) {
    setTemporalStatusBadge("历史不足", "warning");
    elements["temporal-summary"].textContent =
      "历史数据不足，尚不能形成稳定基线；这不代表正常，也不代表异常。请继续积累同口径数据后再观察。";
  } else {
    setTemporalStatusBadge(
      dataQualityNeedsAttention
        ? "数据需关注"
        : "未见时序信号",
      dataQualityNeedsAttention
        ? "warning"
        : "success",
    );
    elements["temporal-summary"].textContent =
      "在近 90 日可用历史和当前阈值下暂未发现时序异常信号；这不等同于“没有问题”，仍需结合本批次冲突和日常抽查。";
  }

  clearNode(elements["temporal-kpi-grid"]);
  const cards = [
    {
      label: "纳入观察的序列",
      value: formatCount(dashboard.seriesCount),
      note: "按矿山、数据源和指标分别建立基线",
    },
    {
      label: "时序预警事件",
      value: String(dashboard.episodes.length),
      note: hasWarnings
        ? "一个事件可包含多个连续异常时点"
        : isColdStart
          ? "历史不足时不按“0 个异常”下结论"
          : "当前阈值下未形成连续预警事件",
      tone: hasWarnings ? "review" : "",
    },
    {
      label: "历史不足序列",
      value: formatCount(dashboard.insufficientHistorySeriesCount),
      note: "基线样本不足的序列单独标注",
      tone:
        dashboard.insufficientHistorySeriesCount !== null &&
        dashboard.insufficientHistorySeriesCount > 0
          ? "warning"
          : "",
    },
    {
      label: "数据质量提示",
      value: String(healthIssueCount),
      note: temporalDataQualityNote(dashboard.health),
      tone: dataQualityNeedsAttention ? "warning" : "",
    },
  ];
  cards.forEach((item) => {
    const card = document.createElement("article");
    card.className =
      `temporal-kpi${item.tone ? ` is-${item.tone}` : ""}`;
    const label = document.createElement("span");
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.textContent = item.value;
    const note = document.createElement("small");
    note.textContent = item.note;
    card.append(label, value, note);
    elements["temporal-kpi-grid"].appendChild(card);
  });

  clearNode(elements["temporal-episode-list"]);
  dashboard.episodes.forEach((episode, index) => {
    const item = document.createElement("li");
    const heading = document.createElement("div");
    heading.className = "temporal-episode-title";
    const title = document.createElement("strong");
    title.textContent =
      `预警事件 ${episode.number || index + 1} · ${episode.mineId || "矿山未标识"}`;
    const contribution = document.createElement("span");
    contribution.textContent =
      `贡献源：${temporalSourceLabel(episode.sourceId, episode.metricCode)}`;
    heading.append(title, contribution);

    const period = document.createElement("p");
    period.className = "temporal-episode-period";
    period.textContent =
      `开始 ${formatDateTime(episode.start)} · 结束 ${formatDateTime(episode.end)}`;
    const explanation = document.createElement("p");
    explanation.className = "temporal-episode-explanation";
    const detectorText = episode.detectors.length
      ? episode.detectors.map(temporalDetectorLabel).join("、")
      : "检测器明细未返回";
    explanation.textContent =
      `${episode.explanation || `触发：${detectorText}。`} 异常时点 ${formatCount(episode.anomalyPoints)} 个；仅作为人工复核线索。`;
    item.append(heading, period, explanation);
    elements["temporal-episode-list"].appendChild(item);
  });
  elements["temporal-episode-empty"].hidden =
    dashboard.episodes.length > 0;
  elements["temporal-episode-empty"].textContent = dataIncomplete
    ? "本次数据未完整，即使未形成预警事件也不能判断正常。"
    : isColdStart
      ? "历史数据不足，暂不生成预警事件；请勿据此判断为正常。"
      : "当前未形成时序预警事件；“未预警”不等于“无问题”。";
}

function setTemporalStatusBadge(label, tone) {
  const badge = elements["temporal-status-badge"];
  badge.textContent = label;
  badge.className = `temporal-status-badge is-${tone}`;
}

function temporalDataQualityNote(health) {
  const parts = [
    ["缺测标记", health.missingCount],
    ["延迟标记", health.lateCount],
    ["修订记录", health.revisedCount],
    ["低质量记录", health.lowQualityCount],
    ["未纳入记录", health.rejectedFeatureCount],
  ]
    .filter(([, value]) => value !== null && value > 0)
    .map(([label, value]) => `${label} ${value}`);
  if (health.featureLimitReached) {
    parts.push("读取达到上限，结果不完整");
  }
  return parts.length
    ? parts.join(" · ")
    : "已入库特征未返回明确质量提示；不代表原始来源完整或及时";
}

function temporalSourceLabel(sourceId, metricCode) {
  const source = sourceId ? sourceLabel(sourceId) : "来源未标识";
  const metric = metricCode
    ? METRIC_LABELS[metricCode] || metricCode
    : null;
  return metric ? `${source}（${metric}）` : source;
}

function temporalDetectorLabel(code) {
  const labels = {
    rolling_mad: "稳健离群",
    ewma: "持续偏移",
    cusum: "累积漂移",
    page_hinkley: "结构突变",
    source_missing: "缺测标记",
    source_latency: "延迟标记",
    source_revision: "频繁修订",
    source_low_quality: "来源质量偏低",
  };
  return labels[code] || String(code);
}

function normalizeAnalytics(rawResponse) {
  const response = objectOrNull(rawResponse) || {};
  const raw = objectOrNull(pickFirst(response, "analytics", "report")) || {};
  const performance = objectOrNull(raw.case_performance) || {};
  const quality = objectOrNull(raw.data_quality) || {};
  const daily = (arrayOrNull(raw.daily_trend) || []).map((item) => {
    const point = objectOrNull(item) || {};
    return {
      day: nullableText(point.day),
      expected: firstNumber(point.expected_reports),
      received: firstNumber(point.received_reports),
      coverage: normalizeRatio(firstNumber(point.coverage_rate)),
      newCases: firstNumber(point.new_cases),
      closedCycles: firstNumber(point.closed_cycles),
      backlog: firstNumber(point.backlog_end),
    };
  });
  return {
    windowStart: raw.window_start,
    windowEnd: raw.window_end,
    asOf: raw.as_of,
    timezone: displayText(raw.timezone, "Asia/Shanghai"),
    scopedMineIds: arrayOrNull(raw.scoped_mine_ids) || [],
    expected: firstNumber(raw.expected_report_count),
    received: firstNumber(raw.received_report_count),
    coverage: normalizeRatio(firstNumber(raw.coverage_rate)),
    summary: displayText(
      raw.summary,
      "近 30 日统计已生成，请结合本批次总览查看。",
    ),
    daily,
    ranking: arrayOrNull(raw.mine_risk_ranking) || [],
    repeated: arrayOrNull(raw.repeated_anomalies) || [],
    performance: {
      newCases: firstNumber(performance.new_case_count),
      closedCases: firstNumber(performance.closed_case_count),
      closedCycles: firstNumber(performance.closed_cycle_count),
      resolutionRate: normalizeRatio(
        firstNumber(performance.new_case_resolution_rate),
      ),
      backlog: firstNumber(performance.open_backlog_count),
      pendingApproval: firstNumber(performance.pending_approval_count),
      oldestBacklogDays: firstNumber(performance.oldest_backlog_days),
      medianClosureHours: firstNumber(performance.median_closure_hours),
      respondedWithin24Hours: normalizeRatio(
        firstNumber(performance.responded_within_24h_rate),
      ),
    },
    quality: {
      invalidBatches: firstNumber(
        quality.ignored_batches_with_invalid_time,
      ),
      invalidCases: firstNumber(quality.ignored_cases_with_invalid_time),
      invalidEvents: firstNumber(quality.ignored_events_with_invalid_time),
      inferredClosures: firstNumber(
        quality.inferred_closure_timestamps,
      ),
    },
  };
}

function renderAnalytics(analytics) {
  elements["trends-empty"].hidden = true;
  elements["trends-content"].hidden = false;
  elements["trend-executive-summary"].textContent = analytics.summary;
  renderTrendKpis(analytics);
  renderDailyTrend(analytics.daily);
  renderMineRanking(analytics.ranking);
  renderRepeatedAnomalies(analytics.repeated);
  renderAnalyticsQuality(analytics.quality);
}

function renderTrendKpis(analytics) {
  clearNode(elements["trend-kpi-grid"]);
  const performance = analytics.performance;
  const coverageComparison = compareRecentCoverage(analytics.daily);
  const cards = [
    {
      label: "30 日报送覆盖",
      value:
        analytics.coverage === null
          ? "未形成比例"
          : formatPercent(analytics.coverage),
      note:
        analytics.expected === null
          ? "应报数量未返回"
          : `实收 ${formatCount(analytics.received)} / 应报 ${formatCount(analytics.expected)} 矿次`,
    },
    {
      label: "近 7 日覆盖变化",
      value: coverageComparison.value,
      note: coverageComparison.note,
    },
    {
      label: "当前开放事项",
      value: formatCount(performance.backlog),
      note:
        performance.oldestBacklogDays === null
          ? "最早积压时长未返回"
          : `最早积压 ${formatCompactDurationDays(performance.oldestBacklogDays)}`,
    },
    {
      label: "待另一人审批",
      value: formatCount(performance.pendingApproval),
      note:
        performance.closedCycles === null
          ? "闭环数量未返回"
          : `本期完成 ${performance.closedCycles} 个办理周期`,
    },
  ];
  cards.forEach((item) => {
    const card = document.createElement("article");
    card.className = "trend-kpi";
    const label = document.createElement("span");
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.textContent = item.value;
    const note = document.createElement("small");
    note.textContent = item.note;
    card.append(label, value, note);
    elements["trend-kpi-grid"].appendChild(card);
  });
}

function compareRecentCoverage(daily) {
  const current = aggregateCoverage(daily.slice(-7));
  const previous = aggregateCoverage(daily.slice(-14, -7));
  if (current === null) {
    return {
      value: "暂无可比数据",
      note: "近 7 日无应报矿次，不按 0% 计算",
    };
  }
  if (previous === null) {
    return {
      value: formatPercent(current),
      note: "前 7 日无可比应报数据",
    };
  }
  const change = current - previous;
  const direction =
    Math.abs(change) < 0.0005 ? "持平" : change > 0 ? "上升" : "下降";
  return {
    value: direction,
    note: `${formatPercent(previous)} → ${formatPercent(current)}（${formatSignedPercentagePoint(change)}）`,
  };
}

function aggregateCoverage(points) {
  let expected = 0;
  let received = 0;
  points.forEach((point) => {
    if (
      point.expected !== null &&
      point.received !== null &&
      point.expected > 0
    ) {
      expected += point.expected;
      received += point.received;
    }
  });
  return expected > 0 ? received / expected : null;
}

function renderDailyTrend(daily) {
  clearNode(elements["daily-trend-chart"]);
  const points = daily.slice(-30);
  if (!points.length) {
    const empty = document.createElement("p");
    empty.className = "muted-note";
    empty.textContent = "暂无每日趋势点。";
    elements["daily-trend-chart"].appendChild(empty);
    return;
  }
  const backlogValues = points
    .map((point) => point.backlog)
    .filter((value) => value !== null);
  const maximum = backlogValues.length
    ? Math.max(1, ...backlogValues)
    : 1;
  points.forEach((point) => {
    const day = document.createElement("div");
    day.className = "trend-day";
    const rate = document.createElement("span");
    rate.className = "trend-day-rate";
    rate.textContent =
      point.coverage === null ? "—" : formatPercent(point.coverage);
    const track = document.createElement("span");
    track.className = "trend-day-bar-track";
    const bar = document.createElement("span");
    bar.className = "trend-day-bar";
    const backlogHeight =
      point.backlog === null ? 0 : Math.max(0, point.backlog / maximum);
    bar.style.height = `${Math.round(backlogHeight * 100)}%`;
    track.appendChild(bar);
    const label = document.createElement("span");
    label.className = "trend-day-label";
    label.textContent = shortDay(point.day);
    day.title =
      `${point.day || "日期未返回"}：覆盖 ${
        point.coverage === null ? "不适用" : formatPercent(point.coverage)
      }，日末开放事项 ${formatCount(point.backlog)}`;
    day.append(rate, track, label);
    elements["daily-trend-chart"].appendChild(day);
  });
}

function renderMineRanking(ranking) {
  clearNode(elements["mine-risk-ranking"]);
  const rows = ranking.slice(0, 5);
  rows.forEach((rawRow, index) => {
    const row = objectOrNull(rawRow) || {};
    const item = document.createElement("li");
    const rank = document.createElement("span");
    rank.className = "risk-rank";
    rank.textContent = String(firstNumber(row.rank) || index + 1);
    const mine = document.createElement("div");
    mine.className = "risk-mine";
    const name = document.createElement("strong");
    name.textContent = displayText(row.mine_id, "矿山未标识");
    const reasons = arrayOrNull(row.reasons) || [];
    const note = document.createElement("small");
    note.textContent = reasons.length
      ? reasons.slice(0, 2).join("；")
      : `开放事项 ${formatCount(firstNumber(row.open_cases))} 件`;
    mine.append(name, note);
    const score = document.createElement("span");
    score.className = "risk-score";
    score.textContent =
      firstNumber(row.risk_score) === null
        ? "关注分未返回"
        : `关注分 ${firstNumber(row.risk_score)}`;
    item.append(rank, mine, score);
    elements["mine-risk-ranking"].appendChild(item);
  });
  elements["mine-ranking-empty"].hidden = rows.length > 0;
}

function renderRepeatedAnomalies(repeated) {
  clearNode(elements["repeated-anomaly-list"]);
  repeated.slice(0, 8).forEach((rawItem) => {
    const item = objectOrNull(rawItem) || {};
    const row = document.createElement("li");
    row.textContent =
      `${displayText(item.mine_id, "矿山未标识")}：${
        displayText(item.anomaly_name, "技术线索")
      }，不同批次出现 ${formatCount(firstNumber(item.distinct_batch_count))} 次`;
    elements["repeated-anomaly-list"].appendChild(row);
  });
  if (!repeated.length) {
    const row = document.createElement("li");
    row.textContent = "当前统计窗口未识别到跨批次重复线索。";
    elements["repeated-anomaly-list"].appendChild(row);
  }
}

function renderAnalyticsQuality(quality) {
  clearNode(elements["analytics-quality-list"]);
  [
    ["批次时间无效而未纳入", quality.invalidBatches],
    ["事项时间无效而未纳入", quality.invalidCases],
    ["办理记录时间无效而未纳入", quality.invalidEvents],
    ["依据事项状态推断关闭时间", quality.inferredClosures],
  ].forEach(([label, value]) => {
    const wrapper = document.createElement("div");
    wrapper.className = "trace-field";
    const term = document.createElement("dt");
    term.textContent = label;
    const definition = document.createElement("dd");
    definition.textContent = formatCount(value);
    wrapper.append(term, definition);
    elements["analytics-quality-list"].appendChild(wrapper);
  });
}

function shortDay(value) {
  if (!value) {
    return "—";
  }
  const parts = String(value).split("-");
  return parts.length >= 3 ? `${parts[1]}/${parts[2]}` : String(value);
}

function formatSignedPercentagePoint(value) {
  const points = value * 100;
  const prefix = points > 0 ? "+" : "";
  return `${prefix}${points.toFixed(1)} 个百分点`;
}

function formatCompactDurationDays(value) {
  if (value < 1) {
    return `${Math.round(value * 24)} 小时`;
  }
  return `${Number(value.toFixed(1))} 天`;
}

function normalizeHistoricalEvidence(rawEvidence, rawScenarioMatches = null) {
  const evidence = objectOrNull(rawEvidence);
  if (!evidence) {
    return null;
  }
  const assessment =
    objectOrNull(pickFirst(evidence, "assessment")) || evidence;
  const rawStatus = String(
    pickFirst(assessment, "status", "historical_status") || "",
  )
    .trim()
    .toLowerCase();
  const rare = booleanOrNull(
    pickFirst(assessment, "historically_rare", "rare"),
  );
  let status = "unknown";
  if (
    rawStatus === "insufficient_history" ||
    rawStatus === "insufficient"
  ) {
    status = "insufficient_history";
  } else if (
    rawStatus === "historically_rare" ||
    rawStatus === "rare" ||
    rare === true
  ) {
    status = "historically_rare";
  } else if (
    rawStatus === "within_baseline" ||
    rawStatus === "normal" ||
    (rawStatus === "ready" && rare === false)
  ) {
    status = "within_baseline";
  }
  const rawMatches =
    rawScenarioMatches ||
    pickFirst(
      evidence,
      "legitimate_scenario_matches",
      "scenario_matches",
    );
  const matchesObject = objectOrNull(rawMatches);
  const matches =
    arrayOrNull(rawMatches) ||
    arrayOrNull(
      matchesObject &&
        pickFirst(
          matchesObject,
          "matched_scenarios",
          "matches",
          "items",
        ),
    ) ||
    [];
  return {
    status,
    selectedSampleCount: firstNumber(
      pickFirst(
        assessment,
        "selected_sample_count",
        "eligible_sample_count",
        "sample_count",
      ),
    ),
    eligibleSampleCount: firstNumber(
      pickFirst(assessment, "eligible_sample_count"),
    ),
    minimumRequiredSamples: firstNumber(
      pickFirst(assessment, "minimum_required_samples", "minimum_samples"),
    ),
    rarityScore: firstNumber(
      pickFirst(assessment, "rarity_score"),
    ),
    overallPValue: firstNumber(
      pickFirst(assessment, "overall_p_value", "p_value"),
    ),
    contextConditioned: booleanOrNull(
      pickFirst(assessment, "context_conditioned"),
    ),
    explanation: nullableText(pickFirst(assessment, "explanation")),
    physicalStatusUnchanged:
      booleanOrNull(
        pickFirst(assessment, "physical_status_unchanged"),
      ) === true,
    legitimateScenarioMatches: matches,
    assessment,
  };
}

function normalizeTemporalEvidence(rawEvidence) {
  const evidence = objectOrNull(rawEvidence);
  if (!evidence) {
    return null;
  }
  const rawStatus = String(pickFirst(evidence, "status") || "")
    .trim()
    .toLowerCase();
  const status = ["normal", "anomalous", "insufficient_history"].includes(
    rawStatus,
  )
    ? rawStatus
    : "insufficient_history";
  return {
    status,
    reasonCode: nullableText(pickFirst(evidence, "reason_code")),
    sampleCount: firstNumber(
      pickFirst(evidence, "sample_count", "baseline_sample_count"),
    ),
    rollingRobustZ: firstNumber(
      pickFirst(evidence, "rolling_robust_z"),
    ),
    explanation: nullableText(pickFirst(evidence, "explanation")),
    raw: evidence,
  };
}

function normalizeEvidenceFusion(rawFusion) {
  const fusion = objectOrNull(rawFusion);
  if (!fusion) {
    return null;
  }
  return {
    agreement: nullableText(pickFirst(fusion, "agreement")),
    shadowPriority: normalizePriority(
      pickFirst(fusion, "shadow_priority"),
    ),
    originalReviewPriority: normalizePriority(
      pickFirst(fusion, "original_review_priority"),
    ),
    physicalStatus: normalizeTechnicalStatus(
      pickFirst(fusion, "physical_status"),
    ),
    physicalStatusUnchanged:
      booleanOrNull(
        pickFirst(fusion, "physical_status_unchanged"),
      ) === true,
    historicalSupportsPhysical:
      booleanOrNull(
        pickFirst(fusion, "historical_supports_physical"),
      ) === true,
    reasons: arrayOrNull(pickFirst(fusion, "reasons")) || [],
    safeguards: arrayOrNull(pickFirst(fusion, "safeguards")) || [],
    raw: fusion,
  };
}

function normalizeOverviewItem(rawItem) {
  const raw =
    rawItem && typeof rawItem === "object" && !Array.isArray(rawItem)
      ? rawItem
      : {};
  const resultCandidates = [
    raw,
    objectOrNull(raw.result),
    objectOrNull(raw.analysis),
    objectOrNull(raw.analysis_result),
    objectOrNull(raw.latest_analysis),
  ].filter(Boolean);
  const technicalStatus = normalizeTechnicalStatus(
    pickAcross(
      resultCandidates,
      "technical_status",
      "status",
      "analysis_status",
      "result.status",
    ),
  );
  const workflowStatus = normalizeWorkflowStatus(
    pickAcross(
      resultCandidates,
      "workflow_status",
      "case_status",
      "workflow.status",
    ),
  );
  const explicitPriority = normalizePriority(
    pickAcross(
      resultCandidates,
      "priority_level",
      "review_priority",
      "priority",
      "priority_code",
    ),
  );
  const priority = explicitPriority || inferPriority(technicalStatus);
  const dataQualityStatus = String(
    pickAcross(
      resultCandidates,
      "data_quality.status",
      "data_quality_status",
    ) || "",
  )
    .trim()
    .toLowerCase();
  const unverifiedDimensions =
    arrayOrNull(
      pickAcross(
        resultCandidates,
        "data_quality.unverified_dimensions",
        "unverified_dimensions",
      ),
    ) || [];
  const mineId = displayText(
    pickAcross(resultCandidates, "mine_id", "mine.id"),
    "矿山编号未返回",
  );
  const mineName = displayText(
    pickAcross(
      resultCandidates,
      "mine_name",
      "display_name",
      "mine.name",
    ),
    mineId,
  );
  const expectedSources = firstNumber(
    pickAcross(
      resultCandidates,
      "expected_source_count",
      "expected_sources_count",
      "data_coverage.expected",
    ),
  );
  const receivedSources = firstNumber(
    pickAcross(
      resultCandidates,
      "received_source_count",
      "received_sources_count",
      "data_coverage.received",
    ),
  );
  const coverageRatio = normalizeRatio(
    firstNumber(
      pickAcross(
        resultCandidates,
        "coverage_ratio",
        "data_coverage.coverage_ratio",
      ),
      expectedSources !== null &&
        expectedSources > 0 &&
        receivedSources !== null
        ? receivedSources / expectedSources
        : undefined,
    ),
  );
  const summary = displayText(
    pickAcross(
      resultCandidates,
      "plain_summary",
      "summary",
      "issue_summary",
      "technical_summary",
    ),
    defaultTechnicalSummary(technicalStatus),
  );
  const historicalEvidence = normalizeHistoricalEvidence(
    pickAcross(resultCandidates, "historical_evidence"),
    pickAcross(
      resultCandidates,
      "legitimate_scenario_matches",
      "historical_evidence.legitimate_scenario_matches",
    ),
  );
  const temporalEvidence = normalizeTemporalEvidence(
    pickAcross(resultCandidates, "temporal_evidence"),
  );
  const evidenceFusion = normalizeEvidenceFusion(
    pickAcross(resultCandidates, "evidence_fusion"),
  );

  return {
    caseId: nullableText(
      pickAcross(resultCandidates, "case_id", "case.id", "id"),
    ),
    analysisRunId: nullableText(
      pickAcross(
        resultCandidates,
        "analysis_run_id",
        "run_id",
        "analysis.id",
      ),
    ),
    mineId,
    mineName,
    companyName: nullableText(
      pickAcross(resultCandidates, "company_name", "company.name"),
    ),
    windowStart: pickAcross(
      resultCandidates,
      "window_start",
      "period_start",
      "analysis.window_start",
    ),
    windowEnd: pickAcross(
      resultCandidates,
      "window_end",
      "period_end",
      "analysis.window_end",
    ),
    priority,
    priorityScore: firstNumber(
      pickAcross(resultCandidates, "priority_score"),
    ),
    priorityReasons:
      arrayOrNull(pickAcross(resultCandidates, "priority_reasons")) || [],
    technicalStatus,
    dataQualityStatus,
    unverifiedDimensions,
    workflowStatus,
    summary,
    minimumGap: firstNumber(
      pickAcross(
        resultCandidates,
        "robust_minimum_reported_gap",
        "minimum_required_gap",
        "minimum_reported_gap",
        "minimum_technical_gap_t",
      ),
    ),
    evidenceGrade: nullableText(
      pickAcross(resultCandidates, "evidence_grade"),
    ),
    expectedSources,
    receivedSources,
    coverageRatio,
    dataReceiptStatus: nullableText(
      pickAcross(
        resultCandidates,
        "data_receipt_status",
        "submission_status",
        "value_status",
      ),
    ),
    assignee: nullableText(
      pickAcross(
        resultCandidates,
        "assignee_name",
        "assignee",
        "assigned_org",
      ),
    ),
    dueAt: pickAcross(resultCandidates, "due_at", "deadline"),
    overdue: Boolean(pickAcross(resultCandidates, "overdue", "is_overdue")),
    updatedAt: pickAcross(
      resultCandidates,
      "updated_at",
      "last_updated_at",
      "analyzed_at",
    ),
    repeatCount: firstNumber(
      pickAcross(
        resultCandidates,
        "repeat_count_30d",
        "repeat_count",
      ),
    ),
    version: firstNumber(
      pickAcross(resultCandidates, "version", "case_version"),
    ),
    historicalEvidence,
    temporalEvidence,
    evidenceFusion,
    raw,
  };
}

function historicalStatusLabel(status) {
  const labels = {
    insufficient_history: "历史样本不足",
    within_baseline: "当前在历史范围内",
    historically_rare: "当前相对历史罕见",
    unknown: "历史状态未形成",
  };
  return labels[status] || labels.unknown;
}

function historicalCompactText(evidence) {
  if (!evidence) {
    return "历史证据尚未评估";
  }
  const sampleText =
    evidence.selectedSampleCount === null
      ? ""
      : ` · ${formatCount(evidence.selectedSampleCount)} 个可比样本`;
  const rarityText =
    evidence.rarityScore === null
      ? ""
      : ` · 罕见度 ${formatNumber(evidence.rarityScore, 1)}/100`;
  return `${historicalStatusLabel(evidence.status)}${sampleText}${rarityText}`;
}

function temporalCompactText(evidence) {
  if (!evidence) {
    return "时序证据尚未评估";
  }
  const labels = {
    normal: "当前时序平稳",
    anomalous: "当前出现时序突变",
    insufficient_history: "可比时序历史不足",
  };
  const sampleText =
    evidence.sampleCount === null
      ? ""
      : ` · ${formatCount(evidence.sampleCount)} 个过去窗口`;
  return `${labels[evidence.status] || labels.insufficient_history}${sampleText}`;
}

function fusionCompactText(fusion) {
  if (!fusion) {
    return "尚未形成多路证据融合";
  }
  const agreement =
    FUSION_AGREEMENT_LABELS[fusion.agreement] ||
    displayText(fusion.agreement, "证据关系未形成");
  const shadow = fusion.shadowPriority
    ? ` · 影子排序 ${statusBadgeSpec(fusion.shadowPriority, "priority").label}`
    : "";
  return `${agreement}${shadow} · 物理结论未改变`;
}

function renderOverviewQueue() {
  clearNode(elements["overview-priority-body"]);
  const query = elements["overview-search"].value.trim().toLocaleLowerCase("zh-CN");
  const focus = elements["overview-focus-filter"].value;
  const items = state.overviewItems
    .filter((item) => overviewItemMatches(item, query, focus))
    .sort(comparePriorityItems)
    .slice(0, 12);

  items.forEach((item) => {
    const row = document.createElement("tr");

    const priorityCell = document.createElement("td");
    priorityCell.appendChild(createStatusBadge(item.priority, "priority"));

    const mineCell = document.createElement("td");
    appendPrimarySecondary(
      mineCell,
      item.mineName,
      `${item.mineId} · ${formatPeriod(item.windowStart, item.windowEnd)}`,
    );

    const summaryCell = document.createElement("td");
    const summary = document.createElement("span");
    summary.className = "table-summary";
    summary.textContent = item.summary;
    summaryCell.appendChild(summary);
    const summaryMeta = [
      item.minimumGap !== null
        ? `最小技术差额 ${formatTon(item.minimumGap)}`
        : null,
      item.evidenceGrade
        ? `支撑等级 ${item.evidenceGrade}（非处罚等级）`
        : null,
      historicalCompactText(item.historicalEvidence),
      temporalCompactText(item.temporalEvidence),
      fusionCompactText(item.evidenceFusion),
    ]
      .filter(Boolean)
      .join(" · ");
    if (summaryMeta) {
      const meta = document.createElement("span");
      meta.className = "table-secondary";
      meta.textContent = summaryMeta;
      summaryCell.appendChild(meta);
    }

    const receiptCell = document.createElement("td");
    appendPrimarySecondary(
      receiptCell,
      dataReceiptLabel(item),
      dataReceiptNote(item),
    );

    const technicalCell = document.createElement("td");
    technicalCell.appendChild(
      createStatusBadge(item.technicalStatus, "technical"),
    );

    const workflowCell = document.createElement("td");
    workflowCell.appendChild(
      createStatusBadge(item.workflowStatus, "workflow"),
    );

    const ownerCell = document.createElement("td");
    appendPrimarySecondary(
      ownerCell,
      item.assignee || "待明确责任人",
      item.dueAt
        ? `${item.overdue ? "已逾期 · " : "期限 · "}${formatDateTime(item.dueAt)}`
        : "期限待安排",
    );

    const actionCell = document.createElement("td");
    const actionStack = document.createElement("div");
    actionStack.className = "row-action-stack";
    if (item.caseId) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "table-action";
      button.textContent = "查看事项";
      button.addEventListener("click", () => openCase(item.caseId));
      actionStack.appendChild(button);
    }
    if (item.analysisRunId) {
      const labelButton = document.createElement("button");
      labelButton.type = "button";
      labelButton.className = "table-action";
      labelButton.textContent = userCan("referenceLabel")
        ? "标记历史样本"
        : "查看历史标签";
      labelButton.addEventListener("click", () =>
        openOverviewReferenceLabelDialog(item),
      );
      actionStack.appendChild(labelButton);
    }
    if (!item.caseId && !item.analysisRunId) {
      const note = document.createElement("span");
      note.className = "table-secondary";
      note.textContent = overviewActionLabel(item);
      actionStack.appendChild(note);
    }
    actionCell.appendChild(actionStack);

    row.append(
      priorityCell,
      mineCell,
      summaryCell,
      receiptCell,
      technicalCell,
      workflowCell,
      ownerCell,
      actionCell,
    );
    elements["overview-priority-body"].appendChild(row);
  });

  elements["overview-queue-empty"].hidden = items.length > 0;
  elements["overview-priority-body"].parentElement.parentElement.hidden =
    items.length === 0;
}

function overviewActionLabel(item) {
  if (item.technicalStatus !== "consistent") {
    return "待形成事项";
  }
  const fullyVerified =
    item.priority === "normal" &&
    item.dataQualityStatus === "sufficient" &&
    item.unverifiedDimensions.length === 0;
  return fullyVerified ? "无需建账" : "待补证/待形成事项";
}

function overviewItemMatches(item, query, focus) {
  const searchText = [
    item.mineName,
    item.mineId,
    item.summary,
    item.assignee,
  ]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase("zh-CN");
  if (query && !searchText.includes(query)) {
    return false;
  }
  if (focus === "missing") {
    return ["missing", "inconclusive", "solver_error"].includes(
      item.technicalStatus,
    );
  }
  if (focus === "inconsistent") {
    return item.technicalStatus === "inconsistent";
  }
  if (focus === "open") {
    return (
      item.caseId !== null &&
      !["closed", "resolved"].includes(item.workflowStatus)
    );
  }
  return true;
}

function comparePriorityItems(left, right) {
  const rank = {
    urgent: 0,
    high: 1,
    supplement: 2,
    normal: 3,
    unknown: 4,
  };
  const rankDifference =
    (Object.prototype.hasOwnProperty.call(rank, left.priority)
      ? rank[left.priority]
      : rank.unknown) -
    (Object.prototype.hasOwnProperty.call(rank, right.priority)
      ? rank[right.priority]
      : rank.unknown);
  if (rankDifference !== 0) {
    return rankDifference;
  }
  if (left.overdue !== right.overdue) {
    return left.overdue ? -1 : 1;
  }
  const leftScore = left.priorityScore === null ? -1 : left.priorityScore;
  const rightScore = right.priorityScore === null ? -1 : right.priorityScore;
  return rightScore - leftScore;
}

function dataReceiptLabel(item) {
  if (
    item.technicalStatus === "missing" ||
    ["missing", "not_received", "late_missing"].includes(
      item.dataReceiptStatus,
    )
  ) {
    return "缺报（未收到）";
  }
  if (item.coverageRatio !== null) {
    return `已收到 ${formatPercent(item.coverageRatio)}`;
  }
  if (item.receivedSources !== null && item.expectedSources !== null) {
    return `已收到 ${item.receivedSources}/${item.expectedSources} 类`;
  }
  return "已收到，覆盖待确认";
}

function dataReceiptNote(item) {
  if (item.technicalStatus === "missing") {
    return "没有数值，不按 0 展示";
  }
  if (item.repeatCount !== null && item.repeatCount > 0) {
    return `近 30 日重复 ${item.repeatCount} 次`;
  }
  return "数据接收与技术判断分开";
}

async function loadJobs() {
  if (state.jobsLoading || !state.authInitialized) {
    return;
  }
  state.jobsLoading = true;
  elements["refresh-jobs"].disabled = true;
  setLoadStatus(elements["jobs-status"], "正在读取分析任务…", "loading");
  try {
    const body = await requestJson(
      state.showArchivedJobs
        ? `${SUPERVISION_API_PATHS.jobs}?include_archived=1`
        : SUPERVISION_API_PATHS.jobs,
    );
    const rawJobs =
      arrayOrNull(
        Array.isArray(body) ? body : pickFirst(body, "items", "jobs"),
      ) || [];
    state.jobs = rawJobs.map(normalizeJob);
    state.jobsLoaded = true;
    renderJobs();
    setLoadStatus(
      elements["jobs-status"],
      state.jobs.length
        ? `共 ${state.jobs.length} 个任务${
            state.showArchivedJobs ? "（含已归档）" : ""
          }；运行中的任务会自动刷新。`
        : "任务列表已读取，当前无任务。",
    );
  } catch (error) {
    state.jobsLoaded = false;
    showJobsEmpty(
      error instanceof ApiError && error.status === 403
        ? "当前账号没有运行或查看分析任务的权限。"
        : "暂时无法读取分析任务。读取失败不表示任务已完成或不存在。",
    );
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, "分析任务"),
      "error",
    );
  } finally {
    state.jobsLoading = false;
    elements["refresh-jobs"].disabled = false;
  }
}

function normalizeJob(rawJob) {
  const raw = objectOrNull(rawJob) || {};
  const outcomes =
    (arrayOrNull(pickFirst(raw, "outcomes", "windows")) || []).map(
      normalizeJobWindow,
    );
  return {
    job_id: displayText(pickFirst(raw, "job_id", "id"), "任务编号未返回"),
    idempotency_key: nullableText(raw.idempotency_key),
    requested_by: displayText(raw.requested_by, "提交人未返回"),
    parent_job_id: nullableText(raw.parent_job_id),
    status: normalizeJobStatus(raw.status),
    total_windows: firstNumber(raw.total_windows, outcomes.length),
    completed_windows: firstNumber(raw.completed_windows),
    succeeded_windows: firstNumber(raw.succeeded_windows),
    failed_windows: firstNumber(raw.failed_windows),
    cancelled_windows: firstNumber(raw.cancelled_windows),
    attempt: firstNumber(raw.attempt),
    cancellation_requested: Boolean(raw.cancellation_requested),
    created_at: raw.created_at,
    started_at: raw.started_at,
    finished_at: raw.finished_at,
    updated_at: raw.updated_at,
    visible_windows: firstNumber(raw.visible_windows),
    scope_limited: Boolean(raw.scope_limited),
    archived_at: raw.archived_at,
    archived_by: nullableText(raw.archived_by),
    archived_reason: nullableText(raw.archived_reason),
    outcomes,
    raw,
  };
}

function normalizeJobWindow(rawWindow) {
  const raw = objectOrNull(rawWindow) || {};
  return {
    window_id: displayText(raw.window_id, "窗口未标识"),
    mine_id: displayText(raw.mine_id, "矿山未标识"),
    status: normalizeJobStatus(raw.status),
    attempt: firstNumber(raw.attempt),
    result_sha256: nullableText(raw.result_sha256),
    error_code: nullableText(raw.error_code),
    error_summary: nullableText(raw.error_summary),
    started_at: raw.started_at,
    finished_at: raw.finished_at,
    result: objectOrNull(raw.result),
  };
}

function normalizeJobStatus(value) {
  const status = String(value || "unknown")
    .trim()
    .toLowerCase()
    .split("-")
    .join("_");
  return Object.prototype.hasOwnProperty.call(JOB_STATUS_LABELS, status)
    ? status
    : status;
}

function renderJobs() {
  clearJobPoll();
  if (!state.jobs.length) {
    showJobsEmpty(
      userCan("directRun")
        ? "当前没有分析任务。可提交内置脱敏窗口，体验任务进度和失败隔离。"
        : "当前授权范围内没有可查看的分析任务。",
    );
    updateRunningJobCount(0);
    return;
  }
  elements["jobs-empty"].hidden = true;
  elements["job-detail"].hidden = true;
  elements["jobs-content"].hidden = false;
  renderJobSummary();
  renderJobTable();
  const runningCount = state.jobs.filter((job) =>
    ["queued", "running"].includes(job.status),
  ).length;
  updateRunningJobCount(runningCount);
  scheduleJobPoll();
}

function showJobsEmpty(message) {
  clearJobPoll();
  elements["jobs-empty"].hidden = false;
  elements["jobs-empty-message"].textContent = message;
  elements["jobs-content"].hidden = true;
  elements["job-detail"].hidden = true;
}

function renderJobSummary() {
  clearNode(elements["jobs-summary-grid"]);
  const statuses = [
    "queued",
    "running",
    "succeeded",
    "partial_failed",
    "failed",
    "cancelled",
  ];
  statuses.forEach((status) => {
    const count = state.jobs.filter((job) => job.status === status).length;
    const card = document.createElement("article");
    card.className =
      `job-summary-card${
        ["queued", "running"].includes(status)
          ? " is-active"
          : ["partial_failed", "failed"].includes(status)
            ? " is-problem"
            : status === "succeeded"
              ? " is-success"
              : ""
      }`;
    const label = document.createElement("span");
    label.textContent = JOB_STATUS_LABELS[status];
    const value = document.createElement("strong");
    value.textContent = String(count);
    card.append(label, value);
    elements["jobs-summary-grid"].appendChild(card);
  });
}

function renderJobTable() {
  clearNode(elements["jobs-table-body"]);
  state.jobs.forEach((job) => {
    const row = document.createElement("tr");
    const statusCell = document.createElement("td");
    statusCell.appendChild(createJobStatusBadge(job.status));

    const identityCell = document.createElement("td");
    appendPrimarySecondary(
      identityCell,
      job.job_id,
      job.archived_at
        ? `${job.requested_by} · 已归档：${job.archived_reason || "未说明原因"}`
        : `${job.requested_by} · ${formatDateTime(job.created_at)}`,
    );

    const progressCell = document.createElement("td");
    progressCell.appendChild(createJobProgress(job));

    const failureCell = document.createElement("td");
    const failure = document.createElement("span");
    failure.className = "job-failure-summary";
    failure.textContent = jobFailureSummary(job);
    failureCell.appendChild(failure);

    const updatedCell = document.createElement("td");
    appendPrimarySecondary(
      updatedCell,
      formatDateTime(job.updated_at),
      job.scope_limited ? "仅显示授权矿山窗口" : "",
    );

    const actionCell = document.createElement("td");
    actionCell.appendChild(createJobActions(job, false));
    row.append(
      statusCell,
      identityCell,
      progressCell,
      failureCell,
      updatedCell,
      actionCell,
    );
    elements["jobs-table-body"].appendChild(row);
  });
}

function createJobProgress(job) {
  const wrapper = document.createElement("div");
  wrapper.className = "job-progress-compact";
  const counts = document.createElement("span");
  const completed = job.completed_windows === null ? 0 : job.completed_windows;
  const total = job.total_windows === null ? 0 : job.total_windows;
  counts.textContent =
    total > 0 ? `${completed} / ${total} 个窗口` : "窗口数未返回";
  const meter = document.createElement("div");
  meter.className = "mini-progress";
  meter.setAttribute("aria-hidden", "true");
  const fill = document.createElement("span");
  fill.style.width = `${jobProgressRatio(job) * 100}%`;
  meter.appendChild(fill);
  wrapper.append(counts, meter);
  return wrapper;
}

function jobProgressRatio(job) {
  if (
    job.total_windows === null ||
    job.total_windows <= 0 ||
    job.completed_windows === null
  ) {
    return 0;
  }
  return Math.max(
    0,
    Math.min(job.completed_windows / job.total_windows, 1),
  );
}

function jobFailureSummary(job) {
  const failures = job.outcomes
    .filter((window) => window.status === "failed")
    .map(
      (window) =>
        `${window.mine_id}/${window.window_id}：${
          window.error_summary || "该窗口分析未完成"
        }`,
    );
  if (failures.length) {
    return `${failures.slice(0, 2).join("；")}${
      failures.length > 2 ? `；另有 ${failures.length - 2} 个失败窗口` : ""
    }`;
  }
  if (job.failed_windows !== null && job.failed_windows > 0) {
    return `${job.failed_windows} 个窗口失败，请打开任务查看摘要。`;
  }
  if (job.status === "cancelled") {
    return "任务已取消，未运行窗口不产生分析结论。";
  }
  return "暂未记录失败窗口。";
}

function createJobStatusBadge(status) {
  const badge = document.createElement("span");
  badge.className = `status-badge is-${String(status).split("_").join("-")}`;
  badge.textContent = JOB_STATUS_LABELS[status] || "状态待确认";
  return badge;
}

function createJobActions(job, detailed) {
  const wrapper = document.createElement("div");
  wrapper.className = detailed ? "job-detail-actions" : "job-row-actions";
  if (!detailed) {
    const view = document.createElement("button");
    view.type = "button";
    view.className = "table-action";
    view.textContent = "查看窗口";
    view.addEventListener("click", () => openJob(job.job_id));
    wrapper.appendChild(view);
  }
  if (userCan("cancelJob") && ["queued", "running"].includes(job.status)) {
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = detailed ? "button quiet compact" : "table-action";
    cancel.textContent = "取消任务";
    cancel.addEventListener("click", () => cancelJob(job.job_id));
    wrapper.appendChild(cancel);
  }
  if (
    userCan("directRun") &&
    ["succeeded", "partial_failed", "failed", "cancelled"].includes(job.status)
  ) {
    const replay = document.createElement("button");
    replay.type = "button";
    replay.className = detailed ? "button secondary compact" : "table-action";
    replay.textContent = "重新执行";
    replay.addEventListener("click", () => replayJob(job.job_id));
    wrapper.appendChild(replay);
  }
  if (
    userCan("cancelJob") &&
    ["succeeded", "partial_failed", "failed", "cancelled"].includes(job.status)
  ) {
    const archive = document.createElement("button");
    archive.type = "button";
    archive.className = detailed ? "button quiet compact" : "table-action";
    archive.textContent = job.archived_at ? "恢复显示" : "归档任务";
    archive.addEventListener("click", () =>
      archiveJob(job, !job.archived_at),
    );
    wrapper.appendChild(archive);
  }
  return wrapper;
}

async function submitPilotJob() {
  if (!userCan("directRun")) {
    setLoadStatus(elements["jobs-status"], "当前账号没有提交分析任务的权限。", "error");
    return;
  }
  setJobSubmitDisabled(true);
  setLoadStatus(
    elements["jobs-status"],
    "正在提交脱敏分析窗口；重复点击将按幂等键返回同一任务…",
    "loading",
  );
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.jobs, {
      method: "POST",
      body: JSON.stringify(buildPilotJobPayload()),
    });
    state.jobsLoaded = false;
    setWorkspace("jobs", false);
    await loadJobs();
    const created = normalizeJob(pickFirst(body, "job") || body);
    setLoadStatus(
      elements["jobs-status"],
      `任务 ${created.job_id} 已提交，可查看各窗口进度。`,
    );
  } catch (error) {
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, "提交分析任务"),
      "error",
    );
  } finally {
    setJobSubmitDisabled(false);
  }
}

function setJobSubmitDisabled(disabled) {
  elements["submit-pilot-job"].disabled = disabled;
  elements["submit-pilot-job-empty"].disabled = disabled;
}

function buildPilotJobPayload() {
  return {
    idempotency_key: "leader-pilot-demo-v1",
    windows: [
      {
        window_id: "M001-20260720",
        mine_id: "M001",
        payload: JSON.parse(JSON.stringify(PRODUCTION_RISK_SAMPLE)),
      },
      {
        window_id: "M002-20260720",
        mine_id: "M002",
        payload: JSON.parse(JSON.stringify(PRODUCTION_NORMAL_SAMPLE)),
      },
    ],
  };
}

async function openJob(jobId, focus = true) {
  if (!jobId) {
    return;
  }
  clearJobPoll();
  setLoadStatus(elements["jobs-status"], "正在读取任务窗口明细…", "loading");
  try {
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.jobs}/${encodeURIComponent(jobId)}`,
    );
    const job = normalizeJob(pickFirst(body, "job") || body);
    const existingIndex = state.jobs.findIndex(
      (item) => item.job_id === job.job_id,
    );
    if (existingIndex >= 0) {
      state.jobs.splice(existingIndex, 1, job);
    }
    state.currentJob = job;
    elements["jobs-content"].hidden = true;
    elements["jobs-empty"].hidden = true;
    elements["job-detail"].hidden = false;
    renderJobDetail(job);
    setLoadStatus(elements["jobs-status"], "");
    if (focus) {
      elements["job-detail-title"].setAttribute("tabindex", "-1");
      elements["job-detail-title"].focus({ preventScroll: true });
    }
    scheduleJobPoll();
  } catch (error) {
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, "任务详情"),
      "error",
    );
  }
}

function renderJobDetail(job) {
  elements["job-detail-id"].textContent = `任务 ${job.job_id}`;
  elements["job-detail-title"].textContent =
    job.parent_job_id ? "重新执行的分析任务" : "批量分析任务";
  elements["job-detail-meta"].textContent = [
    `提交人 ${job.requested_by}`,
    `创建 ${formatDateTime(job.created_at)}`,
    job.parent_job_id ? `来源任务 ${job.parent_job_id}` : null,
    job.scope_limited ? "仅显示当前授权矿山" : null,
  ]
    .filter(Boolean)
    .join(" · ");
  const statusBadge = createJobStatusBadge(job.status);
  elements["job-detail-status"].className = statusBadge.className;
  elements["job-detail-status"].textContent = statusBadge.textContent;
  const completed = job.completed_windows === null ? 0 : job.completed_windows;
  const total = job.total_windows === null ? 0 : job.total_windows;
  elements["job-progress-title"].textContent =
    JOB_STATUS_LABELS[job.status] || "状态待确认";
  elements["job-progress-counts"].textContent =
    `已完成 ${completed}/${total} · 成功 ${
      job.succeeded_windows === null ? "未返回" : job.succeeded_windows
    } · 失败 ${
      job.failed_windows === null ? "未返回" : job.failed_windows
    } · 取消 ${
      job.cancelled_windows === null ? "未返回" : job.cancelled_windows
    }`;
  const percent = Math.round(jobProgressRatio(job) * 100);
  elements["job-progress-fill"].style.width = `${percent}%`;
  elements["job-progress-bar"].setAttribute("aria-valuenow", String(percent));
  clearNode(elements["job-detail-actions"]);
  const actions = createJobActions(job, true);
  Array.from(actions.children).forEach((child) =>
    elements["job-detail-actions"].appendChild(child),
  );
  renderJobWindows(job.outcomes);
}

function renderJobWindows(outcomes) {
  clearNode(elements["job-window-body"]);
  outcomes.forEach((window) => {
    const row = document.createElement("tr");
    addCell(row, window.window_id);
    addCell(row, window.mine_id);
    const statusCell = document.createElement("td");
    statusCell.appendChild(createJobStatusBadge(window.status));
    row.appendChild(statusCell);
    addCell(
      row,
      window.attempt === null ? "未返回" : String(window.attempt),
    );
    addCell(
      row,
      window.status === "failed"
        ? window.error_summary || "该窗口分析未完成"
        : window.result_sha256
          ? `结果哈希 ${shortHash(window.result_sha256)}`
          : window.status === "cancelled"
            ? "未运行，不产生分析结论"
            : "等待结果",
    );
    addCell(row, formatDateTime(window.finished_at));
    elements["job-window-body"].appendChild(row);
  });
  if (!outcomes.length) {
    appendEmptyRow(
      elements["job-window-body"],
      6,
      "当前权限范围内暂无窗口明细。",
    );
  }
}

function showJobList(shouldFocus = true) {
  state.currentJob = null;
  elements["job-detail"].hidden = true;
  if (state.jobs.length) {
    elements["jobs-content"].hidden = false;
    elements["jobs-empty"].hidden = true;
  }
  if (shouldFocus) {
    elements["refresh-jobs"].focus();
  }
  scheduleJobPoll();
}

async function cancelJob(jobId) {
  const confirmation = await requestActionConfirmation({
    title: `停止任务「${jobId}」的剩余窗口？`,
    message:
      "尚未开始的窗口将不再运行；当前正在计算的窗口可能完成，已经生成的结果和审计记录都会保留。",
    confirmLabel: "停止剩余窗口",
    danger: true,
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(elements["jobs-status"], "正在提交取消请求…", "loading");
  try {
    await requestJson(
      `${SUPERVISION_API_PATHS.jobs}/${encodeURIComponent(jobId)}/cancel`,
      { method: "POST" },
    );
    state.jobsLoaded = false;
    await loadJobs();
    setLoadStatus(
      elements["jobs-status"],
      "取消请求已记录；正在运行的窗口完成后，其余窗口将不再执行。",
    );
  } catch (error) {
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, "取消任务"),
      "error",
    );
  }
}

async function replayJob(jobId) {
  const confirmation = await requestActionConfirmation({
    title: `重新执行任务「${jobId}」？`,
    message:
      "系统会创建一个新任务；原任务、原结果和审计记录不会被覆盖或删除。",
    confirmLabel: "创建重跑任务",
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(elements["jobs-status"], "正在创建重新执行任务…", "loading");
  try {
    await requestJson(
      `${SUPERVISION_API_PATHS.jobs}/${encodeURIComponent(jobId)}/replay`,
      {
        method: "POST",
        body: JSON.stringify({
          idempotency_key: `replay-${jobId}-${fileTimestamp()}`,
        }),
      },
    );
    state.jobsLoaded = false;
    state.currentJob = null;
    await loadJobs();
    setLoadStatus(
      elements["jobs-status"],
      "已创建新的执行任务，原任务和结果仍保留。",
    );
  } catch (error) {
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, "重新执行任务"),
      "error",
    );
  }
}

async function archiveJob(job, archived) {
  const confirmation = await requestActionConfirmation({
    title: archived
      ? `归档任务「${job.job_id}」？`
      : `恢复任务「${job.job_id}」到常用列表？`,
    message: archived
      ? "归档只会把已结束任务移出常用列表，任务窗口、结果和审计记录仍可追溯。"
      : "恢复后任务会重新出现在常用列表，原结果不会发生变化。",
    confirmLabel: archived ? "确认归档" : "确认恢复",
    inputLabel: archived ? "归档原因" : "恢复原因",
    inputHelp: "原因会进入操作审计，请说明用途或依据。",
    inputPlaceholder: archived ? "例如：阶段性任务已验收" : "例如：需要再次查阅",
    inputRequired: true,
    inputMinLength: 2,
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(
    elements["jobs-status"],
    archived ? "正在归档任务…" : "正在恢复任务…",
    "loading",
  );
  try {
    await requestJson(
      `${SUPERVISION_API_PATHS.jobs}/${encodeURIComponent(job.job_id)}/archive`,
      {
        method: "POST",
        body: JSON.stringify({
          archived,
          reason: confirmation.value,
        }),
      },
    );
    state.jobsLoaded = false;
    state.currentJob = null;
    await loadJobs();
    showJobList(false);
    setLoadStatus(
      elements["jobs-status"],
      archived
        ? "任务已归档并移出常用列表；原结果和审计记录均已保留。"
        : "任务已恢复到常用列表。",
      "success",
    );
  } catch (error) {
    setLoadStatus(
      elements["jobs-status"],
      explainAccessError(error, archived ? "归档任务" : "恢复任务"),
      "error",
    );
  }
}

function scheduleJobPoll() {
  clearJobPoll();
  if (
    state.workspace !== "jobs" ||
    !state.authInitialized ||
    !state.jobs.some((job) => ["queued", "running"].includes(job.status))
  ) {
    return;
  }
  state.jobPollTimer = window.setTimeout(() => {
    if (state.currentJob) {
      openJob(state.currentJob.job_id, false);
    } else {
      loadJobs();
    }
  }, 3000);
}

function clearJobPoll() {
  if (state.jobPollTimer !== null) {
    window.clearTimeout(state.jobPollTimer);
    state.jobPollTimer = null;
  }
}

function updateRunningJobCount(count) {
  const badge = elements["nav-running-job-count"];
  if (count <= 0) {
    badge.hidden = true;
    badge.textContent = "";
    return;
  }
  badge.hidden = false;
  badge.textContent = count > 99 ? "99+" : String(count);
  badge.setAttribute("aria-label", `${count} 个排队或运行中的任务`);
}

async function refreshAdmin() {
  if (!isAdminUser()) {
    return;
  }
  state.usersLoaded = false;
  state.operationsLoaded = false;
  state.batchesLoaded = false;
  state.legitimateScenariosLoaded = false;
  elements["refresh-admin"].disabled = true;
  try {
    await Promise.all([
      loadUsers(),
      loadOperations(),
      loadBatches(),
      loadLegitimateScenarios(),
    ]);
  } finally {
    elements["refresh-admin"].disabled = false;
  }
}

async function loadLegitimateScenarios() {
  if (state.legitimateScenariosLoading || !userCan("scenarios")) {
    return;
  }
  state.legitimateScenariosLoading = true;
  elements["refresh-legitimate-scenarios"].disabled = true;
  setLoadStatus(
    elements["legitimate-scenarios-status"],
    "正在读取合法情景及版本完整性…",
    "loading",
  );
  try {
    const body = await requestJson(
      SUPERVISION_API_PATHS.legitimateScenarios,
    );
    state.legitimateScenarios =
      arrayOrNull(pickFirst(body, "items")) || [];
    state.legitimateScenariosLoaded = true;
    renderLegitimateScenarios();
    setLoadStatus(
      elements["legitimate-scenarios-status"],
      state.legitimateScenarios.length
        ? `共读取 ${state.legitimateScenarios.length} 个情景版本；旧版本只读保留。`
        : "尚未建立合法情景；系统不会自行推断合法例外。",
    );
  } catch (error) {
    state.legitimateScenariosLoaded = false;
    state.legitimateScenarios = [];
    renderLegitimateScenarios();
    setLoadStatus(
      elements["legitimate-scenarios-status"],
      explainAccessError(error, "合法情景库"),
      "error",
    );
  } finally {
    state.legitimateScenariosLoading = false;
    elements["refresh-legitimate-scenarios"].disabled = false;
  }
}

function renderLegitimateScenarios() {
  clearNode(elements["legitimate-scenarios-table-body"]);
  state.legitimateScenarios.forEach((rawScenario) => {
    const scenario = objectOrNull(rawScenario) || {};
    const row = document.createElement("tr");
    const identityCell = document.createElement("td");
    appendPrimarySecondary(
      identityCell,
      displayText(pickFirst(scenario, "name"), "名称未返回"),
      `${displayText(
        pickFirst(scenario, "scenario_id"),
        "编号未返回",
      )} · 版本 ${formatCount(firstNumber(pickFirst(scenario, "version")))}`,
    );

    const scopeCell = document.createElement("td");
    const mineIds = arrayOrNull(pickFirst(scenario, "mine_ids"));
    appendPrimarySecondary(
      scopeCell,
      mineIds && mineIds.length ? mineIds.join("、") : "全部矿山",
      displayText(
        pickFirst(scenario, "description"),
        "适用依据未返回",
      ),
    );

    const contextCell = document.createElement("td");
    const contextParts = [
      nullableText(pickFirst(scenario, "regime"))
        ? `制度 ${pickFirst(scenario, "regime")}`
        : null,
      nullableText(pickFirst(scenario, "shift"))
        ? `班次 ${pickFirst(scenario, "shift")}`
        : null,
      nullableText(pickFirst(scenario, "season"))
        ? `季节 ${pickFirst(scenario, "season")}`
        : null,
      booleanOrNull(pickFirst(scenario, "maintenance")) === true
        ? "检修"
        : booleanOrNull(pickFirst(scenario, "maintenance")) === false
          ? "非检修"
          : null,
    ].filter(Boolean);
    const requiredEvents =
      arrayOrNull(pickFirst(scenario, "required_event_codes")) || [];
    const requiredTags =
      arrayOrNull(pickFirst(scenario, "required_tags")) || [];
    const featureBounds =
      objectOrNull(pickFirst(scenario, "feature_bounds")) || {};
    appendPrimarySecondary(
      contextCell,
      contextParts.length ? contextParts.join(" · ") : "不限工况",
      [
        requiredEvents.length
          ? `${requiredEvents.length} 个审批事件条件`
          : null,
        requiredTags.length ? `${requiredTags.length} 个标签条件` : null,
        Object.keys(featureBounds).length
          ? `${Object.keys(featureBounds).length} 个特征范围`
          : null,
      ]
        .filter(Boolean)
        .join(" · ") || "无额外匹配条件",
    );

    const activeCell = document.createElement("td");
    const activeBadge = document.createElement("span");
    const active = pickFirst(scenario, "active") === true;
    activeBadge.className =
      `status-badge ${active ? "is-success" : "is-cancelled"}`;
    activeBadge.textContent = active ? "启用" : "停用版本";
    activeCell.appendChild(activeBadge);

    const integrityCell = document.createElement("td");
    const valid =
      pickFirst(scenario, "hash_valid") === true &&
      pickFirst(scenario, "version_chain_valid") !== false;
    const integrityBadge = document.createElement("span");
    integrityBadge.className =
      `status-badge ${valid ? "is-success" : "is-inconclusive"}`;
    integrityBadge.textContent = valid
      ? "定义及版本链有效"
      : "完整性待确认";
    integrityCell.appendChild(integrityBadge);

    row.append(
      identityCell,
      scopeCell,
      contextCell,
      activeCell,
      integrityCell,
    );
    elements["legitimate-scenarios-table-body"].appendChild(row);
  });
  elements["legitimate-scenarios-table-wrap"].hidden =
    state.legitimateScenarios.length === 0;
  elements["legitimate-scenarios-empty"].hidden =
    state.legitimateScenarios.length > 0;
}

function parseScenarioList(value) {
  return [
    ...new Set(
      String(value || "")
        .split(/[，,]/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].sort();
}

function setLegitimateScenarioFormStatus(message, tone = "") {
  elements["legitimate-scenario-form-status"].textContent = message;
  elements["legitimate-scenario-form-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

function legitimateScenarioError(error) {
  if (error instanceof ApiError) {
    const apiError = objectOrNull(error.body && error.body.error) || {};
    if (apiError.code === "legitimate_scenario_conflict") {
      return "保存合法情景版本未完成：版本必须从 1 开始连续递增；请查看列表中的最高版本并填写下一个版本，旧版本不能覆盖。";
    }
    if (apiError.code === "legitimate_scenario_integrity_error") {
      return "保存合法情景版本未完成：已有定义完整性异常，请暂停使用并联系管理员核查。";
    }
    if (apiError.code === "invalid_legitimate_scenario") {
      return "保存合法情景版本未完成：字段或特征范围不符合要求，请检查后重试。";
    }
  }
  return explainAccessError(error, "保存合法情景版本");
}

async function createLegitimateScenario(event) {
  event.preventDefault();
  if (!userCan("scenarios")) {
    setLegitimateScenarioFormStatus(
      "当前账号没有合法情景管理权限。",
      "error",
    );
    return;
  }
  let featureBounds;
  try {
    featureBounds = JSON.parse(
      elements["scenario-feature-bounds"].value,
    );
    if (!objectOrNull(featureBounds)) {
      throw new Error("特征范围必须是 JSON 对象");
    }
  } catch (error) {
    setLegitimateScenarioFormStatus(
      `特征适用范围格式错误：${friendlyError(error)}`,
      "error",
    );
    elements["scenario-feature-bounds"].focus();
    return;
  }
  const maintenanceValue = elements["scenario-maintenance"].value;
  const mineIds = parseScenarioList(
    elements["scenario-mine-ids"].value,
  );
  const optionalText = (id) => {
    const value = elements[id].value.trim();
    return value || null;
  };
  const scenario = {
    scenario_id: elements["scenario-id"].value.trim(),
    version: Number(elements["scenario-version"].value),
    name: elements["scenario-name"].value.trim(),
    description: elements["scenario-description"].value.trim(),
    mine_ids: mineIds.length ? mineIds : null,
    regime: optionalText("scenario-regime"),
    shift: optionalText("scenario-shift"),
    season: optionalText("scenario-season"),
    maintenance:
      maintenanceValue === ""
        ? null
        : maintenanceValue === "true",
    required_event_codes: parseScenarioList(
      elements["scenario-event-codes"].value,
    ),
    required_tags: parseScenarioList(
      elements["scenario-required-tags"].value,
    ),
    feature_bounds: featureBounds,
    active: elements["scenario-active"].checked,
  };
  if (
    !Number.isInteger(scenario.version) ||
    scenario.version < 1
  ) {
    setLegitimateScenarioFormStatus(
      "版本必须是大于等于 1 的整数。",
      "error",
    );
    elements["scenario-version"].focus();
    return;
  }

  elements["submit-legitimate-scenario"].disabled = true;
  setLegitimateScenarioFormStatus(
    "正在保存不可变情景版本…",
  );
  try {
    await requestJson(SUPERVISION_API_PATHS.legitimateScenarios, {
      method: "POST",
      body: JSON.stringify({ scenario }),
    });
    elements["legitimate-scenario-form"].reset();
    elements["scenario-version"].value = "1";
    elements["scenario-active"].checked = true;
    elements["scenario-feature-bounds"].value = "{}";
    state.legitimateScenariosLoaded = false;
    await loadLegitimateScenarios();
    setLegitimateScenarioFormStatus(
      "新版本已保存；同编号旧版本仍只读保留。",
      "success",
    );
  } catch (error) {
    setLegitimateScenarioFormStatus(
      legitimateScenarioError(error),
      "error",
    );
  } finally {
    elements["submit-legitimate-scenario"].disabled = false;
  }
}

async function loadBatches() {
  if (state.batchesLoading || !isAdminUser()) {
    return;
  }
  state.batchesLoading = true;
  elements["refresh-batches"].disabled = true;
  elements["isolate-pilot-batches"].disabled = true;
  setLoadStatus(
    elements["batches-status"],
    "正在读取分析批次及生命周期状态…",
    "loading",
  );
  try {
    const query = state.showInvalidatedBatches
      ? "?include_invalidated=true&limit=500"
      : "?limit=500";
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.batches}${query}`,
    );
    const items =
      arrayOrNull(
        Array.isArray(body) ? body : pickFirst(body, "items", "batches"),
      ) || [];
    state.batches = items.map(normalizeBatchLifecycle);
    state.batchesLoaded = true;
    renderBatches();
    setLoadStatus(
      elements["batches-status"],
      state.batches.length
        ? `共读取 ${state.batches.length} 个批次${
            state.showInvalidatedBatches ? "（含已作废）" : ""
          }。作废与恢复均会记录操作人、原因和版本。`
        : "批次列表已读取，当前没有可展示的批次。",
    );
  } catch (error) {
    state.batchesLoaded = false;
    state.batches = [];
    renderBatches();
    setLoadStatus(
      elements["batches-status"],
      explainAccessError(error, "分析批次"),
      "error",
    );
  } finally {
    state.batchesLoading = false;
    elements["refresh-batches"].disabled = false;
    elements["isolate-pilot-batches"].disabled = false;
  }
}

function normalizeBatchLifecycle(rawBatch) {
  const raw = objectOrNull(rawBatch) || {};
  const lifecycle = objectOrNull(raw.lifecycle) || {};
  return {
    batchId: nullableText(raw.batch_id),
    portfolioName: displayText(raw.portfolio_name, "未命名批次"),
    createdAt: raw.created_at,
    dataMode: nullableText(raw.data_mode),
    mineCount: firstNumber(raw.mine_count, 0),
    active: lifecycle.active !== false,
    version: firstNumber(lifecycle.version, 1),
    invalidatedAt: lifecycle.invalidated_at,
    invalidatedBy: nullableText(lifecycle.invalidated_by),
    reason: nullableText(lifecycle.reason),
  };
}

function renderBatches() {
  clearNode(elements["batches-table-body"]);
  state.batches.forEach((batch) => {
    const row = document.createElement("tr");
    const identityCell = document.createElement("td");
    appendPrimarySecondary(
      identityCell,
      batch.portfolioName,
      displayText(batch.batchId, "批次编号未返回"),
    );
    const modeCell = document.createElement("td");
    appendPrimarySecondary(
      modeCell,
      batchDataModeLabel(batch.dataMode),
      batch.batchId && batch.batchId.startsWith("pilot-")
        ? "历史演示批次"
        : "",
    );
    const countCell = document.createElement("td");
    countCell.textContent = `${batch.mineCount === null ? 0 : batch.mineCount} 座`;
    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className =
      `status-badge ${batch.active ? "is-success" : "is-cancelled"}`;
    badge.textContent = batch.active ? "有效" : "已作废";
    statusCell.appendChild(badge);
    if (!batch.active && batch.reason) {
      const reason = document.createElement("small");
      reason.className = "batch-lifecycle-reason";
      reason.textContent = batch.reason;
      statusCell.appendChild(reason);
    }
    const createdCell = document.createElement("td");
    appendPrimarySecondary(
      createdCell,
      formatDateTime(batch.createdAt),
      batch.invalidatedAt
        ? `作废于 ${formatDateTime(batch.invalidatedAt)}`
        : "",
    );
    const actionCell = document.createElement("td");
    const action = document.createElement("button");
    action.type = "button";
    action.className = `table-action${batch.active ? " is-danger" : ""}`;
    action.textContent = batch.active ? "作废批次" : "恢复批次";
    action.disabled = !batch.batchId || batch.version === null;
    if (batch.batchId) {
      action.addEventListener("click", () =>
        changeBatchLifecycle(batch, !batch.active),
      );
    }
    actionCell.appendChild(action);
    row.append(
      identityCell,
      modeCell,
      countCell,
      statusCell,
      createdCell,
      actionCell,
    );
    elements["batches-table-body"].appendChild(row);
  });
  elements["batches-table-wrap"].hidden = state.batches.length === 0;
  elements["batches-empty"].hidden = state.batches.length > 0;
}

function batchDataModeLabel(value) {
  const mode = String(value || "");
  if (mode.startsWith("governed_")) {
    return "可信治理数据";
  }
  if (mode === "pilot_preview") {
    return "脱敏预览";
  }
  return mode ? displayText(mode, "直接分析") : "直接 / 历史分析";
}

async function changeBatchLifecycle(batch, active) {
  const confirmation = await requestActionConfirmation({
    title: active
      ? `恢复批次「${batch.batchId}」？`
      : `作废批次「${batch.batchId}」？`,
    message: active
      ? "恢复后，该批次可重新参与领导总览、趋势统计和事项查询，请先确认数据口径已经有效。"
      : "作废后，该批次会退出领导总览、趋势统计和事项生成；原始结果及审计记录不会删除。",
    confirmLabel: active ? "确认恢复" : "确认作废",
    danger: !active,
    inputLabel: active ? "恢复原因" : "作废原因",
    inputHelp: "原因会写入不可改写的生命周期审计记录。",
    inputPlaceholder: active
      ? "例如：数据口径已复核，可恢复使用"
      : "例如：误导入、重复批次或仅用于演示",
    inputRequired: true,
    inputMinLength: 2,
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(
    elements["batches-status"],
    active ? "正在恢复批次…" : "正在作废批次…",
    "loading",
  );
  try {
    await requestJson(
      `${SUPERVISION_API_PATHS.batches}/${encodeURIComponent(batch.batchId)}/status`,
      {
        method: "POST",
        body: JSON.stringify({
          active,
          reason: confirmation.value,
          expected_version: batch.version,
        }),
      },
    );
    invalidateFormalViews();
    state.batchesLoaded = false;
    await loadBatches();
    setLoadStatus(
      elements["batches-status"],
      active
        ? "批次已恢复，可重新参与正式视图。"
        : "批次已安全作废并退出正式视图；原结果与审计仍保留。",
      "success",
    );
  } catch (error) {
    setLoadStatus(
      elements["batches-status"],
      batchLifecycleError(error, active ? "恢复批次" : "作废批次"),
      "error",
    );
  }
}

async function isolatePilotBatches() {
  const confirmation = await requestActionConfirmation({
    title: "隔离全部历史演示批次？",
    message:
      "系统只处理编号以 pilot- 开头且当前有效的历史演示批次。它们会退出正式视图，原始结果和审计记录仍可追溯。",
    confirmLabel: "确认隔离演示数据",
    danger: true,
    inputLabel: "隔离原因",
    inputHelp: "建议写明试点阶段或清理依据，便于以后追溯。",
    inputPlaceholder: "例如：试点演示数据，不纳入正式监管统计",
    inputRequired: true,
    inputMinLength: 2,
  });
  if (!confirmation.confirmed) {
    return;
  }
  elements["isolate-pilot-batches"].disabled = true;
  setLoadStatus(
    elements["batches-status"],
    "正在识别并隔离历史演示批次…",
    "loading",
  );
  try {
    const body = await requestJson(
      SUPERVISION_API_PATHS.isolatePilotBatches,
      {
        method: "POST",
        body: JSON.stringify({ reason: confirmation.value }),
      },
    );
    const count = firstNumber(body.isolated_count, 0) || 0;
    invalidateFormalViews();
    state.batchesLoaded = false;
    await loadBatches();
    setLoadStatus(
      elements["batches-status"],
      count
        ? `已隔离 ${count} 个历史演示批次；正式视图将在下次打开时刷新。`
        : "没有发现仍处于有效状态的历史演示批次。",
      "success",
    );
  } catch (error) {
    setLoadStatus(
      elements["batches-status"],
      batchLifecycleError(error, "隔离历史演示批次"),
      "error",
    );
  } finally {
    elements["isolate-pilot-batches"].disabled = false;
  }
}

function invalidateFormalViews() {
  state.overviewLoaded = false;
  state.trendsLoaded = false;
  state.temporalLoaded = false;
  state.casesLoaded = false;
}

function batchLifecycleError(error, subject) {
  if (error instanceof ApiError) {
    const apiError = objectOrNull(error.body && error.body.error) || {};
    if (apiError.code === "version_conflict") {
      return `${subject}未完成：批次状态已被其他管理员更新，请刷新列表后再确认。`;
    }
    if (apiError.code === "batch_not_found") {
      return `${subject}未完成：批次已不存在，请刷新列表。`;
    }
  }
  return explainAccessError(error, subject);
}

async function loadOperations() {
  if (state.operationsLoading || !isAdminUser()) {
    return;
  }
  state.operationsLoading = true;
  elements["refresh-operations"].disabled = true;
  setLoadStatus(
    elements["operations-status"],
    "正在检查关键依赖并读取备份记录…",
    "loading",
  );
  const [readinessResult, backupsResult] = await Promise.allSettled([
    requestReadiness(),
    requestJson(SUPERVISION_API_PATHS.backups),
  ]);

  if (readinessResult.status === "fulfilled") {
    state.readiness = objectOrNull(readinessResult.value);
    renderReadiness(state.readiness);
  } else {
    state.readiness = null;
    renderReadinessFailure(readinessResult.reason);
  }

  if (backupsResult.status === "fulfilled") {
    const body = backupsResult.value;
    state.backups =
      arrayOrNull(pickFirst(body, "items", "backups")) || [];
    renderBackups();
  } else {
    state.backups = [];
    renderBackupFailure(backupsResult.reason);
  }

  state.operationsLoaded =
    readinessResult.status === "fulfilled" ||
    backupsResult.status === "fulfilled";
  const failures = [
    readinessResult.status === "rejected" ? "就绪检查" : null,
    backupsResult.status === "rejected" ? "备份列表" : null,
  ].filter(Boolean);
  setLoadStatus(
    elements["operations-status"],
    failures.length
      ? `${failures.join("、")}读取未完成，请查看下方说明。`
      : `检查完成：${formatDateTime(
          state.readiness && state.readiness.timestamp,
        )}`,
    failures.length ? "error" : "",
  );
  elements["backup-id"].value = defaultBackupId();
  state.operationsLoading = false;
  elements["refresh-operations"].disabled = false;
}

async function requestReadiness() {
  const response = await fetch(SUPERVISION_API_PATHS.readiness, {
    headers: { Accept: "application/json" },
    cache: "no-store",
    credentials: "same-origin",
  });
  const body = await readJsonResponse(response);
  if (
    !response.ok &&
    !["degraded", "not_ready"].includes(String(body.status || ""))
  ) {
    throw new ApiError(response.status, body);
  }
  return body;
}

function renderReadiness(rawReadiness) {
  const readiness = objectOrNull(rawReadiness) || {};
  const status = String(readiness.status || "not_ready");
  const checks = arrayOrNull(readiness.checks) || [];
  const labels = {
    ready: "可用",
    degraded: "需关注",
    not_ready: "未就绪",
  };
  elements["readiness-overall"].className =
    `status-badge ${
      status === "ready"
        ? "is-success"
        : status === "degraded"
          ? "is-review"
          : "is-danger"
    }`;
  elements["readiness-overall"].textContent =
    READINESS_STATUS_LABELS[status] || "状态待确认";
  const problemCount = checks.filter(
    (item) => item && item.status !== "ready",
  ).length;
  elements["readiness-summary"].textContent =
    status === "ready"
      ? `关键依赖均通过，共检查 ${checks.length} 项。`
      : `有 ${problemCount} 项需要处理；未恢复前请避免将未完成分析解释为“无异常”。`;
  clearNode(elements["readiness-checks"]);
  checks.forEach((rawCheck) => {
    const check = objectOrNull(rawCheck) || {};
    const item = document.createElement("li");
    const indicator = document.createElement("span");
    indicator.className =
      `readiness-indicator is-${String(check.status || "not_ready").split("_").join("-")}`;
    const name = document.createElement("strong");
    name.textContent = readinessCheckLabel(check.name);
    const message = document.createElement("span");
    message.className = "readiness-message";
    message.textContent =
      `${displayText(check.message, labels[check.status] || "状态待确认")}${
        firstNumber(check.duration_ms) === null
          ? ""
          : ` · ${firstNumber(check.duration_ms)} ms`
      }`;
    item.append(indicator, name, message);
    elements["readiness-checks"].appendChild(item);
  });
  if (!checks.length) {
    const item = document.createElement("li");
    item.textContent = "服务未返回分项检查，整体状态请以顶部标识为准。";
    elements["readiness-checks"].appendChild(item);
  }
}

function renderReadinessFailure(error) {
  elements["readiness-overall"].className = "status-badge is-danger";
  elements["readiness-overall"].textContent = "检查失败";
  elements["readiness-summary"].textContent =
    explainAccessError(error, "系统就绪状态");
  clearNode(elements["readiness-checks"]);
  const item = document.createElement("li");
  item.textContent =
    "当前无法确认关键依赖是否可用，请联系运维人员处理后再运行正式分析。";
  elements["readiness-checks"].appendChild(item);
}

function readinessCheckLabel(value) {
  const labels = {
    auth_database: "账号与权限数据库",
    repository_database: "监管事项数据库",
    job_database: "分析任务数据库",
    evidence_directory: "证据包目录",
    backup_directory: "备份目录",
  };
  const key = String(value || "");
  return labels[key] || displayText(value, "未命名检查项");
}

function renderBackups() {
  clearNode(elements["backups-table-body"]);
  state.backups.forEach((rawBackup) => {
    const backup = objectOrNull(rawBackup) || {};
    const row = document.createElement("tr");
    addCell(row, displayText(backup.backup_id, "编号未返回"));
    const verificationCell = document.createElement("td");
    const badge = document.createElement("span");
    const valid = backup.verification === "valid";
    badge.className = `status-badge ${valid ? "is-success" : "is-danger"}`;
    badge.textContent = valid ? "完整性有效" : "校验未通过";
    verificationCell.appendChild(badge);
    row.appendChild(verificationCell);
    addCell(row, formatDateTime(backup.created_at));
    const files = arrayOrNull(backup.files) || [];
    const fileSizes = files.map((file) => firstNumber(file && file.size));
    const totalSize = fileSizes.reduce((sum, size) => {
      return sum + (size === null ? 0 : size);
    }, 0);
    addCell(
      row,
      files.length
        ? `${files.length} 个文件 · ${
            fileSizes.some((size) => size === null)
              ? "大小未完整返回"
              : formatFileSize(totalSize)
          }`
        : "文件明细未返回",
    );
    const actionCell = document.createElement("td");
    const verify = document.createElement("button");
    verify.type = "button";
    verify.className = "table-action";
    verify.textContent = "重新校验";
    verify.disabled = !backup.backup_id;
    if (backup.backup_id) {
      verify.addEventListener("click", () =>
        verifyBackup(String(backup.backup_id), verify),
      );
    }
    actionCell.appendChild(verify);
    row.appendChild(actionCell);
    elements["backups-table-body"].appendChild(row);
  });
  if (!state.backups.length) {
    appendEmptyRow(
      elements["backups-table-body"],
      5,
      "暂未创建备份。首次试点前建议先创建并校验一次。",
    );
  }
}

function renderBackupFailure(error) {
  clearNode(elements["backups-table-body"]);
  appendEmptyRow(
    elements["backups-table-body"],
    5,
    backupErrorMessage(error, "读取备份列表"),
  );
}

async function createBackup(event) {
  event.preventDefault();
  if (!isAdminUser()) {
    setBackupActionStatus("当前账号没有备份管理权限。", "error");
    return;
  }
  const backupId = elements["backup-id"].value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(backupId)) {
    setBackupActionStatus(
      "备份编号只能使用英文字母、数字、点、下划线和短横线。",
      "error",
    );
    return;
  }
  elements["create-backup-submit"].disabled = true;
  setBackupActionStatus("正在创建一致性备份并校验文件完整性…");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.backups, {
      method: "POST",
      body: JSON.stringify({ backup_id: backupId }),
    });
    const valid = body && body.verification === "valid";
    setBackupActionStatus(
      valid
        ? `备份 ${backupId} 已创建，完整性校验通过。`
        : `备份 ${backupId} 已创建，但校验状态未返回，请立即重新校验。`,
      valid ? "success" : "error",
    );
    const list = await requestJson(SUPERVISION_API_PATHS.backups);
    state.backups = arrayOrNull(pickFirst(list, "items", "backups")) || [];
    renderBackups();
    elements["backup-id"].value = defaultBackupId();
  } catch (error) {
    setBackupActionStatus(
      backupErrorMessage(error, "创建备份"),
      "error",
    );
  } finally {
    elements["create-backup-submit"].disabled = false;
  }
}

async function verifyBackup(backupId, button) {
  button.disabled = true;
  setBackupActionStatus(`正在重新校验备份 ${backupId}…`);
  try {
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.backups}/${encodeURIComponent(backupId)}/verify`,
    );
    setBackupActionStatus(
      body.verification === "valid"
        ? `备份 ${backupId} 的签名、哈希、大小和文件清单均有效。`
        : `备份 ${backupId} 未返回有效校验结果，请联系运维人员。`,
      body.verification === "valid" ? "success" : "error",
    );
  } catch (error) {
    setBackupActionStatus(
      backupErrorMessage(error, `校验备份 ${backupId}`),
      "error",
    );
  } finally {
    button.disabled = false;
  }
}

function backupErrorMessage(error, subject) {
  if (error instanceof ApiError) {
    const apiError = objectOrNull(error.body && error.body.error) || {};
    if (apiError.code === "backup_unavailable") {
      return `${subject}未完成：当前部署未配置持久化备份目录，请联系运维人员。`;
    }
    if (apiError.code === "backup_exists") {
      return `${subject}未完成：该备份编号已存在，请换一个编号。`;
    }
    if (apiError.code === "backup_invalid") {
      return `${subject}未通过：备份文件或清单完整性异常，请暂停使用并联系运维人员。`;
    }
  }
  return explainAccessError(error, subject);
}

function setBackupActionStatus(message, tone = "") {
  elements["backup-action-status"].textContent = message;
  elements["backup-action-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

function defaultBackupId() {
  const now = new Date();
  const seconds = String(now.getSeconds()).padStart(2, "0");
  return `backup-${fileTimestamp()}${seconds}`;
}

function formatFileSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "大小未返回";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function loadUsers() {
  if (state.usersLoading || !isAdminUser()) {
    return;
  }
  state.usersLoading = true;
  elements["refresh-users"].disabled = true;
  setLoadStatus(elements["users-status"], "正在读取用户列表…", "loading");
  try {
    const body = await requestJson(SUPERVISION_API_PATHS.users);
    state.users =
      arrayOrNull(pickFirst(body, "items", "users")) || [];
    state.usersLoaded = true;
    renderUsers();
    setLoadStatus(
      elements["users-status"],
      `共 ${state.users.length} 个账号。列表不包含密码或会话凭证。`,
    );
  } catch (error) {
    state.usersLoaded = false;
    setLoadStatus(
      elements["users-status"],
      explainAccessError(error, "用户列表"),
      "error",
    );
  } finally {
    state.usersLoading = false;
    elements["refresh-users"].disabled = false;
  }
}

function renderUsers() {
  clearNode(elements["users-table-body"]);
  const currentUsername = state.principal
    ? String(state.principal.username || "").toLocaleLowerCase("zh-CN")
    : "";
  const activeAdminCount = state.users.filter(
    (item) => item.active && item.role === "admin",
  ).length;
  state.users.forEach((user) => {
    const row = document.createElement("tr");
    addCell(row, displayText(user.username, "用户名未返回"));
    addCell(
      row,
      ROLE_LABELS[user.role] || displayText(user.role, "角色未返回"),
    );
    const scopes = arrayOrNull(user.mine_scopes) || [];
    addCell(
      row,
      user.role === "admin"
        ? "全部矿山"
        : scopes.length
          ? scopes.join("、")
          : "未分配",
    );
    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `status-badge ${
      user.active ? "is-success" : "is-cancelled"
    }`;
    badge.textContent = user.active ? "启用" : "停用";
    statusCell.appendChild(badge);
    row.appendChild(statusCell);
    addCell(row, formatDateTime(user.updated_at));
    const actionCell = document.createElement("td");
    const actions = document.createElement("div");
    actions.className = "user-row-actions";
    const normalizedUsername = String(user.username || "").toLocaleLowerCase(
      "zh-CN",
    );
    const isSelf = normalizedUsername === currentUsername;

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = `table-action${user.active ? " is-danger" : ""}`;
    toggle.textContent = user.active ? "停用账号" : "恢复账号";
    const protectsLastAdmin =
      user.active && user.role === "admin" && activeAdminCount <= 1;
    toggle.disabled = Boolean(user.active && (isSelf || protectsLastAdmin));
    if (isSelf && user.active) {
      toggle.title = "不能停用当前登录账号";
    } else if (protectsLastAdmin) {
      toggle.title = "不能停用最后一个启用的管理员";
    } else {
      toggle.addEventListener("click", () =>
        toggleUserStatus(user, !user.active),
      );
    }

    const access = document.createElement("button");
    access.type = "button";
    access.className = "table-action";
    access.textContent = "调整权限";
    access.addEventListener("click", () => beginUserEdit(user));

    const reset = document.createElement("button");
    reset.type = "button";
    reset.className = "table-action";
    reset.textContent = "重置密码";
    reset.addEventListener("click", () => resetUserPassword(user));

    actions.append(toggle, access, reset);
    actionCell.appendChild(actions);
    row.appendChild(actionCell);
    elements["users-table-body"].appendChild(row);
  });
  elements["users-table-wrap"].hidden = state.users.length === 0;
  elements["users-empty"].hidden = state.users.length > 0;
}

async function createUser(event) {
  event.preventDefault();
  if (!isAdminUser()) {
    setUserCreateStatus("当前账号没有用户管理权限。", "error");
    return;
  }
  const username = elements["new-user-username"].value.trim();
  const editing = state.editingUsername !== null;
  const password = editing ? "" : elements["new-user-password"].value;
  const role = elements["new-user-role"].value;
  const mineScopes = elements["new-user-scopes"].value
    .split(/[，,]/)
    .map((value) => value.trim())
    .filter(Boolean);
  if (role !== "admin" && !mineScopes.length) {
    setUserCreateStatus("非管理员账号至少需要授权一个矿山编号。", "error");
    elements["new-user-scopes"].focus();
    return;
  }
  elements["create-user-submit"].disabled = true;
  let changeReason = null;
  if (editing) {
    const confirmation = await requestActionConfirmation({
      title: `保存账号「${username}」的新权限？`,
      message:
        "角色或矿山范围变更后，该账号的现有会话会立即失效，历史办理记录不会改变。",
      confirmLabel: "保存并强制重新登录",
      inputLabel: "调整原因",
      inputHelp: "原因会写入账号操作审计，请说明授权依据。",
      inputPlaceholder: "例如：岗位调整或监管范围变更",
      inputRequired: true,
      inputMinLength: 2,
    });
    if (!confirmation.confirmed) {
      elements["create-user-submit"].disabled = false;
      return;
    }
    changeReason = confirmation.value;
  }
  setUserCreateStatus(editing ? "正在更新账号权限…" : "正在创建账号…");
  try {
    const body = await requestJson(
      editing
        ? `${SUPERVISION_API_PATHS.users}/${encodeURIComponent(username)}/access`
        : SUPERVISION_API_PATHS.users,
      {
        method: "POST",
        body: JSON.stringify(
          editing
            ? {
              role,
              mine_scopes: role === "admin" ? [] : mineScopes,
              reason: changeReason,
            }
            : {
                username,
                password,
                role,
                mine_scopes: role === "admin" ? [] : mineScopes,
              },
        ),
      },
    );
    if (editing && body.reauthentication_required) {
      resetProtectedState();
      showLogin("当前账号权限已更新，请重新登录。");
      return;
    }
    resetUserForm();
    elements["new-user-password"].value = "";
    state.usersLoaded = false;
    await loadUsers();
    setUserCreateStatus(
      editing
        ? "用户权限已更新，目标账号的原有会话已失效。"
        : "用户已创建。初始密码请通过本单位安全渠道交付。",
      "success",
    );
  } catch (error) {
    elements["new-user-password"].value = "";
    setUserCreateStatus(
      userLifecycleError(error, editing ? "更新用户权限" : "创建用户"),
      "error",
    );
  } finally {
    elements["create-user-submit"].disabled = false;
  }
}

function beginUserEdit(user) {
  state.editingUsername = String(user.username);
  elements["user-create-title"].textContent =
    `调整「${state.editingUsername}」的权限`;
  elements["new-user-username"].value = state.editingUsername;
  elements["new-user-username"].disabled = true;
  elements["user-password-wrap"].hidden = true;
  elements["new-user-password"].required = false;
  elements["new-user-password"].value = "";
  elements["new-user-role"].value = user.role;
  elements["new-user-scopes"].value =
    (arrayOrNull(user.mine_scopes) || []).join(", ");
  elements["cancel-user-edit"].hidden = false;
  elements["create-user-submit"].textContent = "保存权限";
  setUserCreateStatus(
    "保存后该用户全部现有会话会失效，需要重新登录。",
  );
  elements["new-user-role"].focus();
}

function resetUserForm() {
  state.editingUsername = null;
  elements["user-create-form"].reset();
  elements["user-create-title"].textContent = "新增用户";
  elements["new-user-username"].disabled = false;
  elements["user-password-wrap"].hidden = false;
  elements["new-user-password"].required = true;
  elements["new-user-password"].value = "";
  elements["cancel-user-edit"].hidden = true;
  elements["create-user-submit"].textContent = "创建用户";
  setUserCreateStatus("");
}

async function toggleUserStatus(user, active) {
  const confirmation = await requestActionConfirmation({
    title: active
      ? `恢复账号「${user.username}」？`
      : `停用账号「${user.username}」？`,
    message: active
      ? "恢复后该账号可以重新登录；原有历史办理记录保持不变。"
      : "该账号将立即不能登录，全部现有会话失效；历史办理记录仍保留姓名和操作时间。",
    confirmLabel: active ? "确认恢复" : "确认停用",
    danger: !active,
    inputLabel: active ? "恢复原因" : "停用原因",
    inputHelp: "原因会进入账号操作审计，请说明依据。",
    inputPlaceholder: active
      ? "例如：人员重新到岗且已完成授权复核"
      : "例如：人员离岗或授权到期",
    inputRequired: true,
    inputMinLength: 2,
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(
    elements["users-status"],
    active ? "正在恢复账号…" : "正在停用账号…",
    "loading",
  );
  try {
    await requestJson(
      `${SUPERVISION_API_PATHS.users}/${encodeURIComponent(user.username)}/status`,
      {
        method: "POST",
        body: JSON.stringify({
          active,
          reason: confirmation.value,
        }),
      },
    );
    state.usersLoaded = false;
    await loadUsers();
    setLoadStatus(
      elements["users-status"],
      active
        ? `账号 ${user.username} 已恢复。`
        : `账号 ${user.username} 已停用，历史记录已保留。`,
      "success",
    );
  } catch (error) {
    setLoadStatus(
      elements["users-status"],
      userLifecycleError(error, active ? "恢复账号" : "停用账号"),
      "error",
    );
  }
}

async function resetUserPassword(user) {
  const confirmation = await requestActionConfirmation({
    title: `重置账号「${user.username}」的密码？`,
    message:
      "保存后该账号全部现有会话会立即失效。新密码不会显示在用户列表或日志中。",
    confirmLabel: "重置并强制重新登录",
    inputLabel: "新密码",
    inputHelp: "至少 12 位，请通过本单位安全渠道交付给本人。",
    inputType: "password",
    inputPlaceholder: "输入至少 12 位的新密码",
    inputRequired: true,
    inputMinLength: 12,
    trimInput: false,
  });
  if (!confirmation.confirmed) {
    return;
  }
  setLoadStatus(elements["users-status"], "正在重置密码…", "loading");
  try {
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.users}/${encodeURIComponent(user.username)}/reset-password`,
      {
        method: "POST",
        body: JSON.stringify({ new_password: confirmation.value }),
      },
    );
    if (body.reauthentication_required) {
      resetProtectedState();
      showLogin("当前账号密码已重置，请使用新密码重新登录。");
      return;
    }
    setLoadStatus(
      elements["users-status"],
      `账号 ${user.username} 的密码已重置，原有会话已失效。`,
      "success",
    );
  } catch (error) {
    setLoadStatus(
      elements["users-status"],
      userLifecycleError(error, "重置密码"),
      "error",
    );
  }
}

function userLifecycleError(error, subject) {
  if (error instanceof ApiError) {
    const apiError = objectOrNull(error.body && error.body.error) || {};
    const messages = {
      cannot_disable_self:
        "不能停用当前登录账号，请使用另一名管理员执行该操作。",
      last_active_admin:
        "不能停用或降级最后一个启用的管理员，请先创建或恢复另一名管理员。",
      user_not_found: "该用户已不存在，请刷新列表。",
      invalid_user_access: "角色或矿山范围不符合要求，请检查后重试。",
    };
    if (messages[apiError.code]) {
      return `${subject}未完成：${messages[apiError.code]}`;
    }
  }
  return explainAccessError(error, subject);
}

function setUserCreateStatus(message, tone = "") {
  elements["user-create-status"].textContent = message;
  elements["user-create-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

async function loadCases() {
  if (state.casesLoading) {
    return;
  }
  state.casesLoading = true;
  elements["refresh-cases"].disabled = true;
  setLoadStatus(elements["cases-status"], "正在读取核查台账…", "loading");
  try {
    const body = await requestJson(
      state.showArchivedCases
        ? `${SUPERVISION_API_PATHS.cases}?include_archived=1`
        : SUPERVISION_API_PATHS.cases,
    );
    const rawItems =
      arrayOrNull(
        Array.isArray(body)
          ? body
          : pickFirst(body, "items", "cases", "results"),
      ) || [];
    state.cases = rawItems.map(normalizeCaseRecord);
    state.casesLoaded = true;
    if (!state.cases.length) {
      showCasesEmpty(
        "当前没有核查事项。技术状态和办理状态独立记录，缺报或数据不足也不会显示为“正常”。",
      );
      setLoadStatus(elements["cases-status"], "台账已读取，当前无事项");
    } else {
      elements["cases-empty"].hidden = true;
      elements["cases-table-content"].hidden = false;
      renderCaseTable();
      setLoadStatus(
        elements["cases-status"],
        `共读取 ${state.cases.length} 项${
          state.showArchivedCases ? "（含已归档）" : ""
        }，筛选只影响当前页面展示。`,
      );
    }
    const openCount = state.cases.filter(
      (item) => !["closed", "resolved"].includes(item.workflowStatus),
    ).length;
    updateOpenCaseCount(openCount);
  } catch (error) {
    state.casesLoaded = false;
    showCasesEmpty(
      "暂时无法读取核查台账。请稍后重试；读取失败不表示事项已办结或不存在。",
    );
    setLoadStatus(
      elements["cases-status"],
      explainSupervisionError(error, "核查台账"),
      "error",
    );
  } finally {
    state.casesLoading = false;
    elements["refresh-cases"].disabled = false;
  }
}

function showCasesEmpty(message) {
  elements["cases-empty"].hidden = false;
  elements["cases-empty-message"].textContent = message;
  elements["cases-table-content"].hidden = true;
  elements["cases-filter-empty"].hidden = true;
}

function normalizeCaseRecord(rawCase) {
  const overviewItem = normalizeOverviewItem(rawCase);
  const raw =
    rawCase && typeof rawCase === "object" && !Array.isArray(rawCase)
      ? rawCase
      : {};
  const caseId = nullableText(pickFirst(raw, "case_id", "id"));
  return {
    ...overviewItem,
    caseId: caseId || overviewItem.caseId,
    title: displayText(
      pickFirst(raw, "title", "case_title"),
      `${overviewItem.mineName}待复核事项`,
    ),
    createdAt: pickFirst(raw, "created_at", "opened_at"),
    updatedAt: pickFirst(
      raw,
      "updated_at",
      "last_updated_at",
      "analyzed_at",
    ),
    archivedAt: raw.archived_at,
    archivedBy: nullableText(raw.archived_by),
    archivedReason: nullableText(raw.archived_reason),
    raw,
  };
}

function renderCaseTable() {
  if (!state.cases.length) {
    return;
  }
  clearNode(elements["case-table-body"]);
  const query = elements["case-search"].value.trim().toLocaleLowerCase("zh-CN");
  const priority = elements["case-priority-filter"].value;
  const technical = elements["case-technical-filter"].value;
  const workflow = elements["case-workflow-filter"].value;
  const filtered = state.cases
    .filter((item) => {
      const searchText = [
        item.caseId,
        item.mineId,
        item.mineName,
        item.title,
        item.summary,
      ]
        .filter(Boolean)
        .join(" ")
        .toLocaleLowerCase("zh-CN");
      return (
        (!query || searchText.includes(query)) &&
        (priority === "all" || item.priority === priority) &&
        (technical === "all" || item.technicalStatus === technical) &&
        (workflow === "all" || item.workflowStatus === workflow)
      );
    })
    .sort(comparePriorityItems);

  filtered.forEach((item) => {
    const row = document.createElement("tr");
    const titleCell = document.createElement("td");
    appendPrimarySecondary(
      titleCell,
      item.title,
      `${item.caseId || "事项编号待返回"} · ${item.mineName}${
        item.archivedAt ? " · 已归档" : ""
      }`,
    );
    const priorityCell = document.createElement("td");
    priorityCell.appendChild(createStatusBadge(item.priority, "priority"));
    const technicalCell = document.createElement("td");
    technicalCell.appendChild(
      createStatusBadge(item.technicalStatus, "technical"),
    );
    const workflowCell = document.createElement("td");
    workflowCell.appendChild(
      createStatusBadge(item.workflowStatus, "workflow"),
    );
    const assigneeCell = document.createElement("td");
    assigneeCell.textContent = item.assignee || "待明确";
    const dueCell = document.createElement("td");
    appendPrimarySecondary(
      dueCell,
      item.dueAt ? formatDateOnly(item.dueAt) : "待安排",
      item.overdue ? "已逾期，请优先跟进" : "",
    );
    const updatedCell = document.createElement("td");
    updatedCell.textContent = formatDateTime(item.updatedAt);
    const actionCell = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "table-action";
    button.textContent = "打开事项";
    button.disabled = !item.caseId;
    if (item.caseId) {
      button.addEventListener("click", () => openCase(item.caseId));
    }
    actionCell.appendChild(button);
    row.append(
      titleCell,
      priorityCell,
      technicalCell,
      workflowCell,
      assigneeCell,
      dueCell,
      updatedCell,
      actionCell,
    );
    elements["case-table-body"].appendChild(row);
  });
  elements["cases-filter-empty"].hidden = filtered.length > 0;
  elements["cases-table-content"].hidden = filtered.length === 0;
}

function showCaseList(shouldFocus = true) {
  elements["case-detail-view"].hidden = true;
  elements["case-list-view"].hidden = false;
  if (shouldFocus) {
    elements["case-search"].focus();
  }
}

async function openCase(caseId) {
  if (!caseId) {
    return;
  }
  setWorkspace("cases", false);
  elements["case-list-view"].hidden = true;
  elements["case-detail-view"].hidden = false;
  elements["case-detail-content"].hidden = true;
  state.currentCaseId = String(caseId);
  setLoadStatus(
    elements["case-detail-loading"],
    "正在读取事项、办理记录和审计校验状态…",
    "loading",
  );

  try {
    await loadCaseDetail(caseId);
    elements["case-detail-content"].hidden = false;
    setLoadStatus(elements["case-detail-loading"], "");
    elements["case-detail-title"].setAttribute("tabindex", "-1");
    elements["case-detail-title"].focus({ preventScroll: true });
    elements["case-detail-view"].scrollIntoView({
      behavior: prefersReducedMotion() ? "auto" : "smooth",
      block: "start",
    });
  } catch (error) {
    state.currentCaseDetail = null;
    setLoadStatus(
      elements["case-detail-loading"],
      explainSupervisionError(error, "事项详情"),
      "error",
    );
  }
}

async function loadCaseDetail(caseId) {
  const encodedId = encodeURIComponent(String(caseId));
  const body = await requestJson(`${SUPERVISION_API_PATHS.cases}/${encodedId}`);
  const initialDetail = normalizeCaseDetail(body);
  let runResponse = null;
  state.currentReferenceLabels = null;
  state.currentReferenceLabelsError = null;
  if (initialDetail.runId) {
    try {
      const encodedRunId = encodeURIComponent(initialDetail.runId);
      runResponse = await requestJson(`/v1/analysis-runs/${encodedRunId}`);
    } catch {
      runResponse = null;
    }
    try {
      const encodedRunId = encodeURIComponent(initialDetail.runId);
      const labelsResponse = await requestJson(
        `/v1/analysis-runs/${encodedRunId}/reference-labels`,
      );
      state.currentReferenceLabels =
        normalizeReferenceLabelResponse(labelsResponse, initialDetail.runId);
    } catch (error) {
      state.currentReferenceLabelsError = error;
    }
  } else {
    state.currentReferenceLabelsError = new Error(
      "事项尚未关联可标注的分析运行",
    );
  }
  const detail = normalizeCaseDetail(body, runResponse);
  if (!detail.caseId) {
    detail.caseId = String(caseId);
  }
  state.currentCaseId = detail.caseId;
  state.currentCaseVersion = detail.version;
  state.currentCaseDetail = detail;
  state.currentCaseResponse = runResponse
    ? { ...body, analysis_run: pickFirst(runResponse, "run") || runResponse }
    : body;
  renderCaseDetail(detail);
}

function normalizeCaseDetail(rawResponse, rawRunResponse = null) {
  const response =
    rawResponse && typeof rawResponse === "object" ? rawResponse : {};
  const rawCase =
    objectOrNull(pickFirst(response, "case", "item")) || response;
  const base = normalizeCaseRecord(rawCase);
  const runWrapper =
    rawRunResponse && typeof rawRunResponse === "object"
      ? rawRunResponse
      : {};
  const run =
    objectOrNull(pickFirst(runWrapper, "run", "item")) || runWrapper;
  const analysis =
    objectOrNull(
      pickAcross(
        [run, rawCase],
        "result",
        "analysis_result",
        "latest_analysis",
        "analysis",
      ),
    ) || {};
  const inputSnapshot =
    objectOrNull(pickFirst(run, "input_snapshot", "input")) || {};
  const candidates = [response, rawCase, run, analysis, inputSnapshot];
  const events =
    arrayOrNull(
      pickFirst(
        response,
        "events",
        "timeline",
        "audit_events",
        "case.events",
      ),
    ) || [];
  const evidence =
    arrayOrNull(
      pickAcross(
        candidates,
        "evidence",
        "evidence_items",
        "evidence_sources",
      ),
    ) || [];
  const checks =
    arrayOrNull(
      pickAcross(
        candidates,
        "recommended_checks",
        "suggested_checks",
        "recommendations",
      ),
    ) || [];
  const historicalEvidence = normalizeHistoricalEvidence(
    pickAcross(candidates, "historical_evidence"),
    pickAcross(
      candidates,
      "legitimate_scenario_matches",
      "historical_evidence.legitimate_scenario_matches",
    ),
  );
  const temporalEvidence = normalizeTemporalEvidence(
    pickAcross(candidates, "temporal_evidence"),
  );
  const evidenceFusion = normalizeEvidenceFusion(
    pickAcross(candidates, "evidence_fusion"),
  );

  return {
    ...base,
    caseId:
      nullableText(pickFirst(rawCase, "case_id", "id")) || base.caseId,
    version: firstNumber(
      pickFirst(rawCase, "version", "case_version", "expected_version"),
      base.version,
    ),
    disposition: nullableText(rawCase.disposition),
    conclusionBy: nullableText(rawCase.conclusion_by),
    conclusionAt: rawCase.conclusion_at,
    approvalBy: nullableText(rawCase.approval_by),
    approvalAt: rawCase.approval_at,
    approvalNote: nullableText(rawCase.approval_note),
    plainSummary: displayText(
      pickAcross(
        candidates,
        "plain_summary",
        "summary",
        "issue_summary",
      ),
      base.summary,
    ),
    evidenceGrade: nullableText(
      pickAcross(
        candidates,
        "evidence_grade",
        "evidence_strength",
        "grade",
      ),
    ),
    evidenceGradeNote: nullableText(
      pickAcross(candidates, "evidence_grade_note", "evidence_explanation"),
    ),
    recommendedChecks: checks.map(String),
    evidence,
    supportingGroups:
      arrayOrNull(
        pickAcross(
          candidates,
          "supporting_source_groups",
          "supporting_sources",
        ),
      ) || [],
    events,
    auditChainValid: booleanOrNull(
      pickFirst(
        response,
        "audit_chain_valid",
        "hash_chain_valid",
        "case.audit_chain_valid",
      ),
    ),
    runHashesValid: booleanOrNull(
      pickFirst(response, "run_hashes_valid", "evidence_hashes_valid"),
    ),
    integrityValid: booleanOrNull(
      pickFirst(response, "integrity_valid"),
    ),
    auditScope: nullableText(pickFirst(response, "audit_scope")),
    inputHash: nullableText(
      pickAcross(
        candidates,
        "snapshot_hash",
        "input_hash",
        "input_batch_hash",
        "trace.input_hash",
      ),
    ),
    resultHash: nullableText(
      pickAcross(candidates, "result_hash", "result_sha256"),
    ),
    currentHash: nullableText(
      pickFirst(
        events.length ? events[events.length - 1] : {},
        "event_hash",
        "current_hash",
      ),
    ),
    batchId: nullableText(
      pickAcross(candidates, "input_batch_id", "batch_id"),
    ),
    modelVersion: nullableText(
      pickAcross(
        candidates,
        "engine_version",
        "model_version",
        "trace.model_version",
      ),
    ),
    rulesetVersion: nullableText(
      pickAcross(candidates, "ruleset_version", "rule_version"),
    ),
    runId: nullableText(
      pickAcross(
        candidates,
        "analysis_run_id",
        "run_id",
        "analysis_id",
      ),
    ),
    windowStart: pickAcross(
      candidates,
      "window_start",
      "period_start",
    ),
    windowEnd: pickAcross(candidates, "window_end", "period_end"),
    inputSnapshot,
    analysis,
    historicalEvidence,
    temporalEvidence,
    evidenceFusion,
    rawResponse: response,
  };
}

function renderCaseDetail(detail) {
  elements["case-detail-id"].textContent =
    `事项 ${detail.caseId || "编号待返回"}`;
  elements["case-detail-title"].textContent =
    detail.title || `${detail.mineName}待复核事项`;
  elements["case-detail-period"].textContent = [
    detail.mineName,
    detail.mineId,
    formatPeriod(detail.windowStart, detail.windowEnd),
    detail.archivedAt
      ? `已归档 · ${formatDateTime(detail.archivedAt)}`
      : "",
    detail.updatedAt ? `最近更新 ${formatDateTime(detail.updatedAt)}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
  setExistingBadge(
    elements["case-priority-badge"],
    detail.priority,
    "priority",
  );
  setExistingBadge(
    elements["case-technical-badge"],
    detail.technicalStatus,
    "technical",
  );
  setExistingBadge(
    elements["case-workflow-badge"],
    detail.workflowStatus,
    "workflow",
  );
  elements["case-plain-summary"].textContent = `${
    detail.archivedAt
      ? `当前事项已归档（${detail.archivedReason || "原因未返回"}）。`
      : ""
  }${detail.plainSummary} 系统结果只用于确定复核顺序和范围，不构成违法事实或责任认定。`;
  renderCaseFacts(detail);
  renderCaseHistoricalEvidence(detail.historicalEvidence);
  renderCaseEvidenceFusion(detail.evidenceFusion, detail.temporalEvidence);
  renderCaseChecks(detail);
  renderCaseEvidence(detail);
  renderCaseTimeline(detail);
  renderCaseAudit(detail);
  resetEvidenceBundle();
  elements["case-evidence-grade"].textContent =
    detail.evidenceGrade || "未评定";
  elements["case-evidence-grade-note"].textContent =
    String(detail.evidenceGrade || "").toUpperCase() === "D"
      ? "证据不足、不能下结论；请补齐来源、边界和原始材料后重新分析。"
      : detail.evidenceGradeNote ||
        "表示现有数据对技术判断的支撑强度，不是风险、处罚或责任等级。";
  elements["case-action-form"].reset();
  configureCaseActionOptions(detail.workflowStatus);
  elements["case-action-status"].textContent = "";
  elements["case-action-status"].className = "form-status";
  elements["reference-label-form"].reset();
  renderReferenceLabels();
  configureReferenceLabelFields();
}

function configureCaseActionOptions(workflowStatus) {
  const allowed = [];
  const isOpen = ["new", "reviewing", "supplement_requested"].includes(
    workflowStatus,
  );
  if (isOpen && userCan("review")) {
    allowed.push("submit_conclusion", "add_note");
    if (workflowStatus !== "reviewing") {
      allowed.push("start_review");
    }
    if (workflowStatus !== "supplement_requested") {
      allowed.push("request_data");
    }
    if (!state.authEnabled) {
      allowed.push("close");
    }
  }
  if (isOpen && userCan("assign")) {
    allowed.push("assign");
  }
  if (workflowStatus === "pending_approval") {
    const conclusionBy = state.currentCaseDetail
      ? state.currentCaseDetail.conclusionBy
      : null;
    const currentUsername = state.principal
      ? nullableText(state.principal.username)
      : null;
    if (
      userCan("approve") &&
      (!conclusionBy || conclusionBy !== currentUsername)
    ) {
      allowed.push("approve", "reject");
    }
    if (
      userCan("review") &&
      conclusionBy &&
      conclusionBy === currentUsername
    ) {
      allowed.push("withdraw_conclusion");
    }
    if (userCan("review")) {
      allowed.push("add_note");
    }
  }
  if (workflowStatus === "closed") {
    const archived = Boolean(
      state.currentCaseDetail && state.currentCaseDetail.archivedAt,
    );
    if (archived && userCan("approve")) {
      allowed.push("restore_case");
    } else if (!archived) {
      if (userCan("approve")) {
        allowed.push("reopen", "archive_case");
      }
      if (userCan("review")) {
        allowed.push("add_note");
      }
    }
  }
  const options = Array.from(elements["case-action"].options || []);
  options.forEach((option) => {
    option.disabled = !allowed.includes(option.value);
    option.hidden =
      option.value === "close" && state.authEnabled
        ? true
        : !allowed.includes(option.value);
  });
  if (allowed.length) {
    elements["case-action"].value = allowed[0];
  }
  elements["case-action-card"].hidden = allowed.length === 0;
  elements["submit-case-action"].disabled = allowed.length === 0;
  elements["evidence-bundle-card"].hidden = !userCan("evidence");
  configureCaseActionFields();
}

function configureCaseActionFields() {
  const action = elements["case-action"].value;
  elements["case-assignee"].disabled = action !== "assign";
  elements["case-disposition"].disabled =
    !["submit_conclusion", "close"].includes(action);
  elements["case-action-note"].required = [
    "add_note",
    "request_data",
    "submit_conclusion",
    "withdraw_conclusion",
    "approve",
    "reject",
    "close",
    "reopen",
    "archive_case",
    "restore_case",
  ].includes(action);
}

function appendCompactFact(container, termText, descriptionText) {
  const term = document.createElement("dt");
  term.textContent = termText;
  const description = document.createElement("dd");
  description.textContent = descriptionText;
  container.append(term, description);
}

function renderCaseHistoricalEvidence(evidence) {
  clearNode(elements["case-historical-facts"]);
  clearNode(elements["case-historical-scenarios"]);
  elements["case-historical-scenarios"].hidden = true;
  if (!evidence) {
    elements["case-historical-status"].className =
      "status-badge is-unknown";
    elements["case-historical-status"].textContent = "尚未评估";
    elements["case-historical-summary"].textContent =
      "尚未返回可审计的历史评估。没有历史结果不代表当前数据正常，仍以物理交叉核验和人工复核为准。";
    appendCompactFact(
      elements["case-historical-facts"],
      "可比历史样本",
      "未返回",
    );
    appendCompactFact(
      elements["case-historical-facts"],
      "罕见度",
      "不能计算",
    );
    return;
  }

  const statusTones = {
    insufficient_history: "is-inconclusive",
    within_baseline: "is-consistent",
    historically_rare: "is-inconsistent",
    unknown: "is-unknown",
  };
  elements["case-historical-status"].className =
    `status-badge ${statusTones[evidence.status] || statusTones.unknown}`;
  elements["case-historical-status"].textContent =
    historicalStatusLabel(evidence.status);
  if (evidence.status === "insufficient_history") {
    elements["case-historical-summary"].textContent =
      "同矿、同工况、同算法口径且经人工核实的样本还不够，当前不能判断“符合历史”或“历史罕见”，更不能当作正常。";
  } else if (evidence.status === "within_baseline") {
    elements["case-historical-summary"].textContent =
      "当前特征落在可比历史基线范围内。这只说明“与过去相似”，不证明数据真实、合法，也不改变物理关系发现的冲突。";
  } else if (evidence.status === "historically_rare") {
    elements["case-historical-summary"].textContent =
      "当前特征组合相对可比历史记录较罕见，建议作为独立线索复核；罕见不等同于违规。";
  } else {
    elements["case-historical-summary"].textContent =
      evidence.explanation ||
      "历史评估状态尚未完整返回，不能据此形成正常或异常判断。";
  }

  const selected =
    evidence.selectedSampleCount === null
      ? "未返回"
      : `${formatCount(evidence.selectedSampleCount)} 个`;
  const minimum =
    evidence.minimumRequiredSamples === null
      ? ""
      : `（至少需要 ${formatCount(evidence.minimumRequiredSamples)} 个）`;
  appendCompactFact(
    elements["case-historical-facts"],
    "可比历史样本",
    `${selected}${minimum}`,
  );
  appendCompactFact(
    elements["case-historical-facts"],
    "罕见度",
    evidence.rarityScore === null
      ? "样本不足或未计算"
      : `${formatNumber(evidence.rarityScore, 1)} / 100`,
  );
  appendCompactFact(
    elements["case-historical-facts"],
    "多指标校正后概率",
    evidence.overallPValue === null
      ? "未计算"
      : formatPercent(evidence.overallPValue),
  );
  appendCompactFact(
    elements["case-historical-facts"],
    "比较口径",
    evidence.contextConditioned === true
      ? "已限定同矿、同工况和同算法口径"
      : "工况条件未完整，需谨慎解释",
  );

  if (evidence.legitimateScenarioMatches.length) {
    const title = document.createElement("strong");
    title.textContent = "匹配到已登记合法情景";
    const list = document.createElement("ul");
    evidence.legitimateScenarioMatches.forEach((rawScenario) => {
      const scenario = objectOrNull(rawScenario);
      const item = document.createElement("li");
      item.textContent = scenario
        ? `${displayText(
            pickFirst(scenario, "name", "scenario_id"),
            "情景名称未返回",
          )}${
            firstNumber(scenario.version) === null
              ? ""
              : ` · 版本 ${formatCount(firstNumber(scenario.version))}`
          }`
        : String(rawScenario);
      list.appendChild(item);
    });
    const note = document.createElement("p");
    note.textContent =
      "匹配只解释历史信号；如物理关系仍冲突，冲突结论和人工核查要求均不取消。";
    elements["case-historical-scenarios"].append(title, list, note);
    elements["case-historical-scenarios"].hidden = false;
  }
}

function humanizeFusionReason(reason) {
  const code = String(reason || "");
  if (FUSION_REASON_LABELS[code]) {
    return FUSION_REASON_LABELS[code];
  }
  if (code.startsWith("physical_status:")) {
    const status = normalizeTechnicalStatus(code.split(":").slice(1).join(":"));
    return `物理技术状态：${statusBadgeSpec(status, "technical").label}。`;
  }
  if (code.startsWith("evidence_grade:")) {
    return `物理证据支撑等级：${displayText(
      code.split(":").slice(1).join(":"),
      "未评定",
    )}（不是处罚等级）。`;
  }
  return `系统理由：${code.split("_").join(" ")}`;
}

function renderCaseEvidenceFusion(fusion, temporalEvidence = null) {
  clearNode(elements["case-fusion-facts"]);
  clearNode(elements["case-fusion-reasons"]);
  if (!fusion) {
    elements["case-fusion-agreement"].className =
      "status-badge is-unknown";
    elements["case-fusion-agreement"].textContent = "尚未融合";
    elements["case-fusion-summary"].textContent =
      "尚未形成可审计的多路证据关系。物理交叉核验仍是当前正式技术结论，不能因辅助结果缺失而降级。";
    appendCompactFact(
      elements["case-fusion-facts"],
      "物理结论",
      "保持原样",
    );
    appendCompactFact(
      elements["case-fusion-facts"],
      "影子排序",
      "未形成",
    );
    appendCompactFact(
      elements["case-fusion-facts"],
      "独立时序证据",
      temporalCompactText(temporalEvidence),
    );
    return;
  }
  const agreement =
    FUSION_AGREEMENT_LABELS[fusion.agreement] ||
    displayText(fusion.agreement, "证据关系待确认");
  const agreementTone =
    fusion.agreement === "corroborated"
      ? "is-inconsistent"
      : fusion.agreement === "no_signal"
        ? "is-consistent"
        : fusion.agreement === "insufficient"
          ? "is-inconclusive"
          : "is-reviewing";
  elements["case-fusion-agreement"].className =
    `status-badge ${agreementTone}`;
  elements["case-fusion-agreement"].textContent = agreement;
  elements["case-fusion-summary"].textContent =
    fusion.agreement === "corroborated"
      ? "物理关系与独立辅助信号方向一致，建议优先人工复核；这仍不是违规或责任认定。"
      : fusion.agreement === "historical_only"
        ? "当前主要由历史或时序信号提示，只进入影子复核建议，不自动改变正式优先级。"
        : "辅助证据用于说明是否相互印证；无论结果如何，物理交叉核验状态均保持不变。";
  appendCompactFact(
    elements["case-fusion-facts"],
    "正式物理结论",
    fusion.physicalStatusUnchanged
      ? "未改变"
      : "保护标记未返回，请仅查看原物理结果",
  );
  appendCompactFact(
    elements["case-fusion-facts"],
    "影子复核排序",
    fusion.shadowPriority
      ? `${statusBadgeSpec(fusion.shadowPriority, "priority").label}（仅辅助）`
      : "未形成",
  );
  appendCompactFact(
    elements["case-fusion-facts"],
    "历史是否印证物理冲突",
    fusion.historicalSupportsPhysical ? "是，作为独立线索" : "否或证据不足",
  );
  appendCompactFact(
    elements["case-fusion-facts"],
    "独立时序证据",
    temporalCompactText(temporalEvidence),
  );
  fusion.reasons.slice(0, 6).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = humanizeFusionReason(reason);
    elements["case-fusion-reasons"].appendChild(item);
  });
}

function normalizeReferenceLabelResponse(rawResponse, fallbackRunId = null) {
  const response = objectOrNull(rawResponse) || {};
  const history = arrayOrNull(pickFirst(response, "history")) || [];
  const current = objectOrNull(pickFirst(response, "current"));
  const last = history.length
    ? objectOrNull(history[history.length - 1])
    : null;
  return {
    runId:
      nullableText(pickFirst(response, "run_id")) ||
      nullableText(fallbackRunId),
    current,
    history,
    chainValid: booleanOrNull(
      pickFirst(response, "chain_valid", "label_chain_valid"),
    ),
    expectedSequence:
      firstNumber(
        current && pickFirst(current, "sequence"),
        last && pickFirst(last, "sequence"),
      ) || 0,
  };
}

function configureReferenceLabelFields() {
  const isLegitimateException =
    elements["reference-label-value"].value === "legitimate_exception";
  elements["reference-label-scenario-wrap"].hidden =
    !isLegitimateException;
  elements["reference-label-scenario"].disabled =
    !isLegitimateException;
  elements["reference-label-scenario"].required =
    isLegitimateException;
  if (
    isLegitimateException &&
    !elements["reference-label-scenario"].value.trim()
  ) {
    const matched = singleMatchedScenarioId(
      state.currentCaseDetail &&
        state.currentCaseDetail.historicalEvidence,
    );
    if (matched) {
      elements["reference-label-scenario"].value = matched;
    }
  }
}

function singleMatchedScenarioId(historicalEvidence) {
  const matches =
    historicalEvidence &&
    Array.isArray(historicalEvidence.legitimateScenarioMatches)
      ? historicalEvidence.legitimateScenarioMatches
      : [];
  if (matches.length !== 1) {
    return null;
  }
  const scenario = objectOrNull(matches[0]);
  if (scenario) {
    return nullableText(pickFirst(scenario, "scenario_id"));
  }
  const text = nullableText(matches[0]);
  return text ? text.split("@")[0] : null;
}

function renderReferenceLabels() {
  const canWrite = userCan("referenceLabel");
  const labels = state.currentReferenceLabels;
  const runId = state.currentCaseDetail
    ? state.currentCaseDetail.runId
    : null;
  elements["reference-label-form"].hidden = !canWrite || !runId;
  elements["reference-label-readonly-note"].hidden = canWrite;
  elements["submit-reference-label"].disabled =
    state.referenceLabelRunning || !runId;
  clearNode(elements["reference-label-current"]);
  clearNode(elements["reference-label-history"]);

  if (state.currentReferenceLabelsError) {
    elements["reference-label-status"].className =
      "form-status is-error";
    elements["reference-label-status"].textContent =
      explainSupervisionError(
        state.currentReferenceLabelsError,
        "历史参考标签",
      );
    const note = document.createElement("p");
    note.textContent =
      "标签未读取时不会把该运行当作合法历史样本。";
    elements["reference-label-current"].appendChild(note);
    elements["reference-label-history-details"].hidden = true;
    return;
  }

  if (!labels) {
    elements["reference-label-status"].className = "form-status";
    elements["reference-label-status"].textContent =
      runId ? "正在读取标签记录…" : "该事项尚未关联分析运行，暂不能标注。";
    elements["reference-label-history-details"].hidden = true;
    return;
  }

  const current = labels.current;
  const headline = document.createElement("strong");
  const meta = document.createElement("span");
  if (current) {
    const labelCode = String(pickFirst(current, "label") || "unresolved");
    headline.textContent =
      REFERENCE_LABEL_LABELS[labelCode] || displayText(labelCode);
    meta.textContent = [
      `第 ${formatCount(firstNumber(pickFirst(current, "sequence")))} 次`,
      nullableText(pickFirst(current, "actor")),
      formatDateTime(pickFirst(current, "created_at")),
      nullableText(pickFirst(current, "scenario_id"))
        ? `情景 ${pickFirst(current, "scenario_id")}`
        : null,
    ]
      .filter(Boolean)
      .join(" · ");
  } else {
    headline.textContent = "尚无人工核实标签";
    meta.textContent =
      "未标注记录不会进入正常历史基线；合法例外仅作场景解释。";
  }
  elements["reference-label-current"].append(headline, meta);
  elements["reference-label-expected-sequence"].value = String(
    labels.expectedSequence,
  );

  if (!labels.history.length) {
    elements["reference-label-status"].className = "form-status";
    elements["reference-label-status"].textContent =
      "尚无标签记录；当前不具备历史参考资格。";
    elements["reference-label-history-details"].hidden = true;
    return;
  }
  elements["reference-label-status"].className =
    labels.chainValid === true
      ? "form-status is-success"
      : "form-status is-error";
  elements["reference-label-status"].textContent =
    labels.chainValid === true
      ? "标签变更链校验有效。"
      : "标签变更链校验异常，系统不得将其用于历史基线。";
  labels.history
    .slice()
    .reverse()
    .forEach((entry) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      const labelCode = String(pickFirst(entry, "label") || "unresolved");
      title.textContent = `第 ${formatCount(
        firstNumber(pickFirst(entry, "sequence")),
      )} 次 · ${
        REFERENCE_LABEL_LABELS[labelCode] || displayText(labelCode)
      }`;
      const metaLine = document.createElement("span");
      metaLine.textContent = [
        nullableText(pickFirst(entry, "actor")),
        formatDateTime(pickFirst(entry, "created_at")),
        nullableText(pickFirst(entry, "scenario_id"))
          ? `情景 ${pickFirst(entry, "scenario_id")}`
          : null,
      ]
        .filter(Boolean)
        .join(" · ");
      const note = document.createElement("p");
      note.textContent = displayText(
        pickFirst(entry, "note"),
        "未填写说明",
      );
      item.append(title, metaLine, note);
      elements["reference-label-history"].appendChild(item);
    });
  elements["reference-label-history-details"].hidden = false;
}

async function reloadReferenceLabels() {
  const runId = state.currentCaseDetail
    ? state.currentCaseDetail.runId
    : null;
  if (!runId) {
    return;
  }
  const body = await requestJson(
    `/v1/analysis-runs/${encodeURIComponent(runId)}/reference-labels`,
  );
  state.currentReferenceLabels =
    normalizeReferenceLabelResponse(body, runId);
  state.currentReferenceLabelsError = null;
  renderReferenceLabels();
  configureReferenceLabelFields();
}

function referenceLabelError(error, subject) {
  if (error instanceof ApiError) {
    const apiError = objectOrNull(error.body && error.body.error) || {};
    if (apiError.code === "legitimate_scenario_not_matched") {
      return `${subject}未完成：该合法情景与本次矿山、工况、审批事件或特征范围不匹配，请核对情景编号和原始审批材料。`;
    }
    if (apiError.code === "invalid_reference_label") {
      return `${subject}未完成：标签内容不完整；合法例外必须引用与本次记录匹配的已批准情景。`;
    }
  }
  return explainAccessError(error, subject);
}

async function submitReferenceLabel(event) {
  event.preventDefault();
  if (state.referenceLabelRunning || !userCan("referenceLabel")) {
    return;
  }
  const runId = state.currentCaseDetail
    ? state.currentCaseDetail.runId
    : null;
  if (!runId) {
    elements["reference-label-status"].className =
      "form-status is-error";
    elements["reference-label-status"].textContent =
      "该事项尚未关联分析运行，不能提交历史参考标签。";
    return;
  }
  const scenarioId = elements["reference-label-scenario"].value.trim();
  const payload = {
    label: elements["reference-label-value"].value,
    expected_sequence:
      firstNumber(elements["reference-label-expected-sequence"].value) || 0,
    note: elements["reference-label-note"].value.trim(),
  };
  if (
    payload.label === "legitimate_exception" &&
    scenarioId
  ) {
    payload.scenario_id = scenarioId;
  }
  if (
    payload.label === "legitimate_exception" &&
    !scenarioId
  ) {
    elements["reference-label-status"].className =
      "form-status is-error";
    elements["reference-label-status"].textContent =
      "标注合法例外时，必须填写与本次工况实际匹配的已批准情景编号。";
    elements["reference-label-scenario"].focus();
    return;
  }
  if (!payload.note) {
    elements["reference-label-status"].className =
      "form-status is-error";
    elements["reference-label-status"].textContent =
      "请填写核实依据；不能只凭算法结果提交标签。";
    elements["reference-label-note"].focus();
    return;
  }

  state.referenceLabelRunning = true;
  elements["submit-reference-label"].disabled = true;
  elements["reference-label-status"].className = "form-status";
  elements["reference-label-status"].textContent =
    "正在追加标签和审计留痕…";
  try {
    const body = await requestJson(
      `/v1/analysis-runs/${encodeURIComponent(runId)}/reference-labels`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    state.currentReferenceLabels =
      normalizeReferenceLabelResponse(body, runId);
    state.currentReferenceLabelsError = null;
    elements["reference-label-note"].value = "";
    renderReferenceLabels();
    configureReferenceLabelFields();
    elements["reference-label-status"].className =
      "form-status is-success";
    elements["reference-label-status"].textContent =
      "标签已追加并留痕；旧标签仍保留。";
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      try {
        await reloadReferenceLabels();
      } catch {
        // Keep the original version-conflict explanation below.
      }
    }
    elements["reference-label-status"].className =
      "form-status is-error";
    elements["reference-label-status"].textContent =
      referenceLabelError(error, "提交历史参考标签");
  } finally {
    state.referenceLabelRunning = false;
    elements["submit-reference-label"].disabled = false;
  }
}

function configureOverviewReferenceLabelFields() {
  const legitimate =
    elements["overview-reference-label-value"].value ===
    "legitimate_exception";
  elements["overview-reference-label-scenario-wrap"].hidden =
    !legitimate;
  elements["overview-reference-label-scenario"].disabled =
    !legitimate;
  elements["overview-reference-label-scenario"].required =
    legitimate;
  if (
    legitimate &&
    !elements["overview-reference-label-scenario"].value.trim()
  ) {
    const matched = singleMatchedScenarioId(
      state.overviewReferenceLabelItem &&
        state.overviewReferenceLabelItem.historicalEvidence,
    );
    if (matched) {
      elements["overview-reference-label-scenario"].value = matched;
    }
  }
}

function closeOverviewReferenceLabelDialog(event = null) {
  if (event) {
    event.preventDefault();
  }
  const dialog = elements["overview-reference-label-dialog"];
  if (dialog.open) {
    dialog.close();
  }
  state.overviewReferenceLabelRunId = null;
  state.overviewReferenceLabelItem = null;
  state.overviewReferenceLabels = null;
  state.overviewReferenceLabelError = null;
}

async function openOverviewReferenceLabelDialog(item) {
  const runId = item ? item.analysisRunId : null;
  if (!runId) {
    return;
  }
  state.overviewReferenceLabelRunId = runId;
  state.overviewReferenceLabelItem = item;
  state.overviewReferenceLabels = null;
  state.overviewReferenceLabelError = null;
  elements["overview-reference-label-form"].reset();
  elements["overview-reference-label-title"].textContent =
    userCan("referenceLabel")
      ? "核实并标记历史样本"
      : "查看历史参考标签";
  elements["overview-reference-label-context"].textContent = [
    item.mineName,
    item.mineId,
    formatPeriod(item.windowStart, item.windowEnd),
    `物理状态：${statusBadgeSpec(
      item.technicalStatus,
      "technical",
    ).label}`,
  ]
    .filter(Boolean)
    .join(" · ");
  configureOverviewReferenceLabelFields();
  renderOverviewReferenceLabels();
  const dialog = elements["overview-reference-label-dialog"];
  if (!dialog.open) {
    dialog.showModal();
  }
  try {
    const body = await requestJson(
      `/v1/analysis-runs/${encodeURIComponent(runId)}/reference-labels`,
    );
    if (state.overviewReferenceLabelRunId !== runId) {
      return;
    }
    state.overviewReferenceLabels =
      normalizeReferenceLabelResponse(body, runId);
  } catch (error) {
    if (state.overviewReferenceLabelRunId !== runId) {
      return;
    }
    state.overviewReferenceLabelError = error;
  }
  renderOverviewReferenceLabels();
  configureOverviewReferenceLabelFields();
}

function renderOverviewReferenceLabels() {
  const labels = state.overviewReferenceLabels;
  const canWrite = userCan("referenceLabel");
  const status = elements["overview-reference-label-status"];
  const currentContainer =
    elements["overview-reference-label-current"];
  const historyContainer =
    elements["overview-reference-label-history"];
  clearNode(currentContainer);
  clearNode(historyContainer);
  elements["overview-reference-label-form"].hidden = !canWrite;
  elements["overview-reference-label-readonly-note"].hidden = canWrite;
  elements["submit-overview-reference-label"].disabled =
    state.overviewReferenceLabelRunning;

  if (state.overviewReferenceLabelError) {
    status.className = "form-status is-error";
    status.textContent = explainSupervisionError(
      state.overviewReferenceLabelError,
      "历史参考标签",
    );
    const note = document.createElement("p");
    note.textContent =
      "读取失败时不会把该运行当作合法历史样本。";
    currentContainer.appendChild(note);
    elements["overview-reference-label-history-details"].hidden = true;
    return;
  }
  if (!labels) {
    status.className = "form-status";
    status.textContent = "正在读取标签记录…";
    const note = document.createElement("p");
    note.textContent =
      "历史标签与物理技术状态分开记录，不会自动生成。";
    currentContainer.appendChild(note);
    elements["overview-reference-label-history-details"].hidden = true;
    return;
  }

  const current = labels.current;
  const headline = document.createElement("strong");
  const meta = document.createElement("span");
  if (current) {
    const code = String(pickFirst(current, "label") || "unresolved");
    headline.textContent =
      REFERENCE_LABEL_LABELS[code] || displayText(code);
    meta.textContent = [
      `第 ${formatCount(firstNumber(pickFirst(current, "sequence")))} 次`,
      nullableText(pickFirst(current, "actor")),
      formatDateTime(pickFirst(current, "created_at")),
      nullableText(pickFirst(current, "scenario_id"))
        ? `情景 ${pickFirst(current, "scenario_id")}`
        : null,
    ]
      .filter(Boolean)
      .join(" · ");
  } else {
    headline.textContent = "尚无人工核实标签";
    meta.textContent =
      "即使物理状态为“当前可协调”，也不会自动进入正常历史基线。";
  }
  currentContainer.append(headline, meta);
  elements["overview-reference-label-expected-sequence"].value =
    String(labels.expectedSequence);

  if (!labels.history.length) {
    status.className = "form-status";
    status.textContent =
      "尚无标签记录；当前不具备历史参考资格。";
    elements["overview-reference-label-history-details"].hidden = true;
    return;
  }
  status.className =
    labels.chainValid === true
      ? "form-status is-success"
      : "form-status is-error";
  status.textContent =
    labels.chainValid === true
      ? "标签变更链校验有效。"
      : "标签变更链校验异常，系统不得将其用于历史基线。";
  labels.history
    .slice()
    .reverse()
    .forEach((entry) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      const code = String(pickFirst(entry, "label") || "unresolved");
      title.textContent = `第 ${formatCount(
        firstNumber(pickFirst(entry, "sequence")),
      )} 次 · ${REFERENCE_LABEL_LABELS[code] || displayText(code)}`;
      const metaLine = document.createElement("span");
      metaLine.textContent = [
        nullableText(pickFirst(entry, "actor")),
        formatDateTime(pickFirst(entry, "created_at")),
      ]
        .filter(Boolean)
        .join(" · ");
      const note = document.createElement("p");
      note.textContent = displayText(
        pickFirst(entry, "note"),
        "未填写说明",
      );
      item.append(title, metaLine, note);
      historyContainer.appendChild(item);
    });
  elements["overview-reference-label-history-details"].hidden = false;
}

async function submitOverviewReferenceLabel(event) {
  event.preventDefault();
  if (
    state.overviewReferenceLabelRunning ||
    !userCan("referenceLabel")
  ) {
    return;
  }
  const runId = state.overviewReferenceLabelRunId;
  if (!runId) {
    return;
  }
  const note = elements["overview-reference-label-note"].value.trim();
  if (!note) {
    elements["overview-reference-label-status"].className =
      "form-status is-error";
    elements["overview-reference-label-status"].textContent =
      "请填写核实依据；不能只凭算法结果提交标签。";
    elements["overview-reference-label-note"].focus();
    return;
  }
  const label = elements["overview-reference-label-value"].value;
  const scenarioId =
    elements["overview-reference-label-scenario"].value.trim();
  const payload = {
    label,
    expected_sequence:
      firstNumber(
        elements["overview-reference-label-expected-sequence"].value,
      ) || 0,
    note,
  };
  if (label === "legitimate_exception" && scenarioId) {
    payload.scenario_id = scenarioId;
  }
  if (label === "legitimate_exception" && !scenarioId) {
    elements["overview-reference-label-status"].className =
      "form-status is-error";
    elements["overview-reference-label-status"].textContent =
      "标注合法例外时，必须填写与本次工况实际匹配的已批准情景编号。";
    elements["overview-reference-label-scenario"].focus();
    return;
  }
  state.overviewReferenceLabelRunning = true;
  elements["submit-overview-reference-label"].disabled = true;
  elements["overview-reference-label-status"].className =
    "form-status";
  elements["overview-reference-label-status"].textContent =
    "正在追加标签和审计留痕…";
  try {
    const body = await requestJson(
      `/v1/analysis-runs/${encodeURIComponent(runId)}/reference-labels`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    );
    state.overviewReferenceLabels =
      normalizeReferenceLabelResponse(body, runId);
    state.overviewReferenceLabelError = null;
    elements["overview-reference-label-note"].value = "";
    renderOverviewReferenceLabels();
    configureOverviewReferenceLabelFields();
    elements["overview-reference-label-status"].className =
      "form-status is-success";
    elements["overview-reference-label-status"].textContent =
      "标签已追加并留痕；物理技术状态没有被改写。";
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      try {
        const body = await requestJson(
          `/v1/analysis-runs/${encodeURIComponent(runId)}/reference-labels`,
        );
        state.overviewReferenceLabels =
          normalizeReferenceLabelResponse(body, runId);
      } catch {
        // Preserve the original conflict for the user-facing explanation.
      }
    }
    renderOverviewReferenceLabels();
    elements["overview-reference-label-status"].className =
      "form-status is-error";
    elements["overview-reference-label-status"].textContent =
      referenceLabelError(error, "提交历史参考标签");
  } finally {
    state.overviewReferenceLabelRunning = false;
    elements["submit-overview-reference-label"].disabled = false;
  }
}

function renderCaseFacts(detail) {
  clearNode(elements["case-facts"]);
  const analysis = detail.analysis || {};
  const scenario = productionScenarioSummary(analysis);
  const evidenceInsufficient =
    scenario.evidenceInsufficient ||
    (detail.technicalStatus === "inconsistent" &&
      scenario.alternatives.length === 0) ||
    String(detail.evidenceGrade || "").toUpperCase() === "D";
  let reported = firstNumber(
    pickFirst(
      analysis,
      "reported_production_t",
      "reported_output_t",
      "reported_value",
    ),
  );
  if (
    reported === null &&
    detail.inputSnapshot &&
    Array.isArray(detail.inputSnapshot.observations)
  ) {
    const observation = detail.inputSnapshot.observations.find(
      (item) => item.metric_code === "coal.reported_output_t",
    );
    reported = firstNumber(observation ? observation.value : undefined);
  }
  const range = pickFirst(
    analysis,
    "scenario_union_production_range",
    "reasonable_production_range",
    "reasonable_range",
  );
  const lower = firstNumber(
    Array.isArray(range) ? range[0] : pickFirst(range, "lower", "min"),
    pickFirst(analysis, "reasonable_lower_t"),
  );
  const upper = firstNumber(
    Array.isArray(range) ? range[1] : pickFirst(range, "upper", "max"),
    pickFirst(analysis, "reasonable_upper_t"),
  );
  const gap = firstNumber(
    pickFirst(
      analysis,
      "robust_minimum_reported_gap",
      "minimum_reported_gap",
      "minimum_technical_gap_t",
      "technical_gap",
    ),
  );
  const receipt =
    detail.technicalStatus === "missing"
      ? "缺报（没有数值，不按 0 处理）"
      : dataReceiptLabel(detail);
  const facts = [
    ["监管对象", detail.companyName ? `${detail.mineName} · ${detail.companyName}` : detail.mineName],
    ["分析期间", formatPeriod(detail.windowStart, detail.windowEnd)],
    ["数据接收", receipt],
    [
      "收到的上报产量",
      reported === null ? "未返回或未收到" : formatTon(reported),
    ],
    [
      "多情景合理技术区间（并集）",
      evidenceInsufficient
        ? "证据不足、不能下结论"
        : lower === null || upper === null
        ? "暂无法计算"
        : `${formatTon(lower)}–${formatTon(upper)}`,
    ],
    [
      "多情景稳健最小技术差额",
      evidenceInsufficient
        ? "证据不足、不能下结论"
        : gap === null
          ? "暂无法判断"
          : `${formatTon(gap)}（仅为技术线索）`,
    ],
    [
      "优先核查情景",
      detail.technicalStatus === "inconsistent"
        ? `${scenario.priorityCount} 个${
            scenario.divergent ? "（情景结论有分歧）" : ""
          }`
        : "无需放宽来源",
    ],
    ["责任人 / 承办单位", detail.assignee || "待明确"],
    [
      "办理期限",
      detail.dueAt
        ? `${formatDateTime(detail.dueAt)}${detail.overdue ? "（已逾期）" : ""}`
        : "待安排",
    ],
    [
      "人工结论提交",
      detail.conclusionBy
        ? `${detail.conclusionBy} · ${formatDateTime(detail.conclusionAt)}`
        : "尚未提交",
    ],
    [
      "双人复核审批",
      detail.approvalBy
        ? `${detail.approvalBy} · ${formatDateTime(detail.approvalAt)}`
        : detail.workflowStatus === "pending_approval"
          ? "等待另一名监管负责人审批"
          : "尚未审批",
    ],
  ];
  facts.forEach(([term, description]) => {
    const wrapper = document.createElement("div");
    wrapper.className = "fact-item";
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = description;
    wrapper.append(dt, dd);
    elements["case-facts"].appendChild(wrapper);
  });
}

function renderCaseChecks(detail) {
  const checks = detail.recommendedChecks.length
    ? detail.recommendedChecks.map(humanizeRecommendedCheck)
    : defaultCaseChecks(detail.technicalStatus);
  renderList(elements["case-recommended-checks"], checks);
}

function defaultCaseChecks(status) {
  if (status === "missing" || status === "inconclusive") {
    return [
      "向数据责任单位确认应报范围、统计时段和未报原因。",
      "补齐阻断分析的原始记录，并核对缺失值与明确零值。",
      "数据补齐后重新交叉核验，再记录人工复核结论。",
    ];
  }
  if (status === "inconsistent") {
    return [
      "保全当前批次原始数据、导出记录和系统日志。",
      "调取相关来源的原始表底、设备日志、视频或业务凭证。",
      "由业务人员统一统计口径后复核，并在台账中记录结论。",
    ];
  }
  return [
    "按监管计划抽查原始记录，并保留本次技术研判结果。",
    "如后续收到更完整数据，重新分析并记录版本变化。",
  ];
}

function renderCaseEvidence(detail) {
  clearNode(elements["case-evidence-list"]);
  const evidence = detail.evidence.slice();
  if (!evidence.length) {
    detail.supportingGroups.forEach((group) => {
      evidence.push({
        source_group: group,
        source_name: sourceLabel(group),
      });
    });
  }
  evidence.forEach((entry, index) => {
    const item =
      entry && typeof entry === "object" && !Array.isArray(entry)
        ? entry
        : { source_name: String(entry) };
    const row = document.createElement("li");
    row.className = "evidence-item";
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = displayText(
      pickFirst(
        item,
        "source_group_name",
        "source_name",
        "name",
        "source_group",
      ),
      `证据来源 ${index + 1}`,
    );
    const meta = document.createElement("span");
    meta.textContent = [
      nullableText(pickFirst(item, "source_system", "source_owner")),
      pickFirst(item, "captured_at", "received_at")
        ? formatDateTime(pickFirst(item, "captured_at", "received_at"))
        : null,
      nullableText(pickFirst(item, "evidence_id", "observation_id")),
    ]
      .filter(Boolean)
      .join(" · ") || "已参与本次技术研判";
    text.append(title, meta);
    row.appendChild(text);

    const uri = safeEvidenceUrl(
      pickFirst(item, "preview_uri", "original_uri", "uri", "url"),
    );
    if (uri) {
      const link = document.createElement("a");
      link.className = "evidence-link";
      link.href = uri;
      link.target = "_blank";
      link.rel = "noreferrer";
      link.textContent = "查看原始材料";
      row.appendChild(link);
    } else {
      const noLink = document.createElement("span");
      noLink.className = "table-secondary";
      noLink.textContent = "材料链接未返回";
      row.appendChild(noLink);
    }
    elements["case-evidence-list"].appendChild(row);
  });
  elements["case-evidence-empty"].hidden = evidence.length > 0;
}

function renderCaseTimeline(detail) {
  clearNode(elements["case-timeline"]);
  const events = detail.events.slice();
  if (!events.length && detail.createdAt) {
    events.push({
      event_type: "created",
      timestamp: detail.createdAt,
      actor_name: "系统",
      comment: "根据技术研判结果形成待复核事项。",
    });
  }
  events
    .sort((left, right) => {
      const leftTime = new Date(
        pickFirst(left, "timestamp", "created_at", "occurred_at") || 0,
      ).valueOf();
      const rightTime = new Date(
        pickFirst(right, "timestamp", "created_at", "occurred_at") || 0,
      ).valueOf();
      return rightTime - leftTime;
    })
    .forEach((event) => {
      const item = document.createElement("li");
      item.className = "timeline-item";
      const time = document.createElement("time");
      time.className = "timeline-time";
      const timestamp = pickFirst(
        event,
        "timestamp",
        "created_at",
        "occurred_at",
      );
      if (timestamp) {
        time.dateTime = String(timestamp);
      }
      time.textContent = formatDateTime(timestamp);
      const content = document.createElement("div");
      content.className = "timeline-content";
      const title = document.createElement("strong");
      title.textContent = eventTypeLabel(
        pickFirst(event, "event_type", "action", "type"),
      );
      const actor = document.createElement("span");
      actor.textContent = displayText(
        pickFirst(
          event,
          "actor_name",
          "actor",
          "operator_name",
          "created_by",
        ),
        "系统记录",
      );
      content.append(title, actor);
      const comment = nullableText(
        pickFirst(event, "comment", "note", "description", "disposition"),
      );
      if (comment) {
        const paragraph = document.createElement("p");
        paragraph.textContent = comment;
        content.appendChild(paragraph);
      }
      item.append(time, content);
      elements["case-timeline"].appendChild(item);
    });

  if (!events.length) {
    const item = document.createElement("li");
    item.className = "timeline-item";
    const time = document.createElement("span");
    time.className = "timeline-time";
    time.textContent = "时间未返回";
    const content = document.createElement("div");
    content.className = "timeline-content";
    const title = document.createElement("strong");
    title.textContent = "暂无办理记录";
    const note = document.createElement("p");
    note.textContent = "提交办理动作后，责任人、说明和版本变化将在此留痕。";
    content.append(title, note);
    item.append(time, content);
    elements["case-timeline"].appendChild(item);
  }
  elements["case-event-count"].textContent = `${events.length} 条记录`;
}

function renderCaseAudit(detail) {
  const hashStatus = elements["case-hash-status"];
  hashStatus.className = "hash-status";
  const integrityValid =
    detail.integrityValid === null
      ? detail.auditChainValid
      : detail.integrityValid;
  if (integrityValid === true) {
    hashStatus.classList.add("is-valid");
    hashStatus.textContent = "✓ 办理记录与分析哈希校验通过";
  } else if (integrityValid === false) {
    hashStatus.classList.add("is-invalid");
    hashStatus.textContent = "! 完整性校验未通过，请暂停据此形成结论";
  } else {
    hashStatus.textContent = "— 服务未返回完整性校验结果";
  }

  clearNode(elements["case-trace-fields"]);
  const fields = [
    ["输入批次", detail.batchId],
    ["分析运行", detail.runId],
    ["输入哈希", detail.inputHash],
    ["结果哈希", detail.resultHash],
    [
      "分析快照校验",
      detail.runHashesValid === null
        ? null
        : detail.runHashesValid
          ? "通过"
          : "未通过",
    ],
    ["最新办理记录哈希", detail.currentHash],
    ["模型版本", detail.modelVersion],
    ["规则版本", detail.rulesetVersion],
    [
      "事项版本",
      detail.version === null ? null : String(detail.version),
    ],
    ["校验范围", detail.auditScope],
  ];
  fields.forEach(([term, value]) => {
    if (!value) {
      return;
    }
    const wrapper = document.createElement("div");
    wrapper.className = "trace-field";
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    elements["case-trace-fields"].appendChild(wrapper);
  });
  if (!elements["case-trace-fields"].children.length) {
    const wrapper = document.createElement("div");
    wrapper.className = "trace-field";
    const dt = document.createElement("dt");
    dt.textContent = "追溯信息";
    const dd = document.createElement("dd");
    dd.textContent = "暂未返回批次、版本或哈希字段";
    wrapper.append(dt, dd);
    elements["case-trace-fields"].appendChild(wrapper);
  }
}

function resetEvidenceBundle() {
  state.currentEvidenceBundle = null;
  state.evidenceRunning = false;
  elements["evidence-bundle-result"].hidden = true;
  elements["evidence-bundle-status"].textContent = "";
  elements["evidence-bundle-status"].className = "form-status";
  elements["generate-evidence"].disabled = false;
  clearNode(elements["evidence-bundle-fields"]);
  clearNode(elements["evidence-bundle-actions"]);
}

async function generateEvidenceBundle() {
  if (
    state.evidenceRunning ||
    !state.currentCaseId ||
    !userCan("evidence")
  ) {
    return;
  }
  if (state.currentCaseVersion === null) {
    setEvidenceStatus("事项版本未返回，请刷新事项后重试。", "error");
    return;
  }
  state.evidenceRunning = true;
  elements["generate-evidence"].disabled = true;
  setEvidenceStatus("正在按当前事项版本生成并校验证据包…");
  try {
    const body = await requestJson(
      `${SUPERVISION_API_PATHS.cases}/${encodeURIComponent(
        state.currentCaseId,
      )}/evidence`,
      {
        method: "POST",
        body: JSON.stringify({
          expected_version: state.currentCaseVersion,
        }),
      },
    );
    renderEvidenceBundle(body);
    setEvidenceStatus("证据包已生成并完成完整性校验。", "success");
  } catch (error) {
    setEvidenceStatus(
      explainAccessError(error, "生成证据包"),
      "error",
    );
  } finally {
    state.evidenceRunning = false;
    elements["generate-evidence"].disabled = false;
  }
}

function renderEvidenceBundle(body) {
  const evidence =
    objectOrNull(pickFirst(body, "evidence", "bundle")) || {};
  const verification = objectOrNull(body.verification) || {};
  const bundleId = nullableText(evidence.bundle_id);
  state.currentEvidenceBundle = {
    bundleId,
    evidence,
    verification,
  };
  elements["evidence-bundle-result"].hidden = false;
  const verificationNode = elements["evidence-verification"];
  verificationNode.className = "hash-status";
  const valid = booleanOrNull(verification.valid);
  if (valid === true) {
    verificationNode.classList.add("is-valid");
    verificationNode.textContent = "✓ 证据包清单与文件哈希校验通过";
  } else if (valid === false) {
    verificationNode.classList.add("is-invalid");
    verificationNode.textContent = "! 证据包校验未通过，请勿移交使用";
  } else {
    verificationNode.textContent = "— 尚未返回证据包校验结果";
  }
  clearNode(elements["evidence-bundle-fields"]);
  const fields = [
    ["证据包编号", bundleId],
    [
      "事项版本",
      evidence.case_version === null ||
      typeof evidence.case_version === "undefined"
        ? null
        : String(evidence.case_version),
    ],
    [
      "清单哈希",
      nullableText(
        pickFirst(verification, "manifest_sha256") ||
          evidence.manifest_sha256,
      ),
    ],
    ["压缩包哈希", nullableText(evidence.bundle_sha256)],
    ["生成账号", nullableText(evidence.created_by)],
    ["生成时间", evidence.generated_at ? formatDateTime(evidence.generated_at) : null],
  ];
  fields.forEach(([term, value]) => {
    if (!value) {
      return;
    }
    const wrapper = document.createElement("div");
    wrapper.className = "trace-field";
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    dd.textContent = value;
    wrapper.append(dt, dd);
    elements["evidence-bundle-fields"].appendChild(wrapper);
  });

  clearNode(elements["evidence-bundle-actions"]);
  if (bundleId) {
    const download = document.createElement("button");
    download.type = "button";
    download.className = "button quiet compact";
    download.textContent = "下载证据包";
    download.addEventListener("click", () =>
      downloadEvidenceBundle(bundleId),
    );
    const verify = document.createElement("button");
    verify.type = "button";
    verify.className = "button quiet compact";
    verify.textContent = "重新校验";
    verify.addEventListener("click", () => verifyEvidenceBundle(bundleId));
    elements["evidence-bundle-actions"].append(download, verify);
  }
}

async function verifyEvidenceBundle(bundleId) {
  setEvidenceStatus("正在重新读取并校验证据包…");
  try {
    const body = await requestJson(
      `/v1/evidence/${encodeURIComponent(bundleId)}/verify`,
    );
    renderEvidenceBundle(body);
    const valid = Boolean(
      body && body.verification && body.verification.valid,
    );
    setEvidenceStatus(
      valid ? "重新校验通过。" : "重新校验未通过，请勿使用该证据包。",
      valid ? "success" : "error",
    );
  } catch (error) {
    setEvidenceStatus(
      explainAccessError(error, "校验证据包"),
      "error",
    );
  }
}

async function downloadEvidenceBundle(bundleId) {
  setEvidenceStatus("正在下载证据包…");
  try {
    const response = await fetch(
      `/v1/evidence/${encodeURIComponent(bundleId)}`,
      {
        method: "GET",
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/zip" },
      },
    );
    if (!response.ok) {
      let body = {};
      try {
        body = JSON.parse(await response.text());
      } catch {
        body = {};
      }
      if (response.status === 401) {
        resetProtectedState();
        showLogin("会话已失效，请重新登录后下载证据包。", "error");
      }
      throw new ApiError(response.status, body);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${bundleId}.zip`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    setEvidenceStatus("证据包下载已开始。", "success");
  } catch (error) {
    setEvidenceStatus(
      explainAccessError(error, "下载证据包"),
      "error",
    );
  }
}

function setEvidenceStatus(message, tone = "") {
  elements["evidence-bundle-status"].textContent = message;
  elements["evidence-bundle-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

async function submitCaseAction(event) {
  event.preventDefault();
  if (state.caseActionRunning || !state.currentCaseId) {
    return;
  }
  const action = elements["case-action"].value;
  const assignee =
    action === "assign" ? elements["case-assignee"].value.trim() : "";
  const disposition =
    ["submit_conclusion", "close"].includes(action)
      ? elements["case-disposition"].value.trim()
      : "";
  const note = elements["case-action-note"].value.trim();
  if (state.currentCaseVersion === null) {
    setCaseActionStatus(
      "当前事项版本未返回，无法安全提交。请返回台账后重新打开事项。",
      "error",
    );
    return;
  }
  if (action === "assign" && !assignee) {
    setCaseActionStatus("交办核查时请填写责任人或承办单位。", "error");
    elements["case-assignee"].focus();
    return;
  }
  if (
    [
      "add_note",
      "request_data",
      "submit_conclusion",
      "withdraw_conclusion",
      "approve",
      "reject",
      "close",
      "reopen",
      "archive_case",
      "restore_case",
    ].includes(action) &&
    !note
  ) {
    setCaseActionStatus("该动作需要填写办理说明。", "error");
    elements["case-action-note"].focus();
    return;
  }
  if (["submit_conclusion", "close"].includes(action) && !disposition) {
    setCaseActionStatus("提交人工结论前请选择复核结果。", "error");
    elements["case-disposition"].focus();
    return;
  }

  const confirmationDetails = {
    submit_conclusion: {
      title: "提交人工复核结论？",
      message:
        "提交后事项进入待审批，必须由另一名监管负责人批准或退回；当前说明和结论将完整留痕。",
      confirmLabel: "提交并等待审批",
    },
    withdraw_conclusion: {
      title: "撤回本人提交的结论？",
      message:
        "事项将回到核查中，当前结论不再等待审批；原提交内容和撤回原因仍保留在时间线。",
      confirmLabel: "确认撤回",
      danger: true,
    },
    approve: {
      title: "批准该人工复核结论？",
      message:
        "批准后事项将关闭，并记录提交人与审批人；请确认已经核验原始材料和业务口径。",
      confirmLabel: "批准并关闭",
    },
    reject: {
      title: "退回该人工复核结论？",
      message:
        "事项将回到核查中，退回说明会通知后续复核并进入办理时间线。",
      confirmLabel: "确认退回",
      danger: true,
    },
    close: {
      title: "关闭该事项？",
      message: "关闭动作及办理说明将永久留痕，事项仍可按权限重新打开。",
      confirmLabel: "确认关闭",
    },
    reopen: {
      title: "重新打开该事项？",
      message:
        "事项将回到核查中，原结论、审批记录和关闭记录均不会被覆盖。",
      confirmLabel: "确认重新打开",
    },
    archive_case: {
      title: "将该事项移出常用台账？",
      message:
        "归档仅隐藏已经关闭的事项，技术结果、证据引用和完整办理记录都不会删除。",
      confirmLabel: "确认归档",
      danger: true,
    },
    restore_case: {
      title: "将该事项恢复到常用台账？",
      message:
        "恢复后事项会重新出现在常用台账，但仍保持关闭状态；原记录不会改变。",
      confirmLabel: "确认恢复",
    },
  };
  const confirmationConfig = confirmationDetails[action];
  if (confirmationConfig) {
    const confirmation = await requestActionConfirmation(confirmationConfig);
    if (!confirmation.confirmed) {
      return;
    }
  }

  state.caseActionRunning = true;
  elements["submit-case-action"].disabled = true;
  setCaseActionStatus("正在提交并写入办理留痕…");
  const body = {
    action,
    expected_version: state.currentCaseVersion,
    note: note ? note : null,
    disposition: disposition ? disposition : null,
    assignee: assignee ? assignee : null,
  };

  try {
    const encodedId = encodeURIComponent(state.currentCaseId);
    await requestJson(
      `${SUPERVISION_API_PATHS.cases}/${encodedId}/actions`,
      {
        method: "POST",
        body: JSON.stringify(body),
      },
    );
    await loadCaseDetail(state.currentCaseId);
    const successMessages = {
      submit_conclusion:
        "人工结论已提交，正等待另一名监管负责人审批。",
      withdraw_conclusion:
        "本人提交的结论已撤回，事项回到核查中；原提交记录仍保留。",
      approve: "已完成双人复核审批，事项已关闭。",
      reject: "结论已退回复核人员，事项回到核查中。",
      reopen: "事项已重新打开，原结论与关闭记录仍保留。",
      archive_case:
        "事项已归档并移出常用台账；技术结果、证据和办理记录仍保留。",
      restore_case: "事项已恢复到常用台账，并保持关闭状态。",
    };
    setCaseActionStatus(
      successMessages[action] ||
        "办理动作已提交，并已刷新事项版本和时间线。",
      "success",
    );
    state.casesLoaded = false;
    state.overviewLoaded = false;
    loadCases();
    loadOverview();
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      const code =
        error.body && error.body.error ? error.body.error.code : "";
      setCaseActionStatus(
        code === "version_conflict"
          ? "事项已被其他人员更新。请返回台账重新打开后，再确认是否提交。"
          : code === "double_review_required"
            ? "认证模式必须先提交人工结论，再由另一名监管负责人审批，不能直接关闭。"
            : "当前办理状态或双人复核规则不支持该动作；提交人与审批人必须是不同账号。",
        "error",
      );
    } else if (error instanceof ApiError && error.status === 403) {
      setCaseActionStatus(
        "当前账号没有执行该动作的权限，或该事项不在授权矿山范围内。",
        "error",
      );
    } else {
      setCaseActionStatus(
        explainSupervisionError(error, "办理动作"),
        "error",
      );
    }
  } finally {
    state.caseActionRunning = false;
    elements["submit-case-action"].disabled = false;
  }
}

function setCaseActionStatus(message, tone = "") {
  elements["case-action-status"].textContent = message;
  elements["case-action-status"].className =
    `form-status${tone ? ` is-${tone}` : ""}`;
}

function downloadCurrentCase() {
  if (!state.currentCaseResponse || !state.currentCaseId) {
    return;
  }
  downloadJson(
    state.currentCaseResponse,
    "mineguard-case",
    state.currentCaseId,
  );
}

function printView(target) {
  document.body.classList.add(`print-${target}`);
  window.addEventListener(
    "afterprint",
    () => document.body.classList.remove(`print-${target}`),
    { once: true },
  );
  window.print();
}

function handleTabKeydown(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
    return;
  }
  event.preventDefault();
  const nextMode =
    event.key === "ArrowLeft" || event.key === "Home"
      ? "production"
      : "personnel";
  setMode(nextMode);
  const target =
    nextMode === "production"
      ? elements["production-tab"]
      : elements["personnel-tab"];
  target.focus();
}

function setMode(mode) {
  if (!API_PATHS[mode] || state.isRunning) {
    return;
  }
  state.mode = mode;

  const isProduction = mode === "production";
  elements["production-tab"].classList.toggle("is-active", isProduction);
  elements["production-tab"].setAttribute("aria-selected", String(isProduction));
  elements["personnel-tab"].classList.toggle("is-active", !isProduction);
  elements["personnel-tab"].setAttribute("aria-selected", String(!isProduction));
  elements["input-panel"].setAttribute(
    "aria-labelledby",
    isProduction ? "production-tab" : "personnel-tab",
  );

  elements["mode-description"].textContent = isProduction
    ? "比对上报产量与皮带、入洗、销售、库存数据，定位相互矛盾的数据来源。"
    : "比对井口人脸与定位卡通行记录，发现人卡不符、有脸无卡或有卡无人。";
  elements["load-risk-sample"].textContent = isProduction
    ? "载入异常示例"
    : "载入人卡异常示例";
  elements["load-normal-sample"].textContent = isProduction
    ? "载入正常示例"
    : "载入通行正常示例";
  elements["analyze-button-text"].textContent = isProduction
    ? "开始交叉核验"
    : "开始人员核验";

  clearDataset();
  hideResult();
}

function clearDataset() {
  state.currentInput = null;
  state.datasetName = "";
  elements["json-editor"].value = "";
  elements["file-input"].value = "";
  elements["dataset-card"].classList.add("is-empty");
  elements["dataset-name"].textContent = "尚未载入数据";
  elements["dataset-summary"].textContent = "请选择示例或上传文件";
  elements["dataset-state"].textContent = "待导入";
  elements["analyze-button"].disabled = true;
  elements["clear-analysis"].disabled = true;
  setRequestStatus("数据载入后即可开始分析");
}

function clearCurrentAnalysis() {
  if (state.isRunning) {
    return;
  }
  clearDataset();
  state.lastResult = null;
  state.lastResultMode = null;
  hideResult();
  setRequestStatus(
    "本次临时输入和结果已从页面清空；正式台账和审计记录未受影响。",
  );
}

function loadDataset(data, name) {
  const clone = JSON.parse(JSON.stringify(data));
  state.currentInput = clone;
  state.datasetName = name;
  elements["json-editor"].value = JSON.stringify(clone, null, 2);
  elements["dataset-card"].classList.remove("is-empty");
  elements["dataset-name"].textContent = name;
  elements["dataset-summary"].textContent = describeDataset(clone);
  elements["dataset-state"].textContent = "已载入";
  elements["analyze-button"].disabled = false;
  elements["clear-analysis"].disabled = false;
  setRequestStatus("数据已就绪，请点击开始分析");
}

function describeDataset(data) {
  if (state.mode === "production") {
    const count = Array.isArray(data.observations) ? data.observations.length : 0;
    const period =
      formatDateOnly(data.window_start) && formatDateOnly(data.window_end)
        ? `${formatDateOnly(data.window_start)} 至 ${formatDateOnly(data.window_end)}`
        : "时间范围待校验";
    return `${data.mine_id || "矿井编号待校验"} · ${period} · ${count} 项观测`;
  }
  const faceCount = Array.isArray(data.faces) ? data.faces.length : 0;
  const cardCount = Array.isArray(data.cards) ? data.cards.length : 0;
  return `${data.session_id || "场次编号待校验"} · ${faceCount} 条人脸 · ${cardCount} 条定位卡`;
}

async function handleFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) {
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    showInputError("文件超过 10 MB，请压缩数据范围后重试。");
    event.target.value = "";
    return;
  }
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data || Array.isArray(data) || typeof data !== "object") {
      throw new Error("顶层必须是一个 JSON 对象");
    }
    loadDataset(data, file.name);
  } catch (error) {
    showInputError(`无法读取该文件：${friendlyError(error)}`);
    event.target.value = "";
  }
}

async function checkService() {
  try {
    const response = await fetch("/health", {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error("service unavailable");
    }
    elements["service-dot"].classList.add("is-online");
    elements["service-dot"].classList.remove("is-offline");
    elements["service-text"].textContent = "分析服务正常";
  } catch {
    elements["service-dot"].classList.remove("is-online");
    elements["service-dot"].classList.add("is-offline");
    elements["service-text"].textContent = "分析服务未连接";
  }
}

async function runAnalysis() {
  let payload;
  try {
    payload = JSON.parse(elements["json-editor"].value);
  } catch (error) {
    showInputError(`JSON 格式有误：${friendlyError(error)}`);
    return;
  }

  if (!payload || Array.isArray(payload) || typeof payload !== "object") {
    showInputError("数据最外层应为一个 JSON 对象。");
    return;
  }

  setRunning(true);
  hideResult();
  setRequestStatus("正在进行多源交叉核验，请稍候…", "running");

  try {
    const body = await requestJson(API_PATHS[state.mode], {
      method: "POST",
      body: JSON.stringify(payload),
    });

    state.currentInput = payload;
    state.lastResult = body;
    state.lastResultMode = state.mode;
    elements["dataset-summary"].textContent = describeDataset(payload);
    elements["dataset-state"].textContent = "分析完成";
    setRequestStatus("分析已完成，结果见下方");
    renderResult(body, state.mode);
  } catch (error) {
    showInputError(explainApiError(error));
  } finally {
    setRunning(false);
  }
}

async function readJsonResponse(response) {
  const text = await response.text();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("服务返回了无法识别的内容");
  }
}

function setRunning(isRunning) {
  state.isRunning = isRunning;
  elements["analyze-button"].disabled = isRunning;
  elements["production-tab"].disabled = isRunning;
  elements["personnel-tab"].disabled = isRunning;
  elements["load-risk-sample"].disabled = isRunning;
  elements["load-normal-sample"].disabled = isRunning;
  elements["upload-button"].disabled = isRunning;
  elements["file-input"].disabled = isRunning;
  elements["clear-analysis"].disabled =
    isRunning || !elements["json-editor"].value.trim();
  elements["analyze-button-text"].textContent = isRunning
    ? "正在分析…"
    : state.mode === "production"
      ? "开始交叉核验"
      : "开始人员核验";
  elements["analyze-button"].setAttribute("aria-busy", String(isRunning));
}

function hideResult() {
  elements["result-section"].hidden = true;
  elements["empty-state"].hidden = false;
}

function renderResult(result, mode) {
  elements["empty-state"].hidden = true;
  elements["result-section"].hidden = false;
  elements["result-title"].textContent =
    mode === "production" ? "产量数据核验结果" : "人员通行核验结果";
  elements["result-time"].textContent =
    `分析时间：${new Intl.DateTimeFormat("zh-CN", {
      dateStyle: "long",
      timeStyle: "medium",
    }).format(new Date())}`;
  elements["raw-output"].textContent = JSON.stringify(result, null, 2);

  if (mode === "production") {
    renderProductionResult(result);
  } else {
    renderPersonnelResult(result);
  }

  requestAnimationFrame(() => {
    elements["decision-banner"].focus({ preventScroll: true });
    elements["result-section"].scrollIntoView({
      behavior: prefersReducedMotion() ? "auto" : "smooth",
      block: "start",
    });
  });
}

function productionScenarioSummary(result) {
  const alternatives = arrayOrNull(result.mcs_alternatives) || [];
  const explicitlyPrioritized = alternatives.filter(
    (alternative) => alternative.minimum_priority === true,
  );
  const priorityAlternatives = explicitlyPrioritized.length
    ? explicitlyPrioritized
    : alternatives;
  const returnedPriorityCount = firstNumber(result.priority_scenario_count);
  const priorityCount =
    returnedPriorityCount !== null && returnedPriorityCount > 0
      ? returnedPriorityCount
      : priorityAlternatives.length;
  const unionCandidate = isFiniteRange(result.scenario_union_production_range)
    ? result.scenario_union_production_range
    : result.reasonable_production_range;
  const unionRange = isFiniteRange(unionCandidate) ? unionCandidate : null;
  const robustGap = firstNumber(
    result.robust_minimum_reported_gap,
    result.minimum_reported_gap,
  );
  const solverStatus = String(result.solver_status || "").toLowerCase();
  const gradeD = String(result.evidence_grade || "").toUpperCase() === "D";
  const notFound =
    result.status === "inconsistent" &&
    (!alternatives.length ||
      solverStatus.includes("mcs_not_found") ||
      solverStatus.includes("scenario_not_found"));
  const unbounded =
    result.status === "inconsistent" &&
    (solverStatus.includes("unbounded") ||
      alternatives.some(
        (alternative) =>
          Object.prototype.hasOwnProperty.call(
            alternative,
            "production_range_bounded",
          ) && alternative.production_range_bounded === false,
      ));
  const missingRange =
    result.status === "inconsistent" && unionRange === null;
  const rawClusters =
    arrayOrNull(result.independent_evidence_clusters) || [];
  const fallbackClusters = priorityAlternatives.flatMap(
    (alternative) =>
      arrayOrNull(alternative.independent_evidence_clusters) || [],
  );
  const clusterKeys = new Set();
  const independentClusters = (rawClusters.length
    ? rawClusters
    : fallbackClusters
  )
    .map((cluster) =>
      (arrayOrNull(cluster) || [])
        .map(nullableText)
        .filter((source) => source !== null),
    )
    .filter((cluster) => {
      if (!cluster.length) {
        return false;
      }
      const key = cluster.slice().sort().join("\u0000");
      if (clusterKeys.has(key)) {
        return false;
      }
      clusterKeys.add(key);
      return true;
    });
  return {
    alternatives,
    priorityAlternatives,
    priorityCount,
    unionRange,
    robustGap,
    divergent: Boolean(result.scenario_conclusion_divergent),
    independentClusters,
    gradeD,
    notFound,
    unbounded,
    evidenceInsufficient:
      ["inconclusive", "solver_error"].includes(result.status) ||
      gradeD ||
      notFound ||
      unbounded ||
      missingRange,
  };
}

function isFiniteRange(value) {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    isFiniteNumber(value[0]) &&
    isFiniteNumber(value[1]) &&
    value[0] <= value[1]
  );
}

function formatEvidenceClusters(clusters) {
  const values = (arrayOrNull(clusters) || [])
    .map((cluster, index) => {
      const sources = (arrayOrNull(cluster) || [])
        .map(sourceLabel)
        .filter(Boolean);
      return sources.length
        ? `簇 ${index + 1}：${sources.join(" + ")}`
        : null;
    })
    .filter(Boolean);
  return values.length ? values.join("；") : "未形成独立证据簇";
}

function renderProductionResult(result) {
  const scenario = productionScenarioSummary(result);
  const presentation = productionPresentation(result);
  setDecision(presentation);
  renderKpis(buildProductionKpis(result));
  renderList(elements["finding-list"], buildProductionFindings(result));
  renderList(
    elements["action-list"],
    result.recommended_checks && result.recommended_checks.length
      ? result.recommended_checks.map(humanizeRecommendedCheck)
      : defaultProductionActions(result.status, scenario.evidenceInsufficient),
  );
  renderProductionEvidence(result);
  renderMetricTable(result.reconciled_metrics || {});
  renderConflictTable(result.mcs_alternatives || [], result);
  renderAssumptions(result.assumptions || []);

  elements["metric-section"].hidden = false;
  elements["conflict-section"].hidden =
    result.status !== "inconsistent" &&
    (!result.mcs_alternatives || result.mcs_alternatives.length === 0);
  elements["personnel-detail-section"].hidden = true;
  elements["assumption-section"].hidden = false;
}

function productionPresentation(result) {
  const scenario = productionScenarioSummary(result);
  if (scenario.evidenceInsufficient) {
    return {
      tone: "neutral",
      symbol: "?",
      level: "证据不足",
      title: "当前不能形成技术差额结论",
      summary:
        "证据等级为 D、核查情景未找到或存在无界情景时，系统只保留待补数和待复核线索，不能据此判断合理产量、少报差额或责任。",
      priority: "补证复核",
    };
  }
  switch (result.status) {
    case "inconsistent":
      return {
        tone: "review",
        symbol: "!",
        level: "需人工复核",
        title: "发现跨来源技术冲突，建议核查",
        summary:
          "多类业务数据无法在现有容差内同时成立。系统给出了可恢复一致性的最小待核查来源组合，但不能据此直接认定责任。",
        priority: "较高",
      };
    case "consistent":
      return {
        tone: "success",
        symbol: "✓",
        level: "暂未发现技术冲突",
        title: "当前数据可协调",
        summary:
          "在当前数据范围、容差和模型假设下，各来源可以协调成立；这不等同于“无违规”，仍应按制度抽查并留存原始证据。",
        priority: "常规",
      };
    case "inconclusive":
      return {
        tone: "neutral",
        symbol: "?",
        level: "数据不足",
        title: "暂时无法形成判断",
        summary:
          "收到的数据质量或完整性不足，不能把本次结果理解为正常；缺失数据不得按零值处理，请补齐阻断项后重新分析。",
        priority: "补数",
      };
    default:
      return {
        tone: "neutral",
        symbol: "×",
        level: "分析未完成",
        title: "本次未形成有效结果",
        summary:
          "计算服务未能完成本次分析。请保留原始数据，并联系技术人员检查后重试。",
        priority: "技术处理",
      };
  }
}

function buildProductionKpis(result) {
  const scenario = productionScenarioSummary(result);
  const range = scenario.unionRange;
  const isUndetermined = scenario.evidenceInsufficient;
  const reportedMetric =
    result.reconciled_metrics &&
    result.reconciled_metrics["coal.reported_output_t"];
  const reportedValues =
    reportedMetric && Array.isArray(reportedMetric.observed_values)
      ? reportedMetric.observed_values
      : [];
  let reportedValue = reportedValues.find(isFiniteNumber);
  if (
    !isFiniteNumber(reportedValue) &&
    state.currentInput &&
    Array.isArray(state.currentInput.observations)
  ) {
    const reportedObservation = state.currentInput.observations.find(
      (observation) =>
        observation.metric_code === "coal.reported_output_t" &&
        isFiniteNumber(observation.value),
    );
    if (reportedObservation) {
      reportedValue = reportedObservation.value;
    }
  }
  const qualityScore =
    result.data_quality && isFiniteNumber(result.data_quality.score)
      ? `${formatNumber(result.data_quality.score, 1)} 分`
      : "未评分";
  const qualityStatus =
    result.data_quality && result.data_quality.status
      ? qualityStatusLabel(result.data_quality.status)
      : "未返回质量状态";
  const scenarioNote = scenario.divergent
    ? "不同情景结论有分歧，不能择一作定案"
    : scenario.priorityCount > 1
      ? "已对全部优先情景取保守结果"
      : "当前仅有一个优先情景";
  return [
    {
      label: "收到的上报产量",
      value: isFiniteNumber(reportedValue) ? formatTon(reportedValue) : "未收到",
      note: `数据质量 ${qualityScore} · ${qualityStatus}（仅反映可分析性）`,
      tone: isFiniteNumber(reportedValue) ? "" : "warning",
    },
    {
      label:
        result.status === "inconsistent"
          ? "多情景合理区间（并集）"
          : "合理产量参考区间",
      value:
        isUndetermined
          ? "证据不足"
          : isFiniteRange(range)
          ? `${formatTon(range[0])}–${formatTon(range[1])}`
          : "暂无法计算",
      note:
        result.status === "inconsistent"
          ? "覆盖全部优先核查情景，不只采用第一个情景"
          : "在现有证据和容差下的技术区间",
      tone: isUndetermined ? "warning" : "",
    },
    {
      label: "多情景稳健最小技术差额",
      value: isUndetermined
        ? "证据不足"
        : isFiniteNumber(scenario.robustGap)
          ? formatTon(scenario.robustGap)
          : "未计算",
      note:
        isUndetermined
          ? "缺失或无界结果不得按零值代入"
          : scenario.divergent
            ? "情景结论有分歧，不支持形成少报结论"
            : "取全部优先情景中的保守下界，仅为核查线索",
      tone:
        !isUndetermined &&
        isFiniteNumber(scenario.robustGap) &&
        scenario.robustGap > 0
          ? "review"
          : isUndetermined
            ? "warning"
            : "success",
    },
    {
      label:
        result.status === "inconsistent" ? "优先核查情景" : "独立证据簇",
      value: isUndetermined
        ? "未形成闭合情景"
        : result.status === "inconsistent"
          ? `${scenario.priorityCount} 个`
          : `${scenario.independentClusters.length} 簇`,
      note:
        isUndetermined
          ? `支撑等级 ${result.evidence_grade || "D"}：证据不足、不能下结论`
          : `${scenarioNote} · 独立证据 ${scenario.independentClusters.length} 簇 · 支撑等级 ${result.evidence_grade || "未评定"}（不是处罚等级）`,
      tone: isUndetermined
        ? "warning"
        : result.status === "inconsistent"
          ? "review"
          : "success",
    },
  ];
}

function buildProductionFindings(result) {
  const findings = [];
  const scenario = productionScenarioSummary(result);
  const range = scenario.unionRange;

  if (scenario.evidenceInsufficient) {
    findings.push(
      "证据不足、不能下结论：当前结果不得用于判断合理产量、少报差额、责任或处罚。",
    );
    if (scenario.gradeD) {
      findings.push("本次多源支撑等级为 D，尚不具备形成技术差额结论的证据条件。");
    }
    if (scenario.notFound) {
      findings.push(
        "在当前搜索范围内未找到可验证的最小待核查情景，应扩大核查范围或补齐来源后重新分析。",
      );
    }
    if (scenario.unbounded) {
      findings.push(
        "至少一个待核查情景的合理产量区间无界或不可计算，不能把缺失边界当成 0，也不能选取其他情景代替。",
      );
    }
    const reasons =
      result.data_quality && result.data_quality.blocking_reasons
        ? result.data_quality.blocking_reasons
        : [];
    reasons.slice(0, 3).forEach((reason) => {
      findings.push(`需补充或修正：${humanizeBlockingReason(reason)}`);
    });
    return findings;
  }

  if (result.status === "inconsistent") {
    findings.push(
      `共形成 ${scenario.priorityCount} 个优先核查情景、${scenario.alternatives.length} 个可展示情景；下方逐项列出，不以第一个情景代替其他可能性。`,
    );
    scenario.alternatives.forEach((alternative, index) => {
      const groups = (alternative.relaxed_source_groups || [])
        .map(sourceLabel)
        .join("、");
      const alternativeRange = alternative.reasonable_production_range;
      const rangeText = isFiniteRange(alternativeRange)
        ? `该情景合理区间 ${formatTon(alternativeRange[0])} 至 ${formatTon(alternativeRange[1])}`
        : "该情景未形成有界合理区间";
      const gapText = isFiniteNumber(alternative.minimum_reported_gap)
        ? `最小技术差额 ${formatTon(alternative.minimum_reported_gap)}`
        : "最小技术差额不可计算";
      findings.push(
        `情景 ${index + 1}：先复核“${groups || "来源未返回"}”；${rangeText}，${gapText}。`,
      );
    });
    if (scenario.divergent) {
      findings.push(
        "不同优先情景对技术差额的结论存在分歧，只能确认“多源数据需要复核”，不能据此认定存在少报或确定差额。",
      );
    }
    if (isFiniteRange(range)) {
      findings.push(
        `全部优先情景的合理产量并集为 ${formatTon(range[0])} 至 ${formatTon(range[1])}，该并集比单一情景更保守。`,
      );
    }
    if (
      isFiniteNumber(scenario.robustGap) &&
      result.all_priority_scenarios_support_positive_gap &&
      !scenario.divergent
    ) {
      findings.push(
        `全部优先情景共同支持的稳健最小技术差额约为 ${formatTon(scenario.robustGap)}；该数值仍只是核查线索，不是实际少报量认定。`,
      );
    } else {
      findings.push(
        "至少一个优先情景不支持正向差额，或情景结论存在分歧，因此不能形成“少报差额”结论。",
      );
    }
  } else if (result.status === "consistent") {
    findings.push("上报产量、主运输、入洗、销售和库存数据可在允许误差内同时成立。");
    if (isFiniteRange(range)) {
      findings.push(
        `当前条件下，产量合理参考区间约为 ${formatTon(range[0])} 至 ${formatTon(range[1])}。`,
      );
    }
    findings.push("“未发现冲突”不等于数据绝对真实，仍需按监管计划进行抽查。");
  } else if (result.status === "inconclusive") {
    const reasons =
      result.data_quality && result.data_quality.blocking_reasons
        ? result.data_quality.blocking_reasons
        : [];
    findings.push("本次没有形成一致或不一致结论，请勿按“正常”处理。");
    reasons.slice(0, 4).forEach((reason) => {
      findings.push(`需补充或修正：${humanizeBlockingReason(reason)}`);
    });
  } else {
    findings.push("系统未生成可用的计算结果，当前数据状态仍待人工判断。");
    findings.push("请转技术人员检查分析服务；领导端不据此形成监管结论。");
  }

  return findings.length ? findings : ["暂无可展示的核心判断。"];
}

function defaultProductionActions(status, evidenceInsufficient = false) {
  if (evidenceInsufficient) {
    return [
      "保全全部原始数据、签名、设备日志和修订记录，不依据本次结果作实体结论。",
      "按照证据不足原因补齐来源或扩大情景搜索范围，再重新分析并由人工复核。",
    ];
  }
  if (status === "consistent") {
    return [
      "保留本次数据及分析结果，纳入常规监管台账。",
      "按既定抽查比例核对原始表底、设备日志和业务凭证。",
    ];
  }
  if (status === "inconclusive") {
    return [
      "按照数据质量阻断原因补齐材料。",
      "确认各数据采用同一统计时段和吨位口径后重新分析。",
    ];
  }
  if (status === "inconsistent") {
    return [
      "保全本次原始数据和系统日志，逐一核对所有优先情景涉及的来源。",
      "比较各情景的原始表底、统计口径和修改记录，不选择单一情景直接定案。",
    ];
  }
  return [
    "保全本次原始数据和系统日志。",
    "联系技术人员检查分析服务后重新提交。",
  ];
}

function renderProductionEvidence(result) {
  const scenario = productionScenarioSummary(result);
  clearNode(elements["source-list"]);
  const suspect = new Set(
    scenario.alternatives.flatMap(
      (alternative) => alternative.relaxed_source_groups || [],
    ),
  );
  const supporting = [
    ...(result.supporting_source_groups || []),
    ...scenario.alternatives.flatMap(
      (alternative) => alternative.supporting_source_groups || [],
    ),
  ];
  const allGroups = [...new Set([...suspect, ...supporting])];

  if (scenario.evidenceInsufficient) {
    appendChip(
      elements["source-list"],
      `支撑等级 ${result.evidence_grade || "D"} · 证据不足`,
      false,
      true,
    );
  }
  if (!allGroups.length && !scenario.evidenceInsufficient) {
    appendChip(elements["source-list"], "暂无有效证据链", false, true);
  } else {
    allGroups.forEach((group) => {
      appendChip(elements["source-list"], sourceLabel(group), suspect.has(group));
    });
  }
  scenario.independentClusters.forEach((cluster, index) => {
    appendChip(
      elements["source-list"],
      `独立证据簇 ${index + 1}：${cluster.map(sourceLabel).join(" + ")}`,
      false,
      true,
    );
  });

  if (scenario.evidenceInsufficient) {
    elements["evidence-explanation"].textContent =
      "证据不足、不能下结论。D 级、未找到情景或无界情景均不得生成合理产量或技术差额结论；请先补证和复核。";
  } else if (suspect.size) {
    elements["evidence-explanation"].textContent =
      `橙色来源汇总了全部 ${scenario.alternatives.length} 个待核查情景，并不表示这些来源“错误”或“造假”。独立证据簇用于避免把同一上游数据重复计算为多份支撑。`;
  } else {
    elements["evidence-explanation"].textContent =
      "带对勾的来源参与了本次协调分析；独立证据簇会合并存在共同依赖的来源。“当前数据可协调”不等同于“无违规”。";
  }
}

function renderMetricTable(metrics) {
  clearNode(elements["metric-table-body"]);
  Object.entries(metrics).forEach(([code, metric]) => {
    const row = document.createElement("tr");
    addCell(row, METRIC_LABELS[code] || code);
    addCell(row, formatObservedValues(code, metric.observed_values));
    addCell(row, formatTon(metric.inferred_value));
    addCell(
      row,
      isFiniteNumber(metric.normalized_residual)
        ? `${formatNumber(metric.normalized_residual, 2)} 个容差`
        : "—",
    );
    elements["metric-table-body"].appendChild(row);
  });

  if (!Object.keys(metrics).length) {
    appendEmptyRow(elements["metric-table-body"], 4, "本次无指标明细");
  }
}

function renderConflictTable(alternatives, result) {
  clearNode(elements["conflict-table-body"]);
  if (!alternatives.length) {
    appendEmptyRow(
      elements["conflict-table-body"],
      7,
      result.status === "inconsistent"
        ? "未找到可验证的最小待核查情景；证据不足、不能下结论。"
        : "本次无需生成待核查情景。",
    );
    return;
  }
  let priorityIndex = 0;
  let supplementaryIndex = 0;
  const hasPriorityMarkers = alternatives.some((alternative) =>
    Object.prototype.hasOwnProperty.call(alternative, "minimum_priority"),
  );
  alternatives.forEach((alternative, index) => {
    const row = document.createElement("tr");
    const isPriority =
      alternative.minimum_priority === true || !hasPriorityMarkers;
    if (isPriority) {
      priorityIndex += 1;
    } else {
      supplementaryIndex += 1;
    }
    addCell(
      row,
      isPriority
        ? `优先情景 ${priorityIndex}`
        : `补充情景 ${supplementaryIndex || index + 1}`,
    );
    addCell(
      row,
      (alternative.relaxed_source_groups || []).map(sourceLabel).join("、") ||
        "—",
    );
    addCell(
      row,
      String(
        alternative.group_count === null ||
          typeof alternative.group_count === "undefined"
          ? "—"
          : alternative.group_count,
      ),
    );
    addCell(
      row,
      isFiniteNumber(alternative.total_reliability_cost)
        ? formatNumber(alternative.total_reliability_cost, 2)
        : "—",
    );
    const range = alternative.reasonable_production_range;
    addCell(
      row,
      isFiniteRange(range)
        ? `${formatTon(range[0])}–${formatTon(range[1])}`
        : alternative.production_range_bounded === false
          ? "无界/不可计算"
          : "未返回",
    );
    addCell(
      row,
      isFiniteNumber(alternative.minimum_reported_gap)
        ? `${formatTon(alternative.minimum_reported_gap)}${
            alternative.supports_positive_reported_gap === false
              ? "（不支持正差额）"
              : ""
          }`
        : "不可计算",
    );
    addCell(
      row,
      formatEvidenceClusters(
        alternative.independent_evidence_clusters || [],
      ),
    );
    elements["conflict-table-body"].appendChild(row);
  });
}

function renderPersonnelResult(result) {
  const mismatchCount = (result.matches || []).filter(
    (match) =>
      ["person_card_mismatch", "identity_conflict"].includes(match.status),
  ).length;
  const temporalPairCount = (result.matches || []).filter(
    (match) => match.status === "temporal_pair_only",
  ).length;
  const unidentifiedLegacyCount = (result.matches || []).filter(
    (match) =>
      match.face_person_id === null &&
      match.status !== "temporal_pair_only",
  ).length;
  const unmatchedFaceCount = (result.unmatched_face_tracks || []).length;
  const unmatchedCardCount = (result.unmatched_card_events || []).length;
  const returnedFindings = Array.isArray(result.findings)
    ? result.findings
    : [];
  const hasRisk =
    mismatchCount +
      temporalPairCount +
      unidentifiedLegacyCount +
      unmatchedFaceCount +
      unmatchedCardCount >
      0 || returnedFindings.length > 0;

  setDecision(
    hasRisk
      ? {
          tone: "review",
          symbol: "!",
          level: "发现待复核事项",
          title: "建议调阅视频和刷卡日志",
          summary:
            "存在身份信息不一致或人脸、定位卡记录未能对应的情况。系统结果用于缩小排查范围，不能单独确认身份或认定违规通行。",
          priority: "较高",
        }
      : {
          tone: "success",
          symbol: "✓",
          level: "暂未发现待复核事项",
          title: "当前人脸与定位卡事件可配对",
          summary:
            "在设定时间范围和匹配规则下，人脸与定位卡事件能够对应；这不代表已经确认实际身份，仍应按制度抽查原始视频。",
          priority: "常规",
        },
  );

  const totalFaces =
    state.currentInput && Array.isArray(state.currentInput.faces)
      ? state.currentInput.faces.length
      : (result.matches || []).length + unmatchedFaceCount;
  const totalCards =
    state.currentInput && Array.isArray(state.currentInput.cards)
      ? state.currentInput.cards.length
      : (result.matches || []).length + unmatchedCardCount;
  const pendingReviewCount =
    mismatchCount +
    temporalPairCount +
    unidentifiedLegacyCount +
    unmatchedFaceCount +
    unmatchedCardCount;
  renderKpis([
    {
      label: "接收通行数据",
      value: `${totalFaces} 人脸 / ${totalCards} 卡`,
      note: `场次 ${result.session_id || "未标识"} · 待复核事项 ${pendingReviewCount} 项`,
    },
    {
      label: "身份信息待复核",
      value: `${mismatchCount + temporalPairCount + unidentifiedLegacyCount} 条`,
      note: `身份冲突 ${mismatchCount} 条 · 仅时间关联 ${temporalPairCount + unidentifiedLegacyCount} 条`,
      tone:
        mismatchCount + temporalPairCount + unidentifiedLegacyCount
          ? "review"
          : "success",
    },
    {
      label: "有脸无卡",
      value: `${unmatchedFaceCount} 条`,
      note: "待复核：可能无卡通行或设备漏读",
      tone: unmatchedFaceCount ? "review" : "success",
    },
    {
      label: "有卡无人",
      value: `${unmatchedCardCount} 条`,
      note: "待复核：可能带卡未通行、摄像机漏检或遮挡",
      tone: unmatchedCardCount ? "review" : "success",
    },
  ]);

  const findings = returnedFindings.map(humanizePersonnelFinding);
  (result.matches || [])
    .filter((match) => match.status === "temporal_pair_only")
    .forEach((match) => {
      const trackId = match.face_track_id || "未标识";
      const alreadyExplained = findings.some(
        (finding) =>
          finding.includes("仅时间关联") && finding.includes(trackId),
      );
      if (!alreadyExplained) {
        findings.push(
          `仅时间关联，身份待确认：人脸轨迹 ${trackId} 与定位卡 ${match.card_id || "未标识"} 只因时间和方向接近而关联，不能计作身份确认匹配。`,
        );
      }
    });
  (result.matches || [])
    .filter(
      (match) =>
        match.face_person_id === null &&
        match.status !== "temporal_pair_only",
    )
    .forEach((match) => {
      findings.push(
        `事件已配对但身份未识别：人脸轨迹 ${match.face_track_id} 已与定位卡 ${match.card_id} 关联，仍需调阅视频确认人员身份。`,
      );
    });
  if (!findings.length) {
    findings.push("本场次未发现身份信息不一致、有脸无卡或有卡无人的情况。");
  }
  renderList(elements["finding-list"], findings);
  renderList(
    elements["action-list"],
    hasRisk
      ? [
          "锁定异常记录前后 2 分钟的井口原始视频，核对实际通行人员。",
          "核查相关定位卡的人员绑定、领用、挂失及刷卡记录。",
          "检查摄像头、读卡器时钟是否同步，排除设备漏拍或漏读。",
          "由安全管理人员复核后，将结论和证据归入监管台账。",
        ]
      : [
          "保留本场次匹配结果，纳入常规监管台账。",
          "按抽查制度复看部分原始视频，确认设备与系统运行正常。",
        ],
  );

  clearNode(elements["source-list"]);
  appendChip(elements["source-list"], "井口人脸记录", false);
  appendChip(elements["source-list"], "人员定位卡记录", false);
  appendChip(elements["source-list"], "人员与卡绑定信息", false);
  elements["evidence-explanation"].textContent =
    "系统按通行时间、方向和身份信息进行全局匹配；最终判断应回看原始视频和刷卡日志。";

  renderPersonnelTable(result.matches || []);
  renderAssumptions([
    "人脸候选身份来自上游识别系统，匹配概率不等同于身份认定。",
    "人卡匹配受设备时钟、通道拥挤、摄像头和读卡器状态影响。",
    "未匹配记录仅为核查线索，须结合原始视频和设备日志复核。",
  ]);

  elements["metric-section"].hidden = true;
  elements["conflict-section"].hidden = true;
  elements["personnel-detail-section"].hidden = false;
  elements["assumption-section"].hidden = false;
}

function renderPersonnelTable(matches) {
  clearNode(elements["personnel-table-body"]);
  matches.forEach((match) => {
    const row = document.createElement("tr");
    addCell(row, match.face_track_id || "—");
    addCell(row, match.face_person_id || "未识别");
    addCell(row, match.card_id || "—");
    addCell(row, match.card_person_id || "—");
    const statusCell = document.createElement("td");
    const badge = document.createElement("span");
    const isMismatch = ["person_card_mismatch", "identity_conflict"].includes(
      match.status,
    );
    const isTemporal =
      match.status === "temporal_pair_only" ||
      match.face_person_id === null;
    badge.className =
      `table-status ${isMismatch || isTemporal ? "is-review" : "is-success"}`;
    badge.textContent = isMismatch
      ? "身份冲突，待复核"
      : isTemporal
        ? "仅时间关联，身份待确认"
        : ["matched", "identity_confirmed"].includes(match.status)
          ? "身份确认匹配"
          : "匹配状态待复核";
    statusCell.appendChild(badge);
    row.appendChild(statusCell);
    elements["personnel-table-body"].appendChild(row);
  });

  if (!matches.length) {
    appendEmptyRow(elements["personnel-table-body"], 5, "本次无已匹配记录");
  }
}

function setDecision(presentation) {
  elements["decision-banner"].className =
    `decision-banner is-${presentation.tone}`;
  elements["decision-symbol"].textContent = presentation.symbol;
  elements["decision-level"].textContent = presentation.level;
  elements["decision-title"].textContent = presentation.title;
  elements["decision-summary"].textContent = presentation.summary;
  elements["priority-text"].textContent = presentation.priority;
}

function renderKpis(items) {
  clearNode(elements["kpi-grid"]);
  items.forEach((item) => {
    const card = document.createElement("article");
    card.className = "kpi-card";
    const label = document.createElement("p");
    label.className = "kpi-label";
    label.textContent = item.label;
    const value = document.createElement("strong");
    value.className = `kpi-value${item.tone ? ` is-${item.tone}` : ""}`;
    value.textContent = item.value;
    const note = document.createElement("span");
    note.className = "kpi-note";
    note.textContent = item.note;
    card.append(label, value, note);
    elements["kpi-grid"].appendChild(card);
  });
}

function renderList(container, values) {
  clearNode(container);
  values.forEach((value) => {
    const item = document.createElement("li");
    item.textContent = String(value);
    container.appendChild(item);
  });
}

function renderAssumptions(assumptions) {
  renderList(
    elements["assumption-list"],
    assumptions.length ? assumptions : ["本次未返回额外口径说明。"],
  );
}

function appendChip(container, label, isSuspect, isNeutral = false) {
  const chip = document.createElement("span");
  chip.className =
    `source-chip${isSuspect ? " is-suspect" : ""}${isNeutral ? " is-neutral" : ""}`;
  chip.textContent = label;
  container.appendChild(chip);
}

function addCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value);
  row.appendChild(cell);
}

function appendEmptyRow(container, columns, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.textContent = message;
  row.appendChild(cell);
  container.appendChild(row);
}

function clearNode(node) {
  node.replaceChildren();
}

function setLoadStatus(target, message, tone = "") {
  target.textContent = message;
  target.className =
    `data-load-status${tone ? ` is-${tone}` : ""}`;
}

function explainSupervisionError(error, subject) {
  if (error instanceof ApiError) {
    const apiError = error.body && error.body.error ? error.body.error : {};
    if (error.status === 401) {
      return `${subject}未读取：当前会话已失效，请重新登录。`;
    }
    if (error.status === 403) {
      return `${subject}未读取：当前账号没有相应权限，或目标不在授权矿山范围内。`;
    }
    if (error.status === 404) {
      return `${subject}接口尚未启用，可稍后重试；当前页面不会把接口缺失解释为“无事项”。`;
    }
    if (error.status === 409) {
      return `${subject}已发生版本变化，请刷新后重新确认。`;
    }
    if (error.status >= 500) {
      return `${subject}服务暂时不可用，请稍后重试。`;
    }
    return `${subject}读取未完成：${apiError.message || `服务返回 ${error.status}`}`;
  }
  if (error instanceof TypeError) {
    return `无法连接${subject}服务，请确认服务已启动后重试。`;
  }
  return `${subject}未完成：${friendlyError(error)}`;
}

function explainAccessError(error, subject) {
  if (error instanceof ApiError) {
    const apiError = error.body && error.body.error ? error.body.error : {};
    const code = apiError.code || "";
    if (error.status === 401) {
      return "当前会话已失效，请重新登录。";
    }
    if (error.status === 403) {
      return code === "csrf_invalid"
        ? `${subject}未提交：请求真实性校验失败，请重新登录后再试。`
        : `${subject}未完成：当前账号没有相应权限，或目标不在授权矿山范围内。`;
    }
    if (error.status === 409) {
      if (code === "version_conflict") {
        return `${subject}未完成：数据版本已变化，请刷新后重新确认。`;
      }
      if (code === "double_review_required") {
        return `${subject}未完成：必须由一人提交结论，再由另一名监管负责人审批。`;
      }
      if (code === "user_conflict") {
        return `${subject}未完成：用户名已存在或账号设置不符合要求。`;
      }
      return `${subject}与当前状态冲突，请刷新后重新确认。`;
    }
    if (error.status === 429) {
      return `${subject}请求过于频繁，请稍后再试。`;
    }
    if (error.status >= 500) {
      return `${subject}服务暂时不可用，请稍后重试。`;
    }
    return `${subject}未完成：${apiError.message || `服务返回 ${error.status}`}`;
  }
  if (error instanceof TypeError) {
    return `无法连接${subject}服务，请检查内网连接后重试。`;
  }
  return `${subject}未完成：${friendlyError(error)}`;
}

function pickFirst(object, ...paths) {
  for (const path of paths) {
    const value = readPath(object, path);
    if (typeof value !== "undefined" && value !== null) {
      return value;
    }
  }
  return undefined;
}

function readPath(object, path) {
  if (!object || typeof object !== "object") {
    return undefined;
  }
  const parts = String(path).split(".");
  let current = object;
  for (const part of parts) {
    if (
      !current ||
      typeof current !== "object" ||
      !Object.prototype.hasOwnProperty.call(current, part)
    ) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

function pickAcross(objects, ...paths) {
  for (const object of objects) {
    const value = pickFirst(object, ...paths);
    if (typeof value !== "undefined" && value !== null) {
      return value;
    }
  }
  return undefined;
}

function objectOrNull(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function arrayOrNull(value) {
  return Array.isArray(value) ? value : null;
}

function firstNumber(...values) {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
    if (
      typeof value === "string" &&
      value.trim() &&
      Number.isFinite(Number(value))
    ) {
      return Number(value);
    }
  }
  return null;
}

function booleanOrNull(value) {
  if (value === true || value === false) {
    return value;
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  return null;
}

function nullableText(value) {
  if (typeof value === "undefined" || value === null) {
    return null;
  }
  const text = String(value).trim();
  return text ? text : null;
}

function displayText(value, fallback = "—") {
  const text = nullableText(value);
  return text === null ? fallback : text;
}

function normalizeRatio(value) {
  if (value === null || typeof value === "undefined") {
    return null;
  }
  const numeric = firstNumber(value);
  if (numeric === null || numeric < 0) {
    return null;
  }
  const ratio = numeric > 1 && numeric <= 100 ? numeric / 100 : numeric;
  return Math.max(0, Math.min(ratio, 1));
}

function countStatuses(items, statuses) {
  return items.filter((item) => statuses.includes(item.technicalStatus)).length;
}

function normalizeTechnicalStatus(value) {
  const status = String(value || "unknown")
    .trim()
    .toLowerCase()
    .split("-")
    .join("_");
  const aliases = {
    conflict: "inconsistent",
    technical_inconsistent: "inconsistent",
    data_insufficient: "inconclusive",
    insufficient: "inconclusive",
    blocked: "inconclusive",
    not_received: "missing",
    late_missing: "missing",
    absent: "missing",
    error: "solver_error",
    failed: "solver_error",
    coordinated: "consistent",
  };
  return aliases[status] || status;
}

function normalizePriority(value) {
  if (typeof value === "undefined" || value === null || value === "") {
    return null;
  }
  const priority = String(value)
    .trim()
    .toLowerCase()
    .split("-")
    .join("_");
  const aliases = {
    critical: "urgent",
    p0: "urgent",
    red: "urgent",
    p1: "urgent",
    p2: "high",
    medium: "high",
    review: "high",
    low: "normal",
    routine: "normal",
    none: "normal",
    data: "supplement",
    data_supplement: "supplement",
    missing: "supplement",
  };
  return aliases[priority] || priority;
}

function inferPriority(technicalStatus) {
  if (technicalStatus === "inconsistent") {
    return "high";
  }
  if (
    ["missing", "inconclusive", "solver_error"].includes(technicalStatus)
  ) {
    return "supplement";
  }
  return "normal";
}

function normalizeWorkflowStatus(value) {
  const status = String(value || "unknown")
    .trim()
    .toLowerCase()
    .split("-")
    .join("_");
  const aliases = {
    open: "new",
    pending: "new",
    unread: "new",
    accepted: "acknowledged",
    assigned_review: "assigned",
    request_supplement: "supplement_requested",
    supplement: "supplement_requested",
    in_review: "reviewing",
    under_review: "reviewing",
    waiting_data: "supplement_requested",
    complete: "resolved",
    completed: "resolved",
    reopened: "reopened",
  };
  return aliases[status] || status;
}

function defaultTechnicalSummary(status) {
  const summaries = {
    inconsistent: "多源数据暂不能在现有容差内同时成立，建议人工复核。",
    inconclusive: "当前数据不足，需补齐阻断项后重新形成技术判断。",
    missing: "预期数据尚未收到；缺报不按零值处理。",
    consistent: "当前收到的数据在现有容差和模型假设下可以协调。",
    solver_error: "本次技术分析未完成，需保留原始数据并检查后重试。",
  };
  return summaries[status] || "技术状态待确认，请结合原始材料人工复核。";
}

function statusBadgeSpec(value, type) {
  const priorityLabels = {
    urgent: "优先复核",
    high: "一般复核",
    supplement: "补数优先",
    normal: "常规",
    unknown: "优先级待定",
  };
  const technicalLabels = {
    inconsistent: "技术不一致",
    inconclusive: "数据不足",
    missing: "缺报",
    consistent: "当前可协调",
    solver_error: "分析未完成",
    unknown: "技术状态待定",
  };
  const workflowLabels = {
    new: "待办理",
    acknowledged: "已阅",
    assigned: "已交办",
    supplement_requested: "待补数",
    reviewing: "核查中",
    pending_approval: "待另一人审批",
    resolved: "已复核",
    closed: "已关闭",
    reopened: "已重新打开",
    unknown: "办理状态待定",
  };
  const labels =
    type === "priority"
      ? priorityLabels
      : type === "technical"
        ? technicalLabels
        : workflowLabels;
  const normalized = value || "unknown";
  return {
    label: labels[normalized] || displayText(normalized, "待确认"),
    tone: String(normalized).split("_").join("-"),
  };
}

function createStatusBadge(value, type) {
  const spec = statusBadgeSpec(value, type);
  const badge = document.createElement("span");
  badge.className = `status-badge is-${spec.tone}`;
  badge.textContent = spec.label;
  return badge;
}

function setExistingBadge(element, value, type) {
  const spec = statusBadgeSpec(value, type);
  element.className = `status-badge is-${spec.tone}`;
  element.textContent = spec.label;
}

function appendPrimarySecondary(cell, primaryText, secondaryText) {
  const primary = document.createElement("span");
  primary.className = "table-primary";
  primary.textContent = displayText(primaryText);
  cell.appendChild(primary);
  if (secondaryText) {
    const secondary = document.createElement("span");
    secondary.className = "table-secondary";
    secondary.textContent = secondaryText;
    cell.appendChild(secondary);
  }
}

function updateOpenCaseCount(count) {
  const badge = elements["nav-open-case-count"];
  if (count === null || count <= 0) {
    badge.hidden = true;
    badge.textContent = "";
    return;
  }
  badge.hidden = false;
  badge.textContent = count > 99 ? "99+" : String(count);
  badge.setAttribute("aria-label", `${count} 项开放事项`);
}

function formatCount(value) {
  return value === null ? "未返回" : formatNumber(value);
}

function formatPercent(value) {
  return value === null
    ? "未返回"
    : new Intl.NumberFormat("zh-CN", {
        style: "percent",
        maximumFractionDigits: 1,
      }).format(value);
}

function formatDateTime(value) {
  if (!value) {
    return "未返回";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return String(value);
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatPeriod(start, end) {
  const startText = formatDateOnly(start);
  const endText = formatDateOnly(end);
  if (startText && endText) {
    return startText === endText ? startText : `${startText} 至 ${endText}`;
  }
  return startText || endText || "分析期间未返回";
}

function eventTypeLabel(value) {
  const eventType = String(value || "event")
    .trim()
    .toLowerCase()
    .split("-")
    .join("_");
  const labels = {
    created: "形成待复核事项",
    acknowledge: "标记已阅",
    acknowledged: "标记已阅",
    assign: "交办核查",
    assigned: "已交办",
    request_supplement: "要求补充数据",
    request_data: "要求补充数据",
    supplement_requested: "要求补充数据",
    start_review: "开始人工复核",
    reviewing: "开始人工复核",
    resolve: "记录复核结论",
    resolved: "已记录复核结论",
    submit_conclusion: "提交人工复核结论",
    approve: "批准人工复核结论",
    reject: "退回人工复核结论",
    withdraw_conclusion: "撤回本人提交的结论",
    close: "关闭事项",
    closed: "关闭事项",
    reopen: "重新打开事项",
    reopened: "重新打开事项",
    archive_case: "归档关闭事项",
    restore_case: "恢复归档事项",
    note: "补充办理说明",
    add_note: "补充办理说明",
  };
  return labels[eventType] || "办理记录";
}

function safeEvidenceUrl(value) {
  const text = nullableText(value);
  if (!text) {
    return null;
  }
  try {
    const url = new URL(text, window.location.origin);
    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }
    return url.href;
  } catch {
    return null;
  }
}

function sourceLabel(source) {
  return SOURCE_LABELS[source] || source;
}

function qualityStatusLabel(status) {
  return (
    {
      sufficient: "质量满足分析要求",
      degraded: "质量下降，请谨慎使用",
      blocked: "质量不足，已阻断判断",
    }[status] || status
  );
}

function humanizeBlockingReason(reason) {
  const text = String(reason);
  const missingPrefix = "missing_required_metric: ";
  if (text.startsWith(missingPrefix)) {
    const metricCode = text.slice(missingPrefix.length);
    return `缺少必需指标“${METRIC_LABELS[metricCode] || metricCode}”，缺失值不得按 0 处理`;
  }
  const separator = text.indexOf(": ");
  if (separator > 0) {
    const observationId = text.slice(0, separator);
    const flag = text.slice(separator + 2);
    if (flag === "signature_invalid") {
      return `记录 ${observationId} 的数字签名无效`;
    }
    return BLOCKING_FLAG_LABELS[flag]
      ? `记录 ${observationId}：${BLOCKING_FLAG_LABELS[flag]}`
      : `记录 ${observationId} 存在数据质量阻断项，需联系数据管理员核实`;
  }
  return text;
}

function humanizeRecommendedCheck(check) {
  let text = String(check);
  Object.entries(SOURCE_LABELS).forEach(([code, label]) => {
    text = text.split(code).join(`“${label}”`);
  });
  return text;
}

function humanizePersonnelFinding(finding) {
  return String(finding)
    .split("疑似带卡不入井或摄像机漏检")
    .join("可能带卡未通行、摄像机漏检或遮挡")
    .split(" 为 entry")
    .join(" 为“入井”")
    .split(" 为 exit")
    .join(" 为“出井”");
}

function formatNumber(value, digits = 0) {
  if (!isFiniteNumber(value)) {
    return "—";
  }
  return new Intl.NumberFormat("zh-CN", {
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  }).format(value);
}

function shortHash(value) {
  const text = nullableText(value);
  if (!text) {
    return "未返回";
  }
  return text.length > 18
    ? `${text.slice(0, 10)}…${text.slice(-6)}`
    : text;
}

function formatTon(value) {
  return isFiniteNumber(value) ? `${formatNumber(value, 1)} 吨` : "—";
}

function formatObservedValues(metricCode, values) {
  if (!Array.isArray(values) || values.length === 0) {
    return "— 数据缺失";
  }
  return values
    .map((value) => {
      if (!isFiniteNumber(value)) {
        return "— 数据无效";
      }
      if (value === 0) {
        return `${formatTon(value)}（来源已明确上报零值）`;
      }
      return formatTon(value);
    })
    .join("、");
}

function formatDateOnly(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return "";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

function isFiniteNumber(value) {
  return typeof value === "number" && Number.isFinite(value);
}

function setRequestStatus(message, type = "") {
  elements["request-status"].textContent = message;
  elements["request-status"].className =
    `request-status${type ? ` is-${type}` : ""}`;
}

function showInputError(message) {
  setRequestStatus(message, "error");
}

function friendlyError(error) {
  return error instanceof Error ? error.message : String(error);
}

class ApiError extends Error {
  constructor(status, body) {
    super("API request failed");
    this.status = status;
    this.body = body;
  }
}

function explainApiError(error) {
  if (error instanceof ApiError) {
    const apiError = error.body && error.body.error ? error.body.error : {};
    if (apiError.code === "validation_error") {
      const details = Array.isArray(apiError.details) ? apiError.details : [];
      if (details.length) {
        const detail = details[0];
        const location = translateLocation(detail.loc || []);
        return `数据校验未通过：${location}${translateValidationMessage(detail.msg)}`;
      }
      return "数据校验未通过，请展开原始数据检查必填项和格式。";
    }
    if (error.status === 413) {
      return "数据文件过大，请缩小分析时间范围后重试。";
    }
    if (error.status === 401) {
      return "当前会话已失效，请重新登录后再分析。";
    }
    if (error.status === 403) {
      return apiError.code === "csrf_invalid"
        ? "请求真实性校验失败，请重新登录后再分析。"
        : "当前账号没有直接分析权限，或该矿山不在授权范围内；请使用受控分析任务或联系管理员。";
    }
    if (error.status === 409) {
      return "分析请求与当前版本或任务状态冲突，请刷新后重新确认。";
    }
    if (error.status >= 500) {
      return "分析服务暂时未能完成计算。原始数据已保留，请稍后重试或联系技术人员。";
    }
    return `请求未被接受：${apiError.message || `服务返回 ${error.status}`}`;
  }
  if (error instanceof TypeError) {
    return "无法连接分析服务，请确认服务已启动后重试。";
  }
  return `分析未完成：${friendlyError(error)}`;
}

function translateLocation(location) {
  if (!location.length) {
    return "";
  }
  const fieldLabels = {
    mine_id: "矿井编号",
    window_start: "分析开始时间",
    window_end: "分析结束时间",
    observations: "观测数据",
    metric_code: "指标代码",
    value: "指标数值",
    tolerance_abs: "允许误差",
    source_group: "数据来源组",
    session_id: "通行场次编号",
    faces: "人脸记录",
    cards: "定位卡记录",
    event_time: "事件时间",
  };
  const parts = location.map((part) => {
    if (typeof part === "number") {
      return `第 ${part + 1} 条`;
    }
    return fieldLabels[part] || String(part);
  });
  return `${parts.join(" → ")}：`;
}

function translateValidationMessage(message) {
  const text = String(message || "");
  if (text.includes("Field required")) {
    return "缺少必填内容";
  }
  if (text.includes("valid datetime")) {
    return "时间格式不正确，且必须包含时区";
  }
  if (text.includes("greater than")) {
    return "数值超出允许范围";
  }
  if (text.includes("Extra inputs")) {
    return "包含系统不认识的字段";
  }
  return text || "内容不符合接口要求";
}

function downloadResult() {
  if (!state.lastResult) {
    return;
  }
  const blob = new Blob([JSON.stringify(state.lastResult, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  const identifier =
    state.lastResultMode === "production"
      ? state.lastResult.mine_id || "production"
      : state.lastResult.session_id || "personnel";
  anchor.href = url;
  anchor.download = `mineguard-${identifier}-${fileTimestamp()}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function fileTimestamp() {
  const date = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}`;
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
