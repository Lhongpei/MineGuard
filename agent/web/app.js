(() => {
  "use strict";

  /*
   * The enterprise agent and the supervision platform are intentionally
   * independent. All integration is kept behind this small HTTP contract.
   * Do not import platform code or place model credentials in the browser.
   */
  const API_ROOT = "/api/v1";
  const endpoints = Object.freeze({
    health: () => "/health",
    platformStatus: () => "/platform-status",
    login: () => "/auth/login",
    me: () => "/auth/me",
    logout: () => "/auth/logout",
    drafts: () => "/drafts",
    draftList: (limit = 50, offset = 0) =>
      `/drafts?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
    draft: (draftId) => `/drafts/${encodeURIComponent(draftId)}`,
    importSource: (draftId) => `/drafts/${encodeURIComponent(draftId)}/import`,
    assist: (draftId) => `/drafts/${encodeURIComponent(draftId)}/assist`,
    questions: (draftId) => `/drafts/${encodeURIComponent(draftId)}/questions`,
    reviews: (draftId) => `/drafts/${encodeURIComponent(draftId)}/reviews`,
    eventSnapshot: (draftId) =>
      `/drafts/${encodeURIComponent(draftId)}/event-snapshot`,
    validate: (draftId) => `/drafts/${encodeURIComponent(draftId)}/validate`,
    confirm: (draftId) => `/drafts/${encodeURIComponent(draftId)}/confirm`,
    submit: (draftId) => `/drafts/${encodeURIComponent(draftId)}/submit`,
    audit: (draftId) => `/drafts/${encodeURIComponent(draftId)}/audit`,
    submissions: (draftId) => `/drafts/${encodeURIComponent(draftId)}/submissions`,
    agentTools: () => "/agent/tools",
    agentRuns: (limit = 20, offset = 0) =>
      `/agent/runs?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
    agentRunsCreate: () => "/agent/runs",
    agentRun: (runId) => `/agent/runs/${encodeURIComponent(runId)}`,
    agentRunCancel: (runId) =>
      `/agent/runs/${encodeURIComponent(runId)}/cancel`,
    agentRunApprove: (runId) =>
      `/agent/runs/${encodeURIComponent(runId)}/approve`,
    agentFlows: () => "/agent/flows",
    agentFlow: (flowId) => `/agent/flows/${encodeURIComponent(flowId)}`,
    agentFlowCancel: (flowId) =>
      `/agent/flows/${encodeURIComponent(flowId)}/cancel`,
    agentFlowRetry: (flowId) =>
      `/agent/flows/${encodeURIComponent(flowId)}/retry`,
    agentJobs: () => "/agent/jobs",
    agentJob: (jobId) => `/agent/jobs/${encodeURIComponent(jobId)}`,
    agentJobRun: (jobId) =>
      `/agent/jobs/${encodeURIComponent(jobId)}/run`,
    agentMemoryProposals: () => "/agent/memory/proposals",
    agentMemoryProposalDecision: (proposalId) =>
      `/agent/memory/proposals/${encodeURIComponent(proposalId)}/decision`,
    agentMemories: () => "/agent/memories",
    agentSkillProposals: () => "/agent/skill-proposals",
    agentSkillProposalDecision: (proposalId) =>
      `/agent/skill-proposals/${encodeURIComponent(proposalId)}/decision`,
    agentSkillVersions: () => "/agent/skill-versions",
    chatSessions: (limit = 30, offset = 0) =>
      `/chat/sessions?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
    chatSessionsCreate: () => "/chat/sessions",
    chatSession: (sessionId) =>
      `/chat/sessions/${encodeURIComponent(sessionId)}`,
    chatMessages: (sessionId) =>
      `/chat/sessions/${encodeURIComponent(sessionId)}/messages`,
  });

  const defaultCoalHealthTask =
    "对当前企业草稿执行全面煤炭数据体检：检查字段完整性、煤量平衡、库存与产销关系、来源可追溯性、历史对比和异常风险；展示模型工具规划和来源已绑定的确定性工具证据。不得人工确认或提交监管平台。";

  const agentTaskPresets = Object.freeze({
    full: defaultCoalHealthTask,
    explain:
      "解释当前草稿中发现的异常、警告和数据差异：用非技术语言说明触发原因、影响范围、计算依据和所绑定的原始凭证；区分模型判断、确定性复算和未核实输入，不得人工确认或提交监管平台。",
    history:
      "分析当前草稿的历史趋势：只使用与当前矿井、指标、统计口径和工况兼容的成功历史记录，说明基线、漂移和变化点；明确历史样本不足或不可比之处，不得把相关性写成因果，不得人工确认或提交监管平台。",
    source:
      "核验当前草稿的数据来源：逐项检查观测值、材料位置、载荷摘要和签名格式是否绑定一致，列出缺失、冲突或只能复算但不能证明来源的项目；不得把格式正确写成来源真实，不得人工确认或提交监管平台。",
  });

  const agentToolCategoryPresentation = Object.freeze({
    draft_governance: { label: "草稿与治理", order: 10 },
    source_evidence: { label: "来源与凭证", order: 20 },
    temporal_quality: { label: "时间与采集质量", order: 30 },
    source_consistency: { label: "指标时序对比", order: 40 },
    physical_reconciliation: { label: "产运销存复算", order: 50 },
    inventory_analysis: { label: "库存分析", order: 60 },
    unit_conversion: { label: "单位换算", order: 70 },
    coal_quality_scenario: { label: "煤质情景复算", order: 80 },
    coal_blending_scenario: { label: "配煤情景复算", order: 90 },
    historical_analysis: { label: "历史与趋势", order: 100 },
    cross_validation: { label: "综合核对", order: 110 },
    audit_governance: { label: "审计与留痕", order: 120 },
    submission_audit: { label: "报送记录审计", order: 130 },
    observation_review: { label: "人工复核记录", order: 140 },
    provenance: { label: "来源链路", order: 25 },
    draft_editing: { label: "草稿修改", order: 900 },
    general: { label: "其他工具", order: 800 },
  });

  const agentToolPresentation = Object.freeze({
    draft_summary: { label: "草稿指标摘要", category: "draft_governance" },
    deterministic_preflight: {
      label: "确定性提交前预检",
      category: "draft_governance",
    },
    source_evidence_check: {
      label: "来源摘要与凭证检查",
      category: "source_evidence",
    },
    align_observation_time: {
      label: "观测时间对齐",
      category: "temporal_quality",
    },
    convert_coal_units: { label: "煤炭单位换算", category: "unit_conversion" },
    calculate_mass_balance: {
      label: "质量平衡情景复算",
      category: "physical_reconciliation",
    },
    calculate_coal_flow_balance: {
      label: "产运销存煤流平衡",
      category: "physical_reconciliation",
    },
    calculate_washing_yield: {
      label: "洗选产率情景复算",
      category: "physical_reconciliation",
    },
    build_historical_baseline: {
      label: "历史稳健基线",
      category: "historical_analysis",
    },
    detect_sensor_drift: {
      label: "传感器漂移候选",
      category: "historical_analysis",
    },
    detect_change_point: {
      label: "时序变化点候选",
      category: "historical_analysis",
    },
    explain_cross_validation: {
      label: "多维交叉核对说明",
      category: "cross_validation",
    },
    convert_coal_quality_basis: {
      label: "煤质基准换算",
      category: "coal_quality_scenario",
    },
    evaluate_coal_blend: {
      label: "配煤场景加权试算",
      category: "coal_blending_scenario",
    },
    calculate_inventory_coverage: {
      label: "库存静态覆盖天数",
      category: "inventory_analysis",
    },
    compare_metric_series: {
      label: "双指标时序对比",
      category: "source_consistency",
    },
    analyze_historical_trend: {
      label: "历史稳健趋势",
      category: "historical_analysis",
    },
    inspect_observation_continuity: {
      label: "观测序列连续性检查",
      category: "temporal_quality",
    },
    compare_source_consistency: {
      label: "数据来源一致性核对",
      category: "source_consistency",
    },
    summarize_provenance_lineage: {
      label: "数据来源链路摘要",
      category: "provenance",
    },
    draft_patch: { label: "草稿字段补丁", category: "draft_editing" },
  });

  const agentToolResultFieldPlans = Object.freeze({
    convert_coal_quality_basis: [
      "property_code",
      "input_value_percent",
      "from_basis",
      "to_basis",
      "converted_value_percent",
      "conversion_factor",
      "input_consistency_checked",
    ],
    evaluate_coal_blend: [
      "quality_basis",
      "component_count",
      "total_mass_t",
      "overall_constraint_status",
    ],
    calculate_inventory_coverage: [
      "status",
      "outflow_metric_code",
      "reporting_window_days",
      "closing_inventory_t",
      "average_daily_outflow_t",
      "coverage_days",
    ],
    compare_metric_series: [
      "status",
      "left_metric_code",
      "right_metric_code",
      "comparison_unit",
      "tolerance_seconds",
      "relative_tolerance",
      "matched_pair_count",
      "left_unmatched_count",
      "right_unmatched_count",
      "outside_tolerance_count",
      "median_signed_gap",
      "p95_absolute_relative_gap",
    ],
    analyze_historical_trend: [
      "status",
      "metric_code",
      "normalization",
      "unit",
      "history_sample_size",
      "current_value",
      "level_median",
      "theil_sen_slope_per_day",
      "slope_scaled_change_30d",
      "relative_slope_scaled_change_30d",
      "direction",
    ],
    inspect_observation_continuity: [
      "status",
      "reason",
      "selected_observation_count",
      "excluded_observation_count",
      "evaluated_series_count",
      "not_evaluated_series_count",
      "series_count",
      "returned_series_count",
      "series_truncated",
      "thresholds",
    ],
    compare_source_consistency: [
      "status",
      "reason",
      "metric_code",
      "time_tolerance_seconds",
      "time_tolerance_origin",
      "selected_source_count",
      "available_source_count",
      "excluded_observation_count",
      "source_count",
      "pair_count",
      "evaluated_pair_count",
      "not_evaluated_pair_count",
    ],
    summarize_provenance_lineage: [
      "status",
      "reason",
      "selected_observation_count",
      "invalid_observation_count",
      "lineage_record_count",
      "evaluated_lineage_count",
      "partial_lineage_count",
      "not_evaluated_lineage_count",
      "manifest_entry_count",
      "valid_manifest_entry_count",
      "invalid_manifest_entry_count",
    ],
  });

  const agentResultFieldLabels = Object.freeze({
    draft_id: "草稿编号",
    revision: "草稿修订号",
    status: "评价状态",
    metric_code: "指标编码",
    property_code: "煤质指标",
    input_value_percent: "输入值",
    from_basis: "原基准",
    to_basis: "目标基准",
    converted_value_percent: "换算结果",
    conversion_factor: "换算系数",
    input_consistency_checked: "输入一致性已核对",
    quality_basis: "煤质基准",
    component_count: "配煤组分数",
    total_mass_t: "总质量",
    overall_constraint_status: "约束评价",
    outflow_metric_code: "出库指标",
    reporting_window_days: "统计窗口",
    closing_inventory_t: "期末库存",
    average_daily_outflow_t: "日均出库量",
    coverage_days: "静态覆盖天数",
    left_metric_code: "左侧指标",
    right_metric_code: "右侧指标",
    comparison_unit: "对比单位",
    tolerance_seconds: "时间容差",
    relative_tolerance: "相对差容差",
    left_point_count: "左侧点数",
    right_point_count: "右侧点数",
    matched_pair_count: "成功配对数",
    left_unmatched_count: "左侧未配对",
    right_unmatched_count: "右侧未配对",
    outside_tolerance_count: "超出容差数",
    median_signed_gap: "差额中位数",
    median_absolute_relative_gap: "绝对相对差中位数",
    p95_absolute_relative_gap: "绝对相对差 P95",
    normalization: "归一方式",
    unit: "单位",
    history_sample_size: "历史样本数",
    minimum_history: "最低历史样本数",
    current_value: "当前值",
    level_median: "历史水平中位数",
    theil_sen_slope_per_day: "每日稳健斜率",
    projected_linear_change_30d: "30 天线性变化尺度",
    relative_linear_change_30d: "30 天相对变化尺度",
    slope_scaled_change_30d: "30 天斜率尺度变化",
    relative_slope_scaled_change_30d: "30 天相对斜率尺度变化",
    direction: "趋势方向",
    series_count: "序列数",
    coverage: "覆盖情况",
    gap_count: "缺口数",
    duplicate_count: "重复点数",
    metric_count: "指标数",
    consistent_metric_count: "一致指标数",
    conflict_count: "冲突数",
    tolerance: "判定容差",
    import_count: "导入批次数",
    field_count: "字段数",
    evidence_digest: "证据摘要",
    selected_observation_count: "选中观测数",
    excluded_observation_count: "排除观测数",
    evaluated_series_count: "已评价序列数",
    not_evaluated_series_count: "未评价序列数",
    returned_series_count: "返回序列数",
    series_truncated: "序列明细已截断",
    thresholds: "检查阈值",
    time_tolerance_seconds: "时间容差",
    time_tolerance_origin: "时间容差来源",
    selected_source_count: "选中来源数",
    available_source_count: "可用来源数",
    source_count: "来源摘要数",
    pair_count: "来源对数",
    evaluated_pair_count: "已评价来源对",
    not_evaluated_pair_count: "未评价来源对",
    invalid_observation_count: "无效观测数",
    lineage_record_count: "来源链记录数",
    evaluated_lineage_count: "完整来源链数",
    partial_lineage_count: "部分来源链数",
    not_evaluated_lineage_count: "未评价来源链数",
    manifest_entry_count: "导入清单项数",
    valid_manifest_entry_count: "有效清单项数",
    invalid_manifest_entry_count: "无效清单项数",
    blocking_count: "阻断项",
    warning_count: "警告项",
    observation_count: "观测总数",
    sample_size: "样本数",
    point_count: "点数",
    event_count: "事件数",
    submission_count: "报送记录数",
    reviewed_count: "已复核观测",
    unreviewed_count: "待复核观测",
    total: "总数",
    valid: "完整性有效",
    integrity_valid: "审计完整性有效",
    head_hash: "链头摘要",
    document_sha256: "草稿摘要",
  });

  const state = {
    interfaceMode: "simple",
    drafts: [],
    activeDraft: null,
    step: 1,
    filter: "all",
    search: "",
    importFormat: "json",
    importPurpose: "source",
    undoStack: [],
    undoBytes: 0,
    dirtyWireFields: new Set(),
    fieldFocusSnapshot: null,
    measurementPage: 1,
    measurementPageSize: 50,
    saveTimer: null,
    savePromise: null,
    loading: false,
    draftsLoaded: false,
    draftLoadError: "",
    draftTotal: 0,
    draftNextOffset: 0,
    draftHasMore: false,
    selectedFile: null,
    lastAssistContent: "",
    lastAssistFormat: "text",
    assistantSource: null,
    suggestions: [],
    principal: null,
    csrfToken: "",
    sessionGeneration: 0,
    serviceHealth: null,
    platformStatus: null,
    reviewState: null,
    reviewLoading: false,
    activeOperation: "",
    submitAttempt: null,
    sessionRecovery: null,
    agent: {
      tools: [],
      toolsLoaded: false,
      toolsLoading: false,
      toolsError: "",
      runs: [],
      total: 0,
      nextOffset: 0,
      hasMore: false,
      selectedRunId: "",
      detail: null,
      creating: false,
      listLoading: false,
      detailLoading: false,
      listError: "",
      detailError: "",
      pollTimer: null,
      pollStartedAt: 0,
      pollFailures: 0,
      requestSequence: 0,
    },
    agentV2: {
      selectedTab: "overview",
      flows: [],
      selectedFlowId: "",
      detail: null,
      jobs: [],
      memoryProposals: [],
      memories: [],
      skillProposals: [],
      skillVersions: [],
      flowsLoaded: false,
      jobsLoaded: false,
      governanceLoaded: false,
      loading: false,
      detailLoading: false,
      error: "",
      requestSequence: 0,
      busy: new Set(),
      pollTimer: null,
      pollStartedAt: 0,
      pollFailures: 0,
    },
    chat: {
      sessions: [],
      total: 0,
      selectedSessionId: "",
      detail: null,
      listLoading: false,
      detailLoading: false,
      creating: false,
      deleting: false,
      sending: false,
      deliveryUnknown: false,
      listError: "",
      detailError: "",
      requestSequence: 0,
      draftChoiceTouched: false,
      pendingReply: null,
      pollTimer: null,
      pollStartedAt: 0,
      pollFailures: 0,
    },
    evidence: {
      draftId: "",
      loading: false,
      submissions: [],
      auditEvents: [],
      auditIntegrity: null,
      error: "",
    },
  };

  const statusLabels = Object.freeze({
    draft: "草稿",
    confirmed: "已确认",
    ready: "待提交",
    submitted: "已提交",
    accepted: "已接收",
    rejected: "被退回",
  });

  const confidenceLabels = Object.freeze({
    high: "高",
    medium: "中",
    low: "低",
    manual: "人工录入",
    unknown: "未知",
  });

  const els = {};

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    cacheElements();
    bindStaticEvents();
    setEnterpriseMode("simple", false);
    applyAgentTaskPreset("full");
    setImportFormat("json");
    renderApprovalEvents();
    renderAgentV2();
    renderOperationalStatus();
    void loadPublicHealth();
    void restoreSession();
  }

  function cacheElements() {
    [
      "connectionState",
      "connectionText",
      "simpleModeButton",
      "professionalModeButton",
      "enterpriseModeNote",
      "simpleStatusItem",
      "simpleStatusText",
      "simpleStatusHint",
      "agentStatusItem",
      "agentStatusText",
      "platformStatusItem",
      "platformStatusText",
      "assistantStatusItem",
      "assistantStatusText",
      "refreshStatusButton",
      "systemStatusHelp",
      "identityChip",
      "identityAvatar",
      "currentUserName",
      "currentUserRole",
      "demoBadge",
      "logoutButton",
      "newDraftButton",
      "agentTaskButton",
      "coalChatButton",
      "refreshDraftsButton",
      "draftSearch",
      "draftList",
      "draftEmpty",
      "draftEmptyTitle",
      "draftEmptyText",
      "clearDraftFilterButton",
      "draftListFooter",
      "draftListSummary",
      "loadMoreDraftsButton",
      "workspace",
      "welcomeCard",
      "welcomeStartButton",
      "welcomeAutofillButton",
      "welcomeNewDraftButton",
      "welcomeActionHint",
      "agentCenterButton",
      "agentCenterQuickCard",
      "agentCenterQuickStatus",
      "agentCenterQuickSummary",
      "agentCenterQuickMeta",
      "openAgentCenterQuickButton",
      "runAgentCenterQuickButton",
      "agentV2Workbench",
      "agentV2WorkbenchTitle",
      "closeAgentV2WorkbenchButton",
      "refreshAgentV2Button",
      "agentV2Error",
      "agentV2ErrorText",
      "agentV2StatAttention",
      "agentV2StatActive",
      "agentV2StatCompleted",
      "agentV2StatScheduled",
      "agentV2BoundDraft",
      "startAgentV2HealthButton",
      "agentV2FlowListSummary",
      "agentV2FlowList",
      "agentV2FlowDetailEmpty",
      "agentV2FlowDetailContent",
      "agentV2FlowTitle",
      "agentV2FlowMeta",
      "agentV2FlowStatus",
      "agentV2FlowSummary",
      "agentV2FlowFindings",
      "cancelAgentV2FlowButton",
      "retryAgentV2FlowButton",
      "agentV2StepList",
      "agentV2JobForm",
      "agentV2JobName",
      "agentV2JobScheduleKind",
      "agentV2JobDailyField",
      "agentV2JobDailyTime",
      "agentV2JobIntervalField",
      "agentV2JobIntervalMinutes",
      "agentV2JobTimezoneField",
      "agentV2JobTimezone",
      "agentV2JobPermissionHint",
      "createAgentV2JobButton",
      "agentV2JobList",
      "agentV2MemoryProposalForm",
      "agentV2MemoryScope",
      "agentV2MemoryKey",
      "agentV2MemoryValue",
      "agentV2MemoryReason",
      "createAgentV2MemoryProposalButton",
      "agentV2SkillProposalForm",
      "agentV2SkillName",
      "agentV2SkillDescription",
      "agentV2SkillProcedure",
      "createAgentV2SkillProposalButton",
      "agentV2MemoryProposalList",
      "agentV2SkillProposalList",
      "agentV2MemoryList",
      "agentV2SkillVersionList",
      "coalChatWorkbench",
      "coalChatWorkbenchTitle",
      "closeCoalChatButton",
      "newCoalChatButton",
      "refreshCoalChatButton",
      "coalChatListSummary",
      "coalChatSessionList",
      "coalChatTitle",
      "coalChatUseCurrentDraft",
      "coalChatDraftBinding",
      "deleteCoalChatButton",
      "coalChatError",
      "coalChatErrorText",
      "retryCoalChatButton",
      "coalChatMessageList",
      "coalChatEmpty",
      "coalChatScopeNotice",
      "coalChatForm",
      "coalChatInput",
      "coalChatInputHint",
      "coalChatCharacterCount",
      "sendCoalChatButton",
      "agentWorkbench",
      "agentWorkbenchTitle",
      "closeAgentWorkbenchButton",
      "startAgentHealthButton",
      "startAgentCustomButton",
      "agentTaskInput",
      "agentTaskInputHint",
      "agentTaskCharacterCount",
      "agentComposerDraftBinding",
      "agentToolCatalogDetails",
      "agentToolCatalogSummary",
      "agentToolCatalog",
      "runCoalHealthButton",
      "refreshAgentRunsButton",
      "agentRunListSummary",
      "agentRunList",
      "loadMoreAgentRunsButton",
      "agentDetailEmpty",
      "agentDetailContent",
      "agentRunDetailTitle",
      "agentRunMeta",
      "agentRunStatus",
      "agentIntegrityState",
      "cancelAgentRunButton",
      "agentRunProgress",
      "agentRunAnswer",
      "agentRunError",
      "agentIntegrityFailure",
      "agentApprovalCard",
      "agentApprovalTitle",
      "agentApprovalExplanation",
      "agentApprovalDetails",
      "rejectAgentApprovalButton",
      "approveAgentApprovalButton",
      "agentApprovalPermissionHint",
      "agentEvidenceSection",
      "agentStepList",
      "credentialNotice",
      "credentialNoticeText",
      "accessNotice",
      "roleGuide",
      "roleGuideTitle",
      "roleGuideLevelBadge",
      "roleGuideSummary",
      "roleGuideContext",
      "roleGuidePermissions",
      "roleGuideSteps",
      "roleGuideCapabilities",
      "roleGuideRestrictions",
      "editor",
      "draftTitle",
      "draftStatus",
      "draftMeta",
      "editorMoreActions",
      "simpleTaskCard",
      "simpleTaskStep",
      "simpleTaskTitle",
      "simpleTaskDescription",
      "simpleTaskProgressText",
      "simpleTaskProgressFill",
      "simpleTaskMeta",
      "simpleTaskButton",
      "simpleDeleteDraftButton",
      "undoButton",
      "deleteDraftButton",
      "saveState",
      "retrySaveButton",
      "stepList",
      "draftForm",
      "approvalEventList",
      "addEventButton",
      "downloadEventSnapshotTemplateButton",
      "eventSnapshotImportNotice",
      "cancelEventSnapshotImportButton",
      "profileSettingsDetails",
      "fileDrop",
      "sourceFile",
      "chooseFileButton",
      "fileHint",
      "pasteLabel",
      "sourceContent",
      "sourceName",
      "sourceSystem",
      "sourceMetaGrid",
      "sourceTruthStatement",
      "importButton",
      "textImportOption",
      "textImportHint",
      "importCapabilityNotice",
      "importCapabilityTitle",
      "importCapabilityText",
      "downloadJsonTemplateButton",
      "downloadCsvTemplateButton",
      "sourceCount",
      "sourceList",
      "runAssistButton",
      "measurementBody",
      "measurementPagination",
      "measurementPageSummary",
      "previousMeasurementPageButton",
      "nextMeasurementPageButton",
      "confirmationProgress",
      "reviewPersistenceHint",
      "confirmHighConfidenceButton",
      "questionCount",
      "questionList",
      "validateButton",
      "preflightSummary",
      "checkList",
      "confirmationOverview",
      "confirmationActorName",
      "confirmationActorId",
      "confirmationActorRole",
      "confirmationPermissionHint",
      "signatureState",
      "confirmDraftButton",
      "submissionGate",
      "submitCard",
      "submitButton",
      "receiptCard",
      "receiptDetails",
      "copyReceiptButton",
      "downloadReceiptButton",
      "newAfterSubmitButton",
      "refreshEvidenceButton",
      "submissionHistory",
      "auditHistory",
      "previousStepButton",
      "stepHint",
      "nextStepButton",
      "toastRegion",
      "sourceDialog",
      "sourceDialogTitle",
      "sourceDialogBody",
      "deleteDialog",
      "deleteConfirmation",
      "confirmDeleteButton",
      "submitDialog",
      "finalSubmitCheck",
      "confirmSubmitButton",
      "loginDialog",
      "loginForm",
      "loginActorId",
      "loginPassword",
      "loginError",
      "loginButton",
      "loginDemoHint",
      "loginRuntimeStatus",
    ].forEach((id) => {
      els[id] = document.getElementById(id);
    });
  }

  function bindStaticEvents() {
    els.simpleModeButton.addEventListener("click", () =>
      setEnterpriseMode("simple"),
    );
    els.professionalModeButton.addEventListener("click", () =>
      setEnterpriseMode("professional"),
    );
    els.simpleTaskButton.addEventListener("click", () =>
      void handleSimpleTaskAction(),
    );
    els.simpleDeleteDraftButton.addEventListener("click", openDeleteDialog);
    els.loginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void login();
    });
    els.loginDialog.addEventListener("cancel", (event) => event.preventDefault());
    els.logoutButton.addEventListener("click", () => void logout());
    els.newDraftButton.addEventListener("click", () => void createDraft());
    els.welcomeStartButton.addEventListener("click", () =>
      void handleWelcomePrimaryAction(),
    );
    els.welcomeAutofillButton.addEventListener("click", () =>
      void handleWelcomeAutofillAction(),
    );
    els.welcomeNewDraftButton.addEventListener("click", () => void createDraft());
    els.agentCenterButton.addEventListener("click", () => void openAgentV2Workbench());
    els.openAgentCenterQuickButton.addEventListener("click", () =>
      void openAgentV2Workbench(),
    );
    els.closeAgentV2WorkbenchButton.addEventListener(
      "click",
      closeAgentV2Workbench,
    );
    els.refreshAgentV2Button.addEventListener("click", () =>
      void refreshAgentV2Workbench(),
    );
    els.runAgentCenterQuickButton.addEventListener("click", () =>
      void startAgentV2HealthCheck(),
    );
    els.startAgentV2HealthButton.addEventListener("click", () =>
      void startAgentV2HealthCheck(),
    );
    els.cancelAgentV2FlowButton.addEventListener("click", () =>
      void cancelSelectedAgentV2Flow(),
    );
    els.retryAgentV2FlowButton.addEventListener("click", () =>
      void retrySelectedAgentV2Flow(),
    );
    document.querySelectorAll("[data-agent-center-tab]").forEach((button) => {
      button.addEventListener("click", () =>
        void selectAgentV2Tab(button.dataset.agentCenterTab),
      );
    });
    els.agentV2JobScheduleKind.addEventListener(
      "change",
      renderAgentV2JobScheduleFields,
    );
    els.agentV2JobForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void createAgentV2Job();
    });
    els.agentV2MemoryProposalForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void createAgentV2MemoryProposal();
    });
    els.agentV2SkillProposalForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void createAgentV2SkillProposal();
    });
    els.agentTaskButton.addEventListener("click", () => void openAgentWorkbench());
    els.coalChatButton.addEventListener("click", () => void openCoalChat());
    els.closeCoalChatButton.addEventListener("click", closeCoalChat);
    els.newCoalChatButton.addEventListener("click", () => void createCoalChat());
    els.deleteCoalChatButton.addEventListener("click", () =>
      void deleteCoalChat(),
    );
    els.refreshCoalChatButton.addEventListener("click", () =>
      void refreshCoalChat(),
    );
    els.retryCoalChatButton.addEventListener("click", () =>
      void retryCoalChat(),
    );
    els.coalChatUseCurrentDraft.addEventListener("change", () => {
      state.chat.draftChoiceTouched = true;
      renderCoalChatControls();
    });
    els.coalChatInput.addEventListener("input", renderCoalChatControls);
    els.coalChatInput.addEventListener("keydown", (event) => {
      if (
        event.key === "Enter" &&
        !event.shiftKey &&
        !event.isComposing
      ) {
        event.preventDefault();
        if (!els.sendCoalChatButton.disabled) void sendCoalChatMessage();
      }
    });
    els.coalChatForm.addEventListener("submit", (event) => {
      event.preventDefault();
      void sendCoalChatMessage();
    });
    els.closeAgentWorkbenchButton.addEventListener("click", closeAgentWorkbench);
    els.startAgentHealthButton.addEventListener("click", () =>
      void startCoalHealthCheck({
        task: defaultCoalHealthTask,
        mode: "auto",
      }),
    );
    els.runCoalHealthButton.addEventListener("click", () =>
      void startCoalHealthCheck({
        task: defaultCoalHealthTask,
        mode: "auto",
      }),
    );
    els.startAgentCustomButton.addEventListener("click", () =>
      void startAgentTaskFromComposer(),
    );
    els.agentTaskInput.addEventListener("input", renderAgentWorkbenchControls);
    document.querySelectorAll("[data-agent-task-preset]").forEach((button) => {
      button.addEventListener("click", () => {
        applyAgentTaskPreset(button.dataset.agentTaskPreset);
        els.agentTaskInput.focus();
      });
    });
    document.querySelectorAll('input[name="agentRunMode"]').forEach((input) => {
      input.addEventListener("change", renderAgentWorkbenchControls);
    });
    els.refreshAgentRunsButton.addEventListener("click", () =>
      void refreshAgentWorkbench(),
    );
    els.loadMoreAgentRunsButton.addEventListener("click", () =>
      void loadAgentRuns({ append: true }),
    );
    els.cancelAgentRunButton.addEventListener("click", () =>
      void cancelSelectedAgentRun(),
    );
    els.approveAgentApprovalButton.addEventListener("click", () =>
      void decideSelectedAgentApproval("approve"),
    );
    els.rejectAgentApprovalButton.addEventListener("click", () =>
      void decideSelectedAgentApproval("reject"),
    );
    els.refreshDraftsButton.addEventListener("click", () => void loadDrafts());
    els.loadMoreDraftsButton.addEventListener("click", () =>
      void loadDrafts({ append: true }),
    );
    els.refreshStatusButton.addEventListener("click", () => void refreshOperationalStatus());
    els.retrySaveButton.addEventListener("click", () => void retrySave());
    els.clearDraftFilterButton.addEventListener("click", clearDraftFilters);
    els.draftSearch.addEventListener("input", (event) => {
      state.search = String(event.target.value || "").trim().toLocaleLowerCase("zh-CN");
      renderDraftList();
    });

    document.querySelectorAll(".draft-tab").forEach((button) => {
      button.addEventListener("click", () => {
        state.filter = button.dataset.filter || "all";
        document.querySelectorAll(".draft-tab").forEach((tab) => {
          tab.classList.toggle("is-active", tab === button);
          tab.setAttribute("aria-selected", String(tab === button));
        });
        renderDraftList();
      });
    });

    els.stepList.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-step]");
      if (!button || !state.activeDraft) return;
      goToStep(Number(button.dataset.step));
    });

    els.previousStepButton.addEventListener("click", () => goToStep(state.step - 1));
    els.nextStepButton.addEventListener("click", () => void advanceStep());
    els.undoButton.addEventListener("click", () => void undoLastChange());
    els.deleteDraftButton.addEventListener("click", openDeleteDialog);
    els.addEventButton.addEventListener("click", guideToApprovalImport);
    els.downloadEventSnapshotTemplateButton.addEventListener(
      "click",
      downloadEventSnapshotTemplate,
    );
    els.cancelEventSnapshotImportButton.addEventListener("click", () => {
      setImportPurpose("source");
      showToast("已返回普通业务材料导入。");
    });

    els.draftForm.addEventListener("focusin", (event) => {
      if (isDraftField(event.target)) {
        state.fieldFocusSnapshot = fieldUndoEntry(event.target.name);
      }
    });
    els.draftForm.addEventListener("input", handleFormInput);
    els.draftForm.addEventListener("change", handleFormChange);

    document.querySelectorAll(".import-option").forEach((button) => {
      button.addEventListener("click", () => setImportFormat(button.dataset.importFormat));
    });
    els.chooseFileButton.addEventListener("click", () => els.sourceFile.click());
    els.sourceFile.addEventListener("change", () => void readSelectedFile());
    ["dragenter", "dragover"].forEach((eventName) => {
      els.fileDrop.addEventListener(eventName, (event) => {
        event.preventDefault();
        els.fileDrop.classList.add("is-dragging");
      });
    });
    ["dragleave", "drop"].forEach((eventName) => {
      els.fileDrop.addEventListener(eventName, (event) => {
        event.preventDefault();
        els.fileDrop.classList.remove("is-dragging");
      });
    });
    els.fileDrop.addEventListener("drop", (event) => {
      const file = event.dataTransfer && event.dataTransfer.files
        ? event.dataTransfer.files[0]
        : null;
      if (file) void readFile(file);
    });
    els.importButton.addEventListener("click", () => void importSource());
    els.downloadJsonTemplateButton.addEventListener(
      "click",
      () => downloadImportTemplate("json"),
    );
    els.downloadCsvTemplateButton.addEventListener(
      "click",
      () => downloadImportTemplate("csv"),
    );
    els.runAssistButton.addEventListener("click", () => void runAssistant());
    els.previousMeasurementPageButton.addEventListener("click", () => {
      state.measurementPage = Math.max(1, state.measurementPage - 1);
      renderMeasurements();
    });
    els.nextMeasurementPageButton.addEventListener("click", () => {
      state.measurementPage += 1;
      renderMeasurements();
    });
    els.confirmHighConfidenceButton.addEventListener(
      "click",
      () => void confirmHighConfidenceMeasurements(),
    );
    els.validateButton.addEventListener("click", () => void runValidation());
    els.confirmDraftButton.addEventListener("click", () => void confirmDraft());
    els.submitButton.addEventListener("click", openSubmitDialog);
    els.copyReceiptButton.addEventListener("click", () => void copyReceipt());
    els.downloadReceiptButton.addEventListener("click", downloadReceipt);
    els.newAfterSubmitButton.addEventListener("click", () => void createDraft());
    els.refreshEvidenceButton.addEventListener("click", () => void loadEvidence(true));

    els.deleteConfirmation.addEventListener("input", () => {
      els.confirmDeleteButton.disabled = els.deleteConfirmation.value.trim() !== "移除";
    });
    els.confirmDeleteButton.addEventListener("click", () => void deleteDraft());
    els.finalSubmitCheck.addEventListener("change", () => {
      els.confirmSubmitButton.disabled = !els.finalSubmitCheck.checked;
    });
    els.confirmSubmitButton.addEventListener("click", () => void submitDraft());

    document.querySelectorAll("[data-close-dialog]").forEach((button) => {
      button.addEventListener("click", () => closeDialog(button.dataset.closeDialog));
    });
    [els.sourceDialog, els.deleteDialog, els.submitDialog].forEach((dialog) => {
      dialog.addEventListener("click", (event) => {
        if (event.target === dialog) dialog.close();
      });
    });
    document.querySelectorAll('[role="tablist"]').forEach(bindTablistKeyboard);
    window.addEventListener("beforeunload", (event) => {
      if (!state.dirtyWireFields.size && !state.savePromise) return;
      event.preventDefault();
      event.returnValue = "";
    });
    document.addEventListener("visibilitychange", () => {
      if (
        !document.hidden &&
        !els.agentWorkbench.hidden &&
        state.agent.selectedRunId &&
        isActiveAgentStatus(state.agent.detail && state.agent.detail.status)
      ) {
        scheduleAgentPoll(0);
      }
      if (
        !document.hidden &&
        !els.agentV2Workbench.hidden &&
        state.agentV2.selectedFlowId &&
        state.agentV2.detail &&
        agentV2ActiveStatuses.has(state.agentV2.detail.status)
      ) {
        scheduleAgentV2Poll(0);
      }
      if (
        !document.hidden &&
        !els.coalChatWorkbench.hidden &&
        state.chat.pendingReply &&
        !state.chat.deliveryUnknown
      ) {
        scheduleCoalChatPoll(0);
      }
    });
  }

  function setEnterpriseMode(mode, userInitiated = true) {
    const professional = mode === "professional";
    state.interfaceMode = professional ? "professional" : "simple";
    document.body.classList.toggle("is-simple-mode", !professional);
    document.body.classList.toggle("is-professional-mode", professional);
    els.simpleModeButton.classList.toggle("is-active", !professional);
    els.simpleModeButton.setAttribute("aria-pressed", String(!professional));
    els.professionalModeButton.classList.toggle("is-active", professional);
    els.professionalModeButton.setAttribute("aria-pressed", String(professional));
    els.enterpriseModeNote.textContent = professional
      ? "专业工具：可管理智能体定时任务、记忆与技能治理，并使用详细分析工具。"
      : "快捷填报：页面只提示当前该做什么；智能体任务中心只展示易懂结论。";
    els.editorMoreActions.open = professional;
    if (!professional) {
      els.roleGuide.open = false;
      if (userInitiated && !els.agentWorkbench.hidden) closeAgentWorkbench();
      if (userInitiated && !els.coalChatWorkbench.hidden) closeCoalChat();
      if (state.agentV2.selectedTab !== "overview") {
        state.agentV2.selectedTab = "overview";
        renderAgentV2Tabs();
      }
    }
    renderOperationalStatus();
    renderSimpleTaskGuide();
    renderAgentV2();
    if (userInitiated) {
      showToast(
        professional
          ? "已进入专业工具，填报草稿和权限没有变化。"
          : "已返回快捷填报，系统会提示当前下一项任务。",
      );
    }
  }

  function bindTablistKeyboard(tablist) {
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    tabs.forEach((tab) => {
      tab.tabIndex = tab.getAttribute("aria-selected") === "true" ? 0 : -1;
      tab.addEventListener("click", () => {
        tabs.forEach((candidate) => {
          candidate.tabIndex = candidate === tab ? 0 : -1;
        });
      });
      tab.addEventListener("keydown", (event) => {
        if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
        event.preventDefault();
        const enabled = tabs.filter((candidate) => !candidate.disabled);
        if (!enabled.length) return;
        const current = enabled.indexOf(tab);
        const next =
          event.key === "Home"
            ? enabled[0]
            : event.key === "End"
              ? enabled[enabled.length - 1]
              : enabled[
                  (current + (event.key === "ArrowRight" ? 1 : -1) + enabled.length) %
                    enabled.length
                ];
        next.focus();
        next.click();
      });
    });
  }

  async function loadPublicHealth() {
    try {
      const payload = await api(endpoints.health(), {
        suppressAuthRedirect: true,
        sessionScoped: false,
        timeoutMs: 8000,
      });
      state.serviceHealth = payload && typeof payload === "object" ? payload : null;
    } catch (error) {
      state.serviceHealth = {
        status: "error",
        message: error.message,
      };
    }
    renderOperationalStatus();
  }

  async function loadPlatformStatus() {
    if (!state.principal || !hasPermission("read")) {
      state.platformStatus = null;
      renderOperationalStatus();
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    try {
      const payload = await api(endpoints.platformStatus(), {
        suppressAuthRedirect: true,
        timeoutMs: 30000,
      });
      if (sessionRequestIsStale(sessionGeneration)) return;
      state.platformStatus = payload && typeof payload === "object" ? payload : null;
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      if (error.status === 404 && state.serviceHealth) {
        state.platformStatus = {
          configured: Boolean(state.serviceHealth.platform_configured),
          reachable: null,
          compatible: null,
          message: state.serviceHealth.platform_configured
            ? "已配置；当前服务版本不支持连通性探测"
            : "尚未配置监管平台接口",
        };
      } else {
        state.platformStatus = {
          configured: Boolean(state.serviceHealth && state.serviceHealth.platform_configured),
          reachable: false,
          compatible: false,
          message: error.message,
        };
      }
    }
    if (sessionRequestIsStale(sessionGeneration)) return;
    renderOperationalStatus();
  }

  async function refreshOperationalStatus() {
    setBusy(els.refreshStatusButton, true, "检查中…");
    await loadPublicHealth();
    await loadPlatformStatus();
    setBusy(els.refreshStatusButton, false);
  }

  function renderOperationalStatus() {
    const health = state.serviceHealth;
    const connected = Boolean(health && health.status === "ok");
    const loopback = ["localhost", "127.0.0.1", "::1"].includes(
      window.location.hostname,
    );
    const demoEnabled = Boolean(
      connected && loopback && health.demo_account_enabled === true,
    );
    els.loginDemoHint.hidden = !demoEnabled;
    if (demoEnabled && !els.loginActorId.value) els.loginActorId.value = "demo";
    setStatusItem(
      els.agentStatusItem,
      els.agentStatusText,
      connected ? "ok" : health ? "error" : "checking",
      connected ? "已连接并运行" : health ? "无法连接" : "正在检查",
    );
    if (els.loginRuntimeStatus) {
      els.loginRuntimeStatus.classList.toggle("is-error", Boolean(health && !connected));
      els.loginRuntimeStatus.textContent = connected
        ? "企业填报服务已启动并正常响应。启动命令所在终端保持不返回提示符是服务器正常运行状态，请勿关闭。"
        : health
          ? "浏览器无法连接企业填报服务。请保持启动命令运行，并确认访问地址和 SSH 端口转发正确。"
          : "正在连接企业填报服务。若服务已启动，启动命令所在终端保持不返回提示符是正常现象。";
    }

    const llmConfigured = Boolean(connected && health.llm_mode === "configured");
    const newsStatus = connected
      ? String(health.news_search_status || "configured_unverified").toLowerCase()
      : "";
    const newsProblem = ["unreachable", "disabled"].includes(newsStatus);
    const newsDegraded = newsStatus === "degraded";
    const assistantState = !connected
      ? health ? "error" : "checking"
      : newsProblem || newsDegraded || !llmConfigured
        ? "warning"
        : "ok";
    const assistantText = !connected
      ? health ? "状态不可用" : "正在检查"
      : llmConfigured
        ? newsStatus === "reachable"
          ? "模型与新闻检索可用"
          : newsDegraded
            ? "模型已配置；新闻检索降级"
            : newsProblem
              ? "模型已配置；新闻检索异常"
              : "模型已配置（调用时验证）"
        : newsStatus === "reachable"
          ? "本地规则；百度新闻可用"
          : newsProblem
            ? "本地规则；新闻检索异常"
            : "本地确定性规则";
    setStatusItem(
      els.assistantStatusItem,
      els.assistantStatusText,
      assistantState,
      assistantText,
    );
    if (llmConfigured) {
      els.assistantStatusItem.title =
        newsStatus === "reachable"
          ? "最近一次新闻检索已取得有效来源；新闻持续更新，仍应打开原文核验。"
          : newsDegraded
            ? "最近一次新闻检索使用了后备源或含未核验时间，结果可能不完整。"
            : newsProblem
              ? "最近一次新闻检索失败；请查看消息中的提供商原因并检查 DNS、代理或 API。"
              : "仅表示管理员已配置模型参数；模型调用和新闻搜索会在实际请求时分别验证。";
    } else {
      els.assistantStatusItem.removeAttribute("title");
    }
    els.textImportOption.disabled =
      state.importPurpose === "event_snapshot" || !llmConfigured;
    els.textImportOption.title =
      !llmConfigured ? "粘贴文字需要管理员先配置智能模型" : "";
    els.textImportHint.textContent = llmConfigured
      ? "适合台账片段或说明"
      : "当前未启用（需智能模型）";
    if (!llmConfigured && state.importFormat === "text") setImportFormat("json");
    els.importCapabilityTitle.textContent = !connected
      ? "企业填报服务当前不可用"
      : llmConfigured
        ? "确定性导入与智能建议均已可用"
        : "当前使用本地确定性规则";
    els.importCapabilityText.textContent = !connected
      ? "请先恢复企业填报服务连接，再导入材料。"
      : llmConfigured
        ? "JSON、CSV 可确定性导入；文字材料会发送给管理员配置的模型生成待核对建议。"
        : "JSON、CSV 可完整导入和预检；未配置模型时不支持从自由文字提取字段，也不会把文字伪装成已导入数据。";

    const platform = state.platformStatus;
    if (!state.principal) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "checking",
        "登录后检查",
      );
    } else if (!hasPermission("read")) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "warning",
        "当前账号无查看权限",
      );
    } else if (!platform) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "checking",
        "正在检查",
      );
    } else if (!platform.configured) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "warning",
        "未配置（可先编辑）",
      );
    } else if (platform.reachable === false || platform.compatible === false) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "error",
        platform.compatible === false ? "契约不兼容" : "暂时不可达",
      );
    } else if (platform.reachable === true && platform.compatible !== false) {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "ok",
        "已连接且兼容",
      );
    } else {
      setStatusItem(
        els.platformStatusItem,
        els.platformStatusText,
        "warning",
        "已配置，未探测",
      );
    }
    if (platform && platform.message) {
      els.platformStatusItem.title = String(platform.message);
    } else {
      els.platformStatusItem.removeAttribute("title");
    }
    renderSimpleOperationalStatus(connected, platform, llmConfigured);
    if (state.activeDraft) renderSubmission();
  }

  function renderSimpleOperationalStatus(connected, platform, llmConfigured) {
    let status = "checking";
    let label = "正在检查";
    let hint = "请稍候，系统正在检查填报和提交能力。";
    if (state.serviceHealth && !connected) {
      status = "error";
      label = "服务未连接";
      hint = "当前不能安全保存，请联系管理员恢复企业填报服务。";
    } else if (connected && !state.principal) {
      status = "ok";
      label = "服务正常，请先登录";
      hint = "登录后系统会自动检查草稿权限和监管提交接口。";
    } else if (connected && !hasPermission("read")) {
      status = "warning";
      label = "账号权限不足";
      hint = "当前账号不能查看填报，请联系管理员调整权限。";
    } else if (connected && !platform) {
      label = "正在检查提交能力";
      hint = "草稿功能已经可用，监管接口状态仍在读取。";
    } else if (connected && !platform.configured) {
      status = "warning";
      label = "可以编辑，暂不能提交";
      hint = "监管接口尚未配置；可以先保存草稿，配置完成后再提交。";
    } else if (
      connected &&
      (platform.reachable === false || platform.compatible === false)
    ) {
      status = "error";
      label = "可以编辑，提交接口异常";
      hint =
        platform.compatible === false
          ? "监管接口版本不兼容，请联系管理员处理后再提交。"
          : "监管接口暂时不可达，请保存草稿并稍后重试。";
    } else if (
      connected &&
      platform.reachable === true &&
      platform.compatible !== false
    ) {
      status = "ok";
      label = "系统正常，可以填报";
      hint = llmConfigured
        ? "保存、智能提取和监管提交均可用。"
        : "保存和监管提交可用；自由文字智能提取暂未启用。";
    } else if (connected) {
      status = "warning";
      label = "可以填报，提交前再检查";
      hint = "监管接口已经配置但尚未完成连通性确认。";
    }
    setStatusItem(els.simpleStatusItem, els.simpleStatusText, status, label);
    els.simpleStatusHint.textContent = hint;
  }

  function setStatusItem(item, textNode, status, label) {
    if (!item || !textNode) return;
    item.classList.remove("is-ok", "is-warning", "is-error", "is-checking");
    item.classList.add(`is-${status}`);
    textNode.textContent = label;
  }

  async function restoreSession() {
    try {
      const payload = await api(endpoints.me(), { suppressAuthRedirect: true });
      applyAuthenticatedSession(payload);
      if (hasPermission("read")) {
        await Promise.all([loadDrafts(), loadPlatformStatus()]);
      } else {
        renderDraftList();
      }
    } catch (error) {
      if (error.status === 401) {
        showLogin("请登录企业账号后继续。");
      } else {
        showLogin(error.message || "暂时无法连接企业填报服务。");
      }
    }
  }

  async function login() {
    const actorId = els.loginActorId.value.trim();
    const password = els.loginPassword.value;
    if (!actorId || !password) {
      els.loginError.textContent = "请输入账号和密码。";
      return;
    }
    els.loginError.textContent = "";
    setBusy(els.loginButton, true, "正在登录…");
    try {
      const payload = await api(endpoints.login(), {
        method: "POST",
        body: { actor_id: actorId, password },
        suppressAuthRedirect: true,
      });
      els.loginPassword.value = "";
      applyAuthenticatedSession(payload);
      if (els.loginDialog.open) els.loginDialog.close();
      if (hasPermission("read")) {
        await Promise.all([loadDrafts(), loadPlatformStatus()]);
      } else {
        renderDraftList();
      }
      await resumeSessionRecovery();
      if (!els.agentWorkbench.hidden && state.agent.selectedRunId) {
        await loadAgentRun(state.agent.selectedRunId);
      }
      if (!els.coalChatWorkbench.hidden) {
        await refreshCoalChat();
      }
      showToast(`已以 ${state.principal.name} 的身份登录。`);
    } catch (error) {
      els.loginError.textContent = error.message;
      els.loginPassword.focus();
    } finally {
      setBusy(els.loginButton, false);
    }
  }

  async function logout() {
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，完成前不能退出。`, "error");
      return;
    }
    setBusy(els.logoutButton, true, "正在退出…");
    try {
      await flushSave();
      await api(endpoints.logout(), { method: "POST", body: {} });
      showLogin("已安全退出，请重新登录。");
    } catch (error) {
      showToast(`未退出：${error.message}。本页内容仍保留。`, "error");
    } finally {
      setBusy(els.logoutButton, false);
    }
  }

  function applyAuthenticatedSession(payload) {
    if (
      !payload ||
      !payload.principal ||
      typeof payload.csrf_token !== "string" ||
      !payload.csrf_token
    ) {
      throw new Error("服务返回的登录会话无效。");
    }
    const previousRecoveryActor =
      state.sessionRecovery && state.sessionRecovery.actorId;
    const switchingAccount = Boolean(
      previousRecoveryActor &&
      previousRecoveryActor !== String(payload.principal.actor_id || ""),
    );
    if (switchingAccount) clearAuthenticatedSession();
    state.principal = payload.principal;
    // The CSRF value deliberately lives only in page memory. The session
    // credential itself remains in the HttpOnly cookie and is never exposed.
    state.csrfToken = payload.csrf_token;
    renderAuthentication();
    renderOperationalStatus();
    if (switchingAccount) {
      showToast("已切换账号；为防止跨账号泄露，上一账号未保存的页面内容已清除。");
    }
  }

  function scrubAuthenticatedDom() {
    els.draftForm.reset();
    els.draftSearch.value = "";
    els.sourceFile.value = "";
    els.sourceContent.value = "";
    els.coalChatInput.value = "";
    els.coalChatUseCurrentDraft.checked = false;
    els.agentTaskInput.value = defaultCoalHealthTask;
    els.deleteConfirmation.value = "";
    els.finalSubmitCheck.checked = false;
    els.confirmDeleteButton.disabled = true;
    els.confirmSubmitButton.disabled = true;
    els.loginActorId.value = "";
    els.loginPassword.value = "";

    [els.sourceDialog, els.deleteDialog, els.submitDialog].forEach((dialog) => {
      if (dialog && dialog.open) dialog.close();
    });
    els.toastRegion.replaceChildren();
    [
      els.approvalEventList,
      els.sourceList,
      els.measurementBody,
      els.questionList,
      els.preflightSummary,
      els.checkList,
      els.confirmationOverview,
      els.submissionGate,
      els.receiptDetails,
      els.submissionHistory,
      els.auditHistory,
      els.sourceDialogBody,
      els.agentRunProgress,
      els.agentRunAnswer,
      els.agentApprovalDetails,
      els.agentStepList,
      els.agentV2FlowList,
      els.agentV2FlowFindings,
      els.agentV2StepList,
      els.agentV2JobList,
      els.agentV2MemoryProposalList,
      els.agentV2SkillProposalList,
      els.agentV2MemoryList,
      els.agentV2SkillVersionList,
    ].forEach((container) => container.replaceChildren());

    els.draftTitle.textContent = "新填报";
    els.draftStatus.textContent = "草稿";
    els.draftStatus.className = "status-badge status-draft";
    els.draftMeta.textContent = "尚未保存";
    els.saveState.textContent = "尚未保存";
    els.saveState.className = "save-state";
    els.retrySaveButton.hidden = true;
    els.draftList.setAttribute("aria-busy", "false");
    els.sourceCount.textContent = "0 个";
    els.measurementPageSummary.textContent = "暂无填报数字";
    els.confirmationProgress.textContent = "尚无可确认数字";
    els.questionCount.textContent = "0";
    els.reviewPersistenceHint.textContent = "逐项核对会由服务端保存并写入审计记录。";
    els.confirmationActorName.textContent = "请先登录";
    els.confirmationActorId.textContent = "账号：—";
    els.confirmationActorRole.textContent = "—";
    els.confirmationPermissionHint.textContent = "";
    els.signatureState.textContent = "未确认";
    els.signatureState.classList.remove("is-signed");
    els.sourceDialogTitle.textContent = "来源详情";
    els.receiptCard.hidden = true;
    els.submitCard.hidden = false;

    els.agentRunDetailTitle.textContent = "煤炭数据体检";
    els.agentRunMeta.textContent = "";
    els.agentRunStatus.textContent = "等待中";
    els.agentRunStatus.className = "agent-status";
    els.agentIntegrityState.textContent = "";
    els.agentIntegrityState.hidden = true;
    els.agentIntegrityState.removeAttribute("title");
    els.agentRunError.textContent = "";
    els.agentRunError.hidden = true;
    els.agentIntegrityFailure.hidden = true;
    els.agentApprovalCard.hidden = true;
    els.agentApprovalTitle.textContent = "是否允许这个工具动作？";
    els.agentApprovalExplanation.textContent = "";
    els.agentApprovalPermissionHint.textContent = "";
    els.approveAgentApprovalButton.removeAttribute("title");
    els.rejectAgentApprovalButton.removeAttribute("title");
    els.agentV2Workbench.hidden = true;
    els.agentV2FlowDetailContent.hidden = true;
    els.agentV2FlowDetailEmpty.hidden = false;
    els.agentV2Error.hidden = true;
    els.agentV2ErrorText.textContent = "";
    els.agentV2MemoryProposalForm.reset();
    els.agentV2SkillProposalForm.reset();
    els.agentV2JobForm.reset();
    els.agentV2JobName.value = "每日煤炭体检";
    els.agentV2JobDailyTime.value = "09:00";
    els.agentV2JobIntervalMinutes.value = "60";
    els.agentV2JobTimezone.value = "Asia/Shanghai";
    renderAgentV2JobScheduleFields();

    els.coalChatWorkbench.hidden = true;
    els.agentWorkbench.hidden = true;
    els.editor.hidden = true;
    els.welcomeCard.hidden = false;
    els.fileDrop.classList.remove("is-dragging");
    document.querySelectorAll(".draft-tab").forEach((tab) => {
      const active = tab.dataset.filter === "all";
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    setImportPurpose("source");
    setImportFormat("json");
  }

  function clearAuthenticatedSession(options = {}) {
    const preserveWorkspace = Boolean(options.preserveWorkspace && state.activeDraft);
    const retainAuthentication = Boolean(
      options.retainAuthentication && state.principal,
    );
    const previousPrincipal = state.principal;
    state.sessionGeneration += 1;
    state.agent.requestSequence += 1;
    state.agentV2.requestSequence += 1;
    state.chat.requestSequence += 1;
    stopAgentPolling();
    stopAgentV2Polling();
    stopCoalChatPolling();
    if (preserveWorkspace) {
      state.sessionRecovery = {
        draftId: state.activeDraft.id,
        revision: state.activeDraft.revision,
        actorId: String((previousPrincipal && previousPrincipal.actor_id) || ""),
        capturedAt: new Date().toISOString(),
      };
    }
    if (!retainAuthentication) {
      state.principal = null;
      state.csrfToken = "";
    }
    state.platformStatus = null;
    state.reviewState = null;
    state.reviewLoading = false;
    state.loading = false;
    state.agent.tools = [];
    state.agent.toolsLoaded = false;
    state.agent.toolsLoading = false;
    state.agent.toolsError = "";
    state.agent.creating = false;
    state.agent.listLoading = false;
    state.agent.detailLoading = false;
    state.agentV2.loading = false;
    state.agentV2.detailLoading = false;
    state.agentV2.busy.clear();
    state.chat.listLoading = false;
    state.chat.detailLoading = false;
    state.chat.creating = false;
    state.chat.deleting = false;
    state.evidence = {
      draftId: "",
      loading: false,
      submissions: [],
      auditEvents: [],
      auditIntegrity: null,
      error: "",
    };
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
    if (!preserveWorkspace) {
      state.drafts = [];
      state.draftTotal = 0;
      state.draftNextOffset = 0;
      state.draftHasMore = false;
      state.activeDraft = null;
      state.step = 1;
      state.filter = "all";
      state.search = "";
      state.importFormat = "json";
      state.importPurpose = "source";
      state.undoStack = [];
      state.undoBytes = 0;
      state.fieldFocusSnapshot = null;
      state.measurementPage = 1;
      state.savePromise = null;
      state.loading = false;
      state.draftsLoaded = false;
      state.draftLoadError = "";
      state.selectedFile = null;
      state.lastAssistContent = "";
      state.lastAssistFormat = "text";
      state.assistantSource = null;
      state.suggestions = [];
      state.dirtyWireFields.clear();
      state.sessionRecovery = null;
      state.submitAttempt = null;
      state.activeOperation = "";
      state.agent.runs = [];
      state.agent.total = 0;
      state.agent.nextOffset = 0;
      state.agent.hasMore = false;
      state.agent.selectedRunId = "";
      state.agent.detail = null;
      state.agent.creating = false;
      state.agent.listLoading = false;
      state.agent.detailLoading = false;
      state.agent.listError = "";
      state.agent.detailError = "";
      state.agent.pollStartedAt = 0;
      state.agent.pollFailures = 0;
      state.agentV2.selectedTab = "overview";
      state.agentV2.flows = [];
      state.agentV2.selectedFlowId = "";
      state.agentV2.detail = null;
      state.agentV2.jobs = [];
      state.agentV2.memoryProposals = [];
      state.agentV2.memories = [];
      state.agentV2.skillProposals = [];
      state.agentV2.skillVersions = [];
      state.agentV2.flowsLoaded = false;
      state.agentV2.jobsLoaded = false;
      state.agentV2.governanceLoaded = false;
      state.agentV2.loading = false;
      state.agentV2.detailLoading = false;
      state.agentV2.error = "";
      state.agentV2.busy.clear();
      state.agentV2.pollStartedAt = 0;
      state.agentV2.pollFailures = 0;
      state.chat.sessions = [];
      state.chat.total = 0;
      state.chat.selectedSessionId = "";
      state.chat.detail = null;
      state.chat.listLoading = false;
      state.chat.detailLoading = false;
      state.chat.creating = false;
      state.chat.listError = "";
      state.chat.detailError = "";
      state.chat.sending = false;
      state.chat.deleting = false;
      state.chat.deliveryUnknown = false;
      state.chat.pendingReply = null;
      state.chat.pollStartedAt = 0;
      state.chat.pollFailures = 0;
      state.chat.draftChoiceTouched = false;
      scrubAuthenticatedDom();
    } else {
      els.saveState.textContent = "登录后继续保存";
      els.saveState.className = "save-state is-error";
      els.retrySaveButton.hidden = true;
      renderAll();
    }
    renderAgentWorkbench();
    renderAgentV2();
    renderCoalChat();
    renderDraftList();
    renderAuthentication();
    renderOperationalStatus();
    renderAgentWorkbenchControls();
    renderCoalChatControls();
  }

  function showLogin(message = "", options = {}) {
    clearAuthenticatedSession({
      preserveWorkspace: Boolean(options.preserveWorkspace),
    });
    els.loginPassword.value = "";
    els.loginError.textContent = message;
    const loopback = ["localhost", "127.0.0.1", "::1"].includes(
      window.location.hostname,
    );
    const demoEnabled = Boolean(
      loopback &&
      state.serviceHealth &&
      state.serviceHealth.demo_account_enabled === true,
    );
    els.loginDemoHint.hidden = !demoEnabled;
    if (!els.loginActorId.value && demoEnabled) {
      els.loginActorId.value = "demo";
    }
    if (!els.loginDialog.open) els.loginDialog.showModal();
    window.setTimeout(() => els.loginActorId.focus(), 0);
  }

  async function resumeSessionRecovery() {
    const recovery = state.sessionRecovery;
    const localDraft = state.activeDraft;
    if (!recovery || !localDraft || localDraft.id !== recovery.draftId) return;
    if (!hasPermission("read")) {
      clearAuthenticatedSession({ retainAuthentication: true });
      showToast("当前账号已无查看权限，上一会话保留的草稿内容已安全清除。", "error");
      return;
    }
    try {
      const payload = await api(endpoints.draft(recovery.draftId));
      const serverDraft = normalizeDraft(unwrapDraft(payload));
      if (serverDraft.revision !== localDraft.revision) {
        els.saveState.textContent = "服务端已有新版本";
        els.saveState.className = "save-state is-error";
        els.retrySaveButton.hidden = false;
        els.retrySaveButton.textContent = "需要人工合并";
        els.retrySaveButton.title =
          "重新登录期间服务端版本发生变化。本页仍保留未保存内容，请先复制，再刷新并人工合并。";
        showToast(
          "重新登录期间草稿已有新版本。本页未保存内容仍保留，请先复制留存，再刷新并人工合并。",
          "error",
        );
        return;
      }
      if (state.dirtyWireFields.size && hasPermission("write")) {
        await flushSave();
        showToast("重新登录成功，刚才未保存的修改也已补存。");
      } else if (state.dirtyWireFields.size) {
        showToast("重新登录的账号无编辑权限；未保存内容仍留在本页。", "error");
        return;
      }
      state.sessionRecovery = null;
      applyReviewState(payload && payload.review_state);
      void loadReviews();
      renderAll();
    } catch (error) {
      showToast(`会话已恢复，但草稿状态核对失败：${error.message}`, "error");
    }
  }

  function hasPermission(permission) {
    return Boolean(
      state.principal &&
      Array.isArray(state.principal.permissions) &&
      state.principal.permissions.includes(permission),
    );
  }

  function credentialRotationRequired() {
    return Boolean(
      state.principal &&
      (state.principal.must_change_password || state.principal.temporary_demo),
    );
  }

  function canFinalizeWith(permission) {
    return (
      hasPermission("read") &&
      hasPermission(permission) &&
      !credentialRotationRequired()
    );
  }

  function principalOperationGuide(principal) {
    const granted = new Set(
      principal && Array.isArray(principal.permissions)
        ? principal.permissions.filter((permission) =>
            [
              "read",
              "write",
              "confirm",
              "submit",
              "governance_review",
              "skill_admin",
            ].includes(permission),
          )
        : [],
    );
    const canRead = granted.has("read");
    const canWrite = granted.has("write");
    const canConfirm = granted.has("confirm");
    const canSubmit = granted.has("submit");
    const canGovernanceReview = granted.has("governance_review");
    const canManageSkills = granted.has("skill_admin");
    const credentialLocked = Boolean(
      principal &&
      (principal.must_change_password || principal.temporary_demo),
    );
    const effectiveConfirm = canConfirm && !credentialLocked;
    const effectiveSubmit = canSubmit && !credentialLocked;
    const isDemo = Boolean(principal && principal.temporary_demo);

    let code = "custom";
    let title = "自定义协作账号";
    let badge = "自定义";
    let summary =
      "页面已按实际授权组合出当前可做事项；请按交接提示与其他岗位协作。";
    if (isDemo) {
      code = "demo";
      title = "本机演示账号";
      badge = "演示";
      summary =
        "用于熟悉填报流程；后端不会允许该账号留下正式确认或向监管端提交。";
    } else if (credentialLocked) {
      code = "credential-locked";
      title = "待换密账号";
      badge = "待换密";
      summary =
        "可继续使用未被锁定的权限；完成凭据更新前不能正式确认或提交。";
    } else if (canRead && canWrite && canConfirm && canSubmit) {
      code = "full-flow";
      title = "全流程权限账号";
      badge = "全流程";
      summary =
        "可以完成查看、填报、逐项复核、账号确认和监管提交，关键动作仍需逐步人工核实。";
    } else if (
      canRead &&
      !canWrite &&
      canConfirm &&
      canSubmit
    ) {
      code = "confirm-submit";
      title = "确认与报送账号";
      badge = "确认 + 报送";
      summary =
        "负责独立复核并报送已核实的数据；发现错误时应退回经办人修改。";
    } else if (
      canRead &&
      canWrite &&
      canConfirm &&
      !canSubmit
    ) {
      code = "write-confirm";
      title = "经办兼确认账号";
      badge = "经办 + 确认";
      summary =
        "可以填报并完成逐项复核和账号确认，最后需交给有提交权限的人员报送。";
    } else if (
      canRead &&
      canWrite &&
      !canConfirm &&
      canSubmit
    ) {
      code = "write-submit";
      title = "经办兼报送账号";
      badge = "经办 + 报送";
      summary =
        "可以整理数据并报送，但只能提交其他确认人已经确认、此后未被修改的版本。";
    } else if (
      canRead &&
      !canWrite &&
      !canConfirm &&
      canSubmit
    ) {
      code = "submitter";
      title = "报送执行账号";
      badge = "报送";
      summary =
        "只负责核验门禁并提交其他确认人已经确认、此后未被修改的版本。";
    } else if (
      canRead &&
      !canWrite &&
      canConfirm &&
      !canSubmit
    ) {
      code = "confirmer";
      title = "复核确认账号";
      badge = "确认";
      summary =
        "负责对照原始材料逐项复核并完成账号确认，不能直接修改或提交。";
    } else if (
      canRead &&
      canWrite &&
      !canConfirm &&
      !canSubmit
    ) {
      code = "editor";
      title = "填报经办账号";
      badge = "经办";
      summary =
        "负责准备来源、修订数据和消除预检阻断项，完成后交确认人员复核。";
    } else if (
      canRead &&
      !canWrite &&
      !canConfirm &&
      !canSubmit
    ) {
      code = "viewer";
      title = "监督查看账号";
      badge = "查看";
      summary =
        "适合领导查看状态、异常、凭证、审计和回执，不会改变企业报送数据。";
    } else if (!granted.size) {
      code = "invalid";
      title = "权限配置异常";
      badge = "异常";
      summary =
        "服务端没有返回可识别权限，页面已安全关闭全部业务操作，请联系管理员。";
    }

    const steps = [];
    if (!canRead) {
      steps.push(
        "先联系管理员补充 read（查看）权限；缺少它时无法在页面列出并打开草稿，不能独立完成业务流程。",
        "权限补齐并重新登录后，再根据页面重新生成的说明开展查看、填报、确认或提交。",
      );
    } else {
      steps.push(
        "先选择目标草稿，查看报送状态、统计窗口、来源材料、预检结果、审计链和历史回执。",
      );
      if (canWrite) {
        steps.push(
          "完成基本信息、真实来源和数据修订，人工核实智能建议；每次修改后重新运行提交前预检。",
        );
      } else {
        steps.push("发现数据或来源问题时记录草稿编号，并转交有编辑权限的经办人修改。");
      }
      if (effectiveConfirm) {
        steps.push(
          "对照原始材料逐条留下当前账号的正式复核记录，清除阻断项后再接受真实性声明并确认。",
        );
      } else {
        steps.push(
          credentialLocked && canConfirm
            ? "先完成个人凭据更新，再由当前确认人逐条复核并确认；锁定状态不能绕过。"
            : "预检通过后，转交有 confirm（确认）权限的正式个人账号逐条复核并确认。",
        );
      }
      if (effectiveSubmit) {
        steps.push(
          "确认草稿修订号未变化、平台状态可用且没有重复提交风险，再提交并保存监管回执。",
        );
      } else {
        steps.push(
          credentialLocked && canSubmit
            ? "完成个人凭据更新并重新核验确认状态后，才能执行监管提交。"
            : "最后转交有 submit（提交）权限的账号报送，并共同核验和留存回执。",
        );
      }
    }

    const capabilities = [];
    if (!canRead) {
      capabilities.push(
        "网页流程当前不可用。权限徽标只说明服务端配置，不能替代查看草稿所需的 read 权限。",
      );
    } else {
      capabilities.push(
        "查看草稿、预检、最终确认状态、审计记录和提交回执。",
        "使用煤炭业务对话与只读智能任务解释异常、复算关系和检查来源。",
      );
      if (canWrite) {
        capabilities.push(
          "新建、导入、编辑草稿，移除没有正在报送且尚未成功提交的草稿。",
          "人工核实后采用智能提取建议，或批准绑定当前修订的草稿补丁。",
        );
      }
      if (effectiveConfirm) {
        capabilities.push(
          "以当前企业个人账号逐条复核观测，并完成企业账号人工确认。",
        );
      }
      if (effectiveSubmit) {
        capabilities.push("提交已经确认、预检通过且未被修改的草稿，并查看提交结果。");
      }
    }

    const restrictions = [];
    if (isDemo) {
      restrictions.push(
        "演示账号仅限本机体验；默认密码必须更换，不能用于正式复核、确认或提交。",
      );
    } else if (credentialLocked) {
      restrictions.push(
        "待换密状态由后端强制锁住确认和提交；请联系管理员更新密码摘要并清除待换密标志。",
      );
    }
    if (!canRead && granted.size) {
      restrictions.push(
        "当前权限组合缺少 read（查看），其他已配置权限不能在网页中独立使用，属于不完整部署配置。",
      );
    } else if (!granted.size) {
      restrictions.push("没有可识别的服务端权限，所有业务操作均已关闭。");
    } else {
      if (!canWrite) {
        restrictions.push(
          "数据、来源或缺项需要修订时，必须转交有 write（编辑）权限的账号。",
        );
      }
      if (!effectiveConfirm) {
        restrictions.push(
          credentialLocked && canConfirm
            ? "当前虽配置 confirm（确认）权限，但凭据限制解除前不会生效。"
            : "正式逐项复核和账号确认必须转交有 confirm（确认）权限的人员。",
        );
      }
      if (!effectiveSubmit) {
        restrictions.push(
          credentialLocked && canSubmit
            ? "当前虽配置 submit（提交）权限，但凭据限制解除前不会生效。"
            : "向监管端报送必须转交有 submit（提交）权限的人员。",
        );
      }
      if (effectiveConfirm && !canWrite) {
        restrictions.push(
          "复核发现错误时请退回经办人修改；修改会使旧确认失效，受影响观测需重新复核。",
        );
      }
      if (effectiveSubmit && !effectiveConfirm) {
        restrictions.push(
          "只能提交他人已确认且之后未改动的版本，不能代替确认人作真实性判断。",
        );
      }
      if (effectiveConfirm && !effectiveSubmit) {
        restrictions.push("完成确认不等于已经报送，仍需提交人员执行并核验监管回执。");
      }
      if (effectiveSubmit) {
        restrictions.push("提交状态未知时先查询记录，不要更换幂等编号盲目重复报送。");
      }
      if (canGovernanceReview && !credentialLocked) {
        capabilities.push("审批或撤销受治理业务记忆，并与提案人保持四眼分离。");
      }
      if (canManageSkills && !credentialLocked) {
        capabilities.push("审批或停用只读技能目录；批准后仍不会自动加载执行。");
      }
    }

    return {
      code,
      title,
      badge,
      summary,
      steps,
      capabilities,
      restrictions,
      permissions: [
        { key: "read", label: "查看", granted: canRead, locked: false },
        { key: "write", label: "编辑", granted: canWrite, locked: false },
        {
          key: "confirm",
          label: "逐项复核与确认",
          granted: canConfirm,
          locked: canConfirm && credentialLocked,
        },
        {
          key: "submit",
          label: "监管提交",
          granted: canSubmit,
          locked: canSubmit && credentialLocked,
        },
        {
          key: "governance_review",
          label: "业务记忆治理",
          granted: canGovernanceReview,
          locked: canGovernanceReview && credentialLocked,
        },
        {
          key: "skill_admin",
          label: "只读技能治理",
          granted: canManageSkills,
          locked: canManageSkills && credentialLocked,
        },
      ],
    };
  }

  function replaceTextList(container, items) {
    const fragment = document.createDocumentFragment();
    items.forEach((item) => fragment.append(el("li", "", item)));
    container.replaceChildren(fragment);
  }

  function renderOperationGuide() {
    const principal = state.principal;
    if (!principal) {
      els.roleGuide.hidden = true;
      els.roleGuide.removeAttribute("data-guide-level");
      els.roleGuide.removeAttribute("data-principal-id");
      els.roleGuideTitle.textContent = "当前账号操作说明";
      els.roleGuideLevelBadge.textContent = "";
      els.roleGuideSummary.textContent = "";
      els.roleGuideContext.textContent = "";
      els.roleGuidePermissions.replaceChildren();
      els.roleGuideSteps.replaceChildren();
      els.roleGuideCapabilities.replaceChildren();
      els.roleGuideRestrictions.replaceChildren();
      return;
    }

    const actorId = String(principal.actor_id || "");
    if (els.roleGuide.dataset.principalId !== actorId) {
      els.roleGuide.open = state.interfaceMode === "professional";
    }
    const guide = principalOperationGuide(principal);
    els.roleGuide.hidden = false;
    els.roleGuide.dataset.guideLevel = guide.code;
    els.roleGuide.dataset.principalId = actorId;
    els.roleGuideTitle.textContent = guide.title;
    els.roleGuideLevelBadge.textContent = guide.badge;
    els.roleGuideSummary.textContent = guide.summary;
    els.roleGuideContext.textContent =
      `当前岗位：${principal.role || "未配置岗位"} · ` +
      `姓名：${principal.name || "未配置姓名"} · ` +
      `账号：${principal.actor_id || "未知账号"}。` +
      "岗位仅用于展示，以下能力按服务端实际授权计算。";

    const permissionFragment = document.createDocumentFragment();
    guide.permissions.forEach((permission) => {
      let stateClass = "is-disabled";
      let stateText = "未授权";
      if (permission.locked) {
        stateClass = "is-locked";
        stateText = "暂锁定";
      } else if (permission.granted) {
        stateClass = "is-enabled";
        stateText = "已授权";
      }
      const badge = el(
        "span",
        `role-guide-permission ${stateClass}`,
        `${permission.label} · ${stateText}`,
      );
      badge.dataset.permission = permission.key;
      permissionFragment.append(badge);
    });
    els.roleGuidePermissions.replaceChildren(permissionFragment);
    replaceTextList(els.roleGuideSteps, guide.steps);
    replaceTextList(els.roleGuideCapabilities, guide.capabilities);
    replaceTextList(els.roleGuideRestrictions, guide.restrictions);
  }

  function renderAuthentication() {
    const principal = state.principal;
    els.identityChip.hidden = !principal;
    els.newDraftButton.disabled =
      !principal || !hasPermission("read") || !hasPermission("write");
    els.welcomeStartButton.disabled =
      !principal || !hasPermission("read") || !hasPermission("write");
    els.welcomeAutofillButton.disabled =
      !principal || !hasPermission("read") || !hasPermission("write");
    els.welcomeNewDraftButton.disabled =
      !principal || !hasPermission("read") || !hasPermission("write");
    els.refreshDraftsButton.disabled = !principal || !hasPermission("read");
    els.agentCenterButton.disabled = !principal || !hasPermission("read");
    els.openAgentCenterQuickButton.disabled = !principal || !hasPermission("read");
    els.credentialNotice.hidden = !credentialRotationRequired();
    els.accessNotice.hidden =
      !principal || hasPermission("write") || credentialRotationRequired();
    els.coalChatButton.disabled = !principal || !hasPermission("read");
    renderOperationGuide();
    if (!principal) {
      els.currentUserName.textContent = "未登录";
      els.currentUserRole.textContent = "—";
      els.identityAvatar.textContent = "企";
      els.identityChip.removeAttribute("title");
      els.identityChip.removeAttribute("aria-label");
      els.demoBadge.hidden = true;
      els.accessNotice.hidden = true;
      renderAgentWorkbenchControls();
      renderAgentV2();
      renderCoalChatControls();
      renderWelcomeActions();
      return;
    }
    els.currentUserName.textContent = principal.name || principal.actor_id;
    els.currentUserRole.textContent = principal.role || "未配置岗位";
    els.identityAvatar.textContent = String(principal.name || "企").slice(0, 1);
    const identityText =
      `${principal.name || "未配置姓名"}，账号 ${principal.actor_id || "未知"}，` +
      `岗位 ${principal.role || "未配置岗位"}`;
    els.identityChip.title = identityText;
    els.identityChip.setAttribute("aria-label", identityText);
    els.demoBadge.hidden = !principal.temporary_demo;
    if (principal.temporary_demo) {
      els.credentialNoticeText.textContent =
        "当前是本机临时演示账号；可用功能以实际权限为准，后端禁止确认、提交。请联系管理员配置个人账号。";
    } else if (principal.must_change_password) {
      els.credentialNoticeText.textContent =
        "当前账号被标记为待换密；可用功能以实际权限为准，后端禁止确认、提交。请联系管理员更新密码摘要。";
    }
    renderAgentWorkbenchControls();
    renderAgentV2();
    renderCoalChatControls();
    renderWelcomeActions();
  }

  function staleSessionError() {
    const error = new Error("会话已变化，旧请求结果已忽略。");
    error.code = "stale_session";
    return error;
  }

  function sessionRequestIsStale(generation, error = null) {
    return (
      generation !== state.sessionGeneration ||
      Boolean(error && error.code === "stale_session")
    );
  }

  async function api(path, options = {}) {
    const requestGeneration = state.sessionGeneration;
    const sessionScoped = options.sessionScoped !== false;
    const method = String(options.method || "GET").toUpperCase();
    const request = {
      method,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(options.headers || {}),
      },
    };
    if (
      state.csrfToken &&
      ["POST", "PATCH", "DELETE"].includes(method) &&
      path !== endpoints.login()
    ) {
      request.headers["X-CSRF-Token"] = state.csrfToken;
    }
    if (Object.prototype.hasOwnProperty.call(options, "body")) {
      request.headers["Content-Type"] = "application/json";
      request.body = JSON.stringify(options.body);
    }
    const controller =
      typeof AbortController === "function" ? new AbortController() : null;
    const timeoutMs = Number(options.timeoutMs || 30000);
    let timeoutId = null;
    if (controller && Number.isFinite(timeoutMs) && timeoutMs > 0) {
      request.signal = controller.signal;
      timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
    }

    let response;
    try {
      response = await fetch(`${API_ROOT}${path}`, request);
    } catch (error) {
      if (sessionScoped && requestGeneration !== state.sessionGeneration) {
        throw staleSessionError();
      }
      if (error && error.name === "AbortError") {
        const timeoutError = new Error(
          "请求等待超时。服务仍可能在处理，请先刷新状态，提交操作不要盲目重复。",
        );
        timeoutError.isTimeout = true;
        timeoutError.code = "client_timeout";
        throw timeoutError;
      }
      setConnection(false);
      throw new Error("无法连接企业填报服务，请确认服务已启动并保持终端运行。");
    } finally {
      if (timeoutId !== null) window.clearTimeout(timeoutId);
    }
    if (sessionScoped && requestGeneration !== state.sessionGeneration) {
      throw staleSessionError();
    }

    const contentType = response.headers.get("content-type") || "";
    let payload = null;
    if (response.status !== 204) {
      if (contentType.includes("application/json")) {
        try {
          payload = await response.json();
        } catch (error) {
          if (sessionScoped && requestGeneration !== state.sessionGeneration) {
            throw staleSessionError();
          }
          throw new Error(`服务返回了无法解析的 JSON（HTTP ${response.status}）。`);
        }
      } else {
        payload = await response.text();
      }
    }

    if (sessionScoped && requestGeneration !== state.sessionGeneration) {
      throw staleSessionError();
    }

    if (!response.ok) {
      const message =
        (payload && typeof payload === "object" && (payload.detail || payload.message)) ||
        (payload &&
          typeof payload === "object" &&
          payload.error &&
          payload.error.message) ||
        (typeof payload === "string" && payload) ||
        `请求失败（${response.status}）`;
      const error = new Error(String(message));
      error.status = response.status;
      error.payload = payload;
      error.code =
        payload && payload.error && typeof payload.error.code === "string"
          ? payload.error.code
          : "";
      if (
        response.status === 401 &&
        !options.suppressAuthRedirect &&
        path !== endpoints.login()
      ) {
        showLogin("登录已失效，请重新登录；本页未保存内容仍保留在浏览器中。", {
          preserveWorkspace:
            Boolean(state.activeDraft) &&
            Boolean(state.dirtyWireFields.size || state.savePromise),
        });
      }
      if (error.code === "credential_rotation_required") {
        renderAuthentication();
      }
      throw error;
    }
    setConnection(true);
    return options.includeResponseMeta
      ? { payload, http_status: response.status }
      : payload;
  }

  function setConnection(online) {
    els.connectionState.classList.toggle("is-online", online);
    els.connectionState.classList.toggle("is-offline", !online);
    els.connectionText.textContent = online ? "企业填报服务已连接" : "企业填报服务未连接";
    if (!online) {
      state.serviceHealth = {
        status: "error",
        message: "无法连接企业填报服务",
      };
      renderOperationalStatus();
    }
  }

  async function loadDrafts(options = {}) {
    if (!state.principal || !hasPermission("read") || state.loading) return;
    const sessionGeneration = state.sessionGeneration;
    const append = Boolean(options.append);
    const offset = append ? state.draftNextOffset : 0;
    if (append && !state.draftHasMore) return;
    state.loading = true;
    state.draftLoadError = "";
    els.refreshDraftsButton.disabled = true;
    els.draftList.setAttribute("aria-busy", "true");
    renderDraftList();
    try {
      const payload = await api(endpoints.draftList(50, offset));
      if (sessionRequestIsStale(sessionGeneration)) return;
      const rows = Array.isArray(payload)
        ? payload
        : payload && Array.isArray(payload.items)
          ? payload.items
          : payload && Array.isArray(payload.drafts)
            ? payload.drafts
            : [];
      const normalized = rows.map(normalizeDraftSummary);
      if (append) {
        const byId = new Map(state.drafts.map((item) => [item.id, item]));
        normalized.forEach((item) => byId.set(item.id, item));
        state.drafts = Array.from(byId.values());
      } else {
        state.drafts = normalized;
      }
      state.draftTotal = Number(
        payload && Number.isFinite(Number(payload.total))
          ? payload.total
          : state.drafts.length,
      );
      state.draftHasMore = Boolean(payload && payload.has_more);
      state.draftNextOffset = Number(
        payload && Number.isFinite(Number(payload.next_offset))
          ? payload.next_offset
          : state.drafts.length,
      );
      state.draftsLoaded = true;
      renderDraftList();
      if (options.openId) {
        await openDraft(options.openId);
      }
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.draftsLoaded = true;
      state.draftLoadError = error.message;
      showToast(error.message, "error");
      renderDraftList();
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.loading = false;
        els.draftList.setAttribute("aria-busy", "false");
        els.refreshDraftsButton.disabled = !hasPermission("read");
        renderDraftList();
      }
    }
  }

  async function createDraft() {
    if (!hasPermission("read") || !hasPermission("write")) {
      showToast("当前账号需要同时具有查看和编辑权限才能新建填报。", "error");
      return;
    }
    if (!(await saveBeforeNavigation())) return;
    state.activeOperation = "新建草稿";
    setBusy(els.newDraftButton, true, "正在新建…");
    setBusy(els.welcomeStartButton, true, "正在新建…");
    setBusy(els.welcomeAutofillButton, true, "正在创建草稿…");
    setBusy(els.welcomeNewDraftButton, true, "正在新建…");
    try {
      const payload = await api(endpoints.drafts(), {
        method: "POST",
        body: {},
      });
      const draft = normalizeDraft(unwrapDraft(payload));
      if (!draft.id) throw new Error("服务未返回草稿编号。");
      state.drafts.unshift(normalizeDraftSummary(draft));
      state.draftTotal += 1;
      state.activeDraft = draft;
      restoreSuggestionsFromDraft(draft);
      applyReviewState(payload && payload.review_state);
      state.step = 1;
      state.undoStack = [];
      state.undoBytes = 0;
      state.dirtyWireFields.clear();
      state.fieldFocusSnapshot = null;
      state.measurementPage = 1;
      state.submitAttempt = null;
      setImportPurpose("source");
      showEditor();
      renderAll();
      showToast("新草稿已创建。");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.newDraftButton, false);
      setBusy(els.welcomeStartButton, false);
      setBusy(els.welcomeAutofillButton, false);
      setBusy(els.welcomeNewDraftButton, false);
      renderAuthentication();
    }
  }

  async function openDraft(draftId) {
    if (!draftId) return;
    if (state.activeDraft && state.activeDraft.id === draftId) return;
    if (!(await saveBeforeNavigation())) return;
    state.activeOperation = "打开草稿";
    try {
      const payload = await api(endpoints.draft(draftId));
      state.activeDraft = normalizeDraft(unwrapDraft(payload));
      restoreSuggestionsFromDraft(state.activeDraft);
      applyReviewState(payload && payload.review_state);
      state.step = state.activeDraft.status === "submitted" ? 6 : suggestedStep(state.activeDraft);
      state.undoStack = [];
      state.undoBytes = 0;
      state.dirtyWireFields.clear();
      state.fieldFocusSnapshot = null;
      state.measurementPage = 1;
      state.submitAttempt = null;
      setImportPurpose("source");
      await loadReviews(draftId);
      showEditor();
      renderAll();
      if (state.step === 6) void loadEvidence();
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
    }
  }

  async function saveBeforeNavigation() {
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请等待完成后再切换草稿。`, "error");
      return false;
    }
    if (!state.activeDraft || state.activeDraft.status === "submitted") return true;
    if (!state.dirtyWireFields.size && !state.savePromise) return true;
    try {
      await flushSave();
      return !state.dirtyWireFields.size;
    } catch {
      showToast("当前草稿仍有未保存内容；为避免丢失，已取消切换。", "error");
      return false;
    }
  }

  function showEditor() {
    els.welcomeCard.hidden = true;
    els.editor.hidden = false;
  }

  function normalizeDraftSummary(raw) {
    const draft = raw || {};
    const enterprise = draft.enterprise || {};
    const receipt = draft.receipt || {};
    const meta = draft._meta || {};
    return {
      id: String(draft.id || draft.draft_id || ""),
      status: normalizeStatus(
        draft.status || (meta.confirmed ? "confirmed" : "draft"),
      ),
      title:
        draft.title ||
        enterprise.name ||
        draft.enterprise_name ||
        "未命名填报",
      mineCode: enterprise.mine_code || draft.mine_code || draft.mine_id || "",
      updatedAt:
        draft.updated_at ||
        draft.created_at ||
        meta.updated_at ||
        meta.created_at ||
        "",
      receiptId:
        receipt.receipt_id ||
        receipt.id ||
        receipt.submission_id ||
        draft.receipt_id ||
        "",
    };
  }

  function normalizeDraft(raw) {
    const source = raw || {};
    const enterprise = source.enterprise || {};
    const reporter = source.reporter || {};
    const period = source.period || {};
    const profile = source.profile || {};
    const meta = source._meta || {};
    const context = source.operational_context || {};
    const signature =
      source.signature ||
      source.confirmation ||
      meta.confirmation ||
      {};
    const fieldProvenance = source.field_provenance || {};
    const measurementRows =
      source.measurements ||
      source.extracted_fields ||
      source.fields ||
      source.observations ||
      [];
    const approvedEvents =
      source.approval_events ||
      context.approval_events ||
      (context.approved_event_codes || []).map((code) => ({ code }));
    const rawSources =
      source.sources ||
      source.source_documents ||
      source.imports ||
      sourcesFromProvenance(fieldProvenance);

    return {
      id: String(source.id || source.draft_id || ""),
      revision: firstDefined(source.revision, source.version, meta.revision, null),
      status: normalizeStatus(
        source.status || (meta.confirmed ? "confirmed" : "draft"),
      ),
      created_at: source.created_at || meta.created_at || "",
      updated_at: source.updated_at || meta.updated_at || "",
      enterprise: {
        id: String(enterprise.id || source.enterprise_id || ""),
        name: String(enterprise.name || source.enterprise_name || ""),
        credit_code: String(
          enterprise.credit_code ||
          enterprise.unified_social_credit_code ||
          source.unified_social_credit_code ||
          source.credit_code ||
          ""
        ),
        mine_code: String(
          enterprise.mine_code || source.mine_code || source.mine_id || "",
        ),
        mine_name: String(enterprise.mine_name || source.mine_name || ""),
      },
      reporter: {
        name: reporter.name || source.reporter_name || "",
        phone: reporter.phone || source.reporter_phone || "",
      },
      period: {
        start: String(period.start || source.window_start || ""),
        end: String(period.end || source.window_end || ""),
      },
      profile: {
        id: String(profile.id || source.profile_id || ""),
        version: String(profile.version || source.profile_version || ""),
      },
      operational_context: {
        regime_code: String(context.regime_code || ""),
        shift_code: String(context.shift_code || ""),
        season_code: String(context.season_code || ""),
        maintenance:
          typeof context.maintenance === "boolean" ? context.maintenance : null,
        approved_event_codes: Array.isArray(context.approved_event_codes)
          ? context.approved_event_codes.map(String)
          : [],
      },
      approval_events: Array.isArray(approvedEvents)
        ? approvedEvents.map(normalizeApprovalEvent)
        : [],
      approval_event_evidence: Array.isArray(
        fieldProvenance["/operational_context/approved_event_codes"],
      )
        ? fieldProvenance["/operational_context/approved_event_codes"].map((item) => ({
            source_name: String(item.source_name || "未命名来源"),
            source_kind: String(item.source_kind || ""),
            locator: String(item.locator || "未提供位置"),
            content_sha256: String(item.content_sha256 || ""),
            extraction_method: String(item.extraction_method || ""),
          }))
        : [],
      field_provenance: clone(fieldProvenance),
      llm_assistance:
        source.llm_assistance && typeof source.llm_assistance === "object"
          ? clone(source.llm_assistance)
          : {
              used: false,
              suggestions: [],
              accepted_field_paths: [],
            },
      sources: normalizeSources(rawSources),
      measurements: Array.isArray(measurementRows)
        ? measurementRows.map((row, index) => {
            const measurement = normalizeMeasurement(row, index, fieldProvenance);
            if (meta.confirmed) measurement.confirmed = true;
            return measurement;
          })
        : [],
      questions: Array.isArray(source.questions)
        ? source.questions.map(normalizeQuestion)
        : [],
      preflight: normalizePreflight(source.preflight || source.validation),
      signature: {
        signer_name:
          signature.signer_name ||
          signature.confirmer_name ||
          signature.name ||
          "",
        signer_title:
          signature.signer_title ||
          signature.confirmer_role ||
          signature.title ||
          signature.role ||
          "",
        method:
          signature.confirmation_method ||
          signature.method ||
          "authenticated_click",
        statement_accepted: Boolean(
          firstDefined(
            signature.statement_accepted,
            signature.accepted,
            meta.confirmed,
            false,
          ),
        ),
        signed_at: signature.signed_at || signature.confirmed_at || "",
        valid: Boolean(
          firstDefined(
            signature.valid,
            signature.signed_at,
            signature.confirmed_at,
            source.status === "confirmed",
            false,
          )
        ),
      },
      receipt: normalizeReceipt(source.receipt || source.submission_receipt),
      notes: String(source.notes || ""),
    };
  }

  function normalizeStatus(status) {
    const value = String(status || "draft").toLowerCase();
    if (["submitted", "accepted", "received"].includes(value)) return "submitted";
    if (["confirmed", "ready", "signed"].includes(value)) return "confirmed";
    if (value === "rejected") return "rejected";
    return "draft";
  }

  function normalizeApprovalEvent(raw) {
    const item = raw || {};
    return {
      code: String(item.code || item.event_code || ""),
      name: String(item.name || item.event_name || ""),
      authority: String(item.authority || item.approving_body || ""),
      approved_at: toLocalDateTime(item.approved_at || item.approval_time || ""),
      source_reference: String(item.source_reference || item.document_ref || ""),
    };
  }

  function sourcesFromProvenance(fieldProvenance) {
    const byIdentity = new Map();
    Object.keys(fieldProvenance || {}).forEach((fieldPath) => {
      const records = Array.isArray(fieldProvenance[fieldPath])
        ? fieldProvenance[fieldPath]
        : [];
      records.forEach((record) => {
        if (!record || typeof record !== "object") return;
        if (
          String(record.source_kind || "").toLowerCase() === "manual" &&
          String(record.extraction_method || "").toLowerCase() === "human_entry"
        ) {
          return;
        }
        const name = String(record.source_name || "未命名来源");
        const digest = String(record.content_sha256 || "");
        const identity = `${name}\u0000${digest}`;
        if (!byIdentity.has(identity)) {
          byIdentity.set(identity, {
            id: digest || name,
            name,
            format: record.source_kind || "manual",
            system: record.extraction_method || "",
            imported_at: record.recorded_at || "",
            digest,
            excerpt: "",
            trusted_statement: true,
          });
        }
      });
    });
    return Array.from(byIdentity.values());
  }

  function normalizeSources(rows) {
    return Array.isArray(rows)
      ? rows.map((row, index) => ({
          id: String(row.id || row.source_id || `source-${index + 1}`),
          name: String(row.name || row.filename || row.source_name || "未命名来源"),
          format: String(row.format || row.type || "text").toLowerCase(),
          system: String(row.system || row.source_system || row.department || ""),
          imported_at: row.imported_at || row.created_at || "",
          digest: String(
            row.digest ||
            row.sha256 ||
            row.content_sha256 ||
            "",
          ),
          excerpt: String(row.excerpt || row.preview || ""),
          trusted_statement: Boolean(
            firstDefined(row.trusted_statement, row.truth_statement, true),
          ),
        }))
      : [];
  }

  function normalizeMeasurement(raw, index, fieldProvenance = {}) {
    const item = raw || {};
    const observation = item.observation || item;
    const valueRecords = fieldProvenance[`/observations/${index}/value`];
    const record =
      Array.isArray(valueRecords) && valueRecords.length
        ? valueRecords[valueRecords.length - 1]
        : {};
    const provenance = item.provenance || item.source || record || {};
    const confidence = normalizeConfidence(
      firstDefined(item.confidence, item.extraction_confidence, provenance.confidence),
    );
    const metricCode = String(
      item.metric_code ||
      item.key ||
      item.field ||
      item.field_key ||
      `field_${index + 1}`,
    );
    return {
      key: metricCode,
      label: String(
        item.label ||
        item.name ||
        item.field_label ||
        friendlyMetricName(metricCode),
      ),
      value:
        item.value === null || item.value === undefined || item.value === ""
          ? ""
          : Number(item.value),
      unit: String(item.unit || "吨"),
      confidence,
      confirmed: Boolean(item.confirmed || item.human_confirmed),
      suggested_by_ai: Boolean(
        firstDefined(item.suggested_by_ai, item.ai_generated, confidence !== null)
      ),
      source: {
        id: String(
          provenance.id ||
          provenance.source_id ||
          observation.source_id ||
          "",
        ),
        name: String(
          provenance.name ||
          provenance.source_name ||
          item.source_name ||
          "未标明来源",
        ),
        location: String(
          provenance.location ||
          provenance.pointer ||
          provenance.locator ||
          item.source_location ||
          "未提供具体位置",
        ),
        excerpt: String(provenance.excerpt || item.source_excerpt || ""),
        digest: String(
          provenance.digest ||
          provenance.sha256 ||
          provenance.content_sha256 ||
          "",
        ),
      },
      observation: {
        source_id: String(observation.source_id || ""),
        observation_id: String(observation.observation_id || ""),
        metric_code: metricCode,
        observed_at: observation.observed_at || "",
        received_at: observation.received_at || "",
        interval_start: firstDefined(observation.interval_start, null),
        interval_end: firstDefined(observation.interval_end, null),
        reset_before: Boolean(observation.reset_before),
        sequence_no: Number.isInteger(observation.sequence_no)
          ? observation.sequence_no
          : 0,
        revision: Number.isInteger(observation.revision)
          ? observation.revision
          : 0,
        payload_sha256: String(observation.payload_sha256 || ""),
        signature: String(observation.signature || ""),
      },
    };
  }

  function friendlyMetricName(metricCode) {
    const known = {
      "coal.opening_inventory_t": "期初库存",
      "coal.production_t": "本期产量",
      "coal.purchase_in_t": "外购调入",
      "coal.sale_out_t": "销售出库",
      "coal.processing_input_t": "洗选投入",
      "coal.processing_output_t": "洗选产出",
      "coal.closing_inventory_t": "期末库存",
      "coal.main_transport_t": "主运输量",
    };
    return known[metricCode] || metricCode || "未命名指标";
  }

  function normalizeConfidence(value) {
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    if (!Number.isFinite(number)) return null;
    return Math.max(0, Math.min(1, number > 1 ? number / 100 : number));
  }

  function normalizeQuestion(raw, index) {
    const item = raw || {};
    const answer = firstDefined(item.answer, item.value, "");
    return {
      id: String(item.id || item.question_id || `question-${index + 1}`),
      field: String(item.field || item.field_key || item.path || ""),
      path: String(item.path || ""),
      prompt: String(item.prompt || item.question || "请补充信息"),
      help: String(item.help || item.reason || ""),
      answer: answer === null || answer === undefined ? "" : String(answer),
      required: item.required !== false,
      multiline: Boolean(item.multiline || item.answer_type === "long_text"),
      resolved: Boolean(item.resolved || String(answer).trim()),
    };
  }

  function normalizeSuggestion(raw, index) {
    const item = raw || {};
    return {
      id: `suggestion-${index + 1}`,
      path: String(item.path || ""),
      value: item.value,
      confidence: normalizeConfidence(item.confidence),
      reason: String(item.reason || "模型未提供说明"),
      source_locator: String(item.source_locator || "未标明位置"),
      advisory_only: true,
    };
  }

  function suggestionIsAdoptable(suggestion, draft) {
    if (!suggestion || !draft) return false;
    const path = String(suggestion.path || "");
    const value = suggestion.value;
    const safeText = (maximum, identifier = false) =>
      typeof value === "string" &&
      value.trim().length > 0 &&
      value.length <= maximum &&
      !/[\u0000-\u001f\u007f]/.test(value) &&
      (!identifier || /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value));
    const textRules = {
      "/enterprise_id": [128, true],
      "/enterprise_name": [256, false],
      "/mine_id": [128, true],
      "/mine_name": [256, false],
      "/profile_id": [128, true],
      "/profile_version": [64, true],
      "/operational_context/regime_code": [64, false],
      "/operational_context/shift_code": [64, false],
      "/operational_context/season_code": [64, false],
    };
    if (textRules[path]) return safeText(...textRules[path]);
    if (path === "/unified_social_credit_code") {
      return (
        typeof value === "string" &&
        /^[0-9A-HJ-NPQRTUWXY]{18}$/.test(value)
      );
    }
    if (path === "/window_start" || path === "/window_end") {
      return (
        typeof value === "string" &&
        value.length <= 64 &&
        /(?:[zZ]|[+-]\d{2}:\d{2})$/.test(value) &&
        Number.isFinite(Date.parse(value))
      );
    }
    if (path === "/operational_context/maintenance") {
      return typeof value === "boolean";
    }
    const match = /^\/observations\/(0|[1-9]\d*)\/([a-z_]+)$/.exec(path);
    if (!match) return false;
    const index = Number(match[1]);
    const measurements = Array.isArray(draft.measurements)
      ? draft.measurements
      : [];
    if (!Number.isSafeInteger(index) || index >= measurements.length) return false;
    const field = match[2];
    if (["source_id", "observation_id", "metric_code"].includes(field)) {
      return safeText(128, true);
    }
    if (field === "unit") return safeText(32);
    if (
      ["observed_at", "received_at", "interval_start", "interval_end"].includes(
        field,
      )
    ) {
      return (
        typeof value === "string" &&
        value.length <= 64 &&
        /(?:[zZ]|[+-]\d{2}:\d{2})$/.test(value) &&
        Number.isFinite(Date.parse(value))
      );
    }
    if (field === "value") {
      return (
        typeof value === "number" &&
        Number.isFinite(value) &&
        Math.abs(value) <= 1_000_000_000_000
      );
    }
    if (field === "reset_before") return typeof value === "boolean";
    if (field === "sequence_no" || field === "revision") {
      return Number.isSafeInteger(value) && value >= 0;
    }
    return false;
  }

  function restoreSuggestionsFromDraft(draft) {
    const assistance = draft && draft.llm_assistance;
    const suggestions =
      assistance && Array.isArray(assistance.suggestions)
        ? assistance.suggestions
        : [];
    const accepted = new Set(
      assistance && Array.isArray(assistance.accepted_field_paths)
        ? assistance.accepted_field_paths.map(String)
        : [],
    );
    state.suggestions = suggestions
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          suggestionIsAdoptable(item, draft) &&
          !accepted.has(String(item.path || "")),
      )
      .map(normalizeSuggestion);
  }

  function normalizePreflight(raw) {
    if (!raw) return null;
    const issueRows = raw.checks || raw.items || raw.findings || raw.issues || [];
    const businessRows = Array.isArray(raw.business_checks)
      ? raw.business_checks.map((item) => ({
          ...item,
          title: item.title || `业务关系：${item.code || "检查项"}`,
          level:
            item.status === "not_evaluated"
              ? "warning"
              : item.status === "failed"
                ? "blocker"
                : item.status,
        }))
      : [];
    const rows = [
      ...(Array.isArray(issueRows) ? issueRows : []),
      ...businessRows,
    ];
    return {
      run_at: raw.run_at || raw.validated_at || "",
      passed: Boolean(firstDefined(raw.passed, raw.valid, false)),
      blockers: Number(
        firstDefined(
          raw.blockers,
          raw.blocking_count,
          rows.filter((item) => normalizeCheckLevel(item.level || item.status) === "blocker")
            .length,
        ),
      ),
      warnings: Number(
        firstDefined(
          raw.warnings,
          raw.warning_count === undefined
            ? undefined
            : Number(raw.warning_count) +
              businessRows.filter((item) => item.level === "warning").length,
          rows.filter((item) => normalizeCheckLevel(item.level || item.status) === "warning")
            .length,
        ),
      ),
      checks: Array.isArray(rows)
        ? rows.map((row, index) => ({
          id: String(row.id || row.code || `check-${index + 1}`),
            title: String(row.title || row.name || row.code || "检查项"),
            message: String(row.message || row.detail || ""),
            level: normalizeCheckLevel(
              row.level ||
              row.status ||
              (row.severity === "blocking" ? "blocker" : row.severity),
            ),
          }))
        : [],
    };
  }

  function normalizeCheckLevel(value) {
    const level = String(value || "").toLowerCase();
    if (["error", "block", "blocker", "failed", "fail"].includes(level)) return "blocker";
    if (["warn", "warning", "review", "not_evaluated"].includes(level)) return "warning";
    return "pass";
  }

  function normalizeReceipt(raw) {
    if (!raw) return null;
    return {
      receipt_id: String(raw.receipt_id || raw.id || raw.submission_id || ""),
      received_at: raw.received_at || raw.submitted_at || raw.created_at || "",
      platform: String(raw.platform || raw.receiver || "辅助监察监管平台"),
      payload_sha256: String(raw.payload_sha256 || raw.digest || raw.sha256 || ""),
      status: String(raw.status || "received"),
      message: String(raw.message || ""),
      raw: clone(raw.raw && typeof raw.raw === "object" ? raw.raw : raw),
    };
  }

  function unwrapDraft(payload) {
    if (!payload || typeof payload !== "object") return payload || {};
    return payload.draft || payload.item || payload;
  }

  function toDraftPayload(draft, wireFields) {
    const observations = draft.measurements.map((item) => ({
      ...clone(item.observation),
      source_id: item.observation.source_id || "",
      observation_id: item.observation.observation_id || "",
      metric_code: item.key,
      value: item.value,
      unit: item.unit,
      observed_at: item.observation.observed_at || "",
      received_at: item.observation.received_at || "",
    }));
    const allFields = {
      enterprise_id: draft.enterprise.id.trim(),
      enterprise_name: draft.enterprise.name.trim(),
      unified_social_credit_code: draft.enterprise.credit_code.trim().toUpperCase(),
      mine_id: draft.enterprise.mine_code.trim(),
      mine_name: draft.enterprise.mine_name.trim(),
      window_start: toWireDateTime(draft.period.start),
      window_end: toWireDateTime(draft.period.end),
      profile_id: draft.profile.id.trim(),
      profile_version: draft.profile.version.trim(),
      operational_context: {
        ...clone(draft.operational_context),
        approved_event_codes: draft.approval_events
          .map((event) => event.code.trim())
          .filter(Boolean),
      },
      observations,
      notes: draft.notes,
    };
    const patch = {};
    wireFields.forEach((field) => {
      if (Object.prototype.hasOwnProperty.call(allFields, field)) {
        patch[field] = allFields[field];
      }
    });
    return {
      expected_revision: draft.revision,
      patch,
    };
  }

  function renderAll() {
    if (!state.activeDraft) return;
    renderDraftHeader();
    renderDraftList();
    populateForm();
    renderApprovalEvents();
    renderSources();
    renderMeasurements();
    renderQuestions();
    renderPreflight();
    renderConfirmation();
    renderSubmission();
    renderStepper();
    lockSubmittedDraft();
    renderAgentWorkbenchControls();
    renderAgentV2();
    renderCoalChatControls();
  }

  function renderDraftHeader() {
    const draft = state.activeDraft;
    els.draftTitle.textContent =
      draft.enterprise.name ||
      (draft.enterprise.mine_code ? `${draft.enterprise.mine_code} 填报` : "新填报");
    els.draftStatus.textContent = statusLabels[draft.status] || "草稿";
    els.draftStatus.className = `status-badge status-${draft.status}`;
    const updated = draft.updated_at ? formatDateTime(draft.updated_at) : "尚未保存时间";
    els.draftMeta.textContent = `草稿编号 ${draft.id} · 更新于 ${updated}`;
    els.deleteDraftButton.disabled = draft.status !== "draft";
    els.undoButton.disabled = state.undoStack.length === 0 || draft.status === "submitted";
  }

  function renderWelcomeActions() {
    const resumable = state.drafts.find((draft) => draft.status !== "submitted");
    const canCreate =
      Boolean(state.principal) &&
      hasPermission("read") &&
      hasPermission("write");
    if (resumable && state.principal && hasPermission("read")) {
      els.welcomeStartButton.dataset.draftId = resumable.id;
      els.welcomeStartButton.textContent =
        `继续未完成填报：${truncateText(resumable.title || "未命名草稿", 22)}`;
      els.welcomeStartButton.disabled = false;
      els.welcomeAutofillButton.textContent = "让 Agent 补全这份草稿";
      els.welcomeAutofillButton.disabled = !canCreate;
      els.welcomeNewDraftButton.hidden = !canCreate;
      els.welcomeNewDraftButton.disabled = !canCreate;
      els.welcomeActionHint.textContent =
        "已找到未完成的填报，建议先继续处理，避免同一统计期重复新建。";
      return;
    }
    delete els.welcomeStartButton.dataset.draftId;
    els.welcomeStartButton.textContent = "开始一份新填报";
    els.welcomeStartButton.disabled = !canCreate;
    els.welcomeAutofillButton.textContent = "让 Agent 从材料自动填入";
    els.welcomeAutofillButton.disabled = !canCreate;
    els.welcomeNewDraftButton.hidden = true;
    els.welcomeActionHint.textContent = canCreate
      ? "当前没有未完成填报，可以开始新建。"
      : "当前账号不能新建填报，请查看账号操作说明。";
  }

  async function handleWelcomePrimaryAction() {
    const draftId = String(els.welcomeStartButton.dataset.draftId || "");
    if (draftId) {
      await openDraft(draftId);
      return;
    }
    await createDraft();
  }

  async function handleWelcomeAutofillAction() {
    if (!hasPermission("read") || !hasPermission("write")) {
      showToast("当前账号需要查看和编辑权限才能让 Agent 自动填入草稿。", "error");
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    setBusy(els.welcomeAutofillButton, true, "正在准备…");
    try {
      const resumable = state.drafts.find((draft) => draft.status !== "submitted");
      if (resumable) {
        await openDraft(resumable.id);
      } else {
        await createDraft();
      }
      if (!state.activeDraft || state.activeDraft.status === "submitted") return;
      goToStep(2);
      showToast(
        "请选择 ERP、MES、地磅或化验系统导出的 JSON/CSV；Agent 会自动写入可验证字段。",
      );
      els.chooseFileButton.focus();
    } finally {
      setBusy(els.welcomeAutofillButton, false);
    }
  }

  function renderDraftList() {
    renderWelcomeActions();
    const knownTotal = Math.max(state.draftTotal, state.drafts.length);
    els.draftListSummary.textContent = state.loading && state.drafts.length
      ? `正在加载更多…已显示 ${state.drafts.length}/${knownTotal} 份`
      : state.draftsLoaded
        ? `已显示 ${state.drafts.length}/${knownTotal} 份`
        : "尚未加载草稿";
    els.loadMoreDraftsButton.hidden = !state.draftHasMore;
    els.loadMoreDraftsButton.disabled = state.loading;
    const rows = state.drafts.filter((draft) => {
      const matchesFilter =
        state.filter === "all" ||
        (state.filter === "draft" && draft.status !== "submitted") ||
        (state.filter === "submitted" && draft.status === "submitted");
      const haystack = `${draft.title} ${draft.mineCode} ${draft.receiptId}`.toLocaleLowerCase(
        "zh-CN",
      );
      return matchesFilter && (!state.search || haystack.includes(state.search));
    });

    const fragment = document.createDocumentFragment();
    if (state.loading && !state.drafts.length) {
      fragment.append(el("p", "draft-empty", "正在读取草稿，请稍候…"));
      els.draftList.replaceChildren(fragment);
      els.draftEmpty.hidden = true;
      return;
    }
    if (state.draftLoadError && !state.drafts.length) {
      const errorState = el("div", "draft-empty");
      errorState.append(
        el("h3", "", "草稿列表加载失败"),
        el("p", "", state.draftLoadError),
      );
      const retry = el("button", "button button-secondary", "重新加载");
      retry.type = "button";
      retry.addEventListener("click", () => void loadDrafts());
      errorState.append(retry);
      fragment.append(errorState);
      els.draftList.replaceChildren(fragment);
      els.draftEmpty.hidden = true;
      return;
    }
    rows.forEach((draft) => {
      const button = el("button", "draft-item");
      button.type = "button";
      button.classList.toggle(
        "is-active",
        Boolean(state.activeDraft && draft.id === state.activeDraft.id),
      );
      if (state.activeDraft && draft.id === state.activeDraft.id) {
        button.setAttribute("aria-current", "true");
      }
      button.addEventListener("click", () => void openDraft(draft.id));

      const head = el("div", "draft-item-head");
      head.append(
        el("strong", "", draft.title),
        el(
          "span",
          `mini-status ${draft.status}`,
          statusLabels[draft.status] || "草稿",
        ),
      );
      const detail =
        draft.status === "submitted" && draft.receiptId
          ? `回执 ${draft.receiptId}`
          : [draft.mineCode, formatDateTime(draft.updatedAt)].filter(Boolean).join(" · ") ||
            "刚刚创建";
      button.append(head, el("p", "", detail));
      fragment.append(button);
    });

    els.draftList.replaceChildren(fragment);
    els.draftEmpty.hidden = rows.length > 0;
    if (!rows.length) {
      const cannotRead = Boolean(state.principal && !hasPermission("read"));
      const narrowed = Boolean(state.drafts.length && (state.search || state.filter !== "all"));
      els.draftEmptyTitle.textContent = cannotRead
        ? "当前账号不能查看草稿"
        : narrowed
        ? "没有符合条件的填报"
        : state.draftsLoaded
          ? "还没有填报"
          : "正在读取草稿";
      els.draftEmptyText.textContent = cannotRead
        ? "网页端需要 read（查看）权限，请联系管理员补齐后重新登录。"
        : narrowed
        ? "清除搜索或切换到“全部”查看其他填报。"
        : hasPermission("read") && hasPermission("write")
          ? "点击“新建填报”，助手会带您逐步完成。"
          : "当前账号不能新建填报，请查看上方账号操作说明。";
      els.clearDraftFilterButton.hidden = !narrowed;
    }
  }

  function clearDraftFilters() {
    state.search = "";
    state.filter = "all";
    els.draftSearch.value = "";
    document.querySelectorAll(".draft-tab").forEach((tab) => {
      const active = tab.dataset.filter === "all";
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    });
    renderDraftList();
  }

  function populateForm() {
    const draft = state.activeDraft;
    setNamedValue("enterprise.id", draft.enterprise.id);
    setNamedValue("enterprise.name", draft.enterprise.name);
    setNamedValue("enterprise.credit_code", draft.enterprise.credit_code);
    setNamedValue("enterprise.mine_code", draft.enterprise.mine_code);
    setNamedValue("enterprise.mine_name", draft.enterprise.mine_name);
    setNamedValue("period.start", toLocalDateTime(draft.period.start));
    setNamedValue("period.end", toLocalDateTime(draft.period.end));
    setNamedValue("profile.id", draft.profile.id);
    setNamedValue("profile.version", draft.profile.version);
    setNamedValue(
      "operational_context.regime_code",
      draft.operational_context.regime_code,
    );
    setNamedValue(
      "operational_context.shift_code",
      draft.operational_context.shift_code,
    );
    setNamedValue(
      "operational_context.season_code",
      draft.operational_context.season_code,
    );
    setNamedValue(
      "operational_context.maintenance",
      draft.operational_context.maintenance === null
        ? ""
        : String(draft.operational_context.maintenance),
    );
    const statement = els.draftForm.elements.namedItem("signature.statement_accepted");
    if (statement) statement.checked = draft.signature.statement_accepted;
  }

  function setNamedValue(name, value) {
    const field = els.draftForm.elements.namedItem(name);
    if (field) field.value = value === null || value === undefined ? "" : value;
  }

  function handleFormInput(event) {
    if (!state.activeDraft || state.activeDraft.status === "submitted") return;
    if (!isDraftField(event.target)) return;
    const changed = applyNamedField(event.target);
    if (!changed) return;
    markWireFieldDirty(event.target.name);
    markDraftChanged();
    if (wireFieldForFormName(event.target.name)) scheduleSave();
    if (String(event.target.name).startsWith("signature.")) {
      invalidateSignature();
      renderConfirmation();
      renderSubmission();
    }
  }

  function handleFormChange(event) {
    if (!state.activeDraft || state.activeDraft.status === "submitted") return;
    if (!isDraftField(event.target)) return;
    if (state.fieldFocusSnapshot) {
      pushUndo(state.fieldFocusSnapshot);
      state.fieldFocusSnapshot = null;
    }
    const changed = applyNamedField(event.target);
    if (!changed) return;
    markWireFieldDirty(event.target.name);
    markDraftChanged();
    if (wireFieldForFormName(event.target.name)) scheduleSave();
  }

  function isDraftField(target) {
    return target instanceof HTMLInputElement ||
      target instanceof HTMLSelectElement ||
      target instanceof HTMLTextAreaElement;
  }

  function applyNamedField(field) {
    const name = field.name;
    if (!name || !state.activeDraft) return false;
    let value = field.type === "checkbox" ? field.checked : field.value;
    if (name === "operational_context.maintenance") {
      value = value === "" ? null : value === "true";
    }
    if (getPath(state.activeDraft, name) === value) return false;
    setPath(state.activeDraft, name, value);
    if (!name.startsWith("signature.")) invalidatePreflightAndSignature();
    return true;
  }

  function wireFieldForFormName(name) {
    const map = {
      "enterprise.id": "enterprise_id",
      "enterprise.name": "enterprise_name",
      "enterprise.credit_code": "unified_social_credit_code",
      "enterprise.mine_code": "mine_id",
      "enterprise.mine_name": "mine_name",
      "period.start": "window_start",
      "period.end": "window_end",
      "profile.id": "profile_id",
      "profile.version": "profile_version",
    };
    if (String(name).startsWith("operational_context.")) {
      return "operational_context";
    }
    return map[name] || "";
  }

  function markWireFieldDirty(name) {
    const field = wireFieldForFormName(name);
    if (field) state.dirtyWireFields.add(field);
  }

  function invalidatePreflightAndSignature() {
    state.activeDraft.preflight = null;
    invalidateSignature();
  }

  function invalidateSignature() {
    if (!state.activeDraft) return;
    state.activeDraft.signature.signed_at = "";
    state.activeDraft.signature.valid = false;
    if (state.activeDraft.status === "confirmed") state.activeDraft.status = "draft";
  }

  function renderApprovalEvents() {
    const events = state.activeDraft ? state.activeDraft.approval_events : [];
    const evidence = state.activeDraft
      ? (state.activeDraft.approval_event_evidence || []).filter(
          (record) =>
            !(
              record.source_kind.toLowerCase() === "manual" &&
              record.extraction_method.toLowerCase() === "human_entry"
            ) &&
            Boolean(record.content_sha256),
        )
      : [];
    const record = evidence.length ? evidence[evidence.length - 1] : null;
    const fragment = document.createDocumentFragment();
    if (!events.length) {
      const row = el("div", `event-row ${record ? "has-evidence" : "missing-evidence"}`);
      const body = el("div", "event-evidence");
      body.append(
        el(
          "strong",
          "",
          record ? "已导入空事件集合快照" : "尚未导入监管事件快照",
        ),
        el(
          "small",
          record ? "" : "text-warning",
          record
            ? `来源：${record.source_name} · ${record.locator} · 摘要 ${shortDigest(record.content_sha256)}`
            : "即使监管查询结果为空，也必须导入 event_codes: [] 的已登记快照，否则不能提交。",
        ),
      );
      row.append(body);
      fragment.append(row);
    }
    events.forEach((eventItem, index) => {
      const row = el("div", "event-row");
      row.dataset.eventIndex = String(index);
      const body = el("div", "event-evidence");
      body.append(el("strong", "", eventItem.code || `事件 ${index + 1}`));
      if (record) {
        body.append(
          el(
            "small",
            "",
            `来源：${record.source_name} · ${record.locator}` +
              (record.content_sha256
                ? ` · 摘要 ${shortDigest(record.content_sha256)}`
                : ""),
          ),
        );
      } else {
        body.append(
          el(
            "small",
            "text-warning",
            "未找到可追溯审批材料；该事件不能作为已验证例外提交。",
          ),
        );
      }
      row.append(body);
      fragment.append(row);
    });
    els.approvalEventList.replaceChildren(fragment);
  }

  function hasRegulatorEventSnapshot(draft) {
    return Boolean(
      draft &&
        Array.isArray(draft.approval_event_evidence) &&
        draft.approval_event_evidence.some(
          (record) =>
            record &&
            !(
              String(record.source_kind || "").toLowerCase() === "manual" &&
              String(record.extraction_method || "").toLowerCase() ===
                "human_entry"
            ) &&
            Boolean(String(record.content_sha256 || "").trim()),
        ),
    );
  }

  function guideToApprovalImport() {
    if (!state.activeDraft || state.activeDraft.status === "submitted") return;
    setImportPurpose("event_snapshot");
    setImportFormat("json");
    goToStep(2);
    showToast("请导入监管端登记的事件快照 JSON；证据摘要和统计窗口必须完全匹配。");
  }

  function downloadEventSnapshotTemplate() {
    const draft = state.activeDraft;
    const template = {
      snapshot_id: "",
      mine_id: draft ? draft.enterprise.mine_code : "",
      window_start: draft ? toWireDateTime(draft.period.start) : "",
      window_end: draft ? toWireDateTime(draft.period.end) : "",
      event_codes: [],
      evidence_sha256: "",
      source_system: "",
      record_id: "",
    };
    downloadTextFile(
      "监管事件快照导入模板.json",
      `${JSON.stringify(template, null, 2)}\n`,
      "application/json;charset=utf-8",
    );
    showToast("事件快照模板已下载；请由监管登记流程填写证据摘要，不要自行编造。");
  }

  function setImportPurpose(purpose) {
    state.importPurpose = purpose === "event_snapshot" ? "event_snapshot" : "source";
    const eventMode = state.importPurpose === "event_snapshot";
    els.eventSnapshotImportNotice.hidden = !eventMode;
    els.sourceMetaGrid.hidden = eventMode;
    document.querySelectorAll(".import-option").forEach((button) => {
      if (eventMode) {
        button.disabled = button.dataset.importFormat !== "json";
      } else if (button.dataset.importFormat === "text") {
        button.disabled = !Boolean(
          state.serviceHealth && state.serviceHealth.llm_mode === "configured",
        );
      } else {
        button.disabled = false;
      }
    });
    if (eventMode) {
      setImportFormat("json");
      els.fileHint.textContent = "当前仅支持监管事件快照 .json 文件，单个文件不超过 2 MiB";
      els.pasteLabel.textContent = "粘贴监管事件快照 JSON";
      els.importButton.textContent = "导入监管事件快照";
    } else {
      els.importButton.textContent = "让 Agent 自动填入草稿";
      setImportFormat(state.importFormat);
    }
  }

  function setImportFormat(format) {
    const requested = ["json", "csv", "text"].includes(format) ? format : "json";
    const llmConfigured = Boolean(
      state.serviceHealth && state.serviceHealth.llm_mode === "configured",
    );
    state.importFormat =
      state.importPurpose === "event_snapshot"
        ? "json"
        : requested === "text" && !llmConfigured
          ? "json"
          : requested;
    document.querySelectorAll(".import-option").forEach((button) => {
      const active = button.dataset.importFormat === state.importFormat;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
    });
    const labels = {
      json: ["当前支持 .json 文件，单个文件不超过 2 MiB", "粘贴 JSON 内容"],
      csv: ["当前支持 .csv 文件，第一行应为字段名，单个文件不超过 2 MiB", "粘贴 CSV 表格内容"],
      text: ["当前支持 .txt 文件，模型辅助内容不超过 256 KiB", "粘贴台账片段或业务说明"],
    };
    els.fileHint.textContent = labels[state.importFormat][0];
    els.pasteLabel.textContent = labels[state.importFormat][1];
    els.sourceFile.accept =
      state.importFormat === "json"
        ? ".json,application/json"
        : state.importFormat === "csv"
          ? ".csv,text/csv"
          : ".txt,text/plain";
    if (state.importPurpose === "event_snapshot") {
      els.fileHint.textContent = "当前仅支持监管事件快照 .json 文件，单个文件不超过 2 MiB";
      els.pasteLabel.textContent = "粘贴监管事件快照 JSON";
    }
  }

  async function readSelectedFile() {
    const file = els.sourceFile.files && els.sourceFile.files[0];
    if (file) await readFile(file);
  }

  async function readFile(file) {
    const sessionGeneration = state.sessionGeneration;
    const draftId = state.activeDraft && state.activeDraft.id;
    if (
      !state.principal ||
      !draftId ||
      !hasPermission("read") ||
      !hasPermission("write")
    ) {
      return;
    }
    if (file.name.length > 255) {
      showToast("文件名超过 255 个字符，请先在本机缩短文件名再导入。", "error");
      return;
    }
    const extension = file.name.split(".").pop().toLowerCase();
    const format = extension === "txt" ? "text" : extension;
    if (state.importPurpose === "event_snapshot" && extension !== "json") {
      showToast("监管事件快照只接受 .json 文件，请使用专用模板。", "error");
      return;
    }
    if (
      format === "text" &&
      (!state.serviceHealth || state.serviceHealth.llm_mode !== "configured")
    ) {
      showToast("当前未配置智能模型，不能从自由文字提取字段。请改用 JSON 或 CSV。", "error");
      return;
    }
    const maxClientSize =
      format === "text" ? 256 * 1024 : 2 * 1024 * 1024;
    if (file.size > maxClientSize) {
      showToast(
        format === "text"
          ? "文字材料超过 256 KiB，请拆分后仅提交必要片段。"
          : "文件超过服务端 2 MiB 限制，请拆分后导入。",
        "error",
      );
      return;
    }
    if (["json", "csv", "txt"].includes(extension)) {
      setImportFormat(extension === "txt" ? "text" : extension);
    }
    try {
      const content = await file.text();
      if (
        sessionRequestIsStale(sessionGeneration) ||
        !state.activeDraft ||
        state.activeDraft.id !== draftId
      ) {
        return;
      }
      state.selectedFile = file;
      els.sourceContent.value = content;
      if (!els.sourceName.value.trim()) els.sourceName.value = file.name;
      showToast(`已读取 ${file.name}，请确认来源后导入。`);
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      showToast("无法读取该文件，请换一个文本、CSV 或 JSON 文件。", "error");
    }
  }

  function validateImportInput() {
    const content = els.sourceContent.value.trim();
    if (!content) return "请选择文件或粘贴数据内容。";
    if (state.importPurpose !== "event_snapshot") {
      const sourceName = els.sourceName.value.trim();
      if (!sourceName) return "请填写来源名称。";
      if (
        sourceName.length > 255 ||
        [".", ".."].includes(sourceName) ||
        /[\/\\\u0000-\u001f\u007f]/.test(sourceName)
      ) {
        return "来源名称须为 1–255 个字符，且不能含 /、\\ 或控制字符。";
      }
      if (els.sourceSystem.value.trim().length > 128) {
        return "来源系统/部门不能超过 128 个字符。";
      }
    }
    if (!els.sourceTruthStatement.checked) {
      return "请先确认材料来自所标注的真实业务或监管来源。";
    }
    if (
      state.importFormat === "text" &&
      (!state.serviceHealth || state.serviceHealth.llm_mode !== "configured")
    ) {
      return "当前未配置智能模型，文字材料不会产生可用提取结果；请改用 JSON 或 CSV。";
    }
    const byteLength = new Blob([content]).size;
    const limit = state.importFormat === "text" ? 256 * 1024 : 2 * 1024 * 1024;
    if (byteLength > limit) {
      return state.importFormat === "text"
        ? "文字材料超过 256 KiB，请拆分后重试。"
        : "导入内容超过服务端 2 MiB 限制，请拆分后重试。";
    }
    if (state.importFormat === "json") {
      try {
        const parsed = parseJsonContent(content);
        if (state.importPurpose === "event_snapshot") {
          const snapshotError = validateEventSnapshotShape(parsed);
          if (snapshotError) return snapshotError;
        }
      } catch {
        return "JSON 格式无法解析，请检查逗号、引号和括号。";
      }
    }
    if (state.importFormat === "csv") {
      const rows = parseCsv(content);
      if (rows.length < 2 || rows[0].length < 2) {
        return "CSV 至少需要一行字段名和一行数据。";
      }
    }
    return "";
  }

  function validateEventSnapshotShape(snapshot) {
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
      return "监管事件快照必须是一个 JSON 对象。";
    }
    const required = [
      "snapshot_id",
      "mine_id",
      "window_start",
      "window_end",
      "event_codes",
      "evidence_sha256",
      "source_system",
      "record_id",
    ];
    const missing = required.filter(
      (field) => !Object.prototype.hasOwnProperty.call(snapshot, field),
    );
    if (missing.length) return `监管事件快照缺少字段：${missing.join("、")}。`;
    if (
      !Array.isArray(snapshot.event_codes) ||
      snapshot.event_codes.length > 32 ||
      snapshot.event_codes.some(
        (code) => typeof code !== "string" || !code.trim() || code.length > 64,
      )
    ) {
      return "event_codes 必须是最多 32 个非空事件编码组成的数组。";
    }
    if (!/^[0-9a-f]{64}$/.test(String(snapshot.evidence_sha256 || ""))) {
      return "evidence_sha256 必须是监管端给出的 64 位小写十六进制摘要。";
    }
    return "";
  }

  function parseJsonContent(content) {
    return JSON.parse(String(content).replace(/^\uFEFF/, ""));
  }

  async function importSource() {
    if (!state.activeDraft || !hasPermission("write")) {
      showToast("当前账号没有导入和编辑权限。", "error");
      return;
    }
    const validationMessage = validateImportInput();
    if (validationMessage) {
      showToast(validationMessage, "error");
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    const eventSnapshotMode = state.importPurpose === "event_snapshot";
    state.activeOperation = eventSnapshotMode ? "导入监管事件快照" : "导入来源";
    setBusy(els.importButton, true, "正在导入…");
    try {
      await flushSave();
      const content = els.sourceContent.value;
      if (eventSnapshotMode) {
        const payload = await api(endpoints.eventSnapshot(state.activeDraft.id), {
          method: "POST",
          body: {
            snapshot: parseJsonContent(content),
            expected_revision: state.activeDraft.revision,
          },
        });
        applyServerDraft(payload);
        clearImportInput();
        setImportPurpose("source");
        renderAll();
        showToast("监管事件快照已按专用接口导入并留痕。");
        goToStep(1);
        return;
      }
      const sourceName = els.sourceName.value.trim();
      state.lastAssistContent = content;
      state.lastAssistFormat = state.importFormat;
      state.assistantSource = {
        id: "",
        name: sourceName,
        location: "智能助手标注的位置",
        excerpt: "",
        digest: "",
      };
      if (state.importFormat !== "text") {
        const payload = await api(endpoints.importSource(state.activeDraft.id), {
          method: "POST",
          body: {
            format: state.importFormat,
            content,
            source_name: sourceName,
            source_system: els.sourceSystem.value.trim(),
            truth_statement: true,
            original_filename: state.selectedFile ? state.selectedFile.name : null,
            expected_revision: state.activeDraft.revision,
          },
        });
        applyServerDraft(payload);
      }
      clearImportInput();
      renderAll();
      showToast(
        state.importFormat === "text"
          ? "文字材料已交给助手读取，结果仍需人工核对。"
          : "来源已导入并自动写入草稿，正在检查缺项和来源完整性。",
      );
      await runAssistant({
        quietStart: true,
        content,
        format: state.lastAssistFormat,
        allowWithoutPersistedSource: state.importFormat === "text",
        parentOperation: true,
      });
      goToStep(3);
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.importButton, false);
      setImportPurpose(state.importPurpose);
      lockSubmittedDraft();
    }
  }

  async function runAssistant(options = {}) {
    if (!state.activeDraft) return;
    if (
      !state.activeDraft.sources.length &&
      !state.lastAssistContent &&
      !options.allowWithoutPersistedSource
    ) {
      showToast("请先导入至少一份真实来源材料。", "error");
      return;
    }
    const assistContent = options.content || state.lastAssistContent || "";
    if (!assistContent && !options.allowRulesOnly) {
      showToast("为保护原材料，页面不会长期保存待提取全文。请在第 2 步重新选择或粘贴材料。", "error");
      return;
    }
    if (state.activeOperation && !options.parentOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    const ownsOperation = !state.activeOperation;
    if (ownsOperation) state.activeOperation = "智能提取";
    setBusy(els.runAssistButton, true, "正在提取…");
    if (!options.quietStart) showToast("智能助手正在读取已导入材料，请稍候。");
    try {
      await flushSave();
      const payload = await api(endpoints.assist(state.activeDraft.id), {
        method: "POST",
        timeoutMs: 75000,
        body: {
          content: assistContent,
          format: options.format || state.lastAssistFormat || "text",
          expected_revision: state.activeDraft.revision,
        },
      });
      applyServerDraft(payload);
      state.suggestions =
        payload && Array.isArray(payload.suggestions)
          ? payload.suggestions
              .map(normalizeSuggestion)
              .filter((item) => suggestionIsAdoptable(item, state.activeDraft))
          : [];
      await refreshQuestions();
      renderAll();
      const count = state.activeDraft.measurements.length;
      const suggestionCount = state.suggestions.length;
      const llmUsed = Boolean(
        payload && (payload.llm_used === true || payload.mode === "llm"),
      );
      showToast(
        suggestionCount
          ? `智能提取完成：有 ${suggestionCount} 条建议等待您决定是否采用。`
          : llmUsed
            ? "模型未找到可引用字段。请检查材料内容和格式，或手工填写对应业务字段。"
            : `规则检查完成：当前有 ${count} 个待核对数字。`,
      );
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      if (ownsOperation) state.activeOperation = "";
      setBusy(els.runAssistButton, false);
      if (state.activeDraft) lockSubmittedDraft();
    }
  }

  async function refreshQuestions() {
    if (!state.activeDraft) return;
    try {
      const payload = await api(endpoints.questions(state.activeDraft.id));
      const rows = Array.isArray(payload)
        ? payload
        : (payload && (payload.questions || payload.items)) || [];
      state.activeDraft.questions = rows.map(normalizeQuestion);
    } catch (error) {
      if (error.status !== 404) throw error;
    }
  }

  async function loadReviews(draftId = state.activeDraft && state.activeDraft.id) {
    if (!draftId || !state.principal || !hasPermission("read")) return;
    const sessionGeneration = state.sessionGeneration;
    state.reviewLoading = true;
    renderReviewHint();
    try {
      const payload = await api(endpoints.reviews(draftId));
      if (sessionRequestIsStale(sessionGeneration)) return;
      if (!state.activeDraft || state.activeDraft.id !== draftId) return;
      applyReviewState(payload && payload.review_state);
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      if (error.status !== 404) {
        showToast(`逐项核对状态加载失败：${error.message}`, "error");
      }
      applyReviewState(null);
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.reviewLoading = false;
        if (state.activeDraft && state.activeDraft.id === draftId) {
          renderMeasurements();
          renderConfirmation();
          renderSubmission();
          renderReviewHint();
        }
      }
    }
  }

  function applyReviewState(raw) {
    if (!raw || typeof raw !== "object") {
      state.reviewState = null;
      if (state.activeDraft && !state.activeDraft.signature.valid) {
        state.activeDraft.measurements.forEach((measurement) => {
          measurement.confirmed = false;
        });
      }
      return;
    }
    const rows = Array.isArray(raw.observations) ? raw.observations : [];
    state.reviewState = {
      revision: firstDefined(raw.revision, state.activeDraft && state.activeDraft.revision, null),
      reviewer_id: String(raw.reviewer_id || ""),
      total: Number(firstDefined(raw.total, rows.length, 0)),
      reviewed_count: Number(
        firstDefined(raw.reviewed_count, rows.filter((item) => item.reviewed).length, 0),
      ),
      all_reviewed: Boolean(raw.all_reviewed),
      observations: rows.map((item) => ({
        observation_id: String(item.observation_id || ""),
        reviewed: Boolean(item.reviewed),
        reviewed_by: String(item.reviewed_by || ""),
        reviewed_at: item.reviewed_at || "",
      })),
    };
    if (!state.activeDraft) return;
    const byId = new Map(
      state.reviewState.observations.map((item) => [
        item.observation_id,
        item.reviewed,
      ]),
    );
    state.activeDraft.measurements.forEach((measurement) => {
      const observationId = measurement.observation.observation_id;
      measurement.confirmed = state.activeDraft.signature.valid
        ? true
        : Boolean(observationId && byId.get(observationId));
    });
  }

  async function setMeasurementReviews(observationIds, reviewed) {
    if (
      !state.activeDraft ||
      state.activeDraft.status === "submitted" ||
      !canFinalizeWith("confirm")
    ) {
      showToast(
        credentialRotationRequired()
          ? "临时或待换密账号不能记录正式核对。"
          : "当前账号没有逐项核对权限。",
        "error",
      );
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    const ids = Array.from(
      new Set(observationIds.map(String).filter((value) => value.trim())),
    );
    if (!ids.length) {
      showToast("观测缺少 observation_id，无法留下可审计核对记录。", "error");
      return;
    }
    state.activeOperation = "保存核对记录";
    state.reviewLoading = true;
    renderMeasurements();
    renderReviewHint();
    try {
      await flushSave();
      const payload = await api(endpoints.reviews(state.activeDraft.id), {
        method: "POST",
        body: {
          observation_ids: ids,
          reviewed: Boolean(reviewed),
          expected_revision: state.activeDraft.revision,
        },
      });
      applyReviewState(payload && payload.review_state);
      renderMeasurements();
      renderConfirmation();
      renderSubmission();
      showToast(reviewed ? `已保存 ${ids.length} 项核对记录。` : "已撤销核对记录。");
    } catch (error) {
      showToast(`核对状态未保存：${error.message}`, "error");
      await loadReviews();
    } finally {
      state.activeOperation = "";
      state.reviewLoading = false;
      renderMeasurements();
      renderReviewHint();
    }
  }

  function renderReviewHint() {
    if (!els.reviewPersistenceHint) return;
    if (state.reviewLoading) {
      els.reviewPersistenceHint.textContent = "正在保存或读取可审计核对状态…";
    } else if (credentialRotationRequired()) {
      els.reviewPersistenceHint.textContent =
        "临时或待换密账号不能留下正式核对记录；请使用企业个人账号。";
    } else if (!hasPermission("confirm")) {
      els.reviewPersistenceHint.textContent =
        "当前账号无 confirm 权限，只能查看其他数据，不能留下正式核对记录。";
    } else if (!state.reviewState) {
      els.reviewPersistenceHint.textContent =
        "核对状态服务暂不可用，当前选择不会被当成最终确认依据。";
    } else {
      els.reviewPersistenceHint.textContent =
        `核对状态已由服务端按当前账号持久保存（${state.reviewState.reviewed_count}/${state.reviewState.total}）。观测变化会自动撤销旧核对。`;
    }
  }

  function applyServerDraft(payload) {
    const hasReviewState = Boolean(
      payload &&
      typeof payload === "object" &&
      Object.prototype.hasOwnProperty.call(payload, "review_state"),
    );
    const reviewState = hasReviewState ? payload.review_state : null;
    const raw = unwrapDraft(payload);
    if (!raw || typeof raw !== "object") return;
    const looksLikeDraft =
      raw.schema_version ||
      raw._meta ||
      raw.id ||
      raw.draft_id ||
      raw.enterprise ||
      raw.measurements ||
      raw.extracted_fields;
    if (looksLikeDraft) {
      const previous = state.activeDraft;
      const next = normalizeDraft(raw);
      if (previous) {
        next.reporter = previous.reporter;
        if (!next.signature.valid) {
          next.signature = {
            ...next.signature,
            signer_name:
              next.signature.signer_name || previous.signature.signer_name,
            signer_title:
              next.signature.signer_title || previous.signature.signer_title,
            method: next.signature.method || previous.signature.method,
            statement_accepted:
              next.signature.statement_accepted ||
              previous.signature.statement_accepted,
          };
        }
        const confirmations = new Map(
          previous.measurements.map((item) => [
            `${item.observation.observation_id}\u0000${item.key}`,
            item.confirmed,
          ]),
        );
        next.measurements.forEach((item) => {
          const key = `${item.observation.observation_id}\u0000${item.key}`;
          if (confirmations.has(key) && !next.signature.valid) {
            item.confirmed = confirmations.get(key);
          }
        });
      }
      state.activeDraft = next;
      restoreSuggestionsFromDraft(next);
      if (hasReviewState) applyReviewState(reviewState);
      state.dirtyWireFields.clear();
      updateDraftSummary();
      return;
    }
    if (payload && Array.isArray(payload.measurements)) {
      state.activeDraft.measurements = payload.measurements.map(normalizeMeasurement);
    }
    if (payload && Array.isArray(payload.questions)) {
      state.activeDraft.questions = payload.questions.map(normalizeQuestion);
    }
    if (payload && Array.isArray(payload.sources)) {
      state.activeDraft.sources = normalizeSources(payload.sources);
    }
    if (hasReviewState) applyReviewState(reviewState);
  }

  function clearImportInput() {
    els.sourceFile.value = "";
    els.sourceContent.value = "";
    els.sourceName.value = "";
    els.sourceSystem.value = "";
    els.sourceTruthStatement.checked = false;
    state.selectedFile = null;
  }

  function downloadImportTemplate(format) {
    if (format === "csv") {
      const headers = [
        "企业编号",
        "企业名称",
        "统一社会信用代码",
        "矿井编号",
        "矿井名称",
        "统计开始",
        "统计结束",
        "配置编号",
        "配置版本",
        "工况",
        "班次",
        "季节",
        "是否检修",
        "来源编号",
        "观测编号",
        "指标编码",
        "数值",
        "单位",
        "观测时间",
        "接收时间",
        "序号",
        "修订号",
        "载荷摘要",
        "来源签名",
      ];
      const example = [
        "ENT-001",
        "示例能源有限公司",
        "91110000ABCDEFGH1X",
        "M001",
        "示例一号矿",
        "2026-07-26T00:00:00+08:00",
        "2026-07-27T00:00:00+08:00",
        "production-default",
        "1",
        "NORMAL_PRODUCTION",
        "A",
        "SUMMER",
        "否",
        "由来源网关填写",
        "由来源网关填写",
        "coal.main_transport_t",
        "7100",
        "t",
        "2026-07-27T00:00:00+08:00",
        "2026-07-27T00:01:00+08:00",
        "1",
        "0",
        "",
        "",
      ];
      downloadTextFile(
        "企业可信填报模板.csv",
        `${headers.map(csvCell).join(",")}\r\n${example.map(csvCell).join(",")}\r\n`,
        "text/csv;charset=utf-8",
      );
      showToast("CSV 模板已下载；空白摘要和签名必须由来源网关填写。");
      return;
    }
    const template = {
      enterprise_id: "ENT-001",
      enterprise_name: "示例能源有限公司",
      unified_social_credit_code: "91110000ABCDEFGH1X",
      mine_id: "M001",
      mine_name: "示例一号矿",
      window_start: "2026-07-26T00:00:00+08:00",
      window_end: "2026-07-27T00:00:00+08:00",
      profile_id: "production-default",
      profile_version: "1",
      operational_context: {
        regime_code: "NORMAL_PRODUCTION",
        shift_code: "A",
        season_code: "SUMMER",
        maintenance: false,
        approved_event_codes: [],
        tags: [],
      },
      observations: [
        {
          source_id: "由来源网关填写",
          observation_id: "由来源网关填写",
          metric_code: "coal.main_transport_t",
          value: 7100,
          unit: "t",
          observed_at: "2026-07-27T00:00:00+08:00",
          received_at: "2026-07-27T00:01:00+08:00",
          interval_start: null,
          interval_end: null,
          reset_before: false,
          sequence_no: 1,
          revision: 0,
          payload_sha256: "",
          signature: "",
        },
      ],
    };
    downloadTextFile(
      "企业可信填报模板.json",
      `${JSON.stringify(template, null, 2)}\n`,
      "application/json;charset=utf-8",
    );
    showToast("JSON 模板已下载；空白摘要和签名必须由来源网关填写。");
  }

  function csvCell(value) {
    const text = String(value);
    return `"${text.replaceAll('"', '""')}"`;
  }

  function downloadTextFile(filename, content, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function renderSources() {
    const rows = state.activeDraft.sources;
    els.sourceCount.textContent = `${rows.length} 个`;
    if (!rows.length) {
      els.sourceList.replaceChildren(
        el("p", "draft-empty", "尚未导入来源。每个数字都应能回到原始材料。"),
      );
      return;
    }
    const fragment = document.createDocumentFragment();
    rows.forEach((source) => {
      const item = el("div", "source-item");
      item.append(el("span", "source-item-icon", source.format.toUpperCase().slice(0, 4)));
      const main = el("div", "source-item-main");
      main.append(
        el("strong", "", source.name),
        el(
          "span",
          "",
          [
            source.system,
            source.imported_at ? formatDateTime(source.imported_at) : "",
            source.digest ? `摘要 ${shortDigest(source.digest)}` : "",
          ]
            .filter(Boolean)
            .join(" · "),
        ),
      );
      item.append(main, el("span", "mini-status submitted", "已留痕"));
      fragment.append(item);
    });
    els.sourceList.replaceChildren(fragment);
  }

  function renderMeasurements() {
    const rows = state.activeDraft.measurements;
    const totalPages = Math.max(1, Math.ceil(rows.length / state.measurementPageSize));
    state.measurementPage = Math.max(1, Math.min(state.measurementPage, totalPages));
    const pageStart = (state.measurementPage - 1) * state.measurementPageSize;
    const visibleRows = rows.slice(pageStart, pageStart + state.measurementPageSize);
    const fragment = document.createDocumentFragment();
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = el("td", "empty-row", "尚无提取结果。请先导入来源并运行智能提取。");
      td.colSpan = 7;
      tr.append(td);
      fragment.append(tr);
    } else {
      visibleRows.forEach((measurement, pageIndex) => {
        const index = pageStart + pageIndex;
        const tr = document.createElement("tr");
        tr.dataset.observationIndex = String(index);
        tr.classList.toggle("needs-review", !measurement.confirmed);

        const metricCell = document.createElement("td");
        const name = el("div", "metric-name");
        name.append(
          el("strong", "", measurement.label),
          el("small", "", `指标代码：${measurement.key || "未填写"}`),
        );
        if (measurement.suggested_by_ai) name.append(el("small", "", "AI 待核对建议"));
        metricCell.append(name);

        const valueCell = document.createElement("td");
        const valueInput = document.createElement("input");
        valueInput.type = "number";
        valueInput.step = "any";
        valueInput.value = measurement.value;
        valueInput.setAttribute("aria-label", `${measurement.label}数值`);
        valueInput.dataset.observationField = "value";
        valueInput.disabled =
          state.activeDraft.status === "submitted" || !hasPermission("write");
        valueInput.addEventListener("focus", () => {
          state.fieldFocusSnapshot = measurementUndoEntry(index);
        });
        valueInput.addEventListener("change", () => {
          if (state.fieldFocusSnapshot) {
            pushUndo(state.fieldFocusSnapshot);
            state.fieldFocusSnapshot = null;
          }
          measurement.value = valueInput.value === "" ? "" : Number(valueInput.value);
          measurement.confirmed = false;
          measurement.suggested_by_ai = false;
          measurement.confidence = null;
          measurement.source = {
            id: "",
            name: "经办人手工更正",
            location: "填报界面人工录入",
            excerpt: "",
            digest: "",
          };
          state.dirtyWireFields.add("observations");
          invalidatePreflightAndSignature();
          renderMeasurements();
          renderConfirmation();
          renderSubmission();
          markDraftChanged();
          scheduleSave();
        });
        valueCell.append(valueInput);

        const unitCell = document.createElement("td");
        const unitInput = document.createElement("input");
        unitInput.type = "text";
        unitInput.value = measurement.unit;
        unitInput.maxLength = 32;
        unitInput.className = "unit-input";
        unitInput.setAttribute("aria-label", `${measurement.label}单位`);
        unitInput.dataset.observationField = "unit";
        unitInput.disabled =
          state.activeDraft.status === "submitted" || !hasPermission("write");
        unitInput.addEventListener("focus", () => {
          state.fieldFocusSnapshot = measurementUndoEntry(index);
        });
        unitInput.addEventListener("change", () => {
          if (state.fieldFocusSnapshot) {
            pushUndo(state.fieldFocusSnapshot);
            state.fieldFocusSnapshot = null;
          }
          measurement.unit = unitInput.value.trim();
          measurement.confirmed = false;
          measurement.suggested_by_ai = false;
          measurement.confidence = null;
          state.dirtyWireFields.add("observations");
          invalidatePreflightAndSignature();
          markDraftChanged();
          scheduleSave();
          renderMeasurements();
          renderConfirmation();
          renderSubmission();
        });
        unitCell.append(unitInput);
        const sourceCell = document.createElement("td");
        const sourceButton = el(
          "button",
          "source-link",
          measurement.source.name || "来源不明",
        );
        sourceButton.type = "button";
        sourceButton.addEventListener("click", () => showSourceDetail(measurement));
        sourceCell.append(sourceButton);

        const confidenceCell = document.createElement("td");
        const band = confidenceBand(measurement.confidence);
        confidenceCell.append(
          el(
            "span",
            `confidence confidence-${band.className}`,
            confidenceText(measurement.confidence),
          ),
        );

        const confirmCell = document.createElement("td");
        const confirmLabel = el("label", "confirmation-check");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.checked = measurement.confirmed;
        checkbox.disabled =
          state.activeDraft.status === "submitted" ||
          state.reviewLoading ||
          !canFinalizeWith("confirm") ||
          !state.reviewState ||
          !measurement.observation.observation_id ||
          measurement.value === "" ||
          !Number.isFinite(Number(measurement.value));
        checkbox.setAttribute("aria-label", `确认${measurement.label}`);
        checkbox.addEventListener("change", () =>
          void setMeasurementReviews(
            [measurement.observation.observation_id],
            checkbox.checked,
          ),
        );
        confirmLabel.append(
          checkbox,
          document.createTextNode(measurement.confirmed ? "已核对" : "待核对"),
        );
        confirmCell.append(confirmLabel);

        const actionCell = document.createElement("td");
        const removeButton = el(
          "button",
          "button button-quiet observation-remove-button",
          "移除此条",
        );
        removeButton.type = "button";
        removeButton.disabled =
          state.activeDraft.status === "submitted" ||
          !hasPermission("write") ||
          Boolean(state.activeOperation);
        removeButton.setAttribute("aria-label", `移除${measurement.label}`);
        removeButton.addEventListener("click", () =>
          void removeMeasurement(index, removeButton),
        );
        actionCell.append(removeButton);

        tr.append(
          metricCell,
          valueCell,
          unitCell,
          sourceCell,
          confidenceCell,
          confirmCell,
          actionCell,
        );
        fragment.append(tr);
      });
    }
    els.measurementBody.replaceChildren(fragment);
    els.measurementPagination.hidden = rows.length <= state.measurementPageSize;
    els.measurementPageSummary.textContent = rows.length
      ? `第 ${state.measurementPage}/${totalPages} 页 · 显示 ${pageStart + 1}–${Math.min(
          pageStart + state.measurementPageSize,
          rows.length,
        )}，共 ${rows.length} 项`
      : "暂无填报数字";
    els.previousMeasurementPageButton.disabled = state.measurementPage <= 1;
    els.nextMeasurementPageButton.disabled = state.measurementPage >= totalPages;
    const confirmed = rows.filter((row) => row.confirmed).length;
    els.confirmationProgress.textContent = rows.length
      ? `已人工确认 ${confirmed}/${rows.length} 项`
      : "尚无可确认数字";
    els.confirmHighConfidenceButton.disabled =
      state.activeDraft.status === "submitted" ||
      state.reviewLoading ||
      !canFinalizeWith("confirm") ||
      !state.reviewState ||
      !visibleRows.some((row) => !row.confirmed && row.confidence >= 0.9);
    renderReviewHint();
    renderSimpleTaskGuide();
  }

  async function removeMeasurement(index, button) {
    if (
      !state.activeDraft ||
      state.activeDraft.status === "submitted" ||
      !hasPermission("write")
    ) {
      showToast("当前账号不能移除这条观测。", "error");
      return;
    }
    const measurement = state.activeDraft.measurements[index];
    if (!measurement) return;
    const accepted = window.confirm(
      `确定移除“${measurement.label}”这一条观测吗？其余观测的来源凭据会按 observation_id 保留；本次报送需要重新预检和确认。`,
    );
    if (!accepted) return;
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    state.activeOperation = "移除一条观测";
    setBusy(button, true, "移除中…");
    try {
      await flushSave();
      const current = state.activeDraft.measurements[index];
      if (!current) throw new Error("这条观测已被其他操作移除，请刷新后核对。");
      pushUndo({
        kind: "insert_measurement",
        index,
        value: clone(current),
      });
      state.activeDraft.measurements.splice(index, 1);
      state.dirtyWireFields.add("observations");
      invalidatePreflightAndSignature();
      markDraftChanged();
      renderAll();
      await flushSave();
      showToast("该观测已移除；其余行的来源摘要和签名已由服务端按观测编号重新对齐。");
    } catch (error) {
      showToast(`观测未能移除：${error.message}`, "error");
    } finally {
      state.activeOperation = "";
      setBusy(button, false);
      if (state.activeDraft) {
        renderMeasurements();
        renderConfirmation();
        renderSubmission();
      }
    }
  }

  function confidenceBand(confidence) {
    if (confidence === null) return { className: "medium", label: "manual" };
    if (confidence >= 0.9) return { className: "high", label: "high" };
    if (confidence >= 0.7) return { className: "medium", label: "medium" };
    return { className: "low", label: "low" };
  }

  function confidenceText(confidence) {
    if (confidence === null) return confidenceLabels.manual;
    const band = confidenceBand(confidence);
    return `${confidenceLabels[band.label]} ${Math.round(confidence * 100)}%`;
  }

  function showSourceDetail(measurement) {
    els.sourceDialogTitle.textContent = `${measurement.label}的数字依据`;
    const dl = document.createElement("dl");
    dl.className = "source-detail";
    const rows = [
      ["当前数值", `${measurement.value} ${measurement.unit}`],
      ["来源材料", measurement.source.name || "未标明来源"],
      ["材料位置", measurement.source.location || "未提供具体位置"],
      ["提取可信度", confidenceText(measurement.confidence)],
      ["内容摘要", measurement.source.digest || "未提供"],
      ["人工状态", measurement.confirmed ? "经办人已核对" : "尚未核对"],
      [
        "来源网关凭据",
        measurement.observation.payload_sha256 && measurement.observation.signature
          ? `已携带摘要 ${shortDigest(measurement.observation.payload_sha256)}；由监管平台独立验签`
          : "缺少摘要或签名，不能正式提交",
      ],
    ];
    rows.forEach(([term, value]) => {
      const wrapper = el("div", "detail-row");
      wrapper.append(el("dt", "", term), el("dd", "", value));
      dl.append(wrapper);
    });
    const content = document.createDocumentFragment();
    content.append(dl);
    if (measurement.source.excerpt) {
      content.append(
        el("h3", "", "原文片段"),
        el("pre", "source-excerpt", measurement.source.excerpt),
      );
    }
    const warning = el("div", "alert alert-warning");
    warning.append(
      el("span", "alert-icon", "AI"),
      el("p", "", "来源定位和可信度用于辅助核对，不证明原材料或数字本身真实。"),
    );
    content.append(warning);
    els.sourceDialogBody.replaceChildren(content);
    els.sourceDialog.showModal();
  }

  async function confirmHighConfidenceMeasurements() {
    if (!state.activeDraft) return;
    const pageStart = (state.measurementPage - 1) * state.measurementPageSize;
    const candidates = state.activeDraft.measurements
      .slice(pageStart, pageStart + state.measurementPageSize)
      .filter(
      (row) => !row.confirmed && row.confidence !== null && row.confidence >= 0.9,
      );
    if (!candidates.length) return;
    const accepted = window.confirm(
      `将确认当前页 ${candidates.length} 个高可信度提取项，不会处理其他分页。可信度只表示提取清晰，不代表事实真实。请确认您已经逐项对照过原始材料。`,
    );
    if (!accepted) return;
    await setMeasurementReviews(
      candidates.map((row) => row.observation.observation_id),
      true,
    );
  }

  function renderQuestions() {
    const rows = state.activeDraft.questions;
    const unresolved = rows.filter(
      (row) => row.required && !questionIsResolved(row),
    ).length;
    els.questionCount.textContent = String(unresolved + state.suggestions.length);
    const fragment = document.createDocumentFragment();
    if (!rows.length && !state.suggestions.length) {
      fragment.append(el("p", "draft-empty", "当前没有缺项追问。"));
    } else {
      state.suggestions.forEach((suggestion) => {
        const card = el("div", "question-card ai-suggestion-card");
        const heading = el("div", "suggestion-heading");
        const title = el("strong", "", `AI 建议：${friendlySuggestionPath(suggestion.path)}`);
        heading.append(
          title,
          el(
            "span",
            `confidence confidence-${confidenceBand(suggestion.confidence).className}`,
            confidenceText(suggestion.confidence),
          ),
        );
        const value = el(
          "code",
          "suggestion-value",
          typeof suggestion.value === "string"
            ? suggestion.value
            : JSON.stringify(suggestion.value),
        );
        const reason = el(
          "p",
          "",
          `${suggestion.reason} · 来源位置：${suggestion.source_locator}`,
        );
        const actions = el("div", "suggestion-actions");
        const reject = el("button", "button button-quiet", "不采用");
        reject.type = "button";
        reject.disabled = !hasPermission("write");
        reject.addEventListener("click", () => dismissSuggestion(suggestion.id));
        const accept = el("button", "button button-secondary", "核对后采用");
        accept.type = "button";
        accept.disabled = !hasPermission("write");
        accept.addEventListener("click", () => void adoptSuggestion(suggestion));
        actions.append(reject, accept);
        card.append(heading, value, reason, actions);
        fragment.append(card);
      });
      rows.forEach((question, questionIndex) => {
        const card = el("div", "question-card");
        card.classList.toggle("is-resolved", questionIsResolved(question));
        if (question.path) {
          card.append(
            el(
              "strong",
              "",
              `${question.prompt}${question.required ? "（必须处理）" : ""}`,
            ),
          );
          if (question.help) card.append(el("small", "", question.help));
          const action = el(
            "button",
            "button button-secondary",
            questionIsResolved(question)
              ? "已补充，等待重新预检"
              : questionNeedsGatewayImport(question.path)
                ? "重新导入来源观测"
                : "去补充这项",
          );
          action.type = "button";
          action.addEventListener("click", () => {
            goToStep(stepForQuestionPath(question.path));
            focusQuestionPath(question.path);
          });
          card.append(action);
          fragment.append(card);
          return;
        }
        const label = document.createElement("label");
        const title = `${question.prompt}${question.required ? "（必答）" : ""}`;
        label.append(el("span", "", title));
        const input = question.multiline
          ? document.createElement("textarea")
          : document.createElement("input");
        if (question.multiline) input.rows = 3;
        input.value = question.answer;
        input.disabled =
          state.activeDraft.status === "submitted" || !hasPermission("write");
        input.addEventListener("focus", () => {
          state.fieldFocusSnapshot = questionUndoEntry(questionIndex);
        });
        input.addEventListener("input", () => {
          question.answer = input.value;
          question.resolved = Boolean(input.value.trim());
          invalidatePreflightAndSignature();
          markDraftChanged();
        });
        input.addEventListener("change", () => {
          if (state.fieldFocusSnapshot) {
            pushUndo(state.fieldFocusSnapshot);
            state.fieldFocusSnapshot = null;
          }
          renderQuestions();
          renderConfirmation();
          renderSubmission();
        });
        label.append(input);
        if (question.help) label.append(el("small", "", question.help));
        card.append(label);
        fragment.append(card);
      });
    }
    els.questionList.replaceChildren(fragment);
    renderSimpleTaskGuide();
  }

  function questionIsResolved(question) {
    if (!question.path) return Boolean(question.answer.trim());
    const localPath = {
      "/enterprise_id": "enterprise.id",
      "/enterprise_name": "enterprise.name",
      "/unified_social_credit_code": "enterprise.credit_code",
      "/mine_id": "enterprise.mine_code",
      "/mine_name": "enterprise.mine_name",
      "/window_start": "period.start",
      "/window_end": "period.end",
      "/profile_id": "profile.id",
      "/profile_version": "profile.version",
      "/operational_context/regime_code": "operational_context.regime_code",
      "/operational_context/shift_code": "operational_context.shift_code",
      "/operational_context/season_code": "operational_context.season_code",
      "/operational_context/maintenance": "operational_context.maintenance",
    }[question.path];
    if (localPath) {
      const value = getPath(state.activeDraft, localPath);
      return value !== null && value !== undefined && String(value).trim() !== "";
    }
    const match = /^\/observations\/(\d+)\/([^/]+)$/.exec(question.path);
    if (match) {
      const measurement = state.activeDraft.measurements[Number(match[1])];
      if (!measurement) return false;
      const field = match[2];
      const value =
        field === "value"
          ? measurement.value
          : field === "unit"
            ? measurement.unit
            : field === "metric_code"
              ? measurement.key
              : measurement.observation[field];
      return value !== null && value !== undefined && String(value).trim() !== "";
    }
    if (question.path === "/observations") {
      return state.activeDraft.measurements.length > 0;
    }
    return Boolean(question.answer.trim());
  }

  function stepForQuestionPath(path) {
    return questionNeedsGatewayImport(path)
      ? 2
      : path.startsWith("/observations")
        ? 3
        : 1;
  }

  function focusQuestionPath(path) {
    const fieldNames = {
      "/enterprise_id": "enterprise.id",
      "/enterprise_name": "enterprise.name",
      "/unified_social_credit_code": "enterprise.credit_code",
      "/mine_id": "enterprise.mine_code",
      "/mine_name": "enterprise.mine_name",
      "/window_start": "period.start",
      "/window_end": "period.end",
      "/profile_id": "profile.id",
      "/profile_version": "profile.version",
      "/operational_context/regime_code": "operational_context.regime_code",
      "/operational_context/shift_code": "operational_context.shift_code",
      "/operational_context/season_code": "operational_context.season_code",
      "/operational_context/maintenance": "operational_context.maintenance",
    };
    const name = fieldNames[path];
    if (name) {
      const field = els.draftForm.elements.namedItem(name);
      if (field) {
        const details = field.closest("details");
        if (details) details.open = true;
        field.focus();
      }
      return;
    }
    const match = /^\/observations\/(\d+)\/([^/]+)$/.exec(path);
    if (!match) return;
    const observationIndex = Number(match[1]);
    const targetPage =
      Math.floor(observationIndex / state.measurementPageSize) + 1;
    if (targetPage !== state.measurementPage) {
      state.measurementPage = targetPage;
      renderMeasurements();
    }
    const field = match[2];
    if (["value", "unit"].includes(field)) {
      const input = els.measurementBody.querySelector(
        `tr[data-observation-index="${observationIndex}"] ` +
          `[data-observation-field="${field}"]`,
      );
      if (input) input.focus();
      return;
    }
    showToast(
      "该字段属于来源网关凭据，不能在填报页面补造；请重新导入来源系统签发的数据。",
      "error",
    );
  }

  function questionNeedsGatewayImport(path) {
    return /^\/observations\/\d+\/(source_id|observation_id|observed_at|received_at|interval_start|interval_end|sequence_no|revision|payload_sha256|signature)$/.test(
      String(path || ""),
    ) || path === "/observations";
  }

  function friendlySuggestionPath(path) {
    const labels = {
      "/enterprise_id": "企业编号",
      "/enterprise_name": "企业名称",
      "/unified_social_credit_code": "统一社会信用代码",
      "/mine_id": "矿井/单位编码",
      "/mine_name": "矿井/单位名称",
      "/window_start": "统计开始时间",
      "/window_end": "统计结束时间",
      "/profile_id": "分析配置编号",
      "/profile_version": "分析配置版本",
      "/operational_context/regime_code": "生产工况",
      "/operational_context/shift_code": "班次",
      "/operational_context/season_code": "季节/气候期",
      "/operational_context/maintenance": "检修状态",
    };
    if (labels[path]) return labels[path];
    const match = /^\/observations\/(\d+)\/([^/]+)$/.exec(path);
    if (match) {
      const fields = {
        source_id: "来源编号",
        observation_id: "观测编号",
        metric_code: "指标编码",
        value: "数值",
        unit: "单位",
        observed_at: "观测时间",
        received_at: "接收时间",
      };
      return `第 ${Number(match[1]) + 1} 条观测 · ${fields[match[2]] || match[2]}`;
    }
    return path || "未知字段";
  }

  function dismissSuggestion(suggestionId) {
    state.suggestions = state.suggestions.filter((item) => item.id !== suggestionId);
    renderQuestions();
    showToast("该建议已忽略，未写入事实数据。");
  }

  async function adoptSuggestion(suggestion) {
    if (
      !state.activeDraft ||
      state.activeDraft.status === "submitted" ||
      !hasPermission("write")
    ) {
      showToast("当前账号没有采用建议和编辑草稿的权限。", "error");
      return;
    }
    const undoEntry = suggestionUndoEntry(suggestion);
    const mapped = applySuggestionValue(suggestion);
    if (!mapped) {
      showToast("该建议字段暂不支持在界面采用，请人工填写对应项。", "error");
      return;
    }
    pushUndo(undoEntry);
    state.suggestions = state.suggestions.filter((item) => item.id !== suggestion.id);
    invalidatePreflightAndSignature();
    markDraftChanged();
    renderAll();
    scheduleSave();
    try {
      await flushSave();
      showToast("建议已作为人工采纳内容写入草稿，仍需最终逐项确认。");
    } catch {
      // saveDraft presents the error and leaves the adopted value visible.
    }
  }

  function applySuggestionValue(suggestion) {
    if (!suggestionIsAdoptable(suggestion, state.activeDraft)) return false;
    const pathMap = {
      "/enterprise_id": ["enterprise.id", "enterprise_id"],
      "/enterprise_name": ["enterprise.name", "enterprise_name"],
      "/unified_social_credit_code": [
        "enterprise.credit_code",
        "unified_social_credit_code",
      ],
      "/mine_id": ["enterprise.mine_code", "mine_id"],
      "/mine_name": ["enterprise.mine_name", "mine_name"],
      "/window_start": ["period.start", "window_start"],
      "/window_end": ["period.end", "window_end"],
      "/profile_id": ["profile.id", "profile_id"],
      "/profile_version": ["profile.version", "profile_version"],
      "/operational_context/regime_code": [
        "operational_context.regime_code",
        "operational_context",
      ],
      "/operational_context/shift_code": [
        "operational_context.shift_code",
        "operational_context",
      ],
      "/operational_context/season_code": [
        "operational_context.season_code",
        "operational_context",
      ],
      "/operational_context/maintenance": [
        "operational_context.maintenance",
        "operational_context",
      ],
    };
    if (pathMap[suggestion.path]) {
      const [localPath, wireField] = pathMap[suggestion.path];
      setPath(state.activeDraft, localPath, suggestion.value);
      state.dirtyWireFields.add(wireField);
      return true;
    }

    const match = /^\/observations\/(\d+)\/([^/]+)$/.exec(suggestion.path);
    if (!match) return false;
    const index = Number(match[1]);
    const field = match[2];
    const measurement = state.activeDraft.measurements[index];
    if (field === "value") {
      measurement.value = suggestion.value;
      measurement.confidence = suggestion.confidence;
      measurement.confirmed = false;
      measurement.suggested_by_ai = true;
      measurement.source = {
        ...(state.assistantSource || {}),
        name:
          (state.assistantSource && state.assistantSource.name) ||
          "智能提取材料",
        location: suggestion.source_locator,
        excerpt: suggestion.reason,
      };
    } else if (field === "metric_code") {
      measurement.key = String(suggestion.value);
      measurement.label = friendlyMetricName(measurement.key);
      measurement.observation.metric_code = measurement.key;
    } else if (field === "unit") {
      measurement.unit = String(suggestion.value);
    } else {
      measurement.observation[field] = suggestion.value;
    }
    state.dirtyWireFields.add("observations");
    return true;
  }

  function suggestionUndoEntry(suggestion) {
    const fieldPaths = {
      "/enterprise_id": "enterprise.id",
      "/enterprise_name": "enterprise.name",
      "/unified_social_credit_code": "enterprise.credit_code",
      "/mine_id": "enterprise.mine_code",
      "/mine_name": "enterprise.mine_name",
      "/window_start": "period.start",
      "/window_end": "period.end",
      "/profile_id": "profile.id",
      "/profile_version": "profile.version",
      "/operational_context/regime_code": "operational_context.regime_code",
      "/operational_context/shift_code": "operational_context.shift_code",
      "/operational_context/season_code": "operational_context.season_code",
      "/operational_context/maintenance": "operational_context.maintenance",
    };
    if (fieldPaths[suggestion.path]) {
      return fieldUndoEntry(fieldPaths[suggestion.path]);
    }
    const match = /^\/observations\/(\d+)\//.exec(String(suggestion.path || ""));
    if (!match || !state.activeDraft) return null;
    const index = Number(match[1]);
    return {
      kind: "measurement",
      index,
      value:
        index < state.activeDraft.measurements.length
          ? clone(state.activeDraft.measurements[index])
          : null,
      previousLength: state.activeDraft.measurements.length,
    };
  }

  async function runValidation() {
    if (!state.activeDraft) return;
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    applyAllFormFields();
    const localErrors = validateLocalCompleteness();
    if (localErrors.length) {
      state.activeDraft.preflight = {
        run_at: new Date().toISOString(),
        passed: false,
        blockers: localErrors.length,
        warnings: 0,
        checks: localErrors.map((message, index) => ({
          id: `local-${index + 1}`,
          title: "内容不完整",
          message,
          level: "blocker",
        })),
      };
      renderPreflight();
      renderConfirmation();
      renderSubmission();
      showToast(`发现 ${localErrors.length} 个必填问题。`, "error");
      return;
    }
    state.activeOperation = "运行预检";
    setBusy(els.validateButton, true, "正在检查…");
    try {
      await flushSave();
      const payload = await api(endpoints.validate(state.activeDraft.id), {
        method: "POST",
        body: {},
      });
      if (payload && payload.draft) {
        applyServerDraft(payload);
      } else {
        state.activeDraft.preflight = normalizePreflight(payload);
      }
      renderAll();
      if (state.activeDraft.preflight && state.activeDraft.preflight.blockers) {
        showToast(`预检发现 ${state.activeDraft.preflight.blockers} 个阻断问题。`, "error");
      } else {
        showToast("预检完成，没有阻断问题。");
      }
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.validateButton, false);
      if (state.activeDraft) lockSubmittedDraft();
    }
  }

  function validateLocalCompleteness() {
    const draft = state.activeDraft;
    const errors = [];
    if (!draft.enterprise.name.trim()) errors.push("请填写企业名称。");
    if (!draft.enterprise.id.trim()) errors.push("请填写企业编号。");
    if (!draft.enterprise.credit_code.trim()) errors.push("请填写统一社会信用代码。");
    else if (
      !/^[0-9A-HJ-NPQRTUWXY]{18}$/.test(
        draft.enterprise.credit_code.trim().toUpperCase(),
      )
    ) {
      errors.push("统一社会信用代码必须是 18 位规范代码。");
    }
    if (!draft.enterprise.mine_code.trim()) errors.push("请填写矿井/单位编码。");
    if (!draft.enterprise.mine_name.trim()) errors.push("请填写矿井/单位名称。");
    if (!draft.profile.id.trim() || !draft.profile.version.trim()) {
      errors.push("请填写管理员提供的分析配置编号与版本。");
    }
    if (!draft.period.start || !draft.period.end) errors.push("请填写完整统计时段。");
    if (
      (draft.period.start && Number.isNaN(new Date(draft.period.start).getTime())) ||
      (draft.period.end && Number.isNaN(new Date(draft.period.end).getTime()))
    ) {
      errors.push("统计时间格式无效，请重新选择开始和结束时间。");
    }
    if (
      draft.period.start &&
      draft.period.end &&
      new Date(draft.period.start) >= new Date(draft.period.end)
    ) {
      errors.push("统计结束时间必须晚于开始时间。");
    }
    const context = draft.operational_context;
    if (
      !context.regime_code ||
      !context.shift_code ||
      !context.season_code ||
      context.maintenance === null
    ) {
      errors.push("请明确填写操作上下文四轴。");
    }
    if (!hasRegulatorEventSnapshot(draft)) {
      errors.push(
        "请导入监管事件快照；即使没有特殊事件也必须导入空结果快照。",
      );
    }
    if (!draft.sources.length) errors.push("请至少导入一份真实来源。");
    if (!draft.measurements.length) errors.push("尚无填报数字，请运行智能提取。");
    if (draft.measurements.some((row) => row.value === "" || !Number.isFinite(Number(row.value)))) {
      errors.push("存在未填写或不是数字的填报项。");
    }
    if (draft.questions.some((row) => row.required && !questionIsResolved(row))) {
      errors.push("还有必答追问未完成。");
    }
    return errors;
  }

  function renderPreflight() {
    const preflight = state.activeDraft.preflight;
    if (!preflight) {
      const idle = el("div", "preflight-idle");
      const copy = document.createElement("div");
      copy.append(
        el("h4", "", "尚未运行预检"),
        el("p", "", "完成前面信息核对后，点击“运行预检”。"),
      );
      idle.append(el("span", "", "检"), copy);
      els.preflightSummary.replaceChildren(idle);
      els.checkList.replaceChildren();
      renderSimpleTaskGuide();
      return;
    }

    const passed = preflight.blockers === 0;
    const result = el("div", `preflight-result ${passed ? "pass" : "blocked"}`);
    const copy = document.createElement("div");
    copy.append(
      el("h4", "", passed ? "预检无阻断问题" : `发现 ${preflight.blockers} 个阻断问题`),
      el(
        "p",
        "",
        `${preflight.warnings} 项需要注意 · 检查于 ${formatDateTime(preflight.run_at)}`,
      ),
    );
    result.append(el("span", "", passed ? "✓" : "!"), copy);
    els.preflightSummary.replaceChildren(result);

    const fragment = document.createDocumentFragment();
    preflight.checks.forEach((check) => {
      const row = el("div", `check-item ${check.level}`);
      const symbol = check.level === "pass" ? "✓" : check.level === "warning" ? "?" : "!";
      const body = document.createElement("div");
      body.append(el("strong", "", check.title));
      if (check.message) body.append(el("p", "", check.message));
      row.append(el("span", "check-symbol", symbol), body);
      fragment.append(row);
    });
    els.checkList.replaceChildren(fragment);
    renderSimpleTaskGuide();
  }

  function renderConfirmation() {
    const draft = state.activeDraft;
    const principal = state.principal || {};
    const confirmedCount = draft.measurements.filter((row) => row.confirmed).length;
    const unresolvedCount = draft.questions.filter(
      (row) => row.required && !questionIsResolved(row),
    ).length;
    const blockers = draft.preflight ? draft.preflight.blockers : null;
    const tiles = [
      ["数字核对", `${confirmedCount}/${draft.measurements.length} 项已确认`],
      ["缺项回答", unresolvedCount ? `${unresolvedCount} 项未完成` : "已完成"],
      ["预检结果", blockers === null ? "尚未运行" : blockers ? `${blockers} 个阻断` : "无阻断"],
    ];
    const fragment = document.createDocumentFragment();
    tiles.forEach(([label, value]) => {
      const tile = el("div", "overview-tile");
      tile.append(el("span", "", label), el("strong", "", value));
      fragment.append(tile);
    });
    els.confirmationOverview.replaceChildren(fragment);
    els.confirmationActorName.textContent = principal.name || "未登录";
    els.confirmationActorRole.textContent = principal.role || "未配置岗位";
    els.confirmationActorId.textContent = `账号：${principal.actor_id || "—"}`;
    els.signatureState.textContent = draft.signature.valid
      ? "已由企业账号确认"
      : "未确认";
    els.signatureState.classList.toggle("is-signed", draft.signature.valid);
    const readyByData = canConfirmDraft(draft);
    const allowedByIdentity = canFinalizeWith("confirm");
    els.confirmDraftButton.disabled =
      draft.status === "submitted" ||
      draft.signature.valid ||
      !readyByData ||
      !allowedByIdentity;
    const statement = els.draftForm.elements.namedItem("signature.statement_accepted");
    if (statement) {
      statement.disabled =
        draft.status === "submitted" ||
        draft.signature.valid ||
        !allowedByIdentity;
    }
    if (draft.signature.valid) {
      els.confirmDraftButton.textContent = "已完成人工确认";
      els.confirmDraftButton.title = "当前修订版本已经确认；修改业务数据后会自动失效";
      els.confirmationPermissionHint.textContent =
        `已由 ${draft.signature.signer_name || "当前确认人"} 于 ${formatDateTime(draft.signature.signed_at)} 确认。`;
    } else if (credentialRotationRequired()) {
      els.confirmDraftButton.textContent = "完成人工确认";
      els.confirmDraftButton.title = "临时或待换密账号不能执行正式确认";
      els.confirmationPermissionHint.textContent =
        "当前账号只能查看和编辑。管理员更换密码摘要并取消待换密标记后，才能正式确认。";
    } else if (!hasPermission("confirm")) {
      els.confirmDraftButton.textContent = "完成人工确认";
      els.confirmDraftButton.title = "当前账号没有 confirm 权限";
      els.confirmationPermissionHint.textContent =
        "当前账号没有人工确认权限，请联系企业管理员。";
    } else if (!readyByData && draft.status !== "submitted") {
      els.confirmDraftButton.textContent = "完成人工确认";
      els.confirmDraftButton.title = "请先完成所有数字核对、必答追问和无阻断预检";
      els.confirmationPermissionHint.textContent =
        "完成数字核对、必答追问和无阻断预检后即可确认。";
    } else {
      els.confirmDraftButton.textContent = "完成人工确认";
      els.confirmDraftButton.removeAttribute("title");
      els.confirmationPermissionHint.textContent =
        "点击后将以当前登录账号执行 authenticated_click 确认。";
    }
    renderSimpleTaskGuide();
  }

  function canConfirmDraft(draft) {
    return (
      draft.measurements.length > 0 &&
      draft.measurements.every((row) => row.confirmed) &&
      Boolean(state.reviewState && state.reviewState.all_reviewed) &&
      state.reviewState.total === draft.measurements.length &&
      draft.questions.every((row) => !row.required || questionIsResolved(row)) &&
      Boolean(draft.preflight) &&
      draft.preflight.blockers === 0
    );
  }

  async function confirmDraft() {
    if (!canFinalizeWith("confirm")) {
      showToast(
        credentialRotationRequired()
          ? "临时或待换密账号不能正式确认，请联系管理员配置个人账号。"
          : "当前账号没有人工确认权限。",
        "error",
      );
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    if (!state.activeDraft || !canConfirmDraft(state.activeDraft)) {
      showToast("请先完成全部数字核对、缺项回答和无阻断预检。", "error");
      return;
    }
    applyAllFormFields();
    const signature = state.activeDraft.signature;
    if (!signature.statement_accepted) {
      showToast("请阅读并勾选企业真实性声明。", "error");
      return;
    }

    state.activeOperation = "人工确认";
    setBusy(els.confirmDraftButton, true, "正在确认…");
    try {
      await flushSave();
      const payload = await api(endpoints.confirm(state.activeDraft.id), {
        method: "POST",
        body: {
          accepted: true,
          attestation:
            "本人已对照原始记录逐项核对，确认有权提交，并理解正常性与合法性最终由监管机关判定。",
          expected_revision: state.activeDraft.revision,
          confirmation_method: "authenticated_click",
        },
      });
      if (payload && (payload.draft || payload.id || payload.draft_id)) {
        applyServerDraft(payload);
      } else {
        state.activeDraft.signature = {
          ...signature,
          ...((payload && (payload.signature || payload.confirmation)) || {}),
          signer_name: state.principal.name,
          signer_title: state.principal.role,
          method: "authenticated_click",
          valid: true,
          signed_at:
            (payload && payload.signed_at) ||
            (payload && payload.signature && payload.signature.signed_at) ||
            new Date().toISOString(),
        };
        state.activeDraft.status = "confirmed";
      }
      if (!state.activeDraft.signature.valid) state.activeDraft.signature.valid = true;
      state.activeDraft.status = "confirmed";
      updateDraftSummary();
      renderAll();
      showToast("人工确认已完成，现在可以提交。");
      goToStep(6);
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.confirmDraftButton, false);
      if (state.activeDraft) renderConfirmation();
    }
  }

  async function openCoalChat() {
    if (!state.principal || !hasPermission("read")) {
      showToast("请先使用有读取权限的企业账号登录。", "error");
      return;
    }
    stopAgentPolling();
    stopAgentV2Polling();
    els.agentWorkbench.hidden = true;
    els.agentV2Workbench.hidden = true;
    els.coalChatWorkbench.hidden = false;
    if (state.activeDraft && !state.chat.draftChoiceTouched) {
      els.coalChatUseCurrentDraft.checked = true;
    }
    renderCoalChat();
    els.coalChatWorkbench.focus();
    await loadCoalChatSessions();
    if (state.chat.selectedSessionId) {
      await loadCoalChatSession(state.chat.selectedSessionId);
    } else if (state.chat.sessions.length) {
      await selectCoalChat(state.chat.sessions[0].session_id);
    }
    if (state.chat.pendingReply && !state.chat.deliveryUnknown) {
      beginCoalChatPolling(state.chat.pendingReply);
    }
  }

  function closeCoalChat() {
    stopCoalChatPolling();
    els.coalChatWorkbench.hidden = true;
    els.coalChatButton.focus();
  }

  async function refreshCoalChat() {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.chat.creating ||
      state.chat.deleting
    ) {
      return;
    }
    await loadCoalChatSessions();
    if (state.chat.selectedSessionId) {
      await loadCoalChatSession(state.chat.selectedSessionId);
    }
  }

  async function retryCoalChat() {
    state.chat.detailError = "";
    state.chat.listError = "";
    if (state.chat.pendingReply) {
      state.chat.deliveryUnknown = false;
      state.chat.sending = true;
      state.chat.pollFailures = 0;
      beginCoalChatPolling(state.chat.pendingReply, true);
      return;
    }
    await refreshCoalChat();
  }

  async function createCoalChat() {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.chat.creating ||
      state.chat.sending ||
      state.chat.deliveryUnknown ||
      state.chat.deleting
    ) {
      return;
    }
    const clientRequestId = newClientRequestId("chat-session");
    const knownIds = new Set(
      state.chat.sessions.map((session) => session.session_id),
    );
    state.chat.creating = true;
    state.chat.listError = "";
    renderCoalChat();
    try {
      const envelope = await api(endpoints.chatSessionsCreate(), {
        method: "POST",
        timeoutMs: 20000,
        includeResponseMeta: true,
        body: {
          title: "煤炭业务对话",
          draft_id: selectedCoalChatDraftId(),
          client_request_id: clientRequestId,
        },
      });
      const session = normalizeCoalChatSession(
        unwrapCoalChatSession(envelope && envelope.payload),
      );
      if (!session.session_id) {
        throw new Error("服务未返回对话编号。");
      }
      upsertCoalChatSession(session);
      state.chat.selectedSessionId = session.session_id;
      state.chat.detail = session;
      state.chat.detailError = "";
      renderCoalChat();
      await loadCoalChatSession(session.session_id, { quiet: true });
      els.coalChatInput.focus();
      showToast("新的煤炭业务对话已建立。");
    } catch (error) {
      if (error.isTimeout || !error.status) {
        await loadCoalChatSessions();
        const recovered = state.chat.sessions.find(
          (session) =>
            !knownIds.has(session.session_id) &&
            session.client_request_id === clientRequestId,
        );
        if (recovered) {
          state.chat.selectedSessionId = recovered.session_id;
          await loadCoalChatSession(recovered.session_id, { quiet: true });
          showToast("创建响应一度中断，已找回新对话，没有重复创建。");
        } else {
          state.chat.listError =
            "新建请求状态暂时无法确认。请先刷新对话列表，不要连续点击“新建对话”。";
          showToast(state.chat.listError, "error");
        }
      } else {
        state.chat.listError = error.message;
        showToast(`对话未能建立：${error.message}`, "error");
      }
    } finally {
      state.chat.creating = false;
      renderCoalChat();
    }
  }

  async function deleteCoalChat() {
    const sessionId = state.chat.selectedSessionId;
    if (
      !sessionId ||
      !state.principal ||
      !hasPermission("read") ||
      state.chat.deleting ||
      state.chat.sending ||
      state.chat.deliveryUnknown ||
      coalChatIntegrityFailed(state.chat.detail)
    ) {
      return;
    }
    const accepted = window.confirm(
      "确定移除当前煤炭业务对话吗？它会从工作列表中移除，页面无法自行恢复；此操作不影响填报草稿。",
    );
    if (!accepted) return;
    state.chat.deleting = true;
    renderCoalChatControls();
    try {
      await api(endpoints.chatSession(sessionId), {
        method: "DELETE",
        timeoutMs: 15000,
      });
      removeCoalChatSessionLocally(sessionId);
      await loadCoalChatSessions();
      if (state.chat.sessions.length) {
        await selectCoalChat(state.chat.sessions[0].session_id);
      }
      showToast("煤炭业务对话已移除。");
    } catch (error) {
      if (error.isTimeout || !error.status) {
        await loadCoalChatSessions();
        if (!state.chat.sessions.some((item) => item.session_id === sessionId)) {
          removeCoalChatSessionLocally(sessionId);
          showToast("删除响应一度中断，服务端已确认对话移除。");
        } else {
          state.chat.detailError =
            "移除状态暂时无法确认。请刷新对话列表后再判断，不要重复点击。";
          showToast(state.chat.detailError, "error");
        }
      } else {
        state.chat.detailError = error.message;
        showToast(`对话未能移除：${error.message}`, "error");
      }
    } finally {
      state.chat.deleting = false;
      renderCoalChat();
    }
  }

  function removeCoalChatSessionLocally(sessionId) {
    stopCoalChatPolling();
    state.chat.sessions = state.chat.sessions.filter(
      (item) => item.session_id !== sessionId,
    );
    state.chat.total = Math.max(0, state.chat.total - 1);
    if (state.chat.selectedSessionId === sessionId) {
      state.chat.selectedSessionId = "";
      state.chat.detail = null;
      state.chat.pendingReply = null;
      state.chat.sending = false;
      state.chat.deliveryUnknown = false;
      state.chat.detailError = "";
    }
    renderCoalChat();
  }

  async function loadCoalChatSessions() {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.chat.listLoading
    ) {
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    state.chat.listLoading = true;
    state.chat.listError = "";
    renderCoalChat();
    try {
      const payload = await api(endpoints.chatSessions(30, 0), {
        timeoutMs: 15000,
      });
      if (sessionRequestIsStale(sessionGeneration)) return;
      const rows = Array.isArray(payload)
        ? payload
        : payload && Array.isArray(payload.sessions)
          ? payload.sessions
          : payload && Array.isArray(payload.items)
            ? payload.items
            : payload && Array.isArray(payload.conversations)
              ? payload.conversations
              : [];
      state.chat.sessions = rows
        .map(normalizeCoalChatSession)
        .filter((session) => session.session_id);
      state.chat.total = Number(
        payload && Number.isFinite(Number(payload.total))
          ? payload.total
          : state.chat.sessions.length,
      );
      if (
        state.chat.selectedSessionId &&
        !state.chat.sessions.some(
          (session) => session.session_id === state.chat.selectedSessionId,
        )
      ) {
        state.chat.selectedSessionId = "";
        state.chat.detail = null;
      }
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.chat.listError = error.message;
      if (error.status !== 401) {
        showToast(`对话列表加载失败：${error.message}`, "error");
      }
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.chat.listLoading = false;
        renderCoalChat();
      }
    }
  }

  async function selectCoalChat(sessionId) {
    if (
      !sessionId ||
      state.chat.sending ||
      state.chat.deliveryUnknown ||
      state.chat.deleting
    ) {
      return;
    }
    stopCoalChatPolling();
    state.chat.selectedSessionId = sessionId;
    state.chat.detail = null;
    state.chat.detailError = "";
    renderCoalChat();
    await loadCoalChatSession(sessionId);
  }

  async function loadCoalChatSession(sessionId, options = {}) {
    if (!sessionId || !state.principal || !hasPermission("read")) return null;
    const polling = Boolean(options.polling);
    const quiet = Boolean(options.quiet);
    const sequence = ++state.chat.requestSequence;
    if (!polling && !quiet) state.chat.detailLoading = true;
    if (!polling && !quiet) renderCoalChat();
    try {
      const payload = await api(endpoints.chatSession(sessionId), {
        timeoutMs: 15000,
      });
      if (
        sequence !== state.chat.requestSequence ||
        state.chat.selectedSessionId !== sessionId
      ) {
        return null;
      }
      const session = normalizeCoalChatSession(unwrapCoalChatSession(payload));
      if (!session.session_id) session.session_id = sessionId;
      state.chat.detail = session;
      state.chat.detailError = "";
      state.chat.pollFailures = 0;
      if (coalChatIntegrityFailed(session)) {
        stopCoalChatPolling();
        state.chat.pendingReply = null;
        state.chat.sending = false;
        state.chat.deliveryUnknown = false;
      }
      upsertCoalChatSession(session);
      renderCoalChat();
      return session;
    } catch (error) {
      if (
        sequence === state.chat.requestSequence &&
        state.chat.selectedSessionId === sessionId
      ) {
        state.chat.pollFailures += 1;
        if (!quiet && !polling) state.chat.detailError = error.message;
        renderCoalChat();
      }
      return null;
    } finally {
      if (sequence === state.chat.requestSequence) {
        state.chat.detailLoading = false;
        renderCoalChat();
      }
    }
  }

  async function sendCoalChatMessage() {
    const sessionId = state.chat.selectedSessionId;
    const content = String(els.coalChatInput.value || "").trim();
    if (!content || content.length > 2000) {
      showToast("请输入 1 到 2000 个字符的煤炭业务问题。", "error");
      els.coalChatInput.focus();
      return;
    }
    if (
      !sessionId ||
      !state.principal ||
      !hasPermission("read") ||
      state.chat.sending ||
      state.chat.deliveryUnknown ||
      state.chat.deleting ||
      coalChatIntegrityFailed(state.chat.detail)
    ) {
      return;
    }
    const detail = state.chat.detail || { messages: [] };
    const messages = Array.isArray(detail.messages) ? detail.messages : [];
    const pending = {
      sessionId,
      content,
      clientMessageId: newClientRequestId("chat-message"),
      baselineCount: messages.length,
      baselineAssistantIds: messages
        .filter((message) => message.role === "assistant")
        .map((message) => message.message_id),
    };
    state.chat.pendingReply = pending;
    state.chat.sending = true;
    state.chat.deliveryUnknown = false;
    state.chat.detailError = "";
    els.coalChatScopeNotice.hidden = true;
    renderCoalChatControls();
    try {
      const envelope = await api(endpoints.chatMessages(sessionId), {
        method: "POST",
        timeoutMs: 60000,
        includeResponseMeta: true,
        body: {
          content,
          draft_id: selectedCoalChatDraftId(),
          client_message_id: pending.clientMessageId,
        },
      });
      const payload = envelope && envelope.payload;
      applyCoalChatMessageResponse(sessionId, payload);
      await loadCoalChatSession(sessionId, { quiet: true });
      els.coalChatInput.value = "";
      renderCoalChat();
      const responsePending = coalChatResponsePending(
        payload,
        envelope && envelope.http_status,
      );
      if (
        coalChatReplyResolved(state.chat.detail, pending) &&
        !responsePending
      ) {
        finishCoalChatReply();
        showToast(
          coalChatLatestMessageIsOutOfScope(state.chat.detail)
            ? "该问题不属于煤炭业务，助手已明确拒绝。"
            : "煤炭业务助手已回复。",
        );
      } else {
        beginCoalChatPolling(pending, true);
      }
    } catch (error) {
      if (coalChatErrorIsOutOfScope(error)) {
        appendLocalCoalChatRefusal(
          sessionId,
          error.message ||
            "这个问题不属于煤炭业务范围，请换一个煤炭相关问题。",
        );
        els.coalChatInput.value = "";
        finishCoalChatReply();
        renderCoalChat();
        return;
      }
      if (
        error.status &&
        error.status < 500 &&
        ![408, 409, 429].includes(error.status)
      ) {
        state.chat.pendingReply = null;
        state.chat.sending = false;
        state.chat.deliveryUnknown = false;
        state.chat.detailError = `问题未发送：${error.message}`;
        renderCoalChat();
        showToast(state.chat.detailError, "error");
        return;
      }
      const refreshed = await loadCoalChatSession(sessionId, { quiet: true });
      if (coalChatUserMessageAccepted(refreshed, pending)) {
        els.coalChatInput.value = "";
        showToast(
          "发送响应一度中断，但问题已被服务端接收；正在等待回答，没有重复发送。",
        );
        beginCoalChatPolling(pending, true);
      } else {
        state.chat.sending = false;
        state.chat.deliveryUnknown = true;
        state.chat.detailError =
          "发送状态暂时无法确认。为避免重复提问，发送按钮已锁定；请点击“重新加载”核对后继续。";
        renderCoalChat();
        showToast(state.chat.detailError, "error");
      }
    }
  }

  function beginCoalChatPolling(pending, immediate = false) {
    if (!pending || pending.sessionId !== state.chat.selectedSessionId) return;
    stopCoalChatPolling();
    state.chat.pendingReply = pending;
    state.chat.sending = true;
    state.chat.deliveryUnknown = false;
    state.chat.pollStartedAt = Date.now();
    state.chat.pollFailures = 0;
    renderCoalChat();
    scheduleCoalChatPoll(immediate ? 0 : 1300);
  }

  function scheduleCoalChatPoll(delayMs = 1300) {
    if (
      !state.chat.pendingReply ||
      els.coalChatWorkbench.hidden ||
      document.hidden
    ) {
      return;
    }
    if (state.chat.pollTimer !== null) {
      window.clearTimeout(state.chat.pollTimer);
    }
    state.chat.pollTimer = window.setTimeout(() => {
      state.chat.pollTimer = null;
      void pollCoalChatReply();
    }, Math.max(0, Number(delayMs) || 0));
  }

  async function pollCoalChatReply() {
    const pending = state.chat.pendingReply;
    if (!pending || pending.sessionId !== state.chat.selectedSessionId) return;
    const detail = await loadCoalChatSession(pending.sessionId, {
      polling: true,
      quiet: true,
    });
    if (coalChatIntegrityFailed(detail)) {
      stopCoalChatPolling();
      renderCoalChat();
      return;
    }
    if (coalChatReplyResolved(detail, pending)) {
      finishCoalChatReply();
      showToast(
        coalChatLatestMessageIsOutOfScope(detail)
          ? "该问题不属于煤炭业务，助手已明确拒绝。"
          : "煤炭业务助手已回复。",
      );
      return;
    }
    if (coalChatReplyFailed(detail, pending)) {
      state.chat.detailError =
        "这次回答没有完成。问题没有被再次发送，您可以修改后重新提问。";
      finishCoalChatReply({ preserveError: true });
      renderCoalChat();
      return;
    }
    if (
      state.chat.pollFailures >= 5 ||
      Date.now() - state.chat.pollStartedAt > 90_000
    ) {
      stopCoalChatPolling();
      state.chat.sending = false;
      state.chat.deliveryUnknown = true;
      state.chat.detailError =
        "回答仍在后台处理或暂时无法读取。为避免重复提问，发送按钮已锁定；请稍后点击“重新加载”。";
      renderCoalChat();
      return;
    }
    scheduleCoalChatPoll(1300);
  }

  function stopCoalChatPolling() {
    if (state.chat.pollTimer !== null) {
      window.clearTimeout(state.chat.pollTimer);
      state.chat.pollTimer = null;
    }
  }

  function finishCoalChatReply(options = {}) {
    stopCoalChatPolling();
    state.chat.pendingReply = null;
    state.chat.sending = false;
    state.chat.deliveryUnknown = false;
    state.chat.pollStartedAt = 0;
    state.chat.pollFailures = 0;
    if (!options.preserveError) state.chat.detailError = "";
    renderCoalChat();
  }

  function applyCoalChatMessageResponse(sessionId, payload) {
    const rawSession = unwrapCoalChatSession(payload);
    const hasSession = Boolean(
      rawSession &&
      typeof rawSession === "object" &&
      (rawSession.session_id || rawSession.id || Array.isArray(rawSession.messages)),
    );
    if (hasSession) {
      const session = normalizeCoalChatSession(rawSession);
      if (!session.session_id) session.session_id = sessionId;
      state.chat.detail = session;
      upsertCoalChatSession(session);
      return;
    }
    if (!state.chat.detail || state.chat.detail.session_id !== sessionId) return;
    const additions = coalChatResponseMessages(payload);
    if (!additions.length) return;
    const existing = state.chat.detail.messages || [];
    additions.forEach((message) => {
      const duplicate = existing.some(
        (item) =>
          (message.message_id && item.message_id === message.message_id) ||
          (item.role === message.role &&
            item.content === message.content &&
            item.created_at === message.created_at),
      );
      if (!duplicate) existing.push(message);
    });
    state.chat.detail.messages = existing;
    upsertCoalChatSession(state.chat.detail);
  }

  function coalChatResponseMessages(payload) {
    if (!payload || typeof payload !== "object") return [];
    const values = [
      payload.assistant_message,
      payload.assistant,
      payload.reply,
      payload.message &&
      typeof payload.message === "object"
        ? payload.message
        : null,
    ].filter((value) => value !== null && value !== undefined);
    return values
      .map((value, index) =>
        normalizeCoalChatMessage(
          typeof value === "string"
            ? { role: "assistant", content: value }
            : value,
          index,
        ),
      )
      .filter((message) => message.content || message.status === "processing");
  }

  function coalChatResponsePending(payload, httpStatus) {
    if (Number(httpStatus) === 202) return true;
    if (!payload || typeof payload !== "object") return false;
    const statuses = [
      payload.status,
      payload.assistant_status,
      payload.assistant_message && payload.assistant_message.status,
      payload.assistant && payload.assistant.status,
    ].map((value) => String(value || "").toLowerCase());
    if (statuses.some((status) => ["queued", "running", "processing"].includes(status))) {
      return true;
    }
    return Boolean(
      payload.run_id &&
      !statuses.some((status) => ["completed", "failed", "rejected"].includes(status)),
    );
  }

  function coalChatReplyResolved(detail, pending) {
    if (!detail || !pending || !Array.isArray(detail.messages)) return false;
    const baselineIds = new Set(pending.baselineAssistantIds || []);
    return detail.messages.some((message, index) => {
      if (
        message.role !== "assistant" ||
        coalChatMessagePending(message) ||
        ["failed", "error"].includes(message.status)
      ) {
        return false;
      }
      const isNew =
        index >= Number(pending.baselineCount || 0) ||
        (message.message_id && !baselineIds.has(message.message_id));
      return Boolean(isNew && (message.content || message.out_of_scope));
    });
  }

  function coalChatReplyFailed(detail, pending) {
    if (!detail || !pending || !Array.isArray(detail.messages)) return false;
    return detail.messages
      .slice(Number(pending.baselineCount || 0))
      .some(
        (message) =>
          message.role === "assistant" &&
          ["failed", "error"].includes(message.status),
      );
  }

  function coalChatUserMessageAccepted(detail, pending) {
    if (!detail || !pending || !Array.isArray(detail.messages)) return false;
    return detail.messages.some(
      (message, index) =>
        message.role === "user" &&
        (message.client_message_id === pending.clientMessageId ||
          (index >= Number(pending.baselineCount || 0) &&
            message.content === pending.content)),
    );
  }

  function coalChatMessagePending(message) {
    return ["queued", "running", "processing"].includes(
      String(message && message.status || "").toLowerCase(),
    );
  }

  function coalChatLatestMessageIsOutOfScope(detail) {
    const messages =
      detail && Array.isArray(detail.messages) ? detail.messages : [];
    const latest = messages[messages.length - 1];
    return Boolean(latest && latest.out_of_scope);
  }

  function coalChatErrorIsOutOfScope(error) {
    const payload = error && error.payload;
    return Boolean(
      (error &&
        ["out_of_scope", "coal_scope_required"].includes(
          String(error.code || ""),
        )) ||
      (payload &&
        typeof payload === "object" &&
        (payload.out_of_scope === true ||
          payload.scope_status === "out_of_scope")),
    );
  }

  function appendLocalCoalChatRefusal(sessionId, content) {
    if (!state.chat.detail || state.chat.detail.session_id !== sessionId) return;
    state.chat.detail.messages = [
      ...(state.chat.detail.messages || []),
      normalizeCoalChatMessage({
        message_id: newClientRequestId("local-refusal"),
        role: "assistant",
        content,
        status: "rejected",
        out_of_scope: true,
        created_at: new Date().toISOString(),
      }),
    ];
    upsertCoalChatSession(state.chat.detail);
  }

  function unwrapCoalChatSession(payload) {
    if (!payload || typeof payload !== "object") return {};
    const nested = payload.session || payload.conversation || payload.chat;
    if (!nested || typeof nested !== "object") return payload;
    if (
      Object.prototype.hasOwnProperty.call(payload, "integrity") &&
      !Object.prototype.hasOwnProperty.call(nested, "integrity")
    ) {
      return { ...nested, integrity: payload.integrity };
    }
    return nested;
  }

  function normalizeCoalChatSession(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const integrityProvided = Object.prototype.hasOwnProperty.call(
      source,
      "integrity",
    );
    const integritySource =
      source.integrity &&
      typeof source.integrity === "object" &&
      !Array.isArray(source.integrity)
        ? source.integrity
        : null;
    const integrity =
      !integrityProvided
        ? null
        : integritySource
          ? {
              valid: integritySource.valid === true,
              event_count: Number(integritySource.event_count || 0),
              head_hash: String(integritySource.head_hash || ""),
            }
          : {
              valid: false,
              event_count: 0,
              head_hash: "",
            };
    const messages =
      !integrity || integrity.valid === true
        ? Array.isArray(source.messages)
          ? source.messages.map(normalizeCoalChatMessage)
          : []
        : [];
    return {
      session_id: String(source.session_id || source.id || ""),
      title: String(source.title || source.subject || "煤炭业务对话"),
      draft_id: String(source.draft_id || ""),
      client_request_id: String(source.client_request_id || ""),
      status: String(source.status || "active"),
      integrity,
      messages,
      created_at: source.created_at || "",
      updated_at: source.updated_at || "",
    };
  }

  function normalizeCoalChatMessage(raw, index = 0) {
    const source = raw && typeof raw === "object" ? raw : {};
    const roleValue = String(source.role || source.author || "assistant").toLowerCase();
    const role = ["user", "assistant", "system"].includes(roleValue)
      ? roleValue
      : "assistant";
    const contentValue = firstDefined(
      source.content,
      source.text,
      source.answer,
      source.message,
      "",
    );
    const content = Array.isArray(contentValue)
      ? contentValue
        .map((part) =>
          typeof part === "string"
            ? part
            : part && typeof part.text === "string"
              ? part.text
              : "",
        )
        .filter(Boolean)
        .join("\n")
      : typeof contentValue === "string"
        ? contentValue
        : "";
    const scopeStatus = String(
      source.scope_status ||
      source.classification ||
      source.reason_code ||
      "",
    ).toLowerCase();
    const evidenceSource =
      source.evidence &&
      typeof source.evidence === "object" &&
      !Array.isArray(source.evidence)
        ? source.evidence
        : {};
    const answerKind = String(
      firstDefined(
        evidenceSource.answer_kind,
        source.answer_kind,
        evidenceSource.kind,
        "",
      ),
    ).toLowerCase();
    const rawTools = firstDefined(
      evidenceSource.tools,
      source.tools,
      evidenceSource.tool_calls,
      source.tool_calls,
      [],
    );
    const tools = Array.isArray(rawTools)
      ? rawTools
        .slice(0, 24)
        .map((rawTool) => {
          const tool =
            rawTool && typeof rawTool === "object" && !Array.isArray(rawTool)
              ? rawTool
              : { tool_name: typeof rawTool === "string" ? rawTool : "" };
          return {
            tool_name: truncateText(
              String(tool.tool_name || tool.name || ""),
              100,
            ),
            status: String(tool.status || "").toLowerCase(),
            evidence_grounding: String(
              tool.evidence_grounding || tool.grounding || "",
            ).toLowerCase(),
          };
        })
        .filter((tool) => tool.tool_name)
      : [];
    const modelGeneratedValue = firstDefined(
      evidenceSource.model_generated,
      source.model_generated,
      false,
    );
    const retrievalSource =
      evidenceSource.retrieval &&
      typeof evidenceSource.retrieval === "object" &&
      !Array.isArray(evidenceSource.retrieval)
        ? evidenceSource.retrieval
        : {};
    const retrievalStatus = String(retrievalSource.status || "").toLowerCase();
    const summarySource =
      evidenceSource.summary &&
      typeof evidenceSource.summary === "object" &&
      !Array.isArray(evidenceSource.summary)
        ? evidenceSource.summary
        : {};
    const summaryStatus = String(summarySource.status || "").toLowerCase();
    const rawNewsSources = firstDefined(
      evidenceSource.sources,
      source.sources,
      [],
    );
    const newsSources = Array.isArray(rawNewsSources)
      ? rawNewsSources
        .slice(0, 10)
        .map(normalizeCoalNewsSource)
        .filter(Boolean)
      : [];
    const resultCount = Number(retrievalSource.result_count);
    const windowDays = Number(retrievalSource.window_days);
    const evidence = {
      answer_kind: answerKind,
      skill_name: truncateText(
        String(firstDefined(evidenceSource.skill_name, source.skill_name, "")),
        100,
      ),
      model_generated:
        modelGeneratedValue === true ||
        modelGeneratedValue === 1 ||
        String(modelGeneratedValue).toLowerCase() === "true",
      local_knowledge_topic: truncateText(
        String(
          firstDefined(
            evidenceSource.local_knowledge_topic,
            source.local_knowledge_topic,
            "",
          ),
        ),
        120,
      ),
      tools,
      retrieval: {
        status: ["succeeded", "partial", "failed", "unavailable"].includes(
          retrievalStatus,
        )
          ? retrievalStatus
          : "",
        searched_at: truncateText(String(retrievalSource.searched_at || ""), 80),
        window_days: Number.isFinite(windowDays) && windowDays >= 0
          ? Math.min(Math.floor(windowDays), 3650)
          : null,
        result_count: Number.isFinite(resultCount) && resultCount >= 0
          ? Math.min(Math.floor(resultCount), 100000)
          : null,
        provider: truncateText(String(retrievalSource.provider || ""), 120),
        failure_code: truncateText(
          String(retrievalSource.failure_code || "").toLowerCase(),
          80,
        ),
        fallback_used: retrievalSource.fallback_used === true,
        partial_reasons: Array.isArray(retrievalSource.partial_reasons)
          ? retrievalSource.partial_reasons
            .slice(0, 10)
            .map((reason) => truncateText(String(reason), 80))
          : [],
        provider_attempts: Array.isArray(retrievalSource.provider_attempts)
          ? retrievalSource.provider_attempts.slice(0, 8).map((attempt) => ({
            provider: truncateText(String(attempt && attempt.provider || ""), 80),
            status: truncateText(
              String(attempt && attempt.status || "").toLowerCase(),
              40,
            ),
            failure_code: truncateText(
              String(attempt && attempt.failure_code || "").toLowerCase(),
              80,
            ),
            result_count: Number.isFinite(Number(attempt && attempt.result_count))
              ? Math.max(0, Math.min(100, Number(attempt.result_count)))
              : 0,
            elapsed_ms: Number.isFinite(Number(attempt && attempt.elapsed_ms))
              ? Math.max(0, Math.min(120000, Number(attempt.elapsed_ms)))
              : null,
          }))
          : [],
      },
      summary: {
        status: [
          "succeeded",
          "failed",
          "unavailable",
          "not_attempted",
        ].includes(summaryStatus)
          ? summaryStatus
          : "",
        provider: truncateText(String(summarySource.provider || ""), 120),
        grounding: truncateText(String(summarySource.grounding || ""), 120),
        source_count: Number.isFinite(Number(summarySource.source_count))
          ? Math.max(0, Math.min(10, Number(summarySource.source_count)))
          : null,
        failure_code: truncateText(
          String(summarySource.failure_code || "").toLowerCase(),
          80,
        ),
      },
      sources: newsSources,
    };
    return {
      message_id: String(source.message_id || source.id || `message-${index + 1}`),
      client_message_id: String(source.client_message_id || ""),
      role,
      content: truncateText(content, 12000),
      status: String(source.status || "completed").toLowerCase(),
      out_of_scope: Boolean(
        source.out_of_scope === true ||
        ["out_of_scope", "non_coal", "scope_rejected"].includes(scopeStatus) ||
        ["out_of_scope", "scope_refusal", "scope_rejected"].includes(answerKind) ||
        source.status === "rejected" && scopeStatus !== "safety_refusal",
      ),
      evidence,
      created_at: source.created_at || source.timestamp || "",
    };
  }

  function normalizeCoalNewsSource(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
    const url = safeCoalNewsSourceUrl(raw.url);
    if (!url) return null;
    return {
      source_id: truncateText(String(raw.source_id || ""), 8),
      title: truncateText(String(raw.title || "新闻来源"), 240),
      publisher: truncateText(String(raw.publisher || ""), 160),
      url,
      search_snippet: truncateText(String(raw.search_snippet || ""), 1000),
      snippet_origin: truncateText(String(raw.snippet_origin || ""), 80),
      snippet_truncated: raw.snippet_truncated === true,
      published_at: truncateText(String(raw.published_at || ""), 80),
      published_time_text: truncateText(
        String(raw.published_time_text || ""),
        80,
      ),
      published_at_estimated: raw.published_at_estimated === true,
      date_confidence: truncateText(String(raw.date_confidence || ""), 40),
      retrieved_at: truncateText(String(raw.retrieved_at || ""), 80),
      retrieval_provider: truncateText(
        String(raw.retrieval_provider || ""),
        80,
      ),
    };
  }

  function coalNewsProviderLabel(provider) {
    return {
      "baidu-news-search": "百度新闻",
      "deepseek-web-search": "DeepSeek 联网搜索",
      "bing-news-rss": "Bing News",
      "multi-provider": "多源检索",
    }[String(provider || "").toLowerCase()] || "新闻源";
  }

  function coalNewsFailureLabel(code) {
    return {
      network_timeout: "连接超时，请检查服务器 DNS 或代理",
      network_unavailable: "服务器网络或 DNS 不可用",
      challenge_required: "百度要求安全验证",
      authentication_failed: "DeepSeek Web Search 鉴权失败",
      rate_limited: "新闻源请求频率受限",
      upstream_blocked: "新闻源拒绝访问",
      upstream_unavailable: "上游新闻服务异常",
      invalid_search_page: "新闻页未返回可识别结果",
      invalid_provider_response: "联网搜索返回格式异常",
      provider_search_error: "联网搜索执行失败",
      no_results: "未取得合格结果",
      busy: "检索任务繁忙",
      deadline_exhausted: "总检索时间已用完",
      providers_exhausted: "所有新闻源均未成功",
    }[String(code || "").toLowerCase()] || "未成功";
  }

  function coalNewsAttemptSummary(attempts) {
    if (!Array.isArray(attempts)) return "";
    return attempts
      .slice(0, 5)
      .map((attempt) => {
        const provider = coalNewsProviderLabel(attempt && attempt.provider);
        if (attempt && attempt.failure_code) {
          return `${provider}：${coalNewsFailureLabel(attempt.failure_code)}`;
        }
        const count = Number(attempt && attempt.result_count);
        return `${provider}：取得 ${Number.isFinite(count) ? count : 0} 条`;
      })
      .join("；");
  }

  function safeCoalNewsSourceUrl(raw) {
    if (typeof raw !== "string") return "";
    const candidate = raw.trim();
    if (!candidate || candidate.length > 2048 || /[\u0000-\u001f\u007f]/.test(candidate)) {
      return "";
    }
    try {
      const parsed = new URL(candidate);
      if (
        parsed.protocol !== "https:" ||
        parsed.username ||
        parsed.password
      ) {
        return "";
      }
      const hostname = parsed.hostname
        .toLowerCase()
        .replace(/^\[|\]$/g, "")
        .replace(/\.$/, "");
      if (
        !hostname ||
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local") ||
        hostname.includes(":") ||
        isNonPublicIpv4Literal(hostname)
      ) {
        return "";
      }
      return parsed.href;
    } catch (_error) {
      return "";
    }
  }

  function isNonPublicIpv4Literal(hostname) {
    if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return false;
    const parts = hostname.split(".").map(Number);
    if (parts.some((part) => part < 0 || part > 255)) return true;
    const [first, second, third] = parts;
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 192 && second === 0 && third === 0) ||
      (first === 192 && second === 0 && third === 2) ||
      (first === 198 && (second === 18 || second === 19)) ||
      (first === 198 && second === 51 && third === 100) ||
      (first === 203 && second === 0 && third === 113)
    );
  }

  function coalChatAnswerProvenance(message, detail) {
    if (!message || message.role !== "assistant") return null;
    const evidence =
      message.evidence &&
      typeof message.evidence === "object" &&
      !Array.isArray(message.evidence)
        ? message.evidence
        : {};
    const answerKind = String(evidence.answer_kind || "").toLowerCase();
    if (
      message.out_of_scope ||
      ["out_of_scope", "scope_refusal", "scope_rejected"].includes(answerKind)
    ) {
      return {
        kind: "scope-refusal",
        badge: "范围控制",
        description: "超出煤炭业务范围，未作为业务分析处理。",
        title: "越界问题拒绝",
      };
    }
    const newsRetrieval =
      answerKind === "news_retrieval" ||
      String(evidence.skill_name || "").toLowerCase() === "coal-news-search";
    if (newsRetrieval) {
      const retrieval =
        evidence.retrieval &&
        typeof evidence.retrieval === "object" &&
        !Array.isArray(evidence.retrieval)
          ? evidence.retrieval
          : {};
      const status = String(retrieval.status || "").toLowerCase();
      const failureCode = String(retrieval.failure_code || "").toLowerCase();
      const sourceCount = Array.isArray(evidence.sources)
        ? evidence.sources.length
        : 0;
      const summary =
        evidence.summary &&
        typeof evidence.summary === "object" &&
        !Array.isArray(evidence.summary)
          ? evidence.summary
          : {};
      const aiSummarized =
        evidence.model_generated === true &&
        String(summary.status || "").toLowerCase() === "succeeded";
      const provider = retrieval.provider
        ? `；检索服务：${coalNewsProviderLabel(retrieval.provider)}`
        : "";
      const attemptSummary = coalNewsAttemptSummary(
        retrieval.provider_attempts,
      );
      if (status === "succeeded" && sourceCount > 0) {
        return {
          kind: "news-retrieval",
          badge: aiSummarized ? "AI 联网摘要" : "联网新闻检索",
          description: aiSummarized
            ? `AI 已基于 ${sourceCount} 条搜索标题和片段归纳；未读取新闻全文，请以原文为准。`
            : `已获取 ${sourceCount} 条可核验来源；AI 摘要不可用，请直接查看来源。`,
          title: `${aiSummarized ? "AI 新闻摘要完成" : "新闻检索成功"}${provider}`,
        };
      }
      if (status === "partial" && sourceCount > 0) {
        return {
          kind: "news-partial",
          badge: aiSummarized ? "AI 摘要 · 部分检索" : "部分检索",
          description: `${aiSummarized ? "AI 已基于现有搜索片段归纳；" : ""}已获取 ${sourceCount} 条有效来源，结果可能不完整。${
            attemptSummary ? ` ${attemptSummary}。` : ""
          }`,
          title: `新闻检索部分成功${provider}`,
        };
      }
      if (status === "failed" && failureCode === "no_results") {
        return {
          kind: "news-no-results",
          badge: "未检索到结果",
          description:
            "本次检索未获得通过校验的来源，不代表没有新闻；可以调整时间范围或关键词后重试。",
          title: `新闻检索完成但没有有效结果${provider}`,
        };
      }
      return {
        kind: "news-failed",
        badge: "检索失败",
        description: `${coalNewsFailureLabel(failureCode)}。${
          attemptSummary ? ` 已尝试：${attemptSummary}。` : ""
        }`,
        title: status === "unavailable"
          ? "新闻搜索服务不可用"
          : status === "failed"
            ? "新闻搜索请求失败"
            : "新闻检索状态或来源无效",
      };
    }
    const successfulTools = Array.isArray(evidence.tools)
      ? evidence.tools.filter((tool) =>
          ["succeeded", "completed", "success"].includes(
            String(tool && tool.status || "").toLowerCase(),
          ),
        )
      : [];
    if (successfulTools.length) {
      const integrityVerified = Boolean(
        detail &&
        detail.integrity &&
        typeof detail.integrity === "object" &&
        detail.integrity.valid === true,
      );
      if (!integrityVerified) {
        return {
          kind: "unmarked",
          badge: "工具记录未验真",
          description: "未返回完整性校验，不能作为企业数据证据。",
          title: "工具记录缺少可验证的对话审计链",
        };
      }
      const draftGrounded = successfulTools.some(
        (tool) =>
          String(tool.evidence_grounding || "").toLowerCase() ===
          "repository_grounded",
      ) || Boolean(detail && detail.draft_id);
      const toolNames = successfulTools
        .map((tool) => tool.tool_name)
        .filter(Boolean)
        .join("、");
      return {
        kind: "tool-evidence",
        badge: draftGrounded ? "草稿工具证据" : "只读工具计算",
        description: `已使用 ${successfulTools.length} 个只读工具；请结合原始凭证人工复核。`,
        title: toolNames ? `已成功执行：${toolNames}` : "已成功执行只读工具",
      };
    }
    if (
      evidence.local_knowledge_topic ||
      ["local_knowledge", "local_common_knowledge", "curated_knowledge"].includes(
        answerKind,
      ) ||
      answerKind.includes("local_knowledge")
    ) {
      return {
        kind: "local-knowledge",
        badge: "本地煤炭常识",
        description: "来自内置煤炭知识，未据此核验企业实际数据。",
        title: evidence.local_knowledge_topic
          ? `本地知识主题：${evidence.local_knowledge_topic}`
          : "本地内置煤炭知识",
      };
    }
    if (
      evidence.model_generated === true ||
      ["model_knowledge", "model_common_knowledge", "llm_knowledge"].includes(
        answerKind,
      ) ||
      answerKind.includes("model_knowledge")
    ) {
      return {
        kind: "model-knowledge",
        badge: "模型通识解释",
        description: "由模型生成，未核验企业数据，不是数据事实或监管结论。",
        title: "模型通识回答",
      };
    }
    return {
      kind: "unmarked",
      badge: "回答来源未标注",
      description: "当前服务未说明回答依据，请勿视为企业数据事实。",
      title: "兼容旧版消息；回答依据未明确",
    };
  }

  function upsertCoalChatSession(session) {
    if (!session || !session.session_id) return;
    const index = state.chat.sessions.findIndex(
      (item) => item.session_id === session.session_id,
    );
    const summary = {
      ...(index >= 0 ? state.chat.sessions[index] : {}),
      ...session,
    };
    if (index >= 0) {
      state.chat.sessions.splice(index, 1, summary);
    } else {
      state.chat.sessions.unshift(summary);
      state.chat.total += 1;
    }
  }

  function selectedCoalChatDraftId() {
    return els.coalChatUseCurrentDraft.checked && state.activeDraft
      ? state.activeDraft.id
      : null;
  }

  function coalChatIntegrityFailed(detail) {
    return Boolean(
      detail &&
      detail.integrity &&
      typeof detail.integrity === "object" &&
      detail.integrity.valid !== true
    );
  }

  function renderCoalChat() {
    renderCoalChatControls();
    renderCoalChatSessions();
    renderCoalChatConversation();
  }

  function renderCoalChatControls() {
    if (!els.coalChatButton) return;
    const canRead = Boolean(state.principal && hasPermission("read"));
    const content = String((els.coalChatInput && els.coalChatInput.value) || "");
    const valid = content.trim().length > 0 && content.length <= 2000;
    const blocked = Boolean(
      state.chat.sending ||
      state.chat.deliveryUnknown ||
      state.chat.creating ||
      state.chat.deleting,
    );
    const integrityFailed = coalChatIntegrityFailed(state.chat.detail);
    els.coalChatButton.disabled = !canRead;
    els.newCoalChatButton.disabled = !canRead || blocked;
    els.refreshCoalChatButton.disabled =
      !canRead || state.chat.listLoading || state.chat.creating || state.chat.deleting;
    els.deleteCoalChatButton.disabled =
      !canRead || !state.chat.selectedSessionId || blocked || integrityFailed;
    els.coalChatInput.disabled =
      !canRead || state.chat.deleting || integrityFailed;
    els.coalChatInput.setAttribute("aria-invalid", String(!valid && content.length > 0));
    els.sendCoalChatButton.disabled =
      !canRead ||
      !state.chat.selectedSessionId ||
      !valid ||
      blocked ||
      integrityFailed;
    els.sendCoalChatButton.textContent = state.chat.sending
      ? "正在分析…"
      : state.chat.deliveryUnknown
        ? "请先重新加载"
        : "发送问题";
    els.sendCoalChatButton.setAttribute(
      "aria-busy",
      String(state.chat.sending),
    );
    els.coalChatCharacterCount.textContent = `${content.length}/2000`;
    els.coalChatCharacterCount.classList.toggle(
      "coal-chat-character-invalid",
      content.length > 2000,
    );
    if (!state.activeDraft) {
      els.coalChatUseCurrentDraft.checked = false;
    } else if (!state.chat.draftChoiceTouched) {
      els.coalChatUseCurrentDraft.checked = true;
    }
    els.coalChatUseCurrentDraft.disabled = !state.activeDraft || blocked;
    els.coalChatDraftBinding.textContent = state.activeDraft
      ? `${
          (state.activeDraft.enterprise &&
            (state.activeDraft.enterprise.mine_name ||
              state.activeDraft.enterprise.name)) ||
          "当前草稿"
        } · ${shortIdentifier(state.activeDraft.id)}`
      : "当前没有打开的草稿";
  }

  function renderCoalChatSessions() {
    if (!els.coalChatSessionList) return;
    const fragment = document.createDocumentFragment();
    if (state.chat.listLoading && !state.chat.sessions.length) {
      fragment.append(el("p", "coal-chat-list-empty", "正在读取对话记录…"));
    } else if (state.chat.listError && !state.chat.sessions.length) {
      fragment.append(
        el("p", "coal-chat-list-empty", `对话列表加载失败：${state.chat.listError}`),
      );
    } else if (!state.chat.sessions.length) {
      fragment.append(
        el(
          "p",
          "coal-chat-list-empty",
          "还没有业务对话。点击“新建对话”开始。",
        ),
      );
    }
    state.chat.sessions.forEach((session) => {
      const button = el("button", "coal-chat-session-item");
      button.type = "button";
      button.disabled =
        state.chat.sending || state.chat.deliveryUnknown || state.chat.deleting;
      const active = session.session_id === state.chat.selectedSessionId;
      button.classList.toggle("is-active", active);
      if (active) button.setAttribute("aria-current", "true");
      button.addEventListener("click", () =>
        void selectCoalChat(session.session_id),
      );
      button.append(
        el("strong", "", truncateText(session.title || "煤炭业务对话", 36)),
        el(
          "small",
          "",
          `${formatDateTime(session.updated_at || session.created_at)}${
            session.draft_id ? " · 已关联草稿" : ""
          }`,
        ),
      );
      fragment.append(button);
    });
    els.coalChatSessionList.replaceChildren(fragment);
    els.coalChatSessionList.setAttribute(
      "aria-busy",
      String(state.chat.listLoading),
    );
    const total = Math.max(state.chat.total, state.chat.sessions.length);
    els.coalChatListSummary.textContent = state.chat.listLoading
      ? `读取中 · 已显示 ${state.chat.sessions.length}/${total}`
      : `最近 ${state.chat.sessions.length}/${total} 项对话`;
  }

  function renderCoalChatConversation() {
    if (!els.coalChatMessageList) return;
    const detail = state.chat.detail;
    const hasDetail = Boolean(
      detail && detail.session_id === state.chat.selectedSessionId,
    );
    els.coalChatTitle.textContent = hasDetail
      ? truncateText(detail.title || "煤炭业务对话", 80)
      : state.chat.detailLoading
        ? "正在读取对话"
        : "请选择或新建一项对话";
    const integrityFailed = coalChatIntegrityFailed(detail);
    const errorMessage = integrityFailed
      ? ""
      : state.chat.detailError || state.chat.listError;
    els.coalChatError.hidden = !errorMessage;
    els.coalChatErrorText.textContent = errorMessage || "";
    const fragment = document.createDocumentFragment();
    if (integrityFailed) {
      fragment.append(
        el(
          "div",
          "coal-chat-error",
          "对话记录完整性异常，请联系管理员。",
        ),
      );
    } else if (state.chat.detailLoading && !hasDetail) {
      fragment.append(coalChatEmptyNode("正在读取对话内容，请稍候。"));
    } else if (!hasDetail) {
      fragment.append(
        coalChatEmptyNode(
          "新建或选择对话后，可以询问生产、洗选、运销、库存、能耗、安全和填报数据，也可以问“帮我看看最近煤炭相关新闻？”",
        ),
      );
    } else if (!detail.messages.length) {
      fragment.append(
        coalChatEmptyNode(
          "可以开始提问。例如：“结合当前草稿，本月煤量关系有哪些需要重点核查？”或“帮我看看最近煤炭相关新闻？”",
        ),
      );
    } else {
      detail.messages.forEach((message) => {
        const refusal = message.out_of_scope;
        const item = el(
          "section",
          `coal-chat-message is-${refusal ? "refusal" : message.role}`,
        );
        item.setAttribute(
          "aria-label",
          refusal
            ? "越界问题拒绝提示"
            : message.role === "user"
              ? "我的问题"
              : "煤炭业务助手回答",
        );
        const label = refusal
          ? "仅限煤炭业务 · 已拒绝"
          : message.role === "user"
            ? "我"
            : message.role === "system"
              ? "系统提示"
              : "煤炭业务助手";
        const bodyText = message.content ||
          (coalChatMessagePending(message) ? "正在分析这个煤炭业务问题…" : "未返回内容");
        item.append(el("span", "coal-chat-message-label", label));
        if (!coalChatMessagePending(message)) {
          const provenance = coalChatAnswerProvenance(message, detail);
          if (provenance) {
            const source = el(
              "div",
              `coal-chat-answer-source is-${provenance.kind}`,
            );
            source.setAttribute("aria-label", `回答依据：${provenance.badge}`);
            source.title = provenance.title;
            source.append(
              el("span", "coal-chat-source-badge", provenance.badge),
              el("small", "coal-chat-source-note", provenance.description),
            );
            item.append(source);
          }
        }
        item.append(el("div", "coal-chat-message-body", bodyText));
        const newsSources = coalChatNewsSourcesNode(message);
        if (newsSources) item.append(newsSources);
        if (message.created_at) {
          item.append(
            el("time", "coal-chat-message-time", formatDateTime(message.created_at)),
          );
        }
        fragment.append(item);
      });
      if (state.chat.sending && !coalChatReplyResolved(detail, state.chat.pendingReply)) {
        const pending = el("section", "coal-chat-message is-assistant");
        pending.setAttribute("aria-label", "煤炭业务助手正在回答");
        pending.append(
          el("span", "coal-chat-message-label", "煤炭业务助手"),
          el("div", "coal-chat-message-body", "正在核对业务范围并分析，请稍候…"),
        );
        fragment.append(pending);
      }
    }
    els.coalChatMessageList.replaceChildren(fragment);
    els.coalChatMessageList.setAttribute(
      "aria-busy",
      String(state.chat.detailLoading || state.chat.sending),
    );
    const outOfScope =
      !integrityFailed && coalChatLatestMessageIsOutOfScope(detail);
    els.coalChatScopeNotice.hidden = !outOfScope;
    window.setTimeout(() => {
      els.coalChatMessageList.scrollTop = els.coalChatMessageList.scrollHeight;
    }, 0);
  }

  function coalChatEmptyNode(text) {
    const empty = el("div", "coal-chat-empty");
    empty.append(
      el("span", "", "煤"),
      el("h3", "", "这里专门讨论煤炭业务"),
      el("p", "", text),
    );
    return empty;
  }

  function coalChatNewsSourcesNode(message) {
    if (!message || message.role !== "assistant") return null;
    const evidence =
      message.evidence &&
      typeof message.evidence === "object" &&
      !Array.isArray(message.evidence)
        ? message.evidence
        : {};
    const isNews =
      String(evidence.answer_kind || "").toLowerCase() === "news_retrieval" ||
      String(evidence.skill_name || "").toLowerCase() === "coal-news-search";
    const sources = Array.isArray(evidence.sources)
      ? evidence.sources.slice(0, 10)
      : [];
    if (!isNews || !sources.length) return null;
    const group = el("section", "coal-chat-news-sources");
    group.setAttribute("aria-label", "新闻来源");
    group.append(
      el("h4", "coal-chat-news-sources-title", `可核验新闻来源（${sources.length}）`),
    );
    const list = el("div", "coal-chat-news-source-list");
    sources.forEach((source, index) => {
      const link = el("a", "coal-chat-news-source-card");
      link.href = source.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.referrerPolicy = "no-referrer";
      link.setAttribute("aria-label", `打开新闻来源 ${index + 1}：${source.title}`);
      link.append(
        el(
          "strong",
          "coal-chat-news-source-title",
          `${source.source_id || `S${index + 1}`}｜${source.title}`,
        ),
        el(
          "span",
          "coal-chat-news-source-publisher",
          `${
            source.retrieval_provider === "baidu-news-search"
              ? "百度标注来源"
              : "来源"
          }：${source.publisher || "未标明"}`,
        ),
        el(
          "span",
          "coal-chat-news-source-time",
          `发布时间：${
            source.published_at
              ? `${formatDateTime(source.published_at)}${
                source.published_at_estimated ? "（约）" : ""
              }`
              : source.published_time_text || "搜索源未提供"
          }`,
        ),
        el(
          "span",
          "coal-chat-news-source-time",
          `检索渠道：${coalNewsProviderLabel(source.retrieval_provider)}`,
        ),
        el(
          "span",
          "coal-chat-news-source-time",
          `检索时间：${
            source.retrieved_at
              ? formatDateTime(source.retrieved_at)
              : evidence.retrieval && evidence.retrieval.searched_at
                ? formatDateTime(evidence.retrieval.searched_at)
                : "未标明"
          }`,
        ),
      );
      if (source.search_snippet) {
        link.append(
          el(
            "p",
            "coal-chat-news-source-snippet",
            `搜索片段（可能截断，未核验正文）：${source.search_snippet}`,
          ),
        );
      }
      list.append(link);
    });
    group.append(list);
    return group;
  }

  const agentV2ActiveStatuses = new Set([
    "queued",
    "running",
    "waiting",
    "retrying",
  ]);

  const agentV2AttentionStatuses = new Set([
    "blocked",
    "failed",
    "lost",
  ]);

  function agentV2StatusLabel(status) {
    const labels = {
      idle: "尚未读取",
      queued: "等待执行",
      running: "正在检查",
      waiting: "等待处理",
      retrying: "正在重试",
      blocked: "需要关注",
      succeeded: "已完成",
      completed: "已完成",
      failed: "执行失败",
      cancelled: "已取消",
      lost: "执行中断",
      enabled: "已启用",
      disabled: "已停用",
      pending: "待审批",
      approved: "已批准",
      rejected: "已拒绝",
      active: "已生效",
      retired: "已停用",
    };
    const normalized = String(status || "idle").toLowerCase();
    return labels[normalized] || normalized.replace(/_/g, " ");
  }

  function normalizeAgentV2Status(status, fallback = "idle") {
    const normalized = String(status || fallback)
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, "_");
    return normalized || fallback;
  }

  function agentV2FlowId(source) {
    return String(
      (source && (source.flow_id || source.id || source.task_id)) || "",
    );
  }

  function normalizeAgentV2Flow(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const stateData =
      source.state && typeof source.state === "object"
        ? source.state
        : source.state_json && typeof source.state_json === "object"
          ? source.state_json
          : {};
    const steps = Array.isArray(source.steps)
      ? source.steps
      : Array.isArray(stateData.steps)
        ? stateData.steps
        : [];
    return {
      ...source,
      flow_id: agentV2FlowId(source),
      workflow_name: String(
        source.workflow_name || source.workflow || "daily_coal_health",
      ),
      goal_text: String(source.goal_text || source.goal || ""),
      draft_id: String(source.draft_id || stateData.draft_id || ""),
      status: normalizeAgentV2Status(source.status, "queued"),
      revision: Number(source.revision || 1),
      current_step: String(
        source.current_step ||
          source.current_step_name ||
          stateData.current_step ||
          "",
      ),
      trigger_type: String(
        source.trigger_type ||
          (source.trigger && source.trigger.type) ||
          "manual",
      ),
      created_at: source.created_at || source.queued_at || "",
      updated_at: source.updated_at || source.completed_at || source.created_at || "",
      completed_at: source.completed_at || "",
      summary:
        source.summary !== undefined
          ? source.summary
          : source.result_summary !== undefined
            ? source.result_summary
            : stateData.summary,
      error_message: String(
        source.error_message ||
          (typeof source.error === "string" ? source.error : "") ||
          (source.error && source.error.message) ||
          (stateData.error && stateData.error.message) ||
          "",
      ),
      steps: steps.map(normalizeAgentV2Step),
      state: stateData,
    };
  }

  function normalizeAgentV2Step(raw, index = 0) {
    const source = raw && typeof raw === "object" ? raw : {};
    const result =
      source.result && typeof source.result === "object" ? source.result : {};
    return {
      ...source,
      step_key: String(
        source.step_key || source.key || source.name || `step-${index + 1}`,
      ),
      title: String(
        source.title ||
          source.label ||
          source.name ||
          source.step_key ||
          `步骤 ${index + 1}`,
      ),
      specialist: String(source.specialist || source.worker || ""),
      status: normalizeAgentV2Status(source.status, "queued"),
      summary: String(
        source.summary ||
          result.summary ||
          result.message ||
          (result.executive_brief && result.executive_brief.headline) ||
          source.error_message ||
          (source.error && source.error.message) ||
          "",
      ),
      started_at: source.started_at || "",
      completed_at: source.completed_at || "",
    };
  }

  function unwrapAgentV2Entity(payload, key) {
    if (!payload || typeof payload !== "object") return null;
    if (payload[key] && typeof payload[key] === "object") return payload[key];
    if (payload.item && typeof payload.item === "object") return payload.item;
    return payload;
  }

  function agentV2List(payload, ...keys) {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== "object") return [];
    for (const key of keys) {
      if (Array.isArray(payload[key])) return payload[key];
    }
    return Array.isArray(payload.items) ? payload.items : [];
  }

  async function openAgentV2Workbench() {
    if (!state.principal || !hasPermission("read")) {
      showToast("请先使用有读取权限的企业账号登录。", "error");
      return;
    }
    stopAgentPolling();
    stopCoalChatPolling();
    els.agentWorkbench.hidden = true;
    els.coalChatWorkbench.hidden = true;
    els.agentV2Workbench.hidden = false;
    if (state.interfaceMode !== "professional") {
      state.agentV2.selectedTab = "overview";
    }
    renderAgentV2();
    els.agentV2Workbench.focus();
    await loadAgentV2Flows();
    if (
      state.agentV2.selectedFlowId &&
      (!state.agentV2.detail ||
        state.agentV2.detail.flow_id !== state.agentV2.selectedFlowId)
    ) {
      await loadAgentV2Flow(state.agentV2.selectedFlowId);
    } else if (!state.agentV2.selectedFlowId && state.agentV2.flows.length) {
      await selectAgentV2Flow(state.agentV2.flows[0].flow_id);
    }
    if (
      state.interfaceMode === "professional" &&
      state.agentV2.selectedTab !== "overview"
    ) {
      await loadAgentV2TabData(state.agentV2.selectedTab);
    }
  }

  function closeAgentV2Workbench() {
    stopAgentV2Polling();
    els.agentV2Workbench.hidden = true;
    const target =
      state.interfaceMode === "simple"
        ? els.openAgentCenterQuickButton
        : els.agentCenterButton;
    if (target && !target.disabled) target.focus();
  }

  async function refreshAgentV2Workbench() {
    if (state.agentV2.loading || state.agentV2.busy.has("refresh")) return;
    state.agentV2.busy.add("refresh");
    setBusy(els.refreshAgentV2Button, true, "刷新中…");
    state.agentV2.error = "";
    renderAgentV2Error();
    try {
      await loadAgentV2Flows({ force: true });
      if (state.agentV2.selectedFlowId) {
        await loadAgentV2Flow(state.agentV2.selectedFlowId, { force: true });
      }
      if (state.interfaceMode === "professional") {
        if (state.agentV2.selectedTab === "schedules") {
          await loadAgentV2Jobs({ force: true });
        }
        if (state.agentV2.selectedTab === "governance") {
          await loadAgentV2Governance({ force: true });
        }
      }
    } finally {
      state.agentV2.busy.delete("refresh");
      setBusy(els.refreshAgentV2Button, false);
      renderAgentV2();
    }
  }

  async function selectAgentV2Tab(tabName) {
    const allowed = ["overview", "schedules", "governance"];
    const next = allowed.includes(tabName) ? tabName : "overview";
    if (state.interfaceMode !== "professional" && next !== "overview") {
      showToast("请切换到“专业工具”后管理定时任务、记忆和技能。");
      return;
    }
    state.agentV2.selectedTab = next;
    renderAgentV2Tabs();
    await loadAgentV2TabData(next);
  }

  async function loadAgentV2TabData(tabName) {
    if (tabName === "overview") {
      await loadAgentV2Flows();
    } else if (tabName === "schedules") {
      await loadAgentV2Jobs();
    } else if (tabName === "governance") {
      await loadAgentV2Governance();
    }
  }

  async function loadAgentV2Flows(options = {}) {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.agentV2.loading ||
      (state.agentV2.flowsLoaded && !options.force)
    ) {
      renderAgentV2();
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    state.agentV2.loading = true;
    state.agentV2.error = "";
    renderAgentV2();
    try {
      const payload = await api(endpoints.agentFlows(), { timeoutMs: 20000 });
      if (sessionRequestIsStale(sessionGeneration)) return;
      const rows = agentV2List(payload, "flows");
      state.agentV2.flows = rows
        .map(normalizeAgentV2Flow)
        .filter((flow) => flow.flow_id);
      state.agentV2.flowsLoaded = true;
      if (
        state.agentV2.selectedFlowId &&
        !state.agentV2.flows.some(
          (flow) => flow.flow_id === state.agentV2.selectedFlowId,
        )
      ) {
        state.agentV2.selectedFlowId = "";
        state.agentV2.detail = null;
      }
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.agentV2.error = error.message;
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.agentV2.loading = false;
        renderAgentV2();
      }
    }
  }

  async function selectAgentV2Flow(flowId) {
    if (!flowId) return;
    state.agentV2.selectedFlowId = flowId;
    state.agentV2.detail = null;
    state.agentV2.pollStartedAt = Date.now();
    state.agentV2.pollFailures = 0;
    renderAgentV2();
    await loadAgentV2Flow(flowId);
  }

  async function loadAgentV2Flow(flowId, options = {}) {
    if (
      !flowId ||
      !state.principal ||
      !hasPermission("read") ||
      (state.agentV2.detailLoading && !options.polling)
    ) {
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    const sequence = ++state.agentV2.requestSequence;
    if (!options.polling) state.agentV2.detailLoading = true;
    renderAgentV2FlowDetail();
    try {
      const payload = await api(endpoints.agentFlow(flowId), {
        timeoutMs: 20000,
      });
      if (
        sessionRequestIsStale(sessionGeneration) ||
        sequence !== state.agentV2.requestSequence ||
        state.agentV2.selectedFlowId !== flowId
      ) {
        return;
      }
      const flow = normalizeAgentV2Flow(
        unwrapAgentV2Entity(payload, "flow"),
      );
      if (!flow.flow_id) throw new Error("服务返回的任务详情缺少任务编号。");
      state.agentV2.detail = flow;
      state.agentV2.error = "";
      state.agentV2.pollFailures = 0;
      upsertAgentV2Flow(flow);
      if (agentV2ActiveStatuses.has(flow.status)) {
        scheduleAgentV2Poll(1800);
      } else {
        stopAgentV2Polling();
      }
    } catch (error) {
      if (
        sessionRequestIsStale(sessionGeneration, error) ||
        sequence !== state.agentV2.requestSequence ||
        state.agentV2.selectedFlowId !== flowId
      ) {
        return;
      }
      state.agentV2.pollFailures += 1;
      state.agentV2.error = error.message;
      if (
        options.polling &&
        state.agentV2.pollFailures < 5 &&
        state.agentV2.detail &&
        agentV2ActiveStatuses.has(state.agentV2.detail.status)
      ) {
        scheduleAgentV2Poll(
          Math.min(10000, 1800 * state.agentV2.pollFailures),
        );
      }
    } finally {
      if (sequence === state.agentV2.requestSequence) {
        state.agentV2.detailLoading = false;
        renderAgentV2();
      }
    }
  }

  function upsertAgentV2Flow(flow) {
    const index = state.agentV2.flows.findIndex(
      (item) => item.flow_id === flow.flow_id,
    );
    if (index >= 0) {
      state.agentV2.flows.splice(index, 1, {
        ...state.agentV2.flows[index],
        ...flow,
      });
    } else {
      state.agentV2.flows.unshift(flow);
    }
  }

  async function startAgentV2HealthCheck() {
    if (state.agentV2.busy.has("create-flow")) return;
    if (!state.principal || !hasPermission("read") || !state.activeDraft) {
      showToast(
        state.activeDraft
          ? "当前账号没有读取该草稿的权限。"
          : "请先从左侧打开一份需要体检的草稿。",
        "error",
      );
      return;
    }
    state.agentV2.busy.add("create-flow");
    const draftId = state.activeDraft.id;
    [els.runAgentCenterQuickButton, els.startAgentV2HealthButton].forEach(
      (button) => setBusy(button, true, "正在发起…"),
    );
    try {
      const payload = await api(endpoints.agentFlows(), {
        method: "POST",
        body: {
          workflow_name: "daily_coal_health",
          draft_id: draftId,
          goal_text:
            "对当前草稿执行每日煤炭体检，汇总来源、时间、煤流平衡和历史异常，给出负责人可读结论。只读分析，不修改、确认或提交草稿。",
          client_request_id: newClientRequestId("daily-health"),
        },
        timeoutMs: 30000,
      });
      const flow = normalizeAgentV2Flow(
        unwrapAgentV2Entity(payload, "flow"),
      );
      if (!flow.flow_id) throw new Error("服务没有返回新任务编号。");
      upsertAgentV2Flow(flow);
      state.agentV2.flowsLoaded = true;
      state.agentV2.selectedFlowId = flow.flow_id;
      state.agentV2.detail = flow;
      state.agentV2.error = "";
      state.agentV2.pollStartedAt = Date.now();
      state.agentV2.pollFailures = 0;
      els.agentWorkbench.hidden = true;
      els.coalChatWorkbench.hidden = true;
      els.agentV2Workbench.hidden = false;
      state.agentV2.selectedTab = "overview";
      renderAgentV2();
      els.agentV2Workbench.focus();
      if (agentV2ActiveStatuses.has(flow.status)) scheduleAgentV2Poll(800);
      showToast("每日煤炭体检已发起，可离开页面后稍后回来查看。");
    } catch (error) {
      state.agentV2.error = error.message;
      renderAgentV2();
      showToast(`体检没有发起成功：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("create-flow");
      [els.runAgentCenterQuickButton, els.startAgentV2HealthButton].forEach(
        (button) => setBusy(button, false),
      );
      renderAgentV2();
    }
  }

  async function cancelSelectedAgentV2Flow() {
    const flow = state.agentV2.detail;
    if (
      !flow ||
      !agentV2ActiveStatuses.has(flow.status) ||
      state.agentV2.busy.has("flow-action")
    ) {
      return;
    }
    state.agentV2.busy.add("flow-action");
    setBusy(els.cancelAgentV2FlowButton, true, "取消中…");
    try {
      const payload = await api(endpoints.agentFlowCancel(flow.flow_id), {
        method: "POST",
        body: { expected_revision: flow.revision },
        timeoutMs: 20000,
      });
      const next = normalizeAgentV2Flow(
        unwrapAgentV2Entity(payload, "flow"),
      );
      state.agentV2.detail = next.flow_id
        ? next
        : { ...flow, status: "cancelled" };
      upsertAgentV2Flow(state.agentV2.detail);
      stopAgentV2Polling();
      showToast("任务已取消；已经产生的只读检查记录仍会保留。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`取消失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("flow-action");
      setBusy(els.cancelAgentV2FlowButton, false);
      renderAgentV2();
    }
  }

  async function retrySelectedAgentV2Flow() {
    const flow = state.agentV2.detail;
    if (
      !flow ||
      !["blocked", "failed"].includes(flow.status) ||
      state.agentV2.busy.has("flow-action")
    ) {
      return;
    }
    state.agentV2.busy.add("flow-action");
    setBusy(els.retryAgentV2FlowButton, true, "重新发起…");
    try {
      const payload = await api(endpoints.agentFlowRetry(flow.flow_id), {
        method: "POST",
        body: { expected_revision: flow.revision },
        timeoutMs: 30000,
      });
      const next = normalizeAgentV2Flow(
        unwrapAgentV2Entity(payload, "flow"),
      );
      if (!next.flow_id) throw new Error("服务没有返回重试后的任务。");
      state.agentV2.detail = next;
      state.agentV2.selectedFlowId = next.flow_id;
      upsertAgentV2Flow(next);
      state.agentV2.pollStartedAt = Date.now();
      state.agentV2.pollFailures = 0;
      if (agentV2ActiveStatuses.has(next.status)) scheduleAgentV2Poll(800);
      showToast("任务已重新发起。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`重新执行失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("flow-action");
      setBusy(els.retryAgentV2FlowButton, false);
      renderAgentV2();
    }
  }

  function scheduleAgentV2Poll(delayMs) {
    stopAgentV2Polling();
    const flow = state.agentV2.detail;
    if (
      !flow ||
      !agentV2ActiveStatuses.has(flow.status) ||
      els.agentV2Workbench.hidden
    ) {
      return;
    }
    if (!state.agentV2.pollStartedAt) state.agentV2.pollStartedAt = Date.now();
    if (Date.now() - state.agentV2.pollStartedAt > 180_000) {
      state.agentV2.error =
        "任务仍在后台执行，页面已停止自动刷新。请稍后点击“刷新”查看。";
      renderAgentV2();
      return;
    }
    state.agentV2.pollTimer = window.setTimeout(() => {
      state.agentV2.pollTimer = null;
      void loadAgentV2Flow(flow.flow_id, { polling: true });
    }, Math.max(0, Number(delayMs) || 0));
  }

  function stopAgentV2Polling() {
    if (state.agentV2.pollTimer !== null) {
      window.clearTimeout(state.agentV2.pollTimer);
      state.agentV2.pollTimer = null;
    }
  }

  function normalizeAgentV2Job(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const schedule =
      source.schedule && typeof source.schedule === "object"
        ? source.schedule
        : source.schedule_json && typeof source.schedule_json === "object"
          ? source.schedule_json
          : {};
    return {
      ...source,
      job_id: String(source.job_id || source.id || ""),
      name: String(source.name || "每日煤炭体检"),
      workflow_name: String(source.workflow_name || "daily_coal_health"),
      draft_id: String(source.draft_id || ""),
      schedule_kind: String(source.schedule_kind || schedule.kind || "daily"),
      schedule,
      enabled: source.enabled !== false && source.status !== "disabled",
      revision: Number(source.revision || 1),
      next_run_at: source.next_run_at || "",
      last_run_at: source.last_run_at || "",
      last_flow_id: String(source.last_flow_id || ""),
    };
  }

  async function loadAgentV2Jobs(options = {}) {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.agentV2.busy.has("load-jobs") ||
      (state.agentV2.jobsLoaded && !options.force)
    ) {
      renderAgentV2Jobs();
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    state.agentV2.busy.add("load-jobs");
    renderAgentV2Jobs();
    try {
      const payload = await api(endpoints.agentJobs(), { timeoutMs: 20000 });
      if (sessionRequestIsStale(sessionGeneration)) return;
      state.agentV2.jobs = agentV2List(payload, "jobs")
        .map(normalizeAgentV2Job)
        .filter((job) => job.job_id);
      state.agentV2.jobsLoaded = true;
      state.agentV2.error = "";
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.agentV2.error = error.message;
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.agentV2.busy.delete("load-jobs");
        renderAgentV2();
      }
    }
  }

  function renderAgentV2JobScheduleFields() {
    const daily = els.agentV2JobScheduleKind.value !== "interval";
    els.agentV2JobDailyField.hidden = !daily;
    els.agentV2JobIntervalField.hidden = daily;
    els.agentV2JobTimezoneField.hidden = !daily;
    els.agentV2JobDailyTime.required = daily;
    els.agentV2JobIntervalMinutes.required = !daily;
  }

  async function createAgentV2Job() {
    if (state.agentV2.busy.has("create-job")) return;
    if (!hasPermission("write") || !state.activeDraft) {
      showToast(
        state.activeDraft
          ? "当前账号没有创建定时任务的编辑权限。"
          : "请先打开需要定时体检的草稿。",
        "error",
      );
      return;
    }
    const scheduleKind = els.agentV2JobScheduleKind.value;
    const intervalMinutes = Number(els.agentV2JobIntervalMinutes.value);
    if (
      scheduleKind === "interval" &&
      (!Number.isFinite(intervalMinutes) ||
        intervalMinutes < 5 ||
        intervalMinutes > 10080)
    ) {
      showToast("间隔时间须为 5 到 10080 分钟。", "error");
      els.agentV2JobIntervalMinutes.focus();
      return;
    }
    const schedule =
      scheduleKind === "interval"
        ? {
            interval_seconds: Math.round(intervalMinutes * 60),
          }
        : {
            time: els.agentV2JobDailyTime.value,
            timezone: els.agentV2JobTimezone.value,
          };
    if (scheduleKind === "daily" && !schedule.time) {
      showToast("请选择每天执行时间。", "error");
      return;
    }
    state.agentV2.busy.add("create-job");
    setBusy(els.createAgentV2JobButton, true, "创建中…");
    try {
      const payload = await api(endpoints.agentJobs(), {
        method: "POST",
        body: {
          name: els.agentV2JobName.value.trim() || "每日煤炭体检",
          workflow_name: "daily_coal_health",
          draft_id: state.activeDraft.id,
          schedule_kind: scheduleKind,
          schedule,
          enabled: true,
        },
        timeoutMs: 20000,
      });
      const job = normalizeAgentV2Job(
        unwrapAgentV2Entity(payload, "job"),
      );
      if (!job.job_id) throw new Error("服务没有返回定时任务编号。");
      state.agentV2.jobs.unshift(job);
      state.agentV2.jobsLoaded = true;
      els.agentV2JobName.value = "每日煤炭体检";
      showToast("定时任务已创建；它只会执行只读煤炭体检。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`创建失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("create-job");
      setBusy(els.createAgentV2JobButton, false);
      renderAgentV2();
    }
  }

  async function updateAgentV2Job(job, action) {
    if (
      !job ||
      !hasPermission("write") ||
      state.agentV2.busy.has(`job-${job.job_id}`)
    ) {
      return;
    }
    state.agentV2.busy.add(`job-${job.job_id}`);
    renderAgentV2Jobs();
    try {
      let payload;
      if (action === "run") {
        payload = await api(endpoints.agentJobRun(job.job_id), {
          method: "POST",
          body: {
            client_request_id: newClientRequestId("job-run"),
          },
          timeoutMs: 30000,
        });
        const flow = normalizeAgentV2Flow(
          unwrapAgentV2Entity(payload, "flow"),
        );
        if (flow.flow_id) {
          upsertAgentV2Flow(flow);
          state.agentV2.flowsLoaded = true;
          state.agentV2.selectedFlowId = flow.flow_id;
          state.agentV2.detail = flow;
        }
        const refreshedJob = normalizeAgentV2Job(
          unwrapAgentV2Entity(payload, "job"),
        );
        if (refreshedJob.job_id) {
          const index = state.agentV2.jobs.findIndex(
            (item) => item.job_id === job.job_id,
          );
          if (index >= 0) state.agentV2.jobs.splice(index, 1, refreshedJob);
        }
        showToast("定时任务已立即执行，可在“今日概览”查看进度。");
      } else {
        payload = await api(endpoints.agentJob(job.job_id), {
          method: "PATCH",
          body: {
            enabled: !job.enabled,
            expected_revision: job.revision,
          },
          timeoutMs: 20000,
        });
        const next = normalizeAgentV2Job(
          unwrapAgentV2Entity(payload, "job"),
        );
        const index = state.agentV2.jobs.findIndex(
          (item) => item.job_id === job.job_id,
        );
        if (index >= 0) {
          state.agentV2.jobs.splice(
            index,
            1,
            next.job_id ? next : { ...job, enabled: !job.enabled },
          );
        }
        showToast(job.enabled ? "定时任务已停用。" : "定时任务已启用。");
      }
      state.agentV2.error = "";
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`操作失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete(`job-${job.job_id}`);
      renderAgentV2();
    }
  }

  async function deleteAgentV2Job(job) {
    if (
      !job ||
      !hasPermission("write") ||
      state.agentV2.busy.has(`job-${job.job_id}`)
    ) {
      return;
    }
    if (
      !window.confirm(
        `确定移除定时任务“${job.name}”吗？历史执行记录仍会保留。`,
      )
    ) {
      return;
    }
    state.agentV2.busy.add(`job-${job.job_id}`);
    renderAgentV2Jobs();
    try {
      await api(endpoints.agentJob(job.job_id), {
        method: "DELETE",
        body: { expected_revision: job.revision },
        timeoutMs: 20000,
      });
      state.agentV2.jobs = state.agentV2.jobs.filter(
        (item) => item.job_id !== job.job_id,
      );
      showToast("定时任务已移除；历史体检记录仍保留。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`移除失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete(`job-${job.job_id}`);
      renderAgentV2();
    }
  }

  function normalizeAgentV2Proposal(raw, kind) {
    const source = raw && typeof raw === "object" ? raw : {};
    return {
      ...source,
      proposal_id: String(source.proposal_id || source.id || ""),
      kind,
      status: normalizeAgentV2Status(source.status, "pending"),
      revision: Number(source.revision || 1),
      title: String(
        source.title ||
          source.key ||
          source.memory_key ||
          source.skill_name ||
          (kind === "memory" ? "业务记忆提案" : "只读技能提案"),
      ),
      description: String(
        source.reason ||
          source.description ||
          source.value ||
          source.value_text ||
          "",
      ),
      created_at: source.created_at || "",
    };
  }

  async function loadAgentV2Governance(options = {}) {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.agentV2.busy.has("load-governance") ||
      (state.agentV2.governanceLoaded && !options.force)
    ) {
      renderAgentV2Governance();
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    state.agentV2.busy.add("load-governance");
    renderAgentV2Governance();
    try {
      const [memoryPayload, memoriesPayload, skillPayload, versionsPayload] =
        await Promise.all([
          api(endpoints.agentMemoryProposals(), { timeoutMs: 20000 }),
          api(endpoints.agentMemories(), { timeoutMs: 20000 }),
          api(endpoints.agentSkillProposals(), { timeoutMs: 20000 }),
          api(endpoints.agentSkillVersions(), { timeoutMs: 20000 }),
        ]);
      if (sessionRequestIsStale(sessionGeneration)) return;
      state.agentV2.memoryProposals = agentV2List(
        memoryPayload,
        "proposals",
        "memory_proposals",
      )
        .map((item) => normalizeAgentV2Proposal(item, "memory"))
        .filter((item) => item.proposal_id);
      state.agentV2.memories = agentV2List(memoriesPayload, "memories");
      state.agentV2.skillProposals = agentV2List(
        skillPayload,
        "proposals",
        "skill_proposals",
      )
        .map((item) => normalizeAgentV2Proposal(item, "skill"))
        .filter((item) => item.proposal_id);
      state.agentV2.skillVersions = agentV2List(
        versionsPayload,
        "skill_versions",
        "skills",
      );
      state.agentV2.governanceLoaded = true;
      state.agentV2.error = "";
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.agentV2.error = error.message;
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.agentV2.busy.delete("load-governance");
        renderAgentV2();
      }
    }
  }

  async function createAgentV2MemoryProposal() {
    if (state.agentV2.busy.has("create-memory")) return;
    if (!hasPermission("write")) {
      showToast("当前账号没有提出业务记忆的编辑权限。", "error");
      return;
    }
    const scopeType = els.agentV2MemoryScope.value;
    const scopeId =
      scopeType === "draft"
        ? state.activeDraft && state.activeDraft.id
        : state.principal && state.principal.actor_id;
    if (!scopeId) {
      showToast("请先打开草稿，再提出仅限当前草稿的记忆。", "error");
      return;
    }
    state.agentV2.busy.add("create-memory");
    setBusy(els.createAgentV2MemoryProposalButton, true, "提交中…");
    try {
      const payload = await api(endpoints.agentMemoryProposals(), {
        method: "POST",
        body: {
          scope_type: scopeType,
          scope_id: String(scopeId),
          key: els.agentV2MemoryKey.value.trim(),
          value: els.agentV2MemoryValue.value.trim(),
          reason: els.agentV2MemoryReason.value.trim(),
          source_refs: [],
        },
        timeoutMs: 20000,
      });
      const proposal = normalizeAgentV2Proposal(
        unwrapAgentV2Entity(payload, "proposal"),
        "memory",
      );
      if (!proposal.proposal_id) throw new Error("服务没有返回记忆提案编号。");
      state.agentV2.memoryProposals.unshift(proposal);
      state.agentV2.governanceLoaded = true;
      els.agentV2MemoryProposalForm.reset();
      showToast("记忆提案已提交，审批前不会影响智能体判断。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`提案提交失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("create-memory");
      setBusy(els.createAgentV2MemoryProposalButton, false);
      renderAgentV2();
    }
  }

  async function createAgentV2SkillProposal() {
    if (state.agentV2.busy.has("create-skill")) return;
    if (!hasPermission("write")) {
      showToast("当前账号没有提出技能的编辑权限。", "error");
      return;
    }
    const skillName = els.agentV2SkillName.value.trim();
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(skillName)) {
      showToast("技能标识只能使用小写字母、数字和连字符。", "error");
      els.agentV2SkillName.focus();
      return;
    }
    const procedure = els.agentV2SkillProcedure.value
      .split(/\r?\n/)
      .map((step) => step.trim())
      .filter(Boolean);
    if (!procedure.length) {
      showToast("请至少填写一个技能执行步骤。", "error");
      return;
    }
    state.agentV2.busy.add("create-skill");
    setBusy(els.createAgentV2SkillProposalButton, true, "提交中…");
    try {
      const payload = await api(endpoints.agentSkillProposals(), {
        method: "POST",
        body: {
          skill_name: skillName,
          description: els.agentV2SkillDescription.value.trim(),
          procedure,
          allowed_tools: ["draft_summary", "deterministic_preflight"],
          source_refs: [],
        },
        timeoutMs: 20000,
      });
      const proposal = normalizeAgentV2Proposal(
        unwrapAgentV2Entity(payload, "proposal"),
        "skill",
      );
      if (!proposal.proposal_id) throw new Error("服务没有返回技能提案编号。");
      state.agentV2.skillProposals.unshift(proposal);
      state.agentV2.governanceLoaded = true;
      els.agentV2SkillProposalForm.reset();
      showToast("技能提案已保存，审批发布后仍需由服务加载才能执行。");
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`提案提交失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete("create-skill");
      setBusy(els.createAgentV2SkillProposalButton, false);
      renderAgentV2();
    }
  }

  async function decideAgentV2Proposal(proposal, decision) {
    if (
      !proposal ||
      proposal.status !== "pending" ||
      !canFinalizeWith("confirm") ||
      state.agentV2.busy.has(`proposal-${proposal.proposal_id}`)
    ) {
      return;
    }
    const approve = decision === "approve";
    const needsOtherReviewer =
      proposal.proposed_by ===
        String((state.principal && state.principal.actor_id) || "") &&
      (proposal.kind === "skill" || proposal.scope_type !== "user");
    if (approve && needsOtherReviewer) {
      showToast("该共享提案必须由另一名有确认权限的人员批准。", "error");
      return;
    }
    const approvalEffect =
      proposal.kind === "memory"
        ? "作为受治理业务记忆生效"
        : "发布为受治理技能版本；服务加载该版本后才能执行";
    if (
      approve &&
      !window.confirm(`确认批准“${proposal.title}”吗？批准后将${approvalEffect}。`)
    ) {
      return;
    }
    state.agentV2.busy.add(`proposal-${proposal.proposal_id}`);
    renderAgentV2Governance();
    try {
      const endpoint =
        proposal.kind === "memory"
          ? endpoints.agentMemoryProposalDecision(proposal.proposal_id)
          : endpoints.agentSkillProposalDecision(proposal.proposal_id);
      const payload = await api(endpoint, {
        method: "POST",
        body: {
          decision: approve ? "approve" : "reject",
          reason: approve
            ? "由当前有确认权限的账号核验后批准。"
            : "由当前有确认权限的账号拒绝，需补充或修正依据。",
          expected_revision: proposal.revision,
        },
        timeoutMs: 20000,
      });
      const next = normalizeAgentV2Proposal(
        unwrapAgentV2Entity(payload, "proposal"),
        proposal.kind,
      );
      const collection =
        proposal.kind === "memory"
          ? state.agentV2.memoryProposals
          : state.agentV2.skillProposals;
      const index = collection.findIndex(
        (item) => item.proposal_id === proposal.proposal_id,
      );
      if (index >= 0) {
        collection.splice(
          index,
          1,
          next.proposal_id
            ? next
            : { ...proposal, status: approve ? "approved" : "rejected" },
        );
      }
      state.agentV2.governanceLoaded = false;
      showToast(
        approve
          ? proposal.kind === "memory"
            ? "记忆提案已批准并留痕。"
            : "技能版本已批准发布；需服务加载后才能执行。"
          : "提案已拒绝并留痕。",
      );
      await loadAgentV2Governance({ force: true });
    } catch (error) {
      state.agentV2.error = error.message;
      showToast(`审批失败：${error.message}`, "error");
    } finally {
      state.agentV2.busy.delete(`proposal-${proposal.proposal_id}`);
      renderAgentV2();
    }
  }

  function renderAgentV2() {
    renderAgentV2Tabs();
    renderAgentV2Error();
    renderAgentV2QuickCard();
    renderAgentV2Summary();
    renderAgentV2FlowList();
    renderAgentV2FlowDetail();
    renderAgentV2JobScheduleFields();
    renderAgentV2Jobs();
    renderAgentV2Governance();
    renderAgentV2Controls();
  }

  function renderAgentV2Tabs() {
    document.querySelectorAll("[data-agent-center-tab]").forEach((button) => {
      const selected =
        button.dataset.agentCenterTab === state.agentV2.selectedTab;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    document.querySelectorAll("[data-agent-center-panel]").forEach((panel) => {
      panel.hidden =
        panel.dataset.agentCenterPanel !== state.agentV2.selectedTab;
    });
  }

  function renderAgentV2Error() {
    els.agentV2Error.hidden = !state.agentV2.error;
    els.agentV2ErrorText.textContent = state.agentV2.error || "";
  }

  function agentV2LatestFlow() {
    const rows = [...state.agentV2.flows];
    rows.sort((left, right) => {
      const leftAt = Date.parse(left.updated_at || left.created_at || "") || 0;
      const rightAt =
        Date.parse(right.updated_at || right.created_at || "") || 0;
      return rightAt - leftAt;
    });
    return rows[0] || null;
  }

  function agentV2FlowNeedsAttention(flow) {
    if (!flow) return false;
    if (agentV2IntegrityFailed(flow) || flow.dispatch_ready === false) return true;
    if (agentV2AttentionStatuses.has(flow.status)) return true;
    const summary =
      flow.summary && typeof flow.summary === "object" ? flow.summary : {};
    const brief =
      flow.state &&
      flow.state.executive_brief &&
      typeof flow.state.executive_brief === "object"
        ? flow.state.executive_brief
        : {};
    const critic =
      flow.state &&
      flow.state.critic &&
      typeof flow.state.critic === "object"
        ? flow.state.critic
        : {};
    const priority = String(
      brief.priority || critic.priority || summary.priority || summary.risk_level || "",
    ).toLowerCase();
    return (
      ["critical", "high", "medium", "严重", "高", "中"].includes(priority) ||
      (Array.isArray(summary.attention_items) &&
        summary.attention_items.length > 0) ||
      (Array.isArray(summary.risks) && summary.risks.length > 0)
    );
  }

  function renderAgentV2QuickCard() {
    const latest = agentV2LatestFlow();
    const corrupt = state.agentV2.flows.filter(
      agentV2IntegrityFailed,
    ).length;
    const attention = state.agentV2.flows.filter(
      agentV2FlowNeedsAttention,
    ).length;
    const active = state.agentV2.flows.filter(
      (flow) =>
        !agentV2IntegrityFailed(flow) &&
        flow.dispatch_ready !== false &&
        agentV2ActiveStatuses.has(flow.status),
    ).length;
    let status = "idle";
    let summary =
      "打开任务中心，可让智能体持续检查当前草稿并给出易懂结论。";
    let meta = "智能体不能代替人工确认，也不能提交监管平台。";
    if (state.agentV2.loading) {
      status = "running";
      summary = "正在读取智能体任务状态…";
    } else if (corrupt) {
      status = "blocked";
      summary = `有 ${corrupt} 项任务审计完整性异常，结论已隐藏，请联系管理员核查。`;
    } else if (attention) {
      status = "blocked";
      summary = `有 ${attention} 项任务需要关注，请打开查看原因和建议。`;
    } else if (active) {
      status = "running";
      summary = `有 ${active} 项体检正在执行，完成后会生成负责人可读结论。`;
    } else if (latest) {
      status = latest.status;
      summary = agentV2LeaderSummary(latest);
      meta = `最近更新：${formatDateTime(
        latest.updated_at || latest.created_at,
      )}`;
    } else if (state.agentV2.flowsLoaded) {
      summary = state.activeDraft
        ? "当前还没有智能体任务，可立即体检这份草稿。"
        : "当前还没有智能体任务，请先打开一份草稿。";
    }
    els.agentCenterQuickStatus.textContent = agentV2StatusLabel(status);
    els.agentCenterQuickStatus.className = `agent-v2-status status-${status}`;
    els.agentCenterQuickSummary.textContent = truncateText(summary, 180);
    els.agentCenterQuickMeta.textContent = meta;
  }

  function renderAgentV2Summary() {
    const now = new Date();
    const todayKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}`;
    const completedToday = state.agentV2.flows.filter((flow) => {
      if (agentV2IntegrityFailed(flow)) return false;
      if (!["succeeded", "completed"].includes(flow.status)) return false;
      const date = new Date(flow.completed_at || flow.updated_at || "");
      if (Number.isNaN(date.getTime())) return false;
      return `${date.getFullYear()}-${date.getMonth()}-${date.getDate()}` ===
        todayKey;
    }).length;
    const attention = state.agentV2.flows.filter(
      agentV2FlowNeedsAttention,
    ).length;
    els.agentV2StatAttention.textContent = String(attention);
    els.agentV2StatActive.textContent = String(
      state.agentV2.flows.filter((flow) =>
        !agentV2IntegrityFailed(flow) &&
        flow.dispatch_ready !== false &&
        agentV2ActiveStatuses.has(flow.status),
      ).length,
    );
    els.agentV2StatCompleted.textContent = String(completedToday);
    els.agentV2StatScheduled.textContent = String(
      state.agentV2.jobs.filter(
        (job) =>
          job.enabled &&
          job.integrity &&
          typeof job.integrity === "object" &&
          job.integrity.valid === true,
      ).length,
    );
    els.agentV2BoundDraft.textContent = state.activeDraft
      ? `当前草稿：${
          state.activeDraft.enterprise.name ||
          state.activeDraft.enterprise.mine_name ||
          state.activeDraft.id
        }（${state.activeDraft.id}）`
      : "请先从左侧打开一份草稿。";
  }

  function renderAgentV2FlowList() {
    const fragment = document.createDocumentFragment();
    if (state.agentV2.loading && !state.agentV2.flows.length) {
      fragment.append(el("p", "agent-v2-empty", "正在读取任务记录…"));
    } else if (!state.agentV2.flows.length) {
      fragment.append(
        el(
          "p",
          "agent-v2-empty",
          state.agentV2.flowsLoaded
            ? "还没有智能体任务。打开草稿后可立即体检。"
            : "打开任务中心后读取任务记录。",
        ),
      );
    } else {
      state.agentV2.flows.forEach((flow) => {
        const integrityFailed = agentV2IntegrityFailed(flow);
        const dispatchPending =
          !integrityFailed &&
          flow.status === "queued" &&
          flow.dispatch_ready === false;
        const button = el("button", "agent-v2-flow-item");
        button.type = "button";
        button.classList.toggle(
          "is-active",
          flow.flow_id === state.agentV2.selectedFlowId,
        );
        button.setAttribute(
          "aria-current",
          flow.flow_id === state.agentV2.selectedFlowId ? "true" : "false",
        );
        button.addEventListener("click", () =>
          void selectAgentV2Flow(flow.flow_id),
        );
        const head = el("span", "agent-v2-flow-item-head");
        head.append(
          el("strong", "", agentV2WorkflowLabel(flow.workflow_name)),
          agentV2StatusNode(
            integrityFailed || dispatchPending ? "blocked" : flow.status,
          ),
        );
        button.append(
          head,
          el(
            "small",
            "",
            integrityFailed
              ? "审计完整性异常，结论已隐藏"
              : dispatchPending
                ? "派发确认尚未完成，未执行任何业务工具"
                : truncateText(agentV2LeaderSummary(flow), 70),
          ),
          el(
            "small",
            "",
            integrityFailed
              ? "记录时间不可信"
              : formatDateTime(flow.updated_at || flow.created_at),
          ),
        );
        fragment.append(button);
      });
    }
    els.agentV2FlowList.replaceChildren(fragment);
    els.agentV2FlowList.setAttribute(
      "aria-busy",
      String(state.agentV2.loading),
    );
    els.agentV2FlowListSummary.textContent = state.agentV2.loading
      ? "正在读取"
      : `共 ${state.agentV2.flows.length} 项`;
  }

  function renderAgentV2FlowDetail() {
    const flow =
      state.agentV2.detail &&
      state.agentV2.detail.flow_id === state.agentV2.selectedFlowId
        ? state.agentV2.detail
        : state.agentV2.flows.find(
            (item) => item.flow_id === state.agentV2.selectedFlowId,
          ) || null;
    if (!flow) {
      els.agentV2FlowDetailContent.hidden = true;
      els.agentV2FlowDetailEmpty.hidden = false;
      if (state.agentV2.detailLoading) {
        els.agentV2FlowDetailEmpty.replaceChildren(
          el("p", "agent-v2-empty", "正在读取任务详情…"),
        );
      } else {
        els.agentV2FlowDetailEmpty.replaceChildren(
          el("span", "", "巡"),
          el("h3", "", "选择一项任务查看结论"),
          el(
            "p",
            "",
            "领导先看结论和需关注事项；需要时再展开各专业步骤。",
          ),
        );
      }
      return;
    }
    els.agentV2FlowDetailEmpty.hidden = true;
    els.agentV2FlowDetailContent.hidden = false;
    els.agentV2FlowTitle.textContent = agentV2WorkflowLabel(flow.workflow_name);
    const integrityFailed = agentV2IntegrityFailed(flow);
    const triggerType =
      flow.trigger && typeof flow.trigger === "object"
        ? flow.trigger.type
        : flow.trigger_type;
    els.agentV2FlowMeta.textContent = integrityFailed
      ? "审计完整性异常，元数据不可信"
      : [
          flow.current_step
            ? `当前步骤：${agentV2StepLabel(flow.current_step)}`
            : "",
          triggerType ? `触发：${agentV2TriggerLabel(triggerType)}` : "",
          flow.updated_at ? `更新：${formatDateTime(flow.updated_at)}` : "",
        ]
          .filter(Boolean)
          .join(" · ");
    const visibleStatus = integrityFailed ? "blocked" : flow.status;
    els.agentV2FlowStatus.textContent = agentV2StatusLabel(visibleStatus);
    els.agentV2FlowStatus.className =
      `agent-v2-status status-${visibleStatus}`;
    els.agentV2FlowSummary.textContent = agentV2LeaderSummary(flow);
    renderAgentV2Findings(flow);
    renderAgentV2Steps(flow);
    els.cancelAgentV2FlowButton.hidden =
      integrityFailed || !agentV2ActiveStatuses.has(flow.status);
    els.retryAgentV2FlowButton.hidden =
      agentV2IntegrityFailed(flow) ||
      !["blocked", "failed"].includes(flow.status);
    const actionBusy = state.agentV2.busy.has("flow-action");
    els.cancelAgentV2FlowButton.disabled = actionBusy;
    els.retryAgentV2FlowButton.disabled = actionBusy;
  }

  function agentV2WorkflowLabel(name) {
    return String(name || "") === "daily_coal_health"
      ? "每日煤炭体检"
      : String(name || "煤炭智能任务").replace(/_/g, " ");
  }

  function agentV2IntegrityFailed(flow) {
    return Boolean(
      flow &&
        (!flow.integrity ||
          typeof flow.integrity !== "object" ||
          flow.integrity.valid !== true),
    );
  }

  function agentV2TriggerLabel(trigger) {
    const labels = {
      manual: "人工发起",
      schedule: "定时执行",
      event: "数据事件",
      retry: "失败重试",
    };
    return labels[String(trigger || "")] || String(trigger || "未知");
  }

  function agentV2StepLabel(step) {
    const labels = {
      preflight: "准备与权限检查",
      prepare_evidence: "汇集只读证据",
      source: "来源凭证核验",
      temporal: "时间与连续性检查",
      physical: "煤流物理关系复算",
      historical: "历史基线与异常分析",
      critic: "反方复核",
      critic_and_executive_brief: "反方复核与负责人摘要",
      brief: "生成负责人摘要",
    };
    const normalized = String(step || "").toLowerCase();
    return labels[normalized] || String(step || "").replace(/_/g, " ");
  }

  function agentV2SpecialistLabel(specialist) {
    const labels = {
      orchestrator: "任务协调员",
      source: "来源凭证专家",
      temporal: "时序质量专家",
      physical: "煤流平衡专家",
      historical: "历史交叉验证专家",
      dissenting_critic: "反方核验员",
      executive_brief: "负责人摘要员",
    };
    const normalized = String(specialist || "").toLowerCase();
    return labels[normalized] || String(specialist || "").replace(/_/g, " ");
  }

  function agentV2LeaderSummary(flow) {
    if (!flow) return "尚无任务结论。";
    if (agentV2IntegrityFailed(flow)) {
      return "任务审计完整性校验失败，结论和步骤证据已遮蔽，请联系管理员核查。";
    }
    const source =
      flow.summary && typeof flow.summary === "object" ? flow.summary : {};
    const stateSummary =
      flow.state &&
      flow.state.summary &&
      typeof flow.state.summary === "object"
        ? flow.state.summary
        : {};
    const executiveBrief =
      flow.state &&
      flow.state.executive_brief &&
      typeof flow.state.executive_brief === "object"
        ? flow.state.executive_brief
        : {};
    const candidates = [
      typeof flow.summary === "string" ? flow.summary : "",
      source.executive_summary,
      source.headline,
      source.conclusion,
      source.summary,
      source.message,
      stateSummary.executive_summary,
      stateSummary.headline,
      stateSummary.conclusion,
      executiveBrief.headline,
      flow.error_message,
    ];
    const selected = candidates.find(
      (value) => typeof value === "string" && value.trim(),
    );
    if (selected) return truncateText(selected.trim(), 900);
    if (agentV2ActiveStatuses.has(flow.status)) {
      return flow.current_step
        ? `正在进行“${agentV2StepLabel(
            flow.current_step,
          )}”，完成后会生成负责人可读结论。`
        : "智能体正在执行只读煤炭体检，完成后会生成负责人可读结论。";
    }
    if (flow.status === "cancelled") {
      return "该任务已取消，没有形成新的完整体检结论。";
    }
    if (agentV2AttentionStatuses.has(flow.status)) {
      return "本次体检未完整完成，请查看专业步骤中的失败原因后重新执行。";
    }
    return "本次任务已结束，服务未提供可展示的文字摘要，请展开步骤查看记录。";
  }

  function agentV2FlowFindings(flow) {
    if (agentV2IntegrityFailed(flow)) return [];
    const summary =
      flow && flow.summary && typeof flow.summary === "object"
        ? flow.summary
        : {};
    const stateSummary =
      flow &&
      flow.state &&
      flow.state.summary &&
      typeof flow.state.summary === "object"
        ? flow.state.summary
        : {};
    const executiveBrief =
      flow &&
      flow.state &&
      flow.state.executive_brief &&
      typeof flow.state.executive_brief === "object"
        ? flow.state.executive_brief
        : {};
    const critic =
      flow &&
      flow.state &&
      flow.state.critic &&
      typeof flow.state.critic === "object"
        ? flow.state.critic
        : {};
    const collections = [
      summary.attention_items,
      summary.findings,
      summary.risks,
      summary.recommendations,
      stateSummary.attention_items,
      stateSummary.findings,
      executiveBrief.next_actions,
      executiveBrief.key_points,
      critic.evidence_conflicts,
    ];
    const results = [];
    collections.forEach((items) => {
      if (!Array.isArray(items)) return;
      items.forEach((item) => {
        let text = "";
        if (typeof item === "string") {
          text = item;
        } else if (item && typeof item === "object") {
          text = String(
            item.message ||
              item.summary ||
              item.title ||
              item.description ||
              item.recommendation ||
              "",
          );
        }
        text = text.trim();
        if (text && !results.includes(text)) results.push(text);
      });
    });
    return results.slice(0, 8);
  }

  function renderAgentV2Findings(flow) {
    const findings = agentV2FlowFindings(flow);
    if (!findings.length) {
      els.agentV2FlowFindings.replaceChildren();
      return;
    }
    const list = el("ul", "agent-v2-finding-list");
    findings.forEach((finding) =>
      list.append(el("li", "", truncateText(finding, 400))),
    );
    els.agentV2FlowFindings.replaceChildren(list);
  }

  function renderAgentV2Steps(flow) {
    const fragment = document.createDocumentFragment();
    if (agentV2IntegrityFailed(flow)) {
      fragment.append(
        el(
          "p",
          "agent-v2-empty",
          "审计完整性异常，专业步骤已停止展示；不要据此作出业务判断。",
        ),
      );
    } else if (!flow.steps.length) {
      fragment.append(
        el(
          "p",
          "agent-v2-empty",
          agentV2ActiveStatuses.has(flow.status)
            ? "专业步骤正在生成，请稍后刷新。"
            : "服务未返回可展示的步骤记录。",
        ),
      );
    } else {
      flow.steps.forEach((step, index) => {
        const card = el("article", "agent-v2-step-card");
        const copy = el("div");
        copy.append(
          el("strong", "", agentV2StepLabel(step.title || step.step_key)),
        );
        const detail = [
          step.specialist
            ? `专业角色：${agentV2SpecialistLabel(step.specialist)}`
            : "",
          step.summary,
        ]
          .filter(Boolean)
          .join(" · ");
        if (detail) copy.append(el("p", "", truncateText(detail, 500)));
        card.append(
          el("span", "agent-v2-step-index", String(index + 1)),
          copy,
          agentV2StatusNode(step.status),
        );
        fragment.append(card);
      });
    }
    els.agentV2StepList.replaceChildren(fragment);
  }

  function agentV2StatusNode(status) {
    return el(
      "span",
      `agent-v2-status status-${normalizeAgentV2Status(status)}`,
      agentV2StatusLabel(status),
    );
  }

  function renderAgentV2Jobs() {
    const canWrite = hasPermission("write");
    els.agentV2JobPermissionHint.textContent = canWrite
      ? state.activeDraft
        ? "定时任务将绑定当前草稿，只执行只读体检。"
        : "请先打开一份草稿。"
      : "当前账号只有查看权限，不能创建或修改定时任务。";
    const fragment = document.createDocumentFragment();
    if (state.agentV2.busy.has("load-jobs") && !state.agentV2.jobs.length) {
      fragment.append(el("p", "agent-v2-empty", "正在读取定时任务…"));
    } else if (!state.agentV2.jobs.length) {
      fragment.append(
        el(
          "p",
          "agent-v2-empty",
          state.agentV2.jobsLoaded
            ? "还没有定时任务。可在上方为当前草稿创建每日体检。"
            : "进入本页后读取定时任务。",
        ),
      );
    } else {
      state.agentV2.jobs.forEach((job) => {
        const auditInvalid = Boolean(
          !job.integrity ||
            typeof job.integrity !== "object" ||
            job.integrity.valid !== true,
        );
        const card = el("article", "agent-v2-job-card");
        const head = el("div", "agent-v2-job-head");
        const title = el("div");
        title.append(
          el("h4", "", job.name),
          el("p", "", agentV2JobScheduleLabel(job)),
        );
        head.append(
          title,
          agentV2StatusNode(
            auditInvalid ? "blocked" : job.enabled ? "enabled" : "disabled",
          ),
        );
        const meta = el(
          "p",
          "",
          [
            job.next_run_at
              ? `下次：${formatDateTime(job.next_run_at)}`
              : "下次时间待计算",
            job.last_run_at
              ? `上次：${formatDateTime(job.last_run_at)}`
              : "尚未执行",
            job.draft_id ? `草稿：${job.draft_id}` : "",
          ]
            .filter(Boolean)
            .join(" · "),
        );
        const actions = el("div", "button-row");
        if (auditInvalid) {
          card.append(
            el(
              "p",
              "agent-v2-alert",
              "审计完整性异常：已禁止运行、启停和移除，请由运维人员核对数据库与审计链。",
            ),
          );
        }
        const busy = state.agentV2.busy.has(`job-${job.job_id}`);
        const runButton = el("button", "button button-secondary", "立即运行");
        runButton.type = "button";
        runButton.disabled = !canWrite || busy || auditInvalid;
        runButton.addEventListener("click", () =>
          void updateAgentV2Job(job, "run"),
        );
        const toggleButton = el(
          "button",
          "button button-secondary",
          job.enabled ? "停用" : "启用",
        );
        toggleButton.type = "button";
        toggleButton.disabled = !canWrite || busy || auditInvalid;
        toggleButton.addEventListener("click", () =>
          void updateAgentV2Job(job, "toggle"),
        );
        const deleteButton = el(
          "button",
          "button button-danger-quiet",
          "移除",
        );
        deleteButton.type = "button";
        deleteButton.disabled = !canWrite || busy || auditInvalid;
        deleteButton.addEventListener("click", () =>
          void deleteAgentV2Job(job),
        );
        actions.append(runButton, toggleButton, deleteButton);
        card.append(head, meta, actions);
        fragment.append(card);
      });
    }
    els.agentV2JobList.replaceChildren(fragment);
  }

  function agentV2JobScheduleLabel(job) {
    if (job.schedule_kind === "event") {
      return `收到业务事件 ${
        job.schedule.event_type || "（未配置）"
      } 时执行`;
    }
    if (job.schedule_kind === "interval") {
      const seconds = Number(
        job.schedule.interval_seconds || job.interval_seconds || 0,
      );
      const minutes = seconds > 0 ? Math.round(seconds / 60) : 0;
      return minutes
        ? `每隔 ${minutes} 分钟执行（不受时区影响）`
        : "按固定间隔执行";
    }
    return `每天 ${job.schedule.time || job.daily_time || "09:00"} 执行 · ${
      job.schedule.timezone || "Asia/Shanghai"
    }`;
  }

  function renderAgentV2Governance() {
    const canWrite = hasPermission("write");
    const canApproveMemory = canFinalizeWith("governance_review");
    const canApproveSkill = canFinalizeWith("skill_admin");
    [
      els.agentV2MemoryKey,
      els.agentV2MemoryValue,
      els.agentV2MemoryReason,
      els.agentV2MemoryScope,
      els.createAgentV2MemoryProposalButton,
      els.agentV2SkillName,
      els.agentV2SkillDescription,
      els.agentV2SkillProcedure,
      els.createAgentV2SkillProposalButton,
    ].forEach((control) => {
      control.disabled = !canWrite;
    });
    renderAgentV2ProposalCollection(
      els.agentV2MemoryProposalList,
      state.agentV2.memoryProposals,
      canApproveMemory,
      "还没有记忆提案。",
    );
    renderAgentV2ProposalCollection(
      els.agentV2SkillProposalList,
      state.agentV2.skillProposals,
      canApproveSkill,
      "还没有技能提案。",
    );
    renderAgentV2AssetCollection(
      els.agentV2MemoryList,
      state.agentV2.memories,
      "memory",
    );
    renderAgentV2AssetCollection(
      els.agentV2SkillVersionList,
      state.agentV2.skillVersions,
      "skill",
    );
  }

  function renderAgentV2ProposalCollection(
    container,
    proposals,
    canApprove,
    emptyText,
  ) {
    const fragment = document.createDocumentFragment();
    if (state.agentV2.busy.has("load-governance") && !proposals.length) {
      fragment.append(el("p", "agent-v2-empty", "正在读取治理提案…"));
    } else if (!proposals.length) {
      fragment.append(el("p", "agent-v2-empty", emptyText));
    } else {
      proposals.forEach((proposal) => {
        const card = el("article", "agent-v2-proposal-card");
        const head = el("div", "agent-v2-proposal-head");
        head.append(
          el("h5", "", proposal.title),
          agentV2StatusNode(proposal.status),
        );
        card.append(
          head,
          el(
            "p",
            "",
            truncateText(
              proposal.description || "提案未提供可展示的理由。",
              500,
            ),
          ),
        );
        if (proposal.status === "pending") {
          const actions = el("div", "button-row");
          const busy = state.agentV2.busy.has(
            `proposal-${proposal.proposal_id}`,
          );
          const needsOtherReviewer =
            proposal.proposed_by ===
              String((state.principal && state.principal.actor_id) || "") &&
            (proposal.kind === "skill" || proposal.scope_type !== "user");
          if (needsOtherReviewer) {
            card.append(
              el(
                "p",
                "",
                "为防止自批，该提案须由另一名具有相应治理审批权限的人员批准；提案人仍可拒绝撤回。",
              ),
            );
          }
          const rejectButton = el(
            "button",
            "button button-secondary",
            "拒绝",
          );
          rejectButton.type = "button";
          rejectButton.disabled = !canApprove || busy;
          rejectButton.title = canApprove
            ? ""
            : "需要相应治理审批权限，且账号不能处于待换密状态";
          rejectButton.addEventListener("click", () =>
            void decideAgentV2Proposal(proposal, "reject"),
          );
          const approveButton = el(
            "button",
            "button button-primary",
            "核验后批准",
          );
          approveButton.type = "button";
          approveButton.disabled = !canApprove || busy || needsOtherReviewer;
          approveButton.title = needsOtherReviewer
            ? "共享记忆或技能不能由提案人本人批准"
            : rejectButton.title;
          approveButton.addEventListener("click", () =>
            void decideAgentV2Proposal(proposal, "approve"),
          );
          actions.append(rejectButton, approveButton);
          card.append(actions);
        }
        fragment.append(card);
      });
    }
    container.replaceChildren(fragment);
  }

  function renderAgentV2AssetCollection(container, items, kind) {
    const fragment = document.createDocumentFragment();
    if (!items.length) {
      fragment.append(
        el(
          "p",
          "agent-v2-empty",
          kind === "memory" ? "暂无已生效记忆。" : "暂无已发布技能。",
        ),
      );
    } else {
      items.forEach((raw) => {
        const source = raw && typeof raw === "object" ? raw : {};
        const title = String(
          source.key ||
            source.memory_key ||
            source.skill_name ||
            source.name ||
            (kind === "memory" ? "业务记忆" : "只读技能"),
        );
        const description = String(
          source.value ||
            source.value_text ||
            source.description ||
            source.summary ||
            "",
        );
        const card = el("article", "agent-v2-asset-card");
        card.append(
          el("h5", "", title),
          el(
            "p",
            "",
            truncateText(
              description ||
                (kind === "memory"
                  ? "已生效"
                  : "已发布，需服务加载后执行"),
              500,
            ),
          ),
        );
        fragment.append(card);
      });
    }
    container.replaceChildren(fragment);
  }

  function renderAgentV2Controls() {
    const canRead = Boolean(state.principal && hasPermission("read"));
    const canWrite = canRead && hasPermission("write");
    const hasDraft = Boolean(state.activeDraft);
    const creatingFlow = state.agentV2.busy.has("create-flow");
    els.agentCenterButton.disabled = !canRead;
    els.openAgentCenterQuickButton.disabled = !canRead;
    els.runAgentCenterQuickButton.disabled =
      !canRead || !hasDraft || creatingFlow;
    els.startAgentV2HealthButton.disabled =
      !canRead || !hasDraft || creatingFlow;
    els.createAgentV2JobButton.disabled =
      !canWrite || !hasDraft || state.agentV2.busy.has("create-job");
    els.refreshAgentV2Button.disabled =
      !canRead || state.agentV2.busy.has("refresh");
  }

  function newClientRequestId(prefix) {
    const randomId =
      window.crypto && typeof window.crypto.randomUUID === "function"
        ? window.crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return `${prefix}-${randomId}`;
  }

  async function openAgentWorkbench() {
    if (!state.principal || !hasPermission("read")) {
      showToast("请先使用有读取权限的企业账号登录。", "error");
      return;
    }
    stopAgentV2Polling();
    stopCoalChatPolling();
    els.coalChatWorkbench.hidden = true;
    els.agentV2Workbench.hidden = true;
    els.agentWorkbench.hidden = false;
    renderAgentWorkbench();
    els.agentWorkbench.focus();
    void loadAgentTools();
    await loadAgentRuns();
    if (state.agent.selectedRunId) {
      state.agent.pollStartedAt = Date.now();
      state.agent.pollFailures = 0;
      await loadAgentRun(state.agent.selectedRunId);
    } else if (state.agent.runs.length) {
      await selectAgentRun(state.agent.runs[0].run_id);
    }
  }

  function closeAgentWorkbench() {
    stopAgentPolling();
    els.agentWorkbench.hidden = true;
    els.agentTaskButton.focus();
  }

  async function refreshAgentWorkbench() {
    void loadAgentTools({ force: true });
    await loadAgentRuns();
    if (state.agent.selectedRunId) {
      state.agent.pollStartedAt = Date.now();
      state.agent.pollFailures = 0;
      await loadAgentRun(state.agent.selectedRunId);
    }
  }

  function applyAgentTaskPreset(presetName) {
    const task = agentTaskPresets[presetName];
    if (!task || !els.agentTaskInput) return;
    els.agentTaskInput.value = task;
    document.querySelectorAll("[data-agent-task-preset]").forEach((button) => {
      const selected = button.dataset.agentTaskPreset === presetName;
      button.classList.toggle("is-active", selected);
      button.setAttribute("aria-pressed", String(selected));
    });
    renderAgentWorkbenchControls();
  }

  function selectedAgentRunMode() {
    const selected = document.querySelector(
      'input[name="agentRunMode"]:checked',
    );
    return selected && selected.value === "deterministic"
      ? "deterministic"
      : "auto";
  }

  function startAgentTaskFromComposer() {
    const task = String(els.agentTaskInput.value || "").trim();
    if (!task || task.length > 4000) {
      showToast("任务要求必须填写 1 到 4000 个字符。", "error");
      els.agentTaskInput.focus();
      return;
    }
    void startCoalHealthCheck({
      task,
      mode: selectedAgentRunMode(),
    });
  }

  async function loadAgentTools(options = {}) {
    if (
      !state.principal ||
      !hasPermission("read") ||
      state.agent.toolsLoading ||
      (state.agent.toolsLoaded && !options.force)
    ) {
      return;
    }
    const sessionGeneration = state.sessionGeneration;
    state.agent.toolsLoading = true;
    state.agent.toolsError = "";
    renderAgentToolCatalog();
    try {
      const payload = await api(endpoints.agentTools(), {
        timeoutMs: 15000,
      });
      if (sessionRequestIsStale(sessionGeneration)) return;
      const rows = Array.isArray(payload)
        ? payload
        : (payload && (payload.tools || payload.items)) || [];
      if (!Array.isArray(rows)) {
        throw new Error("服务返回的工具目录格式无效。");
      }
      state.agent.tools = rows
        .map(normalizeAgentTool)
        .filter((tool) => tool.name);
      state.agent.toolsLoaded = true;
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.agent.toolsError = error.message;
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.agent.toolsLoading = false;
        renderAgentToolCatalog();
      }
    }
  }

  function normalizeAgentTool(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const name = String(source.name || "");
    const presentation = agentToolDisplay(name, source.category);
    return {
      name,
      label: presentation.label,
      category: presentation.category,
      categoryLabel: presentation.categoryLabel,
      categoryOrder: presentation.categoryOrder,
      description: String(source.description || ""),
      risk: ["read", "write"].includes(source.risk)
        ? source.risk
        : "unknown",
      requiresApproval: source.requires_approval === true,
      evidenceGrounding: String(source.evidence_grounding || ""),
      networkAccess:
        source.network_access === true
          ? true
          : source.network_access === false
            ? false
            : null,
      scenarioOnly: source.scenario_only === true,
      allowedProfiles: Array.isArray(source.allowed_profiles)
        ? source.allowed_profiles
            .filter((profile) => typeof profile === "string")
            .slice(0, 8)
        : [],
    };
  }

  function agentToolDisplay(toolName, declaredCategory = "") {
    const name = String(toolName || "");
    const preset = Object.prototype.hasOwnProperty.call(
      agentToolPresentation,
      name,
    )
      ? agentToolPresentation[name]
      : {};
    const category = String(declaredCategory || preset.category || "general");
    const knownCategory = Object.prototype.hasOwnProperty.call(
      agentToolCategoryPresentation,
      category,
    );
    const categoryPreset = knownCategory
      ? agentToolCategoryPresentation[category]
      : agentToolCategoryPresentation.general;
    return {
      name,
      label:
        preset.label ||
        (name ? `扩展工具：${name.replace(/_/g, " ")}` : "未命名工具"),
      category,
      categoryLabel:
        knownCategory
          ? categoryPreset.label
          : `其他工具 · ${category.replace(/_/g, " ")}`,
      categoryOrder:
        knownCategory
          ? categoryPreset.order
          : agentToolCategoryPresentation.general.order,
    };
  }

  function renderAgentToolCatalog() {
    if (!els.agentToolCatalog || !els.agentToolCatalogSummary) return;
    const fragment = document.createDocumentFragment();
    if (state.agent.toolsLoading && !state.agent.tools.length) {
      fragment.append(el("p", "agent-tool-catalog-state", "正在读取工具目录…"));
    } else if (state.agent.toolsError && !state.agent.tools.length) {
      const error = el("div", "agent-tool-catalog-state is-error");
      error.append(
        el("strong", "", "工具目录暂时不可用"),
        el("span", "", state.agent.toolsError),
      );
      const retry = el("button", "button button-secondary", "重新读取");
      retry.type = "button";
      retry.addEventListener("click", () =>
        void loadAgentTools({ force: true }),
      );
      error.append(retry);
      fragment.append(error);
    } else if (!state.agent.toolsLoaded && !state.agent.tools.length) {
      fragment.append(
        el(
          "p",
          "agent-tool-catalog-state",
          state.principal
            ? "尚未读取服务端工具目录。"
            : "登录后可读取服务端工具目录。",
        ),
      );
    } else if (state.agent.toolsLoaded && !state.agent.tools.length) {
      fragment.append(
        el("p", "agent-tool-catalog-state", "当前账号没有可用工具。"),
      );
    } else {
      if (state.agent.toolsError) {
        fragment.append(
          el(
            "p",
            "agent-tool-catalog-state is-error",
            `刷新失败，以下保留上次目录：${state.agent.toolsError}`,
          ),
        );
      }
      const groups = new Map();
      state.agent.tools.forEach((tool) => {
        if (!groups.has(tool.category)) {
          groups.set(tool.category, {
            label: tool.categoryLabel,
            order: tool.categoryOrder,
            tools: [],
          });
        }
        groups.get(tool.category).tools.push(tool);
      });
      Array.from(groups.values())
        .sort(
          (left, right) =>
            left.order - right.order ||
            left.label.localeCompare(right.label, "zh-CN"),
        )
        .forEach((group) => {
          const section = el("section", "agent-tool-group");
          section.append(
            el("h4", "", group.label),
            el("small", "", `${group.tools.length} 项`),
          );
          const grid = el("div", "agent-tool-grid");
          group.tools
            .sort((left, right) =>
              left.label.localeCompare(right.label, "zh-CN"),
            )
            .forEach((tool) => grid.append(agentToolCatalogCard(tool)));
          section.append(grid);
          fragment.append(section);
        });
    }
    els.agentToolCatalog.replaceChildren(fragment);
    els.agentToolCatalog.setAttribute(
      "aria-busy",
      String(state.agent.toolsLoading),
    );
    els.agentToolCatalogSummary.textContent = state.agent.toolsLoading
      ? "正在读取服务端目录"
      : state.agent.toolsError && !state.agent.tools.length
        ? "目录读取失败，不影响已有任务记录"
        : state.agent.toolsError
          ? `保留上次读取的 ${state.agent.tools.length} 项工具`
          : !state.agent.toolsLoaded
            ? "打开工作台后读取服务端目录"
            : `服务端当前提供 ${state.agent.tools.length} 项工具`;
  }

  function agentToolCatalogCard(tool) {
    const card = el("article", "agent-tool-card");
    const title = el("div", "agent-tool-card-title");
    title.append(
      el("strong", "", tool.label),
      el("code", "", tool.name),
    );
    card.append(title);
    if (tool.description) {
      card.append(
        el("p", "", truncateText(tool.description, 240)),
      );
    }
    const badges = el("div", "agent-tool-badges");
    badges.append(
      el(
        "span",
        `agent-tool-badge is-${tool.risk}`,
        tool.risk === "write"
          ? "修改草稿"
          : tool.risk === "read"
            ? "只读"
            : "风险未声明",
      ),
    );
    if (tool.requiresApproval) {
      badges.append(
        el("span", "agent-tool-badge is-approval", "需逐项批准"),
      );
    }
    if (tool.scenarioOnly) {
      badges.append(
        el("span", "agent-tool-badge is-scenario", "仅情景复算"),
      );
    }
    const grounding = agentCatalogGrounding(tool.evidenceGrounding);
    badges.append(
      el(
        "span",
        `agent-tool-badge ${grounding.className}`,
        grounding.label,
      ),
    );
    badges.append(
      el(
        "span",
        `agent-tool-badge ${
          tool.networkAccess === true
            ? "is-network"
            : tool.networkAccess === false
              ? "is-local"
              : "is-unknown"
        }`,
        tool.networkAccess === true
          ? "可能联网"
          : tool.networkAccess === false
            ? "本地执行"
            : "联网属性未声明",
      ),
    );
    card.append(badges);
    if (tool.allowedProfiles.length) {
      card.append(
        el(
          "small",
          "agent-tool-profile",
          `可用范围：${tool.allowedProfiles
            .map(agentToolProfileLabel)
            .join("、")}`,
        ),
      );
    }
    return card;
  }

  function agentCatalogGrounding(value) {
    const normalized = String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, "_");
    if (
      [
        "repository_grounded",
        "repository",
        "repository_bound",
        "draft_repository",
      ].includes(normalized)
    ) {
      return { className: "is-repository", label: "仓库绑定" };
    }
    if (
      [
        "user_supplied",
        "caller_supplied",
        "caller_values",
        "provided_values",
      ].includes(normalized)
    ) {
      return { className: "is-user-supplied", label: "调用者输入" };
    }
    if (normalized === "mixed") {
      return { className: "is-mixed", label: "混合来源" };
    }
    if (normalized === "external_public") {
      return { className: "is-network", label: "公开外部来源" };
    }
    return { className: "is-unknown", label: "来源未声明" };
  }

  function agentToolProfileLabel(profile) {
    const labels = {
      standard: "智能任务",
      chat_read_only: "只读对话",
    };
    return Object.prototype.hasOwnProperty.call(labels, profile)
      ? labels[profile]
      : String(profile).replace(/_/g, " ");
  }

  async function startCoalHealthCheck(options = {}) {
    const task =
      typeof options.task === "string" && options.task.trim()
        ? options.task.trim()
        : defaultCoalHealthTask;
    const mode = options.mode === "deterministic" ? "deterministic" : "auto";
    if (task.length > 4000) {
      showToast("任务要求不能超过 4000 个字符。", "error");
      return;
    }
    if (
      !state.activeDraft ||
      !state.principal ||
      !hasPermission("read") ||
      state.agent.creating
    ) {
      showToast(
        state.activeDraft
          ? "当前账号没有读取并体检该草稿的权限。"
          : "请先打开一份需要体检的草稿。",
        "error",
      );
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    state.agent.creating = true;
    state.activeOperation = "发起煤炭体检";
    const draftId = state.activeDraft.id;
    const knownRunIds = new Set(state.agent.runs.map((run) => run.run_id));
    setBusy(els.startAgentHealthButton, true, "正在发起…");
    setBusy(els.runCoalHealthButton, true, "正在发起…");
    setBusy(els.startAgentCustomButton, true, "正在发起…");
    try {
      await flushSave();
      const payload = await api(endpoints.agentRunsCreate(), {
        method: "POST",
        timeoutMs: 30000,
        body: {
          task,
          draft_id: draftId,
          mode,
        },
      });
      const run = normalizeAgentRun(payload && (payload.run || payload));
      if (!run.run_id) throw new Error("服务未返回智能任务编号。");
      upsertAgentRun(run);
      state.agent.selectedRunId = run.run_id;
      state.agent.detail = run;
      state.agent.detailError = "";
      state.agent.pollStartedAt = Date.now();
      state.agent.pollFailures = 0;
      els.agentWorkbench.hidden = false;
      renderAgentWorkbench();
      els.agentWorkbench.focus();
      scheduleAgentPoll(agentPollInterval(run.status));
      showToast("煤炭体检任务已发起，可在独立任务面板查看过程。");
    } catch (error) {
      if (error.isTimeout || !error.status) {
        els.agentWorkbench.hidden = false;
        renderAgentWorkbench();
        await loadAgentRuns();
        const recovered = state.agent.runs.find(
          (run) =>
            run.draft_id === draftId &&
            run.mode === mode &&
            run.task === task &&
            !knownRunIds.has(run.run_id),
        );
        if (recovered) {
          state.agent.selectedRunId = recovered.run_id;
          els.agentWorkbench.hidden = false;
          await loadAgentRun(recovered.run_id);
          showToast(
            "创建请求一度失去响应，但已从任务列表找到对应体检；没有重复发起。",
          );
        } else {
          showToast(
            `创建请求状态暂时未知：${error.message}。请先刷新任务列表，勿立即重复点击。`,
            "error",
          );
        }
      } else {
        showToast(`智能任务未发起：${error.message}`, "error");
      }
    } finally {
      state.agent.creating = false;
      state.activeOperation = "";
      setBusy(els.startAgentHealthButton, false);
      setBusy(els.runCoalHealthButton, false);
      setBusy(els.startAgentCustomButton, false);
      renderAgentWorkbenchControls();
    }
  }

  async function loadAgentRuns(options = {}) {
    if (!state.principal || !hasPermission("read") || state.agent.listLoading) return;
    const sessionGeneration = state.sessionGeneration;
    const append = Boolean(options.append);
    if (append && !state.agent.hasMore) return;
    const offset = append ? state.agent.nextOffset : 0;
    state.agent.listLoading = true;
    state.agent.listError = "";
    renderAgentRunList();
    try {
      const payload = await api(endpoints.agentRuns(20, offset), {
        timeoutMs: 15000,
      });
      if (sessionRequestIsStale(sessionGeneration)) return;
      const rows = Array.isArray(payload)
        ? payload
        : (payload && (payload.runs || payload.items)) || [];
      const normalized = rows.map(normalizeAgentRun);
      if (append) {
        const byId = new Map(
          state.agent.runs.map((run) => [run.run_id, run]),
        );
        normalized.forEach((run) => byId.set(run.run_id, run));
        state.agent.runs = Array.from(byId.values());
      } else {
        state.agent.runs = normalized;
      }
      state.agent.total = Number(
        payload && Number.isFinite(Number(payload.total))
          ? payload.total
          : state.agent.runs.length,
      );
      state.agent.hasMore = Boolean(payload && payload.has_more);
      state.agent.nextOffset = Number(
        payload && payload.next_offset !== null &&
          Number.isFinite(Number(payload.next_offset))
          ? payload.next_offset
          : state.agent.runs.length,
      );
      if (
        state.agent.selectedRunId &&
        !state.agent.runs.some(
          (run) => run.run_id === state.agent.selectedRunId,
        )
      ) {
        state.agent.selectedRunId = "";
        state.agent.detail = null;
      }
      renderAgentRunList();
    } catch (error) {
      if (sessionRequestIsStale(sessionGeneration, error)) return;
      state.agent.listError = error.message;
      renderAgentRunList();
      if (error.status !== 401) {
        showToast(`智能任务列表加载失败：${error.message}`, "error");
      }
    } finally {
      if (!sessionRequestIsStale(sessionGeneration)) {
        state.agent.listLoading = false;
        renderAgentRunList();
      }
    }
  }

  async function selectAgentRun(runId) {
    if (!runId) return;
    stopAgentPolling();
    state.agent.selectedRunId = runId;
    state.agent.detail = null;
    state.agent.detailError = "";
    state.agent.pollStartedAt = Date.now();
    state.agent.pollFailures = 0;
    renderAgentWorkbench();
    await loadAgentRun(runId);
  }

  async function loadAgentRun(runId, options = {}) {
    if (!runId || !state.principal || !hasPermission("read")) return;
    const polling = Boolean(options.polling);
    const sequence = ++state.agent.requestSequence;
    if (!polling) state.agent.detailLoading = true;
    if (!polling) renderAgentRunDetail();
    try {
      const payload = await api(endpoints.agentRun(runId), {
        timeoutMs: 15000,
      });
      if (
        sequence !== state.agent.requestSequence ||
        state.agent.selectedRunId !== runId
      ) {
        return;
      }
      const run = normalizeAgentRun(payload && (payload.run || payload));
      if (!run.run_id) throw new Error("服务返回的智能任务详情无效。");
      state.agent.detail = run;
      state.agent.detailError = "";
      state.agent.pollFailures = 0;
      upsertAgentRun(run);
      renderAgentWorkbench();
      if (isActiveAgentStatus(run.status)) {
        scheduleAgentPoll(agentPollInterval(run.status));
      } else {
        stopAgentPolling();
      }
    } catch (error) {
      if (
        sequence !== state.agent.requestSequence ||
        state.agent.selectedRunId !== runId
      ) {
        return;
      }
      state.agent.detailError = error.message;
      state.agent.pollFailures += 1;
      renderAgentRunDetail();
      if (
        polling &&
        error.status !== 401 &&
        state.agent.pollFailures < 5
      ) {
        scheduleAgentPoll(Math.min(10000, 2000 * state.agent.pollFailures));
      } else {
        stopAgentPolling();
      }
    } finally {
      if (sequence === state.agent.requestSequence) {
        state.agent.detailLoading = false;
        renderAgentRunDetail();
      }
    }
  }

  function scheduleAgentPoll(delayMs) {
    stopAgentPolling();
    const run = state.agent.detail;
    if (
      !run ||
      !isActiveAgentStatus(run.status) ||
      els.agentWorkbench.hidden ||
      document.hidden
    ) {
      return;
    }
    if (!state.agent.pollStartedAt) state.agent.pollStartedAt = Date.now();
    if (Date.now() - state.agent.pollStartedAt > agentPollLimitMs(run)) {
      state.agent.detailError =
        "页面自动等待已到上限，任务未被取消。请稍后点击刷新查看最终状态。";
      renderAgentRunDetail();
      return;
    }
    state.agent.pollTimer = window.setTimeout(() => {
      state.agent.pollTimer = null;
      void loadAgentRun(run.run_id, { polling: true });
    }, Math.max(0, Number(delayMs) || 0));
  }

  function stopAgentPolling() {
    if (state.agent.pollTimer !== null) {
      window.clearTimeout(state.agent.pollTimer);
      state.agent.pollTimer = null;
    }
  }

  function agentPollInterval(status) {
    return status === "waiting_approval" ? 3000 : 1000;
  }

  function agentPollLimitMs(run) {
    const configured = Number(
      run && run.budgets && run.budgets.max_duration_seconds,
    );
    const seconds = Number.isFinite(configured) && configured > 0
      ? configured + 120
      : 900;
    return Math.min(30 * 60, Math.max(5 * 60, seconds)) * 1000;
  }

  function isActiveAgentStatus(status) {
    return ["queued", "running", "waiting_approval"].includes(
      String(status || ""),
    );
  }

  async function cancelSelectedAgentRun() {
    const run = state.agent.detail;
    if (!run || !isActiveAgentStatus(run.status) || !hasPermission("read")) return;
    const accepted = window.confirm(
      "确定取消这项智能任务吗？已产生的步骤与工具证据会保留，取消不会修改草稿或提交监管平台。",
    );
    if (!accepted) return;
    setBusy(els.cancelAgentRunButton, true, "取消中…");
    try {
      const payload = await api(endpoints.agentRunCancel(run.run_id), {
        method: "POST",
        timeoutMs: 15000,
        body: {},
      });
      const next = normalizeAgentRun(payload && (payload.run || payload));
      state.agent.detail = next;
      upsertAgentRun(next);
      stopAgentPolling();
      renderAgentWorkbench();
      showToast("智能任务已取消，既有过程证据仍保留。");
    } catch (error) {
      await loadAgentRun(run.run_id);
      if (state.agent.detail && state.agent.detail.status === "cancelled") {
        showToast("取消请求一度失去响应，但服务端已确认任务取消。");
      } else {
        showToast(`取消状态未确认：${error.message}，请刷新后再判断。`, "error");
      }
    } finally {
      setBusy(els.cancelAgentRunButton, false);
      renderAgentRunDetail();
    }
  }

  async function decideSelectedAgentApproval(decision) {
    const run = state.agent.detail;
    if (agentIntegrityFailed(run)) {
      els.approveAgentApprovalButton.disabled = true;
      els.rejectAgentApprovalButton.disabled = true;
      showToast(
        "过程证据完整性校验失败，审批已禁用；请取消任务并联系管理员。",
        "error",
      );
      return;
    }
    const approval = pendingAgentApproval(run);
    if (!run || !approval || !["approve", "reject"].includes(decision)) return;
    if (decision === "approve" && !hasPermission("write")) {
      showToast(
        "只读账号可以拒绝或取消，但批准工具继续需要编辑权限。",
        "error",
      );
      return;
    }
    if (!hasPermission("read")) return;
    const toolCall = agentApprovalToolCall(run, approval);
    const verb = decision === "approve" ? "批准" : "拒绝";
    const accepted = window.confirm(
      `${verb}工具“${toolCall.tool_name || "未命名工具"}”执行本卡片所列动作？这不等于企业人工确认，也不会提交监管平台。`,
    );
    if (!accepted) return;
    setBusy(
      decision === "approve"
        ? els.approveAgentApprovalButton
        : els.rejectAgentApprovalButton,
      true,
      `${verb}中…`,
    );
    els.approveAgentApprovalButton.disabled = true;
    els.rejectAgentApprovalButton.disabled = true;
    try {
      const payload = await api(endpoints.agentRunApprove(run.run_id), {
        method: "POST",
        timeoutMs: 15000,
        body: {
          approval_id: approval.approval_id,
          decision,
        },
      });
      const next = normalizeAgentRun(payload && (payload.run || payload));
      state.agent.detail = next;
      upsertAgentRun(next);
      state.agent.pollStartedAt = Date.now();
      state.agent.pollFailures = 0;
      renderAgentWorkbench();
      if (isActiveAgentStatus(next.status)) {
        scheduleAgentPoll(agentPollInterval(next.status));
      }
      showToast(`${verb}决定已记录；仅对该工具动作生效。`);
    } catch (error) {
      await loadAgentRun(run.run_id);
      const refreshed =
        state.agent.detail &&
        state.agent.detail.approvals.find(
          (item) => item.approval_id === approval.approval_id,
        );
      const expectedStatus = decision === "approve" ? "approved" : "rejected";
      if (refreshed && refreshed.status === expectedStatus) {
        showToast(`${verb}请求一度失去响应，但决定已由服务端记录。`);
      } else {
        showToast(`${verb}状态未确认：${error.message}，请刷新后再判断。`, "error");
      }
    } finally {
      setBusy(els.approveAgentApprovalButton, false);
      setBusy(els.rejectAgentApprovalButton, false);
      renderAgentRunDetail();
    }
  }

  function normalizeAgentRun(raw) {
    const source = raw && typeof raw === "object" ? raw : {};
    const integrityProvided = Object.prototype.hasOwnProperty.call(
      source,
      "integrity",
    );
    const integritySource =
      source.integrity &&
      typeof source.integrity === "object" &&
      !Array.isArray(source.integrity)
        ? source.integrity
        : null;
    const allowedStatuses = new Set([
      "queued",
      "running",
      "waiting_approval",
      "completed",
      "failed",
      "cancelled",
    ]);
    const status = allowedStatuses.has(String(source.status))
      ? String(source.status)
      : "queued";
    return {
      run_id: String(source.run_id || source.id || ""),
      actor_id: String(source.actor_id || ""),
      draft_id: String(source.draft_id || ""),
      task: String(source.task || "煤炭数据体检"),
      mode: source.mode === "deterministic" ? "deterministic" : "auto",
      status,
      summary: String(source.summary || ""),
      answer: String(source.answer || ""),
      error:
        source.error && typeof source.error === "object"
          ? {
              code: String(source.error.code || ""),
              message: String(source.error.message || ""),
            }
          : null,
      budgets:
        source.budgets && typeof source.budgets === "object"
          ? clone(source.budgets)
          : {},
      integrity:
        !integrityProvided
          ? null
          : integritySource
          ? {
              valid: integritySource.valid === true,
              event_count: Number(integritySource.event_count || 0),
              head_hash: String(integritySource.head_hash || ""),
            }
          : {
              valid: false,
              event_count: 0,
              head_hash: "",
            },
      steps: Array.isArray(source.steps)
        ? source.steps.map((step, index) => ({
            ...clone(step),
            step_id: String(step.step_id || step.id || `step-${index + 1}`),
            kind: ["model", "tool", "system"].includes(String(step.kind))
              ? String(step.kind)
              : "system",
          }))
        : [],
      tool_calls: Array.isArray(source.tool_calls)
        ? source.tool_calls.map((call, index) => ({
            ...clone(call),
            call_id: String(call.call_id || call.id || `call-${index + 1}`),
            tool_name: String(call.tool_name || call.name || "未命名工具"),
            status: String(call.status || "planned"),
            approval_id: String(call.approval_id || ""),
          }))
        : [],
      approvals: Array.isArray(source.approvals)
        ? source.approvals.map((approval, index) => ({
            ...clone(approval),
            approval_id: String(
              approval.approval_id || approval.id || `approval-${index + 1}`,
            ),
            call_id: String(approval.call_id || approval.tool_call_id || ""),
            status: String(approval.status || "pending"),
          }))
        : [],
      created_at: source.created_at || "",
      updated_at: source.updated_at || "",
      completed_at: source.completed_at || "",
    };
  }

  function upsertAgentRun(run) {
    if (!run || !run.run_id) return;
    const index = state.agent.runs.findIndex(
      (item) => item.run_id === run.run_id,
    );
    if (index >= 0) {
      state.agent.runs.splice(index, 1, {
        ...state.agent.runs[index],
        ...run,
      });
    } else {
      state.agent.runs.unshift(run);
      state.agent.total += 1;
    }
    renderAgentRunList();
  }

  function renderAgentWorkbench() {
    renderAgentWorkbenchControls();
    renderAgentToolCatalog();
    renderAgentRunList();
    renderAgentRunDetail();
  }

  function renderAgentWorkbenchControls() {
    const taskText = String(
      (els.agentTaskInput && els.agentTaskInput.value) || "",
    );
    const taskLength = taskText.length;
    const taskValid = taskText.trim().length > 0 && taskLength <= 4000;
    const canStart = Boolean(
      state.principal &&
      state.activeDraft &&
      hasPermission("read") &&
      !state.agent.creating,
    );
    els.agentTaskButton.disabled = !state.principal || !hasPermission("read");
    els.startAgentHealthButton.disabled = !canStart;
    els.runCoalHealthButton.disabled = !canStart;
    els.startAgentCustomButton.disabled = !canStart || !taskValid;
    els.agentTaskInput.disabled = state.agent.creating;
    els.agentTaskInput.setAttribute("aria-invalid", String(!taskValid));
    els.agentTaskCharacterCount.textContent = `${taskLength}/4000`;
    els.agentTaskCharacterCount.classList.toggle("is-invalid", !taskValid);
    els.agentComposerDraftBinding.textContent = state.activeDraft
      ? `当前草稿：${
          (state.activeDraft.enterprise &&
            (state.activeDraft.enterprise.mine_name ||
              state.activeDraft.enterprise.name)) ||
          shortIdentifier(state.activeDraft.id)
        }`
      : "请先打开一份草稿";
    els.agentComposerDraftBinding.classList.toggle(
      "is-bound",
      Boolean(state.activeDraft),
    );
    document.querySelectorAll("[data-agent-task-preset]").forEach((button) => {
      const matches =
        agentTaskPresets[button.dataset.agentTaskPreset] === taskText;
      button.classList.toggle("is-active", matches);
      button.setAttribute("aria-pressed", String(matches));
      button.disabled = state.agent.creating;
    });
    document.querySelectorAll('input[name="agentRunMode"]').forEach((input) => {
      input.disabled = state.agent.creating;
    });
    els.startAgentHealthButton.title = state.activeDraft
      ? "对当前已保存草稿发起独立体检"
      : "请先打开一份草稿";
    els.runCoalHealthButton.title = els.startAgentHealthButton.title;
    els.startAgentCustomButton.title = !state.activeDraft
      ? "请先打开一份草稿"
      : !taskValid
        ? "请填写 1 到 4000 个字符的任务要求"
        : "按上方任务要求和运行模式发起独立任务";
  }

  function renderAgentRunList() {
    const fragment = document.createDocumentFragment();
    if (state.agent.listLoading && !state.agent.runs.length) {
      fragment.append(el("p", "agent-empty", "正在读取智能任务…"));
    } else if (state.agent.listError && !state.agent.runs.length) {
      const error = el("div", "agent-empty");
      error.append(
        el("strong", "", "任务列表加载失败"),
        el("p", "", state.agent.listError),
      );
      const retry = el("button", "button button-secondary", "重新加载");
      retry.type = "button";
      retry.addEventListener("click", () => void loadAgentRuns());
      error.append(retry);
      fragment.append(error);
    } else if (!state.agent.runs.length) {
      fragment.append(
        el("p", "agent-empty", "还没有智能任务。打开草稿后可发起“一键煤炭体检”。"),
      );
    }
    state.agent.runs.forEach((run) => {
      const button = el("button", "agent-run-item");
      button.type = "button";
      button.classList.toggle(
        "is-active",
        run.run_id === state.agent.selectedRunId,
      );
      if (run.run_id === state.agent.selectedRunId) {
        button.setAttribute("aria-current", "true");
      }
      button.addEventListener("click", () => void selectAgentRun(run.run_id));
      const head = el("span", "agent-run-item-head");
      head.append(
        el("strong", "", truncateText(run.task || "煤炭数据体检", 42)),
        el(
          "span",
          `agent-status status-${run.status}`,
          agentStatusLabel(run.status),
        ),
      );
      button.append(
        head,
        el(
          "small",
          "",
          `${formatDateTime(run.updated_at || run.created_at)} · ${
            run.draft_id ? `草稿 ${shortIdentifier(run.draft_id)}` : "独立任务"
          }`,
        ),
      );
      fragment.append(button);
    });
    els.agentRunList.replaceChildren(fragment);
    els.agentRunList.setAttribute(
      "aria-busy",
      String(state.agent.listLoading),
    );
    const total = Math.max(state.agent.total, state.agent.runs.length);
    els.agentRunListSummary.textContent = state.agent.listLoading
      ? `读取中 · 已显示 ${state.agent.runs.length}/${total}`
      : `已显示 ${state.agent.runs.length}/${total}`;
    els.loadMoreAgentRunsButton.hidden = !state.agent.hasMore;
    els.loadMoreAgentRunsButton.disabled = state.agent.listLoading;
    els.refreshAgentRunsButton.disabled = state.agent.listLoading;
  }

  function renderAgentRunDetail() {
    const run = state.agent.detail;
    const hasDetail = Boolean(
      run && run.run_id === state.agent.selectedRunId,
    );
    els.agentDetailEmpty.hidden = hasDetail || state.agent.detailLoading;
    els.agentDetailContent.hidden = !hasDetail;
    if (!hasDetail) {
      if (state.agent.detailLoading) {
        els.agentDetailEmpty.hidden = false;
        els.agentDetailEmpty.replaceChildren(
          el("span", "", "…"),
          el("h3", "", "正在读取任务详情"),
          el("p", "", "请稍候，页面不会重复发起任务。"),
        );
      } else if (state.agent.detailError) {
        els.agentDetailEmpty.hidden = false;
        const retry = el("button", "button button-secondary", "重新读取");
        retry.type = "button";
        retry.addEventListener("click", () =>
          void loadAgentRun(state.agent.selectedRunId),
        );
        els.agentDetailEmpty.replaceChildren(
          el("span", "", "!"),
          el("h3", "", "任务详情加载失败"),
          el("p", "", state.agent.detailError),
          retry,
        );
      } else {
        els.agentDetailEmpty.hidden = false;
        els.agentDetailEmpty.replaceChildren(
          el("span", "", "诊"),
          el("h3", "", "选择一项任务查看过程"),
          el(
            "p",
            "",
            "这里会分别展示模型规划、确定性工具证据和需要人工批准的动作。",
          ),
        );
      }
      return;
    }
    els.agentRunDetailTitle.textContent = truncateText(
      run.task || "煤炭数据体检",
      120,
    );
    els.agentRunMeta.textContent = [
      run.draft_id ? `关联草稿 ${run.draft_id}` : "未关联草稿",
      `创建于 ${formatDateTime(run.created_at)}`,
      run.mode === "deterministic" ? "仅确定性工具" : "自动规划模式",
    ].join(" · ");
    els.agentRunStatus.textContent = agentStatusLabel(run.status);
    els.agentRunStatus.className = `agent-status status-${run.status}`;
    const integrityFailed = agentIntegrityFailed(run);
    els.agentIntegrityState.hidden = !run.integrity;
    if (run.integrity) {
      els.agentIntegrityState.textContent = run.integrity.valid
        ? `过程链完整 · ${run.integrity.event_count} 条`
        : "过程链校验失败";
      els.agentIntegrityState.className =
        `agent-integrity ${run.integrity.valid ? "is-valid" : "is-invalid"}`;
      els.agentIntegrityState.title = run.integrity.head_hash
        ? `链头摘要 ${shortDigest(run.integrity.head_hash)}`
        : "";
    } else {
      els.agentIntegrityState.className = "agent-integrity";
      els.agentIntegrityState.title = "";
    }
    const canFailSafeCancel = isActiveAgentStatus(run.status);
    els.cancelAgentRunButton.disabled = !canFailSafeCancel;
    els.cancelAgentRunButton.hidden = !canFailSafeCancel;
    els.agentIntegrityFailure.hidden = !integrityFailed;
    els.agentRunProgress.hidden = integrityFailed;
    els.agentRunAnswer.hidden = integrityFailed;
    els.agentEvidenceSection.hidden = integrityFailed;
    if (integrityFailed) {
      els.agentRunAnswer.replaceChildren();
      els.agentRunError.hidden = true;
      els.agentRunError.textContent = "";
      els.agentApprovalCard.hidden = true;
      els.agentApprovalTitle.textContent = "审批已禁用";
      els.agentApprovalExplanation.textContent = "";
      els.agentApprovalDetails.replaceChildren();
      els.agentApprovalPermissionHint.textContent =
        "过程证据完整性校验失败，不能批准或拒绝任何动作。";
      els.approveAgentApprovalButton.disabled = true;
      els.rejectAgentApprovalButton.disabled = true;
      els.agentStepList.replaceChildren();
      return;
    }
    renderAgentProgress(run);
    renderAgentAnswer(run);
    const errorMessage =
      state.agent.detailError ||
      (run.error && (run.error.message || run.error.code)) ||
      "";
    els.agentRunError.hidden = !errorMessage;
    els.agentRunError.textContent = errorMessage
      ? `任务提示：${errorMessage}`
      : "";
    renderAgentApproval(run);
    renderAgentSteps(run);
  }

  function agentIntegrityFailed(run) {
    return Boolean(
      run &&
      run.integrity &&
      typeof run.integrity === "object" &&
      run.integrity.valid !== true
    );
  }

  function renderAgentProgress(run) {
    const budgets = run.budgets || {};
    const entries = [
      [
        "步骤",
        Number(budgets.steps_used || run.steps.length || 0),
        Number(budgets.max_steps || 0),
      ],
      [
        "工具调用",
        Number(budgets.tool_calls_used || run.tool_calls.length || 0),
        Number(budgets.max_tool_calls || 0),
      ],
      [
        "结果大小",
        Number(budgets.result_bytes_used || 0),
        Number(budgets.max_result_bytes || 0),
      ],
      [
        "运行秒数",
        Number(budgets.active_duration_seconds || 0),
        Number(budgets.max_duration_seconds || 0),
      ],
    ];
    const fragment = document.createDocumentFragment();
    entries.forEach(([label, used, maximum]) => {
      const item = el("div", "agent-budget-item");
      const text = maximum > 0 ? `${used}/${maximum}` : String(used);
      item.append(el("span", "", label), el("strong", "", text));
      if (maximum > 0) {
        const progress = document.createElement("progress");
        progress.max = maximum;
        progress.value = Math.min(used, maximum);
        progress.setAttribute("aria-label", `${label}使用 ${text}`);
        item.append(progress);
      }
      fragment.append(item);
    });
    els.agentRunProgress.replaceChildren(fragment);
  }

  function renderAgentAnswer(run) {
    const content = run.answer || run.summary;
    if (!content) {
      els.agentRunAnswer.replaceChildren(
        el(
          "p",
          "agent-empty",
          isActiveAgentStatus(run.status)
            ? "任务仍在进行，完成后这里会给出综合说明。"
            : "该任务没有返回综合说明，请查看下方工具证据。",
        ),
      );
      return;
    }
    els.agentRunAnswer.replaceChildren(
      el(
        "strong",
        "",
        run.mode === "deterministic"
          ? "确定性体检摘要（基于工具结果）"
          : "智能体综合说明（模型生成，需人工判断）",
      ),
      el("p", "", truncateText(content, 5000)),
    );
  }

  function renderAgentApproval(run) {
    const approval = pendingAgentApproval(run);
    els.agentApprovalCard.hidden = !approval;
    if (!approval) return;
    const toolCall = agentApprovalToolCall(run, approval);
    const presentation = agentToolDisplay(toolCall.tool_name);
    els.agentApprovalTitle.textContent =
      `是否允许“${presentation.label}”继续？`;
    els.agentApprovalExplanation.textContent = String(
      approval.rationale ||
        approval.reason ||
        toolCall.summary ||
        "智能体未提供额外理由，请根据工具和参数谨慎决定。",
    );
    const rows = [
      ["工具名称", presentation.label],
      ["技术标识", toolCall.tool_name || "未命名工具"],
      ["动作状态", agentToolStatusLabel(toolCall.status)],
      [
        "草稿修订",
        firstDefined(approval.draft_revision, toolCall.draft_revision, "未提供"),
      ],
      ["审批编号", approval.approval_id],
      [
        "参数摘要",
        shortDigest(
          approval.arguments_sha256 ||
            toolCall.arguments_sha256 ||
            "未返回",
        ),
      ],
      ["脱敏参数", safeAgentValue(toolCall.arguments, 3000)],
    ];
    const fragment = document.createDocumentFragment();
    rows.forEach(([term, detail]) => {
      const row = document.createElement("div");
      row.append(el("dt", "", term), el("dd", "", detail || "未提供"));
      fragment.append(row);
    });
    els.agentApprovalDetails.replaceChildren(fragment);
    const actionable =
      run.status === "waiting_approval" && approval.status === "pending";
    els.approveAgentApprovalButton.disabled =
      !actionable || !hasPermission("write");
    els.rejectAgentApprovalButton.disabled =
      !actionable || !hasPermission("read");
    els.approveAgentApprovalButton.title = hasPermission("write")
      ? "仅批准当前卡片列出的单个工具动作"
      : "批准工具继续需要编辑权限";
    els.agentApprovalPermissionHint.textContent = hasPermission("write")
      ? "当前账号可批准或拒绝；两种决定都会按账号留痕。"
      : "当前是只读账号：可以拒绝或取消任务，但批准工具继续需要编辑权限。";
  }

  function pendingAgentApproval(run) {
    if (!run || !Array.isArray(run.approvals)) return null;
    return run.approvals.find((approval) => approval.status === "pending") || null;
  }

  function agentApprovalToolCall(run, approval) {
    if (!run || !approval) return {};
    return (
      run.tool_calls.find(
        (call) =>
          (approval.call_id && call.call_id === approval.call_id) ||
          (call.approval_id &&
            call.approval_id === approval.approval_id),
      ) || {}
    );
  }

  function renderAgentSteps(run) {
    const fragment = document.createDocumentFragment();
    const representedCalls = new Set();
    run.steps.forEach((step, index) => {
      const evidence =
        step.evidence && typeof step.evidence === "object"
          ? step.evidence
          : {};
      const callId = step.tool_call_id || step.call_id || evidence.call_id;
      const call = callId
        ? run.tool_calls.find((item) => item.call_id === callId)
        : null;
      if (call) representedCalls.add(call.call_id);
      fragment.append(agentStepCard(step, call, index));
    });
    run.tool_calls.forEach((call, index) => {
      if (representedCalls.has(call.call_id)) return;
      fragment.append(
        agentStepCard(
          {
            step_id: `tool-${call.call_id}`,
            kind: "tool",
            summary: call.summary,
            evidence: call.evidence,
          },
          call,
          run.steps.length + index,
        ),
      );
    });
    if (!run.steps.length && !run.tool_calls.length) {
      fragment.append(
        el(
          "p",
          "agent-empty",
          isActiveAgentStatus(run.status)
            ? "任务已排队，尚未产生步骤。"
            : "该任务没有可展示的步骤证据。",
        ),
      );
    }
    els.agentStepList.replaceChildren(fragment);
  }

  function agentStepCard(step, toolCall, index) {
    const kind = step.kind || "system";
    const evidence =
      step.evidence && typeof step.evidence === "object"
        ? step.evidence
        : toolCall && toolCall.evidence && typeof toolCall.evidence === "object"
          ? toolCall.evidence
          : {};
    const deterministic =
      kind === "tool" && evidence.deterministic === true;
    const card = el(
      "article",
      `agent-step-card kind-${kind}${deterministic ? " is-deterministic" : ""}`,
    );
    const head = el("div", "agent-step-head");
    const badgeText =
      kind === "model"
        ? "模型规划 · 非事实证据"
        : deterministic
          ? "确定性工具结果"
          : kind === "tool"
            ? "工具过程 · 待核实"
            : "系统状态";
    head.append(
      el("span", `agent-kind-badge kind-${kind}`, badgeText),
      el("small", "", `第 ${index + 1} 步`),
    );
    const technicalTitle =
      toolCall && toolCall.tool_name
        ? toolCall.tool_name
        : step.title ||
          step.name ||
          step.action ||
          evidence.tool_name ||
          "任务步骤";
    const toolPresentation = agentToolDisplay(
      technicalTitle,
      toolCall && toolCall.category,
    );
    const summary =
      (toolCall &&
        (toolCall.summary ||
          (toolCall.result &&
            typeof toolCall.result === "object" &&
            toolCall.result.summary) ||
          (typeof toolCall.result === "string" ? toolCall.result : "") ||
          (toolCall.error && toolCall.error.message))) ||
      step.summary ||
      step.content ||
      step.explanation ||
      step.message ||
      evidence.summary ||
      evidence.result ||
      "";
    card.append(head);
    if (toolCall) {
      const titleRow = el("div", "agent-tool-title-row");
      const titleText = el("div", "");
      titleText.append(
        el("h5", "", toolPresentation.label),
        el("code", "", toolCall.tool_name || "未命名工具"),
      );
      titleRow.append(
        titleText,
        el("span", "agent-tool-category", toolPresentation.categoryLabel),
      );
      card.append(titleRow);
    } else {
      card.append(el("h5", "", String(technicalTitle)));
    }
    card.append(
      el(
        "p",
        "",
        truncateText(
          safeAgentValue(summary, 4000) ||
            (isActiveAgentStatus(toolCall && toolCall.status)
              ? "正在执行…"
              : "未返回说明。"),
          4000,
        ),
      ),
    );
    if (toolCall) {
      const grounding = agentEvidenceGrounding(toolCall, evidence);
      const groundingPanel = el(
        "div",
        `agent-grounding ${grounding.className}`,
      );
      groundingPanel.append(
        el("span", "", "输入来源"),
        el("strong", "", grounding.label),
        el("small", "", grounding.explanation),
      );
      card.append(groundingPanel);

      const facts = el("dl", "agent-tool-facts");
      const duration = firstDefined(
        toolCall.duration_ms,
        evidence.duration_ms,
        elapsedMilliseconds(toolCall.started_at, toolCall.completed_at),
        null,
      );
      const rows = [
        ["工具状态", agentToolStatusLabel(toolCall.status)],
        [
          "耗时",
          duration === null || duration === undefined
            ? "未返回"
            : `${Number(duration)} ms`,
        ],
        [
          "计算属性",
          deterministic
            ? "确定性复算：相同输入会得到相同结果"
            : "未声明为确定性计算，需人工核实",
        ],
        [
          "结果摘要",
          shortDigest(
            toolCall.result_sha256 ||
              evidence.result_sha256 ||
              "未返回",
          ),
        ],
      ];
      rows.forEach(([term, detail]) => {
        const row = document.createElement("div");
        row.append(el("dt", "", term), el("dd", "", detail));
        facts.append(row);
      });
      card.append(facts);
      const resultDetails = agentToolResultDetails(toolCall);
      if (resultDetails) card.append(resultDetails);
    }
    if (kind === "model") {
      card.append(
        el(
          "small",
          "agent-model-disclaimer",
          "该段是模型的计划或解释，可能有误；请以来源已绑定的工具结果和原始材料为准。调用者提供数值的复算不能证明来源真实。",
        ),
      );
    }
    return card;
  }

  function agentToolResultDetails(toolCall) {
    const result =
      toolCall && toolCall.result && typeof toolCall.result === "object"
        ? toolCall.result
        : null;
    const data =
      result &&
      result.data &&
      typeof result.data === "object" &&
      !Array.isArray(result.data)
        ? result.data
        : null;
    if (!data || toolCall.status !== "succeeded") return null;

    const facts = selectAgentResultFacts(toolCall.tool_name, data);
    const uncertaintyValue = firstDefined(
      data.uncertainty,
      data.uncertainties,
      result.uncertainty,
    );
    const uncertainty =
      uncertaintyValue === undefined ? null : uncertaintyValue;
    const evidence = selectAgentResultEvidence(data, result, facts);
    const details = el("details", "agent-result-details");
    const summary = document.createElement("summary");
    summary.append(
      el("span", "", "查看结构化结果"),
      el(
        "small",
        "",
        [
          facts.length ? `${facts.length} 项关键值` : "",
          uncertainty !== null ? "含不确定性" : "",
          evidence.length ? `${evidence.length} 组证据` : "",
        ]
          .filter(Boolean)
          .join(" · ") || "服务端未返回可展示字段",
      ),
    );
    details.append(summary);
    const body = el("div", "agent-result-body");

    if (facts.length) {
      const factSection = el("section", "agent-result-section");
      factSection.append(el("h6", "", "关键结果"));
      const list = el("dl", "agent-result-facts");
      facts.forEach(({ key, value }) => {
        const row = document.createElement("div");
        row.append(
          el("dt", "", agentResultFieldLabel(key)),
          el("dd", "", formatAgentResultValue(key, value)),
        );
        list.append(row);
      });
      factSection.append(list);
      body.append(factSection);
    }

    if (uncertainty !== null) {
      body.append(agentResultUncertaintyPanel(uncertainty));
    }

    if (evidence.length) {
      const evidenceSection = el("section", "agent-result-section");
      evidenceSection.append(el("h6", "", "证据与明细（限量预览）"));
      const evidenceList = el("div", "agent-result-evidence-list");
      evidence.forEach(({ key, value }) => {
        const evidenceDetails = el("details", "agent-result-evidence");
        const evidenceSummary = document.createElement("summary");
        evidenceSummary.append(
          el("span", "", agentResultFieldLabel(key)),
          el("small", "", agentResultCollectionSummary(value)),
        );
        const preview = boundedAgentResultPreview(value);
        evidenceDetails.append(
          evidenceSummary,
          el("pre", "", safeAgentValue(preview, 4000) || "无可展示内容"),
        );
        evidenceList.append(evidenceDetails);
      });
      evidenceSection.append(evidenceList);
      body.append(evidenceSection);
    }

    const disclaimer = safeAgentValue(
      data.disclaimer || result.disclaimer || "",
      800,
    ).trim();
    const scenario =
      data.status === "scenario_calculated" ||
      String(data.input_origin || "").includes("caller_supplied") ||
      agentToolIsScenarioOnly(toolCall.tool_name);
    if (scenario || disclaimer || data.not_a_regulatory_determination === true) {
      const note = el("p", "agent-result-disclaimer");
      note.append(
        el(
          "strong",
          "",
          scenario ? "情景复算，不是监管认定。" : "结果不是监管认定。",
        ),
      );
      if (disclaimer) {
        note.append(
          document.createTextNode(` ${truncateText(disclaimer, 800)}`),
        );
      } else {
        note.append(
          document.createTextNode(
            " 请结合原始凭证、计量口径和专业人员复核后使用。",
          ),
        );
      }
      body.append(note);
    }

    if (!body.childNodes.length) {
      body.append(
        el("p", "agent-result-empty", "服务端未返回可安全展示的结构化字段。"),
      );
    }
    details.append(body);
    return details;
  }

  function selectAgentResultFacts(toolName, data) {
    const selected = [];
    const seen = new Set();
    const reserved = new Set([
      "uncertainty",
      "uncertainties",
      "disclaimer",
      "not_a_regulatory_determination",
      "evidence",
      "artifacts",
    ]);
    const plan = Object.prototype.hasOwnProperty.call(
      agentToolResultFieldPlans,
      toolName,
    )
      ? agentToolResultFieldPlans[toolName]
      : [];
    const scalarKeys = Object.keys(data).filter((key) => {
      const value = data[key];
      return (
        !reserved.has(key) &&
        !isAgentResultSensitiveKey(key) &&
        (value === null ||
          ["string", "number", "boolean"].includes(typeof value))
      );
    });
    const compactObjectKeys = Object.keys(data).filter(
      (key) =>
        !reserved.has(key) &&
        !isAgentResultSensitiveKey(key) &&
        isAgentResultRecord(data[key]) &&
        Object.keys(data[key]).length <= 8,
    );
    [...plan, ...scalarKeys, ...compactObjectKeys].forEach((key) => {
      if (
        selected.length >= 12 ||
        seen.has(key) ||
        reserved.has(key) ||
        isAgentResultSensitiveKey(key) ||
        !Object.prototype.hasOwnProperty.call(data, key)
      ) {
        return;
      }
      seen.add(key);
      selected.push({ key, value: data[key] });
    });
    return selected;
  }

  function selectAgentResultEvidence(data, result, facts) {
    const used = new Set(facts.map((fact) => fact.key));
    const entries = [];
    const preferredPattern =
      /evidence|observation|record|pair|point|component|propert|constraint|issue|check|evaluation|event|submission|review|audit|integrity|series|metric_result|source_summar|import|field|conflict|lineage/i;
    const candidates = Object.keys(data)
      .filter(
        (key) =>
          !used.has(key) &&
          !["uncertainty", "uncertainties", "disclaimer"].includes(key) &&
          !isAgentResultSensitiveKey(key) &&
          (Array.isArray(data[key]) || isAgentResultRecord(data[key])),
      )
      .sort((left, right) => {
        const leftPreferred = preferredPattern.test(left) ? 0 : 1;
        const rightPreferred = preferredPattern.test(right) ? 0 : 1;
        return leftPreferred - rightPreferred;
      });
    candidates.slice(0, 5).forEach((key) => {
      entries.push({ key, value: data[key] });
    });
    if (
      entries.length < 5 &&
      result.artifacts &&
      (Array.isArray(result.artifacts) ||
        isAgentResultRecord(result.artifacts))
    ) {
      entries.push({ key: "artifacts", value: result.artifacts });
    }
    return entries;
  }

  function agentResultUncertaintyPanel(uncertainty) {
    const section = el("section", "agent-result-section is-uncertainty");
    section.append(el("h6", "", "不确定性与适用边界"));
    if (isAgentResultRecord(uncertainty)) {
      const list = el("dl", "agent-result-facts");
      const keys = Object.keys(uncertainty).slice(0, 12);
      keys.forEach((key) => {
        const row = document.createElement("div");
        row.append(
          el("dt", "", agentResultFieldLabel(key)),
          el("dd", "", formatAgentResultValue(key, uncertainty[key])),
        );
        list.append(row);
      });
      if (Object.keys(uncertainty).length > keys.length) {
        section.append(
          el(
            "small",
            "agent-result-omitted",
            `另有 ${Object.keys(uncertainty).length - keys.length} 项未展开。`,
          ),
        );
      }
      section.append(list);
    } else {
      section.append(
        el(
          "pre",
          "",
          safeAgentValue(boundedAgentResultPreview(uncertainty), 2500) ||
            "未提供",
        ),
      );
    }
    return section;
  }

  function agentToolIsScenarioOnly(toolName) {
    const catalogTool = state.agent.tools.find(
      (tool) => tool.name === toolName,
    );
    if (catalogTool) return catalogTool.scenarioOnly;
    const presentation = Object.prototype.hasOwnProperty.call(
      agentToolPresentation,
      toolName,
    )
      ? agentToolPresentation[toolName]
      : null;
    return Boolean(
      presentation &&
        ["coal_quality_scenario", "coal_blending_scenario"].includes(
          presentation.category,
        ),
    );
  }

  function agentResultFieldLabel(key) {
    const labels = {
      ...agentResultFieldLabels,
      formula_id: "公式版本",
      formula_version: "公式版本",
      formula: "计算公式",
      input_origin: "输入来源",
      evidence_verified: "输入证据已核验",
      uncertainty: "不确定性",
      reason: "限制说明",
      laboratory_method_verified: "试验方法已核验",
      calorific_value_supported: "支持热值换算",
      nonlinear_quality_indices_supported: "支持非线性煤质指标",
      basis_note: "基准说明",
      mass_weighted_linear_model: "采用质量加权线性模型",
      quality_basis_aligned: "煤质基准已对齐",
      laboratory_methods_verified: "试验方法均已核验",
      sampling_uncertainty_included: "已纳入采样不确定性",
      nonlinear_properties_optimized: "已优化非线性指标",
      recipe_optimized: "已优化配方",
      future_demand_forecast: "属于未来需求预测",
      inventory_ownership_verified: "库存权属已核验",
      inventory_cutoff_alignment_verified: "库存截止时点已核验",
      outflow_aggregation_assumption: "出库聚合假设",
      unique_closing_snapshot_required: "要求唯一期末快照",
      threshold_origin: "阈值来源",
      pairing_rule: "配对规则",
      business_relation_verified: "业务关系已核验",
      automatic_exact_unit_conversion: "已执行精确单位换算",
      measurement_uncertainty_included: "已纳入测量不确定性",
      causality_determined: "已判定因果关系",
      parameter_source: "参数来源",
      metric_semantics: "指标语义",
      future_data_excluded: "已排除未来数据",
      only_succeeded_submissions_in_history: "历史仅含成功报送",
      context_matched: "工况已匹配",
      linear_projection_is_forecast: "线性尺度属于预测",
      seasonality_modeled: "已建模季节性",
      artifacts: "产物与凭证索引",
      evidence: "证据摘要",
      series: "序列明细",
      metric_results: "逐指标结果",
      source_summaries: "来源摘要",
      sources: "来源摘要",
      imports: "导入批次",
      fields: "字段来源",
      conflicts: "冲突明细",
      lineage_records: "来源链明细",
      source_kind_counts: "来源类型统计",
      extraction_method_counts: "提取方式统计",
      missing_requested_source_ids: "未找到的来源编号",
      missing_requested_metric_codes: "未找到的指标编码",
      missing_requested_observation_ids: "未找到的观测编号",
      components: "配煤组分",
      properties: "加权煤质",
      constraint_evaluations: "调用者约束评价",
      pairs: "配对明细",
      points: "历史点",
    };
    if (Object.prototype.hasOwnProperty.call(labels, key)) return labels[key];
    return String(key || "字段")
      .replace(/_/g, " ")
      .replace(/\bsha256\b/gi, "摘要");
  }

  function formatAgentResultValue(key, value) {
    if (isAgentResultSensitiveKey(key)) return "[已脱敏]";
    if (value === null || value === undefined || value === "") return "未提供/无法评价";
    if (typeof value === "boolean") return value ? "是" : "否";
    if (Array.isArray(value) || isAgentResultRecord(value)) {
      const preview = boundedAgentResultPreview(value, 0, {
        arrayLimit: 3,
        objectLimit: 6,
        maxDepth: 1,
      });
      return safeAgentValue(preview, 600) || agentResultCollectionSummary(value);
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return "非有限数值（不可采信）";
      const formatted = new Intl.NumberFormat("zh-CN", {
        maximumFractionDigits: 6,
      }).format(value);
      if (/_percent$/i.test(key)) return `${formatted}%`;
      if (
        /(^relative_|_relative_|relative_.*gap|relative_.*change)/i.test(key)
      ) {
        return `${new Intl.NumberFormat("zh-CN", {
          maximumFractionDigits: 3,
        }).format(value * 100)}%`;
      }
      if (/_days?$/i.test(key)) return `${formatted} 天`;
      if (/_seconds?$/i.test(key)) return `${formatted} 秒`;
      if (/_ms$/i.test(key)) return `${formatted} ms`;
      if (/_t$/i.test(key)) return `${formatted} t`;
      return formatted;
    }
    const text = String(value);
    const safeText = safeAgentValue(text, 600);
    if (/sha256|digest|(^|_)hash$/i.test(key)) return shortDigest(safeText);
    const statuses = {
      scenario_calculated: "情景复算完成",
      evaluated: "已评价",
      not_evaluated: "无法评价",
      insufficient_history: "历史样本不足",
      insufficient_points: "时序点不足",
      left_metric_missing: "缺少左侧指标",
      right_metric_missing: "缺少右侧指标",
      no_aligned_pairs: "没有可配对观测",
      candidate_found: "发现候选变化点",
      within_tolerance: "在容差内",
      outside_tolerance: "超出容差",
      all_supplied_constraints_met: "满足调用者提供的全部约束",
      one_or_more_supplied_constraints_not_met:
        "至少一项调用者约束未满足",
      meets_supplied_constraint: "满足调用者提供的约束",
      does_not_meet_supplied_constraint: "不满足调用者提供的约束",
      not_requested: "未请求评价",
      increasing: "上升",
      decreasing: "下降",
      flat: "平稳",
      valid: "有效",
      invalid: "无效",
      complete: "完整",
      partial: "部分覆盖",
    };
    return Object.prototype.hasOwnProperty.call(statuses, text)
      ? `${statuses[text]}（${text}）`
      : safeText;
  }

  function agentResultCollectionSummary(value) {
    if (Array.isArray(value)) return `${value.length} 项`;
    if (isAgentResultRecord(value)) {
      return `${Object.keys(value).length} 个字段`;
    }
    return "1 项";
  }

  function isAgentResultRecord(value) {
    return Boolean(
      value &&
        typeof value === "object" &&
        !Array.isArray(value),
    );
  }

  function isAgentResultSensitiveKey(key) {
    const normalized = String(key || "").toLowerCase();
    if (["__proto__", "prototype", "constructor"].includes(normalized)) {
      return true;
    }
    if (
      /password|secret|token|api.?key|credential|authorization|cookie|private.?key|request.?json|raw.?(body|content)|(^|_)(hmac|encryption|signing|access)_?key($|_)/i.test(
        normalized,
      )
    ) {
      return true;
    }
    return (
      normalized === "signature" ||
      normalized.endsWith("_signature") ||
      normalized.includes("signature_value") ||
      normalized.includes("signature_content")
    );
  }

  function boundedAgentResultPreview(value, depth = 0, options = {}) {
    const arrayLimit = Number(options.arrayLimit || 5);
    const objectLimit = Number(options.objectLimit || 12);
    const maxDepth = Number(options.maxDepth || 2);
    if (value === null || value === undefined) return value;
    if (typeof value === "string") return truncateText(value, 700);
    if (typeof value === "number") {
      return Number.isFinite(value) ? value : "[非有限数值]";
    }
    if (typeof value === "boolean") return value;
    if (depth >= maxDepth) {
      return Array.isArray(value)
        ? `[${value.length} 项，深层内容已省略]`
        : `[${Object.keys(value).length} 个字段，深层内容已省略]`;
    }
    if (Array.isArray(value)) {
      const preview = value
        .slice(0, arrayLimit)
        .map((item) =>
          boundedAgentResultPreview(item, depth + 1, options),
        );
      if (value.length > arrayLimit) {
        preview.push(`[另有 ${value.length - arrayLimit} 项未显示]`);
      }
      return preview;
    }
    if (!isAgentResultRecord(value)) return truncateText(String(value), 700);
    const preview = Object.create(null);
    const keys = Object.keys(value);
    keys.slice(0, objectLimit).forEach((key) => {
      preview[key] = isAgentResultSensitiveKey(key)
        ? "[已脱敏]"
        : boundedAgentResultPreview(value[key], depth + 1, options);
    });
    if (keys.length > objectLimit) {
      preview["省略字段数"] = keys.length - objectLimit;
    }
    return preview;
  }

  function agentEvidenceGrounding(toolCall, evidence) {
    const call =
      toolCall && typeof toolCall === "object" ? toolCall : {};
    const details =
      evidence && typeof evidence === "object" ? evidence : {};
    const callEvidence =
      call.evidence && typeof call.evidence === "object" ? call.evidence : {};
    const result =
      call.result && typeof call.result === "object" ? call.result : {};
    const resultData =
      result.data && typeof result.data === "object" ? result.data : {};
    let grounding = firstDefined(
      call.evidence_grounding,
      details.evidence_grounding,
      callEvidence.evidence_grounding,
      result.evidence_grounding,
      resultData.evidence_grounding,
      "",
    );
    if (grounding && typeof grounding === "object") {
      grounding = firstDefined(
        grounding.kind,
        grounding.type,
        grounding.source,
        grounding.value,
        "",
      );
    }
    const normalized = String(grounding || "")
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, "_");
    if (
      [
        "repository_grounded",
        "repository",
        "repository_bound",
        "draft_repository",
      ].includes(normalized)
    ) {
      return {
        className: "is-repository",
        label: "当前草稿/历史库绑定",
        explanation:
          "工具从当前草稿或兼容的成功历史记录读取数据；仍需结合原始材料人工复核。",
      };
    }
    if (
      [
        "user_supplied",
        "caller_supplied",
        "caller_values",
        "provided_values",
      ].includes(normalized)
    ) {
      return {
        className: "is-user-supplied",
        label: "调用者提供数值，仅复算不证明来源",
        explanation:
          "工具只验证这些输入下的计算关系，不能证明数值来自台账、传感器或其他原始凭证。",
      };
    }
    if (normalized === "mixed") {
      return {
        className: "is-mixed",
        label: "混合来源：部分仓库绑定，部分调用者提供",
        explanation:
          "请逐项区分已绑定记录与临时输入；临时输入的复算结果不能证明其来源真实。",
      };
    }
    if (normalized === "external_public") {
      return {
        className: "is-network",
        label: "公开外部来源，需核验正文",
        explanation:
          "结果来自固定公开检索通道；搜索标题或片段不能替代官方正文和业务适用性判断。",
      };
    }
    return {
      className: "is-unknown",
      label: "来源绑定未声明",
      explanation:
        "当前结果没有可识别的来源绑定标记，不能视为当前草稿或历史库事实。",
    };
  }

  function agentStatusLabel(status) {
    const labels = {
      queued: "等待执行",
      running: "正在体检",
      waiting_approval: "等待人工批准",
      completed: "已完成",
      failed: "执行失败",
      cancelled: "已取消",
    };
    return labels[status] || "状态未知";
  }

  function agentToolStatusLabel(status) {
    const labels = {
      planned: "已规划",
      waiting_approval: "等待人工批准",
      running: "执行中",
      succeeded: "执行成功",
      failed: "执行失败",
      rejected: "人工已拒绝",
    };
    return labels[status] || String(status || "状态未知");
  }

  function safeAgentValue(value, maximum = 3000) {
    if (value === null || value === undefined || value === "") return "";
    let text;
    if (typeof value === "string") {
      text = value;
    } else {
      try {
        text = JSON.stringify(
          value,
          (key, item) =>
            /password|secret|token|api.?key|credential|authorization|signature/i.test(
              key,
            )
              ? "[已脱敏]"
              : item,
          2,
        );
      } catch {
        text = String(value);
      }
    }
    text = text
      .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "[已脱敏]")
      .replace(/\bBearer\s+[A-Za-z0-9._~+\/=-]{8,}/gi, "Bearer [已脱敏]");
    return truncateText(text, maximum);
  }

  function elapsedMilliseconds(start, end) {
    if (!start || !end) return null;
    const amount = new Date(end).getTime() - new Date(start).getTime();
    return Number.isFinite(amount) && amount >= 0 ? amount : null;
  }

  function truncateText(value, maximum) {
    const text = String(value || "");
    return text.length > maximum
      ? `${text.slice(0, Math.max(0, maximum - 1))}…`
      : text;
  }

  function shortIdentifier(value) {
    const text = String(value || "");
    return text.length > 16 ? `${text.slice(0, 8)}…${text.slice(-5)}` : text;
  }

  function renderSubmission() {
    const draft = state.activeDraft;
    const platform = state.platformStatus;
    const pendingSubmission =
      state.evidence.draftId === draft.id &&
      state.evidence.submissions.some(
        (record) =>
          record &&
          record.status === "pending" &&
          Number(record.confirmed_revision) === Number(draft.revision),
      );
    const platformConfigured = platform
      ? Boolean(platform.configured)
      : Boolean(state.serviceHealth && state.serviceHealth.platform_configured);
    const platformReady =
      platformConfigured &&
      (!platform || (platform.reachable !== false && platform.compatible !== false));
    const gateRows = [
      {
        ready:
          draft.measurements.length > 0 &&
          draft.measurements.every((row) => row.confirmed),
        text: "所有填报数字已有确认权限人员逐项核对",
      },
      {
        ready: Boolean(draft.preflight && draft.preflight.blockers === 0),
        text: "最新预检没有阻断问题",
      },
      {
        ready: Boolean(draft.signature.valid && draft.signature.signed_at),
        text: "企业确认人已用登录账号完成声明",
      },
      {
        ready: canFinalizeWith("submit"),
        text: credentialRotationRequired()
          ? "临时或待换密账号禁止正式提交"
          : hasPermission("submit")
            ? "当前登录账号具有提交权限"
            : "当前登录账号没有提交权限",
      },
      {
        ready: platformReady,
        text: !platformConfigured
          ? "尚未配置监管平台接口，可继续编辑但不能提交"
          : platform && platform.compatible === false
            ? "监管接口契约不兼容，请联系管理员"
            : platform && platform.reachable === false
              ? "监管接口当前不可达，请刷新状态后重试"
              : "监管平台接口已配置",
      },
      {
        ready: !pendingSubmission,
        text: pendingSubmission
          ? "同一确认版本仍在提交处理中，请刷新记录，勿重复发起"
          : "当前没有尚未完成的同版本提交",
      },
    ];
    const fragment = document.createDocumentFragment();
    gateRows.forEach((gate) => {
      fragment.append(
        el("div", `gate-item ${gate.ready ? "is-ready" : "is-blocked"}`, gate.text),
      );
    });
    els.submissionGate.replaceChildren(fragment);
    const ready = gateRows.every((row) => row.ready) && draft.status !== "submitted";
    els.submitButton.disabled = !ready;

    const submitted = draft.status === "submitted" || Boolean(draft.receipt);
    els.submitCard.hidden = submitted;
    els.receiptCard.hidden = !submitted;
    if (submitted) renderReceipt();
    renderEvidence();
    renderSimpleTaskGuide();
  }

  function openSubmitDialog() {
    if (!state.activeDraft || els.submitButton.disabled || state.activeOperation) return;
    els.finalSubmitCheck.checked = false;
    els.confirmSubmitButton.disabled = true;
    els.submitDialog.showModal();
  }

  async function submitDraft() {
    if (
      !state.activeDraft ||
      !els.finalSubmitCheck.checked ||
      !canFinalizeWith("submit")
    ) {
      showToast("当前账号不能执行正式提交。", "error");
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    state.activeOperation = "提交监管平台";
    setBusy(els.confirmSubmitButton, true, "正在提交…");
    const draftId = state.activeDraft.id;
    const revision = state.activeDraft.revision;
    if (
      !state.submitAttempt ||
      state.submitAttempt.draftId !== draftId ||
      state.submitAttempt.revision !== revision
    ) {
      state.submitAttempt = {
        draftId,
        revision,
        key: `${draftId}-r${revision}`,
      };
    }
    const idempotencyKey = state.submitAttempt.key;
    try {
      const payload = await api(endpoints.submit(state.activeDraft.id), {
        method: "POST",
        timeoutMs: 55000,
        body: {
          idempotency_key: idempotencyKey,
        },
      });
      if (payload && (payload.draft || payload.id === state.activeDraft.id)) {
        applyServerDraft(payload);
      }
      const receipt = normalizeReceipt(
        (payload && (payload.receipt || payload.submission_receipt)) || payload,
      );
      if (!receipt || !receipt.receipt_id) {
        throw new Error("监管平台未返回有效回执号，请勿重复提交并联系管理员核查。");
      }
      state.activeDraft.receipt = receipt;
      state.activeDraft.status = "submitted";
      updateDraftSummary();
      els.submitDialog.close();
      renderAll();
      showToast("监管平台已接收，回执已保存。");
      void loadEvidence(true);
    } catch (error) {
      const outcome = await reconcileSubmissionAttempt(draftId, idempotencyKey);
      if (outcome === "succeeded") {
        if (els.submitDialog.open) els.submitDialog.close();
        showToast("提交请求的页面等待虽已结束，但平台已成功接收；回执已从提交记录恢复。");
      } else if (outcome === "pending") {
        showToast(
          "提交仍在服务端处理中。请勿换用新幂等键重复提交，稍后点击“刷新记录”核对结果。",
          "error",
        );
      } else if (outcome === "failed_retryable") {
        showToast(
          `提交未成功：${error.message}。可修复网络或平台故障后，用同一幂等键安全重试。`,
          "error",
        );
      } else if (outcome === "failed_final") {
        showToast(
          `提交未通过：${error.message}。请先修正配置或内容，不能原样反复提交。`,
          "error",
        );
      } else {
        showToast(
          `${error.message} 当前无法确认最终状态；请刷新提交记录，切勿盲目重复。`,
          "error",
        );
      }
    } finally {
      state.activeOperation = "";
      setBusy(els.confirmSubmitButton, false);
      if (state.activeDraft) renderSubmission();
    }
  }

  async function reconcileSubmissionAttempt(draftId, idempotencyKey) {
    if (!state.activeDraft || state.activeDraft.id !== draftId) return "unknown";
    await loadEvidence(true);
    const record = state.evidence.submissions.find(
      (item) => item && item.idempotency_key === idempotencyKey,
    );
    if (!record) return "unknown";
    if (record.status === "succeeded" && record.receipt) {
      const receipt = normalizeReceipt(record.receipt);
      if (!receipt || !receipt.receipt_id) return "unknown";
      state.activeDraft.receipt = receipt;
      state.activeDraft.status = "submitted";
      updateDraftSummary();
      renderAll();
      return "succeeded";
    }
    if (record.status === "pending") return "pending";
    if (record.status === "failed") {
      if (record.error && record.error.retryable === true) return "failed_retryable";
      if (record.error && record.error.retryable === false) return "failed_final";
      return "unknown";
    }
    return "unknown";
  }

  function renderReceipt() {
    const receipt = state.activeDraft.receipt || {};
    const rows = [
      ["平台回执号", receipt.receipt_id || "等待平台回执"],
      ["接收时间", formatDateTime(receipt.received_at)],
      ["接收方", receipt.platform || "辅助监察监管平台"],
      ["报送包摘要", receipt.payload_sha256 || "未返回"],
      ["平台状态", receipt.status || "received"],
    ];
    const fragment = document.createDocumentFragment();
    rows.forEach(([term, detail]) => {
      const row = document.createElement("div");
      row.append(el("dt", "", term), el("dd", "", detail));
      fragment.append(row);
    });
    els.receiptDetails.replaceChildren(fragment);
  }

  async function copyReceipt() {
    if (!state.activeDraft || !state.activeDraft.receipt) return;
    const sessionGeneration = state.sessionGeneration;
    const draftId = state.activeDraft.id;
    const receipt = state.activeDraft.receipt;
    const text = [
      `平台回执号：${receipt.receipt_id}`,
      `接收时间：${formatDateTime(receipt.received_at)}`,
      `接收方：${receipt.platform}`,
      `报送包摘要：${receipt.payload_sha256 || "未返回"}`,
      `状态：${receipt.status}`,
    ].join("\n");
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        throw new Error("clipboard unavailable");
      }
      await navigator.clipboard.writeText(text);
      if (
        sessionRequestIsStale(sessionGeneration) ||
        !state.activeDraft ||
        state.activeDraft.id !== draftId
      ) {
        return;
      }
      showToast("回执信息已复制。");
    } catch (error) {
      if (
        sessionRequestIsStale(sessionGeneration, error) ||
        !state.activeDraft ||
        state.activeDraft.id !== draftId
      ) {
        return;
      }
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.setAttribute("readonly", "");
      textarea.className = "sr-only";
      document.body.append(textarea);
      textarea.select();
      const copied =
        typeof document.execCommand === "function" &&
        document.execCommand("copy");
      textarea.remove();
      showToast(
        copied ? "回执信息已复制。" : "浏览器未允许复制，请使用“下载回执 JSON”。",
        copied ? "" : "error",
      );
    }
  }

  function downloadReceipt() {
    if (!state.activeDraft || !state.activeDraft.receipt) return;
    const receipt = state.activeDraft.receipt;
    const content =
      receipt.raw && typeof receipt.raw === "object"
        ? receipt.raw
        : {
            receipt_id: receipt.receipt_id,
            received_at: receipt.received_at,
            platform: receipt.platform,
            payload_sha256: receipt.payload_sha256,
            status: receipt.status,
            message: receipt.message,
          };
    const safeId = String(receipt.receipt_id || state.activeDraft.id)
      .replace(/[^A-Za-z0-9._-]/g, "_")
      .slice(0, 80);
    downloadTextFile(
      `监管平台回执-${safeId}.json`,
      `${JSON.stringify(content, null, 2)}\n`,
      "application/json;charset=utf-8",
    );
    showToast("回执 JSON 已下载。");
  }

  async function loadEvidence(force = false) {
    const draft = state.activeDraft;
    if (!draft || !hasPermission("read")) return;
    const sessionGeneration = state.sessionGeneration;
    if (
      !force &&
      state.evidence.draftId === draft.id &&
      !state.evidence.error
    ) {
      renderEvidence();
      return;
    }
    const draftId = draft.id;
    state.evidence = {
      draftId,
      loading: true,
      submissions: [],
      auditEvents: [],
      auditIntegrity: null,
      error: "",
    };
    renderEvidence();
    const [submissionResult, auditResult] = await Promise.allSettled([
      api(endpoints.submissions(draftId)),
      api(endpoints.audit(draftId)),
    ]);
    if (sessionRequestIsStale(sessionGeneration)) return;
    if (!state.activeDraft || state.activeDraft.id !== draftId) return;
    const errors = [];
    if (submissionResult.status === "fulfilled") {
      const payload = submissionResult.value;
      state.evidence.submissions = Array.isArray(payload)
        ? payload
        : (payload && (payload.submissions || payload.items)) || [];
    } else {
      errors.push(`提交记录：${submissionResult.reason.message}`);
    }
    if (auditResult.status === "fulfilled") {
      const payload = auditResult.value || {};
      state.evidence.auditEvents = Array.isArray(payload.events) ? payload.events : [];
      state.evidence.auditIntegrity = payload.integrity || null;
    } else {
      errors.push(`审计记录：${auditResult.reason.message}`);
    }
    state.evidence.loading = false;
    state.evidence.error = errors.join("；");
    renderEvidence();
  }

  function renderEvidence() {
    if (!state.activeDraft || state.evidence.draftId !== state.activeDraft.id) {
      els.submissionHistory.replaceChildren(
        el("p", "draft-empty", "进入本步骤后加载。"),
      );
      els.auditHistory.replaceChildren(
        el("p", "draft-empty", "进入本步骤后加载。"),
      );
      return;
    }
    if (state.evidence.loading) {
      els.submissionHistory.replaceChildren(
        el("p", "draft-empty", "正在读取提交记录…"),
      );
      els.auditHistory.replaceChildren(
        el("p", "draft-empty", "正在校验审计链…"),
      );
      return;
    }
    const submissionFragment = document.createDocumentFragment();
    if (!state.evidence.submissions.length) {
      submissionFragment.append(el("p", "draft-empty", "尚无提交尝试。"));
    }
    state.evidence.submissions.forEach((record) => {
      const item = el("div", "evidence-item");
      const status = String(record.status || "unknown");
      item.append(
        el("strong", "", submissionStatusLabel(record)),
        el(
          "span",
          "",
          `时间：${formatDateTime(record.updated_at || record.created_at)}`,
        ),
      );
      if (record.request_sha256) {
        item.append(
          el("small", "", `报送包摘要：${shortDigest(record.request_sha256)}`),
        );
      }
      const error = record.error && typeof record.error === "object" ? record.error : {};
      const errorMessage =
        error.message || error.detail || record.error_code || "";
      if (errorMessage) {
        item.append(
          el("small", "text-warning", `失败原因：${String(errorMessage).slice(0, 300)}`),
        );
      }
      const violations = Array.isArray(error.violations)
        ? error.violations.slice(0, 8)
        : [];
      if (violations.length) {
        const list = el("ul", "submission-violations");
        violations.forEach((violation) => {
          const pointer = String(violation.json_pointer || violation.pointer || "");
          const field = friendlyViolationPath(pointer);
          const message = String(violation.message || "未提供原因").slice(0, 500);
          list.append(el("li", "", `${field}（${pointer || "路径未知"}）：${message}`));
        });
        item.append(list);
      }
      if (status === "failed") {
        item.append(
          el(
            "small",
            error.retryable === true ? "text-warning" : "",
            error.retryable === true
              ? "网络或平台故障：修复后可复用原幂等键安全重试。"
              : error.retryable === false
                ? "内容或治理问题：请先修正配置/数据，再按新确认版本处理。"
                : "失败性质尚未明确：请联系管理员核查，勿盲目重复。",
          ),
        );
      }
      submissionFragment.append(item);
    });
    if (state.evidence.error) {
      submissionFragment.prepend(
        el("p", "form-error", state.evidence.error),
      );
    }
    els.submissionHistory.replaceChildren(submissionFragment);

    const auditFragment = document.createDocumentFragment();
    const integrity = state.evidence.auditIntegrity;
    if (integrity) {
      const valid = integrity.valid === true;
      auditFragment.append(
        el(
          "div",
          `evidence-integrity ${valid ? "is-valid" : "is-invalid"}`,
          valid
            ? `审计链完整（${Number(integrity.event_count || 0)} 条）`
            : `审计链校验失败（序号 ${integrity.failed_sequence || "未知"}）`,
        ),
      );
    }
    const events = state.evidence.auditEvents.slice(-10).reverse();
    if (!events.length) {
      auditFragment.append(el("p", "draft-empty", "尚无审计事件。"));
    }
    events.forEach((event) => {
      const item = el("div", "evidence-item");
      item.append(
        el("strong", "", auditEventLabel(event.event_type)),
        el(
          "span",
          "",
          `${formatDateTime(event.occurred_at)} · 操作人 ${event.actor || "系统"}`,
        ),
        el(
          "small",
          "",
          `事件摘要：${shortDigest(event.event_hash || "未返回")}`,
        ),
      );
      auditFragment.append(item);
    });
    els.auditHistory.replaceChildren(auditFragment);
  }

  function submissionStatusLabel(record) {
    const status = String((record && record.status) || "unknown");
    if (status === "pending") return "提交处理中（请勿重复发起）";
    if (status === "succeeded") return "提交成功";
    if (status === "failed") {
      if (record.error && record.error.retryable === true) {
        return "提交失败（可用原幂等键重试）";
      }
      if (record.error && record.error.retryable === false) {
        return "提交未通过（需修正后处理）";
      }
      return "提交失败（需先核查原因）";
    }
    return `提交状态：${status}`;
  }

  function friendlyViolationPath(pointer) {
    const path = String(pointer || "");
    if (path.includes("/human_confirmation/")) return "企业确认身份";
    if (path.includes("/operational_context/")) return "生产运行上下文";
    const observation = /\/observations\/(\d+)\/([^/]+)$/.exec(path);
    if (observation) {
      const fields = {
        metric_code: "指标编码",
        value: "数值",
        unit: "单位",
        payload_sha256: "来源摘要",
        signature: "来源签名",
      };
      return `第 ${Number(observation[1]) + 1} 条观测${
        fields[observation[2]] ? ` · ${fields[observation[2]]}` : ""
      }`;
    }
    if (path.endsWith("/mine_id")) return "矿井/单位编码";
    if (path.endsWith("/window_start")) return "统计开始时间";
    if (path.endsWith("/window_end")) return "统计结束时间";
    return "报送字段";
  }

  function auditEventLabel(eventType) {
    const labels = {
      draft_created: "创建草稿",
      draft_updated: "修改草稿",
      source_imported: "导入来源",
      regulator_event_snapshot_imported: "导入监管事件快照",
      llm_assistance_recorded: "记录智能建议",
      observations_reviewed: "逐项核对",
      observation_reviewed: "逐项核对",
      observation_reviews_revoked: "核对因数据变化失效",
      observation_review_revoked: "核对因数据变化失效",
      human_confirmed: "人工确认",
      draft_confirmed: "人工确认",
      submission_started: "开始提交",
      submission_retry_started: "安全重试提交",
      submission_succeeded: "取得平台回执",
      submission_failed: "提交失败",
      draft_deleted: "从工作列表移除草稿",
    };
    return labels[eventType] || String(eventType || "审计事件");
  }

  function renderStepper() {
    document.querySelectorAll("#stepList li").forEach((item, index) => {
      const step = index + 1;
      item.classList.toggle("is-current", step === state.step);
      item.classList.toggle("is-complete", isStepComplete(step));
      const button = item.querySelector("button");
      button.setAttribute("aria-current", step === state.step ? "step" : "false");
    });
    document.querySelectorAll(".step-panel").forEach((panel) => {
      panel.hidden = Number(panel.dataset.panel) !== state.step;
    });
    els.previousStepButton.disabled = state.step <= 1;
    els.nextStepButton.hidden = state.step >= 6;
    els.nextStepButton.textContent =
      state.step === 5 ? "进入提交与回执" : "保存并进入下一步";
    els.stepHint.textContent = stepHint(state.step);
    renderSimpleTaskGuide();
  }

  function renderSimpleTaskGuide() {
    if (!els.simpleTaskCard) return;
    const draft = state.activeDraft;
    els.simpleTaskCard.hidden = !draft;
    if (!draft) return;

    const targetStep = suggestedStep(draft);
    const completedSteps = [1, 2, 3, 4, 5, 6].filter((step) =>
      isStepComplete(step),
    ).length;
    const unreviewed = draft.measurements.filter((row) => !row.confirmed).length;
    const unresolvedQuestions = draft.questions.filter(
      (row) => row.required && !questionIsResolved(row),
    ).length;
    const blockers = draft.preflight
      ? Math.max(0, Number(draft.preflight.blockers) || 0)
      : 0;
    const submitted = draft.status === "submitted";
    const plans = {
      1: {
        title: "填写企业和统计信息",
        description: hasRegulatorEventSnapshot(draft)
          ? "填写带“必填”标记的企业、时段和实际工况，系统会自动保存。"
          : "填写必填信息，并导入监管事件快照；即使没有特殊事件也必须导入空结果快照。",
        action: "开始填写基本信息",
      },
      2: {
        title: "导入真实业务材料",
        description: "选择系统导出的 JSON、CSV，或在已配置智能辅助时粘贴文字。",
        action: "去导入业务材料",
      },
      3: {
        title: "核对数字并处理缺项",
        description:
          unreviewed || unresolvedQuestions
            ? `还有 ${unreviewed} 个数字和 ${unresolvedQuestions} 个必答缺项需要处理。`
            : "检查每个数字的来源，并回答系统标出的必答缺项。",
        action: "继续核对",
      },
      4: {
        title: "运行提交前检查",
        description: blockers
          ? `当前仍有 ${blockers} 个阻断问题；重新检查后按提示修正。`
          : "系统会检查完整性、来源和逻辑关系，不会替您作真实性确认。",
        action: "运行提交前检查",
      },
      5: {
        title: "由有权账号确认",
        description: "确认人核对汇总内容并作真实性声明；该动作会写入审计记录。",
        action: "去完成企业确认",
      },
      6: {
        title: submitted ? "本次填报已经完成" : "提交并保存平台回执",
        description: submitted
          ? "平台回执和完整操作留痕已经保存，可随时查看或下载。"
          : "最后检查提交条件，明确确认后发送监管平台并保存回执。",
        action: submitted ? "查看回执" : "进入提交页面",
      },
    };
    const canWrite = hasPermission("write");
    const canConfirm = canFinalizeWith("confirm");
    const canSubmit = canFinalizeWith("submit");
    const actionAllowed =
      submitted ||
      (targetStep <= 2 && canWrite) ||
      (targetStep === 3 && (canWrite || canConfirm)) ||
      (targetStep === 4 && canWrite) ||
      (targetStep === 5 && canConfirm) ||
      (targetStep === 6 && canSubmit);
    const waitingPlans = {
      1: {
        title: "等待经办人补充基本信息",
        description: "当前账号不能编辑草稿；请查看缺项并转交具有编辑权限的经办人。",
      },
      2: {
        title: "等待经办人导入业务材料",
        description: "当前账号不能导入来源；请转交具有编辑权限的经办人继续。",
      },
      3: {
        title: "等待有权人员完成核对",
        description: "当前账号不能修改缺项或确认数字；可以查看草稿当前状态。",
      },
      4: {
        title: "等待经办人运行提交前检查",
        description: "当前账号不能写入预检结果；请转交具有编辑权限的经办人。",
      },
      5: {
        title: "等待确认人完成企业确认",
        description: "只有具有确认权限且凭据有效的企业账号才能执行该动作。",
      },
      6: {
        title: "等待提交人发送监管平台",
        description: "只有具有提交权限且凭据有效的企业账号才能执行最终提交。",
      },
    };
    const plan = actionAllowed
      ? plans[targetStep]
      : {
          ...waitingPlans[targetStep],
          action: "查看当前状态",
        };
    els.simpleTaskStep.textContent = submitted
      ? "已完成"
      : `第 ${targetStep} 步，共 6 步`;
    els.simpleTaskTitle.textContent = plan.title;
    els.simpleTaskDescription.textContent = plan.description;
    els.simpleTaskButton.textContent = plan.action;
    els.simpleTaskButton.dataset.targetStep = String(targetStep);
    els.simpleTaskButton.dataset.actionAllowed = String(actionAllowed);
    els.simpleTaskButton.className = actionAllowed
      ? "button button-primary button-large"
      : "button button-secondary button-large";
    els.simpleTaskCard.classList.toggle("is-readonly", !actionAllowed);
    els.simpleDeleteDraftButton.hidden = draft.status !== "draft";
    els.simpleDeleteDraftButton.disabled =
      draft.status !== "draft" || !canWrite;
    els.simpleDeleteDraftButton.title =
      draft.status !== "draft"
        ? "已经人工确认或提交的记录不能移除"
        : canWrite
          ? "从普通工作列表移除，数据库和审计记录仍会保留"
          : "当前账号没有移除草稿所需的 write 权限";
    els.simpleTaskProgressText.textContent = `已完成 ${completedSteps}/6 步`;
    els.simpleTaskProgressFill.style.width =
      `${Math.round((completedSteps / 6) * 100)}%`;
    const meta = [
      `来源 ${draft.sources.length} 份`,
      `待核对 ${unreviewed} 项`,
      `必答缺项 ${unresolvedQuestions} 项`,
      hasRegulatorEventSnapshot(draft) ? "事件快照已导入" : "事件快照待导入",
    ];
    if (draft.preflight) meta.push(`预检阻断 ${blockers} 项`);
    els.simpleTaskMeta.textContent = meta.join(" · ");
  }

  async function handleSimpleTaskAction() {
    if (!state.activeDraft) {
      if (hasPermission("read") && hasPermission("write")) {
        await createDraft();
      } else {
        showToast("当前账号不能新建填报，请查看账号操作说明。", "error");
      }
      return;
    }
    const targetStep = Number(els.simpleTaskButton.dataset.targetStep) || 1;
    goToStep(targetStep);
    if (els.simpleTaskButton.dataset.actionAllowed !== "true") {
      showToast("当前账号仅可查看这一步，请按提示转交有权人员。");
      return;
    }
    if (targetStep === 4 && state.activeDraft.status !== "submitted") {
      await runValidation();
      return;
    }
    const focusTargets = {
      1: () =>
        Array.from(els.draftForm.querySelectorAll('[data-panel="1"] [required]')).find(
          (field) => !String(field.value || "").trim(),
        ) || (!hasRegulatorEventSnapshot(state.activeDraft) ? els.addEventButton : null),
      2: () => els.chooseFileButton,
      3: () =>
        els.measurementBody.querySelector(
          "tr.needs-review input[type='checkbox']:not(:disabled)",
        ) ||
        els.questionList.querySelector("input:not(:disabled), textarea:not(:disabled)") ||
        els.runAssistButton,
      5: () =>
        els.draftForm.elements.namedItem("signature.statement_accepted") ||
        els.confirmDraftButton,
      6: () =>
        state.activeDraft.status === "submitted"
          ? els.copyReceiptButton
          : els.submitButton,
    };
    const target = focusTargets[targetStep] ? focusTargets[targetStep]() : null;
    if (target && typeof target.focus === "function") target.focus();
  }

  function isStepComplete(step) {
    const draft = state.activeDraft;
    if (!draft) return false;
    if (step === 1) {
      const context = draft.operational_context;
      return Boolean(
        draft.enterprise.name &&
        draft.enterprise.id &&
        draft.enterprise.credit_code &&
        draft.enterprise.mine_code &&
        draft.enterprise.mine_name &&
        draft.profile.id &&
        draft.profile.version &&
        draft.period.start &&
        draft.period.end &&
        context.regime_code &&
        context.shift_code &&
        context.season_code &&
        context.maintenance !== null &&
        hasRegulatorEventSnapshot(draft),
      );
    }
    if (step === 2) return draft.sources.length > 0;
    if (step === 3) {
      return (
        draft.measurements.length > 0 &&
        draft.measurements.every((row) => row.confirmed) &&
        draft.questions.every((row) => !row.required || questionIsResolved(row))
      );
    }
    if (step === 4) return Boolean(draft.preflight && draft.preflight.blockers === 0);
    if (step === 5) return Boolean(draft.signature.valid);
    return draft.status === "submitted";
  }

  function stepHint(step) {
    const hints = {
      1: "请完善企业、时段、实际工况并导入监管事件快照",
      2: "导入真实业务记录并注明来源",
      3: "逐项查看来源并人工确认",
      4: "预检不会代替监管审核",
      5: "由有权确认人完成真实性声明",
      6: "提交成功后请保存平台回执",
    };
    return hints[step] || "";
  }

  function suggestedStep(draft) {
    if (!isBasicDraftComplete(draft)) return 1;
    if (!draft.sources.length) return 2;
    if (
      !draft.measurements.length ||
      draft.measurements.some((row) => !row.confirmed) ||
      draft.questions.some((row) => row.required && !questionIsResolved(row))
    ) {
      return 3;
    }
    if (!draft.preflight || draft.preflight.blockers) return 4;
    if (!draft.signature.valid) return 5;
    return 6;
  }

  function isBasicDraftComplete(draft) {
    const context = draft.operational_context;
    return Boolean(
      draft.enterprise.name &&
      draft.enterprise.id &&
      draft.enterprise.credit_code &&
      draft.enterprise.mine_code &&
      draft.enterprise.mine_name &&
      draft.profile.id &&
      draft.profile.version &&
      draft.period.start &&
      draft.period.end &&
      context.regime_code &&
      context.shift_code &&
      context.season_code &&
      context.maintenance !== null &&
      hasRegulatorEventSnapshot(draft),
    );
  }

  async function advanceStep() {
    if (!state.activeDraft) return;
    applyAllFormFields();
    if (state.step === 1) {
      const errors = validateBasicStep();
      if (errors.length) {
        showToast(errors[0], "error");
        if (!hasRegulatorEventSnapshot(state.activeDraft)) {
          els.addEventButton.focus();
        } else {
          focusFirstInvalid();
        }
        return;
      }
    }
    if (state.step === 2 && !state.activeDraft.sources.length) {
      showToast("请先导入至少一份真实来源材料。", "error");
      return;
    }
    if (
      state.step === 3 &&
      (!state.activeDraft.measurements.length ||
        state.activeDraft.measurements.some((row) => !row.confirmed) ||
        state.activeDraft.questions.some(
          (row) => row.required && !questionIsResolved(row),
        ))
    ) {
      showToast("请先逐项核对数字并完成必答追问。", "error");
      return;
    }
    if (
      state.step === 4 &&
      (!state.activeDraft.preflight || state.activeDraft.preflight.blockers > 0)
    ) {
      showToast("请先完成无阻断问题的预检。", "error");
      return;
    }
    if (state.step === 5 && !state.activeDraft.signature.valid) {
      showToast("请先完成企业账号人工确认。", "error");
      return;
    }
    try {
      await flushSave();
    } catch {
      showToast("草稿尚未保存，已停留在当前步骤。请重试保存。", "error");
      return;
    }
    goToStep(state.step + 1);
  }

  function validateBasicStep() {
    const draft = state.activeDraft;
    const errors = [];
    const required = [
      [draft.enterprise.name, "请填写企业名称。"],
      [draft.enterprise.id, "请填写企业编号。"],
      [draft.enterprise.credit_code, "请填写统一社会信用代码。"],
      [draft.enterprise.mine_code, "请填写矿井/单位编码。"],
      [draft.enterprise.mine_name, "请填写矿井/单位名称。"],
      [draft.profile.id, "请填写分析配置编号。"],
      [draft.profile.version, "请填写分析配置版本。"],
      [draft.period.start, "请填写统计开始时间。"],
      [draft.period.end, "请填写统计结束时间。"],
      [draft.operational_context.regime_code, "请选择生产工况。"],
      [draft.operational_context.shift_code, "请选择班次。"],
      [draft.operational_context.season_code, "请选择季节/气候期。"],
      [
        draft.operational_context.maintenance !== null,
        "请选择是否处于检修状态。",
      ],
      [
        hasRegulatorEventSnapshot(draft),
        "请导入监管事件快照；即使没有特殊事件也必须导入空结果快照。",
      ],
    ];
    required.forEach(([value, message]) => {
      if (!value) errors.push(message);
    });
    if (
      draft.enterprise.credit_code &&
      !/^[0-9A-HJ-NPQRTUWXY]{18}$/.test(
        draft.enterprise.credit_code.trim().toUpperCase(),
      )
    ) {
      errors.push("统一社会信用代码必须是 18 位规范代码。");
    }
    if (
      (draft.period.start && Number.isNaN(new Date(draft.period.start).getTime())) ||
      (draft.period.end && Number.isNaN(new Date(draft.period.end).getTime()))
    ) {
      errors.push("统计时间格式无效，请重新选择。");
    }
    if (
      draft.period.start &&
      draft.period.end &&
      new Date(draft.period.start) >= new Date(draft.period.end)
    ) {
      errors.push("统计结束时间必须晚于开始时间。");
    }
    return errors;
  }

  function focusFirstInvalid() {
    const required = Array.from(els.draftForm.querySelectorAll("[required]"));
    const first = required.find((field) => !field.checkValidity());
    if (!first) return;
    const details = first.closest("details");
    if (details) details.open = true;
    first.focus();
    if (typeof first.reportValidity === "function") first.reportValidity();
  }

  function goToStep(step) {
    state.step = Math.max(1, Math.min(6, Number(step) || 1));
    renderStepper();
    if (state.step === 5) renderConfirmation();
    if (state.step === 6) {
      renderSubmission();
      void loadEvidence();
    }
    els.workspace.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function applyAllFormFields() {
    if (!state.activeDraft) return;
    [
      "enterprise.name",
      "enterprise.id",
      "enterprise.credit_code",
      "enterprise.mine_code",
      "enterprise.mine_name",
      "period.start",
      "period.end",
      "profile.id",
      "profile.version",
      "operational_context.regime_code",
      "operational_context.shift_code",
      "operational_context.season_code",
      "operational_context.maintenance",
      "signature.statement_accepted",
    ].forEach((name) => {
      const field = els.draftForm.elements.namedItem(name);
      if (field) applyNamedField(field);
    });
  }

  function scheduleSave() {
    if (!state.activeDraft || state.activeDraft.status === "submitted") return;
    clearTimeout(state.saveTimer);
    els.saveState.textContent = "有未保存修改";
    els.saveState.className = "save-state is-saving";
    els.retrySaveButton.hidden = true;
    state.saveTimer = window.setTimeout(() => {
      state.saveTimer = null;
      void saveDraft().catch(() => {
        // saveDraft renders a persistent retry affordance and error message.
      });
    }, 700);
  }

  async function flushSave() {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
    while (
      state.activeDraft &&
      state.activeDraft.status !== "submitted" &&
      (state.savePromise || state.dirtyWireFields.size)
    ) {
      if (state.savePromise) await state.savePromise;
      else await saveDraft();
    }
  }

  async function saveDraft() {
    if (!state.activeDraft || state.activeDraft.status === "submitted") return;
    if (state.savePromise) {
      await state.savePromise;
      return;
    }
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
    if (!state.dirtyWireFields.size) {
      els.saveState.textContent = "已保存";
      els.saveState.className = "save-state";
      els.retrySaveButton.hidden = true;
      return;
    }
    const operation = saveDraftOnce();
    state.savePromise = operation;
    try {
      await operation;
    } finally {
      if (state.savePromise === operation) state.savePromise = null;
    }
  }

  async function saveDraftOnce() {
    els.saveState.textContent = "保存中…";
    els.saveState.className = "save-state is-saving";
    const draftAtStart = state.activeDraft;
    const savingFields = new Set(state.dirtyWireFields);
    savingFields.forEach((field) => state.dirtyWireFields.delete(field));
    try {
      const payload = await api(endpoints.draft(draftAtStart.id), {
        method: "PATCH",
        body: toDraftPayload(draftAtStart, savingFields),
      });
      if (state.activeDraft !== draftAtStart) return;
      const responseDraft = unwrapDraft(payload);
      if (responseDraft && typeof responseDraft === "object") {
        const responseMeta = responseDraft._meta || {};
        const confirmation =
          responseMeta.confirmation ||
          responseDraft.confirmation ||
          responseDraft.signature ||
          {};
        const serverConfirmed = Boolean(responseMeta.confirmed);
        draftAtStart.revision = firstDefined(
          responseDraft.revision,
          responseDraft.version,
          responseDraft._meta && responseDraft._meta.revision,
          draftAtStart.revision,
        );
        draftAtStart.updated_at =
          responseDraft.updated_at ||
          (responseDraft._meta && responseDraft._meta.updated_at) ||
          new Date().toISOString();
        // Confirmation, submission and receipt are authoritative server
        // states. A local undo snapshot must never resurrect an invalidated
        // confirmation or make a draft appear submit-ready.
        draftAtStart.status = normalizeStatus(
          responseDraft.status || (serverConfirmed ? "confirmed" : "draft"),
        );
        draftAtStart.signature = {
          signer_name: String(
            confirmation.confirmer_name ||
              confirmation.signer_name ||
              "",
          ),
          signer_title: String(
            confirmation.confirmer_role ||
              confirmation.signer_title ||
              "",
          ),
          method: String(
            confirmation.confirmation_method ||
              confirmation.method ||
              "authenticated_click",
          ),
          statement_accepted: serverConfirmed,
          signed_at:
            (serverConfirmed &&
              (confirmation.confirmed_at || confirmation.signed_at)) ||
            "",
          valid: serverConfirmed,
        };
        draftAtStart.receipt = normalizeReceipt(responseDraft.receipt);
      }
      if (
        payload &&
        Object.prototype.hasOwnProperty.call(payload, "review_state") &&
        !state.dirtyWireFields.has("observations")
      ) {
        applyReviewState(payload.review_state);
      }
      const moreChanges = state.dirtyWireFields.size > 0;
      els.saveState.textContent = moreChanges ? "有未保存修改" : "已保存";
      els.saveState.className = moreChanges ? "save-state is-saving" : "save-state";
      if (moreChanges && state.saveTimer === null) {
        state.saveTimer = window.setTimeout(() => {
          state.saveTimer = null;
          void saveDraft().catch(() => {
            // The failed state remains visible with an explicit retry button.
          });
        }, 700);
      }
      els.retrySaveButton.hidden = true;
      updateDraftSummary();
      renderDraftHeader();
      renderDraftList();
      renderMeasurements();
      renderConfirmation();
      renderSubmission();
    } catch (error) {
      savingFields.forEach((field) => state.dirtyWireFields.add(field));
      els.saveState.textContent = "保存失败";
      els.saveState.className = "save-state is-error";
      els.retrySaveButton.hidden = false;
      els.retrySaveButton.textContent =
        error.status === 409 ? "草稿有冲突" : "重试保存";
      els.retrySaveButton.title =
        error.status === 409
          ? "草稿已被另一页面修改。请先复制当前未保存内容，再刷新页面人工核对。"
          : "重新发送当前未保存修改";
      showToast(`草稿未保存：${error.message}`, "error");
      throw error;
    }
  }

  async function retrySave() {
    if (!state.dirtyWireFields.size) {
      els.retrySaveButton.hidden = true;
      return;
    }
    try {
      await flushSave();
      showToast("草稿已保存。");
    } catch (error) {
      if (error.status === 409) {
        showToast(
          "检测到并发修改，未自动覆盖他人内容。请复制当前值后刷新，再人工合并。",
          "error",
        );
      }
    }
  }

  function markDraftChanged() {
    if (!state.activeDraft) return;
    state.activeDraft.updated_at = new Date().toISOString();
    updateDraftSummary();
    renderDraftHeader();
    renderStepper();
  }

  function updateDraftSummary() {
    if (!state.activeDraft) return;
    const summary = normalizeDraftSummary(state.activeDraft);
    const index = state.drafts.findIndex((row) => row.id === summary.id);
    if (index >= 0) state.drafts.splice(index, 1, summary);
    else state.drafts.unshift(summary);
  }

  function fieldUndoEntry(name) {
    if (!state.activeDraft || !name) return null;
    return {
      kind: "field",
      name: String(name),
      value: clone(getPath(state.activeDraft, name)),
    };
  }

  function measurementUndoEntry(index) {
    if (!state.activeDraft || !state.activeDraft.measurements[index]) return null;
    return {
      kind: "measurement",
      index,
      value: clone(state.activeDraft.measurements[index]),
      previousLength: state.activeDraft.measurements.length,
    };
  }

  function questionUndoEntry(index) {
    if (!state.activeDraft || !state.activeDraft.questions[index]) return null;
    return {
      kind: "question",
      index,
      value: clone(state.activeDraft.questions[index]),
    };
  }

  function pushUndo(entry) {
    if (
      !entry ||
      !state.activeDraft ||
      state.activeDraft.status === "submitted"
    ) {
      return false;
    }
    const wrapped = {
      ...entry,
      draftId: state.activeDraft.id,
    };
    const bytes = JSON.stringify(wrapped).length * 2;
    if (bytes > 256 * 1024) return false;
    wrapped.undoBytes = bytes;
    state.undoStack.push(wrapped);
    state.undoBytes += bytes;
    while (
      state.undoStack.length > 50 ||
      state.undoBytes > 512 * 1024
    ) {
      const removed = state.undoStack.shift();
      state.undoBytes -= Number((removed && removed.undoBytes) || 0);
    }
    els.undoButton.disabled = false;
    return true;
  }

  async function undoLastChange() {
    if (!state.undoStack.length || !state.activeDraft) return;
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    state.activeOperation = "撤销修改";
    setBusy(els.undoButton, true, "撤销中…");
    try {
      await flushSave();
      const entry = state.undoStack[state.undoStack.length - 1];
      if (!entry || entry.draftId !== state.activeDraft.id) {
        throw new Error("撤销记录不属于当前草稿，已停止操作。");
      }
      state.undoStack.pop();
      state.undoBytes -= Number(entry.undoBytes || 0);
      if (!applyUndoEntry(entry)) {
        throw new Error("该修改已无法安全撤销。");
      }
      invalidatePreflightAndSignature();
      markDraftChanged();
      renderAll();
      els.saveState.textContent = "有未保存修改";
      els.saveState.className = "save-state is-saving";
      await flushSave();
      showToast("已撤销最近一次修改。");
    } catch (error) {
      showToast(`撤销未完成：${error.message}`, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.undoButton, false);
      els.undoButton.disabled = state.undoStack.length === 0;
      if (state.activeDraft) lockSubmittedDraft();
    }
  }

  function applyUndoEntry(entry) {
    if (!state.activeDraft) return false;
    if (entry.kind === "field" && entry.name) {
      setPath(state.activeDraft, entry.name, clone(entry.value));
      markWireFieldDirty(entry.name);
      return true;
    }
    if (entry.kind === "measurement") {
      if (entry.index < 0) return false;
      if (entry.index >= Number(entry.previousLength || 0)) {
        state.activeDraft.measurements.splice(Number(entry.previousLength || 0));
      } else {
        state.activeDraft.measurements[entry.index] = clone(entry.value);
      }
      state.dirtyWireFields.add("observations");
      return true;
    }
    if (entry.kind === "insert_measurement") {
      state.activeDraft.measurements.splice(entry.index, 0, clone(entry.value));
      state.dirtyWireFields.add("observations");
      return true;
    }
    if (entry.kind === "question" && state.activeDraft.questions[entry.index]) {
      state.activeDraft.questions[entry.index] = clone(entry.value);
      return true;
    }
    return false;
  }

  function openDeleteDialog() {
    if (
      !state.activeDraft ||
      state.activeDraft.status !== "draft" ||
      !hasPermission("write")
    ) {
      showToast("只有尚未人工确认的草稿才能移除。", "error");
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    els.deleteConfirmation.value = "";
    els.confirmDeleteButton.disabled = true;
    els.deleteDialog.showModal();
  }

  async function deleteDraft() {
    const draft = state.activeDraft;
    if (
      !draft ||
      draft.status !== "draft" ||
      els.deleteConfirmation.value.trim() !== "移除"
    ) {
      return;
    }
    if (state.activeOperation) {
      showToast(`正在${state.activeOperation}，请稍候。`, "error");
      return;
    }
    state.activeOperation = "移除草稿";
    setBusy(els.confirmDeleteButton, true, "正在移除…");
    try {
      clearTimeout(state.saveTimer);
      state.saveTimer = null;
      await flushSave();
      if (!state.activeDraft || state.activeDraft.id !== draft.id) {
        throw new Error("当前草稿已切换，已停止移除。");
      }
      await api(endpoints.draft(draft.id), {
        method: "DELETE",
        body: { expected_revision: state.activeDraft.revision },
      });
      clearTimeout(state.saveTimer);
      state.saveTimer = null;
      state.dirtyWireFields.clear();
      const wasLoaded = state.drafts.some((row) => row.id === draft.id);
      state.drafts = state.drafts.filter((row) => row.id !== draft.id);
      state.draftTotal = Math.max(0, state.draftTotal - 1);
      if (wasLoaded && state.draftHasMore) {
        // Offset pagination is relative to the current server list. Removing
        // one already-loaded row shifts the first unseen row back by one;
        // keeping the old offset would silently skip that row.
        state.draftNextOffset = Math.max(0, state.draftNextOffset - 1);
      }
      state.activeDraft = null;
      state.undoStack = [];
      state.undoBytes = 0;
      els.deleteDialog.close();
      els.editor.hidden = true;
      els.welcomeCard.hidden = false;
      renderDraftList();
      renderAgentV2();
      renderCoalChatControls();
      showToast("草稿已从工作列表移除；审计留痕仍保留。");
    } catch (error) {
      showToast(error.message, "error");
    } finally {
      state.activeOperation = "";
      setBusy(els.confirmDeleteButton, false);
    }
  }

  function lockSubmittedDraft() {
    const submitted = state.activeDraft.status === "submitted";
    els.draftForm.querySelectorAll("input, select, textarea").forEach((control) => {
      const confirmationControl = control.closest(".step-panel[data-panel='5']");
      if (confirmationControl) {
        control.disabled =
          submitted ||
          state.activeDraft.signature.valid ||
          !canFinalizeWith("confirm");
      } else if (!control.closest(".step-panel[data-panel='6']")) {
        control.disabled = submitted || !hasPermission("write");
      }
    });
    els.addEventButton.disabled = submitted || !hasPermission("write");
    els.importButton.disabled = submitted || !hasPermission("write");
    els.runAssistButton.disabled = submitted || !hasPermission("write");
    els.validateButton.disabled = submitted || !hasPermission("read");
    els.confirmDraftButton.disabled =
      submitted ||
      !canConfirmDraft(state.activeDraft) ||
      !canFinalizeWith("confirm");
    els.deleteDraftButton.disabled =
      state.activeDraft.status !== "draft" || !hasPermission("write");
    els.simpleDeleteDraftButton.disabled =
      state.activeDraft.status !== "draft" || !hasPermission("write");
    els.simpleDeleteDraftButton.hidden = state.activeDraft.status !== "draft";
  }

  function openDialogById(dialogId) {
    const dialog = document.getElementById(dialogId);
    if (dialog && typeof dialog.showModal === "function") dialog.showModal();
  }

  function closeDialog(dialogId) {
    const dialog = document.getElementById(dialogId);
    if (dialog && dialog.open) dialog.close();
  }

  function showToast(message, kind = "") {
    const text = String(message);
    if (text.includes("会话已变化，旧请求结果已忽略")) return;
    const toast = el("div", `toast ${kind}`.trim(), text);
    toast.setAttribute("role", kind === "error" ? "alert" : "status");
    els.toastRegion.append(toast);
    window.setTimeout(() => toast.remove(), 4600);
  }

  function setBusy(button, busy, busyText = "") {
    if (!button) return;
    if (busy) {
      if (!button.dataset.originalText) button.dataset.originalText = button.textContent;
      if (!Object.prototype.hasOwnProperty.call(button.dataset, "originalDisabled")) {
        button.dataset.originalDisabled = String(button.disabled);
      }
      button.textContent = busyText || "处理中…";
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    } else {
      if (button.dataset.originalText) {
        button.textContent = button.dataset.originalText;
        delete button.dataset.originalText;
      }
      button.disabled = button.dataset.originalDisabled === "true";
      delete button.dataset.originalDisabled;
      button.removeAttribute("aria-busy");
    }
  }

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
      const character = text[index];
      const next = text[index + 1];
      if (character === '"' && quoted && next === '"') {
        field += '"';
        index += 1;
      } else if (character === '"') {
        quoted = !quoted;
      } else if (character === "," && !quoted) {
        row.push(field);
        field = "";
      } else if ((character === "\n" || character === "\r") && !quoted) {
        if (character === "\r" && next === "\n") index += 1;
        row.push(field);
        if (row.some((cell) => cell.trim())) rows.push(row);
        row = [];
        field = "";
      } else {
        field += character;
      }
    }
    row.push(field);
    if (row.some((cell) => cell.trim())) rows.push(row);
    return rows;
  }

  function setPath(target, path, value) {
    const parts = path.split(".");
    let cursor = target;
    parts.slice(0, -1).forEach((part) => {
      if (!cursor[part] || typeof cursor[part] !== "object") cursor[part] = {};
      cursor = cursor[part];
    });
    cursor[parts[parts.length - 1]] = value;
  }

  function getPath(target, path) {
    return path.split(".").reduce((cursor, part) => {
      if (cursor === null || cursor === undefined) return undefined;
      return cursor[part];
    }, target);
  }

  function firstDefined(...values) {
    for (const value of values) {
      if (value !== null && value !== undefined) return value;
    }
    return undefined;
  }

  function clone(value) {
    if (typeof structuredClone === "function") return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
  }

  function el(tagName, className = "", text = null) {
    const node = document.createElement(tagName);
    if (className) node.className = className;
    if (text !== null && text !== undefined) node.textContent = String(text);
    return node;
  }

  function shortDigest(value) {
    const digest = String(value);
    return digest.length > 14 ? `${digest.slice(0, 8)}…${digest.slice(-5)}` : digest;
  }

  function toLocalDateTime(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value).slice(0, 16);
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }

  function toWireDateTime(value) {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toISOString();
  }

  function formatDateTime(value) {
    if (!value) return "未记录";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(date);
  }

  // Kept as a named export point for simple browser-level integration tests.
  window.EnterpriseReportingAgent = Object.freeze({
    API_ROOT,
    endpoints,
    parseCsv,
    normalizeConfidence,
  });

  void openDialogById;
})();
