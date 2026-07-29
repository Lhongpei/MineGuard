from __future__ import annotations

from html.parser import HTMLParser
import json
from pathlib import Path


WEB_ROOT = Path(__file__).resolve().parents[1] / "src" / "mineguard" / "web"


class FrontendAuditParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.asset_references: list[str] = []
        self.inline_handlers: list[str] = []
        self.inline_scripts = 0
        self.details_count = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        if identifier := attributes.get("id"):
            self.ids.append(identifier)
        if tag == "details":
            self.details_count += 1
        for name in ("src", "href"):
            reference = attributes.get(name)
            if reference:
                self.asset_references.append(reference)
        self.inline_handlers.extend(
            name for name in attributes if name.startswith("on")
        )
        if tag == "script" and not attributes.get("src"):
            self.inline_scripts += 1


def parse_frontend() -> tuple[str, FrontendAuditParser]:
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    parser = FrontendAuditParser()
    parser.feed(html)
    return html, parser


def test_frontend_is_self_contained_and_csp_friendly() -> None:
    _, parser = parse_frontend()

    assert parser.inline_scripts == 0
    assert parser.inline_handlers == []
    assert len(parser.ids) == len(set(parser.ids))
    assert all(
        reference.startswith(("/", "#"))
        for reference in parser.asset_references
    )


def test_leader_view_keeps_technical_detail_secondary() -> None:
    html, parser = parse_frontend()

    assert "技术线索不构成违法认定" in html
    assert "领导看结果只需三步" in html
    assert "查看专业分析依据" in html
    assert parser.details_count >= 3


def test_frontend_uses_safe_text_rendering_and_all_statuses() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "innerHTML" not in script
    assert "insertAdjacentHTML" not in script
    assert "value || 0" not in script
    for status in (
        'case "inconsistent"',
        'case "consistent"',
        'case "inconclusive"',
        "分析未完成",
    ):
        assert status in script
    assert "来源已明确上报零值" in script
    assert "不是处罚等级" in script


def test_safety_map_uses_optional_validated_boundary_without_overclaiming() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "/v1/map/boundary" in script
    assert "createElementNS" in script
    assert "边界来源、坐标系和点位精度仍须现场验收" in script
    assert "不是测绘底图或导航依据" in html
    assert "历史尾概率" in script
    assert "directional_tail_probability" in script


def test_personnel_identity_statuses_are_rendered_explicitly() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for status in (
        "identity_confirmed",
        "identity_conflict",
        "temporal_pair_only",
        "person_card_mismatch",
    ):
        assert status in script
    assert "身份确认匹配" in script
    assert "身份冲突，待复核" in script
    assert "仅时间关联，身份待确认" in script


def test_leader_workspaces_use_workflow_apis_and_keep_statuses_separate() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for workspace in ("辖区总览", "核查台账", "临时分析"):
        assert workspace in html
    assert "载入脱敏试点数据" in html
    assert "缺报不按零值处理" in html
    assert "优先级：先看谁" in html
    assert "技术状态：数据说明什么" in html
    assert "办理状态：事情办到哪一步" in html
    for endpoint in (
        "/v1/dashboard/overview",
        "/v1/analyze/production/batch",
        "/v1/cases",
        "/v1/analysis-runs/",
    ):
        assert endpoint in script
    assert "expected_version" in script
    assert "audit_chain_valid" in script


def test_leadership_simple_mode_is_default_and_keeps_professional_mode() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for identifier in (
        'id="interface-leader-mode"',
        'id="interface-professional-mode"',
        'id="leadership-workspace"',
        'id="decisions-workspace"',
        'id="reports-workspace"',
    ):
        assert identifier in html
    for label in (
        "领导简洁模式",
        "今日态势",
        "待我决策",
        "监管报告",
        "今天只看四件事",
        "今日需要关注的 3 件事",
    ):
        assert label in html
    assert 'interfaceMode: "leader"' in script
    assert 'setInterfaceMode("leader", false)' in script
    assert 'openProfessionalWorkspace("overview")' in script
    assert "refreshLeadershipDashboard" in script
    assert "renderLeadershipDecisions" in script
    assert "缺失不按零" in script


def test_leadership_summary_is_deterministic_and_does_not_persist_identity() -> None:
    _, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for source in (
        "state.overview",
        "state.analytics",
        "state.safetyDashboard",
        "state.cases",
    ):
        assert source in script
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "innerHTML",
        "insertAdjacentHTML",
    ):
        assert forbidden not in script
    assert "技术线索" in script
    assert "不证明辖区安全或合规" in script


def test_admin_can_govern_historical_verification_references() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "历史参考样本治理" in html
    assert "登记人与审批人必须不同" in script
    assert "/v1/admin/verification-references" in script
    for value in (
        "verification-reference-production-digest",
        "verification-reference-electricity-digest",
        "verification-reference-explosives-digest",
        "expected_sample_sha256",
        "registry_integrity_valid",
        "audit_chain_valid",
        "approve",
        "reject",
    ):
        assert value in html or value in script
    assert "生产核验只使用正文完全匹配" in html
    assert "当前登记账号不能自批" in script


def test_pilot_overview_is_an_explicit_non_persistent_preview() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    pilot_loader = script.split(
        "async function loadPilotOverview()", maxsplit=1
    )[1].split("function buildPilotBatchPayload()", maxsplit=1)[0]

    assert "batchProduction}?preview=1" in pilot_loader
    assert "脱敏试点预览 · 不保存" in pilot_loader
    assert "未保存批次，不生成案件、算法特征或正式趋势" in pilot_loader
    assert "SUPERVISION_API_PATHS.overview" not in pilot_loader
    assert "refreshTrendWorkspace" not in pilot_loader
    assert "loadCases" not in pilot_loader


def test_consistent_overview_only_skips_case_when_quality_is_verified() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "function overviewActionLabel(item)" in script
    assert 'item.priority === "normal"' in script
    assert 'item.dataQualityStatus === "sufficient"' in script
    assert "item.unverifiedDimensions.length === 0" in script
    assert 'return fullyVerified ? "无需建账" : "待补证/待形成事项";' in script
    assert (
        'item.technicalStatus === "consistent" ? "无需建账"'
        not in script
    )


def test_intranet_authentication_uses_memory_csrf_without_session_tokens() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "登录监管工作台" in html
    assert "会话凭证仅由浏览器安全 Cookie 管理" in html
    for endpoint in (
        "/v1/auth/csrf",
        "/v1/auth/login",
        "/v1/auth/logout",
    ):
        assert endpoint in script
    assert '"X-CSRF-Token"' in script
    assert 'credentials: "same-origin"' in script
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "session_token",
    ):
        assert forbidden not in script


def test_jobs_double_review_evidence_and_admin_workspaces_are_present() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for workspace in ("分析任务", "用户管理"):
        assert workspace in html
    for status in (
        "queued",
        "running",
        "succeeded",
        "partial_failed",
        "failed",
        "cancelled",
    ):
        assert status in script
    for action in (
        "submit_conclusion",
        "pending_approval",
        "approve",
        "reject",
    ):
        assert action in script
    for endpoint in (
        "/v1/analysis-jobs",
        "/v1/admin/users",
        "/evidence",
        "/verify",
    ):
        assert endpoint in script
    assert "提交人与审批人必须是不同账号" in script
    assert "不是风险、处罚或责任等级" in html


def test_leadership_trends_keep_missing_values_distinct_from_zero() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "近 30 日变化" in html
    assert "趋势与积压" in html
    assert "矿山关注排序" in html
    assert "/v1/dashboard/trends?days=30" in script
    assert "近 7 日无应报矿次，不按 0% 计算" in script
    assert "仅用于安排核查顺序，不是风险、处罚或责任认定" in html
    for field in (
        "daily_trend",
        "mine_risk_ranking",
        "repeated_anomalies",
        "case_performance",
        "data_quality",
    ):
        assert field in script


def test_v21_production_result_uses_all_scenarios_and_fails_closed() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for label in (
        "所有可恢复一致性的最小待核查情景",
        "该情景合理区间",
        "该情景最小差额",
        "独立证据簇",
    ):
        assert label in html
    for field in (
        "robust_minimum_reported_gap",
        "scenario_union_production_range",
        "scenario_conclusion_divergent",
        "priority_scenario_count",
        "independent_evidence_clusters",
    ):
        assert field in script
    assert "多情景稳健最小技术差额" in script
    assert "证据不足、不能下结论" in script
    assert "mcs_alternatives[0]" not in script
    assert "全部优先情景" in script


def test_temporal_dashboard_is_plain_language_and_never_overstates() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "时序异常与数据质量" in html
    assert "时序异常与数据源健康" not in html
    assert "未出现提示不能证明原始数据源完整或及时" in html
    assert "算法预警只是核查线索，不是定案" in html
    assert "/v1/dashboard/temporal?days=90" in script
    assert "历史数据不足，尚不能形成稳定基线" in script
    assert "开始 ${formatDateTime(episode.start)}" in script
    assert "结束 ${formatDateTime(episode.end)}" in script
    assert "贡献源：" in script
    assert "不能作为定案" in script
    assert "未读取不代表无异常" in script
    assert 'dashboard.reason === "data_truncated"' in script
    assert "数据未完整，不能判断正常" in script
    assert "未覆盖部分不能判断正常" in script
    assert "不代表原始来源完整或及时" in script
    assert "未见明确缺失、延迟" not in script
    assert script.index("if (hasWarnings)") < script.index(
        "} else if (dataIncomplete)"
    )
    assert script.index("} else if (dataIncomplete)") < script.index(
        "} else if (isColdStart)"
    )
    for status in ("anomalous", "normal", "insufficient_history"):
        assert status in script


def test_temporal_dashboard_keeps_points_and_draws_an_explainable_svg() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    for identifier in (
        'id="temporal-series-select"',
        'id="temporal-series-summary"',
        'id="temporal-series-chart"',
    ):
        assert identifier in html
    assert "选一条序列看 90 日变化" in html
    assert "阴影和上下界来自算法基线" in html
    for field in (
        "series.points",
        "point.observed_value",
        "point.baseline_median",
        "thresholds.rolling_lower",
        "thresholds.rolling_upper",
        "point.anomalous",
        "point.missing",
    ):
        assert field in script
    assert "function normalizeTemporalSeries(" in script
    assert "function renderTemporalSeriesChart(" in script
    assert "series.find(temporalSeriesHasWarnings)" in script
    assert 'document.createElementNS(' in script
    assert '"polygon"' in script
    assert '"polyline"' in script
    assert '"circle"' in script
    assert "曲线断开表示缺测或没有有效数值" in script
    assert "红点只提示需要复核" in script
    assert "含冷启动阶段序列" in script
    assert "不等于当前仍不足" in script
    assert "后续已形成基线" in script
    assert "innerHTML" not in script
    for selector in (
        ".temporal-series-panel",
        ".temporal-series-chart",
        ".temporal-observed-line",
        ".temporal-baseline-line",
        ".temporal-bound-band",
        ".temporal-anomaly-point",
    ):
        assert selector in styles


def test_demo_dataset_has_a_global_non_official_watermark() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    for identifier in (
        'id="demo-dataset-banner"',
        'id="demo-dataset-title"',
        'id="demo-dataset-description"',
    ):
        assert identifier in html
    assert "严禁用于正式统计、监管认定或对外报送" in html
    assert "function normalizeDemoDatasetMetadata(" in script
    assert "function setDemoDatasetContext(" in script
    assert "function renderDemoDatasetBanner(" in script
    assert 'dataset_id: "pilot-preview"' in script
    assert "localTrial === true" not in script
    for marker in (
        '"demo_dataset"',
        '"data_mode"',
        '"synthetic"',
        '"local_trial"',
    ):
        assert marker in script
    assert "textContent" in script
    assert "innerHTML" not in script
    assert ".demo-dataset-banner" in styles
    assert ".demo-dataset-banner-inner" in styles


def test_safety_workspace_has_leader_summary_mine_files_and_alert_ledger() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    for label in (
        "安全态势",
        "四色总览",
        "一矿一档",
        "矿井最新关键指标",
        "安全预警列表",
        "井下人数",
        "甲烷最高点",
        "最新风量",
    ):
        assert label in html or label in script
    assert "暂无开放预警”不等于现场安全" in html
    assert "不是事故、处罚或责任等级" in html
    assert "不会直接控制停产、断电、复电或撤人" in html
    assert "/v1/dashboard/safety" in script
    assert "/v1/safety/alerts" in script
    assert "/v1/reports/safety-alerts.csv" in html
    for field in (
        "approved_underground_personnel",
        "latest_metrics",
        "open_alerts",
        "shadow_alerts",
        "shadow_summary",
        "operational",
        "risk_level",
        "occurrence_count",
        "overdue",
    ):
        assert field in script


def test_safety_alert_actions_are_permissioned_versioned_and_csrf_protected() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'safetyAssign: ["admin", "supervisor"]' in script
    assert 'safetyReview: ["admin", "supervisor", "reviewer"]' in script
    assert 'safetyApprove: ["admin", "supervisor"]' in script
    assert 'safetyProfile: ["admin"]' in script
    assert "function userCanSafetyAction(action)" in script
    assert "const allowedActions = availableSafetyActions(alert);" in script


def test_safety_attachments_are_hashed_uploaded_and_download_only() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "createSafetyAttachmentPanel(alert)" in script
    assert "SAFETY_ATTACHMENT_MAX_BYTES = 5 * 1024 * 1024" in script
    assert 'window.crypto.subtle.digest("SHA-256", bytes)' in script
    assert "/attachments" in script
    assert "/download" in script
    assert "download.download = attachment.filename" in script
    assert 'userCan("safetyReview")' in script
    attachment_code = script[
        script.index("const SAFETY_ATTACHMENT_MAX_BYTES") :
        script.index("function renderSafetyAlerts()")
    ]
    assert "URL.createObjectURL" not in attachment_code
    assert "FileReader" not in attachment_code
    assert "if (allowedActions.length > 0)" in script
    assert "expected_version: alert.version" in script
    assert 'method: "POST"' in script
    assert "/actions`" in script
    for action in (
        "assign",
        "acknowledge",
        "start",
        "resolve",
        "close",
        "reopen",
        "add_note",
    ):
        assert action in script


def test_frontend_is_installable_without_caching_authenticated_api_data() -> None:
    html = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    worker = (WEB_ROOT / "service-worker.js").read_text(encoding="utf-8")
    manifest = json.loads(
        (WEB_ROOT / "manifest.webmanifest").read_text(encoding="utf-8")
    )

    assert 'rel="manifest"' in html
    assert 'navigator.serviceWorker.register("/service-worker.js")' in script
    assert manifest["display"] == "standalone"
    assert manifest["start_url"] == "/"
    assert {
        (item["src"], item["sizes"], item["type"])
        for item in manifest["icons"]
    } >= {
        ("/assets/icon-192.png", "192x192", "image/png"),
        ("/assets/icon-512.png", "512x512", "image/png"),
    }
    assert (WEB_ROOT / "icon-192.png").stat().st_size > 0
    assert (WEB_ROOT / "icon-512.png").stat().st_size > 0
    assert 'url.pathname.startsWith("/v1/")' in worker
    assert "/assets/app.js" in worker
    assert "/assets/icon-192.png" in worker
    assert "/assets/icon-512.png" in worker
    # requestJson adds the in-memory CSRF token for every mutating request.
    assert '"X-CSRF-Token"' in script
    assert 'credentials: "same-origin"' in script


def test_periodic_regulatory_report_is_plain_language_scoped_and_printable() -> None:
    html, parser = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    assert parser.inline_handlers == []
    for text in (
        "生成领导监管报告",
        "月度报告",
        "季度报告",
        "固定自然周期",
        "缺报、历史不足与核验阻断",
        "不会自动外发、签批、立案或改变台账状态",
        "打印 / 另存为 PDF",
    ):
        assert text in html
    for identifier in (
        'id="regulatory-report-form"',
        'id="regulatory-report-kind"',
        'id="regulatory-report-year"',
        'id="regulatory-report-month"',
        'id="regulatory-report-quarter"',
        'id="regulatory-report-timezone"',
        'id="regulatory-report-quality-issues"',
        'id="regulatory-report-mine-body"',
        'id="print-regulatory-report"',
    ):
        assert identifier in html
    assert "/v1/reports/regulatory" in script
    assert "new URLSearchParams(selection)" in script
    assert "Asia/Shanghai" in script
    assert "regulatoryReportingLabel" in script
    assert "无可统计应报记录" in script
    assert "历史样本不足" in script
    assert "核验被阻断" in script
    assert "不等于安全认定" in script
    assert "window.print()" in script
    assert "print-regulatory-report" in styles
    assert "@media print" in styles
    report_renderer = script.split(
        "function renderRegulatoryReport", maxsplit=1
    )[1].split("function printRegulatoryReport", maxsplit=1)[0]
    assert ".innerHTML" not in report_renderer
    assert ".textContent" in report_renderer


def test_missing_safety_profile_is_explicit_and_admin_can_complete_it() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "管理员需补齐矿井档案" in script
    assert "缺项期间不能形成完整阈值判断" in script
    assert "管理员 · 新增或补齐矿井档案" in html
    assert "/v1/admin/mines" in script
    for field in (
        "mine_id",
        "mine_name",
        "gas_category",
        "approved_underground_personnel",
        "approved_capacity_tpy",
        "longitude",
        "latitude",
        "enabled",
    ):
        assert field in script


def test_mine_file_shows_production_verification_without_overstating() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "生产核验需关注" in html
    for field in (
        "verification_summary",
        "production_verification",
        "overall_clue_level",
        "jointly_upgraded",
        "verification_ratio",
        "robust_z",
    ):
        assert field in script
    for label in (
        "尚未运行吨煤耗电与吨煤火工品核验",
        "历史不足",
        "数据阻断",
        "本次无关注",
        "两路同向印证",
    ):
        assert label in script
    assert "本窗口未形成需要关注的历史偏离线索" in script
    assert "本窗口生产数据正常" not in script


def test_safety_mine_map_is_offline_relative_and_links_to_filter() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")
    renderer = script.split(
        "function renderSafetyMap()", maxsplit=1
    )[1].split("function handleSafetyMineSelection", maxsplit=1)[0]

    assert "矿井分布示意" in html
    assert "不是测绘底图或导航依据" in html
    assert "档案经纬度不足，暂以一矿一档为准" in html
    assert "minimumLongitude" in renderer
    assert "maximumLongitude" in renderer
    assert "minimumLatitude" in renderer
    assert "maximumLatitude" in renderer
    assert "dataset.safetyMine" in renderer
    assert "map-x-" in renderer
    assert "map-y-" in renderer
    assert ".style" not in renderer
    assert ".safety-map-point.map-x-10" in styles
    assert ".safety-map-point.map-y-10" in styles


def test_admin_safety_rule_approval_is_explicit_versioned_and_hidden_by_role() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "管理员 · 安全规则审批" in html
    assert "登记的方案版本不等于已审批" in html
    assert "本页不编辑阈值内容" in html
    assert 'safetyRules: ["admin"]' in script
    assert "/v1/admin/safety-rules" in script
    assert "expected_fingerprint: rule.fingerprint" in script
    assert "inputMinLength: 10" in script
    assert 'action === "approve"' in script
    assert 'action === "retire"' in script
    for field in (
        "rule_version",
        "fingerprint",
        "effective_from",
        "effective_to",
        "authority_reference",
        "decision_note",
    ):
        assert field in script
    for status in ("proposal", "draft", "approved", "retired"):
        assert status in script


def test_safety_workspace_is_responsive_and_has_no_inline_event_handlers() -> None:
    _, parser = parse_frontend()
    styles = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")

    assert parser.inline_handlers == []
    for selector in (
        ".safety-level-grid",
        ".safety-mine-grid",
        ".safety-metric-grid",
        ".safety-alert-actions",
    ):
        assert selector in styles
    assert "@media (max-width: 900px)" in styles
    assert "@media (max-width: 680px)" in styles


def test_admin_operations_explain_readiness_and_verify_backups() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "系统就绪与备份" in html
    assert "立即备份并校验" in html
    assert "重新校验" in script
    assert "/ready" in script
    assert "/v1/admin/backups" in script
    assert "backup_id" in script
    assert "backup_invalid" in script
    assert "X-CSRF-Token" in script


def test_user_lifecycle_actions_are_available_without_erasing_history() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    user_renderer = script.split("function renderUsers()", maxsplit=1)[1].split(
        "async function createUser", maxsplit=1
    )[0]
    user_actions = script.split(
        "async function toggleUserStatus", maxsplit=1
    )[1].split("function userLifecycleError", maxsplit=1)[0]

    assert "账号生命周期" in html
    assert "账号不做物理删除" in html
    for identifier in (
        'id="cancel-user-edit"',
        'id="user-password-wrap"',
    ):
        assert identifier in html
    for label in ("停用账号", "恢复账号", "调整权限", "重置密码"):
        assert label in user_renderer
    assert "cannot_disable_self" in script
    assert "last_active_admin" in script
    assert "beginUserEdit(user)" in user_renderer
    assert "/access" in script
    assert "/status" in user_actions
    assert "/reset-password" in user_actions
    assert "new_password: confirmation.value" in user_actions
    assert "历史办理记录" in user_actions


def test_case_lifecycle_supports_withdraw_archive_restore_and_audit_history() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    option_logic = script.split(
        "function configureCaseActionOptions", maxsplit=1
    )[1].split("function renderCaseFacts", maxsplit=1)[0]
    submit_logic = script.split(
        "async function submitCaseAction", maxsplit=1
    )[1].split("function setCaseActionStatus", maxsplit=1)[0]

    for action, label in (
        ("withdraw_conclusion", "撤回本人待审批结论"),
        ("archive_case", "移出常用台账（归档）"),
        ("restore_case", "恢复到常用台账"),
    ):
        assert f'value="{action}"' in html
        assert label in html
        assert action in option_logic
        assert action in submit_logic
    assert 'workflowStatus === "pending_approval"' in option_logic
    assert "conclusionBy === currentUsername" in option_logic
    assert 'workflowStatus === "closed"' in option_logic
    assert "requestActionConfirmation" in submit_logic
    assert "expected_version" in submit_logic
    assert "?include_archived=1" in script
    assert 'id="show-archived-cases"' in html


def test_completed_jobs_can_be_archived_and_restored_without_deleting_results() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    job_actions = script.split(
        "function createJobActions", maxsplit=1
    )[1].split("async function submitPilotJob", maxsplit=1)[0]
    archive_logic = script.split(
        "async function archiveJob", maxsplit=1
    )[1].split("function clearJobPoll", maxsplit=1)[0]

    assert 'id="show-archived-jobs"' in html
    assert "查看已归档" in html
    assert "归档任务" in job_actions
    assert "恢复显示" in job_actions
    assert "/archive" in archive_logic
    assert "archived," in archive_logic
    assert "reason: confirmation.value" in archive_logic
    assert "结果和审计记录" in archive_logic
    assert "?include_archived=1" in script


def test_temporary_analysis_can_be_cleared_without_touching_formal_records() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    clear_logic = script.split(
        "function clearCurrentAnalysis", maxsplit=1
    )[1].split("function loadDataset", maxsplit=1)[0]

    assert 'id="clear-analysis"' in html
    assert "清空本次数据" in html
    assert "clearCurrentAnalysis" in script
    assert "clearDataset()" in clear_logic
    assert "state.lastResult = null" in clear_logic
    assert "state.lastResultMode = null" in clear_logic
    assert "hideResult()" in clear_logic
    assert "正式台账和审计记录未受影响" in clear_logic


def test_consequential_actions_use_an_accessible_confirmation_dialog() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    dialog_logic = script.split(
        "function requestActionConfirmation", maxsplit=1
    )[1].split("async function initializeAuthentication", maxsplit=1)[0]

    assert "<dialog" in html
    assert 'id="action-confirm-dialog"' in html
    assert 'aria-labelledby="action-confirm-title"' in html
    assert 'aria-describedby="action-confirm-message"' in html
    assert 'id="action-confirm-error"' in html
    assert 'role="alert"' in html
    assert 'id="action-confirm-cancel"' in html
    assert 'type="button"' in html
    assert "dialog.showModal()" in dialog_logic
    assert 'elements["action-confirm-cancel"].focus()' in dialog_logic
    assert "current.trigger.focus()" in dialog_logic
    assert "inputRequired" in dialog_logic
    assert "inputMinLength" in dialog_logic
    assert "window.confirm" not in script


def test_pilot_batch_isolation_ui_uses_governed_soft_invalidation_when_present() -> None:
    """Keep future batch cleanup UI on the auditable invalidation endpoint."""

    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    has_isolation_ui = (
        'id="isolate-pilot-batches"' in html
        or "isolatePilotBatches" in script
    )
    if not has_isolation_ui:
        return

    assert 'id="isolate-pilot-batches"' in html
    assert "/v1/admin/analysis-batches/isolate-pilots" in script
    assert "requestActionConfirmation" in script
    assert "reason" in script


def test_admin_can_invalidate_and_restore_batches_with_version_guard() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    lifecycle_logic = script.split(
        "async function changeBatchLifecycle", maxsplit=1
    )[1].split("async function isolatePilotBatches", maxsplit=1)[0]

    assert 'id="show-invalidated-batches"' in html
    assert 'id="batches-table-body"' in html
    assert "作废会让批次退出领导总览" in html
    assert "?include_invalidated=true" in script
    assert "/status" in lifecycle_logic
    assert "expected_version: batch.version" in lifecycle_logic
    assert "reason: confirmation.value" in lifecycle_logic
    assert "requestActionConfirmation" in lifecycle_logic
    assert "原始结果及审计记录不会删除" in lifecycle_logic


def test_resetting_current_admin_password_returns_to_login() -> None:
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    reset_logic = script.split(
        "async function resetUserPassword", maxsplit=1
    )[1].split("function userLifecycleError", maxsplit=1)[0]

    assert "body.reauthentication_required" in reset_logic
    assert "resetProtectedState()" in reset_logic
    assert "showLogin(" in reset_logic


def test_conditional_history_is_plain_language_and_never_overrides_physics() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert "历史证据与综合研判" in html
    assert "历史不足不算正常" in html
    assert "合法情景也不能覆盖物理冲突" in html
    for field in (
        "historical_evidence",
        "assessment",
        "selected_sample_count",
        "rarity_score",
        "temporal_evidence",
        "evidence_fusion",
        "agreement",
        "shadow_priority",
        "physical_status_unchanged",
    ):
        assert field in script
    for label in (
        "历史样本不足",
        "当前在历史范围内",
        "当前相对历史罕见",
        "当前出现时序突变",
        "独立时序证据",
        "物理结论未改变",
    ):
        assert label in script
    assert "没有历史结果不代表当前数据正常" in script
    assert "合法情景仍保留物理冲突" not in script


def test_reference_labels_are_append_only_and_available_without_a_case() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'id="overview-reference-label-dialog"' in html
    assert "系统不会把“当前可协调”自动标成正常" in html
    assert "每次提交都会追加留痕，不覆盖旧标签" in html
    for label in (
        "verified_normal",
        "legitimate_exception",
        "confirmed_data_error",
        "confirmed_technical_anomaly",
        "adjudicated_violation",
        "unresolved",
    ):
        assert label in html
        assert label in script
    assert "/reference-labels" in script
    assert "expected_sequence" in script
    assert "analysisRunId" in script
    assert "openOverviewReferenceLabelDialog(item)" in script
    assert 'referenceLabel: ["admin", "supervisor"]' in script
    assert "不会自动进入正常历史基线" in script


def test_admin_legitimate_scenarios_are_versioned_and_explanatory_only() -> None:
    html, _ = parse_frontend()
    script = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
    create_logic = script.split(
        "async function createLegitimateScenario", maxsplit=1
    )[1].split("async function loadBatches", maxsplit=1)[0]

    assert "合法情景库" in html
    assert "修改时请新建版本，不覆盖旧版本" in html
    assert "/v1/admin/legitimate-scenarios" in script
    for field in (
        "scenario_id",
        "version",
        "name",
        "description",
        "mine_ids",
        "regime",
        "shift",
        "season",
        "maintenance",
        "required_event_codes",
        "required_tags",
        "feature_bounds",
        "active",
    ):
        assert field in create_logic
    assert "JSON.stringify({ scenario })" in create_logic
    assert "created_by" not in create_logic
    assert "context_match" not in create_logic
    assert "同编号旧版本仍只读保留" in create_logic
