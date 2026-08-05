from __future__ import annotations

import re
import subprocess
from pathlib import Path

WEB_ROOT = Path(__file__).resolve().parents[1] / "web"
HTML = (WEB_ROOT / "index.html").read_text(encoding="utf-8")
JS = (WEB_ROOT / "app.js").read_text(encoding="utf-8")
CSS = (WEB_ROOT / "styles.css").read_text(encoding="utf-8")


def test_frontend_assets_exist_and_are_linked() -> None:
    assert (WEB_ROOT / "README.md").is_file()
    assert '<link rel="stylesheet" href="./styles.css">' in HTML
    assert '<script src="./app.js" defer></script>' in HTML
    assert CSS.strip()


def test_six_business_steps_are_explicit() -> None:
    expected = [
        "基本信息",
        "导入来源",
        "提取核对",
        "提交前预检",
        "人工确认",
        "提交回执",
    ]
    assert HTML.count('data-step="') == 6
    assert HTML.count('data-panel="') == 6
    for label in expected:
        assert label in HTML


def test_core_field_labels_are_not_accidentally_duplicated() -> None:
    for label in (
        "企业名称",
        "企业编号",
        "统一社会信用代码",
        "矿井/单位编码",
        "矿井/单位名称",
        "统计开始时间",
        "统计结束时间",
    ):
        assert HTML.count(f"<span>{label} <em>必填</em></span>") == 1


def test_required_governance_language_is_visible() -> None:
    for text in (
        "智能提取结果只是待核对建议，不代表事实",
        "操作上下文四轴",
        "生产工况",
        "班次",
        "季节/气候期",
        "检修状态",
        "已批准的特殊事件",
        "提取可信度",
        "人工确认",
        "平台回执号",
        "接收回执不代表监管认可",
        "脱敏草稿摘要发送到管理员配置的第三方模型",
        "不会自动确认或提交",
        "请勿粘贴 API 密钥",
    ):
        assert text in HTML


def test_all_http_paths_are_relative_and_centralized() -> None:
    assert 'const API_ROOT = "/api/v1"' in JS
    for path in (
        "/drafts",
        "/import",
        "/assist",
        "/questions",
        "/event-snapshot",
        "/validate",
        "/confirm",
        "/submit",
    ):
        assert path in JS
    assert "fetch(`${API_ROOT}${path}`" in JS
    assert "http://" not in JS
    assert "https://" not in JS


def test_frontend_adapts_to_independent_flat_draft_contract() -> None:
    for field in (
        "enterprise_id",
        "enterprise_name",
        "unified_social_credit_code",
        "mine_id",
        "mine_name",
        "window_start",
        "window_end",
        "profile_id",
        "profile_version",
        "operational_context",
        "observations",
        "expected_revision",
    ):
        assert field in JS
    assert "confirmer_name" in JS
    assert "confirmer_role" in JS
    assert "attestation" in JS


def test_frontend_uses_server_session_principal_and_in_memory_csrf() -> None:
    for path in ("/auth/login", "/auth/me", "/auth/logout"):
        assert path in JS
    for element_id in (
        'id="loginDialog"',
        'id="loginForm"',
        'id="logoutButton"',
        'id="confirmationActorName"',
        'id="credentialNotice"',
    ):
        assert element_id in HTML
    assert '"X-CSRF-Token"' in JS
    assert 'credentials: "same-origin"' in JS
    assert "state.csrfToken" in JS
    assert "localStorage" not in JS
    assert "sessionStorage" not in JS
    assert 'confirmation_method: "authenticated_click"' in JS
    assert 'actor: "local-operator"' not in JS
    assert "temporary_demo" in JS
    assert "credentialRotationRequired" in JS


def test_role_guidance_is_permission_driven_and_fail_closed() -> None:
    for element_id in (
        'id="roleGuide"',
        'id="roleGuideTitle"',
        'id="roleGuideLevelBadge"',
        'id="roleGuideSummary"',
        'id="roleGuideContext"',
        'id="roleGuidePermissions"',
        'id="roleGuideSteps"',
        'id="roleGuideCapabilities"',
        'id="roleGuideRestrictions"',
    ):
        assert element_id in HTML
    assert "岗位名称不授予能力" in HTML
    assert "function principalOperationGuide(principal)" in JS
    assert "function renderOperationGuide()" in JS
    assert "renderOperationGuide();" in JS
    guide = JS[
        JS.index("function principalOperationGuide(principal)") : JS.index(
            "function replaceTextList"
        )
    ]
    for permission in ("read", "write", "confirm", "submit"):
        assert f'granted.has("{permission}")' in guide
    assert "principal.must_change_password" in guide
    assert "principal.temporary_demo" in guide
    assert "principal.role" not in guide
    assert "innerHTML" not in guide
    render = JS[
        JS.index("function renderOperationGuide()") : JS.index(
            "function renderAuthentication()"
        )
    ]
    assert "principal.role" in render
    assert "textContent" in render
    assert "replaceChildren" in render


def test_runtime_capabilities_are_visible_before_final_submission() -> None:
    for path in (
        "/health",
        "/platform-status",
        "/reviews",
        "/audit",
        "/submissions",
    ):
        assert path in JS
    for element_id in (
        'id="agentStatusText"',
        'id="platformStatusText"',
        'id="assistantStatusText"',
        'id="loginRuntimeStatus"',
        'id="submissionHistory"',
        'id="auditHistory"',
    ):
        assert element_id in HTML
    assert "启动命令所在终端保持不返回提示符是服务器正常运行状态" in JS
    assert "尚未配置监管平台接口，可继续编辑但不能提交" in JS
    assert "health.demo_account_enabled === true" in JS


def test_review_state_is_server_persisted_and_authoritative() -> None:
    assert "loadReviews" in JS
    assert "setMeasurementReviews" in JS
    assert "expected_revision: state.activeDraft.revision" in JS
    assert "state.reviewState.all_reviewed" in JS
    assert "观测变化会自动撤销旧核对" in JS
    assert "reviewCache" not in JS
    # A separate submitter must not be forced to repeat the confirmer's review.
    assert (
        "measurement.confirmed = state.activeDraft.signature.valid\n        ? true"
    ) in JS


def test_saved_llm_suggestions_survive_reload_without_reoffering_adopted_paths() -> (
    None
):
    assert "restoreSuggestionsFromDraft" in JS
    assert "assistance.accepted_field_paths" in JS
    assert '!accepted.has(String(item.path || ""))' in JS
    assert "source.llm_assistance" in JS


def test_llm_suggestions_cannot_create_sparse_rows_or_adopt_unsupported_fields() -> (
    None
):
    assert "suggestionIsAdoptable" in JS
    assert "index >= measurements.length" in JS
    assert "while (state.activeDraft.measurements.length <= index)" not in JS
    assert "suggestionIsAdoptable(item, draft)" in JS
    assert "suggestionIsAdoptable(suggestion, state.activeDraft)" in JS
    assert "suggestionIsAdoptable(item, state.activeDraft)" in JS


def test_wire_adapter_handles_real_flat_draft_metadata() -> None:
    assert "source.unified_social_credit_code" in JS
    assert "responseDraft._meta && responseDraft._meta.revision" in JS
    assert "responseDraft._meta && responseDraft._meta.updated_at" in JS
    # The browser must not invent source-gateway identity or event timestamps.
    assert 'observation_id: item.observation.observation_id || ""' in JS
    assert 'observed_at: item.observation.observed_at || ""' in JS
    assert 'received_at: item.observation.received_at || ""' in JS
    assert '"manual" &&' in JS
    assert '"human_entry"' in JS


def test_import_templates_and_real_server_limits_are_explained() -> None:
    for text in (
        "下载 JSON 模板",
        "下载 CSV 模板",
        "payload_sha256",
        "signature",
        "手工修改观测值、单位、时间或来源编号会使原网关签名失效",
        "不超过 2 MiB",
        "不支持在这里凭空创建",
        "event_codes: []",
        "evidence_sha256",
        "下载事件快照模板",
    ):
        assert text in HTML
    assert "2 * 1024 * 1024" in JS
    assert "256 * 1024" in JS
    assert "5 * 1024 * 1024" not in JS


def test_autosave_serializes_requests_and_blocks_unsafe_navigation() -> None:
    assert "state.savePromise" in JS
    assert "saveBeforeNavigation" in JS
    assert "当前草稿仍有未保存内容；为避免丢失，已取消切换" in JS
    assert "state.dirtyWireFields.size" in JS
    assert 'id="retrySaveButton"' in HTML
    assert "await flushSave();\n      await api(endpoints.logout()" in JS
    assert "preserveWorkspace" in JS
    assert "resumeSessionRecovery" in JS
    assert 'id="loadMoreDraftsButton"' in HTML
    assert "payload.has_more" in JS
    assert "payload.next_offset" in JS


def test_long_operations_have_explicit_time_budgets_and_safe_submit_recovery() -> None:
    assert "timeoutMs: 75000" in JS
    assert "timeoutMs: 55000" in JS
    assert "timeoutMs: 30000" in JS
    assert "reconcileSubmissionAttempt" in JS
    assert "idempotencyKey" in JS
    assert "请勿换用新幂等键重复提交" in JS


def test_measurements_are_paginated_removable_and_undo_is_bounded() -> None:
    assert 'id="measurementPagination"' in HTML
    assert 'id="previousMeasurementPageButton"' in HTML
    assert "measurementPageSize: 50" in JS
    assert "visibleRows" in JS
    assert "移除此条" in JS
    assert "await flushSave();\n      const entry = state.undoStack" in JS
    assert "state.undoBytes > 512 * 1024" in JS
    assert "clone(state.activeDraft)" not in JS


def test_draft_pagination_does_not_skip_after_removing_a_loaded_row() -> None:
    assert "draftNextOffset" in JS
    assert "state.draftNextOffset - 1" in JS


def test_server_authority_and_evidence_labels_are_not_invented_locally() -> None:
    assert "const serverConfirmed = Boolean(responseMeta.confirmed)" in JS
    assert "valid: serverConfirmed" in JS
    for event_name in (
        "observations_reviewed",
        "observation_reviews_revoked",
        "human_confirmed",
        "regulator_event_snapshot_imported",
    ):
        assert event_name in JS
    assert "error.violations.slice(0, 8)" in JS
    assert "error.retryable === true" in JS
    assert "提交失败（可安全重试）" not in JS


def test_event_snapshot_uses_dedicated_contract_and_accepts_single_bom() -> None:
    for field in (
        "snapshot_id",
        "mine_id",
        "window_start",
        "window_end",
        "event_codes",
        "evidence_sha256",
        "source_system",
        "record_id",
    ):
        assert field in JS
    assert "endpoints.eventSnapshot(state.activeDraft.id)" in JS
    assert "parseJsonContent" in JS
    assert 'replace(/^\\uFEFF/, "")' in JS


def test_agent_workbench_is_independent_and_draft_health_check_is_one_click() -> None:
    for element_id in (
        'id="agentTaskButton"',
        'id="agentWorkbench"',
        'id="startAgentHealthButton"',
        'id="runCoalHealthButton"',
        'id="agentRunList"',
        'id="agentRunDetailTitle"',
        'id="agentIntegrityState"',
        'id="agentStepList"',
        'id="agentApprovalCard"',
    ):
        assert element_id in HTML
    panel = HTML[HTML.index('id="agentWorkbench"') : HTML.index('id="welcomeCard"')]
    assert "模型规划与确定性工具结果会分开显示" in panel
    assert "智能体不能替您完成人工确认" in panel
    assert 'id="submitButton"' not in panel
    assert 'id="confirmDraftButton"' not in panel
    assert "draft_id: draftId" in JS
    assert 'mode: "auto"' in JS
    start_function = JS[
        JS.index("async function startCoalHealthCheck") : JS.index(
            "async function loadAgentRuns"
        )
    ]
    assert '!hasPermission("read")' in start_function
    assert '!hasPermission("write")' not in start_function


def test_agent_task_composer_supports_leader_presets_custom_text_and_modes() -> None:
    for element_id in (
        'id="agentTaskComposerTitle"',
        'id="agentTaskInput"',
        'id="agentTaskCharacterCount"',
        'id="agentComposerDraftBinding"',
        'id="startAgentCustomButton"',
    ):
        assert element_id in HTML
    for label in (
        "全面体检",
        "解释异常与凭证",
        "历史趋势",
        "来源核验",
        "自动规划",
        "仅确定性",
        "开始这项任务",
    ):
        assert label in HTML
    assert 'maxlength="4000"' in HTML
    assert HTML.count('data-agent-task-preset="') == 4
    assert 'name="agentRunMode" value="auto" checked' in HTML
    assert 'name="agentRunMode" value="deterministic"' in HTML
    assert "const agentTaskPresets = Object.freeze" in JS
    assert "function startAgentTaskFromComposer" in JS
    assert "task.length > 4000" in JS
    assert "mode: selectedAgentRunMode()" in JS
    assert "task,\n          draft_id: draftId,\n          mode," in JS
    assert "state.agent.creating" in JS
    assert "run.task === task" in JS
    assert "run.mode === mode" in JS


def test_agent_run_api_adapter_status_polling_and_decisions_are_complete() -> None:
    for path in (
        "/agent/runs",
        "/cancel",
        "/approve",
    ):
        assert path in JS
    for status in (
        "queued",
        "running",
        "waiting_approval",
        "completed",
        "failed",
        "cancelled",
    ):
        assert status in JS
    assert 'decision === "approve"' in JS
    assert 'decision: "approve"' not in JS  # the same adapter also supports reject
    assert "approval_id: approval.approval_id" in JS
    assert "只读账号可以拒绝或取消" in JS
    assert '!actionable || !hasPermission("write")' in JS
    assert 'status === "waiting_approval" ? 3000 : 1000' in JS
    assert "agentPollLimitMs" in JS
    assert "pollFailures < 5" in JS
    assert "error.status !== 401" in JS
    assert "evidence.call_id" in JS
    assert "source.integrity" in JS
    assert "创建请求状态暂时未知" in JS
    assert "请先刷新任务列表，勿立即重复点击" in JS


def test_agent_tool_evidence_is_not_presented_as_model_fact() -> None:
    for text in (
        "模型规划 · 非事实证据",
        "确定性工具结果",
        "工具过程 · 待核实",
        "确定性体检摘要（基于工具结果）",
        "evidence.deterministic === true",
        "以来源已绑定的工具结果和原始材料为准",
        "批准仅对本卡片所列动作生效",
        "当前草稿/历史库绑定",
        "调用者提供数值，仅复算不证明来源",
        "来源绑定未声明",
        "确定性复算：相同输入会得到相同结果",
    ):
        assert text in JS or text in HTML
    for path in (
        "call.evidence_grounding",
        "details.evidence_grounding",
        "callEvidence.evidence_grounding",
        "resultData.evidence_grounding",
        '"repository_grounded"',
        '"user_supplied"',
        'normalized === "mixed"',
    ):
        assert path in JS
    assert "不能视为当前草稿或历史库事实" in JS
    run_list_at = HTML.index('id="agentRunList"')
    run_error_at = HTML.index('id="agentRunError"')
    assert 'aria-live="polite"' in HTML[run_list_at - 100 : run_list_at + 150]
    assert 'role="alert"' in HTML[run_error_at - 80 : run_error_at + 100]


def test_agent_integrity_failure_is_fail_closed_in_markup_and_handlers() -> None:
    for element_id in (
        'id="agentIntegrityFailure"',
        'id="agentEvidenceSection"',
    ):
        assert element_id in HTML
    assert "过程证据完整性校验失败，以下内容不可采信" in HTML
    assert "综合说明、工具结果和审批详情已安全遮蔽" in HTML
    assert "function agentIntegrityFailed" in JS
    assert "run.integrity.valid !== true" in JS
    assert "integrityProvided" in JS
    assert "Object.prototype.hasOwnProperty.call" in JS
    assert "els.agentRunAnswer.replaceChildren()" in JS
    assert "els.agentStepList.replaceChildren()" in JS
    assert "els.agentApprovalDetails.replaceChildren()" in JS
    assert "els.agentEvidenceSection.hidden = integrityFailed" in JS
    assert "els.approveAgentApprovalButton.disabled = true" in JS
    assert "els.rejectAgentApprovalButton.disabled = true" in JS
    decision = JS[
        JS.index("async function decideSelectedAgentApproval") : JS.index(
            "function normalizeAgentRun"
        )
    ]
    assert decision.index("agentIntegrityFailed(run)") < decision.index(
        "endpoints.agentRunApprove"
    )
    cancel = JS[
        JS.index("async function cancelSelectedAgentRun") : JS.index(
            "async function decideSelectedAgentApproval"
        )
    ]
    assert "agentIntegrityFailed" not in cancel
    render = JS[
        JS.index("function renderAgentRunDetail") : JS.index(
            "function renderAgentProgress"
        )
    ]
    assert render.index("if (integrityFailed)") < render.index("renderAgentAnswer(run)")


def test_agent_integrity_fail_closed_behavior_in_jsdom() -> None:
    script = Path(__file__).with_name("frontend_integrity_dom.test.js")
    completed = subprocess.run(
        ["node", str(script)],
        cwd=WEB_ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM integrity fail-closed checks passed" in completed.stdout


def test_role_guidance_permission_matrix_behavior_in_jsdom() -> None:
    script = Path(__file__).with_name("frontend_role_guidance_dom.test.js")
    completed = subprocess.run(
        ["node", str(script)],
        cwd=WEB_ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (
        "JSDOM role guidance permission matrix checks passed" in completed.stdout
    )


def test_coal_chat_is_separate_scoped_and_uses_a_centralized_contract() -> None:
    for element_id in (
        'id="coalChatButton"',
        'id="coalChatWorkbench"',
        'id="newCoalChatButton"',
        'id="coalChatSessionList"',
        'id="coalChatMessageList"',
        'id="coalChatUseCurrentDraft"',
        'id="coalChatInput"',
        'id="sendCoalChatButton"',
        'id="deleteCoalChatButton"',
        'id="coalChatScopeNotice"',
    ):
        assert element_id in HTML
    panel = HTML[
        HTML.index('id="coalChatWorkbench"') : HTML.index('id="agentWorkbench"')
    ]
    for text in (
        "仅限煤炭相关业务，不是监管结论",
        "不能确认草稿或报送监管平台",
        "非煤炭业务问题会被明确拒绝",
        "不构成监管结论，不能用于确认或报送",
    ):
        assert text in panel
    assert 'id="submitButton"' not in panel
    assert 'id="confirmDraftButton"' not in panel
    assert 'maxlength="2000"' in panel
    for adapter in (
        "chatSessions:",
        "chatSessionsCreate:",
        "chatSession:",
        "chatMessages:",
    ):
        assert adapter in JS
    for path in ("/chat/sessions", "/messages"):
        assert path in JS


def test_coal_chat_guards_async_duplicates_scope_and_integrity() -> None:
    for text in (
        "client_message_id: pending.clientMessageId",
        "state.chat.sending",
        "state.chat.deliveryUnknown",
        "Number(httpStatus) === 202",
        "payload.run_id",
        "scheduleCoalChatPoll",
        "90_000",
        "发送按钮已锁定",
        "该问题不属于煤炭业务，助手已明确拒绝",
        "对话记录完整性异常，请联系管理员",
    ):
        assert text in JS
    assert 'method: "DELETE"' in JS
    assert "确定移除当前煤炭业务对话吗" in JS
    assert "coalChatIntegrityFailed(state.chat.detail)" in JS
    assert "source.messages.map(normalizeCoalChatMessage)" in JS
    assert "textContent" in JS
    assert "innerHTML" not in JS


def test_coal_chat_labels_answer_basis_without_inventing_data_evidence() -> None:
    for token in (
        "coalChatAnswerProvenance",
        "evidenceSource.local_knowledge_topic",
        "evidenceSource.model_generated",
        "evidenceSource.answer_kind",
        "evidenceSource.tools",
        "repository_grounded",
        '"succeeded", "completed", "success"',
    ):
        assert token in JS
    for label in (
        "本地煤炭常识",
        "模型通识解释",
        "草稿工具证据",
        "范围控制",
        "回答来源未标注",
        "工具记录未验真",
    ):
        assert label in JS
    for warning in (
        "未据此核验企业实际数据",
        "未核验企业数据，不是数据事实或监管结论",
        "请勿视为企业数据事实",
        "不能作为企业数据证据",
    ):
        assert warning in JS
    assert "detail.integrity.valid === true" in JS
    assert ".coal-chat-answer-source" in CSS
    assert ".coal-chat-source-badge" in CSS


def test_coal_news_sources_are_fail_closed_and_safely_linked() -> None:
    for token in (
        "coal-news-search",
        "news_retrieval",
        "evidenceSource.retrieval",
        "evidenceSource.sources",
        "retrievalSource.failure_code",
        "safeCoalNewsSourceUrl",
        "isNonPublicIpv4Literal",
        'parsed.protocol !== "https:"',
        "parsed.username",
        "parsed.password",
        'link.target = "_blank"',
        'link.rel = "noopener noreferrer"',
        'link.referrerPolicy = "no-referrer"',
        ".slice(0, 10)",
    ):
        assert token in JS
    for label in (
        "联网新闻检索",
        "部分检索",
        "未检索到结果",
        "检索失败",
        "本次检索未获得通过校验的来源，不代表没有新闻",
        "连接超时，请检查服务器 DNS 或代理",
        "百度要求安全验证",
        "DeepSeek Web Search 鉴权失败",
        "可核验新闻来源",
            "百度标注来源",
            "搜索片段（可能截断，未核验正文）",
        "发布时间：",
        "检索渠道：",
        "检索时间：",
    ):
        assert label in JS
    assert "帮我看看最近煤炭相关新闻" in HTML
    assert "模型已配置（调用时验证）" in JS
    assert ".coal-chat-news-source-card" in CSS


def test_coal_chat_behavior_in_jsdom() -> None:
    script = Path(__file__).with_name("frontend_coal_chat_dom.test.js")
    completed = subprocess.run(
        ["node", str(script)],
        cwd=WEB_ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM coal chat checks passed" in completed.stdout


def test_confirmation_identity_is_read_only_and_no_fake_signature_choices() -> None:
    confirmation = HTML[HTML.index('data-panel="5"') : HTML.index('data-panel="6"')]
    assert 'name="signature.signer_name"' not in confirmation
    assert 'name="signature.signer_title"' not in confirmation
    assert 'name="signature.method"' not in confirmation
    assert "企业数字签名" not in confirmation
    assert "线下签章核验" not in confirmation
    assert "登录账号点击确认" in confirmation
    assert "人工实名确认" not in confirmation
    assert "企业账号人工确认" in confirmation


def test_dynamic_content_uses_safe_dom_apis() -> None:
    forbidden = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write")
    for token in forbidden:
        assert token not in JS
    assert "textContent" in JS
    assert "createElement" in JS
    assert "replaceChildren" in JS


def test_frontend_has_no_secret_or_platform_code_dependency() -> None:
    combined = "\n".join((HTML, JS, CSS))
    assert not re.search(r"\bsk-[A-Za-z0-9_-]{8,}", combined)
    assert "api_key" not in combined.lower()
    assert "../platform" not in combined
    assert "src/mineguard" not in combined


def test_destructive_draft_delete_requires_confirmation_and_submission_locks() -> None:
    assert 'id="deleteConfirmation"' in HTML
    assert 'id="confirmDeleteButton"' in HTML
    assert 'id="simpleDeleteDraftButton"' in HTML
    assert "els.simpleDeleteDraftButton.addEventListener" in JS
    assert "从普通工作列表移除，数据库和审计记录仍会保留" in JS
    assert '!== "移除"' in JS
    assert 'draft.status !== "draft"' in JS
    assert "草稿已从工作列表移除；审计留痕仍保留" in JS
    assert "这不是物理擦除" in HTML


def test_submit_gate_requires_data_confirmation_preflight_and_signature() -> None:
    assert "draft.measurements.every((row) => row.confirmed)" in JS
    assert "draft.preflight.blockers === 0" in JS
    assert "draft.signature.valid && draft.signature.signed_at" in JS
    assert 'id="submitButton"' in HTML
    assert (
        "disabled"
        in HTML[HTML.index('id="submitButton"') : HTML.index('id="submitButton"') + 120]
    )


def test_responsive_layout_is_present() -> None:
    assert "@media (max-width: 780px)" in CSS
    assert "@media (max-width: 520px)" in CSS
    assert "@media print" in CSS


def test_quick_reporting_mode_is_default_and_professional_tools_remain() -> None:
    for token in (
        '<body class="is-simple-mode">',
        'id="simpleModeButton"',
        'id="professionalModeButton"',
        'id="simpleStatusItem"',
        'id="simpleTaskCard"',
        'id="editorMoreActions"',
        'id="welcomeNewDraftButton"',
        'id="welcomeAutofillButton"',
    ):
        assert token in HTML
    assert 'interfaceMode: "simple"' in JS
    assert 'setEnterpriseMode("simple", false)' in JS
    assert 'document.body.classList.toggle("is-simple-mode"' in JS
    assert 'document.body.classList.toggle("is-professional-mode"' in JS
    assert ".is-simple-mode #agentTaskButton" in CSS
    assert ".is-simple-mode #coalChatButton" in CSS
    assert ".is-professional-mode .simple-task-card" in CSS
    for retained in ("煤炭智能任务", "煤炭业务对话", "当前账号操作说明"):
        assert retained in HTML
    for forbidden in ("localStorage", "sessionStorage"):
        assert forbidden not in HTML
        assert forbidden not in JS


def test_agent_autofill_is_source_grounded_and_never_auto_submits() -> None:
    assert "handleWelcomeAutofillAction" in JS
    assert "让 Agent 自动填入草稿" in JS
    assert "Agent 会自动写入可验证字段" in JS
    assert "自由文字和历史推断只形成" in HTML
    assert "待核对建议，不能冒充原始观测" in HTML
    assert "不会自动确认或提交" in HTML


def test_autofill_evidence_preview_is_read_only_and_evidence_layered() -> None:
    for element_id in (
        'id="autofillEvidenceButton"',
        'id="autofillEvidenceDialog"',
        'id="autofillIngestionList"',
        'id="autofillRawList"',
        'id="autofillHistoryList"',
        'id="autofillPhysicalList"',
        'id="autofillConflictList"',
    ):
        assert element_id in HTML
    for text in (
        "自动写入不等于企业确认",
        "历史数据只提供建议",
        "物理关系只用于分析",
        "不能生成来源签名",
    ):
        assert text in HTML
    for token in (
        "endpoints.ingestions(draftId)",
        "function autofillRawEvidence",
        "historical_suggestion",
        "physical_inference",
        "证据预览为只读页面",
        "不展示原文、签名或连接密钥",
    ):
        assert token in JS
    preview = JS[
        JS.index("async function openAutofillEvidenceDialog") : JS.index(
            "function renderMeasurements"
        )
    ]
    assert 'method: "POST"' not in preview
    assert 'method: "PATCH"' not in preview
    assert 'method: "DELETE"' not in preview
    assert "innerHTML" not in preview


def test_quick_workflow_keeps_event_snapshot_and_review_boundaries() -> None:
    assert "function hasRegulatorEventSnapshot(draft)" in JS
    assert JS.count("hasRegulatorEventSnapshot(draft)") >= 5
    assert "即使没有特殊事件也必须导入空结果快照" in JS
    assert "核对后确认本页高可信度项" in HTML
    assert ".slice(pageStart, pageStart + state.measurementPageSize)" in JS
    assert "不会处理其他分页" in JS
    assert ".is-simple-mode #confirmHighConfidenceButton" in CSS
    assert "renderSimpleTaskGuide();" in JS
    assert 'dataset.actionAllowed = String(actionAllowed)' in JS


def test_enterprise_mode_behavior_in_jsdom() -> None:
    script = Path(__file__).with_name("frontend_enterprise_mode_dom.test.js")
    completed = subprocess.run(
        ["node", str(script)],
        cwd=WEB_ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM enterprise mode checks passed" in completed.stdout


def test_agent_v2_task_center_is_governed_and_uses_centralized_contract() -> None:
    for element_id in (
        'id="agentCenterButton"',
        'id="agentCenterQuickCard"',
        'id="agentV2Workbench"',
        'id="startAgentV2HealthButton"',
        'id="agentV2FlowList"',
        'id="agentV2FlowSummary"',
        'id="agentV2JobForm"',
        'id="agentV2JobList"',
        'id="agentV2MemoryProposalList"',
        'id="agentV2SkillProposalList"',
    ):
        assert element_id in HTML
    for adapter in (
        "agentFlows:",
        "agentFlowCancel:",
        "agentFlowRetry:",
        "agentJobs:",
        "agentMemoryProposals:",
        "agentSkillProposals:",
        "agentSkillVersions:",
    ):
        assert adapter in JS
    for path in (
        "/agent/flows",
        "/agent/jobs",
        "/agent/memory/proposals",
        "/agent/skill-proposals",
        "/agent/skill-versions",
    ):
        assert path in JS
    assert "workflow_name: \"daily_coal_health\"" in JS
    assert "expected_revision: proposal.revision" in JS
    assert "expected_revision: job.revision" in JS
    assert "智能体可以持续检查和提出建议，但没有确认、签名或提交权限" in HTML
    assert "技能批准后只发布版本，仍需服务加载后才能执行" in HTML
    assert ".is-simple-mode .agent-v2-professional-only" in CSS


def test_agent_v2_task_center_behavior_in_jsdom() -> None:
    script = Path(__file__).with_name("frontend_agent_v2_dom.test.js")
    completed = subprocess.run(
        ["node", str(script)],
        cwd=WEB_ROOT.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM agent V2 task center checks passed" in completed.stdout
