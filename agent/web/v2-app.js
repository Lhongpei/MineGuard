(() => {
  "use strict";

  const FIVE_QUANTITIES = Object.freeze([
    ["风量", [["ventilation_m3_min", "风量", "m³/min"]]],
    ["电量", [["electricity_kwh", "电量", "kWh"]]],
    [
      "火工品量",
      [
        ["detonators_count", "雷管", "发"],
        ["explosives_kg", "炸药", "kg"],
      ],
    ],
    ["入井人员量", [["mine_entry_persons", "入井人员量", "人次"]]],
    ["产量", [["production_t", "产量", "t"]]],
  ]);
  const METRICS = Object.freeze(
    FIVE_QUANTITIES.flatMap(([, metrics]) => metrics),
  );
  const METRIC_LABELS = Object.freeze({
    ventilation_m3_min: "风量",
    electricity_kwh: "电量",
    detonators_count: "火工品量（雷管）",
    explosives_kg: "火工品量（炸药）",
    mine_entry_persons: "入井人员量",
    labor_persons: "入井人员量",
    production_t: "产量",
  });
  const SCOPES = Object.freeze([
    ["daily_total", "日报合计"],
    ["zero_shift", "零点班"],
    ["eight_shift", "八点班"],
    ["four_shift", "四点班"],
  ]);
  const STATUS = Object.freeze({
    ready_review: "待复核",
    queued: "已确认，待发送",
    submitted: "已送达政府",
    quarantined: "已隔离",
    stored: "已安全收取",
    acknowledged: "已向政府确认收取",
    draft: "填写中",
    discarded: "已放弃",
  });
  const state = {
    csrf: "",
    principal: null,
    status: null,
    imports: [],
    drafts: [],
    currentDraft: null,
    risks: [],
    currentRisk: null,
    messages: [],
    response: null,
    showDiscarded: false,
    busy: new Set(),
  };

  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) =>
    String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  const shortHash = (value) => (value ? `${String(value).slice(0, 12)}…` : "—");
  const formatTime = (value) => {
    if (!value) return "—";
    const parsed = new Date(value);
    return Number.isNaN(parsed.valueOf()) ? String(value) : parsed.toLocaleString("zh-CN");
  };
  const statusText = (value) => STATUS[value] || value || "—";
  const metricLabel = (value) => METRIC_LABELS[value] || value || "未列明";
  const can = (permission) =>
    Boolean(
      state.principal &&
        Array.isArray(state.principal.permissions) &&
        state.principal.permissions.includes(permission),
    );
  const credentialsLocked = () =>
    Boolean(
      state.principal &&
        (state.principal.must_change_password || state.principal.temporary_demo),
    );

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    document.querySelectorAll("[data-fq-tab]").forEach((button) => {
      button.addEventListener("click", () => activateTab(button.dataset.fqTab));
    });
    $("fqRefreshInbox").addEventListener("click", () => loadInbox(true));
    $("fqRefreshDrafts").addEventListener("click", () => loadDrafts(true));
    $("fqRefreshRisks").addEventListener("click", () => loadRisks(true));
    $("fqRefreshAudit").addEventListener("click", () => loadAudit(true));
    $("fqShowDiscarded").addEventListener("change", (event) => {
      state.showDiscarded = event.target.checked;
      void Promise.all([loadInbox(true), loadDrafts(false)]);
    });
    $("fqUploadForm").addEventListener("submit", uploadFile);
    $("fqScanWatch").addEventListener("click", scanWatchedDirectories);
    $("fqPollRisks").addEventListener("click", pollRisks);
    $("fqDraftList").addEventListener("click", handleDraftListClick);
    $("fqImportRows").addEventListener("click", handleImportClick);
    $("fqRiskList").addEventListener("click", handleRiskListClick);
    $("fqDraftDetail").addEventListener("input", handleDraftEdit);
    $("fqDraftDetail").addEventListener("change", handleDraftEdit);
    $("fqDraftDetail").addEventListener("click", handleDraftAction);
    $("fqRiskDetail").addEventListener("click", handleRiskAction);
    $("fqRiskDetail").addEventListener("submit", handleRiskSubmit);
    $("fqRiskDetail").addEventListener("input", handleResponseEdit);
    $("fqRiskDetail").addEventListener("change", handleResponseEdit);
    window.addEventListener("focus", () => void refreshSession(false));
    const logoutButton = $("logoutButton");
    const loginButton = $("loginButton");
    if (logoutButton) logoutButton.addEventListener("click", () => window.setTimeout(resetSession, 200));
    if (loginButton) loginButton.addEventListener("click", () => window.setTimeout(() => refreshSession(true), 300));
    void refreshSession(true);
    window.setInterval(() => void refreshSession(false), 15000);
  }

  async function api(path, options = {}) {
    const method = (options.method || "GET").toUpperCase();
    const headers = { Accept: "application/json" };
    let body;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    if (!["GET", "HEAD", "OPTIONS"].includes(method) && state.csrf) {
      headers["X-CSRF-Token"] = state.csrf;
    }
    const response = await fetch(path, {
      method,
      headers,
      body,
      credentials: "same-origin",
      cache: "no-store",
    });
    const raw = await response.text();
    let payload = null;
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch (_error) {
        throw new Error(`服务返回了无法识别的内容（HTTP ${response.status}）`);
      }
    }
    if (!response.ok) {
      if (response.status === 401) resetSession();
      const errorMessage =
        (payload && payload.error && payload.error.message) ||
        (payload && payload.message) ||
        `请求失败（HTTP ${response.status}）`;
      const error = new Error(errorMessage);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  async function refreshSession(forceLoad) {
    try {
      const payload = await api("/api/v1/auth/me");
      const actorChanged =
        (state.principal && state.principal.actor_id) !==
        (payload.principal && payload.principal.actor_id);
      state.principal = payload.principal;
      state.csrf = payload.csrf_token;
      if (actorChanged || forceLoad || !state.status) await loadAll();
    } catch (error) {
      if (error.status !== 401) message(error.message, "error");
    }
  }

  function resetSession() {
    state.csrf = "";
    state.principal = null;
    state.status = null;
    state.currentDraft = null;
    state.currentRisk = null;
    state.response = null;
    message("请登录企业账号后继续。", "notice");
  }

  async function loadAll() {
    message("正在读取本矿工作状态…", "notice");
    const results = await Promise.allSettled([
      loadStatus(),
      loadInbox(false),
      loadDrafts(false),
      loadRisks(false),
      loadAudit(false),
    ]);
    const failed = results.find((item) => item.status === "rejected");
    if (failed) {
      message((failed.reason && failed.reason.message) || "部分数据加载失败。", "error");
    } else {
      message(`已连接：${(state.status && state.status.mine_name) || "本矿"}。`, "success");
    }
  }

  function message(text, kind = "notice") {
    const target = $("fqGlobalMessage");
    target.textContent = text;
    target.className = `fq-global-message is-${kind}`;
  }

  function setBusy(key, busy, label = "正在处理…") {
    if (busy) state.busy.add(key);
    else state.busy.delete(key);
    const element = $(key);
    if (!element) return;
    if (busy) {
      element.dataset.originalText = element.textContent;
      element.textContent = label;
      element.disabled = true;
    } else {
      element.textContent = element.dataset.originalText || element.textContent;
      element.disabled = false;
    }
  }

  function activateTab(name) {
    document.querySelectorAll("[data-fq-tab]").forEach((button) => {
      const active = button.dataset.fqTab === name;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    document.querySelectorAll("[data-fq-panel]").forEach((panel) => {
      const active = panel.dataset.fqPanel === name;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });
  }

  async function loadStatus() {
    state.status = await api("/api/v2/status");
    const directories = state.status.watched_directories || [];
    $("fqWatchSummary").textContent = directories.length
      ? `已配置 ${directories.length} 个受控目录：${directories.join("；")}`
      : "尚未配置固定监听目录；可继续使用人工上传或设备/API 接口。";
    $("fqIdentityCard").innerHTML = `
      <h3>本实例身份</h3>
      <dl class="fq-definition-list">
        <div><dt>煤矿</dt><dd>${escapeHtml(state.status.mine_name)}（${escapeHtml(state.status.mine_id)}）</dd></div>
        <div><dt>经营主体</dt><dd>${escapeHtml(state.status.operator_id)}</dd></div>
        <div><dt>智能体系统</dt><dd>${escapeHtml(state.status.system_id)}</dd></div>
      </dl>
      <p class="fq-safe-note">身份来自启动配置，页面无跨矿切换入口。</p>`;
    $("fqExchangeCard").innerHTML = `
      <h3>政府接口</h3>
      <p class="fq-big-state ${state.status.platform_configured ? "is-ok" : "is-warn"}">
        ${state.status.platform_configured ? "已配置，后台自动重试" : "未配置，仅保存本地待发消息"}
      </p>
      <dl class="fq-definition-list">
        <div><dt>最近确认游标</dt><dd>${escapeHtml(state.status.last_acknowledged_cursor || "尚无")}</dd></div>
        <div><dt>双层签名密钥</dt><dd>${state.status.platform_configured && state.status.distinct_application_and_transport_secrets ? "显式配置且相互独立" : "离线或未完成配置"}</dd></div>
        <div><dt>政府验签 key</dt><dd>${escapeHtml((state.status.regulator_verification_key_ids || []).join("、"))}</dd></div>
        <div><dt>采集方式</dt><dd>人工导入和直采均进入同一复核与报送流程</dd></div>
      </dl>`;
  }

  async function loadInbox(notify) {
    const query = state.showDiscarded ? "?include_discarded=true" : "";
    const payload = await api(`/api/v2/imports${query}`);
    state.imports = payload.items || [];
    renderImports();
    if (notify) message("收件箱已刷新。", "success");
  }

  function renderImports() {
    const rows = $("fqImportRows");
    if (!state.imports.length) {
      rows.innerHTML = '<tr><td colspan="6" class="fq-empty">暂无记录</td></tr>';
      return;
    }
    rows.innerHTML = state.imports
      .map(
        (item) => `<tr>
          <td>${escapeHtml(formatTime(item.created_at))}</td>
          <td><strong>${escapeHtml(item.filename)}</strong>${item.error_message ? `<small class="fq-error-text">${escapeHtml(item.error_message)}</small>` : ""}</td>
          <td>${item.acquisition_mode === "direct_collection" ? "直采" : "人工导入"}</td>
          <td><span class="fq-status is-${escapeHtml(item.status)}">${escapeHtml(statusText(item.status))}</span></td>
          <td><code title="${escapeHtml(item.content_sha256)}">${escapeHtml(shortHash(item.content_sha256))}</code></td>
          <td>${item.draft_id && item.status !== "discarded" ? `<button class="fq-link-button" data-open-draft="${escapeHtml(item.draft_id)}" type="button">去复核</button>` : "—"}</td>
        </tr>`,
      )
      .join("");
  }

  async function uploadFile(event) {
    event.preventDefault();
    const file = $("fqUploadFile").files[0];
    if (!file) return message("请先选择文件。", "error");
    if (file.size > 20 * 1024 * 1024) return message("文件超过 20 MiB，未上传。", "error");
    setBusy("fqUploadButton", true, "正在安全导入…");
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let offset = 0; offset < bytes.length; offset += 32768) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
      }
      const result = await api("/api/v2/imports", {
        method: "POST",
        body: { filename: file.name, content_base64: btoa(binary) },
      });
      $("fqUploadForm").reset();
      await Promise.all([loadInbox(false), loadDrafts(false), loadAudit(false)]);
      if (result.duplicate) message("同一内容已经接收过，本次未重复建稿。", "notice");
      else message("导入成功，已生成待人工复核草稿。", "success");
      if (result.draft_id) {
        activateTab("review");
        await openDraft(result.draft_id);
      }
    } catch (error) {
      message(error.message, "error");
    } finally {
      setBusy("fqUploadButton", false);
    }
  }

  async function scanWatchedDirectories() {
    setBusy("fqScanWatch", true, "正在扫描…");
    try {
      const payload = await api("/api/v2/watch/scan", { method: "POST", body: {} });
      await Promise.all([loadInbox(false), loadDrafts(false)]);
      message(
        payload.count
          ? `本次处理 ${payload.count} 个稳定文件；请进入复核页检查。`
          : "未发现新的稳定文件；新文件会在连续两次扫描保持不变后处理。",
        payload.count ? "success" : "notice",
      );
    } catch (error) {
      message(error.message, "error");
    } finally {
      setBusy("fqScanWatch", false);
    }
  }

  function handleImportClick(event) {
    const button = event.target.closest("[data-open-draft]");
    if (!button) return;
    activateTab("review");
    void openDraft(button.dataset.openDraft);
  }

  async function loadDrafts(notify) {
    const query = state.showDiscarded ? "?include_discarded=true" : "";
    const payload = await api(`/api/v2/drafts${query}`);
    state.drafts = payload.items || [];
    renderDraftList();
    if (notify) message("草稿列表已刷新。", "success");
  }

  function renderDraftList() {
    const target = $("fqDraftList");
    if (!state.drafts.length) {
      target.innerHTML = '<p class="fq-empty">暂无草稿</p>';
      return;
    }
    target.innerHTML = state.drafts
      .map((draft) => {
        const selected =
          state.currentDraft && state.currentDraft.draft_id === draft.draft_id;
        return `<button class="fq-list-item ${selected ? "is-selected" : ""}" data-draft-id="${escapeHtml(draft.draft_id)}" type="button">
          <span><strong>${escapeHtml(draft.payload.reporting_month)} 月报</strong><small>${escapeHtml(draft.payload.period_start)} 至 ${escapeHtml(draft.payload.period_end)}</small></span>
          <span class="fq-status is-${escapeHtml(draft.status)}">${escapeHtml(statusText(draft.status))}</span>
        </button>`;
      })
      .join("");
  }

  function handleDraftListClick(event) {
    const button = event.target.closest("[data-draft-id]");
    if (button) void openDraft(button.dataset.draftId);
  }

  async function openDraft(draftId) {
    try {
      state.currentDraft = await api(`/api/v2/drafts/${encodeURIComponent(draftId)}`);
      renderDraftList();
      renderDraft();
    } catch (error) {
      message(error.message, "error");
    }
  }

  function measurementSet(day, scope) {
    const measurements =
      scope === "daily_total"
        ? day.reported_quantity.daily_total
        : day.reported_quantity.shifts[scope].measurements;
    if (
      !measurements.mine_entry_persons &&
      measurements.labor_persons
    ) {
      measurements.mine_entry_persons = {
        ...measurements.labor_persons,
        metric_code: "mine_entry_persons",
        aggregation: "sum",
      };
      delete measurements.labor_persons;
    }
    return measurements;
  }

  function renderDraft() {
    const target = $("fqDraftDetail");
    const draft = state.currentDraft;
    if (!draft) return;
    const locked = ["queued", "submitted", "discarded"].includes(draft.status);
    const importRecord = state.imports.find(
      (item) => item.import_id === draft.import_id,
    );
    const importWarnings = ((importRecord && importRecord.suggestions) || []).filter(
      (item) => item.kind !== "column_mapping",
    );
    let missing = 0;
    for (const day of draft.payload.days) {
      for (const [scope] of SCOPES) {
        for (const [metric] of METRICS) {
          if (measurementSet(day, scope)[metric].value === null) missing += 1;
        }
      }
    }
    const days = draft.payload.days
      .map((day, dayIndex) => {
        let dayMissing = 0;
        for (const [scope] of SCOPES) {
          for (const [metric] of METRICS) {
            if (measurementSet(day, scope)[metric].value === null) dayMissing += 1;
          }
        }
        const groups = SCOPES.map(([scope, scopeLabel]) => {
          const values = measurementSet(day, scope);
          return `<div class="fq-measure-group"><h5>${scopeLabel}</h5><div class="fq-metric-grid">${FIVE_QUANTITIES.map(
            ([quantityLabel, metrics]) => `<section class="fq-quantity-group ${metrics.length > 1 ? "is-fire-material" : ""}"><h6>${quantityLabel}</h6>${metrics.map(
              ([metric, label, unit]) => {
                const measurement = values[metric];
                const integerMetric = ["detonators_count", "mine_entry_persons"].includes(metric);
                return `<label><span>${label}<small>${unit}</small></span><input type="number" min="0" step="${integerMetric ? "1" : "any"}" value="${measurement.value == null ? "" : measurement.value}" data-fq-value data-day="${dayIndex}" data-scope="${scope}" data-metric="${metric}" ${locked ? "disabled" : ""}><em>${measurement.value === null ? "缺失" : "已报告"}</em></label>`;
              },
            ).join("")}</section>`,
          ).join("")}</div></div>`;
        }).join("");
        return `<details class="fq-day-card" ${dayMissing ? "" : ""}>
          <summary><span><strong>${escapeHtml(day.date)}</strong><small>${dayMissing ? `${dayMissing} 个数据格缺失，需核对` : "五类数据均完整（含火工品两个子项）"}</small></span><span class="fq-status ${dayMissing ? "is-warn" : "is-ok"}">${dayMissing ? "待补充/说明" : "完整"}</span></summary>
          <label class="field fq-operating-state"><span>当日运行状态</span><select data-fq-operating-state data-day="${dayIndex}" ${locked ? "disabled" : ""}>${[
            ["producing", "生产"], ["stopped", "停产"], ["maintenance", "检修"], ["restarting", "复产过渡"], ["unknown", "待确认"],
          ].map(([value, label]) => `<option value="${value}" ${day.operating_state === value ? "selected" : ""}>${label}</option>`).join("")}</select></label>
          ${groups}
        </details>`;
      })
      .join("");
    const finalizeAllowed = can("confirm") && can("submit") && !credentialsLocked();
    const permissionHint = credentialsLocked()
      ? "当前为临时/演示账号，必须换成正式逐用户账号后才能确认报送。"
      : !finalizeAllowed
        ? "当前账号缺少确认或提交权限，可继续复核和保存。"
        : "确认后消息进入可靠发送队列；接收回执不代表监管认定正常。";
    target.innerHTML = `
      <div class="fq-detail-head"><div><p class="eyebrow">${escapeHtml(draft.payload.mine.mine_name)}</p><h3>${escapeHtml(draft.payload.reporting_month)} 五量月报</h3><p>${escapeHtml(draft.payload.period_start)} 至 ${escapeHtml(draft.payload.period_end)} · 修订 ${draft.revision}</p></div><span class="fq-status is-${escapeHtml(draft.status)}">${escapeHtml(statusText(draft.status))}</span></div>
      <div class="fq-summary-strip"><span><strong>${draft.payload.days.length}</strong>日报天数</span><span class="${missing ? "is-warn" : "is-ok"}"><strong>${missing}</strong>缺失测量</span><span><strong>${draft.payload.sources.length}</strong>来源记录</span><span><strong>${draft.submission_revision}</strong>报送版本</span></div>
      ${importWarnings.length ? `<div class="fq-import-warning"><strong>导入映射需要人工核对</strong><ul>${importWarnings.slice(0, 20).map((item) => `<li>${escapeHtml(item.reason || "存在未明确的来源字段")}</li>`).join("")}</ul></div>` : ""}
      <div class="fq-safe-note">空白保持为 null，系统不会用 0 或历史值填补。展开每一天可核对日报合计和三个班次。</div>
      <div class="fq-day-list">${days}</div>
      <div class="fq-sticky-actions">
        <button class="button button-secondary" type="button" data-fq-action="save-draft" ${locked || !can("write") ? "disabled" : ""}>保存复核修改</button>
        ${draft.status === "ready_review" && can("write") ? '<button class="button button-danger-quiet" type="button" data-fq-action="discard-draft">放弃草稿</button>' : ""}
        ${draft.status === "queued" ? '<button class="button button-primary" type="button" data-fq-action="send-draft">立即重试发送</button>' : ""}
      </div>
      <section class="fq-confirm-card">
        <h4>人工确认并报送</h4><p>${escapeHtml(permissionHint)}</p>
        <div class="fq-form-grid">
          <label class="field"><span>确认人姓名</span><input id="fqDraftConfirmerName" value="${escapeHtml((state.principal && state.principal.name) || "")}" ${locked ? "disabled" : ""}></label>
          <label class="field"><span>岗位/角色</span><input id="fqDraftConfirmerRole" value="${escapeHtml((state.principal && state.principal.role) || "企业填报员")}" ${locked ? "disabled" : ""}></label>
        </div>
        <label class="field"><span>确认说明</span><textarea id="fqDraftAttestation" rows="3" ${locked ? "disabled" : ""}>本人已对照原始日报、三个班次记录及单位口径逐项核对。</textarea></label>
        <label class="check-row"><input id="fqDraftAccepted" type="checkbox" ${locked ? "disabled" : ""}><span>我确认本月完整内容真实反映企业核对结果，并同意发送至政府监管平台。</span></label>
        <button class="button button-primary" type="button" data-fq-action="confirm-draft" ${locked || !finalizeAllowed ? "disabled" : ""}>确认并进入发送队列</button>
        ${draft.receipt ? `<div class="fq-receipt"><strong>政府已接收</strong><span>回执：${escapeHtml((draft.receipt.payload && draft.receipt.payload.receipt_id) || draft.receipt.message_id)}</span><small>政府接收并排队，不等于监管结论。</small></div>` : ""}
      </section>`;
  }

  function handleDraftEdit(event) {
    if (!state.currentDraft || ["queued", "submitted"].includes(state.currentDraft.status)) return;
    const input = event.target;
    const dayIndex = Number(input.dataset.day);
    if (!Number.isInteger(dayIndex)) return;
    const day = state.currentDraft.payload.days[dayIndex];
    if (input.matches("[data-fq-operating-state]")) {
      day.operating_state = input.value;
      return;
    }
    if (!input.matches("[data-fq-value]")) return;
    const measurement = measurementSet(day, input.dataset.scope)[input.dataset.metric];
    if (input.value.trim() === "") {
      measurement.value = null;
      measurement.quality_flags = ["missing"];
    } else {
      measurement.value = Number(input.value);
      measurement.quality_flags = [
        "reported",
        ...(measurement.quality_flags || []).filter(
          (flag) => !["reported", "missing", "unavailable", "not_applicable"].includes(flag),
        ),
      ];
    }
    input.parentElement.querySelector("em").textContent = measurement.value === null ? "缺失" : "已报告";
  }

  async function handleDraftAction(event) {
    const button = event.target.closest("[data-fq-action]");
    if (!button || !state.currentDraft) return;
    const action = button.dataset.fqAction;
    let discardReason = "";
    if (action === "discard-draft") {
      const entered = window.prompt(
        "请输入放弃原因。草稿与原始导入仍会保留在审计记录中。",
        "重复导入或本次无需报送",
      );
      if (entered === null) return;
      discardReason = entered.trim();
      if (!discardReason) return message("请填写放弃原因。", "error");
    }
    button.disabled = true;
    try {
      if (action === "save-draft") {
        state.currentDraft = await api(`/api/v2/drafts/${encodeURIComponent(state.currentDraft.draft_id)}`, {
          method: "PATCH",
          body: { expected_revision: state.currentDraft.revision, payload: state.currentDraft.payload },
        });
        message("复核修改已保存。", "success");
      } else if (action === "confirm-draft") {
        if (!$("fqDraftAccepted").checked) throw new Error("请先勾选人工确认声明。");
        state.currentDraft = await api(`/api/v2/drafts/${encodeURIComponent(state.currentDraft.draft_id)}/confirm`, {
          method: "POST",
          body: {
            expected_revision: state.currentDraft.revision,
            confirmer_name: $("fqDraftConfirmerName").value.trim(),
            confirmer_role: $("fqDraftConfirmerRole").value.trim(),
            attestation: $("fqDraftAttestation").value.trim(),
            accepted: true,
          },
        });
        message("已完成企业确认，消息已可靠入队并会自动重试。", "success");
      } else if (action === "send-draft") {
        await api(`/api/v2/drafts/${encodeURIComponent(state.currentDraft.draft_id)}/send-now`, { method: "POST", body: {} });
        state.currentDraft = await api(`/api/v2/drafts/${encodeURIComponent(state.currentDraft.draft_id)}`);
        message("已执行一次发送；失败时仍会保留并后台重试。", "success");
      } else if (action === "discard-draft") {
        await api(`/api/v2/drafts/${encodeURIComponent(state.currentDraft.draft_id)}`, {
          method: "DELETE",
          body: {
            expected_revision: state.currentDraft.revision,
            reason: discardReason,
          },
        });
        state.currentDraft = null;
        $("fqDraftDetail").innerHTML = '<div class="fq-empty-state"><h3>草稿已放弃</h3><p>内容未物理删除，可在收件箱勾选“查看已放弃记录”追溯。</p></div>';
        await Promise.all([loadInbox(false), loadDrafts(false), loadAudit(false)]);
        activateTab("inbox");
        message("草稿已放弃并写入审计链；原始导入和草稿内容仍保留。", "success");
        return;
      }
      await Promise.all([loadDrafts(false), loadAudit(false)]);
      renderDraft();
    } catch (error) {
      message(error.message, "error");
      button.disabled = false;
    }
  }

  async function loadRisks(notify) {
    const payload = await api("/api/v2/risks");
    state.risks = payload.items || [];
    renderRiskList();
    const count = state.risks.length;
    $("fqRiskCount").hidden = count === 0;
    $("fqRiskCount").textContent = String(count);
    if (notify) message("风险列表已刷新。", "success");
  }

  function renderRiskList() {
    const target = $("fqRiskList");
    if (!state.risks.length) {
      target.innerHTML = '<p class="fq-empty">暂无风险报告</p>';
      return;
    }
    target.innerHTML = state.risks
      .map((record) => {
        const payload = record.report.payload;
        const selected =
          state.currentRisk && state.currentRisk.report_id === record.report_id;
        return `<button class="fq-list-item ${selected ? "is-selected" : ""}" data-report-id="${escapeHtml(record.report_id)}" type="button"><span><strong>${escapeHtml(payload.reporting_month)} · ${payload.outcome === "risk" ? "风险" : "数据不足"}</strong><small>${escapeHtml(payload.summary)}</small></span><span class="fq-status is-risk">${payload.findings.length} 项</span></button>`;
      })
      .join("");
  }

  function handleRiskListClick(event) {
    const button = event.target.closest("[data-report-id]");
    if (button) void openRisk(button.dataset.reportId);
  }

  async function pollRisks() {
    setBusy("fqPollRisks", true, "正在安全拉取…");
    try {
      const payload = await api("/api/v2/risks/poll", { method: "POST", body: {} });
      await Promise.all([loadRisks(false), loadAudit(false)]);
      message(payload.result ? "新报告已验签并保存到本地收件箱。" : "目前没有新的风险报告。", payload.result ? "success" : "notice");
    } catch (error) {
      message(error.message, "error");
    } finally {
      setBusy("fqPollRisks", false);
    }
  }

  async function openRisk(reportId) {
    try {
      state.currentRisk = await api(`/api/v2/risks/${encodeURIComponent(reportId)}`);
      const chat = await api(`/api/v2/risks/${encodeURIComponent(reportId)}/chat`);
      state.messages = chat.items || [];
      state.response = null;
      renderRiskList();
      renderRisk();
    } catch (error) {
      message(error.message, "error");
    }
  }

  function renderRisk() {
    const target = $("fqRiskDetail");
    if (!state.currentRisk) return;
    const payload = state.currentRisk.report.payload;
    const findings = payload.findings
      .map(
        (finding, index) => `<article class="fq-finding">
          <div class="fq-finding-head"><span class="fq-severity is-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span><div><small>风险 ${index + 1}</small><h4>${escapeHtml(finding.title)}</h4></div></div>
          <p>${escapeHtml(finding.summary)}</p>
          <dl class="fq-definition-list"><div><dt>日期</dt><dd>${escapeHtml((finding.affected_dates || []).join("、") || "未列明")}</dd></div><div><dt>指标</dt><dd>${escapeHtml((finding.affected_metrics || []).map(metricLabel).join("、") || "未列明")}</dd></div></dl>
          <details><summary>查看算法证据</summary>${(finding.evidence || []).map((evidence) => `<div class="fq-evidence"><strong>${escapeHtml(evidence.method)}</strong><span>${escapeHtml(evidence.summary)}</span><small>观测 ${escapeHtml(evidence.observed_value == null ? "—" : evidence.observed_value)}；参考 ${escapeHtml(evidence.expected_min == null ? "—" : evidence.expected_min)}～${escapeHtml(evidence.expected_max == null ? "—" : evidence.expected_max)}；分数 ${escapeHtml(evidence.score == null ? "—" : evidence.score)}</small></div>`).join("")}</details>
        </article>`,
      )
      .join("");
    const messages = state.messages.length
      ? state.messages.map((item) => `<div class="fq-chat-message is-${escapeHtml(item.role)}"><strong>${item.role === "assistant" ? "煤矿风险助手" : "企业人员"}</strong><p>${escapeHtml(item.content)}</p>${item.tools && item.tools.length ? `<small>只读工具：${escapeHtml(item.tools.join("、"))}</small>` : ""}</div>`).join("")
      : '<p class="fq-empty">可询问“为什么提示这个风险”“该核对哪些原始记录”等。</p>';
    target.innerHTML = `
      <div class="fq-detail-head"><div><p class="eyebrow">${escapeHtml(payload.mine.mine_name)}</p><h3>${escapeHtml(payload.reporting_month)} 算法报告</h3><p>政府签发 ${escapeHtml(formatTime(payload.issued_at))} · 回复期限 ${escapeHtml(formatTime(payload.response_due_at))}</p></div><span class="fq-status is-risk">${payload.outcome === "risk" ? "需回复" : "数据不足"}</span></div>
      <div class="fq-risk-summary"><strong>算法结论</strong><p>${escapeHtml(payload.summary)}</p><small>引擎 ${escapeHtml(payload.algorithm.engine_id)} ${escapeHtml(payload.algorithm.engine_version)}；模块：${escapeHtml(payload.algorithm.modules.join("、"))}</small></div>
      <div class="fq-findings">${findings}</div>
      <section class="fq-chat"><div class="fq-section-head"><div><h4>围绕本报告对话</h4><p>不能查新闻、闲聊或替企业编造原因。</p></div></div><div class="fq-chat-log" id="fqChatLog">${messages}</div><form id="fqChatForm" class="fq-chat-form"><textarea id="fqChatQuestion" rows="2" maxlength="2000" placeholder="例如：L1 求解器为什么把 7 月 31 日列入核对范围？" required></textarea><button class="button button-secondary" type="submit">询问</button></form></section>
      <section id="fqResponseArea">${state.response ? responseHtml(state.response) : `<div class="fq-response-start"><div><h4>形成企业回执</h4><p>逐项填写事实原因、证据索引和措施，人工确认后发送。</p></div><button class="button button-primary" type="button" data-risk-action="create-response" ${!can("write") ? "disabled" : ""}>开始填写回执</button></div>`}</section>`;
  }

  function responseHtml(response) {
    const locked = ["queued", "submitted"].includes(response.status);
    const reasonOptions = [
      ["equipment_maintenance", "设备检修"], ["power_outage", "停电"], ["planned_shutdown", "计划停产"], ["restart_transition", "停复产过渡"], ["geology_change", "地质变化"], ["production_plan_change", "生产计划变化"], ["shift_arrangement", "班次安排"], ["ventilation_adjustment", "通风调整"], ["blasting_plan_change", "爆破计划变化"], ["meter_or_source_error", "仪表/来源错误"], ["transcription_or_mapping_error", "抄录/映射错误"], ["other", "其他"], ["unknown_under_investigation", "仍在调查"],
    ];
    const responseKinds = [["explanation", "事实说明"], ["correction_submitted", "已提交更正报表"], ["clarification_request", "请求澄清"], ["unable_to_determine", "暂无法确定"]];
    const cards = response.document.finding_responses.map((item, index) => {
      const action = (item.actions && item.actions[0]) || null;
      return `<article class="fq-response-finding"><h5>回复风险 ${index + 1}</h5>
        <div class="fq-form-grid"><label class="field"><span>回复类型</span><select data-response-field="response_kind" data-response-index="${index}" ${locked ? "disabled" : ""}>${responseKinds.map(([value,label]) => `<option value="${value}" ${item.response_kind === value ? "selected" : ""}>${label}</option>`).join("")}</select></label><label class="field"><span>原因分类</span><select data-response-field="reason_code" data-response-index="${index}" ${locked ? "disabled" : ""}>${reasonOptions.map(([value,label]) => `<option value="${value}" ${item.reason_code === value ? "selected" : ""}>${label}</option>`).join("")}</select></label></div>
        <label class="field"><span>核实事实（不能只写“情况属实”）</span><textarea rows="4" data-response-field="facts" data-response-index="${index}" ${locked ? "disabled" : ""}>${escapeHtml(item.facts)}</textarea></label>
        <div class="fq-form-grid"><label class="field"><span>证据编号（多个用逗号）</span><input data-response-field="evidence_refs" data-response-index="${index}" value="${escapeHtml((item.evidence_refs || []).join(","))}" ${locked ? "disabled" : ""}></label><label class="field"><span>更正报表消息 ID（仅“已更正”填写）</span><input data-response-field="corrected_submission_message_id" data-response-index="${index}" value="${escapeHtml(item.corrected_submission_message_id || "")}" ${locked ? "disabled" : ""}></label></div>
        <label class="check-row"><input type="checkbox" data-response-action="enabled" data-response-index="${index}" ${action ? "checked" : ""} ${locked ? "disabled" : ""}><span>记录调查/整改措施</span></label>
        <div class="fq-form-grid"><label class="field"><span>措施类型</span><select data-response-action="action_type" data-response-index="${index}" ${!action || locked ? "disabled" : ""}>${[["investigation","调查"],["data_correction","数据更正"],["corrective","纠正措施"],["preventive","预防措施"]].map(([v,l]) => `<option value="${v}" ${action && action.action_type === v ? "selected" : ""}>${l}</option>`).join("")}</select></label><label class="field"><span>状态</span><select data-response-action="status" data-response-index="${index}" ${!action || locked ? "disabled" : ""}>${[["planned","计划中"],["in_progress","进行中"],["completed","已完成"],["not_applicable","不适用"]].map(([v,l]) => `<option value="${v}" ${action && action.status === v ? "selected" : ""}>${l}</option>`).join("")}</select></label></div><label class="field"><span>措施说明</span><input data-response-action="description" data-response-index="${index}" value="${escapeHtml((action && action.description) || "")}" ${!action || locked ? "disabled" : ""}></label>
      </article>`;
    }).join("");
    const attachments = response.document.attachments.length
      ? response.document.attachments.map((item, index) => `<div class="fq-attachment" data-attachment-index="${index}"><div class="fq-form-grid"><label class="field"><span>证据编号</span><input data-attachment-field="evidence_id" value="${escapeHtml(item.evidence_id)}" ${locked ? "disabled" : ""}></label><label class="field"><span>标题</span><input data-attachment-field="title" value="${escapeHtml(item.title)}" ${locked ? "disabled" : ""}></label><label class="field"><span>媒体类型</span><input data-attachment-field="media_type" value="${escapeHtml(item.media_type)}" ${locked ? "disabled" : ""}></label><label class="field"><span>文件大小（字节）</span><input type="number" min="0" data-attachment-field="size_bytes" value="${escapeHtml(item.size_bytes)}" ${locked ? "disabled" : ""}></label></div><label class="field"><span>原件 SHA-256</span><input maxlength="64" data-attachment-field="sha256" value="${escapeHtml(item.sha256)}" ${locked ? "disabled" : ""}></label>${locked ? "" : `<button class="fq-link-button is-danger" type="button" data-risk-action="remove-attachment" data-index="${index}">移除证据索引</button>`}</div>`).join("")
      : '<p class="fq-empty">尚未登记证据。原始文件留在企业本地，只向政府发送内容摘要和索引。</p>';
    const finalizeAllowed = can("confirm") && can("submit") && !credentialsLocked();
    return `<div class="fq-response-editor"><div class="fq-section-head"><div><h4>结构化企业回执</h4><p>状态：${escapeHtml(statusText(response.status))} · 修订 ${response.revision}</p></div></div>${cards}<div class="fq-section-head"><div><h5>证据索引</h5><p>不在这里上传原件；原件保留于企业受控位置。</p></div>${locked ? "" : '<button class="button button-secondary" type="button" data-risk-action="add-attachment">添加证据索引</button>'}</div><div id="fqAttachments">${attachments}</div><div class="fq-sticky-actions"><button class="button button-secondary" type="button" data-risk-action="save-response" ${locked || !can("write") ? "disabled" : ""}>保存回执草稿</button></div><section class="fq-confirm-card"><h4>人工确认回复</h4><div class="fq-form-grid"><label class="field"><span>确认人姓名</span><input id="fqResponseConfirmerName" value="${escapeHtml((state.principal && state.principal.name) || "")}" ${locked ? "disabled" : ""}></label><label class="field"><span>岗位/角色</span><input id="fqResponseConfirmerRole" value="${escapeHtml((state.principal && state.principal.role) || "企业负责人")}" ${locked ? "disabled" : ""}></label></div><label class="field"><span>确认说明</span><textarea id="fqResponseAttestation" rows="3" ${locked ? "disabled" : ""}>本人确认上述事实、证据索引和措施已经企业核实。</textarea></label><label class="check-row"><input id="fqResponseAccepted" type="checkbox" ${locked ? "disabled" : ""}><span>我确认并同意向政府发送本回复；理解接收回执不代表风险已消除。</span></label><button class="button button-primary" type="button" data-risk-action="confirm-response" ${locked || !finalizeAllowed ? "disabled" : ""}>确认并发送回复</button>${response.receipt ? `<div class="fq-receipt"><strong>政府已记录回复</strong><span>${escapeHtml((response.receipt.payload && response.receipt.payload.receipt_id) || response.receipt.message_id)}</span><small>风险状态：未因接收回执自动消除。</small></div>` : ""}</section></div>`;
  }

  async function handleRiskSubmit(event) {
    if (event.target.id !== "fqChatForm") return;
    event.preventDefault();
    const question = $("fqChatQuestion").value.trim();
    if (!question) return;
    const button = event.target.querySelector("button");
    button.disabled = true;
    try {
      const payload = await api(`/api/v2/risks/${encodeURIComponent(state.currentRisk.report_id)}/chat`, { method: "POST", body: { question } });
      state.messages = payload.messages || [];
      renderRisk();
      message("已基于当前风险报告完成解释。", "success");
    } catch (error) {
      message(error.message, "error");
      button.disabled = false;
    }
  }

  function handleResponseEdit(event) {
    if (!state.response || ["queued", "submitted"].includes(state.response.status)) return;
    const input = event.target;
    const responseIndex = Number(input.dataset.responseIndex);
    if (Number.isInteger(responseIndex)) {
      const item = state.response.document.finding_responses[responseIndex];
      if (input.dataset.responseField) {
        const field = input.dataset.responseField;
        if (field === "evidence_refs") item[field] = input.value.split(/[,，]/).map((value) => value.trim()).filter(Boolean);
        else if (field === "corrected_submission_message_id") item[field] = input.value.trim() || null;
        else item[field] = input.value;
      }
      if (input.dataset.responseAction) {
        const field = input.dataset.responseAction;
        if (field === "enabled") {
          item.actions = input.checked ? [{ action_type: "investigation", description: "待填写具体措施。", status: "planned" }] : [];
          renderRisk();
          return;
        }
        if (item.actions[0]) item.actions[0][field] = input.value;
      }
    }
    const attachment = input.closest("[data-attachment-index]");
    if (attachment && input.dataset.attachmentField) {
      const item = state.response.document.attachments[Number(attachment.dataset.attachmentIndex)];
      item[input.dataset.attachmentField] = input.dataset.attachmentField === "size_bytes" ? Number(input.value) : input.value.trim();
    }
  }

  async function handleRiskAction(event) {
    const button = event.target.closest("[data-risk-action]");
    if (!button || !state.currentRisk) return;
    const action = button.dataset.riskAction;
    try {
      if (action === "create-response") {
        state.response = await api(`/api/v2/risks/${encodeURIComponent(state.currentRisk.report_id)}/response`, { method: "POST", body: {} });
      } else if (action === "add-attachment") {
        state.response.document.attachments.push({ evidence_id: `EVID-${Date.now()}`, title: "待填写证据标题", media_type: "application/pdf", size_bytes: 0, sha256: "", retention_location: "enterprise_local" });
      } else if (action === "remove-attachment") {
        const removed = state.response.document.attachments.splice(Number(button.dataset.index), 1)[0];
        for (const item of state.response.document.finding_responses) item.evidence_refs = item.evidence_refs.filter((id) => id !== removed.evidence_id);
      } else if (action === "save-response") {
        state.response = await api(`/api/v2/responses/${encodeURIComponent(state.response.response_id)}`, { method: "PATCH", body: { expected_revision: state.response.revision, document: state.response.document } });
        message("回执草稿已保存。", "success");
      } else if (action === "confirm-response") {
        if (!$("fqResponseAccepted").checked) throw new Error("请先勾选人工确认声明。");
        state.response = await api(`/api/v2/responses/${encodeURIComponent(state.response.response_id)}/confirm`, { method: "POST", body: { expected_revision: state.response.revision, confirmer_name: $("fqResponseConfirmerName").value.trim(), confirmer_role: $("fqResponseConfirmerRole").value.trim(), attestation: $("fqResponseAttestation").value.trim(), accepted: true } });
        message("企业回复已确认并进入可靠发送队列。", "success");
      }
      renderRisk();
      await loadAudit(false);
    } catch (error) {
      message(error.message, "error");
      button.disabled = false;
    }
  }

  async function loadAudit(notify) {
    const payload = await api("/api/v2/audit");
    $("fqAuditIntegrity").textContent = payload.valid
      ? `完整性校验通过 · 链头 ${shortHash(payload.head_hash)}`
      : "完整性校验失败，请停止报送并联系管理员";
    $("fqAuditIntegrity").className = payload.valid ? "is-ok" : "is-error";
    const events = [...(payload.events || [])].reverse();
    $("fqAuditEvents").innerHTML = events.length
      ? events.map((event) => `<article><span class="fq-timeline-dot" aria-hidden="true"></span><div><strong>${escapeHtml(event.event_type)}</strong><p>${escapeHtml(formatTime(event.occurred_at))} · ${escapeHtml(event.actor)}</p><small>序号 ${event.sequence} · ${escapeHtml(shortHash(event.event_hash))}</small></div></article>`).join("")
      : '<p class="fq-empty">暂无留痕</p>';
    if (notify) message("身份、接口和留痕状态已刷新。", "success");
  }
})();
