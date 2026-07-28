"use strict";

const state = {
  token: window.localStorage.getItem("mineEdgeApiToken") || "",
  refreshing: false,
};

const labels = {
  coal_output: "出煤",
  electricity: "用电",
  personnel: "人员",
  methane: "瓦斯",
  explosives: "火工品",
  ventilation: "通风",
  blue: "蓝色",
  yellow: "黄色",
  orange: "橙色",
  red: "红色",
  healthy: "正常",
  degraded: "需关注",
  failed: "失败",
  disabled: "已暂停",
  starting: "启动中",
  ok: "正常",
  missing_data: "缺数",
  source_failure: "采集失败",
  partial_records_rejected: "部分记录被拒绝",
  awaiting_first_poll: "等待首次采集",
  worker_stopped: "调度线程停止",
};

function authHeaders() {
  return state.token ? { Authorization: `Bearer ${state.token}` } : {};
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.error && body.error.message;
    throw new Error(detail || `请求失败（${response.status}）`);
  }
  return body;
}

function text(id, value) {
  document.getElementById(id).textContent = String(
    value === null || value === undefined ? "—" : value,
  );
}

function displayTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN");
}

async function loadHealth() {
  const badge = document.getElementById("connectionBadge");
  try {
    const health = await api("/api/v1/health");
    badge.textContent =
      health.status === "ok"
        ? "运行正常"
        : health.database && health.database.ok === false
          ? "本机存储异常"
          : "有来源需关注";
    badge.className = `badge ${health.status === "ok" ? "ok" : "bad"}`;
    text("mineName", health.mine_id);
    text("clientName", `边缘客户端：${health.client_id}`);
    text("observationCount", health.stats.observations);
    text("alertCount", health.stats.alerts);
    text("pendingCount", health.stats.outbox_pending);
    text("deliveredCount", health.stats.outbox_delivered);
    const sourceSummary = health.sources_summary || {};
    text(
      "sourceHealthCount",
      `${sourceSummary.healthy || 0}/${sourceSummary.enabled || 0}`,
    );
    text(
      "sourceHealthHint",
      sourceSummary.attention
        ? `${sourceSummary.attention} 个来源需关注`
        : sourceSummary.starting
          ? `${sourceSummary.starting} 个来源正在启动`
        : "启用来源中健康数量",
    );
    document.getElementById("calibrationWarning").hidden =
      Boolean(health.thresholds_calibrated);
  } catch (error) {
    badge.textContent = "无法连接";
    badge.className = "badge bad";
  }
}

async function sourceAction(sourceId, action) {
  await api(`/api/v1/sources/${encodeURIComponent(sourceId)}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  await Promise.all([loadSources(), loadHealth()]);
}

function sourceButton(label, action, source, secondary = false) {
  const button = document.createElement("button");
  button.textContent = label;
  if (secondary) button.className = "secondary";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await sourceAction(source.source_id, action);
    } catch (error) {
      button.textContent = error.message;
      window.setTimeout(() => {
        button.textContent = label;
      }, 2500);
    } finally {
      window.setTimeout(() => {
        button.disabled = false;
      }, 1000);
    }
  });
  return button;
}

async function loadSources() {
  const list = document.getElementById("sourcesList");
  try {
    const body = await api("/api/v1/sources");
    list.replaceChildren();
    if (!body.items.length) {
      list.className = "source-grid empty-state";
      list.textContent = "尚未配置连续采集来源；可继续使用手工导入和受控推送。";
      return;
    }
    list.className = "source-grid";
    for (const source of body.items) {
      const card = document.createElement("article");
      card.className = "source-card";
      const header = document.createElement("header");
      const title = document.createElement("h3");
      title.textContent = source.source_id;
      const health = document.createElement("span");
      health.className = `health-chip ${source.health}`;
      health.textContent = labels[source.health] || source.health;
      header.append(title, health);

      const details = document.createElement("dl");
      details.className = "source-meta";
      const rows = [
        ["适配器", source.adapter],
        ["当前信号", labels[source.signal] || source.signal],
        ["调度心跳", displayTime(source.last_heartbeat_at)],
        ["最后成功", displayTime(source.last_success_at)],
        ["最后有效数据", displayTime(source.last_data_at)],
        ["连续失败", source.consecutive_failures],
        ["累计入库", source.records_inserted],
        ["读取状态", source.in_flight ? "读取中/等待底层返回" : "空闲"],
        ["下次采集", displayTime(source.next_run_at)],
      ];
      if (source.last_error) rows.push(["最近错误", source.last_error]);
      for (const [name, value] of rows) {
        const term = document.createElement("dt");
        term.textContent = name;
        const description = document.createElement("dd");
        description.textContent = String(value);
        details.append(term, description);
      }

      const actions = document.createElement("div");
      actions.className = "source-actions";
      if (source.enabled) {
        actions.append(
          sourceButton("立即采集", "run-now", source, true),
          sourceButton("暂停采集", "disable", source, true),
        );
      } else {
        actions.append(sourceButton("启用采集", "enable", source));
      }
      card.append(header, details, actions);
      list.append(card);
    }
  } catch (error) {
    list.className = "source-grid empty-state";
    list.textContent = error.message;
  }
}

async function loadAlerts() {
  const list = document.getElementById("alertsList");
  try {
    const body = await api("/api/v1/alerts?limit=50");
    list.replaceChildren();
    if (!body.items.length) {
      list.className = "list empty-state";
      list.textContent = "暂无预警";
      return;
    }
    list.className = "list";
    const levelOrder = { red: 4, orange: 3, yellow: 2, blue: 1 };
    body.items.sort((a, b) => levelOrder[b.level] - levelOrder[a.level]);
    for (const alert of body.items) {
      const item = document.createElement("article");
      item.className = `alert-item ${alert.level}`;
      const stripe = document.createElement("span");
      stripe.className = "alert-stripe";
      const detail = document.createElement("div");
      const title = document.createElement("h3");
      title.textContent = alert.title;
      const message = document.createElement("p");
      message.textContent = alert.message;
      detail.append(title, message);
      const side = document.createElement("div");
      const level = document.createElement("div");
      level.className = "level";
      level.textContent = labels[alert.level] || alert.level;
      const time = document.createElement("time");
      time.textContent = displayTime(alert.triggered_at);
      side.append(level, time);
      item.append(stripe, detail, side);
      list.append(item);
    }
  } catch (error) {
    list.className = "list empty-state";
    list.textContent = error.message;
  }
}

async function loadObservations() {
  const tbody = document.getElementById("observationsBody");
  try {
    const body = await api("/api/v1/observations?limit=100");
    tbody.replaceChildren();
    for (const observation of body.items) {
      const row = document.createElement("tr");
      const values = [
        displayTime(observation.observed_at),
        labels[observation.kind] || observation.kind,
        observation.location_code,
        observation.metric,
        `${observation.value} ${observation.unit}`,
      ];
      for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.append(cell);
      }
      const source = document.createElement("td");
      const isManual = observation.provenance.channel === "manual";
      source.textContent = isManual
        ? `人工：${observation.provenance.operator_id}`
        : observation.provenance.source_id;
      if (isManual) source.className = "source-manual";
      row.append(source);
      tbody.append(row);
    }
    if (!body.items.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 6;
      cell.className = "empty-state";
      cell.textContent = "尚未收到观测数据";
      row.append(cell);
      tbody.append(row);
    }
  } catch (error) {
    tbody.replaceChildren();
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-state";
    cell.textContent = error.message;
    row.append(cell);
    tbody.append(row);
  }
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    await loadHealth();
    await Promise.all([loadSources(), loadAlerts(), loadObservations()]);
  } finally {
    state.refreshing = false;
  }
}

document.getElementById("apiToken").value = state.token;
document.getElementById("saveTokenButton").addEventListener("click", async () => {
  state.token = document.getElementById("apiToken").value.trim();
  window.localStorage.setItem("mineEdgeApiToken", state.token);
  await refresh();
});

document.getElementById("flushButton").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = "正在上报…";
  try {
    const body = await api("/api/v1/outbox/flush", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const result = body.results[0];
    button.textContent =
      result.status === "delivered" ? `已上报 ${result.events} 条` : "当前无需上报";
    await loadHealth();
  } catch (error) {
    button.textContent = error.message;
  } finally {
    window.setTimeout(() => {
      button.disabled = false;
      button.textContent = "立即尝试上报";
    }, 2500);
  }
});

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const item of document.querySelectorAll(".tab")) {
      item.classList.toggle("active", item === tab);
    }
    for (const view of document.querySelectorAll(".tab-view")) {
      view.hidden = view.id !== tab.dataset.target;
    }
  });
}

for (const button of document.querySelectorAll(".refresh-button")) {
  button.addEventListener("click", refresh);
}

document.getElementById("manualForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const result = document.getElementById("manualResult");
  const values = Object.fromEntries(new FormData(event.currentTarget));
  const observed = new Date(values.observed_at);
  const numeric = Number(values.value);
  const value = Number.isNaN(numeric) ? values.value : numeric;
  const payload = {
    kind: values.kind,
    metric: values.metric,
    value,
    unit: values.unit,
    location_code: values.location_code,
    observed_at: observed.toISOString(),
    provenance: {
      channel: "manual",
      source_id: values.source_id,
      operator_id: values.operator_id,
      reason: values.reason,
      evidence_ref: values.evidence_ref,
    },
  };
  result.textContent = "正在保存…";
  try {
    const body = await api("/api/v1/ingest/manual", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    result.textContent = body.duplicate
      ? `该记录已存在（${body.observation_id}）`
      : `补录成功，已进入上报队列（${body.observation_id}）`;
    await refresh();
  } catch (error) {
    result.textContent = `补录失败：${error.message}`;
  }
});

const now = new Date();
now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
document.querySelector("[name=observed_at]").value = now.toISOString().slice(0, 16);

refresh();
window.setInterval(refresh, 10000);
