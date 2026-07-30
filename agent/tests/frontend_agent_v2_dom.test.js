"use strict";

const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const projectRoot = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(projectRoot, "web", "index.html"), "utf8");
const app = fs.readFileSync(path.join(projectRoot, "web", "app.js"), "utf8");

assert(!app.toLowerCase().includes("</script"), "app.js cannot close inline script");

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function jsonResponse(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        return String(name).toLowerCase() === "content-type"
          ? "application/json"
          : "";
      },
    },
    async json() {
      return clone(payload);
    },
    async text() {
      return payload === null ? "" : JSON.stringify(payload);
    },
  };
}

function waitFor(predicate, message, timeoutMs = 4000) {
  const startedAt = Date.now();
  return new Promise((resolve, reject) => {
    function poll() {
      try {
        if (predicate()) {
          resolve();
          return;
        }
      } catch (error) {
        reject(error);
        return;
      }
      if (Date.now() - startedAt >= timeoutMs) {
        reject(new Error(`Timed out: ${message}`));
        return;
      }
      setTimeout(poll, 10);
    }
    poll();
  });
}

const draftSummary = {
  draft_id: "draft-v2-1",
  status: "draft",
  enterprise_name: "智能巡检示范煤业",
  mine_id: "MINE-V2-1",
  updated_at: "2026-07-30T08:00:00Z",
};

const draftDetail = {
  ...draftSummary,
  revision: 3,
  enterprise_id: "ENT-V2-1",
  unified_social_credit_code: "91140100MA0ABCDEF1",
  mine_name: "智能巡检一号矿",
  window_start: "2026-07-01T00:00:00Z",
  window_end: "2026-07-31T23:59:59Z",
  profile_id: "production-default",
  profile_version: "1",
  operational_context: {
    regime_code: "NORMAL_PRODUCTION",
    shift_code: "DAILY",
    season_code: "SUMMER",
    maintenance: false,
    approved_event_codes: [],
  },
  field_provenance: {
    "/operational_context/approved_event_codes": [
      {
        source_name: "监管事件查询结果",
        source_kind: "regulator_snapshot",
        locator: "event-registry/result",
        content_sha256: "a".repeat(64),
        extraction_method: "regulator_event_snapshot_import",
      },
    ],
  },
  sources: [],
  observations: [],
  questions: [],
  approval_events: [],
  signature: { valid: false },
  _meta: { revision: 3, updated_at: "2026-07-30T08:00:00Z" },
};

const completedFlow = {
  flow_id: "flow-existing",
  workflow_name: "daily_coal_health",
  draft_id: "draft-v2-1",
  status: "succeeded",
  revision: 3,
  trigger_type: "schedule",
  current_step: "brief",
  created_at: "2026-07-30T08:05:00Z",
  updated_at: "2026-07-30T08:06:00Z",
  completed_at: "2026-07-30T08:06:00Z",
  dispatch_ready: true,
  integrity: { valid: true },
  summary: {
    executive_summary: "整体数据可以继续核对，但库存来源仍需补充一份原始凭证。",
    attention_items: ["期末库存缺少来源材料，请经办人补充后再作事实确认。"],
  },
  steps: [
    {
      step_key: "source",
      title: "source",
      specialist: "来源凭证专家",
      status: "succeeded",
      summary: "已检查字段级来源绑定。",
    },
    {
      step_key: "critic",
      title: "critic",
      specialist: "反方核验专家",
      status: "succeeded",
      summary: "结论未超出工具证据。",
    },
  ],
};

const initialJob = {
  job_id: "job-existing",
  name: "每天上午巡检",
  workflow_name: "daily_coal_health",
  draft_id: "draft-v2-1",
  schedule_kind: "daily",
  schedule: { time: "09:00", timezone: "Asia/Shanghai" },
  enabled: true,
  revision: 2,
  next_run_at: "2026-07-31T01:00:00Z",
  integrity: { valid: true },
};

const memoryProposal = {
  proposal_id: "memory-proposal-1",
  key: "belt-maintenance-window",
  reason: "来自当前草稿所附检修记录。",
  status: "pending",
  revision: 4,
};

const skillProposal = {
  proposal_id: "skill-proposal-1",
  skill_name: "month-end-inventory-check",
  description: "月末库存只读核对流程。",
  status: "pending",
  revision: 5,
};

function createScenario(principal) {
  const requests = [];
  const runtimeErrors = [];
  let memoryDecision = "pending";
  let jobRevision = 2;

  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    const body = options.body ? JSON.parse(String(options.body)) : null;
    requests.push({ method, path: url.pathname, search: url.search, body });

    if (url.pathname === "/api/v1/health") {
      return jsonResponse({
        status: "ok",
        llm_mode: "configured",
        platform_configured: true,
      });
    }
    if (url.pathname === "/api/v1/auth/me") {
      return jsonResponse({ principal, csrf_token: `csrf-${principal.actor_id}` });
    }
    if (url.pathname === "/api/v1/platform-status") {
      return jsonResponse({
        configured: true,
        reachable: true,
        compatible: true,
        message: "测试接口正常",
      });
    }
    if (url.pathname === "/api/v1/drafts" && method === "GET") {
      return jsonResponse({ items: [draftSummary], total: 1, has_more: false });
    }
    if (url.pathname === "/api/v1/drafts/draft-v2-1" && method === "GET") {
      return jsonResponse({ draft: draftDetail });
    }
    if (
      url.pathname === "/api/v1/drafts/draft-v2-1/reviews" &&
      method === "GET"
    ) {
      return jsonResponse({
        review_state: {
          revision: 3,
          total: 0,
          reviewed_count: 0,
          all_reviewed: false,
          observations: [],
        },
      });
    }

    if (url.pathname === "/api/v1/agent/flows" && method === "GET") {
      return jsonResponse({ flows: [completedFlow], total: 1 });
    }
    if (url.pathname === "/api/v1/agent/flows" && method === "POST") {
      return jsonResponse(
        {
          flow: {
            ...completedFlow,
            flow_id: "flow-created",
            trigger_type: "manual",
            revision: 1,
            summary: {
              executive_summary: "新发起的体检已完成，未发现阻断项。",
              attention_items: [],
            },
          },
        },
        202,
      );
    }
    if (
      url.pathname === "/api/v1/agent/flows/flow-existing" &&
      method === "GET"
    ) {
      return jsonResponse({ flow: completedFlow });
    }
    if (
      url.pathname === "/api/v1/agent/flows/flow-created" &&
      method === "GET"
    ) {
      return jsonResponse({
        flow: {
          ...completedFlow,
          flow_id: "flow-created",
          trigger_type: "manual",
          summary: { executive_summary: "新发起的体检已完成，未发现阻断项。" },
        },
      });
    }

    if (url.pathname === "/api/v1/agent/jobs" && method === "GET") {
      return jsonResponse({ jobs: [{ ...initialJob, revision: jobRevision }] });
    }
    if (url.pathname === "/api/v1/agent/jobs" && method === "POST") {
      return jsonResponse({
        job: {
          job_id: "job-created",
          ...body,
          revision: 1,
          next_run_at: "2026-07-31T01:00:00Z",
          integrity: { valid: true },
        },
      });
    }
    if (
      url.pathname === "/api/v1/agent/jobs/job-existing/run" &&
      method === "POST"
    ) {
      return jsonResponse({
        flow: {
          ...completedFlow,
          flow_id: "flow-run-now",
          trigger_type: "schedule",
        },
      });
    }
    if (
      url.pathname === "/api/v1/agent/jobs/job-existing" &&
      method === "PATCH"
    ) {
      jobRevision += 1;
      return jsonResponse({
        job: {
          ...initialJob,
          enabled: body.enabled,
          revision: jobRevision,
          integrity: { valid: true },
        },
      });
    }
    if (
      url.pathname === "/api/v1/agent/jobs/job-existing" &&
      method === "DELETE"
    ) {
      return jsonResponse(null, 204);
    }

    if (
      url.pathname === "/api/v1/agent/memory/proposals" &&
      method === "GET"
    ) {
      return jsonResponse({
        proposals: [{ ...memoryProposal, status: memoryDecision }],
      });
    }
    if (
      url.pathname === "/api/v1/agent/memory/proposals" &&
      method === "POST"
    ) {
      return jsonResponse({
        proposal: {
          proposal_id: "memory-proposal-created",
          ...body,
          status: "pending",
          revision: 1,
        },
      });
    }
    if (url.pathname === "/api/v1/agent/memories" && method === "GET") {
      return jsonResponse({
        memories:
          memoryDecision === "approved"
            ? [{ key: "belt-maintenance-window", value: "每周二 09:00 检修" }]
            : [],
      });
    }
    if (
      url.pathname ===
        "/api/v1/agent/memory/proposals/memory-proposal-1/decision" &&
      method === "POST"
    ) {
      memoryDecision = body.decision === "approve" ? "approved" : "rejected";
      return jsonResponse({
        proposal: { ...memoryProposal, status: memoryDecision, revision: 5 },
      });
    }
    if (
      url.pathname === "/api/v1/agent/skill-proposals" &&
      method === "GET"
    ) {
      return jsonResponse({ proposals: [skillProposal] });
    }
    if (
      url.pathname === "/api/v1/agent/skill-proposals" &&
      method === "POST"
    ) {
      return jsonResponse({
        proposal: {
          proposal_id: "skill-proposal-created",
          ...body,
          status: "pending",
          revision: 1,
        },
      });
    }
    if (url.pathname === "/api/v1/agent/skill-versions" && method === "GET") {
      return jsonResponse({ skill_versions: [] });
    }

    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const instrumentedHtml = html.replace(
    '<script src="./app.js" defer></script>',
    `<script>${app}</script>`,
  );
  const dom = new JSDOM(instrumentedHtml, {
    runScripts: "dangerously",
    url: "http://127.0.0.1:8090/",
    beforeParse(window) {
      window.fetch = fakeFetch;
      window.confirm = () => true;
      window.HTMLElement.prototype.scrollIntoView = () => {};
      const dialogPrototype = window.HTMLDialogElement
        ? window.HTMLDialogElement.prototype
        : window.HTMLElement.prototype;
      if (typeof dialogPrototype.showModal !== "function") {
        dialogPrototype.showModal = function showModal() {
          this.setAttribute("open", "");
        };
      }
      if (typeof dialogPrototype.close !== "function") {
        dialogPrototype.close = function close() {
          this.removeAttribute("open");
        };
      }
      for (const storageName of ["localStorage", "sessionStorage"]) {
        Object.defineProperty(window, storageName, {
          configurable: true,
          get() {
            throw new Error(`${storageName} must not be used`);
          },
        });
      }
      window.addEventListener("error", (event) => {
        runtimeErrors.push(event.error || new Error(event.message));
      });
      window.addEventListener("unhandledrejection", (event) => {
        runtimeErrors.push(event.reason);
      });
    },
  });
  return { dom, document: dom.window.document, requests, runtimeErrors };
}

async function openDraft(scenario) {
  const { document } = scenario;
  await waitFor(
    () =>
      document.getElementById("welcomeStartButton").dataset.draftId ===
      "draft-v2-1",
    "unfinished draft",
  );
  document.getElementById("welcomeStartButton").click();
  await waitFor(
    () => document.getElementById("editor").hidden === false,
    "draft editor",
  );
}

function findButton(container, text) {
  return Array.from(container.querySelectorAll("button")).find(
    (button) => button.textContent.trim() === text,
  );
}

async function testFullAgentCenter() {
  const scenario = createScenario({
    actor_id: "operator-v2",
    name: "智能体管理员",
    role: "企业复核负责人",
    permissions: [
      "read",
      "write",
      "confirm",
      "governance_review",
      "skill_admin",
    ],
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
  });
  const { dom, document, requests, runtimeErrors } = scenario;
  try {
    await openDraft(scenario);
    assert(document.body.classList.contains("is-simple-mode"));
    assert.equal(document.getElementById("agentCenterButton").disabled, false);
    assert.equal(document.getElementById("runAgentCenterQuickButton").disabled, false);

    document.getElementById("openAgentCenterQuickButton").click();
    await waitFor(
      () =>
        document.getElementById("agentV2Workbench").hidden === false &&
        document.getElementById("agentV2FlowSummary").textContent.includes(
          "库存来源仍需补充",
        ),
      "leader summary",
    );
    assert.match(
      document.getElementById("agentV2FlowFindings").textContent,
      /期末库存缺少来源材料/,
    );
    assert.match(document.getElementById("agentV2StepList").textContent, /反方复核/);

    document.getElementById("runAgentCenterQuickButton").click();
    document.getElementById("runAgentCenterQuickButton").click();
    await waitFor(
      () =>
        requests.filter(
          (item) => item.method === "POST" && item.path === "/api/v1/agent/flows",
        ).length === 1,
      "single flow creation",
    );
    const flowCreate = requests.find(
      (item) => item.method === "POST" && item.path === "/api/v1/agent/flows",
    );
    assert.equal(flowCreate.body.workflow_name, "daily_coal_health");
    assert.equal(flowCreate.body.draft_id, "draft-v2-1");
    assert(flowCreate.body.client_request_id);

    document.getElementById("professionalModeButton").click();
    document.querySelector('[data-agent-center-tab="schedules"]').click();
    await waitFor(
      () => document.getElementById("agentV2JobList").textContent.includes("每天上午巡检"),
      "job list",
    );
    document.getElementById("agentV2JobName").value = "每两小时体检";
    document.getElementById("agentV2JobScheduleKind").value = "interval";
    document.getElementById("agentV2JobScheduleKind").dispatchEvent(
      new dom.window.Event("change", { bubbles: true }),
    );
    document.getElementById("agentV2JobIntervalMinutes").value = "120";
    document.getElementById("agentV2JobForm").dispatchEvent(
      new dom.window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        requests.some(
          (item) => item.method === "POST" && item.path === "/api/v1/agent/jobs",
        ),
      "job creation",
    );
    const jobCreate = requests.find(
      (item) => item.method === "POST" && item.path === "/api/v1/agent/jobs",
    );
    assert.equal(jobCreate.body.schedule.interval_seconds, 7200);
    assert.equal(jobCreate.body.draft_id, "draft-v2-1");

    const existingJobCard = Array.from(
      document.querySelectorAll(".agent-v2-job-card"),
    ).find((card) => card.textContent.includes("每天上午巡检"));
    findButton(existingJobCard, "立即运行").click();
    await waitFor(
      () =>
        requests.some(
          (item) =>
            item.method === "POST" &&
            item.path === "/api/v1/agent/jobs/job-existing/run",
        ),
      "run job now",
    );
    await waitFor(
      () => {
        const currentCard = Array.from(
          document.querySelectorAll(".agent-v2-job-card"),
        ).find((card) => card.textContent.includes("每天上午巡检"));
        const button = currentCard && findButton(currentCard, "停用");
        return Boolean(button && !button.disabled);
      },
      "job action unlocked",
    );
    const currentJobCard = Array.from(
      document.querySelectorAll(".agent-v2-job-card"),
    ).find((card) => card.textContent.includes("每天上午巡检"));
    findButton(currentJobCard, "停用").click();
    await waitFor(
      () =>
        requests.some(
          (item) =>
            item.method === "PATCH" &&
            item.path === "/api/v1/agent/jobs/job-existing",
        ),
      "disable job",
    );
    const jobPatch = requests.find(
      (item) =>
        item.method === "PATCH" &&
        item.path === "/api/v1/agent/jobs/job-existing",
    );
    assert.equal(jobPatch.body.expected_revision, 2);
    assert.equal(jobPatch.body.enabled, false);

    document.querySelector('[data-agent-center-tab="governance"]').click();
    await waitFor(
      () =>
        document
          .getElementById("agentV2MemoryProposalList")
          .textContent.includes("belt-maintenance-window"),
      "governance proposals",
    );
    const memoryCard = document.querySelector(
      "#agentV2MemoryProposalList .agent-v2-proposal-card",
    );
    const approveButton = findButton(memoryCard, "核验后批准");
    assert.equal(approveButton.disabled, false);
    approveButton.click();
    await waitFor(
      () =>
        requests.some(
          (item) =>
            item.method === "POST" &&
            item.path.endsWith("/memory-proposal-1/decision"),
        ),
      "memory approval",
    );
    const decision = requests.find((item) =>
      item.path.endsWith("/memory-proposal-1/decision"),
    );
    assert.equal(decision.body.expected_revision, 4);
    assert.equal(decision.body.decision, "approve");

    document.getElementById("agentV2SkillName").value =
      "month-end-inventory-check";
    document.getElementById("agentV2SkillDescription").value =
      "检查月末库存来源和物理关系";
    document.getElementById("agentV2SkillProcedure").value =
      "读取草稿摘要\n执行确定性预检";
    document.getElementById("agentV2SkillProposalForm").dispatchEvent(
      new dom.window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        requests.some(
          (item) =>
            item.method === "POST" &&
            item.path === "/api/v1/agent/skill-proposals",
        ),
      "skill proposal",
    );
    const skillCreate = requests.find(
      (item) =>
        item.method === "POST" &&
        item.path === "/api/v1/agent/skill-proposals",
    );
    assert.deepEqual(skillCreate.body.allowed_tools, [
      "draft_summary",
      "deterministic_preflight",
    ]);
    assert.deepEqual(skillCreate.body.procedure, [
      "读取草稿摘要",
      "执行确定性预检",
    ]);

    assert.equal(
      requests.filter(
        (item) =>
          item.path.includes("/confirm") || item.path.includes("/submit"),
      ).length,
      0,
      "agent center must never call confirmation or submission endpoints",
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  } finally {
    dom.window.close();
  }
}

async function testReadOnlyPermissionBoundary() {
  const scenario = createScenario({
    actor_id: "viewer-v2",
    name: "只读查看人",
    role: "企业负责人",
    permissions: ["read"],
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
  });
  const { dom, document, requests, runtimeErrors } = scenario;
  try {
    await openDraft(scenario);
    document.getElementById("openAgentCenterQuickButton").click();
    await waitFor(
      () => document.getElementById("agentV2FlowSummary").textContent.includes("库存来源"),
      "read-only flow summary",
    );
    document.getElementById("professionalModeButton").click();
    document.querySelector('[data-agent-center-tab="schedules"]').click();
    await waitFor(
      () => document.getElementById("agentV2JobList").textContent.includes("每天上午巡检"),
      "read-only jobs",
    );
    assert.equal(document.getElementById("createAgentV2JobButton").disabled, true);
    document.querySelector('[data-agent-center-tab="governance"]').click();
    await waitFor(
      () =>
        document
          .getElementById("agentV2MemoryProposalList")
          .textContent.includes("belt-maintenance-window"),
      "read-only proposals",
    );
    assert.equal(
      findButton(
        document.querySelector(
          "#agentV2MemoryProposalList .agent-v2-proposal-card",
        ),
        "核验后批准",
      ).disabled,
      true,
    );
    assert.equal(
      requests.filter((item) => ["POST", "PATCH", "DELETE"].includes(item.method))
        .length,
      0,
    );
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  } finally {
    dom.window.close();
  }
}

async function main() {
  await testFullAgentCenter();
  await testReadOnlyPermissionBoundary();
  console.log("JSDOM agent V2 task center checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
