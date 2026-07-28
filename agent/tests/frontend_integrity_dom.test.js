"use strict";

const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const projectRoot = path.resolve(__dirname, "..");
const htmlPath = path.join(projectRoot, "web", "index.html");
const appPath = path.join(projectRoot, "web", "app.js");
const html = fs.readFileSync(htmlPath, "utf8");
const app = fs.readFileSync(appPath, "utf8");

assert(!app.toLowerCase().includes("</script"), "app.js cannot close inline script");

const badRun = {
  run_id: "run-bad",
  actor_id: "leader-1",
  task: "完整性失败任务",
  mode: "auto",
  status: "waiting_approval",
  answer: "伪造综合答案绝不能显示",
  integrity: {
    valid: false,
    event_count: 4,
    head_hash: "f".repeat(64),
  },
  budgets: {
    steps_used: 2,
    max_steps: 8,
    tool_calls_used: 1,
    max_tool_calls: 12,
  },
  steps: [
    {
      step_id: "step-model",
      kind: "model",
      content: "伪造模型步骤绝不能显示",
    },
    {
      step_id: "step-tool",
      kind: "tool",
      tool_call_id: "call-bad",
      evidence: {
        deterministic: true,
        evidence_grounding: "repository_grounded",
      },
    },
  ],
  tool_calls: [
    {
      call_id: "call-bad",
      tool_name: "伪造工具名称绝不能显示",
      status: "waiting_approval",
      approval_id: "approval-bad",
      arguments: { patch: "伪造审批参数绝不能显示" },
      result: { data: { secret_result: "伪造工具结果绝不能显示" } },
    },
  ],
  approvals: [
    {
      approval_id: "approval-bad",
      call_id: "call-bad",
      status: "pending",
      rationale: "伪造审批理由绝不能显示",
    },
  ],
  created_at: "2026-07-27T00:00:00Z",
  updated_at: "2026-07-27T00:00:01Z",
};

const legacyRun = {
  run_id: "run-legacy",
  actor_id: "leader-1",
  task: "旧版无完整性字段任务",
  mode: "deterministic",
  status: "completed",
  answer: "旧版兼容答案可显示",
  budgets: {},
  steps: [],
  tool_calls: [],
  approvals: [],
  created_at: "2026-07-27T00:00:00Z",
  updated_at: "2026-07-27T00:00:01Z",
};

const malformedRun = {
  ...legacyRun,
  run_id: "run-malformed",
  task: "畸形完整性字段任务",
  answer: "畸形完整性字段下的伪造答案绝不能显示",
  integrity: null,
};

const summaries = [
  {
    run_id: badRun.run_id,
    task: badRun.task,
    mode: badRun.mode,
    status: badRun.status,
    updated_at: badRun.updated_at,
  },
  {
    run_id: legacyRun.run_id,
    task: legacyRun.task,
    mode: legacyRun.mode,
    status: legacyRun.status,
    updated_at: legacyRun.updated_at,
  },
  {
    run_id: malformedRun.run_id,
    task: malformedRun.task,
    mode: malformedRun.mode,
    status: malformedRun.status,
    updated_at: malformedRun.updated_at,
  },
];

const requests = [];

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
      return JSON.parse(JSON.stringify(payload));
    },
    async text() {
      return JSON.stringify(payload);
    },
  };
}

async function fakeFetch(input, options = {}) {
  const url = new URL(String(input), "http://127.0.0.1:8090/");
  const method = String(options.method || "GET").toUpperCase();
  requests.push(`${method} ${url.pathname}${url.search}`);
  if (url.pathname === "/api/v1/health") {
    return jsonResponse({
      status: "ok",
      llm_mode: "configured",
      platform_configured: false,
    });
  }
  if (url.pathname === "/api/v1/auth/me") {
    return jsonResponse({
      principal: {
        actor_id: "leader-1",
        name: "测试领导",
        role: "负责人",
        permissions: ["read", "write"],
      },
      csrf_token: "csrf-test-token",
    });
  }
  if (url.pathname === "/api/v1/platform-status") {
    return jsonResponse({
      configured: false,
      reachable: null,
      compatible: null,
      message: "未配置",
    });
  }
  if (url.pathname === "/api/v1/drafts") {
    return jsonResponse({ items: [], total: 0, has_more: false });
  }
  if (url.pathname === "/api/v1/agent/runs" && method === "GET") {
    return jsonResponse({
      runs: summaries,
      total: summaries.length,
      has_more: false,
    });
  }
  if (url.pathname === "/api/v1/agent/runs/run-bad" && method === "GET") {
    return jsonResponse({ run: badRun });
  }
  if (
    url.pathname === "/api/v1/agent/runs/run-bad/cancel" &&
    method === "POST"
  ) {
    return jsonResponse({
      run: { ...badRun, status: "cancelled" },
    });
  }
  if (url.pathname === "/api/v1/agent/runs/run-legacy" && method === "GET") {
    return jsonResponse({ run: legacyRun });
  }
  if (
    url.pathname === "/api/v1/agent/runs/run-malformed" &&
    method === "GET"
  ) {
    return jsonResponse({ run: malformedRun });
  }
  throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
}

function waitFor(predicate, message, timeoutMs = 3000) {
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

async function main() {
  const instrumentedHtml = html.replace(
    '<script src="./app.js" defer></script>',
    `<script>${app}</script>`,
  );
  const runtimeErrors = [];
  const dom = new JSDOM(instrumentedHtml, {
    runScripts: "dangerously",
    url: "http://127.0.0.1:8090/",
    beforeParse(window) {
      window.fetch = fakeFetch;
      window.confirm = () => true;
      window.addEventListener("error", (event) => {
        runtimeErrors.push(event.error || new Error(event.message));
      });
      window.addEventListener("unhandledrejection", (event) => {
        runtimeErrors.push(event.reason);
      });
    },
  });
  const { document } = dom.window;

  await waitFor(
    () => document.getElementById("agentTaskButton").disabled === false,
    "authenticated session",
  );
  document.getElementById("agentTaskButton").click();
  await waitFor(
    () => document.getElementById("agentIntegrityFailure").hidden === false,
    "invalid integrity detail",
  );

  const bodyText = document.body.textContent;
  assert.match(
    document.getElementById("agentIntegrityFailure").textContent,
    /过程证据完整性校验失败，以下内容不可采信/,
  );
  assert.equal(document.getElementById("agentRunAnswer").hidden, true);
  assert.equal(document.getElementById("agentRunAnswer").textContent, "");
  assert.equal(document.getElementById("agentEvidenceSection").hidden, true);
  assert.equal(document.getElementById("agentStepList").textContent, "");
  assert.equal(document.getElementById("agentApprovalCard").hidden, true);
  assert.equal(document.getElementById("agentApprovalDetails").textContent, "");
  assert.equal(document.getElementById("approveAgentApprovalButton").disabled, true);
  assert.equal(document.getElementById("rejectAgentApprovalButton").disabled, true);
  assert.equal(document.getElementById("cancelAgentRunButton").hidden, false);
  assert.equal(document.getElementById("cancelAgentRunButton").disabled, false);
  for (const forbidden of [
    badRun.answer,
    "伪造模型步骤绝不能显示",
    "伪造工具名称绝不能显示",
    "伪造工具结果绝不能显示",
    "伪造审批参数绝不能显示",
    "伪造审批理由绝不能显示",
  ]) {
    assert(!bodyText.includes(forbidden), `DOM leaked untrusted value: ${forbidden}`);
  }

  const approvalsBefore = requests.filter((item) =>
    item.includes("/approve"),
  ).length;
  document.getElementById("approveAgentApprovalButton").click();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const approvalsAfter = requests.filter((item) =>
    item.includes("/approve"),
  ).length;
  assert.equal(approvalsAfter, approvalsBefore, "invalid run must not approve");

  document.getElementById("cancelAgentRunButton").click();
  await waitFor(
    () =>
      requests.some(
        (item) => item === "POST /api/v1/agent/runs/run-bad/cancel",
      ),
    "fail-safe cancellation",
  );

  const legacyButton = Array.from(
    document.querySelectorAll(".agent-run-item"),
  ).find((button) => button.textContent.includes(legacyRun.task));
  assert(legacyButton, "legacy run missing from list");
  legacyButton.click();
  await waitFor(
    () =>
      document.getElementById("agentRunAnswer").textContent.includes(
        legacyRun.answer,
      ),
    "legacy run without integrity",
  );
  assert.equal(document.getElementById("agentIntegrityFailure").hidden, true);
  assert.equal(document.getElementById("agentRunAnswer").hidden, false);

  const malformedButton = Array.from(
    document.querySelectorAll(".agent-run-item"),
  ).find((button) => button.textContent.includes(malformedRun.task));
  assert(malformedButton, "malformed-integrity run missing from list");
  malformedButton.click();
  await waitFor(
    () => document.getElementById("agentIntegrityFailure").hidden === false,
    "malformed integrity must fail closed",
  );
  assert.equal(document.getElementById("agentRunAnswer").hidden, true);
  assert(
    !document.body.textContent.includes(malformedRun.answer),
    "malformed integrity leaked answer",
  );
  assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));

  dom.window.close();
  console.log("JSDOM integrity fail-closed checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
