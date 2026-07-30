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
  return JSON.parse(JSON.stringify(value));
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

const draftSummary = {
  draft_id: "draft-simple-1",
  status: "draft",
  enterprise_name: "快捷填报示范煤业",
  mine_id: "MINE-SIMPLE-1",
  updated_at: "2026-07-29T08:00:00Z",
};

const draftDetail = {
  ...draftSummary,
  revision: 3,
  enterprise_id: "ENT-SIMPLE-1",
  unified_social_credit_code: "91140100MA0ABCDEF1",
  mine_name: "快捷填报一号矿",
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
  _meta: {
    revision: 3,
    updated_at: "2026-07-29T08:00:00Z",
  },
};

function createScenario(principal) {
  const requests = [];
  const runtimeErrors = [];

  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    requests.push(`${method} ${url.pathname}${url.search}`);
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
      return jsonResponse({
        items: [draftSummary],
        total: 1,
        has_more: false,
      });
    }
    if (url.pathname === "/api/v1/drafts/draft-simple-1" && method === "GET") {
      return jsonResponse({ draft: draftDetail });
    }
    if (url.pathname === "/api/v1/drafts/draft-simple-1" && method === "DELETE") {
      return jsonResponse({ deleted: true });
    }
    if (
      url.pathname === "/api/v1/drafts/draft-simple-1/reviews" &&
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
    if (
      url.pathname === "/api/v1/drafts/draft-simple-1/submissions" &&
      method === "GET"
    ) {
      return jsonResponse({ items: [], integrity: { valid: true } });
    }
    if (
      url.pathname === "/api/v1/drafts/draft-simple-1/audit" &&
      method === "GET"
    ) {
      return jsonResponse({ events: [], integrity: { valid: true } });
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

async function openSuggestedDraft(scenario) {
  const { document } = scenario;
  await waitFor(
    () =>
      document.getElementById("welcomeStartButton").dataset.draftId ===
      "draft-simple-1",
    "unfinished draft continuation",
  );
  assert.match(
    document.getElementById("welcomeStartButton").textContent,
    /继续未完成填报/,
  );
  document.getElementById("welcomeStartButton").click();
  try {
    await waitFor(
      () =>
        document.getElementById("editor").hidden === false &&
        document.getElementById("simpleTaskButton").dataset.targetStep === "2",
      "draft editor and suggested second step",
    );
  } catch (error) {
    error.message +=
      `; requests=${scenario.requests.join(" | ")}` +
      `; editorHidden=${document.getElementById("editor").hidden}` +
      `; target=${document.getElementById("simpleTaskButton").dataset.targetStep || ""}` +
      `; toast=${document.getElementById("toastRegion").textContent}`;
    throw error;
  }
}

async function testAutofillShortcutOpensSourceStep() {
  const scenario = createScenario({
    actor_id: "autofill-operator",
    name: "自动填报测试用户",
    role: "企业经办",
    permissions: ["read", "write"],
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
  });
  const { dom, document, runtimeErrors } = scenario;
  try {
    await waitFor(
      () =>
        document.getElementById("welcomeAutofillButton").textContent.includes(
          "补全这份草稿",
        ),
      "autofill shortcut",
    );
    document.getElementById("welcomeAutofillButton").click();
    await waitFor(
      () =>
        document.getElementById("editor").hidden === false &&
        document.querySelector('.step-panel[data-panel="2"]').hidden === false,
      "autofill shortcut source step",
    );
    assert.equal(document.activeElement.id, "chooseFileButton");
    assert.match(
      document.getElementById("toastRegion").textContent,
      /Agent 会自动写入可验证字段/,
    );
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  } finally {
    dom.window.close();
  }
}

async function testOperatorModeSwitchAndSteps() {
  const scenario = createScenario({
    actor_id: "operator-1",
    name: "全流程测试用户",
    role: "企业经办与确认",
    permissions: ["read", "write", "confirm", "submit"],
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
  });
  const { dom, document, requests, runtimeErrors } = scenario;
  try {
    await openSuggestedDraft(scenario);
    assert(document.body.classList.contains("is-simple-mode"));
    assert(!document.body.classList.contains("is-professional-mode"));
    assert.equal(
      document.getElementById("simpleModeButton").getAttribute("aria-pressed"),
      "true",
    );
    assert.equal(document.getElementById("editorMoreActions").open, false);
    assert.equal(document.getElementById("welcomeNewDraftButton").hidden, false);
    assert.equal(document.getElementById("simpleDeleteDraftButton").disabled, false);
    assert.equal(document.getElementById("simpleTaskButton").dataset.actionAllowed, "true");

    const requestCount = requests.length;
    document.getElementById("professionalModeButton").click();
    assert(document.body.classList.contains("is-professional-mode"));
    assert.equal(document.getElementById("editorMoreActions").open, true);
    assert.equal(document.getElementById("agentTaskButton").disabled, false);
    assert.equal(requests.length, requestCount, "mode switch must not call APIs");
    document.getElementById("simpleModeButton").click();
    assert(document.body.classList.contains("is-simple-mode"));
    assert.equal(document.getElementById("editorMoreActions").open, false);
    assert.equal(requests.length, requestCount, "returning mode must not call APIs");
    assert.equal(
      document.querySelector('[name="enterprise.name"]').value,
      "快捷填报示范煤业",
    );

    const stepButtons = Array.from(
      document.querySelectorAll("#stepList button[data-step]"),
    );
    const panels = Array.from(document.querySelectorAll(".step-panel"));
    assert.equal(stepButtons.length, 6);
    assert.equal(panels.length, 6);
    for (let step = 1; step <= 6; step += 1) {
      stepButtons[step - 1].click();
      assert.deepEqual(
        panels
          .filter((panel) => !panel.hidden)
          .map((panel) => panel.dataset.panel),
        [String(step)],
      );
      assert.equal(stepButtons[step - 1].getAttribute("aria-current"), "step");
      assert.equal(
        document.getElementById("previousStepButton").disabled,
        step === 1,
      );
      assert.equal(document.getElementById("nextStepButton").hidden, step === 6);
    }

    document.getElementById("simpleDeleteDraftButton").click();
    assert.equal(document.getElementById("deleteDialog").open, true);
    const deleteConfirmation = document.getElementById("deleteConfirmation");
    deleteConfirmation.value = "移除";
    deleteConfirmation.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
    assert.equal(document.getElementById("confirmDeleteButton").disabled, false);
    document.getElementById("confirmDeleteButton").click();
    await waitFor(
      () =>
        requests.includes("DELETE /api/v1/drafts/draft-simple-1") &&
        document.getElementById("editor").hidden === true,
      "visible shortcut draft deletion",
    );
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  } finally {
    dom.window.close();
  }
}

async function testReadOnlyModeCannotUpgradePermissions() {
  const scenario = createScenario({
    actor_id: "viewer-1",
    name: "只读测试用户",
    role: "系统管理员",
    permissions: ["read"],
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
  });
  const { dom, document, requests, runtimeErrors } = scenario;
  try {
    await openSuggestedDraft(scenario);
    assert.equal(document.getElementById("newDraftButton").disabled, true);
    assert.equal(document.getElementById("welcomeNewDraftButton").hidden, true);
    assert.equal(document.getElementById("simpleDeleteDraftButton").disabled, true);
    assert.equal(document.getElementById("simpleTaskButton").dataset.actionAllowed, "false");
    assert.match(document.getElementById("simpleTaskTitle").textContent, /等待经办人/);
    const writeRequestsBefore = requests.filter((item) =>
      /^(POST|PATCH|DELETE) /.test(item),
    ).length;
    document.getElementById("simpleTaskButton").click();
    document.getElementById("professionalModeButton").click();
    assert.equal(document.getElementById("newDraftButton").disabled, true);
    assert.equal(document.querySelector('[name="enterprise.name"]').disabled, true);
    document.getElementById("simpleModeButton").click();
    const writeRequestsAfter = requests.filter((item) =>
      /^(POST|PATCH|DELETE) /.test(item),
    ).length;
    assert.equal(writeRequestsAfter, writeRequestsBefore);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  } finally {
    dom.window.close();
  }
}

async function main() {
  await testAutofillShortcutOpensSourceStep();
  await testOperatorModeSwitchAndSteps();
  await testReadOnlyModeCannotUpgradePermissions();
  console.log("JSDOM enterprise mode checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
