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

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function createTestDom(fakeFetch, setupWindow = null) {
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
      if (typeof setupWindow === "function") setupWindow(window);
      window.addEventListener("error", (event) => {
        runtimeErrors.push(event.error || new Error(event.message));
      });
      window.addEventListener("unhandledrejection", (event) => {
        runtimeErrors.push(event.reason);
      });
    },
  });
  return {
    dom,
    document: dom.window.document,
    window: dom.window,
    runtimeErrors,
  };
}

async function assertNoRuntimeErrors(runtimeErrors) {
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
}

function account(actorId, permissions, overrides = {}) {
  return {
    actor_id: actorId,
    name: `${actorId} 用户`,
    role: "测试岗位",
    permissions,
    authentication_method: "password_session",
    must_change_password: false,
    temporary_demo: false,
    ...overrides,
  };
}

function listText(document, id) {
  return Array.from(document.getElementById(id).querySelectorAll("li")).map(
    (item) => item.textContent,
  );
}

function permissionState(document, permission) {
  const badge = document.querySelector(
    `#roleGuidePermissions [data-permission="${permission}"]`,
  );
  assert(badge, `missing ${permission} permission badge`);
  return {
    text: badge.textContent,
    enabled: badge.classList.contains("is-enabled"),
    disabled: badge.classList.contains("is-disabled"),
    locked: badge.classList.contains("is-locked"),
  };
}

function assertPermission(document, permission, expectedState) {
  const state = permissionState(document, permission);
  assert.equal(state[expectedState], true, `${permission} should be ${expectedState}`);
}

function assertNoPrivilegedCapabilities(capabilities) {
  assert.doesNotMatch(capabilities, /新建、导入、编辑草稿/);
  assert.doesNotMatch(capabilities, /完成企业账号人工确认/);
  assert.doesNotMatch(capabilities, /提交已经确认/);
}

async function renderFor(principal, verify) {
  const requests = [];

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
      if (principal === null) {
        return jsonResponse(
          {
            error: {
              code: "authentication_required",
              message: "请登录",
            },
          },
          401,
        );
      }
      return jsonResponse({
        principal,
        csrf_token: `csrf-${principal.actor_id || "invalid"}`,
      });
    }
    if (url.pathname === "/api/v1/auth/logout" && method === "POST") {
      return jsonResponse({});
    }
    if (url.pathname === "/api/v1/platform-status") {
      return jsonResponse({
        configured: false,
        reachable: null,
        compatible: null,
        message: "未配置",
      });
    }
    if (url.pathname === "/api/v1/drafts" && method === "GET") {
      return jsonResponse({ items: [], total: 0, has_more: false });
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const { dom, document, window, runtimeErrors } = createTestDom(fakeFetch);

  if (principal === null) {
    await waitFor(
      () =>
        requests.includes("GET /api/v1/auth/me") &&
        document.getElementById("loginDialog").hasAttribute("open"),
      "unauthenticated state",
    );
  } else {
    await waitFor(
      () =>
        document.getElementById("roleGuide").dataset.principalId ===
          String(principal.actor_id || "") &&
        document.getElementById("roleGuide").hidden === false,
      `role guide for ${principal.actor_id}`,
    );
  }

  try {
    await verify({ document, window, requests });
    await assertNoRuntimeErrors(runtimeErrors);
  } finally {
    dom.window.close();
  }
}

async function testHealthSurvivesUnauthenticatedSessionReset() {
  const health = deferred();
  const requests = [];

  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    requests.push(`${method} ${url.pathname}${url.search}`);
    if (url.pathname === "/api/v1/health") return health.promise;
    if (url.pathname === "/api/v1/auth/me") {
      return jsonResponse(
        {
          error: {
            code: "authentication_required",
            message: "请登录",
          },
        },
        401,
      );
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const { dom, document, runtimeErrors } = createTestDom(fakeFetch);
  try {
    await waitFor(
      () =>
        requests.includes("GET /api/v1/auth/me") &&
        document.getElementById("loginDialog").hasAttribute("open"),
      "401 login prompt before health",
    );
    assert.equal(document.getElementById("agentStatusText").textContent, "正在检查");
    assert.equal(document.getElementById("loginDemoHint").hidden, true);

    health.resolve(
      jsonResponse({
        status: "ok",
        llm_mode: "configured",
        platform_configured: false,
        demo_account_enabled: true,
      }),
    );
    await waitFor(
      () =>
        document.getElementById("agentStatusText").textContent ===
          "已连接并运行" &&
        document.getElementById("loginDemoHint").hidden === false,
      "public health after session reset",
    );
    assert.equal(document.getElementById("loginActorId").value, "demo");
    assert(document.getElementById("agentStatusItem").classList.contains("is-ok"));
    await assertNoRuntimeErrors(runtimeErrors);
  } finally {
    dom.window.close();
  }
}

async function testStaleAccountResponsesCannotOverwriteNewSession() {
  const staleDrafts = deferred();
  const stalePlatform = deferred();
  const requests = [];
  let draftRequestCount = 0;
  let platformRequestCount = 0;
  const accountA = account("account-a", ["read", "write"], {
    name: "旧账号A",
    role: "旧经办岗位",
  });
  const accountB = account("account-b", ["read", "write"], {
    name: "新账号B安全状态",
    role: "新经办岗位",
  });

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
      return jsonResponse({
        principal: accountA,
        csrf_token: "csrf-account-a",
      });
    }
    if (url.pathname === "/api/v1/auth/logout" && method === "POST") {
      return jsonResponse({});
    }
    if (url.pathname === "/api/v1/auth/login" && method === "POST") {
      return jsonResponse({
        principal: accountB,
        csrf_token: "csrf-account-b",
      });
    }
    if (url.pathname === "/api/v1/drafts" && method === "GET") {
      draftRequestCount += 1;
      if (draftRequestCount === 1) return staleDrafts.promise;
      return jsonResponse({
        items: [
          {
            draft_id: "draft-b",
            status: "draft",
            enterprise_name: "B草稿安全状态",
            mine_id: "mine-b",
            updated_at: "2026-07-28T06:00:00Z",
          },
        ],
        total: 1,
        has_more: false,
      });
    }
    if (url.pathname === "/api/v1/platform-status") {
      platformRequestCount += 1;
      if (platformRequestCount === 1) return stalePlatform.promise;
      return jsonResponse({
        configured: true,
        reachable: true,
        compatible: true,
        message: "B平台状态安全",
      });
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const { dom, document, window, runtimeErrors } = createTestDom(fakeFetch);
  try {
    await waitFor(
      () =>
        document.getElementById("roleGuide").dataset.principalId ===
          accountA.actor_id &&
        draftRequestCount === 1 &&
        platformRequestCount === 1,
      "account A delayed loaders",
    );

    document.getElementById("logoutButton").click();
    await waitFor(
      () =>
        requests.includes("POST /api/v1/auth/logout") &&
        document.getElementById("loginDialog").hasAttribute("open"),
      "account A logout",
    );
    document.getElementById("loginActorId").value = accountB.actor_id;
    document.getElementById("loginPassword").value = "account-b-password";
    document.getElementById("loginForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );

    await waitFor(
      () =>
        document.getElementById("roleGuide").dataset.principalId ===
          accountB.actor_id &&
        document.getElementById("draftList").textContent.includes(
          "B草稿安全状态",
        ) &&
        document.getElementById("platformStatusText").textContent ===
          "已连接且兼容" &&
        document.getElementById("draftList").getAttribute("aria-busy") ===
          "false",
      "account B state",
    );
    assert.equal(
      document.getElementById("platformStatusItem").title,
      "B平台状态安全",
    );
    assert.match(
      document.getElementById("toastRegion").textContent,
      /已以 新账号B安全状态 的身份登录/,
    );

    staleDrafts.resolve(
      jsonResponse({
        items: [
          {
            draft_id: "stale-a-draft",
            status: "draft",
            enterprise_name: "STALE-A-DRAFT-MARKER",
          },
        ],
        total: 1,
        has_more: false,
      }),
    );
    stalePlatform.reject(new Error("STALE-A-PLATFORM-FAILURE"));
    await new Promise((resolve) => setTimeout(resolve, 50));

    assert.equal(
      document.getElementById("roleGuide").dataset.principalId,
      accountB.actor_id,
    );
    assert.equal(document.getElementById("currentUserName").textContent, accountB.name);
    assert.match(document.getElementById("draftList").textContent, /B草稿安全状态/);
    assert.doesNotMatch(document.body.textContent, /STALE-A-DRAFT-MARKER/);
    assert.doesNotMatch(document.body.textContent, /STALE-A-PLATFORM-FAILURE/);
    assert.equal(document.getElementById("platformStatusText").textContent, "已连接且兼容");
    assert.equal(
      document.getElementById("platformStatusItem").title,
      "B平台状态安全",
    );
    assert.equal(document.getElementById("draftList").getAttribute("aria-busy"), "false");
    assert.equal(document.getElementById("refreshDraftsButton").disabled, false);
    await assertNoRuntimeErrors(runtimeErrors);
  } finally {
    dom.window.close();
  }
}

async function testDelayedFileReadCannotWriteAfterLogout() {
  const fileContent = deferred();
  const requests = [];
  let fileTextCalled = false;
  const principal = account("file-reader", ["read", "write"]);

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
      return jsonResponse({ principal, csrf_token: "csrf-file-reader" });
    }
    if (url.pathname === "/api/v1/platform-status") {
      return jsonResponse({ configured: false, message: "未配置" });
    }
    if (url.pathname === "/api/v1/drafts" && method === "GET") {
      return jsonResponse({ items: [], total: 0, has_more: false });
    }
    if (url.pathname === "/api/v1/drafts" && method === "POST") {
      return jsonResponse({
        draft: {
          draft_id: "file-draft",
          revision: 1,
          status: "draft",
          enterprise_id: "enterprise-file",
          enterprise_name: "文件导入测试企业",
          mine_id: "mine-file",
          mine_name: "文件导入测试矿",
          operational_context: {},
          observations: [],
          sources: [],
          questions: [],
          approval_events: [],
          signature: { valid: false },
        },
      });
    }
    if (url.pathname === "/api/v1/auth/logout" && method === "POST") {
      return jsonResponse({});
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const { dom, document, window, runtimeErrors } = createTestDom(fakeFetch);
  try {
    await waitFor(
      () =>
        document.getElementById("roleGuide").dataset.principalId ===
          principal.actor_id &&
        document.getElementById("newDraftButton").disabled === false,
      "file reader session",
    );
    document.getElementById("newDraftButton").click();
    await waitFor(
      () =>
        document.getElementById("editor").hidden === false &&
        document.getElementById("newDraftButton").disabled === false,
      "draft for delayed file",
    );

    const fakeFile = {
      name: "delayed-sensitive.json",
      size: 128,
      text() {
        fileTextCalled = true;
        return fileContent.promise;
      },
    };
    const sourceFile = document.getElementById("sourceFile");
    Object.defineProperty(sourceFile, "files", {
      configurable: true,
      value: [fakeFile],
    });
    sourceFile.dispatchEvent(
      new window.Event("change", { bubbles: true, cancelable: true }),
    );
    await waitFor(() => fileTextCalled, "delayed file read started");

    document.getElementById("logoutButton").click();
    await waitFor(
      () =>
        requests.includes("POST /api/v1/auth/logout") &&
        document.getElementById("roleGuide").hidden === true &&
        document.getElementById("loginDialog").hasAttribute("open"),
      "logout during file read",
    );

    const sensitiveContent = "DELAYED-FILE-SENSITIVE-CONTENT-81c2";
    fileContent.resolve(`{"secret":"${sensitiveContent}"}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(document.getElementById("sourceContent").value, "");
    assert.equal(document.getElementById("sourceName").value, "");
    assert.doesNotMatch(document.body.textContent, new RegExp(sensitiveContent));
    assert.doesNotMatch(
      document.getElementById("toastRegion").textContent,
      /delayed-sensitive\.json|已读取/,
    );
    await assertNoRuntimeErrors(runtimeErrors);
  } finally {
    dom.window.close();
  }
}

async function testSameActorReadRevocationScrubsRecoveredWorkspace() {
  const requests = [];
  const actorId = "same-actor";
  const oldPrincipal = account(actorId, ["read", "write"], {
    name: "同账号旧权限",
  });
  const restrictedPrincipal = account(actorId, ["write"], {
    name: "同账号权限收缩",
    role: "不可查看岗位",
  });
  const sensitive = "SAME-ACTOR-OLD-DRAFT-SENSITIVE-4d09";
  let draftListRequestCount = 0;

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
        principal: oldPrincipal,
        csrf_token: "csrf-same-old",
      });
    }
    if (url.pathname === "/api/v1/auth/login" && method === "POST") {
      return jsonResponse({
        principal: restrictedPrincipal,
        csrf_token: "csrf-same-restricted",
      });
    }
    if (url.pathname === "/api/v1/platform-status") {
      return jsonResponse({ configured: false, message: "未配置" });
    }
    if (url.pathname === "/api/v1/drafts" && method === "GET") {
      draftListRequestCount += 1;
      if (draftListRequestCount > 1) {
        return jsonResponse(
          {
            error: {
              code: "authentication_required",
              message: "会话已过期",
            },
          },
          401,
        );
      }
      return jsonResponse({
        items: [
          {
            draft_id: "same-actor-draft",
            status: "draft",
            enterprise_name: sensitive,
            mine_id: "same-mine",
            updated_at: "2026-07-28T06:00:00Z",
          },
        ],
        total: 1,
        has_more: false,
      });
    }
    if (
      url.pathname === "/api/v1/drafts/same-actor-draft" &&
      method === "GET"
    ) {
      return jsonResponse({
        draft: {
          draft_id: "same-actor-draft",
          revision: 3,
          status: "draft",
          enterprise_id: "same-enterprise",
          enterprise_name: sensitive,
          mine_id: "same-mine",
          mine_name: sensitive,
          window_start: "2026-07-01T00:00:00Z",
          window_end: "2026-07-31T23:59:59Z",
          profile_id: "production-default",
          profile_version: "1",
          operational_context: {},
          observations: [],
          sources: [],
          questions: [],
          approval_events: [],
          signature: { valid: false },
        },
      });
    }
    if (
      url.pathname === "/api/v1/drafts/same-actor-draft/reviews" &&
      method === "GET"
    ) {
      return jsonResponse({
        review_state: {
          reviewed_observation_ids: [],
          all_reviewed: false,
        },
      });
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
  }

  const { dom, document, window, runtimeErrors } = createTestDom(fakeFetch);
  try {
    await waitFor(
      () => document.querySelector(".draft-item"),
      "same actor draft list",
    );
    document.querySelector(".draft-item").click();
    await waitFor(
      () =>
        document.getElementById("editor").hidden === false &&
        document.body.textContent.includes(sensitive),
      "old same-actor workspace",
    );

    const enterpriseName = document.querySelector(
      '[name="enterprise.name"]',
    );
    enterpriseName.value = sensitive;
    enterpriseName.dispatchEvent(
      new window.Event("input", { bubbles: true }),
    );
    document.getElementById("refreshDraftsButton").click();
    await waitFor(
      () =>
        draftListRequestCount === 2 &&
        document.getElementById("loginDialog").hasAttribute("open"),
      "expired session preserving workspace",
    );

    document.getElementById("loginActorId").value = actorId;
    document.getElementById("loginPassword").value = "same-actor-password";
    document.getElementById("loginForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        document.getElementById("roleGuide").dataset.principalId === actorId &&
        document.getElementById("roleGuide").hidden === false &&
        document.getElementById("loginDialog").hasAttribute("open") === false,
      "same actor restricted session",
    );

    assert.equal(
      document.getElementById("currentUserName").textContent,
      restrictedPrincipal.name,
    );
    assertPermission(document, "read", "disabled");
    assertPermission(document, "write", "enabled");
    assert.match(
      document.getElementById("roleGuideCapabilities").textContent,
      /网页流程当前不可用/,
    );
    assert.equal(document.getElementById("editor").hidden, true);
    assert.equal(document.getElementById("welcomeCard").hidden, false);
    assert.equal(document.getElementById("draftList").getAttribute("aria-busy"), "false");
    assert.match(
      document.getElementById("draftEmptyText").textContent,
      /网页端需要 read（查看）权限/,
    );
    assert.doesNotMatch(document.body.textContent, new RegExp(sensitive));
    for (const field of document.querySelectorAll("input, textarea")) {
      assert.doesNotMatch(String(field.value), new RegExp(sensitive));
    }
    assert.equal(
      requests.filter(
        (request) =>
          request.startsWith("GET /api/v1/drafts?") &&
          request.includes("limit="),
      ).length,
      2,
    );
    await assertNoRuntimeErrors(runtimeErrors);
  } finally {
    dom.window.close();
  }
}

async function main() {
  await testHealthSurvivesUnauthenticatedSessionReset();
  await testStaleAccountResponsesCannotOverwriteNewSession();
  await testDelayedFileReadCannotWriteAfterLogout();
  await testSameActorReadRevocationScrubsRecoveredWorkspace();

  await renderFor(null, async ({ document }) => {
    const guide = document.getElementById("roleGuide");
    assert.equal(guide.hidden, true);
    assert.equal(guide.hasAttribute("data-guide-level"), false);
    assert.equal(guide.hasAttribute("data-principal-id"), false);
    assert.equal(document.getElementById("roleGuideSummary").textContent, "");
    assert.equal(document.getElementById("roleGuidePermissions").children.length, 0);
    assert.equal(document.getElementById("roleGuideSteps").children.length, 0);
    assert.equal(document.getElementById("roleGuideCapabilities").children.length, 0);
    assert.equal(document.getElementById("roleGuideRestrictions").children.length, 0);
  });

  await renderFor(
    account("role-spoof", ["read"], {
      role: "全流程权限账号",
    }),
    async ({ document }) => {
      const guide = document.getElementById("roleGuide");
      assert.equal(guide.dataset.guideLevel, "viewer");
      assert.equal(document.getElementById("roleGuideTitle").textContent, "监督查看账号");
      assert.match(document.getElementById("roleGuideContext").textContent, /全流程权限账号/);
      assertPermission(document, "read", "enabled");
      assertPermission(document, "write", "disabled");
      assertPermission(document, "confirm", "disabled");
      assertPermission(document, "submit", "disabled");
    },
  );

  await renderFor(account("viewer", ["read"]), async ({ document }) => {
    const capabilities = listText(document, "roleGuideCapabilities").join("\n");
    const restrictions = listText(document, "roleGuideRestrictions").join("\n");
    assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "viewer");
    assert.match(capabilities, /查看草稿/);
    assert.match(capabilities, /只读智能任务/);
    assertNoPrivilegedCapabilities(capabilities);
    assert.match(restrictions, /write（编辑）权限/);
    assert.match(restrictions, /confirm（确认）权限/);
    assert.match(restrictions, /submit（提交）权限/);
  });

  await renderFor(account("editor", ["read", "write"]), async ({ document }) => {
    const capabilities = listText(document, "roleGuideCapabilities").join("\n");
    assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "editor");
    assertPermission(document, "read", "enabled");
    assertPermission(document, "write", "enabled");
    assertPermission(document, "confirm", "disabled");
    assertPermission(document, "submit", "disabled");
    assert.match(capabilities, /新建、导入、编辑草稿/);
    assert.doesNotMatch(capabilities, /完成企业账号人工确认/);
    assert.doesNotMatch(capabilities, /提交已经确认/);
  });

  await renderFor(
    account("confirmer", ["read", "confirm"]),
    async ({ document }) => {
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      const restrictions = listText(document, "roleGuideRestrictions").join("\n");
      assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "confirmer");
      assertPermission(document, "read", "enabled");
      assertPermission(document, "write", "disabled");
      assertPermission(document, "confirm", "enabled");
      assertPermission(document, "submit", "disabled");
      assert.match(capabilities, /完成企业账号人工确认/);
      assert.doesNotMatch(capabilities, /新建、导入、编辑草稿/);
      assert.doesNotMatch(capabilities, /提交已经确认/);
      assert.match(restrictions, /退回经办人修改/);
    },
  );

  await renderFor(
    account("submitter", ["read", "submit"]),
    async ({ document }) => {
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      const restrictions = listText(document, "roleGuideRestrictions").join("\n");
      assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "submitter");
      assertPermission(document, "read", "enabled");
      assertPermission(document, "write", "disabled");
      assertPermission(document, "confirm", "disabled");
      assertPermission(document, "submit", "enabled");
      assert.match(capabilities, /提交已经确认/);
      assert.doesNotMatch(capabilities, /完成企业账号人工确认/);
      assert.match(restrictions, /不能代替确认人/);
    },
  );

  await renderFor(
    account("write-confirm", ["read", "write", "confirm"]),
    async ({ document }) => {
      const guide = document.getElementById("roleGuide");
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      assert.equal(guide.dataset.guideLevel, "write-confirm");
      assert.equal(document.getElementById("roleGuideTitle").textContent, "经办兼确认账号");
      assertPermission(document, "write", "enabled");
      assertPermission(document, "confirm", "enabled");
      assertPermission(document, "submit", "disabled");
      assert.match(capabilities, /新建、导入、编辑草稿/);
      assert.match(capabilities, /完成企业账号人工确认/);
      assert.doesNotMatch(capabilities, /提交已经确认/);
    },
  );

  await renderFor(
    account("write-submit", ["read", "write", "submit"]),
    async ({ document }) => {
      const guide = document.getElementById("roleGuide");
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      const restrictions = listText(document, "roleGuideRestrictions").join("\n");
      assert.equal(guide.dataset.guideLevel, "write-submit");
      assert.equal(document.getElementById("roleGuideTitle").textContent, "经办兼报送账号");
      assertPermission(document, "write", "enabled");
      assertPermission(document, "confirm", "disabled");
      assertPermission(document, "submit", "enabled");
      assert.match(capabilities, /新建、导入、编辑草稿/);
      assert.match(capabilities, /提交已经确认/);
      assert.doesNotMatch(capabilities, /完成企业账号人工确认/);
      assert.match(restrictions, /不能代替确认人/);
    },
  );

  await renderFor(
    account("confirm-submit", ["read", "confirm", "submit"]),
    async ({ document }) => {
      const guide = document.getElementById("roleGuide");
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      const restrictions = listText(document, "roleGuideRestrictions").join("\n");
      assert.equal(guide.dataset.guideLevel, "confirm-submit");
      assert.equal(document.getElementById("roleGuideTitle").textContent, "确认与报送账号");
      assertPermission(document, "write", "disabled");
      assertPermission(document, "confirm", "enabled");
      assertPermission(document, "submit", "enabled");
      assert.doesNotMatch(capabilities, /新建、导入、编辑草稿/);
      assert.match(capabilities, /完成企业账号人工确认/);
      assert.match(capabilities, /提交已经确认/);
      assert.match(restrictions, /退回经办人修改/);
    },
  );

  await renderFor(
    account("full-flow", ["read", "write", "confirm", "submit"]),
    async ({ document }) => {
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "full-flow");
      assert.equal(
        document.getElementById("roleGuideTitle").textContent,
        "全流程权限账号",
      );
      assert.equal(document.getElementById("roleGuideLevelBadge").textContent, "全流程");
      for (const permission of ["read", "write", "confirm", "submit"]) {
        assertPermission(document, permission, "enabled");
      }
      assert.match(capabilities, /查看草稿/);
      assert.match(capabilities, /新建、导入、编辑草稿/);
      assert.match(capabilities, /完成企业账号人工确认/);
      assert.match(capabilities, /提交已经确认/);
    },
  );

  await renderFor(
    account("demo", ["read", "write", "confirm", "submit"], {
      name: "本机演示用户",
      role: "演示管理员",
      must_change_password: true,
      temporary_demo: true,
    }),
    async ({ document }) => {
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      const restrictions = listText(document, "roleGuideRestrictions").join("\n");
      assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "demo");
      assertPermission(document, "read", "enabled");
      assertPermission(document, "write", "enabled");
      assertPermission(document, "confirm", "locked");
      assertPermission(document, "submit", "locked");
      assert.doesNotMatch(capabilities, /完成企业账号人工确认/);
      assert.doesNotMatch(capabilities, /提交已经确认/);
      assert.match(restrictions, /演示账号仅限本机体验/);
      assert.match(restrictions, /凭据限制解除前不会生效/);
    },
  );

  await renderFor(
    account("locked", ["read", "write", "confirm", "submit"], {
      must_change_password: true,
    }),
    async ({ document }) => {
      assert.equal(
        document.getElementById("roleGuide").dataset.guideLevel,
        "credential-locked",
      );
      assertPermission(document, "confirm", "locked");
      assertPermission(document, "submit", "locked");
      assert.match(
        document.getElementById("roleGuideRestrictions").textContent,
        /待换密状态由后端强制锁住确认和提交/,
      );
    },
  );

  const noReadPermissionSets = [
    ["write"],
    ["confirm"],
    ["submit"],
    ["write", "confirm"],
    ["write", "submit"],
    ["confirm", "submit"],
    ["write", "confirm", "submit"],
  ];
  for (const permissions of noReadPermissionSets) {
    const suffix = permissions.join("-");
    await renderFor(
      account(`no-read-${suffix}`, permissions),
      async ({ document, window, requests }) => {
        const capabilities = listText(
          document,
          "roleGuideCapabilities",
        );
        assert.equal(capabilities.length, 1);
        assert.match(capabilities[0], /网页流程当前不可用/);
        assertNoPrivilegedCapabilities(capabilities.join("\n"));
        assertPermission(document, "read", "disabled");
        for (const permission of permissions) {
          assertPermission(document, permission, "enabled");
        }
        assert.equal(document.getElementById("newDraftButton").disabled, true);
        assert.equal(document.getElementById("welcomeStartButton").disabled, true);
        assert.equal(document.getElementById("coalChatButton").disabled, true);
        assert.match(
          document.getElementById("draftEmptyText").textContent,
          /网页端需要 read（查看）权限/,
        );
        assert.match(
          document.getElementById("roleGuideRestrictions").textContent,
          /权限组合缺少 read（查看）/,
        );
        if (permissions.length === 1 && permissions[0] === "write") {
          const createRequestsBefore = requests.filter(
            (request) => request === "POST /api/v1/drafts",
          ).length;
          document.getElementById("newDraftButton").click();
          document.getElementById("newDraftButton").dispatchEvent(
            new window.Event("click", { bubbles: true, cancelable: true }),
          );
          await new Promise((resolve) => setTimeout(resolve, 20));
          const createRequestsAfter = requests.filter(
            (request) => request === "POST /api/v1/drafts",
          ).length;
          assert.equal(createRequestsAfter, createRequestsBefore);
          assert.match(
            document.getElementById("toastRegion").textContent,
            /需要同时具有查看和编辑权限才能新建填报/,
          );
        }
      },
    );
  }

  await renderFor(
    account("malformed", "read,write,confirm,submit"),
    async ({ document }) => {
      const capabilities = listText(document, "roleGuideCapabilities").join("\n");
      assert.equal(document.getElementById("roleGuide").dataset.guideLevel, "invalid");
      assert.equal(document.getElementById("newDraftButton").disabled, true);
      assert.equal(document.getElementById("coalChatButton").disabled, true);
      for (const permission of ["read", "write", "confirm", "submit"]) {
        assertPermission(document, permission, "disabled");
      }
      assert.match(capabilities, /网页流程当前不可用/);
      assertNoPrivilegedCapabilities(capabilities);
    },
  );

  await renderFor(
    account("xss", ["read"], {
      name: '<script>window.roleGuideXss = "name"</script>',
      role: '<img src=x onerror="window.roleGuideXss = \'role\'">',
    }),
    async ({ document, window }) => {
      const guide = document.getElementById("roleGuide");
      assert.match(guide.textContent, /<script>window\.roleGuideXss/);
      assert.match(guide.textContent, /<img src=x onerror=/);
      assert.equal(guide.querySelector("script"), null);
      assert.equal(guide.querySelector("img"), null);
      assert.equal(window.roleGuideXss, undefined);
      assert.equal(guide.dataset.guideLevel, "viewer");
    },
  );

  const sensitive = "ROLE-GUIDE-SENSITIVE-9f31a7";
  await renderFor(
    account(sensitive, ["read", "write", "confirm", "submit"], {
      name: sensitive,
      role: sensitive,
    }),
    async ({ document, requests }) => {
      const guide = document.getElementById("roleGuide");
      assert.equal(guide.dataset.principalId, sensitive);
      assert.match(document.body.textContent, new RegExp(sensitive));

      const textEntryIds = [
        "draftSearch",
        "sourceContent",
        "coalChatInput",
        "agentTaskInput",
        "deleteConfirmation",
        "loginActorId",
        "loginPassword",
      ];
      for (const id of textEntryIds) {
        document.getElementById(id).value = sensitive;
      }
      document
        .querySelectorAll(
          '#draftForm input:not([type="checkbox"]):not([type="radio"]):not([type="file"]):not([type="datetime-local"]), #draftForm textarea',
        )
        .forEach((field) => {
          field.value = sensitive;
        });

      const dynamicContainerIds = [
        "draftList",
        "sourceList",
        "measurementBody",
        "questionList",
        "preflightSummary",
        "checkList",
        "confirmationOverview",
        "submissionGate",
        "receiptDetails",
        "submissionHistory",
        "auditHistory",
        "sourceDialogBody",
        "agentToolCatalog",
        "agentRunList",
        "agentRunAnswer",
        "agentApprovalDetails",
        "agentStepList",
        "coalChatSessionList",
        "coalChatMessageList",
      ];
      for (const id of dynamicContainerIds) {
        const marker = document.createElement("span");
        marker.textContent = sensitive;
        document.getElementById(id).replaceChildren(marker);
      }

      assert(
        Array.from(document.querySelectorAll("input, textarea")).some((field) =>
          String(field.value).includes(sensitive),
        ),
        "test setup must place the marker in form values",
      );
      for (const id of dynamicContainerIds) {
        assert.match(document.getElementById(id).textContent, new RegExp(sensitive));
      }

      document.getElementById("logoutButton").click();
      await waitFor(
        () =>
          requests.includes("POST /api/v1/auth/logout") &&
          guide.hidden === true &&
          document.getElementById("loginDialog").hasAttribute("open"),
        "explicit logout cleanup",
      );

      assert.doesNotMatch(document.body.textContent, new RegExp(sensitive));
      assert.doesNotMatch(document.body.outerHTML, new RegExp(sensitive));
      for (const field of document.querySelectorAll("input, textarea")) {
        assert.doesNotMatch(String(field.value), new RegExp(sensitive));
      }
      assert.equal(guide.hasAttribute("data-principal-id"), false);
      assert.equal(guide.hasAttribute("data-guide-level"), false);
      assert(
        Object.values(guide.dataset).every(
          (value) => !String(value).includes(sensitive),
        ),
      );
      for (const id of dynamicContainerIds) {
        assert.doesNotMatch(
          document.getElementById(id).textContent,
          new RegExp(sensitive),
        );
      }
      assert.equal(document.getElementById("roleGuideContext").textContent, "");
      assert.equal(document.getElementById("roleGuidePermissions").children.length, 0);
      assert.equal(document.getElementById("roleGuideSteps").children.length, 0);
      assert.equal(document.getElementById("roleGuideCapabilities").children.length, 0);
      assert.equal(document.getElementById("roleGuideRestrictions").children.length, 0);
    },
  );

  console.log("JSDOM role guidance permission matrix checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
