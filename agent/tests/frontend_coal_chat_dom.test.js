"use strict";

const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const projectRoot = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(projectRoot, "web", "index.html"), "utf8");
const app = fs.readFileSync(path.join(projectRoot, "web", "app.js"), "utf8");

const draft = {
  draft_id: "draft-coal-1",
  revision: 1,
  status: "draft",
  enterprise_id: "enterprise-1",
  enterprise_name: "示范煤业",
  mine_id: "mine-1",
  mine_name: "一号矿",
  window_start: "2026-07-01T00:00:00Z",
  window_end: "2026-07-31T23:59:59Z",
  observations: [],
  sources: [],
  questions: [],
  approval_events: [],
  operational_context: {},
  signature: { valid: false },
};

const sessions = new Map([
  [
    "chat-good",
    {
      session_id: "chat-good",
      title: "七月煤量分析",
      draft_id: "",
      status: "active",
      integrity: { valid: true, event_count: 2, head_hash: "a".repeat(64) },
      created_at: "2026-07-27T01:00:00Z",
      updated_at: "2026-07-27T01:01:00Z",
      messages: [
        {
          message_id: "old-user",
          role: "user",
          content: "原煤产量怎么看？",
          status: "completed",
          created_at: "2026-07-27T01:00:00Z",
        },
        {
          message_id: "old-assistant",
          role: "assistant",
          content: '<img src=x onerror="window.chatXss=true">请先核对计量口径。',
          status: "completed",
          evidence: {
            answer_kind: "local_knowledge",
            local_knowledge_topic: "measurement_calibration",
          },
          created_at: "2026-07-27T01:01:00Z",
        },
        {
          message_id: "model-assistant",
          role: "assistant",
          content: "煤的燃点会随煤种和试验条件变化。",
          status: "completed",
          evidence: {
            answer_kind: "model_common_knowledge",
            model_generated: true,
          },
          created_at: "2026-07-27T01:01:30Z",
        },
        {
          message_id: "tool-assistant",
          role: "assistant",
          content: "已核对当前草稿中的煤量平衡。",
          status: "completed",
          evidence: {
            answer_kind: "draft_tool_evidence",
            tools: [
              {
                tool_name: "coal_flow_balance",
                status: "succeeded",
                evidence_grounding: "repository_grounded",
              },
            ],
          },
          created_at: "2026-07-27T01:01:40Z",
        },
        {
          message_id: "news-assistant",
          role: "assistant",
          content: "<b>近期煤炭新闻摘要</b>",
          status: "completed",
          evidence: {
            answer_kind: "news_retrieval",
            skill_name: "coal-news-search",
            model_generated: true,
            summary: {
              status: "succeeded",
              provider: "deepseek-chat-completions",
              grounding: "search_title_and_snippet",
              source_count: 1,
            },
            retrieval: {
              status: "succeeded",
              searched_at: "2026-07-28T09:05:00Z",
              window_days: 7,
              result_count: 5,
              provider: "test-search",
            },
            sources: [
              {
                source_id: "S1",
                title: "<img src=x onerror=window.newsXss=true> 合法新闻",
                publisher: "测试通讯社",
                url: "https://news.example.com/coal?id=1",
                search_snippet:
                  "<script>window.newsSnippetXss=true</script>煤炭搜索片段",
                published_at: "2026-07-28T08:00:00Z",
                retrieved_at: "2026-07-28T09:05:00Z",
                retrieval_provider: "baidu-news-search",
              },
              {
                title: "脚本链接",
                publisher: "恶意来源",
                url: "javascript:alert(1)",
              },
              {
                title: "带凭据链接",
                publisher: "恶意来源",
                url: "https://user:pass@example.com/private",
              },
              {
                title: "本机链接",
                publisher: "恶意来源",
                url: "https://localhost/admin",
              },
              {
                title: "私网链接",
                publisher: "恶意来源",
                url: "https://192.168.1.8/internal",
              },
            ],
          },
          created_at: "2026-07-28T09:05:00Z",
        },
        {
          message_id: "news-empty-assistant",
          role: "assistant",
          content: "检索服务声称成功但没有安全来源。",
          status: "completed",
          evidence: {
            answer_kind: "news_retrieval",
            skill_name: "coal-news-search",
            retrieval: {
              status: "succeeded",
              searched_at: "2026-07-28T09:05:00Z",
              result_count: 1,
            },
            sources: [
              {
                title: "数据链接",
                publisher: "无效来源",
                url: "data:text/html,unsafe",
              },
            ],
          },
          created_at: "2026-07-28T09:05:10Z",
        },
        {
          message_id: "news-no-results-assistant",
          role: "assistant",
          content: "当前条件下没有检索到可核验的新闻来源。",
          status: "completed",
          evidence: {
            answer_kind: "news_retrieval",
            skill_name: "coal-news-search",
            retrieval: {
              status: "failed",
              failure_code: "no_results",
              searched_at: "2026-07-28T09:06:00Z",
              result_count: 0,
              provider: "test-search",
            },
            sources: [],
          },
          created_at: "2026-07-28T09:06:00Z",
        },
      ],
    },
  ],
  [
    "chat-bad",
    {
      session_id: "chat-bad",
      title: "完整性异常记录",
      status: "active",
      integrity: null,
      created_at: "2026-07-27T02:00:00Z",
      updated_at: "2026-07-27T02:01:00Z",
      messages: [
        {
          message_id: "forged",
          role: "assistant",
          content: "伪造对话正文绝不能显示",
          status: "completed",
        },
      ],
    },
  ],
  [
    "chat-legacy",
    {
      session_id: "chat-legacy",
      title: "旧版工具记录",
      status: "active",
      created_at: "2026-07-27T02:10:00Z",
      updated_at: "2026-07-27T02:11:00Z",
      messages: [
        {
          message_id: "legacy-tool",
          role: "assistant",
          content: "旧服务声称完成了一次工具核验。",
          status: "completed",
          evidence: {
            tools: [
              {
                tool_name: "coal_flow_balance",
                status: "succeeded",
                evidence_grounding: "repository_grounded",
              },
            ],
          },
        },
      ],
    },
  ],
]);

const requests = [];
const postedBodies = [];
let chatGetAfterPost = 0;
let chatDeleted = false;
let messagePostCount = 0;
let sessionPostCount = 0;

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function response(payload, status = 200) {
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

function listSessions() {
  return Array.from(sessions.values())
    .filter((item) => !(chatDeleted && item.session_id === "chat-good"))
    .map((item) => ({
      session_id: item.session_id,
      title: item.title,
      draft_id: item.draft_id || "",
      created_at: item.created_at,
      updated_at: item.updated_at,
    }));
}

async function fakeFetch(input, options = {}) {
  const url = new URL(String(input), "http://127.0.0.1:8090/");
  const method = String(options.method || "GET").toUpperCase();
  requests.push(`${method} ${url.pathname}${url.search}`);

  if (url.pathname === "/api/v1/health") {
    return response({
      status: "ok",
      llm_mode: "configured",
      platform_configured: false,
    });
  }
  if (url.pathname === "/api/v1/auth/me") {
    return response({
      principal: {
        actor_id: "leader-1",
        name: "测试领导",
        role: "负责人",
        permissions: ["read", "write"],
      },
      csrf_token: "csrf-chat-test",
    });
  }
  if (url.pathname === "/api/v1/platform-status") {
    return response({ configured: false, message: "未配置" });
  }
  if (url.pathname === "/api/v1/drafts" && method === "GET") {
    return response({
      items: [
        {
          draft_id: draft.draft_id,
          status: "draft",
          enterprise_name: draft.enterprise_name,
          mine_name: draft.mine_name,
          updated_at: "2026-07-27T00:00:00Z",
        },
      ],
      total: 1,
      has_more: false,
    });
  }
  if (
    url.pathname === `/api/v1/drafts/${draft.draft_id}` &&
    method === "GET"
  ) {
    return response({ draft });
  }
  if (
    url.pathname === `/api/v1/drafts/${draft.draft_id}/reviews` &&
    method === "GET"
  ) {
    return response({
      review_state: {
        reviewed_observation_ids: [],
        all_reviewed: false,
      },
    });
  }
  if (url.pathname === "/api/v1/chat/sessions" && method === "GET") {
    const items = listSessions();
    return response({ sessions: items, total: items.length });
  }
  if (url.pathname === "/api/v1/chat/sessions" && method === "POST") {
    sessionPostCount += 1;
    const body = JSON.parse(options.body);
    postedBodies.push(body);
    const created = {
      session_id: "chat-new",
      client_request_id: body.client_request_id,
      title: body.title,
      draft_id: body.draft_id,
      status: "active",
      integrity: { valid: true, event_count: 1, head_hash: "b".repeat(64) },
      created_at: "2026-07-27T03:00:00Z",
      updated_at: "2026-07-27T03:00:00Z",
      messages: [],
    };
    sessions.set(created.session_id, created);
    return response({ session: created }, 201);
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-good" &&
    method === "GET"
  ) {
    const session = sessions.get("chat-good");
    if (messagePostCount && chatGetAfterPost < 2) {
      chatGetAfterPost += 1;
    } else if (messagePostCount) {
      const pending = session.messages.find(
        (message) => message.message_id === "async-assistant",
      );
      if (pending && pending.status === "processing") {
        pending.status = "completed";
        pending.content = "产量差异应先核对入洗量、库存变化和计量时间窗。";
        session.updated_at = "2026-07-27T04:02:00Z";
      }
    }
    return response({ session });
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-bad" &&
    method === "GET"
  ) {
    return response({ session: sessions.get("chat-bad") });
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-new" &&
    method === "GET"
  ) {
    return response({ session: sessions.get("chat-new") });
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-legacy" &&
    method === "GET"
  ) {
    return response({ session: sessions.get("chat-legacy") });
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-good/messages" &&
    method === "POST"
  ) {
    messagePostCount += 1;
    const body = JSON.parse(options.body);
    postedBodies.push(body);
    const session = sessions.get("chat-good");
    session.messages.push({
      message_id: `user-${messagePostCount}`,
      client_message_id: body.client_message_id,
      role: "user",
      content: body.content,
      status: "completed",
      created_at: "2026-07-27T04:00:00Z",
    });
    if (body.content.includes("天气")) {
      session.messages.push({
        message_id: "scope-refusal",
        role: "assistant",
        content: "天气预报不属于煤炭业务范围，请改问煤矿生产或煤炭数据问题。",
        status: "rejected",
        scope_status: "out_of_scope",
        evidence: { answer_kind: "out_of_scope" },
        created_at: "2026-07-27T04:03:00Z",
      });
      return response({ session });
    }
    session.messages.push({
      message_id: "async-assistant",
      role: "assistant",
      content: "",
      status: "processing",
      created_at: "2026-07-27T04:01:00Z",
    });
    chatGetAfterPost = 0;
    return response(
      {
        status: "processing",
        run_id: "chat-run-1",
        assistant_message: {
          message_id: "async-assistant",
          role: "assistant",
          status: "processing",
        },
      },
      202,
    );
  }
  if (
    url.pathname === "/api/v1/chat/sessions/chat-good" &&
    method === "DELETE"
  ) {
    await new Promise((resolve) => setTimeout(resolve, 30));
    chatDeleted = true;
    sessions.delete("chat-good");
    return response(null, 204);
  }
  throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
}

function waitFor(predicate, message, timeoutMs = 5000) {
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
  const { document, Event, KeyboardEvent } = dom.window;
  Object.defineProperty(document, "hidden", {
    configurable: true,
    value: false,
  });

  await waitFor(
    () => document.querySelector(".draft-item"),
    "draft list",
  );
  document.querySelector(".draft-item").click();
  await waitFor(
    () => document.getElementById("draftTitle").textContent.includes("示范煤业"),
    "active draft",
  );

  document.getElementById("coalChatButton").click();
  await waitFor(
    () => document.querySelectorAll(".coal-chat-session-item").length === 3,
    "chat sessions",
  );
  await waitFor(
    () => document.getElementById("coalChatTitle").textContent.includes("七月煤量"),
    "first session",
  );
  assert.equal(document.getElementById("coalChatUseCurrentDraft").checked, true);
  assert.match(
    document.getElementById("coalChatDraftBinding").textContent,
    /一号矿/,
  );
  assert.equal(
    document.querySelectorAll(".coal-chat-message-body img").length,
    0,
    "assistant content must never be interpreted as HTML",
  );
  assert.match(document.body.textContent, /<img src=x onerror=/);
  assert.equal(dom.window.chatXss, undefined);
  assert.match(document.body.textContent, /本地煤炭常识/);
  assert.match(document.body.textContent, /模型通识解释/);
  assert.match(document.body.textContent, /草稿工具证据/);
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-model-knowledge")
      .textContent,
    /未核验企业数据，不是数据事实或监管结论/,
  );
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-tool-evidence").title,
    /coal_flow_balance/,
  );
  assert.equal(
    document.getElementById("assistantStatusText").textContent,
    "模型已配置（调用时验证）",
  );
  assert.equal(
    document.querySelectorAll(".coal-chat-answer-source.is-news-retrieval").length,
    1,
    "only a retrieval with a valid source may be marked successful",
  );
  assert.equal(
    document.querySelectorAll(".coal-chat-answer-source.is-news-failed").length,
    1,
    "a claimed success without a safe source must fail closed",
  );
  assert.equal(
    document.querySelectorAll(".coal-chat-answer-source.is-news-no-results")
      .length,
    1,
    "an empty successful search must not be mislabeled as a network failure",
  );
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-news-no-results")
      .textContent,
    /未检索到结果.*不代表没有新闻/s,
  );
  assert.match(document.body.textContent, /检索失败.*未成功/s);
  const newsLinks = Array.from(
    document.querySelectorAll(".coal-chat-news-source-card"),
  );
  assert.equal(newsLinks.length, 1, "unsafe news source URLs must be dropped");
  assert.equal(newsLinks[0].protocol, "https:");
  assert.equal(newsLinks[0].target, "_blank");
  assert.equal(newsLinks[0].rel, "noopener noreferrer");
  assert.equal(newsLinks[0].referrerPolicy, "no-referrer");
  assert.match(newsLinks[0].textContent, /测试通讯社/);
  assert.match(newsLinks[0].textContent, /S1/);
  assert.match(newsLinks[0].textContent, /百度标注来源/);
  assert.match(newsLinks[0].textContent, /搜索片段（可能截断，未核验正文）/);
  assert.match(newsLinks[0].textContent, /煤炭搜索片段/);
  assert.match(newsLinks[0].textContent, /发布时间：/);
  assert.match(newsLinks[0].textContent, /检索时间：/);
  assert.equal(document.querySelectorAll(".coal-chat-news-source-card img").length, 0);
  assert.equal(document.querySelectorAll(".coal-chat-news-source-card script").length, 0);
  assert.equal(dom.window.newsXss, undefined);
  assert.equal(dom.window.newsSnippetXss, undefined);
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-news-retrieval")
      .textContent,
    /AI 联网摘要.*未读取新闻全文/s,
  );

  const legacyButton = Array.from(
    document.querySelectorAll(".coal-chat-session-item"),
  ).find((button) => button.textContent.includes("旧版工具记录"));
  assert(legacyButton, "legacy chat session missing");
  legacyButton.click();
  await waitFor(
    () => document.getElementById("coalChatTitle").textContent.includes("旧版工具"),
    "legacy session selected",
  );
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-unmarked").textContent,
    /工具记录未验真.*不能作为企业数据证据/s,
  );
  assert(
    !document.getElementById("coalChatMessageList").textContent.includes(
      "草稿工具证据",
    ),
    "unverified legacy tool record was presented as evidence",
  );

  document.getElementById("newCoalChatButton").click();
  document.getElementById("newCoalChatButton").click();
  await waitFor(() => sessionPostCount === 1, "single new-session request");
  await waitFor(
    () => document.getElementById("coalChatTitle").textContent.includes("煤炭业务对话"),
    "new session selected",
  );
  assert.equal(postedBodies[0].draft_id, draft.draft_id);
  assert.match(postedBodies[0].client_request_id, /^chat-session-/);

  const goodButton = Array.from(
    document.querySelectorAll(".coal-chat-session-item"),
  ).find((button) => button.textContent.includes("七月煤量分析"));
  assert(goodButton, "good chat session missing");
  goodButton.click();
  await waitFor(
    () => document.getElementById("coalChatTitle").textContent.includes("七月煤量"),
    "good session reselected",
  );

  const input = document.getElementById("coalChatInput");
  input.value = "结合当前草稿，解释本月产量差异。";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  const form = document.getElementById("coalChatForm");
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await waitFor(() => messagePostCount === 1, "one async message POST");
  assert.equal(document.getElementById("sendCoalChatButton").disabled, true);
  await waitFor(
    () =>
      document.body.textContent.includes(
        "产量差异应先核对入洗量、库存变化和计量时间窗。",
      ),
    "asynchronous assistant reply",
  );
  await waitFor(
    () => document.getElementById("sendCoalChatButton").disabled === true,
    "empty input remains disabled after reply",
  );
  assert.equal(messagePostCount, 1, "duplicate submit must stay suppressed");
  assert.equal(postedBodies[1].draft_id, draft.draft_id);
  assert.match(postedBodies[1].client_message_id, /^chat-message-/);

  input.value = "请告诉我明天北京天气。";
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(
    new KeyboardEvent("keydown", {
      key: "Enter",
      bubbles: true,
      cancelable: true,
    }),
  );
  await waitFor(() => messagePostCount === 2, "scope message POST");
  await waitFor(
    () => document.getElementById("coalChatScopeNotice").hidden === false,
    "clear out-of-scope notice",
  );
  assert.match(
    document.getElementById("coalChatScopeNotice").textContent,
    /超出煤炭业务范围/,
  );
  assert.match(
    document.querySelector(".coal-chat-answer-source.is-scope-refusal")
      .textContent,
    /范围控制/,
  );
  await waitFor(
    () => document.getElementById("newCoalChatButton").disabled === false,
    "scope refusal completion",
  );

  const badButton = Array.from(
    document.querySelectorAll(".coal-chat-session-item"),
  ).find((button) => button.textContent.includes("完整性异常记录"));
  assert(badButton, "invalid-integrity chat missing");
  badButton.click();
  await waitFor(
    () =>
      document.getElementById("coalChatMessageList").textContent.includes(
        "对话记录完整性异常，请联系管理员",
      ),
    "fail-closed chat detail",
  );
  assert(
    !document.body.textContent.includes("伪造对话正文绝不能显示"),
    "invalid-integrity message leaked",
  );
  assert.equal(document.getElementById("coalChatInput").disabled, true);
  assert.equal(document.getElementById("sendCoalChatButton").disabled, true);
  assert.equal(document.getElementById("deleteCoalChatButton").disabled, true);

  const goodAgain = Array.from(
    document.querySelectorAll(".coal-chat-session-item"),
  ).find((button) => button.textContent.includes("七月煤量分析"));
  goodAgain.click();
  await waitFor(
    () => document.getElementById("deleteCoalChatButton").disabled === false,
    "valid chat deletion enabled",
  );
  document.getElementById("deleteCoalChatButton").click();
  document.getElementById("deleteCoalChatButton").click();
  await waitFor(
    () =>
      requests.filter(
        (item) => item === "DELETE /api/v1/chat/sessions/chat-good",
      ).length === 1,
    "single DELETE request",
  );
  await waitFor(
    () =>
      !Array.from(document.querySelectorAll(".coal-chat-session-item")).some(
        (button) => button.textContent.includes("七月煤量分析"),
      ),
    "deleted chat removed",
  );

  assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
  dom.window.close();
  console.log("JSDOM coal chat checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
