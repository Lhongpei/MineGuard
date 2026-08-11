"use strict";

const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const root = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(root, "web", "index.html"), "utf8");
const script = fs.readFileSync(path.join(root, "web", "v2-app.js"), "utf8");

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return JSON.stringify(payload);
    },
  };
}

function waitFor(predicate, label, timeoutMs = 3000) {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    function poll() {
      try {
        if (predicate()) return resolve();
      } catch (error) {
        return reject(error);
      }
      if (Date.now() - started > timeoutMs) {
        return reject(new Error(`Timed out: ${label}`));
      }
      setTimeout(poll, 10);
    }
    poll();
  });
}

const metricSpecs = [
  ["ventilation_m3_min", "m3/min", "time_weighted_average", 4800],
  ["electricity_kwh", "kWh", "sum", 96000],
  ["detonators_count", "count", "sum", 120],
  ["explosives_kg", "kg", "sum", 240],
  ["mine_entry_persons", "person", "sum", 320],
  ["production_t", "t", "sum", 2600],
  ["extraction_t", "t", "sum", 2660],
  ["sales_t", "t", "sum", 2500],
  ["transport_t", "t", "sum", 2480],
  ["wash_feed_t", "t", "sum", 2550],
  ["invoiced_quantity_t", "t", "sum", 2440],
];

function measurements() {
  return Object.fromEntries(
    metricSpecs.map(([metric, unit, aggregation, value]) => [
      metric,
      {
        metric_code: metric,
        value,
        unit,
        aggregation,
        quality_flags: ["reported"],
        source_refs: ["source-ledger"],
      },
    ]),
  );
}

const firstMessageId = "11111111-1111-4111-8111-111111111111";
const basePayload = {
  mine: {
    mine_id: "MINE-CORRECTION-DOM",
    mine_name: "更正链测试煤矿",
    operator_id: "operator-correction-dom",
    operator_name: "更正链测试煤业",
  },
  reporting_month: "2026-07",
  timezone: "Asia/Shanghai",
  period_start: "2026-07-01",
  period_end: "2026-07-01",
  closed_at: "2026-07-02T00:00:00+08:00",
  comparison_context: {
    capacity_band: "medium",
    mining_method: "underground",
    shift_system: "three-shift-eight-hour",
    coal_type: "bituminous",
    operating_regime: "normal-production",
  },
  days: [
    {
      date: "2026-07-01",
      operating_state: "producing",
      reported_quantity: { daily_total: measurements(), shifts: {} },
    },
  ],
  sources: [
    {
      source_id: "source-ledger",
      acquisition_mode: "manual_import",
      source_system: "enterprise-ledger",
      source_record_id: "ledger-2026-07",
      source_location: "controlled-import",
      captured_at: "2026-07-01T23:00:00+08:00",
      media_type: "text/csv",
      evidence_sha256: "a".repeat(64),
      normalization: "deterministic",
    },
  ],
  agent_processing: {
    normalization_performed: true,
    model_assistance_used: false,
    processing_record_sha256: "b".repeat(64),
  },
};

const submitted = {
  draft_id: "draft-submitted-r1",
  import_id: "import-submitted-r1",
  revision: 1,
  submission_revision: 1,
  correlation_id: firstMessageId,
  predecessor: null,
  contract_version: "ten-quantity-submission-v3",
  read_only: false,
  status: "submitted",
  payload: basePayload,
  review_gate: { required: false },
  receipt: { payload: { receipt_id: "government-receipt-r1" } },
};

const correction = {
  ...submitted,
  draft_id: "draft-correction-r2",
  import_id: "import-correction-r2",
  submission_revision: 2,
  predecessor: {
    message_id: firstMessageId,
    payload_sha256: "c".repeat(64),
  },
  status: "ready_review",
  receipt: null,
};

async function main() {
  const requests = [];
  const runtimeErrors = [];
  let correctionCreated = false;
  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    requests.push({ path: url.pathname, method, options });
    if (url.pathname === "/api/v1/auth/me") {
      return response({
        principal: {
          actor_id: "preparer-2",
          name: "更正经办人",
          role: "企业填报员",
          permissions: ["read", "write", "confirm", "submit"],
          must_change_password: false,
          temporary_demo: false,
        },
        csrf_token: "csrf-correction-test",
      });
    }
    if (url.pathname === "/api/v2/status") {
      return response({
        mine_id: basePayload.mine.mine_id,
        mine_name: basePayload.mine.mine_name,
        operator_id: basePayload.mine.operator_id,
        system_id: "agent-correction-dom",
        watched_directories: [],
        platform_configured: true,
      });
    }
    if (url.pathname === "/api/v2/imports") return response({ items: [] });
    if (url.pathname === "/api/v2/drafts") {
      return response({ items: correctionCreated ? [correction, submitted] : [submitted] });
    }
    if (url.pathname === "/api/v2/risks") return response({ items: [] });
    if (url.pathname === "/api/v2/audit") {
      return response({ valid: true, head_hash: "d".repeat(64), events: [] });
    }
    if (url.pathname.endsWith("/ingestions")) {
      return response({
        items: [],
        latest_preflight: null,
        sync_state: null,
        source_health: [],
        freshness: { overall_state: "not_applicable", stale_required_source_ids: [] },
      });
    }
    if (
      url.pathname === `/api/v2/drafts/${submitted.draft_id}/correction` &&
      method === "POST"
    ) {
      assert.equal(options.headers["X-CSRF-Token"], "csrf-correction-test");
      assert.deepEqual(JSON.parse(options.body), {
        expected_revision: 1,
        expected_submission_revision: 1,
        accepted: true,
      });
      correctionCreated = true;
      return response({ draft: correction, created: true, duplicate: false }, 201);
    }
    if (url.pathname === `/api/v2/drafts/${submitted.draft_id}`) {
      return response(submitted);
    }
    if (url.pathname === `/api/v2/drafts/${correction.draft_id}`) {
      return response(correction);
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}`);
  }

  const instrumented = html
    .replace('<script src="./app.js" defer></script>', "")
    .replace('<script src="./v2-app.js" defer></script>', `<script>${script}</script>`);
  const dom = new JSDOM(instrumented, {
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
  try {
    const { document } = dom.window;
    await waitFor(
      () => document.querySelector(`[data-draft-id="${submitted.draft_id}"]`),
      "submitted draft list",
    );
    document.querySelector(`[data-draft-id="${submitted.draft_id}"]`).click();
    await waitFor(
      () => document.querySelector('[data-fq-action="create-correction"]'),
      "create correction action",
    );
    document.querySelector('[data-fq-action="create-correction"]').click();
    await waitFor(
      () => /第 2 版正式更正草稿/.test(document.getElementById("fqDraftDetail").textContent),
      "opened correction draft",
    );
    assert.match(document.getElementById("fqDraftDetail").textContent, /直接前序消息/);
    assert.equal(
      document.querySelector('[data-fq-action="discard-draft"]'),
      null,
      "正式更正草稿不能被放弃，否则唯一后继链会永久卡死",
    );
    assert.match(document.getElementById("fqGlobalMessage").textContent, /第 2 版更正草稿已创建/);
    assert.equal(
      requests.filter((item) => item.path.endsWith("/correction")).length,
      1,
    );
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
    console.log("JSDOM ten-quantity correction flow checks passed");
  } finally {
    dom.window.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
