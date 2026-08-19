"use strict";

const assert = require("assert").strict;
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const projectRoot = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(projectRoot, "web", "index.html"), "utf8");
const script = fs.readFileSync(path.join(projectRoot, "web", "v2-app.js"), "utf8");

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return payload == null ? "" : JSON.stringify(payload);
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

const metrics = [
  ["ventilation_m3_min", "m3/min", "time_weighted_average", 4800],
  ["electricity_kwh", "kWh", "sum", 96000],
  ["detonators_count", "count", "sum", 120],
  ["explosives_kg", "kg", "sum", 240],
  ["mine_entry_persons", "person", "sum", 320],
  ["production_t", "t", "sum", 2600],
];

function measurementSet(sourceId) {
  return Object.fromEntries(
    metrics.map(([metric, unit, aggregation, value]) => [
      metric,
      {
        metric_code: metric,
        value,
        unit,
        aggregation,
        quality_flags: ["reported"],
        source_refs: [sourceId],
      },
    ]),
  );
}

const draft = {
  draft_id: "fq-machine-draft-1",
  import_id: "fq-machine-import-2",
  revision: 4,
  submission_revision: 1,
  status: "ready_review",
  payload: {
    mine: {
      mine_id: "MINE-DOM-001",
      mine_name: "自动填报测试煤矿",
      operator_id: "operator-dom-001",
      operator_name: "自动填报测试煤业",
    },
    reporting_month: "2026-07",
    timezone: "Asia/Shanghai",
    period_start: "2026-07-01",
    period_end: "2026-07-01",
    closed_at: "2026-07-02T00:00:00+08:00",
    comparison_context: {
      capacity_band: "0.9-1.2Mtpa",
      mining_method: "underground-longwall",
      shift_system: "three-shift-eight-hour",
      coal_type: "thermal-coal",
      operating_regime: "normal-production",
    },
    days: [
      {
        date: "2026-07-01",
        operating_state: "producing",
        reported_quantity: {
          daily_total: measurementSet("source-erp"),
          shifts: {
            zero_shift: {
              shift_code: "ZERO",
              start_at: "2026-07-01T00:00:00+08:00",
              end_at: "2026-07-01T08:00:00+08:00",
              measurements: measurementSet("source-erp"),
            },
            eight_shift: {
              shift_code: "EIGHT",
              start_at: "2026-07-01T08:00:00+08:00",
              end_at: "2026-07-01T16:00:00+08:00",
              measurements: measurementSet("source-erp"),
            },
            four_shift: {
              shift_code: "FOUR",
              start_at: "2026-07-01T16:00:00+08:00",
              end_at: "2026-07-02T00:00:00+08:00",
              measurements: measurementSet("source-erp"),
            },
          },
        },
      },
    ],
    sources: [
      {
        source_id: "source-erp",
        acquisition_mode: "direct_collection",
        source_system: "ERP",
        source_record_id: "erp-20260701",
        source_location: "production_daily",
        captured_at: "2026-07-02T00:01:00+08:00",
        media_type: "application/json",
        evidence_sha256: "a".repeat(64),
        normalization: "deterministic mapping",
      },
    ],
    agent_processing: {
      normalization_performed: true,
      model_assistance_used: false,
      processing_record_sha256: "b".repeat(64),
    },
  },
};

async function main() {
  const requests = [];
  const runtimeErrors = [];
  let machineSyncResumed = false;
  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    requests.push(`${method} ${url.pathname}${url.search}`);
    if (url.pathname === "/api/v1/auth/me") {
      return response({
        principal: {
          actor_id: "fq-viewer",
          name: "五量复核查看人",
          role: "企业复核",
          permissions: ["read", "write", "confirm", "submit"],
          must_change_password: false,
          temporary_demo: false,
        },
        csrf_token: "csrf-fq-viewer",
      });
    }
    if (url.pathname === "/api/v2/status") {
      return response({
        mine_id: "MINE-DOM-001",
        mine_name: "自动填报测试煤矿",
        operator_id: "operator-dom-001",
        system_id: "agent-dom-001",
        watched_directories: [],
        platform_configured: false,
        machine_connector_enabled: true,
        connector_client_count: 1,
      });
    }
    if (url.pathname === "/api/v2/imports") {
      return response({
        items: [
          {
            import_id: draft.import_id,
            draft_id: draft.draft_id,
            filename: "erp-2026-07.json",
            acquisition_mode: "direct_collection",
            status: "ready_review",
            content_sha256: "c".repeat(64),
            suggestions: [],
          },
        ],
      });
    }
    if (url.pathname === "/api/v2/drafts") return response({ items: [draft] });
    if (url.pathname === `/api/v2/drafts/${draft.draft_id}`) {
      return response({
        ...draft,
        revision: machineSyncResumed ? 5 : draft.revision,
        sync_state: machineSyncResumed
          ? {
              state: "active",
              message: "机器来源可继续更新此待复核草稿",
              can_resume: false,
            }
          : {
              state: "paused",
              reason_code: "human_changes_detected",
              message: "检测到人工修改，自动同步已暂停以避免覆盖",
              can_resume: true,
            },
      });
    }
    if (
      url.pathname === `/api/v2/drafts/${draft.draft_id}/machine-resume` &&
      method === "POST"
    ) {
      const body = JSON.parse(options.body);
      assert.deepEqual(body, { expected_revision: 4, accepted: true });
      machineSyncResumed = true;
      return response({
        draft: {
          ...draft,
          revision: 5,
          sync_state: {
            state: "active",
            message: "机器来源可继续更新此待复核草稿",
            can_resume: false,
          },
        },
      });
    }
    if (url.pathname === `/api/v2/drafts/${draft.draft_id}/ingestions`) {
      return response({
        items: [
          {
            ingestion_id: "ingestion-1",
            client_id: "mine-authoritative-connector",
            source_id: "source-erp",
            source_name: "ERP 生产日报",
            source_system: "ERP",
            format: "json",
            status: "completed",
            event_id: "event-erp-202607-v2",
            request_hash: "d".repeat(12),
            created_at: "2026-07-02T00:01:00+08:00",
            completed_at: "2026-07-02T00:01:01+08:00",
            draft_revision: 4,
            content: "DO_NOT_RENDER_RAW_CONTENT",
            signature: "DO_NOT_RENDER_SIGNATURE",
            secret: "DO_NOT_RENDER_SECRET",
          },
          {
            ingestion_id: "ingestion-rejected",
            source_id: "source-scale",
            source_name: "地磅来源",
            source_system: "SCALE",
            format: "json",
            status: "rejected",
            event_id: "event-scale-conflict",
            created_at: "2026-07-02T00:02:00+08:00",
            completed_at: "2026-07-02T00:02:01+08:00",
            rejection: {
              code: "connector_source_conflict",
              message: "2026-07-01 production_t 多来源数值冲突 <img src=x onerror=alert(1)>",
              recorded_at: "2026-07-02T00:02:01+08:00",
            },
          },
        ],
        latest_preflight: {
          status: "review_required",
          bound_revision: 3,
          source_count: 1,
          missing_count: 0,
          missing_day_count: 1,
          arithmetic_mismatch_count: 2,
          warnings: ["2 个日报与班次合计需要人工复核。"],
        },
        sync_state: machineSyncResumed
          ? {
              state: "active",
              message: "机器来源可继续更新此待复核草稿",
              can_resume: false,
            }
          : {
              state: "paused",
              reason_code: "human_changes_detected",
              message: "检测到人工修改，自动同步已暂停以避免覆盖",
              can_resume: true,
            },
        source_health: [
          {
            source_id: "source-erp",
            source_name: "ERP 生产日报",
            source_system: "ERP",
            required: true,
            outcome: "success_empty",
            completed_at: "2026-07-02T01:00:00+08:00",
            last_nonempty_at: "2026-07-01T23:00:00+08:00",
            coverage_as_of: "2026-07-01",
            freshness_max_seconds: 3600,
            age_seconds: 7200,
            freshness_state: "stale",
            error_code: "source_empty",
          },
        ],
        freshness: {
          overall_state: "stale",
          stale_required_source_ids: ["source-erp"],
        },
      });
    }
    if (url.pathname === "/api/v2/risks") return response({ items: [] });
    if (url.pathname === "/api/v2/audit") {
      return response({ valid: true, head_hash: "e".repeat(64), events: [] });
    }
    throw new Error(`Unexpected request: ${method} ${url.pathname}${url.search}`);
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
      () => document.querySelector(`[data-draft-id="${draft.draft_id}"]`),
      "V2 draft list",
    );
    document.querySelector(`[data-draft-id="${draft.draft_id}"]`).click();
    await waitFor(
      () => document.querySelector(".fq-autofill-source"),
      "V2 autofill evidence",
    );
    assert.match(document.getElementById("fqConnectorSummary").textContent, /已启用/);
    const evidence = document.querySelector(".fq-autofill-evidence");
    assert.match(evidence.textContent, /ERP 生产日报/);
    assert.match(evidence.textContent, /认证客户端 mine-authoritative-connector/);
    assert.match(evidence.textContent, /日报\/班次不一致/);
    assert.match(evidence.textContent, /2 个日报与班次合计需要人工复核/);
    assert.match(evidence.textContent, /自动写入不等于企业确认/);
    assert.match(evidence.textContent, /自动同步已暂停/);
    assert.match(evidence.textContent, /放弃手工修改并恢复自动同步/);
    assert.match(evidence.textContent, /自动采集时效/);
    assert.match(evidence.textContent, /成功但结果为空/);
    assert.match(evidence.textContent, /必需来源已不可用于当前就绪判断/);
    assert.match(evidence.textContent, /旧预检不能作为当前确认依据/);
    assert.equal(
      document.querySelector('[data-fq-action="confirm-draft"]').disabled,
      true,
      "stale required machine sources must disable confirmation in the UI",
    );
    assert.match(evidence.textContent, /多来源数值冲突/);
    assert.match(evidence.textContent, /connector_source_conflict/);
    assert.match(evidence.textContent, /缺失整日报/);
    assert.match(evidence.textContent, /这份预检已经过期/);
    assert.match(evidence.textContent, /当前草稿为修订 4/);
    assert.equal(evidence.querySelector("img"), null, "rejection text must be escaped");
    assert.match(document.getElementById("fqDraftDetail").textContent, /生产数据批次/);
    assert.match(document.getElementById("fqDraftDetail").textContent, /1 个数据日期/);
    assert.match(document.getElementById("fqDraftDetail").textContent, /申报窗口内的完整内容/);
    assert(!document.getElementById("fqDraftDetail").textContent.includes("本月完整内容"));
    for (const forbidden of [
      "DO_NOT_RENDER_RAW_CONTENT",
      "DO_NOT_RENDER_SIGNATURE",
      "DO_NOT_RENDER_SECRET",
    ]) {
      assert(!evidence.textContent.includes(forbidden));
    }
    assert.equal(
      requests.filter((item) => /^(POST|PATCH|DELETE) /.test(item)).length,
      0,
      "evidence preview cannot mutate server state without an explicit action",
    );
    document.querySelector('[data-fq-action="resume-machine-sync"]').click();
    await waitFor(
      () => requests.includes(`POST /api/v2/drafts/${draft.draft_id}/machine-resume`),
      "explicit machine sync resume",
    );
    await waitFor(
      () => /自动同步开启/.test(document.getElementById("fqDraftDetail").textContent),
      "active sync state after resume",
    );
    assert.equal(
      requests.filter((item) => item === `POST /api/v2/drafts/${draft.draft_id}/machine-resume`).length,
      1,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(runtimeErrors.length, 0, String(runtimeErrors[0] || ""));
    console.log("JSDOM five-quantity autofill evidence checks passed");
  } finally {
    dom.window.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
