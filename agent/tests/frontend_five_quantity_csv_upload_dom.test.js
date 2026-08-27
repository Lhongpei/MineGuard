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

const metricDefinitions = [
  ["ventilation_m3_min", "m3/min", "time_weighted_average", 4800],
  ["electricity_kwh", "kWh", "sum", 96000],
  ["detonators_count", "count", "sum", 120],
  ["explosives_kg", "kg", "sum", 240],
  ["mine_entry_persons", "person", "sum", 320],
  ["production_t", "t", "sum", 2600],
];

function measurements(sourceId) {
  return Object.fromEntries(
    metricDefinitions.map(([metric, unit, aggregation, value]) => [
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

function shift(sourceId, code, start, end) {
  return {
    shift_code: code,
    start_at: start,
    end_at: end,
    measurements: measurements(sourceId),
  };
}

const draft = {
  draft_id: "fq-csv-draft-1",
  import_id: "fq-csv-import-1",
  revision: 1,
  submission_revision: 1,
  status: "ready_review",
  payload: {
    mine: {
      mine_id: "MINE-CSV-001",
      mine_name: "CSV 测试煤矿",
      operator_id: "operator-csv-001",
      operator_name: "CSV 测试煤业",
    },
    reporting_month: "2026-07",
    timezone: "Asia/Shanghai",
    period_start: "2026-07-01T08:30:00+08:00",
    period_end: "2026-07-02T08:30:00+08:00",
    closed_at: "2026-07-03T00:00:00+08:00",
    comparison_context: {
      capacity_band: "medium",
      mining_method: "underground",
      shift_system: "three-shift-eight-hour",
      coal_type: "bituminous",
      operating_regime: "normal-production",
    },
    days: ["2026-07-01", "2026-07-02"].map((date) => ({
      date: `${date}T08:30:00+08:00`,
      operating_state: "producing",
      reported_quantity: {
        daily_total: measurements(`source-${date}`),
        shifts: {
          zero_shift: shift(
            `source-${date}`,
            "ZERO",
            `${date}T00:00:00+08:00`,
            `${date}T08:00:00+08:00`,
          ),
          eight_shift: shift(
            `source-${date}`,
            "EIGHT",
            `${date}T08:00:00+08:00`,
            `${date}T16:00:00+08:00`,
          ),
          four_shift: shift(
            `source-${date}`,
            "FOUR",
            `${date}T16:00:00+08:00`,
            `${date}T23:59:59+08:00`,
          ),
        },
      },
    })),
    sources: ["2026-07-01", "2026-07-02"].map((date) => ({
      source_id: `source-${date}`,
      acquisition_mode: "manual_import",
      source_system: "enterprise-five-quantity-import",
      source_record_id: `七月五量.csv#CSV!${date}`,
      source_location: `CSV!${date}`,
      captured_at: "2026-07-03T00:00:00+08:00",
      media_type: "text/csv",
      evidence_sha256: "a".repeat(64),
      normalization: "deterministic mapping",
    })),
    agent_processing: {
      normalization_performed: true,
      model_assistance_used: false,
      processing_record_sha256: "b".repeat(64),
    },
  },
};

function createDom(permissions) {
  const requests = [];
  const runtimeErrors = [];
  let imported = false;
  let watchDirectories = [];
  let downloadedBlob = null;
  let downloadedName = "";
  async function fakeFetch(input, options = {}) {
    const url = new URL(String(input), "http://127.0.0.1:8090/");
    const method = String(options.method || "GET").toUpperCase();
    requests.push({ method, path: `${url.pathname}${url.search}`, options });
    if (url.pathname === "/api/v1/auth/me") {
      return response({
        principal: {
          actor_id: "csv-user",
          name: "CSV 填报员",
          role: "企业填报员",
          permissions,
          must_change_password: false,
          temporary_demo: false,
        },
        csrf_token: "csrf-csv-user",
      });
    }
    if (url.pathname === "/api/v2/status") {
      return response({
        mine_id: "MINE-CSV-001",
        mine_name: "CSV 测试煤矿",
        operator_id: "operator-csv-001",
        system_id: "agent-csv-001",
        watched_directories: watchDirectories,
        platform_configured: false,
        machine_connector_enabled: false,
        connector_client_count: 0,
      });
    }
    if (url.pathname === "/api/v2/imports/preview" && method === "POST") {
      return response({
        preview_id: "11111111-1111-4111-8111-111111111111",
        detected_months: ["2026-07"],
        row_count: 2,
        valid_day_count: 2,
        warnings: [
          {
            code: "ambiguous_column",
            severity: "warning",
            message: "“原煤”列需要人工选择映射 <img src=x onerror=alert(1)>",
          },
        ],
        columns: [
          {
            source_index: 0,
            source_header: "日期",
            target_metric: "date",
            target_period: null,
            target_unit: "ISO date",
            confidence: 1,
            source: "deterministic",
            reason: "日期列固定",
            status: "date",
          },
          {
            source_index: 1,
            source_header: "风量(m3/min)",
            target_metric: "ventilation_m3_min",
            target_period: "daily_total",
            target_unit: "m3/min",
            confidence: 0.99,
            source: "deterministic",
            reason: "标准表头精确匹配",
            status: "mapped",
          },
          {
            source_index: 2,
            source_header: "本矿电耗",
            target_metric: "electricity_kwh",
            target_period: "daily_total",
            target_unit: "kWh",
            confidence: 0.61,
            source: "llm",
            reason: "非标准表头，建议映射为日报电量",
            status: "needs_review",
          },
          {
            source_index: 3,
            source_header: "原煤",
            target_metric: null,
            target_period: null,
            target_unit: null,
            confidence: 0.42,
            source: "llm",
            reason: "可能是产量，但口径不明确",
            status: "unmapped",
          },
          {
            source_index: 4,
            source_header: "备注",
            target_metric: null,
            target_period: null,
            target_unit: null,
            confidence: 0,
            source: "deterministic",
            reason: "不是五量数值列",
            status: "blocked",
          },
        ],
      });
    }
    if (url.pathname === "/api/v2/watch/config" && method === "PUT") {
      watchDirectories = JSON.parse(options.body).directories;
      return response({
        watched_directories: watchDirectories,
        enabled: watchDirectories.length > 0,
      });
    }
    if (
      url.pathname === "/api/v2/imports/11111111-1111-4111-8111-111111111111/materialize" &&
      method === "POST"
    ) {
      imported = true;
      return response(
        {
          import_id: draft.import_id,
          draft_id: draft.draft_id,
          status: "ready_review",
          duplicate: false,
          draft,
        },
        201,
      );
    }
    if (url.pathname === "/api/v2/imports" && method === "POST") {
      imported = true;
      return response(
        {
          import_id: draft.import_id,
          draft_id: draft.draft_id,
          status: "ready_review",
          duplicate: false,
          draft,
        },
        200,
      );
    }
    if (url.pathname === "/api/v2/imports") {
      return response({
        items: imported
          ? [
              {
                import_id: draft.import_id,
                draft_id: draft.draft_id,
                filename: "七月五量.csv",
                acquisition_mode: "manual_import",
                status: "ready_review",
                content_sha256: "c".repeat(64),
                suggestions: [],
                created_at: "2026-07-03T00:00:00+08:00",
              },
            ]
          : [],
      });
    }
    if (url.pathname === "/api/v2/drafts") {
      return response({ items: imported ? [draft] : [] });
    }
    if (url.pathname === `/api/v2/drafts/${draft.draft_id}`) {
      return response({ ...draft, sync_state: { state: "not_machine" } });
    }
    if (url.pathname === `/api/v2/drafts/${draft.draft_id}/ingestions`) {
      return response({
        items: [],
        latest_preflight: null,
        sync_state: { state: "not_machine" },
        source_health: [],
        freshness: null,
      });
    }
    if (url.pathname === "/api/v2/risks") return response({ items: [] });
    if (url.pathname === "/api/v2/audit") {
      return response({ valid: true, head_hash: "d".repeat(64), events: [] });
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
      window.TextEncoder = TextEncoder;
      window.URL.createObjectURL = (blob) => {
        downloadedBlob = blob;
        return "blob:csv-template";
      };
      window.URL.revokeObjectURL = () => {};
      window.HTMLAnchorElement.prototype.click = function click() {
        downloadedName = this.download;
      };
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
    requests,
    runtimeErrors,
    getDownloadedBlob: () => downloadedBlob,
    getDownloadedName: () => downloadedName,
  };
}

function attachFile(window, input, file) {
  Object.defineProperty(input, "files", {
    configurable: true,
    value: [file],
  });
  input.dispatchEvent(new window.Event("change", { bubbles: true }));
}

function readBlob(window, blob) {
  return new Promise((resolve, reject) => {
    const reader = new window.FileReader();
    reader.addEventListener("load", () => resolve(String(reader.result || "")));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsText(blob);
  });
}

async function main() {
  const writer = createDom(["read", "write", "confirm", "submit"]);
  try {
    const { window } = writer.dom;
    const { document } = window;
    await waitFor(
      () => /CSV 测试煤矿/.test(document.getElementById("fqGlobalMessage").textContent),
      "writer session load",
    );

    const input = document.getElementById("fqUploadFile");
    const uploadButton = document.getElementById("fqUploadButton");
    assert.equal(input.disabled, false);
    assert.equal(uploadButton.disabled, true, "upload waits for a selected file");

    document.getElementById("fqDownloadCsvTemplate").click();
    assert.equal(writer.getDownloadedName(), "生产数据填报模板.csv");
    assert.equal(writer.getDownloadedBlob().type, "text/csv;charset=utf-8");
    assert(writer.getDownloadedBlob().size > 20);
    const templateText = await readBlob(window, writer.getDownloadedBlob());
    const templateColumns = templateText.replace(/^\ufeff/, "").trim().split(",");
    assert.equal(templateColumns.length, 12, "default template is date plus eleven atomic fields");
    for (const label of [
      "开采量_采掘计量(t)",
      "销售量(t)",
      "运输量(t)",
      "洗煤量_入洗原煤(t)",
      "开票量(t)",
    ]) {
      assert(templateColumns.includes(label), `default template includes ${label}`);
    }
    assert.match(document.getElementById("fqUploadResult").textContent, /生产数据 CSV 模板已下载/);

    const csv = Buffer.from(
      "日期,风量(m3/min),电量(kWh),雷管(发),炸药(kg),入井人员量(人次),产量(t)\n" +
        "2026-07-01,4800,96000,120,240,320,2600\n" +
        "2026-07-02,4900,97000,121,242,322,2700\n",
      "utf8",
    );
    attachFile(window, input, {
      name: "七月五量.csv",
      size: csv.length,
      async arrayBuffer() {
        return csv.buffer.slice(csv.byteOffset, csv.byteOffset + csv.byteLength);
      },
    });
    assert.match(document.getElementById("fqSelectedFileSummary").textContent, /七月五量\.csv/);
    assert.match(document.getElementById("fqSelectedFileSummary").textContent, /等待 Agent 识别/);
    assert.equal(uploadButton.disabled, false);

    const watchInput = document.getElementById("fqWatchDirectories");
    watchInput.value = "C:\\ProductionData\nD:\\ScaleExports";
    document.getElementById("fqWatchConfigForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () => /已保存 2 个/.test(document.getElementById("fqWatchConfigResult").textContent),
      "watch directory configuration",
    );
    const watchRequest = writer.requests.find(
      (item) => item.method === "PUT" && item.path === "/api/v2/watch/config",
    );
    assert.deepEqual(JSON.parse(watchRequest.options.body).directories, [
      "C:\\ProductionData",
      "D:\\ScaleExports",
    ]);
    assert.equal(watchRequest.options.headers["X-CSRF-Token"], "csrf-csv-user");

    document.getElementById("fqUploadForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        writer.requests.filter(
          (item) => item.method === "POST" && item.path === "/api/v2/imports",
        ).length === 1,
      "CSV direct import",
    );
    const importPost = writer.requests.find(
      (item) => item.method === "POST" && item.path === "/api/v2/imports",
    );
    assert(importPost, "CSV import must use the one-step automatic recognition endpoint");
    assert.equal(importPost.options.headers["X-CSRF-Token"], "csrf-csv-user");
    const importBody = JSON.parse(importPost.options.body);
    assert.equal(importBody.filename, "七月五量.csv");
    assert.equal(
      Buffer.from(importBody.content_base64, "base64").toString("utf8"),
      csv.toString("utf8"),
    );
    assert.equal(
      writer.requests.filter(
        (item) => item.method === "POST" && item.path === "/api/v2/imports/preview",
      ).length,
      0,
      "enterprise users must not be forced through a mapping preview",
    );
    await waitFor(
      () => /待人工核验记录/.test(document.getElementById("fqGlobalMessage").textContent),
      "CSV draft creation",
    );
    assert.equal(document.getElementById("fqPanelReview").hidden, false);
    await waitFor(
      () => /2026\/07\/01 08:30 至 2026\/07\/02 08:30/.test(document.getElementById("fqDraftDetail").textContent),
      "created draft detail",
    );
    const detail = document.getElementById("fqDraftDetail");
    assert.match(detail.textContent, /当前已填 5\/10，可部分报送/);
    assert.match(detail.textContent, /未填项目保持 null 并标记为缺失/);
    assert.match(detail.textContent, /安全生产支撑/);
    assert.match(detail.textContent, /生产煤流/);
    assert.match(detail.textContent, /经营票据/);
    assert.equal(detail.querySelectorAll(".fq-shift-review").length, 2);
    assert(
      [...detail.querySelectorAll(".fq-shift-review")].every((item) => !item.open),
      "advanced shift details stay collapsed by default",
    );
    assert.equal(
      detail.querySelectorAll('[data-fq-value][data-metric="sales_t"]').length,
      0,
      "missing V2 fields are shown but never fabricated into the payload",
    );

    assert.equal(
      writer.requests.filter(
        (item) => item.method === "POST" && /\/(confirm|send-now)$/.test(item.path),
      ).length,
      0,
      "upload may create a draft but may not confirm or send it",
    );

    attachFile(window, input, {
      name: "过大.csv",
      size: 20 * 1024 * 1024 + 1,
      async arrayBuffer() {
        throw new Error("oversized file must not be read");
      },
    });
    assert.equal(uploadButton.disabled, true);
    assert.match(document.getElementById("fqUploadResult").textContent, /文件过大/);

    const jsonBytes = Buffer.from('{"days":[]}', "utf8");
    attachFile(window, input, {
      name: "五量.json",
      size: jsonBytes.length,
      async arrayBuffer() {
        return jsonBytes.buffer.slice(
          jsonBytes.byteOffset,
          jsonBytes.byteOffset + jsonBytes.byteLength,
        );
      },
    });
    assert.match(uploadButton.textContent, /读取文件/);
    document.getElementById("fqUploadForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        writer.requests.filter(
          (item) => item.method === "POST" && item.path === "/api/v2/imports",
        ).length === 2,
      "non-CSV legacy import",
    );
    const directImport = writer.requests.filter(
      (item) => item.method === "POST" && item.path === "/api/v2/imports",
    )[1];
    assert.equal(JSON.parse(directImport.options.body).filename, "五量.json");
    assert.equal(
      writer.requests.filter(
        (item) => item.method === "POST" && item.path === "/api/v2/imports/preview",
      ).length,
      0,
      "all formats use the same direct automatic-recognition path",
    );

    const manualRow = document.querySelector("#fqManualRows tr");
    assert(manualRow, "manual fallback starts with one editable row");
    manualRow.querySelector('[data-manual-date]').value = "2026-07-15T09:45";
    manualRow.querySelector('[data-manual-metric="production_t"]').value = "123.5";
    document.getElementById("fqManualForm").dispatchEvent(
      new window.Event("submit", { bubbles: true, cancelable: true }),
    );
    await waitFor(
      () =>
        writer.requests.filter(
          (item) => item.method === "POST" && item.path === "/api/v2/imports",
        ).length === 3 && document.getElementById("fqManualSubmit").disabled === false,
      "manual production data import",
    );
    const manualPost = writer.requests.filter(
      (item) => item.method === "POST" && item.path === "/api/v2/imports",
    )[2];
    const manualBody = JSON.parse(manualPost.options.body);
    assert.match(manualBody.filename, /^manual-production-data-\d+\.csv$/);
    const manualCsv = Buffer.from(manualBody.content_base64, "base64").toString("utf8");
    assert.match(manualCsv, /2026-07-15T09:45/);
    assert.match(manualCsv, /123\.5/);
    assert.equal(writer.runtimeErrors.length, 0, String(writer.runtimeErrors[0] || ""));
  } finally {
    writer.dom.window.close();
  }

  const reader = createDom(["read"]);
  try {
    const { document } = reader.dom.window;
    await waitFor(
      () => /CSV 测试煤矿/.test(document.getElementById("fqGlobalMessage").textContent),
      "read-only session load",
    );
    assert.equal(document.getElementById("fqUploadFile").disabled, true);
    assert.equal(document.getElementById("fqUploadButton").disabled, true);
    assert.equal(document.getElementById("fqScanWatch").disabled, true);
    assert.equal(document.getElementById("fqDownloadCsvTemplate").disabled, false);
    assert.match(document.getElementById("fqSelectedFileSummary").textContent, /只能查看/);
    assert.equal(reader.runtimeErrors.length, 0, String(reader.runtimeErrors[0] || ""));
  } finally {
    reader.dom.window.close();
  }

  console.log("JSDOM five-quantity CSV upload checks passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
