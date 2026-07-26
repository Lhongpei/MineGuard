"use client";

import { useState } from "react";

const productionRisk = {
  tone: "review",
  symbol: "!",
  level: "需人工复核",
  title: "发现跨来源技术冲突，建议核查",
  summary:
    "多类业务数据无法在现有容差内同时成立。系统给出了可恢复一致性的最小待核查来源组合，但不能据此直接认定责任。",
  priority: "较高",
  kpis: [
    ["收到的上报产量", "5,000 吨", "数据质量满足分析要求，仅反映可分析性"],
    ["合理产量参考区间", "6,993.5–7,206.5 吨", "现有证据与容差下的技术区间"],
    ["最小上报技术差额", "1,993.5 吨", "仅为核查线索，不等于认定少报"],
    ["建议优先核查", "生产上报", "多源支撑等级 A，不是处罚等级"],
  ],
  findings: [
    "可恢复一致性的首选最小待核查组合是“生产上报”，建议核对原始记录、统计口径和修改日志。",
    "主运输、入洗、销售和库存数据在当前模型中共同支持约 6,993.5 至 7,206.5 吨的技术区间。",
    "上报值与合理区间之间至少存在约 1,993.5 吨技术差额。",
    "上限测算仅描述当前假设下的敏感性，不是对实际未申报量的认定。",
  ],
  actions: [
    "优先核查生产上报的原始记录、统计口径及修订日志。",
    "核验对应设备的检定、校准、时钟和断点续传记录。",
    "复核运输、入洗、销售和库存原始凭证。",
    "保全相关表底、设备日志、视频和业务凭证后开展人工复核。",
  ],
  sources: [
    ["生产上报", true],
    ["主运输皮带", false],
    ["洗煤计量", false],
    ["销售台账", false],
    ["库存盘点", false],
  ],
};

const productionNormal = {
  tone: "success",
  symbol: "✓",
  level: "暂未发现技术冲突",
  title: "当前数据可协调",
  summary:
    "在当前数据范围、容差和模型假设下，各来源可以协调成立；这不等同于“无违规”，仍应按制度抽查并留存原始证据。",
  priority: "常规",
  kpis: [
    ["收到的上报产量", "7,050 吨", "数据质量满足分析要求，仅反映可分析性"],
    ["合理产量参考区间", "6,993.5–7,150 吨", "现有证据与容差下的技术区间"],
    ["最小上报技术差额", "0 吨", "未发现超出容差的上报技术差额"],
    ["后续安排", "常规抽查", "本期未形成异常证据等级"],
  ],
  findings: [
    "上报产量、主运输、入洗、销售和库存数据可在允许误差内同时成立。",
    "“未发现冲突”不等于数据绝对真实，也不等于没有违规。",
    "建议继续按既定抽查比例核对原始表底、设备日志和业务凭证。",
  ],
  actions: [
    "保留本次数据及分析结果，纳入常规监管台账。",
    "按既定抽查比例核对原始表底、设备日志和业务凭证。",
  ],
  sources: [
    ["生产上报", false],
    ["主运输皮带", false],
    ["洗煤计量", false],
    ["销售台账", false],
    ["库存盘点", false],
  ],
};

const personnelRisk = {
  tone: "review",
  symbol: "!",
  level: "发现待复核事项",
  title: "建议调阅视频和刷卡日志",
  summary:
    "发现身份信息不一致以及人脸、定位卡记录未能对应的情况。系统只用于缩小排查范围，不能单独确认身份或认定违规通行。",
  priority: "较高",
  kpis: [
    ["接收通行数据", "3 人脸 / 2 卡", "井口 A 通道入井场次"],
    ["身份信息待复核", "1 条", "候选身份与卡绑定身份不同"],
    ["有脸无卡", "1 条", "也可能是读卡器漏读或时钟偏差"],
    ["有卡无人", "0 条", "来源明确返回零条记录"],
  ],
  findings: [
    "人卡信息不一致：一条人脸候选身份与定位卡绑定身份不同，待视频复核。",
    "有脸无卡：一条人脸轨迹未匹配到定位卡；可能为无卡通行、设备漏读或时钟偏差。",
  ],
  actions: [
    "锁定相关记录前后 2 分钟的井口原始视频。",
    "核查定位卡的人员绑定、领用、挂失及刷卡记录。",
    "检查摄像头、读卡器时钟是否同步，排除设备漏拍或漏读。",
    "由安全管理人员复核后，将结论和证据归入监管台账。",
  ],
  sources: [
    ["井口人脸记录", false],
    ["人员定位卡记录", false],
    ["人员与卡绑定信息", false],
  ],
};

const personnelNormal = {
  tone: "success",
  symbol: "✓",
  level: "暂未发现待复核事项",
  title: "本场次人卡记录可以对应",
  summary:
    "在设定时间范围和匹配规则下，人脸与定位卡事件均已配对；仍应按制度抽查原始视频。",
  priority: "常规",
  kpis: [
    ["接收通行数据", "2 人脸 / 2 卡", "井口 A 通道入井场次"],
    ["身份信息待复核", "0 条", "来源明确返回零条记录"],
    ["有脸无卡", "0 条", "来源明确返回零条记录"],
    ["有卡无人", "0 条", "来源明确返回零条记录"],
  ],
  findings: [
    "本场次未发现身份信息不一致、有脸无卡或有卡无人的情况。",
    "事件已配对不等于身份已经依法确认，仍应按抽查制度复看原始视频。",
  ],
  actions: [
    "保留本场次匹配结果，纳入常规监管台账。",
    "按抽查制度复看部分原始视频，确认设备与系统运行正常。",
  ],
  sources: [
    ["井口人脸记录", false],
    ["人员定位卡记录", false],
    ["人员与卡绑定信息", false],
  ],
};

const productionMetrics = [
  ["上报原煤产量", "5,000 吨", "7,050 吨", "20.50 个容差"],
  ["主运输皮带量", "7,100 吨", "7,050 吨", "0.47 个容差"],
  ["入洗原煤量", "6,800 吨", "6,800 吨", "0"],
  ["原煤外销量", "0 吨（明确零值）", "0 吨", "0"],
  ["原煤库存变化", "+250 吨", "+250 吨", "0"],
];

const personnelMatches = [
  ["轨迹 ***001", "人员 P**1", "卡号 ***001", "事件已配对"],
  ["轨迹 ***002", "人员 P**9 / 卡绑定 P**2", "卡号 ***002", "身份信息待复核"],
  ["轨迹 ***003", "人员 P**3", "—", "有脸无卡"],
];

export default function Home() {
  const [mode, setMode] = useState("production");
  const [scenario, setScenario] = useState("risk");
  const result =
    mode === "production"
      ? scenario === "risk"
        ? productionRisk
        : productionNormal
      : scenario === "risk"
        ? personnelRisk
        : personnelNormal;

  function switchMode(nextMode) {
    setMode(nextMode);
    setScenario("risk");
  }

  return (
    <>
      <header className="siteHeader">
        <div className="headerInner">
          <div className="brand">
            <span className="brandMark" aria-hidden="true">监</span>
            <span>
              <strong>矿安智察</strong>
              <small>煤矿多源数据辅助监管</small>
            </span>
          </div>
          <span className="demoBadge">公开演示 · 仅内置样例</span>
        </div>
      </header>

      <main className="pageShell">
        <section className="intro">
          <div>
            <p className="eyebrow">领导监管工作台</p>
            <h1>先看结论，再看线索，最后安排核查</h1>
            <p>
              把生产、运输、入洗、销售、库存或人员通行数据放在同一口径下交叉核验，
              用通俗语言回答“是否需要查、重点查哪里、下一步做什么”。
            </p>
          </div>
          <aside className="scopeNote">
            <strong>辅助研判</strong>
            <span>技术线索仅用于确定人工核查优先级，不构成违法事实认定。</span>
          </aside>
        </section>

        <section className="workspace">
          <div className="toolbar">
            <div className="tabs" role="tablist" aria-label="监管事项">
              <button
                className={mode === "production" ? "active" : ""}
                onClick={() => switchMode("production")}
                role="tab"
                aria-selected={mode === "production"}
              >
                产量数据核验
              </button>
              <button
                className={mode === "personnel" ? "active" : ""}
                onClick={() => switchMode("personnel")}
                role="tab"
                aria-selected={mode === "personnel"}
              >
                人员通行核验
              </button>
            </div>
            <div className="scenarios" aria-label="演示场景">
              <span>切换演示：</span>
              <button
                className={scenario === "risk" ? "selected" : ""}
                onClick={() => setScenario("risk")}
              >
                待复核样例
              </button>
              <button
                className={scenario === "normal" ? "selected" : ""}
                onClick={() => setScenario("normal")}
              >
                可协调样例
              </button>
            </div>
          </div>

          <div className={`decision ${result.tone}`}>
            <span className="decisionSymbol" aria-hidden="true">{result.symbol}</span>
            <div>
              <p className="decisionLevel">{result.level}</p>
              <h2>{result.title}</h2>
              <p>{result.summary}</p>
            </div>
            <div className="priority">
              <span>核查优先级</span>
              <strong>{result.priority}</strong>
            </div>
          </div>

          <div className="kpiGrid">
            {result.kpis.map(([label, value, note]) => (
              <article className="kpi" key={label}>
                <p>{label}</p>
                <strong>{value}</strong>
                <span>{note}</span>
              </article>
            ))}
          </div>

          <div className="resultGrid">
            <article className="card">
              <p className="cardKicker">核心判断</p>
              <h3>发现了什么</h3>
              <ul>
                {result.findings.map((finding) => <li key={finding}>{finding}</li>)}
              </ul>
            </article>
            <article className="card actionCard">
              <p className="cardKicker">处置建议</p>
              <h3>下一步怎么做</h3>
              <ol>
                {result.actions.map((action) => <li key={action}>{action}</li>)}
              </ol>
            </article>
          </div>

          <article className="evidence">
            <div>
              <p className="cardKicker">支撑本次判断的数据来源</p>
              <h3>证据链概览</h3>
            </div>
            <div className="chips">
              {result.sources.map(([source, suspect]) => (
                <span className={suspect ? "chip suspect" : "chip"} key={source}>
                  {suspect ? "!" : "✓"} {source}
                </span>
              ))}
            </div>
            <p>
              {result.tone === "review"
                ? "橙色来源是优先待核查组合，不代表该来源已经被认定错误或造假。"
                : "当前数据能够协调不等于没有违规，仍需按监管计划抽查。"}
            </p>
          </article>

          <details className="technical">
            <summary>
              <strong>查看专业分析依据</strong>
              <span>领导无需阅读，供业务与技术人员复核</span>
            </summary>
            <div className="technicalBody">
              <h3>{mode === "production" ? "指标比对明细" : "事件匹配明细"}</h3>
              <div className="tableScroll">
                <table>
                  <thead>
                    <tr>
                      {(mode === "production"
                        ? ["指标", "接收值", "协调参考值", "偏离程度"]
                        : ["人脸轨迹", "候选身份", "定位卡", "判断"]
                      ).map((heading) => <th key={heading}>{heading}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {(mode === "production" ? productionMetrics : personnelMatches).map(
                      (row) => (
                        <tr key={row.join("|")}>
                          {row.map((cell) => <td key={cell}>{cell}</td>)}
                        </tr>
                      ),
                    )}
                  </tbody>
                </table>
              </div>
              <h3>口径与使用边界</h3>
              <ul>
                <li>协调参考值是模型计算结果，不称为真实值。</li>
                <li>合理区间是给定容差和假设下的技术区间，不是统计置信区间。</li>
                <li>零值表示来源明确上报为零；缺失值不得自动按零处理。</li>
                <li>本公网页面是静态演示，不接收或保存真实监管数据。</li>
              </ul>
            </div>
          </details>

          <footer className="legalNote">
            <strong>技术线索不构成违法认定。</strong>
            任何责任认定均须结合原始证据、业务口径和法定程序，由有权限人员作出。
          </footer>
        </section>
      </main>
    </>
  );
}
