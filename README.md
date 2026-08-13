# 煤矿十量 V3 监管平台与一矿一智能体

本仓库现在只有两个可部署软件：

```text
每座煤矿独立部署 agent/
  原始十量 → 人工导入或固定目录/API/只读库直采 → 规范化 → 企业确认
                                      │ V3 HTTPS/JSON/双 HMAC
                                      ▼
政府集中部署 platform/
  自动验签接收 → 唯一十量算法 → 风险报告 → 企业回复/修订重算 → 领导只读大屏
```

- `agent/`：一座煤矿一个独立智能体。不同煤矿不共享数据库、用户、文件、会话或
  密钥；负责导入、规范化、缺项提示、人工确认、可靠报送、风险解读和回复草稿。
- `platform/`：政府侧独立监管平台。自动分析各矿数据并追加留痕；领导端只查看、
  筛选和钻取，不能代企业填报、改数据、改结论或删除风险。
- `contracts/`：双方共同实现的中立 V3 Schema、OpenAPI、签名规范和测试向量；它
  不是运行产品，也不是双方的 Python 运行时依赖。
- `connector-service/`：企业 Agent 的可选伴随采集组件。需要隔离访问 ERP/MES、
  HTTP 接口或只读 SQLite 时单独起进程；它只按版本化 HMAC 接口向本矿 Agent 建立
  待复核草稿，不是第三个业务产品，不能连接政府端、确认或报送。当前随仓连接器已经
  输出十量 V3 的 11 个原子字段；来源没有的字段保持 `null + missing`，并须在本矿完成
  影子运行和逐来源验收后才可用于正式草稿。

原第三套 `edge-agent` 已退役。固定目录监听、稳定文件识别、哈希去重、持久 outbox
和断网重试都属于企业智能体的采集能力；简单目录监听内置在 `agent/`，需要网络/
数据库隔离时可用 `connector-service/` 伴随进程。人工导入和直采是并列合法采集
方式，仅用于追溯，不形成信任等级，也不改变算法权重或阈值。

当前正式主线是十量 V3。五量 V2 报文、签名和数据库记录仅保留只读审计与历史展示，
不会被补造新增字段或重新解释。字段、CSV 和生产配置的权威入口见
[十量 V3 部署与运行](docs/十量V3部署与运行.md)。

## 唯一算法和求解器

政府端唯一业务算法分析正式“十量”：风量、电量、火工品量、入井人员量、产量、
开采量、销售量、运输量、洗煤量和开票量。数据层使用 11 个原子字段；火工品量拆为
`detonators_count` 与 `explosives_kg`，二者单位不同、绝不能相加。其余字段依次为
`ventilation_m3_min`、`electricity_kwh`、`mine_entry_persons`、`production_t`、
`extraction_t`、`sales_t`、`transport_t`、`wash_feed_t` 和
`invoiced_quantity_t`。

开票主量必须非负，只表示本期正常/蓝字发票对应的实物煤量；红票、退票、作废、折让
和退货在企业来源系统作为辅助明细独立留存，净额另行派生，不能把红票负数写进主字段。
当前 V3 主报文不传这些辅助事件。完整管线依次执行：

1. 契约、缺失、单位、非负、日报与三班算术核对；
2. 停产、检修、复产和稳产工况识别；
3. 产量—开采—洗选进料—销售—运输—开票的同期间软关系核对；合法库存结转、
   在途和结算时差不能被简单“不相等”替代；
4. 本矿正式准入历史的 Median/MAD、Rolling MAD、EWMA、CUSUM、
   Page-Hinkley、漂移和变化点；
5. 至少三座可比矿、每矿等权且按截止日冻结的匿名同类矿区间；
6. HiGHS 加权 L1 联合协调与最小冲突集 MCS；
7. 证据覆盖不足时保守返回 `insufficient_data`，否则给出
   `normal_candidate` 或 `risk`。

求解器只在第 6 步内部使用。规则层先按真实 `sum`、`time_weighted_average`、
`snapshot` 语义完成确定性核对；主 HiGHS 求上报观测与本矿历史、匿名同类矿软区间
联合相容所需的最小加权 L1 调整，MCS 再把观测容差和参考带硬化，定位最少需要放宽的
日期、指标和证据组。它不预测所谓“真实产量”，也不把历史或同类矿经验当成物理定律。
既有时序算法没有删除，而是并入这一个引擎，与 L1/MCS 共同形成证据。

当前 `ten-quantity-submission-v3` 只承载 11 个十量主原子和来源引用，不承载期初/期末
库存、洗后产品与损耗、逐批运输/开票日期或来源依赖域。因此生产适配器只执行主量的
确定性核对、软关系、历史/同类矿和通用 L1/MCS；原煤收发存、洗选投入产出、逐批凭证
账龄及其窗口流网络在高级证据核心中已实现，但本合同边界会明确标记为 `skipped`，不会
参与当前结论，也不会把缺少这些未发布字段冒充为数据不足。启用这些模块必须另发独立、
版本化的辅助证据合同并完成验收，不能原地扩展已经冻结的 V3 主报文。

首期数据即使暂未发现风险，也只能进入隔离的“参考候选”，不能用本月整体分布证明
自己后直接污染历史。只有完整、无复核/风险信号，并且已有正式本矿历史或冻结匿名
同类矿作为独立锚点的正常候选，才进入正式历史基线。

企业文字解释只会记为 `explanation_recorded`，不能消除数值风险。只有更高修订版数据
沿完整签名血缘重新通过同一算法，风险才可成为 `cleared_by_reanalysis`。

## 本机启动

需要 Python 3.11+。先准备两把不同的演示密钥；生产必须改成密钥系统生成的随机值：

```bash
export DEMO_MESSAGE_SECRET='DEMO_message_HMAC_secret_change_me_32_bytes'
export DEMO_TRANSPORT_SECRET='DEMO_transport_HMAC_secret_change_me_32_bytes'
```

启动政府端：

```bash
# 如果当前已经激活 agent/.venv，先退出；仅 cd 不会切换虚拟环境
deactivate 2>/dev/null || true
cd /home/sevan/coral/platform
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -c constraints.txt -e .
command -v mineguard

export MINEGUARD_V2_CLIENTS_JSON="$(python3 - <<'PY'
import json, os
print(json.dumps({"clients": [{
  "sender_id": "agent-mine-qy-001",
  "party_id": "operator-qy-001",
  "mine_id": "MINE-QY-001",
  "mine_name": "示例一号煤矿",
  "comparison_context": {
    "capacity_band": "0.9-1.2Mtpa",
    "mining_method": "underground-longwall",
    "shift_system": "three-shift-eight-hour",
    "coal_type": "thermal-coal",
    "operating_regime": "normal-production"
  },
  "active_message_key_id": "demo-exchange-key",
  "message_keys": {
    "demo-exchange-key": os.environ["DEMO_MESSAGE_SECRET"]
  },
  "transport_secrets": [os.environ["DEMO_TRANSPORT_SECRET"]]
}]}))
PY
)"
mineguard serve --host 127.0.0.1 --port 8080 \
  --state-directory .mineguard-v2
```

`command -v mineguard` 应显示
`/home/sevan/coral/platform/.venv/bin/mineguard`。如仍找不到入口，可直接运行
`/home/sevan/coral/platform/.venv/bin/mineguard`。若启动提示端口已占用，先用
`ss -ltnp | grep ':8080'` 查明旧服务，再停止旧服务或为新服务改用其他端口。

新本机状态目录默认账号为 `admin / 123123123`。`serve` 是常驻进程，看到监听提示后
终端不返回属于正常现象。打开 <http://127.0.0.1:8080/>，或另开终端检查：

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

再开一个终端启动这一座矿的企业智能体：

```bash
cd /home/sevan/coral/agent
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

export DEMO_MESSAGE_SECRET='DEMO_message_HMAC_secret_change_me_32_bytes'
export DEMO_TRANSPORT_SECRET='DEMO_transport_HMAC_secret_change_me_32_bytes'
export ENTERPRISE_MINE_ID='MINE-QY-001'
export ENTERPRISE_MINE_NAME='示例一号煤矿'
export ENTERPRISE_OPERATOR_ID='operator-qy-001'
export ENTERPRISE_OPERATOR_NAME='示例煤矿经营主体'
export ENTERPRISE_SYSTEM_ID='agent-mine-qy-001'
export ENTERPRISE_CAPACITY_BAND='0.9-1.2Mtpa'
export ENTERPRISE_MINING_METHOD='underground-longwall'
export ENTERPRISE_SHIFT_SYSTEM='three-shift-eight-hour'
export ENTERPRISE_COAL_TYPE='thermal-coal'
export ENTERPRISE_OPERATING_REGIME='normal-production'
export ENTERPRISE_EXCHANGE_HMAC_SECRET="$DEMO_MESSAGE_SECRET"
export PLATFORM_V3_BASE_URL='http://127.0.0.1:8080'
export PLATFORM_V3_SENDER_ID='agent-mine-qy-001'
export PLATFORM_V3_TRANSPORT_HMAC_SECRET="$DEMO_TRANSPORT_SECRET"
enterprise-agent serve --host 127.0.0.1 --port 8090
```

打开 <http://127.0.0.1:8090/>。未配置逐用户账号时，本机演示账号为
`demo / 123123123`；正式确认和提交应配置具名用户及权限。可选的通用模型服务只
用于煤炭领域映射、解释和回复草稿。正式环境通过企业身份绑定的 `.mgllm`
启用；一企业一把供应商 Key、配额和吊销范围，API Key 不得写进仓库、前端或
普通环境文件。政府 Platform 不生成、导入、解密、保存或转发这些凭据。没有模型
时，导入、校验、报送和确定性算法仍可工作。签发、Windows 向导导入和轮换见
[企业模型凭据签发与轮换](docs/企业模型凭据签发与轮换.md)。

远程服务器上仍建议两个服务只监听 `127.0.0.1`，使用 SSH 隧道或 HTTPS 反向代理，
不要直接暴露明文 HTTP。

### 一键生成多矿历史演示

该命令保留用于展示五量 V2 历史数据的只读兼容能力。政府端安装完成后，可在独立状态
目录生成 10 座演示矿数据：8 座程序合成教学矿各有
连续 3 个完整自然月，另有“太岳矿”“梗阳矿”各 1 个固定的 2026 年 7 月样表月份：

```bash
cd /home/sevan/coral/platform
mineguard seed-v2-demo \
  --state-directory .mineguard-v2-demo-v2 \
  --through-month 2026-07-31
mineguard serve --host 127.0.0.1 --port 8080 \
  --state-directory .mineguard-v2-demo-v2
```

默认仍用 `admin / 123123123` 登录。前 8 座教学矿中的产量、连续通风负荷、电耗、
入井人员和火工品作业节奏具有确定但彼此独立的日波动，不会再因固定比例而在时序图中
完全重合。演示覆盖人工导入、直采、正常基线、日报与班次
不一致、时序漂移、变化点、匿名同类矿偏离、缺失值和停复产；所有矿名、来源和留痕
均明确标注来源。太岳矿和梗阳矿的数字逐格来自仓库内两份 `.et` 样表，固定保留
2026-07-01 至 2026-07-31 的原值、空白、公式缓存值和班次差异，不会补数、插值或
平移成其他月份；展示名称是明确的演示映射，不是从首份文件的“XX煤矿”标题猜测。
两份样表没有企业签名，单位和“用工量→入井人员量”口径也未经监管核验。该命令拒绝
写入未由它创建的非空目录，所有演示数据均不得用于监管认定。只查看大屏无需配置企业
客户端；要让 `/readyz` 通过并实际接收 Agent 报送，仍须配置
`MINEGUARD_V2_CLIENTS_JSON`。该运维变量名当前为兼容保留；正式新报送仍走十量 V3。

## 数据保存位置

- 政府端：`platform/.mineguard-v2/mineguard.db` 及同目录认证/备份状态；集中保存多矿
  规范报文、算法运行、风险、回复和审计链。
- 企业端：每座矿自己的 `ENTERPRISE_AGENT_DB`（默认 `agent/data/enterprise-agent.db`）；
  只保存本矿导入材料、确认、outbox/inbox、风险会话和审计。

两端绝不能指向同一个数据库或共享状态目录。
`.mineguard-v2`、`fq_*` 及部分 Python 文件名是原地升级时保留的存储/代码标识，不等于
新报送仍使用五量 V2；业务合同以报文 `contract_version` 和 `/v3/` 路径为准。

## 验证与文档

```bash
cd /home/sevan/coral
python3 contracts/scripts/validate_contracts.py
PYTHONPATH=platform/src python3 -m pytest -q platform/tests
PYTHONPATH=agent/src python3 -m pytest -q agent/tests
PYTHONPATH=connector-service/src python3 -m pytest -q connector-service/tests
python3 scripts/verify_two_process.py --timeout 60
```

进一步说明先看 [十量 V3 部署与运行](docs/十量V3部署与运行.md)，再看
[`mineguard.cn` 正式上线步骤](docs/mineguard.cn正式上线步骤.md)、
[正式生产部署与签字说明](docs/正式生产部署与签字说明.md)、
[自动采集与自动填报部署指南](docs/自动采集与自动填报部署指南.md)、
[企业模型凭据签发与轮换](docs/企业模型凭据签发与轮换.md)、
[Windows 二进制发行与安装](docs/Windows二进制发行与安装.md)、
[Windows 原生部署与运维](docs/Windows原生部署与运维.md)、
[政府平台说明](platform/README.md)和[企业智能体说明](agent/README.md)。

`docs/V2*.md` 只记录五量 V2 历史架构、迁移和审计口径，不再作为新部署入口。

仅停用 demo 账号不等于正式版。实地正式上线还必须使用带 Authenticode 签名的正式候选
介质，或按介质外 SHA-256 核验的 `INTERNAL-UNSIGNED` 受控内网正式介质，并完成 HTTPS、
逐矿身份与双 HMAC、企业四眼复核、备份恢复和现场验收。

旧 V1 契约仅保留用于历史记录审计重放，不属于新部署的默认启动拓扑。
