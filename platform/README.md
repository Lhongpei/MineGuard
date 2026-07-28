# MineGuard 多源交叉验证与核查闭环

MineGuard 是面向煤矿监管的单节点内网影子运行版：接收已登记来源的签名观测，
执行产、运、洗、销、存交叉验证，把技术异常转为可分派、复核、双人审批和导出的
核查事项，并向非技术管理人员提供辖区总览与趋势页面。

系统只形成“技术核查线索”，不会自动认定违法事实、责任或处罚结论。

正式内网发布物是 Python 包及内置的 `src/mineguard/web` 前端，通过
`mineguard serve` 启动。根目录 `app/` 与 `package.json` 是早期公网视觉原型，
不接入可信数据、案件或证据链，不属于 0.5.0 验收范围，不能替代正式服务。

## 当前可用能力

- 服务端版本化管理来源、矿区、指标、单位、容差、可靠性、根来源组和分析参数；
- 校验观测载荷哈希、HMAC、序号、修订号、时间、单位、来源有效期和校准有效期；
- 单矿可信接入，以及按应报矿井名单接入辖区批次并明确显示缺报；
- 五量线性规划协调、物料平衡、最小修正集、合理产量区间和技术敏感性结果；
- 算法 V2.1 对全部最小优先修正情景取稳健结论；情景缺失、无界、分歧或
  搜索预算不足时自动降为 D 级，不输出差额结论；
- 绝对误差、相对误差和设备分辨率组成动态容差；共享 PLC、数据库或人工台账的
  来源按依赖连通簇去重，不重复计算“独立证据”；
- 区分窗口总量、区间增量、累计表、时点库存和瞬时流率，校验覆盖率、边界、
  重叠和显式复位，缺失值从不按零处理；
- 可配置的跨窗口物料流网络，支持库存连续、运输时延、显式期初在途、损耗区间、
  主最优面可辨识区间和最小修复建议；未知量返回 `null`/区间而不是伪造 0；
- 滚动 MAD、EWMA、双向 CUSUM、Page-Hinkley 和数据质量检测，领导端按异常
  片段展示；冷启动、历史截断和不可信试算均不下“正常”结论；
- 保留同矿、同引擎、同配置、同来源结构及同注册表快照的技术经验校准；样本不足
  20 个或查询截断时不输出经验概率；
- 新增按矿井、兼容键和完整运行工况精确匹配的人工核验正常历史基线，使用多维
  median/MAD 和上尾最大稳健距离的 `+1` 经验稀有度；核心工况不完整或少于
  20 个合格人工核验正常样本时，明确显示未评估或历史不足；
- 生产鉴权模式下，吨煤核验历史样本须先绑定产量、用电、火工品 SHA-256 与
  证据引用进入不可变注册表，再由非登记人按预期摘要批准；正式分析仅接纳
  JSON 与摘要完全匹配且审计链有效的批准样本，开发免鉴权试算则明确标记为
  `caller_supplied_untrusted`；
- 六类追加式历史标签与不可变合法情景版本；只有“人工核验正常”可进入正常
  基线，“经批准合法例外”只关联版本化场景解释辅助信号。历史、时序和合法情景
  只生成保守影子研判，不改写物理 L1/MCS 主结论；
- 受治理分析落库前自动生成当前窗口时序证据：仅使用严格先前、同矿、同兼容键
  和同四轴工况的可信窗口，冷启动或读取截断时失败关闭；
- 人脸—定位卡时间及身份交叉匹配（管理员直接分析工具）；
- 独立矿端边缘服务的六类只读遥测接入：raw-body HMAC、客户端矿井范围、
  nonce 防重放、批次/观测幂等、断网续传回执和原始批次留存；
- 人员、甲烷和通风的版本化确定性规则、数据质量门、状态去抖、联合升级及
  蓝/黄/橙/红技术预警；矿端本地预警仅作提示，平台按自己的规则重新计算；
- 安全预警可指派、确认、开始处置、解决、关闭和重开，采用乐观锁和追加式
  哈希审计链；规则结果不具备风机、断电、复电或其他生产控制权限；
- 吨煤生产电耗与吨煤炸药的同矿同工况历史核验：生产电量优先、五类干扰电量
  显式剔除、Median/MAD 稳健基线、时间防泄漏、冷启动失败关闭和同向线索升级；
- 登录、CSRF、`admin/supervisor/reviewer/viewer` 角色权限和矿区数据域隔离；
- 辖区总览、30 日趋势、矿井风险排序、重复异常、积压和办理时效；风险分
  采用 0—100 有界、按应报次数归一和 14 天半衰期衰减，并展示分项；
- 持久化异步任务，支持幂等提交、窗口失败隔离、取消、重放和重启恢复；
- 分派、补数、说明、提交结论、不同账号审批/退回、重开和追加式审计事件；
- 批次请求、响应和分析上下文分别做哈希校验，并校验输入快照、配置快照、结果
  哈希和办理哈希链；新建且三部分完整性有效的批次才有资格成为历史参考，
  迁移回填的旧批次只展示、不进入正常基线；
- 可下载、可离线校验的 HMAC 证据 ZIP 包；
- `/health`、`/live`、`/ready` 就绪检查，以及六个 SQLite 库的备份、校验和
  恢复到新目录。

## 首次启动

需要 Python 3.11+。安装本地命令：

```bash
python3 -m pip install -c constraints.txt -e .
mineguard --version
```

`constraints.txt` 固定了本次全量回归所用的数值计算和数据校验依赖版本。升级其中
任一版本前，应重新执行算法、迁移、接口和备份恢复测试，不应在生产主机上直接漂移
到未经验证的新版本。

本机首次启动可用一条命令完成。环境变量密码至少 8 个字符；下例仅为本地试用，
不要在共享终端或 shell 历史中写真实生产密码：

```bash
MINEGUARD_ADMIN_PASSWORD='change-this-local-password' \
  mineguard serve --host 127.0.0.1 --port 8080 \
  --state-directory .mineguard
```

然后打开 <http://127.0.0.1:8080/>，以 `admin` 和上述密码登录。若未设置
`MINEGUARD_ADMIN_PASSWORD`，终端会一次性显示随机管理员密码。已有用户库不会重复
创建管理员。

本次已初始化的本地验收实例约定登录账号为 `admin`、密码为 `123123123`。该口令
只用于当前受控演示，首次登录后应立即在页面修改；新建状态目录不会固定使用该
口令，仍按上述环境变量或一次性随机密码流程初始化。

不安装也可运行：

```bash
MINEGUARD_ADMIN_PASSWORD='change-this-local-password' \
  PYTHONPATH=src python3 -m mineguard.cli serve \
  --host 127.0.0.1 --port 8080 --state-directory .mineguard
```

`--no-auth` 只允许用于隔离本机的脱敏演示，不属于内网影子运行配置。对内网用户
开放前，应由 HTTPS 反向代理提供访问入口，并给后端增加 `--secure-cookie`。

## 领导工作台

登录后的中文页面按任务组织：

- “辖区总览”查看应报、实报、缺报、技术不一致、优先级和开放事项；
- “趋势研判”查看覆盖率、重复异常、矿井排序、案件积压和办理时效；
- “趋势研判”的“时序异常与数据源健康”卡查看近 90 日漂移、变点、冷启动和
  来源质量提示；预警只表示应优先复核，不是定案；
- “核查台账”查看物理、条件历史、时序和合法情景是否相互支持，办理事项并执行
  不同账号的结论复核；有审批权限的人员可追加历史参考标签；
- “分析任务”查看批量任务进度、单窗口失败、取消和重放；
- “系统管理”供管理员维护账号、合法情景和历史参考样本，执行不同账号审批，
  并查看配置、就绪状态和运行信息；
- “临时分析”保留管理员使用的原始 JSON 分析工具。

页面中的风险分、证据等级和最小上报差额都是技术指标，不是处罚等级或违法认定。
领导应关注覆盖率、重复出现、待复核积压和原始证据是否齐全，而不是只看单一分数。

## 数据生命周期与删除策略

监管数据默认不从业务前端硬删除，而以可恢复、可审计的状态变更处置：

- 账号由管理员停用或恢复；停用、改权和重置密码都会使相关会话失效；
- 待审批结论可由提交人说明原因后撤回；案件完成双人审批并关闭后，可归档或恢复；
- 运行中的任务可取消，终态任务可填写原因后归档或恢复；
- 错误批次可填写原因后作废或恢复；历史 `pilot-*` 演示批次可集中隔离，避免进入
  正式总览、趋势、案件和校准统计；
- 历史参考标签以追加事件和哈希链保存；合法情景以 `scenario_id + version`
  保存，不提供删除或原地覆盖，修订或停用必须新增版本；
- 吨煤核验历史样本按 `sample_id` 绑定规范化正文、三类来源摘要和证据引用；
  批准或驳回后不可改判，正文变化须使用新样本编号重新登记；
- 证据包、办理/权限审计和备份不提供业务前端硬删除。达到本单位留存期限后的销毁，
  应按经批准的离线运维流程执行并保留审批、范围和校验记录。

归档或作废只影响默认业务视图，不抹除原始记录和历史链；管理员可在相应页面查看
已归档或已作废数据并恢复。

## 可信数据接入

完整可复制流程见 [可信数据接入说明](docs/可信数据接入说明.md)。仓库提供一套
仅供演示的配置：

- [五量分析配置](examples/governance/profile-five-flow.json)
- `examples/governance/source-*.json` 五个来源注册样例

受治理接口是：

```text
POST /v1/governance/profiles
POST /v1/governance/sources
POST /v1/ingest/production
POST /v1/ingest/production/batch
POST /v1/ingest/production/jobs
GET/POST /v1/analysis-runs/{run_id}/reference-labels
GET/POST /v1/admin/legitimate-scenarios
GET/POST /v1/admin/verification-references
POST /v1/admin/verification-references/{sample_id}/actions
GET/POST /v1/admin/external-event-snapshots
GET/POST /v1/admin/external-confirmers
```

调用方只能提交原始签名观测，不能自行传入容差、可靠性、来源组、质量分或分析
参数。可信请求可提交受控的 `operational_context`，用于同工况历史匹配，但它
不能覆盖物理参数。要形成历史评估，`regime_code`、`shift_code`、
`season_code` 和 `maintenance` 四个核心字段必须完整。企业报送的事件代码（包括
空集合）必须与监管端预先登记的不可变查询快照精确匹配矿井、时间窗、完整代码集和
来源证据摘要；该匹配证明报送复用了监管查询结果，但不单独证明事件真实，也不改变
物理结论。
标签写入要求管理员或对应矿区 `supervisor` 的审批权限；合法情景仅管理员管理。
直接分析和调用方自带参数的异步任务仅对管理员开放，不能替代可信接入。

### 企业智能体独立接入

仓库上级目录的 `agent/` 是企业侧独立服务，`platform/` 不 import 它的代码，
不共享其数据库或内部模型；企业端也不 import `mineguard`。双方仅分别实现
`../contracts/` 中的版本化 HTTP/JSON Schema、观测签名和运输 HMAC 规范。

监管端机器接口为：

```text
GET  /v1/enterprise-submission-capabilities
POST /v1/enterprise-submissions
GET  /v1/enterprise-submissions/{submission_id}/receipt
```

启动前通过监管端环境变量登记企业客户端：

```bash
export MINEGUARD_EXTERNAL_CLIENTS_JSON='[{"client_id":"enterprise-client-001","enterprise_id":"ENT-001","mine_ids":["M001"],"secrets":["DEMO_ONLY_change_transport_secret_32_chars"]}]'
```

`secrets` 第一项为当前运输 HMAC 密钥，每项至少 32 字节；轮换窗口可短暂保留旧
密钥，完成后应删除。平台按 `enterprise_id` 和 `mine_ids` 限制客户端范围。
企业端对应配置为同一 `PLATFORM_CLIENT_ID` 和
`PLATFORM_TRANSPORT_HMAC_SECRET`。每条观测必须先由独立设备/采集网关使用来源
密钥签名，填报智能体只搬运摘要与签名，不能持有来源密钥或给人工数据补签。
运输密钥与来源密钥不能复用。

`verified_event_snapshots` 仅用于旧部署配置的启动迁移。新快照应由监管管理员通过
`POST /v1/admin/external-event-snapshots` 登记；写入需要登录会话、CSRF 令牌和
`config.manage` 权限。平台保存完整排序结果、查询来源、创建人和内容摘要，相同
`snapshot_id` 同内容可幂等重试，不同内容冲突，且不提供更新或删除接口。企业接入
只查询该持久化注册表，不直接信任企业客户端配置中的事件集合。

`authorized_confirmers` 同样只保留旧部署启动迁移能力。新确认人通过
`POST /v1/admin/external-confirmers` 登记。确认人以
`client_id + enterprise_id + confirmer_id` 为自然键，从版本 1 连续追加；改名、
角色调整和停用均新增下一版本，停用版本设置 `active=false`，不提供覆盖或删除。
接入只匹配数据库当前版本的姓名、角色和 `authenticated_click` 方法，并将命中的
`registration_id`、版本和内容 SHA-256 固化进分析批次上下文。

机器客户端注册不能代替监管来源治理。首次报送前，管理员仍须在本平台独立登记
草稿引用的同一 `profile_id + version` 和全部 `source_id`；来源所属矿井、
指标、单位、容差、有效期和 HMAC 密钥都以监管注册表为准，企业报文不能覆盖。
设备/采集网关的来源密钥必须与监管端相应来源登记密钥一致；填报智能体不获得
该密钥，且两套系统不得共享注册表文件或数据库。

接收回执固定表达“接入时尚未形成监管结论”。它只证明本次报文通过契约、完整性、
权限和接入检查，不代表数据正常、真实、合法或合规；物理/历史/时序研判及监管
人员复核仍在平台侧独立完成。完整本地双进程配置见
[本地双系统运行](../docs/本地双系统运行.md)。

### 矿端边缘遥测接入

上级目录的 `edge-agent/` 是第三套独立进程，负责对出煤、用电、人员、甲烷、
火工品和通风做只读采集、规范化、本地留存与断网续传。它不 import `platform`
或 `agent`，也没有设备写入、风机控制、断电或复电接口。双方只实现
`../contracts/openapi/edge-telemetry-v1.openapi.json` 和固定 HMAC 向量。

监管端接口为：

```text
GET  /v1/edge-telemetry-capabilities
POST /v1/edge-telemetry-batches
GET  /v1/edge-telemetry-batches/{batch_id}/receipt
GET  /v1/dashboard/safety
GET  /v1/safety/alerts
GET  /v1/safety/alerts/{alert_id}
POST /v1/safety/alerts/{alert_id}/actions
GET  /v1/safety/runs
GET/POST /v1/admin/mines
GET/POST /v1/admin/safety-rules
POST /v1/admin/safety-rules/{version}/actions
GET  /v1/verification/runs
GET  /v1/reports/regulatory
```

先生成至少 32 个随机字节并仅以 Base64 传递。例如：

```bash
EDGE_HMAC_SECRET_BASE64="$(openssl rand -base64 32 | tr -d '\n')"
export EDGE_HMAC_SECRET_BASE64
export MINEGUARD_EDGE_CLIENTS_JSON="$(
  python3 -c 'import json,os; print(json.dumps([{
    "client_id":"mine-edge-M001",
    "mine_ids":["M001"],
    "secrets":[os.environ["EDGE_HMAC_SECRET_BASE64"]]
  }], separators=(",",":")))'
)"
```

矿端配置完全相同的客户端、矿井、平台地址和
`MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64`。不要把 Base64 文本再次当作 HMAC
密钥本身；双方都先严格 Base64 解码。密钥只给矿端进程和监管接入层，不给浏览器、
LLM、人工填报页或井下生产控制系统。

每个新批号必须是
`{client_id}--batch_{32位小写十六进制摘要}`，且客户端编码最长 88 字符。平台
在落库前同时核对报文前缀和已通过 HMAC 的客户端身份，防止不同客户端抢占同一
全局批号。升级已有试点时先升级矿端并排空旧 pending，再开启本版平台；不要给
在途旧批次自动换号。完整兼容步骤见
[`contracts/VERSIONING.md`](../contracts/VERSIONING.md)。

平台还接受 V1 的可选 `interval` 统计窗口，以及不含个人身份的细化指标：
皮带瞬时产量/速度/运行/故障、区域人数、无卡入井、人卡不符、超时计数和雷管
整数计数。窗口存在时必须满足 `end > start`、`end <= received_at`，时区必须
可解释，聚合口径只能使用合同枚举。数据源健康使用
`source.heartbeat_age_seconds`（秒）、`source.consecutive_failures`
（整数计数）和 `source.missing_state`（0/1）；这三项强制
`location_code == source_id`。平台把窗口随原始观测持久化并在监管看板最新指标
中原样展示，不把来源健康或本地状态直接解释为违法、合规或生产控制指令。

首次复算前，管理员必须通过“矿井档案”或 `POST /v1/admin/mines` 配置
`gas_category`（`low_gas`/`high_gas`）和
`approved_underground_personnel`。未配置时平台会完整留存观测并产生蓝色
“参数待配置”线索，不会擅自假设瓦斯等级或核定人数。默认规则快照来自建设方案，
正式投产必须按适用规程完成版本审批。边缘端 `local_alerts` 永远只保存为提示；
监管台账只接收平台对原始观测独立复算的结果。

平台接收批次后会先尝试同步复算，同时将未完成状态持久化。后台线程持续扫描
`pending` 和到期的 `failed` 批次，按指数退避重试；同一矿井通过数据库租约
串行执行，进程中断后租约到期可自动恢复。默认最多尝试 5 次，之后进入死信，
失败预警保持开放。监管负责人和管理员可在安全工作台的“平台安全复算队列”
按状态查看批次、尝试次数、下次重试和稳定错误码，并对失败/死信批次点击
“受控重算”；同一能力也可由具备 `analysis.run` 权限的人员调用
`POST /v1/edge-telemetry-batches/{batch_id}/recalculate` 受控重算。`/ready`
会分别显示等待积压、退避重试、运行中和死信。部署参数见
`MINEGUARD_EDGE_EVALUATION_*` 环境变量。

主通风机运行、故障和倒机采用三个独立二值指标，平台拒绝非 `0/1` 值，并按
审批规则中的 `main_fan` 等级独立生成或恢复预警。矿端和平台均不提供风机控制
接口；现场仍须完成 PLC/厂商字段的只读映射和联调。

加入主通风机策略后的内置快照版本为
`qinyuan-safety-2026.07-v2`。升级时不会修改旧版本的内容或指纹；若数据库中
仍有缺少 `main_fan` 的旧批准版本，平台保留其审计记录但不把它解释成新版，
并提示先退役旧版、核对完整指纹后审批 V2。

站内每次新建、升级、降级、恢复以及人工办理都会先写入持久化通知 outbox。
如需接政务消息网关，在监管端配置
`MINEGUARD_SAFETY_WEBHOOKS_JSON`；每个目标含 `webhook_id`、HTTPS `url`、
`minimum_level` 和至少 32 随机字节的 `secret_base64`。平台以
`webhook_id + notification_id` 作为目标投递幂等键，发送内容摘要和 HMAC。
每个目标独立持久化成功、重试和死信状态：单个目标失败不会阻塞其他目标，成功
目标不会重复投递。管理员可在系统管理页查看逐目标状态并只重试 `dead` 目标，
也可使用 `GET /v1/safety/notifications` 和
`POST /v1/safety/notifications/{notification_id}/retry`。投递器拒绝 HTTP
重定向。未配置外部目标时不会联网，站内预警、台账和通知 outbox 仍完整工作。
重试接口仅接受管理员 CSRF 请求；`{"webhook_id":"county-gateway-01"}` 只重试
指定死信目标，`{}` 重试该通知的全部死信目标，非 `dead` 状态返回冲突。

管理员可在“预警责任路由”按矿井、类别和最低级别配置接收账号、备岗账号及
未读升级分钟数。所有匹配路由并行知会，最具体的一条保持唯一主责；每条路由
分别保留账号级已读，并在未读超时后独立升级备岗。蓝黄橙红办理期限从平台生成
正式预警起算，超过 `due_at` 产生一次性升级事件；重开后开始新一轮期限与回执。
路由增删会幂等重算当前开放预警，重启不会重复事件。影子预警不进入正式交办。
`/ready` 会暴露线程停运、未路由正式预警和待已读数量，部署轮询间隔由
`MINEGUARD_RESPONSIBILITY_POLL_SECONDS` 设置。

监管一张图可用 `--map-geojson /path/boundary.geojson` 或
`MINEGUARD_MAP_GEOJSON_PATH` 加载部署方提供的 Polygon/MultiPolygon 边界。
平台启动时限制大小和点数、校验经纬度及闭合环并剥离非必要属性，浏览器通过
受鉴权的 `GET /v1/map/boundary` 获取。未配置时仍只显示相对位置示意；即使
配置成功，也必须另行验收边界来源、坐标系和点位精度，不能用于测绘或导航。

安全预警卡支持核查附件闭环。复核人员、监管负责人和管理员可向
`POST /v1/safety/alerts/{alert_id}/attachments` 提交
`filename`、`media_type`、`content_base64`、`sha256` 和可选 `note`；
单文件解码后最多 5 MiB，仅允许 PDF、JPEG、PNG、UTF-8 TXT/CSV 以及无宏
XLSX/DOCX。平台核对哈希、文件特征和 OOXML 包结构，净化文件名后把内容作为
不可变 BLOB 与元数据存入同一监管数据库，并向预警哈希事件链追加
`attachment_added`。相同预警下的相同内容返回冲突，不提供覆盖或删除接口。
列表和下载分别使用：

```text
GET /v1/safety/alerts/{alert_id}/attachments
GET /v1/safety/alerts/{alert_id}/attachments/{attachment_id}/download
```

列表和下载按账号矿井范围授权；下载响应固定为
`application/octet-stream` 和 `Content-Disposition: attachment`，不在页面
内联渲染，并在下载前重新核对大小和 SHA-256。白名单和强制下载不替代生产环境
的终端防病毒、敏感信息检查及材料留存制度。

领导工作台提供确定性的月度/季度监管分析报告。报告只接受固定自然月
`YYYY-MM` 或自然季度 `YYYY-Q1` 至 `YYYY-Q4`，统计时区固定显式传入
`Asia/Shanghai`；任意起止日、自定义时区、未来报告期和重复参数均被拒绝。
例如：

```text
GET /v1/reports/regulatory?kind=monthly&period=2026-07&timezone=Asia%2FShanghai
GET /v1/reports/regulatory?kind=quarterly&period=2026-Q2&timezone=Asia%2FShanghai
```

接口根据当前登录账号的矿井范围复用领导统计、安全驾驶舱/预警台账和生产
交叉核验结果。无应报记录、缺报、历史不足、核验阻断、完整性失败和读取上限
都会显式进入报告质量状态，不能归入“正常”。页面只用安全文本节点展示内容，
支持浏览器打印/另存为 PDF，不提供自动外发、签批、立案或状态修改。详细口径
见 [月度季度监管报告](docs/月度季度监管报告.md)。

算法 V2.1 的管理员直调接口为：

```text
POST /v1/analyze/aggregation
POST /v1/analyze/flow
POST /v1/analyze/temporal
POST /v1/analyze/safety
POST /v1/analyze/verification
GET  /v1/dashboard/temporal?days=90
```

前三个接口用于配置验证、离线复现和算法人员调试；正式五量结果仍应走可信接入。
这些沙箱直调不会自动形成正式案件、办理事件或证据包，不得替代全证据闭环。
启用认证时，`/v1/analyze/verification` 还会逐条要求历史样本与平台已批准注册表
精确匹配；未注册、草案、驳回、正文变化或审计链异常均返回冲突并停止分析。
管理员可在“系统管理 → 历史参考样本治理”登记样本与证据，登记账号不能审批
自己的样本。关闭认证仅用于本地试算，返回结果会明确标记调用方历史不可信。
算法公式、字段、示例、冷启动和使用边界见
[算法 V2.1 说明](docs/算法V2.1说明.md)。

## 运维与备份

可执行的 systemd、HTTPS、巡检、备份、恢复和故障处理步骤见
[内网部署与运维手册](docs/内网部署与运维手册.md)，验收口径见
[内网可用版验收标准](docs/内网可用版验收标准.md)。

六库备份示例：

```bash
mineguard backup nightly-20260726 \
  --state-directory .mineguard

mineguard verify-backup nightly-20260726 \
  --state-directory .mineguard

mineguard restore-backup nightly-20260726 \
  --state-directory .mineguard-restored \
  --backup-directory .mineguard/backups \
  --key-file .mineguard/backup.key
```

备份 HMAC 密钥不在备份包内，必须另行离线保留。六库备份包含证据元数据和证据
签名密钥；新生成证据包的完整 ZIP 也以 BLOB 保存在 `evidence.db` 中，恢复后可
按哈希重建 `.mineguard/evidence/` 文件缓存。下载证据包后可离线校验：

```bash
mineguard verify-evidence /path/to/bundle.zip \
  --state-directory .mineguard
```

可直接采用仓库中的 [systemd 服务示例](deploy/mineguard.service.example)、
[环境变量示例](deploy/mineguard.env.example) 和
[Nginx HTTPS 示例](deploy/nginx-mineguard.conf.example)，按本单位路径与证书
标准调整后再启用。

## 命令行分析与测试

```bash
mineguard production examples/production_inconsistent.json
mineguard aggregate examples/aggregation_interval.json
mineguard flow examples/flow_anomalous.json
mineguard temporal examples/temporal_drift.json
mineguard personnel examples/personnel_session.json
mineguard safety @examples/safety-evaluation.json
mineguard verify-production @examples/production-verification.json
mineguard demo
pytest
```

## 使用边界

- 当前运行时是 Python 标准库 HTTP 服务、单工作进程和 SQLite，适合受控内网的
  单节点影子运行，不提供集群并发写、高可用或跨节点事务。
- 来源观测、证据包和备份清单使用共享密钥 HMAC。HMAC 能检查完整性和持钥方
  来源，但不是公钥数字签名、可信时间戳、不可否认签名或法律意义的证据保全。
- 本地事件哈希链可发现内容变化，但本地管理员仍可能同时改数据并重算哈希；
  它不是 WORM 或对象锁。
- 正式业务辅助仍需部署单位接入 TLS、统一 SSO/IAM、KMS/HSM、设备侧签名、
  WORM/对象锁、生产级数据库、监控告警、异地备份和原始凭证系统。
- 上线前必须确定矿井授权清单、角色名单、数据最小化、留存期限、日志访问、
  设备密钥轮换、证据调阅和恢复演练责任人，并完成安全、业务和法律授权。
