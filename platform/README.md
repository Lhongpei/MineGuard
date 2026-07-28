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
- 六类追加式历史标签与不可变合法情景版本；只有“人工核验正常”可进入正常
  基线，“经批准合法例外”只关联版本化场景解释辅助信号。历史、时序和合法情景
  只生成保守影子研判，不改写物理 L1/MCS 主结论；
- 受治理分析落库前自动生成当前窗口时序证据：仅使用严格先前、同矿、同兼容键
  和同四轴工况的可信窗口，冷启动或读取截断时失败关闭；
- 人脸—定位卡时间及身份交叉匹配（管理员直接分析工具）；
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
- “系统管理”供管理员维护账号并查看配置、就绪状态和运行信息；
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

算法 V2.1 的管理员直调接口为：

```text
POST /v1/analyze/aggregation
POST /v1/analyze/flow
POST /v1/analyze/temporal
GET  /v1/dashboard/temporal?days=90
```

前三个接口用于配置验证、离线复现和算法人员调试；正式五量结果仍应走可信接入。
这些沙箱直调不会自动形成正式案件、办理事件或证据包，不得替代全证据闭环。
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
