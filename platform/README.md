# MineGuard · 矿安智察 · 煤矿十量智能辅助监管系统 V3

`platform/` 是政府侧独立软件。它只接收各煤矿企业智能体发送的规范十量 V3 报文，自动
运行唯一监管算法，形成不可变报告、风险通知、企业回复和修订重算留痕，并向领导
提供只读驾驶舱。

它不负责企业填报，不连接矿区设备，不允许领导修改企业数据、算法参数或风险状态。
企业端实现位于 `../agent/`，双方没有 Python import、数据库或文件目录依赖，只分别
实现 `../contracts/` 发布的 V3 HTTPS/JSON/双 HMAC 协议。五量 V2 仅保留只读历史
验签、审计和展示，不得补造新增字段或重新形成正式结论。

## 十量口径

正式十量固定为风量、电量、火工品量、入井人员量、产量、开采量、销售量、运输量、
洗煤量和开票量。火工品量拆成不同单位的雷管与炸药，因此底层共 11 个原子字段：

```text
ventilation_m3_min  electricity_kwh   detonators_count   explosives_kg
mine_entry_persons  production_t      extraction_t       sales_t
transport_t         wash_feed_t       invoiced_quantity_t
```

`mine_entry_persons` 是实际入井人次；`production_t` 是企业报表产量，
`extraction_t` 是采掘计量；`transport_t` 是出矿/外运净吨数，`wash_feed_t` 是入洗
原煤量。`invoiced_quantity_t` 必须非负，只记录正常/蓝字发票对应实物吨数；红票、
退票、作废、折让和退货在企业来源系统作为辅助明细独立留存，净额另算，不能把负数
写进主字段；当前 V3 主报文不传这些辅助事件。
完整单位、聚合和班次要求见
[十量 V3 部署与运行](../docs/十量V3部署与运行.md#2-十量与-11-个原子字段)。

## 主流程

```text
单矿 Agent 签名月报
  → 平台验签、幂等接收、追加留痕
  → 自动运行 mineguard-ten-quantity-engine
  → normal_candidate / risk / insufficient_data
  → 企业主动拉取需要回复的分析报告
  → 企业确认送达并提交人工确认的原因/证据/措施
  → 平台追加记录；原因说明不消除风险
  → 更正月报按同一算法重算通过后，才记为 cleared_by_reanalysis
```

一个企业客户端只能绑定一个煤矿。多个煤矿由政府端集中注册，但每矿必须使用独立
`sender_id`、经营主体、消息密钥和运输密钥。

## 唯一算法与求解器位置

当前兼容函数名仍可见于内部 Python 实现，但 V3 提交会按 `quantity_scope=ten_quantity_v3`
进入十量管线。该管线依次完成：

1. 11 原子字段的缺失、单位、非负值及日报—三班确定性核对；
2. 停产、检修、复产爬坡和生产工况识别；
3. 产量、开采、洗煤进料、销售、运输、开票的同期间软关系核对，避免把合法库存、
   在途和结算时差误写成简单等式；
4. 本矿正式准入历史的 Median/MAD、Rolling MAD、EWMA、CUSUM、Page-Hinkley、
   漂移和 SSE/BIC 变化点；
5. 至少三座可比矿、每矿等权且按报告截止日冻结的匿名同类矿参考区间；
6. HiGHS 加权 L1 联合协调和严格反事实最小冲突集 MCS；
7. 证据合并与三态结论；十量主字段、必需班次或当前可执行模块的证据不足时返回
   `insufficient_data`，不能把“无法验证”显示为冲突；
8. 独立的历史基线准入：首期完整正常数据只进入隔离参考候选；只有求解成功、没有
   复核级/风险级信号，并有正式本矿历史或冻结匿名同类矿独立锚点的数据才进入正式
   历史基线。

求解器只在第 6 步内部使用。班次窗口、汇总口径、非负性和日报—班次确定性差异检查
先由规则层完成；随后 HiGHS 解“在各观测容差和软参考区间下，所有十量联合相容所需
的最小加权 L1 调整”。它不直接预测真实产量，也不把历史关系当成物理真理。销售、
运输和开票分别保留业务含义，不作为三次出库重复扣减。MCS 再用
严格容差可行性问题回答“最少放松哪些观测或参考组后才可行”，用于给领导和企业指出
优先核查的日期、指标及证据组合。既有时序算法仍在同一引擎内，与 L1/MCS 互补。

`manual_import` 与 `direct_collection` 是并列合法的来源方式，只用于追溯；算法不会
按采集方式设置权重、阈值或信任等级。

本版 V3 主报文没有期初/期末库存、洗后产品与损耗、逐批运输/开票日期和来源依赖域。
所以高级核心中的原煤收发存、洗选投入产出、逐批凭证账龄及窗口流网络在生产适配器中
明确为 `skipped`，不会参与当前结论，也不会因缺少这些未发布字段而制造
`insufficient_data`。要启用这些能力，必须新增独立、版本化的辅助证据合同、持久化与
快照哈希，再完成单独验收；不得把当前 11 个主量静默解释成库存或逐批凭证。

## 最快开始：两条短路径

从 U 盘复制完整的 `platform/` 目录后，先进入该目录，只需运行：

```bash
bash start.sh
```

中文菜单提供“演示启动、正式首次配置、启动现有配置、健康检查、退出”五项。若本目录
还没有 `.venv`，脚本只会从同目录 `wheelhouse/`（或 `MINEGUARD_WHEELHOUSE` 指定的
离线目录）安装，明确禁用网络索引；缺少完整离线依赖时会停下并给出中文提示，不会偷偷
联网、提权或修改 systemd。已有环境时直接进入菜单。

已经安装好 `mineguard` 后，Linux 上先看演示也只需一条命令，不需要准备
`clients.json`，也不需要写环境变量或长参数：

```bash
mineguard demo
```

命令会准备隔离演示数据并在 `127.0.0.1:8080` 前台启动。用 Edge 或 Chrome 打开
<http://127.0.0.1:8080/>，登录账号为 `admin`，密码为 `123123123`。默认账号只限本机
展示，不能用于正式运行、企业报送或监管认定；Internet Explorer 不支持。终端一直占用
表示平台正在运行，不是卡死；按 `Ctrl+C` 即停止。

正式内网首次配置也不需要手写一串参数。先把单位批准的 `clients.json` 放在不会移动的
受控路径，然后依次运行：

```bash
mineguard setup
mineguard start
```

`mineguard setup` 会逐项询问 `clients.json` 完整路径、是否已有 HTTPS 反向代理、管理员
账号和密码。正式配置必须确认 HTTPS；密码输入时终端不会显示字符，需要再输入一次确认。
正式密码至少 12 个字符，并包含大小写字母、数字、符号中的至少三类，且不能使用演示或
常见弱口令。向导只在状态目录保存非敏感启动配置和密码摘要，不保存
明文密码；`clients.json` 中的逐矿密钥仍留在原受控文件，因此该文件配置后不能随意移动。
默认状态目录是当前目录下的 `.mineguard-v2`，默认端口是 `8080`，所以通常无需附加任何
参数。`mineguard start` 仍只监听 `127.0.0.1`；正式领导端应通过单位批准的 HTTPS 反向
代理访问。需要长期常驻时再按部署文档配置 systemd，而不是让人工终端一直开着。

## 开发环境安装与高级启动

需要 Python 3.11+：

```bash
# 如果当前已经激活 agent/.venv，先退出；仅 cd 不会切换虚拟环境
deactivate 2>/dev/null || true
cd /home/sevan/coral/platform
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -c constraints.txt -e .
command -v mineguard
```

输出应为 `/home/sevan/coral/platform/.venv/bin/mineguard`。`cd platform` 不会自动
从企业端虚拟环境切换到政府端环境；必要时也可以始终使用该绝对路径。若出现
`Address already in use`，用 `ss -ltnp | grep ':8080'` 识别现有服务，停止旧服务或
改用未占用端口。

下面是保留给兼容部署、排障和自动化的 `serve` 高级入口；日常演示优先使用
`mineguard demo`，正式首次配置优先使用 `mineguard setup` 后接 `mineguard start`。

为一座接入测试矿配置政府登记信息。消息 HMAC 与 HTTP 运输 HMAC 应使用不同密钥。下例
`change_me` 是故意不能通过校验的占位值，必须先替换成两把不同的独立随机密钥：

```bash
export MINEGUARD_V2_CLIENTS_JSON='{
  "clients": [{
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
      "demo-exchange-key": "DEMO_message_HMAC_secret_change_me_32_bytes"
    },
    "transport_secrets": ["DEMO_transport_HMAC_secret_change_me_32_bytes"]
  }]
}'
mineguard serve --host 127.0.0.1 --port 8080 \
  --state-directory .mineguard-v2
```

政府客户端注册变量目前仍名为 `MINEGUARD_V2_CLIENTS_JSON`（Windows 推荐对应的
`MINEGUARD_V2_CLIENTS_FILE`），这是兼容旧部署脚本的稳定运维名称；同一注册表会验证
V3 客户端与 V3 双 HMAC，不代表提交路径仍是 V2。

打开 <http://127.0.0.1:8080/>。全新本机状态目录的默认账号是
`admin / 123123123`。这只用于回环地址演示；非本机监听首次启动必须预先设置至少
8 个字符的 `MINEGUARD_ADMIN_PASSWORD`，生产应使用独立随机长口令和 HTTPS。

领导端账号由独立运维命令维护，不在只读监管业务页中修改。命令必须指向正在运行
服务使用的同一个 `--state-directory`，可以在服务运行时执行，无需重启：

```bash
# 先查看可授权的煤矿 ID 和现有账号
mineguard user mines --state-directory .mineguard-v2
mineguard user list  --state-directory .mineguard-v2

# 新增只能查看指定煤矿的领导账号；受控演示初始密码为 123123123
mineguard user add leader_a \
  --role viewer \
  --mine-id MINE-QY-001 \
  --state-directory .mineguard-v2 \
  --demo-default-password

# 辖区全部煤矿仍使用只读 viewer，不必授予 admin
mineguard user add leader_all \
  --role viewer \
  --all-mines \
  --state-directory .mineguard-v2 \
  --demo-default-password

# 多矿账号重复传入 --mine-id；修改范围会立即注销该账号现有会话
mineguard user set-access leader_a \
  --role viewer \
  --mine-id MINE-QY-001 \
  --mine-id MINE-QY-002 \
  --state-directory .mineguard-v2

mineguard user disable leader_a --state-directory .mineguard-v2
mineguard user enable leader_a  --state-directory .mineguard-v2
mineguard user reset-password leader_a \
  --state-directory .mineguard-v2 --demo-default-password

# 从旧版本升级后，如提示“凭据策略过期”，账号本人在服务器本机交互改密
mineguard user change-password admin \
  --state-directory .mineguard-v2
```

不加 `--demo-default-password` 时会安全交互输入密码。正式状态必须在服务器
本机附着的交互终端无回显输入；不接受命令行、管道或
`MINEGUARD_NEW_USER_PASSWORD` 环境变量。该环境变量只保留给非正式兼容流程，
命令读取时也会立即从当前进程环境中清除。`viewer`、`reviewer`、`supervisor` 在当前 V3
领导端均为只读且受 `--mine-id` 限制；`admin` 查看全部煤矿，只应给系统管理员。
正式状态中新建或管理员重置的账号标记为“待换密”；该账号完成自助改密前不能访问监管
业务。正式启动会拒绝仍启用的 `123123123`/临时演示账号，但不会因普通领导账号等待首次
改密而阻断整个平台；至少一个正式管理员必须已完成改密。旧版本账号没有可验证的当前
凭据策略标记，升级后必须通过上面的本机 `change-password` 验证旧密码并轮换，正式启动
不会仅凭弱口令字典猜测其安全性。该命令拒绝管道、环境变量和命令行明文密码。演示状态
不受此门禁影响。
`--all-mines` 会展开为当前全部煤矿的明确授权；后续新增煤矿时再次执行
`set-access --all-mines` 即可。账号不物理删除，离岗时使用 `disable`，以保留权限
审计和历史留痕。

正式注册表必须显式填写非演示的 `sender_id`、`party_id`、`mine_id`、
`mine_name` 和五个 `comparison_context` 维度，并配置消息密钥和另一把不同的
运输密钥。正式门禁会检查当前及轮换窗口内的全部密钥，拒绝演示/占位 key ID、
低多样性或短片段重复密钥、跨用途复用密钥，以及 `unclassified`、`replace`等占位
分组值。轮换时可在 `message_keys` 中短期保留旧 key ID，并用
`active_message_key_id` 指定当前密钥。

服务启动后终端保持占用是正常现象。另开终端检查：

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

需要查看五量 V2 历史兼容展示时，可生成完全隔离的混合来源演示数据：

```bash
mineguard seed-v2-demo --state-directory .mineguard-v2-demo-v2 \
  --through-month 2026-07-31
mineguard serve --state-directory .mineguard-v2-demo-v2
```

该数据集共 10 座矿、26 次月报：8 座合成教学矿各 3 个完整月；太岳矿、梗阳矿分别
只有固定的 2026 年 7 月 1 次月报，其数值逐格来自随包 `.et` 样表。样表空白仍为
`null`，明确零值仍为 `0`，公式只读已保存缓存，日报/班次差异不修正，也不会复制、
插值或平移到其他月份。两类来源在留痕中分别标识；样表没有企业签名，身份、单位和
业务口径未经监管核验。命令不会写入没有演示所有权标记的非空目录。只查看大屏无需
客户端注册，实际接收 Agent 报送和通过 `/readyz` 仍需要配置注册表。
逐字段来源、固定哈希和已知缺失见
[太岳矿与梗阳矿样表演示说明](docs/太岳矿与梗阳矿样表演示说明.md)。

该演示命令不为旧样表补造开采、销售、运输、洗煤或开票数据；这些记录在 V3 界面中
明确显示为 Legacy/字段不足，不得用于十量算法验收。

## 接口边界

企业交换接口与 OpenAPI 一致：

```text
POST /v3/ten-quantity-submissions
GET  /v3/ten-quantity-submissions/{message_id}/receipt
GET  /v3/analysis-reports/next?after_cursor=...
GET  /v3/analysis-reports/{report_id}
POST /v3/analysis-reports/{report_id}/delivery-ack
POST /v3/analysis-reports/{report_id}/responses
GET  /v3/risk-responses/{response_id}/receipt
```

领导业务接口只有登录与只读查询：

```text
GET /v2/regulatory/overview
GET /v2/regulatory/mines
GET /v2/regulatory/mines/{mine_id}
GET /v2/regulatory/findings
GET /v2/regulatory/exchanges
```

政府前端右上角“全屏”按钮右侧提供“大屏展示”。也可以在已登录会话中直接打开并收藏：

```text
http://<政府平台地址>:<端口>/wallboard
```

大屏是独立只读单页：不显示筛选、搜索、导出和业务操作，业务数据每 10 秒自动更新，
重点煤矿每 8 秒自动轮播；更新失败时保留最后一次成功数据并提示异常。浏览器禁止页面
在无用户手势时自行进入全屏，因此从普通监管页点击“大屏展示”会尝试进入全屏，直接
打开上述地址时可使用浏览器 F11 或受管终端的 kiosk 模式。大屏不绕过政府账号登录，
不得把账号、密码或会话令牌写入 URL。

不存在企业数据新增、修改、删除、手工改结论或风险关闭接口。后台机器交换 POST 不
授予领导账号任何写权限。

## 数据和安全

- V3 与只读 V2 历史表位于 `--state-directory` 下的 `mineguard.db`，与每矿 Agent 数据库完全分离；
- 报文、日报事实、算法输入摘要、run、报告、投递确认、回复和状态迁移均追加保存；
- SQLite 表有禁止 UPDATE/DELETE 的触发器，审计事件形成 SHA-256 链；
- HTTP 时间窗和 nonce 防重放持久化，重启后仍生效；
- `sender_id ↔ mine_id` 双向唯一，路径、信封、payload、报告和风险项均再次核对矿井；
- 同类矿输出只有匿名区间和样本数，不向企业泄露其他矿明细；
- 原因回复只形成 `explanation_recorded`，风险结论不会因此被覆盖。

生产部署、字段、CSV、密钥轮换、备份和故障验收先见
[十量 V3 部署与运行](../docs/十量V3部署与运行.md)。旧 `V2*.md` 只用于历史迁移和
只读审计参考。
领导日常查看与交办见 [领导端十量 V3 操作说明](docs/领导端十量V3操作说明.md)。

政府端原生 Windows 安装、离线 wheelhouse、低权限 WinSW 服务、NTFS ACL、健康检查
和备份恢复见 [Windows 原生部署与运维](docs/Windows原生部署与运维.md)。
不交付源码的 Windows 二进制构建入口、Nuitka standalone 结构、自检和签名参数见
[Windows 二进制构建](packaging/windows/README.md)。

## 验证

```bash
cd /home/sevan/coral
python3 contracts/scripts/validate_contracts.py
PYTHONPATH=platform/src python3 -m pytest -q platform/tests
cd platform
ruff check src tests
ruff format --check src tests
```

HTTP 端到端测试会在随机本机端口真实完成 V3 报送、唯一算法、报告拉取、送达
确认、企业回复和只读大屏查询，并用中立 Schema 校验三个政府出站消息。

生产命令 `mineguard` 只导入当前 V3 平台和备份组件，不导入旧 edge、安全、案件或多算法
运行栈，也不再安装第二套 legacy 命令。仓库中的旧源码只可用于受控数据迁移参考，
不能作为新部署入口，也不能把旧 V1 API 或五量 V2 当作 V3 主线。
