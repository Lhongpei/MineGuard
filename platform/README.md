# MineGuard · 矿安智察 · 煤矿智能辅助监管系统 V2

`platform/` 是政府侧独立软件。它只接收各煤矿企业智能体发送的规范五量报文，自动
运行唯一监管算法，形成不可变报告、风险通知、企业回复和修订重算留痕，并向领导
提供只读驾驶舱。

它不负责企业填报，不连接矿区设备，不允许领导修改企业数据、算法参数或风险状态。
企业端实现位于 `../agent/`，双方没有 Python import、数据库或文件目录依赖，只分别
实现 `../contracts/` 发布的 V2 HTTPS/JSON/HMAC 协议。

## 五量口径

正式五量固定为风量、电量、火工品量、入井人员量和产量。底层使用六个规范原子字段：
火工品量分别保存雷管数量（`count`）、炸药质量（`kg`）等带单位子项，各子项不能跨
单位相加；`mine_entry_persons` 表示统计范围内实际发生的入井人次，必须为整数并按
`sum` 聚合，不表示泛用工、在册/排班人数或时点井下人数。六个原子字段只是五量的
规范化表达，不是“六量”。

## 主流程

```text
单矿 Agent 签名月报
  → 平台验签、幂等接收、追加留痕
  → 自动运行 mineguard-five-quantity-engine
  → normal_candidate / risk / insufficient_data
  → 企业主动拉取需要回复的分析报告
  → 企业确认送达并提交人工确认的原因/证据/措施
  → 平台追加记录；原因说明不消除风险
  → 更正月报按同一算法重算通过后，才记为 cleared_by_reanalysis
```

一个企业客户端只能绑定一个煤矿。多个煤矿由政府端集中注册，但每矿必须使用独立
`sender_id`、经营主体、消息密钥和运输密钥。

## 唯一算法与求解器位置

唯一公开算法入口是：

```python
analyze_five_quantity(submission, history=..., peer_bands=..., parameters=...)
```

它在一条版本化管线内完成：

1. 缺失、单位、非负值及日报—三班确定性核对；
2. 停产、检修、复产爬坡和生产工况识别；
3. 本矿正式准入历史的 Median/MAD、Rolling MAD、EWMA、CUSUM、Page-Hinkley、
   漂移和 SSE/BIC 变化点；
4. 至少三座可比矿、每矿等权且按报告截止日冻结的匿名同类矿参考区间；
5. HiGHS 加权 L1 联合协调和严格反事实最小冲突集 MCS；
6. 证据合并与三态结论；
7. 独立的历史基线准入：首期完整正常数据只进入隔离参考候选；只有求解成功、没有
   复核级/风险级信号，并有正式本矿历史或冻结匿名同类矿独立锚点的数据才进入正式
   历史基线。

求解器只在第 5 步内部使用。班次窗口、汇总口径、非负性和日报—班次确定性差异检查
先由规则层完成；随后 HiGHS 解“在各观测容差和软参考区间下，所有五量联合相容所需
的最小加权 L1 调整”。它不直接预测真实产量，也不把历史关系当成物理真理。MCS 再用
严格容差可行性问题回答“最少放松哪些观测或参考组后才可行”，用于给领导和企业指出
优先核查的日期、指标及证据组合。既有时序算法仍在同一引擎内，与 L1/MCS 互补。

`manual_import` 与 `direct_collection` 是并列合法的来源方式，只用于追溯；算法不会
按采集方式设置权重、阈值或信任等级。

## 本机启动

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

为一座演示矿配置政府登记信息。消息 HMAC 与 HTTP 运输 HMAC 应使用不同密钥：

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
```

不加 `--demo-default-password` 时会安全交互输入密码，也可通过
`MINEGUARD_NEW_USER_PASSWORD` 注入。`viewer`、`reviewer`、`supervisor` 在当前 V2
领导端均为只读且受 `--mine-id` 限制；`admin` 查看全部煤矿，只应给系统管理员。
`--all-mines` 会展开为当前全部煤矿的明确授权；后续新增煤矿时再次执行
`set-access --all-mines` 即可。账号不物理删除，离岗时使用 `disable`，以保留权限
审计和历史留痕。

正式注册表必须显式配置消息密钥和另一把不同的运输密钥；相同密钥或缺少运输密钥会
在启动时直接拒绝。轮换时可在 `message_keys` 中短期保留旧 key ID，并用
`active_message_key_id` 指定当前密钥。

服务启动后终端保持占用是正常现象。另开终端检查：

```bash
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

需要直接查看多矿时序和风险场景时，可生成完全隔离的混合来源演示数据：

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

## 接口边界

企业交换接口与 OpenAPI 一致：

```text
POST /v2/five-quantity-submissions
GET  /v2/five-quantity-submissions/{message_id}/receipt
GET  /v2/analysis-reports/next?after_cursor=...
GET  /v2/analysis-reports/{report_id}
POST /v2/analysis-reports/{report_id}/delivery-ack
POST /v2/analysis-reports/{report_id}/responses
GET  /v2/risk-responses/{response_id}/receipt
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

- V2 表位于 `--state-directory` 下的 `mineguard.db`，与每矿 Agent 数据库完全分离；
- 报文、日报事实、算法输入摘要、run、报告、投递确认、回复和状态迁移均追加保存；
- SQLite 表有禁止 UPDATE/DELETE 的触发器，审计事件形成 SHA-256 链；
- HTTP 时间窗和 nonce 防重放持久化，重启后仍生效；
- `sender_id ↔ mine_id` 双向唯一，路径、信封、payload、报告和风险项均再次核对矿井；
- 同类矿输出只有匿名区间和样本数，不向企业泄露其他矿明细；
- 原因回复只形成 `explanation_recorded`，风险结论不会因此被覆盖。

生产部署、Nginx、systemd、密钥轮换、备份和故障验收见
[V2 部署与运行](../docs/V2部署与运行.md)与
[V2 验收清单](../docs/V2验收清单.md)。

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

`test_regulatory_v2_http.py` 会在随机本机端口真实完成报送、唯一算法、报告拉取、送达
确认、企业回复和只读大屏查询，并用中立 Schema 校验三个政府出站消息。

生产命令 `mineguard` 只导入 V2 平台和备份组件，不导入旧 edge、安全、案件或多算法
运行栈，也不再安装第二套 legacy 命令。仓库中的旧源码只可用于受控数据迁移参考，
不能作为新部署入口，也不能把旧 V1 API 当作 V2 主线。
