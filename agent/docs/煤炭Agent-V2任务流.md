# Legacy：通用煤炭 Agent V2 耐久任务流与治理说明

> **Legacy 文档。** 当前默认产品是“一矿一智能体”的五量报送 V2，主流程和部署
> 说明见 [README](../README.md) 与 [部署与运维](部署与运维.md)。本文描述的通用
> 任务、调度、记忆和技能治理只为历史迁移保留，不在默认前端和启动配置中使用。

本文对应企业端当前实现的 `enterprise-agent-flow-v2`。它说明“每日煤炭数据
体检”、耐久任务、调度、事件触发、受治理记忆和技能提案的实际能力、接口及安全
边界。本文不是后续规划清单；未在本文明确写为“已实现”的能力，不应视为生产承诺。

历史实现只读取企业端 SQLite 中已经存在的旧式草稿和成功提交历史，不导入监管端
源码或数据库，也不控制矿端设备。当前架构只有企业 Agent 和政府 Platform 两个
产品；固定目录和受控连接器归企业 Agent 管理。

## 1. 能力定位

Agent V2 把一次煤炭核验从“聊天问一句、进程内算一次”提升为可持久化、可恢复、
可取消、可重试和可审计的任务流。当前内置且唯一可执行的 V2 工作流是：

```text
daily_coal_health / 2.0
```

它不依赖大模型和外网。即使未配置 `DEEPSEEK_API_KEY`，仍会使用本地确定性工具
完成核验。模型提取、煤炭对话、新闻搜索和旧版 Harness 任务是相邻能力，不是这个
工作流的执行依赖。

一次完整体检按以下顺序运行：

```text
绑定既有草稿
    │
    ├─ 准备证据快照：草稿摘要 + 确定性预检
    │
    ├─ 来源凭证专家 ─────┐
    ├─ 时序质量专家 ─────┤  四个专家并行、彼此独立记录步骤结果
    ├─ 物理平衡专家 ─────┤
    └─ 历史交叉专家 ─────┘
                │
                └─ 确定性反方核验
                         │
                         └─ 负责人摘要与人工复核建议
```

### 1.1 四类专家

| 专家 | 当前使用的主要只读工具 | 回答的问题 |
| --- | --- | --- |
| 来源凭证专家 | `source_evidence_check`、`summarize_provenance_lineage`、`compare_source_consistency` | 来源摘要、载荷摘要、字段血缘和同指标多来源是否需要复核 |
| 时序质量专家 | `align_observation_time`、`inspect_observation_continuity` | 观测是否落在统计窗口，是否延迟、缺测、跳号或发生序列重置 |
| 物理平衡专家 | `calculate_coal_flow_balance` | 产量、主运、库存收发存和煤流去向是否在配置容差内闭合 |
| 历史交叉专家 | `explain_cross_validation`、`analyze_historical_trend` | 当前值与同矿已成功提交历史、物理和来源证据是否一致，证据是否充分 |

准备阶段按煤炭监管价值优先选择最多 64 个指标，产量、主运、库存、购销、洗选和
煤质优先于普通辅助指标，而不是按指标编码字典序截断。来源凭证总检覆盖全部观测，
多来源明细比较最多处理优先级最高的 12 个指标；历史交叉验证按每批 8 个指标覆盖
本次所选范围，历史趋势明细最多 12 个。负责人摘要会明确展示
`analyzed / total / omitted`、选择策略和未覆盖清单摘要；没有全覆盖时关注级别至少
为“中”，证据置信范围标为 `limited`，不能显示成“全部正常”。工具结果会被有界
持久化，超长数组保留计数和摘要，而不是无限写入数据库。

### 1.2 反方核验与负责人摘要

四个专家完成后，系统不会让同一模型自由总结自己的结论，而是由本地确定性反方
核验器重新检查：

- 预检阻断项；
- 来源载荷摘要缺失或不匹配；
- 煤流平衡超容差；
- 时间对齐和连续性问题；
- 历史与交叉验证的阻断、警告或证据不足；
- 专家步骤是否失败、部分完成或缺少评价证据。

反方核验输出 `critical / high / medium / low` 关注级别，再生成领导可先读的标题、
四维摘要和最多 5 项下一步建议。该摘要是业务辅助，不是监管认定、法律意见、原因
归责或提交指令。

来源签名在企业端仍只做格式与载荷摘要一致性检查；真正持密钥的 HMAC 验证由监管
平台完成。统计异常也不能单独证明企业违法或现场事故原因。

### 1.3 自动填报与历史、物理证据

网页已经支持“让 Agent 从材料自动填入”：符合合同的 JSON、CSV 经过确定性导入后
直接写入草稿并记录字段来源；自由文字只生成待人工选择的模型候选。该入口要求用户
主动提供材料，不会后台登录 ERP/MES。

V2 同时提供纯函数 `agent_v2.autofill.build_autofill_proposal(...)`，供受控适配器
或后续只读预览接口统一整理三类证据：

- `raw_observation`：原始材料中的普通业务字段可以成为待复核补丁；观测值必须改走
  带来源凭据的专用导入，不能被普通补丁“洗成”手工值；
- `historical_suggestion`：按样本量、支持率和工况匹配度降权，只能补充空白上下文；
- `physical_inference`：始终标为 `analysis_only`，不能冒充当前原始观测。

提案绑定草稿修订号、文档摘要和历史快照摘要；同字段冲突时不选择值，已有不同值时
不覆盖，模型/OCR 置信度封顶，秘密、签名、确认、提交和状态字段整项丢弃。该函数本身
没有数据库、确认、签名或提交能力。当前网页不会把历史或物理推断自动套用；未来接入
只读预览时，也必须由人员逐字段选择并经过现有受控草稿补丁审批。

## 2. 耐久任务状态与恢复

任务、步骤和事件都先写入企业端 SQLite。页面关闭、浏览器断开不会删除任务。

| 状态 | 含义 | 可执行动作 |
| --- | --- | --- |
| `queued` | 已持久化，等待后台工作线程领取 | 可取消 |
| `running` | 正在准备证据、并行核验或生成摘要 | 可请求取消；取消会在安全检查点生效 |
| `blocked` | 绑定草稿不可用等外部条件使任务无法继续 | 修复条件后重试 |
| `succeeded` | 已形成完整或可用的负责人摘要 | 查看结果；不能原地重跑 |
| `failed` | 执行边界、完整性或全部专家失败 | 排查后重试；完整性失败不得盲目重试 |
| `cancelled` | 执行前取消，或运行中在安全检查点完成取消 | 查看留痕；不能重试 |

当前实现没有 `waiting` 状态。前端若为兼容旧数据显示“等待处理”，不代表 V2
后台会写入该状态。

每个任务有递增 `revision`。取消、重试和定时任务修改可携带
`expected_revision`；若期间已有其他请求更新，服务返回冲突，调用方应刷新后重新
判断，不能覆盖新状态。

### 2.1 幂等与账号隔离

- 手工创建任务可传 `client_request_id`；同一登录账号重复使用相同编号和相同
  参数时返回原任务，不重复执行。
- 相同编号若被复用于不同草稿、目标或工作流，服务拒绝。
- 任务列表、详情、取消和重试都按创建账号隔离；知道别人的任务编号也不能读取。
- 调度执行使用计划编号和计划执行时点构造幂等编号，避免同一到期点重复生成任务。
- 事件使用每个账号内唯一的 `client_event_id`，重放同一事件只返回原记录。

### 2.2 取消与重试

排队任务取消后立即进入 `cancelled`。运行中任务只设置持久化取消标记；系统在准备
证据、专家汇合和生成摘要等安全检查点停止。已经进入某个本地只读工具的短步骤不会
通过强杀线程中断，但其结果不会绕过后续取消检查形成新的完整结论。

只有 `blocked` 和 `failed` 可重试。重试会：

1. 将同一任务重新置为 `queued`；
2. `attempt` 加一；
3. 清空上一尝试的汇总状态和错误；
4. 保留上一尝试的步骤、结果摘要和事件链；
5. 在新尝试中重新读取当前草稿快照并完整复算。

### 2.3 服务重启恢复

`enterprise-agent serve` 启动 V2 时会扫描未完成任务：

- 原 `running` 步骤标为 `failed / flow_interrupted`；
- 若任务已有取消标记，则完成为 `cancelled`；
- 其余原 `running` 任务增加一次尝试并回到 `queued`；
- 原本已排队的任务重新加入有界工作队列；
- 已结束任务不会自动重放。

这里允许自动重算，是因为 V2 工作流只有本地只读工具。这个恢复规则不能照搬到确认、
提交、设备控制或其他有外部副作用的动作。

每个任务和计划都有 SHA-256 追加事件链及同表链头锚点。接口读取任务详情时会校验
完整性。链校验失败时，应停止使用结论、保全数据库副本并调查，不要直接改表或把
状态人工改成成功。该链可以发现意外损坏和不完整改库，但不是外部数字签名，不能
抵御能同时重写整库并重算摘要的主机管理员。

## 3. 定时与事件触发

计划只允许启动白名单中的 `daily_coal_health`，不能把 URL、命令、脚本、模型提示
或任意工具名写成执行目标。

| `schedule_kind` | 计划内容 | 当前限制 |
| --- | --- | --- |
| `daily` | `{"time":"09:00","timezone":"Asia/Shanghai"}` | 时间为 `HH:MM`，时区必须是主机可用的 IANA 时区 |
| `interval` | `{"interval_seconds":3600}` | 300–2592000 秒，即 5 分钟至 30 天 |
| `event` | `{"event_type":"draft_data_arrived"}` | 小写字母开头的受限业务事件名；由事件 API 触发 |

单个账号最多保留 50 个未删除计划，单实例最多 1000 个。删除是软删除：停止后续
触发但保留计划事件链。计划修改使用乐观修订号。

网页“智能体任务中心”当前可直接创建每日和间隔计划。事件计划及事件发送已通过
HTTP API 实现，当前网页没有配置入口。

### 3.1 登录、Cookie 与 CSRF

以下 `curl` 例子只用于已授权的本机或测试环境。先登录，把 Cookie 保存在临时
文件，并从登录响应复制本次会话的 `csrf_token`。不要在文档、工单或聊天中粘贴
真实密码、Cookie 或令牌。

```bash
curl -sS \
  -c /tmp/enterprise-agent.cookies \
  -H 'Content-Type: application/json' \
  --data '{"actor_id":"demo","password":"123123123"}' \
  http://127.0.0.1:8090/api/v1/auth/login

export AGENT_CSRF_TOKEN='粘贴登录响应中的 csrf_token'
```

生产环境应替换为正式 HTTPS origin 和实名账号。所有 `POST`、`PATCH`、`DELETE`
请求都必须同时发送 Cookie 和 `X-CSRF-Token`；GET 只需要 Cookie。下面例子省略
真实凭据，只复用上一步生成的临时 Cookie 文件。

### 3.2 手工发起一次体检

```bash
curl -sS \
  -b /tmp/enterprise-agent.cookies \
  -H "X-CSRF-Token: ${AGENT_CSRF_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{
    "workflow_name":"daily_coal_health",
    "draft_id":"替换为已有草稿编号",
    "goal_text":"检查本期煤流、来源、时序和历史交叉证据",
    "client_request_id":"manual-health-20260730-001"
  }' \
  http://127.0.0.1:8090/api/v1/agent/flows
```

查看本人任务和详情：

```bash
curl -sS \
  -b /tmp/enterprise-agent.cookies \
  'http://127.0.0.1:8090/api/v1/agent/flows?limit=20&offset=0'

curl -sS \
  -b /tmp/enterprise-agent.cookies \
  'http://127.0.0.1:8090/api/v1/agent/flows/替换为任务编号'
```

### 3.3 创建每日或间隔计划

```bash
curl -sS \
  -b /tmp/enterprise-agent.cookies \
  -H "X-CSRF-Token: ${AGENT_CSRF_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{
    "name":"每日九点煤炭体检",
    "workflow_name":"daily_coal_health",
    "draft_id":"替换为已有草稿编号",
    "goal_text":"形成负责人晨会摘要",
    "schedule_kind":"daily",
    "schedule":{"time":"09:00","timezone":"Asia/Shanghai"},
    "enabled":true,
    "client_request_id":"daily-job-001"
  }' \
  http://127.0.0.1:8090/api/v1/agent/jobs
```

间隔计划只需改为：

```json
{
  "schedule_kind": "interval",
  "schedule": {"interval_seconds": 3600}
}
```

计划始终绑定创建时选定的既有草稿。它不会自动把“今天”换成另一份新草稿，也不会
自动改变草稿统计窗口。周期报表应由上游先创建或导入新草稿，再通过受控集成更新或
新建相应计划。

### 3.4 创建事件计划并发送事件

先由有 `write` 权限的账号创建事件计划：

```bash
curl -sS \
  -b /tmp/enterprise-agent.cookies \
  -H "X-CSRF-Token: ${AGENT_CSRF_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{
    "name":"草稿数据到齐后体检",
    "workflow_name":"daily_coal_health",
    "draft_id":"替换为已有草稿编号",
    "schedule_kind":"event",
    "schedule":{"event_type":"draft_data_arrived"},
    "enabled":true,
    "client_request_id":"event-job-001"
  }' \
  http://127.0.0.1:8090/api/v1/agent/jobs
```

再发送同账号、同事件名和同草稿的事件：

```bash
curl -sS \
  -b /tmp/enterprise-agent.cookies \
  -H "X-CSRF-Token: ${AGENT_CSRF_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data '{
    "event_type":"draft_data_arrived",
    "client_event_id":"source-batch-20260730-001",
    "draft_id":"替换为已有草稿编号",
    "payload":{"batch_id":"batch-20260730-001","source_count":5}
  }' \
  http://127.0.0.1:8090/api/v1/agent/events
```

事件载荷必须是 JSON 对象，不超过 16 KiB，不得包含密码、令牌或 API Key。
事件只匹配同一账号创建、已启用、事件名相同且草稿编号相同的计划。返回记录列出
成功创建的任务和失败的计划；一个计划失败不会阻断其他匹配计划。

`client_event_id` 是幂等键，不是任意可重复使用的业务标签。上游重试同一事件时
必须复用；新批次必须使用新编号。

## 4. 任务中心按角色使用

网页顶部“智能体任务中心”面向领导和业务人员提供同一个入口，但实际按钮仍以登录
会话中的权限为准，`role` 文本不会授权。

### 4.1 领导或只读查看人员

具有 `read` 即可：

1. 打开一份草稿；
2. 点击“智能体任务中心”；
3. 点击“立即开始体检”；
4. 先看“需要关注、执行中、今日完成”统计和负责人摘要；
5. 需要追问业务人员时，再展开四个专业步骤和证据冲突；
6. 可取消本人未结束任务，或重试本人 `blocked / failed` 任务。

手工发起 V2 体检也是只读操作，因此不要求 `write`。领导不需要查看每个工具参数，
但应把草稿编号、修订号、关注级别和建议复核项交给经办或确认人员。

### 4.2 填报经办人

具有 `read, write` 时，除手工体检外还可以：

- 创建、修改、启停、立即运行和软删除本人计划；
- 提出业务记忆或技能提案；
- 通过上游受控集成发送业务事件。

任务发现异常后，经办人应回到草稿和原始凭证处理。V2 自身不会写草稿。修改草稿后
应重新发起体检；旧任务绑定的 `draft_revision` 和 `document_sha256` 仍保留，不能
冒充对新版本的检查。

### 4.3 复核确认人与治理人员

`confirm` 只用于企业数据的逐项复核与人工确认，不再隐式授予 Agent 治理权限。
审批或撤销业务记忆需要 `governance_review`；审批或停用技能目录需要
`skill_admin`。可按单位职责由同一实名账号持有，也可分别授予不同人员。

待换密账号和本机 demo 即使配置中出现这些权限，也不能进行正式治理审批。

### 4.4 报送人员

`submit` 不授予任务计划或治理写权限。同时具有 `read, submit`、但没有 `write`
的账号可以查看和手工运行只读体检，但不能创建计划或提案；没有相应
`governance_review / skill_admin` 也不能审批治理提案。

## 5. 受治理记忆与技能提案

当前“学习”是提案审批制，不是模型自动改代码、改提示词或即时自我训练。

### 5.1 业务记忆

记忆支持四种作用域：

- `user`：仅提案人本人可见；
- `draft`：绑定企业端现有草稿；
- `mine`：本企业部署内的矿井作用域；
- `enterprise`：本企业部署内的企业作用域。

当前 HTTP 服务按“一个企业端实例属于一个企业安全域”运行；共享作用域在该实例内
可见，个人作用域仍严格按账号隔离。若未来一个实例承载多个企业，不能直接沿用这个
单租户访问映射，必须由权威租户声明填充企业、矿井和草稿访问范围。

提案必须提供键、JSON 值、理由和来源引用，不允许保存疑似密码、Token 或 API Key。
来源引用是人工声明并做格式与摘要绑定，当前不会反向访问来源系统独立验证真伪；
页面/API 会标记 `declared_reference_not_independently_verified`。
批准后生成不可变版本；相同作用域和键的新版本生效时，旧版本变为 `superseded`，
而不是被覆盖。有效记忆可由 `governance_review` 人员撤销。

共享的 `draft / mine / enterprise` 记忆若要批准，必须由另一名具有
`governance_review`
权限的人员完成，提案人不能自批。`user` 私有记忆不强制跨人，但仍需经过
`governance_review` 权限的显式审批动作。生产内控若要求所有记忆都四眼，应把
提出和审批权限配置给不同实名账号。

### 5.2 技能提案

技能提案只能引用当前公开目录中的本地、只读、不联网、无需批准工具。服务会拒绝：

- `draft_patch`；
- 确认、提交、删除、Shell、命令执行、文件写入、浏览器和联网能力；
- 不在只读白名单中的工具；
- 步骤描述中暗含上述危险能力；
- 疑似包含秘密的描述、步骤和来源。

所有技能批准都强制四眼：提案人不能批准自己的技能。批准后生成有版本号的目录记录，
状态虽为 `active`，但 `runtime_activation` 固定为 `approved_inactive`。这表示：

> 已通过目录治理，不代表已装入正在运行的 Harness 或 V2 工作流。

当前版本没有热加载，也没有“审批后立即执行”。要让某个批准技能真正可执行，仍需
单独的代码审查、测试、发布和显式运行时注册；部署负责人不得通过直接改 SQLite
绕过这一步。目录版本可由 `skill_admin` 人员停用。

## 6. HTTP API 与权限矩阵

| API | 方法 | 最低权限 | 说明 |
| --- | --- | --- | --- |
| `/api/v1/agent/workflows` | GET | `read` | 查看已执行白名单 |
| `/api/v1/agent/flows` | GET、POST | `read` | 查看本人任务、发起只读体检 |
| `/api/v1/agent/flows/{id}` | GET | `read` | 查看本人任务步骤和完整性 |
| `/api/v1/agent/flows/{id}/cancel` | POST | `read` | 取消本人未结束任务 |
| `/api/v1/agent/flows/{id}/retry` | POST | `read` | 重试本人失败或受阻任务 |
| `/api/v1/agent/jobs` | GET | `read` | 查看本人计划 |
| `/api/v1/agent/jobs` | POST | `write` | 创建计划 |
| `/api/v1/agent/jobs/{id}` | GET | `read` | 查看计划与事件链 |
| `/api/v1/agent/jobs/{id}` | PATCH、DELETE | `write` | 修改或软删除本人计划 |
| `/api/v1/agent/jobs/{id}/run` | POST | `write` | 立即运行计划 |
| `/api/v1/agent/events` | GET | `read` | 查看本人近期触发事件 |
| `/api/v1/agent/events` | POST | `write` | 发送幂等业务事件 |
| `/api/v1/agent/memory/proposals` | GET | `read` | 查看有权访问的记忆提案 |
| `/api/v1/agent/memory/proposals` | POST | `write` | 提出记忆 |
| `/api/v1/agent/memory/proposals/{id}/decision` | POST | `governance_review` | 批准或拒绝 |
| `/api/v1/agent/memories`、`/{id}` | GET | `read` | 查看有权访问的记忆 |
| `/api/v1/agent/memories/{id}` | DELETE | `governance_review` | 撤销有效记忆 |
| `/api/v1/agent/skill-proposals` | GET | `read`；非技能管理员仅本人 | 查看技能提案 |
| `/api/v1/agent/skill-proposals` | POST | `write` | 提出技能 |
| `/api/v1/agent/skill-proposals/{id}/decision` | POST | `skill_admin` | 由另一名技能管理员批准，或拒绝 |
| `/api/v1/agent/skill-versions`、`/{id}` | GET | `read` | 查看技能目录版本 |
| `/api/v1/agent/skill-versions/{id}` | DELETE | `skill_admin` | 停用当前有效版本 |

所有变更接口仍受登录 Cookie、同源检查和 CSRF 保护。请求体中的 `actor_id` 不会
替代登录身份。

## 7. Legacy 环境变量参考（不要用于五量 V2 默认启动）

服务不会自动读取 `.env`。应由 systemd `EnvironmentFile`、容器 Secret 或单位
密钥系统在启动前注入；修改后需要重启。

### 7.1 服务与账号

| 变量 | 默认值/范围 | 说明 |
| --- | --- | --- |
| `ENTERPRISE_AGENT_DB` | `./data/enterprise-agent.db` | 生产必须使用绝对路径 |
| `ENTERPRISE_AGENT_HOST` | `127.0.0.1` | 建议保持回环监听，由 HTTPS 代理接入 |
| `ENTERPRISE_AGENT_PORT` | `8090`，1–65535 | HTTP 监听端口 |
| `ENTERPRISE_AGENT_USERS_JSON` | 未设置 | 逐用户账号 JSON；未配置且仅回环时启用临时 demo |
| `ENTERPRISE_AGENT_ALLOW_ANONYMOUS_LOCAL` | `false` | 仅回环开发调试；非回环启动会失败 |
| `ENTERPRISE_AGENT_SESSION_TTL_SECONDS` | `28800`，300–604800 | 服务端会话有效期 |
| `ENTERPRISE_AGENT_SECURE_COOKIE` | `false` | HTTPS 代理生产环境应设为 `true` |
| `ENTERPRISE_AGENT_PUBLIC_ORIGIN` | 未设置 | 唯一浏览器 HTTP(S) origin，不含路径和查询 |

### 7.2 Agent V2

| 变量 | 默认值/范围 | 说明 |
| --- | --- | --- |
| `AGENT_V2_ENABLED` | `true` | 关闭后所有 V2 路由返回不可用；旧 Harness 仍可单独运行 |
| `AGENT_V2_SCHEDULER_ENABLED` | `true` | 只控制后台到期轮询；手工 V2 任务仍可运行 |
| `AGENT_V2_SCHEDULER_POLL_SECONDS` | `5`，0.25–60 | 到期计划轮询间隔 |
| `AGENT_V2_WORKER_COUNT` | `2`，1–8 | 耐久任务工作线程数 |
| `AGENT_V2_SPECIALIST_WORKER_COUNT` | `4`，1–8 | 四专家并行线程池上限 |
| `AGENT_V2_FLOW_LEASE_SECONDS` | `120`，30–600 | 多实例执行租约；运行中按约三分之一周期续租 |

任务队列容量、单账号活动任务上限和全局活动任务上限当前使用代码内的保守默认值
200、20 和 200，没有环境变量开关。

### 7.3 Legacy V1 监管平台运输

| 变量 | 默认值/范围 | 说明 |
| --- | --- | --- |
| `PLATFORM_BASE_URL` | 未设置 | 监管平台地址；生产应为 HTTPS |
| `PLATFORM_CLIENT_ID` | 未设置 | 监管端登记的企业客户端 |
| `PLATFORM_TRANSPORT_HMAC_SECRET` | 未设置，至少 32 字节 | 企业报送运输密钥，不是来源签名密钥 |
| `PLATFORM_SUBMISSION_PATH` | `/v1/enterprise-submissions` | 提交路径 |
| `PLATFORM_CAPABILITIES_PATH` | `/v1/enterprise-submission-capabilities` | 能力协商路径 |
| `PLATFORM_BEARER_TOKEN` | 未设置 | 仅监管端明确签发第二因子时使用 |
| `PLATFORM_TIMEOUT_SECONDS` | `20`，1–120 | 平台 HTTP 超时 |

只要设置了任一平台核心项，就必须同时设置
`PLATFORM_BASE_URL + PLATFORM_CLIENT_ID + PLATFORM_TRANSPORT_HMAC_SECRET`。
历史通用体检不依赖这些变量。当前五量交换必须改用 `PLATFORM_V2_*` 与
`ENTERPRISE_EXCHANGE_*`，详见主 README；不要把本表复制到默认环境文件。

### 7.4 可选模型

| 变量 | 默认值/范围 | 说明 |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | 未设置 | 缺省为规则模式；不得写入仓库或浏览器 |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | OpenAI-compatible API 根地址 |
| `DEEPSEEK_MODEL` | `deepseek-v4-flash` | 管理员批准的模型名 |
| `DEEPSEEK_TIMEOUT_SECONDS` | `20`，1–120 | 模型请求超时 |
| `DEEPSEEK_MAX_RETRIES` | `2`，0–5 | 模型请求重试次数 |

V2 每日体检不调用该模型；这些变量服务于提取、旧 Harness、通识或新闻归纳等相邻
功能。

### 7.5 煤炭新闻检索

| 变量 | 默认值/范围 |
| --- | --- |
| `COAL_NEWS_SEARCH_ENABLED` | `true` |
| `COAL_NEWS_SEARCH_TIMEOUT_SECONDS` | `25`，3–60 |
| `COAL_NEWS_BAIDU_ENABLED` | `true` |
| `COAL_NEWS_BAIDU_TIMEOUT_SECONDS` | `3`，1–10 |
| `COAL_NEWS_DEEPSEEK_WEB_SEARCH_ENABLED` | `true` |
| `COAL_NEWS_DEEPSEEK_TIMEOUT_SECONDS` | `24`，3–60 |
| `COAL_NEWS_BING_FALLBACK_ENABLED` | `false` |
| `COAL_NEWS_SEARCH_CACHE_TTL_SECONDS` | `300`，30–3600 |
| `COAL_NEWS_SEARCH_MAX_RESULTS` | `8`，1–20 |
| `COAL_NEWS_SEARCH_MAX_RESPONSE_BYTES` | `1048576`，65536–2097152 |
| `COAL_NEWS_SEARCH_MAX_CONCURRENCY` | `4`，1–8 |

新闻检索与 V2 体检是两条独立通道。搜索联网失败不会阻止本地 V2 任务，也不能用
离线模型记忆冒充最新新闻。

## 8. SQLite 表、备份与恢复

V2 与草稿使用同一企业端数据库文件，但使用独立表：

| 领域 | 表 |
| --- | --- |
| 耐久任务 | `agent_flows`、`agent_flow_steps`、`agent_flow_events` |
| 计划与事件 | `agent_jobs`、`agent_job_events`、`agent_trigger_events` |
| 记忆治理 | `agent_memory_proposals`、`agent_memories` |
| 技能治理 | `agent_skill_proposals`、`agent_skill_versions` |

备份不能只挑业务表，也不能只在服务运行时复制主 `.db` 文件。SQLite WAL 模式下
可能同时存在 `-wal` 和 `-shm`。当前没有内置在线备份命令，推荐：

1. 在维护窗口停止 `enterprise-agent`；
2. 确认 8090 后端端口已关闭；
3. 备份整个状态目录；
4. 使用加密存储、最小权限和明确留存策略；
5. 启动服务并检查 health；
6. 抽查草稿、回执、任务/计划事件链、治理提案和目录版本完整性。

恢复时应保持原数据库绝对路径、运行账号所有权和目录权限。首次启动会恢复审计可验证
的可派发排队任务和租约过期的只读任务，并修复“已启用但没有下次运行时间”的每日/
间隔计划。未完成业务事件会由调度器按完整性校验、事件租约和进度检查点自动续跑；
同一事件/请求留下且从未派发、从未启动、没有步骤的流，即使先被孤儿回收，也只能
在精确幂等重放时通过审计事件复活。损坏或长期无法恢复的事件父记录最多保留未派发
流 24 小时，避免永久占用账号容量。系统不会补跑服务停机期间每一个定时历史时点；
到期记录按恢复后的调度状态处理。

如果只恢复主库而遗漏 WAL，可能丢失最近任务、计划或审批事件。若恢复后出现审计链
不一致，应停止业务、保全恢复介质和当前副本，不要用 SQL 手工拼接事件。

旧库迁移使用跨进程独占事务。高于当前程序支持版本的数据库会在任何写入前拒绝降级
打开；缺少当前内容摘要、父审批绑定、事件链锚点或流控制摘要的历史行不会因“补列”
变成可信数据，而是逐条失败关闭。治理列表、任务容量和恢复派发会跳过隔离行；指定
编号的读取/修改仍拒绝，以便保留取证证据。同键业务内容应通过新提案重建，或使用经
审批的离线迁移程序，不得直接 SQL 填空哈希或改成成功状态。Schema v4 还为升级表
安装写入守卫，使布尔状态、修订号、治理状态、父提案绑定和版本唯一性等后续写入与
新建库采用一致的失败关闭规则；迁移前已有的不可信行仍保留隔离，不会被洗白。

## 9. 自动获取数据的当前归属

当前架构不再把 `edge-agent` 作为第三产品。人工上传、固定目录监听、设备/API 直采
和以后经批准的连接器都在每矿独立的企业 Agent 内实现；它们只生成待人工复核月报，
不能自动确认或绕过 outbox。

已实现的固定目录具备后缀白名单、稳定等待、no-follow 读取、内容去重和 Agent 状态
目录隔离。尚未实现任意 HTTP GET；若增加厂商接口，必须采用逐来源固定 allowlist、
HTTPS/CA、禁止重定向、独立凭据、超时、响应上限、内容类型、健康状态和隔离队列，
不得把浏览器 Cookie、CSRF 或任意 URL 固化到采集脚本。

## 10. 故障排查

### 10.1 health 显示 V2 不可用

检查：

```bash
curl -fsS http://127.0.0.1:8090/api/v1/health
sudo journalctl -u enterprise-agent -n 200 --no-pager
```

- `agent_v2_available=false`：检查 `AGENT_V2_ENABLED`，修改后重启；
- `agent_v2_scheduler_enabled=false`：手工任务仍可运行，但每日/间隔到期不会自动
  轮询；检查 `AGENT_V2_SCHEDULER_ENABLED`；
- V2 路由返回 `503 agent_v2_unavailable`：确认访问的是已重启的新进程，而不是
  同端口旧实例。

### 10.2 任务长期排队或运行失败

- 检查数据库路径是否正确、磁盘是否已满、运行账号是否可写状态目录；
- 检查 `AGENT_V2_WORKER_COUNT` 是否为 1–8；
- 查看任务详情中的 `current_step`、`error_code` 和步骤结果；
- `draft_unavailable`：绑定草稿已删除或不可读，恢复草稿条件后再重试；
- `all_specialists_failed`：检查草稿结构和本地工具测试；
- `flow_integrity_failed`：不要重试或改库，先保全并调查；
- 服务重启后，旧运行实例停止续租；到租约到期才形成新 `attempt`，避免两台进程
  同时写同一任务。这是预期恢复行为。
- 内置工具有 30 秒以内的工作流硬截止，并使用最多 64 个有界守护隔离线程；即使
  缺陷只读工具永久阻塞，也不会阻止 Python 进程退出。Python 仍不能在进程内安全
  强杀任意第三方代码，因此未来接入数据库驱动或厂商 SDK 时，适配器本身必须同时
  配置连接/读取超时、响应上限和可取消 I/O，不能只依赖外层截止。

### 10.3 计划没有执行

- 确认计划 `enabled=true`、`deleted_at` 为空；
- 每日计划使用 `Asia/Shanghai` 等主机可用 IANA 时区；精简容器需安装 `tzdata`；
- 间隔不得小于 300 秒；
- 检查 `next_run_at`、`last_run_at`、`last_error` 和计划事件链；
- 调度关闭时，“立即运行”仍可由 `write` 账号手工触发，但到期轮询不会运行；
- 计划绑定固定草稿，不会自动选择最新草稿。

### 10.4 事件收到但没有触发任务

核对事件与计划是否：

- 属于同一登录账号；
- `event_type` 完全相同；
- 计划已启用且未软删除；
- 事件 `draft_id` 与计划绑定草稿相同；
- `client_event_id` 没有被错误复用于另一批数据。

查看 `GET /api/v1/agent/events` 返回的 `triggered`，再查看计划
`last_error`。一个事件成功接收不保证一定存在匹配计划。

### 10.5 返回 403 或 409

- `403 csrf_token_invalid`：重新登录或调用 `/api/v1/auth/me` 取得当前会话令牌，
  并同时发送对应 Cookie；
- `403 permission_denied`：核对实际 `permissions`，不要依据 `role` 猜测；
- `409` 修订冲突：GET 最新对象，人工确认状态后使用新 `expected_revision`；
- 记忆四眼审批冲突：换另一名有 `governance_review` 的实名账号；
- 技能四眼审批冲突：换另一名有 `skill_admin` 的实名账号，不要共享提案人账号。

### 10.6 技能批准后仍不能运行

这是设计行为。检查返回的
`runtime_activation=approved_inactive`。当前批准动作只发布可审计目录版本，
不会热加载。需要经过代码审查、测试和部署后，由未来显式运行时注册机制加载。

## 11. 不可突破的安全边界

Agent V2 当前明确保证：

- 只读取企业端既有草稿和本地合法提交历史；
- 不自动修改或补全草稿；
- 不替企业人员逐项核对；
- 不执行企业人工确认；
- 不签发来源凭证或运输签名；
- 不向监管平台提交；
- 不控制矿端、传感器、PLC、DCS 或其他设备；
- 不执行 Shell、浏览器、任意网络请求或用户提供代码；
- 不把治理提案自动变成正在运行的技能；
- 不把异常分数直接当作违法、事故原因或监管结论。

任何未来新增抓数、写草稿、外部系统动作或运行时技能，都必须另行设计最小权限、
幂等、审批、审计、租户隔离和失败恢复，不能借用当前只读重放机制绕过门禁。
