# 煤矿数据监管平台与企业填报智能体

本仓库包含两套职责相对对立、可分别部署的系统，以及一套中立接口规范：

```text
企业侧 agent/  ── HTTPS + JSON + HMAC ──>  监管侧 platform/
       │                                      │
       └──── 各自实现 contracts/ 的规范 ──────┘
```

- `platform/`：监管平台，独立登记矿井、分析配置和可信来源，执行物理交叉验证、
  历史/时序证据分析、人工复核和监管审计。
- `agent/`：企业填报智能体，独立完成材料导入、缺项追问、来源追溯、煤炭确定性
  体检、受控工具规划、只读煤炭业务对话、企业人工确认和报送；不作“正常”、
  “合法”或“合规”认定。
- `contracts/`：版本化 HTTP/JSON Schema、OpenAPI、签名规范和互操作样例。它是
  双方唯一共享的边界规范，不是运行时依赖包。

`platform` 与 `agent` 不互相 import 源码，不共享 Python 模型、数据库、文件目录
或内部密钥。双方只通过契约规定的网络接口交互；任一方都可在保持契约兼容的前提下
独立升级、替换或停机。

## 本地快速启动

需要 Python 3.11+。先启动监管平台：

```bash
cd platform
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -c constraints.txt -e .
export MINEGUARD_ADMIN_PASSWORD='123123123'
export MINEGUARD_EXTERNAL_CLIENTS_JSON='[{"client_id":"enterprise-client-001","enterprise_id":"ENT-001","mine_ids":["M001"],"secrets":["DEMO_ONLY_change_transport_secret_32_chars"]}]'
mineguard serve --host 127.0.0.1 --port 8080 --state-directory .mineguard
```

在另一个终端启动企业智能体：

```bash
cd agent
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
export PLATFORM_BASE_URL='http://127.0.0.1:8080'
export PLATFORM_CLIENT_ID='enterprise-client-001'
export PLATFORM_TRANSPORT_HMAC_SECRET='DEMO_ONLY_change_transport_secret_32_chars'
enterprise-agent serve --host 127.0.0.1 --port 8090
```

两条 `serve` 命令都是常驻前台服务，成功后终端不会返回 shell 提示符。请保持
它们运行，在另一个终端分别请求 `/ready` 和 `/api/v1/health`。如果是在远程
服务器启动企业端，请从自己的电脑建立
`ssh -N -L 8090:127.0.0.1:8090 用户名@服务器` 隧道，再访问本机地址；不要把
远程服务器的 `127.0.0.1` 当作浏览器电脑的地址。

打开监管平台 <http://127.0.0.1:8080/> 和企业智能体
<http://127.0.0.1:8090/>。监管端演示账号为 `admin / 123123123`；企业端未配置
用户时会提供仅限回环地址的 `demo / 123123123` 临时账号。临时账号只能体验
查看和编辑，不能代表企业确认或提交。新状态目录仅在首次初始化时读取监管端
密码，既有账号不会被覆盖。正式使用必须配置企业逐用户账号、随机长口令、TLS
和密钥管理服务。

实际报送前，必须先在监管端注册智能体草稿引用的同一
`profile_id + version`、全部 `source_id`、确认人和精确统计窗口的事件查询
快照。来源 HMAC 密钥只存在于设备/采集网关与监管端；智能体只导入网关预签名的
`payload_sha256 + signature`，不能持密钥给人工数据补签。完整配置和故障排查见
[本地双系统运行](docs/本地双系统运行.md)；企业端长期常驻、systemd、安全环境
文件及备份恢复见[企业端部署与运维](agent/docs/部署与运维.md)。

企业端还必须单独导入与草稿矿井/窗口精确一致的监管事件查询快照；“查询结果为空”
也需要权威空集及证据摘要。普通生产报告里的 `approved_event_codes: []` 不能替代
监管快照，平台最终仍用自己登记的不可变快照独立比对。

DeepSeek 是可选的候选字段提取和煤炭任务规划能力。未设置 `DEEPSEEK_API_KEY`
时，一键体检会改用固定的本地确定性工具组合；导入、校验、追问、人工确认和提交
也都可工作。任何模型密钥都只能通过企业端环境变量或密钥系统注入，不能写入仓库、
浏览器或报送数据。第三方模型的数据出境范围和纯确定性运行方式见
[企业端说明](agent/README.md#模型配置与数据出境)。

企业领导、经办人、确认人、提交人和管理员的权限边界、标准步骤与交接方法见
[企业端分级账号操作手册](agent/docs/分级账号操作手册.md)。网页登录后也会按
服务端返回的实际权限自动显示“当前账号操作说明”；岗位名称只用于展示，不会扩大权限。

## 验证

三部分可分别测试：

```bash
python3 contracts/scripts/validate_contracts.py
(cd platform && python3 -m pytest)
(cd agent && python3 -m pytest)
```

再运行一次完全黑盒的双进程与运维故障验收。它使用临时数据库、随机本机端口和
一次性演示密钥，分别启动监管平台与企业智能体，只通过 HTTP/JSON/HMAC 完成
profile、五个来源、确认人和事件快照登记，以及企业登录、导入、预检、确认、
提交、回执与批次上下文核验；还会检查端口占用、非安全远程监听、演示账号权限、
显式 HTTPS public origin 的代理边界、逐观测核对、监管配置缺失、错误运输密钥、
重复提交、平台停机恢复、双端重启持久性和子进程清理。脚本不会导入任一系统的
Python 包；同时会通过企业 HTTP API 验收煤炭工具目录、运行轨迹、预算、审计链、
无模型确定性降级、煤炭对话领域拒绝、只读边界、会话完整性和删除，以及确认/提交
能力隔离：

```bash
python3 scripts/verify_two_process.py
```

监管端返回接收回执，只说明契约、签名和接入检查已通过并进入监管处理流程，不代表
数据正常、合法、合规，也不替代后续算法研判和监管人员复核。
