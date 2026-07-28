# 矿端边缘智能体

这是一个与监管平台、企业填报 Agent **代码独立**的矿端进程，负责：

- 只读采集出煤、用电、人员、瓦斯、火工品、通风六类观测；
- 归一化皮带、人员异常和来源健康等不含个人身份的细化指标；
- 统一 UTC 时间、单位、矿井/位置/来源标识；
- 使用 SQLite 持久化、幂等去重并在断网时排队；
- 在矿端执行甲烷、超员、主通风机和风量四色规则；风机运行、
  故障和倒机状态同时按中立契约上报，供监管端独立复算；
- 使用固定批协议和 raw-body HMAC 向监管接收端安全上报；
- 提供本地健康页、人工有痕补录和运维 API。

它**不读取或导入** `platform/`、`agent/`、`contracts/` 中的任何 Python
代码，也没有风机启停、传感器参数修改、生产控制、源文件删除接口。

## 1. 五分钟启动

Python 3.11 及以上，无运行时第三方依赖：

```bash
cd /home/sevan/coral/edge-agent
python -m venv .venv
. .venv/bin/activate
pip install -e .
mine-edge-agent run-once \
  --adapter jsonl \
  --source examples/six-kinds.jsonl \
  --source-id demo-gateway \
  --no-forward
mine-edge-agent serve
```

浏览器打开 <http://127.0.0.1:8091/>。直接使用源码也可以：

```bash
PYTHONPATH=src python -m mine_edge status
PYTHONPATH=src python -m mine_edge serve
```

命令在前台持续运行不是“卡死”；看到启动信息后应保持终端打开，通过浏览器或
另一个终端访问。按 `Ctrl+C` 会安全退出。

默认数据库为 `./data/mine-edge.sqlite3`，默认矿井为 `demo-mine`。默认阈值仅供
开发联调，页面会持续显示警告。投产前必须配置 `.env.example` 中的身份、认证、
监管地址及经审批的矿井阈值。

## 2. 采集适配器

所有适配器均实现 `ReadOnlyAdapter.poll()`，且声明 `read_only = True`。

### JSONL

每行一个观测对象。重复运行不会重复入库，因为 `source_event_id/event_id +
revision + source_id` 构成稳定身份；没有事件号时使用规范化内容摘要。

```bash
mine-edge-agent run-once --adapter jsonl --source /data/export/readings.jsonl
```

### 文件投递

只读扫描目录顶层的 `*.json` 和 `*.jsonl`。JSON 可以是单个对象或对象数组。
智能体不会删除、重命名或移动源文件：

```bash
mine-edge-agent run-once --adapter file-drop --source /data/drop/inbox
```

### HTTP 轮询

适配器固定执行 `GET`，接受对象、数组或 `{"observations": [...]}`：

```bash
mine-edge-agent run-once \
  --adapter http-poll \
  --source https://gateway.example/read-only/observations \
  --source-token "$SOURCE_READ_TOKEN" \
  --ca-file /etc/ssl/certs/enterprise-ca.pem
```

`--source-token` 只用于源系统的只读 Bearer 认证，不是监管上行密钥。为避免令牌
被重定向到另一地址，HTTP 适配器不自动跟随 3xx；应直接配置最终只读 URL。

### 多源连续采集

`serve` 会读取 `MINE_EDGE_SOURCES_JSON`，为每个来源启动一条独立调度线程。一个
来源超时、格式错误或凭证缺失，只会改变该来源的健康状态，不会阻塞其他来源，
也不会阻塞独立的监管上行线程。

```bash
export MINE_EDGE_SOURCES_JSON='[
  {
    "source_id": "personnel-api",
    "adapter": "http-poll",
    "url": "https://gateway.example/read-only/personnel",
    "interval_seconds": 15,
    "jitter_seconds": 3,
    "timeout_seconds": 5,
    "missing_after_seconds": 90,
    "enabled": true,
    "token_env": "MINE_SOURCE_PERSONNEL_TOKEN"
  },
  {
    "source_id": "gas-drop",
    "adapter": "file-drop",
    "path": "/data/mine-edge/gas-drop",
    "interval_seconds": 10,
    "jitter_seconds": 2,
    "timeout_seconds": 3,
    "missing_after_seconds": 60,
    "methane_adaptive_sampling": {
      "enabled": true,
      "trigger_ratio": 0.8,
      "accelerated_interval_seconds": 2,
      "window_seconds": 300
    },
    "enabled": true
  }
]'
export MINE_SOURCE_PERSONNEL_TOKEN='只读源系统令牌'
mine-edge-agent sources
mine-edge-agent serve
```

- `interval_seconds` 是基础周期，`jitter_seconds` 每周期增加随机延迟，避免所有
  矿井同时请求；
- `timeout_seconds` 超时后立即标记该来源失败且不启动重叠采集；底层阻塞读取
  即使尚未返回，也不会占用其他来源线程；
- `missing_after_seconds` 从最后一条有效数据计算统一“缺数”信号；成功读取空目录
  只算连接心跳，不会把它冒充成新数据；
- `methane_adaptive_sampling` 是只读动态加密采样：默认在最近新入库且质量有效的
  `methane.concentration_percent` 达到蓝色预警阈值的 80%，或本周期生成甲烷
  本地提示时，把该来源切到较短轮询周期。`trigger_ratio` 范围为 0.1–1，
  `accelerated_interval_seconds` 必须短于常规周期，`window_seconds` 最长
  3600 秒；每次新触发只续一个有界窗口；
- 加密窗口内的失败、超时、空返回或低值不会被解释为“恢复正常”，不会提前放慢。
  窗口写入本地 SQLite；重启仅恢复尚未过期的剩余时间，并再次按当前
  `window_seconds` 封顶。此能力只调整适配器下一次只读轮询时间，不调用设备写
  接口，也不改变矿井既有监控系统采样参数；每次触发还会在
  `source_scheduler_events` 中追加原因、归一化值、实际阈值和截止时间，历史
  记录不会被当前状态覆盖；
- `enabled=false` 可预配置为暂停。页面和 API 的启用/暂停只控制采集连接器，
  不控制任何矿井设备；运行中修改不持久化，重启后以环境配置为准；
- `token_env` 只保存环境变量名，状态接口和前端永远不返回令牌值。

运行中查看：

```bash
curl http://127.0.0.1:8091/api/v1/sources
mine-edge-agent source-run-once personnel-api --no-forward
```

`GET /api/v1/sources` 的每个来源会在 `methane_adaptive_sampling` 中返回
`mode`、`effective_interval_seconds`、`accelerated_until`、
`last_trigger_reason`、`trigger_count` 和 `restored_after_restart`；汇总字段
`summary.methane_accelerated` 表示当前处于加密窗口的来源数。状态同时固定声明
`poll_schedule_only=true`、`device_write_capability=false`。

### 通用输入

```json
{
  "event_id": "gas-sensor-1-298193",
  "kind": "methane",
  "metric": "methane_concentration",
  "value": 0.82,
  "unit": "%",
  "location_code": "face-101",
  "observed_at": "2026-07-28T08:00:00+08:00",
  "sequence_no": 298193,
  "revision": 0,
  "source_record_id": "gas-gateway:298193",
  "status_code": "online",
  "interval": {
    "start": "2026-07-28T07:55:00+08:00",
    "end": "2026-07-28T08:00:00+08:00",
    "timezone": "Asia/Shanghai",
    "aggregation": "snapshot",
    "shift_code": "day-A"
  },
  "quality": {
    "valid": true,
    "completeness": 1.0,
    "timeliness": 1.0,
    "device_health": "healthy",
    "clock_synchronized": true,
    "flags": []
  }
}
```

六类 `kind` 是 `coal_output`、`electricity`、`personnel`、`methane`、
`explosives`、`ventilation`；非业务技术遥测另用 `source_health`，只承载
心跳年龄、连续失败次数和缺数状态，且 `location_code` 必须等于
`source_id`。`interval` 可省略；存在时必须提供起止、时区和聚合口径，结束
时间必须晚于开始且不得晚于边缘接收时间。单位换算见
[数据和规则说明](docs/data-and-rules.md)。

## 3. 人工补录

人工数据不能伪装成自动采集，必须同时提供操作者、补录原因和凭证引用：

```bash
curl -X POST http://127.0.0.1:8091/api/v1/ingest/manual \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MINE_EDGE_API_TOKEN" \
  --data '{
    "kind":"personnel",
    "metric":"underground_count",
    "value":182,
    "unit":"人",
    "location_code":"underground",
    "observed_at":"2026-07-28T08:00:00+08:00",
    "provenance":{
      "channel":"manual",
      "source_id":"shift-report",
      "operator_id":"operator-037",
      "reason":"人员定位网关 08:00-08:05 通讯中断",
      "evidence_ref":"shift-report-20260728-A"
    }
  }'
```

记录会保留 `quality=manual`、`acquisition_mode=authenticated_manual_entry`
和完整 provenance；上行时投影为合同规定的 `manual_attestation`。
原自动采集记录不会被覆盖；修订必须使用相同事件号和更高 `revision`。

## 4. HTTP API

| 方法与路径 | 作用 |
|---|---|
| `GET /api/v1/health` | 无密钥健康检查、累计数和队列状态 |
| `GET /api/v1/config` | 脱敏配置、阈值校准状态 |
| `GET /api/v1/observations` | 最近观测，可传 `kind`、`limit` |
| `GET /api/v1/alerts` | 最近本地预警，可传 `level`、`limit` |
| `GET /api/v1/outbox` | 上行队列，可传 `status`、`limit` |
| `GET /api/v1/sources` | 每源心跳、缺数、最近成功和连续失败 |
| `POST /api/v1/ingest` | 受控网关推送，顶层含 `source_id` 和 `observations` |
| `POST /api/v1/ingest/manual` | 有痕人工补录 |
| `POST /api/v1/outbox/flush` | 立即尝试上行 |
| `POST /api/v1/sources/{id}/enable` | 启用该只读采集连接器 |
| `POST /api/v1/sources/{id}/disable` | 暂停该只读采集连接器 |
| `POST /api/v1/sources/{id}/run-now` | 立即调度一次采集 |

除健康检查和静态页面外，设置 `MINE_EDGE_API_TOKEN` 后均要求 Bearer
令牌。`PUT/PATCH/DELETE` 一律拒绝。没有 `/control`、`/fan` 或设备写接口。
监听非本机地址时程序会强制要求 API 令牌，实际部署还应使用 HTTPS 反向代理、
IP 白名单和主机防火墙。

## 5. 断网续传

观测、本地预警和 outbox 在一个 SQLite 事务中落盘。上行发送前为一组记录分配
稳定 `batch_id`；失败后保持同一批号，以 5 秒起步做指数退避，默认上限一小时。
服务模式每五秒检查到期批次。可查看：

```bash
mine-edge-agent status
mine-edge-agent flush --max-batches 20
```

监管接收端返回 HTTP 2xx 后，边缘端还会严格解析
`edge-telemetry-receipt-v1`，逐项核对 `batch_id`、`client_id`、`mine_id`
和原请求体 SHA-256；只有全部一致才算成功。空回执、非合同 JSON、身份或摘要
不匹配的 2xx 均按失败退避重试，在此之前不会确认队列送达。回执最多读取
64 KiB，签名请求拒绝所有 HTTP 重定向，避免认证头被重放到其他地址。
已送达行也会保留作现场审计，不做自动物理删除。详细线协议见
[上行协议](docs/wire-protocol.md)。

`MINE_EDGE_UPSTREAM_URL` 只能填写 origin，例如
`https://regulator.example:8443`，不能带账号密码、base path、query 或
fragment。监管上行必须使用 HTTPS；只有本机联调的 `localhost`、`127.0.0.0/8`
或 `::1` 可使用 HTTP。程序固定追加 `/v1/edge-telemetry-batches`。

新批次使用 `{client_id}--batch_{digest}` 命名，防止不同客户端占用同一个全局
批号；因此 `client_id` 最长 88 个字符。批次首次分配后持久化，断网重试不会
改变批号。升级已有节点时先在旧接收策略下排空旧格式 pending，再启用监管端
强制前缀校验；程序不会擅自给旧在途批次换号，以免已接收请求被重复入账。
过渡兼容仅识别旧版本实际生成的 `batch_{32位小写十六进制}`，不会放宽新批次
或其他任意无前缀批号。

推荐把与平台登记完全相同的 base64 字符串配置为
`MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64`。双方各自解码为原始字节后计算 HMAC；
不要把 base64 文本本身直接当作密钥字节。

## 6. systemd 部署

1. 将源码或 wheel 安装到 `/opt/mine-edge-agent/venv`。
2. 创建不可登录的 `mine-edge` 系统用户和 `/var/lib/mine-edge-agent`。
3. 将 `.env.example` 复制为
   `/etc/mine-edge-agent/mine-edge-agent.env`，权限设为 `0600`。
4. 安装 `deploy/mine-edge-agent.service` 后执行：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mine-edge-agent
sudo systemctl status mine-edge-agent
journalctl -u mine-edge-agent -f
```

unit 采用只读系统目录、私有临时目录、禁止提权，仅允许写
`/var/lib/mine-edge-agent`。备份、恢复和故障排查见
[运维手册](docs/operations.md)。

## 7. 测试

```bash
pip install -e '.[dev]'
pytest
ruff check .
```

MVP 已覆盖六类归一化、细化非 PII 指标、可选统计窗口、来源健康技术观测、
人工来源强约束、幂等/修订、SQLite 原子队列、四色规则、指数退避、客户端
命名空间稳定批号、HMAC 固定向量、严格回执绑定、无重定向传输、只读适配器和
HTTP 接口。多源调度器会自动持久化并上送 `source.*` 健康观测，并支持甲烷异常
触发的有界只读加密轮询。真实矿井投产还必须完成源系统字段映射、标准依据确认、阈值
审批、时间同步、网络/证书联调、容量压测、灾备演练和至少一个完整班次的并行
核验。
