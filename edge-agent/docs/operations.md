# 运维、备份与故障排查

## 每日检查

```bash
curl -fsS http://127.0.0.1:8091/api/v1/health
mine-edge-agent status
journalctl -u mine-edge-agent --since today
```

重点查看 `database.ok`、`outbox_pending`、`last_forward_success_at`、
`last_forward_error` 和 `sources_summary`。断网时 pending 增长是预期行为，
但磁盘容量必须持续监控。

采集来源的详细状态在 `GET /api/v1/sources` 和本机前端“采集来源”页：

- `last_heartbeat_at`：该来源调度线程最近一次心跳；
- `last_success_at`：最近一次成功完成读取，即使结果为空也会更新；
- `last_data_at`：最近一次取得有效且已入库/去重的数据；
- `consecutive_failures`：连续失败次数，达到 3 次显示“失败”；
- `signal=missing_data`：超过 `missing_after_seconds` 没有有效数据；
- `in_flight=true`：正在读取，或底层读取已超时但仍未返回。
- `methane_adaptive_sampling.mode=accelerated`：最近有效甲烷值达到配置比例，
  或本周期生成了甲烷本地提示，当前仅缩短该来源的只读轮询周期；
- `accelerated_until`、`last_trigger_reason`、`trigger_count`：加密窗口截止时间、
  最近触发原因和累计触发次数；`restored_after_restart=true` 表示本次启动恢复了
  SQLite 中尚未到期且已按当前配置重新封顶的窗口；
- `poll_schedule_only=true`、`device_write_capability=false`：动态采样不具备
  修改传感器、PLC 或矿井设备参数的能力。

每个来源有独立线程和超时边界，监管上行也使用单独线程。某个来源故障不应造成
其他来源或上行停止；排障时应先按 `source_id` 定位，不要整体停服务。
加密窗口内出现失败、超时、空结果或低值时不会提前切回常规周期；持续异常可由
后续新观测续窗，单次窗口始终受 `window_seconds`（最大 3600 秒）约束。
SQLite 表 `source_scheduler_state` 保存可恢复当前窗口，
`source_scheduler_events` 追加保存每次触发的原因、归一化甲烷值、实际阈值和
截止时间，便于现场审计；不要直接手工修改这些表。
HTTP 来源返回 3xx 时不会自动跟随，以免只读令牌被带到另一地址；应把配置改为
最终 HTTPS URL。

## 安全备份

SQLite 使用 WAL。不要在服务运行时只复制主数据库文件。优先使用 SQLite 在线
备份命令：

```bash
sqlite3 /var/lib/mine-edge-agent/mine-edge.sqlite3 \
  ".backup '/var/backups/mine-edge-$(date +%F).sqlite3'"
```

备份目录应加密、限制访问并按主管部门保存期限管理。每月至少执行一次隔离环境
恢复演练：

```bash
MINE_EDGE_DB=/tmp/restore-check.sqlite3 mine-edge-agent status
```

指定恢复库前应复制备份到该路径，不应覆盖仍在使用的生产库。

## 常见故障

### 服务启动后终端不返回

`serve` 是前台常驻服务，这是正常现象。保持终端运行，从另一终端执行健康检查，
或交给 systemd。按 `Ctrl+C` 停止。

### 待上报持续增长

依次检查：

1. `MINE_EDGE_UPSTREAM_URL` 是否只包含 HTTPS origin（协议、主机、可选端口），
   没有 userinfo、路径、query 或 fragment；
2. DNS、路由、TLS/CA、反向代理是否可达；
3. `MINE_EDGE_CLIENT_ID` 和 HMAC 密钥是否与监管端登记一致；
4. 主机 UTC 时间/NTP 是否正常；
5. 日志中的 HTTP 状态、回执合同、身份/请求体摘要绑定或验签错误。

失败批次会指数退避。修复后运行 `mine-edge-agent flush`，不要直接修改数据库。
HTTP 2xx 但回执为空、超过 64 KiB、字段不合法，或回执中的批号、客户端、矿井、
请求体摘要不匹配，也会保持 pending。服务端 3xx 不会自动跟随；应修正 origin，
不要用重定向迁移监管接收地址。

### 同一源文件重复运行

这是允许的。具有稳定 `event_id` 的同一修订会被判为 duplicate，不会重复预警或
上报。源系统更正时保持事件号，增加 `revision`。

### 暂停、启用或立即检查单个来源

```bash
curl -X POST http://127.0.0.1:8091/api/v1/sources/gas-gateway/disable \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MINE_EDGE_API_TOKEN" \
  --data '{}'

curl -X POST http://127.0.0.1:8091/api/v1/sources/gas-gateway/enable \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MINE_EDGE_API_TOKEN" \
  --data '{}'

curl -X POST http://127.0.0.1:8091/api/v1/sources/gas-gateway/run-now \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $MINE_EDGE_API_TOKEN" \
  --data '{}'
```

这三个操作只改变本进程的只读采集连接器，不控制传感器、风机或其他生产设备，
且启停状态在进程重启后恢复环境配置。永久调整应修改
`MINE_EDGE_SOURCES_JSON` 后按变更流程重启。来源标识包含 `:` 等字符时，调用方
应做标准 URL 编码。页面中的心跳、最近成功和累计计数也以本次进程启动为起点；
长期数据完整性应以本地观测库和监管接收记录核对。

### 阈值警告一直显示

只有完成正式审批和回放验证后才设置
`MINE_EDGE_THRESHOLDS_CALIBRATED=true`。不要仅为隐藏页面提示而设置。

## 容量和保留

MVP 不自动清理观测、预警或已送达队列，确保审计证据不被静默删除。正式试点前
应根据采样频率压测容量，并由数据治理制度确定归档、WORM 留存和经授权的清理
流程。清理不应通过本服务的 HTTP API 暴露。

## 变更和密钥

- 环境文件权限 `0600`，不把密钥写入源码、日志、前端或备份说明；
- HMAC 密钥轮换需监管接收端提供双密钥过渡窗口；
- API 令牌用于矿内本机接口，HMAC 密钥只用于监管上行，两者不能复用；
- 变更矿井编码、客户端编码、时区、阈值前先备份并记录审批单；
- 源系统适配器使用只读账号和最小网络权限。
