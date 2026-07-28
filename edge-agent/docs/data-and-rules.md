# 数据归一化与本地规则

## 时间

- 接受带时区 ISO 8601、Unix 秒或 Unix 毫秒；
- 无时区文本按 `MINE_EDGE_LOCAL_TIMEZONE` 解释；
- 入库及上行统一为 UTC RFC 3339 毫秒格式；
- 现场必须使用 NTP，接收端还应检查未来时间和过旧数据。

## 单位

| 类别 | 接受 | 统一 |
|---|---|---|
| 出煤 | `t`、`kg` | `t` |
| 皮带瞬时产量 | `t/h`、`kg/h` | `t/h` |
| 皮带速度 | `m/s` | `m/s` |
| 皮带秤运行/故障 | 布尔、0/1、有限状态枚举 | `bool`，上行 `count` 0/1 |
| 用电 | `Wh`、`kWh`、`MWh` | `kWh` |
| 井下/区域人员 | `人`、`person`、`count` | `person` 整数 |
| 无卡/人卡不符/超时等事件 | `count`、`次` | `count` 整数 |
| 甲烷 | `%`、`fraction`、`ppm` | `%` |
| 炸药 | `g`、`kg`、`t` | `kg` |
| 雷管 | `count`、`发`、`枚` | `count` 整数 |
| 通风量 | `m3/s`、`m³/s`、`m3/min` | `m3/s` |
| 压力 | `Pa`、`kPa` | `Pa` |
| 风速 | `m/s` | `m/s` |
| 风机状态 | 布尔、运行/停止等有限枚举 | `bool` |
| 来源心跳年龄 | `s`、`ms`、`min` | `s` |
| 来源连续失败 | `count` | `count` 整数 |
| 来源缺数状态 | 布尔、0/1、有限状态枚举 | `bool`，上行 `count` 0/1 |

不认识的单位直接拒绝，禁止猜测。原值和原单位保存在 provenance。
雷管指标与炸药质量指标走不同分支：雷管不接受 `kg`，小数计数也直接拒绝。

## 统计窗口

单条观测可带 `interval`，也可保持旧格式不带窗口。只要出现该对象，
`start`、`end`、`timezone`、`aggregation` 必须齐全：

- `end > start`，且 `end` 不得晚于本条 `received_at`；
- 时间必须带偏移；`timezone` 只接受 `UTC`、数值偏移或系统可识别的 IANA 名称；
- `aggregation` 只能是 `window_total`、`interval_delta`、
  `cumulative_register`、`snapshot`、`instantaneous_rate`；
- 可选 `shift_code` 只能使用最长 64 字符的安全标识，不放人员姓名或其他 PII。

## 四色规则

规则选择已触发的最高等级：

- 甲烷：浓度越高越严重，默认蓝 0.5%、黄 0.8%、橙 1.0%、红 1.5%；
- 超员：人数除以对应位置核定容量，默认蓝 80%、黄 90%、橙 100%、红 110%；
- 风量：实际风量除以位置最低风量，默认蓝 ≤95%、黄 ≤90%、橙 ≤80%、
  红 ≤70%；
- 主通风机报告停止或故障：红色；报告倒机：黄色并要求核对备用机和
  风量恢复。

人员和绝对风量只有在 `personnel_capacity`、`airflow_minimum` 配置了对应
`location_code`、`metric` 或通配符 `*` 时才预警，避免虚构矿井容量。也可直接
采集 `airflow_ratio`。

这些默认值是**软件演示参数，不是法律或现场处置标准**。投产流程应当是：

1. 安全、通风、机电、生产专业共同确认指标口径和适用依据；
2. 为每个位置配置容量/最低风量，复核传感器量程和采样周期；
3. 形成审批记录并通过历史回放测试误报、漏报；
4. 设置 `MINE_EDGE_THRESHOLDS_CALIBRATED=true`；
5. 每次规程、采掘布局或设备变化后重新评审。

本地预警只提供更快的辅助提示，不代替矿井既有安全监控系统、法定报警和人工
处置，不会自动下发控制命令。

连续调度可为每个来源配置 `methane_adaptive_sampling`。默认以蓝色甲烷阈值的
80% 作为提前加密比例；达到比例或生成甲烷本地提示后，只缩短边缘适配器下一次
只读轮询间隔，并在有界窗口后恢复常规周期。失败、空结果和低值不会提前清除
窗口；窗口状态持久化用于安全重启恢复，但不会向传感器或 PLC 写入采样参数。

上行只投影 `edge-telemetry-batch-v1` 白名单指标。主通风机运行、故障和倒机
分别投影为 `ventilation.main_fan_running`、
`ventilation.main_fan_fault`、`ventilation.main_fan_changeover`，使用
`count` 单位和严格的 `0/1` 值；`airflow_ratio` 仍只用于本地提示，不会用
虚构数值塞入其他指标。风量上行会从内部 `m3/s` 精确换算为合同要求的
`m3/min`。皮带秤状态和 `source.missing_state` 同样使用 `count` 0/1；
`source.heartbeat_age_seconds` 使用秒，`source.consecutive_failures` 使用
整数计数。所有 `source.*` 技术指标必须令 `location_code == source_id`，
且不得承载姓名、卡号、身份证号或轨迹明细。
