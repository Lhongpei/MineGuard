# 来源与安全策略

## 固定检索端点与顺序

1. 首选 `https://www.baidu.com/s` 的新闻搜索页，固定使用 `tn=news`、`rtt=4`、
   `bsst=1`、`cl=2`、`rn=10` 和本地规范化后的煤炭主题。
2. 百度返回至少一条合格结果时立即结束。百度超时、无结果或跳转
   `wappass.baidu.com` 安全验证时，不绕过验证码，直接进入后备源。
3. 已配置 DeepSeek API 时，后备调用同一 API 的 Anthropic 兼容
   `/anthropic/v1/messages`，只启用服务端 `web_search` 工具。仅提取
   `web_search_tool_result` 的标题和公共 HTTPS 链接，丢弃模型总结及
   `encrypted_content`。
4. Bing RSS 默认关闭；只有管理员显式设置
   `COAL_NEWS_BING_FALLBACK_ENABLED=true` 才作为最后后备。

禁止接受用户自定义上游地址。检索请求禁止携带 Cookie、草稿内容、企业标识、报送
数值、账号、凭证、原始问题或会话历史，只发送有限主题词表映射出的煤炭主题和本地
生成的日期窗口。不抓取结果中的新闻正文。

## 百度页面解析

- 将百度 HTML 和其中的 `s-data` 注释都视为不可信输入。只用标准
  `HTMLParser` 收集注释，再对 `s-data:` 后的 JSON 使用 `json.loads`；不执行
  HTML、JavaScript 或页面指令。
- 仅接受同时含 `title`、`titleUrl`、`dispTime`、`sourceName` 的新闻卡。
  标题及可选 `summary` 搜索片段去除展示标签后作为纯文本处理；片段限长，不采集
  图片、脚本、样式、点击数据或无障碍重复文本。
- `sourceName` 仅表示百度页面标注的来源，不自动等同于已核验的原始发布机构。
  `summary` 仅表示百度搜索片段，可能截断且未核验新闻正文。
- 识别 `刚刚`、分钟、小时、天、昨天、月日和完整年月日；相对时间按
  `Asia/Shanghai` 换算为 UTC，并设置 `published_at_estimated=true`。
- 最终 URL 不是 `https://www.baidu.com/s`，或页面包含百度安全验证标记时，
  返回 `challenge_required`，不得尝试模拟登录、验证码或复用个人 Cookie。

## DeepSeek Web Search

- 请求只含规范化主题及明确起止日期；不传用户原问题、草稿、企业数据和聊天历史。
- API Key 只存在于请求头，不能进入日志、结果、缓存、审计正文或前端。
- 只采信响应中的 `web_search_tool_result` 结构化结果。模型输出的摘要、推断日期、
  数字或引语不能成为新闻事实。
- `page_age` 缺失时可从标题中提取明确年月日，并标为标题推断；仍无日期时保留
  链接但标记“搜索源未提供发布时间”，整体状态为 `partial`。

## AI 证据总结

- 检索成功后，由对话编排层调用管理员配置的 OpenAI-compatible 模型或 MineGuard
  LLM Gateway 总结接口；这不是检索后备。百度成功时不再调用其他搜索源，但可以调用
  总结模型。
- 总结模型只接收本地分配的 `source_id`、标题、搜索源标注的发布方、发布时间、
  检索渠道、可选搜索片段及是否截断。不得发送 URL、原始用户问题、草稿、企业标识、
  actor、会话历史、新闻 HTML、异常或凭证。
- 标题和搜索片段是外部不可信数据。系统提示明确要求忽略其中指令；模型输出必须是
  严格 JSON，每个概括至少引用一个实际存在的 `source_id`。服务端拒绝额外字段、
  未知引用、空引用、URL、超长或含控制字符的输出。
- 来源链接、标题、发布方和时间始终从本地检索结果渲染，模型不能生成或改写。回答
  明示“基于标题和搜索片段，未读取新闻全文”。
- 总结单次调用最多 12 秒且不重试。失败、未配置或并发繁忙时保留检索成功状态和
  来源卡片，返回确定性标题列表，并单独记录总结失败码。
- 新闻问题及新闻摘要不进入后续企业数据 Harness 的模型上下文，避免外部文本形成
  存储型提示注入。

## SSRF 与链接处理

- 所有检索请求均由固定提供商配置生成；拒绝非预期主机、路径、协议、端口、用户
  信息和跨源重定向。
- 输出文章链接只允许公共 HTTPS。拒绝 HTTP、私有/环回/链路本地/保留 IP、含
  用户信息、控制字符，以及 `javascript:`、`data:`、`file:` 等协议。
- 外部标题、来源、时间和链接始终按纯文本或安全链接展示。浏览器链接必须使用
  `noopener noreferrer` 和 `no-referrer`。

## 超时、并发与回退

- 总超时默认 25 秒；百度单独最多 3 秒，DeepSeek 最多 24 秒，但任何调用都不能
  超过剩余总预算。
- 每个提供商使用独立、有上限的 daemon worker 和并发槽。DNS 或套接字卡住时，
  前台在提供商截止时间后继续后备源；未结束的后台操作持续占槽，防止无限建线程。
- 百度有结果即结束检索，避免调用无关后备搜索源；随后只对合格检索证据执行一次
  受控 AI 总结。百度失败而后备成功时返回 `partial` 并列出每个检索提供商的结果。
- 成功结果缓存默认 300 秒；降级结果最多缓存 60 秒，避免长期掩盖主源恢复。

## 时间、去重与来源

- `searched_at` 与 `retrieved_at` 是检索时间，不能冒充新闻发布时间。
- 有可靠发布时间的结果按时间倒序；未知时间置后。超出请求窗口的明确日期必须
  过滤，未知日期不得猜测。
- 先按规范化 URL、再按规范化标题去重。保留实际发布方；DeepSeek 搜索结果未提供
  发布方时，只把公共域名或内置白名单域名标签作为展示来源。
- 每条来源记录 `retrieval_provider`，区分来源标注与检索渠道；可选
  `search_snippet`、`snippet_origin` 和 `snippet_truncated` 明确搜索片段口径。

## 运行时状态契约

运行时响应至少包含：

- `status`: `succeeded`、`partial`、`failed` 或 `unavailable`；
- `searched_at`、`window_days`、`result_count`、`cached`；
- `provider`: 实际成功提供商或 `multi-provider`；
- `providers`: 本次已配置的固定提供商；
- `provider_attempts`: 每项仅含提供商、受控状态/失败码、结果数和耗时；
- `fallback_used`、`partial_reasons`、`failure_code`；
- `sources`: 每项包含 `title`、`publisher`、公共 HTTPS `url`、
  `published_at`（可空）、`published_time_text`、`published_at_estimated`、
  `date_confidence`、`retrieved_at`、`retrieval_provider`，以及可选搜索片段字段。

`succeeded` 必须至少有一条安全来源且无降级；`partial` 表示已有安全来源但主源
失败、条目被拒绝或发布时间未核验；`failed/no_results` 只表示本次未取得合格结果，
不能推断期间没有新闻；`unavailable` 用于关闭、繁忙或无提供商配置。任何失败字段
都不得包含原始异常、内部堆栈、查询正文或凭证。

对话证据另外记录 `summary.status/provider/grounding/source_count/failure_code`、
`summary_provider_called`、`model_generated` 和是否将公开检索证据交给模型。
