# 五量企业智能体前端

默认页面是面向企业经办人和负责人的四步工作区，不要求用户理解 JSON Schema、
HMAC、求解器或任务编排：

1. **数据收件箱**：以“上传 CSV，自动生成填报草稿”为主入口，可下载中文标准模板；也支持 ET/XLS/XLSX/JSON/JSONL 或立即扫描固定目录；
2. **规范化复核与报送**：逐日展开日报合计和零点、八点、四点班的风量、电量、
   火工品量、入井人员量、产量五类数据；火工品量内分雷管、炸药子项，保存后由正式
   账号人工确认；
3. **风险解读与回复**：查看政府唯一算法的 finding 和证据，用当前报告范围内的工具
   解释，再逐项填写原因、证据索引和措施；
4. **留痕与设置**：只读显示本实例固定煤矿、经营主体、系统身份、政府连接、cursor
   和 append-only 审计完整性。

人工导入和直采的数据均进入同一复核与报送流程。缺失值显示为空和“缺失”，页面
不会用 0、历史均值或模型猜测填补。企业确认和回复确认均要求 `confirm + submit`
权限；演示/待换密账号即使误配权限也会被服务器拒绝。

CSV 上传后的准确流程是“安全预检 → 已批准配置/本地规则/受约束模型给出映射建议 →
人员处理黄色或红色列并确认映射 → 生成待复核草稿 → 逐日复核 → 具名确认后进入发送
队列”。模型只看到表头和整数/日期/文本等类型统计，不接收原始数值；映射下拉也只能
选择固定五量字段和日报/三班次。上传和映射确认都不会调用报送确认或发送接口；只读
账号的文件选择和目录扫描入口会在页面上直接锁定。

## 文件

- `index.html`：V2 四页 shell；Legacy DOM 仅为迁移兼容，父容器固定 hidden；
- `v2-app.js`：V2 会话、导入、复核、报送、风险对话、回复和留痕；
- `styles.css`：桌面、平板、手机和打印样式；
- `app.js`：Legacy V1 界面逻辑，当前主界面不提供入口。

所有业务文本按纯文本转义后呈现。浏览器会话凭证只在 HttpOnly Cookie，CSRF token
只保存在页面内存，所有 V2 修改请求发送 `X-CSRF-Token`。

## V2 API

`v2-app.js` 使用企业后端相对路径：

```text
GET  /api/v2/status
GET/POST /api/v2/imports  # GET 可带 include_discarded=true
POST /api/v2/imports/preview
POST /api/v2/imports/{preview_id}/materialize
POST /api/v2/watch/scan
GET  /api/v2/drafts       # 可带 include_discarded=true
GET/PATCH/DELETE /api/v2/drafts/{id}  # DELETE 仅软放弃未确认稿
POST /api/v2/drafts/{id}/confirm
GET  /api/v2/risks
POST /api/v2/risks/poll
GET/POST /api/v2/risks/{id}/chat
POST /api/v2/risks/{id}/response
GET/PATCH /api/v2/responses/{id}
POST /api/v2/responses/{id}/confirm
GET  /api/v2/audit
```

模型 API Key、平台 HMAC、私有 CA 和原始证据文件永远不进入浏览器。证据表单只发送
编号、标题、媒体类型、大小和 SHA-256；原件保留在企业本地受控位置。

## 本地运行与检查

静态文件应由企业 Agent 同源提供：

```bash
cd /home/sevan/coral/agent
PYTHONPATH=src python -m enterprise_agent serve --host 127.0.0.1 --port 8090
```

只用 `python -m http.server` 查看时 API 不存在，页面会提示登录/服务未连接，不会
伪造数据。自动检查：

```bash
pytest -q tests/test_five_quantity_http_frontend_v2.py tests/test_frontend_static.py
```
