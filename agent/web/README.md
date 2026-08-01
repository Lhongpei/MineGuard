# 五量企业智能体前端

默认页面是面向企业经办人和负责人的四步工作区，不要求用户理解 JSON Schema、
HMAC、求解器或任务编排：

1. **数据收件箱**：人工上传 ET/XLS/XLSX/CSV/JSON/JSONL，或立即扫描固定目录；
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
