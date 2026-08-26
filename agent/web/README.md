# 企业生产数据智能体前端

默认页面是面向企业经办人和负责人的四步工作区，不要求用户理解 JSON Schema、
HMAC、求解器或任务编排：

1. **数据报送**：固定目录或只读连接器自动发现数据，每批执行确定性检查和 AI 检查；通过后直接进入可靠发送队列，结构变化、歧义或冲突才进入待人工核验。文件导入和手工填表是兜底入口；
2. **待人工核验**：只处理自动检查未通过和人工录入的批次。可核对日报合计并按需展开班次；缺少部分指标是中性覆盖状态，不会单独阻断；
3. **监管风险**：只接收政府判定为实际异常的风险报告。AI 使用已配置模型解释报告并支持连续对话，还可把管理员在对话中明确提供的事实整理成可编辑回执草稿；管理员核实后确认发送；
4. **留痕与设置**：只读显示本实例固定煤矿、经营主体、系统身份、政府连接、cursor
   和 append-only 审计完整性。

缺失值显示为空和“未提供”，页面不会用 0、历史均值或模型猜测填补。批次可以是任意
日期范围、跨自然月、部分日期和部分指标。自动来源检查通过后无需逐批人工确认；人工导入
或待核验批次仍由具备权限的企业账号处理。风险回复必须由企业管理员最终确认。

企业页面不提供字段映射设置。导入器在本地白名单规则范围内自动识别，不能安全识别时
保留待核验，不猜测或自动采用歧义列。默认 CSV 模板是日期加 11 个原子字段的 12 列
日汇总表，不向日常经办人展开四十余列班次宽表。只读账号的导入、扫描和手工填写入口
会直接锁定。

十个业务量是风量、电量、火工品量、入井人员量、产量、开采量、销售量、运输量、
洗煤量和开票量。火工品量因为雷管与炸药单位不同，对应两个原子字段，所以底层共有
11 个原子字段。日常页面统一称为“生产数据”，具体核对项中再显示各业务量名称。
开票主字段只接受非负的正常/蓝字发票实物吨数；红票、退票、作废、折让和退货应在
企业来源系统保留辅助明细并另算净额，不能在日汇总开票量中填写负数。

## 文件

- `index.html`：生产数据报送、待人工核验、监管风险、留痕与设置四页工作区；
- `v2-app.js`：承载生产数据会话、导入、复核、报送、风险对话、回复和留痕；
- `styles.css`：桌面、平板、手机和打印样式；
- `app.js`：Legacy V1 界面逻辑，当前主界面不提供入口。

所有业务文本按纯文本转义后呈现。浏览器会话凭证只在 HttpOnly Cookie，CSRF token
只保存在页面内存，所有修改请求发送 `X-CSRF-Token`。

## 浏览器 API

浏览器端仍访问 `/api/v2/*` 稳定内部路由；这不是企业—政府交换合同版本。新草稿最终
只会形成十量 V3 报文并提交 `/v3/ten-quantity-submissions`，五量 V2 仅可只读展示。

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
POST /api/v2/risks/{id}/response-draft
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
