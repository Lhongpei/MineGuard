# 十量 V3 正式软件使用手册

本目录包含两本与当前十量 V3 主线对应的手册源文件和 PDF：

- `企业端软件使用手册.tex`：一矿一 Agent、CSV/连接器建待复核稿、11 原子字段、
  单位失败关闭、四眼复核、可靠报送、唯一更正链和风险回复；
- `领导监管端软件使用手册.tex`：政府只读驾驶舱、三步快速查看、十量 4/5/1 分组、
  风险/数据不足语义和交换留痕；
- `manual-style.tex`：两本手册共用的版式。

五量 V2 仅作历史只读复核和审计，不是新报送或新部署入口。字段、接口和生产门槛还应
结合 [十量 V3 部署与运行](../docs/十量V3部署与运行.md)、
[企业分级账号操作手册](../agent/docs/分级账号操作手册.md)和
[政府平台 README](../platform/README.md)核对。

重新生成：

```bash
cd /home/sevan/coral/manuals
xelatex -interaction=nonstopmode -halt-on-error 企业端软件使用手册.tex
xelatex -interaction=nonstopmode -halt-on-error 企业端软件使用手册.tex
xelatex -interaction=nonstopmode -halt-on-error 领导监管端软件使用手册.tex
xelatex -interaction=nonstopmode -halt-on-error 领导监管端软件使用手册.tex
```

需要运行两遍，以生成正确的目录、交叉引用和总页数。PDF 发布前应核对软件版本、
页面按钮名称、默认演示账号、部署域名和本单位业务制度。
