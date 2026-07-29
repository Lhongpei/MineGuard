# 正式软件使用手册

本目录包含两本与当前软件实现对应的正式手册源文件和 PDF：

- `企业端软件使用手册.tex`：Enterprise Reporting Agent 0.1.0；
- `领导监管端软件使用手册.tex`：MineGuard 0.5.0；
- `manual-style.tex`：两本手册共用的版式。

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
