import "./globals.css";

export const metadata = {
  title: "矿安智察 · 领导端演示",
  description: "煤矿多源数据辅助监管领导端公开演示",
};

export default function RootLayout({ children }) {
  return (
    <html lang="zh-CN">
      <body>{children}</body>
    </html>
  );
}
