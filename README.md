# M87 网络工具

浏览器内的网络诊断与资源提取工具。前端为原生 HTML/CSS/JS，无构建步骤、无外部 CDN 依赖，
全部资源同源加载；解析与提取在浏览器本地完成，服务器侧不接触目标报文。

## 在线使用

```
https://awreffyt.github.io/-m87-net-tools/
```

根目录为跳转页，正式入口在 `/web/index.html`。手机与桌面同源，可添加到主屏使用。

## 功能

| 视图 | 能力 |
|---|---|
| 站点探测 | HTTP 状态、重定向链、响应头、TLS、页面元信息 |
| 资源提取 | 图片、视频、音频、链接、脚本、样式、字体、iframe；支持 SPA 内联路径、懒加载属性、`srcset`、内联 `style` 背景图、`og:image`；支持同域内链递归与 CSS/JS 深挖 |
| DNS 查询 | A / AAAA / MX / TXT / NS / CNAME |
| 抓包分析 | 会话管理、协议统计、链路分析、TCP 载荷还原 |
| 密码破解 | 挑战页参数识别与本地求解 |

资源提取支持一键打包 ZIP、导出 CSV / JSON。遇到带 cookie 挑战的站点会进入云端排队，
后台求解完成后前端自动回填结果，无需手动重试。

## 目录结构

```
index.html               根跳转页
web/
  index.html             正式入口
  styles.css             全站样式
  site.config.js         站点名与版本配置
  queue.txt              云端排队信箱地址（由工作流自动维护）
  snapshots/             提取结果快照缓存
  proxy.php              PHP 单文件版代理入口
  js/
    m87.bundle.obf.js    主程序包（产物）
    common.obf.js        公共层
    probe.obf.js         站点探测
    extract.obf.js       资源提取
    dns.obf.js           DNS 查询
    capture.obf.js       抓包分析
    cipher.obf.js        本地求解
    local.obf.js         本地模式路由
    app.obf.js           外壳与路由
    assist.js            行为增强（自动跟进云端结果）
tools/
  snapshot.py            后台抓取与求解
.github/workflows/
  snapshot.yml           定时任务：收割请求、求解、落快照
```

`.obf.js` 为构建产物，源码不入本仓库。

## 后台任务

`snapshot.yml` 每 15 分钟运行一次：读取排队信箱中的待处理地址 → 抓取 → 识别 → 求解 →
结果写入 `web/snapshots/` → 提交回仓库。前端读取同源快照，命中即秒出。

任务运行在本仓库的 Actions 上，无独立服务器、无外部托管平台。

## PHP 单文件版

`web/proxy.php` 可单独部署到任意支持 PHP 的站点，供无法访问主站的场景使用。

## 说明

- 网页版不要求注册，不收集用户数据，不上传目标页面以外的内容。
- 仅用于诊断自有站点、检查自身项目的资源可达性与安全配置。
- 请勿用于未获授权的站点。
