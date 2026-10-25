# M87 网络抓包工具

纯 Python（FastAPI + 标准库）实现的网络诊断工具箱，包含站点探测、资源提取、
DNS 查询和抓包分析四个模块。前端为原生 HTML/CSS/JS，无构建步骤、无外部 CDN 依赖。

## 功能

- **站点探测**：HTTP 状态、重定向链、响应头、TLS、页面元信息
- **资源提取**：解析图片、视频、音频、链接、脚本、样式、字体、iframe
  - 支持内联 `<script>` 内的资源路径（SPA 站点）
  - 支持懒加载属性（`data-src` / `data-bg` / `data-srcset` 等 18 种）
  - 支持 `srcset`、内联 `style` 背景图、`og:image` 等
  - 「顺藤摸瓜」：递归抓取同域内链，并深挖 CSS / JS 里的隐藏资源
  - 一键打包 ZIP、导出 CSV / JSON
- **DNS 查询**：A / AAAA / MX / TXT / NS / CNAME 记录
- **抓包分析**：会话管理、协议统计、链路分析

## 本地运行

```bash
pip install -r requirements.txt
bash run.sh
# 打开 http://localhost:8000
```

## 部署到 Render（免费）

1. 将本仓库推送到 GitHub：

   ```bash
   git init
   git add .
   git commit -m "init: M87 网络抓包工具"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/<仓库名>.git
   git push -u origin main
   ```

2. 打开 <https://dashboard.render.com/register> 注册（可直接用 GitHub 账号登录）。

3. 控制台点 **New +** → **Web Service** → 选择刚推送的仓库。

4. 配置项：

   | 配置项 | 值 |
   |---|---|
   | Language / Runtime | **Docker** |
   | Dockerfile Path | `./Dockerfile` |
   | Plan | **Free** |
   | Region | Singapore（离国内最近） |
   | Health Check Path | `/` |

   仓库里已有 `render.yaml`，Render 一般会自动识别并填好上述内容。

5. 点 **Create Web Service**，等待 2~4 分钟构建完成，拿到形如
   `https://m87-net-tools.onrender.com` 的公网地址即可分享。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8000` | Render 会自动注入，无需手动设置 |
| `ALLOW_PRIVATE_TARGETS` | `0` | 设为 `1` 才允许抓取内网 / 本机地址（仅调试用，公网务必保持 `0`） |

### 免费版的限制

- **休眠**：15 分钟无访问会进入休眠，下次访问冷启动约 30~60 秒。
- **出站网络**：Render 节点在海外，抓国内站点可能较慢或失败；
  抓海外站点比本地开发环境更通畅。
- **磁盘**：免费实例磁盘是临时的，重启后 `data/sessions` 里的抓包会话会清空。

## 项目结构

```
app/
  main.py      FastAPI 入口与路由
  tools.py     站点探测 / 资源提取 / 顺藤摸瓜 / DNS
  capture.py   抓包会话与分析
  pcapfile.py  PCAP 读写
  guard.py     反爬与防护（UA 拦截、频率限制、安全响应头）
  build.py     资源打包（ZIP）
web/
  index.html   单页前端
  js/          各模块脚本
  styles.css   样式
```

## 安全说明

- `guard.py` 会对 `curl` / `python-requests` / 扫描器等 UA 返回 403，
  并对 `/api/tools` 做每分钟 20 次的频率限制。
- 内网 / 本机地址默认禁止访问，避免 SSRF。
- 响应默认附带 CSP、`X-Frame-Options: DENY` 等安全头。
