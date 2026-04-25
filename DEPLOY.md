# 部署指南

## 推荐方案对比

| 平台 | WebSocket | 文件持久化 | 定时任务 | 24h 在线 | 评价 |
|---|---|---|---|---|---|
| **Render.com** | ✅ | ✅（Disk） | ✅ | ✅ | **最推荐**，免费层够用 |
| **Railway** | ✅ | ✅（Volume） | ✅ | ✅ | 体验好，按量付费 |
| **Fly.io** | ✅ | ✅（Volume） | ✅ | ✅ | 免费额度大 |
| **VPS（阿里云/腾讯云）** | ✅ | ✅ | ✅ | ✅ | 完全控制，月付低 |
| **Vercel** | ❌ | ❌（/tmp 不持久） | ❌ | ⚠ 冷启动 | **不推荐**，但能跑 |

---

## 方案 A：Vercel 部署（已配置好）

### 重要限制
- ❌ **不支持 WebSocket 长连接** —— 已自动降级到 SSE（`/admin/events`）
- ❌ **文件系统只读** —— 已切到 `/tmp/cardkey-data`，但**冷启动会丢失数据**
- ❌ **定时任务不工作** —— 自动备份/告警/补货都失效（已自动跳过）
- ⚠ **建议接外部存储**：Vercel KV / Vercel Postgres / Upstash Redis

### 部署步骤
```bash
# 1. 安装 Vercel CLI
npm i -g vercel

# 2. 登录
vercel login

# 3. 在项目根目录部署
vercel --prod
```

或者推到 GitHub，在 vercel.com 关联仓库。

### 数据持久化建议
默认在 Vercel 上数据会随冷启动丢失。要持久化必须：
1. 在 Vercel 控制台启用 Vercel KV 或 Postgres
2. 修改 `loadKeys()/saveKeys()/loadConfig()/saveConfig()` 改读写 KV/数据库
3. 或挂载 Upstash Redis（免费层够用）

未做改造时，每次冷启动数据会从 `data/` 内的 seed 文件恢复（`config.json`、`keys.json`、`logs.json`），但**新增的卡密、修改、日志都会在冷启动后丢失**。

---

## 方案 B：Render.com 部署（推荐）

### 一键 deploy
1. 推到 GitHub
2. 登录 [render.com](https://render.com)，New → Web Service
3. 连接你的仓库
4. 配置：
   - **Build Command**：`npm install`
   - **Start Command**：`node server.js`
   - **Plan**：Free
5. 加 **Persistent Disk**：
   - Mount Path：`/var/data`
   - 大小：1 GB
6. 加环境变量：
   - `DATA_DIR=/var/data`
   - `PORT=3000`（Render 会自动注入，不用设）

WebSocket、定时任务、文件存储全部正常工作。

---

## 方案 C：自建 VPS

```bash
# 1. 装 Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 2. 上传代码
scp -r card-key-system/ user@your-server:/opt/

# 3. 装 PM2 守护进程
ssh user@your-server
cd /opt/card-key-system
npm install
sudo npm i -g pm2
pm2 start server.js --name cardkey
pm2 startup
pm2 save

# 4. 开 nginx 反代（可选，启用 HTTPS）
```

---

## 通用安全建议

- 第一时间在"系统设置"修改默认密码 `admin123`
- 启用应用的"HMAC 签名"
- 在"系统设置"里开启自动补货时设合理的阈值
- 把 `client/` 编译产物（`bin/`、`obj/`）从仓库排除（已在 .gitignore）
