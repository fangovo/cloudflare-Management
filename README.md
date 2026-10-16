# Cloudflare 第三方管理面板 v2.5

单文件 Cloudflare Module Worker（`_worker.js`）。前端内嵌在同一个文件里，只调用同源 `/api`，
所有 Cloudflare API 请求都由 Worker 后端代理转发，浏览器不直连 `api.cloudflare.com`（无 CORS 问题）。

> 本仓库为**单文件发布**：只有一个 `_worker.js`，不需要额外的 `frontend/` 目录或构建步骤。

## 功能

### Workers
- 列表、部署 / 编辑 / 删除
- workers.dev 子域名开关
- 环境变量（文本 / 密钥 / JSON）与 Secrets 管理
- KV / D1 / R2 绑定
- 账号级自定义域名（绑定 / 解绑 / 列表）
- 兼容性日期与兼容性标志设置
- Cron 定时触发器（查看 / 设置）
- 路由（Route）管理：查看 / 添加 / 删除
- 版本列表与回滚（Versions API，Beta）

### 批量创建 Worker
- 多账号批量部署
- KV 内置模板（`CF_ACCOUNTS_KV`）
- GitHub 仓库链接自动识别并查找 `_worker.js`
- 自动查找或创建 KV / D1 并绑定
- 支持直链 / ZIP / 粘贴代码 / 上传文件多种代码来源
- 执行日志逐条回显

### KV
- 命名空间 CRUD（含 jurisdiction：默认 / EU / US / FedRAMP）
- 键分页 + 前缀搜索
- 单键读取 / 写入 / 删除（支持 TTL / 过期时间戳）
- 批量写入 / 批量删除

### D1
- 数据库创建 / 列表 / 删除
- 参数化查询（`params`）
- Raw 模式
- 导出备份（轮询获取下载链接）

### R2
- 存储桶管理（jurisdiction 支持 EU / US / FedRAMP；存储类型 Standard / InfrequentAccess）
- 对象操作（S3 兼容接口）：列表 / 上传 / 删除 / 生成预签名下载链接
- 一键换取 R2 临时 S3 凭证（免手动创建 R2 API Token）
- r2.dev 公共开发 URL 开关
- 存储桶自定义域名（添加 / 移除）
- R2 数据目录（Iceberg REST catalog，查看 / 启用 / 禁用）
- R2 指标（平均存储 / 已检索数据 / A 类操作 / B 类操作 / 请求分布）

### 域名 / DNS
- Zone 管理（添加 / 列表 / 删除）
- DNS 记录 CRUD、PATCH 部分更新、批量导入
- Zone 访问分析（请求数 / 流量 / 访问量、国家分布、可选时间范围与筛选）
- DNS 列表自动标注被 Worker 绑定的记录（显示所属 Worker 名）
- 注意：2026-06-30 起，DNS 记录不能通过更新接口修改「类型」，需删除重建

### Pages
- 项目管理（创建 / 列表 / 删除）
- 部署记录（列表 / 触发 / 重试 / 回滚 / 删除）
- 直接部署：文件上传 / ZIP / GitHub 导入
- 高级模式：根目录 `_worker.js` 作为 Pages Functions 部署
- 绑定管理：环境变量 / KV / D1（生产 + 预览环境）
- 兼容性日期与兼容性标志
- 自定义域名（Cloudflare 域名自动补 CNAME；外部域名给出配置提示）

### 用量统计
- GraphQL 今日请求（Workers + Pages）
- 按 Worker 排行（请求数 / 错误数）
- 24 小时时间序列

### 设置与鉴权
- workers.dev 子域名设置
- 鉴权方式查看与 Token 权限自检

### OAuth 登录（推荐）
点「使用 Cloudflare 账号登录」，走官方 OAuth 2.0 + PKCE（S256）授权，
不用创建 / 粘贴 API Token；access token 过期前自动用 refresh token 续期；多账号切换互不干扰。

> 想自己创建并公开一个 OAuth 客户端：见 **[OAuth 客户端配置教程](OAUTH.md)**（从零创建 → 域名验证 → 设为公开 → 接入面板）。

## 功能截图

![Workers 管理](screenshots/workers.png)

![批量创建 Worker](screenshots/batch-create.png)

![Workers KV 管理](screenshots/workers-kv.png)

![D1 数据库管理](screenshots/d1.png)

![域名管理](screenshots/domains.png)

![Pages 管理](screenshots/pages.png)

![Pages 部署记录](screenshots/pages-deployments.png)

![OAuth 账号切换](screenshots/oauth-accounts.png)

## 部署教程

### 方式一：wrangler 命令行（推荐）

**1. 准备环境**

- 安装 Node.js（LTS 版，官网 https://nodejs.org）
- 安装 wrangler：`npm install -g wrangler`

**2. 登录 Cloudflare**

```bash
wrangler login
```

会打开浏览器授权，点允许即可。

**3. 设置面板访问密码**

```bash
wrangler secret put ACCESS_PASSWORD
```

按提示输入面板登录密码（变量名已固定，不用改文件）。密码忘了就重复这一步，会直接覆盖。

**4. 部署**

```bash
wrangler deploy
```

成功后会输出地址，类似 `https://cf-manager-v2.xxx.workers.dev`，打开输入密码即可使用。

`wrangler.toml` 参考：

```toml
name = "cf-manager-v2"
main = "_worker.js"
compatibility_date = "2026-09-01"
compatibility_flags = ["nodejs_compat"]

# 可选：预置 OAuth Client ID（32 位 hex），免去逐浏览器手动填写
# [vars]
# OAUTH_CLIENT_ID = "<你的 OAuth 客户端 ID>"

# 可选：批量创建 Worker 的内置模板存储
# [[kv_namespaces]]
# binding = "CF_ACCOUNTS_KV"
# id = "<你的 KV namespace id>"
```

**可选：批量部署模板**

想用面板里的「批量创建 Worker」内置模板，需要先创建 KV：

```bash
wrangler kv namespace create CF_ACCOUNTS_KV
```

把返回的 id 填到 `wrangler.toml` 的 `CF_ACCOUNTS_KV` 绑定里，再 `wrangler deploy` 一次。

### 方式二：Cloudflare 官网部署

**1. 创建 Worker**

- 登录 https://dash.cloudflare.com → 左侧「Workers 和 Pages」→「创建」→「创建 Worker」
- 名字填 `cf-manager-v2` → 点「部署」

**2. 粘贴代码**

- 进入 Worker 页面 → 右上角「编辑代码」
- 清空编辑器里的示例代码
- 用记事本打开本地的 `_worker.js`，全选复制粘贴进去（文件约 470KB，粘贴时页面可能卡几秒，耐心等）
- 点「保存并部署」

注意：`_worker.js` 已经是打包好的完整文件（前端都嵌在里面），只贴这一个文件即可。

**3. 设置访问密码**

- Worker 页面 →「设置」→「变量和机密」→「添加」
- 类型选「机密」，名称填 `ACCESS_PASSWORD`，值填你的面板密码 → 保存

**4. 设置运行时（与 `wrangler.toml` 对齐）**

- 「设置」→「运行时」
- 兼容性日期填 `2026-09-01`
- 兼容性标志加 `nodejs_compat`

**5. 访问**

地址是 `https://cf-manager-v2.你的子域.workers.dev`，输入密码登录。

> 提醒：官网方式每次更新都要重新粘贴一遍，适合偶尔改一次；经常改的话还是 wrangler 一行命令更省事。

### 日常更新

- 本仓库为单文件发布，**直接修改 `_worker.js`** 即可，无需构建步骤。
- 想换 Worker 名字就改 `wrangler.toml` 第一行的 `name`。

## 鉴权方式

- **OAuth 2.0 登录（推荐）**：登录页点橙色的「使用 Cloudflare 账号登录」，
  跳转 Cloudflare 官方授权页点允许即可，不用创建 API Token、不用复制粘贴密钥
- **API Token**：Bearer 鉴权，按最小权限配置
- **Global API Key（旧版兼容）**：拥有账号全部权限，请妥善保管

OAuth 说明：标准 Authorization Code + PKCE（S256）流程；access token 过期前 2 分钟
自动用 refresh token 续期；OAuth 应用为公开应用，任何 Cloudflare 账号都能授权登录；
账号列表显示 Cloudflare 账号邮箱，多账号切换互不干扰。

OAuth Client ID 通过部署环境变量 `OAUTH_CLIENT_ID` 预置（32 位 hex，属公开标识），
配置后所有浏览器无需再手动填写。

凭据保存在浏览器 localStorage，每次请求发送给同源 Worker 后端，
不直接发往 `api.cloudflare.com`。

## 安全提示

- **务必设置 `ACCESS_PASSWORD`**。未设置时面板 `/api` 无任何鉴权，任何人都能访问，
  且其中「直链拉取脚本 / 一键部署」等接口会代为请求外部 URL。
- 建议再叠加一层 Cloudflare Access（Zero Trust）限制来源，避免面板直接暴露在公网。
- 凭据存于浏览器本地，请勿在不可信的设备上登录。

## 已知限制

- Versions API 为 Beta 接口，权限不足时会优雅降级提示
- R2 对象级操作需 S3 兼容凭证：可在面板内一键换取临时凭证，或手动填写 R2 API Token 的 Access Key / Secret
- Secrets 为逐条调用官方接口（非 bulk 批量接口），且需要 Token 具备对应权限
- 分析 / 用量类接口需要 Token（或 OAuth 账号）具备 Analytics 相关权限
- 2026-06-30 起 DNS 记录不能通过更新接口修改类型，需删除重建
- 受接口与内存限制，脚本、ZIP 与单个对象有大小上限（脚本约 5MB、Pages ZIP 约 100MB 等）

## 反馈

问题反馈 / 交流群：https://t.me/yifang_chat
