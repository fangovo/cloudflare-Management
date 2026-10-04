# Cloudflare 第三方管理面板 v2

单文件 Cloudflare Module Worker（`_worker.js`），前端只调用同源 `/api`，
所有 Cloudflare API 请求都由 Worker 后端代理转发，浏览器不再直连 `api.cloudflare.com`（无 CORS 问题）。

## 功能

- **Workers**：列表、部署/编辑/删除、workers.dev 开关、环境变量、Secrets 批量更新、
  KV / D1 / R2 绑定、账号级自定义域名、版本列表（Beta）
- **批量创建 Worker**：多账号批量部署、KV 模板、GitHub 链接自动转换、自动创建 KV/D1、执行日志
- **KV**：命名空间 CRUD、键分页/前缀搜索、单键 CRUD、批量写入/删除
- **D1**：数据库 CRUD、参数化查询、Raw 模式、导出备份（轮询）
- **R2**：存储桶管理（jurisdiction 支持 EU/US/FedRAMP；对象级操作需走 S3 兼容接口）
- **域名/DNS**：Zone 管理、记录 CRUD、PATCH 更新、批量导入
  - 注意：2026-06-30 起 DNS 记录不能通过更新接口改类型，需删除重建
- **Pages**：项目管理、部署记录、触发/重试/回滚/删除部署、自定义域名
- **用量统计**：GraphQL 今日请求、按 Worker 排行
- **设置**：workers.dev 子域名、鉴权方式查看、反馈入口

## 部署教程

### 方式一：wrangler 命令行（推荐）

**1. 准备环境**

- 安装 Node.js（LTS 版，官网 https://nodejs.org 下载）
- 安装 wrangler：`npm install -g wrangler`

**2. 解压源码**，进到 `cf-manager-src` 目录。

**3. 登录 Cloudflare**

```bash
wrangler login
```

会打开浏览器授权，点允许就行。

**4. 设置面板访问密码**

```bash
wrangler secret put ACCESS_PASSWORD
```

按提示输入你想要的面板登录密码（`wrangler.toml` 里已经配好了变量名，不用改文件）。
密码忘了就重复这一步，重新设置会直接覆盖。

**5. 部署**

```bash
wrangler deploy
```

成功后会输出一个地址，类似 `https://cf-manager-v2.xxx.workers.dev`，打开输入密码就能用。

**可选：批量部署模板**

如果你想用面板里的「批量创建 Worker」内置模板，先创建 KV 再绑定：

```bash
wrangler kv namespace create CF_ACCOUNTS_KV
```

把返回的 id 填到 `wrangler.toml` 底部注释掉的那段里（去掉 `#`），再 `wrangler deploy` 一次。

### 方式二：Cloudflare 官网部署

**1. 创建 Worker**

- 登录 https://dash.cloudflare.com → 左侧「Workers 和 Pages」→「创建」→「创建 Worker」
- 名字填 `cf-manager-v2` → 点「部署」

**2. 粘贴代码**

- 进到 Worker 页面 → 右上角「编辑代码」
- 把编辑器里的示例代码全删掉
- 用记事本打开本地的 `_worker.js`，全选复制，粘贴进去（文件约 285KB，粘贴时页面可能卡几秒，耐心等）
- 点「保存并部署」

注意：`_worker.js` 已经是打包好的完整文件（前端都嵌在里面了），只贴这一个文件就行，不用管 `frontend/` 目录。

**3. 设置访问密码**

- Worker 页面 →「设置」→「变量和机密」→「添加」
- 类型选「机密」，名称填 `ACCESS_PASSWORD`，值填你的面板密码 → 保存

**4. 设置运行时（跟 wrangler.toml 对齐）**

- 「设置」→「运行时」
- 兼容性日期填 `2026-09-01`
- 兼容性标志加 `nodejs_compat`

**5. 访问**

地址是 `https://cf-manager-v2.你的子域名.workers.dev`，输入密码登录。

> 提醒：官网方式每次更新都要重新粘贴一遍，适合偶尔改一次；经常改的话还是 wrangler 一行命令更省事。

### 日常更新

- 前端代码改 `frontend/static.js`，改完先跑 `python3 build.py` 再 `wrangler deploy`
- 只改界面文字、样式的话，直接改 `_worker.js` 里对应的 HTML/CSS 也行，别动 `// ---------------- 前端 JS ----------------` 这行标记
- 想换 Worker 名字就改 `wrangler.toml` 第一行的 `name`

部署完成后访问 `https://<worker名>.<子域>.workers.dev`，
先输入访问密码，再添加 Cloudflare 凭据（推荐 API Token，最小权限原则）。

## 鉴权方式

- **API Token（推荐）**：Bearer 鉴权，按最小权限配置
- **Global API Key（旧版兼容）**：拥有账号全部权限，请妥善保管

凭据保存在浏览器 localStorage，每次请求发送给同源 Worker 后端，
不直接发往前端的 `api.cloudflare.com`。

## 已知限制

- Versions API 为 Beta 接口，权限不足时会优雅降级提示
- R2 仅做存储桶管理，对象上传/下载需走 S3 兼容接口
- Secrets 批量更新、Analytics 等接口需要 Token 具备对应权限

## 反馈

问题反馈 / 交流群：https://t.me/yifang_chat
