# 更新日志

版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)：`主版本.次版本.修订号`。
单文件发布，升级方式就是替换 `.js` 文件并重新部署（配置与绑定不受影响）。

## v2.9.0 — 2026-10-23

一次完整的代码审查 + 修复。**升级后旧会话失效，需要重新登录一次。**

### 安全
- 会话令牌从「密码的固定 HMAC」改为 `v1.<过期>.<随机ID>.<HMAC>`：
  每次登录不同、7 天自动过期、可选 KV 落库吊销
- `/auth` 增加失败限流（同 IP 5 分钟 10 次），密码比较改为常量时间
- Cookie 在 HTTPS 下补 `Secure`
- 全站安全响应头 + CSP（禁外部脚本、禁 iframe 嵌套）
- API 响应统一 `Cache-Control: no-store`、去掉 pretty-print
- `accountId` 强制 32 位 hex 校验（它会被拼进 API 路径与 GraphQL 串）
- 直链检查补齐十进制 / 十六进制 / 八进制 IP、IPv6 映射、CGNAT 等绕过写法
- 移除 Google Fonts 外链

### 数据安全
- 重新上传代码时**原样带回线上 settings**（`compatibility_date`、`compatibility_flags`、
  `observability`、`limits`、`placement`、`usage_model`），修复「改个变量就把运行时配置冲掉」
- 多模块（ESM bundle）Worker 拒绝「保存变量」，避免只回传主模块把代码改残
- 明文变量整行删除现在真的会删除（此前只对 secret 生效）
- Pages 生产 / 预览的删除标记分开计算，不再互相误删对方独有的绑定

### 修复
- GitHub 单文件链接部署 Pages 报 `u8.subarray is not a function`
- 更新 DNS 记录时未传 `proxied` 会被强制关闭橙云
- 权限自检把「域名 / DNS」误报为可用（只探了 `/zones`，没探 DNS 记录）
- ZIP 未限制解压体积、未过滤 `../`（zip 炸弹 / zip-slip）
- S3 SigV4 未按 RFC3986 编码，键名含 `!'()*` 时签名失败
- S3 XML 转义顺序错误导致二次解码

### 性能
- 所有 Cloudflare 请求加 20s 超时 + 429/5xx 退避重试
- 批量拉取限制并发 6；`list-workers` / 路由 / 权限探针不再无上限并发
- zones、DNS 记录按 `result_info` 自动翻页
- secrets 改走 `secrets-bulk`（失败自动逐条回退）
- Pages 资源哈希改用原生 SHA-256（`PAGES_HASH_MODE` 可切回 BLAKE3）
- 页面与前端脚本进程内缓存，不再每个请求重复拼装几十万字符

## v2.8.2 — 2026-10-23
- OAuth scope 增加 `argotunnel.read/write`
- Token 权限检测新增隧道探针；权限说明补 Argo Tunnel (Legacy)

## v2.8.1 / v2.8 — 2026-10
- 新增「隧道管理」：列表 / 创建 / 详情 / 规则编辑 / 删除
- 建隧道自动写 ingress + CNAME，失败回滚；删隧道连带清理 CNAME
- 隧道规则编辑改为「子域名 + 主域名」下拉，支持可选路径与实时预览

## v2.7 — 2026-10
- KV / D1 / R2 页面新增用量卡（GraphQL 聚合 + 存储快照 + 额度进度条）
- 三个页面共享一份 5 分钟缓存，限流后自动重试一次

## v2.6.1 / v2.6 — 2026-10
- 修复 GraphQL `dimensions.scriptName` 返回 `__unknown__` 时的归属判断
- 未归属流量在榜单末尾单列「未归属流量」

## v2.5 — 2026-10
- `list-worker-routes-all` 改为并行拉取各 zone 路由

## v2.4 / v2.3 — 2026-10
- 设置页移除手填 OAuth Client ID，改由环境变量 `OAUTH_CLIENT_ID` 预置

## v2.2 / v2.1 — 2026-10
- OAuth scope 改用 `workers-scripts.admin`（修复 `invalid_scope`）
- 修复重新部署会清空线上 secrets 的数据丢失问题
- `pagesAssetHash` 改为哈希原始字节
- 删除死代码 `r2-object-download-url` 重复分支

## v2.0
- 首个版本：Workers / KV / D1 / R2 / Pages / DNS 管理，内嵌前端
