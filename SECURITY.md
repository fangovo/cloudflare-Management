# 安全说明

## 支持范围

只维护最新的次版本（当前 `2.9.x`）。更早的版本请先升级再报告问题。

## 报告漏洞

**请不要在公开 issue 里贴 API Token、Global Key、访问密码或截图里的账号信息。**

反馈渠道：<https://t.me/yifang_chat>

报告时请说明：

1. 版本号（文件头注释里有）
2. 复现步骤，或最小复现片段
3. 影响面：能否未授权访问、能否读写他人账号、能否导致数据丢失
4. 如果涉及凭据，请先去 Dashboard 把该 Token 吊销，再提供脱敏后的信息

## 威胁模型

这个面板本质上是一个**凭据代理**：它接收用户提供的 Cloudflare API Token，
代为调用 Cloudflare API。所以需要保护的是「谁能用这个面板」和「凭据会不会泄漏」。

### 凭据在哪里

| 数据 | 位置 | 说明 |
|---|---|---|
| API Token / Global Key / OAuth token | 浏览器 `localStorage` | 每次请求随 body 发给同源 Worker |
| 访问密码 | Worker Secret `ACCESS_PASSWORD` | 只存在于服务端 |
| 会话令牌 | 浏览器 Cookie | `HMAC(密码, 过期时间+随机ID)`，可被伪造校验 |
| 会话记录（可选） | KV `SESSIONS` | 只存 `sess:<id>` 标记，不存凭据 |

Worker **不写数据库、不落日志**，所以服务端被攻破不会泄漏用户凭据；
但反过来，**任何 XSS 都能直接读走 `localStorage` 里的 Token**——这也是为什么
v2.9 加了 CSP（`script-src 'self'`，禁外部脚本、禁 iframe 嵌套）。

### 已知的、被接受的风险

- **单密码模式**：`ACCESS_PASSWORD` 是唯一的口令，没有多用户 / 角色。所有访问者权限相同。
- **限流是单节点内存计数**：Cloudflare 会按地理位置调度到不同 isolate，
  攻击者换 IP / 换节点可以绕过。它是"挡住脚本爆破"，不是"挡住定向攻击"。
- **前端内嵌在同一个文件里**：前端一旦有 XSS，CSP 只能限制外传通道，不能阻止执行。
- **`PATCH` 部分更新的语义**：某些 Cloudflare 接口对未传字段的处理不一致，
  代码里已经尽量只在字段存在时才提交。

## 部署加固清单

- [ ] 一定要设置 `ACCESS_PASSWORD`，且**不要用弱口令**（面板是公网可访问的）
- [ ] 用**最小权限的 API Token**，别用 Global API Key
- [ ] 在前面加一层 [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/policies/access/)（Zero Trust），
      限制来源邮箱 / IP
- [ ] 绑自定义域名 + 开 SSL，别用 `workers.dev` 直接对外（更容易被扫到）
- [ ] 可选：绑定 `SESSIONS` KV，便于吊销会话
- [ ] 定期在 Dashboard 里轮换 API Token
- [ ] 不要把面板地址发到公开群组

## 安全相关的实现细节

| 点 | 实现 |
|---|---|
| 密码比较 | 双方 SHA-256 后逐字节 XOR，无短路（常量时间） |
| 会话过期 | 令牌内嵌 `exp`，默认 7 天，验签时校验 |
| 会话吊销 | `SESSIONS` KV 中存在 `sess:<id>` 才放行 |
| 暴力破解 | 同 IP 5 分钟 10 次失败后返回 429 |
| SSRF | 直链拉取限制 http(s)，拒绝内网 / 回环 / CGNAT / IPv6 映射等写法 |
| ZIP 炸弹 | 解压时限制单文件 25 MB、总量 100 MB，过滤 `../` |
| CSP | `default-src 'self'`；`connect-src` 仅放行 GitHub 两个域名 |
| 缓存 | API 响应 `no-store`，避免凭据进浏览器缓存 |
