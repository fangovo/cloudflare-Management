(function(){
var DEFAULT_WORKER_SCRIPT = "export default {\n  async fetch(request, env, ctx) {\n    return new Response(\'Hello World\');\n  }\n};";
function el(id){ return document.getElementById(id); }
function esc(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function escA(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function fmtBJ(iso){ try{ var d = new Date(iso); if(!iso || isNaN(d.getTime())) return iso || ""; var p = function(n){ return (n < 10 ? "0" : "") + n; }; var t = new Date(d.getTime() + 8 * 3600000); return t.getUTCFullYear() + "-" + p(t.getUTCMonth() + 1) + "-" + p(t.getUTCDate()) + " " + p(t.getUTCHours()) + ":" + p(t.getUTCMinutes()) + ":" + p(t.getUTCSeconds()); }catch(e){ return iso || ""; } }
function showNotification(message, type){
  type = type || "success";
  var n = document.createElement("div");
  n.textContent = message;
  var bg = type === "success" ? "#10b981" : (type === "warning" ? "#f59e0b" : "#ef4444");
  n.style.cssText = "position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;color:#fff;z-index:10000;max-width:420px;box-shadow:0 4px 12px rgba(0,0,0,0.15);background:" + bg;
  document.body.appendChild(n);
  setTimeout(function(){ n.remove(); }, type === "warning" ? 6000 : 3200);
}
function copyToClipboard(text, event){ if(event) event.stopPropagation(); if(navigator.clipboard){ navigator.clipboard.writeText(text).then(function(){ showNotification("已复制到剪贴板"); }).catch(function(){ showNotification("复制失败","error"); }); } }
function debugOut(v){ el("debugOut").textContent = (typeof v === "string") ? v : JSON.stringify(v, null, 2); el("outModal").style.display = "flex"; }
function closeOut(){ el("outModal").style.display = "none"; }
function loadSaved(){ try { return JSON.parse(localStorage.getItem("cfm_accounts") || "[]"); } catch(e){ return []; } }
function saveAccounts(a){ localStorage.setItem("cfm_accounts", JSON.stringify(a)); }
function getActiveIdx(){ var i = parseInt(localStorage.getItem("cfm_active_idx") || "-1", 10); return isNaN(i) ? -1 : i; }
function getActiveAccount(){ var arr = loadSaved(); var i = getActiveIdx(); return (i >= 0 && arr[i]) ? arr[i] : null; }
// 账号显示名：key 模式显示邮箱；token 的 label 若缺失或就是 token 本身（旧数据），不直接显示 token
function accountTitle(a){
  if(!a) return "";
  if(a.mode === "key") return a.email || "";
  var label = a.label || "";
  if(a.mode === "token" && label === a.token) label = "";
  if(a.mode === "oauth" && !label) label = "OAuth 授权";
  return label || "API Token";
}
function nowStr2(){ return new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false }).replace(/\//g, "-"); }
// ---- OAuth 2.0 + PKCE（Cloudflare 官方授权）----
var OAUTH_DEFAULT_CLIENT_ID = "11ba6a4eb7ab0bc9e1cbdd9d46f59b02";
var OAUTH_AUTH_URL = "https://dash.cloudflare.com/oauth2/auth";
var OAUTH_SCOPES = "workers-scripts.read workers-scripts.write workers-routes.read workers-routes.write workers-tail.read workers-kv-storage.read workers-kv-storage.write d1.read d1.write workers-r2.read workers-r2.write zone.read zone.write dns.read dns.write page.read page.write analytics.read account-analytics.read account-settings.read memberships.read user-details.read";
function getOAuthClientId(){ return localStorage.getItem("cfm_oauth_client_id") || OAUTH_DEFAULT_CLIENT_ID; }
function setOAuthClientId(id){ if(id) localStorage.setItem("cfm_oauth_client_id", id); else localStorage.removeItem("cfm_oauth_client_id"); }
function authPayload(){
  var a = getActiveAccount();
  if(!a) return {};
  if(a.mode === "token") return { authMode: "token", token: a.token };
  if(a.mode === "oauth") return { authMode: "oauth", token: a.access_token };
  return { authMode: "key", email: a.email, key: a.key };
}
// OAuth token 快过期（2 分钟内）时自动刷新；刷新失败返回 false
var _oauthRefreshing = null;
async function ensureOAuthFresh(){
  var a = getActiveAccount();
  if(!a || a.mode !== "oauth") return true;
  if(a.expires_at && Date.now() < a.expires_at - 120000) return true;
  if(_oauthRefreshing) return _oauthRefreshing;
  _oauthRefreshing = (async function(){
    try {
      var r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "oauth-refresh", refresh_token: a.refresh_token, client_id: a.client_id || getOAuthClientId() }) });
      var res = await r.json();
      if(res && res.success && res.access_token){
        a.access_token = res.access_token;
        if(res.refresh_token) a.refresh_token = res.refresh_token;
        a.expires_at = Date.now() + (res.expires_in || 3600) * 1000;
        var arr = loadSaved(); var idx = getActiveIdx();
        if(arr[idx] && arr[idx].mode === "oauth"){ arr[idx] = a; saveAccounts(arr); }
        return true;
      }
    } catch(e){}
    return false;
  })();
  var ok = await _oauthRefreshing;
  _oauthRefreshing = null;
  return ok;
}
async function api(action, body){
  var a0 = getActiveAccount();
  if(a0 && a0.mode === "oauth"){
    var fresh = await ensureOAuthFresh();
    if(!fresh) return { success: false, error: "OAuth 授权已过期，请重新使用 Cloudflare 账号登录", oauthExpired: true };
  }
  var payload = authPayload();
  payload.action = action;
  if(body){ for(var k in body){ payload[k] = body[k]; } }
  var r;
  try { r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) }); }
  catch(e){ return { success: false, error: "网络请求失败，请检查网络后重试" }; }
  var res;
  try { res = await r.json(); } catch(e){ res = { success: false, error: "响应解析失败" }; }
  if(r.status === 401 && res && res.error && res.error.indexOf("未授权") >= 0){ location.href = "/login"; }
  return res;
}
async function ensureAccountId(){
  var cached = localStorage.getItem("cfm_accountId");
  if(cached) return cached;
  var r = await api("list-accounts");
  if(r && r.success && r.result && r.result.length){
    localStorage.setItem("cfm_accountId", r.result[0].id);
    return r.result[0].id;
  }
  return null;
}
var page = document.body && document.body.dataset ? document.body.dataset.page : "";
if(page === "login"){
  var authMode = "token";
  window.switchAuthMode = function(m){
    authMode = m;
    el("tabToken").className = "mode-tab" + (m === "token" ? " active" : "");
    el("tabKey").className = "mode-tab" + (m === "key" ? " active" : "");
    el("tokenFields").style.display = (m === "token") ? "block" : "none";
    el("keyFields").style.display = (m === "key") ? "block" : "none";
    el("batchLoginHint").textContent = (m === "token") ? "Token 模式：每行一个，格式：备注|Token（备注可省略）" : "Key 模式：每行一个，格式：邮箱|GlobalApiKey";
  };
  // ---- OAuth 2.0 + PKCE 登录 ----
  function _b64url(buf){
    var bin = String.fromCharCode.apply(null, new Uint8Array(buf));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function _randB64(n){
    var arr = new Uint8Array(n);
    (window.crypto || window.msCrypto).getRandomValues(arr);
    return _b64url(arr.buffer).slice(0, n);
  }
  async function _codeChallenge(verifier){
    var d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return _b64url(d);
  }
  window.startOAuthLogin = async function(){
    var clientId = getOAuthClientId();
    if(!clientId){ alert("请先在设置页配置 OAuth Client ID"); return; }
    try {
      var verifier = _randB64(64);
      var state = _randB64(32);
      var challenge = await _codeChallenge(verifier);
      sessionStorage.setItem("cfm_oauth_verifier", verifier);
      sessionStorage.setItem("cfm_oauth_state", state);
      var redirectUri = location.origin + "/oauth/callback";
      var url = OAUTH_AUTH_URL
        + "?client_id=" + encodeURIComponent(clientId)
        + "&response_type=code"
        + "&redirect_uri=" + encodeURIComponent(redirectUri)
        + "&scope=" + encodeURIComponent(OAUTH_SCOPES)
        + "&state=" + encodeURIComponent(state)
        + "&code_challenge=" + encodeURIComponent(challenge)
        + "&code_challenge_method=S256";
      location.href = url;
    } catch(e){ alert("启动 OAuth 失败：浏览器不支持 WebCrypto（需要 HTTPS）"); }
  };
  function renderSaved(){
    var cont = el("savedAccounts"); var arr = loadSaved(); cont.innerHTML = "";
    if(!arr.length){ cont.textContent = "未找到已保存账号"; return; }
    arr.forEach(function(a, idx){
      var d = document.createElement("div"); d.className = "account-row";
      var pillCls = a.mode === "token" ? "blue" : (a.mode === "oauth" ? "green" : "amber");
      var pillTxt = a.mode === "token" ? "Token" : (a.mode === "oauth" ? "OAuth" : "Key");
      var title = esc(accountTitle(a)) + ' <span class="pill ' + pillCls + '">' + pillTxt + '</span>';
      d.innerHTML = "<div><div style=\"font-weight:600\">" + title + "</div><div class=\"small\">添加于 " + esc(a.added || "") + "</div></div>";
      var btn = document.createElement("button"); btn.className = "btn"; btn.textContent = "快速登录";
      btn.onclick = function(){ localStorage.setItem("cfm_active_idx", String(idx)); localStorage.removeItem("cfm_accountId"); location.href = "/app"; };
      var wrap = document.createElement("div"); wrap.appendChild(btn); d.appendChild(wrap); cont.appendChild(d);
    });
  }
  function nowStr(){ return new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false }).replace(/\//g, "-"); }
  async function doVerify(email, key, token, label){
    var body = (authMode === "token") ? { authMode: "token", token: token } : { authMode: "key", email: email, key: key };
    body.action = "validate-credentials";
    var r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    var res; try { res = await r.json(); } catch(e){ res = {}; }
    if(res && res.success){
      var arr = loadSaved();
      var autoLabel = (authMode === "token" && res.result && res.result.length && res.result[0].name) ? res.result[0].name : "";
      var acc = (authMode === "token") ? { mode: "token", label: label || autoLabel || "API Token", token: token, added: nowStr() } : { mode: "key", email: email, key: key, added: nowStr() };
      var key2 = (authMode === "token") ? ("t:" + token.slice(-8)) : ("k:" + email);
      var ex = arr.findIndex(function(x){ return (x.mode === "token" ? "t:" + String(x.token).slice(-8) : "k:" + x.email) === key2; });
      if(ex !== -1) arr.splice(ex, 1);
      arr.unshift(acc); saveAccounts(arr);
      localStorage.setItem("cfm_active_idx", "0"); localStorage.removeItem("cfm_accountId");
      location.href = "/app";
    } else { alert("验证失败：" + ((res && res.error) || "unknown")); }
  }
  el("verifyBtn").addEventListener("click", function(){
    if(authMode === "token"){ var t = el("newToken").value.trim(); if(!t) return alert("请输入 API Token"); doVerify(null, null, t, el("newLabel").value.trim()); }
    else { var e = el("newEmail").value.trim(), k = el("newKey").value.trim(); if(!e || !k) return alert("请输入邮箱和 Global API Key"); doVerify(e, k); }
  });
  el("openBatchModalBtn").addEventListener("click", function(){ el("batchLoginModal").style.display = "flex"; });
  el("confirmBatchLogin").addEventListener("click", function(){
    var raw = el("batchLoginInput").value; if(!raw.trim()) return alert("请输入内容");
    var arr = loadSaved(); var n = 0;
    raw.split("\n").forEach(function(line){
      line = line.trim(); if(!line) return;
      var parts = line.split("|");
      if(authMode === "token"){
        var token, label;
        if(parts.length >= 2){ label = parts[0].trim(); token = parts.slice(1).join("|").trim(); } else { token = parts[0].trim(); label = "API Token"; }
        if(token){ arr.unshift({ mode: "token", label: label, token: token, added: nowStr() }); n++; }
      } else {
        if(parts.length >= 2){ var em = parts[0].trim(), ky = parts.slice(1).join("|").trim(); if(em && ky){ arr.unshift({ mode: "key", email: em, key: ky, added: nowStr() }); n++; } }
      }
    });
    if(n > 0){ saveAccounts(arr); renderSaved(); el("batchLoginModal").style.display = "none"; el("batchLoginInput").value = ""; showNotification("已导入 " + n + " 个账号"); }
    else { alert("未解析到有效账号，请检查格式"); }
  });
  el("clearBtn").addEventListener("click", function(){
    var b = el("clearBtn");
    if(b.dataset.armed){
      delete b.dataset.armed;
      localStorage.removeItem("cfm_accounts"); localStorage.removeItem("cfm_active_idx"); localStorage.removeItem("cfm_accountId");
      renderSaved();
      b.textContent = "清除本地账号"; b.style.background = "#e5e7eb"; b.style.color = "#111";
    } else {
      b.dataset.armed = "1"; b.textContent = "再次点击确认清除"; b.style.background = "#ef4444"; b.style.color = "#fff";
      setTimeout(function(){ if(b.dataset.armed){ delete b.dataset.armed; b.textContent = "清除本地账号"; b.style.background = "#e5e7eb"; b.style.color = "#111"; } }, 5000);
    }
  });
  window.submitPw = async function(){    var pw = el("pwInput").value; el("pwError").textContent = "";
    try {
      var r = await fetch("/auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: pw }) });
      var res = await r.json();
      if(res.success){ el("pwOverlay").style.display = "none"; initLogin(); }
      else { el("pwError").textContent = res.error || "密码错误"; el("pwInput").value = ""; el("pwInput").focus(); }
    } catch(e){ el("pwError").textContent = "网络错误，请刷新重试"; }
  };
  async function initLogin(){
    try {
      var r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "check-features" }) });
      if(r.status === 401){ el("pwOverlay").style.display = "flex"; setTimeout(function(){ el("pwInput").focus(); }, 100); return; }
    } catch(e){}
    renderSaved();
  }
  initLogin();
  return;
}
if(page === "oauth-callback"){
  // OAuth 授权回调：校验 state，用 code + PKCE verifier 换 token，保存账号后进 /app
  (async function(){
    var msgEl = el("cbMsg"), errEl = el("cbErr"), spinEl = el("cbSpin");
    function fail(t){
      if(spinEl) spinEl.style.display = "none";
      if(msgEl) msgEl.textContent = "授权失败";
      if(errEl) errEl.innerHTML = esc(t) + '<br><br><a href="/login" style="color:#2563eb">返回登录页</a>';
    }
    var q = new URLSearchParams(location.search);
    if(q.get("error")){ fail("Cloudflare 返回错误：" + q.get("error")); return; }
    var code = q.get("code"), state = q.get("state");
    var verifier = sessionStorage.getItem("cfm_oauth_verifier");
    var savedState = sessionStorage.getItem("cfm_oauth_state");
    sessionStorage.removeItem("cfm_oauth_verifier");
    sessionStorage.removeItem("cfm_oauth_state");
    if(!code){ fail("未收到授权码"); return; }
    if(!state || !savedState || state !== savedState){ fail("state 校验失败，已中止（防 CSRF）"); return; }
    if(!verifier){ fail("PKCE 校验数据丢失，请重新发起登录"); return; }
    if(msgEl) msgEl.textContent = "正在换取访问令牌…";
    var clientId = getOAuthClientId();
    var redirectUri = location.origin + "/oauth/callback";
    var r;
    try {
      r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "oauth-exchange", code: code, code_verifier: verifier, redirect_uri: redirectUri, client_id: clientId }) });
    } catch(e){ fail("网络请求失败"); return; }
    if(r.status === 401){ fail("面板会话已过期，请先完成面板访问密码验证，再重新发起 OAuth 登录"); return; }
    var res; try { res = await r.json(); } catch(e){ res = {}; }
    if(!res || !res.success){ fail(res.error || "换取令牌失败"); return; }
    if(msgEl) msgEl.textContent = "正在验证账号…";
    // 用新 token 验证并保存账号
    var acc = { mode: "oauth", label: res.email || "OAuth 授权", access_token: res.access_token,
      refresh_token: res.refresh_token || "", expires_at: Date.now() + (res.expires_in || 3600) * 1000,
      client_id: clientId, added: new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false }).replace(/\//g, "-") };
    var arr = loadSaved();
    arr.unshift(acc); saveAccounts(arr);
    localStorage.setItem("cfm_active_idx", "0");
    localStorage.removeItem("cfm_accountId");
    location.href = "/app";
  })();
  return;
}
if(page === "app"){
var currentAccountId = null;
function navTo(p){
  document.querySelectorAll(".nav .item").forEach(function(i){ i.classList.remove("active"); });
  document.querySelectorAll(".page-content").forEach(function(x){ x.classList.remove("active"); });
  var nav = document.querySelector('.nav .item[data-page="' + p + '"]');
  var pg = el(p + "-page");
  if(nav) nav.classList.add("active"); if(pg) pg.classList.add("active");
  if(p === "workers") refreshWorkers();
  else if(p === "batch") renderBatchPage();
  else if(p === "kv") refreshKVNamespaces();
  else if(p === "d1") refreshD1Databases();
  else if(p === "r2") refreshR2Buckets();
  else if(p === "dns") showZonesList();
  else if(p === "pages") refreshPagesProjects();
  else if(p === "settings") loadSubdomainSettings();
}
window.navTo = navTo;
window.saveOAuthClientId = function(){
  var v = el("oauthClientIdInput").value.trim();
  setOAuthClientId(v);
  var ohint = el("oauthClientIdHint");
  if(ohint) ohint.textContent = v ? "已使用自定义 Client ID" : "当前使用内置默认 Client ID";
  showNotification("OAuth Client ID 已保存");
};
window.logout = function(){ localStorage.removeItem("cfm_active_idx"); localStorage.removeItem("cfm_accountId"); location.href = "/login"; };
function openAccountSwitcher(){
  var arr = loadSaved(); var cur = getActiveAccount(); var cont = el("accountListContainer"); cont.innerHTML = "";
  if(!arr.length){ cont.innerHTML = "<div style=\"padding:16px;text-align:center;color:#64748b\">暂无其他账号</div>"; }
  arr.forEach(function(acc, idx){
    var isActive = cur && acc.mode === cur.mode && ((acc.mode === "token" && acc.token === cur.token) || (acc.mode === "key" && acc.email === cur.email) || (acc.mode === "oauth" && acc.access_token === cur.access_token));
    var title = esc(accountTitle(acc));
    var pillC = acc.mode === "token" ? "blue" : (acc.mode === "oauth" ? "green" : "amber");
    var pillT = acc.mode === "token" ? "Token" : (acc.mode === "oauth" ? "OAuth" : "Key");
    var d = document.createElement("div"); d.className = "acct-row" + (isActive ? " acct-active" : "");
    d.innerHTML = "<div style=\"flex:1;cursor:pointer\" data-idx=\"" + idx + "\"><div style=\"font-weight:600\">" + title + (isActive ? "<span class=\"badge\">当前</span>" : "") + " <span class=\"pill " + pillC + "\">" + pillT + "</span></div><div class=\"small\">" + esc(acc.added || "") + "</div></div>" + (isActive ? "" : "<button class=\"trash-btn\" data-idx=\"" + idx + "\">✕</button>");
    cont.appendChild(d);
  });
  Array.from(cont.querySelectorAll("[data-idx]")).forEach(function(node){
    node.addEventListener("click", function(e){
      e.stopPropagation();
      var idx = parseInt(this.getAttribute("data-idx"), 10);
      if(this.tagName === "BUTTON"){ if(!confirm("确定要移除此账号吗？")) return; var a2 = loadSaved(); a2.splice(idx, 1); saveAccounts(a2); openAccountSwitcher(); return; }
      localStorage.setItem("cfm_active_idx", String(idx)); localStorage.removeItem("cfm_accountId");
      showNotification("正在切换账号..."); setTimeout(function(){ location.reload(); }, 500);
    });
  });
  ensureAddAccountSection();
  el("accountModal").style.display = "flex";
}
window.openAccountSwitcher = openAccountSwitcher;
window.closeAccountSwitcher = function(){ el("accountModal").style.display = "none"; };
// ---- 切换账号弹窗内的添加账号 ----
function ensureAddAccountSection(){
  if(el("addAccountSection")) return;
  var box = el("accountModal").querySelector(".modal-box");
  var sec = document.createElement("div");
  sec.id = "addAccountSection";
  sec.style.cssText = "margin-top:12px;border-top:1px solid #eef2f6;padding-top:12px";
  sec.innerHTML = '<button class="btn primary" style="width:100%" onclick="toggleAddAccountForm()">+ 添加账号</button>'
    + '<div id="addAccountForm" style="display:none;margin-top:12px">'
    + '<div class="tabs" style="margin-bottom:10px">'
    + '<div class="tab active" data-aatab="token" onclick="switchAddAccountTab(\'token\')">API Token</div>'
    + '<div class="tab" data-aatab="key" onclick="switchAddAccountTab(\'key\')">Global Key</div>'
    + '</div>'
    + '<div id="aaTokenPane"><div class="label">API Token</div><input id="aaToken" class="input" placeholder="粘贴 API Token">'
    + '<div class="label" style="margin-top:8px">备注名（可选）</div><input id="aaLabel" class="input" placeholder="留空则自动使用 Cloudflare 账号名"></div>'
    + '<div id="aaKeyPane" style="display:none"><div class="label">邮箱</div><input id="aaEmail" class="input" placeholder="Cloudflare 账号邮箱">'
    + '<div class="label" style="margin-top:8px">Global API Key</div><input id="aaKey" class="input" placeholder="粘贴 Global API Key"></div>'
    + '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button class="btn primary" onclick="confirmAddAccount()">验证并保存</button>'
    + '<button class="btn" onclick="toggleAddAccountForm()">取消</button>'
    + '<button class="btn" onclick="startOAuthLogin()">OAuth 添加</button></div>'
    + '</div>';
  box.appendChild(sec);
}
function toggleAddAccountForm(){ var f = el("addAccountForm"); if(f) f.style.display = (f.style.display === "none" ? "" : "none"); }
function switchAddAccountTab(t){
  Array.from(document.querySelectorAll("[data-aatab]")).forEach(function(x){ x.classList.toggle("active", x.getAttribute("data-aatab") === t); });
  el("aaTokenPane").style.display = t === "token" ? "" : "none";
  el("aaKeyPane").style.display = t === "key" ? "" : "none";
}
async function confirmAddAccount(){
  var tabEl = document.querySelector("[data-aatab].active");
  var tab = tabEl ? tabEl.getAttribute("data-aatab") : "token";
  var body, label = "", key2;
  if(tab === "token"){
    var token = el("aaToken").value.trim();
    if(!token) return showNotification("请输入 API Token", "error");
    label = el("aaLabel").value.trim();
    body = { authMode: "token", token: token };
    key2 = "t:" + token.slice(-8);
  } else {
    var email = el("aaEmail").value.trim(), key = el("aaKey").value.trim();
    if(!email || !key) return showNotification("请输入邮箱和 Global API Key", "error");
    body = { authMode: "key", email: email, key: key };
    key2 = "k:" + email;
  }
  body.action = "validate-credentials";
  showNotification("正在验证...", "warning");
  var r;
  try { r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch(e){ showNotification("网络请求失败", "error"); return; }
  var res; try { res = await r.json(); } catch(e){ res = {}; }
  if(res && res.success){
    var autoLabel = (tab === "token" && res.result && res.result.length && res.result[0].name) ? res.result[0].name : "";
    var acc = (tab === "token")
      ? { mode: "token", label: label || autoLabel || "API Token", token: body.token, added: nowStr2() }
      : { mode: "key", email: body.email, key: body.key, added: nowStr2() };
    var arr = loadSaved();
    var ex = arr.findIndex(function(x){
      var k = x.mode === "token" ? "t:" + String(x.token).slice(-8) : (x.mode === "key" ? "k:" + x.email : "o:" + x.access_token);
      return k === key2;
    });
    if(ex !== -1) arr.splice(ex, 1);
    arr.unshift(acc); saveAccounts(arr);
    localStorage.setItem("cfm_active_idx", "0"); localStorage.removeItem("cfm_accountId");
    showNotification("账号已添加");
    setTimeout(function(){ location.reload(); }, 600);
  } else {
    showNotification("验证失败：" + ((res && res.error) || "unknown"), "error");
  }
}
window.toggleAddAccountForm = toggleAddAccountForm; window.switchAddAccountTab = switchAddAccountTab; window.confirmAddAccount = confirmAddAccount;
function tagRow(label, inner, left){
  return "<div class=\"tag-row" + (left ? " left" : "") + "\"><span class=\"tag-row-label\">" + label + "</span>" +
    (inner ? inner : "<span class=\"small\" style=\"color:#94a3b8\">无</span>") + "</div>";
}
async function refreshWorkers(){
  el("workersList").innerHTML = "加载中...";
  currentAccountId = await ensureAccountId();
  if(!currentAccountId){ el("workersList").innerHTML = "无法获取 Account ID，请检查 Token 权限"; return; }
  var res = await api("list-workers", { accountId: currentAccountId });
  if(!res || !res.success){ el("workersList").innerHTML = "获取 Workers 失败：" + esc((res && res.error) || ""); return; }
  var list = el("workersList"); list.innerHTML = "";
  if(!res.result.length){ list.innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无 Workers</div>"; }
  res.result.forEach(function(w){
    var name = w.id;
    var bindings = w.bindings || [];
    var envB = bindings.filter(function(b){ return b.type === "plain_text" || b.type === "secret_text" || b.type === "json"; });
    var kvB = bindings.filter(function(b){ return b.type === "kv_namespace"; });
    var d1B = bindings.filter(function(b){ return b.type === "d1" || b.type === "d1_database"; });
    var r2B = bindings.filter(function(b){ return b.type === "r2_bucket"; });
    var subOn = w.subdomainEnabled !== false;
    var domains = w.domains || [];
    var div = document.createElement("div"); div.className = "worker-row";
    var html = "<div class=\"worker-info\"><div style=\"font-weight:700\">" + esc(name) + "</div>";
    if(w.defaultDomain){
      html += "<div class=\"worker-domains\" style=\"margin-top:8px\"><div class=\"small\">默认域名</div>";
      html += "<a href=\"https://" + escA(w.defaultDomain.hostname) + "\" target=\"_blank\" class=\"domain-tag workers-dev\">" + esc(w.defaultDomain.hostname) + "<span class=\"domain-status " + (subOn ? "active" : "inactive") + "\">" + (subOn ? "已启用" : "已禁用") + "</span></a>";
      html += "<label class=\"switch\" style=\"vertical-align:middle;margin-left:8px\"><input type=\"checkbox\" " + (subOn ? "checked" : "") + " data-subtoggle=\"" + escA(name) + "\"><span class=\"slider\"></span></label></div>";
    }
    html += "<div class=\"worker-domains\" style=\"margin-top:8px\"><div class=\"small\">自定义域名</div>";
    if(domains.length){
      domains.forEach(function(dm){
        var st = dm.status || "active";
        html += "<span style=\"display:inline-block;position:relative\"><a href=\"https://" + escA(dm.hostname) + "\" target=\"_blank\" class=\"domain-tag\">" + esc(dm.hostname) + "<span class=\"domain-status " + (st === "active" ? "active" : "pending") + "\">" + (st === "active" ? "已启用" : esc(st)) + "</span></a><span class=\"del-domain-btn\" title=\"解绑\" data-deldom=\"" + escA(dm.id) + "|" + escA(name) + "|" + escA(dm.hostname) + "\">✕</span></span>";
      });
    } else { html += "<span class=\"small\" style=\"color:#94a3b8\">暂无</span>"; }
    html += "</div></div>";
    html += "<div class=\"worker-right\"><div class=\"worker-tag-rows\">";
    html += tagRow("环境变量", envB.map(function(b){
      return b.type === "secret_text"
        ? "<span class=\"res-tag secret\" title=\"密钥\">" + esc(b.name) + "</span>"
        : "<span class=\"res-tag env\">" + esc(b.name) + "</span>";
    }).join(""));
    html += tagRow("KV", kvB.map(function(b){ return "<span class=\"res-tag kv\">" + esc(b.name) + "</span>"; }).join(""));
    html += tagRow("D1", d1B.map(function(b){ return "<span class=\"res-tag d1\">" + esc(b.name) + "</span>"; }).join(""));
    var cronNames = (w.cronTriggers || []).map(function(c){ return typeof c === "string" ? c : (c.cron || ""); }).filter(function(c){ return !!c; });
    html += tagRow("Cron", cronNames.map(function(c){ return "<span class=\"res-tag cron\">" + esc(c) + "</span>"; }).join(""));
    if(r2B.length) html += tagRow("R2", r2B.map(function(b){ return "<span class=\"res-tag r2\">" + esc(b.name) + "</span>"; }).join(""));
    html += "</div><div class=\"btns\">";
    html += "<button class=\"btn\" data-act=\"env\" data-name=\"" + escA(name) + "\">环境</button>";
    html += "<button class=\"btn\" data-act=\"bind\" data-name=\"" + escA(name) + "\">绑定</button>";
    html += "<button class=\"btn\" data-act=\"compat\" data-name=\"" + escA(name) + "\">兼容日期</button>";
    html += "<button class=\"btn\" data-act=\"compatflags\" data-name=\"" + escA(name) + "\">兼容标志</button>";
    html += "<button class=\"btn\" data-act=\"cron\" data-name=\"" + escA(name) + "\">Cron</button>";
    html += "<button class=\"btn\" data-act=\"domain\" data-name=\"" + escA(name) + "\">域名</button>";
    html += "<button class=\"btn\" data-act=\"versions\" data-name=\"" + escA(name) + "\">版本</button>";
    html += "<button class=\"btn\" data-act=\"edit\" data-name=\"" + escA(name) + "\">编辑</button>";
    html += "<button class=\"btn danger\" data-act=\"delete\" data-name=\"" + escA(name) + "\">删除</button>";
    html += "</div></div>";
    div.innerHTML = html;
    list.appendChild(div);
  });
  Array.from(list.querySelectorAll("[data-subtoggle]")).forEach(function(cb){
    cb.addEventListener("change", function(){ toggleWorkerSubdomain(this.getAttribute("data-subtoggle"), this.checked); });
  });
  Array.from(list.querySelectorAll("[data-deldom]")).forEach(function(s){
    s.addEventListener("click", function(){
      var parts = this.getAttribute("data-deldom").split("|");
      deleteWorkerDomain(parts[1], parts[0], parts[2]);
    });
  });
  Array.from(list.querySelectorAll(".btns .btn")).forEach(function(b){
    b.addEventListener("click", function(){
      var act = this.getAttribute("data-act"), nm = this.getAttribute("data-name");
      if(act === "env") openEnvFor(nm);
      else if(act === "bind") openBindFor(nm);
      else if(act === "compat") openCompatModal(nm);
      else if(act === "compatflags") openCompatFlagsModal(nm);
      else if(act === "cron") openCronModal(nm);
      else if(act === "domain") openAddDomainModal(nm);
      else if(act === "versions") openVersionsFor(nm);
      else if(act === "edit") editWorker(nm);
      else if(act === "delete") deleteWorker(nm);
    });
  });
  updateWorkerMetrics();
}
async function updateWorkerMetrics(){
  try {
    var r = await api("get-usage-today", { accountId: currentAccountId });
    if(r && r.success && r.data){
      el("metricCount").textContent = r.data.total.toLocaleString() + " / 100,000";
      el("metricBar").style.width = r.data.percentage + "%";
      el("metricSub").textContent = "Workers " + r.data.workers.toLocaleString() + " · Pages " + r.data.pages.toLocaleString();
    }
  } catch(e){}
}
async function toggleWorkerSubdomain(name, enabled){
  var r = await api("toggle-worker-subdomain", { accountId: currentAccountId, scriptName: name, enabled: enabled });
  if(r && r.success){ showNotification(enabled ? "workers.dev 已启用" : "workers.dev 已禁用"); setTimeout(refreshWorkers, 800); }
  else { showNotification((r && r.error) || "操作失败", "error"); refreshWorkers(); }
}
window.toggleWorkerSubdomain = toggleWorkerSubdomain;
var currentWorkerForDomain = "";
var domainZonesCache = [];
async function openAddDomainModal(name){
  currentWorkerForDomain = name; el("newDomainPrefix").value = ""; domainZonesCache = [];
  el("addDomainModal").style.display = "flex";
  el("domainZoneWrap").innerHTML = '<div class="small">加载域名中...</div>'; updateDomainPreview();
  var r = await api("list-zones");
  var zones = (r && r.success && r.result) ? r.result : [];
  domainZonesCache = zones.map(function(z){ return z.name; });
  if(!zones.length) el("domainZoneWrap").innerHTML = '<div class="small" style="color:#ef4444">该账号下没有可用域名，请先到「域名管理」添加</div>';
  else if(zones.length === 1) el("domainZoneWrap").innerHTML = '<div style="font-size:15px;font-weight:600">' + esc(zones[0].name) + '</div>';
  else {
    var opts = zones.map(function(z){ return '<option value="' + esc(z.name) + '">' + esc(z.name) + '</option>'; }).join("");
    el("domainZoneWrap").innerHTML = '<select id="newDomainZone" class="input" onchange="updateDomainPreview()">' + opts + '</select>';
  }
  updateDomainPreview();
}
function updateDomainPreview(){
  var prefix = el("newDomainPrefix").value.trim().replace(/\.$/, "");
  var zone = "", sel = el("newDomainZone");
  if(sel) zone = sel.value; else if(domainZonesCache.length === 1) zone = domainZonesCache[0];
  el("domainPreview").textContent = prefix ? (prefix + "." + zone) : zone;
}
function closeAddDomainModal(){ el("addDomainModal").style.display = "none"; currentWorkerForDomain = ""; }
async function confirmAddDomain(){
  var prefix = el("newDomainPrefix").value.trim().replace(/\.$/, "");
  var zone = "", sel = el("newDomainZone");
  if(sel) zone = sel.value; else if(domainZonesCache.length === 1) zone = domainZonesCache[0];
  if(!zone) return showNotification("没有可用域名", "error");
  var h = prefix ? (prefix + "." + zone) : zone;
  var r = await api("add-worker-domain", { accountId: currentAccountId, scriptName: currentWorkerForDomain, hostname: h });
  if(r && r.success){ showNotification("域名绑定成功"); closeAddDomainModal(); refreshWorkers(); }
  else showNotification((r && r.error) || "绑定失败", "error");
}
async function deleteWorkerDomain(scriptName, domainId, hostname){ 
  if(!confirm("确定解绑域名 " + hostname + " 吗？")) return;
  var r = await api("delete-worker-domain", { accountId: currentAccountId, scriptName: scriptName, domainId: domainId });
  if(r && r.success){ showNotification("域名已解绑"); refreshWorkers(); }
  else showNotification((r && r.error) || "解绑失败", "error");
}
window.openAddDomainModal = openAddDomainModal; window.closeAddDomainModal = closeAddDomainModal;
window.confirmAddDomain = confirmAddDomain; window.deleteWorkerDomain = deleteWorkerDomain; window.updateDomainPreview = updateDomainPreview;
function openCreateWorker(){ el("createName").value = ""; el("createName").readOnly = false; el("createScript").value = DEFAULT_WORKER_SCRIPT; el("createModal").style.display = "flex"; }
function closeCreate(){ el("createModal").style.display = "none"; }
async function confirmCreate(){
  var name = el("createName").value.trim(), script = el("createScript").value;
  if(!name) return showNotification("请输入 Worker 名称", "error");
  var r = await api("deploy-worker", { accountId: currentAccountId, scriptName: name, scriptSource: script, metadataBindings: [] });
  if(r && r.success){ saveWorkerDeployHistory(name, script); showNotification("部署成功"); closeCreate(); setTimeout(refreshWorkers, 800); }
  else { showNotification((r && r.error) || "部署失败", "error"); debugOut(r); }
}
async function editWorker(name){
  var r = await api("get-worker-script", { accountId: currentAccountId, scriptName: name });
  if(r && r.rawScript !== undefined){ el("createName").value = name; el("createName").readOnly = true; el("createScript").value = r.rawScript; el("createModal").style.display = "flex"; }
  else { showNotification("获取脚本失败", "error"); debugOut(r); }
}
async function deleteWorker(name){
  if(!confirm("确定删除 Worker: " + name + " 吗？")) return;
  var r = await api("delete-worker", { accountId: currentAccountId, scriptName: name });
  if(r && r.success){ showNotification("删除成功"); setTimeout(refreshWorkers, 600); } else showNotification((r && r.error) || "删除失败", "error");
}
window.openCreateWorker = openCreateWorker; window.closeCreate = closeCreate; window.confirmCreate = confirmCreate;
// ---- 一键部署（新版新建 Worker）----
function ensureQuickDeployModal(){
  if(el("quickDeployModal")) return;
  var h = '<div id="quickDeployModal" class="modal"><div class="modal-box">'
    + '<div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">一键部署</h3>'
    + '<span style="cursor:pointer;font-size:18px;color:#94a3b8" onclick="closeQuickDeploy()">&#10005;</span></div>'
    + '<div class="small" style="margin:8px 0 14px">账号里已有同名 Worker 会自动转为更新，没有则新建</div>'
    + '<div class="label">代码来源</div>'
    + '<div style="display:flex;gap:18px;margin-bottom:10px;font-size:13px">'
    + '<label style="cursor:pointer"><input type="radio" name="qdSrc" value="url" checked onchange="qdSwitchSrc()"> 直链</label>'
    + '<label style="cursor:pointer"><input type="radio" name="qdSrc" value="editor" onchange="qdSwitchSrc()"> 编辑框</label>'
    + '<label style="cursor:pointer"><input type="radio" name="qdSrc" value="file" onchange="qdSwitchSrc()"> 上传</label>'
    + '</div>'
    + '<div id="qdSrcUrl"><input id="qdUrl" class="input" placeholder=".js 直链"></div>'
    + '<div id="qdSrcEditor" style="display:none"><textarea id="qdEditor" class="input" rows="12" style="min-height:240px;font-size:13px" placeholder="在此粘贴 Worker 脚本"></textarea></div>'
    + '<div id="qdSrcFile" style="display:none"><input type="file" id="qdFile" accept=".js,.zip" class="input"></div>'
    + '<div class="label" style="margin-top:14px">项目名</div>'
    + '<input id="qdName" class="input" placeholder="例如: my-worker" oninput="qdAutoHostname()">'
    + '<div class="small" style="margin-top:4px">将以此名称新建 Worker（账号里已有同名则转为更新）</div>'
    + '<div class="label" style="margin-top:14px">环境变量 <span class="small">（可选）</span></div>'
    + '<div id="qdEnvList"></div>'
    + '<button class="btn small" style="margin-top:6px" onclick="qdAddEnvRow()">+ 添加变量</button>'
    + '<div class="label" style="margin-top:14px">KV 绑定 <span class="small">（可选）</span></div>'
    + '<div id="qdKvList"></div>'
    + '<div style="margin-top:6px"><button class="btn small" onclick="qdAddKvRow()">+ 添加 KV</button></div>'
    + '<div class="small" style="margin-top:4px">下拉选择已有命名空间；没有想要的就在右侧输入新名称，会自动创建</div>'
    + '<div class="label" style="margin-top:14px">D1 数据库 <span class="small">（可选）</span></div>'
    + '<div id="qdD1List"></div>'
    + '<div style="margin-top:6px"><button class="btn small" onclick="qdAddD1Row()">+ 添加 D1</button></div>'
    + '<div class="small" style="margin-top:4px">下拉选择已有数据库；没有想要的就在右侧输入新名称，会自动创建并绑定</div>'
    + '<div class="label" style="margin-top:14px">项目域名 <span class="small">（可选）</span></div>'
    + '<input id="qdHostname" class="input" placeholder="留空则自动生成：项目名.所选域名" oninput="this.dataset.manual=\'1\'">'
    + '<div class="label" style="margin-top:14px">域名列表</div>'
    + '<select id="qdZone" class="input" onchange="qdAutoHostname()"><option value="">不绑定域名</option></select>'
    + '<div class="small" style="margin-top:4px">账号接入的 CF 域名，选定后自动生成上方未填写的域名</div>'
    + '<div style="display:flex;align-items:center;gap:10px;margin-top:14px"><span class="label" style="margin:0">分配域名</span>'
    + '<label class="switch"><input type="checkbox" id="qdAssignDomain" checked><span class="slider"></span></label>'
    + '<span class="small">开启后分配 workers.dev 域名；选择自定义域名时自动关闭</span></div>'
    + '<div id="qdStatus" class="small" style="margin-top:12px;color:#1e40af"></div>'
    + '<div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" id="qdDeployBtn" onclick="confirmQuickDeploy()">开始部署</button><button class="btn" onclick="closeQuickDeploy()">取消</button></div>'
    + '</div></div>';
  document.body.insertAdjacentHTML("beforeend", h);
  var m = el("quickDeployModal");
  m.addEventListener("click", function(e){ if(e.target === m) closeQuickDeploy(); });
}
function openQuickDeploy(){
  ensureQuickDeployModal();
  el("qdName").value = ""; el("qdUrl").value = ""; el("qdEditor").value = "";
  el("qdEnvList").innerHTML = ""; el("qdKvList").innerHTML = ""; el("qdD1List").innerHTML = "";
  el("qdHostname").value = ""; el("qdHostname").dataset.manual = "";
  el("qdAssignDomain").checked = true;
  el("qdFile").value = ""; el("qdStatus").textContent = "";
  document.querySelector('input[name="qdSrc"][value="url"]').checked = true; qdSwitchSrc();
  qdLoadZones();
  qdLoadKvOptions(true); qdLoadD1Options(true);
  el("quickDeployModal").style.display = "flex";
}
// ---- 一键部署：环境变量 / KV / D1 行 ----
function qdAddEnvRow(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px";
  d.innerHTML = '<input class="input qd-env-name" placeholder="变量名" style="flex:1"><input class="input qd-env-val" placeholder="变量值" style="flex:2"><button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdEnvList").appendChild(d);
}
// 一键部署 KV/D1 下拉（样式对齐"绑定资源"弹窗：名称 (ID)；右侧可输新名称自动创建）
var qdKvCache = [], qdD1Cache = [];
function qdToggleKvRow(sel){
  var row = sel.parentNode;
  var nw = row.querySelector(".qd-kv-new"), bn = row.querySelector(".qd-kv-bind");
  var hasSel = !!sel.value;
  nw.style.display = hasSel ? "none" : "";
  bn.style.display = hasSel ? "" : "none";
}
function qdAddKvRow(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px;align-items:center";
  d.innerHTML = '<select class="input qd-kv-sel" style="flex:2;min-width:140px" onchange="qdToggleKvRow(this)"><option value="">— 下拉选择已有 —</option></select>'
    + '<input class="input qd-kv-new" placeholder="或输入新名称，自动创建" style="flex:2;min-width:140px">'
    + '<input class="input qd-kv-bind" placeholder="绑定名(留空自动)" style="flex:1;min-width:90px;display:none">'
    + '<button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdKvList").appendChild(d);
  qdRefreshKvSelects();
}
function qdToggleD1Row(sel){
  var row = sel.parentNode;
  var nw = row.querySelector(".qd-d1-new"), bn = row.querySelector(".qd-d1-bind");
  var hasSel = !!sel.value;
  nw.style.display = hasSel ? "none" : "";
  bn.style.display = hasSel ? "" : "none";
}
function qdAddD1Row(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px;align-items:center";
  d.innerHTML = '<select class="input qd-d1-sel" style="flex:2;min-width:140px" onchange="qdToggleD1Row(this)"><option value="">— 下拉选择已有 —</option></select>'
    + '<input class="input qd-d1-new" placeholder="或输入新名称，自动创建并绑定" style="flex:2;min-width:140px">'
    + '<input class="input qd-d1-bind" placeholder="绑定名(留空自动)" style="flex:1;min-width:90px;display:none">'
    + '<button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdD1List").appendChild(d);
  qdRefreshD1Selects();
}
function qdRefreshKvSelects(){
  Array.from(document.querySelectorAll(".qd-kv-sel")).forEach(function(sel){
    var cur = sel.value;
    sel.innerHTML = '<option value="">— 下拉选择已有 —</option>';
    qdKvCache.forEach(function(ns){
      var o = document.createElement("option");
      o.value = ns.title;
      o.textContent = (ns.title || ns.id) + " (" + ns.id + ")";
      sel.appendChild(o);
    });
    sel.value = cur;
  });
}
function qdRefreshD1Selects(){
  Array.from(document.querySelectorAll(".qd-d1-sel")).forEach(function(sel){
    var cur = sel.value;
    sel.innerHTML = '<option value="">— 下拉选择已有 —</option>';
    qdD1Cache.forEach(function(db){
      var o = document.createElement("option");
      o.value = db.name;
      o.textContent = (db.name || db.uuid || db.id) + " (" + (db.uuid || db.id) + ")";
      sel.appendChild(o);
    });
    sel.value = cur;
  });
}
async function qdLoadKvOptions(silent){
  try {
    var r = await api("list-kv-namespaces", { accountId: currentAccountId });
    qdKvCache = r.result || [];
  } catch(e){ qdKvCache = []; }
  qdRefreshKvSelects();
  if(!silent) showNotification(qdKvCache.length ? ("已加载 " + qdKvCache.length + " 个 KV 命名空间") : "没有 KV 命名空间，可直接输入名称创建");
}
async function qdLoadD1Options(silent){
  try {
    var r = await api("list-d1", { accountId: currentAccountId });
    qdD1Cache = r.result || [];
  } catch(e){ qdD1Cache = []; }
  qdRefreshD1Selects();
  if(!silent) showNotification(qdD1Cache.length ? ("已加载 " + qdD1Cache.length + " 个 D1 数据库") : "没有 D1 数据库，可直接输入名称创建");
}
window.qdAddEnvRow = qdAddEnvRow; window.qdAddKvRow = qdAddKvRow; window.qdAddD1Row = qdAddD1Row;
window.qdToggleKvRow = qdToggleKvRow; window.qdToggleD1Row = qdToggleD1Row;
window.qdLoadKvOptions = qdLoadKvOptions; window.qdLoadD1Options = qdLoadD1Options;
function closeQuickDeploy(){ var m = el("quickDeployModal"); if(m) m.style.display = "none"; }
function qdSwitchSrc(){
  var v = document.querySelector('input[name="qdSrc"]:checked').value;
  el("qdSrcUrl").style.display = v === "url" ? "" : "none";
  el("qdSrcEditor").style.display = v === "editor" ? "" : "none";
  el("qdSrcFile").style.display = v === "file" ? "" : "none";
}
async function qdLoadZones(){
  var sel = el("qdZone");
  sel.innerHTML = '<option value="">不绑定域名</option>';
  try {
    var r = await api("list-zones", {});
    (r.result || []).forEach(function(z){
      var o = document.createElement("option"); o.value = z.name; o.textContent = z.name; sel.appendChild(o);
    });
  } catch(e){}
}
function qdAutoHostname(){
  var hostEl = el("qdHostname");
  var zone = el("qdZone").value;
  var assignEl = el("qdAssignDomain");
  if(assignEl) assignEl.checked = !zone;
  if(hostEl.dataset.manual === "1") return;
  var name = el("qdName").value.trim().toLowerCase().replace(/[^a-z0-9-]/g, "");
  hostEl.value = (zone && name) ? (name + "." + zone) : "";
}
function qdFileToText(f){
  return new Promise(function(res, rej){
    var r = new FileReader(); r.onload = function(){ res(r.result); }; r.onerror = rej; r.readAsText(f);
  });
}
function qdFileToBase64(f){
  return new Promise(function(res, rej){
    var r = new FileReader();
    r.onload = function(){ var s = String(r.result); res(s.slice(s.indexOf(",") + 1)); };
    r.onerror = rej; r.readAsDataURL(f);
  });
}
async function confirmQuickDeploy(){
  var name = el("qdName").value.trim();
  if(!name) return showNotification("请输入项目名", "error");
  var src = document.querySelector('input[name="qdSrc"]:checked').value;
  var payload = { accountId: currentAccountId, scriptName: name };
  if(src === "url"){
    var url = el("qdUrl").value.trim();
    if(!url) return showNotification("请输入直链", "error");
    payload.sourceKind = "url"; payload.sourceUrl = url;
  } else if(src === "editor"){
    var text = el("qdEditor").value;
    if(!text.trim()) return showNotification("请填写脚本内容", "error");
    payload.sourceKind = "text"; payload.sourceText = text;
  } else {
    var f = el("qdFile").files[0];
    if(!f) return showNotification("请选择文件", "error");
    if(/\.zip$/i.test(f.name)){ payload.sourceKind = "b64zip"; payload.sourceB64 = await qdFileToBase64(f); }
    else { payload.sourceKind = "text"; payload.sourceText = await qdFileToText(f); }
  }
  var envVars = [];
  Array.from(document.querySelectorAll("#qdEnvList .qd-env-name")).forEach(function(inp, i){
    var n = inp.value.trim();
    if(n) envVars.push({ name: n, value: document.querySelectorAll("#qdEnvList .qd-env-val")[i].value });
  });
  if(envVars.length) payload.envVars = envVars;
  var kvList = [];
  Array.from(document.querySelectorAll("#qdKvList > div")).forEach(function(row){
    var sel = row.querySelector(".qd-kv-sel"), nw = row.querySelector(".qd-kv-new"), bn = row.querySelector(".qd-kv-bind");
    var ns = (nw.value.trim() || sel.value || "").trim();
    if(ns) kvList.push({ nsName: ns, bindName: bn.value.trim() });
  });
  if(kvList.length) payload.kvList = kvList;
  var d1List = [];
  Array.from(document.querySelectorAll("#qdD1List > div")).forEach(function(row){
    var sel = row.querySelector(".qd-d1-sel"), nw = row.querySelector(".qd-d1-new"), bn = row.querySelector(".qd-d1-bind");
    var n = (nw.value.trim() || sel.value || "").trim();
    if(n) d1List.push({ name: n, bindName: bn.value.trim() });
  });
  if(d1List.length) payload.d1List = d1List;
  var host = el("qdHostname").value.trim();
  if(host) payload.hostname = host;
  payload.assignDomain = el("qdAssignDomain").checked;
  var btn = el("qdDeployBtn");
  btn.disabled = true; btn.textContent = "部署中...";
  el("qdStatus").textContent = "正在部署，请稍候...";
  try {
    var r = await api("quick-deploy", payload);
    if(r && r.success){
      el("qdStatus").textContent = (r.notes || []).join("；");
      showNotification("部署成功");
      setTimeout(function(){ closeQuickDeploy(); refreshWorkers(); }, 1500);
    } else {
      el("qdStatus").textContent = "";
      showNotification((r && r.error) || "部署失败", "error");
    }
  } catch(e){ showNotification("请求失败", "error"); }
  btn.disabled = false; btn.textContent = "开始部署";
}
window.openQuickDeploy = openQuickDeploy; window.closeQuickDeploy = closeQuickDeploy;
window.qdSwitchSrc = qdSwitchSrc; window.qdAutoHostname = qdAutoHostname; window.confirmQuickDeploy = confirmQuickDeploy;
// ---- 一键部署：Pages 独立弹窗 ----
function ensureQuickDeployPagesModal(){
  if(el("quickDeployPagesModal")) return;
  var h = '<div id="quickDeployPagesModal" class="modal"><div class="modal-box">'
    + '<div style="display:flex;justify-content:space-between;align-items:center"><h3 style="margin:0">一键部署</h3>'
    + '<span style="cursor:pointer;font-size:18px;color:#94a3b8" onclick="closeQuickDeployPages()">&#10005;</span></div>'
    + '<div class="small" style="margin:8px 0 14px">账号里已有同名 Pages 项目会自动转为更新（重新部署），没有则新建</div>'
    + '<div class="label">代码来源</div>'
    + '<div style="display:flex;gap:18px;margin-bottom:10px;font-size:13px">'
    + '<label style="cursor:pointer"><input type="radio" name="qdPagesSrc" value="url" checked onchange="qdPagesSwitchSrc()"> 直链</label>'
    + '<label style="cursor:pointer"><input type="radio" name="qdPagesSrc" value="file" onchange="qdPagesSwitchSrc()"> 上传</label>'
    + '</div>'
    + '<div id="qdPagesSrcUrl"><input id="qdPagesUrl" class="input" placeholder=".zip 直链"></div>'
    + '<div id="qdPagesSrcFile" style="display:none"><input type="file" id="qdPagesFiles" multiple class="input"><div class="small" style="margin-top:4px">可多选文件；单个 .zip 包会自动解包</div></div>'
    + '<div class="label" style="margin-top:14px">项目名</div>'
    + '<input id="qdPagesName" class="input" placeholder="例如: my-site" oninput="qdPagesAutoHostname()">'
    + '<div class="small" style="margin-top:4px">仅小写字母、数字、连字符；已有同名则转为更新</div>'
    + '<div class="label" style="margin-top:14px">分支</div>'
    + '<input id="qdPagesBranch" class="input" placeholder="main" style="max-width:200px">'
    + '<div class="label" style="margin-top:14px">环境变量 <span class="small">（可选）</span></div>'
    + '<div id="qdPagesEnvList"></div>'
    + '<button class="btn small" style="margin-top:6px" onclick="qdPagesAddEnvRow()">+ 添加变量</button>'
    + '<div class="label" style="margin-top:14px">KV 绑定 <span class="small">（可选）</span></div>'
    + '<div id="qdPagesKvList"></div>'
    + '<div style="margin-top:6px"><button class="btn small" onclick="qdPagesAddKvRow()">+ 添加 KV</button></div>'
    + '<div class="small" style="margin-top:4px">下拉选择已有命名空间；没有想要的就在右侧输入新名称，会自动创建</div>'
    + '<div class="label" style="margin-top:14px">D1 数据库 <span class="small">（可选）</span></div>'
    + '<div id="qdPagesD1List"></div>'
    + '<div style="margin-top:6px"><button class="btn small" onclick="qdPagesAddD1Row()">+ 添加 D1</button></div>'
    + '<div class="small" style="margin-top:4px">下拉选择已有数据库；没有想要的就在右侧输入新名称，会自动创建并绑定</div>'
    + '<div class="label" style="margin-top:14px">项目域名 <span class="small">（可选）</span></div>'
    + '<input id="qdPagesHostname" class="input" placeholder="留空则自动生成：项目名.所选域名" oninput="this.dataset.manual=\'1\'">'
    + '<div class="label" style="margin-top:14px">域名列表</div>'
    + '<select id="qdPagesZone" class="input" onchange="qdPagesAutoHostname()"><option value="">不绑定域名</option></select>'
    + '<div class="small" style="margin-top:4px">账号接入的 CF 域名，选定后自动生成上方未填写的域名</div>'
    + '<div id="qdPagesStatus" class="small" style="margin-top:12px;color:#1e40af"></div>'
    + '<div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" id="qdPagesDeployBtn" onclick="confirmQuickDeployPages()">开始部署</button><button class="btn" onclick="closeQuickDeployPages()">取消</button></div>'
    + '</div></div>';
  document.body.insertAdjacentHTML("beforeend", h);
}
function openQuickDeployPages(){
  ensureQuickDeployPagesModal();
  el("qdPagesName").value = ""; el("qdPagesUrl").value = ""; el("qdPagesBranch").value = "";
  el("qdPagesFiles").value = ""; el("qdPagesStatus").textContent = "";
  el("qdPagesEnvList").innerHTML = ""; el("qdPagesKvList").innerHTML = ""; el("qdPagesD1List").innerHTML = "";
  el("qdPagesHostname").value = ""; el("qdPagesHostname").dataset.manual = "";
  document.querySelector('input[name="qdPagesSrc"][value="url"]').checked = true; qdPagesSwitchSrc();
  el("quickDeployPagesModal").style.display = "flex";
  qdLoadKvOptions(); qdLoadD1Options(); qdPagesLoadZones();
}
// ---- Pages 一键部署：环境变量/KV/D1/域名 ----
function qdPagesAddEnvRow(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px";
  d.innerHTML = '<input class="input qd-env-name" placeholder="变量名" style="flex:1"><input class="input qd-env-val" placeholder="值" style="flex:2"><button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdPagesEnvList").appendChild(d);
}
function qdPagesAddKvRow(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px;align-items:center";
  d.innerHTML = '<select class="input qd-kv-sel" style="flex:2;min-width:140px" onchange="qdToggleKvRow(this)"><option value="">— 下拉选择已有 —</option></select>'
    + '<input class="input qd-kv-new" placeholder="或输入新名称，自动创建" style="flex:2;min-width:140px">'
    + '<input class="input qd-kv-bind" placeholder="绑定名(留空自动)" style="flex:1;min-width:90px;display:none">'
    + '<button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdPagesKvList").appendChild(d);
  qdRefreshKvSelects();
}
function qdPagesAddD1Row(){
  var d = document.createElement("div");
  d.style.cssText = "display:flex;gap:8px;margin-top:6px;align-items:center";
  d.innerHTML = '<select class="input qd-d1-sel" style="flex:2;min-width:140px" onchange="qdToggleD1Row(this)"><option value="">— 下拉选择已有 —</option></select>'
    + '<input class="input qd-d1-new" placeholder="或输入新名称，自动创建并绑定" style="flex:2;min-width:140px">'
    + '<input class="input qd-d1-bind" placeholder="绑定名(留空自动)" style="flex:1;min-width:90px;display:none">'
    + '<button class="btn small" onclick="this.parentNode.remove()">✕</button>';
  el("qdPagesD1List").appendChild(d);
  qdRefreshD1Selects();
}
async function qdPagesLoadZones(){
  var sel = el("qdPagesZone");
  sel.innerHTML = '<option value="">不绑定域名</option>';
  try {
    var r = await api("list-zones", {});
    (r.result || []).forEach(function(z){
      var o = document.createElement("option"); o.value = z.name; o.textContent = z.name; sel.appendChild(o);
    });
  } catch(e){}
}
function qdPagesAutoHostname(){
  var hostEl = el("qdPagesHostname");
  if(hostEl.dataset.manual === "1") return;
  var zone = el("qdPagesZone").value;
  var name = el("qdPagesName").value.trim().toLowerCase().replace(/[^a-z0-9-]/g, "");
  hostEl.value = (zone && name) ? (name + "." + zone) : "";
}
window.qdPagesAddEnvRow = qdPagesAddEnvRow; window.qdPagesAddKvRow = qdPagesAddKvRow;
window.qdPagesAddD1Row = qdPagesAddD1Row; window.qdPagesLoadZones = qdPagesLoadZones;
window.qdPagesAutoHostname = qdPagesAutoHostname;
function closeQuickDeployPages(){ el("quickDeployPagesModal").style.display = "none"; }
function qdPagesSwitchSrc(){
  var v = document.querySelector('input[name="qdPagesSrc"]:checked').value;
  el("qdPagesSrcUrl").style.display = v === "url" ? "" : "none";
  el("qdPagesSrcFile").style.display = v === "file" ? "" : "none";
}
function qdReadFilesAsBase64(files){
  return Promise.all(Array.from(files).map(function(f){
    return new Promise(function(res, rej){
      var r = new FileReader();
      r.onload = function(){ var s = String(r.result); res({ path: "/" + (f.webkitRelativePath || f.name), content: s.slice(s.indexOf(",") + 1) }); };
      r.onerror = rej; r.readAsDataURL(f);
    });
  }));
}
async function confirmQuickDeployPages(){
  var name = el("qdPagesName").value.trim().toLowerCase();
  if(!name) return showNotification("请输入项目名", "error");
  if(!/^[a-z0-9][a-z0-9-]*$/.test(name) || name.length > 63) return showNotification("项目名不合法：仅小写字母、数字、连字符", "error");
  var src = document.querySelector('input[name="qdPagesSrc"]:checked').value;
  var payload = { accountId: currentAccountId, projectName: name, branch: el("qdPagesBranch").value.trim() || "main" };
  var envVars = [];
  Array.from(document.querySelectorAll("#qdPagesEnvList > div")).forEach(function(row){
    var n = row.querySelector(".qd-env-name").value.trim(), v = row.querySelector(".qd-env-val").value;
    if(n) envVars.push({ name: n, value: v });
  });
  if(envVars.length) payload.envVars = envVars;
  var kvList = [];
  Array.from(document.querySelectorAll("#qdPagesKvList > div")).forEach(function(row){
    var sel = row.querySelector(".qd-kv-sel"), nw = row.querySelector(".qd-kv-new"), bn = row.querySelector(".qd-kv-bind");
    var n = (nw.value.trim() || sel.value || "").trim();
    if(n) kvList.push({ name: n, bindName: bn.value.trim() });
  });
  if(kvList.length) payload.kvList = kvList;
  var d1List = [];
  Array.from(document.querySelectorAll("#qdPagesD1List > div")).forEach(function(row){
    var sel = row.querySelector(".qd-d1-sel"), nw = row.querySelector(".qd-d1-new"), bn = row.querySelector(".qd-d1-bind");
    var n = (nw.value.trim() || sel.value || "").trim();
    if(n) d1List.push({ name: n, bindName: bn.value.trim() });
  });
  if(d1List.length) payload.d1List = d1List;
  var host = el("qdPagesHostname").value.trim();
  if(host) payload.hostname = host;
  if(src === "url"){
    var url = el("qdPagesUrl").value.trim();
    if(!url) return showNotification("请输入直链", "error");
    payload.sourceKind = "url"; payload.sourceUrl = url;
  } else {
    var fs = el("qdPagesFiles").files;
    if(!fs || !fs.length) return showNotification("请选择文件", "error");
    if(fs.length === 1 && /\.zip$/i.test(fs[0].name)){
      payload.sourceKind = "b64zip"; payload.sourceB64 = await qdFileToBase64(fs[0]);
    } else {
      payload.sourceKind = "files"; payload.files = await qdReadFilesAsBase64(fs);
    }
  }
  var btn = el("qdPagesDeployBtn");
  btn.disabled = true; btn.textContent = "部署中...";
  el("qdPagesStatus").textContent = "正在部署，请稍候...";
  try {
    var r = await api("quick-deploy-pages", payload);
    if(r && r.success){
      var msg = (r.notes && r.notes.length ? r.notes.join("；") : "Pages 部署成功") + (r.url ? ("；" + r.url) : "");
      el("qdPagesStatus").textContent = msg + (r.warning ? ("；" + r.warning) : "");
      showNotification("部署成功");
      setTimeout(function(){ closeQuickDeployPages(); }, 1500);
    } else {
      el("qdPagesStatus").textContent = "";
      showNotification((r && r.error) || "部署失败", "error");
    }
  } catch(e){ showNotification("请求失败", "error"); }
  btn.disabled = false; btn.textContent = "开始部署";
}
window.openQuickDeployPages = openQuickDeployPages; window.closeQuickDeployPages = closeQuickDeployPages;
window.qdPagesSwitchSrc = qdPagesSwitchSrc; window.confirmQuickDeployPages = confirmQuickDeployPages;
window.editWorker = editWorker; window.deleteWorker = deleteWorker;
// 面板部署历史（localStorage）：用于 Worker 版本回滚
function getWorkerDeployHistory(name){
  try {
    var h = JSON.parse(localStorage.getItem("cfm_worker_history_" + name) || "[]");
    return Array.isArray(h) ? h : [];
  } catch(e){ return []; }
}
function saveWorkerDeployHistory(name, scriptSource){
  try {
    var h = getWorkerDeployHistory(name);
    h.unshift({ time: new Date().toISOString(), source: scriptSource });
    if(h.length > 20) h = h.slice(0, 20);
    localStorage.setItem("cfm_worker_history_" + name, JSON.stringify(h));
  } catch(e){}
}
async function rollbackWorkerToHistory(name, idx){
  var h = getWorkerDeployHistory(name);
  if(!h[idx]) return showNotification("历史记录不存在", "error");
  if(!confirm("回滚 Worker " + name + " 到 " + fmtBJ(h[idx].time) + " 的版本？")) return;
  showNotification("正在回滚...", "warning");
  var r = await api("deploy-worker", { accountId: currentAccountId, scriptName: name, scriptSource: h[idx].source, metadataBindings: [] });
  if(r && r.success){
    showNotification("回滚成功");
    saveWorkerDeployHistory(name, h[idx].source);
    closeVersionsModal(); setTimeout(refreshWorkers, 800);
  } else showNotification((r && r.error) || "回滚失败", "error");
}
window.rollbackWorkerToHistory = rollbackWorkerToHistory;
async function rollbackWorkerVersion(name, versionId){
  if(!confirm("将 Worker " + name + " 回滚到该版本？线上流量将切回此版本。")) return;
  showNotification("正在回滚...", "warning");
  var r = await api("rollback-worker-version", { accountId: currentAccountId, scriptName: name, versionId: versionId });
  if(r && r.success){ showNotification("回滚成功"); closeVersionsModal(); setTimeout(refreshWorkers, 800); }
  else showNotification((r && r.error) || "回滚失败", "error");
}
window.rollbackWorkerVersion = rollbackWorkerVersion;
async function openVersionsFor(name){
  el("versionsSub").textContent = name;
  el("versionsList").innerHTML = "加载中...";
  el("versionsModal").style.display = "flex";
  var r = await api("list-worker-versions", { accountId: currentAccountId, scriptName: name });
  var html = "";
  // 面板部署历史（可回滚）
  var hist = getWorkerDeployHistory(name);
  if(hist.length){
    html += "<h4 style=\"margin:0 0 8px\">面板部署历史 <span class=\"small\" style=\"color:#6b7280\">（可回滚）</span></h4>";
    html += "<table class=\"table\"><thead><tr><th>部署时间</th><th>操作</th></tr></thead><tbody>";
    hist.forEach(function(hh, idx){
      html += "<tr><td>" + esc(fmtBJ(hh.time)) + "</td><td><button class=\"btn small\" onclick=\"rollbackWorkerToHistory('" + escA(name) + "', " + idx + ")\">回滚</button></td></tr>";
    });
    html += "</tbody></table><div style=\"height:16px\"></div>";
  } else {
    html += "<div class=\"small\" style=\"color:#6b7280;margin-bottom:12px\">暂无面板部署历史（通过面板部署后会自动记录，可回滚）</div>";
  }
  // Cloudflare 版本列表（仅展示）
  html += "<h4 style=\"margin:0 0 8px\">Cloudflare 版本记录</h4>";
  if(!r || !r.success){ html += "<div class=\"small\">" + esc((r && r.error) || "获取失败") + "</div>"; }
  else {
    var vers = r.result || [];
    // 获取当前线上版本，用于标记
    var curVid = "";
    try {
      var rc = await api("get-worker-current-version", { accountId: currentAccountId, scriptName: name });
      if(rc && rc.success && rc.currentVersionId) curVid = rc.currentVersionId;
    } catch(e){}
    if(!vers.length){ html += "<div class=\"small\">暂无版本记录</div>"; }
    else {
      html += "<table class=\"table\"><thead><tr><th>版本 ID</th><th>创建时间</th><th>兼容日期</th><th>状态</th><th>操作</th></tr></thead><tbody>";
      vers.forEach(function(v){
        var vid = v.id || "";
        var isCur = curVid && vid === curVid;
        html += "<tr><td style=\"font-family:monospace;font-size:11px\">" + esc(vid) + "</td><td>" + esc(fmtBJ(v.created_on)) + "</td><td>" + esc(v.compatibility_date || v.compatibilityDate || "-") + "</td><td>" + (isCur ? "<span class=\"pill green\">当前</span>" : "") + "</td><td>" + (isCur ? "" : "<button class=\"btn small\" onclick=\"rollbackWorkerVersion('" + escA(name) + "', '" + escA(vid) + "')\">回滚</button>") + "</td></tr>";
      });
      html += "</tbody></table><div class=\"small\" style=\"color:#6b7280;margin-top:8px\">回滚将把线上流量切回所选版本（100%），无需重新上传代码</div>";
    }
  }
  el("versionsList").innerHTML = html;
}
window.openVersionsFor = openVersionsFor;
window.closeVersionsModal = function(){ el("versionsModal").style.display = "none"; };
var currentCompatWorker = "";
var selectedCompatDate = "";
var COMPAT_DATE_LIST = [
  { date: "2026-09-11", changes: ["新建项目的默认兼容日期"] },
  { date: "2026-08-04", changes: ["Node.js 兼容默认启用 (nodejs_compat / nodejs_compat_v2)"] },
  { date: "2026-01-29", changes: ["Node.js stub 模块支持"] },
  { date: "2026-01-22", changes: ["require_returns_default_export"] },
  { date: "2026-01-20", changes: ["rpc_params_dup_stubs：RPC 参数中的 stub 改为复制而非转移所有权"] },
  { date: "2024-09-23", changes: ["nodejs_compat v2 自动启用"] },
  { date: "2022-03-21", changes: ["首个兼容日期"] }
];
async function openCompatModal(name){
  currentCompatWorker = name; selectedCompatDate = "";
  el("compatDateInput").value = "";
  el("compatModal").style.display = "flex";
  el("compatCurrentVal").textContent = "";
  renderCompatDateList("");
  try{
    var r = await api("list-worker-versions", { accountId: currentAccountId, scriptName: name });
    var vers = (r && r.result) || [];
    var cd = vers.length ? (vers[0].compatibility_date || vers[0].compatibilityDate || "") : "";
    var m = String(cd).match(/^(\d{4}-\d{2}-\d{2})/);
    if(m){ selectedCompatDate = m[1]; el("compatDateInput").value = m[1]; el("compatCurrentVal").textContent = "（当前: " + m[1] + "）"; renderCompatDateList(m[1]); }
  }catch(e){}
}
function renderCompatDateList(activeDate){
  var html = "";
  COMPAT_DATE_LIST.forEach(function(item){
    var isActive = item.date === activeDate;
    html += "<div data-cdate=\"" + item.date + "\" style=\"border:1px solid " + (isActive ? "#2563eb" : "#e6edf3") + ";border-radius:8px;padding:12px;margin-bottom:8px;cursor:pointer;background:" + (isActive ? "#eff6ff" : "#fff") + "\">";
    html += "<div style=\"font-weight:600;font-size:14px\">\uD83D\uDCC5 " + esc(item.date) + "</div>";
    item.changes.forEach(function(c){ html += "<div class=\"small\" style=\"margin-top:4px\">\u2022 " + esc(c) + "</div>"; });
    html += "</div>";
  });
  el("compatDateList").innerHTML = html;
  var _box = el("compatDateList");
  Array.from(_box.querySelectorAll("[data-cdate]")).forEach(function(d){
    d.addEventListener("click", function(){ selectCompatDate(this.getAttribute("data-cdate")); });
  });
}
function selectCompatDate(d){
  selectedCompatDate = d;
  el("compatDateInput").value = d;
  renderCompatDateList(d);
}
function closeCompatModal(){ el("compatModal").style.display = "none"; currentCompatWorker = ""; selectedCompatDate = ""; }
async function confirmCompatDate(){
  var d = (selectedCompatDate || el("compatDateInput").value || "").trim();
  if(!d) return showNotification("请选择兼容日期", "error");
  if(!/^\d{4}-\d{2}-\d{2}$/.test(d)) return showNotification("日期格式不正确，应为 YYYY-MM-DD", "error");
  var _dt = new Date(d + "T00:00:00Z");
  if(isNaN(_dt.getTime()) || _dt.toISOString().slice(0, 10) !== d) return showNotification("不是合法的日历日期", "error");
  showNotification("正在保存兼容日期...", "success");
  var r = await api("set-worker-compatibility", { accountId: currentAccountId, scriptName: currentCompatWorker, compatibilityDate: d });
  if(r && r.success){ showNotification("兼容日期已更新为 " + d); closeCompatModal(); setTimeout(refreshWorkers, 800); }
  else showNotification((r && r.error) || "更新失败", "error");
}
window.openCompatModal = openCompatModal; window.closeCompatModal = closeCompatModal; window.confirmCompatDate = confirmCompatDate; window.selectCompatDate = selectCompatDate;
var currentCompatFlagsWorker = "";
var selectedCompatFlags = [];
var COMPAT_FLAGS_LIST = [
  "nodejs_compat", "nodejs_compat_v2", "no_nodejs_compat",
  "python_workers", "python_workers_314", "python_process_pth_files",
  "export_commonjs_default", "require_returns_default_export",
  "throw_on_not_implemented_tls_options", "no_throw_on_not_implemented_tls_options",
  "streams_enable_constructors", "transformstream_enable_standard_constructor",
  "durable_object_alarms", "durable_object_evictable",
  "durable_object_io_tasks_prevent_eviction", "durable_object_io_tasks_do_not_prevent_eviction",
  "web_socket_compression", "fetch_refuses_unknown_protocols",
  "formdata_parser_supports_files", "html_rewriter_treats_esi_include_as_void_tag"
];
async function openCompatFlagsModal(name){
  currentCompatFlagsWorker = name; selectedCompatFlags = [];
  el("compatFlagsCustom").value = "";
  el("compatFlagsModal").style.display = "flex";
  el("compatFlagsCurrent").textContent = "";
  renderCompatFlagsList();
  try{
    var r = await api("get-worker-settings", { accountId: currentAccountId, scriptName: name });
    var flags = (r && r.result && r.result.compatibility_flags) || [];
    if(Array.isArray(flags) && flags.length){
      selectedCompatFlags = flags.slice();
      el("compatFlagsCurrent").textContent = "（当前: " + flags.join(", ") + "）";
      renderCompatFlagsList();
    }
  }catch(e){}
}
function renderCompatFlagsList(){
  var html = "";
  var allFlags = COMPAT_FLAGS_LIST.slice();
  selectedCompatFlags.forEach(function(f){ if(allFlags.indexOf(f) < 0) allFlags.push(f); });
  allFlags.forEach(function(f){
    var on = selectedCompatFlags.indexOf(f) >= 0;
    html += "<label style=\"display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid " + (on ? "#2563eb" : "#e6edf3") + ";border-radius:8px;margin-bottom:6px;cursor:pointer;background:" + (on ? "#eff6ff" : "#fff") + "\">";
    html += "<input type=\"checkbox\" data-cflag=\"" + escA(f) + "\"" + (on ? " checked" : "") + " onchange=\"toggleCompatFlag(this)\">";
    html += "<span style=\"font-family:monospace;font-size:13px\">" + esc(f) + "</span></label>";
  });
  el("compatFlagsList").innerHTML = html || "<div class=\"small\">无可用标志</div>";
}
function toggleCompatFlag(cb){
  var f = cb.getAttribute("data-cflag");
  var i = selectedCompatFlags.indexOf(f);
  if(cb.checked && i < 0) selectedCompatFlags.push(f);
  else if(!cb.checked && i >= 0) selectedCompatFlags.splice(i, 1);
  renderCompatFlagsList();
}
function addCustomCompatFlag(){
  var f = el("compatFlagsCustom").value.trim();
  if(!f) return;
  if(selectedCompatFlags.indexOf(f) < 0) selectedCompatFlags.push(f);
  el("compatFlagsCustom").value = "";
  renderCompatFlagsList();
}
function closeCompatFlagsModal(){ el("compatFlagsModal").style.display = "none"; currentCompatFlagsWorker = ""; selectedCompatFlags = []; }
async function confirmCompatFlags(){
  showNotification("正在保存兼容性标志...", "success");
  var r = await api("set-worker-compat-flags", { accountId: currentAccountId, scriptName: currentCompatFlagsWorker, flags: selectedCompatFlags });
  if(r && r.success){ showNotification("兼容性标志已更新"); closeCompatFlagsModal(); setTimeout(refreshWorkers, 800); }
  else showNotification((r && r.error) || "更新失败", "error");
}
window.openCompatFlagsModal = openCompatFlagsModal; window.closeCompatFlagsModal = closeCompatFlagsModal;
window.confirmCompatFlags = confirmCompatFlags; window.toggleCompatFlag = toggleCompatFlag; window.addCustomCompatFlag = addCustomCompatFlag;
var currentCronWorker = "";
var currentCrons = [];
var cronActiveTab = "schedule";
async function openCronModal(name){
  currentCronWorker = name; currentCrons = []; cronActiveTab = "schedule";
  el("cronWorkerName").textContent = name;
  el("cronModal").style.display = "flex";
  el("cronList").innerHTML = "加载中...";
  switchCronTab("schedule");
  updateCronPreview();
  try{
    var r = await api("get-worker-schedules", { accountId: currentAccountId, scriptName: name });
    if(r && r.success && r.result) currentCrons = r.result.map(function(s){ return typeof s === "string" ? s : (s.cron || ""); }).filter(function(c){ return !!c; });
  }catch(e){}
  renderCronList();
}
function closeCronModal(){ el("cronModal").style.display = "none"; currentCronWorker = ""; currentCrons = []; }
function switchCronTab(tab){
  cronActiveTab = tab;
  document.querySelectorAll("#cronModal [data-crontab]").forEach(function(e){ e.classList.toggle("active", e.getAttribute("data-crontab") === tab); });
  el("cron-schedule").style.display = tab === "schedule" ? "block" : "none";
  el("cron-expr").style.display = tab === "expr" ? "block" : "none";
  el("cronWeekDay").style.display = (tab === "schedule" && el("cronFreq").value === "weeks") ? "block" : "none";
  updateCronPreview();
}
function buildCronFromSchedule(){
  var freq = el("cronFreq").value;
  var val = parseInt(el("cronFreqVal").value, 10) || 1;
  if(val < 1) val = 1;
  if(freq === "minutes"){ if(val > 59) val = 59; return "*/" + val + " * * * *"; }
  if(freq === "hours"){ if(val > 23) val = 23; return "0 */" + val + " * * *"; }
  if(freq === "days"){ if(val > 31) val = 31; return "0 0 */" + val + " * *"; }
  if(freq === "weeks"){ var dow = el("cronWeekDaySel").value; return "0 0 * * " + dow; }
  if(freq === "months"){ if(val > 31) val = 31; return "0 0 " + val + " * *"; }
  return "*/30 * * * *";
}
function getCurrentCron(){
  if(cronActiveTab === "expr"){ return el("cronExprInput").value.trim(); }
  return buildCronFromSchedule();
}
function parseCronField(f, min, max){
  var vals = {};
  if(f === "*") return null;
  var parts = f.split(",");
  for(var i = 0; i < parts.length; i++){
    var p = parts[i];
    var step = 1;
    if(p.indexOf("/") >= 0){ var sp = p.split("/"); p = sp[0]; step = parseInt(sp[1], 10) || 1; }
    var s = min, e = max;
    if(p === "*"){ s = min; e = max; }
    else if(p.indexOf("-") >= 0){ var r = p.split("-"); s = parseInt(r[0], 10); e = parseInt(r[1], 10); }
    else if(p !== ""){ s = e = parseInt(p, 10); }
    if(isNaN(s) || isNaN(e)) return false;
    for(var v = s; v <= e; v += step){ if(v >= min && v <= max) vals[v] = true; }
  }
  return vals;
}
function nextCronTimes(cron, count){
  var fields = cron.trim().split(/\s+/);
  if(fields.length !== 5) return null;
  var mi = parseCronField(fields[0], 0, 59);
  var hr = parseCronField(fields[1], 0, 23);
  var dy = parseCronField(fields[2], 1, 31);
  var mo = parseCronField(fields[3], 1, 12);
  var wd = parseCronField(fields[4], 0, 7);
  if(mi === false || hr === false || dy === false || mo === false || wd === false) return null;
  if(wd && wd[7]) wd[0] = true;
  var out = [];
  var d = new Date();
  d.setUTCSeconds(0, 0);
  d.setUTCMinutes(d.getUTCMinutes() + 1);
  var guard = 0;
  while(out.length < count && guard < 525600){
    guard++;
    var ok = true;
    if(mi && !mi[d.getUTCMinutes()]) ok = false;
    if(ok && hr && !hr[d.getUTCHours()]) ok = false;
    if(ok && mo && !mo[d.getUTCMonth() + 1]) ok = false;
    var domMatch = !dy || dy[d.getUTCDate()];
    var dowMatch = !wd || wd[d.getUTCDay()];
    if(ok){
      if(dy && wd){ ok = domMatch || dowMatch; }
      else if(dy){ ok = domMatch; }
      else if(wd){ ok = dowMatch; }
    }
    if(ok) out.push(new Date(d.getTime()));
    d.setUTCMinutes(d.getUTCMinutes() + 1);
  }
  return out;
}
function fmtUTC(d){
  var days = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
  var months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  function p(n){ return (n < 10 ? "0" : "") + n; }
  return days[d.getUTCDay()] + ", " + p(d.getUTCDate()) + " " + months[d.getUTCMonth()] + " " + d.getUTCFullYear() + " " + p(d.getUTCHours()) + ":" + p(d.getUTCMinutes()) + ":00";
}
function updateCronPreview(){
  var cron = getCurrentCron();
  el("cronPreviewExpr").textContent = cron || "-";
  el("cronFreq").onchange = function(){ el("cronWeekDay").style.display = el("cronFreq").value === "weeks" ? "block" : "none"; updateCronPreview(); };
  if(!cron){ el("cronPreview").innerHTML = "<span style=\"color:#ef4444\">请输入 Cron 表达式</span>"; return; }
  var times = nextCronTimes(cron, 5);
  if(!times){ el("cronPreview").innerHTML = "<span style=\"color:#ef4444\">表达式格式不正确</span>"; return; }
  if(!times.length){ el("cronPreview").innerHTML = "<span style=\"color:#ef4444\">未来一年内无匹配时间</span>"; return; }
  var html = "";
  times.forEach(function(t){ html += "<div>\u2022 " + esc(fmtUTC(t)) + "</div>"; });
  el("cronPreview").innerHTML = html;
}
function renderCronList(){
  if(!currentCrons.length){ el("cronList").innerHTML = "<div class=\"small\">暂无触发器</div>"; return; }
  var html = "";
  currentCrons.forEach(function(c, i){
    html += "<div class=\"kv-item\"><code style=\"font-size:13px\">" + esc(c) + "</code><button class=\"trash-btn\" onclick=\"deleteCron(" + i + ")\">删除</button></div>";
  });
  el("cronList").innerHTML = html;
}
async function saveCrons(){
  var crons = currentCrons.map(function(c){ return { cron: c }; });
  var r = await api("set-worker-schedules", { accountId: currentAccountId, scriptName: currentCronWorker, crons: crons });
  return r;
}
async function addCron(){
  var cron = getCurrentCron();
  if(!cron) return showNotification("请输入 Cron 表达式", "error");
  if(!nextCronTimes(cron, 1)) return showNotification("Cron 表达式格式不正确", "error");
  if(currentCrons.indexOf(cron) >= 0) return showNotification("该触发器已存在", "error");
  currentCrons.push(cron);
  var r = await saveCrons();
  if(r && r.success){ showNotification("Cron 触发器已添加: " + cron); renderCronList(); el("cronExprInput").value = ""; }
  else { currentCrons.pop(); showNotification((r && r.error) || "添加失败", "error"); }
}
async function deleteCron(i){
  var removed = currentCrons.splice(i, 1);
  var r = await saveCrons();
  if(r && r.success){ showNotification("已删除触发器"); renderCronList(); }
  else { currentCrons.splice(i, 0, removed[0]); showNotification((r && r.error) || "删除失败", "error"); }
}
window.openCronModal = openCronModal; window.closeCronModal = closeCronModal; window.switchCronTab = switchCronTab; window.updateCronPreview = updateCronPreview; window.addCron = addCron; window.deleteCron = deleteCron;
var currentWorkerForEnv = "";
async function openEnvFor(name){
  currentWorkerForEnv = name; el("envModal").style.display = "flex";
  el("envRows").innerHTML = "加载中...";
  var r = await api("get-worker-variables", { accountId: currentAccountId, scriptName: name });
  el("envRows").innerHTML = "";
  if(r && r.success && r.result && r.result.vars && r.result.vars.length){ r.result.vars.forEach(function(v){ addEnvRow(v.name, v.type || "plain_text", v.value || ""); }); }
  else addEnvRow();
}
function addEnvRow(name, type, value){
  name = name || ""; type = type || "plain_text"; value = value || "";
  var div = document.createElement("div");
  div.style.cssText = "display:flex;gap:8px;margin-top:8px;align-items:center";
  div.innerHTML = "<input class=\"input env-name\" placeholder=\"变量名\" value=\"" + escA(name) + "\" style=\"flex:2\">" +
    "<select class=\"input env-type\" style=\"width:130px\"><option value=\"plain_text\">文本</option><option value=\"secret_text\">密钥</option><option value=\"json\">JSON</option></select>" +
    "<textarea class=\"input env-value\" placeholder=\"变量值\" style=\"flex:3;min-height:60px;resize:vertical\">" + esc(value) + "</textarea>" +
    "<button class=\"btn danger\">删除</button>";
  var sel = div.querySelector("select"), ta = div.querySelector("textarea");
  sel.value = type;
  function syncPh(){ ta.placeholder = (sel.value === "secret_text") ? "留空则保持不变" : "变量值"; }
  sel.addEventListener("change", syncPh); syncPh();
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("envRows").appendChild(div);
}
async function saveEnv(){
  var rows = Array.from(el("envRows").children); var vars = [];
  for(var i = 0; i < rows.length; i++){
    var nm = rows[i].querySelector(".env-name").value.trim();
    var tp = rows[i].querySelector(".env-type").value;
    var vv = rows[i].querySelector(".env-value").value;
    if(!nm) continue;
    if(tp === "secret_text" && !vv){ vars.push({ name: nm, type: tp, value: "" }); continue; } // 密钥留空=保持不变（传空名占位，后端不删）
    if(tp === "json"){ try { JSON.parse(vv); } catch(e){ showNotification("变量「" + nm + "」的 JSON 格式不正确：" + e.message, "error"); return; } }
    vars.push({ name: nm, type: tp, value: vv });
  }
  var r = await api("put-worker-variables", { accountId: currentAccountId, scriptName: currentWorkerForEnv, variables: vars });
  if(r && r.success){ showNotification("环境变量已保存"); el("envModal").style.display = "none"; refreshWorkers(); }
  else { showNotification((r && r.error) || "保存失败", "error"); debugOut(r); }
}
window.openEnvFor = openEnvFor; window.addEnvRow = addEnvRow; window.saveEnv = saveEnv;
window.closeEnvModal = function(){ el("envModal").style.display = "none"; };
var currentBindType = "kv", currentWorkerForBind = "";
function openBindFor(name){ currentWorkerForBind = name; el("bindModal").style.display = "flex"; refreshBindList(); }
function closeBindModal(){ el("bindModal").style.display = "none"; }
async function refreshBindList(){
  var type = el("bindType").value; currentBindType = type;
  el("bindSelect").innerHTML = "<option value=\"\">加载中...</option>";
  try {
    var r, arr = [];
    if(type === "kv"){ r = await api("list-kv-namespaces", { accountId: currentAccountId }); arr = r.result || [];
      el("bindSelect").innerHTML = arr.length ? "" : "<option value=\"\">未找到 KV 命名空间</option>";
      arr.forEach(function(ns){ var o = document.createElement("option"); o.value = ns.id; o.textContent = (ns.title || ns.id) + " (" + ns.id + ")"; el("bindSelect").appendChild(o); });
    } else if(type === "d1"){ r = await api("list-d1", { accountId: currentAccountId }); arr = r.result || [];
      el("bindSelect").innerHTML = arr.length ? "" : "<option value=\"\">未找到 D1 数据库</option>";
      arr.forEach(function(db){ var id = db.uuid || db.id; var o = document.createElement("option"); o.value = id; o.textContent = (db.name || id) + " (" + id + ")"; el("bindSelect").appendChild(o); });
    } else { r = await api("list-r2-buckets", { accountId: currentAccountId }); arr = r.result || [];
      el("bindSelect").innerHTML = arr.length ? "" : "<option value=\"\">未找到 R2 存储桶</option>";
      arr.forEach(function(b){ var nm = b.name || b; var o = document.createElement("option"); o.value = nm; o.textContent = nm; el("bindSelect").appendChild(o); });
    }
  } catch(e){ el("bindSelect").innerHTML = "<option value=\"\">加载失败</option>"; }
}
async function confirmBind(){
  var type = currentBindType, ref = el("bindSelect").value;
  var bindName = el("bindName").value.trim() || (type === "kv" ? "MY_KV" : (type === "d1" ? "MY_DB" : "MY_BUCKET"));
  if(!ref) return showNotification("请选择要绑定的资源", "error");
  var newBinding = (type === "kv") ? { type: "kv_namespace", name: bindName, namespace_id: ref }
    : (type === "d1") ? { type: "d1", name: bindName, id: ref }
    : { type: "r2_bucket", name: bindName, bucket_name: ref };
  var sr = await api("get-worker-script", { accountId: currentAccountId, scriptName: currentWorkerForBind });
  var script = (sr && sr.rawScript) ? sr.rawScript : DEFAULT_WORKER_SCRIPT;
  var r = await api("deploy-worker", { accountId: currentAccountId, scriptName: currentWorkerForBind, scriptSource: script, metadataBindings: [newBinding] });
  if(r && r.success){ showNotification("绑定成功"); closeBindModal(); setTimeout(refreshWorkers, 800); }
  else { showNotification((r && r.error) || "绑定失败", "error"); debugOut(r); }
}
window.openBindFor = openBindFor; window.closeBindModal = closeBindModal;
window.refreshBindList = refreshBindList; window.confirmBind = confirmBind;
var batchTemplates = [], batchTemplatesLoaded = false;
function appendBatchLog(msg, color){
  var log = el("batchLog"); var d = document.createElement("div");
  d.style.color = color || "#fff"; d.textContent = "[" + new Date().toLocaleTimeString() + "] " + msg;
  log.appendChild(d); log.scrollTop = log.scrollHeight;
}
function renderBatchPage(){
  var arr = loadSaved(); var list = el("batchAccountList"); list.innerHTML = "";
  if(!arr.length){ list.innerHTML = "<div style=\"padding:10px;color:#999\">请先在登录页添加账号</div>"; return; }
  arr.forEach(function(acc, idx){
    var title = esc(accountTitle(acc));
    var pillCls = acc.mode === "token" ? "blue" : (acc.mode === "oauth" ? "green" : "amber");
    var modeTxt = acc.mode === "token" ? "Token" : (acc.mode === "oauth" ? "OAuth" : "Key");
    var d = document.createElement("div"); d.className = "account-check-item";
    d.innerHTML = "<label style=\"flex:1;cursor:pointer;display:flex;align-items:center\"><input type=\"checkbox\" class=\"batch-acc-chk\" value=\"" + idx + "\" style=\"margin-right:8px\"><span style=\"font-size:13px\">" + title + " <span class=\"pill " + pillCls + "\">" + modeTxt + "</span></span></label>";
    list.appendChild(d);
  });
  clearBatchBindingLists();
  loadBatchTemplateOptions().then(function(){ if(el("batchScriptSourceType").value === "builtin") applyBatchTemplatePreset(true); });
  renderBatchPagesAccounts();
  qdLoadKvOptions(true); qdLoadD1Options(true);
}
window.toggleSelectAllAccounts = function(cb){ document.querySelectorAll(".batch-acc-chk").forEach(function(c){ c.checked = cb.checked; }); };
window.toggleSelectAllPagesAccounts = function(cb){ document.querySelectorAll(".batch-pages-acc-chk").forEach(function(c){ c.checked = cb.checked; }); };
function switchBatchTab(t){
  Array.from(document.querySelectorAll("[data-batchtab]")).forEach(function(x){ x.classList.toggle("active", x.getAttribute("data-batchtab") === t); });
  el("batchWorkerPane").style.display = t === "worker" ? "" : "none";
  el("batchPagesPane").style.display = t === "pages" ? "" : "none";
}
function renderBatchPagesAccounts(){
  var arr = loadSaved(); var list = el("batchPagesAccountList"); if(!list) return; list.innerHTML = "";
  if(!arr.length){ list.innerHTML = "<div style=\"padding:10px;color:#999\">请先在登录页添加账号</div>"; return; }
  arr.forEach(function(acc, idx){
    var title = esc(accountTitle(acc));
    var pillCls = acc.mode === "token" ? "blue" : (acc.mode === "oauth" ? "green" : "amber");
    var modeTxt = acc.mode === "token" ? "Token" : (acc.mode === "oauth" ? "OAuth" : "Key");
    var d = document.createElement("div"); d.className = "account-check-item";
    d.innerHTML = "<label style=\"flex:1;cursor:pointer;display:flex;align-items:center\"><input type=\"checkbox\" class=\"batch-pages-acc-chk\" value=\"" + idx + "\" style=\"margin-right:8px\"><span style=\"font-size:13px\">" + title + " <span class=\"pill " + pillCls + "\">" + modeTxt + "</span></span></label>";
    list.appendChild(d);
  });
}
function toggleBatchPagesSrc(){
  var v = document.querySelector('input[name="batchPagesSrc"]:checked').value;
  el("batchPagesUrlDiv").style.display = v === "url" ? "" : "none";
  el("batchPagesFileDiv").style.display = v === "file" ? "" : "none";
}
function appendBatchPagesLog(msg, color){
  var log = el("batchPagesLog"); if(!log) return;
  var d = document.createElement("div");
  d.style.color = color || "#fff"; d.textContent = "[" + new Date().toLocaleTimeString() + "] " + msg;
  log.appendChild(d); log.scrollTop = log.scrollHeight;
}
window.switchBatchTab = switchBatchTab; window.toggleBatchPagesSrc = toggleBatchPagesSrc;
window.addBatchPagesEnvRow = function(k, v){
  var div = document.createElement("div"); div.className = "env-row-batch";
  div.innerHTML = "<input class=\"input b-penv-key\" placeholder=\"Key\" value=\"" + escA(k || "") + "\" style=\"flex:1\"><input class=\"input b-penv-val\" placeholder=\"Value\" value=\"" + escA(v || "") + "\" style=\"flex:1\"><button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchPagesEnvList").appendChild(div);
};
window.addBatchPagesKvRow = function(){
  var div = document.createElement("div"); div.className = "env-row-batch batch-pkv-row"; div.style.alignItems = "center";
  div.innerHTML = "<select class=\"input qd-kv-sel\" style=\"flex:2;min-width:120px\" onchange=\"qdToggleKvRow(this)\"><option value=\"\">— 下拉选择已有 —</option></select>"
    + "<input class=\"input qd-kv-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:120px\">"
    + "<input class=\"input qd-kv-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:80px;display:none\">"
    + "<button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchPagesKvList").appendChild(div);
  qdRefreshKvSelects();
};
window.addBatchPagesD1Row = function(){
  var div = document.createElement("div"); div.className = "env-row-batch batch-pd1-row"; div.style.alignItems = "center";
  div.innerHTML = "<select class=\"input qd-d1-sel\" style=\"flex:2;min-width:120px\" onchange=\"qdToggleD1Row(this)\"><option value=\"\">— 下拉选择已有 —</option></select>"
    + "<input class=\"input qd-d1-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:120px\">"
    + "<input class=\"input qd-d1-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:80px;display:none\">"
    + "<button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchPagesD1List").appendChild(div);
  qdRefreshD1Selects();
};
window.startBatchPagesCreate = async function(){
  var name = el("batchPagesName").value.trim().toLowerCase();
  if(!name) return alert("请输入项目名");
  if(!/^[a-z0-9][a-z0-9-]*$/.test(name) || name.length > 63) return alert("项目名不合法：仅小写字母、数字、连字符");
  var chks = Array.from(document.querySelectorAll(".batch-pages-acc-chk:checked"));
  if(!chks.length) return alert("请至少选择一个账号");
  var src = document.querySelector('input[name="batchPagesSrc"]:checked').value;
  var payload = { projectName: name, branch: el("batchPagesBranch").value.trim() || "main" };
  if(src === "url"){
    var url = el("batchPagesUrl").value.trim();
    if(!url) return alert("请输入直链");
    payload.sourceKind = "url"; payload.sourceUrl = url;
  } else {
    var fs = el("batchPagesFiles").files;
    if(!fs || !fs.length) return alert("请选择文件");
    appendBatchPagesLog("读取上传文件...", "#9ca3af");
    if(fs.length === 1 && /\.zip$/i.test(fs[0].name)){
      payload.sourceKind = "b64zip"; payload.sourceB64 = await qdFileToBase64(fs[0]);
    } else {
      payload.sourceKind = "files"; payload.files = await qdReadFilesAsBase64(fs);
    }
  }
  var envVars = [];
  el("batchPagesEnvList").querySelectorAll(".env-row-batch").forEach(function(row){
    var k = row.querySelector(".b-penv-key").value.trim(), v = row.querySelector(".b-penv-val").value;
    if(k) envVars.push({ name: k, value: v });
  });
  var kvRows = Array.from(el("batchPagesKvList").querySelectorAll(".batch-pkv-row")).map(function(r){
    var sel = r.querySelector(".qd-kv-sel");
    var nm = (r.querySelector(".qd-kv-new").value.trim() || (sel && sel.value) || "").trim();
    if(!nm) return null;
    return { bindName: r.querySelector(".qd-kv-bind").value.trim(), name: nm };
  }).filter(function(x){ return x; });
  var d1Rows = Array.from(el("batchPagesD1List").querySelectorAll(".batch-pd1-row")).map(function(r){
    var sel = r.querySelector(".qd-d1-sel");
    var nm = (r.querySelector(".qd-d1-new").value.trim() || (sel && sel.value) || "").trim();
    if(!nm) return null;
    return { bindName: r.querySelector(".qd-d1-bind").value.trim(), name: nm };
  }).filter(function(x){ return x; });
  if(envVars.length) payload.envVars = envVars;
  if(kvRows.length) payload.kvList = kvRows;
  if(d1Rows.length) payload.d1List = d1Rows;
  var accounts = loadSaved();
  el("batchPagesLog").innerHTML = "";
  appendBatchPagesLog("开始批量部署 Pages，共 " + chks.length + " 个账号", "#fcd34d");
  for(var ci = 0; ci < chks.length; ci++){
    var acc = accounts[parseInt(chks[ci].value, 10)];
    if(!acc) continue;
    var label = acc.mode === "token" ? (acc.label || "Token") : acc.email;
    appendBatchPagesLog("处理账号: " + label + " ...");
    try {
      var ar = await batchApi(acc, "list-accounts");
      if(!ar.success || !ar.result || !ar.result.length){ appendBatchPagesLog("  获取 AccountID 失败", "#ef4444"); continue; }
      var aid = ar.result[0].id;
      var p = Object.assign({}, payload, { accountId: aid });
      var r = await batchApi(acc, "quick-deploy-pages", p);
      if(r && r.success) appendBatchPagesLog("  " + label + ": 部署成功" + (r.url ? " " + r.url : ""), "#4ade80");
      else appendBatchPagesLog("  " + label + ": 失败 " + ((r && r.error) || ""), "#ef4444");
    } catch(e){ appendBatchPagesLog("  " + label + ": 异常 " + e.message, "#ef4444"); }
  }
  appendBatchPagesLog("批量操作结束", "#fcd34d");
};
function clearBatchBindingLists(){ ["batchEnvList","batchKvList","batchD1List"].forEach(function(id){ if(el(id)) el(id).innerHTML = ""; }); }
async function loadBatchTemplateOptions(force){
  if(batchTemplatesLoaded && !force) return batchTemplates;
  var sel = el("batchBuiltinSelect"); if(sel) sel.innerHTML = "<option value=\"\">加载中...</option>";
  try {
    var res = await api("load-batch-templates-kv");
    if(!res || !res.success) throw new Error((res && res.error) || "读取失败");
    batchTemplates = res.templates || []; batchTemplatesLoaded = true;
    if(sel){ sel.innerHTML = "";
      if(batchTemplates.length){ batchTemplates.forEach(function(t){ var o = document.createElement("option"); o.value = t.key; o.textContent = t.templateName || t.key; sel.appendChild(o); }); }
      else sel.innerHTML = "<option value=\"\">KV 中没有可用模板</option>";
    }
  } catch(e){ batchTemplates = []; if(sel) sel.innerHTML = "<option value=\"\">模板加载失败（需绑定 CF_ACCOUNTS_KV）</option>"; }
  return batchTemplates;
}
function getSelectedBatchTemplate(){ var k = el("batchBuiltinSelect") ? el("batchBuiltinSelect").value : ""; return batchTemplates.find(function(t){ return String(t.key) === String(k); }) || null; }
function applyBatchTemplatePreset(silent){
  var p = getSelectedBatchTemplate(); if(!p) return false;
  el("batchWorkerName").value = p.workerName || "";
  clearBatchBindingLists();
  (p.env || []).forEach(function(x){ addBatchEnvRow(x.key, x.value); });
  (p.kv || []).forEach(function(x){ addBatchKvRow(x.bind, x.name); });
  (p.d1 || []).forEach(function(x){ addBatchD1Row(x.bind, x.name); });
  if(!silent) showNotification("已填充模板：" + p.templateName);
  return true;
}
window.toggleBatchSourceInput = function(){
  var t = el("batchScriptSourceType").value;
  el("batchSourceBuiltinDiv").style.display = (t === "builtin") ? "block" : "none";
  el("batchSourceUrlDiv").style.display = (t === "url") ? "block" : "none";
  el("batchSourceCustomDiv").style.display = (t === "custom") ? "block" : "none";
  if(t === "builtin"){ loadBatchTemplateOptions().then(function(){ applyBatchTemplatePreset(true); }); }
  else { el("batchWorkerName").value = ""; clearBatchBindingLists(); }
  if(t === "custom"){ var s = localStorage.getItem("cfm_custom_script"); if(s && !el("batchCustomScript").value) el("batchCustomScript").value = s; }
};
if(el("batchBuiltinSelect")){ el("batchBuiltinSelect").addEventListener("change", function(){ if(el("batchScriptSourceType").value === "builtin") applyBatchTemplatePreset(); }); }
document.addEventListener("input", function(e){ if(e.target && e.target.id === "batchCustomScript") localStorage.setItem("cfm_custom_script", e.target.value); });
window.saveCustomScriptFile = function(){
  var s = el("batchCustomScript").value; if(!s.trim()) return showNotification("脚本内容为空", "error");
  localStorage.setItem("cfm_custom_script", s);
  var a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([s], { type: "text/javascript" })); a.download = "_worker.js"; a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);
  showNotification("已保存并下载");
};
var WORKER_FILENAMES = ["_worker.js", "worker.js", "index.js", "src/worker.js", "src/index.js"];
function isRawUrl(u){ return u.indexOf("raw.githubusercontent.com") >= 0 || u.indexOf("cdn.jsdelivr.net") >= 0; }
function githubBlobToRaw(u){ var m = u.match(/github\.com\/([^\/]+)\/([^\/]+)\/blob\/([^\/]+)\/(.+)/); return m ? "https://raw.githubusercontent.com/" + m[1] + "/" + m[2] + "/" + m[3] + "/" + m[4] : null; }
function isGithubRepo(u){ return /github\.com\/[^\/]+\/[^\/]+(\/tree\/[^\/]+)?\/?$/.test(u) && u.indexOf("/blob/") < 0 && !isRawUrl(u); }
window.normalizeGithubUrl = function(input){
  var val = input.value.trim(); var hint = el("urlConvertHint");
  if(!val || isRawUrl(val)){ if(hint) hint.style.display = "none"; return; }
  var raw = githubBlobToRaw(val);
  if(raw){ input.value = raw; if(hint){ hint.textContent = "已转换为 raw 链接"; hint.style.display = "block"; } return; }
  if(isGithubRepo(val) && hint){ hint.textContent = "检测到 GitHub 仓库，点击「处理链接」自动查找 _worker.js"; hint.style.display = "block"; }
};
async function resolveScriptUrl(inputUrl){
  if(isRawUrl(inputUrl)) return { url: inputUrl };
  var raw = githubBlobToRaw(inputUrl);
  if(raw) return { url: raw, msg: "blob 链接已转换" };
  if(isGithubRepo(inputUrl)){
    var m = inputUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(?:\/tree\/([^\/]+))?/);
    if(!m) return { url: inputUrl };
    var user = m[1], repo = m[2], branch = m[3] || "main";
    if(!m[3]){ try { var ri = await fetch("https://api.github.com/repos/" + user + "/" + repo); if(ri.ok){ var ij = await ri.json(); branch = ij.default_branch || "main"; } } catch(e){} }
    for(var i = 0; i < WORKER_FILENAMES.length; i++){
      var ru = "https://raw.githubusercontent.com/" + user + "/" + repo + "/" + branch + "/" + WORKER_FILENAMES[i];
      try { var hr = await fetch(ru, { method: "HEAD" }); if(hr.ok) return { url: ru, msg: "找到 " + WORKER_FILENAMES[i] }; } catch(e){}
    }
    return { url: inputUrl, error: "未能在该仓库找到 JS 文件" };
  }
  return { url: inputUrl };
}
window.prepareBatchScriptUrl = async function(){
  var url = el("batchScriptUrl").value.trim(); if(!url) return showNotification("请先输入链接", "error");
  var r = await resolveScriptUrl(url);
  if(r.error) return showNotification(r.error, "error");
  el("batchScriptUrl").value = r.url;
  showNotification(r.msg || "链接可用");
};
window.addBatchEnvRow = function(k, v){
  var div = document.createElement("div"); div.className = "env-row-batch";
  div.innerHTML = "<input class=\"input b-env-key\" placeholder=\"Key\" value=\"" + escA(k || "") + "\" style=\"flex:1\"><input class=\"input b-env-val\" placeholder=\"Value\" value=\"" + escA(v || "") + "\" style=\"flex:1\"><button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchEnvList").appendChild(div);
};
window.addBatchKvRow = function(){
  var div = document.createElement("div"); div.className = "env-row-batch batch-kv-row"; div.style.alignItems = "center";
  div.innerHTML = "<select class=\"input qd-kv-sel\" style=\"flex:2;min-width:120px\" onchange=\"qdToggleKvRow(this)\"><option value=\"\">— 下拉选择已有 —</option></select>"
    + "<input class=\"input qd-kv-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:120px\">"
    + "<input class=\"input qd-kv-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:80px;display:none\">"
    + "<button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchKvList").appendChild(div);
  qdRefreshKvSelects();
};
window.addBatchD1Row = function(){
  var div = document.createElement("div"); div.className = "env-row-batch batch-d1-row"; div.style.alignItems = "center";
  div.innerHTML = "<select class=\"input qd-d1-sel\" style=\"flex:2;min-width:120px\" onchange=\"qdToggleD1Row(this)\"><option value=\"\">— 下拉选择已有 —</option></select>"
    + "<input class=\"input qd-d1-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:120px\">"
    + "<input class=\"input qd-d1-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:80px;display:none\">"
    + "<button class=\"trash-btn\">✕</button>";
  div.querySelector("button").addEventListener("click", function(){ div.remove(); });
  el("batchD1List").appendChild(div);
  qdRefreshD1Selects();
};
function batchAuthFor(acc){
  if(acc.mode === "token") return { authMode: "token", token: acc.token };
  if(acc.mode === "oauth") return { authMode: "oauth", token: acc.access_token };
  return { authMode: "key", email: acc.email, key: acc.key };
}
async function batchApi(acc, action, body){
  var p = batchAuthFor(acc); p.action = action;
  if(body){ for(var k in body) p[k] = body[k]; }
  var r = await fetch("/api", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p) });
  try { return await r.json(); } catch(e){ return { success: false, error: "解析失败" }; }
}
window.startBatchCreate = async function(){
  var name = el("batchWorkerName").value.trim();
  if(!name) return alert("请输入 Worker 名称");
  var chks = Array.from(document.querySelectorAll(".batch-acc-chk:checked"));
  if(!chks.length) return alert("请至少选择一个账号");
  var sourceType = el("batchScriptSourceType").value;
  var scriptUrl = "", customScript = "", tpl = null;
  if(sourceType === "builtin"){ await loadBatchTemplateOptions(); tpl = getSelectedBatchTemplate(); if(!tpl) return alert("请选择有效的 KV 内置模板"); }
  else if(sourceType === "custom"){ customScript = el("batchCustomScript").value.trim(); if(!customScript) return alert("自定义脚本为空"); }
  else { scriptUrl = el("batchScriptUrl").value.trim(); if(!scriptUrl) return alert("请输入脚本链接");
    var rs = await resolveScriptUrl(scriptUrl); if(rs.error) return alert(rs.error); scriptUrl = rs.url; el("batchScriptUrl").value = scriptUrl; }
  var bindings = [];
  el("batchEnvList").querySelectorAll(".env-row-batch").forEach(function(row){
    var k = row.querySelector(".b-env-key").value.trim(), v = row.querySelector(".b-env-val").value;
    if(k) bindings.push({ type: "plain_text", name: k, text: v });
  });
  var kvRows = Array.from(el("batchKvList").querySelectorAll(".batch-kv-row")).map(function(r){
    var sel = r.querySelector(".qd-kv-sel");
    var nm = (r.querySelector(".qd-kv-new").value.trim() || (sel && sel.value) || "").trim();
    if(!nm) return null;
    var bn = r.querySelector(".qd-kv-bind").value.trim();
    var bind = bn || nm.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
    if(/^\d/.test(bind)) bind = '_' + bind;
    if(!bind) bind = 'KV';
    return { bind: bind, name: nm };
  }).filter(function(x){ return x; });
  var d1Rows = Array.from(el("batchD1List").querySelectorAll(".batch-d1-row")).map(function(r){
    var sel = r.querySelector(".qd-d1-sel");
    var nm = (r.querySelector(".qd-d1-new").value.trim() || (sel && sel.value) || "").trim();
    if(!nm) return null;
    var bn = r.querySelector(".qd-d1-bind").value.trim();
    var bind = bn || nm.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
    if(/^\d/.test(bind)) bind = '_' + bind;
    if(!bind) bind = 'DB';
    return { bind: bind, name: nm };
  }).filter(function(x){ return x; });
  var scriptContent = "";
  if(customScript){ scriptContent = customScript.replace(/\bwindow\b/g, "globalThis"); appendBatchLog("使用自定义脚本（" + scriptContent.length + " 字符）", "#60a5fa"); }
  else if(tpl){
    if(tpl.scriptSource){ scriptContent = tpl.scriptSource.replace(/\bwindow\b/g, "globalThis"); appendBatchLog("使用模板内置脚本: " + tpl.templateName, "#60a5fa"); }
    else if(tpl.scriptUrl){ appendBatchLog("获取模板远程脚本...", "#60a5fa");
      var fr = await api("fetch-external-script", { url: tpl.scriptUrl });
      if(!fr.success){ appendBatchLog("脚本获取失败: " + fr.error, "#ef4444"); return; }
      scriptContent = fr.content.replace(/\bwindow\b/g, "globalThis"); appendBatchLog("脚本获取成功", "#4ade80");
    } else { appendBatchLog("模板缺少脚本来源", "#ef4444"); return; }
  } else {
    appendBatchLog("获取远程脚本: " + scriptUrl, "#60a5fa");
    var fr2 = await api("fetch-external-script", { url: scriptUrl });
    if(!fr2.success){ appendBatchLog("脚本获取失败: " + fr2.error, "#ef4444"); return; }
    scriptContent = fr2.content.replace(/\bwindow\b/g, "globalThis"); appendBatchLog("脚本获取成功", "#4ade80");
  }
  if(!scriptContent) return alert("脚本内容为空");
  var accounts = loadSaved();
  el("batchLog").innerHTML = "";
  appendBatchLog("开始批量部署，共 " + chks.length + " 个账号", "#fcd34d");
  var enableSub = el("batchEnableSubdomain").checked;
  for(var ci = 0; ci < chks.length; ci++){
    var acc = accounts[parseInt(chks[ci].value, 10)];
    if(!acc) continue;
    var label = acc.mode === "token" ? (acc.label || "Token") : acc.email;
    appendBatchLog("处理账号: " + label + " ...");
    try {
      var ar = await batchApi(acc, "list-accounts");
      if(!ar.success || !ar.result || !ar.result.length){ appendBatchLog("  获取 AccountID 失败", "#ef4444"); continue; }
      var aid = ar.result[0].id;
      var localBindings = bindings.slice();
      if(kvRows.length){
        var kl = await batchApi(acc, "list-kv-namespaces", { accountId: aid });
        for(var ki = 0; ki < kvRows.length; ki++){
          var kv = kvRows[ki]; appendBatchLog("  检查 KV: " + kv.name, "#9ca3af");
          var tk = (kl.result || []).find(function(x){ return x.title === kv.name; });
          if(!tk){ appendBatchLog("  创建 KV: " + kv.name, "#fbbf24");
            var ck = await batchApi(acc, "create-kv-namespace", { accountId: aid, title: kv.name });
            if(ck.success && ck.result) tk = ck.result; else { appendBatchLog("  KV 创建失败", "#ef4444"); continue; } }
          localBindings.push({ type: "kv_namespace", name: kv.bind, namespace_id: tk.id });
        }
      }
      if(d1Rows.length){
        var dl = await batchApi(acc, "list-d1", { accountId: aid });
        for(var di = 0; di < d1Rows.length; di++){
          var d1 = d1Rows[di]; appendBatchLog("  检查 D1: " + d1.name, "#9ca3af");
          var td = (dl.result || []).find(function(x){ return x.name === d1.name; });
          if(!td){ appendBatchLog("  创建 D1: " + d1.name, "#fbbf24");
            var cd = await batchApi(acc, "create-d1-database", { accountId: aid, name: d1.name });
            if(cd.success && cd.result) td = cd.result; else { appendBatchLog("  D1 创建失败", "#ef4444"); continue; } }
          localBindings.push({ type: "d1", name: d1.bind, id: td.uuid || td.id });
        }
      }
      var dr = await batchApi(acc, "deploy-worker", { accountId: aid, scriptName: name, scriptSource: scriptContent, metadataBindings: localBindings });
      if(dr.success){
        appendBatchLog("  " + label + ": 部署成功", "#4ade80");
        await batchApi(acc, "toggle-worker-subdomain", { accountId: aid, scriptName: name, enabled: enableSub });
        appendBatchLog("  子域名: " + (enableSub ? "开启" : "关闭"), "#9ca3af");
        if(enableSub){
          var sdr = await batchApi(acc, "get-workers-subdomain", { accountId: aid });
          if(sdr.success && sdr.result && sdr.result.subdomain) appendBatchLog("  https://" + name + "." + sdr.result.subdomain + ".workers.dev", "#60a5fa");
        }
      } else appendBatchLog("  " + label + ": " + (dr.error || "失败"), "#ef4444");
    } catch(e){ appendBatchLog("  " + label + ": 异常 " + e.message, "#ef4444"); }
  }
  appendBatchLog("批量操作结束", "#fcd34d");
};
var currentKvNs = null, currentKvTitle = "", kvCursor = null, kvPrefix = "";
async function refreshKVNamespaces(){
  backToKvNamespaces(true);
  el("kvNamespacesList").innerHTML = "加载中...";
  var aid = await ensureAccountId(); if(!aid) return;
  var r = await api("list-kv-namespaces", { accountId: aid });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("kvNamespacesList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无 KV 命名空间</div>"; return; }
  el("kvNamespacesList").innerHTML = "";
  arr.forEach(function(ns){
    var d = document.createElement("div"); d.className = "kv-item";
    d.innerHTML = "<div style=\"flex:1;min-width:0\"><div style=\"font-weight:600\">" + esc(ns.title) + "</div><div class=\"small\" style=\"font-family:monospace;word-break:break-all\">" + esc(ns.id) + "</div></div>" +
      "<div class=\"btns\"><button class=\"btn\" data-a=\"view\" data-id=\"" + escA(ns.id) + "\" data-t=\"" + escA(ns.title) + "\">键值</button>" +
      "<button class=\"btn\" data-a=\"rename\" data-id=\"" + escA(ns.id) + "\" data-t=\"" + escA(ns.title) + "\">重命名</button>" +
      "<button class=\"btn danger\" data-a=\"del\" data-id=\"" + escA(ns.id) + "\">删除</button></div>";
    el("kvNamespacesList").appendChild(d);
  });
  Array.from(el("kvNamespacesList").querySelectorAll("button")).forEach(function(b){
    b.addEventListener("click", function(){
      var a = this.getAttribute("data-a"), id = this.getAttribute("data-id"), t = this.getAttribute("data-t");
      if(a === "view") viewKvKeys(id, t);
      else if(a === "rename") renameKvNamespace(id, t);
      else if(a === "del") deleteKvNamespace(id);
    });
  });
}
function backToKvNamespaces(silent){
  currentKvNs = null; kvCursor = null;
  el("kvKeysSection").style.display = "none";
  if(!silent) refreshKVNamespaces();
}
async function viewKvKeys(nsId, title){
  currentKvNs = nsId; currentKvTitle = title; kvCursor = null; kvPrefix = "";
  el("kvKeyPrefix").value = "";
  el("kvKeysTitle").textContent = "键值管理 - " + title;
  el("kvKeysSection").style.display = "block";
  refreshKvKeys(true);
}
async function refreshKvKeys(reset){
  if(reset){ kvCursor = null; kvPrefix = el("kvKeyPrefix").value.trim(); }
  var aid = await ensureAccountId();
  el("kvKeysList").innerHTML = "加载中...";
  var r = await api("list-kv-keys", { accountId: aid, namespaceId: currentKvNs, limit: 100, cursor: kvCursor, prefix: kvPrefix });
  if(!r || !r.success){ el("kvKeysList").innerHTML = "加载失败：" + esc((r && r.error) || ""); return; }
  var keys = r.result || [];
  kvCursor = (r.result_info && r.result_info.cursor) ? r.result_info.cursor : null;
  el("kvNextPageBtn").style.display = kvCursor ? "inline-block" : "none";
  el("kvPageInfo").textContent = "本页 " + keys.length + " 条" + (r.result_info && r.result_info.count ? ("（总计约 " + r.result_info.count + "）") : "");
  if(!keys.length){ el("kvKeysList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无键</div>"; return; }
  el("kvKeysList").innerHTML = "";
  keys.forEach(function(k){
    var d = document.createElement("div"); d.className = "kv-item";
    d.innerHTML = "<div style=\"flex:1;min-width:0;word-break:break-all;font-family:monospace;font-size:12px\">" + esc(k.name) + (k.expiration ? "<div class=\"small\">过期: " + new Date(k.expiration * 1000).toLocaleString() + "</div>" : "") + "</div>" +
      "<div class=\"btns\"><button class=\"btn small\" data-a=\"view\">查看</button><button class=\"btn small\" data-a=\"edit\">编辑</button><button class=\"btn small danger\" data-a=\"del\">删除</button></div>";
    d.querySelector("[data-a=\"view\"]").addEventListener("click", function(){ viewKvValue(k.name); });
    d.querySelector("[data-a=\"edit\"]").addEventListener("click", function(){ openKvValueModal(k.name); });
    d.querySelector("[data-a=\"del\"]").addEventListener("click", function(){ deleteKvKey(k.name); });
    el("kvKeysList").appendChild(d);
  });
}
function kvNextPage(){ refreshKvKeys(false); }
async function viewKvValue(key){
  var aid = await ensureAccountId();
  var r = await api("get-kv-value", { accountId: aid, namespaceId: currentKvNs, kvKey: key });
  if(r && r.success) debugOut("Key: " + key + "\n\n" + r.value);
  else showNotification("读取失败", "error");
}
async function deleteKvKey(key){
  if(!confirm("删除键 " + key + "？")) return;
  var aid = await ensureAccountId();
  var r = await api("delete-kv-value", { accountId: aid, namespaceId: currentKvNs, kvKey: key });
  if(r && r.success){ showNotification("已删除"); refreshKvKeys(true); } else showNotification("删除失败", "error");
}
async function openKvValueModal(key){
  el("kvKey").value = key || ""; el("kvKey").readOnly = !!key;
  el("kvValue").value = ""; el("kvTtl").value = ""; el("kvExp").value = "";
  el("kvValueModalTitle").textContent = key ? ("编辑键值 - " + key) : "添加键值";
  if(key){ var aid = await ensureAccountId(); var r = await api("get-kv-value", { accountId: aid, namespaceId: currentKvNs, kvKey: key }); if(r && r.success) el("kvValue").value = r.value; }
  el("kvValueModal").style.display = "flex";
}
function closeKVValueModal(){ el("kvValueModal").style.display = "none"; }
async function confirmKVPut(){
  var key = el("kvKey").value.trim(), val = el("kvValue").value;
  if(!key) return showNotification("请输入 Key", "error");
  var aid = await ensureAccountId();
  var r = await api("put-kv-value", { accountId: aid, namespaceId: currentKvNs, kvKey: key, value: val, expiration_ttl: el("kvTtl").value.trim(), expiration: el("kvExp").value.trim() });
  if(r && r.success){ showNotification("已保存"); closeKVValueModal(); refreshKvKeys(true); } else showNotification((r && r.error) || "保存失败", "error");
}
function openCreateKVNamespace(){ el("createKVModal").style.display = "flex"; }
function closeCreateKVModal(){ el("createKVModal").style.display = "none"; }
async function confirmCreateKVNamespace(){
  var t = el("kvNamespaceName").value.trim(); if(!t) return showNotification("请输入名称", "error");
  var aid = await ensureAccountId();
  var r = await api("create-kv-namespace", { accountId: aid, title: t, jurisdiction: el("kvJurisdiction").value });
  if(r && r.success){ showNotification("创建成功"); closeCreateKVModal(); refreshKVNamespaces(); } else showNotification((r && r.error) || "创建失败", "error");
}
async function renameKvNamespace(id, title){
  var nt = prompt("重命名命名空间", title); if(!nt || nt === title) return;
  var aid = await ensureAccountId();
  var r = await api("rename-kv-namespace", { accountId: aid, namespaceId: id, title: nt });
  if(r && r.success){ showNotification("已重命名"); refreshKVNamespaces(); } else showNotification((r && r.error) || "失败", "error");
}
async function deleteKvNamespace(id){
  if(!confirm("删除此命名空间？其下所有键值将丢失，此操作不可逆！")) return;
  var aid = await ensureAccountId();
  var r = await api("delete-kv-namespace", { accountId: aid, namespaceId: id });
  if(r && r.success){ showNotification("已删除"); refreshKVNamespaces(); } else showNotification((r && r.error) || "删除失败", "error");
}
function openKvBulkWrite(){ el("kvBulkWriteInput").value = ""; el("kvBulkWriteModal").style.display = "flex"; }
function closeKvBulkWrite(){ el("kvBulkWriteModal").style.display = "none"; }
async function confirmKvBulkWrite(){
  var items;
  try { items = JSON.parse(el("kvBulkWriteInput").value); if(!Array.isArray(items)) throw new Error("not array"); }
  catch(e){ return showNotification("JSON 数组格式错误", "error"); }
  var aid = await ensureAccountId();
  var r = await api("bulk-write-kv", { accountId: aid, namespaceId: currentKvNs, items: items });
  if(r && r.success){ showNotification("批量写入完成"); closeKvBulkWrite(); refreshKvKeys(true); debugOut(r.result); }
  else showNotification((r && r.error) || "失败", "error");
}
function openKvBulkDelete(){ el("kvBulkDeleteInput").value = ""; el("kvBulkDeleteModal").style.display = "flex"; }
function closeKvBulkDelete(){ el("kvBulkDeleteModal").style.display = "none"; }
async function confirmKvBulkDelete(){
  var keys = el("kvBulkDeleteInput").value.split("\n").map(function(x){ return x.trim(); }).filter(function(x){ return x; });
  if(!keys.length) return showNotification("请输入要删除的 key", "error");
  if(!confirm("确认删除 " + keys.length + " 个键？")) return;
  var aid = await ensureAccountId();
  var r = await api("bulk-delete-kv", { accountId: aid, namespaceId: currentKvNs, keys: keys });
  if(r && r.success){ showNotification("批量删除完成"); closeKvBulkDelete(); refreshKvKeys(true); } else showNotification((r && r.error) || "失败", "error");
}
window.refreshKVNamespaces = refreshKVNamespaces; window.viewKvKeys = viewKvKeys; window.backToKvNamespaces = backToKvNamespaces;
window.refreshKvKeys = refreshKvKeys; window.kvNextPage = kvNextPage; window.openKvValueModal = openKvValueModal;
window.closeKVValueModal = closeKVValueModal; window.confirmKVPut = confirmKVPut;
window.openCreateKVNamespace = openCreateKVNamespace; window.closeCreateKVModal = closeCreateKVModal; window.confirmCreateKVNamespace = confirmCreateKVNamespace;
window.openKvBulkWrite = openKvBulkWrite; window.closeKvBulkWrite = closeKvBulkWrite; window.confirmKvBulkWrite = confirmKvBulkWrite;
window.openKvBulkDelete = openKvBulkDelete; window.closeKvBulkDelete = closeKvBulkDelete; window.confirmKvBulkDelete = confirmKvBulkDelete;
async function refreshD1Databases(){
  el("d1DatabasesList").innerHTML = "加载中...";
  el("d1DatabaseSelect").innerHTML = "<option value=\"\">- 选择数据库 -</option>";
  var aid = await ensureAccountId(); if(!aid) return;
  var r = await api("list-d1", { accountId: aid });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("d1DatabasesList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无 D1 数据库</div>"; return; }
  el("d1DatabasesList").innerHTML = "";
  arr.forEach(function(db){
    var id = db.uuid || db.id;
    var d = document.createElement("div"); d.className = "kv-item";
    d.innerHTML = "<div style=\"flex:1;min-width:0\"><div style=\"font-weight:600\">" + esc(db.name) + "</div><div class=\"small\" style=\"font-family:monospace;word-break:break-all\">" + esc(id) + " · " + esc(db.version || "") + "</div></div>" +
      "<div class=\"btns\"><button class=\"btn small\" data-a=\"exp\">导出</button><button class=\"btn small danger\" data-a=\"del\">删除</button></div>";
    d.querySelector("[data-a=\"exp\"]").addEventListener("click", function(){ el("d1DatabaseSelect").value = id; openD1Export(); });
    d.querySelector("[data-a=\"del\"]").addEventListener("click", function(){ deleteD1Database(id); });
    el("d1DatabasesList").appendChild(d);
    var o = document.createElement("option"); o.value = id; o.textContent = db.name; el("d1DatabaseSelect").appendChild(o);
  });
}
function openCreateD1Database(){ el("createD1Modal").style.display = "flex"; }
function closeCreateD1Modal(){ el("createD1Modal").style.display = "none"; }
async function confirmCreateD1Database(){
  var n = el("d1DatabaseName").value.trim(); if(!n) return showNotification("请输入名称", "error");
  var aid = await ensureAccountId();
  var r = await api("create-d1-database", { accountId: aid, name: n, primary_location_hint: el("d1Location").value });
  if(r && r.success){ showNotification("创建成功"); closeCreateD1Modal(); refreshD1Databases(); } else showNotification((r && r.error) || "创建失败", "error");
}
async function deleteD1Database(id){
  if(!confirm("删除此 D1 数据库？数据将丢失，不可逆！")) return;
  var aid = await ensureAccountId();
  var r = await api("delete-d1-database", { accountId: aid, databaseId: id });
  if(r && r.success){ showNotification("已删除"); refreshD1Databases(); } else showNotification((r && r.error) || "删除失败", "error");
}
function parseD1Params(){
  var t = el("d1Params").value.trim();
  if(!t) return [];
  try { var p = JSON.parse(t); return Array.isArray(p) ? p : null; } catch(e){ return null; }
}
async function executeD1Query(){
  var db = el("d1DatabaseSelect").value, q = el("d1Query").value.trim();
  if(!db || !q) return showNotification("请选择数据库并输入 SQL", "error");
  var params = parseD1Params();
  if(params === null) return showNotification("参数必须是 JSON 数组", "error");
  var aid = await ensureAccountId();
  var r = await api("execute-d1-query", { accountId: aid, databaseId: db, query: q, params: params });
  var box = el("d1QueryResults"); box.style.display = "block";
  if(r && r.success) box.innerHTML = "<pre>" + esc(JSON.stringify(r.result, null, 2)) + "</pre>";
  else { box.innerHTML = "<pre>" + esc(JSON.stringify(r, null, 2)) + "</pre>"; showNotification((r && r.error) || "查询失败", "error"); }
}
async function executeD1Raw(){
  var db = el("d1DatabaseSelect").value, q = el("d1Query").value.trim();
  if(!db || !q) return showNotification("请选择数据库并输入 SQL", "error");
  var aid = await ensureAccountId();
  var r = await api("execute-d1-raw", { accountId: aid, databaseId: db, query: q });
  var box = el("d1QueryResults"); box.style.display = "block";
  if(r && r.success){
    var res = r.result && r.result[0];
    if(res && res.columns){ var html = "<table class=\"table\"><thead><tr>"; res.columns.forEach(function(c){ html += "<th>" + esc(c) + "</th>"; }); html += "</tr></thead><tbody>";
      (res.rows || []).forEach(function(row){ html += "<tr>"; row.forEach(function(c){ html += "<td>" + esc(String(c)) + "</td>"; }); html += "</tr>"; });
      box.innerHTML = html + "</tbody></table>"; return; }
  }
  box.innerHTML = "<pre>" + esc(JSON.stringify(r, null, 2)) + "</pre>";
}
async function d1ShowTables(){
  var db = el("d1DatabaseSelect").value;
  if(!db) return showNotification("请先选择数据库", "error");
  el("d1Query").value = "SELECT name, sql FROM sqlite_master WHERE type=\"table\" ORDER BY name;";
  executeD1Query();
}
var d1ExportTimer = null;
function openD1Export(){
  if(!el("d1DatabaseSelect").value) return showNotification("请先选择数据库", "error");
  el("d1ExportStatus").textContent = "点击开始后请勿关闭窗口";
  el("d1ExportLink").innerHTML = ""; el("d1ExportBtn").disabled = false;
  el("d1ExportModal").style.display = "flex";
}
function closeD1Export(){ if(d1ExportTimer){ clearInterval(d1ExportTimer); d1ExportTimer = null; } el("d1ExportModal").style.display = "none"; }
async function startD1Export(){
  var db = el("d1DatabaseSelect").value;
  var aid = await ensureAccountId();
  el("d1ExportBtn").disabled = true;
  el("d1ExportStatus").textContent = "正在启动导出...";
  var r = await api("d1-export-start", { accountId: aid, databaseId: db });
  if(!r || !r.success){ el("d1ExportStatus").textContent = "启动失败：" + ((r && r.error) || ""); el("d1ExportBtn").disabled = false; return; }
  var bookmark = r.result && r.result.current_bookmark;
  el("d1ExportStatus").textContent = "导出进行中，轮询等待完成（导出期间数据库不可查询）...";
  d1ExportTimer = setInterval(async function(){
    var pr = await api("d1-export-poll", { accountId: aid, databaseId: db, bookmark: bookmark });
    if(!pr || !pr.success){ el("d1ExportStatus").textContent = "轮询失败：" + ((pr && pr.error) || ""); clearInterval(d1ExportTimer); d1ExportTimer = null; el("d1ExportBtn").disabled = false; return; }
    var st = pr.result && pr.result.status;
    if(pr.result && pr.result.current_bookmark) bookmark = pr.result.current_bookmark;
    if(st === "complete" && pr.result.signed_url){
      clearInterval(d1ExportTimer); d1ExportTimer = null;
      el("d1ExportStatus").textContent = "导出完成（链接 1 小时内有效）";
      el("d1ExportLink").innerHTML = "<a class=\"btn primary\" href=\"" + escA(pr.result.signed_url) + "\" target=\"_blank\">下载 SQL 备份文件</a>";
      el("d1ExportBtn").disabled = false;
    } else { el("d1ExportStatus").textContent = "导出进行中...（状态: " + esc(st || "?") + "）"; }
  }, 3000);
}
window.refreshD1Databases = refreshD1Databases; window.openCreateD1Database = openCreateD1Database;
window.closeCreateD1Modal = closeCreateD1Modal; window.confirmCreateD1Database = confirmCreateD1Database;
window.executeD1Query = executeD1Query; window.executeD1Raw = executeD1Raw; window.d1ShowTables = d1ShowTables;
window.openD1Export = openD1Export; window.closeD1Export = closeD1Export; window.startD1Export = startD1Export;
async function refreshR2Buckets(){
  el("r2BucketsList").innerHTML = "加载中...";
  var aid = await ensureAccountId(); if(!aid) return;
  var jur = el("r2Jurisdiction") ? el("r2Jurisdiction").value : "default";
  var r = await api("list-r2-buckets", { accountId: aid, jurisdiction: jur });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("r2BucketsList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">" + ((r && r.success) ? "暂无存储桶" + (jur !== "default" ? "（当前辖区：" + esc(jur) + "，换辖区试试）" : "") : "加载失败：" + esc((r && r.error) || "")) + "</div>"; return; }
  el("r2BucketsList").innerHTML = "";
  arr.forEach(function(b){
    var nm = b.name || b;
    var d = document.createElement("div"); d.className = "kv-item";
    d.innerHTML = "<div style=\"flex:1;min-width:0\"><div style=\"font-weight:600\">" + esc(nm) + "</div><div class=\"small\">" + esc(b.creation_date || "") + (b.storage_class ? " · " + esc(b.storage_class) : "") + (b.location ? " · " + esc(b.location) : "") + "</div></div>" +
      "<div class=\"btns\"><select class=\"input\" data-sc=\"" + escA(nm) + "\" style=\"width:auto;font-size:12px\"><option value=\"Standard\">Standard</option><option value=\"InfrequentAccess\">InfrequentAccess</option></select>" +
      "<button class=\"btn small primary\" data-a=\"mgr\">管理</button><button class=\"btn small\" data-a=\"sc\">改存储类型</button><button class=\"btn small danger\" data-a=\"del\">删除</button></div>";
    var sel = d.querySelector("select"); if(b.storage_class) sel.value = b.storage_class;
    d.querySelector("[data-a=\"mgr\"]").addEventListener("click", function(){ openR2BucketDetail(nm); });
    d.querySelector("[data-a=\"sc\"]").addEventListener("click", function(){ updateR2StorageClass(nm, sel.value); });
    d.querySelector("[data-a=\"del\"]").addEventListener("click", function(){ deleteR2Bucket(nm); });
    el("r2BucketsList").appendChild(d);
  });
}
function openCreateR2Bucket(){ el("createR2Modal").style.display = "flex"; }
function closeCreateR2Modal(){ el("createR2Modal").style.display = "none"; }
async function confirmCreateR2Bucket(){
  var n = el("r2BucketName").value.trim(); if(!n) return showNotification("请输入名称", "error");
  var aid = await ensureAccountId();
  var jur = el("r2Jurisdiction") ? el("r2Jurisdiction").value : "default";
  var r = await api("create-r2-bucket", { accountId: aid, name: n, locationHint: el("r2Location").value, storageClass: el("r2StorageClass").value, jurisdiction: jur });
  if(r && r.success){ showNotification("创建成功"); closeCreateR2Modal(); refreshR2Buckets(); } else showNotification((r && r.error) || "创建失败", "error");
}
async function updateR2StorageClass(name, sc){
  var aid = await ensureAccountId();
  var r = await api("update-r2-bucket", { accountId: aid, name: name, storageClass: sc });
  if(r && r.success){ showNotification("已更新为 " + sc); refreshR2Buckets(); } else showNotification((r && r.error) || "更新失败", "error");
}
async function deleteR2Bucket(name){
  if(!confirm("删除存储桶 " + name + "？桶必须为空才能删除！")) return;
  var aid = await ensureAccountId();
  var jur = el("r2Jurisdiction") ? el("r2Jurisdiction").value : "default";
  var r = await api("delete-r2-bucket", { accountId: aid, name: name, jurisdiction: jur });
  if(r && r.success){ showNotification("已删除"); refreshR2Buckets(); } else showNotification((r && r.error) || "删除失败（桶可能非空）", "error");
}
window.refreshR2Buckets = refreshR2Buckets; window.openCreateR2Bucket = openCreateR2Bucket;
window.closeCreateR2Modal = closeCreateR2Modal; window.confirmCreateR2Bucket = confirmCreateR2Bucket;
// ===== R2 存储桶详情（对标 Cloudflare 官方控制台：对象 / 指标 / 设置） =====
var r2Detail = { name: "", tab: "objects", prefix: "", info: null, token: "", s3ok: null, tempCreds: null, credsTried: false };
function r2S3StoreKey(){ return "cfm_r2s3_" + (localStorage.getItem("cfm_accountId") || "default"); }
function getR2S3Creds(){ try { return JSON.parse(localStorage.getItem(r2S3StoreKey()) || "null"); } catch(e){ return null; } }
// 解析可用 S3 凭证：优先手动保存的，其次自动申请临时凭证（有效期 1 小时，内存存放）
async function ensureR2S3Creds(){
  var manual = getR2S3Creds();
  if(manual && manual.accessKeyId) return manual;
  if(r2Detail.tempCreds && r2Detail.tempCreds.expireAt > Date.now()) return r2Detail.tempCreds;
  var aid = await ensureAccountId();
  var r = await api("r2-temp-credentials", { accountId: aid, name: r2Detail.name, permission: "object-read-write", ttlSeconds: 3600 });
  if(r && r.success && r.result && r.result.accessKeyId){
    r2Detail.tempCreds = { accessKeyId: r.result.accessKeyId, secretAccessKey: r.result.secretAccessKey, sessionToken: r.result.sessionToken, expireAt: Date.now() + 3300 * 1000 };
    return r2Detail.tempCreds;
  }
  return null;
}
function r2S3Payload(extra){
  var c = r2Detail._creds || getR2S3Creds() || {};
  var s3 = { accessKeyId: c.accessKeyId || "", secretAccessKey: c.secretAccessKey || "" };
  if(c.sessionToken) s3.sessionToken = c.sessionToken;
  var p = { s3: s3 };
  if(extra) for(var k in extra) p[k] = extra[k];
  return p;
}
function fmtR2Size(n){ n = Number(n) || 0; if(n < 1024) return n + " B"; if(n < 1048576) return (n/1024).toFixed(1) + " KB"; if(n < 1073741824) return (n/1048576).toFixed(2) + " MB"; return (n/1073741824).toFixed(2) + " GB"; }
async function openR2BucketDetail(name){
  r2Detail.name = name; r2Detail.tab = "objects"; r2Detail.prefix = ""; r2Detail.info = null; r2Detail.token = ""; r2Detail.s3ok = null; r2Detail._creds = null;
  el("r2DetailName").textContent = name;
  el("r2ListCard").style.display = "none";
  el("r2DetailCard").style.display = "block";
  switchR2Tab("objects");
}
function closeR2Detail(){
  el("r2DetailCard").style.display = "none";
  el("r2ListCard").style.display = "block";
  r2Detail.name = "";
}
function switchR2Tab(tab){
  r2Detail.tab = tab;
  var tabs = document.querySelectorAll(".r2-tab");
  for(var i = 0; i < tabs.length; i++) tabs[i].className = "r2-tab" + (tabs[i].getAttribute("data-tab") === tab ? " active" : "");
  el("r2TabObjects").style.display = tab === "objects" ? "block" : "none";
  el("r2TabMetrics").style.display = tab === "metrics" ? "block" : "none";
  el("r2TabSettings").style.display = tab === "settings" ? "block" : "none";
  if(tab === "objects") renderR2ObjectsTab();
  else if(tab === "metrics") renderR2MetricsTab();
  else renderR2SettingsTab();
}
// ---------- 对象 tab ----------
async function renderR2ObjectsTab(){
  var box = el("r2TabObjects");
  box.innerHTML = "<div class=\"small\" style=\"text-align:center;padding:20px\">正在准备 S3 访问凭证...</div>";
  var creds = await ensureR2S3Creds();
  if(!creds){
    box.innerHTML = "<div style=\"max-width:560px;margin:20px auto;text-align:center\">" +
      "<h4 style=\"margin:0 0 8px\">配置 R2 S3 API 凭证</h4>" +
      "<div class=\"small\" style=\"margin-bottom:16px\">自动获取临时凭证失败（Token 可能缺少 R2 权限），请手动输入 R2 API 令牌。<br>获取位置：Cloudflare 控制台 → R2 对象存储 → 管理 R2 API 令牌。<br>凭证仅保存在本浏览器本地，随请求发送用于签名，不会上传存储。</div>" +
      "<div class=\"label\" style=\"text-align:left\">Access Key ID</div><input id=\"r2S3KeyId\" class=\"input\" placeholder=\"Access Key ID\" autocomplete=\"off\">" +
      "<div class=\"label\" style=\"text-align:left;margin-top:10px\">Secret Access Key</div><input id=\"r2S3Secret\" class=\"input\" type=\"password\" placeholder=\"Secret Access Key\" autocomplete=\"off\">" +
      "<div style=\"display:flex;gap:8px;justify-content:center;margin-top:14px\"><button class=\"btn primary\" onclick=\"saveR2S3Creds()\">保存并验证</button></div>" +
      "<div id=\"r2S3TestMsg\" class=\"small\" style=\"margin-top:10px\"></div></div>";
    return;
  }
  r2Detail._creds = creds;
  box.innerHTML =
    "<div id=\"r2ObjStats\" style=\"display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px\"></div>" +
    "<div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px\">" +
      "<div class=\"small\" id=\"r2PathNav\" style=\"font-size:13px\"></div>" +
      "<div style=\"display:flex;gap:8px\">" +
        "<input type=\"file\" id=\"r2FileInput\" multiple style=\"display:none\">" +
        "<button class=\"btn\" onclick=\"r2CreateFolder()\">添加文件夹</button>" +
        "<button class=\"btn primary\" onclick=\"document.getElementById('r2FileInput').click()\">上传文件</button>" +
        "<button class=\"btn\" onclick=\"loadR2Objects()\" title=\"刷新\">↻</button>" +
      "</div></div>" +
    "<div id=\"r2DropZone\"><div id=\"r2ObjList\">加载中...</div>" +
    "<div class=\"small\" style=\"margin-top:10px;color:#94a3b8\">超过 300 MB 的文件请使用 S3 兼容 API 或 rclone 等工具直接上传。</div></div>";
  var fi = el("r2FileInput");
  fi.addEventListener("change", function(){ r2UploadFiles(fi.files); fi.value = ""; });
  var dz = el("r2DropZone");
  dz.addEventListener("dragover", function(e){ e.preventDefault(); dz.style.outline = "2px dashed #2563eb"; dz.style.outlineOffset = "-2px"; });
  dz.addEventListener("dragleave", function(){ dz.style.outline = ""; });
  dz.addEventListener("drop", function(e){ e.preventDefault(); dz.style.outline = ""; if(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) r2UploadFiles(e.dataTransfer.files); });
  loadR2BucketInfo();
  loadR2Objects();
}
async function saveR2S3Creds(){
  var id = el("r2S3KeyId").value.trim(), sec = el("r2S3Secret").value.trim();
  if(!id || !sec){ el("r2S3TestMsg").textContent = "请填写完整凭证"; return; }
  localStorage.setItem(r2S3StoreKey(), JSON.stringify({ accessKeyId: id, secretAccessKey: sec }));
  el("r2S3TestMsg").textContent = "正在验证...";
  var aid = await ensureAccountId();
  var r = await api("r2-s3-test", { accountId: aid, name: r2Detail.name, s3: { accessKeyId: id, secretAccessKey: sec } });
  if(r && r.success){ showNotification("S3 凭证验证通过"); renderR2ObjectsTab(); }
  else { el("r2S3TestMsg").textContent = "验证失败：" + ((r && r.error) || ""); }
}
function r2ClearS3Creds(){ localStorage.removeItem(r2S3StoreKey()); r2Detail.tempCreds = null; r2Detail._creds = null; renderR2ObjectsTab(); }
async function loadR2BucketInfo(){
  var aid = await ensureAccountId();
  var jur = el("r2Jurisdiction") ? el("r2Jurisdiction").value : "default";
  var r = await api("get-r2-bucket", { accountId: aid, name: r2Detail.name, jurisdiction: jur });
  if(r && r.success) r2Detail.info = r.result;
  renderR2ObjStats();
}
function renderR2ObjStats(){
  var box = el("r2ObjStats"); if(!box) return;
  var b = r2Detail.info || {};
  var locName = { wnam: "北美西部", enam: "北美东部", weur: "西欧", eeur: "东欧", apac: "亚太地区", oc: "大洋洲" };
  var stats = [
    { k: "默认存储类", v: esc(b.storage_class || "标准") },
    { k: "位置", v: esc(locName[b.location] || b.location || "-") },
    { k: "创建时间", v: esc(b.creation_date ? String(b.creation_date).slice(0, 10) : "-") },
    { k: "A 类操作（读）", v: "-" },
    { k: "B 类操作（写）", v: "-" }
  ];
  box.innerHTML = stats.map(function(s){
    return "<div class=\"r2-stat\"><div class=\"k\">" + s.k + "</div><div class=\"v\">" + s.v + "</div></div>";
  }).join("");
}
function r2PathCrumbs(){
  var nav = el("r2PathNav"); if(!nav) return;
  var parts = r2Detail.prefix ? r2Detail.prefix.replace(/\/$/, "").split("/") : [];
  var h = "<a href=\"javascript:void(0)\" onclick=\"r2NavPrefix('')\" style=\"color:#2563eb;text-decoration:none\">" + esc(r2Detail.name) + "</a>";
  var acc = "";
  parts.forEach(function(p, i){
    acc += p + "/";
    h += " / <a href=\"javascript:void(0)\" onclick=\"r2NavPrefix('" + escA(acc) + "')\" style=\"color:#2563eb;text-decoration:none\">" + esc(p) + "</a>";
  });
  nav.innerHTML = h;
}
function r2NavPrefix(prefix){ r2Detail.prefix = prefix || ""; r2Detail.token = ""; loadR2Objects(); }
async function loadR2Objects(){
  var box = el("r2ObjList"); if(!box) return;
  box.innerHTML = "加载中...";
  r2PathCrumbs();
  var aid = await ensureAccountId();
  var p = r2S3Payload({ accountId: aid, name: r2Detail.name, prefix: r2Detail.prefix, maxKeys: 100 });
  if(r2Detail.token) p.continuationToken = r2Detail.token;
  var r = await api("r2-objects-list", p);
  if(!r || !r.success){ box.innerHTML = "<div style=\"text-align:center;padding:20px;color:#ef4444\">加载失败：" + esc((r && r.error) || "") + "<div style=\"margin-top:8px\"><button class=\"btn small\" onclick=\"r2ClearS3Creds()\">重新配置 S3 凭证</button></div></div>"; return; }
  var d = r.result || {};
  r2Detail.token = d.isTruncated ? d.nextToken : "";
  var rows = "";
  (d.folders || []).forEach(function(f){
    var short = f.replace(r2Detail.prefix, "").replace(/\/$/, "");
    rows += "<tr class=\"r2-objrow\"><td><a href=\"javascript:void(0)\" onclick=\"r2NavPrefix('" + escA(f) + "')\" style=\"color:#2563eb;text-decoration:none\">📁 " + esc(short) + "</a></td><td>文件夹</td><td>-</td><td>-</td><td>-</td><td></td></tr>";
  });
  (d.files || []).forEach(function(f){
    if(f.key === r2Detail.prefix) return;
    var short = f.key.replace(r2Detail.prefix, "");
    if(!short) return;
    var lm = f.lastModified ? fmtBJ(f.lastModified) : "-";
    rows += "<tr class=\"r2-objrow\"><td style=\"word-break:break-all\">" + esc(short) + "</td><td>文件</td><td>" + esc(f.storageClass || "Standard") + "</td><td>" + fmtR2Size(f.size) + "</td><td>" + esc(lm) + "</td>" +
      "<td style=\"white-space:nowrap\"><button class=\"btn small\" onclick=\"r2DownloadObject('" + escA(f.key) + "')\">下载</button> <button class=\"btn small danger\" onclick=\"r2DeleteObject('" + escA(f.key) + "')\">删除</button></td></tr>";
  });
  var more = d.isTruncated ? "<div style=\"text-align:center;margin-top:10px\"><button class=\"btn small\" onclick=\"loadR2ObjectsMore()\">加载更多</button></div>" : "";
  if(!rows){
    box.innerHTML = "<div style=\"border:1px dashed #e2e8f0;border-radius:8px;padding:48px 20px;text-align:center;color:#64748b\">" +
      "<div style=\"font-size:44px;margin-bottom:12px\">☁️⬆️</div>" +
      "<div style=\"font-weight:600;color:#0f1724;margin-bottom:6px\">您的存储桶已准备就绪。添加文件即可开始使用。</div>" +
      "<div style=\"margin-bottom:6px\"><a href=\"javascript:void(0)\" onclick=\"document.getElementById('r2FileInput').click()\" style=\"color:#2563eb;text-decoration:none\">拖放或从计算机中选择 &gt;</a></div>" +
      "<div class=\"small\">超过 300 MB 的文件只能使用 S3 兼容性 API 或 Workers 上载。</div></div>" + more;
  } else {
    box.innerHTML = "<table class=\"table\" style=\"margin-top:0\"><thead><tr><th>对象</th><th>类型</th><th>存储类</th><th>大小</th><th>已修改</th><th>操作</th></tr></thead><tbody>" + rows + "</tbody></table>" + more;
  }
}
function loadR2ObjectsMore(){ loadR2ObjectsKeep(); }
async function loadR2ObjectsKeep(){
  // 分页追加：保持已有行，追加下一页
  var aid = await ensureAccountId();
  var p = r2S3Payload({ accountId: aid, name: r2Detail.name, prefix: r2Detail.prefix, maxKeys: 100, continuationToken: r2Detail.token });
  var r = await api("r2-objects-list", p);
  if(!r || !r.success){ showNotification((r && r.error) || "加载失败", "error"); return; }
  r2Detail.token = "";
  loadR2Objects();
}
function readFileAsBase64R2(f){
  return new Promise(function(res, rej){
    var r = new FileReader();
    r.onload = function(){ var s = String(r.result || ""); var i = s.indexOf(","); res(i >= 0 ? s.slice(i + 1) : s); };
    r.onerror = function(){ rej(new Error("读取失败")); };
    r.readAsDataURL(f);
  });
}
async function r2UploadFiles(fileList){
  var files = Array.from(fileList || []);
  if(!files.length) return;
  var over = files.filter(function(f){ return f.size > 50 * 1048576; });
  if(over.length) return showNotification("单个文件超过 50MB（" + over[0].name + "），请用 S3 工具直传", "error");
  var aid = await ensureAccountId();
  var ok = 0, fail = 0;
  showNotification("开始上传 " + files.length + " 个文件...");
  for(var i = 0; i < files.length; i++){
    var f = files[i];
    try {
      var b64 = await readFileAsBase64R2(f);
      var key = r2Detail.prefix + f.name;
      var r = await api("r2-object-put", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, content: b64, contentType: f.type || "application/octet-stream" }));
      if(r && r.success) ok++; else { fail++; showNotification("上传失败 " + f.name + "：" + ((r && r.error) || ""), "error"); }
    } catch(e){ fail++; showNotification("上传失败 " + f.name + "：" + e.message, "error"); }
  }
  showNotification("上传完成：成功 " + ok + "，失败 " + fail);
  loadR2Objects();
}
async function r2DeleteObject(key){
  var short = key.replace(r2Detail.prefix, "");
  if(!confirm("删除对象 " + short + "？")) return;
  var aid = await ensureAccountId();
  var r = await api("r2-object-delete", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key }));
  if(r && r.success){ showNotification("已删除"); loadR2Objects(); }
  else showNotification((r && r.error) || "删除失败", "error");
}
async function r2DownloadObject(key){
  var aid = await ensureAccountId();
  var r = await api("r2-object-download-url", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, expires: 3600 }));
  if(r && r.success && r.result && r.result.url){ window.open(r.result.url, "_blank"); }
  else showNotification((r && r.error) || "生成下载链接失败", "error");
}
async function r2CreateFolder(){
  var name = prompt("文件夹名称：");
  if(!name) return;
  name = name.trim().replace(/^\/+|\/+$/g, "");
  if(!name) return;
  var aid = await ensureAccountId();
  var key = r2Detail.prefix + name + "/";
  var r = await api("r2-object-put", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, content: "", contentType: "application/x-directory" }));
  if(r && r.success){ showNotification("文件夹已创建"); loadR2Objects(); }
  else showNotification((r && r.error) || "创建失败", "error");
}
window.openR2BucketDetail = openR2BucketDetail; window.closeR2Detail = closeR2Detail; window.switchR2Tab = switchR2Tab;
window.saveR2S3Creds = saveR2S3Creds; window.r2ClearS3Creds = r2ClearS3Creds; window.r2NavPrefix = r2NavPrefix;
window.loadR2Objects = loadR2Objects; window.loadR2ObjectsMore = loadR2ObjectsMore; window.r2UploadFiles = r2UploadFiles;
window.r2DeleteObject = r2DeleteObject; window.r2DownloadObject = r2DownloadObject; window.r2CreateFolder = r2CreateFolder;
// ---------- 指标 tab ----------
function renderR2MetricsTab(){
  var box = el("r2TabMetrics");
  box.innerHTML = "<div style=\"display:flex;justify-content:flex-end;margin-bottom:12px\"><select id=\"r2MetricsRange\" class=\"input\" style=\"width:auto\" onchange=\"renderR2MetricsTab()\"><option value=\"24h\">过去 24 小时</option><option value=\"7d\">过去 7 天</option><option value=\"30d\">过去 30 天</option></select></div>" +
    "<div id=\"r2MetricsCards\" style=\"display:grid;grid-template-columns:repeat(6,1fr);gap:12px\"><div class=\"small\">指标加载中...</div></div>";
  loadR2Metrics();
}
async function loadR2Metrics(){
  var box = el("r2MetricsCards"); if(!box) return;
  var range = el("r2MetricsRange") ? el("r2MetricsRange").value : "24h";
  var aid = await ensureAccountId();
  var r = await api("r2-metrics", { accountId: aid, name: r2Detail.name, range: range });
  var cards = [
    { k: "平均存储", v: "-" }, { k: "已检索数据", v: "-" }, { k: "A 类操作", v: "-" }, { k: "B 类操作", v: "-" }, { k: "免费操作", v: "-" }, { k: "请求总数", v: "-" }
  ];
  if(r && r.success && r.result){
    var m = r.result;
    cards[0].v = m.avgStorage || "-"; cards[1].v = m.egress || "-"; cards[2].v = m.classA || "-"; cards[3].v = m.classB || "-"; cards[4].v = m.freeOps || "-"; cards[5].v = m.requests || "-";
  } else {
    box.innerHTML = "<div class=\"small\" style=\"grid-column:1/-1;text-align:center;padding:20px\">指标暂不可用：" + esc((r && r.error) || "未知错误") + "</div>";
    return;
  }
  box.innerHTML = "<div class=\"small\" style=\"grid-column:1/-1;color:#94a3b8\">统计口径：A 类=写入/列出类操作；B 类=读取类操作；免费=删除对象/取消分片上传（不计费）。GraphQL 数据约有 1-2 小时延迟。</div>" +
  cards.map(function(c){
    return "<div class=\"card\" style=\"padding:16px\"><div class=\"r2-stat\"><div class=\"k\">" + c.k + "</div><div class=\"v\" style=\"font-size:20px\">" + esc(c.v) + "</div></div></div>";
  }).join("");
}
// ---------- 设置 tab ----------
function renderR2SettingsTab(){
  var box = el("r2TabSettings");
  box.innerHTML = "<div id=\"r2SettingsBody\">加载中...</div>";
  loadR2Settings();
}
async function loadR2Settings(){
  var box = el("r2SettingsBody"); if(!box) return;
  var aid = await ensureAccountId();
  var jur = el("r2Jurisdiction") ? el("r2Jurisdiction").value : "default";
  var r = await api("get-r2-bucket", { accountId: aid, name: r2Detail.name, jurisdiction: jur });
  var b = (r && r.success && r.result) || {};
  var locName = { wnam: "北美西部", enam: "北美东部", weur: "西欧", eeur: "东欧", apac: "亚太地区", oc: "大洋洲" };
  var s3ep = "https://" + aid + ".r2.cloudflarestorage.com/" + r2Detail.name;
  var h = "<h4 style=\"margin:0 0 12px\">常规问题</h4>" +
    "<div class=\"card\" style=\"padding:16px;margin-bottom:20px\"><div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:12px\">" +
    "<div class=\"r2-stat\"><div class=\"k\">名称：</div><div class=\"v\">" + esc(b.name || r2Detail.name) + "</div></div>" +
    "<div class=\"r2-stat\"><div class=\"k\">位置：</div><div class=\"v\">" + esc(locName[b.location] || b.location || "-") + "</div></div>" +
    "<div class=\"r2-stat\"><div class=\"k\">创建时间：</div><div class=\"v\">" + esc(b.creation_date ? fmtBJ(b.creation_date) : "-") + "</div></div>" +
    "</div><div class=\"r2-stat\" style=\"margin-top:12px\"><div class=\"k\">S3 API：</div><div class=\"v\" style=\"font-weight:400;font-size:13px\">" + esc(s3ep) +
    " <button class=\"btn small\" onclick=\"copyToClipboard('" + escA(s3ep) + "')\">复制</button></div></div></div>";
  h += "<h4 style=\"margin:0 0 12px\">自定义域 <span title=\"将您自己的域名绑定到此存储桶\" style=\"cursor:help;color:#94a3b8\">ⓘ</span></h4><div id=\"r2CustomDomains\"><div class=\"small\">加载中...</div></div>";
  h += "<h4 style=\"margin:20px 0 12px\">公共开发 URL <span title=\"r2.dev 域名，用于开发测试\" style=\"cursor:help;color:#94a3b8\">ⓘ</span></h4><div id=\"r2PublicUrl\"><div class=\"small\">加载中...</div></div>";
  h += "<h4 style=\"margin:20px 0 12px\">R2 数据目录 <span title=\"Apache Iceberg 兼容的数据目录，可用 Spark / PyIceberg 等查询引擎连接\" style=\"cursor:help;color:#94a3b8\">ⓘ</span></h4><div id=\"r2DataCatalog\"><div class=\"small\">加载中...</div></div>";
  box.innerHTML = h;
  loadR2Domains();
  loadR2DataCatalog();
}
async function loadR2Domains(){
  var aid = await ensureAccountId();
  var r = await api("r2-bucket-domains", { accountId: aid, name: r2Detail.name });
  var cd = el("r2CustomDomains"), pu = el("r2PublicUrl");
  if(!r || !r.success){
    if(cd) cd.innerHTML = "<div class=\"small\">加载失败：" + esc((r && r.error) || "") + "</div>";
    if(pu) pu.innerHTML = "<div class=\"small\">加载失败：" + esc((r && r.error) || "") + "</div>";
    return;
  }
  var d = r.result || {};
  var customs = d.custom || [];
  if(cd){
    cd.innerHTML = "<div class=\"card\" style=\"padding:16px\">" +
      (customs.length ? customs.map(function(x){
        return "<div class=\"kv-item\"><span>" + esc(x.domain || x) + "</span><button class=\"btn small danger\" onclick=\"r2RemoveCustomDomain('" + escA(x.domain || x) + "')\">删除</button></div>";
      }).join("") : "<div class=\"small\" style=\"text-align:center;padding:8px\">没有为此存储桶分配自定义域。</div>") +
      "<div style=\"margin-top:10px;display:flex;gap:8px\"><input id=\"r2NewDomain\" class=\"input\" placeholder=\"例如 cdn.example.com\" style=\"max-width:320px\"><button class=\"btn\" onclick=\"r2AddCustomDomain()\">添加</button></div></div>";
  }
  if(pu){
    var pub = d.publicUrl || "";
    pu.innerHTML = "<div class=\"card\" style=\"padding:16px\"><div style=\"display:flex;justify-content:space-between;align-items:center;gap:10px\">" +
      "<span class=\"small\">" + (pub ? "已启用：<b>" + esc(pub) + "</b>" : "已对此存储桶禁用公用开发 URL。") + "</span>" +
      (pub ? "<button class=\"btn small danger\" onclick=\"r2TogglePublicUrl(false)\">禁用</button>" : "<button class=\"btn primary small\" onclick=\"r2TogglePublicUrl(true)\">启用</button>") +
      "</div></div>";
  }
}
async function r2AddCustomDomain(){
  var domain = el("r2NewDomain").value.trim();
  if(!domain) return showNotification("请输入域名", "error");
  var aid = await ensureAccountId();
  var r = await api("r2-custom-domain-add", { accountId: aid, name: r2Detail.name, domain: domain });
  if(r && r.success){ showNotification("自定义域已添加"); loadR2Domains(); }
  else showNotification((r && r.error) || "添加失败", "error");
}
async function r2RemoveCustomDomain(domain){
  if(!confirm("删除自定义域 " + domain + "？")) return;
  var aid = await ensureAccountId();
  var r = await api("r2-custom-domain-remove", { accountId: aid, name: r2Detail.name, domain: domain });
  if(r && r.success){ showNotification("已删除"); loadR2Domains(); }
  else showNotification((r && r.error) || "删除失败", "error");
}
async function r2TogglePublicUrl(enable){
  var aid = await ensureAccountId();
  var r = await api("r2-public-url-toggle", { accountId: aid, name: r2Detail.name, enable: enable });
  if(r && r.success){ showNotification(enable ? "公共开发 URL 已启用" : "已禁用"); loadR2Domains(); }
  else showNotification((r && r.error) || "操作失败", "error");
}
async function loadR2DataCatalog(){
  var box = el("r2DataCatalog"); if(!box) return;
  var aid = await ensureAccountId();
  var r = await api("r2-catalog-get", { accountId: aid, name: r2Detail.name });
  if(!r || !r.success){
    box.innerHTML = "<div class=\"card\" style=\"padding:16px\"><div class=\"small\">加载失败：" + esc((r && r.error) || "") + "</div></div>";
    return;
  }
  var c = r.result || {};
  if(!c.enabled){
    box.innerHTML = "<div class=\"card\" style=\"padding:16px\"><div style=\"display:flex;justify-content:space-between;align-items:center;gap:10px\">" +
      "<span class=\"small\">已对此存储桶禁用数据目录。</span>" +
      "<button class=\"btn primary small\" onclick=\"r2ToggleDataCatalog(true)\">启用</button></div></div>";
    return;
  }
  var maint = c.maintenance || {};
  var comp = maint.compaction || {}, snap = maint.snapshot_expiration || {};
  var maintTxt = "压缩：" + (comp.state === "enabled" ? "已启用" : "未启用") + " · 快照过期：" + (snap.state === "enabled" ? "已启用" : "未启用");
  box.innerHTML = "<div class=\"card\" style=\"padding:16px\">" +
    "<div class=\"r2-stat\" style=\"margin-bottom:10px\"><div class=\"k\">目录 URI：</div><div class=\"v\" style=\"font-weight:400;font-size:13px;word-break:break-all\">" + esc(c.catalogUri || "") +
    " <button class=\"btn small\" onclick=\"copyToClipboard('" + escA(c.catalogUri || "") + "')\">复制</button></div></div>" +
    "<div class=\"r2-stat\" style=\"margin-bottom:10px\"><div class=\"k\">仓库名称：</div><div class=\"v\" style=\"font-weight:400;font-size:13px;word-break:break-all\">" + esc(c.warehouse || "") +
    " <button class=\"btn small\" onclick=\"copyToClipboard('" + escA(c.warehouse || "") + "')\">复制</button></div></div>" +
    "<div class=\"small\" style=\"margin-bottom:12px\">" + esc(maintTxt) + " · 与 Iceberg 兼容的查询引擎（例如 Spark、PyIceberg）使用上述信息连接到此存储桶的数据目录。</div>" +
    "<button class=\"btn small danger\" onclick=\"r2ToggleDataCatalog(false)\">禁用</button></div>";
}
async function r2ToggleDataCatalog(enable){
  if(!enable && !confirm("禁用数据目录后，Iceberg 表引用将暂时不可访问，确定禁用？")) return;
  var aid = await ensureAccountId();
  var r = await api(enable ? "r2-catalog-enable" : "r2-catalog-disable", { accountId: aid, name: r2Detail.name });
  if(r && r.success){ showNotification(enable ? "数据目录已启用" : "数据目录已禁用"); loadR2DataCatalog(); }
  else showNotification((r && r.error) || "操作失败", "error");
}
window.renderR2MetricsTab = renderR2MetricsTab; window.loadR2Metrics = loadR2Metrics;
window.renderR2SettingsTab = renderR2SettingsTab; window.r2AddCustomDomain = r2AddCustomDomain;
window.r2RemoveCustomDomain = r2RemoveCustomDomain; window.r2TogglePublicUrl = r2TogglePublicUrl;
window.loadR2DataCatalog = loadR2DataCatalog; window.r2ToggleDataCatalog = r2ToggleDataCatalog;
var currentZoneId = null, currentZoneName = "", currentEditingRecord = null;
function showZonesList(){ el("zonesList").style.display = "block"; el("dnsRecordsSection").style.display = "none"; currentZoneId = null; refreshZones(); }
window.backToZones = showZonesList;
async function refreshZones(){
  el("zonesList").innerHTML = "加载中...";
  var r = await api("list-zones");
  var zones = (r && r.result) || [];
  if(!zones.length){ el("zonesList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无域名</div>"; return; }
  var html = "";
  zones.forEach(function(z){
    var pill = z.status === "active" ? "<span class=\"pill green\">已激活</span>" : "<span class=\"pill amber\">" + esc(z.status) + "</span>";
    var ns = "";
    if(z.status !== "active" && z.name_servers && z.name_servers.length){
      ns = "<div class=\"small\" style=\"margin:10px 0 6px;color:#b45309;font-weight:600\">请到注册商设置以下 NS：</div><div style=\"display:flex;flex-wrap:wrap;gap:6px\">";
      z.name_servers.forEach(function(s){ ns += "<span class=\"ns-pill\">" + esc(s) + "<span class=\"ns-copy-icon\" style=\"cursor:pointer;margin-left:4px\" data-ns=\"" + escA(s) + "\">⧉</span></span>"; });
      ns += "</div>";
    }
    html += "<div class=\"card\" style=\"margin-bottom:12px\">" +
      "<div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap\">" +
      "<div style=\"min-width:0\"><div style=\"font-size:19px;font-weight:700;color:#111827;word-break:break-all\">" + esc(z.name) + "</div>" +
      "<div class=\"small\" style=\"margin-top:4px\">" + esc((z.plan && z.plan.name) || "") + " &nbsp;·&nbsp; <span style=\"font-family:monospace\">" + esc(z.id) + "</span></div></div>" +
      "<div style=\"display:flex;align-items:center;gap:8px;flex-shrink:0\">" + pill +
      "<button class=\"btn small\" data-a=\"dns\" data-id=\"" + escA(z.id) + "\" data-n=\"" + escA(z.name) + "\">管理 DNS</button>" +
      "<button class=\"trash-btn\" data-a=\"del\" data-id=\"" + escA(z.id) + "\">删除</button></div></div>" + ns + "</div>";
  });
  el("zonesList").innerHTML = html;
  Array.from(el("zonesList").querySelectorAll("[data-ns]")).forEach(function(s){ s.addEventListener("click", function(e){ copyToClipboard(this.getAttribute("data-ns"), e); }); });
  Array.from(el("zonesList").querySelectorAll("button")).forEach(function(b){
    b.addEventListener("click", function(){
      var a = this.getAttribute("data-a");
      if(a === "dns") viewZoneDNS(this.getAttribute("data-id"), this.getAttribute("data-n"));
      else if(a === "del") deleteZone(this.getAttribute("data-id"));
    });
  });
}
function openAddZone(){ el("addZoneModal").style.display = "flex"; }
function closeAddZoneModal(){ el("addZoneModal").style.display = "none"; }
async function confirmAddZone(){
  var n = el("zoneName").value.trim(); if(!n) return showNotification("请输入域名", "error");
  var aid = await ensureAccountId();
  var r = await api("create-zone", { accountId: aid, name: n });
  if(r && r.success){ showNotification("已添加，请去注册商修改 NS"); closeAddZoneModal(); refreshZones(); } else showNotification((r && r.error) || "添加失败", "error");
}
async function deleteZone(id){
  if(!confirm("删除此域名？不可逆！")) return;
  var r = await api("delete-zone", { zoneId: id });
  if(r && r.success){ showNotification("已删除"); refreshZones(); } else showNotification((r && r.error) || "删除失败", "error");
}
function viewZoneDNS(id, name){
  currentZoneId = id; currentZoneName = name;
  el("zonesList").style.display = "none"; el("dnsRecordsSection").style.display = "block";
  el("selectedZoneName").textContent = name + " - DNS 记录";
  refreshDNSRecords();
}
async function refreshDNSRecords(){
  el("dnsRecordsList").innerHTML = "加载中...";
  var r = await api("list-dns-records", { zoneId: currentZoneId });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("dnsRecordsList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无 DNS 记录</div>"; return; }
  var html = "<table class=\"table\"><thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th style=\"text-align:right\">操作</th></tr></thead><tbody>";
  arr.forEach(function(x){
    html += "<tr><td><span class=\"pill\">" + esc(x.type) + "</span></td><td>" + esc(x.name) + "</td><td style=\"max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\" title=\"" + escA(x.content) + "\">" + esc(x.content) + "</td><td>" + (x.ttl === 1 ? "自动" : x.ttl) + "</td><td>" + (x.proxied ? "<span class=\"pill amber\">已代理</span>" : "关闭") + "</td>" +
      "<td style=\"text-align:right;white-space:nowrap\"><button class=\"btn small\" data-a=\"edit\" data-id=\"" + escA(x.id) + "\">编辑</button> <button class=\"btn small danger\" data-a=\"del\" data-id=\"" + escA(x.id) + "\">删除</button></td></tr>";
  });
  el("dnsRecordsList").innerHTML = html + "</tbody></table>";
  Array.from(el("dnsRecordsList").querySelectorAll("button")).forEach(function(b){
    b.addEventListener("click", function(){
      var a = this.getAttribute("data-a"), id = this.getAttribute("data-id");
      if(a === "edit") editDNSRecord(id); else deleteDNSRecord(id);
    });
  });
}
function openAddDNSRecord(){ el("addDNSRecordModal").style.display = "flex"; }
function closeAddDNSRecordModal(){ el("addDNSRecordModal").style.display = "none"; }
async function confirmAddDNSRecord(){
  var t = el("dnsRecordType").value, n = el("dnsRecordName").value.trim(), c = el("dnsRecordContent").value.trim();
  if(!n || !c) return showNotification("请填写完整", "error");
  var r = await api("create-dns-record", { zoneId: currentZoneId, type: t, name: n, content: c, ttl: parseInt(el("dnsRecordTTL").value, 10), proxied: el("dnsRecordProxied").checked });
  if(r && r.success){ showNotification("添加成功"); closeAddDNSRecordModal(); refreshDNSRecords(); } else showNotification((r && r.error) || "添加失败", "error");
}
async function editDNSRecord(id){
  var r = await api("list-dns-records", { zoneId: currentZoneId });
  var rec = ((r && r.result) || []).find(function(x){ return x.id === id; });
  if(!rec) return showNotification("未找到记录", "error");
  currentEditingRecord = rec;
  el("editDnsRecordName").value = rec.name; el("editDnsRecordContent").value = rec.content;
  el("editDnsRecordTTL").value = String(rec.ttl); el("editDnsRecordProxied").checked = !!rec.proxied;
  el("editDNSRecordModal").style.display = "flex";
}
function closeEditDNSRecordModal(){ el("editDNSRecordModal").style.display = "none"; currentEditingRecord = null; }
async function confirmEditDNSRecord(){
  var r = await api("update-dns-record", { zoneId: currentZoneId, recordId: currentEditingRecord.id, name: el("editDnsRecordName").value.trim(), content: el("editDnsRecordContent").value.trim(), ttl: parseInt(el("editDnsRecordTTL").value, 10), proxied: el("editDnsRecordProxied").checked });
  if(r && r.success){ showNotification("更新成功"); closeEditDNSRecordModal(); refreshDNSRecords(); } else showNotification((r && r.error) || "更新失败", "error");
}
async function deleteDNSRecord(id){
  if(!confirm("删除此 DNS 记录？")) return;
  var r = await api("delete-dns-record", { zoneId: currentZoneId, recordId: id });
  if(r && r.success){ showNotification("已删除"); refreshDNSRecords(); } else showNotification((r && r.error) || "删除失败", "error");
}
function openDnsBatchImport(){ el("dnsBatchInput").value = ""; el("dnsBatchModal").style.display = "flex"; }
function closeDnsBatchImport(){ el("dnsBatchModal").style.display = "none"; }
async function confirmDnsBatchImport(){
  var posts = [];
  var lines = el("dnsBatchInput").value.split("\n");
  for(var i = 0; i < lines.length; i++){
    var p = lines[i].trim(); if(!p) continue;
    var f = p.split(",");
    if(f.length < 3){ showNotification("第 " + (i + 1) + " 行格式错误", "error"); return; }
    posts.push({ type: f[0].trim().toUpperCase(), name: f[1].trim(), content: f.slice(2, 3).join(",").trim(), ttl: f[3] ? parseInt(f[3].trim(), 10) : 1, proxied: f[4] ? f[4].trim().toLowerCase() === "true" : false });
  }
  if(!posts.length) return showNotification("没有有效记录", "error");
  var r = await api("batch-dns-records", { zoneId: currentZoneId, posts: posts });
  if(r && r.success){ showNotification("批量导入成功（" + posts.length + " 条）"); closeDnsBatchImport(); refreshDNSRecords(); }
  else { showNotification((r && r.error) || "导入失败", "error"); debugOut(r); }
}
window.refreshZones = refreshZones; window.openAddZone = openAddZone; window.closeAddZoneModal = closeAddZoneModal; window.confirmAddZone = confirmAddZone;
window.viewZoneDNS = viewZoneDNS; window.refreshDNSRecords = refreshDNSRecords;
window.openAddDNSRecord = openAddDNSRecord; window.closeAddDNSRecordModal = closeAddDNSRecordModal; window.confirmAddDNSRecord = confirmAddDNSRecord;
window.editDNSRecord = editDNSRecord; window.closeEditDNSRecordModal = closeEditDNSRecordModal; window.confirmEditDNSRecord = confirmEditDNSRecord;
window.openDnsBatchImport = openDnsBatchImport; window.closeDnsBatchImport = closeDnsBatchImport; window.confirmDnsBatchImport = confirmDnsBatchImport;
window.copyToClipboard = copyToClipboard;
var currentPagesProject = "";
async function refreshPagesProjects(){
  backToPagesProjects(true);
  el("pagesProjectsList").innerHTML = "加载中...";
  var aid = await ensureAccountId(); if(!aid) return;
  var r = await api("list-pages-projects", { accountId: aid });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("pagesProjectsList").innerHTML = "<div style=\"text-align:center;padding:20px;color:#6b7280\">暂无 Pages 项目</div>"; return; }
  el("pagesProjectsList").innerHTML = "";
  arr.forEach(function(p){
    var d = document.createElement("div"); d.className = "kv-item";
    d.innerHTML = "<div style=\"flex:1;min-width:0\"><div style=\"font-weight:600\">" + esc(p.name) + "</div><div class=\"small\"><a href=\"" + escA(p.canonical_deployment && p.canonical_deployment.url || ("https://" + p.subdomain)) + "\" target=\"_blank\" style=\"color:#f59e0b\">" + esc(p.subdomain || "") + "</a> · 生产分支 " + esc(p.production_branch || "-") + "</div></div>" +
      "<div class=\"btns\"><button class=\"btn small\" data-a=\"deps\" data-n=\"" + escA(p.name) + "\">部署记录</button><button class=\"btn small\" data-a=\"del\" data-n=\"" + escA(p.name) + "\" style=\"color:#ef4444\">删除</button></div>";
    d.querySelector("[data-a=\"deps\"]").addEventListener("click", function(){ viewPagesDeployments(this.getAttribute("data-n")); });
    d.querySelector("[data-a=\"del\"]").addEventListener("click", function(){ deletePagesProject(this); });
    el("pagesProjectsList").appendChild(d);
  });
}
async function deletePagesProject(btn){
  var name = btn.getAttribute("data-n");
  if(btn.getAttribute("data-confirm") !== "1"){
    btn.setAttribute("data-confirm", "1"); btn.textContent = "确认删除？"; btn.classList.add("danger");
    setTimeout(function(){ btn.setAttribute("data-confirm", ""); btn.textContent = "删除"; btn.classList.remove("danger"); }, 5000);
    return;
  }
  btn.setAttribute("data-confirm", "");
  var aid = await ensureAccountId(); if(!aid) return;
  var r = await api("delete-pages-project", { accountId: aid, projectName: name });
  if(r && r.success){ showNotification("项目已删除"); refreshPagesProjects(); } else showNotification((r && r.error) || "删除失败", "error");
}
function backToPagesProjects(silent){ currentPagesProject = ""; el("pagesDeploySection").style.display = "none"; el("pagesProjectsList").style.display = "block"; if(!silent) refreshPagesProjects(); }
function openCreatePagesProject(){ openQuickDeployPages(); }
function closeCreatePagesModal(){ el("createPagesModal").style.display = "none"; }
async function confirmCreatePagesProject(){
  var input = el("pagesProjectNameInput"); var n = input.value.trim().toLowerCase(); input.value = n;
  if(!n) return showNotification("请输入项目名", "error");
  if(!/^[a-z0-9][a-z0-9-]*$/.test(n) || n.length > 63) return showNotification("项目名不合法：仅小写字母、数字、连字符，且以字母数字开头", "error");
  var btn = document.querySelector("#createPagesModal .btn.primary");
  if(btn){ btn.disabled = true; btn.textContent = "创建中..."; }
  try{
    var aid = await ensureAccountId();
    if(!aid) throw new Error("无法获取账号 ID");
    var r = await api("create-pages-project", { accountId: aid, name: n, production_branch: el("pagesBranchInput").value.trim() || "main" });
    if(r && r.success){ showNotification("创建成功"); closeCreatePagesModal(); input.value = ""; refreshPagesProjects(); }
    else throw new Error((r && r.error) || "创建失败");
  }catch(err){ showNotification(err.message || "创建失败", "error"); }
  if(btn){ btn.disabled = false; btn.textContent = "创建"; }
}
function switchPagesDeployTab(t){
  el("pdeploy-upload").style.display = t === "upload" ? "block" : "none";
  el("pdeploy-github").style.display = t === "github" ? "block" : "none";
  Array.from(document.querySelectorAll("[data-ptab]")).forEach(function(x){ x.classList.toggle("active", x.getAttribute("data-ptab") === t); });
}
function pagesDeployStatus(msg, isErr){
  var s = el("pagesDeployStatus"); if(!s) return;
  s.innerHTML = msg ? ("<span style=\"color:" + (isErr ? "#dc2626" : "#1e40af") + "\">" + esc(msg) + "</span>") : "";
}
function getPagesUploadFiles(){
  var a = Array.from(el("pagesUploadFiles").files || []), b = Array.from(el("pagesUploadDir").files || []);
  var seen = {}, out = [];
  a.concat(b).forEach(function(f){ var k = (f.webkitRelativePath || f.name) + "|" + f.size; if(!seen[k]){ seen[k] = 1; out.push(f); } });
  return out;
}
function refreshPagesUploadList(){
  var fs = getPagesUploadFiles(), box = el("pagesUploadList");
  if(!box) return;
  if(!fs.length){ box.textContent = ""; return; }
  var total = fs.reduce(function(s, f){ return s + f.size; }, 0);
  box.textContent = "已选择 " + fs.length + " 个文件，共 " + (total / 1048576).toFixed(2) + " MB";
}
function clearPagesUpload(){ el("pagesUploadFiles").value = ""; el("pagesUploadDir").value = ""; refreshPagesUploadList(); pagesDeployStatus(""); }
function readFileAsBase64(f){
  return new Promise(function(res, rej){
    var r = new FileReader();
    r.onload = function(){ var s = String(r.result || ""); var i = s.indexOf(","); res(i >= 0 ? s.slice(i + 1) : s); };
    r.onerror = function(){ rej(new Error("读取文件失败：" + f.name)); };
    r.readAsDataURL(f);
  });
}
async function startPagesUpload(){
  var fs = getPagesUploadFiles();
  if(!fs.length) return showNotification("请先选择文件或文件夹", "error");
  if(fs.length > 2000) return showNotification("文件数量超过 2000，请精简", "error");
  var total = fs.reduce(function(s, f){ return s + f.size; }, 0);
  if(total > 100 * 1048576) return showNotification("文件总大小超过 100MB，请精简", "error");
  var bad = fs.filter(function(f){ return f.size > 25 * 1048576; });
  if(bad.length) return showNotification("单个文件超过 25MB：" + bad[0].name, "error");
  var btn = el("pagesUploadBtn"); btn.disabled = true; btn.textContent = "读取文件中...";
  pagesDeployStatus("正在读取 " + fs.length + " 个文件...");
  try{
    var files = [];
    for(var i = 0; i < fs.length; i++){
      var f = fs[i];
      var b64 = await readFileAsBase64(f);
      var rel = f.webkitRelativePath || f.name;
      var slash = rel.indexOf("/");
      if(slash >= 0) rel = rel.slice(slash + 1);
      if(!rel) rel = f.name;
      files.push({ path: "/" + rel, content: b64 });
      if(i % 20 === 0) pagesDeployStatus("正在读取文件 " + (i + 1) + "/" + fs.length + "...");
    }
    btn.textContent = "部署中...";
    pagesDeployStatus("正在上传并部署，请稍候...");
    var aid = await ensureAccountId();
    var r = await api("pages-deploy-upload", { accountId: aid, projectName: currentPagesProject, branch: el("pagesUploadBranch").value.trim(), files: files });
    if(r && r.success){ var msg = "部署成功"; if(r.stage === "failure") msg = "部署失败，请查看部署记录"; else if(r.stage && r.stage !== "success") msg = "部署已提交，仍在处理中"; if(r.warning) msg += "（" + r.warning + "）"; showNotification(msg + (r.url ? ("：" + r.url) : ""), r.warning ? "warning" : "success"); pagesDeployStatus(r.warning || ""); clearPagesUpload(); setTimeout(refreshPagesDeployments, 1500); }
    else { showNotification((r && r.error) || "部署失败", "error"); pagesDeployStatus((r && r.error) || "部署失败", true); }
  }catch(e){ showNotification(e.message || "部署失败", "error"); pagesDeployStatus(e.message || "部署失败", true); }
  btn.disabled = false; btn.textContent = "上传并部署";
}
async function startPagesGithubDeploy(){
  var url = el("pagesGithubUrl").value.trim();
  if(!url) return showNotification("请输入 GitHub 仓库地址", "error");
  var btn = el("pagesGithubBtn"); btn.disabled = true; btn.textContent = "导入中...";
  pagesDeployStatus("正在从 GitHub 下载仓库并部署，请稍候...");
  try{
    var aid = await ensureAccountId();
    var r = await api("pages-deploy-github", { accountId: aid, projectName: currentPagesProject, repoUrl: url, branch: el("pagesGithubBranch").value.trim() });
    if(r && r.success){ var msg = "部署成功"; if(r.warning) msg += "（" + r.warning + "）"; showNotification(msg + (r.url ? ("：" + r.url) : ""), r.warning ? "warning" : "success"); pagesDeployStatus(r.warning || ""); setTimeout(refreshPagesDeployments, 1500); }
    else { showNotification((r && r.error) || "部署失败", "error"); pagesDeployStatus((r && r.error) || "部署失败", true); }
  }catch(e){ showNotification(e.message || "部署失败", "error"); pagesDeployStatus(e.message || "部署失败", true); }
  btn.disabled = false; btn.textContent = "导入并部署";
}
async function viewPagesDeployments(name){
  currentPagesProject = name;
  el("pagesProjectName").textContent = "部署记录 - " + name;
  el("pagesProjectsList").style.display = "none"; el("pagesDeploySection").style.display = "block";
  refreshPagesDeployments();
}
async function refreshPagesDeployments(){
  var aid = await ensureAccountId();
  el("pagesDeployList").innerHTML = "加载中...";
  refreshPagesOverview();
  var r = await api("list-pages-deployments", { accountId: aid, projectName: currentPagesProject });
  var arr = (r && r.result) || [];
  if(!arr.length){ el("pagesDeployList").innerHTML = "<div class=\"small\" style=\"padding:12px\">暂无部署</div>"; return; }
  el("pagesDeployList").innerHTML = "";
  arr.forEach(function(d){
    var st = d.latest_stage && d.latest_stage.name, ok = d.latest_stage && d.latest_stage.status === "success";
    var failed = d.latest_stage && d.latest_stage.status === "failure";
    var div = document.createElement("div"); div.className = "deploy-item";
    var btns = "<div class=\"btns\">";
    if(d.url) btns += "<a class=\"btn small\" href=\"" + escA(d.url) + "\" target=\"_blank\">访问</a>";
    if(failed) btns += "<button class=\"btn small\" data-a=\"retry\" data-id=\"" + escA(d.id) + "\">重试</button>";
    btns += "<button class=\"btn small\" data-a=\"rollback\" data-id=\"" + escA(d.id) + "\" title=\"回滚到此版本\">回滚</button>";
    btns += "<button class=\"trash-btn\" data-a=\"del\" data-id=\"" + escA(d.id) + "\">✕</button></div>";
    div.innerHTML = "<div style=\"flex:1;min-width:0\"><div style=\"font-weight:600;font-family:monospace;font-size:12px\">" + esc(String(d.id).slice(0, 8)) + " <span class=\"pill " + (ok ? "green" : (failed ? "red" : "amber")) + "\">" + esc(st || "?") + "</span></div>" +
      "<div class=\"small\">" + esc(d.branch || "") + " · " + esc(fmtBJ(d.created_on)) + "</div></div>" + btns;
    var rb = div.querySelector("[data-a=\"retry\"]");
    if(rb) rb.addEventListener("click", function(){ retryPagesDeployment(this.getAttribute("data-id")); });
    var rbb = div.querySelector("[data-a=\"rollback\"]");
    if(rbb) rbb.addEventListener("click", function(){ rollbackPagesDeployment(this.getAttribute("data-id")); });
    div.querySelector("[data-a=\"del\"]").addEventListener("click", function(){ deletePagesDeployment(this.getAttribute("data-id")); });
    el("pagesDeployList").appendChild(div);
  });
}
async function refreshPagesOverview(){
  var box = el("pagesProjectOverview");
  if(!box) return;
  box.innerHTML = "<div class=\"small\">加载中...</div>";
  try{
    var aid = await ensureAccountId();
    var r = await api("get-pages-project-overview", { accountId: aid, projectName: currentPagesProject });
    var o = (r && r.result) || {};
    var html = "";
    var domains = o.domains || [];
    html += "<div style=\"margin-bottom:10px\"><span class=\"label\">自定义域名（" + domains.length + "）</span><div style=\"margin-top:6px\">";
    if(!domains.length) html += "<span class=\"small\">暂无</span>";
    domains.forEach(function(dm){
      var cls = dm.status === "active" ? "green" : "amber";
      html += "<a class=\"domain-tag\" href=\"https://" + escA(dm.name) + "\" target=\"_blank\">" + esc(dm.name) + "<span class=\"domain-status " + cls + "\">" + esc(dm.status || "?") + "</span></a>";
    });
    html += "</div></div>";
    var mainUrl = (o.canonical_deployment && o.canonical_deployment.url) || ((o.latest_deployment && o.latest_deployment.url) || "");
    html += "<div style=\"margin-bottom:10px\"><span class=\"label\">主域名</span><div style=\"margin-top:6px\">" + (mainUrl ? "<a class=\"domain-tag workers-dev\" href=\"" + escA(mainUrl) + "\" target=\"_blank\">" + esc(mainUrl.replace(/^https?:\/\//, "")) + "</a>" : "<span class=\"small\">-</span>") + "</div></div>";
    html += "<div><span class=\"label\">绑定</span><div class=\"worker-tag-rows\" style=\"margin-top:6px;align-items:flex-start\">";
    html += tagRow("环境变量", (o.env_vars || []).map(function(n){ return "<span class=\"res-tag env\">" + esc(n) + "</span>"; }).join(""), true);
    html += tagRow("KV", (o.kv_namespaces || []).map(function(n){ return "<span class=\"res-tag kv\">" + esc(n) + "</span>"; }).join(""), true);
    html += tagRow("D1", (o.d1_databases || []).map(function(n){ return "<span class=\"res-tag d1\">" + esc(n) + "</span>"; }).join(""), true);
    html += "</div></div>";
    box.innerHTML = html;
  }catch(e){ box.innerHTML = "<div class=\"small\">加载失败</div>"; }
}
async function triggerPagesDeploy(){
  var btn = document.querySelector("#pagesDeploySection .btn.primary");
  if(btn){ btn.disabled = true; btn.textContent = "部署中..."; }
  try{
    var aid = await ensureAccountId();
    var r = await api("trigger-pages-deployment", { accountId: aid, projectName: currentPagesProject });
    if(r && r.success){ showNotification("已触发部署"); setTimeout(refreshPagesDeployments, 1200); }
    else throw new Error((r && r.error) || "触发失败");
  }catch(err){ showNotification(err.message || "触发失败", "error"); }
  if(btn){ btn.disabled = false; btn.textContent = "触发部署"; }
}
async function retryPagesDeployment(id){
  var aid = await ensureAccountId();
  var r = await api("retry-pages-deployment", { accountId: aid, projectName: currentPagesProject, deploymentId: id });
  if(r && r.success){ showNotification("已重试"); setTimeout(refreshPagesDeployments, 1500); } else showNotification((r && r.error) || "重试失败（仅失败的部署可重试）", "error");
}
async function rollbackPagesDeployment(id){
  if(!confirm("回滚到部署 " + String(id).slice(0, 8) + "？将下载该版本的页面文件并重新部署为新版本。")) return;
  var aid = await ensureAccountId();
  showNotification("正在回滚，请稍候...", "warning");
  var r = await api("rollback-pages-deployment", { accountId: aid, projectName: currentPagesProject, deploymentId: id });
  if(r && r.success){ showNotification(r.message || "回滚成功"); setTimeout(refreshPagesDeployments, 2000); } else showNotification((r && r.error) || "回滚失败", "error");
}
async function deletePagesDeployment(id){
  if(!confirm("删除此部署？")) return;
  var aid = await ensureAccountId();
  var r = await api("delete-pages-deployment", { accountId: aid, projectName: currentPagesProject, deploymentId: id });
  if(r && r.success){ showNotification("已删除"); refreshPagesDeployments(); } else showNotification((r && r.error) || "失败", "error");
}
var pagesDomainsProject = "";
var pagesDomainZonesCache = [];
var pagesDomainTab = "cf";
function switchPagesDomainTab(mode){
  pagesDomainTab = mode;
  el("pagesDomainCfPane").style.display = mode === "cf" ? "block" : "none";
  el("pagesDomainExtPane").style.display = mode === "ext" ? "block" : "none";
  el("pagesDomainTabCf").className = "btn small" + (mode === "cf" ? " primary" : "");
  el("pagesDomainTabExt").className = "btn small" + (mode === "ext" ? " primary" : "");
  if(mode === "ext" && pagesDomainsProject) el("pagesDomainCnameTarget").textContent = pagesDomainsProject + ".pages.dev";
}
async function openPagesDomains(name){
  pagesDomainsProject = name || currentPagesProject;
  if(!pagesDomainsProject) return showNotification("请先进入一个项目", "error");
  el("pagesDomainsModal").style.display = "flex";
  switchPagesDomainTab("cf");
  el("pagesDomainsList").innerHTML = "加载中...";
  await loadPagesDomainZones();
  refreshPagesDomainsList();
}
async function refreshPagesDomainsList(){
  el("pagesDomainsList").innerHTML = "加载中...";
  var aid = await ensureAccountId();
  var r = await api("list-pages-domains", { accountId: aid, projectName: pagesDomainsProject });
  var arr = (r && r.result) || [];
  el("pagesDomainsList").innerHTML = "";
  if(!arr.length) el("pagesDomainsList").innerHTML = "<div class=\"small\">暂无自定义域名</div>";
  // 判断域名是否在 Cloudflare 托管（后缀匹配 zone）
  var zones = pagesDomainZonesCache || [];
  function isCfHosted(host){
    var h = String(host || "").toLowerCase();
    for(var i = 0; i < zones.length; i++){
      var z = String(zones[i] || "").toLowerCase();
      if(h === z || h.endsWith("." + z)) return true;
    }
    return false;
  }
  arr.forEach(function(dm){
    var st = dm.status === "active" ? "<span class=\"pill green\">已启用</span>" : "<span class=\"pill amber\">" + esc(dm.status || "?") + "</span>";
    var d = document.createElement("div"); d.className = "deploy-item";
    var hint = "";
    if(dm.status !== "active" && pagesDomainsProject){
      if(isCfHosted(dm.name)){
        hint = "<div class=\"small\" style=\"color:#6b7280;margin-top:4px\">Cloudflare 托管域名，DNS 自动配置中，稍后刷新查看</div>";
      } else {
        hint = "<div class=\"small\" style=\"color:#92400e;margin-top:4px\">外部域名，请手动添加 CNAME：" + esc(dm.name) + " → " + esc(pagesDomainsProject + ".pages.dev") + "</div>";
      }
    }
    d.innerHTML = "<div style=\"flex:1\"><a href=\"https://" + escA(dm.name) + "\" target=\"_blank\" style=\"color:#3b82f6;font-weight:600\">" + esc(dm.name) + "</a> " + st + hint + "</div>";
    var btn = document.createElement("button"); btn.className = "trash-btn"; btn.textContent = "✕"; btn.title = "删除";
    btn.addEventListener("click", function(){ deletePagesDomain(dm.name); });
    d.appendChild(btn); el("pagesDomainsList").appendChild(d);
  });
}
async function loadPagesDomainZones(){
  el("pagesDomainPrefix").value = ""; pagesDomainZonesCache = [];
  el("pagesDomainZoneWrap").innerHTML = '<div class="small">加载域名中...</div>'; updatePagesDomainPreview();
  var r = await api("list-zones");
  var zones = (r && r.success && r.result) ? r.result : [];
  pagesDomainZonesCache = zones.map(function(z){ return z.name; });
  if(!zones.length) el("pagesDomainZoneWrap").innerHTML = '<div class="small" style="color:#ef4444">该账号下没有可用域名，请先到「域名管理」添加</div>';
  else {
    var opts = zones.map(function(z){ return '<option value="' + escA(z.name) + '">' + esc(z.name) + '</option>'; }).join("");
    el("pagesDomainZoneWrap").innerHTML = '<select id="pagesDomainZone" class="input" onchange="updatePagesDomainPreview()">' + opts + '</select>';
  }
  updatePagesDomainPreview();
}
function updatePagesDomainPreview(){
  var prefix = el("pagesDomainPrefix").value.trim().replace(/\.$/, "");
  var zone = "", sel = el("pagesDomainZone");
  if(sel) zone = sel.value; else if(pagesDomainZonesCache.length === 1) zone = pagesDomainZonesCache[0];
  el("pagesDomainPreview").textContent = prefix ? (prefix + "." + zone) : zone;
}
function closePagesDomains(){ el("pagesDomainsModal").style.display = "none"; }
async function confirmAddPagesDomain(){
  var aid = await ensureAccountId();
  var h = "";
  if(pagesDomainTab === "ext"){
    h = el("pagesDomainExternal").value.trim().toLowerCase().replace(/\.$/, "");
    if(!h || h.indexOf(".") < 0) return showNotification("请输入完整的外部域名", "error");
  } else {
    var prefix = el("pagesDomainPrefix").value.trim().replace(/\.$/, "");
    var zone = "", sel = el("pagesDomainZone");
    if(sel) zone = sel.value; else if(pagesDomainZonesCache.length === 1) zone = pagesDomainZonesCache[0];
    if(!zone) return showNotification("没有可用域名", "error");
    h = prefix ? (prefix + "." + zone) : zone;
  }
  var r = await api("add-pages-domain", { accountId: aid, projectName: pagesDomainsProject, hostname: h });
  if(r && r.success){
    if(pagesDomainTab === "ext"){
      showNotification("添加成功！请到 DNS 服务商添加 CNAME：" + h + " → " + pagesDomainsProject + ".pages.dev", "warning");
    } else {
      showNotification("添加成功" + (r.dnsNote || ""));
    }
    el("pagesDomainPrefix").value = ""; el("pagesDomainExternal").value = ""; refreshPagesDomainsList();
  } else showNotification((r && r.error) || "失败", "error");
}
async function deletePagesDomain(h){
  if(!confirm("删除域名 " + h + "？")) return;
  var aid = await ensureAccountId();
  var r = await api("delete-pages-domain", { accountId: aid, projectName: pagesDomainsProject, hostname: h });
  if(r && r.success){ showNotification("已删除"); refreshPagesDomainsList(); } else showNotification((r && r.error) || "失败", "error");
}
var pagesBindKvCache = [], pagesBindD1Cache = [];
async function openPagesBindModal(){
  var name = currentPagesProject; if(!name) return showNotification("请先进入一个项目", "error");
  el("pagesBindProjectName").textContent = name; el("pagesBindModal").style.display = "flex";
  el("pagesEnvRows").innerHTML = "加载中..."; el("pagesKvRows").innerHTML = ""; el("pagesD1Rows").innerHTML = "";
  var aid = await ensureAccountId();
  var kvr = await api("list-kv-namespaces", { accountId: aid });
  pagesBindKvCache = (kvr && kvr.success && kvr.result) ? kvr.result : [];
  var d1r = await api("list-d1", { accountId: aid });
  pagesBindD1Cache = (d1r && d1r.success && d1r.result) ? d1r.result : [];
  var r = await api("get-pages-bindings", { accountId: aid, projectName: name });
  var prod = (r && r.success && r.result && (r.result.production || r.result.preview)) || {};
  el("pagesEnvRows").innerHTML = "";
  var ev = prod.env_vars || {};
  Object.keys(ev).forEach(function(k){ var eo = ev[k] || {}; addPagesEnvRow(k, eo.value || "", (eo.type === "secret_text") ? "secret" : "text"); });
  var kv = prod.kv_namespaces || {};
  Object.keys(kv).forEach(function(k){ addPagesKvRow(k, kv[k] && kv[k].namespace_id); });
  var d1o = prod.d1_databases || prod.d1 || {}, d1map = d1o.d1_databases ? d1o.d1_databases : d1o;
  Object.keys(d1map).forEach(function(k){ var v = d1map[k]; addPagesD1Row(k, v && (v.id || v.database_id)); });
}
function closePagesBindModal(){ el("pagesBindModal").style.display = "none"; }
function switchPagesBindTab(tab){
  document.querySelectorAll("#pagesBindModal [data-pbtab]").forEach(function(e){ e.classList.toggle("active", e.getAttribute("data-pbtab") === tab); });
  el("pbind-env").style.display = tab === "env" ? "block" : "none";
  el("pbind-kv").style.display = tab === "kv" ? "block" : "none";
  el("pbind-d1").style.display = tab === "d1" ? "block" : "none";
}
function pagesBindDelBtn(div){
  var btn = document.createElement("button"); btn.className = "trash-btn"; btn.textContent = "✕";
  btn.addEventListener("click", function(){ div.remove(); });
  div.appendChild(btn);
}
function addPagesEnvRow(n, v, t){
  var div = document.createElement("div"); div.className = "env-row-batch";
  div.innerHTML = '<input class="input pb-name" placeholder="变量名" value="' + escA(n || "") + '" style="flex:2"><input class="input pb-val" placeholder="值" value="' + escA(v || "") + '" style="flex:2" type="' + ((t === "secret") ? "password" : "text") + '"><select class="input pb-type" style="flex:1;max-width:110px"><option value="text"' + ((t !== "secret") ? " selected" : "") + '>明文</option><option value="secret"' + ((t === "secret") ? " selected" : "") + '>密钥</option></select>';
  div.querySelector(".pb-type").addEventListener("change", function(){
    div.querySelector(".pb-val").type = (this.value === "secret") ? "password" : "text";
  });
  pagesBindDelBtn(div); el("pagesEnvRows").appendChild(div);
}
function addPagesKvRow(binding, nsId){
  var div = document.createElement("div"); div.className = "env-row-batch";
  var opts = pagesBindKvCache.map(function(ns){ return '<option value="' + escA(ns.id) + '"' + (ns.id === nsId ? " selected" : "") + '>' + esc((ns.title || ns.id) + " (" + ns.id + ")") + '</option>'; }).join("");
  div.innerHTML = '<input class="input pb-name" placeholder="绑定名，如 KV" value="' + escA(binding || "") + '" style="flex:2"><select class="input pb-val" style="flex:3">' + opts + '</select>';
  pagesBindDelBtn(div); el("pagesKvRows").appendChild(div);
}
function addPagesD1Row(binding, dbId){
  var div = document.createElement("div"); div.className = "env-row-batch";
  var opts = pagesBindD1Cache.map(function(db){ var id = db.uuid || db.id; return '<option value="' + escA(id) + '"' + (id === dbId ? " selected" : "") + '>' + esc((db.name || id) + " (" + id + ")") + '</option>'; }).join("");
  div.innerHTML = '<input class="input pb-name" placeholder="绑定名，如 DB" value="' + escA(binding || "") + '" style="flex:2"><select class="input pb-val" style="flex:3">' + opts + '</select>';
  pagesBindDelBtn(div); el("pagesD1Rows").appendChild(div);
}
async function savePagesBindings(){
  var envVars = {}, kv = {}, d1 = {};
  Array.from(document.querySelectorAll("#pagesEnvRows .env-row-batch")).forEach(function(row){
    var n = row.querySelector(".pb-name").value.trim(), v = row.querySelector(".pb-val").value;
    var t = row.querySelector(".pb-type") ? row.querySelector(".pb-type").value : "text";
    if(n) envVars[n] = { value: v, type: t };
  });
  Array.from(document.querySelectorAll("#pagesKvRows .env-row-batch")).forEach(function(row){
    var n = row.querySelector(".pb-name").value.trim(), v = row.querySelector(".pb-val").value;
    if(n && v) kv[n] = v;
  });
  Array.from(document.querySelectorAll("#pagesD1Rows .env-row-batch")).forEach(function(row){
    var n = row.querySelector(".pb-name").value.trim(), v = row.querySelector(".pb-val").value;
    if(n && v) d1[n] = v;
  });
  var aid = await ensureAccountId();
  var r = await api("set-pages-bindings", { accountId: aid, projectName: currentPagesProject, envVars: envVars, kv: kv, d1: d1 });
  if(r && r.success){ showNotification("绑定已保存"); closePagesBindModal(); } else showNotification((r && r.error) || "保存失败", "error");
}
window.refreshPagesProjects = refreshPagesProjects; window.backToPagesProjects = backToPagesProjects;
window.openCreatePagesProject = openCreatePagesProject; window.closeCreatePagesModal = closeCreatePagesModal; window.confirmCreatePagesProject = confirmCreatePagesProject;
window.switchPagesDeployTab = switchPagesDeployTab; window.clearPagesUpload = clearPagesUpload; window.startPagesUpload = startPagesUpload; window.startPagesGithubDeploy = startPagesGithubDeploy; window.refreshPagesUploadList = refreshPagesUploadList;
window.viewPagesDeployments = viewPagesDeployments; window.refreshPagesDeployments = refreshPagesDeployments; window.triggerPagesDeploy = triggerPagesDeploy;
window.retryPagesDeployment = retryPagesDeployment; window.deletePagesDeployment = deletePagesDeployment; window.rollbackPagesDeployment = rollbackPagesDeployment;
window.openPagesDomains = openPagesDomains; window.closePagesDomains = closePagesDomains; window.confirmAddPagesDomain = confirmAddPagesDomain; window.deletePagesProject = deletePagesProject; window.switchPagesDomainTab = switchPagesDomainTab; window.updatePagesDomainPreview = updatePagesDomainPreview;
window.refreshPagesDomainsList = refreshPagesDomainsList; window.loadPagesDomainZones = loadPagesDomainZones; window.updatePagesDomainPreview = updatePagesDomainPreview; window.deletePagesDomain = deletePagesDomain;
window.openPagesBindModal = openPagesBindModal; window.closePagesBindModal = closePagesBindModal; window.switchPagesBindTab = switchPagesBindTab; window.addPagesEnvRow = addPagesEnvRow; window.addPagesKvRow = addPagesKvRow; window.addPagesD1Row = addPagesD1Row; window.savePagesBindings = savePagesBindings;
// Pages 兼容日期
var pagesCompatSelectedDate = "";
async function openPagesCompatModal(){
  if(!currentPagesProject) return showNotification("请先进入一个项目", "error");
  el("pagesCompatProjectName").textContent = currentPagesProject;
  pagesCompatSelectedDate = "";
  el("pagesCompatDateInput").value = "";
  el("pagesCompatModal").style.display = "flex";
  el("pagesCompatCurrentVal").textContent = "";
  renderPagesCompatDateList("");
  try{
    var aid = await ensureAccountId();
    var r = await api("get-pages-project-overview", { accountId: aid, projectName: currentPagesProject });
    var dc = (r && r.result && r.result.deployment_configs) || {};
    var cd = ((dc.production || {}).compatibility_date) || ((dc.preview || {}).compatibility_date) || "";
    var m = String(cd).match(/^(\d{4}-\d{2}-\d{2})/);
    if(m){ pagesCompatSelectedDate = m[1]; el("pagesCompatDateInput").value = m[1]; el("pagesCompatCurrentVal").textContent = "（当前: " + m[1] + "）"; renderPagesCompatDateList(m[1]); }
  }catch(e){}
}
function renderPagesCompatDateList(activeDate){
  var html = "";
  COMPAT_DATE_LIST.forEach(function(item){
    var isActive = item.date === activeDate;
    html += "<div data-pcdate=\"" + item.date + "\" style=\"border:1px solid " + (isActive ? "#2563eb" : "#e6edf3") + ";border-radius:8px;padding:12px;margin-bottom:8px;cursor:pointer;background:" + (isActive ? "#eff6ff" : "#fff") + "\">";
    html += "<div style=\"font-weight:600;font-size:14px\">📅 " + esc(item.date) + "</div>";
    item.changes.forEach(function(c){ html += "<div class=\"small\" style=\"margin-top:4px\">• " + esc(c) + "</div>"; });
    html += "</div>";
  });
  el("pagesCompatDateList").innerHTML = html;
  Array.from(el("pagesCompatDateList").querySelectorAll("[data-pcdate]")).forEach(function(d){
    d.addEventListener("click", function(){ pagesCompatSelectedDate = this.getAttribute("data-pcdate"); el("pagesCompatDateInput").value = pagesCompatSelectedDate; renderPagesCompatDateList(pagesCompatSelectedDate); });
  });
}
function closePagesCompatModal(){ el("pagesCompatModal").style.display = "none"; pagesCompatSelectedDate = ""; }
async function confirmPagesCompatDate(){
  var d = (pagesCompatSelectedDate || el("pagesCompatDateInput").value || "").trim();
  if(!d) return showNotification("请选择兼容日期", "error");
  if(!/^\d{4}-\d{2}-\d{2}$/.test(d)) return showNotification("日期格式不正确", "error");
  var aid = await ensureAccountId();
  showNotification("正在保存...", "success");
  var r = await api("set-pages-compatibility", { accountId: aid, projectName: currentPagesProject, compatibilityDate: d });
  if(r && r.success){ showNotification("Pages 兼容日期已更新为 " + d); closePagesCompatModal(); }
  else showNotification((r && r.error) || "更新失败", "error");
}
// Pages 兼容性标志
var pagesCompatSelectedFlags = [];
async function openPagesCompatFlagsModal(){
  if(!currentPagesProject) return showNotification("请先进入一个项目", "error");
  el("pagesCompatFlagsProjectName").textContent = currentPagesProject;
  pagesCompatSelectedFlags = [];
  el("pagesCompatFlagsCustom").value = "";
  el("pagesCompatFlagsModal").style.display = "flex";
  el("pagesCompatFlagsCurrent").textContent = "";
  renderPagesCompatFlagsList();
  try{
    var aid = await ensureAccountId();
    var r = await api("get-pages-project-overview", { accountId: aid, projectName: currentPagesProject });
    var dc = (r && r.result && r.result.deployment_configs) || {};
    var flags = ((dc.production || {}).compatibility_flags) || ((dc.preview || {}).compatibility_flags) || [];
    if(Array.isArray(flags) && flags.length){
      pagesCompatSelectedFlags = flags.slice();
      el("pagesCompatFlagsCurrent").textContent = "（当前: " + flags.join(", ") + "）";
      renderPagesCompatFlagsList();
    }
  }catch(e){}
}
function renderPagesCompatFlagsList(){
  var html = "";
  var allFlags = COMPAT_FLAGS_LIST.slice();
  pagesCompatSelectedFlags.forEach(function(f){ if(allFlags.indexOf(f) < 0) allFlags.push(f); });
  allFlags.forEach(function(f){
    var on = pagesCompatSelectedFlags.indexOf(f) >= 0;
    html += "<label style=\"display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid " + (on ? "#2563eb" : "#e6edf3") + ";border-radius:8px;margin-bottom:6px;cursor:pointer;background:" + (on ? "#eff6ff" : "#fff") + "\">";
    html += "<input type=\"checkbox\" data-pcflag=\"" + escA(f) + "\"" + (on ? " checked" : "") + " onchange=\"togglePagesCompatFlag(this)\">";
    html += "<span style=\"font-family:monospace;font-size:13px\">" + esc(f) + "</span></label>";
  });
  el("pagesCompatFlagsList").innerHTML = html || "<div class=\"small\">无可用标志</div>";
}
function togglePagesCompatFlag(cb){
  var f = cb.getAttribute("data-pcflag");
  var i = pagesCompatSelectedFlags.indexOf(f);
  if(cb.checked && i < 0) pagesCompatSelectedFlags.push(f);
  else if(!cb.checked && i >= 0) pagesCompatSelectedFlags.splice(i, 1);
  renderPagesCompatFlagsList();
}
function addCustomPagesCompatFlag(){
  var f = el("pagesCompatFlagsCustom").value.trim();
  if(!f) return;
  if(pagesCompatSelectedFlags.indexOf(f) < 0) pagesCompatSelectedFlags.push(f);
  el("pagesCompatFlagsCustom").value = "";
  renderPagesCompatFlagsList();
}
function closePagesCompatFlagsModal(){ el("pagesCompatFlagsModal").style.display = "none"; pagesCompatSelectedFlags = []; }
async function confirmPagesCompatFlags(){
  var aid = await ensureAccountId();
  showNotification("正在保存...", "success");
  var r = await api("set-pages-compatibility", { accountId: aid, projectName: currentPagesProject, flags: pagesCompatSelectedFlags });
  if(r && r.success){ showNotification("Pages 兼容性标志已更新"); closePagesCompatFlagsModal(); }
  else showNotification((r && r.error) || "更新失败", "error");
}
window.openPagesCompatModal = openPagesCompatModal; window.closePagesCompatModal = closePagesCompatModal; window.confirmPagesCompatDate = confirmPagesCompatDate;
window.openPagesCompatFlagsModal = openPagesCompatFlagsModal; window.closePagesCompatFlagsModal = closePagesCompatFlagsModal;
window.confirmPagesCompatFlags = confirmPagesCompatFlags; window.togglePagesCompatFlag = togglePagesCompatFlag; window.addCustomPagesCompatFlag = addCustomPagesCompatFlag;
var _cfSubdomain = "";
async function loadSubdomainSettings(){
  // OAuth Client ID 配置回显
  var ocb = el("oauthCbUrl"); if(ocb) ocb.textContent = location.origin + "/oauth/callback";
  var oinp = el("oauthClientIdInput"); if(oinp) oinp.value = getOAuthClientId();
  var ohint = el("oauthClientIdHint");
  if(ohint) ohint.textContent = localStorage.getItem("cfm_oauth_client_id") ? "已使用自定义 Client ID" : "当前使用内置默认 Client ID";
  var aid = await ensureAccountId();
  el("currentSubdomain").textContent = "加载中..."; _cfSubdomain = "";
  var r = await api("get-workers-subdomain", { accountId: aid });
  var inp = el("newSubdomain"), btn = el("saveSubdomainBtn");
  if(r && r.success && r.result && r.result.subdomain){
    _cfSubdomain = r.result.subdomain;
    el("currentSubdomain").textContent = r.result.subdomain + ".workers.dev";
    if(inp){ inp.value = r.result.subdomain; inp.disabled = true; }
    if(btn){ btn.disabled = true; btn.textContent = "已设置"; }
    el("subdomainHint").textContent = "该账号已设置 workers.dev 子域名，每个账号仅可设置一次，无法修改。";
  } else {
    el("currentSubdomain").textContent = "未设置";
    if(inp) inp.disabled = false;
    if(btn){ btn.disabled = false; btn.textContent = "保存设置"; }
    el("subdomainHint").textContent = "设置后，您的 Workers 将通过 https://worker-name.子域名.workers.dev 访问";
  }
}
async function saveSubdomain(){
  var s = el("newSubdomain").value.trim();
  if(!s) return showNotification("请输入子域名", "error");
  if(_cfSubdomain){
    if(s === _cfSubdomain) return showNotification("子域名已是 " + s + "，无需重复设置");
    return showNotification("该账号已设置子域名 " + _cfSubdomain + "，每个账号仅可设置一次，无法修改", "error");
  }
  if(!confirm("确定将 workers.dev 子域名设置为 " + s + " 吗？只能设置一次，设置后无法修改！")) return;
  var aid = await ensureAccountId();
  var r = await api("put-workers-subdomain", { accountId: aid, subdomain: s });
  if(r && r.success){ showNotification("设置成功"); loadSubdomainSettings(); }
  else {
    var msg = (r && r.error) || "设置失败";
    if(msg.indexOf("associated subdomain") >= 0) msg = "该账号已设置过 workers.dev 子域名，每个账号仅可设置一次，无法修改";
    showNotification(msg, "error"); loadSubdomainSettings();
  }
}
window.saveSubdomain = saveSubdomain;
window.debugOut = debugOut; window.closeOut = closeOut;
async function initApp(){
  if(!getActiveAccount()){ location.href = "/login"; return; }
  // 存量 OAuth 账号标签迁移：把通用的“OAuth 授权”换成真实邮箱（只对旧存档跑一次）
  try {
    var _ma = getActiveAccount();
    if(_ma && _ma.mode === "oauth" && (!_ma.label || _ma.label === "OAuth 授权")){
      var _ur = await api("oauth-userinfo", {});
      if(_ur && _ur.success && _ur.email){
        var _arr = loadSaved(); var _idx = getActiveIdx();
        if(_arr[_idx] && _arr[_idx].mode === "oauth"){ _arr[_idx].label = _ur.email; saveAccounts(_arr); }
      }
    }
  } catch(e){}
  var _acc0 = getActiveAccount();
  if(_acc0){
    var _label0 = accountTitle(_acc0);
    var _pill0 = _acc0.mode === "token" ? "blue" : (_acc0.mode === "oauth" ? "green" : "amber");
    var _mt0 = _acc0.mode === "token" ? "Token" : (_acc0.mode === "oauth" ? "OAuth" : "Key");
    el("acctInfo").innerHTML = "<span style=\"font-weight:600\">" + esc(_label0) + "</span> <span class=\"pill " + _pill0 + "\">" + _mt0 + "</span><br><span class=\"small\">验证中...</span>";
  }
  var r;
  try { r = await api("validate-credentials"); } catch(e){ r = null; }
  if(r && r.success && r.result && r.result.length){
    var a = getActiveAccount();
    // 自动修复 token 账号显示名：label 缺失或就是 token 本身时，用 Cloudflare 账号名
    if(a && a.mode === "token" && (!a.label || a.label === a.token) && r.result[0].name){
      a.label = r.result[0].name;
      var _arr = loadSaved(); var _idx = getActiveIdx();
      if(_idx >= 0){ _arr[_idx] = a; saveAccounts(_arr); }
    }
    var label = accountTitle(a);
    var pillCls = a.mode === "token" ? "blue" : (a.mode === "oauth" ? "green" : "amber");
    var modeTxt = a.mode === "token" ? "Token" : (a.mode === "oauth" ? "OAuth" : "Key");
    el("acctInfo").innerHTML = "<span style=\"font-weight:600\">" + esc(label) + "</span> <span class=\"pill " + pillCls + "\">" + modeTxt + "</span><br><span class=\"small\">" + r.result.length + " 个账号</span>";
    localStorage.setItem("cfm_accountId", r.result[0].id);
    currentAccountId = r.result[0].id;
    el("authModeBadge").textContent = modeTxt;
    el("authModeBadge").className = "pill " + pillCls;
    el("authModeInfo").textContent = "当前使用 " + (a.mode === "token" ? "API Token（推荐）" : (a.mode === "oauth" ? "OAuth 2.0 授权" : "Global API Key（旧版）")) + " 鉴权 · " + label;
  }
  refreshWorkers();
}
Array.from(document.querySelectorAll(".modal")).forEach(function(m){
  m.addEventListener("click", function(e){ if(e.target === m) m.style.display = "none"; });
});
document.addEventListener("click", function(e){
  var t = (e.target && e.target.closest) ? e.target.closest("[data-close-modal]") : null;
  if(t){ var m = t.closest(".modal"); if(m) m.style.display = "none"; }
});
document.addEventListener("keydown", function(e){
  if(e.key === "Escape") Array.from(document.querySelectorAll(".modal")).forEach(function(m){ m.style.display = "none"; });
});
initApp();
}
})();