// Cloudflare 第三方管理面板 v2（2026-09 重写）
// - 鉴权：支持 API Token（推荐）与 Global API Key（旧版）双模式
// - Workers：经典上传 + 新版 Versions 列表；自定义域名走账号级新接口 PUT /accounts/{id}/workers/domains
// - Secrets：支持 PATCH .../secrets-bulk 批量增删改
// - KV：bulk 批量写/删；D1：params 参数化查询 + /raw + 导出备份；R2：桶管理；Pages：项目/部署管理
// - DNS：PATCH 更新记录 + /dns_records/batch 批量导入
// 部署：wrangler deploy；可选环境变量 ACCESS_PASSWORD（访问密码）、CF_ACCOUNTS_KV（批量模板）

export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env);
  }
};

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

const DEFAULT_BATCH_TEMPLATES = [
  {
    key: 'cmliu',
    templateName: 'CMliu',
    sourceWorkerName: 'edge',
    workerName: 'edge',
    scriptUrl: 'https://raw.githubusercontent.com/cmliu/edgetunnel/refs/heads/main/_worker.js',
    env: [{ key: 'admin', value: '123456' }],
    kv: [{ bind: 'KV', name: 'cmliu_kv' }],
    d1: []
  },
  {
    key: 'laowang',
    templateName: 'laowang',
    sourceWorkerName: 'laowang',
    workerName: 'laowang',
    scriptUrl: 'https://raw.githubusercontent.com/eooce/Cloudflare-proxy/refs/heads/main/_worker.js',
    env: [{ key: 'PASSWORD', value: '123456' }],
    kv: [],
    d1: []
  },
  {
    key: 'Joey',
    templateName: 'Joey',
    sourceWorkerName: 'joey',
    workerName: 'joey',
    scriptUrl: 'https://raw.githubusercontent.com/byJoey/cfnew/refs/heads/main/%E5%B0%91%E5%B9%B4%E4%BD%A0%E7%9B%B8%E4%BF%A1%E5%85%89%E5%90%97',
    env: [{ key: 'u', value: '119d4f24-fe13-40ec-9df0-8fe19d30b914' }],
    kv: [{ bind: 'C', name: 'Joey_kv' }],
    d1: []
  },
  {
    key: 'lh',
    templateName: 'liehuo',
    sourceWorkerName: 'liehuo',
    workerName: 'liehuo',
    scriptUrl: 'https://raw.githubusercontent.com/xtgm/stallTCP1.32V2/refs/heads/main/_worker.js',
    env: [{ key: 'UUID', value: '119d4f24-fe13-40ec-9df0-8fe19d30b914' }, { key: 'WP', value: '123456' }, { key: 'SUB_PWD', value: '123456' }],
    kv: [{ bind: 'LH', name: 'lh_kv' }],
    d1: [{ bind: 'DB', name: 'lh_db' }]
  }
];

// ---------------- 会话 / 密码保护 ----------------
// HMAC-SHA256(password, 'cf-manager-session-v1') 作为会话凭证，不可逆推
async function sessionToken(password) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('cf-manager-session-v1'));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return 'sess_' + hex.slice(0, 48);
}
function getSessionToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)cf_session=([^;]+)/);
  return m ? m[1] : null;
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const p = url.pathname;
  const hasPassword = !!(env && env.ACCESS_PASSWORD);

  if (p === '/auth' && request.method === 'POST') {
    try {
      const body = await request.json();
      if (!hasPassword || body.password === env.ACCESS_PASSWORD) {
        const token = hasPassword ? await sessionToken(env.ACCESS_PASSWORD) : 'nopwd';
        return new Response(JSON.stringify({ success: true }), {
          headers: {
            'content-type': 'application/json',
            'Set-Cookie': 'cf_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800'
          }
        });
      }
      return new Response(JSON.stringify({ success: false, error: '密码错误' }), {
        status: 401, headers: { 'content-type': 'application/json' }
      });
    } catch (e) {
      return new Response(JSON.stringify({ success: false }), { status: 400, headers: { 'content-type': 'application/json' } });
    }
  }

  if (hasPassword) {
    const token = getSessionToken(request);
    const expected = await sessionToken(env.ACCESS_PASSWORD);
    const valid = !!(token && token === expected);
    const isPublic = p === '/login' || p === '/login/' || p === '/static.js' || p === '/static-v2.js' || p === '/static-v3.js' || p === '/auth' || p === '/oauth/callback';
    if (!valid && !isPublic) {
      if (request.method === 'GET') return Response.redirect(url.origin + '/login', 302);
      return new Response(JSON.stringify({ success: false, error: '未授权，请先输入访问密码' }), {
        status: 401, headers: { 'content-type': 'application/json' }
      });
    }
  }

  if ((p === '/static.js' || p === '/static-v2.js' || p === '/static-v3.js') && request.method === 'GET') {
    return new Response(renderStaticJS(), {
      headers: {
        'content-type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      }
    });
  }

  if (request.method === 'GET' && (p === '/' || p === '/index.html')) {
    return Response.redirect(url.origin + '/login', 302);
  }
  if (request.method === 'GET' && (p === '/login' || p === '/login/')) {
    return new Response(renderLoginHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (request.method === 'GET' && p.startsWith('/app')) {
    return new Response(renderAppHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (request.method === 'GET' && (p === '/admin' || p === '/admin/')) {
    return Response.redirect(url.origin + '/app', 302);
  }
  if (request.method === 'GET' && p === '/oauth/callback') {
    return new Response(renderOAuthCallbackHTML(), { headers: { 'content-type': 'text/html; charset=utf-8' } });
  }
  if (p === '/api' && request.method === 'POST') {
    return handleAPI(request, env);
  }
  return new Response('Not Found', { status: 404 });
}

// ---------------- Cloudflare API 底层 ----------------
function buildAuth(payload) {
  if (payload.authMode === 'token') {
    if (!payload.token) throw new Error('API Token required');
    return { mode: 'token', token: String(payload.token).trim() };
  }
  // OAuth 授权码模式拿到的 access_token，用法与 API Token 完全一致（Bearer）
  if (payload.authMode === 'oauth') {
    if (!payload.token) throw new Error('OAuth token required');
    return { mode: 'token', token: String(payload.token).trim() };
  }
  if (!payload.email || !payload.key) throw new Error('email & key required');
  return { mode: 'key', email: String(payload.email).trim(), key: String(payload.key).trim() };
}

function cfHeaders(auth) {
  if (auth.mode === 'token') return { 'Authorization': 'Bearer ' + auth.token };
  return { 'X-Auth-Email': auth.email, 'X-Auth-Key': auth.key };
}

// 统一请求：返回 { ok, status, data }
async function cfReq(method, path, auth, body, extra) {
  const url = path.startsWith('http') ? path : CF_API_BASE + path;
  const headers = cfHeaders(auth);
  const opts = { method, headers };
  if (body !== undefined && body !== null) {
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
      opts.body = body;
    } else {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
  }
  if (extra && extra.headers) Object.assign(headers, extra.headers);
  if (extra && extra.rawBody !== undefined) opts.body = extra.rawBody;
  const res = await fetch(url, opts);
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch (e) { data = { success: res.ok, raw: text.slice(0, 2000) }; }
  return { ok: res.ok, status: res.status, data };
}

function json(obj, status) {
  return new Response(JSON.stringify(obj, null, 2), { status: status || 200, headers: { 'content-type': 'application/json' } });
}
async function safeJSON(req) { try { return await req.json(); } catch (e) { return {}; } }

async function getAccountId(auth) {
  const r = await cfReq('GET', '/accounts', auth);
  const arr = r.data && r.data.result;
  if (Array.isArray(arr) && arr.length) return arr[0].id;
  throw new Error('无法获取 Account ID，请检查 Token 权限（需要 Account 读取权限）');
}

function normalizeDeployScript(scriptContent) {
  if (typeof scriptContent !== 'string' || !scriptContent) return scriptContent;
  if (!/\bwindow\b/.test(scriptContent)) return scriptContent;
  return scriptContent.replace(/\bwindow\b/g, 'globalThis');
}

// 下载脚本源码：直接 fetch 取完整响应体（不经过 cfReq 的 2000 字符截断）
// 优先 Accept: application/javascript 直取源码，失败回退 multipart 解析
async function downloadWorkerScript(auth, accountId, scriptName) {
  const path = '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName);
  async function doFetch(extraHeaders) {
    const resp = await fetch(CF_API_BASE + path, { method: 'GET', headers: Object.assign({}, cfHeaders(auth), extraHeaders || {}) });
    return { status: resp.status, text: await resp.text(), contentType: resp.headers.get('content-type') || '' };
  }
  let r = await doFetch({ 'Accept': 'application/javascript' });
  if (r.status === 404) return { ok: false, status: 404 };
  let rawText = r.text, contentType = r.contentType;
  // Accept 头被忽略、返回 JSON 包裹时：尝试解析，否则重取一次不带 Accept
  if (rawText.trim().startsWith('{')) {
    let parsed = null;
    try { parsed = JSON.parse(rawText); } catch (e) {}
    if (parsed && parsed.success === false) {
      r = await doFetch();
      if (r.status === 404) return { ok: false, status: 404 };
      rawText = r.text; contentType = r.contentType;
    } else if (parsed && parsed.result && parsed.result.script) {
      return { ok: true, status: 200, rawScript: parsed.result.script };
    }
  }
  let scriptContent = null;
  if (contentType.includes('multipart/form-data')) {
    const m = contentType.match(/boundary=([^;]+)/);
    const boundary = m ? m[1].trim() : null;
    if (boundary) {
      const parts = rawText.split('--' + boundary);
      for (const part of parts) {
        if (/Content-Type:\s*application\/javascript/i.test(part) || /filename="[^"]*\.m?js"/i.test(part) || /name="script"/i.test(part)) {
          const bm = part.match(/\r?\n\r?\n([\s\S]*)/);
          if (bm && bm[1]) { scriptContent = bm[1].replace(/\r?\n--\s*$/, '').trim(); break; }
        }
      }
    }
  } else if (!rawText.trim().startsWith('{')) {
    scriptContent = rawText;
  }
  if (!scriptContent && /export\s+default|addEventListener/.test(rawText)) {
    const mm = rawText.match(/(export\s+default[\s\S]+|addEventListener[\s\S]+)/);
    if (mm) scriptContent = mm[0].split(/\r?\n--/)[0].trim();
  }
  return { ok: true, status: 200, rawScript: scriptContent || rawText };
}

// 规范化 bindings（上传用）
function cleanBindingsForUpload(bindings) {
  return (bindings || []).map((b) => {
    const c = Object.assign({}, b);
    delete c.last_deployed_from;
    if (c.type === 'd1_database') c.type = 'd1';
    if (c.type === 'd1') return { type: 'd1', id: c.id || c.database_id, name: c.name };
    if (c.type === 'kv_namespace') return { type: 'kv_namespace', namespace_id: c.namespace_id || c.id, name: c.name };
    if (c.type === 'r2_bucket') return { type: 'r2_bucket', bucket_name: c.bucket_name || c.name, name: c.name };
    if (c.type === 'plain_text' || c.type === 'secret_text') {
      return { type: c.type, name: c.name, text: String(c.text != null ? c.text : '') };
    }
    if (c.type === 'json') {
      // Cloudflare 的 json 绑定走 `json` 字段（解析后的 JSON 值），不是 `text`
      const raw = c.json !== undefined && c.json !== null ? c.json : String(c.text != null ? c.text : '');
      try { return { type: 'json', name: c.name, json: typeof raw === 'string' ? JSON.parse(raw) : raw }; }
      catch (e) { throw new Error('变量「' + c.name + '」的 JSON 格式不正确：' + e.message); }
    }
    return c;
  });
}

async function uploadWorkerScript(auth, accountId, scriptName, scriptSource, metadataBindings, usageModel, compatibilityDate) {
  let finalScript = normalizeDeployScript(scriptSource);
  if (typeof finalScript !== 'string' || finalScript.trim().length === 0) {
    finalScript = "export default { async fetch() { return new Response('Deployed via CF Manager'); } };";
  }
  const isModule = finalScript.includes('export default') || finalScript.includes('export {');
  const form = new FormData();
  const metadata = { bindings: cleanBindingsForUpload(metadataBindings), usage_model: usageModel || 'standard' };
  if (compatibilityDate) metadata.compatibility_date = compatibilityDate;
  if (isModule) {
    metadata.main_module = 'worker.js';
    form.append('metadata', JSON.stringify(metadata));
    form.append('worker.js', new Blob([finalScript], { type: 'application/javascript+module' }), 'worker.js');
  } else {
    metadata.body_part = 'script';
    form.append('metadata', JSON.stringify(metadata));
    form.append('script', new Blob([finalScript], { type: 'application/javascript' }), 'worker.js');
  }
  const r = await cfReq('PUT', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName), auth, form);
  return r;
}

// ============ BLAKE3（Pages 资源哈希用，纯 JS 实现） ============
const B3_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];
const B3_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
function b3Rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function b3G(s, a, b, c, d, mx, my) {
  s[a] = (s[a] + s[b] + mx) | 0; s[d] = b3Rotr(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) | 0;     s[b] = b3Rotr(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + my) | 0; s[d] = b3Rotr(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) | 0;     s[b] = b3Rotr(s[b] ^ s[c], 7);
}
function b3Compress(cv, blockWords, counter, blockLen, flags) {
  const s = [cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
             B3_IV[0], B3_IV[1], B3_IV[2], B3_IV[3],
             counter >>> 0, 0, blockLen >>> 0, flags >>> 0];
  let m = blockWords.slice();
  for (let r = 0; r < 7; r++) {
    b3G(s, 0, 4, 8, 12, m[0], m[1]); b3G(s, 1, 5, 9, 13, m[2], m[3]);
    b3G(s, 2, 6, 10, 14, m[4], m[5]); b3G(s, 3, 7, 11, 15, m[6], m[7]);
    b3G(s, 0, 5, 10, 15, m[8], m[9]); b3G(s, 1, 6, 11, 12, m[10], m[11]);
    b3G(s, 2, 7, 8, 13, m[12], m[13]); b3G(s, 3, 4, 9, 14, m[14], m[15]);
    const nm = new Array(16);
    for (let i = 0; i < 16; i++) nm[i] = m[B3_PERM[i]];
    m = nm;
  }
  const out = new Array(16);
  for (let i = 0; i < 8; i++) { out[i] = (s[i] ^ s[i + 8]) | 0; out[i + 8] = (s[i + 8] ^ cv[i]) | 0; }
  return out;
}
function b3CV(inputCv, blockWords, counter, blockLen, flags) {
  return b3Compress(inputCv, blockWords, counter, blockLen, flags).slice(0, 8);
}
function blake3Hex(data) {
  const CHUNK = 1024, BLOCK = 64;
  const nChunks = Math.max(1, Math.ceil(data.length / CHUNK));
  const chunkOut = (c) => {
    const chunk = data.subarray(c * CHUNK, Math.min((c + 1) * CHUNK, data.length));
    const nBlocks = Math.max(1, Math.ceil(chunk.length / BLOCK));
    let inputCv = B3_IV.slice(), out = null;
    for (let b = 0; b < nBlocks; b++) {
      const block = chunk.subarray(b * BLOCK, Math.min((b + 1) * BLOCK, chunk.length));
      const words = new Array(16).fill(0);
      for (let i = 0; i < block.length; i++) words[i >> 2] |= block[i] << ((i & 3) * 8);
      let flags = 0;
      if (b === 0) flags |= 1;
      if (b === nBlocks - 1) flags |= 2;
      out = { inputCv, blockWords: words, counter: c, blockLen: block.length, flags };
      inputCv = b3CV(inputCv, words, c, block.length, flags);
    }
    return out;
  };
  const outCV = (o) => b3CV(o.inputCv, o.blockWords, o.counter, o.blockLen, o.flags);
  const parentOut = (leftCV, rightCV) => ({ inputCv: B3_IV.slice(), blockWords: leftCV.concat(rightCV), counter: 0, blockLen: BLOCK, flags: 4 });
  const parentCV = (leftCV, rightCV) => outCV(parentOut(leftCV, rightCV));
  const popcount = (n) => { let c = 0; n >>>= 0; while (n) { c += n & 1; n >>>= 1; } return c; };
  const doMerge = (stack, target) => {
    while (stack.length > target) {
      const right = stack.pop(), left = stack.pop();
      stack.push(parentCV(left, right));
    }
  };
  // 完成的分块：lazy merge 后入栈；最后一个分块留在 chunk_state
  const stack = [];
  let lastOut = null;
  for (let c = 0; c < nChunks; c++) {
    const out = chunkOut(c);
    if (c < nChunks - 1) {
      doMerge(stack, popcount(c));
      stack.push(outCV(out));
    } else lastOut = out;
  }
  // finalize 前的额外合并
  doMerge(stack, popcount(nChunks - 1));
  // 从右向左折叠
  let output = lastOut, n = stack.length;
  while (n > 0) { output = parentOut(stack[n - 1], outCV(output)); n--; }
  const root = output;
  const w = b3Compress(root.inputCv, root.blockWords, root.counter, root.blockLen, root.flags | 8);
  // 字按小端字节序输出
  let hex = '';
  for (let i = 0; i < 8; i++) {
    const v = w[i] >>> 0;
    hex += ('0' + (v & 255).toString(16)).slice(-2) + ('0' + ((v >>> 8) & 255).toString(16)).slice(-2)
         + ('0' + ((v >>> 16) & 255).toString(16)).slice(-2) + ('0' + ((v >>> 24) & 255).toString(16)).slice(-2);
  }
  return hex;
}
function u8ToBase64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function base64ToU8(b64) {
  const s = atob(String(b64 || ''));
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
// ============ 一键部署用辅助函数 ============
// 直链 URL 安全检查：仅 http/https，拒绝内网/本地地址
function checkUrlSafe(rawUrl) {
  const url = String(rawUrl || '').trim();
  if (!url) return { ok: false, error: 'url required' };
  let u;
  try { u = new URL(url); } catch (e) { return { ok: false, error: '无效的 URL' }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { ok: false, error: '仅支持 http/https' };
  const host = u.hostname.toLowerCase();
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '169.254.169.254' ||
      host.startsWith('10.') || host.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host.endsWith('.internal') || host.endsWith('.local')) {
    return { ok: false, error: '内网/本地地址不允许' };
  }
  return { ok: true, url: u.toString() };
}
// 从 zip 包中提取 Worker 脚本（优先 _worker.js，否则取第一个 .js）
async function extractWorkerScriptFromZip(zipBytes) {
  const files = await zipToFiles(zipBytes);
  const jsFiles = files.filter(function (f) { return /\.js$/i.test(f.path); });
  if (!jsFiles.length) throw new Error('ZIP 包中没有找到 .js 文件');
  const pick = jsFiles.find(function (f) { return /(^|\/)_worker\.js$/i.test(f.path); }) || jsFiles[0];
  return new TextDecoder().decode(pick.data);
}
// ============ ZIP 解析（GitHub 导入用） ============
async function inflateRaw(data) {
  const ds = new DecompressionStream('deflate-raw');
  const buf = await new Response(new Blob([data]).stream().pipeThrough(ds)).arrayBuffer();
  return new Uint8Array(buf);
}
function parseZipEntries(zip) {
  const dv = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 70000); i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('ZIP 解析失败');
  const count = dv.getUint16(eocd + 10, true);
  let p = dv.getUint32(eocd + 16, true);
  const entries = [];
  const dec = new TextDecoder();
  for (let i = 0; i < count; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const flags = dv.getUint16(p + 8, true);
    const method = dv.getUint16(p + 10, true);
    const compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
    const localOff = dv.getUint32(p + 42, true);
    const name = dec.decode(zip.subarray(p + 46, p + 46 + nameLen));
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith('/')) continue;
    if ((flags & 1) || (flags & 8)) continue;
    if (localOff + 30 > zip.length || dv.getUint32(localOff, true) !== 0x04034b50) continue;
    const dataOff = localOff + 30 + dv.getUint16(localOff + 26, true) + dv.getUint16(localOff + 28, true);
    entries.push({ name, method, data: zip.subarray(dataOff, dataOff + compSize) });
  }
  return entries;
}
async function zipToFiles(zipBytes) {
  const entries = parseZipEntries(zipBytes);
  let prefix = '';
  if (entries.length && entries[0].name.includes('/')) prefix = entries[0].name.split('/')[0] + '/';
  const files = [];
  for (const e of entries) {
    let name = e.name;
    if (prefix && name.startsWith(prefix)) name = name.slice(prefix.length);
    if (!name || name.startsWith('.git/')) continue;
    const data = e.method === 8 ? await inflateRaw(e.data) : e.data.slice();
    files.push({ path: '/' + name, data });
  }
  return files;
}
function parseGithubUrl(url) {
  const u = String(url || '').trim();
  const m = u.match(/github\.com\/([^\/\s]+)\/([^\/\s#?]+)/i);
  if (!m) return null;
  const owner = m[1], repo = m[2].replace(/\.git$/, '');
  // 检测单文件链接：/blob/<branch>/<path> 或 /raw/<branch>/<path>
  const fm = u.match(/github\.com\/[^\/\s]+\/[^\/\s#?]+\/(blob|raw)\/([^\/\s#?]+)\/(.+?)(?:[#?].*)?$/i);
  let file = null;
  if (fm) file = { branch: fm[2], path: fm[3].replace(/\/$/, '') };
  return { owner, repo, file };
}
async function fetchGithubSingleFile(owner, repo, branch, path) {
  const url = 'https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + encodeURIComponent(branch) + '/' + path.split('/').map(encodeURIComponent).join('/');
  const r = await fetch(url, { headers: { 'User-Agent': 'cf-manager' } });
  if (!r.ok) throw new Error('下载单文件失败（' + r.status + '）：' + path);
  const buf = new Uint8Array(await r.arrayBuffer());
  let b64 = '';
  for (let i = 0; i < buf.length; i += 8192) b64 += String.fromCharCode.apply(null, buf.subarray(i, i + 8192));
  const name = path.split('/').pop();
  return { files: [{ path: '/' + name, data: btoa(b64) }], branch, singleFile: name };
}
async function fetchGithubRepo(owner, repo, branch) {
  let br = (branch || '').trim();
  if (!br) {
    const r = await fetch('https://api.github.com/repos/' + owner + '/' + repo, { headers: { 'User-Agent': 'cf-manager', 'Accept': 'application/vnd.github+json' } });
    if (!r.ok) throw new Error('GitHub 仓库不存在或无权访问：' + owner + '/' + repo);
    br = (await r.json()).default_branch || 'main';
  }
  const zr = await fetch('https://codeload.github.com/' + owner + '/' + repo + '/zip/refs/heads/' + encodeURIComponent(br), { headers: { 'User-Agent': 'cf-manager' } });
  if (!zr.ok) throw new Error('下载仓库压缩包失败（分支 ' + br + ' 不存在？）');
  return { files: await zipToFiles(new Uint8Array(await zr.arrayBuffer())), branch: br };
}
// ============ Pages Direct Upload ============
const PAGES_SPECIAL_FILES = ['/_headers', '/_redirects', '/_routes.json'];
function guessContentType(path) {
  const ext = (path.split('.').pop() || '').toLowerCase();
  const map = { html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript', json: 'application/json', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml', webp: 'image/webp', ico: 'image/x-icon', txt: 'text/plain', xml: 'application/xml', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf', map: 'application/json', webmanifest: 'application/manifest+json', pdf: 'application/pdf', mp4: 'video/mp4', wasm: 'application/wasm' };
  return map[ext] || 'application/octet-stream';
}
function pagesAssetHash(b64, path) {
  const dot = path.lastIndexOf('.');
  const ext = dot >= 0 ? path.slice(dot + 1).toLowerCase() : '';
  return blake3Hex(new TextEncoder().encode(b64 + ext)).slice(0, 32);
}
// 构造 Pages 高级模式的 `_worker.bundle` 内嵌 multipart（metadata + 模块文件），与 wrangler pages deploy 一致
function buildPagesWorkerBundle(scriptBytes) {
  const boundary = '----cfmworker' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
  const enc = new TextEncoder();
  const parts = [];
  const push = (s) => parts.push(enc.encode(s));
  push('--' + boundary + '\r\n');
  push('Content-Disposition: form-data; name="metadata"\r\n\r\n');
  push(JSON.stringify({ main_module: '_worker.js' }) + '\r\n');
  push('--' + boundary + '\r\n');
  push('Content-Disposition: form-data; name="_worker.js"; filename="_worker.js"\r\n');
  push('Content-Type: application/javascript+module\r\n\r\n');
  parts.push(scriptBytes instanceof Uint8Array ? scriptBytes : new Uint8Array(scriptBytes));
  push('\r\n--' + boundary + '--\r\n');
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
async function pagesDirectDeploy(auth, accountId, projectName, files, branch) {
  if (!projectName || !/^[a-z0-9][a-z0-9-]*$/.test(projectName)) return { ok: false, error: '项目名不合法（小写字母/数字/连字符）' };
  if (!files.length) return { ok: false, error: '没有可部署的文件' };
  if (files.length > 2000) return { ok: false, error: '文件数量超过 2000，请精简后再试' };
  let total = 0;
  for (const f of files) {
    total += f.data.length;
    if (f.data.length > 25 * 1024 * 1024) return { ok: false, error: '单个文件超过 25MB：' + f.path };
  }
  if (total > 100 * 1024 * 1024) return { ok: false, error: '文件总大小超过 100MB，请精简后再试' };
  let pr = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), auth);
  let prodBranch = pr.ok && pr.data.result && pr.data.result.production_branch;
  if (!pr.ok) {
    const cr = await cfReq('POST', '/accounts/' + accountId + '/pages/projects', auth, { name: projectName, production_branch: branch || 'main' });
    if (!cr.ok) return { ok: false, error: '创建 Pages 项目失败: ' + (((cr.data.errors || [])[0] || {}).message || '未知错误') };
    prodBranch = cr.data.result && cr.data.result.production_branch;
  }
  const tr = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/upload-token', auth);
  const jwt = tr.ok && tr.data.result && tr.data.result.jwt;
  if (!jwt) return { ok: false, error: '获取上传 token 失败' };
  const jheaders = { 'Authorization': 'Bearer ' + jwt, 'Content-Type': 'application/json' };
  const hashed = files.map((f) => {
    const b64 = u8ToBase64(f.data);
    return { path: f.path, hash: pagesAssetHash(b64, f.path), b64, contentType: guessContentType(f.path) };
  });
  // 高级模式：根目录 _worker.js 作为 Pages Functions Worker（不进静态 manifest）
  let workerBundle = null;
  const staticHashed = [];
  for (const h of hashed) {
    if (h.path === '/_worker.js') {
      try { workerBundle = buildPagesWorkerBundle(base64ToU8(h.b64)); }
      catch (e) { return { ok: false, error: '构建 _worker.js 失败：' + (e.message || e) }; }
    } else staticHashed.push(h);
  }
  const postJwt = async (url, body) => {
    try {
      const r = await fetch(url, { method: 'POST', headers: jheaders, body: JSON.stringify(body) });
      const j = await r.json().catch(() => ({}));
      return { ok: r.ok, j };
    } catch (e) { return { ok: false, j: {}, netErr: String(e && e.message || e) }; }
  };
  let missing = new Set(staticHashed.map((h) => h.hash));
  const cm = await postJwt('https://api.cloudflare.com/client/v4/pages/assets/check-missing', { hashes: staticHashed.map((h) => h.hash) });
  if (cm.ok && cm.j && Array.isArray(cm.j.result)) missing = new Set(cm.j.result);
  const toUpload = staticHashed.filter((h) => missing.has(h.hash));
  for (let i = 0; i < toUpload.length; i += 5) {
    const batch = toUpload.slice(i, i + 5).map((h) => ({ key: h.hash, value: h.b64, metadata: { contentType: h.contentType }, base64: true }));
    const ur = await postJwt('https://api.cloudflare.com/client/v4/pages/assets/upload', batch);
    if (!ur.ok) return { ok: false, error: '上传文件失败: ' + (((ur.j.errors || [])[0] || {}).message || ur.netErr || '未知错误') };
  }
  await postJwt('https://api.cloudflare.com/client/v4/pages/assets/upsert-hashes', { hashes: staticHashed.map((h) => h.hash) });
  const manifest = {}, specials = {};
  for (const h of staticHashed) {
    if (PAGES_SPECIAL_FILES.includes(h.path)) specials[h.path] = h;
    else manifest[h.path] = h.hash;
  }
  const form = new FormData();
  form.append('manifest', JSON.stringify(manifest));
  form.append('branch', branch || prodBranch || 'main');
  for (const sp of PAGES_SPECIAL_FILES) {
    if (specials[sp]) form.append(sp.slice(1), new Blob([base64ToU8(specials[sp].b64)], { type: specials[sp].contentType }), sp.slice(1));
  }
  if (workerBundle) form.append('_worker.bundle', new Blob([workerBundle], { type: 'application/octet-stream' }), '_worker.bundle');
  const dr = await cfReq('POST', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/deployments', auth, form);
  if (!dr.ok) return { ok: false, error: '创建部署失败: ' + (((dr.data.errors || [])[0] || {}).message || '未知错误') };
  const d = dr.data.result || {};
  // 轮询部署状态，最多等待约 20 秒，确认是否真正上线
  let stageStatus = '';
  if (d.id) {
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      try {
        const st = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/deployments/' + d.id, auth);
        const dd = (st.ok && st.data.result) || {};
        stageStatus = (dd.latest_stage && dd.latest_stage.status) || '';
        if (stageStatus === 'success' || stageStatus === 'failure' || stageStatus === 'canceled') break;
      } catch (e) { /* 忽略单次轮询失败 */ }
    }
  }
  return { ok: true, url: d.url, id: d.id, stage: stageStatus, advancedMode: !!workerBundle };
}

// ---------------- R2 S3 兼容 API（SigV4 签名） ----------------
// R2 对象级操作（列表/上传/下载/删除）只能走 S3 兼容接口。
// S3 凭证（Access Key ID + Secret）由前端随请求传入，仅用于本次签名，不存储不记录。
async function sha256HexBytes(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function hmacBytes(keyBytes, data) {
  const k = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, typeof data === 'string' ? new TextEncoder().encode(data) : data);
  return new Uint8Array(sig);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function getS3Creds(payload) {
  const s3 = payload.s3 || {};
  const accessKeyId = String(s3.accessKeyId || '').trim();
  const secretAccessKey = String(s3.secretAccessKey || '').trim();
  if (!accessKeyId || !secretAccessKey) throw new Error('请先配置 R2 S3 API 凭证（Access Key ID / Secret Access Key）');
  const out = { accessKeyId, secretAccessKey };
  if (s3.sessionToken) out.sessionToken = String(s3.sessionToken);
  return out;
}
// 对 R2 S3 endpoint 发起 SigV4 签名请求，返回 { ok, status, text }
async function r2S3Fetch(accountId, creds, method, bucket, key, queryParams, extraHeaders, bodyBytes) {
  const host = accountId + '.r2.cloudflarestorage.com';
  const region = 'auto', service = 's3';
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, '') + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const body = bodyBytes || new Uint8Array(0);
  const payloadHash = await sha256HexBytes(body);
  const encodedKey = key ? '/' + String(key).split('/').map((s) => encodeURIComponent(s)).join('/') : '';
  const canonicalUri = '/' + bucket + encodedKey;
  const qp = Object.keys(queryParams || {}).sort()
    .map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(queryParams[k])).join('&');
  const headers = { 'host': host, 'x-amz-content-sha256': payloadHash, 'x-amz-date': amzDate };
  if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;
  if (extraHeaders) for (const k of Object.keys(extraHeaders)) headers[k.toLowerCase()] = extraHeaders[k];
  const sortedKeys = Object.keys(headers).sort();
  const signedHeaders = sortedKeys.join(';');
  const canonicalHeaders = sortedKeys.map((k) => k + ':' + String(headers[k]).trim() + '\n').join('');
  const canonicalRequest = [method, canonicalUri, qp, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const credentialScope = [dateStamp, region, service, 'aws4_request'].join('/');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256HexBytes(new TextEncoder().encode(canonicalRequest))].join('\n');
  let sk = await hmacBytes(new TextEncoder().encode('AWS4' + creds.secretAccessKey), dateStamp);
  sk = await hmacBytes(sk, region);
  sk = await hmacBytes(sk, service);
  sk = await hmacBytes(sk, 'aws4_request');
  const sigBytes = await hmacBytes(sk, stringToSign);
  const signature = [...sigBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
  headers['authorization'] = 'AWS4-HMAC-SHA256 Credential=' + creds.accessKeyId + '/' + credentialScope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
  const url = 'https://' + host + canonicalUri + (qp ? '?' + qp : '');
  const res = await fetch(url, { method, headers, body: (method === 'GET' || method === 'HEAD') ? undefined : body });
  const text = await res.text();
  return { ok: res.ok, status: res.status, text };
}
// 解析 S3 ListObjectsV2 的 XML（轻量正则解析）
function parseS3ListXml(xml) {
  const out = { files: [], folders: [], isTruncated: false, nextToken: '', count: 0 };
  const tag = (src, name) => {
    const m = src.match(new RegExp('<' + name + '>([\\s\\S]*?)</' + name + '>'));
    return m ? m[1] : '';
  };
  const unesc = (s) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'");
  const trunc = tag(xml, 'IsTruncated');
  out.isTruncated = trunc === 'true';
  out.nextToken = unesc(tag(xml, 'NextContinuationToken'));
  out.count = parseInt(tag(xml, 'KeyCount') || '0', 10) || 0;
  const contents = xml.match(/<Contents>[\s\S]*?<\/Contents>/g) || [];
  for (const c of contents) {
    out.files.push({
      key: unesc(tag(c, 'Key')),
      size: parseInt(tag(c, 'Size') || '0', 10) || 0,
      lastModified: tag(c, 'LastModified'),
      storageClass: tag(c, 'StorageClass') || 'Standard',
      etag: tag(c, 'ETag').replace(/"/g, ''),
    });
  }
  const prefixes = xml.match(/<CommonPrefixes>[\s\S]*?<\/CommonPrefixes>/g) || [];
  for (const p of prefixes) {
    const px = unesc(tag(p, 'Prefix'));
    if (px) out.folders.push(px);
  }
  return out;
}
function s3ErrorMessage(text, fallback) {
  const m = String(text || '').match(/<Message>([\s\S]*?)<\/Message>/);
  return (m && m[1]) || fallback || 'S3 请求失败';
}

// ---------------- API dispatcher ----------------
// OAuth token 换取 / 刷新（PKCE 公开客户端，无需 secret；verifier 经后端内存转发，不落地）
async function handleOAuthToken(action, payload) {
  const clientId = String(payload.client_id || '').trim();
  if (!clientId) return json({ success: false, error: '缺少 client_id' }, 400);
  let params;
  if (action === 'oauth-exchange') {
    const code = String(payload.code || '').trim();
    const verifier = String(payload.code_verifier || '').trim();
    const redirectUri = String(payload.redirect_uri || '').trim();
    if (!code || !verifier || !redirectUri) return json({ success: false, error: '缺少授权参数' }, 400);
    params = { grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, code_verifier: verifier };
  } else {
    const refreshToken = String(payload.refresh_token || '').trim();
    if (!refreshToken) return json({ success: false, error: '缺少 refresh_token' }, 400);
    params = { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId };
  }
  const body = new URLSearchParams(params).toString();
  const tr = await fetch('https://dash.cloudflare.com/oauth2/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body
  });
  const td = await tr.json().catch(() => ({}));
  if (!tr.ok || !td.access_token) {
    const msg = (td && (td.error_description || td.error)) || ('HTTP ' + tr.status);
    return json({ success: false, error: (action === 'oauth-exchange' ? '换取令牌失败：' : '刷新令牌失败：') + msg });
  }
  // 换取成功后顺手取用户邮箱，前端拿来当账号显示名（best-effort，失败不影响登录）
  let email = '';
  try {
    const ur = await fetch(CF_API_BASE + '/user', { headers: { 'Authorization': 'Bearer ' + td.access_token } });
    const ud = await ur.json().catch(() => ({}));
    if (ud && ud.success && ud.result && ud.result.email) email = String(ud.result.email);
  } catch (e) {}
  return json({ success: true, access_token: td.access_token,
    refresh_token: td.refresh_token || (action === 'oauth-refresh' ? params.refresh_token : ''),
    expires_in: td.expires_in || 0, scope: td.scope || '', email });
}

async function handleAPI(req, env) {
  const payload = await safeJSON(req);
  const action = payload.action;
  if (!action) return json({ success: false, error: 'action required' }, 400);

  // 无需鉴权
  if (action === 'check-features') {
    return json({ success: true, hasPassword: !!(env && env.ACCESS_PASSWORD) });
  }

  // OAuth 换 token / 刷新 token：不走 Cloudflare API 凭据，直接调 Cloudflare OAuth 端点
  if (action === 'oauth-exchange' || action === 'oauth-refresh') {
    return handleOAuthToken(action, payload);
  }

  let auth;
  try { auth = buildAuth(payload); }
  catch (e) { return json({ success: false, error: e.message }, 400); }

  // 拉取外部脚本：已鉴权 + URL 白名单式限制（防开放代理/SSRF）
  if (action === 'fetch-external-script') {
    const chk = checkUrlSafe(payload.url);
    if (!chk.ok) return json({ success: false, error: chk.error }, 400);
    try {
      const resp = await fetch(chk.url, { headers: { 'User-Agent': 'CF-Manager/2.0' } });
      if (!resp.ok) return json({ success: false, error: 'Fetch failed: ' + resp.status });
      const text = await resp.text();
      if (text.length > 5 * 1024 * 1024) return json({ success: false, error: '脚本过大（>5MB）' }, 400);
      return json({ success: true, content: text });
    } catch (e) {
      return json({ success: false, error: String(e && e.message || e) });
    }
  }

  try {
    switch (action) {
      case 'validate-credentials': {
        let r = await cfReq('GET', '/accounts', auth);
        if ((!r.ok || !(r.data && r.data.result)) && auth.mode === 'token') {
          const v = await cfReq('GET', '/user/tokens/verify', auth);
          if (v.ok) return json({ success: true, via: 'token-verify', result: v.data.result });
        }
        if (!r.ok) {
          const msg = (r.data && r.data.errors && r.data.errors[0] && r.data.errors[0].message) || '验证失败，请检查凭据与权限';
          return json({ success: false, error: msg });
        }
        return json({ success: true, result: r.data.result });
      }

      case 'oauth-userinfo': {
        // 取当前 OAuth 账号的用户邮箱（用于账号显示名；旧存档的通用标签靠它刷新）
        const r = await cfReq('GET', '/user', auth);
        const email = r.ok && r.data && r.data.result && r.data.result.email;
        return json({ success: !!email, email: email || '' });
      }

      case 'list-accounts': {
        const r = await cfReq('GET', '/accounts', auth);
        return json({ success: r.ok, result: r.data.result, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      case 'list-workers': {
        const accountId = payload.accountId || await getAccountId(auth);
        // 三个账号级请求并行
        const [r, sd, dm] = await Promise.all([
          cfReq('GET', '/accounts/' + accountId + '/workers/scripts', auth),
          cfReq('GET', '/accounts/' + accountId + '/workers/subdomain', auth).catch(() => ({ ok: false })),
          cfReq('GET', '/accounts/' + accountId + '/workers/domains', auth).catch(() => ({ ok: false })),
        ]);
        const workers = (r.ok && r.data.result) || [];
        const accountSubdomain = (sd.ok && sd.data.result && sd.data.result.subdomain) || null;
        // 新版账号级自定义域名接口（一次性拉取，按 service 归属）
        const allDomains = (dm.ok && Array.isArray(dm.data.result)) ? dm.data.result : [];
        // 每个 Worker 的 bindings / subdomain 状态全部并行拉取
        await Promise.all(workers.map(async (w) => {
          const name = w.id;
          w.domains = allDomains.filter((d) => d.service === name);
          const [b, s, sch] = await Promise.all([
            cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(name) + '/bindings', auth).catch(() => ({ ok: false })),
            cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(name) + '/subdomain', auth).catch(() => ({ ok: false })),
            cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(name) + '/schedules', auth).catch(() => ({ ok: false })),
          ]);
          w.bindings = (b.ok && b.data.result) || [];
          w.subdomainEnabled = s.ok ? (s.data.result.enabled !== false) : true;
          w.cronTriggers = (sch.ok && sch.data.result && sch.data.result.schedules) || [];
          w.previewsEnabled = s.ok ? !!s.data.result.previews_enabled : false;
          if (accountSubdomain) {
            w.defaultDomain = { hostname: name + '.' + accountSubdomain + '.workers.dev', enabled: w.subdomainEnabled !== false };
          }
        }));
        return json({ success: r.ok, result: workers, accountSubdomain });
      }

      case 'get-worker-script': {
        const accountId = payload.accountId || await getAccountId(auth);
        const dl = await downloadWorkerScript(auth, accountId, payload.scriptName);
        if (!dl.ok) return json({ ok: false, status: 404, rawScript: "export default { async fetch() { return new Response('New Worker'); } };" });
        return json({ ok: true, status: 200, rawScript: dl.rawScript });
      }

      case 'deploy-worker': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        // 合并现有 bindings（保留未被覆盖的）
        let currentBindings = [];
        try {
          const b = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/bindings', auth);
          if (b.ok && b.data.result) currentBindings = b.data.result;
        } catch (e) {}
        const finalBindings = cleanBindingsForUpload(currentBindings);
        try {
          (payload.metadataBindings || []).forEach((nb) => {
            const idx = finalBindings.findIndex((ob) => ob.name === nb.name);
            const clean = cleanBindingsForUpload([nb])[0];
            if (idx !== -1) finalBindings[idx] = clean; else finalBindings.push(clean);
          });
        } catch (e) { return json({ success: false, error: e.message || '绑定格式错误' }, 400); }
        const r = await uploadWorkerScript(auth, accountId, payload.scriptName, payload.scriptSource, finalBindings, payload.usage_model);
        if (!r.ok) {
          const msg = (r.data.errors && r.data.errors[0] && (r.data.errors[0].message + (r.data.errors[0].code ? ' (' + r.data.errors[0].code + ')' : ''))) || '部署失败';
          return json({ success: false, error: msg, details: r.data });
        }
        return json({ success: true, message: 'Worker 部署成功', result: r.data.result });
      }

      case 'quick-deploy': {
        // 一键部署：拉代码（直链/.zip/编辑框/上传）→ D1 查找或创建并绑定 → 部署 Worker（同名则更新）→ 绑自定义域名
        const accountId = payload.accountId || await getAccountId(auth);
        const scriptName = String(payload.scriptName || '').trim();
        if (!scriptName) return json({ success: false, error: '项目名不能为空' }, 400);
        const notes = [];
        // 1) 解析脚本内容
        let scriptSource = '';
        try {
          const kind = payload.sourceKind;
          if (kind === 'text') {
            scriptSource = String(payload.sourceText || '');
          } else if (kind === 'url') {
            const chk = checkUrlSafe(payload.sourceUrl);
            if (!chk.ok) return json({ success: false, error: chk.error }, 400);
            const resp = await fetch(chk.url, { headers: { 'User-Agent': 'CF-Manager/2.0' } });
            if (!resp.ok) return json({ success: false, error: '直链下载失败: HTTP ' + resp.status });
            const ctype = (resp.headers.get('content-type') || '').toLowerCase();
            const isZip = /\.zip(\?|#|$)/i.test(chk.url) || ctype.includes('zip');
            if (isZip) {
              const buf = new Uint8Array(await resp.arrayBuffer());
              if (buf.length > 20 * 1024 * 1024) return json({ success: false, error: 'ZIP 包过大（>20MB）' }, 400);
              scriptSource = await extractWorkerScriptFromZip(buf);
            } else {
              scriptSource = await resp.text();
            }
          } else if (kind === 'b64zip') {
            const bin = atob(String(payload.sourceB64 || ''));
            const buf = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
            if (buf.length > 20 * 1024 * 1024) return json({ success: false, error: 'ZIP 包过大（>20MB）' }, 400);
            scriptSource = await extractWorkerScriptFromZip(buf);
          } else {
            return json({ success: false, error: '未知的代码来源' }, 400);
          }
        } catch (e) { return json({ success: false, error: '代码解析失败: ' + (e.message || e) }); }
        if (!scriptSource || !scriptSource.trim()) return json({ success: false, error: '脚本内容为空' }, 400);
        if (scriptSource.length > 5 * 1024 * 1024) return json({ success: false, error: '脚本过大（>5MB）' }, 400);
        // 2) D1：按名查找，没有则创建（支持多个）
        const d1Bindings = [];
        const d1List = Array.isArray(payload.d1List) ? payload.d1List : (payload.d1Name ? [{ name: payload.d1Name }] : []);
        let d1Cache = null;
        const getD1List = async function () {
          if (d1Cache) return d1Cache;
          d1Cache = [];
          try {
            const lr = await cfReq('GET', '/accounts/' + accountId + '/d1/database?per_page=100', auth);
            if (lr.ok && lr.data.result) d1Cache = lr.data.result;
          } catch (e) {}
          return d1Cache;
        };
        for (const item of d1List) {
          const d1Name = String((item && item.name) || '').trim();
          if (!d1Name) continue;
          let db = (await getD1List()).find(function (d) { return d.name === d1Name; });
          if (!db) {
            const cr = await cfReq('POST', '/accounts/' + accountId + '/d1/database', auth, { name: d1Name });
            if (!cr.ok) return json({ success: false, error: 'D1 创建失败(' + d1Name + '): ' + (((cr.data.errors || [])[0] || {}).message || '未知错误') });
            db = cr.data.result;
            d1Cache.push(db);
            notes.push('已创建 D1 数据库: ' + d1Name);
          } else {
            notes.push('已找到 D1 数据库: ' + d1Name);
          }
          let bindName = String((item && item.bindName) || '').trim() || d1Name.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
          if (/^\d/.test(bindName)) bindName = '_' + bindName;
          if (!bindName) bindName = 'DB';
          d1Bindings.push({ type: 'd1', name: bindName, id: db.uuid || db.id });
          notes.push('D1 绑定变量名: ' + bindName);
        }
        // 2b) KV：按名查找，没有则创建（支持多个）
        const kvBindings = [];
        const kvList = Array.isArray(payload.kvList) ? payload.kvList : [];
        let kvCache = null;
        const getKvList = async function () {
          if (kvCache) return kvCache;
          kvCache = [];
          try {
            const lr = await cfReq('GET', '/accounts/' + accountId + '/storage/kv/namespaces?per_page=100', auth);
            if (lr.ok && lr.data.result) kvCache = lr.data.result;
          } catch (e) {}
          return kvCache;
        };
        for (const item of kvList) {
          const nsName = String((item && item.nsName) || '').trim();
          if (!nsName) continue;
          let ns = (await getKvList()).find(function (n) { return n.title === nsName; });
          if (!ns) {
            const cr = await cfReq('POST', '/accounts/' + accountId + '/storage/kv/namespaces', auth, { title: nsName });
            if (!cr.ok) return json({ success: false, error: 'KV 创建失败(' + nsName + '): ' + (((cr.data.errors || [])[0] || {}).message || '未知错误') });
            ns = cr.data.result;
            kvCache.push(ns);
            notes.push('已创建 KV 命名空间: ' + nsName);
          } else {
            notes.push('已找到 KV 命名空间: ' + nsName);
          }
          let bindName = String((item && item.bindName) || '').trim() || nsName.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
          if (/^\d/.test(bindName)) bindName = '_' + bindName;
          if (!bindName) bindName = 'KV';
          kvBindings.push({ type: 'kv_namespace', name: bindName, namespace_id: ns.id });
          notes.push('KV 绑定变量名: ' + bindName);
        }
        // 2c) 环境变量（明文）
        const envBindings = [];
        const envList = Array.isArray(payload.envVars) ? payload.envVars : [];
        for (const item of envList) {
          const n = String((item && item.name) || '').trim();
          if (!n) continue;
          envBindings.push({ type: 'plain_text', name: n, text: String((item && item.value) || '') });
        }
        if (envBindings.length) notes.push('已设置 ' + envBindings.length + ' 个环境变量');
        // 3) 部署：保留已有 bindings（同名更新不丢配置），合并 D1 绑定
        let currentBindings = [];
        try {
          const b = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/bindings', auth);
          if (b.ok && b.data.result) currentBindings = b.data.result;
        } catch (e) {}
        const finalBindings = cleanBindingsForUpload(currentBindings);
        try {
          d1Bindings.concat(kvBindings, envBindings).forEach(function (nb) {
            const idx = finalBindings.findIndex(function (ob) { return ob.name === nb.name; });
            const clean = cleanBindingsForUpload([nb])[0];
            if (idx !== -1) finalBindings[idx] = clean; else finalBindings.push(clean);
          });
        } catch (e) { return json({ success: false, error: e.message || '绑定格式错误' }, 400); }
        const r = await uploadWorkerScript(auth, accountId, scriptName, scriptSource, finalBindings, payload.usage_model);
        if (!r.ok) {
          const msg = (r.data.errors && r.data.errors[0] && (r.data.errors[0].message + (r.data.errors[0].code ? ' (' + r.data.errors[0].code + ')' : ''))) || '部署失败';
          return json({ success: false, error: msg, details: r.data });
        }
        notes.push('Worker ' + scriptName + ' 部署成功');
        // 3b) 分配域名 (workers.dev)：默认开启；选了自定义域名时前端会自动关闭
        const assignDomain = payload.assignDomain !== false;
        try {
          const sr = await cfReq('POST', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/subdomain', auth, { enabled: assignDomain });
          notes.push(sr.ok ? (assignDomain ? '已分配 workers.dev 域名' : '已关闭 workers.dev 域名分配') : 'workers.dev 域名设置失败');
        } catch (e) { notes.push('workers.dev 域名设置失败'); }
        // 4) 自定义域名（可选）
        const hostname = String(payload.hostname || '').replace(/^https?:\/\//, '').replace(/\/$/, '').trim().toLowerCase();
        if (hostname) {
          let zone = null;
          const labels = hostname.split('.');
          for (let i = 0; i <= labels.length - 2; i++) {
            const cand = labels.slice(i).join('.');
            const zr = await cfReq('GET', '/zones?name=' + encodeURIComponent(cand) + '&per_page=5', auth);
            if (zr.ok && zr.data.result && zr.data.result.length) {
              zone = zr.data.result.find(function (z) { return z.name.toLowerCase() === cand; }) || zr.data.result[0];
              break;
            }
          }
          if (!zone) {
            notes.push('域名 ' + hostname + ' 未找到归属 Zone，已跳过绑定');
          } else {
            const dr = await cfReq('PUT', '/accounts/' + accountId + '/workers/domains', auth, {
              hostname: hostname, service: scriptName, zone_id: zone.id, environment: 'production'
            });
            if (!dr.ok) notes.push('域名绑定失败: ' + (((dr.data.errors || [])[0] || {}).message || '未知错误'));
            else notes.push('已绑定域名: ' + hostname);
          }
        }
        return json({ success: true, notes: notes });
      }

      case 'quick-deploy-pages': {
        // Pages 一键部署：项目不存在则创建，然后直接部署（同名项目转为更新）
        const accountId = payload.accountId || await getAccountId(auth);
        const projectName = String(payload.projectName || '').trim().toLowerCase();
        if (!projectName) return json({ success: false, error: '项目名不能为空' }, 400);
        if (!/^[a-z0-9][a-z0-9-]*$/.test(projectName) || projectName.length > 63) {
          return json({ success: false, error: '项目名不合法：仅小写字母、数字、连字符' }, 400);
        }
        const branch = String(payload.branch || '').trim() || 'main';
        let files = [];
        try {
          const kind = payload.sourceKind;
          if (kind === 'url') {
            const chk = checkUrlSafe(payload.sourceUrl);
            if (!chk.ok) return json({ success: false, error: chk.error }, 400);
            const resp = await fetch(chk.url, { headers: { 'User-Agent': 'CF-Manager/2.0' } });
            if (!resp.ok) return json({ success: false, error: '直链下载失败: HTTP ' + resp.status });
            const buf = new Uint8Array(await resp.arrayBuffer());
            if (buf.length > 100 * 1024 * 1024) return json({ success: false, error: '文件过大（>100MB）' }, 400);
            files = await zipToFiles(buf);
          } else if (kind === 'b64zip') {
            const bin = atob(String(payload.sourceB64 || ''));
            const buf = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
            if (buf.length > 100 * 1024 * 1024) return json({ success: false, error: '文件过大（>100MB）' }, 400);
            files = await zipToFiles(buf);
          } else if (kind === 'files') {
            files = (payload.files || []).map((f) => {
              let p = String(f.path || '').replace(/\\/g, '/');
              if (!p.startsWith('/')) p = '/' + p;
              return { path: p, data: base64ToU8(String(f.content || '')) };
            });
          } else {
            return json({ success: false, error: '未知的代码来源' }, 400);
          }
        } catch (e) { return json({ success: false, error: '代码解析失败: ' + (e.message || e) }); }
        if (!files.length) return json({ success: false, error: '没有可部署的文件' }, 400);
        const r = await pagesDirectDeploy(auth, accountId, projectName, files, branch);
        if (!r.ok) return json({ success: false, error: r.error || '部署失败' });
        const pnotes = ['Pages 项目 ' + projectName + ' 部署成功'];
        // 绑定：环境变量 / KV / D1
        const penv = {}, pkv = {}, pd1 = {};
        for (const item of (Array.isArray(payload.envVars) ? payload.envVars : [])) {
          const n = String((item && item.name) || '').trim();
          if (n) penv[n] = { type: 'plain_text', value: String((item && item.value) || '') };
        }
        // KV：按 title 查找，没有则创建
        let pkvCache = null;
        const getPkvList = async function () {
          if (pkvCache) return pkvCache;
          pkvCache = [];
          try {
            const lr = await cfReq('GET', '/accounts/' + accountId + '/storage/kv/namespaces?per_page=100', auth);
            if (lr.ok && lr.data.result) pkvCache = lr.data.result;
          } catch (e) {}
          return pkvCache;
        };
        for (const item of (Array.isArray(payload.kvList) ? payload.kvList : [])) {
          const nsName = String((item && item.name) || '').trim();
          if (!nsName) continue;
          let ns = (await getPkvList()).find(function (n) { return n.title === nsName; });
          if (!ns) {
            const cr = await cfReq('POST', '/accounts/' + accountId + '/storage/kv/namespaces', auth, { title: nsName });
            if (!cr.ok) return json({ success: false, error: 'KV 创建失败(' + nsName + '): ' + (((cr.data.errors || [])[0] || {}).message || '未知错误') });
            ns = cr.data.result;
            pkvCache.push(ns);
            pnotes.push('已创建 KV 命名空间: ' + nsName);
          }
          let bindName = String((item && item.bindName) || '').trim() || nsName.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
          if (/^\d/.test(bindName)) bindName = '_' + bindName;
          if (!bindName) bindName = 'KV';
          pkv[bindName] = { namespace_id: ns.id };
          pnotes.push('KV 绑定: ' + bindName);
        }
        // D1：按名查找，没有则创建
        let pd1Cache = null;
        const getPd1List = async function () {
          if (pd1Cache) return pd1Cache;
          pd1Cache = [];
          try {
            const lr = await cfReq('GET', '/accounts/' + accountId + '/d1/database?per_page=100', auth);
            if (lr.ok && lr.data.result) pd1Cache = lr.data.result;
          } catch (e) {}
          return pd1Cache;
        };
        for (const item of (Array.isArray(payload.d1List) ? payload.d1List : [])) {
          const d1Name = String((item && item.name) || '').trim();
          if (!d1Name) continue;
          let db = (await getPd1List()).find(function (d) { return d.name === d1Name; });
          if (!db) {
            const cr = await cfReq('POST', '/accounts/' + accountId + '/d1/database', auth, { name: d1Name });
            if (!cr.ok) return json({ success: false, error: 'D1 创建失败(' + d1Name + '): ' + (((cr.data.errors || [])[0] || {}).message || '未知错误') });
            db = cr.data.result;
            pd1Cache.push(db);
            pnotes.push('已创建 D1 数据库: ' + d1Name);
          }
          let bindName = String((item && item.bindName) || '').trim() || d1Name.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');
          if (/^\d/.test(bindName)) bindName = '_' + bindName;
          if (!bindName) bindName = 'DB';
          pd1[bindName] = { id: db.uuid || db.id };
          pnotes.push('D1 绑定: ' + bindName);
        }
        if (Object.keys(penv).length || Object.keys(pkv).length || Object.keys(pd1).length) {
          const br = await cfReq('PATCH', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName), auth, {
            deployment_configs: { production: { env_vars: penv, kv_namespaces: pkv, d1_databases: pd1 }, preview: { env_vars: penv, kv_namespaces: pkv, d1_databases: pd1 } }
          });
          if (br.ok) pnotes.push('环境变量/KV/D1 绑定已保存（生产 + 预览）');
          else pnotes.push('绑定保存失败: ' + (((br.data.errors || [])[0] || {}).message || '未知错误'));
        }
        // 自定义域名（可选）
        const phost = String(payload.hostname || '').trim();
        if (phost) {
          const dr = await cfReq('POST', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/domains', auth, { name: phost });
          if (dr.ok) pnotes.push('已绑定域名: ' + phost);
          else pnotes.push('域名绑定失败: ' + (((dr.data.errors || [])[0] || {}).message || '未知错误'));
        }
        return json({ success: true, url: r.url, id: r.id, fileCount: files.length, warning: r.warning || '', notes: pnotes });
      }

      case 'delete-worker': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName), auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      // 新版 Versions API（Beta）：版本列表
      case 'rollback-worker-version': {
        // Worker 回滚：把流量切回指定的历史版本（无需下载旧代码）
        const accountId = payload.accountId || await getAccountId(auth);
        const scriptName = String(payload.scriptName || '').trim();
        const versionId = String(payload.versionId || '').trim();
        if (!scriptName || !versionId) return json({ success: false, error: '缺少 Worker 名或版本 ID' }, 400);
        const r = await cfReq('POST', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/deployments', auth, {
          strategy: 'percentage',
          versions: [{ version_id: versionId, percentage: 100 }]
        });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '回滚失败' });
        return json({ success: true, message: '已回滚到指定版本' });
      }

      case 'get-worker-current-version': {
        // 获取 Worker 当前线上版本的 version_id（用于在版本列表中标记“当前”）
        const accountId = payload.accountId || await getAccountId(auth);
        const scriptName = String(payload.scriptName || '').trim();
        if (!scriptName) return json({ success: false, error: '缺少 Worker 名' }, 400);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/deployments', auth);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '获取当前部署失败' });
        const deps = (r.data.result && r.data.result.deployments) || r.data.result || [];
        const latest = Array.isArray(deps) ? deps[0] : null;
        const vers = (latest && latest.versions) || [];
        const cur = vers.length ? (vers[0].version_id || vers[0].id) : null;
        return json({ success: true, currentVersionId: cur });
      }

      case 'list-worker-versions': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/workers/' + encodeURIComponent(payload.scriptName) + '/versions', auth);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || 'Versions API 不可用（Beta 接口，需要较新权限）', beta: true });
        return json({ success: true, result: r.data.result });
      }

      case 'set-worker-compatibility': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        const cd = String(payload.compatibilityDate || '').trim();
        if (!/^\d{4}-\d{2}-\d{2}$/.test(cd)) return json({ success: false, error: '兼容日期格式不正确，应为 YYYY-MM-DD' }, 400);
        // 用 PATCH settings 接口（multipart/form-data），无需重传代码，不丢绑定
        const fd = new FormData();
        fd.append('settings', new Blob([JSON.stringify({ compatibility_date: cd })], { type: 'application/json' }));
        const r = await cfReq('PATCH', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/settings', auth, fd);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '更新失败' });
        return json({ success: true, message: '兼容日期已更新为 ' + cd });
      }

      case 'set-worker-compat-flags': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        const flags = Array.isArray(payload.flags) ? payload.flags.map((f) => String(f).trim()).filter((f) => f) : [];
        // 用 PATCH settings 接口更新 compatibility_flags
        const fd2 = new FormData();
        fd2.append('settings', new Blob([JSON.stringify({ compatibility_flags: flags })], { type: 'application/json' }));
        const r2 = await cfReq('PATCH', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/settings', auth, fd2);
        if (!r2.ok) return json({ success: false, error: ((r2.data.errors || [])[0] || {}).message || '更新失败' });
        return json({ success: true, message: '兼容性标志已更新' });
      }

      case 'get-worker-settings': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/settings', auth);
        return json({ success: r.ok, result: r.data.result || {}, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      case 'get-worker-schedules': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/schedules', auth);
        const arr = (r.ok && r.data.result && r.data.result.schedules) || [];
        return json({ success: r.ok, result: arr, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      case 'set-worker-schedules': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.scriptName) return json({ success: false, error: 'scriptName required' }, 400);
        const crons = Array.isArray(payload.crons) ? payload.crons : [];
        // PUT body 为裸 JSON 数组 [{cron: "..."}]，整体替换
        const r = await cfReq('PUT', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/schedules', auth, crons);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '更新失败' });
        return json({ success: true, result: (r.data.result && r.data.result.schedules) || [] });
      }

      case 'get-worker-variables': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/bindings', auth);
        const vars = [];
        if (r.ok && r.data.result) r.data.result.forEach((b) => {
          if (b.type === 'plain_text' || b.type === 'secret_text') vars.push({ name: b.name, type: b.type, value: b.text || '' });
          // json 绑定的值在 `json` 字段（已解析），secret 的值读不出来（留空=保持不变）
          else if (b.type === 'json') vars.push({ name: b.name, type: b.type, value: (b.json !== undefined && b.json !== null) ? JSON.stringify(b.json) : (b.text || '') });
        });
        return json({ success: true, result: { vars } });
      }

      // 环境变量：全量重传（保留 KV/D1/R2 等非变量绑定）
      case 'put-worker-variables': {
        const accountId = payload.accountId || await getAccountId(auth);
        const scriptName = payload.scriptName;
        if (!scriptName || !Array.isArray(payload.variables)) return json({ success: false, error: 'bad params' }, 400);
        // JSON 类型提前校验，给出明确报错
        for (const v of payload.variables) {
          if (v.type === 'json') {
            try { JSON.parse(String(v.value)); }
            catch (e) { return json({ success: false, error: '变量「' + v.name + '」的 JSON 格式不正确：' + e.message }, 400); }
          }
        }
        let currentScript = null, currentBindings = [];
        try {
          const b = await cfReq('GET', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/bindings', auth);
          if (b.ok && b.data.result) currentBindings = b.data.result;
        } catch (e) {}
        try {
          const dl = await downloadWorkerScript(auth, accountId, scriptName);
          if (dl.ok && dl.rawScript) currentScript = dl.rawScript;
        } catch (e) {}
        if (!currentScript) currentScript = "export default { async fetch() { return new Response('Worker updated.'); } };";
        // 密钥语义：整行删除 => 删除该密钥；保留行但值留空 => 保持不变；填了值 => 更新
        const submittedNames = new Set(payload.variables.map((v) => v.name));
        const existingSecrets = new Set(currentBindings.filter((b) => b.type === 'secret_text').map((b) => b.name));
        const deleteSecrets = [...existingSecrets].filter((n) => !submittedNames.has(n));
        const effectiveVars = payload.variables.filter((v) => !(v.type === 'secret_text' && String(v.value == null ? '' : v.value) === ''));
        const effectiveNames = new Set(effectiveVars.map((v) => v.name));
        // secrets 通过上传 metadata 单独处理，不从旧 bindings 里带（旧值不可读，带空值会清空）
        const otherBindings = cleanBindingsForUpload(currentBindings).filter((b) => b.type !== 'secret_text' && (!effectiveNames.has(b.name) || (b.type !== 'plain_text' && b.type !== 'json')));
        // 校验 D1 绑定：数据库若已被删除则跳过，避免整个上传失败
        const skippedD1 = [];
        let d1Ids = null;
        const d1Bindings = otherBindings.filter((b) => b.type === 'd1');
        if (d1Bindings.length) {
          try {
            const dl = await cfReq('GET', '/accounts/' + accountId + '/d1/database', auth);
            if (dl.ok && dl.data.result) d1Ids = new Set(dl.data.result.map((d) => d.uuid || d.id));
          } catch (e) {}
        }
        const validBindings = otherBindings.filter((b) => {
          if (b.type === 'd1' && d1Ids && !d1Ids.has(b.id)) { skippedD1.push(b.name); return false; }
          return true;
        });
        const envBindings = effectiveVars.map((v) => ({ type: v.type === 'secret_text' ? 'secret_text' : (v.type === 'json' ? 'json' : 'plain_text'), name: v.name, text: String(v.value == null ? '' : v.value) }));
        const r = await uploadWorkerScript(auth, accountId, scriptName, currentScript, validBindings.concat(envBindings));
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '保存失败' });
        // 删除被整行移除的密钥
        const delErrs = [];
        for (const n of deleteSecrets) {
          try {
            const dr = await cfReq('DELETE', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/secrets/' + encodeURIComponent(n), auth);
            if (!dr.ok) delErrs.push(n);
          } catch (e) { delErrs.push(n); }
        }
        return json({ success: true, message: '环境变量已保存' + (skippedD1.length ? '；以下 D1 绑定因数据库不存在已跳过：' + skippedD1.join('、') : '') + (delErrs.length ? '；但以下密钥删除失败：' + delErrs.join('、') : '') });
      }

      // secrets 批量增删改（不重传代码）：逐个调用官方 secrets 接口
      case 'patch-worker-secrets': {
        const accountId = payload.accountId || await getAccountId(auth);
        const scriptName = payload.scriptName;
        const secrets = payload.secrets || {};
        for (const n of Object.keys(secrets)) {
          let v = secrets[n];
          if (v && typeof v === 'object' && 'text' in v) v = v.text;
          let r;
          if (v === null || v === undefined) {
            r = await cfReq('DELETE', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/secrets/' + encodeURIComponent(n), auth);
          } else {
            r = await cfReq('PUT', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(scriptName) + '/secrets', auth, { name: n, text: String(v), type: 'secret_text' });
          }
          if (!r.ok) return json({ success: false, error: '密钥「' + n + '」' + (v == null ? '删除' : '保存') + '失败：' + (((r.data.errors || [])[0] || {}).message || '未知错误') });
        }
        return json({ success: true, message: '密钥批量更新成功' });
      }

      case 'get-workers-subdomain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/subdomain', auth);
        return json({ success: r.ok, result: r.data.result, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'put-workers-subdomain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('PUT', '/accounts/' + accountId + '/workers/subdomain', auth, { subdomain: payload.subdomain });
        return json({ success: r.ok, result: r.data.result, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'toggle-worker-subdomain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/workers/scripts/' + encodeURIComponent(payload.scriptName) + '/subdomain', auth, { enabled: !!payload.enabled });
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      // ===== 自定义域名（新版账号级接口）=====
      case 'list-worker-domains': {
        const accountId = payload.accountId || await getAccountId(auth);
        const q = payload.scriptName ? '?service=' + encodeURIComponent(payload.scriptName) : '';
        const r = await cfReq('GET', '/accounts/' + accountId + '/workers/domains' + q, auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'add-worker-domain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const cleanHost = String(payload.hostname || '').replace(/^https?:\/\//, '').replace(/\/$/, '').trim().toLowerCase();
        if (!cleanHost) return json({ success: false, error: 'hostname required' }, 400);
        // 找到归属 zone：精确匹配，否则逐级剥 subdomain
        let zone = null;
        const labels = cleanHost.split('.');
        for (let i = 0; i <= labels.length - 2; i++) {
          const cand = labels.slice(i).join('.');
          const zr = await cfReq('GET', '/zones?name=' + encodeURIComponent(cand) + '&per_page=5', auth);
          if (zr.ok && zr.data.result && zr.data.result.length) {
            zone = zr.data.result.find((z) => z.name.toLowerCase() === cand) || zr.data.result[0];
            break;
          }
        }
        if (!zone) return json({ success: false, error: '该域名没有接入此 Cloudflare 账号的 Zone' });
        const r = await cfReq('PUT', '/accounts/' + accountId + '/workers/domains', auth, {
          hostname: cleanHost, service: payload.scriptName, zone_id: zone.id, environment: 'production'
        });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '绑定失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'delete-worker-domain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/workers/domains/' + encodeURIComponent(payload.domainId), auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      // ===== KV =====
      case 'list-kv-namespaces': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/storage/kv/namespaces?per_page=100', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-kv-namespace': {
        const accountId = payload.accountId || await getAccountId(auth);
        const body = { title: payload.title };
        if (payload.jurisdiction && payload.jurisdiction !== 'default') body.jurisdiction = payload.jurisdiction;
        const r = await cfReq('POST', '/accounts/' + accountId + '/storage/kv/namespaces', auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '创建失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'rename-kv-namespace': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('PUT', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId, auth, { title: payload.title });
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'delete-kv-namespace': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId, auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'list-kv-keys': {
        const accountId = payload.accountId || await getAccountId(auth);
        let q = '?limit=' + Math.min(1000, Math.max(10, payload.limit || 100));
        if (payload.cursor) q += '&cursor=' + encodeURIComponent(payload.cursor);
        if (payload.prefix) q += '&prefix=' + encodeURIComponent(payload.prefix);
        const r = await cfReq('GET', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/keys' + q, auth);
        return json({ success: r.ok, result: r.data.result || [], result_info: r.data.result_info, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'get-kv-value': {
        const accountId = payload.accountId || await getAccountId(auth);
        const kvKey = payload.kvKey || payload.key;
        const url = CF_API_BASE + '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/values/' + encodeURIComponent(kvKey);
        const resp = await fetch(url, { headers: cfHeaders(auth) });
        const text = await resp.text();
        return json({ success: resp.ok, value: text, truncated: text.length >= 1024 * 1024 });
      }
      case 'put-kv-value': {
        const accountId = payload.accountId || await getAccountId(auth);
        let q = '';
        const qp = [];
        if (payload.expiration_ttl) qp.push('expiration_ttl=' + encodeURIComponent(payload.expiration_ttl));
        if (payload.expiration) qp.push('expiration=' + encodeURIComponent(payload.expiration));
        if (qp.length) q = '?' + qp.join('&');
        const kvKey = payload.kvKey || payload.key;
        const url = '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/values/' + encodeURIComponent(kvKey) + q;
        const r = await cfReq('PUT', url, auth, null, { headers: { 'Content-Type': 'application/octet-stream' }, rawBody: payload.value || '' });
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'delete-kv-value': {
        const accountId = payload.accountId || await getAccountId(auth);
        const kvKey = payload.kvKey || payload.key;
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/values/' + encodeURIComponent(kvKey), auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'bulk-write-kv': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('PUT', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/bulk', auth, payload.items || []);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '批量写入失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'bulk-delete-kv': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/storage/kv/namespaces/' + payload.namespaceId + '/bulk/delete', auth, payload.keys || []);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '批量删除失败' });
        return json({ success: true, result: r.data.result });
      }

      // ===== D1 =====
      case 'list-d1': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/d1/database?per_page=100', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-d1-database': {
        const accountId = payload.accountId || await getAccountId(auth);
        const body = { name: payload.name };
        if (payload.primary_location_hint && payload.primary_location_hint !== 'auto') body.primary_location_hint = payload.primary_location_hint;
        const r = await cfReq('POST', '/accounts/' + accountId + '/d1/database', auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '创建失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'delete-d1-database': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/d1/database/' + payload.databaseId, auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'execute-d1-query': {
        const accountId = payload.accountId || await getAccountId(auth);
        const body = { sql: payload.query };
        if (Array.isArray(payload.params) && payload.params.length) body.params = payload.params;
        const r = await cfReq('POST', '/accounts/' + accountId + '/d1/database/' + payload.databaseId + '/query', auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '查询失败', details: r.data });
        return json({ success: true, result: r.data.result });
      }
      case 'execute-d1-raw': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/d1/database/' + payload.databaseId + '/raw', auth, { sql: payload.query });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '查询失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'd1-export-start': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/d1/database/' + payload.databaseId + '/export', auth, { output_format: 'polling' });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '导出启动失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'd1-export-poll': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/d1/database/' + payload.databaseId + '/export', auth, { output_format: 'polling', current_bookmark: payload.bookmark });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '导出轮询失败' });
        return json({ success: true, result: r.data.result });
      }

      // ===== R2 =====
      case 'list-r2-buckets': {
        const accountId = payload.accountId || await getAccountId(auth);
        const headers = {};
        if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
        const r = await cfReq('GET', '/accounts/' + accountId + '/r2/buckets?per_page=100', auth, null, { headers });
        return json({ success: r.ok, result: (r.data.result && r.data.result.buckets) || r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-r2-bucket': {
        const accountId = payload.accountId || await getAccountId(auth);
        const body = { name: payload.name };
        if (payload.locationHint && payload.locationHint !== 'auto') body.locationHint = payload.locationHint;
        if (payload.storageClass && payload.storageClass !== 'Standard') body.storageClass = payload.storageClass;
        const headers = {};
        if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
        const r = await cfReq('POST', '/accounts/' + accountId + '/r2/buckets', auth, body, { headers });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '创建失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'update-r2-bucket': {
        // 修改存储桶默认存储类型：Cloudflare 要求通过 cf-r2-storage-class 请求头传递
        const accountId = payload.accountId || await getAccountId(auth);
        const sc = String(payload.storageClass || '');
        if (sc !== 'Standard' && sc !== 'InfrequentAccess') return json({ success: false, error: '存储类型无效' });
        const r = await cfReq('PATCH', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name), auth, null, { headers: { 'cf-r2-storage-class': sc } });
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'delete-r2-bucket': {
        const accountId = payload.accountId || await getAccountId(auth);
        const headers = {};
        if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name), auth, null, { headers });
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'get-r2-bucket': {
        // 存储桶详情：名称 / 创建时间 / 位置 / 存储类型
        const accountId = payload.accountId || await getAccountId(auth);
        const headers = {};
        if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
        const r = await cfReq('GET', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name), auth, null, { headers });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '获取存储桶详情失败' });
        return json({ success: true, result: r.data.result || {} });
      }
      case 'r2-s3-test': {
        // 测试 S3 凭证：列 1 个对象
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const r = await r2S3Fetch(accountId, creds, 'GET', payload.name, '', { 'list-type': '2', 'max-keys': '1' });
          if (!r.ok) return json({ success: false, error: s3ErrorMessage(r.text, 'S3 凭证验证失败（HTTP ' + r.status + '）') });
          return json({ success: true });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-objects-list': {
        // S3 ListObjectsV2：prefix 前缀 + delimiter='/' 实现文件夹导航
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const qp = { 'list-type': '2', 'max-keys': String(Math.min(parseInt(payload.maxKeys || '100', 10) || 100, 1000)), 'delimiter': '/' };
          if (payload.prefix) qp['prefix'] = payload.prefix;
          if (payload.continuationToken) qp['continuation-token'] = payload.continuationToken;
          const r = await r2S3Fetch(accountId, creds, 'GET', payload.name, '', qp);
          if (!r.ok) return json({ success: false, error: s3ErrorMessage(r.text, '列出对象失败（HTTP ' + r.status + '）') });
          return json({ success: true, result: parseS3ListXml(r.text) });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-object-put': {
        // S3 PutObject：前端传 base64 内容（单文件建议 ≤ 50MB）
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const key = String(payload.key || '');
          if (!key || key.endsWith('/')) return json({ success: false, error: '对象键名无效' });
          const body = b64ToBytes(payload.content || '');
          if (body.length > 100 * 1024 * 1024) return json({ success: false, error: '单个文件超过 100MB，请用 S3 兼容 API 直传' });
          const r = await r2S3Fetch(accountId, creds, 'PUT', payload.name, key, {}, payload.contentType ? { 'content-type': payload.contentType } : null, body);
          if (!r.ok) return json({ success: false, error: s3ErrorMessage(r.text, '上传失败（HTTP ' + r.status + '）') });
          return json({ success: true, result: { key, size: body.length } });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-object-delete': {
        // S3 DeleteObject（单个）
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const key = String(payload.key || '');
          if (!key) return json({ success: false, error: '对象键名无效' });
          const r = await r2S3Fetch(accountId, creds, 'DELETE', payload.name, key);
          if (!r.ok) return json({ success: false, error: s3ErrorMessage(r.text, '删除失败（HTTP ' + r.status + '）') });
          return json({ success: true });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-object-download-url': {
        // 生成 S3 预签名下载 URL（有效期 payload.expires 秒，默认 3600），前端直接打开下载
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const key = String(payload.key || '');
          if (!key) return json({ success: false, error: '对象键名无效' });
          const host = accountId + '.r2.cloudflarestorage.com';
          const region = 'auto', service = 's3';
          const expires = Math.min(parseInt(payload.expires || '3600', 10) || 3600, 604800);
          const now = new Date();
          const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, '') + 'Z';
          const dateStamp = amzDate.slice(0, 8);
          const canonicalUri = '/' + payload.name + '/' + key.split('/').map((s) => encodeURIComponent(s)).join('/');
          const credentialScope = [dateStamp, region, service, 'aws4_request'].join('/');
          const qp = {
            'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
            'X-Amz-Credential': creds.accessKeyId + '/' + credentialScope,
            'X-Amz-Date': amzDate,
            'X-Amz-Expires': String(expires),
            'X-Amz-SignedHeaders': 'host',
          };
          if (creds.sessionToken) qp['X-Amz-Security-Token'] = creds.sessionToken;
          const qpStr = Object.keys(qp).sort().map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(qp[k])).join('&');
          const canonicalRequest = ['GET', canonicalUri, qpStr, 'host:' + host + '\n', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
          const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256HexBytes(new TextEncoder().encode(canonicalRequest))].join('\n');
          let sk = await hmacBytes(new TextEncoder().encode('AWS4' + creds.secretAccessKey), dateStamp);
          sk = await hmacBytes(sk, region); sk = await hmacBytes(sk, service); sk = await hmacBytes(sk, 'aws4_request');
          const sigBytes = await hmacBytes(sk, stringToSign);
          const signature = [...sigBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
          return json({ success: true, result: { url: 'https://' + host + canonicalUri + '?' + qpStr + '&X-Amz-Signature=' + signature, expires } });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-temp-credentials': {
        // 用 Cloudflare API Token 换取 R2 临时 S3 凭证（免手动创建 R2 API Token）
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const body = {
            bucket: payload.name,
            permission: payload.permission || 'object-read-write',
            ttlSeconds: Math.min(parseInt(payload.ttlSeconds || '3600', 10) || 3600, 86400),
          };
          if (payload.objects) body.objects = payload.objects;
          const r = await cfReq('POST', '/accounts/' + accountId + '/r2/temp-access-credentials', auth, body);
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '获取临时凭证失败（Token 可能缺少 R2 权限）' });
          const creds = r.data.result || {};
          return json({ success: true, result: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken } });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-bucket-domains': {
        // 存储桶域名：r2.dev 公共开发 URL + 自定义域名列表
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const headers = {};
          if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
          const bn = encodeURIComponent(payload.name);
          const [managed, custom] = await Promise.all([
            cfReq('GET', '/accounts/' + accountId + '/r2/buckets/' + bn + '/domains/managed', auth, null, { headers }),
            cfReq('GET', '/accounts/' + accountId + '/r2/buckets/' + bn + '/domains/custom', auth, null, { headers }),
          ]);
          const m = (managed.ok && managed.data.result) || {};
          const list = (custom.ok && custom.data.result) || [];
          const customs = Array.isArray(list) ? list : (list.domains || []);
          return json({
            success: true,
            result: {
              publicUrl: m.enabled && m.domain ? ('https://' + m.domain) : '',
              publicDomain: m.domain || '',
              publicEnabled: !!m.enabled,
              custom: customs.map((x) => typeof x === 'string' ? { domain: x } : x),
            },
          });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-public-url-toggle': {
        // 启用/禁用 r2.dev 公共开发 URL
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const headers = {};
          if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
          const r = await cfReq('PUT', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name) + '/domains/managed',
            auth, { enabled: !!payload.enable }, { headers });
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '操作失败' });
          return json({ success: true, result: r.data.result });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-custom-domain-add': {
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const headers = {};
          if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
          const domain = String(payload.domain || '').trim();
          if (!domain) return json({ success: false, error: '请输入域名' });
          // zoneId：从域名自动匹配账号下的 zone
          let zoneId = payload.zoneId || '';
          if (!zoneId) {
            const zr = await cfReq('GET', '/zones?per_page=100', auth);
            const zones = (zr.ok && zr.data.result) || [];
            const match = zones.find((z) => domain === z.name || domain.endsWith('.' + z.name));
            if (match) zoneId = match.id;
          }
          if (!zoneId) return json({ success: false, error: '该域名不在本账号的站点列表中，请先添加站点' });
          const r = await cfReq('POST', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name) + '/domains/custom',
            auth, { domain, enabled: true, zoneId }, { headers });
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '添加失败' });
          return json({ success: true, result: r.data.result });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-custom-domain-remove': {
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const headers = {};
          if (payload.jurisdiction && payload.jurisdiction !== 'default') headers['cf-r2-jurisdiction'] = payload.jurisdiction;
          const r = await cfReq('DELETE', '/accounts/' + accountId + '/r2/buckets/' + encodeURIComponent(payload.name) + '/domains/custom/' + encodeURIComponent(payload.domain),
            auth, null, { headers });
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '删除失败' });
          return json({ success: true });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-catalog-get': {
        // 查询 R2 数据目录状态（Iceberg REST catalog）
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const r = await cfReq('GET', '/accounts/' + accountId + '/r2-catalog/' + encodeURIComponent(payload.name), auth);
          if (!r.ok) {
            const msg = ((r.data.errors || [])[0] || {}).message || '';
            // 目录未启用时 API 返回 404，视为未启用而非报错
            if (r.status === 404) return json({ success: true, result: { enabled: false } });
            return json({ success: false, error: msg || '查询失败' });
          }
          const c = r.data.result || {};
          const active = (c.status === 'active');
          return json({
            success: true,
            result: {
              enabled: active,
              status: c.status || '',
              warehouse: c.name || (accountId + '_' + payload.name),
              catalogUri: 'https://catalog.cloudflarestorage.com/' + accountId + '/' + payload.name,
              maintenance: c.maintenance_config || null,
              credentialStatus: c.credential_status || '',
            },
          });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-catalog-enable': {
        // 启用 R2 数据目录
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const r = await cfReq('POST', '/accounts/' + accountId + '/r2-catalog/' + encodeURIComponent(payload.name) + '/enable', auth);
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '启用失败' });
          return json({ success: true, result: r.data.result });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-catalog-disable': {
        // 禁用 R2 数据目录（保留数据与元数据）
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const r = await cfReq('POST', '/accounts/' + accountId + '/r2-catalog/' + encodeURIComponent(payload.name) + '/disable', auth);
          if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '禁用失败' });
          return json({ success: true });
        } catch (e) { return json({ success: false, error: e.message }); }
      }
      case 'r2-metrics': {
        // R2 指标（GraphQL）：平均存储 / 已检索数据 / A类操作 / B类操作 / 请求分布
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const rangeH = payload.range === '7d' ? 168 : payload.range === '30d' ? 720 : 24;
          const end = new Date();
          const start = new Date(end.getTime() - rangeH * 3600000);
          const iso = (d) => d.toISOString().replace(/\.\d+Z$/, 'Z');
          const bucketName = payload.name;
          const gql = async (query) => {
            const res = await fetch('https://api.cloudflare.com/client/v4/graphql', {
              method: 'POST',
              headers: Object.assign({ 'Content-Type': 'application/json' }, cfHeaders(auth)),
              body: JSON.stringify({ query }),
            });
            const t = await res.text();
            let d; try { d = JSON.parse(t); } catch (e) { d = { errors: [{ message: 'GraphQL 响应解析失败' }] }; }
            return d;
          };
          const q = (node, fields, dims) =>
            '{ viewer { accounts(filter: { accountTag: "' + accountId + '" }) { ' + node +
            '(limit: 10000, filter: { bucketName: "' + bucketName + '", datetime_geq: "' + iso(start) + '", datetime_leq: "' + iso(end) + '" }) ' +
            '{ ' + fields + (dims ? ' dimensions { ' + dims + ' }' : '') + ' } } } }';
          const [st, op, bw] = await Promise.all([
            gql(q('r2StorageAdaptiveGroups', 'max { payloadSize metadataSize objectCount }', '')),
            gql(q('r2OperationsAdaptiveGroups', 'sum { requests }', 'actionType')),
            gql(q('r2BandwidthUsageAdaptiveGroups', 'sum { bytesDownload bytesUpload }', '')),
          ]);
          const err = (d) => (d.errors && d.errors[0] && d.errors[0].message) || '';
          if (err(st) || err(op) || err(bw)) {
            return json({ success: false, error: '指标查询失败：' + (err(st) || err(op) || err(bw)) });
          }
          const acc0 = (d, i) => (((d.data || {}).viewer || {}).accounts || [])[i || 0] || {};
          const sGroups = acc0(st).r2StorageAdaptiveGroups || [];
          const oGroups = acc0(op).r2OperationsAdaptiveGroups || [];
          const bGroups = acc0(bw).r2BandwidthUsageAdaptiveGroups || [];
          const sMax = (sGroups[0] && sGroups[0].max) || {};
          const avgBytes = (sMax.payloadSize || 0) + (sMax.metadataSize || 0);
          const bwSum = (bGroups[0] && bGroups[0].sum) || {};
          // 按 R2 计费口径归类：A类=写入/列表类，B类=读取类，删除/取消分片上传免费
          const classA = new Set(['PutObject', 'CopyObject', 'CompleteMultipartUpload', 'CreateMultipartUpload', 'UploadPart', 'UploadPartCopy', 'ListBuckets', 'ListObjects', 'ListObjectsV2', 'ListMultipartUploads', 'ListParts', 'PutBucket', 'PutBucketCors', 'PutBucketLifecycle', 'PutBucketLifecycleConfiguration', 'PutBucketEncryption', 'LifecycleStorageTierTransition']);
          const classB = new Set(['GetObject', 'HeadObject', 'HeadBucket', 'UsageSummary', 'GetBucketLocation', 'GetBucketCors', 'GetBucketLifecycle', 'GetBucketLifecycleConfiguration', 'GetBucketEncryption']);
          const freeOps = new Set(['DeleteObject', 'DeleteObjects', 'DeleteBucket', 'AbortMultipartUpload']);
          let aCount = 0, bCount = 0, freeCount = 0, total = 0;
          for (const g of oGroups) {
            const n = (g.sum && g.sum.requests) || 0;
            total += n;
            const at = (g.dimensions && g.dimensions.actionType) || '';
            if (classA.has(at)) aCount += n;
            else if (classB.has(at)) bCount += n;
            else if (freeOps.has(at)) freeCount += n;
            else bCount += n; // 未知读类操作按 B 类计入，避免漏算
          }
          const fmtB = (n) => {
            n = Number(n) || 0;
            if (n < 1024) return n + ' B';
            if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
            if (n < 1073741824) return (n / 1048576).toFixed(2) + ' MB';
            return (n / 1073741824).toFixed(2) + ' GB';
          };
          const fmtN = (n) => Number(n).toLocaleString('en-US');
          return json({
            success: true,
            result: {
              avgStorage: fmtB(avgBytes),
              egress: fmtB(bwSum.bytesDownload || 0),
              classA: fmtN(aCount),
              classB: fmtN(bCount),
              freeOps: fmtN(freeCount),
              requests: fmtN(total),
            },
          });
        } catch (e) { return json({ success: false, error: e.message }); }
      }

      case 'r2-object-download-url': {
        // 生成 S3 预签名下载 URL（有效期 payload.expires 秒，默认 3600），前端直接打开下载
        try {
          const accountId = payload.accountId || await getAccountId(auth);
          const creds = getS3Creds(payload);
          const key = String(payload.key || '');
          if (!key) return json({ success: false, error: '对象键名无效' });
          const host = accountId + '.r2.cloudflarestorage.com';
          const region = 'auto', service = 's3';
          const expires = Math.min(parseInt(payload.expires || '3600', 10) || 3600, 604800);
          const now = new Date();
          const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\..+/, '') + 'Z';
          const dateStamp = amzDate.slice(0, 8);
          const canonicalUri = '/' + payload.name + '/' + key.split('/').map((s) => encodeURIComponent(s)).join('/');
          const credentialScope = [dateStamp, region, service, 'aws4_request'].join('/');
          const qp = {
            'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
            'X-Amz-Credential': creds.accessKeyId + '/' + credentialScope,
            'X-Amz-Date': amzDate,
            'X-Amz-Expires': String(expires),
            'X-Amz-SignedHeaders': 'host',
          };
          if (creds.sessionToken) qp['X-Amz-Security-Token'] = creds.sessionToken;
          const qpStr = Object.keys(qp).sort().map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(qp[k])).join('&');
          const canonicalRequest = ['GET', canonicalUri, qpStr, 'host:' + host + '\n', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
          const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, await sha256HexBytes(new TextEncoder().encode(canonicalRequest))].join('\n');
          let sk = await hmacBytes(new TextEncoder().encode('AWS4' + creds.secretAccessKey), dateStamp);
          sk = await hmacBytes(sk, region); sk = await hmacBytes(sk, service); sk = await hmacBytes(sk, 'aws4_request');
          const sigBytes = await hmacBytes(sk, stringToSign);
          const signature = [...sigBytes].map((b) => b.toString(16).padStart(2, '0')).join('');
          return json({ success: true, result: { url: 'https://' + host + canonicalUri + '?' + qpStr + '&X-Amz-Signature=' + signature, expires } });
        } catch (e) { return json({ success: false, error: e.message }); }
      }

      // ===== DNS =====
      case 'list-zones': {
        const r = await cfReq('GET', '/zones?per_page=100', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-zone': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/zones', auth, { name: payload.name, account: { id: accountId }, jump_start: true, type: 'full' });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '添加失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'delete-zone': {
        const r = await cfReq('DELETE', '/zones/' + payload.zoneId, auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'list-dns-records': {
        let q = '?per_page=100';
        if (payload.type) q += '&type=' + encodeURIComponent(payload.type);
        if (payload.name) q += '&name=' + encodeURIComponent(payload.name);
        const r = await cfReq('GET', '/zones/' + payload.zoneId + '/dns_records' + q, auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-dns-record': {
        const body = { type: payload.type, name: payload.name, content: payload.content, ttl: payload.ttl || 1, proxied: !!payload.proxied };
        if (payload.comment) body.comment = payload.comment;
        if (payload.priority) body.priority = Number(payload.priority);
        const r = await cfReq('POST', '/zones/' + payload.zoneId + '/dns_records', auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '添加失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'update-dns-record': {
        // 新版用 PATCH 做部分更新；type 不可再修改
        const body = { name: payload.name, content: payload.content, ttl: payload.ttl || 1, proxied: !!payload.proxied };
        if (payload.comment !== undefined) body.comment = payload.comment;
        const r = await cfReq('PATCH', '/zones/' + payload.zoneId + '/dns_records/' + payload.recordId, auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '更新失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'delete-dns-record': {
        const r = await cfReq('DELETE', '/zones/' + payload.zoneId + '/dns_records/' + payload.recordId, auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'batch-dns-records': {
        // 事务性批量：posts 用于批量导入
        const r = await cfReq('POST', '/zones/' + payload.zoneId + '/dns_records/batch', auth, {
          deletes: payload.deletes || [], patches: payload.patches || [],
          puts: payload.puts || [], posts: payload.posts || []
        });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '批量操作失败', details: r.data });
        return json({ success: true, result: r.data.result });
      }

      // ===== Pages =====
      case 'list-pages-projects': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/pages/projects', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'create-pages-project': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/pages/projects', auth, { name: payload.name, production_branch: payload.production_branch || 'main' });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '创建失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'delete-pages-project': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName), auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'pages-deploy-upload': {
        const accountId = payload.accountId || await getAccountId(auth);
        const files = (payload.files || []).map((f) => {
          let p = String(f.path || '').replace(/\\/g, '/');
          if (!p.startsWith('/')) p = '/' + p;
          return { path: p, data: base64ToU8(String(f.content || '')) };
        });
        const hasIndex = files.some((f) => /(^|\/)index\.html?$/.test(f.path));
        const hasWorkerJs = files.some((f) => f.path === '/_worker.js');
        const r = await pagesDirectDeploy(auth, accountId, String(payload.projectName || '').trim(), files, String(payload.branch || '').trim());
        let warning = '';
        if (r.ok && r.advancedMode) warning = '已按 Pages 高级模式部署：所有请求由 _worker.js 处理。';
        else if (r.ok && !hasIndex) warning = '注意：上传的文件中没有 index.html，访问首页会显示 404。';
        return json({ success: r.ok, error: r.error, url: r.url, id: r.id, fileCount: files.length, stage: r.stage, warning, advancedMode: !!r.advancedMode });
      }
      case 'pages-deploy-github': {
        const accountId = payload.accountId || await getAccountId(auth);
        const gh = parseGithubUrl(payload.repoUrl || '');
        if (!gh) return json({ success: false, error: 'GitHub 链接格式不正确' }, 400);
        let g;
        try {
          if (gh.file) {
            // 单文件链接（如 .../blob/main/_worker.js）：只下载这一个文件
            g = await fetchGithubSingleFile(gh.owner, gh.repo, gh.file.branch, gh.file.path);
          } else {
            g = await fetchGithubRepo(gh.owner, gh.repo, payload.branch);
          }
        }
        catch (e) { return json({ success: false, error: e.message }); }
        // 部署前检查：Pages 需要 index.html 才能正常访问首页（高级模式 _worker.js 除外）
        const hasIndex = g.files.some((f) => /(^|\/)index\.html?$/.test(f.path));
        const hasWorkerJs = g.files.some((f) => f.path === '/_worker.js');
        let warning = '';
        if (!hasIndex && !hasWorkerJs) warning = '注意：部署内容中没有 index.html，访问首页会显示 404。';
        const r = await pagesDirectDeploy(auth, accountId, String(payload.projectName || '').trim(), g.files, g.branch);
        if (r.ok && r.advancedMode) warning += (warning ? ' ' : '') + '已按 Pages 高级模式部署：所有请求由 _worker.js 处理。';
        return json({ success: r.ok, error: r.error, url: r.url, id: r.id, branch: g.branch, fileCount: g.files.length, warning: r.ok ? warning : '', advancedMode: !!r.advancedMode });
      }
      case 'list-pages-deployments': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/deployments?per_page=25', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'trigger-pages-deployment': {
        const accountId = payload.accountId || await getAccountId(auth);
        const pn = encodeURIComponent(payload.projectName);
        // 先判断项目类型：Git 关联项目可用 branch 触发构建；直接上传项目必须带 manifest（无文件无法重建）
        const pj = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + pn, auth);
        const proj = (pj.ok && pj.data.result) || {};
        const isGit = !!(proj.source && proj.source.type);
        if (!isGit) {
          return json({ success: false, error: '该项目为「直接上传」类型，Cloudflare 不支持无文件重新部署。请用「文件上传」或「GitHub 导入」重新部署；若上次部署失败，可在部署记录里点「重试」。' });
        }
        const body = { branch: payload.branch || proj.production_branch || 'main' };
        const r = await cfReq('POST', '/accounts/' + accountId + '/pages/projects/' + pn + '/deployments', auth, body);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '触发失败' });
        return json({ success: true, result: r.data.result });
      }
      case 'retry-pages-deployment': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('POST', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/deployments/' + encodeURIComponent(payload.deploymentId) + '/retry', auth, {});
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'rollback-pages-deployment': {
        // Pages 回滚：从目标部署的 URL 下载文件，重新部署为新版本
        const accountId = payload.accountId || await getAccountId(auth);
        const projectName = String(payload.projectName || '').trim();
        const deploymentId = String(payload.deploymentId || '').trim();
        if (!projectName || !deploymentId) return json({ success: false, error: '缺少项目名或部署 ID' }, 400);
        // 获取部署信息，拿到 URL
        const dg = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(projectName) + '/deployments/' + encodeURIComponent(deploymentId), auth);
        if (!dg.ok) return json({ success: false, error: '获取部署信息失败：' + (((dg.data.errors || [])[0] || {}).message || '未知错误') });
        const depUrl = (dg.data.result && (dg.data.result.url || (dg.data.result.aliases && dg.data.result.aliases[0]))) || ('https://' + deploymentId + '.' + projectName + '.pages.dev');
        // 下载首页
        let html;
        try {
          const hr = await fetch(depUrl, { redirect: 'follow' });
          if (!hr.ok) return json({ success: false, error: '下载部署文件失败：HTTP ' + hr.status });
          html = await hr.text();
        } catch (e) { return json({ success: false, error: '下载部署文件失败：' + (e.message || e) }); }
        const files = [{ path: '/index.html', data: new TextEncoder().encode(html) }];
        // 解析 HTML 中的静态资源（css/js/图片等）
        const assetUrls = new Set();
        const re = /(?:src|href)=["']([^"'#?]+)["']/gi;
        let m;
        while ((m = re.exec(html)) !== null) {
          let u = m[1].trim();
          if (!u || u.startsWith('data:') || u.startsWith('mailto:') || u.startsWith('tel:') || u.startsWith('javascript:')) continue;
          if (u.startsWith('//')) u = 'https:' + u;
          else if (u.startsWith('/')) u = depUrl.replace(/\/$/, '') + u;
          else if (!/^https?:\/\//i.test(u)) u = depUrl.replace(/\/$/, '') + '/' + u;
          // 只下载同部署域名的资源
          try {
            const depHost = new URL(depUrl).hostname;
            if (new URL(u).hostname === depHost) assetUrls.add(u);
          } catch (e) {}
        }
        for (const au of assetUrls) {
          try {
            const ar = await fetch(au, { redirect: 'follow' });
            if (!ar.ok) continue;
            const buf = new Uint8Array(await ar.arrayBuffer());
            if (buf.length > 25 * 1024 * 1024) continue;
            const apath = '/' + new URL(au).pathname.replace(/^\/+/, '');
            if (apath === '/' || apath === '/index.html') continue;
            files.push({ path: apath, data: buf });
            if (files.length >= 100) break;
          } catch (e) {}
        }
        const r = await pagesDirectDeploy(auth, accountId, projectName, files, '');
        if (!r.ok) return json({ success: false, error: '回滚部署失败：' + (r.error || '未知错误') });
        return json({ success: true, message: '已回滚到部署 ' + deploymentId.slice(0, 8) + ' 的版本（' + files.length + ' 个文件）', result: r });
      }
      case 'get-pages-project-overview': {
        const accountId = payload.accountId || await getAccountId(auth);
        const pn = encodeURIComponent(payload.projectName);
        const [proj, domains] = await Promise.all([
          cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + pn, auth),
          cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + pn + '/domains', auth),
        ]);
        const p = (proj.ok && proj.data.result) || {};
        const dc = (p.deployment_configs || {});
        const prod = dc.production || {};
        const cfg = prod || {};
        const envVars = Object.keys(cfg.env_vars || {});
        const kv = Object.keys((cfg.kv_namespaces || {}));
        const d1 = Object.keys((cfg.d1_databases || {}));
        return json({ success: proj.ok, result: {
          name: p.name || payload.projectName,
          production_branch: p.production_branch || '',
          domains: (domains.ok && domains.data.result) || [],
          canonical_deployment: p.canonical_deployment || null,
          latest_deployment: p.latest_deployment || null,
          env_vars: envVars, kv_namespaces: kv, d1_databases: d1,
          deployment_configs: p.deployment_configs || {},
        }, error: !proj.ok && ((proj.data.errors || [])[0] || {}).message });
      }
      case 'delete-pages-deployment': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/deployments/' + encodeURIComponent(payload.deploymentId) + '?force=true', auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'list-pages-domains': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/domains', auth);
        return json({ success: r.ok, result: r.data.result || [], error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }
      case 'add-pages-domain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const hostname = payload.hostname || payload.domain;
        const r = await cfReq('POST', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/domains', auth, { name: hostname });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '添加失败' });
        // 如果域名属于当前账号的 Cloudflare Zone，自动创建 CNAME 解析
        let dnsNote = '';
        try {
          const zonesR = await cfReq('GET', '/zones?per_page=50', auth);
          const zones = (zonesR.ok && zonesR.data.result) || [];
          const hn = String(hostname || '').toLowerCase();
          let matchedZone = null;
          for (const z of zones) {
            const zn = String(z.name || '').toLowerCase();
            if (hn === zn || hn.endsWith('.' + zn)) {
              if (!matchedZone || zn.length > String(matchedZone.name || '').length) matchedZone = z;
            }
          }
          if (matchedZone) {
            const target = payload.projectName + '.pages.dev';
            // 检查是否已有记录
            const existR = await cfReq('GET', '/zones/' + matchedZone.id + '/dns_records?name=' + encodeURIComponent(hn) + '&type=CNAME', auth);
            const existing = (existR.ok && existR.data.result) || [];
            if (existing.length === 0) {
              const createR = await cfReq('POST', '/zones/' + matchedZone.id + '/dns_records', auth, {
                type: 'CNAME', name: hn, content: target, ttl: 1, proxied: false
              });
              if (createR.ok) dnsNote = '，已自动添加 CNAME 解析';
              else dnsNote = '，但自动添加 DNS 失败：' + (((createR.data.errors || [])[0] || {}).message || '未知错误');
            } else {
              dnsNote = '，DNS 记录已存在';
            }
          }
        } catch (e) { /* DNS 自动配置失败不影响主流程 */ }
        return json({ success: true, result: r.data.result, dnsNote: dnsNote });
      }
      case 'delete-pages-domain': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('DELETE', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName) + '/domains/' + encodeURIComponent(payload.hostname || payload.domain), auth);
        return json({ success: r.ok, error: !r.ok && ((r.data.errors || [])[0] || {}).message });
      }

      case 'get-pages-bindings': {
        const accountId = payload.accountId || await getAccountId(auth);
        const r = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName), auth);
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '获取失败' });
        return json({ success: true, result: (r.data.result && r.data.result.deployment_configs) || {} });
      }
      case 'set-pages-bindings': {
        const accountId = payload.accountId || await getAccountId(auth);
        const envVars = payload.envVars || {}, kv = payload.kv || {}, d1 = payload.d1 || {};
        const cfg = { env_vars: {}, kv_namespaces: {}, d1_databases: {} };
        Object.keys(envVars).forEach((k) => {
          if (!k) return;
          const ev = envVars[k];
          // 支持 {value, type} 或纯字符串（向后兼容）
          const val = (ev && typeof ev === 'object') ? ev.value : ev;
          const typ = (ev && typeof ev === 'object' && ev.type === 'secret') ? 'secret_text' : 'plain_text';
          if (val !== '' && val !== undefined) cfg.env_vars[k] = { type: typ, value: String(val) };
        });
        Object.keys(kv).forEach((k) => { if (k && kv[k]) cfg.kv_namespaces[k] = { namespace_id: kv[k] }; });
        Object.keys(d1).forEach((k) => { if (k && d1[k]) cfg.d1_databases[k] = { id: d1[k] }; });
        // 删除语义：先读现有配置，对已删除的键显式置 null（Cloudflare PATCH 为合并语义，空对象不会删除）
        try {
          const cur = await cfReq('GET', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName), auth);
          const dc = cur.ok && cur.data.result && cur.data.result.deployment_configs;
          if (dc) {
            ['production', 'preview'].forEach((env) => {
              const c = dc[env] || {};
              Object.keys(c.env_vars || {}).forEach((k) => { if (!(k in cfg.env_vars)) cfg.env_vars[k] = null; });
              Object.keys(c.kv_namespaces || {}).forEach((k) => { if (!(k in cfg.kv_namespaces)) cfg.kv_namespaces[k] = null; });
              Object.keys(c.d1_databases || c.d1 || {}).forEach((k) => { if (!(k in cfg.d1_databases)) cfg.d1_databases[k] = null; });
            });
          }
        } catch (e) { /* 读现有配置失败则按原逻辑提交 */ }
        const r = await cfReq('PATCH', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName), auth, { deployment_configs: { production: cfg, preview: cfg } });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '保存失败' });
        return json({ success: true, message: '绑定已保存（生产 + 预览环境）' });
      }

      case 'set-pages-compatibility': {
        const accountId = payload.accountId || await getAccountId(auth);
        if (!payload.projectName) return json({ success: false, error: 'projectName required' }, 400);
        const cfg = {};
        if (payload.compatibilityDate) {
          const cd = String(payload.compatibilityDate).trim();
          if (!/^\d{4}-\d{2}-\d{2}$/.test(cd)) return json({ success: false, error: '兼容日期格式不正确' }, 400);
          cfg.compatibility_date = cd;
        }
        if (Array.isArray(payload.flags)) {
          cfg.compatibility_flags = payload.flags.map((f) => String(f).trim()).filter((f) => f);
        }
        if (!Object.keys(cfg).length) return json({ success: false, error: '没有要更新的内容' }, 400);
        const r = await cfReq('PATCH', '/accounts/' + accountId + '/pages/projects/' + encodeURIComponent(payload.projectName), auth, {
          deployment_configs: { production: cfg, preview: cfg }
        });
        if (!r.ok) return json({ success: false, error: ((r.data.errors || [])[0] || {}).message || '更新失败' });
        return json({ success: true, message: 'Pages 兼容性设置已更新' });
      }

      // ===== 用量统计（GraphQL）=====
      case 'get-usage-today': {
        const accountId = payload.accountId || await getAccountId(auth);
        const now = new Date();
        const end = now.toISOString();
        now.setUTCHours(0, 0, 0, 0);
        const start = now.toISOString();
        try {
          const r = await cfReq('POST', '/graphql', auth, {
            query: 'query getBillingMetrics($accountId:String!,$filter:AccountWorkersInvocationsAdaptiveFilter_InputObject){viewer{accounts(filter:{accountTag:$accountId}){pagesFunctionsInvocationsAdaptiveGroups(limit:1000,filter:$filter){sum{requests}}workersInvocationsAdaptive(limit:10000,filter:$filter){sum{requests}}}}}',
            variables: { accountId, filter: { datetime_geq: start, datetime_leq: end } }
          });
          const ac = r.data && r.data.data && r.data.data.viewer && r.data.data.viewer.accounts && r.data.data.viewer.accounts[0];
          const p = ((ac && ac.pagesFunctionsInvocationsAdaptiveGroups) || []).reduce((t, i) => t + ((i.sum && i.sum.requests) || 0), 0);
          const w = ((ac && ac.workersInvocationsAdaptive) || []).reduce((t, i) => t + ((i.sum && i.sum.requests) || 0), 0);
          return json({ success: true, data: { total: p + w, workers: w, pages: p, percentage: Math.min(100, ((p + w) / 100000) * 100) } });
        } catch (e) {
          return json({ success: true, data: { total: 0, workers: 0, pages: 0, percentage: 0 } });
        }
      }
      case 'get-usage-per-worker': {
        const accountId = payload.accountId || await getAccountId(auth);
        const now = new Date();
        const end = now.toISOString();
        now.setUTCHours(0, 0, 0, 0);
        const start = now.toISOString();
        const r = await cfReq('POST', '/graphql', auth, {
          query: 'query($accountId:String!,$filter:AccountWorkersInvocationsAdaptiveFilter_InputObject){viewer{accounts(filter:{accountTag:$accountId}){workersInvocationsAdaptiveGroups(limit:25,filter:$filter,orderBy:[sum_requests_DESC]){dimensions{scriptName}sum{requests errors}}}}}',
          variables: { accountId, filter: { datetime_geq: start, datetime_leq: end } }
        });
        const ac = r.data && r.data.data && r.data.data.viewer && r.data.data.viewer.accounts && r.data.data.viewer.accounts[0];
        const rows = ((ac && ac.workersInvocationsAdaptiveGroups) || []).map((g) => ({
          name: (g.dimensions && g.dimensions.scriptName) || '(unknown)',
          count: (g.sum && g.sum.requests) || 0,
          errors: (g.sum && g.sum.errors) || 0
        }));
        return json({ success: r.ok, result: rows });
      }

      // ===== 批量模板（KV）=====
      case 'load-batch-templates-kv': {
        if (!env || !env.CF_ACCOUNTS_KV) return json({ success: false, error: 'CF_ACCOUNTS_KV 未绑定，无法读取内置模板' });
        await ensureDefaultBatchTemplates(env.CF_ACCOUNTS_KV);
        const templates = await loadBatchTemplatesFromKV(env.CF_ACCOUNTS_KV);
        return json({ success: true, templates });
      }

      default:
        return json({ success: false, error: 'unknown action: ' + action }, 400);
    }
  } catch (e) {
    return json({ success: false, error: String((e && e.message) || e) }, 500);
  }
}

function sanitizeBatchTemplate(template, fallbackKey) {
  const tpl = template && typeof template === 'object' ? template : {};
  const templateName = String(tpl.templateName || tpl.name || tpl.displayName || fallbackKey || '').trim();
  const workerName = String(tpl.workerName || tpl.sourceWorkerName || '').trim();
  const sourceWorkerName = String(tpl.sourceWorkerName || tpl.workerName || '').trim();
  const env = Array.isArray(tpl.env) ? tpl.env.map((item) => ({
    key: String((item && (item.key || item.name)) || '').trim(),
    value: item && item.value != null ? String(item.value) : ''
  })).filter((item) => item.key) : [];
  const kv = Array.isArray(tpl.kv) ? tpl.kv.map((item) => ({
    bind: String((item && (item.bind || item.key || item.name)) || '').trim(),
    name: String((item && (item.name || item.namespaceName || item.namespace)) || '').trim()
  })).filter((item) => item.bind) : [];
  const d1 = Array.isArray(tpl.d1) ? tpl.d1.map((item) => ({
    bind: String((item && (item.bind || item.key || item.name)) || '').trim(),
    name: String((item && (item.name || item.databaseName || item.database)) || '').trim()
  })).filter((item) => item.bind) : [];
  return {
    key: String(tpl.key || fallbackKey || templateName).trim(),
    templateName, sourceWorkerName, workerName,
    scriptUrl: tpl.scriptUrl ? String(tpl.scriptUrl).trim() : '',
    scriptSource: tpl.scriptSource ? String(tpl.scriptSource) : '',
    env, kv, d1
  };
}

async function ensureDefaultBatchTemplates(kv) {
  for (const item of DEFAULT_BATCH_TEMPLATES) {
    const exists = await kv.get(item.key);
    if (!exists) { await kv.put(item.key, JSON.stringify(item)); continue; }
    try {
      const parsed = JSON.parse(exists);
      const merged = sanitizeBatchTemplate(Object.assign({}, parsed, item, {
        scriptSource: parsed.scriptSource || item.scriptSource,
        scriptUrl: parsed.scriptUrl || item.scriptUrl,
        env: item.env, kv: item.kv,
        d1: Array.isArray(parsed.d1) && parsed.d1.length ? parsed.d1 : item.d1
      }), item.key);
      if (JSON.stringify(merged) !== JSON.stringify(parsed)) await kv.put(item.key, JSON.stringify(merged));
    } catch (e) { await kv.put(item.key, JSON.stringify(item)); }
  }
}

async function loadBatchTemplatesFromKV(kv) {
  const items = [];
  for (const item of DEFAULT_BATCH_TEMPLATES) {
    const raw = await kv.get(item.key);
    if (!raw) continue;
    try { items.push(sanitizeBatchTemplate(JSON.parse(raw), item.key)); }
    catch (e) { items.push(sanitizeBatchTemplate(item, item.key)); }
  }
  return items.filter((item) => item.templateName && (item.workerName || item.sourceWorkerName || item.scriptUrl || item.scriptSource));
}

// ---------------- 页面渲染 ----------------
// OAuth 授权回调页：校验 state，用 code + PKCE verifier 换 token，结果存浏览器本地
function renderOAuthCallbackHTML() {
  return '<!doctype html>\n<html>\n<head>\n<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Cloudflare 授权回调</title>\n<style>\nbody{font-family:system-ui,Arial;margin:0;background:#f6f8fa;color:#0f1724;display:flex;justify-content:center;align-items:center;min-height:100vh}\n.card{background:#fff;border-radius:12px;padding:32px;box-shadow:0 6px 18px rgba(2,6,23,0.08);max-width:420px;text-align:center}\n.err{color:#ef4444;margin-top:12px;font-size:14px}\n.ok{color:#10b981;margin-top:12px;font-size:14px}\n.spin{width:32px;height:32px;border:3px solid #e5e7eb;border-top-color:#2563eb;border-radius:50%;margin:0 auto 16px;animation:sp 0.8s linear infinite}\n@keyframes sp{to{transform:rotate(360deg)}}\n</style>\n</head>\n<body data-page="oauth-callback">\n<div class="card">\n  <div class="spin" id="cbSpin"></div>\n  <div id="cbMsg" style="font-size:15px">正在完成 Cloudflare 授权…</div>\n  <div id="cbErr" class="err"></div>\n</div>\n<script src="/static.js"></script>\n</body>\n</html>';
}

function renderLoginHTML() {
  return '<!doctype html>\n<html>\n<head>\n<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>连接您的 Cloudflare 账号</title>\n<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">\n<style>\n:root{--bg:#f6f8fa;--muted:#6b7280;--accent:#2563eb}\nbody{font-family:Inter,system-ui,Arial;margin:0;background:var(--bg);color:#0f1724}\n.container{max-width:920px;margin:32px auto;padding:24px}\n.card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 6px 18px rgba(2,6,23,0.04)}\n.h1{font-size:28px;font-weight:700;margin-bottom:6px}\n.small{color:var(--muted);margin-bottom:12px}\n.account-row{padding:12px;border-radius:8px;border:1px solid #eef2ff;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center}\n.input{padding:10px;border-radius:8px;border:1px solid #e6edf3;width:100%;box-sizing:border-box}\n.btn{padding:10px 12px;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer}\n.note{font-size:13px;color:var(--muted);margin-top:8px}\n.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);justify-content:center;align-items:center;z-index:9999}\n.modal-content{background:#fff;border-radius:12px;width:90%;max-width:520px;padding:24px}\n.modal-title{font-size:18px;font-weight:700;margin-bottom:16px}\ntextarea.input{min-height:120px;resize:vertical;font-family:monospace}\n.mode-tabs{display:flex;gap:8px;margin:12px 0}\n.mode-tab{padding:8px 14px;border-radius:8px;border:1px solid #e6edf3;background:#fff;cursor:pointer;font-size:13px}\n.mode-tab.active{background:#eff6ff;border-color:#bfdbfe;color:#1e40af;font-weight:600}\n</style>\n</head>\n<body data-page="login">\n<div class="container">\n  <div class="card">\n    <div class="h1">连接您的 Cloudflare 账号</div>\n    <div class="small">支持 API Token（推荐）与 Global API Key（旧版）两种鉴权方式</div>\n    <div style="margin:14px 0;padding:14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px">\n      <div style="font-weight:600;margin-bottom:8px">免 Token 登录</div>\n      <button class="btn" id="oauthLoginBtn" onclick="startOAuthLogin()" style="background:#f6821f">使用 Cloudflare 账号登录</button>\n      <div class="note">浏览器内完成官方 OAuth 2.0 授权，无需创建和粘贴 API Token</div>\n    </div>\n    <div style="margin-top:12px">\n      <div style="font-weight:600;margin-bottom:6px">已保存的账号</div>\n      <div id="savedAccounts">未找到已保存账号</div>\n    </div>\n    <hr style="margin:18px 0">\n    <div style="font-weight:600">添加新账号</div>\n    <div class="note">账号凭据仅存储在当前浏览器本地</div>\n    <div class="mode-tabs">\n      <div class="mode-tab active" id="tabToken" onclick="switchAuthMode(\'token\')">API Token（推荐）</div>\n      <div class="mode-tab" id="tabKey" onclick="switchAuthMode(\'key\')">Global API Key（旧版）</div>\n    </div>\n    <div id="tokenFields">\n      <div style="margin-top:8px"><label class="small">API Token</label>\n      <input id="newToken" type="password" class="input" placeholder="粘贴 API Token"></div>\n      <div style="margin-top:8px"><label class="small">备注名称（可选）</label>\n      <input id="newLabel" class="input" placeholder="例如：主账号"></div>\n      <div class="note">创建位置：Cloudflare 控制台 → 我的个人资料 → API 令牌 → 创建令牌<br>所需权限：Workers Scripts(读写)、Workers KV Storage(读写)、D1(读写)、Workers R2 Storage(读写)、Zone/DNS(读写)、Account Settings(读)、Account Analytics(读)、Cloudflare Pages(读写)</div>\n    </div>\n    <div id="keyFields" style="display:none">\n      <div style="margin-top:8px"><label class="small">Cloudflare 账号邮箱</label>\n      <input id="newEmail" class="input" placeholder="your@email.com"></div>\n      <div style="margin-top:8px"><label class="small">Global API Key</label>\n      <input id="newKey" type="password" class="input" placeholder="您的 Global API Key"></div>\n      <div class="note">右上角头像 → 我的个人资料 → API 令牌 → 下拉查看 Global API Key（旧版方案）</div>\n    </div>\n    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">\n      <button class="btn" id="verifyBtn">验证并进入管理后台</button>\n      <button class="btn" id="openBatchModalBtn" style="background:#4b5563;color:#fff">批量导入账号</button>\n      <button class="btn" id="clearBtn" style="background:#e5e7eb;color:#111">清除本地账号</button>\n    </div>\n  </div>\n</div>\n<div id="batchLoginModal" class="modal">\n  <div class="modal-content">\n    <div class="modal-title">批量添加账号</div>\n    <div class="small" id="batchLoginHint">Token 模式：每行一个，格式：备注|Token（备注可省略）</div>\n    <textarea id="batchLoginInput" class="input" placeholder="备注1|token1\ntoken2"></textarea>\n    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">\n      <button class="btn" style="background:#e5e7eb;color:#111" onclick="document.getElementById(\'batchLoginModal\').style.display=\'none\'">取消</button>\n      <button class="btn" id="confirmBatchLogin">确认导入</button>\n    </div>\n  </div>\n</div>\n<div id="pwOverlay" style="display:none;position:fixed;inset:0;background:rgba(15,23,36,0.88);z-index:99999;justify-content:center;align-items:center">\n  <div style="background:#fff;border-radius:16px;padding:36px 32px;width:90%;max-width:380px;box-shadow:0 20px 60px rgba(0,0,0,0.35)">\n    <div style="font-size:22px;font-weight:700;margin-bottom:6px">访问验证</div>\n    <div style="color:#6b7280;font-size:14px;margin-bottom:20px">请输入访问密码以继续使用管理面板</div>\n    <input id="pwInput" type="password" class="input" placeholder="请输入访问密码" style="margin-bottom:12px" onkeydown="if(event.key===\'Enter\')submitPw()">\n    <div id="pwError" style="color:#ef4444;font-size:13px;min-height:20px;margin-bottom:10px"></div>\n    <button class="btn" style="width:100%;padding:12px" onclick="submitPw()">确认进入</button>\n  </div>\n</div>\n<script src="/static-v3.js"></script>\n</body>\n</html>';
}

function renderAppHTML() {
  return '<!doctype html>\n<html>\n<head>\n<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>Cloudflare 管理平台 v2</title>\n<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">\n<style>\n:root{--bg:#f6f8fa;--card:#fff;--muted:#6b7280;--accent:#2563eb;--danger:#ef4444}\n*{box-sizing:border-box}\nbody{font-family:Inter,Arial;margin:0;background:var(--bg);color:#0f1724}\n.app{display:flex;min-height:100vh}\n.sidebar{width:240px;background:#fff;border-right:1px solid #eef2f6;padding:22px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;flex-shrink:0}\n.logo{display:flex;align-items:center;gap:10px;font-weight:700}\n.nav{margin-top:22px}\n.nav .item{display:flex;align-items:center;gap:10px;padding:10px;border-radius:8px;color:#334155;margin-bottom:6px;cursor:pointer;font-size:14px}\n.nav .item.active{background:#f8fafc;font-weight:600}\n.nav .item:hover{background:#f1f5f9}\n.main{flex:1;padding:26px;min-width:0}\n.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px}\n.metric{background:#fff;padding:20px;border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04);display:flex;flex-direction:column;gap:8px}\n.metric .bar{height:8px;background:#eef2ff;border-radius:999px;overflow:hidden}\n.metric .bar > i{display:block;height:100%;background:linear-gradient(90deg,#2563eb,#60a5fa);width:0%}\n.grid{display:grid;grid-template-columns:1fr;gap:18px}\n.card{background:var(--card);padding:18px;border-radius:12px;box-shadow:0 6px 18px rgba(2,6,23,0.04)}\n.workers-list{padding:6px}\n.worker-row{display:flex;justify-content:space-between;align-items:flex-start;padding:16px;border-radius:10px;border:1px solid #eef2ff;background:#fbfdff;margin-bottom:12px;gap:12px;flex-wrap:wrap}\n.worker-info{flex:1;min-width:260px}\n.worker-right{display:flex;flex-direction:column;align-items:flex-end;gap:10px}\n.worker-tags{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:6px;margin-bottom:4px}\n.worker-meta{color:var(--muted);font-size:13px}\n.btns{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}\n.btn{padding:8px 10px;border-radius:8px;border:1px solid #e6eef9;background:#fff;cursor:pointer;font-size:12px}\n.btn.primary{background:var(--accent);color:#fff;border:0}\n.btn.danger{background:#ef4444;color:#fff;border:0}\n.btn.success{background:#10b981;color:#fff;border:0}\n.btn.small{font-size:11px;padding:4px 8px}\n.btn:disabled{opacity:.5;cursor:not-allowed}\n.small{font-size:13px;color:var(--muted)}\n.modal{display:none;position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,0.45);align-items:center;justify-content:center;z-index:1000}\n.modal-box{width:720px;max-width:94vw;background:#fff;border-radius:12px;padding:20px;max-height:90vh;overflow:auto}\n.modal-box.small{width:480px}\n.input{width:100%;padding:10px;border-radius:8px;border:1px solid #e6edf3}\ntextarea.input{font-family:monospace}\n.kv-item{padding:8px;border-radius:8px;border:1px solid #f1f5f9;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;gap:8px}\npre{background:#0b1220;color:#e6f2ff;padding:12px;border-radius:8px;overflow:auto}\n.label{font-size:12px;color:#64748b;margin-bottom:6px}\n.switch{position:relative;display:inline-block;width:34px;height:18px;flex-shrink:0}\n.switch input{opacity:0;width:0;height:0}\n.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background-color:#ccc;transition:.4s;border-radius:24px}\n.slider:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background-color:white;transition:.4s;border-radius:50%}\ninput:checked + .slider{background-color:#2563eb}\ninput:checked + .slider:before{transform:translateX(16px)}\n.page-content{display:none}\n.page-content.active{display:block}.r2-tab{padding:10px 16px;border:0;background:none;cursor:pointer;font-size:14px;color:#64748b;border-bottom:2px solid transparent;margin-bottom:-1px}.r2-tab.active{color:#0f1724;font-weight:600;border-bottom-color:#2563eb}.r2-stat{padding:4px 0}.r2-stat .k{font-size:12px;color:#64748b}.r2-stat .v{font-size:14px;font-weight:600;margin-top:2px;word-break:break-all}.r2-objrow:hover{background:#f8fafc}\n.table{width:100%;border-collapse:collapse;margin-top:12px}\n.table th,.table td{padding:12px;text-align:left;border-bottom:1px solid #eef2f6;font-size:13px}\n.table th{background:#f8fafc;font-weight:600}\n.sql-console{background:#0f172a;color:#e2e8f0;padding:16px;border-radius:8px;margin-top:12px}\n.sql-console textarea{width:100%;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:12px;font-family:monospace;min-height:120px}\n.sql-results{margin-top:12px;background:#1e293b;padding:12px;border-radius:6px;max-height:320px;overflow:auto}\n.domain-tag{display:inline-block;padding:4px 8px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;margin-right:6px;margin-bottom:4px;text-decoration:none;color:#334155}\n.domain-tag:hover{background:#f1f5f9}\n.domain-tag.workers-dev{background:#eff6ff;border-color:#dbeafe}\n.domain-status{font-size:11px;padding:2px 6px;border-radius:4px;margin-left:6px}\n.domain-status.active{background:#f0fdf4;color:#166534}\n.domain-status.inactive{background:#fef2f2;color:#dc2626}\n.domain-status.pending{background:#fffbeb;color:#d97706}\n.del-domain-btn{display:inline-block;margin-left:4px;width:16px;height:16px;line-height:16px;text-align:center;border-radius:50%;background:#fee2e2;color:#ef4444;font-size:10px;cursor:pointer}\n.del-domain-btn:hover{background:#fecaca}\n.res-tag{font-size:11px;padding:2px 8px;border-radius:6px;border:1px solid transparent;display:inline-flex;align-items:center;font-weight:500}\n.res-tag.kv{background:#eff6ff;color:#1e40af;border-color:#bfdbfe}\n.res-tag.d1{background:#fff7ed;color:#9a3412;border-color:#fed7aa}\n.res-tag.env{background:#f0fdf4;color:#166534;border-color:#bbf7d0}\n.res-tag.r2{background:#faf5ff;color:#6b21a8;border-color:#e9d5ff}\n.res-tag.cron{background:#fefce8;color:#854d0e;border-color:#fde68a}\n.res-tag.secret{background:#fef2f2;color:#991b1b;border-color:#fecaca}\n.worker-tag-rows{display:flex;flex-direction:column;gap:6px;margin-bottom:6px;align-items:flex-end;max-width:100%}\n.tag-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;justify-content:flex-end;max-width:100%}\n.tag-row-label{font-size:11px;color:#64748b;font-weight:600;min-width:56px;text-align:right;flex-shrink:0}\n.tag-row.left{justify-content:flex-start}\n.tag-row.left .tag-row-label{text-align:left;min-width:0}\n.count{display:inline-block;background:#eef2ff;color:#2563eb;font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;margin-left:4px}\n.tag-row .res-tag{margin:0}\n.batch-layout{display:flex;gap:20px}\n.batch-sidebar{width:300px;flex-shrink:0;border-right:1px solid #eef2f6;overflow-y:auto;padding-right:16px;max-height:calc(100vh - 160px)}\n.batch-main{flex:1;min-width:0}\n.account-check-item{display:flex;align-items:center;padding:8px;border-bottom:1px solid #eef2f6}\n.account-check-item:hover{background:#f8fafc}\n.log-area{background:#1e293b;color:#10b981;padding:12px;border-radius:8px;font-family:monospace;font-size:12px;margin-top:16px;min-height:150px;max-height:300px;overflow-y:auto;white-space:pre-wrap}\n.env-row-batch{display:flex;gap:10px;margin-top:10px;padding:10px;border:1px solid #eef2f6;border-radius:8px;background:#fbfdff;align-items:center}\n.acct-row{padding:10px;border-bottom:1px solid #eef2f6;display:flex;justify-content:space-between;align-items:center}\n.acct-active{background:#eff6ff}\n.badge{background:#dbeafe;color:#1e40af;font-size:10px;padding:2px 6px;border-radius:4px;margin-left:6px}\n.trash-btn{background:none;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;color:#ef4444;padding:6px 12px;font-size:11px;display:inline-flex;align-items:center;gap:4px}\n.trash-btn:hover{background:#fef2f2}\n.ns-pill{display:inline-flex;align-items:center;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:2px 6px;font-family:monospace;font-size:11px;color:#334155;margin-right:6px;margin-bottom:4px}\n.copy-btn{background:#f1f5f9;border:1px solid #e2e8f0;padding:4px 8px;border-radius:4px;font-size:11px;cursor:pointer;margin-left:4px}\n.copy-btn:hover{background:#e2e8f0}\n.tabs{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}\n.tab{padding:8px 14px;border-radius:8px;border:1px solid #e6edf3;background:#fff;cursor:pointer;font-size:13px}\n.tab.active{background:#eff6ff;border-color:#bfdbfe;color:#1e40af;font-weight:600}\n.pill{font-size:11px;padding:2px 8px;border-radius:999px;background:#f1f5f9;color:#475569}\n.pill.green{background:#f0fdf4;color:#166534}\n.pill.red{background:#fef2f2;color:#dc2626}\n.pill.amber{background:#fffbeb;color:#d97706}\n.pill.blue{background:#eff6ff;color:#1e40af}\n</style>\n</head>\n<body data-page="app">\n<div class="app">\n  <aside class="sidebar">\n    <div class="logo"><span style="font-size:18px">CF</span> 管理平台 <span class="pill blue">v2</span></div>\n    <nav class="nav">\n      <div class="item active" data-page="workers" onclick="navTo(\'workers\')">Workers</div>\n      <div class="item" data-page="pages" onclick="navTo(\'pages\')">Pages</div>\n      <div class="item" data-page="batch" onclick="navTo(\'batch\')">批量创建 Worker/Pages</div>\n      <div class="item" data-page="kv" onclick="navTo(\'kv\')">Workers KV</div>\n      <div class="item" data-page="d1" onclick="navTo(\'d1\')">D1 数据库</div>\n      <div class="item" data-page="r2" onclick="navTo(\'r2\')">R2 存储</div>\n      <div class="item" data-page="dns" onclick="navTo(\'dns\')">域名管理</div>\n      \n      <div class="item" data-page="settings" onclick="navTo(\'settings\')">设置</div>\n    </nav>\n    <div style="margin-top:auto;padding-top:20px;border-top:1px solid #eef2f6">\n       <div class="small" style="margin-bottom:4px">当前账号 <span id="authModeBadge" class="pill"></span></div>\n       <div style="font-weight:600;font-size:13px;word-break:break-all;cursor:pointer" id="acctInfo" onclick="openAccountSwitcher()" title="切换账号">未登录</div>\n       <div style="margin-top:8px;font-size:11px;color:var(--muted);display:flex;justify-content:space-between">\n         <span onclick="openAccountSwitcher()" style="cursor:pointer;text-decoration:underline">切换</span>\n         <span onclick="logout()" style="cursor:pointer;color:#ef4444">退出</span>\n       </div>\n    </div>\n  </aside>\n  <main class="main">\n    <div id="workers-page" class="page-content active">\n      <div class="header"><div style="font-size:20px;font-weight:700">Workers 管理</div><div><button class="btn primary" onclick="openQuickDeploy()">新建 Worker</button></div></div>\n      <div class="metric"><div class="small">今天的请求（UTC）</div>\n        <div style="font-size:28px;font-weight:700" id="metricCount">- / 100,000</div>\n        <div class="bar"><i id="metricBar"></i></div>\n        <div class="small" id="metricSub">加载中...</div>\n      </div>\n      <div class="card" style="margin-top:16px"><h2 style="margin:0">Workers 列表</h2><div class="small">查看和管理您的 Cloudflare Workers</div><div class="workers-list" id="workersList" style="margin-top:12px"></div></div>\n    </div>\n    <div id="batch-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">批量创建</div></div>\n      <div class="tabs" style="margin-bottom:16px">\n        <div class="tab active" data-batchtab="worker" onclick="switchBatchTab(\'worker\')">批量创建 Worker</div>\n        <div class="tab" data-batchtab="pages" onclick="switchBatchTab(\'pages\')">批量创建 Pages</div>\n      </div>\n      <div id="batchWorkerPane">\n      <div class="batch-layout">\n        <div class="batch-sidebar">\n          <div style="padding-bottom:10px;border-bottom:1px solid #eef2f6;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">\n            <span style="font-weight:600">选择账号</span>\n            <label style="font-size:12px;cursor:pointer"><input type="checkbox" id="selectAllAccounts" onchange="toggleSelectAllAccounts(this)"> 全选</label>\n          </div>\n          <div id="batchAccountList"></div>\n        </div>\n        <div class="batch-main">\n          <div class="card"><div style="font-weight:600;margin-bottom:12px">基本配置</div>\n            <label class="small">Worker 名称</label><input id="batchWorkerName" class="input" placeholder="例如: my-proxy-worker">\n            <div style="margin-top:12px"><label class="small" style="display:flex;align-items:center;cursor:pointer"><input type="checkbox" id="batchEnableSubdomain" checked style="margin-right:8px"> 开启默认域名 (*.workers.dev)</label></div>\n            <label class="small" style="display:block;margin-top:12px">代码来源</label>\n            <select id="batchScriptSourceType" class="input" onchange="toggleBatchSourceInput()">\n              <option value="builtin">内置模板 (KV 配置)</option><option value="url">远程链接 (URL)</option><option value="custom">自定义脚本 (本地编辑)</option>\n            </select>\n            <div id="batchSourceBuiltinDiv" style="margin-top:8px"><select id="batchBuiltinSelect" class="input"><option value="">正在加载 KV 模板...</option></select>\n              <div class="note small" style="margin-top:4px">模板从 <code>CF_ACCOUNTS_KV</code> 读取</div></div>\n            <div id="batchSourceUrlDiv" style="margin-top:8px;display:none">\n              <div style="display:flex;gap:8px;align-items:center"><input id="batchScriptUrl" class="input" placeholder="https://github.com/user/repo 或 raw链接" oninput="normalizeGithubUrl(this)">\n              <button class="btn" style="white-space:nowrap;background:#0ea5e9;color:#fff;flex-shrink:0" onclick="prepareBatchScriptUrl()">处理链接</button></div>\n              <div class="note small" style="margin-top:4px">支持粘贴 GitHub 项目地址，自动查找 _worker.js 并转 raw 链接</div><div id="urlConvertHint" style="font-size:12px;color:#10b981;margin-top:4px;display:none"></div>\n            </div>\n            <div id="batchSourceCustomDiv" style="margin-top:8px;display:none">\n              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><span style="font-size:13px;font-weight:600;color:#374151">自定义脚本编辑器</span>\n              <button class="btn small" style="background:#10b981;color:#fff" onclick="saveCustomScriptFile()">下载 _worker.js</button></div>\n              <textarea id="batchCustomScript" class="input" rows="14" style="font-size:12px;min-height:280px;resize:vertical" placeholder="// 在此编写或粘贴 Worker 脚本"></textarea>\n              <div style="font-size:11px;color:#9ca3af;margin-top:4px">脚本自动保存到 localStorage</div>\n            </div>\n          </div>\n          <div class="card" style="margin-top:16px"><div style="font-weight:600;margin-bottom:12px">高级绑定配置</div>\n            <div style="margin-bottom:16px"><div style="font-size:13px;font-weight:600;margin-bottom:4px;color:#374151">环境变量 (ENV)</div><div id="batchEnvList"></div>\n              <button class="btn small" style="margin-top:6px" onclick="addBatchEnvRow()">+ 添加变量</button></div>\n            <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">\n              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-size:13px;font-weight:600;color:#374151">KV 命名空间 (自动查找或创建)</div><button class="btn small" onclick="addBatchKvRow()">+ 添加</button></div>\n              <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">下拉选择已有命名空间；没有想要的就输入新名称，会自动创建</div><div id="batchKvList"></div></div>\n            <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">\n              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-size:13px;font-weight:600;color:#374151">D1 数据库 (自动查找或创建)</div><button class="btn small" onclick="addBatchD1Row()">+ 添加</button></div>\n              <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">下拉选择已有数据库；没有想要的就输入新名称，会自动创建</div><div id="batchD1List"></div></div>\n            <button class="btn primary" style="margin-top:10px;width:100%" onclick="startBatchCreate()">开始批量创建</button>\n          </div>\n          <div style="font-weight:600;margin-top:16px">执行日志</div><div id="batchLog" class="log-area">等待开始...</div>\n        </div>\n      </div>\n      </div>\n      <div id="batchPagesPane" style="display:none">\n      <div class="batch-layout">\n        <div class="batch-sidebar">\n          <div style="padding-bottom:10px;border-bottom:1px solid #eef2f6;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">\n            <span style="font-weight:600">选择账号</span>\n            <label style="font-size:12px;cursor:pointer"><input type="checkbox" id="selectAllPagesAccounts" onchange="toggleSelectAllPagesAccounts(this)"> 全选</label>\n          </div>\n          <div id="batchPagesAccountList"></div>\n        </div>\n        <div class="batch-main">\n          <div class="card"><div style="font-weight:600;margin-bottom:12px">基本配置</div>\n            <label class="small">项目名</label><input id="batchPagesName" class="input" placeholder="例如: my-site">\n            <div class="small" style="margin-top:4px">仅小写字母、数字、连字符；同名项目会自动转为更新</div>\n            <label class="small" style="display:block;margin-top:12px">代码来源</label>\n            <div style="display:flex;gap:18px;margin-top:6px;font-size:13px">\n              <label style="cursor:pointer"><input type="radio" name="batchPagesSrc" value="url" checked onchange="toggleBatchPagesSrc()"> 直链</label>\n              <label style="cursor:pointer"><input type="radio" name="batchPagesSrc" value="file" onchange="toggleBatchPagesSrc()"> 上传</label>\n            </div>\n            <div id="batchPagesUrlDiv" style="margin-top:8px"><input id="batchPagesUrl" class="input" placeholder=".zip 直链"></div>\n            <div id="batchPagesFileDiv" style="margin-top:8px;display:none"><input type="file" id="batchPagesFiles" multiple class="input"><div class="small" style="margin-top:4px">可多选文件；单个 .zip 包会自动解包</div></div>\n            <label class="small" style="display:block;margin-top:12px">分支</label>\n            <input id="batchPagesBranch" class="input" placeholder="main" style="max-width:200px">\n          </div>\n          <div class="card" style="margin-top:16px"><div style="font-weight:600;margin-bottom:12px">高级绑定配置</div>\n            <div style="margin-bottom:16px"><div style="font-size:13px;font-weight:600;margin-bottom:4px;color:#374151">环境变量 (ENV)</div><div id="batchPagesEnvList"></div>\n              <button class="btn small" style="margin-top:6px" onclick="addBatchPagesEnvRow()">+ 添加变量</button></div>\n            <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">\n              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-size:13px;font-weight:600;color:#374151">KV 命名空间 (自动查找或创建)</div><button class="btn small" onclick="addBatchPagesKvRow()">+ 添加</button></div>\n              <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">下拉选择已有命名空间；没有想要的就输入新名称，会自动创建</div><div id="batchPagesKvList"></div></div>\n            <div style="margin-bottom:16px;border-top:1px solid #eee;padding-top:10px">\n              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px"><div style="font-size:13px;font-weight:600;color:#374151">D1 数据库 (自动查找或创建)</div><button class="btn small" onclick="addBatchPagesD1Row()">+ 添加</button></div>\n              <div style="font-size:11px;color:#9ca3af;margin-bottom:6px">下拉选择已有数据库；没有想要的就输入新名称，会自动创建</div><div id="batchPagesD1List"></div></div>\n            <button class="btn primary" style="margin-top:10px;width:100%" onclick="startBatchPagesCreate()">开始批量创建</button>\n          </div>\n          <div style="font-weight:600;margin-top:16px">执行日志</div><div id="batchPagesLog" class="log-area">等待开始...</div>\n        </div>\n      </div>\n      </div>\n    </div>\n    <div id="kv-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">Workers KV 管理</div><div style="display:flex;gap:8px"><button class="btn" onclick="openKvBulkWrite()">批量写入</button><button class="btn primary" onclick="openCreateKVNamespace()">创建命名空间</button></div></div>\n      <div class="card"><h3 style="margin:0">KV 命名空间列表</h3><div class="small" style="margin-top:8px">管理您的 Workers KV 命名空间</div><div id="kvNamespacesList" style="margin-top:16px"></div></div>\n      <div id="kvKeysSection" class="card" style="margin-top:16px;display:none">\n        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><div><h3 style="margin:0" id="kvKeysTitle">键值管理</h3><div class="small" id="kvKeysSub"></div></div>\n        <div style="display:flex;gap:8px"><button class="btn" onclick="backToKvNamespaces()">返回列表</button><button class="btn" onclick="openKvBulkDelete()">批量删除</button><button class="btn primary" onclick="openKvValueModal()">添加键值</button></div></div>\n        <div style="display:flex;gap:8px;margin-top:12px"><input id="kvKeyPrefix" class="input" placeholder="按前缀筛选" style="max-width:280px"><button class="btn" onclick="refreshKvKeys(true)">筛选</button></div>\n        <div id="kvKeysList" style="margin-top:12px"></div>\n        <div style="margin-top:8px;display:flex;gap:8px;align-items:center"><button class="btn small" id="kvNextPageBtn" onclick="kvNextPage()" style="display:none">下一页</button><span class="small" id="kvPageInfo"></span></div>\n      </div>\n    </div>\n    <div id="d1-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">D1 数据库管理</div><div><button class="btn primary" onclick="openCreateD1Database()">创建数据库</button></div></div>\n      <div class="card"><h3 style="margin:0">D1 SQL 数据库</h3><div class="small" style="margin-top:8px">管理您的 Cloudflare D1 数据库实例</div><div id="d1DatabasesList" style="margin-top:16px"></div></div>\n      <div class="card" style="margin-top:16px"><h4 style="margin:0">SQL 控制台</h4><div class="small" style="margin-top:8px">支持参数化查询（params），用 ? 占位</div>\n        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap"><select id="d1DatabaseSelect" class="input" style="max-width:320px"><option value="">- 选择数据库 -</option></select>\n        <button class="btn" onclick="d1ShowTables()">查看表结构</button><button class="btn" onclick="openD1Export()">导出备份</button></div>\n        <div class="sql-console"><textarea id="d1Query" placeholder="SELECT * FROM users WHERE id = ? LIMIT 10;"></textarea>\n        <input id="d1Params" class="input" placeholder=\'参数 JSON 数组，可选，例如：[1, "abc"]\' style="margin-top:8px;background:#1e293b;color:#e2e8f0;border-color:#334155">\n        <div style="display:flex;gap:8px;margin-top:8px"><button class="btn primary" onclick="executeD1Query()">执行查询</button><button class="btn" onclick="executeD1Raw()" style="background:#334155;color:#fff">Raw 模式（大结果集）</button></div></div>\n        <div id="d1QueryResults" class="sql-results" style="display:none"></div>\n      </div>\n    </div>\n    <div id="r2-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">R2 对象存储</div><div style="display:flex;gap:8px;align-items:center"><select id="r2Jurisdiction" class="input" style="width:auto" onchange="refreshR2Buckets()"><option value="default">辖区：默认</option><option value="eu">EU</option><option value="us">US</option><option value="fedramp">FedRAMP</option></select><button class="btn primary" onclick="openCreateR2Bucket()">创建存储桶</button></div></div>\n      <div class="card" id="r2ListCard"><h3 style="margin:0">存储桶列表</h3><div class="small" style="margin-top:8px">点击「管理」进入存储桶，可上传/下载文件、查看指标与设置</div><div id="r2BucketsList" style="margin-top:16px"></div></div><div class="card" id="r2DetailCard" style="display:none;margin-top:16px"><div style="display:flex;align-items:center;gap:10px;margin-bottom:4px"><button class="btn small" onclick="closeR2Detail()">← 返回</button><span class="small"><a href="javascript:void(0)" onclick="closeR2Detail()" style="color:#2563eb;text-decoration:none">R2 对象存储</a> &gt; <b id="r2DetailName"></b></span></div><div style="display:flex;gap:4px;border-bottom:1px solid #eef2f6;margin:12px 0 16px"><button class="r2-tab" data-tab="objects" onclick="switchR2Tab(\'objects\')">对象</button><button class="r2-tab" data-tab="metrics" onclick="switchR2Tab(\'metrics\')">指标</button><button class="r2-tab" data-tab="settings" onclick="switchR2Tab(\'settings\')">设置</button></div><div id="r2TabObjects"></div><div id="r2TabMetrics" style="display:none"></div><div id="r2TabSettings" style="display:none"></div></div>\n    </div>\n    <div id="dns-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">域名管理</div><div><button class="btn primary" onclick="openAddZone()">添加新域名</button></div></div>\n      <div class="card"><h3 style="margin:0">域名列表</h3><div class="small" style="margin-top:8px">管理您的 Cloudflare 域名</div><div id="zonesList" style="margin-top:16px"></div></div>\n      <div id="dnsRecordsSection" class="card" style="margin-top:16px;display:none">\n        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">\n          <div><h3 style="margin:0" id="selectedZoneName">域名 DNS 记录</h3><div class="small" id="selectedZoneInfo"></div></div>\n          <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" onclick="openDnsBatchImport()">批量导入</button><button class="btn primary" onclick="openAddDNSRecord()">添加 DNS 记录</button><button class="btn" onclick="backToZones()">返回域名列表</button></div>\n        </div>\n        <div id="dnsRecordsList"></div>\n      </div>\n    </div>\n    <div id="pages-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">Pages 管理</div><div><button class="btn primary" onclick="openCreatePagesProject()">创建项目</button></div></div>\n      <div class="card"><h3 style="margin:0">Pages 项目</h3><div class="small" style="margin-top:8px">管理您的 Cloudflare Pages 项目与部署</div><div id="pagesProjectsList" style="margin-top:16px"></div></div>\n      <div id="pagesDeploySection" class="card" style="margin-top:16px;display:none">\n        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:8px">\n          <div><h3 style="margin:0" id="pagesProjectName">部署记录</h3><div class="small" id="pagesProjectInfo"></div></div>\n          <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn" onclick="openPagesDomains()">自定义域名</button><button class=\"btn\" onclick=\"openPagesBindModal()\">环境/KV/D1</button><button class="btn" onclick="openPagesCompatModal()">兼容日期</button><button class="btn" onclick="openPagesCompatFlagsModal()">兼容标志</button><button class="btn primary" onclick="triggerPagesDeploy()">触发部署</button><button class="btn" onclick="backToPagesProjects()">返回项目列表</button></div>\n        </div>\n        <div class=\"card\" style=\"margin-bottom:16px\"><h4 style=\"margin:0 0 12px\">项目概览</h4><div id=\"pagesProjectOverview\"><div class=\"small\">加载中...</div></div></div><div class=\"card\" style=\"margin-bottom:16px\"><h4 style=\"margin:0 0 12px\">部署新版本</h4><div class=\"tabs\"><div class=\"tab active\" data-ptab=\"upload\" onclick=\"switchPagesDeployTab(\'upload\')\">文件上传</div><div class=\"tab\" data-ptab=\"github\" onclick=\"switchPagesDeployTab(\'github\')\">GitHub 导入</div></div><div id=\"pdeploy-upload\"><div class=\"label\">选择文件（可多选）或整个文件夹 <span class=\"small\">（最多2000个文件，单文件≤25MB，总计≤100MB）</span></div><div style=\"display:flex;gap:8px;flex-wrap:wrap\"><label class=\"btn\" style=\"cursor:pointer\">选择文件<input type=\"file\" id=\"pagesUploadFiles\" multiple onchange=\"refreshPagesUploadList()\" style=\"display:none\"></label><label class=\"btn\" style=\"cursor:pointer\">选择文件夹<input type=\"file\" id=\"pagesUploadDir\" webkitdirectory onchange=\"refreshPagesUploadList()\" style=\"display:none\"></label><button class=\"btn\" onclick=\"clearPagesUpload()\">清空</button></div><div id=\"pagesUploadList\" class=\"small\" style=\"margin-top:8px\"></div><div style=\"display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap\"><input id=\"pagesUploadBranch\" class=\"input\" placeholder=\"分支（默认 main）\" style=\"max-width:200px\"><button class=\"btn primary\" id=\"pagesUploadBtn\" onclick=\"startPagesUpload()\">上传并部署</button></div></div><div id=\"pdeploy-github\" style=\"display:none\"><div class=\"label\">GitHub 仓库地址</div><input id=\"pagesGithubUrl\" class=\"input\" placeholder=\"https://github.com/owner/repo\"><div class=\"label\" style=\"margin-top:12px\">分支（留空则用仓库默认分支）</div><input id=\"pagesGithubBranch\" class=\"input\" placeholder=\"main\" style=\"max-width:200px\"><div style=\"margin-top:12px\"><button class=\"btn primary\" id=\"pagesGithubBtn\" onclick=\"startPagesGithubDeploy()\">导入并部署</button></div><div class=\"small\" style=\"margin-top:8px\">将下载仓库 ZIP 包并直接部署到 Pages（公开仓库）</div></div><div id=\"pagesDeployStatus\" class=\"small\" style=\"margin-top:12px\"></div></div>\n<div id="pagesDeployList"></div>\n      </div>\n    </div>\n    <div id="settings-page" class="page-content">\n      <div class="header"><div style="font-size:20px;font-weight:700">设置</div></div>\n      <div class="card"><h3 style="margin:0">Workers 域名设置</h3><div class="small" style="margin-top:8px">设置您的 workers.dev 子域名（每个账号仅可设置一次）</div>\n        <div class="small" style="margin-top:8px">当前子域名：<span id="currentSubdomain" style="font-weight:600;color:#1e40af">加载中...</span></div>\n        <div style="margin-top:12px;display:flex;gap:8px"><input id="newSubdomain" class="input" placeholder="输入子域名" style="max-width:320px"><button id="saveSubdomainBtn" class="btn primary" onclick="saveSubdomain()">保存设置</button></div>\n        <div id="subdomainHint" class="small" style="margin-top:8px">设置后，您的 Workers 将通过 https://worker-name.your-subdomain.workers.dev 访问</div></div>\n      <div class="card" style="margin-top:16px"><h3 style="margin:0">当前鉴权方式</h3><div class="small" style="margin-top:8px" id="authModeInfo"></div>\n        <div class="small" style="margin-top:8px">建议使用 API Token 并按最小权限配置；Global API Key 为旧版方案，拥有账号全部权限，请妥善保管。</div></div>\n      <div class="card" style="margin-top:16px"><h3 style="margin:0">OAuth 登录配置</h3>\n        <div class="small" style="margin-top:8px">在 Cloudflare 控制台 → 管理账号 → OAuth 客户端 创建客户端后，将 Client ID 填在这里（Client ID 是公开标识，可放心填写）。回调地址固定为：<span style="font-family:monospace" id="oauthCbUrl"></span></div>\n        <div style="margin-top:12px;display:flex;gap:8px"><input id="oauthClientIdInput" class="input" placeholder="OAuth Client ID" style="max-width:360px"><button class="btn primary" onclick="saveOAuthClientId()">保存</button></div>\n        <div class="small" style="margin-top:8px" id="oauthClientIdHint"></div></div>\n      <div class="card" style="margin-top:16px"><h3 style="margin:0">关于与反馈</h3>\n        <div class="small" style="margin-top:8px">Cloudflare 第三方管理面板 v2 · 基于最新 Cloudflare API 构建</div>\n        <div style="margin-top:8px"><a href="https://t.me/yifang_chat" target="_blank" style="color:#2563eb">问题反馈 / 加入交流群</a></div></div>\n    </div>\n  </main>\n</div>\n'
  + '<!-- Modals -->'
  +  '<div id="accountModal" class="modal"><div class="modal-box small">\n    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px"><h3 style="margin:0">切换账号</h3><button class="trash-btn" onclick="closeAccountSwitcher()">✕</button></div>\n    <div id="accountListContainer"></div></div></div>'
  +  '<div id="envModal" class="modal"><div class="modal-box">\n    <h3>管理环境变量</h3><div class="label">为 Worker 配置环境变量（文本 / 密钥 / JSON）</div>\n    <div id="envRows" style="margin-top:8px"></div>\n    <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap"><button class="btn primary" onclick="addEnvRow()">添加变量</button><button class="btn" onclick="saveEnv()">保存</button><button class="btn" onclick="closeEnvModal()">取消</button></div></div></div>'
  +  '<div id="bindModal" class="modal"><div class="modal-box">\n    <h3>绑定资源</h3><div class="label">选择要绑定的资源</div>\n    <div style="display:flex;gap:8px;margin-top:8px"><select id="bindType" class="input" onchange="refreshBindList()"><option value="kv">KV 命名空间</option><option value="d1">D1 数据库</option><option value="r2">R2 存储桶</option></select></div>\n    <div style="margin-top:8px"><select id="bindSelect" class="input"></select></div>\n    <div style="margin-top:8px"><input id="bindName" class="input" placeholder="绑定变量名，例如 MY_KV"></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmBind()">确认绑定</button><button class="btn" onclick="closeBindModal()">取消</button></div></div></div>'
  +  '<div id="createModal" class="modal"><div class="modal-box">\n    <h3>新建 / 编辑 Worker</h3><div class="label">Worker 名称</div><input id="createName" class="input" placeholder="worker-name">\n    <div class="label" style="margin-top:8px">脚本 (.js)</div>\n    <textarea id="createScript" class="input" rows="20" style="min-height:420px;font-size:13px;resize:vertical"></textarea>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreate()">保存并部署</button><button class="btn" onclick="closeCreate()">取消</button></div></div></div>'
  +  '<div id="versionsModal" class="modal"><div class="modal-box">\n    <h3>版本历史 <span class="pill blue">Versions API (Beta)</span></h3><div class="small" id="versionsSub"></div>\n    <div id="versionsList" style="margin-top:12px"></div>\n    <div style="display:flex;justify-content:flex-end;margin-top:8px"><button class="btn" onclick="closeVersionsModal()">关闭</button></div></div></div>'
  +  '<div id="compatModal" class="modal"><div class="modal-box" style="width:560px">\n'  +  '    <h3 style="margin:0 0 4px">\u517c\u5bb9\u65e5\u671f</h3>\n'  +  '    <div class="small" style="margin-bottom:12px">\u6307\u5b9a\u4e00\u4e2a\u65e5\u671f\uff0c\u5411\u540e\u4e0d\u517c\u5bb9\u7684\u8fd0\u884c\u65f6\u66f4\u6539\u5728\u8be5\u65e5\u671f\u4e4b\u540e\u4e0d\u4f1a\u5f71\u54cd\u60a8\u7684 Worker\u3002<span id="compatCurrentVal" style="font-weight:600;color:#1e40af"></span></div>\n'  +  '    <div id="compatDateList" style="max-height:420px;overflow-y:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>\n'  +  '    <div style="display:flex;gap:8px;margin-top:12px;align-items:center"><input id="compatDateInput" type="date" class="input" style="max-width:200px" onchange="selectCompatDate(this.value)"><span class="small">\u6216\u76f4\u63a5\u9009\u62e9\u65e5\u671f</span></div>\n'  +  '    <div style="display:flex;justify-content:space-between;margin-top:16px"><button class="btn" onclick="closeCompatModal()">\u53d6\u6d88</button><button class="btn primary" onclick="confirmCompatDate()">\u9009\u62e9</button></div></div></div>\n'
  +  '<div id="compatFlagsModal" class="modal"><div class="modal-box" style="width:560px;position:relative">\n    <span data-close-modal onclick="closeCompatFlagsModal()" style="position:absolute;top:12px;right:16px;font-size:20px;cursor:pointer;color:#9ca3af" title="\u5173\u95ed">&times;</span>\n    <h3 style="margin:0 0 4px">\u517c\u5bb9\u6027\u6807\u5fd7</h3>\n    <div class="small" style="margin-bottom:12px">\u9009\u62e9\u8981\u542f\u7528\u7684\u517c\u5bb9\u6027\u6807\u5fd7\uff0c\u4fdd\u5b58\u540e\u7acb\u5373\u751f\u6548\u3002<span id="compatFlagsCurrent" style="font-weight:600;color:#1e40af"></span></div>\n    <div id="compatFlagsList" style="max-height:380px;overflow-y:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>\n    <div style="display:flex;gap:8px;margin-top:12px;align-items:center"><input id="compatFlagsCustom" class="input" placeholder="\u81ea\u5b9a\u4e49\u6807\u5fd7\uff0c\u4f8b\u5982 my_flag" style="flex:1"><button class="btn" onclick="addCustomCompatFlag()">\u6dfb\u52a0</button></div>\n    <div style="display:flex;justify-content:space-between;margin-top:16px"><button class="btn" onclick="closeCompatFlagsModal()">\u53d6\u6d88</button><button class="btn primary" onclick="confirmCompatFlags()">\u4fdd\u5b58</button></div></div></div>\n'  +  '<div id="cronModal" class="modal"><div class="modal-box" style="width:560px">\n'  +  '    <h3 style="margin:0 0 4px">Cron \u89e6\u53d1\u5668 <span class="pill blue" id="cronWorkerName"></span></h3>\n'  +  '    <div class="small" style="margin-bottom:12px">\u6309\u7167\u57fa\u4e8e\u65f6\u95f4\u7684\u5b9a\u671f\u8ba1\u5212\u6267\u884c Worker\u3002\u9700\u8981 scheduled() \u4e8b\u4ef6\u5904\u7406\u7a0b\u5e8f\u3002</div>\n'  +  '    <div class="label">\u5f53\u524d\u89e6\u53d1\u5668</div><div id="cronList" style="margin-bottom:12px"></div>\n'  +  '    <div class="tabs"><div class="tab active" data-crontab="schedule" onclick="switchCronTab(\'schedule\')">\u8ba1\u5212</div><div class="tab" data-crontab="expr" onclick="switchCronTab(\'expr\')">Cron \u8868\u8fbe\u5f0f</div></div>\n'  +  '    <div id="cron-schedule"><div class="label">\u6267\u884c Worker \u7684\u9891\u7387</div>\n'  +  '    <select id="cronFreq" class="input" onchange="updateCronPreview()"><option value="minutes">\u5206\u949f</option><option value="hours">\u5c0f\u65f6</option><option value="days">\u5929</option><option value="weeks">\u5468</option><option value="months">\u6708</option></select>\n'  +  '    <input id="cronFreqVal" class="input" type="number" min="1" value="30" style="margin-top:8px" oninput="updateCronPreview()" placeholder="\u95f4\u9694\u503c">\n'  +  '    <div id="cronWeekDay" style="display:none;margin-top:8px"><select id="cronWeekDaySel" class="input" onchange="updateCronPreview()"><option value="1">\u5468\u4e00</option><option value="2">\u5468\u4e8c</option><option value="3">\u5468\u4e09</option><option value="4">\u5468\u56db</option><option value="5">\u5468\u4e94</option><option value="6">\u5468\u516d</option><option value="0">\u5468\u65e5</option></select></div></div>\n'  +  '    <div id="cron-expr" style="display:none"><div class="label">Cron \u8868\u8fbe\u5f0f (UTC)</div><input id="cronExprInput" class="input" placeholder="*/30 * * * *" oninput="updateCronPreview()"><div class="small" style="margin-top:4px">\u683c\u5f0f: \u5206 \u65f6 \u65e5 \u6708 \u5468</div></div>\n'  +  '    <div style="background:#eff6ff;border-radius:8px;padding:12px;margin-top:12px"><div class="small" style="font-weight:600;margin-bottom:8px">\u5373\u5c06\u53d1\u751f\u7684\u4e8b\u4ef6\u4f30\u8ba1\u65f6\u95f4 (UTC)</div><div id="cronPreview" class="small"></div><div class="small" style="margin-top:8px">Cron: <code id="cronPreviewExpr" style="font-weight:600"></code></div></div>\n'  +  '    <div style="display:flex;justify-content:space-between;margin-top:16px"><button class="btn" onclick="closeCronModal()">\u53d6\u6d88</button><button class="btn primary" onclick="addCron()">\u6dfb\u52a0</button></div></div></div>'
  +  '<div id="createKVModal" class="modal"><div class="modal-box small">\n    <h3>创建 KV 命名空间</h3><div class="label">名称</div><input id="kvNamespaceName" class="input" placeholder="my-kv-namespace">\n    <div class="label" style="margin-top:12px">数据辖区（可选，仅创建时可设）</div>\n    <select id="kvJurisdiction" class="input"><option value="default">默认</option><option value="eu">EU</option><option value="us">US</option><option value="fedramp">FedRAMP</option></select>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreateKVNamespace()">创建</button><button class="btn" onclick="closeCreateKVModal()">取消</button></div></div></div>'
  +  '<div id="kvValueModal" class="modal"><div class="modal-box">\n    <h3 id="kvValueModalTitle">添加/更新键值</h3><div class="label">Key</div><input id="kvKey" class="input" placeholder="例如：user123">\n    <div class="label" style="margin-top:8px">Value</div><textarea id="kvValue" class="input" rows="6"></textarea>\n    <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap"><input id="kvTtl" class="input" placeholder="过期 TTL（秒，≥60，可选）" style="max-width:220px"><input id="kvExp" class="input" placeholder="过期时间戳（秒，可选）" style="max-width:220px"></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmKVPut()">保存</button><button class="btn" onclick="closeKVValueModal()">取消</button></div></div></div>'
  +  '<div id="kvBulkWriteModal" class="modal"><div class="modal-box">\n    <h3>KV 批量写入 <span class="pill blue">bulk</span></h3><div class="label">JSON 数组，每项 {key, value, expiration_ttl?}，单次最多 10000 条</div>\n    <textarea id="kvBulkWriteInput" class="input" rows="10" placeholder=\'[{"key":"k1","value":"v1"},{"key":"k2","value":"v2","expiration_ttl":3600}]\'></textarea>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmKvBulkWrite()">提交</button><button class="btn" onclick="closeKvBulkWrite()">取消</button></div></div></div>'
  +  '<div id="kvBulkDeleteModal" class="modal"><div class="modal-box small">\n    <h3>KV 批量删除</h3><div class="label">每行一个 key，单次最多 10000 个</div>\n    <textarea id="kvBulkDeleteInput" class="input" rows="8" placeholder="key1\nkey2"></textarea>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn danger" onclick="confirmKvBulkDelete()">确认删除</button><button class="btn" onclick="closeKvBulkDelete()">取消</button></div></div></div>'
  +  '<div id="createD1Modal" class="modal"><div class="modal-box small">\n    <h3>创建 D1 数据库</h3><div class="label">名称</div><input id="d1DatabaseName" class="input" placeholder="my-d1-database">\n    <div class="label" style="margin-top:12px">位置提示</div>\n    <select id="d1Location" class="input"><option value="auto">自动（默认）</option><option value="wnam">北美西部</option><option value="enam">北美东部</option><option value="weur">西欧</option><option value="eeur">东欧</option><option value="apac">亚太地区</option><option value="oc">大洋洲</option></select>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreateD1Database()">创建</button><button class="btn" onclick="closeCreateD1Modal()">取消</button></div></div></div>'
  +  '<div id="d1ExportModal" class="modal"><div class="modal-box small">\n    <h3>导出 D1 备份</h3><div class="small">导出为 SQL 文件（轮询获取下载链接，链接 1 小时有效）</div>\n    <div id="d1ExportStatus" class="small" style="margin-top:8px">点击开始后请勿关闭窗口</div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" id="d1ExportBtn" onclick="startD1Export()">开始导出</button><button class="btn" onclick="closeD1Export()">关闭</button></div>\n    <div id="d1ExportLink" style="margin-top:12px"></div></div></div>'
  +  '<div id="createR2Modal" class="modal"><div class="modal-box small">\n    <h3>创建 R2 存储桶</h3><div class="label">存储桶名称</div><input id="r2BucketName" class="input" placeholder="my-bucket">\n    <div class="label" style="margin-top:12px">位置提示</div>\n    <select id="r2Location" class="input"><option value="auto">自动（默认）</option><option value="wnam">北美西部</option><option value="enam">北美东部</option><option value="weur">西欧</option><option value="eeur">东欧</option><option value="apac">亚太地区</option><option value="oc">大洋洲</option></select>\n    <div class="label" style="margin-top:12px">存储类型</div>\n    <select id="r2StorageClass" class="input"><option value="Standard">Standard</option><option value="InfrequentAccess">InfrequentAccess</option></select>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreateR2Bucket()">创建</button><button class="btn" onclick="closeCreateR2Modal()">取消</button></div></div></div>'
  +  '<div id="addDomainModal" class="modal"><div class="modal-box small">\n    <h3>绑定自定义域名</h3><div class="label">子域名前缀（留空则直接绑定根域名）</div>\n    <input id="newDomainPrefix" class="input" placeholder="例如 app" oninput="updateDomainPreview()">\n    <div class="label" style="margin-top:12px">根域名</div>\n    <div id="domainZoneWrap"><div class="small">加载中...</div></div>\n    <div class="small" style="margin-top:10px">完整域名：<span id="domainPreview" style="font-weight:600;color:#1e40af;font-size:14px"></span></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddDomain()">绑定</button><button class="btn" onclick="closeAddDomainModal()">取消</button></div></div></div>\'\n  +  \'<div id="addZoneModal" class="modal"><div class="modal-box small">\n    <h3>添加新域名</h3><div class="label">输入要接入 Cloudflare 的域名</div><input id="zoneName" class="input" placeholder="example.com">\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddZone()">添加</button><button class="btn" onclick="closeAddZoneModal()">取消</button></div></div></div>'
  +  '<div id="addDNSRecordModal" class="modal"><div class="modal-box">\n    <h3>添加 DNS 记录</h3><div class="label">记录类型</div>\n    <select id="dnsRecordType" class="input"><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option><option value="MX">MX</option><option value="TXT">TXT</option><option value="NS">NS</option><option value="SRV">SRV</option><option value="CAA">CAA</option></select>\n    <div class="label" style="margin-top:8px">记录名称</div><input id="dnsRecordName" class="input" placeholder="例如：www 或 @">\n    <div class="label" style="margin-top:8px">记录内容</div><input id="dnsRecordContent" class="input" placeholder="例如：192.0.2.1">\n    <div class="label" style="margin-top:8px">TTL</div>\n    <select id="dnsRecordTTL" class="input"><option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option></select>\n    <div style="margin-top:8px"><label><input type="checkbox" id="dnsRecordProxied"> 启用代理（橙色云）</label></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddDNSRecord()">添加记录</button><button class="btn" onclick="closeAddDNSRecordModal()">取消</button></div></div></div>'
  +  '<div id="editDNSRecordModal" class="modal"><div class="modal-box">\n    <h3>编辑 DNS 记录</h3><div class="small">记录类型不可修改，如需改类型请删除后重建</div>\n    <div class="label" style="margin-top:8px">记录名称</div><input id="editDnsRecordName" class="input">\n    <div class="label" style="margin-top:8px">记录内容</div><input id="editDnsRecordContent" class="input">\n    <div class="label" style="margin-top:8px">TTL</div>\n    <select id="editDnsRecordTTL" class="input"><option value="1">自动</option><option value="120">2分钟</option><option value="300">5分钟</option><option value="3600">1小时</option><option value="86400">1天</option></select>\n    <div style="margin-top:8px"><label><input type="checkbox" id="editDnsRecordProxied"> 启用代理（橙色云）</label></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmEditDNSRecord()">保存修改</button><button class="btn" onclick="closeEditDNSRecordModal()">取消</button></div></div></div>'
  +  '<div id="dnsBatchModal" class="modal"><div class="modal-box">\n    <h3>批量导入 DNS 记录 <span class="pill blue">batch（事务）</span></h3><div class="label">每行一条：类型,名称,内容,TTL(可选),proxied(可选 true/false)。任一失败全部回滚。</div>\n    <textarea id="dnsBatchInput" class="input" rows="10" placeholder="A,www,192.0.2.1,300,true\nCNAME,blog,example.com,1,false\nTXT,@,v=spf1 include:_spf.example.com ~all"></textarea>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmDnsBatchImport()">开始导入</button><button class="btn" onclick="closeDnsBatchImport()">取消</button></div></div></div>'
  +  '<div id="createPagesModal" class="modal"><div class="modal-box small">\n    <h3>创建 Pages 项目</h3><div class="label">项目名称</div><input id="pagesProjectNameInput" class="input" placeholder="my-site">\n    <div class="label" style="margin-top:12px">生产分支</div><input id="pagesBranchInput" class="input" placeholder="main" value="main">\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmCreatePagesProject()">创建</button><button class="btn" data-close-modal onclick="closeCreatePagesModal()">取消</button></div></div></div>'
  +  '<div id="pagesDomainsModal" class="modal"><div class="modal-box" style="position:relative">\n    <span data-close-modal onclick="closePagesDomains()" style="position:absolute;top:12px;right:16px;font-size:20px;cursor:pointer;color:#9ca3af" title="关闭">&times;</span>\n    <h3>Pages 自定义域名</h3><div id="pagesDomainsList" style="margin-top:12px"></div>\n    <div style="border-top:1px solid #eef2f6;margin-top:12px;padding-top:12px">\n    <div style="display:flex;gap:8px;margin-bottom:12px"><button class="btn small" id="pagesDomainTabCf" onclick="switchPagesDomainTab(\'cf\')">Cloudflare 域名</button><button class="btn small" id="pagesDomainTabExt" onclick="switchPagesDomainTab(\'ext\')">外部域名</button></div>\n    <div id="pagesDomainCfPane"><div class="label">子域名前缀（留空则直接绑定根域名）</div>\n    <input id="pagesDomainPrefix" class="input" placeholder="例如 app" oninput="updatePagesDomainPreview()">\n    <div class="label" style="margin-top:12px">根域名</div>\n    <div id="pagesDomainZoneWrap"><div class="small">加载中...</div></div>\n    <div class="small" style="margin-top:10px">完整域名：<span id="pagesDomainPreview" style="font-weight:600;color:#1e40af;font-size:14px"></span></div>\n    <div class="small" style="color:#6b7280;margin-top:6px">Cloudflare 托管的域名会自动添加 DNS 解析</div></div>\n    <div id="pagesDomainExtPane" style="display:none"><div class="label">完整域名（DNS 不在 Cloudflare 托管）</div>\n    <input id="pagesDomainExternal" class="input" placeholder="例如 app.example.com">\n    <div class="small" style="color:#6b7280;margin-top:8px">添加后需到你的 DNS 服务商手动添加 CNAME 记录：<br>主机记录：<span style="font-weight:600">app</span> → 记录值：<span id="pagesDomainCnameTarget" style="font-weight:600;color:#1e40af"></span><br>（根域名请用 A 记录指向 76.76.21.21，或用 DNS 服务商的 CNAME 扁平化功能）</div></div>\n    <div style="display:flex;gap:8px;margin-top:12px"><button class="btn primary" onclick="confirmAddPagesDomain()">添加</button><button class="btn" id="pagesDomainsCloseBtn" data-close-modal onclick="closePagesDomains()">关闭</button></div></div></div></div>'
  +  '<div id="pagesBindModal" class="modal"><div class="modal-box" style="position:relative">\n    <span data-close-modal onclick="closePagesBindModal()" style="position:absolute;top:12px;right:16px;font-size:20px;cursor:pointer;color:#9ca3af" title="关闭">&times;</span>\n    <h3>Pages 绑定 <span class="pill blue" id="pagesBindProjectName"></span></h3>\n    <div class="small">同时应用到生产与预览环境。删除整行 = 删除该项。</div>\n    <div class="tabs" style="margin-top:12px"><div class="tab active" data-pbtab="env" onclick="switchPagesBindTab(\'env\')">环境变量</div><div class="tab" data-pbtab="kv" onclick="switchPagesBindTab(\'kv\')">KV 命名空间</div><div class="tab" data-pbtab="d1" onclick="switchPagesBindTab(\'d1\')">D1 数据库</div></div>\n    <div id="pbind-env"><div id="pagesEnvRows" style="margin-top:6px"></div><div style="margin-top:8px"><button class="btn small" onclick="addPagesEnvRow()">+ 添加变量</button></div></div>\n    <div id="pbind-kv" style="display:none"><div id="pagesKvRows" style="margin-top:6px"></div><div style="margin-top:8px"><button class="btn small" onclick="addPagesKvRow()">+ 添加 KV 绑定</button></div></div>\n    <div id="pbind-d1" style="display:none"><div id="pagesD1Rows" style="margin-top:6px"></div><div style="margin-top:8px"><button class="btn small" onclick="addPagesD1Row()">+ 添加 D1 绑定</button></div></div>\n    <div style="display:flex;gap:8px;margin-top:16px"><button class="btn primary" onclick="savePagesBindings()">保存</button><button class="btn" data-close-modal onclick="closePagesBindModal()">取消</button></div></div></div>'
  +  '<div id="pagesCompatModal" class="modal"><div class="modal-box" style="width:560px;position:relative">\n    <span data-close-modal onclick="closePagesCompatModal()" style="position:absolute;top:12px;right:16px;font-size:20px;cursor:pointer;color:#9ca3af" title="关闭">&times;</span>\n    <h3 style="margin:0 0 4px">Pages 兼容日期 <span class="pill blue" id="pagesCompatProjectName"></span></h3>\n    <div class="small" style="margin-bottom:12px">设置 Pages Functions 的兼容日期，同时应用到生产与预览环境。<span id="pagesCompatCurrentVal" style="font-weight:600;color:#1e40af"></span></div>\n    <div id="pagesCompatDateList" style="max-height:380px;overflow-y:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>\n    <div style="display:flex;gap:8px;margin-top:12px;align-items:center"><input id="pagesCompatDateInput" type="date" class="input" style="max-width:200px"><span class="small">或直接选择日期</span></div>\n    <div style="display:flex;justify-content:space-between;margin-top:16px"><button class="btn" onclick="closePagesCompatModal()">取消</button><button class="btn primary" onclick="confirmPagesCompatDate()">保存</button></div></div></div>\n'
  +  '<div id="pagesCompatFlagsModal" class="modal"><div class="modal-box" style="width:560px;position:relative">\n    <span data-close-modal onclick="closePagesCompatFlagsModal()" style="position:absolute;top:12px;right:16px;font-size:20px;cursor:pointer;color:#9ca3af" title="关闭">&times;</span>\n    <h3 style="margin:0 0 4px">Pages 兼容性标志 <span class="pill blue" id="pagesCompatFlagsProjectName"></span></h3>\n    <div class="small" style="margin-bottom:12px">选择要启用的兼容性标志，同时应用到生产与预览环境。<span id="pagesCompatFlagsCurrent" style="font-weight:600;color:#1e40af"></span></div>\n    <div id="pagesCompatFlagsList" style="max-height:380px;overflow-y:auto;border:1px solid #eef2f6;border-radius:8px;padding:8px"></div>\n    <div style="display:flex;gap:8px;margin-top:12px;align-items:center"><input id="pagesCompatFlagsCustom" class="input" placeholder="自定义标志，例如 my_flag" style="flex:1"><button class="btn" onclick="addCustomPagesCompatFlag()">添加</button></div>\n    <div style="display:flex;justify-content:space-between;margin-top:16px"><button class="btn" onclick="closePagesCompatFlagsModal()">取消</button><button class="btn primary" onclick="confirmPagesCompatFlags()">保存</button></div></div></div>\n'
  +  '<div id="outModal" class="modal"><div class="modal-box">\n    <h3>调试输出</h3><pre id="debugOut" style="height:300px;overflow:auto"></pre>\n    <div style="display:flex;justify-content:flex-end;margin-top:8px"><button class="btn" onclick="closeOut()">关闭</button></div></div></div>'
  +  '<script src="/static-v3.js"></script>\n</body>\n</html>';
}

// ---------------- 前端 JS ----------------
// 注意：前端代码中不使用反引号与 ${}，全部用字符串拼接，避免模板转义问题
// 本段由 build.py 自动生成，请勿手工编辑；改 frontend/static.js 后重新运行 build.py
function renderStaticJS() {
  return "(function(){\nvar DEFAULT_WORKER_SCRIPT = \"export default {\\n  async fetch(request, env, ctx) {\\n    return new Response(\\'Hello World\\');\\n  }\\n};\";\nfunction el(id){ return document.getElementById(id); }\nfunction esc(s){ return String(s==null?\"\":s).replace(/&/g,\"&amp;\").replace(/</g,\"&lt;\").replace(/>/g,\"&gt;\"); }\nfunction escA(s){ return String(s==null?\"\":s).replace(/&/g,\"&amp;\").replace(/\"/g,\"&quot;\").replace(/</g,\"&lt;\").replace(/>/g,\"&gt;\"); }\nfunction fmtBJ(iso){ try{ var d = new Date(iso); if(!iso || isNaN(d.getTime())) return iso || \"\"; var p = function(n){ return (n < 10 ? \"0\" : \"\") + n; }; var t = new Date(d.getTime() + 8 * 3600000); return t.getUTCFullYear() + \"-\" + p(t.getUTCMonth() + 1) + \"-\" + p(t.getUTCDate()) + \" \" + p(t.getUTCHours()) + \":\" + p(t.getUTCMinutes()) + \":\" + p(t.getUTCSeconds()); }catch(e){ return iso || \"\"; } }\nfunction showNotification(message, type){\n  type = type || \"success\";\n  var n = document.createElement(\"div\");\n  n.textContent = message;\n  var bg = type === \"success\" ? \"#10b981\" : (type === \"warning\" ? \"#f59e0b\" : \"#ef4444\");\n  n.style.cssText = \"position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;color:#fff;z-index:10000;max-width:420px;box-shadow:0 4px 12px rgba(0,0,0,0.15);background:\" + bg;\n  document.body.appendChild(n);\n  setTimeout(function(){ n.remove(); }, type === \"warning\" ? 6000 : 3200);\n}\nfunction copyToClipboard(text, event){ if(event) event.stopPropagation(); if(navigator.clipboard){ navigator.clipboard.writeText(text).then(function(){ showNotification(\"已复制到剪贴板\"); }).catch(function(){ showNotification(\"复制失败\",\"error\"); }); } }\nfunction debugOut(v){ el(\"debugOut\").textContent = (typeof v === \"string\") ? v : JSON.stringify(v, null, 2); el(\"outModal\").style.display = \"flex\"; }\nfunction closeOut(){ el(\"outModal\").style.display = \"none\"; }\nfunction loadSaved(){ try { return JSON.parse(localStorage.getItem(\"cfm_accounts\") || \"[]\"); } catch(e){ return []; } }\nfunction saveAccounts(a){ localStorage.setItem(\"cfm_accounts\", JSON.stringify(a)); }\nfunction getActiveIdx(){ var i = parseInt(localStorage.getItem(\"cfm_active_idx\") || \"-1\", 10); return isNaN(i) ? -1 : i; }\nfunction getActiveAccount(){ var arr = loadSaved(); var i = getActiveIdx(); return (i >= 0 && arr[i]) ? arr[i] : null; }\n// 账号显示名：key 模式显示邮箱；token 的 label 若缺失或就是 token 本身（旧数据），不直接显示 token\nfunction accountTitle(a){\n  if(!a) return \"\";\n  if(a.mode === \"key\") return a.email || \"\";\n  var label = a.label || \"\";\n  if(a.mode === \"token\" && label === a.token) label = \"\";\n  if(a.mode === \"oauth\" && !label) label = \"OAuth 授权\";\n  return label || \"API Token\";\n}\nfunction nowStr2(){ return new Date().toLocaleString(\"zh-CN\", { timeZone: \"Asia/Shanghai\", hour12: false }).replace(/\\//g, \"-\"); }\n// ---- OAuth 2.0 + PKCE（Cloudflare 官方授权）----\nvar OAUTH_DEFAULT_CLIENT_ID = \"11ba6a4eb7ab0bc9e1cbdd9d46f59b02\";\nvar OAUTH_AUTH_URL = \"https://dash.cloudflare.com/oauth2/auth\";\nvar OAUTH_SCOPES = \"workers-scripts.read workers-scripts.write workers-routes.read workers-routes.write workers-tail.read workers-kv-storage.read workers-kv-storage.write d1.read d1.write workers-r2.read workers-r2.write zone.read zone.write dns.read dns.write page.read page.write analytics.read account-analytics.read account-settings.read memberships.read user-details.read\";\nfunction getOAuthClientId(){ return localStorage.getItem(\"cfm_oauth_client_id\") || OAUTH_DEFAULT_CLIENT_ID; }\nfunction setOAuthClientId(id){ if(id) localStorage.setItem(\"cfm_oauth_client_id\", id); else localStorage.removeItem(\"cfm_oauth_client_id\"); }\nfunction authPayload(){\n  var a = getActiveAccount();\n  if(!a) return {};\n  if(a.mode === \"token\") return { authMode: \"token\", token: a.token };\n  if(a.mode === \"oauth\") return { authMode: \"oauth\", token: a.access_token };\n  return { authMode: \"key\", email: a.email, key: a.key };\n}\n// OAuth token 快过期（2 分钟内）时自动刷新；刷新失败返回 false\nvar _oauthRefreshing = null;\nasync function ensureOAuthFresh(){\n  var a = getActiveAccount();\n  if(!a || a.mode !== \"oauth\") return true;\n  if(a.expires_at && Date.now() < a.expires_at - 120000) return true;\n  if(_oauthRefreshing) return _oauthRefreshing;\n  _oauthRefreshing = (async function(){\n    try {\n      var r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" },\n        body: JSON.stringify({ action: \"oauth-refresh\", refresh_token: a.refresh_token, client_id: a.client_id || getOAuthClientId() }) });\n      var res = await r.json();\n      if(res && res.success && res.access_token){\n        a.access_token = res.access_token;\n        if(res.refresh_token) a.refresh_token = res.refresh_token;\n        a.expires_at = Date.now() + (res.expires_in || 3600) * 1000;\n        var arr = loadSaved(); var idx = getActiveIdx();\n        if(arr[idx] && arr[idx].mode === \"oauth\"){ arr[idx] = a; saveAccounts(arr); }\n        return true;\n      }\n    } catch(e){}\n    return false;\n  })();\n  var ok = await _oauthRefreshing;\n  _oauthRefreshing = null;\n  return ok;\n}\nasync function api(action, body){\n  var a0 = getActiveAccount();\n  if(a0 && a0.mode === \"oauth\"){\n    var fresh = await ensureOAuthFresh();\n    if(!fresh) return { success: false, error: \"OAuth 授权已过期，请重新使用 Cloudflare 账号登录\", oauthExpired: true };\n  }\n  var payload = authPayload();\n  payload.action = action;\n  if(body){ for(var k in body){ payload[k] = body[k]; } }\n  var r;\n  try { r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(payload) }); }\n  catch(e){ return { success: false, error: \"网络请求失败，请检查网络后重试\" }; }\n  var res;\n  try { res = await r.json(); } catch(e){ res = { success: false, error: \"响应解析失败\" }; }\n  if(r.status === 401 && res && res.error && res.error.indexOf(\"未授权\") >= 0){ location.href = \"/login\"; }\n  return res;\n}\nasync function ensureAccountId(){\n  var cached = localStorage.getItem(\"cfm_accountId\");\n  if(cached) return cached;\n  var r = await api(\"list-accounts\");\n  if(r && r.success && r.result && r.result.length){\n    localStorage.setItem(\"cfm_accountId\", r.result[0].id);\n    return r.result[0].id;\n  }\n  return null;\n}\nvar page = document.body && document.body.dataset ? document.body.dataset.page : \"\";\nif(page === \"login\"){\n  var authMode = \"token\";\n  window.switchAuthMode = function(m){\n    authMode = m;\n    el(\"tabToken\").className = \"mode-tab\" + (m === \"token\" ? \" active\" : \"\");\n    el(\"tabKey\").className = \"mode-tab\" + (m === \"key\" ? \" active\" : \"\");\n    el(\"tokenFields\").style.display = (m === \"token\") ? \"block\" : \"none\";\n    el(\"keyFields\").style.display = (m === \"key\") ? \"block\" : \"none\";\n    el(\"batchLoginHint\").textContent = (m === \"token\") ? \"Token 模式：每行一个，格式：备注|Token（备注可省略）\" : \"Key 模式：每行一个，格式：邮箱|GlobalApiKey\";\n  };\n  // ---- OAuth 2.0 + PKCE 登录 ----\n  function _b64url(buf){\n    var bin = String.fromCharCode.apply(null, new Uint8Array(buf));\n    return btoa(bin).replace(/\\+/g, \"-\").replace(/\\//g, \"_\").replace(/=+$/, \"\");\n  }\n  function _randB64(n){\n    var arr = new Uint8Array(n);\n    (window.crypto || window.msCrypto).getRandomValues(arr);\n    return _b64url(arr.buffer).slice(0, n);\n  }\n  async function _codeChallenge(verifier){\n    var d = await crypto.subtle.digest(\"SHA-256\", new TextEncoder().encode(verifier));\n    return _b64url(d);\n  }\n  window.startOAuthLogin = async function(){\n    var clientId = getOAuthClientId();\n    if(!clientId){ alert(\"请先在设置页配置 OAuth Client ID\"); return; }\n    try {\n      var verifier = _randB64(64);\n      var state = _randB64(32);\n      var challenge = await _codeChallenge(verifier);\n      sessionStorage.setItem(\"cfm_oauth_verifier\", verifier);\n      sessionStorage.setItem(\"cfm_oauth_state\", state);\n      var redirectUri = location.origin + \"/oauth/callback\";\n      var url = OAUTH_AUTH_URL\n        + \"?client_id=\" + encodeURIComponent(clientId)\n        + \"&response_type=code\"\n        + \"&redirect_uri=\" + encodeURIComponent(redirectUri)\n        + \"&scope=\" + encodeURIComponent(OAUTH_SCOPES)\n        + \"&state=\" + encodeURIComponent(state)\n        + \"&code_challenge=\" + encodeURIComponent(challenge)\n        + \"&code_challenge_method=S256\";\n      location.href = url;\n    } catch(e){ alert(\"启动 OAuth 失败：浏览器不支持 WebCrypto（需要 HTTPS）\"); }\n  };\n  function renderSaved(){\n    var cont = el(\"savedAccounts\"); var arr = loadSaved(); cont.innerHTML = \"\";\n    if(!arr.length){ cont.textContent = \"未找到已保存账号\"; return; }\n    arr.forEach(function(a, idx){\n      var d = document.createElement(\"div\"); d.className = \"account-row\";\n      var pillCls = a.mode === \"token\" ? \"blue\" : (a.mode === \"oauth\" ? \"green\" : \"amber\");\n      var pillTxt = a.mode === \"token\" ? \"Token\" : (a.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n      var title = esc(accountTitle(a)) + ' <span class=\"pill ' + pillCls + '\">' + pillTxt + '</span>';\n      d.innerHTML = \"<div><div style=\\\"font-weight:600\\\">\" + title + \"</div><div class=\\\"small\\\">添加于 \" + esc(a.added || \"\") + \"</div></div>\";\n      var btn = document.createElement(\"button\"); btn.className = \"btn\"; btn.textContent = \"快速登录\";\n      btn.onclick = function(){ localStorage.setItem(\"cfm_active_idx\", String(idx)); localStorage.removeItem(\"cfm_accountId\"); location.href = \"/app\"; };\n      var wrap = document.createElement(\"div\"); wrap.appendChild(btn); d.appendChild(wrap); cont.appendChild(d);\n    });\n  }\n  function nowStr(){ return new Date().toLocaleString(\"zh-CN\", { timeZone: \"Asia/Shanghai\", hour12: false }).replace(/\\//g, \"-\"); }\n  async function doVerify(email, key, token, label){\n    var body = (authMode === \"token\") ? { authMode: \"token\", token: token } : { authMode: \"key\", email: email, key: key };\n    body.action = \"validate-credentials\";\n    var r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(body) });\n    var res; try { res = await r.json(); } catch(e){ res = {}; }\n    if(res && res.success){\n      var arr = loadSaved();\n      var autoLabel = (authMode === \"token\" && res.result && res.result.length && res.result[0].name) ? res.result[0].name : \"\";\n      var acc = (authMode === \"token\") ? { mode: \"token\", label: label || autoLabel || \"API Token\", token: token, added: nowStr() } : { mode: \"key\", email: email, key: key, added: nowStr() };\n      var key2 = (authMode === \"token\") ? (\"t:\" + token.slice(-8)) : (\"k:\" + email);\n      var ex = arr.findIndex(function(x){ return (x.mode === \"token\" ? \"t:\" + String(x.token).slice(-8) : \"k:\" + x.email) === key2; });\n      if(ex !== -1) arr.splice(ex, 1);\n      arr.unshift(acc); saveAccounts(arr);\n      localStorage.setItem(\"cfm_active_idx\", \"0\"); localStorage.removeItem(\"cfm_accountId\");\n      location.href = \"/app\";\n    } else { alert(\"验证失败：\" + ((res && res.error) || \"unknown\")); }\n  }\n  el(\"verifyBtn\").addEventListener(\"click\", function(){\n    if(authMode === \"token\"){ var t = el(\"newToken\").value.trim(); if(!t) return alert(\"请输入 API Token\"); doVerify(null, null, t, el(\"newLabel\").value.trim()); }\n    else { var e = el(\"newEmail\").value.trim(), k = el(\"newKey\").value.trim(); if(!e || !k) return alert(\"请输入邮箱和 Global API Key\"); doVerify(e, k); }\n  });\n  el(\"openBatchModalBtn\").addEventListener(\"click\", function(){ el(\"batchLoginModal\").style.display = \"flex\"; });\n  el(\"confirmBatchLogin\").addEventListener(\"click\", function(){\n    var raw = el(\"batchLoginInput\").value; if(!raw.trim()) return alert(\"请输入内容\");\n    var arr = loadSaved(); var n = 0;\n    raw.split(\"\\n\").forEach(function(line){\n      line = line.trim(); if(!line) return;\n      var parts = line.split(\"|\");\n      if(authMode === \"token\"){\n        var token, label;\n        if(parts.length >= 2){ label = parts[0].trim(); token = parts.slice(1).join(\"|\").trim(); } else { token = parts[0].trim(); label = \"API Token\"; }\n        if(token){ arr.unshift({ mode: \"token\", label: label, token: token, added: nowStr() }); n++; }\n      } else {\n        if(parts.length >= 2){ var em = parts[0].trim(), ky = parts.slice(1).join(\"|\").trim(); if(em && ky){ arr.unshift({ mode: \"key\", email: em, key: ky, added: nowStr() }); n++; } }\n      }\n    });\n    if(n > 0){ saveAccounts(arr); renderSaved(); el(\"batchLoginModal\").style.display = \"none\"; el(\"batchLoginInput\").value = \"\"; showNotification(\"已导入 \" + n + \" 个账号\"); }\n    else { alert(\"未解析到有效账号，请检查格式\"); }\n  });\n  el(\"clearBtn\").addEventListener(\"click\", function(){\n    var b = el(\"clearBtn\");\n    if(b.dataset.armed){\n      delete b.dataset.armed;\n      localStorage.removeItem(\"cfm_accounts\"); localStorage.removeItem(\"cfm_active_idx\"); localStorage.removeItem(\"cfm_accountId\");\n      renderSaved();\n      b.textContent = \"清除本地账号\"; b.style.background = \"#e5e7eb\"; b.style.color = \"#111\";\n    } else {\n      b.dataset.armed = \"1\"; b.textContent = \"再次点击确认清除\"; b.style.background = \"#ef4444\"; b.style.color = \"#fff\";\n      setTimeout(function(){ if(b.dataset.armed){ delete b.dataset.armed; b.textContent = \"清除本地账号\"; b.style.background = \"#e5e7eb\"; b.style.color = \"#111\"; } }, 5000);\n    }\n  });\n  window.submitPw = async function(){    var pw = el(\"pwInput\").value; el(\"pwError\").textContent = \"\";\n    try {\n      var r = await fetch(\"/auth\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ password: pw }) });\n      var res = await r.json();\n      if(res.success){ el(\"pwOverlay\").style.display = \"none\"; initLogin(); }\n      else { el(\"pwError\").textContent = res.error || \"密码错误\"; el(\"pwInput\").value = \"\"; el(\"pwInput\").focus(); }\n    } catch(e){ el(\"pwError\").textContent = \"网络错误，请刷新重试\"; }\n  };\n  async function initLogin(){\n    try {\n      var r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify({ action: \"check-features\" }) });\n      if(r.status === 401){ el(\"pwOverlay\").style.display = \"flex\"; setTimeout(function(){ el(\"pwInput\").focus(); }, 100); return; }\n    } catch(e){}\n    renderSaved();\n  }\n  initLogin();\n  return;\n}\nif(page === \"oauth-callback\"){\n  // OAuth 授权回调：校验 state，用 code + PKCE verifier 换 token，保存账号后进 /app\n  (async function(){\n    var msgEl = el(\"cbMsg\"), errEl = el(\"cbErr\"), spinEl = el(\"cbSpin\");\n    function fail(t){\n      if(spinEl) spinEl.style.display = \"none\";\n      if(msgEl) msgEl.textContent = \"授权失败\";\n      if(errEl) errEl.innerHTML = esc(t) + '<br><br><a href=\"/login\" style=\"color:#2563eb\">返回登录页</a>';\n    }\n    var q = new URLSearchParams(location.search);\n    if(q.get(\"error\")){ fail(\"Cloudflare 返回错误：\" + q.get(\"error\")); return; }\n    var code = q.get(\"code\"), state = q.get(\"state\");\n    var verifier = sessionStorage.getItem(\"cfm_oauth_verifier\");\n    var savedState = sessionStorage.getItem(\"cfm_oauth_state\");\n    sessionStorage.removeItem(\"cfm_oauth_verifier\");\n    sessionStorage.removeItem(\"cfm_oauth_state\");\n    if(!code){ fail(\"未收到授权码\"); return; }\n    if(!state || !savedState || state !== savedState){ fail(\"state 校验失败，已中止（防 CSRF）\"); return; }\n    if(!verifier){ fail(\"PKCE 校验数据丢失，请重新发起登录\"); return; }\n    if(msgEl) msgEl.textContent = \"正在换取访问令牌…\";\n    var clientId = getOAuthClientId();\n    var redirectUri = location.origin + \"/oauth/callback\";\n    var r;\n    try {\n      r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" },\n        body: JSON.stringify({ action: \"oauth-exchange\", code: code, code_verifier: verifier, redirect_uri: redirectUri, client_id: clientId }) });\n    } catch(e){ fail(\"网络请求失败\"); return; }\n    if(r.status === 401){ fail(\"面板会话已过期，请先完成面板访问密码验证，再重新发起 OAuth 登录\"); return; }\n    var res; try { res = await r.json(); } catch(e){ res = {}; }\n    if(!res || !res.success){ fail(res.error || \"换取令牌失败\"); return; }\n    if(msgEl) msgEl.textContent = \"正在验证账号…\";\n    // 用新 token 验证并保存账号\n    var acc = { mode: \"oauth\", label: res.email || \"OAuth 授权\", access_token: res.access_token,\n      refresh_token: res.refresh_token || \"\", expires_at: Date.now() + (res.expires_in || 3600) * 1000,\n      client_id: clientId, added: new Date().toLocaleString(\"zh-CN\", { timeZone: \"Asia/Shanghai\", hour12: false }).replace(/\\//g, \"-\") };\n    var arr = loadSaved();\n    arr.unshift(acc); saveAccounts(arr);\n    localStorage.setItem(\"cfm_active_idx\", \"0\");\n    localStorage.removeItem(\"cfm_accountId\");\n    location.href = \"/app\";\n  })();\n  return;\n}\nif(page === \"app\"){\nvar currentAccountId = null;\nfunction navTo(p){\n  document.querySelectorAll(\".nav .item\").forEach(function(i){ i.classList.remove(\"active\"); });\n  document.querySelectorAll(\".page-content\").forEach(function(x){ x.classList.remove(\"active\"); });\n  var nav = document.querySelector('.nav .item[data-page=\"' + p + '\"]');\n  var pg = el(p + \"-page\");\n  if(nav) nav.classList.add(\"active\"); if(pg) pg.classList.add(\"active\");\n  if(p === \"workers\") refreshWorkers();\n  else if(p === \"batch\") renderBatchPage();\n  else if(p === \"kv\") refreshKVNamespaces();\n  else if(p === \"d1\") refreshD1Databases();\n  else if(p === \"r2\") refreshR2Buckets();\n  else if(p === \"dns\") showZonesList();\n  else if(p === \"pages\") refreshPagesProjects();\n  else if(p === \"settings\") loadSubdomainSettings();\n}\nwindow.navTo = navTo;\nwindow.saveOAuthClientId = function(){\n  var v = el(\"oauthClientIdInput\").value.trim();\n  setOAuthClientId(v);\n  var ohint = el(\"oauthClientIdHint\");\n  if(ohint) ohint.textContent = v ? \"已使用自定义 Client ID\" : \"当前使用内置默认 Client ID\";\n  showNotification(\"OAuth Client ID 已保存\");\n};\nwindow.logout = function(){ localStorage.removeItem(\"cfm_active_idx\"); localStorage.removeItem(\"cfm_accountId\"); location.href = \"/login\"; };\nfunction openAccountSwitcher(){\n  var arr = loadSaved(); var cur = getActiveAccount(); var cont = el(\"accountListContainer\"); cont.innerHTML = \"\";\n  if(!arr.length){ cont.innerHTML = \"<div style=\\\"padding:16px;text-align:center;color:#64748b\\\">暂无其他账号</div>\"; }\n  arr.forEach(function(acc, idx){\n    var isActive = cur && acc.mode === cur.mode && ((acc.mode === \"token\" && acc.token === cur.token) || (acc.mode === \"key\" && acc.email === cur.email) || (acc.mode === \"oauth\" && acc.access_token === cur.access_token));\n    var title = esc(accountTitle(acc));\n    var pillC = acc.mode === \"token\" ? \"blue\" : (acc.mode === \"oauth\" ? \"green\" : \"amber\");\n    var pillT = acc.mode === \"token\" ? \"Token\" : (acc.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n    var d = document.createElement(\"div\"); d.className = \"acct-row\" + (isActive ? \" acct-active\" : \"\");\n    d.innerHTML = \"<div style=\\\"flex:1;cursor:pointer\\\" data-idx=\\\"\" + idx + \"\\\"><div style=\\\"font-weight:600\\\">\" + title + (isActive ? \"<span class=\\\"badge\\\">当前</span>\" : \"\") + \" <span class=\\\"pill \" + pillC + \"\\\">\" + pillT + \"</span></div><div class=\\\"small\\\">\" + esc(acc.added || \"\") + \"</div></div>\" + (isActive ? \"\" : \"<button class=\\\"trash-btn\\\" data-idx=\\\"\" + idx + \"\\\">✕</button>\");\n    cont.appendChild(d);\n  });\n  Array.from(cont.querySelectorAll(\"[data-idx]\")).forEach(function(node){\n    node.addEventListener(\"click\", function(e){\n      e.stopPropagation();\n      var idx = parseInt(this.getAttribute(\"data-idx\"), 10);\n      if(this.tagName === \"BUTTON\"){ if(!confirm(\"确定要移除此账号吗？\")) return; var a2 = loadSaved(); a2.splice(idx, 1); saveAccounts(a2); openAccountSwitcher(); return; }\n      localStorage.setItem(\"cfm_active_idx\", String(idx)); localStorage.removeItem(\"cfm_accountId\");\n      showNotification(\"正在切换账号...\"); setTimeout(function(){ location.reload(); }, 500);\n    });\n  });\n  ensureAddAccountSection();\n  el(\"accountModal\").style.display = \"flex\";\n}\nwindow.openAccountSwitcher = openAccountSwitcher;\nwindow.closeAccountSwitcher = function(){ el(\"accountModal\").style.display = \"none\"; };\n// ---- 切换账号弹窗内的添加账号 ----\nfunction ensureAddAccountSection(){\n  if(el(\"addAccountSection\")) return;\n  var box = el(\"accountModal\").querySelector(\".modal-box\");\n  var sec = document.createElement(\"div\");\n  sec.id = \"addAccountSection\";\n  sec.style.cssText = \"margin-top:12px;border-top:1px solid #eef2f6;padding-top:12px\";\n  sec.innerHTML = '<button class=\"btn primary\" style=\"width:100%\" onclick=\"toggleAddAccountForm()\">+ 添加账号</button>'\n    + '<div id=\"addAccountForm\" style=\"display:none;margin-top:12px\">'\n    + '<div class=\"tabs\" style=\"margin-bottom:10px\">'\n    + '<div class=\"tab active\" data-aatab=\"token\" onclick=\"switchAddAccountTab(\\'token\\')\">API Token</div>'\n    + '<div class=\"tab\" data-aatab=\"key\" onclick=\"switchAddAccountTab(\\'key\\')\">Global Key</div>'\n    + '</div>'\n    + '<div id=\"aaTokenPane\"><div class=\"label\">API Token</div><input id=\"aaToken\" class=\"input\" placeholder=\"粘贴 API Token\">'\n    + '<div class=\"label\" style=\"margin-top:8px\">备注名（可选）</div><input id=\"aaLabel\" class=\"input\" placeholder=\"留空则自动使用 Cloudflare 账号名\"></div>'\n    + '<div id=\"aaKeyPane\" style=\"display:none\"><div class=\"label\">邮箱</div><input id=\"aaEmail\" class=\"input\" placeholder=\"Cloudflare 账号邮箱\">'\n    + '<div class=\"label\" style=\"margin-top:8px\">Global API Key</div><input id=\"aaKey\" class=\"input\" placeholder=\"粘贴 Global API Key\"></div>'\n    + '<div style=\"display:flex;gap:8px;margin-top:12px;flex-wrap:wrap\"><button class=\"btn primary\" onclick=\"confirmAddAccount()\">验证并保存</button>'\n    + '<button class=\"btn\" onclick=\"toggleAddAccountForm()\">取消</button>'\n    + '<button class=\"btn\" onclick=\"startOAuthLogin()\">OAuth 添加</button></div>'\n    + '</div>';\n  box.appendChild(sec);\n}\nfunction toggleAddAccountForm(){ var f = el(\"addAccountForm\"); if(f) f.style.display = (f.style.display === \"none\" ? \"\" : \"none\"); }\nfunction switchAddAccountTab(t){\n  Array.from(document.querySelectorAll(\"[data-aatab]\")).forEach(function(x){ x.classList.toggle(\"active\", x.getAttribute(\"data-aatab\") === t); });\n  el(\"aaTokenPane\").style.display = t === \"token\" ? \"\" : \"none\";\n  el(\"aaKeyPane\").style.display = t === \"key\" ? \"\" : \"none\";\n}\nasync function confirmAddAccount(){\n  var tabEl = document.querySelector(\"[data-aatab].active\");\n  var tab = tabEl ? tabEl.getAttribute(\"data-aatab\") : \"token\";\n  var body, label = \"\", key2;\n  if(tab === \"token\"){\n    var token = el(\"aaToken\").value.trim();\n    if(!token) return showNotification(\"请输入 API Token\", \"error\");\n    label = el(\"aaLabel\").value.trim();\n    body = { authMode: \"token\", token: token };\n    key2 = \"t:\" + token.slice(-8);\n  } else {\n    var email = el(\"aaEmail\").value.trim(), key = el(\"aaKey\").value.trim();\n    if(!email || !key) return showNotification(\"请输入邮箱和 Global API Key\", \"error\");\n    body = { authMode: \"key\", email: email, key: key };\n    key2 = \"k:\" + email;\n  }\n  body.action = \"validate-credentials\";\n  showNotification(\"正在验证...\", \"warning\");\n  var r;\n  try { r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(body) }); }\n  catch(e){ showNotification(\"网络请求失败\", \"error\"); return; }\n  var res; try { res = await r.json(); } catch(e){ res = {}; }\n  if(res && res.success){\n    var autoLabel = (tab === \"token\" && res.result && res.result.length && res.result[0].name) ? res.result[0].name : \"\";\n    var acc = (tab === \"token\")\n      ? { mode: \"token\", label: label || autoLabel || \"API Token\", token: body.token, added: nowStr2() }\n      : { mode: \"key\", email: body.email, key: body.key, added: nowStr2() };\n    var arr = loadSaved();\n    var ex = arr.findIndex(function(x){\n      var k = x.mode === \"token\" ? \"t:\" + String(x.token).slice(-8) : (x.mode === \"key\" ? \"k:\" + x.email : \"o:\" + x.access_token);\n      return k === key2;\n    });\n    if(ex !== -1) arr.splice(ex, 1);\n    arr.unshift(acc); saveAccounts(arr);\n    localStorage.setItem(\"cfm_active_idx\", \"0\"); localStorage.removeItem(\"cfm_accountId\");\n    showNotification(\"账号已添加\");\n    setTimeout(function(){ location.reload(); }, 600);\n  } else {\n    showNotification(\"验证失败：\" + ((res && res.error) || \"unknown\"), \"error\");\n  }\n}\nwindow.toggleAddAccountForm = toggleAddAccountForm; window.switchAddAccountTab = switchAddAccountTab; window.confirmAddAccount = confirmAddAccount;\nfunction tagRow(label, inner, left){\n  return \"<div class=\\\"tag-row\" + (left ? \" left\" : \"\") + \"\\\"><span class=\\\"tag-row-label\\\">\" + label + \"</span>\" +\n    (inner ? inner : \"<span class=\\\"small\\\" style=\\\"color:#94a3b8\\\">无</span>\") + \"</div>\";\n}\nasync function refreshWorkers(){\n  el(\"workersList\").innerHTML = \"加载中...\";\n  currentAccountId = await ensureAccountId();\n  if(!currentAccountId){ el(\"workersList\").innerHTML = \"无法获取 Account ID，请检查 Token 权限\"; return; }\n  var res = await api(\"list-workers\", { accountId: currentAccountId });\n  if(!res || !res.success){ el(\"workersList\").innerHTML = \"获取 Workers 失败：\" + esc((res && res.error) || \"\"); return; }\n  var list = el(\"workersList\"); list.innerHTML = \"\";\n  if(!res.result.length){ list.innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无 Workers</div>\"; }\n  res.result.forEach(function(w){\n    var name = w.id;\n    var bindings = w.bindings || [];\n    var envB = bindings.filter(function(b){ return b.type === \"plain_text\" || b.type === \"secret_text\" || b.type === \"json\"; });\n    var kvB = bindings.filter(function(b){ return b.type === \"kv_namespace\"; });\n    var d1B = bindings.filter(function(b){ return b.type === \"d1\" || b.type === \"d1_database\"; });\n    var r2B = bindings.filter(function(b){ return b.type === \"r2_bucket\"; });\n    var subOn = w.subdomainEnabled !== false;\n    var domains = w.domains || [];\n    var div = document.createElement(\"div\"); div.className = \"worker-row\";\n    var html = \"<div class=\\\"worker-info\\\"><div style=\\\"font-weight:700\\\">\" + esc(name) + \"</div>\";\n    if(w.defaultDomain){\n      html += \"<div class=\\\"worker-domains\\\" style=\\\"margin-top:8px\\\"><div class=\\\"small\\\">默认域名</div>\";\n      html += \"<a href=\\\"https://\" + escA(w.defaultDomain.hostname) + \"\\\" target=\\\"_blank\\\" class=\\\"domain-tag workers-dev\\\">\" + esc(w.defaultDomain.hostname) + \"<span class=\\\"domain-status \" + (subOn ? \"active\" : \"inactive\") + \"\\\">\" + (subOn ? \"已启用\" : \"已禁用\") + \"</span></a>\";\n      html += \"<label class=\\\"switch\\\" style=\\\"vertical-align:middle;margin-left:8px\\\"><input type=\\\"checkbox\\\" \" + (subOn ? \"checked\" : \"\") + \" data-subtoggle=\\\"\" + escA(name) + \"\\\"><span class=\\\"slider\\\"></span></label></div>\";\n    }\n    html += \"<div class=\\\"worker-domains\\\" style=\\\"margin-top:8px\\\"><div class=\\\"small\\\">自定义域名</div>\";\n    if(domains.length){\n      domains.forEach(function(dm){\n        var st = dm.status || \"active\";\n        html += \"<span style=\\\"display:inline-block;position:relative\\\"><a href=\\\"https://\" + escA(dm.hostname) + \"\\\" target=\\\"_blank\\\" class=\\\"domain-tag\\\">\" + esc(dm.hostname) + \"<span class=\\\"domain-status \" + (st === \"active\" ? \"active\" : \"pending\") + \"\\\">\" + (st === \"active\" ? \"已启用\" : esc(st)) + \"</span></a><span class=\\\"del-domain-btn\\\" title=\\\"解绑\\\" data-deldom=\\\"\" + escA(dm.id) + \"|\" + escA(name) + \"|\" + escA(dm.hostname) + \"\\\">✕</span></span>\";\n      });\n    } else { html += \"<span class=\\\"small\\\" style=\\\"color:#94a3b8\\\">暂无</span>\"; }\n    html += \"</div></div>\";\n    html += \"<div class=\\\"worker-right\\\"><div class=\\\"worker-tag-rows\\\">\";\n    html += tagRow(\"环境变量\", envB.map(function(b){\n      return b.type === \"secret_text\"\n        ? \"<span class=\\\"res-tag secret\\\" title=\\\"密钥\\\">\" + esc(b.name) + \"</span>\"\n        : \"<span class=\\\"res-tag env\\\">\" + esc(b.name) + \"</span>\";\n    }).join(\"\"));\n    html += tagRow(\"KV\", kvB.map(function(b){ return \"<span class=\\\"res-tag kv\\\">\" + esc(b.name) + \"</span>\"; }).join(\"\"));\n    html += tagRow(\"D1\", d1B.map(function(b){ return \"<span class=\\\"res-tag d1\\\">\" + esc(b.name) + \"</span>\"; }).join(\"\"));\n    var cronNames = (w.cronTriggers || []).map(function(c){ return typeof c === \"string\" ? c : (c.cron || \"\"); }).filter(function(c){ return !!c; });\n    html += tagRow(\"Cron\", cronNames.map(function(c){ return \"<span class=\\\"res-tag cron\\\">\" + esc(c) + \"</span>\"; }).join(\"\"));\n    if(r2B.length) html += tagRow(\"R2\", r2B.map(function(b){ return \"<span class=\\\"res-tag r2\\\">\" + esc(b.name) + \"</span>\"; }).join(\"\"));\n    html += \"</div><div class=\\\"btns\\\">\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"env\\\" data-name=\\\"\" + escA(name) + \"\\\">环境</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"bind\\\" data-name=\\\"\" + escA(name) + \"\\\">绑定</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"compat\\\" data-name=\\\"\" + escA(name) + \"\\\">兼容日期</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"compatflags\\\" data-name=\\\"\" + escA(name) + \"\\\">兼容标志</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"cron\\\" data-name=\\\"\" + escA(name) + \"\\\">Cron</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"domain\\\" data-name=\\\"\" + escA(name) + \"\\\">域名</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"versions\\\" data-name=\\\"\" + escA(name) + \"\\\">版本</button>\";\n    html += \"<button class=\\\"btn\\\" data-act=\\\"edit\\\" data-name=\\\"\" + escA(name) + \"\\\">编辑</button>\";\n    html += \"<button class=\\\"btn danger\\\" data-act=\\\"delete\\\" data-name=\\\"\" + escA(name) + \"\\\">删除</button>\";\n    html += \"</div></div>\";\n    div.innerHTML = html;\n    list.appendChild(div);\n  });\n  Array.from(list.querySelectorAll(\"[data-subtoggle]\")).forEach(function(cb){\n    cb.addEventListener(\"change\", function(){ toggleWorkerSubdomain(this.getAttribute(\"data-subtoggle\"), this.checked); });\n  });\n  Array.from(list.querySelectorAll(\"[data-deldom]\")).forEach(function(s){\n    s.addEventListener(\"click\", function(){\n      var parts = this.getAttribute(\"data-deldom\").split(\"|\");\n      deleteWorkerDomain(parts[1], parts[0], parts[2]);\n    });\n  });\n  Array.from(list.querySelectorAll(\".btns .btn\")).forEach(function(b){\n    b.addEventListener(\"click\", function(){\n      var act = this.getAttribute(\"data-act\"), nm = this.getAttribute(\"data-name\");\n      if(act === \"env\") openEnvFor(nm);\n      else if(act === \"bind\") openBindFor(nm);\n      else if(act === \"compat\") openCompatModal(nm);\n      else if(act === \"compatflags\") openCompatFlagsModal(nm);\n      else if(act === \"cron\") openCronModal(nm);\n      else if(act === \"domain\") openAddDomainModal(nm);\n      else if(act === \"versions\") openVersionsFor(nm);\n      else if(act === \"edit\") editWorker(nm);\n      else if(act === \"delete\") deleteWorker(nm);\n    });\n  });\n  updateWorkerMetrics();\n}\nasync function updateWorkerMetrics(){\n  try {\n    var r = await api(\"get-usage-today\", { accountId: currentAccountId });\n    if(r && r.success && r.data){\n      el(\"metricCount\").textContent = r.data.total.toLocaleString() + \" / 100,000\";\n      el(\"metricBar\").style.width = r.data.percentage + \"%\";\n      el(\"metricSub\").textContent = \"Workers \" + r.data.workers.toLocaleString() + \" · Pages \" + r.data.pages.toLocaleString();\n    }\n  } catch(e){}\n}\nasync function toggleWorkerSubdomain(name, enabled){\n  var r = await api(\"toggle-worker-subdomain\", { accountId: currentAccountId, scriptName: name, enabled: enabled });\n  if(r && r.success){ showNotification(enabled ? \"workers.dev 已启用\" : \"workers.dev 已禁用\"); setTimeout(refreshWorkers, 800); }\n  else { showNotification((r && r.error) || \"操作失败\", \"error\"); refreshWorkers(); }\n}\nwindow.toggleWorkerSubdomain = toggleWorkerSubdomain;\nvar currentWorkerForDomain = \"\";\nvar domainZonesCache = [];\nasync function openAddDomainModal(name){\n  currentWorkerForDomain = name; el(\"newDomainPrefix\").value = \"\"; domainZonesCache = [];\n  el(\"addDomainModal\").style.display = \"flex\";\n  el(\"domainZoneWrap\").innerHTML = '<div class=\"small\">加载域名中...</div>'; updateDomainPreview();\n  var r = await api(\"list-zones\");\n  var zones = (r && r.success && r.result) ? r.result : [];\n  domainZonesCache = zones.map(function(z){ return z.name; });\n  if(!zones.length) el(\"domainZoneWrap\").innerHTML = '<div class=\"small\" style=\"color:#ef4444\">该账号下没有可用域名，请先到「域名管理」添加</div>';\n  else if(zones.length === 1) el(\"domainZoneWrap\").innerHTML = '<div style=\"font-size:15px;font-weight:600\">' + esc(zones[0].name) + '</div>';\n  else {\n    var opts = zones.map(function(z){ return '<option value=\"' + esc(z.name) + '\">' + esc(z.name) + '</option>'; }).join(\"\");\n    el(\"domainZoneWrap\").innerHTML = '<select id=\"newDomainZone\" class=\"input\" onchange=\"updateDomainPreview()\">' + opts + '</select>';\n  }\n  updateDomainPreview();\n}\nfunction updateDomainPreview(){\n  var prefix = el(\"newDomainPrefix\").value.trim().replace(/\\.$/, \"\");\n  var zone = \"\", sel = el(\"newDomainZone\");\n  if(sel) zone = sel.value; else if(domainZonesCache.length === 1) zone = domainZonesCache[0];\n  el(\"domainPreview\").textContent = prefix ? (prefix + \".\" + zone) : zone;\n}\nfunction closeAddDomainModal(){ el(\"addDomainModal\").style.display = \"none\"; currentWorkerForDomain = \"\"; }\nasync function confirmAddDomain(){\n  var prefix = el(\"newDomainPrefix\").value.trim().replace(/\\.$/, \"\");\n  var zone = \"\", sel = el(\"newDomainZone\");\n  if(sel) zone = sel.value; else if(domainZonesCache.length === 1) zone = domainZonesCache[0];\n  if(!zone) return showNotification(\"没有可用域名\", \"error\");\n  var h = prefix ? (prefix + \".\" + zone) : zone;\n  var r = await api(\"add-worker-domain\", { accountId: currentAccountId, scriptName: currentWorkerForDomain, hostname: h });\n  if(r && r.success){ showNotification(\"域名绑定成功\"); closeAddDomainModal(); refreshWorkers(); }\n  else showNotification((r && r.error) || \"绑定失败\", \"error\");\n}\nasync function deleteWorkerDomain(scriptName, domainId, hostname){ \n  if(!confirm(\"确定解绑域名 \" + hostname + \" 吗？\")) return;\n  var r = await api(\"delete-worker-domain\", { accountId: currentAccountId, scriptName: scriptName, domainId: domainId });\n  if(r && r.success){ showNotification(\"域名已解绑\"); refreshWorkers(); }\n  else showNotification((r && r.error) || \"解绑失败\", \"error\");\n}\nwindow.openAddDomainModal = openAddDomainModal; window.closeAddDomainModal = closeAddDomainModal;\nwindow.confirmAddDomain = confirmAddDomain; window.deleteWorkerDomain = deleteWorkerDomain; window.updateDomainPreview = updateDomainPreview;\nfunction openCreateWorker(){ el(\"createName\").value = \"\"; el(\"createName\").readOnly = false; el(\"createScript\").value = DEFAULT_WORKER_SCRIPT; el(\"createModal\").style.display = \"flex\"; }\nfunction closeCreate(){ el(\"createModal\").style.display = \"none\"; }\nasync function confirmCreate(){\n  var name = el(\"createName\").value.trim(), script = el(\"createScript\").value;\n  if(!name) return showNotification(\"请输入 Worker 名称\", \"error\");\n  var r = await api(\"deploy-worker\", { accountId: currentAccountId, scriptName: name, scriptSource: script, metadataBindings: [] });\n  if(r && r.success){ saveWorkerDeployHistory(name, script); showNotification(\"部署成功\"); closeCreate(); setTimeout(refreshWorkers, 800); }\n  else { showNotification((r && r.error) || \"部署失败\", \"error\"); debugOut(r); }\n}\nasync function editWorker(name){\n  var r = await api(\"get-worker-script\", { accountId: currentAccountId, scriptName: name });\n  if(r && r.rawScript !== undefined){ el(\"createName\").value = name; el(\"createName\").readOnly = true; el(\"createScript\").value = r.rawScript; el(\"createModal\").style.display = \"flex\"; }\n  else { showNotification(\"获取脚本失败\", \"error\"); debugOut(r); }\n}\nasync function deleteWorker(name){\n  if(!confirm(\"确定删除 Worker: \" + name + \" 吗？\")) return;\n  var r = await api(\"delete-worker\", { accountId: currentAccountId, scriptName: name });\n  if(r && r.success){ showNotification(\"删除成功\"); setTimeout(refreshWorkers, 600); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nwindow.openCreateWorker = openCreateWorker; window.closeCreate = closeCreate; window.confirmCreate = confirmCreate;\n// ---- 一键部署（新版新建 Worker）----\nfunction ensureQuickDeployModal(){\n  if(el(\"quickDeployModal\")) return;\n  var h = '<div id=\"quickDeployModal\" class=\"modal\"><div class=\"modal-box\">'\n    + '<div style=\"display:flex;justify-content:space-between;align-items:center\"><h3 style=\"margin:0\">一键部署</h3>'\n    + '<span style=\"cursor:pointer;font-size:18px;color:#94a3b8\" onclick=\"closeQuickDeploy()\">&#10005;</span></div>'\n    + '<div class=\"small\" style=\"margin:8px 0 14px\">账号里已有同名 Worker 会自动转为更新，没有则新建</div>'\n    + '<div class=\"label\">代码来源</div>'\n    + '<div style=\"display:flex;gap:18px;margin-bottom:10px;font-size:13px\">'\n    + '<label style=\"cursor:pointer\"><input type=\"radio\" name=\"qdSrc\" value=\"url\" checked onchange=\"qdSwitchSrc()\"> 直链</label>'\n    + '<label style=\"cursor:pointer\"><input type=\"radio\" name=\"qdSrc\" value=\"editor\" onchange=\"qdSwitchSrc()\"> 编辑框</label>'\n    + '<label style=\"cursor:pointer\"><input type=\"radio\" name=\"qdSrc\" value=\"file\" onchange=\"qdSwitchSrc()\"> 上传</label>'\n    + '</div>'\n    + '<div id=\"qdSrcUrl\"><input id=\"qdUrl\" class=\"input\" placeholder=\".js 直链\"></div>'\n    + '<div id=\"qdSrcEditor\" style=\"display:none\"><textarea id=\"qdEditor\" class=\"input\" rows=\"12\" style=\"min-height:240px;font-size:13px\" placeholder=\"在此粘贴 Worker 脚本\"></textarea></div>'\n    + '<div id=\"qdSrcFile\" style=\"display:none\"><input type=\"file\" id=\"qdFile\" accept=\".js,.zip\" class=\"input\"></div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">项目名</div>'\n    + '<input id=\"qdName\" class=\"input\" placeholder=\"例如: my-worker\" oninput=\"qdAutoHostname()\">'\n    + '<div class=\"small\" style=\"margin-top:4px\">将以此名称新建 Worker（账号里已有同名则转为更新）</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">环境变量 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdEnvList\"></div>'\n    + '<button class=\"btn small\" style=\"margin-top:6px\" onclick=\"qdAddEnvRow()\">+ 添加变量</button>'\n    + '<div class=\"label\" style=\"margin-top:14px\">KV 绑定 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdKvList\"></div>'\n    + '<div style=\"margin-top:6px\"><button class=\"btn small\" onclick=\"qdAddKvRow()\">+ 添加 KV</button></div>'\n    + '<div class=\"small\" style=\"margin-top:4px\">下拉选择已有命名空间；没有想要的就在右侧输入新名称，会自动创建</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">D1 数据库 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdD1List\"></div>'\n    + '<div style=\"margin-top:6px\"><button class=\"btn small\" onclick=\"qdAddD1Row()\">+ 添加 D1</button></div>'\n    + '<div class=\"small\" style=\"margin-top:4px\">下拉选择已有数据库；没有想要的就在右侧输入新名称，会自动创建并绑定</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">项目域名 <span class=\"small\">（可选）</span></div>'\n    + '<input id=\"qdHostname\" class=\"input\" placeholder=\"留空则自动生成：项目名.所选域名\" oninput=\"this.dataset.manual=\\'1\\'\">'\n    + '<div class=\"label\" style=\"margin-top:14px\">域名列表</div>'\n    + '<select id=\"qdZone\" class=\"input\" onchange=\"qdAutoHostname()\"><option value=\"\">不绑定域名</option></select>'\n    + '<div class=\"small\" style=\"margin-top:4px\">账号接入的 CF 域名，选定后自动生成上方未填写的域名</div>'\n    + '<div style=\"display:flex;align-items:center;gap:10px;margin-top:14px\"><span class=\"label\" style=\"margin:0\">分配域名</span>'\n    + '<label class=\"switch\"><input type=\"checkbox\" id=\"qdAssignDomain\" checked><span class=\"slider\"></span></label>'\n    + '<span class=\"small\">开启后分配 workers.dev 域名；选择自定义域名时自动关闭</span></div>'\n    + '<div id=\"qdStatus\" class=\"small\" style=\"margin-top:12px;color:#1e40af\"></div>'\n    + '<div style=\"display:flex;gap:8px;margin-top:12px\"><button class=\"btn primary\" id=\"qdDeployBtn\" onclick=\"confirmQuickDeploy()\">开始部署</button><button class=\"btn\" onclick=\"closeQuickDeploy()\">取消</button></div>'\n    + '</div></div>';\n  document.body.insertAdjacentHTML(\"beforeend\", h);\n  var m = el(\"quickDeployModal\");\n  m.addEventListener(\"click\", function(e){ if(e.target === m) closeQuickDeploy(); });\n}\nfunction openQuickDeploy(){\n  ensureQuickDeployModal();\n  el(\"qdName\").value = \"\"; el(\"qdUrl\").value = \"\"; el(\"qdEditor\").value = \"\";\n  el(\"qdEnvList\").innerHTML = \"\"; el(\"qdKvList\").innerHTML = \"\"; el(\"qdD1List\").innerHTML = \"\";\n  el(\"qdHostname\").value = \"\"; el(\"qdHostname\").dataset.manual = \"\";\n  el(\"qdAssignDomain\").checked = true;\n  el(\"qdFile\").value = \"\"; el(\"qdStatus\").textContent = \"\";\n  document.querySelector('input[name=\"qdSrc\"][value=\"url\"]').checked = true; qdSwitchSrc();\n  qdLoadZones();\n  qdLoadKvOptions(true); qdLoadD1Options(true);\n  el(\"quickDeployModal\").style.display = \"flex\";\n}\n// ---- 一键部署：环境变量 / KV / D1 行 ----\nfunction qdAddEnvRow(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px\";\n  d.innerHTML = '<input class=\"input qd-env-name\" placeholder=\"变量名\" style=\"flex:1\"><input class=\"input qd-env-val\" placeholder=\"变量值\" style=\"flex:2\"><button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdEnvList\").appendChild(d);\n}\n// 一键部署 KV/D1 下拉（样式对齐\"绑定资源\"弹窗：名称 (ID)；右侧可输新名称自动创建）\nvar qdKvCache = [], qdD1Cache = [];\nfunction qdToggleKvRow(sel){\n  var row = sel.parentNode;\n  var nw = row.querySelector(\".qd-kv-new\"), bn = row.querySelector(\".qd-kv-bind\");\n  var hasSel = !!sel.value;\n  nw.style.display = hasSel ? \"none\" : \"\";\n  bn.style.display = hasSel ? \"\" : \"none\";\n}\nfunction qdAddKvRow(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px;align-items:center\";\n  d.innerHTML = '<select class=\"input qd-kv-sel\" style=\"flex:2;min-width:140px\" onchange=\"qdToggleKvRow(this)\"><option value=\"\">— 下拉选择已有 —</option></select>'\n    + '<input class=\"input qd-kv-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:140px\">'\n    + '<input class=\"input qd-kv-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:90px;display:none\">'\n    + '<button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdKvList\").appendChild(d);\n  qdRefreshKvSelects();\n}\nfunction qdToggleD1Row(sel){\n  var row = sel.parentNode;\n  var nw = row.querySelector(\".qd-d1-new\"), bn = row.querySelector(\".qd-d1-bind\");\n  var hasSel = !!sel.value;\n  nw.style.display = hasSel ? \"none\" : \"\";\n  bn.style.display = hasSel ? \"\" : \"none\";\n}\nfunction qdAddD1Row(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px;align-items:center\";\n  d.innerHTML = '<select class=\"input qd-d1-sel\" style=\"flex:2;min-width:140px\" onchange=\"qdToggleD1Row(this)\"><option value=\"\">— 下拉选择已有 —</option></select>'\n    + '<input class=\"input qd-d1-new\" placeholder=\"或输入新名称，自动创建并绑定\" style=\"flex:2;min-width:140px\">'\n    + '<input class=\"input qd-d1-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:90px;display:none\">'\n    + '<button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdD1List\").appendChild(d);\n  qdRefreshD1Selects();\n}\nfunction qdRefreshKvSelects(){\n  Array.from(document.querySelectorAll(\".qd-kv-sel\")).forEach(function(sel){\n    var cur = sel.value;\n    sel.innerHTML = '<option value=\"\">— 下拉选择已有 —</option>';\n    qdKvCache.forEach(function(ns){\n      var o = document.createElement(\"option\");\n      o.value = ns.title;\n      o.textContent = (ns.title || ns.id) + \" (\" + ns.id + \")\";\n      sel.appendChild(o);\n    });\n    sel.value = cur;\n  });\n}\nfunction qdRefreshD1Selects(){\n  Array.from(document.querySelectorAll(\".qd-d1-sel\")).forEach(function(sel){\n    var cur = sel.value;\n    sel.innerHTML = '<option value=\"\">— 下拉选择已有 —</option>';\n    qdD1Cache.forEach(function(db){\n      var o = document.createElement(\"option\");\n      o.value = db.name;\n      o.textContent = (db.name || db.uuid || db.id) + \" (\" + (db.uuid || db.id) + \")\";\n      sel.appendChild(o);\n    });\n    sel.value = cur;\n  });\n}\nasync function qdLoadKvOptions(silent){\n  try {\n    var r = await api(\"list-kv-namespaces\", { accountId: currentAccountId });\n    qdKvCache = r.result || [];\n  } catch(e){ qdKvCache = []; }\n  qdRefreshKvSelects();\n  if(!silent) showNotification(qdKvCache.length ? (\"已加载 \" + qdKvCache.length + \" 个 KV 命名空间\") : \"没有 KV 命名空间，可直接输入名称创建\");\n}\nasync function qdLoadD1Options(silent){\n  try {\n    var r = await api(\"list-d1\", { accountId: currentAccountId });\n    qdD1Cache = r.result || [];\n  } catch(e){ qdD1Cache = []; }\n  qdRefreshD1Selects();\n  if(!silent) showNotification(qdD1Cache.length ? (\"已加载 \" + qdD1Cache.length + \" 个 D1 数据库\") : \"没有 D1 数据库，可直接输入名称创建\");\n}\nwindow.qdAddEnvRow = qdAddEnvRow; window.qdAddKvRow = qdAddKvRow; window.qdAddD1Row = qdAddD1Row;\nwindow.qdToggleKvRow = qdToggleKvRow; window.qdToggleD1Row = qdToggleD1Row;\nwindow.qdLoadKvOptions = qdLoadKvOptions; window.qdLoadD1Options = qdLoadD1Options;\nfunction closeQuickDeploy(){ var m = el(\"quickDeployModal\"); if(m) m.style.display = \"none\"; }\nfunction qdSwitchSrc(){\n  var v = document.querySelector('input[name=\"qdSrc\"]:checked').value;\n  el(\"qdSrcUrl\").style.display = v === \"url\" ? \"\" : \"none\";\n  el(\"qdSrcEditor\").style.display = v === \"editor\" ? \"\" : \"none\";\n  el(\"qdSrcFile\").style.display = v === \"file\" ? \"\" : \"none\";\n}\nasync function qdLoadZones(){\n  var sel = el(\"qdZone\");\n  sel.innerHTML = '<option value=\"\">不绑定域名</option>';\n  try {\n    var r = await api(\"list-zones\", {});\n    (r.result || []).forEach(function(z){\n      var o = document.createElement(\"option\"); o.value = z.name; o.textContent = z.name; sel.appendChild(o);\n    });\n  } catch(e){}\n}\nfunction qdAutoHostname(){\n  var hostEl = el(\"qdHostname\");\n  var zone = el(\"qdZone\").value;\n  var assignEl = el(\"qdAssignDomain\");\n  if(assignEl) assignEl.checked = !zone;\n  if(hostEl.dataset.manual === \"1\") return;\n  var name = el(\"qdName\").value.trim().toLowerCase().replace(/[^a-z0-9-]/g, \"\");\n  hostEl.value = (zone && name) ? (name + \".\" + zone) : \"\";\n}\nfunction qdFileToText(f){\n  return new Promise(function(res, rej){\n    var r = new FileReader(); r.onload = function(){ res(r.result); }; r.onerror = rej; r.readAsText(f);\n  });\n}\nfunction qdFileToBase64(f){\n  return new Promise(function(res, rej){\n    var r = new FileReader();\n    r.onload = function(){ var s = String(r.result); res(s.slice(s.indexOf(\",\") + 1)); };\n    r.onerror = rej; r.readAsDataURL(f);\n  });\n}\nasync function confirmQuickDeploy(){\n  var name = el(\"qdName\").value.trim();\n  if(!name) return showNotification(\"请输入项目名\", \"error\");\n  var src = document.querySelector('input[name=\"qdSrc\"]:checked').value;\n  var payload = { accountId: currentAccountId, scriptName: name };\n  if(src === \"url\"){\n    var url = el(\"qdUrl\").value.trim();\n    if(!url) return showNotification(\"请输入直链\", \"error\");\n    payload.sourceKind = \"url\"; payload.sourceUrl = url;\n  } else if(src === \"editor\"){\n    var text = el(\"qdEditor\").value;\n    if(!text.trim()) return showNotification(\"请填写脚本内容\", \"error\");\n    payload.sourceKind = \"text\"; payload.sourceText = text;\n  } else {\n    var f = el(\"qdFile\").files[0];\n    if(!f) return showNotification(\"请选择文件\", \"error\");\n    if(/\\.zip$/i.test(f.name)){ payload.sourceKind = \"b64zip\"; payload.sourceB64 = await qdFileToBase64(f); }\n    else { payload.sourceKind = \"text\"; payload.sourceText = await qdFileToText(f); }\n  }\n  var envVars = [];\n  Array.from(document.querySelectorAll(\"#qdEnvList .qd-env-name\")).forEach(function(inp, i){\n    var n = inp.value.trim();\n    if(n) envVars.push({ name: n, value: document.querySelectorAll(\"#qdEnvList .qd-env-val\")[i].value });\n  });\n  if(envVars.length) payload.envVars = envVars;\n  var kvList = [];\n  Array.from(document.querySelectorAll(\"#qdKvList > div\")).forEach(function(row){\n    var sel = row.querySelector(\".qd-kv-sel\"), nw = row.querySelector(\".qd-kv-new\"), bn = row.querySelector(\".qd-kv-bind\");\n    var ns = (nw.value.trim() || sel.value || \"\").trim();\n    if(ns) kvList.push({ nsName: ns, bindName: bn.value.trim() });\n  });\n  if(kvList.length) payload.kvList = kvList;\n  var d1List = [];\n  Array.from(document.querySelectorAll(\"#qdD1List > div\")).forEach(function(row){\n    var sel = row.querySelector(\".qd-d1-sel\"), nw = row.querySelector(\".qd-d1-new\"), bn = row.querySelector(\".qd-d1-bind\");\n    var n = (nw.value.trim() || sel.value || \"\").trim();\n    if(n) d1List.push({ name: n, bindName: bn.value.trim() });\n  });\n  if(d1List.length) payload.d1List = d1List;\n  var host = el(\"qdHostname\").value.trim();\n  if(host) payload.hostname = host;\n  payload.assignDomain = el(\"qdAssignDomain\").checked;\n  var btn = el(\"qdDeployBtn\");\n  btn.disabled = true; btn.textContent = \"部署中...\";\n  el(\"qdStatus\").textContent = \"正在部署，请稍候...\";\n  try {\n    var r = await api(\"quick-deploy\", payload);\n    if(r && r.success){\n      el(\"qdStatus\").textContent = (r.notes || []).join(\"；\");\n      showNotification(\"部署成功\");\n      setTimeout(function(){ closeQuickDeploy(); refreshWorkers(); }, 1500);\n    } else {\n      el(\"qdStatus\").textContent = \"\";\n      showNotification((r && r.error) || \"部署失败\", \"error\");\n    }\n  } catch(e){ showNotification(\"请求失败\", \"error\"); }\n  btn.disabled = false; btn.textContent = \"开始部署\";\n}\nwindow.openQuickDeploy = openQuickDeploy; window.closeQuickDeploy = closeQuickDeploy;\nwindow.qdSwitchSrc = qdSwitchSrc; window.qdAutoHostname = qdAutoHostname; window.confirmQuickDeploy = confirmQuickDeploy;\n// ---- 一键部署：Pages 独立弹窗 ----\nfunction ensureQuickDeployPagesModal(){\n  if(el(\"quickDeployPagesModal\")) return;\n  var h = '<div id=\"quickDeployPagesModal\" class=\"modal\"><div class=\"modal-box\">'\n    + '<div style=\"display:flex;justify-content:space-between;align-items:center\"><h3 style=\"margin:0\">一键部署</h3>'\n    + '<span style=\"cursor:pointer;font-size:18px;color:#94a3b8\" onclick=\"closeQuickDeployPages()\">&#10005;</span></div>'\n    + '<div class=\"small\" style=\"margin:8px 0 14px\">账号里已有同名 Pages 项目会自动转为更新（重新部署），没有则新建</div>'\n    + '<div class=\"label\">代码来源</div>'\n    + '<div style=\"display:flex;gap:18px;margin-bottom:10px;font-size:13px\">'\n    + '<label style=\"cursor:pointer\"><input type=\"radio\" name=\"qdPagesSrc\" value=\"url\" checked onchange=\"qdPagesSwitchSrc()\"> 直链</label>'\n    + '<label style=\"cursor:pointer\"><input type=\"radio\" name=\"qdPagesSrc\" value=\"file\" onchange=\"qdPagesSwitchSrc()\"> 上传</label>'\n    + '</div>'\n    + '<div id=\"qdPagesSrcUrl\"><input id=\"qdPagesUrl\" class=\"input\" placeholder=\".zip 直链\"></div>'\n    + '<div id=\"qdPagesSrcFile\" style=\"display:none\"><input type=\"file\" id=\"qdPagesFiles\" multiple class=\"input\"><div class=\"small\" style=\"margin-top:4px\">可多选文件；单个 .zip 包会自动解包</div></div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">项目名</div>'\n    + '<input id=\"qdPagesName\" class=\"input\" placeholder=\"例如: my-site\" oninput=\"qdPagesAutoHostname()\">'\n    + '<div class=\"small\" style=\"margin-top:4px\">仅小写字母、数字、连字符；已有同名则转为更新</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">分支</div>'\n    + '<input id=\"qdPagesBranch\" class=\"input\" placeholder=\"main\" style=\"max-width:200px\">'\n    + '<div class=\"label\" style=\"margin-top:14px\">环境变量 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdPagesEnvList\"></div>'\n    + '<button class=\"btn small\" style=\"margin-top:6px\" onclick=\"qdPagesAddEnvRow()\">+ 添加变量</button>'\n    + '<div class=\"label\" style=\"margin-top:14px\">KV 绑定 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdPagesKvList\"></div>'\n    + '<div style=\"margin-top:6px\"><button class=\"btn small\" onclick=\"qdPagesAddKvRow()\">+ 添加 KV</button></div>'\n    + '<div class=\"small\" style=\"margin-top:4px\">下拉选择已有命名空间；没有想要的就在右侧输入新名称，会自动创建</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">D1 数据库 <span class=\"small\">（可选）</span></div>'\n    + '<div id=\"qdPagesD1List\"></div>'\n    + '<div style=\"margin-top:6px\"><button class=\"btn small\" onclick=\"qdPagesAddD1Row()\">+ 添加 D1</button></div>'\n    + '<div class=\"small\" style=\"margin-top:4px\">下拉选择已有数据库；没有想要的就在右侧输入新名称，会自动创建并绑定</div>'\n    + '<div class=\"label\" style=\"margin-top:14px\">项目域名 <span class=\"small\">（可选）</span></div>'\n    + '<input id=\"qdPagesHostname\" class=\"input\" placeholder=\"留空则自动生成：项目名.所选域名\" oninput=\"this.dataset.manual=\\'1\\'\">'\n    + '<div class=\"label\" style=\"margin-top:14px\">域名列表</div>'\n    + '<select id=\"qdPagesZone\" class=\"input\" onchange=\"qdPagesAutoHostname()\"><option value=\"\">不绑定域名</option></select>'\n    + '<div class=\"small\" style=\"margin-top:4px\">账号接入的 CF 域名，选定后自动生成上方未填写的域名</div>'\n    + '<div id=\"qdPagesStatus\" class=\"small\" style=\"margin-top:12px;color:#1e40af\"></div>'\n    + '<div style=\"display:flex;gap:8px;margin-top:12px\"><button class=\"btn primary\" id=\"qdPagesDeployBtn\" onclick=\"confirmQuickDeployPages()\">开始部署</button><button class=\"btn\" onclick=\"closeQuickDeployPages()\">取消</button></div>'\n    + '</div></div>';\n  document.body.insertAdjacentHTML(\"beforeend\", h);\n}\nfunction openQuickDeployPages(){\n  ensureQuickDeployPagesModal();\n  el(\"qdPagesName\").value = \"\"; el(\"qdPagesUrl\").value = \"\"; el(\"qdPagesBranch\").value = \"\";\n  el(\"qdPagesFiles\").value = \"\"; el(\"qdPagesStatus\").textContent = \"\";\n  el(\"qdPagesEnvList\").innerHTML = \"\"; el(\"qdPagesKvList\").innerHTML = \"\"; el(\"qdPagesD1List\").innerHTML = \"\";\n  el(\"qdPagesHostname\").value = \"\"; el(\"qdPagesHostname\").dataset.manual = \"\";\n  document.querySelector('input[name=\"qdPagesSrc\"][value=\"url\"]').checked = true; qdPagesSwitchSrc();\n  el(\"quickDeployPagesModal\").style.display = \"flex\";\n  qdLoadKvOptions(); qdLoadD1Options(); qdPagesLoadZones();\n}\n// ---- Pages 一键部署：环境变量/KV/D1/域名 ----\nfunction qdPagesAddEnvRow(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px\";\n  d.innerHTML = '<input class=\"input qd-env-name\" placeholder=\"变量名\" style=\"flex:1\"><input class=\"input qd-env-val\" placeholder=\"值\" style=\"flex:2\"><button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdPagesEnvList\").appendChild(d);\n}\nfunction qdPagesAddKvRow(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px;align-items:center\";\n  d.innerHTML = '<select class=\"input qd-kv-sel\" style=\"flex:2;min-width:140px\" onchange=\"qdToggleKvRow(this)\"><option value=\"\">— 下拉选择已有 —</option></select>'\n    + '<input class=\"input qd-kv-new\" placeholder=\"或输入新名称，自动创建\" style=\"flex:2;min-width:140px\">'\n    + '<input class=\"input qd-kv-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:90px;display:none\">'\n    + '<button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdPagesKvList\").appendChild(d);\n  qdRefreshKvSelects();\n}\nfunction qdPagesAddD1Row(){\n  var d = document.createElement(\"div\");\n  d.style.cssText = \"display:flex;gap:8px;margin-top:6px;align-items:center\";\n  d.innerHTML = '<select class=\"input qd-d1-sel\" style=\"flex:2;min-width:140px\" onchange=\"qdToggleD1Row(this)\"><option value=\"\">— 下拉选择已有 —</option></select>'\n    + '<input class=\"input qd-d1-new\" placeholder=\"或输入新名称，自动创建并绑定\" style=\"flex:2;min-width:140px\">'\n    + '<input class=\"input qd-d1-bind\" placeholder=\"绑定名(留空自动)\" style=\"flex:1;min-width:90px;display:none\">'\n    + '<button class=\"btn small\" onclick=\"this.parentNode.remove()\">✕</button>';\n  el(\"qdPagesD1List\").appendChild(d);\n  qdRefreshD1Selects();\n}\nasync function qdPagesLoadZones(){\n  var sel = el(\"qdPagesZone\");\n  sel.innerHTML = '<option value=\"\">不绑定域名</option>';\n  try {\n    var r = await api(\"list-zones\", {});\n    (r.result || []).forEach(function(z){\n      var o = document.createElement(\"option\"); o.value = z.name; o.textContent = z.name; sel.appendChild(o);\n    });\n  } catch(e){}\n}\nfunction qdPagesAutoHostname(){\n  var hostEl = el(\"qdPagesHostname\");\n  if(hostEl.dataset.manual === \"1\") return;\n  var zone = el(\"qdPagesZone\").value;\n  var name = el(\"qdPagesName\").value.trim().toLowerCase().replace(/[^a-z0-9-]/g, \"\");\n  hostEl.value = (zone && name) ? (name + \".\" + zone) : \"\";\n}\nwindow.qdPagesAddEnvRow = qdPagesAddEnvRow; window.qdPagesAddKvRow = qdPagesAddKvRow;\nwindow.qdPagesAddD1Row = qdPagesAddD1Row; window.qdPagesLoadZones = qdPagesLoadZones;\nwindow.qdPagesAutoHostname = qdPagesAutoHostname;\nfunction closeQuickDeployPages(){ el(\"quickDeployPagesModal\").style.display = \"none\"; }\nfunction qdPagesSwitchSrc(){\n  var v = document.querySelector('input[name=\"qdPagesSrc\"]:checked').value;\n  el(\"qdPagesSrcUrl\").style.display = v === \"url\" ? \"\" : \"none\";\n  el(\"qdPagesSrcFile\").style.display = v === \"file\" ? \"\" : \"none\";\n}\nfunction qdReadFilesAsBase64(files){\n  return Promise.all(Array.from(files).map(function(f){\n    return new Promise(function(res, rej){\n      var r = new FileReader();\n      r.onload = function(){ var s = String(r.result); res({ path: \"/\" + (f.webkitRelativePath || f.name), content: s.slice(s.indexOf(\",\") + 1) }); };\n      r.onerror = rej; r.readAsDataURL(f);\n    });\n  }));\n}\nasync function confirmQuickDeployPages(){\n  var name = el(\"qdPagesName\").value.trim().toLowerCase();\n  if(!name) return showNotification(\"请输入项目名\", \"error\");\n  if(!/^[a-z0-9][a-z0-9-]*$/.test(name) || name.length > 63) return showNotification(\"项目名不合法：仅小写字母、数字、连字符\", \"error\");\n  var src = document.querySelector('input[name=\"qdPagesSrc\"]:checked').value;\n  var payload = { accountId: currentAccountId, projectName: name, branch: el(\"qdPagesBranch\").value.trim() || \"main\" };\n  var envVars = [];\n  Array.from(document.querySelectorAll(\"#qdPagesEnvList > div\")).forEach(function(row){\n    var n = row.querySelector(\".qd-env-name\").value.trim(), v = row.querySelector(\".qd-env-val\").value;\n    if(n) envVars.push({ name: n, value: v });\n  });\n  if(envVars.length) payload.envVars = envVars;\n  var kvList = [];\n  Array.from(document.querySelectorAll(\"#qdPagesKvList > div\")).forEach(function(row){\n    var sel = row.querySelector(\".qd-kv-sel\"), nw = row.querySelector(\".qd-kv-new\"), bn = row.querySelector(\".qd-kv-bind\");\n    var n = (nw.value.trim() || sel.value || \"\").trim();\n    if(n) kvList.push({ name: n, bindName: bn.value.trim() });\n  });\n  if(kvList.length) payload.kvList = kvList;\n  var d1List = [];\n  Array.from(document.querySelectorAll(\"#qdPagesD1List > div\")).forEach(function(row){\n    var sel = row.querySelector(\".qd-d1-sel\"), nw = row.querySelector(\".qd-d1-new\"), bn = row.querySelector(\".qd-d1-bind\");\n    var n = (nw.value.trim() || sel.value || \"\").trim();\n    if(n) d1List.push({ name: n, bindName: bn.value.trim() });\n  });\n  if(d1List.length) payload.d1List = d1List;\n  var host = el(\"qdPagesHostname\").value.trim();\n  if(host) payload.hostname = host;\n  if(src === \"url\"){\n    var url = el(\"qdPagesUrl\").value.trim();\n    if(!url) return showNotification(\"请输入直链\", \"error\");\n    payload.sourceKind = \"url\"; payload.sourceUrl = url;\n  } else {\n    var fs = el(\"qdPagesFiles\").files;\n    if(!fs || !fs.length) return showNotification(\"请选择文件\", \"error\");\n    if(fs.length === 1 && /\\.zip$/i.test(fs[0].name)){\n      payload.sourceKind = \"b64zip\"; payload.sourceB64 = await qdFileToBase64(fs[0]);\n    } else {\n      payload.sourceKind = \"files\"; payload.files = await qdReadFilesAsBase64(fs);\n    }\n  }\n  var btn = el(\"qdPagesDeployBtn\");\n  btn.disabled = true; btn.textContent = \"部署中...\";\n  el(\"qdPagesStatus\").textContent = \"正在部署，请稍候...\";\n  try {\n    var r = await api(\"quick-deploy-pages\", payload);\n    if(r && r.success){\n      var msg = (r.notes && r.notes.length ? r.notes.join(\"；\") : \"Pages 部署成功\") + (r.url ? (\"；\" + r.url) : \"\");\n      el(\"qdPagesStatus\").textContent = msg + (r.warning ? (\"；\" + r.warning) : \"\");\n      showNotification(\"部署成功\");\n      setTimeout(function(){ closeQuickDeployPages(); }, 1500);\n    } else {\n      el(\"qdPagesStatus\").textContent = \"\";\n      showNotification((r && r.error) || \"部署失败\", \"error\");\n    }\n  } catch(e){ showNotification(\"请求失败\", \"error\"); }\n  btn.disabled = false; btn.textContent = \"开始部署\";\n}\nwindow.openQuickDeployPages = openQuickDeployPages; window.closeQuickDeployPages = closeQuickDeployPages;\nwindow.qdPagesSwitchSrc = qdPagesSwitchSrc; window.confirmQuickDeployPages = confirmQuickDeployPages;\nwindow.editWorker = editWorker; window.deleteWorker = deleteWorker;\n// 面板部署历史（localStorage）：用于 Worker 版本回滚\nfunction getWorkerDeployHistory(name){\n  try {\n    var h = JSON.parse(localStorage.getItem(\"cfm_worker_history_\" + name) || \"[]\");\n    return Array.isArray(h) ? h : [];\n  } catch(e){ return []; }\n}\nfunction saveWorkerDeployHistory(name, scriptSource){\n  try {\n    var h = getWorkerDeployHistory(name);\n    h.unshift({ time: new Date().toISOString(), source: scriptSource });\n    if(h.length > 20) h = h.slice(0, 20);\n    localStorage.setItem(\"cfm_worker_history_\" + name, JSON.stringify(h));\n  } catch(e){}\n}\nasync function rollbackWorkerToHistory(name, idx){\n  var h = getWorkerDeployHistory(name);\n  if(!h[idx]) return showNotification(\"历史记录不存在\", \"error\");\n  if(!confirm(\"回滚 Worker \" + name + \" 到 \" + fmtBJ(h[idx].time) + \" 的版本？\")) return;\n  showNotification(\"正在回滚...\", \"warning\");\n  var r = await api(\"deploy-worker\", { accountId: currentAccountId, scriptName: name, scriptSource: h[idx].source, metadataBindings: [] });\n  if(r && r.success){\n    showNotification(\"回滚成功\");\n    saveWorkerDeployHistory(name, h[idx].source);\n    closeVersionsModal(); setTimeout(refreshWorkers, 800);\n  } else showNotification((r && r.error) || \"回滚失败\", \"error\");\n}\nwindow.rollbackWorkerToHistory = rollbackWorkerToHistory;\nasync function rollbackWorkerVersion(name, versionId){\n  if(!confirm(\"将 Worker \" + name + \" 回滚到该版本？线上流量将切回此版本。\")) return;\n  showNotification(\"正在回滚...\", \"warning\");\n  var r = await api(\"rollback-worker-version\", { accountId: currentAccountId, scriptName: name, versionId: versionId });\n  if(r && r.success){ showNotification(\"回滚成功\"); closeVersionsModal(); setTimeout(refreshWorkers, 800); }\n  else showNotification((r && r.error) || \"回滚失败\", \"error\");\n}\nwindow.rollbackWorkerVersion = rollbackWorkerVersion;\nasync function openVersionsFor(name){\n  el(\"versionsSub\").textContent = name;\n  el(\"versionsList\").innerHTML = \"加载中...\";\n  el(\"versionsModal\").style.display = \"flex\";\n  var r = await api(\"list-worker-versions\", { accountId: currentAccountId, scriptName: name });\n  var html = \"\";\n  // 面板部署历史（可回滚）\n  var hist = getWorkerDeployHistory(name);\n  if(hist.length){\n    html += \"<h4 style=\\\"margin:0 0 8px\\\">面板部署历史 <span class=\\\"small\\\" style=\\\"color:#6b7280\\\">（可回滚）</span></h4>\";\n    html += \"<table class=\\\"table\\\"><thead><tr><th>部署时间</th><th>操作</th></tr></thead><tbody>\";\n    hist.forEach(function(hh, idx){\n      html += \"<tr><td>\" + esc(fmtBJ(hh.time)) + \"</td><td><button class=\\\"btn small\\\" onclick=\\\"rollbackWorkerToHistory('\" + escA(name) + \"', \" + idx + \")\\\">回滚</button></td></tr>\";\n    });\n    html += \"</tbody></table><div style=\\\"height:16px\\\"></div>\";\n  } else {\n    html += \"<div class=\\\"small\\\" style=\\\"color:#6b7280;margin-bottom:12px\\\">暂无面板部署历史（通过面板部署后会自动记录，可回滚）</div>\";\n  }\n  // Cloudflare 版本列表（仅展示）\n  html += \"<h4 style=\\\"margin:0 0 8px\\\">Cloudflare 版本记录</h4>\";\n  if(!r || !r.success){ html += \"<div class=\\\"small\\\">\" + esc((r && r.error) || \"获取失败\") + \"</div>\"; }\n  else {\n    var vers = r.result || [];\n    // 获取当前线上版本，用于标记\n    var curVid = \"\";\n    try {\n      var rc = await api(\"get-worker-current-version\", { accountId: currentAccountId, scriptName: name });\n      if(rc && rc.success && rc.currentVersionId) curVid = rc.currentVersionId;\n    } catch(e){}\n    if(!vers.length){ html += \"<div class=\\\"small\\\">暂无版本记录</div>\"; }\n    else {\n      html += \"<table class=\\\"table\\\"><thead><tr><th>版本 ID</th><th>创建时间</th><th>兼容日期</th><th>状态</th><th>操作</th></tr></thead><tbody>\";\n      vers.forEach(function(v){\n        var vid = v.id || \"\";\n        var isCur = curVid && vid === curVid;\n        html += \"<tr><td style=\\\"font-family:monospace;font-size:11px\\\">\" + esc(vid) + \"</td><td>\" + esc(fmtBJ(v.created_on)) + \"</td><td>\" + esc(v.compatibility_date || v.compatibilityDate || \"-\") + \"</td><td>\" + (isCur ? \"<span class=\\\"pill green\\\">当前</span>\" : \"\") + \"</td><td>\" + (isCur ? \"\" : \"<button class=\\\"btn small\\\" onclick=\\\"rollbackWorkerVersion('\" + escA(name) + \"', '\" + escA(vid) + \"')\\\">回滚</button>\") + \"</td></tr>\";\n      });\n      html += \"</tbody></table><div class=\\\"small\\\" style=\\\"color:#6b7280;margin-top:8px\\\">回滚将把线上流量切回所选版本（100%），无需重新上传代码</div>\";\n    }\n  }\n  el(\"versionsList\").innerHTML = html;\n}\nwindow.openVersionsFor = openVersionsFor;\nwindow.closeVersionsModal = function(){ el(\"versionsModal\").style.display = \"none\"; };\nvar currentCompatWorker = \"\";\nvar selectedCompatDate = \"\";\nvar COMPAT_DATE_LIST = [\n  { date: \"2026-09-11\", changes: [\"新建项目的默认兼容日期\"] },\n  { date: \"2026-08-04\", changes: [\"Node.js 兼容默认启用 (nodejs_compat / nodejs_compat_v2)\"] },\n  { date: \"2026-01-29\", changes: [\"Node.js stub 模块支持\"] },\n  { date: \"2026-01-22\", changes: [\"require_returns_default_export\"] },\n  { date: \"2026-01-20\", changes: [\"rpc_params_dup_stubs：RPC 参数中的 stub 改为复制而非转移所有权\"] },\n  { date: \"2024-09-23\", changes: [\"nodejs_compat v2 自动启用\"] },\n  { date: \"2022-03-21\", changes: [\"首个兼容日期\"] }\n];\nasync function openCompatModal(name){\n  currentCompatWorker = name; selectedCompatDate = \"\";\n  el(\"compatDateInput\").value = \"\";\n  el(\"compatModal\").style.display = \"flex\";\n  el(\"compatCurrentVal\").textContent = \"\";\n  renderCompatDateList(\"\");\n  try{\n    var r = await api(\"list-worker-versions\", { accountId: currentAccountId, scriptName: name });\n    var vers = (r && r.result) || [];\n    var cd = vers.length ? (vers[0].compatibility_date || vers[0].compatibilityDate || \"\") : \"\";\n    var m = String(cd).match(/^(\\d{4}-\\d{2}-\\d{2})/);\n    if(m){ selectedCompatDate = m[1]; el(\"compatDateInput\").value = m[1]; el(\"compatCurrentVal\").textContent = \"（当前: \" + m[1] + \"）\"; renderCompatDateList(m[1]); }\n  }catch(e){}\n}\nfunction renderCompatDateList(activeDate){\n  var html = \"\";\n  COMPAT_DATE_LIST.forEach(function(item){\n    var isActive = item.date === activeDate;\n    html += \"<div data-cdate=\\\"\" + item.date + \"\\\" style=\\\"border:1px solid \" + (isActive ? \"#2563eb\" : \"#e6edf3\") + \";border-radius:8px;padding:12px;margin-bottom:8px;cursor:pointer;background:\" + (isActive ? \"#eff6ff\" : \"#fff\") + \"\\\">\";\n    html += \"<div style=\\\"font-weight:600;font-size:14px\\\">\\uD83D\\uDCC5 \" + esc(item.date) + \"</div>\";\n    item.changes.forEach(function(c){ html += \"<div class=\\\"small\\\" style=\\\"margin-top:4px\\\">\\u2022 \" + esc(c) + \"</div>\"; });\n    html += \"</div>\";\n  });\n  el(\"compatDateList\").innerHTML = html;\n  var _box = el(\"compatDateList\");\n  Array.from(_box.querySelectorAll(\"[data-cdate]\")).forEach(function(d){\n    d.addEventListener(\"click\", function(){ selectCompatDate(this.getAttribute(\"data-cdate\")); });\n  });\n}\nfunction selectCompatDate(d){\n  selectedCompatDate = d;\n  el(\"compatDateInput\").value = d;\n  renderCompatDateList(d);\n}\nfunction closeCompatModal(){ el(\"compatModal\").style.display = \"none\"; currentCompatWorker = \"\"; selectedCompatDate = \"\"; }\nasync function confirmCompatDate(){\n  var d = (selectedCompatDate || el(\"compatDateInput\").value || \"\").trim();\n  if(!d) return showNotification(\"请选择兼容日期\", \"error\");\n  if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(d)) return showNotification(\"日期格式不正确，应为 YYYY-MM-DD\", \"error\");\n  var _dt = new Date(d + \"T00:00:00Z\");\n  if(isNaN(_dt.getTime()) || _dt.toISOString().slice(0, 10) !== d) return showNotification(\"不是合法的日历日期\", \"error\");\n  showNotification(\"正在保存兼容日期...\", \"success\");\n  var r = await api(\"set-worker-compatibility\", { accountId: currentAccountId, scriptName: currentCompatWorker, compatibilityDate: d });\n  if(r && r.success){ showNotification(\"兼容日期已更新为 \" + d); closeCompatModal(); setTimeout(refreshWorkers, 800); }\n  else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\nwindow.openCompatModal = openCompatModal; window.closeCompatModal = closeCompatModal; window.confirmCompatDate = confirmCompatDate; window.selectCompatDate = selectCompatDate;\nvar currentCompatFlagsWorker = \"\";\nvar selectedCompatFlags = [];\nvar COMPAT_FLAGS_LIST = [\n  \"nodejs_compat\", \"nodejs_compat_v2\", \"no_nodejs_compat\",\n  \"python_workers\", \"python_workers_314\", \"python_process_pth_files\",\n  \"export_commonjs_default\", \"require_returns_default_export\",\n  \"throw_on_not_implemented_tls_options\", \"no_throw_on_not_implemented_tls_options\",\n  \"streams_enable_constructors\", \"transformstream_enable_standard_constructor\",\n  \"durable_object_alarms\", \"durable_object_evictable\",\n  \"durable_object_io_tasks_prevent_eviction\", \"durable_object_io_tasks_do_not_prevent_eviction\",\n  \"web_socket_compression\", \"fetch_refuses_unknown_protocols\",\n  \"formdata_parser_supports_files\", \"html_rewriter_treats_esi_include_as_void_tag\"\n];\nasync function openCompatFlagsModal(name){\n  currentCompatFlagsWorker = name; selectedCompatFlags = [];\n  el(\"compatFlagsCustom\").value = \"\";\n  el(\"compatFlagsModal\").style.display = \"flex\";\n  el(\"compatFlagsCurrent\").textContent = \"\";\n  renderCompatFlagsList();\n  try{\n    var r = await api(\"get-worker-settings\", { accountId: currentAccountId, scriptName: name });\n    var flags = (r && r.result && r.result.compatibility_flags) || [];\n    if(Array.isArray(flags) && flags.length){\n      selectedCompatFlags = flags.slice();\n      el(\"compatFlagsCurrent\").textContent = \"（当前: \" + flags.join(\", \") + \"）\";\n      renderCompatFlagsList();\n    }\n  }catch(e){}\n}\nfunction renderCompatFlagsList(){\n  var html = \"\";\n  var allFlags = COMPAT_FLAGS_LIST.slice();\n  selectedCompatFlags.forEach(function(f){ if(allFlags.indexOf(f) < 0) allFlags.push(f); });\n  allFlags.forEach(function(f){\n    var on = selectedCompatFlags.indexOf(f) >= 0;\n    html += \"<label style=\\\"display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid \" + (on ? \"#2563eb\" : \"#e6edf3\") + \";border-radius:8px;margin-bottom:6px;cursor:pointer;background:\" + (on ? \"#eff6ff\" : \"#fff\") + \"\\\">\";\n    html += \"<input type=\\\"checkbox\\\" data-cflag=\\\"\" + escA(f) + \"\\\"\" + (on ? \" checked\" : \"\") + \" onchange=\\\"toggleCompatFlag(this)\\\">\";\n    html += \"<span style=\\\"font-family:monospace;font-size:13px\\\">\" + esc(f) + \"</span></label>\";\n  });\n  el(\"compatFlagsList\").innerHTML = html || \"<div class=\\\"small\\\">无可用标志</div>\";\n}\nfunction toggleCompatFlag(cb){\n  var f = cb.getAttribute(\"data-cflag\");\n  var i = selectedCompatFlags.indexOf(f);\n  if(cb.checked && i < 0) selectedCompatFlags.push(f);\n  else if(!cb.checked && i >= 0) selectedCompatFlags.splice(i, 1);\n  renderCompatFlagsList();\n}\nfunction addCustomCompatFlag(){\n  var f = el(\"compatFlagsCustom\").value.trim();\n  if(!f) return;\n  if(selectedCompatFlags.indexOf(f) < 0) selectedCompatFlags.push(f);\n  el(\"compatFlagsCustom\").value = \"\";\n  renderCompatFlagsList();\n}\nfunction closeCompatFlagsModal(){ el(\"compatFlagsModal\").style.display = \"none\"; currentCompatFlagsWorker = \"\"; selectedCompatFlags = []; }\nasync function confirmCompatFlags(){\n  showNotification(\"正在保存兼容性标志...\", \"success\");\n  var r = await api(\"set-worker-compat-flags\", { accountId: currentAccountId, scriptName: currentCompatFlagsWorker, flags: selectedCompatFlags });\n  if(r && r.success){ showNotification(\"兼容性标志已更新\"); closeCompatFlagsModal(); setTimeout(refreshWorkers, 800); }\n  else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\nwindow.openCompatFlagsModal = openCompatFlagsModal; window.closeCompatFlagsModal = closeCompatFlagsModal;\nwindow.confirmCompatFlags = confirmCompatFlags; window.toggleCompatFlag = toggleCompatFlag; window.addCustomCompatFlag = addCustomCompatFlag;\nvar currentCronWorker = \"\";\nvar currentCrons = [];\nvar cronActiveTab = \"schedule\";\nasync function openCronModal(name){\n  currentCronWorker = name; currentCrons = []; cronActiveTab = \"schedule\";\n  el(\"cronWorkerName\").textContent = name;\n  el(\"cronModal\").style.display = \"flex\";\n  el(\"cronList\").innerHTML = \"加载中...\";\n  switchCronTab(\"schedule\");\n  updateCronPreview();\n  try{\n    var r = await api(\"get-worker-schedules\", { accountId: currentAccountId, scriptName: name });\n    if(r && r.success && r.result) currentCrons = r.result.map(function(s){ return typeof s === \"string\" ? s : (s.cron || \"\"); }).filter(function(c){ return !!c; });\n  }catch(e){}\n  renderCronList();\n}\nfunction closeCronModal(){ el(\"cronModal\").style.display = \"none\"; currentCronWorker = \"\"; currentCrons = []; }\nfunction switchCronTab(tab){\n  cronActiveTab = tab;\n  document.querySelectorAll(\"#cronModal [data-crontab]\").forEach(function(e){ e.classList.toggle(\"active\", e.getAttribute(\"data-crontab\") === tab); });\n  el(\"cron-schedule\").style.display = tab === \"schedule\" ? \"block\" : \"none\";\n  el(\"cron-expr\").style.display = tab === \"expr\" ? \"block\" : \"none\";\n  el(\"cronWeekDay\").style.display = (tab === \"schedule\" && el(\"cronFreq\").value === \"weeks\") ? \"block\" : \"none\";\n  updateCronPreview();\n}\nfunction buildCronFromSchedule(){\n  var freq = el(\"cronFreq\").value;\n  var val = parseInt(el(\"cronFreqVal\").value, 10) || 1;\n  if(val < 1) val = 1;\n  if(freq === \"minutes\"){ if(val > 59) val = 59; return \"*/\" + val + \" * * * *\"; }\n  if(freq === \"hours\"){ if(val > 23) val = 23; return \"0 */\" + val + \" * * *\"; }\n  if(freq === \"days\"){ if(val > 31) val = 31; return \"0 0 */\" + val + \" * *\"; }\n  if(freq === \"weeks\"){ var dow = el(\"cronWeekDaySel\").value; return \"0 0 * * \" + dow; }\n  if(freq === \"months\"){ if(val > 31) val = 31; return \"0 0 \" + val + \" * *\"; }\n  return \"*/30 * * * *\";\n}\nfunction getCurrentCron(){\n  if(cronActiveTab === \"expr\"){ return el(\"cronExprInput\").value.trim(); }\n  return buildCronFromSchedule();\n}\nfunction parseCronField(f, min, max){\n  var vals = {};\n  if(f === \"*\") return null;\n  var parts = f.split(\",\");\n  for(var i = 0; i < parts.length; i++){\n    var p = parts[i];\n    var step = 1;\n    if(p.indexOf(\"/\") >= 0){ var sp = p.split(\"/\"); p = sp[0]; step = parseInt(sp[1], 10) || 1; }\n    var s = min, e = max;\n    if(p === \"*\"){ s = min; e = max; }\n    else if(p.indexOf(\"-\") >= 0){ var r = p.split(\"-\"); s = parseInt(r[0], 10); e = parseInt(r[1], 10); }\n    else if(p !== \"\"){ s = e = parseInt(p, 10); }\n    if(isNaN(s) || isNaN(e)) return false;\n    for(var v = s; v <= e; v += step){ if(v >= min && v <= max) vals[v] = true; }\n  }\n  return vals;\n}\nfunction nextCronTimes(cron, count){\n  var fields = cron.trim().split(/\\s+/);\n  if(fields.length !== 5) return null;\n  var mi = parseCronField(fields[0], 0, 59);\n  var hr = parseCronField(fields[1], 0, 23);\n  var dy = parseCronField(fields[2], 1, 31);\n  var mo = parseCronField(fields[3], 1, 12);\n  var wd = parseCronField(fields[4], 0, 7);\n  if(mi === false || hr === false || dy === false || mo === false || wd === false) return null;\n  if(wd && wd[7]) wd[0] = true;\n  var out = [];\n  var d = new Date();\n  d.setUTCSeconds(0, 0);\n  d.setUTCMinutes(d.getUTCMinutes() + 1);\n  var guard = 0;\n  while(out.length < count && guard < 525600){\n    guard++;\n    var ok = true;\n    if(mi && !mi[d.getUTCMinutes()]) ok = false;\n    if(ok && hr && !hr[d.getUTCHours()]) ok = false;\n    if(ok && mo && !mo[d.getUTCMonth() + 1]) ok = false;\n    var domMatch = !dy || dy[d.getUTCDate()];\n    var dowMatch = !wd || wd[d.getUTCDay()];\n    if(ok){\n      if(dy && wd){ ok = domMatch || dowMatch; }\n      else if(dy){ ok = domMatch; }\n      else if(wd){ ok = dowMatch; }\n    }\n    if(ok) out.push(new Date(d.getTime()));\n    d.setUTCMinutes(d.getUTCMinutes() + 1);\n  }\n  return out;\n}\nfunction fmtUTC(d){\n  var days = [\"Sun\",\"Mon\",\"Tue\",\"Wed\",\"Thu\",\"Fri\",\"Sat\"];\n  var months = [\"Jan\",\"Feb\",\"Mar\",\"Apr\",\"May\",\"Jun\",\"Jul\",\"Aug\",\"Sep\",\"Oct\",\"Nov\",\"Dec\"];\n  function p(n){ return (n < 10 ? \"0\" : \"\") + n; }\n  return days[d.getUTCDay()] + \", \" + p(d.getUTCDate()) + \" \" + months[d.getUTCMonth()] + \" \" + d.getUTCFullYear() + \" \" + p(d.getUTCHours()) + \":\" + p(d.getUTCMinutes()) + \":00\";\n}\nfunction updateCronPreview(){\n  var cron = getCurrentCron();\n  el(\"cronPreviewExpr\").textContent = cron || \"-\";\n  el(\"cronFreq\").onchange = function(){ el(\"cronWeekDay\").style.display = el(\"cronFreq\").value === \"weeks\" ? \"block\" : \"none\"; updateCronPreview(); };\n  if(!cron){ el(\"cronPreview\").innerHTML = \"<span style=\\\"color:#ef4444\\\">请输入 Cron 表达式</span>\"; return; }\n  var times = nextCronTimes(cron, 5);\n  if(!times){ el(\"cronPreview\").innerHTML = \"<span style=\\\"color:#ef4444\\\">表达式格式不正确</span>\"; return; }\n  if(!times.length){ el(\"cronPreview\").innerHTML = \"<span style=\\\"color:#ef4444\\\">未来一年内无匹配时间</span>\"; return; }\n  var html = \"\";\n  times.forEach(function(t){ html += \"<div>\\u2022 \" + esc(fmtUTC(t)) + \"</div>\"; });\n  el(\"cronPreview\").innerHTML = html;\n}\nfunction renderCronList(){\n  if(!currentCrons.length){ el(\"cronList\").innerHTML = \"<div class=\\\"small\\\">暂无触发器</div>\"; return; }\n  var html = \"\";\n  currentCrons.forEach(function(c, i){\n    html += \"<div class=\\\"kv-item\\\"><code style=\\\"font-size:13px\\\">\" + esc(c) + \"</code><button class=\\\"trash-btn\\\" onclick=\\\"deleteCron(\" + i + \")\\\">删除</button></div>\";\n  });\n  el(\"cronList\").innerHTML = html;\n}\nasync function saveCrons(){\n  var crons = currentCrons.map(function(c){ return { cron: c }; });\n  var r = await api(\"set-worker-schedules\", { accountId: currentAccountId, scriptName: currentCronWorker, crons: crons });\n  return r;\n}\nasync function addCron(){\n  var cron = getCurrentCron();\n  if(!cron) return showNotification(\"请输入 Cron 表达式\", \"error\");\n  if(!nextCronTimes(cron, 1)) return showNotification(\"Cron 表达式格式不正确\", \"error\");\n  if(currentCrons.indexOf(cron) >= 0) return showNotification(\"该触发器已存在\", \"error\");\n  currentCrons.push(cron);\n  var r = await saveCrons();\n  if(r && r.success){ showNotification(\"Cron 触发器已添加: \" + cron); renderCronList(); el(\"cronExprInput\").value = \"\"; }\n  else { currentCrons.pop(); showNotification((r && r.error) || \"添加失败\", \"error\"); }\n}\nasync function deleteCron(i){\n  var removed = currentCrons.splice(i, 1);\n  var r = await saveCrons();\n  if(r && r.success){ showNotification(\"已删除触发器\"); renderCronList(); }\n  else { currentCrons.splice(i, 0, removed[0]); showNotification((r && r.error) || \"删除失败\", \"error\"); }\n}\nwindow.openCronModal = openCronModal; window.closeCronModal = closeCronModal; window.switchCronTab = switchCronTab; window.updateCronPreview = updateCronPreview; window.addCron = addCron; window.deleteCron = deleteCron;\nvar currentWorkerForEnv = \"\";\nasync function openEnvFor(name){\n  currentWorkerForEnv = name; el(\"envModal\").style.display = \"flex\";\n  el(\"envRows\").innerHTML = \"加载中...\";\n  var r = await api(\"get-worker-variables\", { accountId: currentAccountId, scriptName: name });\n  el(\"envRows\").innerHTML = \"\";\n  if(r && r.success && r.result && r.result.vars && r.result.vars.length){ r.result.vars.forEach(function(v){ addEnvRow(v.name, v.type || \"plain_text\", v.value || \"\"); }); }\n  else addEnvRow();\n}\nfunction addEnvRow(name, type, value){\n  name = name || \"\"; type = type || \"plain_text\"; value = value || \"\";\n  var div = document.createElement(\"div\");\n  div.style.cssText = \"display:flex;gap:8px;margin-top:8px;align-items:center\";\n  div.innerHTML = \"<input class=\\\"input env-name\\\" placeholder=\\\"变量名\\\" value=\\\"\" + escA(name) + \"\\\" style=\\\"flex:2\\\">\" +\n    \"<select class=\\\"input env-type\\\" style=\\\"width:130px\\\"><option value=\\\"plain_text\\\">文本</option><option value=\\\"secret_text\\\">密钥</option><option value=\\\"json\\\">JSON</option></select>\" +\n    \"<textarea class=\\\"input env-value\\\" placeholder=\\\"变量值\\\" style=\\\"flex:3;min-height:60px;resize:vertical\\\">\" + esc(value) + \"</textarea>\" +\n    \"<button class=\\\"btn danger\\\">删除</button>\";\n  var sel = div.querySelector(\"select\"), ta = div.querySelector(\"textarea\");\n  sel.value = type;\n  function syncPh(){ ta.placeholder = (sel.value === \"secret_text\") ? \"留空则保持不变\" : \"变量值\"; }\n  sel.addEventListener(\"change\", syncPh); syncPh();\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"envRows\").appendChild(div);\n}\nasync function saveEnv(){\n  var rows = Array.from(el(\"envRows\").children); var vars = [];\n  for(var i = 0; i < rows.length; i++){\n    var nm = rows[i].querySelector(\".env-name\").value.trim();\n    var tp = rows[i].querySelector(\".env-type\").value;\n    var vv = rows[i].querySelector(\".env-value\").value;\n    if(!nm) continue;\n    if(tp === \"secret_text\" && !vv){ vars.push({ name: nm, type: tp, value: \"\" }); continue; } // 密钥留空=保持不变（传空名占位，后端不删）\n    if(tp === \"json\"){ try { JSON.parse(vv); } catch(e){ showNotification(\"变量「\" + nm + \"」的 JSON 格式不正确：\" + e.message, \"error\"); return; } }\n    vars.push({ name: nm, type: tp, value: vv });\n  }\n  var r = await api(\"put-worker-variables\", { accountId: currentAccountId, scriptName: currentWorkerForEnv, variables: vars });\n  if(r && r.success){ showNotification(\"环境变量已保存\"); el(\"envModal\").style.display = \"none\"; refreshWorkers(); }\n  else { showNotification((r && r.error) || \"保存失败\", \"error\"); debugOut(r); }\n}\nwindow.openEnvFor = openEnvFor; window.addEnvRow = addEnvRow; window.saveEnv = saveEnv;\nwindow.closeEnvModal = function(){ el(\"envModal\").style.display = \"none\"; };\nvar currentBindType = \"kv\", currentWorkerForBind = \"\";\nfunction openBindFor(name){ currentWorkerForBind = name; el(\"bindModal\").style.display = \"flex\"; refreshBindList(); }\nfunction closeBindModal(){ el(\"bindModal\").style.display = \"none\"; }\nasync function refreshBindList(){\n  var type = el(\"bindType\").value; currentBindType = type;\n  el(\"bindSelect\").innerHTML = \"<option value=\\\"\\\">加载中...</option>\";\n  try {\n    var r, arr = [];\n    if(type === \"kv\"){ r = await api(\"list-kv-namespaces\", { accountId: currentAccountId }); arr = r.result || [];\n      el(\"bindSelect\").innerHTML = arr.length ? \"\" : \"<option value=\\\"\\\">未找到 KV 命名空间</option>\";\n      arr.forEach(function(ns){ var o = document.createElement(\"option\"); o.value = ns.id; o.textContent = (ns.title || ns.id) + \" (\" + ns.id + \")\"; el(\"bindSelect\").appendChild(o); });\n    } else if(type === \"d1\"){ r = await api(\"list-d1\", { accountId: currentAccountId }); arr = r.result || [];\n      el(\"bindSelect\").innerHTML = arr.length ? \"\" : \"<option value=\\\"\\\">未找到 D1 数据库</option>\";\n      arr.forEach(function(db){ var id = db.uuid || db.id; var o = document.createElement(\"option\"); o.value = id; o.textContent = (db.name || id) + \" (\" + id + \")\"; el(\"bindSelect\").appendChild(o); });\n    } else { r = await api(\"list-r2-buckets\", { accountId: currentAccountId }); arr = r.result || [];\n      el(\"bindSelect\").innerHTML = arr.length ? \"\" : \"<option value=\\\"\\\">未找到 R2 存储桶</option>\";\n      arr.forEach(function(b){ var nm = b.name || b; var o = document.createElement(\"option\"); o.value = nm; o.textContent = nm; el(\"bindSelect\").appendChild(o); });\n    }\n  } catch(e){ el(\"bindSelect\").innerHTML = \"<option value=\\\"\\\">加载失败</option>\"; }\n}\nasync function confirmBind(){\n  var type = currentBindType, ref = el(\"bindSelect\").value;\n  var bindName = el(\"bindName\").value.trim() || (type === \"kv\" ? \"MY_KV\" : (type === \"d1\" ? \"MY_DB\" : \"MY_BUCKET\"));\n  if(!ref) return showNotification(\"请选择要绑定的资源\", \"error\");\n  var newBinding = (type === \"kv\") ? { type: \"kv_namespace\", name: bindName, namespace_id: ref }\n    : (type === \"d1\") ? { type: \"d1\", name: bindName, id: ref }\n    : { type: \"r2_bucket\", name: bindName, bucket_name: ref };\n  var sr = await api(\"get-worker-script\", { accountId: currentAccountId, scriptName: currentWorkerForBind });\n  var script = (sr && sr.rawScript) ? sr.rawScript : DEFAULT_WORKER_SCRIPT;\n  var r = await api(\"deploy-worker\", { accountId: currentAccountId, scriptName: currentWorkerForBind, scriptSource: script, metadataBindings: [newBinding] });\n  if(r && r.success){ showNotification(\"绑定成功\"); closeBindModal(); setTimeout(refreshWorkers, 800); }\n  else { showNotification((r && r.error) || \"绑定失败\", \"error\"); debugOut(r); }\n}\nwindow.openBindFor = openBindFor; window.closeBindModal = closeBindModal;\nwindow.refreshBindList = refreshBindList; window.confirmBind = confirmBind;\nvar batchTemplates = [], batchTemplatesLoaded = false;\nfunction appendBatchLog(msg, color){\n  var log = el(\"batchLog\"); var d = document.createElement(\"div\");\n  d.style.color = color || \"#fff\"; d.textContent = \"[\" + new Date().toLocaleTimeString() + \"] \" + msg;\n  log.appendChild(d); log.scrollTop = log.scrollHeight;\n}\nfunction renderBatchPage(){\n  var arr = loadSaved(); var list = el(\"batchAccountList\"); list.innerHTML = \"\";\n  if(!arr.length){ list.innerHTML = \"<div style=\\\"padding:10px;color:#999\\\">请先在登录页添加账号</div>\"; return; }\n  arr.forEach(function(acc, idx){\n    var title = esc(accountTitle(acc));\n    var pillCls = acc.mode === \"token\" ? \"blue\" : (acc.mode === \"oauth\" ? \"green\" : \"amber\");\n    var modeTxt = acc.mode === \"token\" ? \"Token\" : (acc.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n    var d = document.createElement(\"div\"); d.className = \"account-check-item\";\n    d.innerHTML = \"<label style=\\\"flex:1;cursor:pointer;display:flex;align-items:center\\\"><input type=\\\"checkbox\\\" class=\\\"batch-acc-chk\\\" value=\\\"\" + idx + \"\\\" style=\\\"margin-right:8px\\\"><span style=\\\"font-size:13px\\\">\" + title + \" <span class=\\\"pill \" + pillCls + \"\\\">\" + modeTxt + \"</span></span></label>\";\n    list.appendChild(d);\n  });\n  clearBatchBindingLists();\n  loadBatchTemplateOptions().then(function(){ if(el(\"batchScriptSourceType\").value === \"builtin\") applyBatchTemplatePreset(true); });\n  renderBatchPagesAccounts();\n  qdLoadKvOptions(true); qdLoadD1Options(true);\n}\nwindow.toggleSelectAllAccounts = function(cb){ document.querySelectorAll(\".batch-acc-chk\").forEach(function(c){ c.checked = cb.checked; }); };\nwindow.toggleSelectAllPagesAccounts = function(cb){ document.querySelectorAll(\".batch-pages-acc-chk\").forEach(function(c){ c.checked = cb.checked; }); };\nfunction switchBatchTab(t){\n  Array.from(document.querySelectorAll(\"[data-batchtab]\")).forEach(function(x){ x.classList.toggle(\"active\", x.getAttribute(\"data-batchtab\") === t); });\n  el(\"batchWorkerPane\").style.display = t === \"worker\" ? \"\" : \"none\";\n  el(\"batchPagesPane\").style.display = t === \"pages\" ? \"\" : \"none\";\n}\nfunction renderBatchPagesAccounts(){\n  var arr = loadSaved(); var list = el(\"batchPagesAccountList\"); if(!list) return; list.innerHTML = \"\";\n  if(!arr.length){ list.innerHTML = \"<div style=\\\"padding:10px;color:#999\\\">请先在登录页添加账号</div>\"; return; }\n  arr.forEach(function(acc, idx){\n    var title = esc(accountTitle(acc));\n    var pillCls = acc.mode === \"token\" ? \"blue\" : (acc.mode === \"oauth\" ? \"green\" : \"amber\");\n    var modeTxt = acc.mode === \"token\" ? \"Token\" : (acc.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n    var d = document.createElement(\"div\"); d.className = \"account-check-item\";\n    d.innerHTML = \"<label style=\\\"flex:1;cursor:pointer;display:flex;align-items:center\\\"><input type=\\\"checkbox\\\" class=\\\"batch-pages-acc-chk\\\" value=\\\"\" + idx + \"\\\" style=\\\"margin-right:8px\\\"><span style=\\\"font-size:13px\\\">\" + title + \" <span class=\\\"pill \" + pillCls + \"\\\">\" + modeTxt + \"</span></span></label>\";\n    list.appendChild(d);\n  });\n}\nfunction toggleBatchPagesSrc(){\n  var v = document.querySelector('input[name=\"batchPagesSrc\"]:checked').value;\n  el(\"batchPagesUrlDiv\").style.display = v === \"url\" ? \"\" : \"none\";\n  el(\"batchPagesFileDiv\").style.display = v === \"file\" ? \"\" : \"none\";\n}\nfunction appendBatchPagesLog(msg, color){\n  var log = el(\"batchPagesLog\"); if(!log) return;\n  var d = document.createElement(\"div\");\n  d.style.color = color || \"#fff\"; d.textContent = \"[\" + new Date().toLocaleTimeString() + \"] \" + msg;\n  log.appendChild(d); log.scrollTop = log.scrollHeight;\n}\nwindow.switchBatchTab = switchBatchTab; window.toggleBatchPagesSrc = toggleBatchPagesSrc;\nwindow.addBatchPagesEnvRow = function(k, v){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch\";\n  div.innerHTML = \"<input class=\\\"input b-penv-key\\\" placeholder=\\\"Key\\\" value=\\\"\" + escA(k || \"\") + \"\\\" style=\\\"flex:1\\\"><input class=\\\"input b-penv-val\\\" placeholder=\\\"Value\\\" value=\\\"\" + escA(v || \"\") + \"\\\" style=\\\"flex:1\\\"><button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchPagesEnvList\").appendChild(div);\n};\nwindow.addBatchPagesKvRow = function(){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch batch-pkv-row\"; div.style.alignItems = \"center\";\n  div.innerHTML = \"<select class=\\\"input qd-kv-sel\\\" style=\\\"flex:2;min-width:120px\\\" onchange=\\\"qdToggleKvRow(this)\\\"><option value=\\\"\\\">— 下拉选择已有 —</option></select>\"\n    + \"<input class=\\\"input qd-kv-new\\\" placeholder=\\\"或输入新名称，自动创建\\\" style=\\\"flex:2;min-width:120px\\\">\"\n    + \"<input class=\\\"input qd-kv-bind\\\" placeholder=\\\"绑定名(留空自动)\\\" style=\\\"flex:1;min-width:80px;display:none\\\">\"\n    + \"<button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchPagesKvList\").appendChild(div);\n  qdRefreshKvSelects();\n};\nwindow.addBatchPagesD1Row = function(){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch batch-pd1-row\"; div.style.alignItems = \"center\";\n  div.innerHTML = \"<select class=\\\"input qd-d1-sel\\\" style=\\\"flex:2;min-width:120px\\\" onchange=\\\"qdToggleD1Row(this)\\\"><option value=\\\"\\\">— 下拉选择已有 —</option></select>\"\n    + \"<input class=\\\"input qd-d1-new\\\" placeholder=\\\"或输入新名称，自动创建\\\" style=\\\"flex:2;min-width:120px\\\">\"\n    + \"<input class=\\\"input qd-d1-bind\\\" placeholder=\\\"绑定名(留空自动)\\\" style=\\\"flex:1;min-width:80px;display:none\\\">\"\n    + \"<button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchPagesD1List\").appendChild(div);\n  qdRefreshD1Selects();\n};\nwindow.startBatchPagesCreate = async function(){\n  var name = el(\"batchPagesName\").value.trim().toLowerCase();\n  if(!name) return alert(\"请输入项目名\");\n  if(!/^[a-z0-9][a-z0-9-]*$/.test(name) || name.length > 63) return alert(\"项目名不合法：仅小写字母、数字、连字符\");\n  var chks = Array.from(document.querySelectorAll(\".batch-pages-acc-chk:checked\"));\n  if(!chks.length) return alert(\"请至少选择一个账号\");\n  var src = document.querySelector('input[name=\"batchPagesSrc\"]:checked').value;\n  var payload = { projectName: name, branch: el(\"batchPagesBranch\").value.trim() || \"main\" };\n  if(src === \"url\"){\n    var url = el(\"batchPagesUrl\").value.trim();\n    if(!url) return alert(\"请输入直链\");\n    payload.sourceKind = \"url\"; payload.sourceUrl = url;\n  } else {\n    var fs = el(\"batchPagesFiles\").files;\n    if(!fs || !fs.length) return alert(\"请选择文件\");\n    appendBatchPagesLog(\"读取上传文件...\", \"#9ca3af\");\n    if(fs.length === 1 && /\\.zip$/i.test(fs[0].name)){\n      payload.sourceKind = \"b64zip\"; payload.sourceB64 = await qdFileToBase64(fs[0]);\n    } else {\n      payload.sourceKind = \"files\"; payload.files = await qdReadFilesAsBase64(fs);\n    }\n  }\n  var envVars = [];\n  el(\"batchPagesEnvList\").querySelectorAll(\".env-row-batch\").forEach(function(row){\n    var k = row.querySelector(\".b-penv-key\").value.trim(), v = row.querySelector(\".b-penv-val\").value;\n    if(k) envVars.push({ name: k, value: v });\n  });\n  var kvRows = Array.from(el(\"batchPagesKvList\").querySelectorAll(\".batch-pkv-row\")).map(function(r){\n    var sel = r.querySelector(\".qd-kv-sel\");\n    var nm = (r.querySelector(\".qd-kv-new\").value.trim() || (sel && sel.value) || \"\").trim();\n    if(!nm) return null;\n    return { bindName: r.querySelector(\".qd-kv-bind\").value.trim(), name: nm };\n  }).filter(function(x){ return x; });\n  var d1Rows = Array.from(el(\"batchPagesD1List\").querySelectorAll(\".batch-pd1-row\")).map(function(r){\n    var sel = r.querySelector(\".qd-d1-sel\");\n    var nm = (r.querySelector(\".qd-d1-new\").value.trim() || (sel && sel.value) || \"\").trim();\n    if(!nm) return null;\n    return { bindName: r.querySelector(\".qd-d1-bind\").value.trim(), name: nm };\n  }).filter(function(x){ return x; });\n  if(envVars.length) payload.envVars = envVars;\n  if(kvRows.length) payload.kvList = kvRows;\n  if(d1Rows.length) payload.d1List = d1Rows;\n  var accounts = loadSaved();\n  el(\"batchPagesLog\").innerHTML = \"\";\n  appendBatchPagesLog(\"开始批量部署 Pages，共 \" + chks.length + \" 个账号\", \"#fcd34d\");\n  for(var ci = 0; ci < chks.length; ci++){\n    var acc = accounts[parseInt(chks[ci].value, 10)];\n    if(!acc) continue;\n    var label = acc.mode === \"token\" ? (acc.label || \"Token\") : acc.email;\n    appendBatchPagesLog(\"处理账号: \" + label + \" ...\");\n    try {\n      var ar = await batchApi(acc, \"list-accounts\");\n      if(!ar.success || !ar.result || !ar.result.length){ appendBatchPagesLog(\"  获取 AccountID 失败\", \"#ef4444\"); continue; }\n      var aid = ar.result[0].id;\n      var p = Object.assign({}, payload, { accountId: aid });\n      var r = await batchApi(acc, \"quick-deploy-pages\", p);\n      if(r && r.success) appendBatchPagesLog(\"  \" + label + \": 部署成功\" + (r.url ? \" \" + r.url : \"\"), \"#4ade80\");\n      else appendBatchPagesLog(\"  \" + label + \": 失败 \" + ((r && r.error) || \"\"), \"#ef4444\");\n    } catch(e){ appendBatchPagesLog(\"  \" + label + \": 异常 \" + e.message, \"#ef4444\"); }\n  }\n  appendBatchPagesLog(\"批量操作结束\", \"#fcd34d\");\n};\nfunction clearBatchBindingLists(){ [\"batchEnvList\",\"batchKvList\",\"batchD1List\"].forEach(function(id){ if(el(id)) el(id).innerHTML = \"\"; }); }\nasync function loadBatchTemplateOptions(force){\n  if(batchTemplatesLoaded && !force) return batchTemplates;\n  var sel = el(\"batchBuiltinSelect\"); if(sel) sel.innerHTML = \"<option value=\\\"\\\">加载中...</option>\";\n  try {\n    var res = await api(\"load-batch-templates-kv\");\n    if(!res || !res.success) throw new Error((res && res.error) || \"读取失败\");\n    batchTemplates = res.templates || []; batchTemplatesLoaded = true;\n    if(sel){ sel.innerHTML = \"\";\n      if(batchTemplates.length){ batchTemplates.forEach(function(t){ var o = document.createElement(\"option\"); o.value = t.key; o.textContent = t.templateName || t.key; sel.appendChild(o); }); }\n      else sel.innerHTML = \"<option value=\\\"\\\">KV 中没有可用模板</option>\";\n    }\n  } catch(e){ batchTemplates = []; if(sel) sel.innerHTML = \"<option value=\\\"\\\">模板加载失败（需绑定 CF_ACCOUNTS_KV）</option>\"; }\n  return batchTemplates;\n}\nfunction getSelectedBatchTemplate(){ var k = el(\"batchBuiltinSelect\") ? el(\"batchBuiltinSelect\").value : \"\"; return batchTemplates.find(function(t){ return String(t.key) === String(k); }) || null; }\nfunction applyBatchTemplatePreset(silent){\n  var p = getSelectedBatchTemplate(); if(!p) return false;\n  el(\"batchWorkerName\").value = p.workerName || \"\";\n  clearBatchBindingLists();\n  (p.env || []).forEach(function(x){ addBatchEnvRow(x.key, x.value); });\n  (p.kv || []).forEach(function(x){ addBatchKvRow(x.bind, x.name); });\n  (p.d1 || []).forEach(function(x){ addBatchD1Row(x.bind, x.name); });\n  if(!silent) showNotification(\"已填充模板：\" + p.templateName);\n  return true;\n}\nwindow.toggleBatchSourceInput = function(){\n  var t = el(\"batchScriptSourceType\").value;\n  el(\"batchSourceBuiltinDiv\").style.display = (t === \"builtin\") ? \"block\" : \"none\";\n  el(\"batchSourceUrlDiv\").style.display = (t === \"url\") ? \"block\" : \"none\";\n  el(\"batchSourceCustomDiv\").style.display = (t === \"custom\") ? \"block\" : \"none\";\n  if(t === \"builtin\"){ loadBatchTemplateOptions().then(function(){ applyBatchTemplatePreset(true); }); }\n  else { el(\"batchWorkerName\").value = \"\"; clearBatchBindingLists(); }\n  if(t === \"custom\"){ var s = localStorage.getItem(\"cfm_custom_script\"); if(s && !el(\"batchCustomScript\").value) el(\"batchCustomScript\").value = s; }\n};\nif(el(\"batchBuiltinSelect\")){ el(\"batchBuiltinSelect\").addEventListener(\"change\", function(){ if(el(\"batchScriptSourceType\").value === \"builtin\") applyBatchTemplatePreset(); }); }\ndocument.addEventListener(\"input\", function(e){ if(e.target && e.target.id === \"batchCustomScript\") localStorage.setItem(\"cfm_custom_script\", e.target.value); });\nwindow.saveCustomScriptFile = function(){\n  var s = el(\"batchCustomScript\").value; if(!s.trim()) return showNotification(\"脚本内容为空\", \"error\");\n  localStorage.setItem(\"cfm_custom_script\", s);\n  var a = document.createElement(\"a\"); a.href = URL.createObjectURL(new Blob([s], { type: \"text/javascript\" })); a.download = \"_worker.js\"; a.click();\n  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 1000);\n  showNotification(\"已保存并下载\");\n};\nvar WORKER_FILENAMES = [\"_worker.js\", \"worker.js\", \"index.js\", \"src/worker.js\", \"src/index.js\"];\nfunction isRawUrl(u){ return u.indexOf(\"raw.githubusercontent.com\") >= 0 || u.indexOf(\"cdn.jsdelivr.net\") >= 0; }\nfunction githubBlobToRaw(u){ var m = u.match(/github\\.com\\/([^\\/]+)\\/([^\\/]+)\\/blob\\/([^\\/]+)\\/(.+)/); return m ? \"https://raw.githubusercontent.com/\" + m[1] + \"/\" + m[2] + \"/\" + m[3] + \"/\" + m[4] : null; }\nfunction isGithubRepo(u){ return /github\\.com\\/[^\\/]+\\/[^\\/]+(\\/tree\\/[^\\/]+)?\\/?$/.test(u) && u.indexOf(\"/blob/\") < 0 && !isRawUrl(u); }\nwindow.normalizeGithubUrl = function(input){\n  var val = input.value.trim(); var hint = el(\"urlConvertHint\");\n  if(!val || isRawUrl(val)){ if(hint) hint.style.display = \"none\"; return; }\n  var raw = githubBlobToRaw(val);\n  if(raw){ input.value = raw; if(hint){ hint.textContent = \"已转换为 raw 链接\"; hint.style.display = \"block\"; } return; }\n  if(isGithubRepo(val) && hint){ hint.textContent = \"检测到 GitHub 仓库，点击「处理链接」自动查找 _worker.js\"; hint.style.display = \"block\"; }\n};\nasync function resolveScriptUrl(inputUrl){\n  if(isRawUrl(inputUrl)) return { url: inputUrl };\n  var raw = githubBlobToRaw(inputUrl);\n  if(raw) return { url: raw, msg: \"blob 链接已转换\" };\n  if(isGithubRepo(inputUrl)){\n    var m = inputUrl.match(/github\\.com\\/([^\\/]+)\\/([^\\/]+)(?:\\/tree\\/([^\\/]+))?/);\n    if(!m) return { url: inputUrl };\n    var user = m[1], repo = m[2], branch = m[3] || \"main\";\n    if(!m[3]){ try { var ri = await fetch(\"https://api.github.com/repos/\" + user + \"/\" + repo); if(ri.ok){ var ij = await ri.json(); branch = ij.default_branch || \"main\"; } } catch(e){} }\n    for(var i = 0; i < WORKER_FILENAMES.length; i++){\n      var ru = \"https://raw.githubusercontent.com/\" + user + \"/\" + repo + \"/\" + branch + \"/\" + WORKER_FILENAMES[i];\n      try { var hr = await fetch(ru, { method: \"HEAD\" }); if(hr.ok) return { url: ru, msg: \"找到 \" + WORKER_FILENAMES[i] }; } catch(e){}\n    }\n    return { url: inputUrl, error: \"未能在该仓库找到 JS 文件\" };\n  }\n  return { url: inputUrl };\n}\nwindow.prepareBatchScriptUrl = async function(){\n  var url = el(\"batchScriptUrl\").value.trim(); if(!url) return showNotification(\"请先输入链接\", \"error\");\n  var r = await resolveScriptUrl(url);\n  if(r.error) return showNotification(r.error, \"error\");\n  el(\"batchScriptUrl\").value = r.url;\n  showNotification(r.msg || \"链接可用\");\n};\nwindow.addBatchEnvRow = function(k, v){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch\";\n  div.innerHTML = \"<input class=\\\"input b-env-key\\\" placeholder=\\\"Key\\\" value=\\\"\" + escA(k || \"\") + \"\\\" style=\\\"flex:1\\\"><input class=\\\"input b-env-val\\\" placeholder=\\\"Value\\\" value=\\\"\" + escA(v || \"\") + \"\\\" style=\\\"flex:1\\\"><button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchEnvList\").appendChild(div);\n};\nwindow.addBatchKvRow = function(){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch batch-kv-row\"; div.style.alignItems = \"center\";\n  div.innerHTML = \"<select class=\\\"input qd-kv-sel\\\" style=\\\"flex:2;min-width:120px\\\" onchange=\\\"qdToggleKvRow(this)\\\"><option value=\\\"\\\">— 下拉选择已有 —</option></select>\"\n    + \"<input class=\\\"input qd-kv-new\\\" placeholder=\\\"或输入新名称，自动创建\\\" style=\\\"flex:2;min-width:120px\\\">\"\n    + \"<input class=\\\"input qd-kv-bind\\\" placeholder=\\\"绑定名(留空自动)\\\" style=\\\"flex:1;min-width:80px;display:none\\\">\"\n    + \"<button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchKvList\").appendChild(div);\n  qdRefreshKvSelects();\n};\nwindow.addBatchD1Row = function(){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch batch-d1-row\"; div.style.alignItems = \"center\";\n  div.innerHTML = \"<select class=\\\"input qd-d1-sel\\\" style=\\\"flex:2;min-width:120px\\\" onchange=\\\"qdToggleD1Row(this)\\\"><option value=\\\"\\\">— 下拉选择已有 —</option></select>\"\n    + \"<input class=\\\"input qd-d1-new\\\" placeholder=\\\"或输入新名称，自动创建\\\" style=\\\"flex:2;min-width:120px\\\">\"\n    + \"<input class=\\\"input qd-d1-bind\\\" placeholder=\\\"绑定名(留空自动)\\\" style=\\\"flex:1;min-width:80px;display:none\\\">\"\n    + \"<button class=\\\"trash-btn\\\">✕</button>\";\n  div.querySelector(\"button\").addEventListener(\"click\", function(){ div.remove(); });\n  el(\"batchD1List\").appendChild(div);\n  qdRefreshD1Selects();\n};\nfunction batchAuthFor(acc){\n  if(acc.mode === \"token\") return { authMode: \"token\", token: acc.token };\n  if(acc.mode === \"oauth\") return { authMode: \"oauth\", token: acc.access_token };\n  return { authMode: \"key\", email: acc.email, key: acc.key };\n}\nasync function batchApi(acc, action, body){\n  var p = batchAuthFor(acc); p.action = action;\n  if(body){ for(var k in body) p[k] = body[k]; }\n  var r = await fetch(\"/api\", { method: \"POST\", headers: { \"Content-Type\": \"application/json\" }, body: JSON.stringify(p) });\n  try { return await r.json(); } catch(e){ return { success: false, error: \"解析失败\" }; }\n}\nwindow.startBatchCreate = async function(){\n  var name = el(\"batchWorkerName\").value.trim();\n  if(!name) return alert(\"请输入 Worker 名称\");\n  var chks = Array.from(document.querySelectorAll(\".batch-acc-chk:checked\"));\n  if(!chks.length) return alert(\"请至少选择一个账号\");\n  var sourceType = el(\"batchScriptSourceType\").value;\n  var scriptUrl = \"\", customScript = \"\", tpl = null;\n  if(sourceType === \"builtin\"){ await loadBatchTemplateOptions(); tpl = getSelectedBatchTemplate(); if(!tpl) return alert(\"请选择有效的 KV 内置模板\"); }\n  else if(sourceType === \"custom\"){ customScript = el(\"batchCustomScript\").value.trim(); if(!customScript) return alert(\"自定义脚本为空\"); }\n  else { scriptUrl = el(\"batchScriptUrl\").value.trim(); if(!scriptUrl) return alert(\"请输入脚本链接\");\n    var rs = await resolveScriptUrl(scriptUrl); if(rs.error) return alert(rs.error); scriptUrl = rs.url; el(\"batchScriptUrl\").value = scriptUrl; }\n  var bindings = [];\n  el(\"batchEnvList\").querySelectorAll(\".env-row-batch\").forEach(function(row){\n    var k = row.querySelector(\".b-env-key\").value.trim(), v = row.querySelector(\".b-env-val\").value;\n    if(k) bindings.push({ type: \"plain_text\", name: k, text: v });\n  });\n  var kvRows = Array.from(el(\"batchKvList\").querySelectorAll(\".batch-kv-row\")).map(function(r){\n    var sel = r.querySelector(\".qd-kv-sel\");\n    var nm = (r.querySelector(\".qd-kv-new\").value.trim() || (sel && sel.value) || \"\").trim();\n    if(!nm) return null;\n    var bn = r.querySelector(\".qd-kv-bind\").value.trim();\n    var bind = bn || nm.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');\n    if(/^\\d/.test(bind)) bind = '_' + bind;\n    if(!bind) bind = 'KV';\n    return { bind: bind, name: nm };\n  }).filter(function(x){ return x; });\n  var d1Rows = Array.from(el(\"batchD1List\").querySelectorAll(\".batch-d1-row\")).map(function(r){\n    var sel = r.querySelector(\".qd-d1-sel\");\n    var nm = (r.querySelector(\".qd-d1-new\").value.trim() || (sel && sel.value) || \"\").trim();\n    if(!nm) return null;\n    var bn = r.querySelector(\".qd-d1-bind\").value.trim();\n    var bind = bn || nm.toUpperCase().replace(/[^A-Z0-9_]/g, '_').replace(/^_+/, '');\n    if(/^\\d/.test(bind)) bind = '_' + bind;\n    if(!bind) bind = 'DB';\n    return { bind: bind, name: nm };\n  }).filter(function(x){ return x; });\n  var scriptContent = \"\";\n  if(customScript){ scriptContent = customScript.replace(/\\bwindow\\b/g, \"globalThis\"); appendBatchLog(\"使用自定义脚本（\" + scriptContent.length + \" 字符）\", \"#60a5fa\"); }\n  else if(tpl){\n    if(tpl.scriptSource){ scriptContent = tpl.scriptSource.replace(/\\bwindow\\b/g, \"globalThis\"); appendBatchLog(\"使用模板内置脚本: \" + tpl.templateName, \"#60a5fa\"); }\n    else if(tpl.scriptUrl){ appendBatchLog(\"获取模板远程脚本...\", \"#60a5fa\");\n      var fr = await api(\"fetch-external-script\", { url: tpl.scriptUrl });\n      if(!fr.success){ appendBatchLog(\"脚本获取失败: \" + fr.error, \"#ef4444\"); return; }\n      scriptContent = fr.content.replace(/\\bwindow\\b/g, \"globalThis\"); appendBatchLog(\"脚本获取成功\", \"#4ade80\");\n    } else { appendBatchLog(\"模板缺少脚本来源\", \"#ef4444\"); return; }\n  } else {\n    appendBatchLog(\"获取远程脚本: \" + scriptUrl, \"#60a5fa\");\n    var fr2 = await api(\"fetch-external-script\", { url: scriptUrl });\n    if(!fr2.success){ appendBatchLog(\"脚本获取失败: \" + fr2.error, \"#ef4444\"); return; }\n    scriptContent = fr2.content.replace(/\\bwindow\\b/g, \"globalThis\"); appendBatchLog(\"脚本获取成功\", \"#4ade80\");\n  }\n  if(!scriptContent) return alert(\"脚本内容为空\");\n  var accounts = loadSaved();\n  el(\"batchLog\").innerHTML = \"\";\n  appendBatchLog(\"开始批量部署，共 \" + chks.length + \" 个账号\", \"#fcd34d\");\n  var enableSub = el(\"batchEnableSubdomain\").checked;\n  for(var ci = 0; ci < chks.length; ci++){\n    var acc = accounts[parseInt(chks[ci].value, 10)];\n    if(!acc) continue;\n    var label = acc.mode === \"token\" ? (acc.label || \"Token\") : acc.email;\n    appendBatchLog(\"处理账号: \" + label + \" ...\");\n    try {\n      var ar = await batchApi(acc, \"list-accounts\");\n      if(!ar.success || !ar.result || !ar.result.length){ appendBatchLog(\"  获取 AccountID 失败\", \"#ef4444\"); continue; }\n      var aid = ar.result[0].id;\n      var localBindings = bindings.slice();\n      if(kvRows.length){\n        var kl = await batchApi(acc, \"list-kv-namespaces\", { accountId: aid });\n        for(var ki = 0; ki < kvRows.length; ki++){\n          var kv = kvRows[ki]; appendBatchLog(\"  检查 KV: \" + kv.name, \"#9ca3af\");\n          var tk = (kl.result || []).find(function(x){ return x.title === kv.name; });\n          if(!tk){ appendBatchLog(\"  创建 KV: \" + kv.name, \"#fbbf24\");\n            var ck = await batchApi(acc, \"create-kv-namespace\", { accountId: aid, title: kv.name });\n            if(ck.success && ck.result) tk = ck.result; else { appendBatchLog(\"  KV 创建失败\", \"#ef4444\"); continue; } }\n          localBindings.push({ type: \"kv_namespace\", name: kv.bind, namespace_id: tk.id });\n        }\n      }\n      if(d1Rows.length){\n        var dl = await batchApi(acc, \"list-d1\", { accountId: aid });\n        for(var di = 0; di < d1Rows.length; di++){\n          var d1 = d1Rows[di]; appendBatchLog(\"  检查 D1: \" + d1.name, \"#9ca3af\");\n          var td = (dl.result || []).find(function(x){ return x.name === d1.name; });\n          if(!td){ appendBatchLog(\"  创建 D1: \" + d1.name, \"#fbbf24\");\n            var cd = await batchApi(acc, \"create-d1-database\", { accountId: aid, name: d1.name });\n            if(cd.success && cd.result) td = cd.result; else { appendBatchLog(\"  D1 创建失败\", \"#ef4444\"); continue; } }\n          localBindings.push({ type: \"d1\", name: d1.bind, id: td.uuid || td.id });\n        }\n      }\n      var dr = await batchApi(acc, \"deploy-worker\", { accountId: aid, scriptName: name, scriptSource: scriptContent, metadataBindings: localBindings });\n      if(dr.success){\n        appendBatchLog(\"  \" + label + \": 部署成功\", \"#4ade80\");\n        await batchApi(acc, \"toggle-worker-subdomain\", { accountId: aid, scriptName: name, enabled: enableSub });\n        appendBatchLog(\"  子域名: \" + (enableSub ? \"开启\" : \"关闭\"), \"#9ca3af\");\n        if(enableSub){\n          var sdr = await batchApi(acc, \"get-workers-subdomain\", { accountId: aid });\n          if(sdr.success && sdr.result && sdr.result.subdomain) appendBatchLog(\"  https://\" + name + \".\" + sdr.result.subdomain + \".workers.dev\", \"#60a5fa\");\n        }\n      } else appendBatchLog(\"  \" + label + \": \" + (dr.error || \"失败\"), \"#ef4444\");\n    } catch(e){ appendBatchLog(\"  \" + label + \": 异常 \" + e.message, \"#ef4444\"); }\n  }\n  appendBatchLog(\"批量操作结束\", \"#fcd34d\");\n};\nvar currentKvNs = null, currentKvTitle = \"\", kvCursor = null, kvPrefix = \"\";\nasync function refreshKVNamespaces(){\n  backToKvNamespaces(true);\n  el(\"kvNamespacesList\").innerHTML = \"加载中...\";\n  var aid = await ensureAccountId(); if(!aid) return;\n  var r = await api(\"list-kv-namespaces\", { accountId: aid });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"kvNamespacesList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无 KV 命名空间</div>\"; return; }\n  el(\"kvNamespacesList\").innerHTML = \"\";\n  arr.forEach(function(ns){\n    var d = document.createElement(\"div\"); d.className = \"kv-item\";\n    d.innerHTML = \"<div style=\\\"flex:1;min-width:0\\\"><div style=\\\"font-weight:600\\\">\" + esc(ns.title) + \"</div><div class=\\\"small\\\" style=\\\"font-family:monospace;word-break:break-all\\\">\" + esc(ns.id) + \"</div></div>\" +\n      \"<div class=\\\"btns\\\"><button class=\\\"btn\\\" data-a=\\\"view\\\" data-id=\\\"\" + escA(ns.id) + \"\\\" data-t=\\\"\" + escA(ns.title) + \"\\\">键值</button>\" +\n      \"<button class=\\\"btn\\\" data-a=\\\"rename\\\" data-id=\\\"\" + escA(ns.id) + \"\\\" data-t=\\\"\" + escA(ns.title) + \"\\\">重命名</button>\" +\n      \"<button class=\\\"btn danger\\\" data-a=\\\"del\\\" data-id=\\\"\" + escA(ns.id) + \"\\\">删除</button></div>\";\n    el(\"kvNamespacesList\").appendChild(d);\n  });\n  Array.from(el(\"kvNamespacesList\").querySelectorAll(\"button\")).forEach(function(b){\n    b.addEventListener(\"click\", function(){\n      var a = this.getAttribute(\"data-a\"), id = this.getAttribute(\"data-id\"), t = this.getAttribute(\"data-t\");\n      if(a === \"view\") viewKvKeys(id, t);\n      else if(a === \"rename\") renameKvNamespace(id, t);\n      else if(a === \"del\") deleteKvNamespace(id);\n    });\n  });\n}\nfunction backToKvNamespaces(silent){\n  currentKvNs = null; kvCursor = null;\n  el(\"kvKeysSection\").style.display = \"none\";\n  if(!silent) refreshKVNamespaces();\n}\nasync function viewKvKeys(nsId, title){\n  currentKvNs = nsId; currentKvTitle = title; kvCursor = null; kvPrefix = \"\";\n  el(\"kvKeyPrefix\").value = \"\";\n  el(\"kvKeysTitle\").textContent = \"键值管理 - \" + title;\n  el(\"kvKeysSection\").style.display = \"block\";\n  refreshKvKeys(true);\n}\nasync function refreshKvKeys(reset){\n  if(reset){ kvCursor = null; kvPrefix = el(\"kvKeyPrefix\").value.trim(); }\n  var aid = await ensureAccountId();\n  el(\"kvKeysList\").innerHTML = \"加载中...\";\n  var r = await api(\"list-kv-keys\", { accountId: aid, namespaceId: currentKvNs, limit: 100, cursor: kvCursor, prefix: kvPrefix });\n  if(!r || !r.success){ el(\"kvKeysList\").innerHTML = \"加载失败：\" + esc((r && r.error) || \"\"); return; }\n  var keys = r.result || [];\n  kvCursor = (r.result_info && r.result_info.cursor) ? r.result_info.cursor : null;\n  el(\"kvNextPageBtn\").style.display = kvCursor ? \"inline-block\" : \"none\";\n  el(\"kvPageInfo\").textContent = \"本页 \" + keys.length + \" 条\" + (r.result_info && r.result_info.count ? (\"（总计约 \" + r.result_info.count + \"）\") : \"\");\n  if(!keys.length){ el(\"kvKeysList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无键</div>\"; return; }\n  el(\"kvKeysList\").innerHTML = \"\";\n  keys.forEach(function(k){\n    var d = document.createElement(\"div\"); d.className = \"kv-item\";\n    d.innerHTML = \"<div style=\\\"flex:1;min-width:0;word-break:break-all;font-family:monospace;font-size:12px\\\">\" + esc(k.name) + (k.expiration ? \"<div class=\\\"small\\\">过期: \" + new Date(k.expiration * 1000).toLocaleString() + \"</div>\" : \"\") + \"</div>\" +\n      \"<div class=\\\"btns\\\"><button class=\\\"btn small\\\" data-a=\\\"view\\\">查看</button><button class=\\\"btn small\\\" data-a=\\\"edit\\\">编辑</button><button class=\\\"btn small danger\\\" data-a=\\\"del\\\">删除</button></div>\";\n    d.querySelector(\"[data-a=\\\"view\\\"]\").addEventListener(\"click\", function(){ viewKvValue(k.name); });\n    d.querySelector(\"[data-a=\\\"edit\\\"]\").addEventListener(\"click\", function(){ openKvValueModal(k.name); });\n    d.querySelector(\"[data-a=\\\"del\\\"]\").addEventListener(\"click\", function(){ deleteKvKey(k.name); });\n    el(\"kvKeysList\").appendChild(d);\n  });\n}\nfunction kvNextPage(){ refreshKvKeys(false); }\nasync function viewKvValue(key){\n  var aid = await ensureAccountId();\n  var r = await api(\"get-kv-value\", { accountId: aid, namespaceId: currentKvNs, kvKey: key });\n  if(r && r.success) debugOut(\"Key: \" + key + \"\\n\\n\" + r.value);\n  else showNotification(\"读取失败\", \"error\");\n}\nasync function deleteKvKey(key){\n  if(!confirm(\"删除键 \" + key + \"？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"delete-kv-value\", { accountId: aid, namespaceId: currentKvNs, kvKey: key });\n  if(r && r.success){ showNotification(\"已删除\"); refreshKvKeys(true); } else showNotification(\"删除失败\", \"error\");\n}\nasync function openKvValueModal(key){\n  el(\"kvKey\").value = key || \"\"; el(\"kvKey\").readOnly = !!key;\n  el(\"kvValue\").value = \"\"; el(\"kvTtl\").value = \"\"; el(\"kvExp\").value = \"\";\n  el(\"kvValueModalTitle\").textContent = key ? (\"编辑键值 - \" + key) : \"添加键值\";\n  if(key){ var aid = await ensureAccountId(); var r = await api(\"get-kv-value\", { accountId: aid, namespaceId: currentKvNs, kvKey: key }); if(r && r.success) el(\"kvValue\").value = r.value; }\n  el(\"kvValueModal\").style.display = \"flex\";\n}\nfunction closeKVValueModal(){ el(\"kvValueModal\").style.display = \"none\"; }\nasync function confirmKVPut(){\n  var key = el(\"kvKey\").value.trim(), val = el(\"kvValue\").value;\n  if(!key) return showNotification(\"请输入 Key\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"put-kv-value\", { accountId: aid, namespaceId: currentKvNs, kvKey: key, value: val, expiration_ttl: el(\"kvTtl\").value.trim(), expiration: el(\"kvExp\").value.trim() });\n  if(r && r.success){ showNotification(\"已保存\"); closeKVValueModal(); refreshKvKeys(true); } else showNotification((r && r.error) || \"保存失败\", \"error\");\n}\nfunction openCreateKVNamespace(){ el(\"createKVModal\").style.display = \"flex\"; }\nfunction closeCreateKVModal(){ el(\"createKVModal\").style.display = \"none\"; }\nasync function confirmCreateKVNamespace(){\n  var t = el(\"kvNamespaceName\").value.trim(); if(!t) return showNotification(\"请输入名称\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"create-kv-namespace\", { accountId: aid, title: t, jurisdiction: el(\"kvJurisdiction\").value });\n  if(r && r.success){ showNotification(\"创建成功\"); closeCreateKVModal(); refreshKVNamespaces(); } else showNotification((r && r.error) || \"创建失败\", \"error\");\n}\nasync function renameKvNamespace(id, title){\n  var nt = prompt(\"重命名命名空间\", title); if(!nt || nt === title) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"rename-kv-namespace\", { accountId: aid, namespaceId: id, title: nt });\n  if(r && r.success){ showNotification(\"已重命名\"); refreshKVNamespaces(); } else showNotification((r && r.error) || \"失败\", \"error\");\n}\nasync function deleteKvNamespace(id){\n  if(!confirm(\"删除此命名空间？其下所有键值将丢失，此操作不可逆！\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"delete-kv-namespace\", { accountId: aid, namespaceId: id });\n  if(r && r.success){ showNotification(\"已删除\"); refreshKVNamespaces(); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nfunction openKvBulkWrite(){ el(\"kvBulkWriteInput\").value = \"\"; el(\"kvBulkWriteModal\").style.display = \"flex\"; }\nfunction closeKvBulkWrite(){ el(\"kvBulkWriteModal\").style.display = \"none\"; }\nasync function confirmKvBulkWrite(){\n  var items;\n  try { items = JSON.parse(el(\"kvBulkWriteInput\").value); if(!Array.isArray(items)) throw new Error(\"not array\"); }\n  catch(e){ return showNotification(\"JSON 数组格式错误\", \"error\"); }\n  var aid = await ensureAccountId();\n  var r = await api(\"bulk-write-kv\", { accountId: aid, namespaceId: currentKvNs, items: items });\n  if(r && r.success){ showNotification(\"批量写入完成\"); closeKvBulkWrite(); refreshKvKeys(true); debugOut(r.result); }\n  else showNotification((r && r.error) || \"失败\", \"error\");\n}\nfunction openKvBulkDelete(){ el(\"kvBulkDeleteInput\").value = \"\"; el(\"kvBulkDeleteModal\").style.display = \"flex\"; }\nfunction closeKvBulkDelete(){ el(\"kvBulkDeleteModal\").style.display = \"none\"; }\nasync function confirmKvBulkDelete(){\n  var keys = el(\"kvBulkDeleteInput\").value.split(\"\\n\").map(function(x){ return x.trim(); }).filter(function(x){ return x; });\n  if(!keys.length) return showNotification(\"请输入要删除的 key\", \"error\");\n  if(!confirm(\"确认删除 \" + keys.length + \" 个键？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"bulk-delete-kv\", { accountId: aid, namespaceId: currentKvNs, keys: keys });\n  if(r && r.success){ showNotification(\"批量删除完成\"); closeKvBulkDelete(); refreshKvKeys(true); } else showNotification((r && r.error) || \"失败\", \"error\");\n}\nwindow.refreshKVNamespaces = refreshKVNamespaces; window.viewKvKeys = viewKvKeys; window.backToKvNamespaces = backToKvNamespaces;\nwindow.refreshKvKeys = refreshKvKeys; window.kvNextPage = kvNextPage; window.openKvValueModal = openKvValueModal;\nwindow.closeKVValueModal = closeKVValueModal; window.confirmKVPut = confirmKVPut;\nwindow.openCreateKVNamespace = openCreateKVNamespace; window.closeCreateKVModal = closeCreateKVModal; window.confirmCreateKVNamespace = confirmCreateKVNamespace;\nwindow.openKvBulkWrite = openKvBulkWrite; window.closeKvBulkWrite = closeKvBulkWrite; window.confirmKvBulkWrite = confirmKvBulkWrite;\nwindow.openKvBulkDelete = openKvBulkDelete; window.closeKvBulkDelete = closeKvBulkDelete; window.confirmKvBulkDelete = confirmKvBulkDelete;\nasync function refreshD1Databases(){\n  el(\"d1DatabasesList\").innerHTML = \"加载中...\";\n  el(\"d1DatabaseSelect\").innerHTML = \"<option value=\\\"\\\">- 选择数据库 -</option>\";\n  var aid = await ensureAccountId(); if(!aid) return;\n  var r = await api(\"list-d1\", { accountId: aid });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"d1DatabasesList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无 D1 数据库</div>\"; return; }\n  el(\"d1DatabasesList\").innerHTML = \"\";\n  arr.forEach(function(db){\n    var id = db.uuid || db.id;\n    var d = document.createElement(\"div\"); d.className = \"kv-item\";\n    d.innerHTML = \"<div style=\\\"flex:1;min-width:0\\\"><div style=\\\"font-weight:600\\\">\" + esc(db.name) + \"</div><div class=\\\"small\\\" style=\\\"font-family:monospace;word-break:break-all\\\">\" + esc(id) + \" · \" + esc(db.version || \"\") + \"</div></div>\" +\n      \"<div class=\\\"btns\\\"><button class=\\\"btn small\\\" data-a=\\\"exp\\\">导出</button><button class=\\\"btn small danger\\\" data-a=\\\"del\\\">删除</button></div>\";\n    d.querySelector(\"[data-a=\\\"exp\\\"]\").addEventListener(\"click\", function(){ el(\"d1DatabaseSelect\").value = id; openD1Export(); });\n    d.querySelector(\"[data-a=\\\"del\\\"]\").addEventListener(\"click\", function(){ deleteD1Database(id); });\n    el(\"d1DatabasesList\").appendChild(d);\n    var o = document.createElement(\"option\"); o.value = id; o.textContent = db.name; el(\"d1DatabaseSelect\").appendChild(o);\n  });\n}\nfunction openCreateD1Database(){ el(\"createD1Modal\").style.display = \"flex\"; }\nfunction closeCreateD1Modal(){ el(\"createD1Modal\").style.display = \"none\"; }\nasync function confirmCreateD1Database(){\n  var n = el(\"d1DatabaseName\").value.trim(); if(!n) return showNotification(\"请输入名称\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"create-d1-database\", { accountId: aid, name: n, primary_location_hint: el(\"d1Location\").value });\n  if(r && r.success){ showNotification(\"创建成功\"); closeCreateD1Modal(); refreshD1Databases(); } else showNotification((r && r.error) || \"创建失败\", \"error\");\n}\nasync function deleteD1Database(id){\n  if(!confirm(\"删除此 D1 数据库？数据将丢失，不可逆！\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"delete-d1-database\", { accountId: aid, databaseId: id });\n  if(r && r.success){ showNotification(\"已删除\"); refreshD1Databases(); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nfunction parseD1Params(){\n  var t = el(\"d1Params\").value.trim();\n  if(!t) return [];\n  try { var p = JSON.parse(t); return Array.isArray(p) ? p : null; } catch(e){ return null; }\n}\nasync function executeD1Query(){\n  var db = el(\"d1DatabaseSelect\").value, q = el(\"d1Query\").value.trim();\n  if(!db || !q) return showNotification(\"请选择数据库并输入 SQL\", \"error\");\n  var params = parseD1Params();\n  if(params === null) return showNotification(\"参数必须是 JSON 数组\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"execute-d1-query\", { accountId: aid, databaseId: db, query: q, params: params });\n  var box = el(\"d1QueryResults\"); box.style.display = \"block\";\n  if(r && r.success) box.innerHTML = \"<pre>\" + esc(JSON.stringify(r.result, null, 2)) + \"</pre>\";\n  else { box.innerHTML = \"<pre>\" + esc(JSON.stringify(r, null, 2)) + \"</pre>\"; showNotification((r && r.error) || \"查询失败\", \"error\"); }\n}\nasync function executeD1Raw(){\n  var db = el(\"d1DatabaseSelect\").value, q = el(\"d1Query\").value.trim();\n  if(!db || !q) return showNotification(\"请选择数据库并输入 SQL\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"execute-d1-raw\", { accountId: aid, databaseId: db, query: q });\n  var box = el(\"d1QueryResults\"); box.style.display = \"block\";\n  if(r && r.success){\n    var res = r.result && r.result[0];\n    if(res && res.columns){ var html = \"<table class=\\\"table\\\"><thead><tr>\"; res.columns.forEach(function(c){ html += \"<th>\" + esc(c) + \"</th>\"; }); html += \"</tr></thead><tbody>\";\n      (res.rows || []).forEach(function(row){ html += \"<tr>\"; row.forEach(function(c){ html += \"<td>\" + esc(String(c)) + \"</td>\"; }); html += \"</tr>\"; });\n      box.innerHTML = html + \"</tbody></table>\"; return; }\n  }\n  box.innerHTML = \"<pre>\" + esc(JSON.stringify(r, null, 2)) + \"</pre>\";\n}\nasync function d1ShowTables(){\n  var db = el(\"d1DatabaseSelect\").value;\n  if(!db) return showNotification(\"请先选择数据库\", \"error\");\n  el(\"d1Query\").value = \"SELECT name, sql FROM sqlite_master WHERE type=\\\"table\\\" ORDER BY name;\";\n  executeD1Query();\n}\nvar d1ExportTimer = null;\nfunction openD1Export(){\n  if(!el(\"d1DatabaseSelect\").value) return showNotification(\"请先选择数据库\", \"error\");\n  el(\"d1ExportStatus\").textContent = \"点击开始后请勿关闭窗口\";\n  el(\"d1ExportLink\").innerHTML = \"\"; el(\"d1ExportBtn\").disabled = false;\n  el(\"d1ExportModal\").style.display = \"flex\";\n}\nfunction closeD1Export(){ if(d1ExportTimer){ clearInterval(d1ExportTimer); d1ExportTimer = null; } el(\"d1ExportModal\").style.display = \"none\"; }\nasync function startD1Export(){\n  var db = el(\"d1DatabaseSelect\").value;\n  var aid = await ensureAccountId();\n  el(\"d1ExportBtn\").disabled = true;\n  el(\"d1ExportStatus\").textContent = \"正在启动导出...\";\n  var r = await api(\"d1-export-start\", { accountId: aid, databaseId: db });\n  if(!r || !r.success){ el(\"d1ExportStatus\").textContent = \"启动失败：\" + ((r && r.error) || \"\"); el(\"d1ExportBtn\").disabled = false; return; }\n  var bookmark = r.result && r.result.current_bookmark;\n  el(\"d1ExportStatus\").textContent = \"导出进行中，轮询等待完成（导出期间数据库不可查询）...\";\n  d1ExportTimer = setInterval(async function(){\n    var pr = await api(\"d1-export-poll\", { accountId: aid, databaseId: db, bookmark: bookmark });\n    if(!pr || !pr.success){ el(\"d1ExportStatus\").textContent = \"轮询失败：\" + ((pr && pr.error) || \"\"); clearInterval(d1ExportTimer); d1ExportTimer = null; el(\"d1ExportBtn\").disabled = false; return; }\n    var st = pr.result && pr.result.status;\n    if(pr.result && pr.result.current_bookmark) bookmark = pr.result.current_bookmark;\n    if(st === \"complete\" && pr.result.signed_url){\n      clearInterval(d1ExportTimer); d1ExportTimer = null;\n      el(\"d1ExportStatus\").textContent = \"导出完成（链接 1 小时内有效）\";\n      el(\"d1ExportLink\").innerHTML = \"<a class=\\\"btn primary\\\" href=\\\"\" + escA(pr.result.signed_url) + \"\\\" target=\\\"_blank\\\">下载 SQL 备份文件</a>\";\n      el(\"d1ExportBtn\").disabled = false;\n    } else { el(\"d1ExportStatus\").textContent = \"导出进行中...（状态: \" + esc(st || \"?\") + \"）\"; }\n  }, 3000);\n}\nwindow.refreshD1Databases = refreshD1Databases; window.openCreateD1Database = openCreateD1Database;\nwindow.closeCreateD1Modal = closeCreateD1Modal; window.confirmCreateD1Database = confirmCreateD1Database;\nwindow.executeD1Query = executeD1Query; window.executeD1Raw = executeD1Raw; window.d1ShowTables = d1ShowTables;\nwindow.openD1Export = openD1Export; window.closeD1Export = closeD1Export; window.startD1Export = startD1Export;\nasync function refreshR2Buckets(){\n  el(\"r2BucketsList\").innerHTML = \"加载中...\";\n  var aid = await ensureAccountId(); if(!aid) return;\n  var jur = el(\"r2Jurisdiction\") ? el(\"r2Jurisdiction\").value : \"default\";\n  var r = await api(\"list-r2-buckets\", { accountId: aid, jurisdiction: jur });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"r2BucketsList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">\" + ((r && r.success) ? \"暂无存储桶\" + (jur !== \"default\" ? \"（当前辖区：\" + esc(jur) + \"，换辖区试试）\" : \"\") : \"加载失败：\" + esc((r && r.error) || \"\")) + \"</div>\"; return; }\n  el(\"r2BucketsList\").innerHTML = \"\";\n  arr.forEach(function(b){\n    var nm = b.name || b;\n    var d = document.createElement(\"div\"); d.className = \"kv-item\";\n    d.innerHTML = \"<div style=\\\"flex:1;min-width:0\\\"><div style=\\\"font-weight:600\\\">\" + esc(nm) + \"</div><div class=\\\"small\\\">\" + esc(b.creation_date || \"\") + (b.storage_class ? \" · \" + esc(b.storage_class) : \"\") + (b.location ? \" · \" + esc(b.location) : \"\") + \"</div></div>\" +\n      \"<div class=\\\"btns\\\"><select class=\\\"input\\\" data-sc=\\\"\" + escA(nm) + \"\\\" style=\\\"width:auto;font-size:12px\\\"><option value=\\\"Standard\\\">Standard</option><option value=\\\"InfrequentAccess\\\">InfrequentAccess</option></select>\" +\n      \"<button class=\\\"btn small primary\\\" data-a=\\\"mgr\\\">管理</button><button class=\\\"btn small\\\" data-a=\\\"sc\\\">改存储类型</button><button class=\\\"btn small danger\\\" data-a=\\\"del\\\">删除</button></div>\";\n    var sel = d.querySelector(\"select\"); if(b.storage_class) sel.value = b.storage_class;\n    d.querySelector(\"[data-a=\\\"mgr\\\"]\").addEventListener(\"click\", function(){ openR2BucketDetail(nm); });\n    d.querySelector(\"[data-a=\\\"sc\\\"]\").addEventListener(\"click\", function(){ updateR2StorageClass(nm, sel.value); });\n    d.querySelector(\"[data-a=\\\"del\\\"]\").addEventListener(\"click\", function(){ deleteR2Bucket(nm); });\n    el(\"r2BucketsList\").appendChild(d);\n  });\n}\nfunction openCreateR2Bucket(){ el(\"createR2Modal\").style.display = \"flex\"; }\nfunction closeCreateR2Modal(){ el(\"createR2Modal\").style.display = \"none\"; }\nasync function confirmCreateR2Bucket(){\n  var n = el(\"r2BucketName\").value.trim(); if(!n) return showNotification(\"请输入名称\", \"error\");\n  var aid = await ensureAccountId();\n  var jur = el(\"r2Jurisdiction\") ? el(\"r2Jurisdiction\").value : \"default\";\n  var r = await api(\"create-r2-bucket\", { accountId: aid, name: n, locationHint: el(\"r2Location\").value, storageClass: el(\"r2StorageClass\").value, jurisdiction: jur });\n  if(r && r.success){ showNotification(\"创建成功\"); closeCreateR2Modal(); refreshR2Buckets(); } else showNotification((r && r.error) || \"创建失败\", \"error\");\n}\nasync function updateR2StorageClass(name, sc){\n  var aid = await ensureAccountId();\n  var r = await api(\"update-r2-bucket\", { accountId: aid, name: name, storageClass: sc });\n  if(r && r.success){ showNotification(\"已更新为 \" + sc); refreshR2Buckets(); } else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\nasync function deleteR2Bucket(name){\n  if(!confirm(\"删除存储桶 \" + name + \"？桶必须为空才能删除！\")) return;\n  var aid = await ensureAccountId();\n  var jur = el(\"r2Jurisdiction\") ? el(\"r2Jurisdiction\").value : \"default\";\n  var r = await api(\"delete-r2-bucket\", { accountId: aid, name: name, jurisdiction: jur });\n  if(r && r.success){ showNotification(\"已删除\"); refreshR2Buckets(); } else showNotification((r && r.error) || \"删除失败（桶可能非空）\", \"error\");\n}\nwindow.refreshR2Buckets = refreshR2Buckets; window.openCreateR2Bucket = openCreateR2Bucket;\nwindow.closeCreateR2Modal = closeCreateR2Modal; window.confirmCreateR2Bucket = confirmCreateR2Bucket;\n// ===== R2 存储桶详情（对标 Cloudflare 官方控制台：对象 / 指标 / 设置） =====\nvar r2Detail = { name: \"\", tab: \"objects\", prefix: \"\", info: null, token: \"\", s3ok: null, tempCreds: null, credsTried: false };\nfunction r2S3StoreKey(){ return \"cfm_r2s3_\" + (localStorage.getItem(\"cfm_accountId\") || \"default\"); }\nfunction getR2S3Creds(){ try { return JSON.parse(localStorage.getItem(r2S3StoreKey()) || \"null\"); } catch(e){ return null; } }\n// 解析可用 S3 凭证：优先手动保存的，其次自动申请临时凭证（有效期 1 小时，内存存放）\nasync function ensureR2S3Creds(){\n  var manual = getR2S3Creds();\n  if(manual && manual.accessKeyId) return manual;\n  if(r2Detail.tempCreds && r2Detail.tempCreds.expireAt > Date.now()) return r2Detail.tempCreds;\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-temp-credentials\", { accountId: aid, name: r2Detail.name, permission: \"object-read-write\", ttlSeconds: 3600 });\n  if(r && r.success && r.result && r.result.accessKeyId){\n    r2Detail.tempCreds = { accessKeyId: r.result.accessKeyId, secretAccessKey: r.result.secretAccessKey, sessionToken: r.result.sessionToken, expireAt: Date.now() + 3300 * 1000 };\n    return r2Detail.tempCreds;\n  }\n  return null;\n}\nfunction r2S3Payload(extra){\n  var c = r2Detail._creds || getR2S3Creds() || {};\n  var s3 = { accessKeyId: c.accessKeyId || \"\", secretAccessKey: c.secretAccessKey || \"\" };\n  if(c.sessionToken) s3.sessionToken = c.sessionToken;\n  var p = { s3: s3 };\n  if(extra) for(var k in extra) p[k] = extra[k];\n  return p;\n}\nfunction fmtR2Size(n){ n = Number(n) || 0; if(n < 1024) return n + \" B\"; if(n < 1048576) return (n/1024).toFixed(1) + \" KB\"; if(n < 1073741824) return (n/1048576).toFixed(2) + \" MB\"; return (n/1073741824).toFixed(2) + \" GB\"; }\nasync function openR2BucketDetail(name){\n  r2Detail.name = name; r2Detail.tab = \"objects\"; r2Detail.prefix = \"\"; r2Detail.info = null; r2Detail.token = \"\"; r2Detail.s3ok = null; r2Detail._creds = null;\n  el(\"r2DetailName\").textContent = name;\n  el(\"r2ListCard\").style.display = \"none\";\n  el(\"r2DetailCard\").style.display = \"block\";\n  switchR2Tab(\"objects\");\n}\nfunction closeR2Detail(){\n  el(\"r2DetailCard\").style.display = \"none\";\n  el(\"r2ListCard\").style.display = \"block\";\n  r2Detail.name = \"\";\n}\nfunction switchR2Tab(tab){\n  r2Detail.tab = tab;\n  var tabs = document.querySelectorAll(\".r2-tab\");\n  for(var i = 0; i < tabs.length; i++) tabs[i].className = \"r2-tab\" + (tabs[i].getAttribute(\"data-tab\") === tab ? \" active\" : \"\");\n  el(\"r2TabObjects\").style.display = tab === \"objects\" ? \"block\" : \"none\";\n  el(\"r2TabMetrics\").style.display = tab === \"metrics\" ? \"block\" : \"none\";\n  el(\"r2TabSettings\").style.display = tab === \"settings\" ? \"block\" : \"none\";\n  if(tab === \"objects\") renderR2ObjectsTab();\n  else if(tab === \"metrics\") renderR2MetricsTab();\n  else renderR2SettingsTab();\n}\n// ---------- 对象 tab ----------\nasync function renderR2ObjectsTab(){\n  var box = el(\"r2TabObjects\");\n  box.innerHTML = \"<div class=\\\"small\\\" style=\\\"text-align:center;padding:20px\\\">正在准备 S3 访问凭证...</div>\";\n  var creds = await ensureR2S3Creds();\n  if(!creds){\n    box.innerHTML = \"<div style=\\\"max-width:560px;margin:20px auto;text-align:center\\\">\" +\n      \"<h4 style=\\\"margin:0 0 8px\\\">配置 R2 S3 API 凭证</h4>\" +\n      \"<div class=\\\"small\\\" style=\\\"margin-bottom:16px\\\">自动获取临时凭证失败（Token 可能缺少 R2 权限），请手动输入 R2 API 令牌。<br>获取位置：Cloudflare 控制台 → R2 对象存储 → 管理 R2 API 令牌。<br>凭证仅保存在本浏览器本地，随请求发送用于签名，不会上传存储。</div>\" +\n      \"<div class=\\\"label\\\" style=\\\"text-align:left\\\">Access Key ID</div><input id=\\\"r2S3KeyId\\\" class=\\\"input\\\" placeholder=\\\"Access Key ID\\\" autocomplete=\\\"off\\\">\" +\n      \"<div class=\\\"label\\\" style=\\\"text-align:left;margin-top:10px\\\">Secret Access Key</div><input id=\\\"r2S3Secret\\\" class=\\\"input\\\" type=\\\"password\\\" placeholder=\\\"Secret Access Key\\\" autocomplete=\\\"off\\\">\" +\n      \"<div style=\\\"display:flex;gap:8px;justify-content:center;margin-top:14px\\\"><button class=\\\"btn primary\\\" onclick=\\\"saveR2S3Creds()\\\">保存并验证</button></div>\" +\n      \"<div id=\\\"r2S3TestMsg\\\" class=\\\"small\\\" style=\\\"margin-top:10px\\\"></div></div>\";\n    return;\n  }\n  r2Detail._creds = creds;\n  box.innerHTML =\n    \"<div id=\\\"r2ObjStats\\\" style=\\\"display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px\\\"></div>\" +\n    \"<div style=\\\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:12px\\\">\" +\n      \"<div class=\\\"small\\\" id=\\\"r2PathNav\\\" style=\\\"font-size:13px\\\"></div>\" +\n      \"<div style=\\\"display:flex;gap:8px\\\">\" +\n        \"<input type=\\\"file\\\" id=\\\"r2FileInput\\\" multiple style=\\\"display:none\\\">\" +\n        \"<button class=\\\"btn\\\" onclick=\\\"r2CreateFolder()\\\">添加文件夹</button>\" +\n        \"<button class=\\\"btn primary\\\" onclick=\\\"document.getElementById('r2FileInput').click()\\\">上传文件</button>\" +\n        \"<button class=\\\"btn\\\" onclick=\\\"loadR2Objects()\\\" title=\\\"刷新\\\">↻</button>\" +\n      \"</div></div>\" +\n    \"<div id=\\\"r2DropZone\\\"><div id=\\\"r2ObjList\\\">加载中...</div>\" +\n    \"<div class=\\\"small\\\" style=\\\"margin-top:10px;color:#94a3b8\\\">超过 300 MB 的文件请使用 S3 兼容 API 或 rclone 等工具直接上传。</div></div>\";\n  var fi = el(\"r2FileInput\");\n  fi.addEventListener(\"change\", function(){ r2UploadFiles(fi.files); fi.value = \"\"; });\n  var dz = el(\"r2DropZone\");\n  dz.addEventListener(\"dragover\", function(e){ e.preventDefault(); dz.style.outline = \"2px dashed #2563eb\"; dz.style.outlineOffset = \"-2px\"; });\n  dz.addEventListener(\"dragleave\", function(){ dz.style.outline = \"\"; });\n  dz.addEventListener(\"drop\", function(e){ e.preventDefault(); dz.style.outline = \"\"; if(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) r2UploadFiles(e.dataTransfer.files); });\n  loadR2BucketInfo();\n  loadR2Objects();\n}\nasync function saveR2S3Creds(){\n  var id = el(\"r2S3KeyId\").value.trim(), sec = el(\"r2S3Secret\").value.trim();\n  if(!id || !sec){ el(\"r2S3TestMsg\").textContent = \"请填写完整凭证\"; return; }\n  localStorage.setItem(r2S3StoreKey(), JSON.stringify({ accessKeyId: id, secretAccessKey: sec }));\n  el(\"r2S3TestMsg\").textContent = \"正在验证...\";\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-s3-test\", { accountId: aid, name: r2Detail.name, s3: { accessKeyId: id, secretAccessKey: sec } });\n  if(r && r.success){ showNotification(\"S3 凭证验证通过\"); renderR2ObjectsTab(); }\n  else { el(\"r2S3TestMsg\").textContent = \"验证失败：\" + ((r && r.error) || \"\"); }\n}\nfunction r2ClearS3Creds(){ localStorage.removeItem(r2S3StoreKey()); r2Detail.tempCreds = null; r2Detail._creds = null; renderR2ObjectsTab(); }\nasync function loadR2BucketInfo(){\n  var aid = await ensureAccountId();\n  var jur = el(\"r2Jurisdiction\") ? el(\"r2Jurisdiction\").value : \"default\";\n  var r = await api(\"get-r2-bucket\", { accountId: aid, name: r2Detail.name, jurisdiction: jur });\n  if(r && r.success) r2Detail.info = r.result;\n  renderR2ObjStats();\n}\nfunction renderR2ObjStats(){\n  var box = el(\"r2ObjStats\"); if(!box) return;\n  var b = r2Detail.info || {};\n  var locName = { wnam: \"北美西部\", enam: \"北美东部\", weur: \"西欧\", eeur: \"东欧\", apac: \"亚太地区\", oc: \"大洋洲\" };\n  var stats = [\n    { k: \"默认存储类\", v: esc(b.storage_class || \"标准\") },\n    { k: \"位置\", v: esc(locName[b.location] || b.location || \"-\") },\n    { k: \"创建时间\", v: esc(b.creation_date ? String(b.creation_date).slice(0, 10) : \"-\") },\n    { k: \"A 类操作（读）\", v: \"-\" },\n    { k: \"B 类操作（写）\", v: \"-\" }\n  ];\n  box.innerHTML = stats.map(function(s){\n    return \"<div class=\\\"r2-stat\\\"><div class=\\\"k\\\">\" + s.k + \"</div><div class=\\\"v\\\">\" + s.v + \"</div></div>\";\n  }).join(\"\");\n}\nfunction r2PathCrumbs(){\n  var nav = el(\"r2PathNav\"); if(!nav) return;\n  var parts = r2Detail.prefix ? r2Detail.prefix.replace(/\\/$/, \"\").split(\"/\") : [];\n  var h = \"<a href=\\\"javascript:void(0)\\\" onclick=\\\"r2NavPrefix('')\\\" style=\\\"color:#2563eb;text-decoration:none\\\">\" + esc(r2Detail.name) + \"</a>\";\n  var acc = \"\";\n  parts.forEach(function(p, i){\n    acc += p + \"/\";\n    h += \" / <a href=\\\"javascript:void(0)\\\" onclick=\\\"r2NavPrefix('\" + escA(acc) + \"')\\\" style=\\\"color:#2563eb;text-decoration:none\\\">\" + esc(p) + \"</a>\";\n  });\n  nav.innerHTML = h;\n}\nfunction r2NavPrefix(prefix){ r2Detail.prefix = prefix || \"\"; r2Detail.token = \"\"; loadR2Objects(); }\nasync function loadR2Objects(){\n  var box = el(\"r2ObjList\"); if(!box) return;\n  box.innerHTML = \"加载中...\";\n  r2PathCrumbs();\n  var aid = await ensureAccountId();\n  var p = r2S3Payload({ accountId: aid, name: r2Detail.name, prefix: r2Detail.prefix, maxKeys: 100 });\n  if(r2Detail.token) p.continuationToken = r2Detail.token;\n  var r = await api(\"r2-objects-list\", p);\n  if(!r || !r.success){ box.innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#ef4444\\\">加载失败：\" + esc((r && r.error) || \"\") + \"<div style=\\\"margin-top:8px\\\"><button class=\\\"btn small\\\" onclick=\\\"r2ClearS3Creds()\\\">重新配置 S3 凭证</button></div></div>\"; return; }\n  var d = r.result || {};\n  r2Detail.token = d.isTruncated ? d.nextToken : \"\";\n  var rows = \"\";\n  (d.folders || []).forEach(function(f){\n    var short = f.replace(r2Detail.prefix, \"\").replace(/\\/$/, \"\");\n    rows += \"<tr class=\\\"r2-objrow\\\"><td><a href=\\\"javascript:void(0)\\\" onclick=\\\"r2NavPrefix('\" + escA(f) + \"')\\\" style=\\\"color:#2563eb;text-decoration:none\\\">📁 \" + esc(short) + \"</a></td><td>文件夹</td><td>-</td><td>-</td><td>-</td><td></td></tr>\";\n  });\n  (d.files || []).forEach(function(f){\n    if(f.key === r2Detail.prefix) return;\n    var short = f.key.replace(r2Detail.prefix, \"\");\n    if(!short) return;\n    var lm = f.lastModified ? fmtBJ(f.lastModified) : \"-\";\n    rows += \"<tr class=\\\"r2-objrow\\\"><td style=\\\"word-break:break-all\\\">\" + esc(short) + \"</td><td>文件</td><td>\" + esc(f.storageClass || \"Standard\") + \"</td><td>\" + fmtR2Size(f.size) + \"</td><td>\" + esc(lm) + \"</td>\" +\n      \"<td style=\\\"white-space:nowrap\\\"><button class=\\\"btn small\\\" onclick=\\\"r2DownloadObject('\" + escA(f.key) + \"')\\\">下载</button> <button class=\\\"btn small danger\\\" onclick=\\\"r2DeleteObject('\" + escA(f.key) + \"')\\\">删除</button></td></tr>\";\n  });\n  var more = d.isTruncated ? \"<div style=\\\"text-align:center;margin-top:10px\\\"><button class=\\\"btn small\\\" onclick=\\\"loadR2ObjectsMore()\\\">加载更多</button></div>\" : \"\";\n  if(!rows){\n    box.innerHTML = \"<div style=\\\"border:1px dashed #e2e8f0;border-radius:8px;padding:48px 20px;text-align:center;color:#64748b\\\">\" +\n      \"<div style=\\\"font-size:44px;margin-bottom:12px\\\">☁️⬆️</div>\" +\n      \"<div style=\\\"font-weight:600;color:#0f1724;margin-bottom:6px\\\">您的存储桶已准备就绪。添加文件即可开始使用。</div>\" +\n      \"<div style=\\\"margin-bottom:6px\\\"><a href=\\\"javascript:void(0)\\\" onclick=\\\"document.getElementById('r2FileInput').click()\\\" style=\\\"color:#2563eb;text-decoration:none\\\">拖放或从计算机中选择 &gt;</a></div>\" +\n      \"<div class=\\\"small\\\">超过 300 MB 的文件只能使用 S3 兼容性 API 或 Workers 上载。</div></div>\" + more;\n  } else {\n    box.innerHTML = \"<table class=\\\"table\\\" style=\\\"margin-top:0\\\"><thead><tr><th>对象</th><th>类型</th><th>存储类</th><th>大小</th><th>已修改</th><th>操作</th></tr></thead><tbody>\" + rows + \"</tbody></table>\" + more;\n  }\n}\nfunction loadR2ObjectsMore(){ loadR2ObjectsKeep(); }\nasync function loadR2ObjectsKeep(){\n  // 分页追加：保持已有行，追加下一页\n  var aid = await ensureAccountId();\n  var p = r2S3Payload({ accountId: aid, name: r2Detail.name, prefix: r2Detail.prefix, maxKeys: 100, continuationToken: r2Detail.token });\n  var r = await api(\"r2-objects-list\", p);\n  if(!r || !r.success){ showNotification((r && r.error) || \"加载失败\", \"error\"); return; }\n  r2Detail.token = \"\";\n  loadR2Objects();\n}\nfunction readFileAsBase64R2(f){\n  return new Promise(function(res, rej){\n    var r = new FileReader();\n    r.onload = function(){ var s = String(r.result || \"\"); var i = s.indexOf(\",\"); res(i >= 0 ? s.slice(i + 1) : s); };\n    r.onerror = function(){ rej(new Error(\"读取失败\")); };\n    r.readAsDataURL(f);\n  });\n}\nasync function r2UploadFiles(fileList){\n  var files = Array.from(fileList || []);\n  if(!files.length) return;\n  var over = files.filter(function(f){ return f.size > 50 * 1048576; });\n  if(over.length) return showNotification(\"单个文件超过 50MB（\" + over[0].name + \"），请用 S3 工具直传\", \"error\");\n  var aid = await ensureAccountId();\n  var ok = 0, fail = 0;\n  showNotification(\"开始上传 \" + files.length + \" 个文件...\");\n  for(var i = 0; i < files.length; i++){\n    var f = files[i];\n    try {\n      var b64 = await readFileAsBase64R2(f);\n      var key = r2Detail.prefix + f.name;\n      var r = await api(\"r2-object-put\", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, content: b64, contentType: f.type || \"application/octet-stream\" }));\n      if(r && r.success) ok++; else { fail++; showNotification(\"上传失败 \" + f.name + \"：\" + ((r && r.error) || \"\"), \"error\"); }\n    } catch(e){ fail++; showNotification(\"上传失败 \" + f.name + \"：\" + e.message, \"error\"); }\n  }\n  showNotification(\"上传完成：成功 \" + ok + \"，失败 \" + fail);\n  loadR2Objects();\n}\nasync function r2DeleteObject(key){\n  var short = key.replace(r2Detail.prefix, \"\");\n  if(!confirm(\"删除对象 \" + short + \"？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-object-delete\", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key }));\n  if(r && r.success){ showNotification(\"已删除\"); loadR2Objects(); }\n  else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nasync function r2DownloadObject(key){\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-object-download-url\", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, expires: 3600 }));\n  if(r && r.success && r.result && r.result.url){ window.open(r.result.url, \"_blank\"); }\n  else showNotification((r && r.error) || \"生成下载链接失败\", \"error\");\n}\nasync function r2CreateFolder(){\n  var name = prompt(\"文件夹名称：\");\n  if(!name) return;\n  name = name.trim().replace(/^\\/+|\\/+$/g, \"\");\n  if(!name) return;\n  var aid = await ensureAccountId();\n  var key = r2Detail.prefix + name + \"/\";\n  var r = await api(\"r2-object-put\", r2S3Payload({ accountId: aid, name: r2Detail.name, key: key, content: \"\", contentType: \"application/x-directory\" }));\n  if(r && r.success){ showNotification(\"文件夹已创建\"); loadR2Objects(); }\n  else showNotification((r && r.error) || \"创建失败\", \"error\");\n}\nwindow.openR2BucketDetail = openR2BucketDetail; window.closeR2Detail = closeR2Detail; window.switchR2Tab = switchR2Tab;\nwindow.saveR2S3Creds = saveR2S3Creds; window.r2ClearS3Creds = r2ClearS3Creds; window.r2NavPrefix = r2NavPrefix;\nwindow.loadR2Objects = loadR2Objects; window.loadR2ObjectsMore = loadR2ObjectsMore; window.r2UploadFiles = r2UploadFiles;\nwindow.r2DeleteObject = r2DeleteObject; window.r2DownloadObject = r2DownloadObject; window.r2CreateFolder = r2CreateFolder;\n// ---------- 指标 tab ----------\nfunction renderR2MetricsTab(){\n  var box = el(\"r2TabMetrics\");\n  box.innerHTML = \"<div style=\\\"display:flex;justify-content:flex-end;margin-bottom:12px\\\"><select id=\\\"r2MetricsRange\\\" class=\\\"input\\\" style=\\\"width:auto\\\" onchange=\\\"renderR2MetricsTab()\\\"><option value=\\\"24h\\\">过去 24 小时</option><option value=\\\"7d\\\">过去 7 天</option><option value=\\\"30d\\\">过去 30 天</option></select></div>\" +\n    \"<div id=\\\"r2MetricsCards\\\" style=\\\"display:grid;grid-template-columns:repeat(6,1fr);gap:12px\\\"><div class=\\\"small\\\">指标加载中...</div></div>\";\n  loadR2Metrics();\n}\nasync function loadR2Metrics(){\n  var box = el(\"r2MetricsCards\"); if(!box) return;\n  var range = el(\"r2MetricsRange\") ? el(\"r2MetricsRange\").value : \"24h\";\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-metrics\", { accountId: aid, name: r2Detail.name, range: range });\n  var cards = [\n    { k: \"平均存储\", v: \"-\" }, { k: \"已检索数据\", v: \"-\" }, { k: \"A 类操作\", v: \"-\" }, { k: \"B 类操作\", v: \"-\" }, { k: \"免费操作\", v: \"-\" }, { k: \"请求总数\", v: \"-\" }\n  ];\n  if(r && r.success && r.result){\n    var m = r.result;\n    cards[0].v = m.avgStorage || \"-\"; cards[1].v = m.egress || \"-\"; cards[2].v = m.classA || \"-\"; cards[3].v = m.classB || \"-\"; cards[4].v = m.freeOps || \"-\"; cards[5].v = m.requests || \"-\";\n  } else {\n    box.innerHTML = \"<div class=\\\"small\\\" style=\\\"grid-column:1/-1;text-align:center;padding:20px\\\">指标暂不可用：\" + esc((r && r.error) || \"未知错误\") + \"</div>\";\n    return;\n  }\n  box.innerHTML = \"<div class=\\\"small\\\" style=\\\"grid-column:1/-1;color:#94a3b8\\\">统计口径：A 类=写入/列出类操作；B 类=读取类操作；免费=删除对象/取消分片上传（不计费）。GraphQL 数据约有 1-2 小时延迟。</div>\" +\n  cards.map(function(c){\n    return \"<div class=\\\"card\\\" style=\\\"padding:16px\\\"><div class=\\\"r2-stat\\\"><div class=\\\"k\\\">\" + c.k + \"</div><div class=\\\"v\\\" style=\\\"font-size:20px\\\">\" + esc(c.v) + \"</div></div></div>\";\n  }).join(\"\");\n}\n// ---------- 设置 tab ----------\nfunction renderR2SettingsTab(){\n  var box = el(\"r2TabSettings\");\n  box.innerHTML = \"<div id=\\\"r2SettingsBody\\\">加载中...</div>\";\n  loadR2Settings();\n}\nasync function loadR2Settings(){\n  var box = el(\"r2SettingsBody\"); if(!box) return;\n  var aid = await ensureAccountId();\n  var jur = el(\"r2Jurisdiction\") ? el(\"r2Jurisdiction\").value : \"default\";\n  var r = await api(\"get-r2-bucket\", { accountId: aid, name: r2Detail.name, jurisdiction: jur });\n  var b = (r && r.success && r.result) || {};\n  var locName = { wnam: \"北美西部\", enam: \"北美东部\", weur: \"西欧\", eeur: \"东欧\", apac: \"亚太地区\", oc: \"大洋洲\" };\n  var s3ep = \"https://\" + aid + \".r2.cloudflarestorage.com/\" + r2Detail.name;\n  var h = \"<h4 style=\\\"margin:0 0 12px\\\">常规问题</h4>\" +\n    \"<div class=\\\"card\\\" style=\\\"padding:16px;margin-bottom:20px\\\"><div style=\\\"display:grid;grid-template-columns:repeat(3,1fr);gap:12px\\\">\" +\n    \"<div class=\\\"r2-stat\\\"><div class=\\\"k\\\">名称：</div><div class=\\\"v\\\">\" + esc(b.name || r2Detail.name) + \"</div></div>\" +\n    \"<div class=\\\"r2-stat\\\"><div class=\\\"k\\\">位置：</div><div class=\\\"v\\\">\" + esc(locName[b.location] || b.location || \"-\") + \"</div></div>\" +\n    \"<div class=\\\"r2-stat\\\"><div class=\\\"k\\\">创建时间：</div><div class=\\\"v\\\">\" + esc(b.creation_date ? fmtBJ(b.creation_date) : \"-\") + \"</div></div>\" +\n    \"</div><div class=\\\"r2-stat\\\" style=\\\"margin-top:12px\\\"><div class=\\\"k\\\">S3 API：</div><div class=\\\"v\\\" style=\\\"font-weight:400;font-size:13px\\\">\" + esc(s3ep) +\n    \" <button class=\\\"btn small\\\" onclick=\\\"copyToClipboard('\" + escA(s3ep) + \"')\\\">复制</button></div></div></div>\";\n  h += \"<h4 style=\\\"margin:0 0 12px\\\">自定义域 <span title=\\\"将您自己的域名绑定到此存储桶\\\" style=\\\"cursor:help;color:#94a3b8\\\">ⓘ</span></h4><div id=\\\"r2CustomDomains\\\"><div class=\\\"small\\\">加载中...</div></div>\";\n  h += \"<h4 style=\\\"margin:20px 0 12px\\\">公共开发 URL <span title=\\\"r2.dev 域名，用于开发测试\\\" style=\\\"cursor:help;color:#94a3b8\\\">ⓘ</span></h4><div id=\\\"r2PublicUrl\\\"><div class=\\\"small\\\">加载中...</div></div>\";\n  h += \"<h4 style=\\\"margin:20px 0 12px\\\">R2 数据目录 <span title=\\\"Apache Iceberg 兼容的数据目录，可用 Spark / PyIceberg 等查询引擎连接\\\" style=\\\"cursor:help;color:#94a3b8\\\">ⓘ</span></h4><div id=\\\"r2DataCatalog\\\"><div class=\\\"small\\\">加载中...</div></div>\";\n  box.innerHTML = h;\n  loadR2Domains();\n  loadR2DataCatalog();\n}\nasync function loadR2Domains(){\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-bucket-domains\", { accountId: aid, name: r2Detail.name });\n  var cd = el(\"r2CustomDomains\"), pu = el(\"r2PublicUrl\");\n  if(!r || !r.success){\n    if(cd) cd.innerHTML = \"<div class=\\\"small\\\">加载失败：\" + esc((r && r.error) || \"\") + \"</div>\";\n    if(pu) pu.innerHTML = \"<div class=\\\"small\\\">加载失败：\" + esc((r && r.error) || \"\") + \"</div>\";\n    return;\n  }\n  var d = r.result || {};\n  var customs = d.custom || [];\n  if(cd){\n    cd.innerHTML = \"<div class=\\\"card\\\" style=\\\"padding:16px\\\">\" +\n      (customs.length ? customs.map(function(x){\n        return \"<div class=\\\"kv-item\\\"><span>\" + esc(x.domain || x) + \"</span><button class=\\\"btn small danger\\\" onclick=\\\"r2RemoveCustomDomain('\" + escA(x.domain || x) + \"')\\\">删除</button></div>\";\n      }).join(\"\") : \"<div class=\\\"small\\\" style=\\\"text-align:center;padding:8px\\\">没有为此存储桶分配自定义域。</div>\") +\n      \"<div style=\\\"margin-top:10px;display:flex;gap:8px\\\"><input id=\\\"r2NewDomain\\\" class=\\\"input\\\" placeholder=\\\"例如 cdn.example.com\\\" style=\\\"max-width:320px\\\"><button class=\\\"btn\\\" onclick=\\\"r2AddCustomDomain()\\\">添加</button></div></div>\";\n  }\n  if(pu){\n    var pub = d.publicUrl || \"\";\n    pu.innerHTML = \"<div class=\\\"card\\\" style=\\\"padding:16px\\\"><div style=\\\"display:flex;justify-content:space-between;align-items:center;gap:10px\\\">\" +\n      \"<span class=\\\"small\\\">\" + (pub ? \"已启用：<b>\" + esc(pub) + \"</b>\" : \"已对此存储桶禁用公用开发 URL。\") + \"</span>\" +\n      (pub ? \"<button class=\\\"btn small danger\\\" onclick=\\\"r2TogglePublicUrl(false)\\\">禁用</button>\" : \"<button class=\\\"btn primary small\\\" onclick=\\\"r2TogglePublicUrl(true)\\\">启用</button>\") +\n      \"</div></div>\";\n  }\n}\nasync function r2AddCustomDomain(){\n  var domain = el(\"r2NewDomain\").value.trim();\n  if(!domain) return showNotification(\"请输入域名\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-custom-domain-add\", { accountId: aid, name: r2Detail.name, domain: domain });\n  if(r && r.success){ showNotification(\"自定义域已添加\"); loadR2Domains(); }\n  else showNotification((r && r.error) || \"添加失败\", \"error\");\n}\nasync function r2RemoveCustomDomain(domain){\n  if(!confirm(\"删除自定义域 \" + domain + \"？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-custom-domain-remove\", { accountId: aid, name: r2Detail.name, domain: domain });\n  if(r && r.success){ showNotification(\"已删除\"); loadR2Domains(); }\n  else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nasync function r2TogglePublicUrl(enable){\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-public-url-toggle\", { accountId: aid, name: r2Detail.name, enable: enable });\n  if(r && r.success){ showNotification(enable ? \"公共开发 URL 已启用\" : \"已禁用\"); loadR2Domains(); }\n  else showNotification((r && r.error) || \"操作失败\", \"error\");\n}\nasync function loadR2DataCatalog(){\n  var box = el(\"r2DataCatalog\"); if(!box) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"r2-catalog-get\", { accountId: aid, name: r2Detail.name });\n  if(!r || !r.success){\n    box.innerHTML = \"<div class=\\\"card\\\" style=\\\"padding:16px\\\"><div class=\\\"small\\\">加载失败：\" + esc((r && r.error) || \"\") + \"</div></div>\";\n    return;\n  }\n  var c = r.result || {};\n  if(!c.enabled){\n    box.innerHTML = \"<div class=\\\"card\\\" style=\\\"padding:16px\\\"><div style=\\\"display:flex;justify-content:space-between;align-items:center;gap:10px\\\">\" +\n      \"<span class=\\\"small\\\">已对此存储桶禁用数据目录。</span>\" +\n      \"<button class=\\\"btn primary small\\\" onclick=\\\"r2ToggleDataCatalog(true)\\\">启用</button></div></div>\";\n    return;\n  }\n  var maint = c.maintenance || {};\n  var comp = maint.compaction || {}, snap = maint.snapshot_expiration || {};\n  var maintTxt = \"压缩：\" + (comp.state === \"enabled\" ? \"已启用\" : \"未启用\") + \" · 快照过期：\" + (snap.state === \"enabled\" ? \"已启用\" : \"未启用\");\n  box.innerHTML = \"<div class=\\\"card\\\" style=\\\"padding:16px\\\">\" +\n    \"<div class=\\\"r2-stat\\\" style=\\\"margin-bottom:10px\\\"><div class=\\\"k\\\">目录 URI：</div><div class=\\\"v\\\" style=\\\"font-weight:400;font-size:13px;word-break:break-all\\\">\" + esc(c.catalogUri || \"\") +\n    \" <button class=\\\"btn small\\\" onclick=\\\"copyToClipboard('\" + escA(c.catalogUri || \"\") + \"')\\\">复制</button></div></div>\" +\n    \"<div class=\\\"r2-stat\\\" style=\\\"margin-bottom:10px\\\"><div class=\\\"k\\\">仓库名称：</div><div class=\\\"v\\\" style=\\\"font-weight:400;font-size:13px;word-break:break-all\\\">\" + esc(c.warehouse || \"\") +\n    \" <button class=\\\"btn small\\\" onclick=\\\"copyToClipboard('\" + escA(c.warehouse || \"\") + \"')\\\">复制</button></div></div>\" +\n    \"<div class=\\\"small\\\" style=\\\"margin-bottom:12px\\\">\" + esc(maintTxt) + \" · 与 Iceberg 兼容的查询引擎（例如 Spark、PyIceberg）使用上述信息连接到此存储桶的数据目录。</div>\" +\n    \"<button class=\\\"btn small danger\\\" onclick=\\\"r2ToggleDataCatalog(false)\\\">禁用</button></div>\";\n}\nasync function r2ToggleDataCatalog(enable){\n  if(!enable && !confirm(\"禁用数据目录后，Iceberg 表引用将暂时不可访问，确定禁用？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(enable ? \"r2-catalog-enable\" : \"r2-catalog-disable\", { accountId: aid, name: r2Detail.name });\n  if(r && r.success){ showNotification(enable ? \"数据目录已启用\" : \"数据目录已禁用\"); loadR2DataCatalog(); }\n  else showNotification((r && r.error) || \"操作失败\", \"error\");\n}\nwindow.renderR2MetricsTab = renderR2MetricsTab; window.loadR2Metrics = loadR2Metrics;\nwindow.renderR2SettingsTab = renderR2SettingsTab; window.r2AddCustomDomain = r2AddCustomDomain;\nwindow.r2RemoveCustomDomain = r2RemoveCustomDomain; window.r2TogglePublicUrl = r2TogglePublicUrl;\nwindow.loadR2DataCatalog = loadR2DataCatalog; window.r2ToggleDataCatalog = r2ToggleDataCatalog;\nvar currentZoneId = null, currentZoneName = \"\", currentEditingRecord = null;\nfunction showZonesList(){ el(\"zonesList\").style.display = \"block\"; el(\"dnsRecordsSection\").style.display = \"none\"; currentZoneId = null; refreshZones(); }\nwindow.backToZones = showZonesList;\nasync function refreshZones(){\n  el(\"zonesList\").innerHTML = \"加载中...\";\n  var r = await api(\"list-zones\");\n  var zones = (r && r.result) || [];\n  if(!zones.length){ el(\"zonesList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无域名</div>\"; return; }\n  var html = \"\";\n  zones.forEach(function(z){\n    var pill = z.status === \"active\" ? \"<span class=\\\"pill green\\\">已激活</span>\" : \"<span class=\\\"pill amber\\\">\" + esc(z.status) + \"</span>\";\n    var ns = \"\";\n    if(z.status !== \"active\" && z.name_servers && z.name_servers.length){\n      ns = \"<div class=\\\"small\\\" style=\\\"margin:10px 0 6px;color:#b45309;font-weight:600\\\">请到注册商设置以下 NS：</div><div style=\\\"display:flex;flex-wrap:wrap;gap:6px\\\">\";\n      z.name_servers.forEach(function(s){ ns += \"<span class=\\\"ns-pill\\\">\" + esc(s) + \"<span class=\\\"ns-copy-icon\\\" style=\\\"cursor:pointer;margin-left:4px\\\" data-ns=\\\"\" + escA(s) + \"\\\">⧉</span></span>\"; });\n      ns += \"</div>\";\n    }\n    html += \"<div class=\\\"card\\\" style=\\\"margin-bottom:12px\\\">\" +\n      \"<div style=\\\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap\\\">\" +\n      \"<div style=\\\"min-width:0\\\"><div style=\\\"font-size:19px;font-weight:700;color:#111827;word-break:break-all\\\">\" + esc(z.name) + \"</div>\" +\n      \"<div class=\\\"small\\\" style=\\\"margin-top:4px\\\">\" + esc((z.plan && z.plan.name) || \"\") + \" &nbsp;·&nbsp; <span style=\\\"font-family:monospace\\\">\" + esc(z.id) + \"</span></div></div>\" +\n      \"<div style=\\\"display:flex;align-items:center;gap:8px;flex-shrink:0\\\">\" + pill +\n      \"<button class=\\\"btn small\\\" data-a=\\\"dns\\\" data-id=\\\"\" + escA(z.id) + \"\\\" data-n=\\\"\" + escA(z.name) + \"\\\">管理 DNS</button>\" +\n      \"<button class=\\\"trash-btn\\\" data-a=\\\"del\\\" data-id=\\\"\" + escA(z.id) + \"\\\">删除</button></div></div>\" + ns + \"</div>\";\n  });\n  el(\"zonesList\").innerHTML = html;\n  Array.from(el(\"zonesList\").querySelectorAll(\"[data-ns]\")).forEach(function(s){ s.addEventListener(\"click\", function(e){ copyToClipboard(this.getAttribute(\"data-ns\"), e); }); });\n  Array.from(el(\"zonesList\").querySelectorAll(\"button\")).forEach(function(b){\n    b.addEventListener(\"click\", function(){\n      var a = this.getAttribute(\"data-a\");\n      if(a === \"dns\") viewZoneDNS(this.getAttribute(\"data-id\"), this.getAttribute(\"data-n\"));\n      else if(a === \"del\") deleteZone(this.getAttribute(\"data-id\"));\n    });\n  });\n}\nfunction openAddZone(){ el(\"addZoneModal\").style.display = \"flex\"; }\nfunction closeAddZoneModal(){ el(\"addZoneModal\").style.display = \"none\"; }\nasync function confirmAddZone(){\n  var n = el(\"zoneName\").value.trim(); if(!n) return showNotification(\"请输入域名\", \"error\");\n  var aid = await ensureAccountId();\n  var r = await api(\"create-zone\", { accountId: aid, name: n });\n  if(r && r.success){ showNotification(\"已添加，请去注册商修改 NS\"); closeAddZoneModal(); refreshZones(); } else showNotification((r && r.error) || \"添加失败\", \"error\");\n}\nasync function deleteZone(id){\n  if(!confirm(\"删除此域名？不可逆！\")) return;\n  var r = await api(\"delete-zone\", { zoneId: id });\n  if(r && r.success){ showNotification(\"已删除\"); refreshZones(); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nfunction viewZoneDNS(id, name){\n  currentZoneId = id; currentZoneName = name;\n  el(\"zonesList\").style.display = \"none\"; el(\"dnsRecordsSection\").style.display = \"block\";\n  el(\"selectedZoneName\").textContent = name + \" - DNS 记录\";\n  refreshDNSRecords();\n}\nasync function refreshDNSRecords(){\n  el(\"dnsRecordsList\").innerHTML = \"加载中...\";\n  var r = await api(\"list-dns-records\", { zoneId: currentZoneId });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"dnsRecordsList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无 DNS 记录</div>\"; return; }\n  var html = \"<table class=\\\"table\\\"><thead><tr><th>类型</th><th>名称</th><th>内容</th><th>TTL</th><th>代理</th><th style=\\\"text-align:right\\\">操作</th></tr></thead><tbody>\";\n  arr.forEach(function(x){\n    html += \"<tr><td><span class=\\\"pill\\\">\" + esc(x.type) + \"</span></td><td>\" + esc(x.name) + \"</td><td style=\\\"max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\\\" title=\\\"\" + escA(x.content) + \"\\\">\" + esc(x.content) + \"</td><td>\" + (x.ttl === 1 ? \"自动\" : x.ttl) + \"</td><td>\" + (x.proxied ? \"<span class=\\\"pill amber\\\">已代理</span>\" : \"关闭\") + \"</td>\" +\n      \"<td style=\\\"text-align:right;white-space:nowrap\\\"><button class=\\\"btn small\\\" data-a=\\\"edit\\\" data-id=\\\"\" + escA(x.id) + \"\\\">编辑</button> <button class=\\\"btn small danger\\\" data-a=\\\"del\\\" data-id=\\\"\" + escA(x.id) + \"\\\">删除</button></td></tr>\";\n  });\n  el(\"dnsRecordsList\").innerHTML = html + \"</tbody></table>\";\n  Array.from(el(\"dnsRecordsList\").querySelectorAll(\"button\")).forEach(function(b){\n    b.addEventListener(\"click\", function(){\n      var a = this.getAttribute(\"data-a\"), id = this.getAttribute(\"data-id\");\n      if(a === \"edit\") editDNSRecord(id); else deleteDNSRecord(id);\n    });\n  });\n}\nfunction openAddDNSRecord(){ el(\"addDNSRecordModal\").style.display = \"flex\"; }\nfunction closeAddDNSRecordModal(){ el(\"addDNSRecordModal\").style.display = \"none\"; }\nasync function confirmAddDNSRecord(){\n  var t = el(\"dnsRecordType\").value, n = el(\"dnsRecordName\").value.trim(), c = el(\"dnsRecordContent\").value.trim();\n  if(!n || !c) return showNotification(\"请填写完整\", \"error\");\n  var r = await api(\"create-dns-record\", { zoneId: currentZoneId, type: t, name: n, content: c, ttl: parseInt(el(\"dnsRecordTTL\").value, 10), proxied: el(\"dnsRecordProxied\").checked });\n  if(r && r.success){ showNotification(\"添加成功\"); closeAddDNSRecordModal(); refreshDNSRecords(); } else showNotification((r && r.error) || \"添加失败\", \"error\");\n}\nasync function editDNSRecord(id){\n  var r = await api(\"list-dns-records\", { zoneId: currentZoneId });\n  var rec = ((r && r.result) || []).find(function(x){ return x.id === id; });\n  if(!rec) return showNotification(\"未找到记录\", \"error\");\n  currentEditingRecord = rec;\n  el(\"editDnsRecordName\").value = rec.name; el(\"editDnsRecordContent\").value = rec.content;\n  el(\"editDnsRecordTTL\").value = String(rec.ttl); el(\"editDnsRecordProxied\").checked = !!rec.proxied;\n  el(\"editDNSRecordModal\").style.display = \"flex\";\n}\nfunction closeEditDNSRecordModal(){ el(\"editDNSRecordModal\").style.display = \"none\"; currentEditingRecord = null; }\nasync function confirmEditDNSRecord(){\n  var r = await api(\"update-dns-record\", { zoneId: currentZoneId, recordId: currentEditingRecord.id, name: el(\"editDnsRecordName\").value.trim(), content: el(\"editDnsRecordContent\").value.trim(), ttl: parseInt(el(\"editDnsRecordTTL\").value, 10), proxied: el(\"editDnsRecordProxied\").checked });\n  if(r && r.success){ showNotification(\"更新成功\"); closeEditDNSRecordModal(); refreshDNSRecords(); } else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\nasync function deleteDNSRecord(id){\n  if(!confirm(\"删除此 DNS 记录？\")) return;\n  var r = await api(\"delete-dns-record\", { zoneId: currentZoneId, recordId: id });\n  if(r && r.success){ showNotification(\"已删除\"); refreshDNSRecords(); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nfunction openDnsBatchImport(){ el(\"dnsBatchInput\").value = \"\"; el(\"dnsBatchModal\").style.display = \"flex\"; }\nfunction closeDnsBatchImport(){ el(\"dnsBatchModal\").style.display = \"none\"; }\nasync function confirmDnsBatchImport(){\n  var posts = [];\n  var lines = el(\"dnsBatchInput\").value.split(\"\\n\");\n  for(var i = 0; i < lines.length; i++){\n    var p = lines[i].trim(); if(!p) continue;\n    var f = p.split(\",\");\n    if(f.length < 3){ showNotification(\"第 \" + (i + 1) + \" 行格式错误\", \"error\"); return; }\n    posts.push({ type: f[0].trim().toUpperCase(), name: f[1].trim(), content: f.slice(2, 3).join(\",\").trim(), ttl: f[3] ? parseInt(f[3].trim(), 10) : 1, proxied: f[4] ? f[4].trim().toLowerCase() === \"true\" : false });\n  }\n  if(!posts.length) return showNotification(\"没有有效记录\", \"error\");\n  var r = await api(\"batch-dns-records\", { zoneId: currentZoneId, posts: posts });\n  if(r && r.success){ showNotification(\"批量导入成功（\" + posts.length + \" 条）\"); closeDnsBatchImport(); refreshDNSRecords(); }\n  else { showNotification((r && r.error) || \"导入失败\", \"error\"); debugOut(r); }\n}\nwindow.refreshZones = refreshZones; window.openAddZone = openAddZone; window.closeAddZoneModal = closeAddZoneModal; window.confirmAddZone = confirmAddZone;\nwindow.viewZoneDNS = viewZoneDNS; window.refreshDNSRecords = refreshDNSRecords;\nwindow.openAddDNSRecord = openAddDNSRecord; window.closeAddDNSRecordModal = closeAddDNSRecordModal; window.confirmAddDNSRecord = confirmAddDNSRecord;\nwindow.editDNSRecord = editDNSRecord; window.closeEditDNSRecordModal = closeEditDNSRecordModal; window.confirmEditDNSRecord = confirmEditDNSRecord;\nwindow.openDnsBatchImport = openDnsBatchImport; window.closeDnsBatchImport = closeDnsBatchImport; window.confirmDnsBatchImport = confirmDnsBatchImport;\nwindow.copyToClipboard = copyToClipboard;\nvar currentPagesProject = \"\";\nasync function refreshPagesProjects(){\n  backToPagesProjects(true);\n  el(\"pagesProjectsList\").innerHTML = \"加载中...\";\n  var aid = await ensureAccountId(); if(!aid) return;\n  var r = await api(\"list-pages-projects\", { accountId: aid });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"pagesProjectsList\").innerHTML = \"<div style=\\\"text-align:center;padding:20px;color:#6b7280\\\">暂无 Pages 项目</div>\"; return; }\n  el(\"pagesProjectsList\").innerHTML = \"\";\n  arr.forEach(function(p){\n    var d = document.createElement(\"div\"); d.className = \"kv-item\";\n    d.innerHTML = \"<div style=\\\"flex:1;min-width:0\\\"><div style=\\\"font-weight:600\\\">\" + esc(p.name) + \"</div><div class=\\\"small\\\"><a href=\\\"\" + escA(p.canonical_deployment && p.canonical_deployment.url || (\"https://\" + p.subdomain)) + \"\\\" target=\\\"_blank\\\" style=\\\"color:#f59e0b\\\">\" + esc(p.subdomain || \"\") + \"</a> · 生产分支 \" + esc(p.production_branch || \"-\") + \"</div></div>\" +\n      \"<div class=\\\"btns\\\"><button class=\\\"btn small\\\" data-a=\\\"deps\\\" data-n=\\\"\" + escA(p.name) + \"\\\">部署记录</button><button class=\\\"btn small\\\" data-a=\\\"del\\\" data-n=\\\"\" + escA(p.name) + \"\\\" style=\\\"color:#ef4444\\\">删除</button></div>\";\n    d.querySelector(\"[data-a=\\\"deps\\\"]\").addEventListener(\"click\", function(){ viewPagesDeployments(this.getAttribute(\"data-n\")); });\n    d.querySelector(\"[data-a=\\\"del\\\"]\").addEventListener(\"click\", function(){ deletePagesProject(this); });\n    el(\"pagesProjectsList\").appendChild(d);\n  });\n}\nasync function deletePagesProject(btn){\n  var name = btn.getAttribute(\"data-n\");\n  if(btn.getAttribute(\"data-confirm\") !== \"1\"){\n    btn.setAttribute(\"data-confirm\", \"1\"); btn.textContent = \"确认删除？\"; btn.classList.add(\"danger\");\n    setTimeout(function(){ btn.setAttribute(\"data-confirm\", \"\"); btn.textContent = \"删除\"; btn.classList.remove(\"danger\"); }, 5000);\n    return;\n  }\n  btn.setAttribute(\"data-confirm\", \"\");\n  var aid = await ensureAccountId(); if(!aid) return;\n  var r = await api(\"delete-pages-project\", { accountId: aid, projectName: name });\n  if(r && r.success){ showNotification(\"项目已删除\"); refreshPagesProjects(); } else showNotification((r && r.error) || \"删除失败\", \"error\");\n}\nfunction backToPagesProjects(silent){ currentPagesProject = \"\"; el(\"pagesDeploySection\").style.display = \"none\"; el(\"pagesProjectsList\").style.display = \"block\"; if(!silent) refreshPagesProjects(); }\nfunction openCreatePagesProject(){ openQuickDeployPages(); }\nfunction closeCreatePagesModal(){ el(\"createPagesModal\").style.display = \"none\"; }\nasync function confirmCreatePagesProject(){\n  var input = el(\"pagesProjectNameInput\"); var n = input.value.trim().toLowerCase(); input.value = n;\n  if(!n) return showNotification(\"请输入项目名\", \"error\");\n  if(!/^[a-z0-9][a-z0-9-]*$/.test(n) || n.length > 63) return showNotification(\"项目名不合法：仅小写字母、数字、连字符，且以字母数字开头\", \"error\");\n  var btn = document.querySelector(\"#createPagesModal .btn.primary\");\n  if(btn){ btn.disabled = true; btn.textContent = \"创建中...\"; }\n  try{\n    var aid = await ensureAccountId();\n    if(!aid) throw new Error(\"无法获取账号 ID\");\n    var r = await api(\"create-pages-project\", { accountId: aid, name: n, production_branch: el(\"pagesBranchInput\").value.trim() || \"main\" });\n    if(r && r.success){ showNotification(\"创建成功\"); closeCreatePagesModal(); input.value = \"\"; refreshPagesProjects(); }\n    else throw new Error((r && r.error) || \"创建失败\");\n  }catch(err){ showNotification(err.message || \"创建失败\", \"error\"); }\n  if(btn){ btn.disabled = false; btn.textContent = \"创建\"; }\n}\nfunction switchPagesDeployTab(t){\n  el(\"pdeploy-upload\").style.display = t === \"upload\" ? \"block\" : \"none\";\n  el(\"pdeploy-github\").style.display = t === \"github\" ? \"block\" : \"none\";\n  Array.from(document.querySelectorAll(\"[data-ptab]\")).forEach(function(x){ x.classList.toggle(\"active\", x.getAttribute(\"data-ptab\") === t); });\n}\nfunction pagesDeployStatus(msg, isErr){\n  var s = el(\"pagesDeployStatus\"); if(!s) return;\n  s.innerHTML = msg ? (\"<span style=\\\"color:\" + (isErr ? \"#dc2626\" : \"#1e40af\") + \"\\\">\" + esc(msg) + \"</span>\") : \"\";\n}\nfunction getPagesUploadFiles(){\n  var a = Array.from(el(\"pagesUploadFiles\").files || []), b = Array.from(el(\"pagesUploadDir\").files || []);\n  var seen = {}, out = [];\n  a.concat(b).forEach(function(f){ var k = (f.webkitRelativePath || f.name) + \"|\" + f.size; if(!seen[k]){ seen[k] = 1; out.push(f); } });\n  return out;\n}\nfunction refreshPagesUploadList(){\n  var fs = getPagesUploadFiles(), box = el(\"pagesUploadList\");\n  if(!box) return;\n  if(!fs.length){ box.textContent = \"\"; return; }\n  var total = fs.reduce(function(s, f){ return s + f.size; }, 0);\n  box.textContent = \"已选择 \" + fs.length + \" 个文件，共 \" + (total / 1048576).toFixed(2) + \" MB\";\n}\nfunction clearPagesUpload(){ el(\"pagesUploadFiles\").value = \"\"; el(\"pagesUploadDir\").value = \"\"; refreshPagesUploadList(); pagesDeployStatus(\"\"); }\nfunction readFileAsBase64(f){\n  return new Promise(function(res, rej){\n    var r = new FileReader();\n    r.onload = function(){ var s = String(r.result || \"\"); var i = s.indexOf(\",\"); res(i >= 0 ? s.slice(i + 1) : s); };\n    r.onerror = function(){ rej(new Error(\"读取文件失败：\" + f.name)); };\n    r.readAsDataURL(f);\n  });\n}\nasync function startPagesUpload(){\n  var fs = getPagesUploadFiles();\n  if(!fs.length) return showNotification(\"请先选择文件或文件夹\", \"error\");\n  if(fs.length > 2000) return showNotification(\"文件数量超过 2000，请精简\", \"error\");\n  var total = fs.reduce(function(s, f){ return s + f.size; }, 0);\n  if(total > 100 * 1048576) return showNotification(\"文件总大小超过 100MB，请精简\", \"error\");\n  var bad = fs.filter(function(f){ return f.size > 25 * 1048576; });\n  if(bad.length) return showNotification(\"单个文件超过 25MB：\" + bad[0].name, \"error\");\n  var btn = el(\"pagesUploadBtn\"); btn.disabled = true; btn.textContent = \"读取文件中...\";\n  pagesDeployStatus(\"正在读取 \" + fs.length + \" 个文件...\");\n  try{\n    var files = [];\n    for(var i = 0; i < fs.length; i++){\n      var f = fs[i];\n      var b64 = await readFileAsBase64(f);\n      var rel = f.webkitRelativePath || f.name;\n      var slash = rel.indexOf(\"/\");\n      if(slash >= 0) rel = rel.slice(slash + 1);\n      if(!rel) rel = f.name;\n      files.push({ path: \"/\" + rel, content: b64 });\n      if(i % 20 === 0) pagesDeployStatus(\"正在读取文件 \" + (i + 1) + \"/\" + fs.length + \"...\");\n    }\n    btn.textContent = \"部署中...\";\n    pagesDeployStatus(\"正在上传并部署，请稍候...\");\n    var aid = await ensureAccountId();\n    var r = await api(\"pages-deploy-upload\", { accountId: aid, projectName: currentPagesProject, branch: el(\"pagesUploadBranch\").value.trim(), files: files });\n    if(r && r.success){ var msg = \"部署成功\"; if(r.stage === \"failure\") msg = \"部署失败，请查看部署记录\"; else if(r.stage && r.stage !== \"success\") msg = \"部署已提交，仍在处理中\"; if(r.warning) msg += \"（\" + r.warning + \"）\"; showNotification(msg + (r.url ? (\"：\" + r.url) : \"\"), r.warning ? \"warning\" : \"success\"); pagesDeployStatus(r.warning || \"\"); clearPagesUpload(); setTimeout(refreshPagesDeployments, 1500); }\n    else { showNotification((r && r.error) || \"部署失败\", \"error\"); pagesDeployStatus((r && r.error) || \"部署失败\", true); }\n  }catch(e){ showNotification(e.message || \"部署失败\", \"error\"); pagesDeployStatus(e.message || \"部署失败\", true); }\n  btn.disabled = false; btn.textContent = \"上传并部署\";\n}\nasync function startPagesGithubDeploy(){\n  var url = el(\"pagesGithubUrl\").value.trim();\n  if(!url) return showNotification(\"请输入 GitHub 仓库地址\", \"error\");\n  var btn = el(\"pagesGithubBtn\"); btn.disabled = true; btn.textContent = \"导入中...\";\n  pagesDeployStatus(\"正在从 GitHub 下载仓库并部署，请稍候...\");\n  try{\n    var aid = await ensureAccountId();\n    var r = await api(\"pages-deploy-github\", { accountId: aid, projectName: currentPagesProject, repoUrl: url, branch: el(\"pagesGithubBranch\").value.trim() });\n    if(r && r.success){ var msg = \"部署成功\"; if(r.warning) msg += \"（\" + r.warning + \"）\"; showNotification(msg + (r.url ? (\"：\" + r.url) : \"\"), r.warning ? \"warning\" : \"success\"); pagesDeployStatus(r.warning || \"\"); setTimeout(refreshPagesDeployments, 1500); }\n    else { showNotification((r && r.error) || \"部署失败\", \"error\"); pagesDeployStatus((r && r.error) || \"部署失败\", true); }\n  }catch(e){ showNotification(e.message || \"部署失败\", \"error\"); pagesDeployStatus(e.message || \"部署失败\", true); }\n  btn.disabled = false; btn.textContent = \"导入并部署\";\n}\nasync function viewPagesDeployments(name){\n  currentPagesProject = name;\n  el(\"pagesProjectName\").textContent = \"部署记录 - \" + name;\n  el(\"pagesProjectsList\").style.display = \"none\"; el(\"pagesDeploySection\").style.display = \"block\";\n  refreshPagesDeployments();\n}\nasync function refreshPagesDeployments(){\n  var aid = await ensureAccountId();\n  el(\"pagesDeployList\").innerHTML = \"加载中...\";\n  refreshPagesOverview();\n  var r = await api(\"list-pages-deployments\", { accountId: aid, projectName: currentPagesProject });\n  var arr = (r && r.result) || [];\n  if(!arr.length){ el(\"pagesDeployList\").innerHTML = \"<div class=\\\"small\\\" style=\\\"padding:12px\\\">暂无部署</div>\"; return; }\n  el(\"pagesDeployList\").innerHTML = \"\";\n  arr.forEach(function(d){\n    var st = d.latest_stage && d.latest_stage.name, ok = d.latest_stage && d.latest_stage.status === \"success\";\n    var failed = d.latest_stage && d.latest_stage.status === \"failure\";\n    var div = document.createElement(\"div\"); div.className = \"deploy-item\";\n    var btns = \"<div class=\\\"btns\\\">\";\n    if(d.url) btns += \"<a class=\\\"btn small\\\" href=\\\"\" + escA(d.url) + \"\\\" target=\\\"_blank\\\">访问</a>\";\n    if(failed) btns += \"<button class=\\\"btn small\\\" data-a=\\\"retry\\\" data-id=\\\"\" + escA(d.id) + \"\\\">重试</button>\";\n    btns += \"<button class=\\\"btn small\\\" data-a=\\\"rollback\\\" data-id=\\\"\" + escA(d.id) + \"\\\" title=\\\"回滚到此版本\\\">回滚</button>\";\n    btns += \"<button class=\\\"trash-btn\\\" data-a=\\\"del\\\" data-id=\\\"\" + escA(d.id) + \"\\\">✕</button></div>\";\n    div.innerHTML = \"<div style=\\\"flex:1;min-width:0\\\"><div style=\\\"font-weight:600;font-family:monospace;font-size:12px\\\">\" + esc(String(d.id).slice(0, 8)) + \" <span class=\\\"pill \" + (ok ? \"green\" : (failed ? \"red\" : \"amber\")) + \"\\\">\" + esc(st || \"?\") + \"</span></div>\" +\n      \"<div class=\\\"small\\\">\" + esc(d.branch || \"\") + \" · \" + esc(fmtBJ(d.created_on)) + \"</div></div>\" + btns;\n    var rb = div.querySelector(\"[data-a=\\\"retry\\\"]\");\n    if(rb) rb.addEventListener(\"click\", function(){ retryPagesDeployment(this.getAttribute(\"data-id\")); });\n    var rbb = div.querySelector(\"[data-a=\\\"rollback\\\"]\");\n    if(rbb) rbb.addEventListener(\"click\", function(){ rollbackPagesDeployment(this.getAttribute(\"data-id\")); });\n    div.querySelector(\"[data-a=\\\"del\\\"]\").addEventListener(\"click\", function(){ deletePagesDeployment(this.getAttribute(\"data-id\")); });\n    el(\"pagesDeployList\").appendChild(div);\n  });\n}\nasync function refreshPagesOverview(){\n  var box = el(\"pagesProjectOverview\");\n  if(!box) return;\n  box.innerHTML = \"<div class=\\\"small\\\">加载中...</div>\";\n  try{\n    var aid = await ensureAccountId();\n    var r = await api(\"get-pages-project-overview\", { accountId: aid, projectName: currentPagesProject });\n    var o = (r && r.result) || {};\n    var html = \"\";\n    var domains = o.domains || [];\n    html += \"<div style=\\\"margin-bottom:10px\\\"><span class=\\\"label\\\">自定义域名（\" + domains.length + \"）</span><div style=\\\"margin-top:6px\\\">\";\n    if(!domains.length) html += \"<span class=\\\"small\\\">暂无</span>\";\n    domains.forEach(function(dm){\n      var cls = dm.status === \"active\" ? \"green\" : \"amber\";\n      html += \"<a class=\\\"domain-tag\\\" href=\\\"https://\" + escA(dm.name) + \"\\\" target=\\\"_blank\\\">\" + esc(dm.name) + \"<span class=\\\"domain-status \" + cls + \"\\\">\" + esc(dm.status || \"?\") + \"</span></a>\";\n    });\n    html += \"</div></div>\";\n    var mainUrl = (o.canonical_deployment && o.canonical_deployment.url) || ((o.latest_deployment && o.latest_deployment.url) || \"\");\n    html += \"<div style=\\\"margin-bottom:10px\\\"><span class=\\\"label\\\">主域名</span><div style=\\\"margin-top:6px\\\">\" + (mainUrl ? \"<a class=\\\"domain-tag workers-dev\\\" href=\\\"\" + escA(mainUrl) + \"\\\" target=\\\"_blank\\\">\" + esc(mainUrl.replace(/^https?:\\/\\//, \"\")) + \"</a>\" : \"<span class=\\\"small\\\">-</span>\") + \"</div></div>\";\n    html += \"<div><span class=\\\"label\\\">绑定</span><div class=\\\"worker-tag-rows\\\" style=\\\"margin-top:6px;align-items:flex-start\\\">\";\n    html += tagRow(\"环境变量\", (o.env_vars || []).map(function(n){ return \"<span class=\\\"res-tag env\\\">\" + esc(n) + \"</span>\"; }).join(\"\"), true);\n    html += tagRow(\"KV\", (o.kv_namespaces || []).map(function(n){ return \"<span class=\\\"res-tag kv\\\">\" + esc(n) + \"</span>\"; }).join(\"\"), true);\n    html += tagRow(\"D1\", (o.d1_databases || []).map(function(n){ return \"<span class=\\\"res-tag d1\\\">\" + esc(n) + \"</span>\"; }).join(\"\"), true);\n    html += \"</div></div>\";\n    box.innerHTML = html;\n  }catch(e){ box.innerHTML = \"<div class=\\\"small\\\">加载失败</div>\"; }\n}\nasync function triggerPagesDeploy(){\n  var btn = document.querySelector(\"#pagesDeploySection .btn.primary\");\n  if(btn){ btn.disabled = true; btn.textContent = \"部署中...\"; }\n  try{\n    var aid = await ensureAccountId();\n    var r = await api(\"trigger-pages-deployment\", { accountId: aid, projectName: currentPagesProject });\n    if(r && r.success){ showNotification(\"已触发部署\"); setTimeout(refreshPagesDeployments, 1200); }\n    else throw new Error((r && r.error) || \"触发失败\");\n  }catch(err){ showNotification(err.message || \"触发失败\", \"error\"); }\n  if(btn){ btn.disabled = false; btn.textContent = \"触发部署\"; }\n}\nasync function retryPagesDeployment(id){\n  var aid = await ensureAccountId();\n  var r = await api(\"retry-pages-deployment\", { accountId: aid, projectName: currentPagesProject, deploymentId: id });\n  if(r && r.success){ showNotification(\"已重试\"); setTimeout(refreshPagesDeployments, 1500); } else showNotification((r && r.error) || \"重试失败（仅失败的部署可重试）\", \"error\");\n}\nasync function rollbackPagesDeployment(id){\n  if(!confirm(\"回滚到部署 \" + String(id).slice(0, 8) + \"？将下载该版本的页面文件并重新部署为新版本。\")) return;\n  var aid = await ensureAccountId();\n  showNotification(\"正在回滚，请稍候...\", \"warning\");\n  var r = await api(\"rollback-pages-deployment\", { accountId: aid, projectName: currentPagesProject, deploymentId: id });\n  if(r && r.success){ showNotification(r.message || \"回滚成功\"); setTimeout(refreshPagesDeployments, 2000); } else showNotification((r && r.error) || \"回滚失败\", \"error\");\n}\nasync function deletePagesDeployment(id){\n  if(!confirm(\"删除此部署？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"delete-pages-deployment\", { accountId: aid, projectName: currentPagesProject, deploymentId: id });\n  if(r && r.success){ showNotification(\"已删除\"); refreshPagesDeployments(); } else showNotification((r && r.error) || \"失败\", \"error\");\n}\nvar pagesDomainsProject = \"\";\nvar pagesDomainZonesCache = [];\nvar pagesDomainTab = \"cf\";\nfunction switchPagesDomainTab(mode){\n  pagesDomainTab = mode;\n  el(\"pagesDomainCfPane\").style.display = mode === \"cf\" ? \"block\" : \"none\";\n  el(\"pagesDomainExtPane\").style.display = mode === \"ext\" ? \"block\" : \"none\";\n  el(\"pagesDomainTabCf\").className = \"btn small\" + (mode === \"cf\" ? \" primary\" : \"\");\n  el(\"pagesDomainTabExt\").className = \"btn small\" + (mode === \"ext\" ? \" primary\" : \"\");\n  if(mode === \"ext\" && pagesDomainsProject) el(\"pagesDomainCnameTarget\").textContent = pagesDomainsProject + \".pages.dev\";\n}\nasync function openPagesDomains(name){\n  pagesDomainsProject = name || currentPagesProject;\n  if(!pagesDomainsProject) return showNotification(\"请先进入一个项目\", \"error\");\n  el(\"pagesDomainsModal\").style.display = \"flex\";\n  switchPagesDomainTab(\"cf\");\n  el(\"pagesDomainsList\").innerHTML = \"加载中...\";\n  await loadPagesDomainZones();\n  refreshPagesDomainsList();\n}\nasync function refreshPagesDomainsList(){\n  el(\"pagesDomainsList\").innerHTML = \"加载中...\";\n  var aid = await ensureAccountId();\n  var r = await api(\"list-pages-domains\", { accountId: aid, projectName: pagesDomainsProject });\n  var arr = (r && r.result) || [];\n  el(\"pagesDomainsList\").innerHTML = \"\";\n  if(!arr.length) el(\"pagesDomainsList\").innerHTML = \"<div class=\\\"small\\\">暂无自定义域名</div>\";\n  // 判断域名是否在 Cloudflare 托管（后缀匹配 zone）\n  var zones = pagesDomainZonesCache || [];\n  function isCfHosted(host){\n    var h = String(host || \"\").toLowerCase();\n    for(var i = 0; i < zones.length; i++){\n      var z = String(zones[i] || \"\").toLowerCase();\n      if(h === z || h.endsWith(\".\" + z)) return true;\n    }\n    return false;\n  }\n  arr.forEach(function(dm){\n    var st = dm.status === \"active\" ? \"<span class=\\\"pill green\\\">已启用</span>\" : \"<span class=\\\"pill amber\\\">\" + esc(dm.status || \"?\") + \"</span>\";\n    var d = document.createElement(\"div\"); d.className = \"deploy-item\";\n    var hint = \"\";\n    if(dm.status !== \"active\" && pagesDomainsProject){\n      if(isCfHosted(dm.name)){\n        hint = \"<div class=\\\"small\\\" style=\\\"color:#6b7280;margin-top:4px\\\">Cloudflare 托管域名，DNS 自动配置中，稍后刷新查看</div>\";\n      } else {\n        hint = \"<div class=\\\"small\\\" style=\\\"color:#92400e;margin-top:4px\\\">外部域名，请手动添加 CNAME：\" + esc(dm.name) + \" → \" + esc(pagesDomainsProject + \".pages.dev\") + \"</div>\";\n      }\n    }\n    d.innerHTML = \"<div style=\\\"flex:1\\\"><a href=\\\"https://\" + escA(dm.name) + \"\\\" target=\\\"_blank\\\" style=\\\"color:#3b82f6;font-weight:600\\\">\" + esc(dm.name) + \"</a> \" + st + hint + \"</div>\";\n    var btn = document.createElement(\"button\"); btn.className = \"trash-btn\"; btn.textContent = \"✕\"; btn.title = \"删除\";\n    btn.addEventListener(\"click\", function(){ deletePagesDomain(dm.name); });\n    d.appendChild(btn); el(\"pagesDomainsList\").appendChild(d);\n  });\n}\nasync function loadPagesDomainZones(){\n  el(\"pagesDomainPrefix\").value = \"\"; pagesDomainZonesCache = [];\n  el(\"pagesDomainZoneWrap\").innerHTML = '<div class=\"small\">加载域名中...</div>'; updatePagesDomainPreview();\n  var r = await api(\"list-zones\");\n  var zones = (r && r.success && r.result) ? r.result : [];\n  pagesDomainZonesCache = zones.map(function(z){ return z.name; });\n  if(!zones.length) el(\"pagesDomainZoneWrap\").innerHTML = '<div class=\"small\" style=\"color:#ef4444\">该账号下没有可用域名，请先到「域名管理」添加</div>';\n  else {\n    var opts = zones.map(function(z){ return '<option value=\"' + escA(z.name) + '\">' + esc(z.name) + '</option>'; }).join(\"\");\n    el(\"pagesDomainZoneWrap\").innerHTML = '<select id=\"pagesDomainZone\" class=\"input\" onchange=\"updatePagesDomainPreview()\">' + opts + '</select>';\n  }\n  updatePagesDomainPreview();\n}\nfunction updatePagesDomainPreview(){\n  var prefix = el(\"pagesDomainPrefix\").value.trim().replace(/\\.$/, \"\");\n  var zone = \"\", sel = el(\"pagesDomainZone\");\n  if(sel) zone = sel.value; else if(pagesDomainZonesCache.length === 1) zone = pagesDomainZonesCache[0];\n  el(\"pagesDomainPreview\").textContent = prefix ? (prefix + \".\" + zone) : zone;\n}\nfunction closePagesDomains(){ el(\"pagesDomainsModal\").style.display = \"none\"; }\nasync function confirmAddPagesDomain(){\n  var aid = await ensureAccountId();\n  var h = \"\";\n  if(pagesDomainTab === \"ext\"){\n    h = el(\"pagesDomainExternal\").value.trim().toLowerCase().replace(/\\.$/, \"\");\n    if(!h || h.indexOf(\".\") < 0) return showNotification(\"请输入完整的外部域名\", \"error\");\n  } else {\n    var prefix = el(\"pagesDomainPrefix\").value.trim().replace(/\\.$/, \"\");\n    var zone = \"\", sel = el(\"pagesDomainZone\");\n    if(sel) zone = sel.value; else if(pagesDomainZonesCache.length === 1) zone = pagesDomainZonesCache[0];\n    if(!zone) return showNotification(\"没有可用域名\", \"error\");\n    h = prefix ? (prefix + \".\" + zone) : zone;\n  }\n  var r = await api(\"add-pages-domain\", { accountId: aid, projectName: pagesDomainsProject, hostname: h });\n  if(r && r.success){\n    if(pagesDomainTab === \"ext\"){\n      showNotification(\"添加成功！请到 DNS 服务商添加 CNAME：\" + h + \" → \" + pagesDomainsProject + \".pages.dev\", \"warning\");\n    } else {\n      showNotification(\"添加成功\" + (r.dnsNote || \"\"));\n    }\n    el(\"pagesDomainPrefix\").value = \"\"; el(\"pagesDomainExternal\").value = \"\"; refreshPagesDomainsList();\n  } else showNotification((r && r.error) || \"失败\", \"error\");\n}\nasync function deletePagesDomain(h){\n  if(!confirm(\"删除域名 \" + h + \"？\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"delete-pages-domain\", { accountId: aid, projectName: pagesDomainsProject, hostname: h });\n  if(r && r.success){ showNotification(\"已删除\"); refreshPagesDomainsList(); } else showNotification((r && r.error) || \"失败\", \"error\");\n}\nvar pagesBindKvCache = [], pagesBindD1Cache = [];\nasync function openPagesBindModal(){\n  var name = currentPagesProject; if(!name) return showNotification(\"请先进入一个项目\", \"error\");\n  el(\"pagesBindProjectName\").textContent = name; el(\"pagesBindModal\").style.display = \"flex\";\n  el(\"pagesEnvRows\").innerHTML = \"加载中...\"; el(\"pagesKvRows\").innerHTML = \"\"; el(\"pagesD1Rows\").innerHTML = \"\";\n  var aid = await ensureAccountId();\n  var kvr = await api(\"list-kv-namespaces\", { accountId: aid });\n  pagesBindKvCache = (kvr && kvr.success && kvr.result) ? kvr.result : [];\n  var d1r = await api(\"list-d1\", { accountId: aid });\n  pagesBindD1Cache = (d1r && d1r.success && d1r.result) ? d1r.result : [];\n  var r = await api(\"get-pages-bindings\", { accountId: aid, projectName: name });\n  var prod = (r && r.success && r.result && (r.result.production || r.result.preview)) || {};\n  el(\"pagesEnvRows\").innerHTML = \"\";\n  var ev = prod.env_vars || {};\n  Object.keys(ev).forEach(function(k){ var eo = ev[k] || {}; addPagesEnvRow(k, eo.value || \"\", (eo.type === \"secret_text\") ? \"secret\" : \"text\"); });\n  var kv = prod.kv_namespaces || {};\n  Object.keys(kv).forEach(function(k){ addPagesKvRow(k, kv[k] && kv[k].namespace_id); });\n  var d1o = prod.d1_databases || prod.d1 || {}, d1map = d1o.d1_databases ? d1o.d1_databases : d1o;\n  Object.keys(d1map).forEach(function(k){ var v = d1map[k]; addPagesD1Row(k, v && (v.id || v.database_id)); });\n}\nfunction closePagesBindModal(){ el(\"pagesBindModal\").style.display = \"none\"; }\nfunction switchPagesBindTab(tab){\n  document.querySelectorAll(\"#pagesBindModal [data-pbtab]\").forEach(function(e){ e.classList.toggle(\"active\", e.getAttribute(\"data-pbtab\") === tab); });\n  el(\"pbind-env\").style.display = tab === \"env\" ? \"block\" : \"none\";\n  el(\"pbind-kv\").style.display = tab === \"kv\" ? \"block\" : \"none\";\n  el(\"pbind-d1\").style.display = tab === \"d1\" ? \"block\" : \"none\";\n}\nfunction pagesBindDelBtn(div){\n  var btn = document.createElement(\"button\"); btn.className = \"trash-btn\"; btn.textContent = \"✕\";\n  btn.addEventListener(\"click\", function(){ div.remove(); });\n  div.appendChild(btn);\n}\nfunction addPagesEnvRow(n, v, t){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch\";\n  div.innerHTML = '<input class=\"input pb-name\" placeholder=\"变量名\" value=\"' + escA(n || \"\") + '\" style=\"flex:2\"><input class=\"input pb-val\" placeholder=\"值\" value=\"' + escA(v || \"\") + '\" style=\"flex:2\" type=\"' + ((t === \"secret\") ? \"password\" : \"text\") + '\"><select class=\"input pb-type\" style=\"flex:1;max-width:110px\"><option value=\"text\"' + ((t !== \"secret\") ? \" selected\" : \"\") + '>明文</option><option value=\"secret\"' + ((t === \"secret\") ? \" selected\" : \"\") + '>密钥</option></select>';\n  div.querySelector(\".pb-type\").addEventListener(\"change\", function(){\n    div.querySelector(\".pb-val\").type = (this.value === \"secret\") ? \"password\" : \"text\";\n  });\n  pagesBindDelBtn(div); el(\"pagesEnvRows\").appendChild(div);\n}\nfunction addPagesKvRow(binding, nsId){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch\";\n  var opts = pagesBindKvCache.map(function(ns){ return '<option value=\"' + escA(ns.id) + '\"' + (ns.id === nsId ? \" selected\" : \"\") + '>' + esc((ns.title || ns.id) + \" (\" + ns.id + \")\") + '</option>'; }).join(\"\");\n  div.innerHTML = '<input class=\"input pb-name\" placeholder=\"绑定名，如 KV\" value=\"' + escA(binding || \"\") + '\" style=\"flex:2\"><select class=\"input pb-val\" style=\"flex:3\">' + opts + '</select>';\n  pagesBindDelBtn(div); el(\"pagesKvRows\").appendChild(div);\n}\nfunction addPagesD1Row(binding, dbId){\n  var div = document.createElement(\"div\"); div.className = \"env-row-batch\";\n  var opts = pagesBindD1Cache.map(function(db){ var id = db.uuid || db.id; return '<option value=\"' + escA(id) + '\"' + (id === dbId ? \" selected\" : \"\") + '>' + esc((db.name || id) + \" (\" + id + \")\") + '</option>'; }).join(\"\");\n  div.innerHTML = '<input class=\"input pb-name\" placeholder=\"绑定名，如 DB\" value=\"' + escA(binding || \"\") + '\" style=\"flex:2\"><select class=\"input pb-val\" style=\"flex:3\">' + opts + '</select>';\n  pagesBindDelBtn(div); el(\"pagesD1Rows\").appendChild(div);\n}\nasync function savePagesBindings(){\n  var envVars = {}, kv = {}, d1 = {};\n  Array.from(document.querySelectorAll(\"#pagesEnvRows .env-row-batch\")).forEach(function(row){\n    var n = row.querySelector(\".pb-name\").value.trim(), v = row.querySelector(\".pb-val\").value;\n    var t = row.querySelector(\".pb-type\") ? row.querySelector(\".pb-type\").value : \"text\";\n    if(n) envVars[n] = { value: v, type: t };\n  });\n  Array.from(document.querySelectorAll(\"#pagesKvRows .env-row-batch\")).forEach(function(row){\n    var n = row.querySelector(\".pb-name\").value.trim(), v = row.querySelector(\".pb-val\").value;\n    if(n && v) kv[n] = v;\n  });\n  Array.from(document.querySelectorAll(\"#pagesD1Rows .env-row-batch\")).forEach(function(row){\n    var n = row.querySelector(\".pb-name\").value.trim(), v = row.querySelector(\".pb-val\").value;\n    if(n && v) d1[n] = v;\n  });\n  var aid = await ensureAccountId();\n  var r = await api(\"set-pages-bindings\", { accountId: aid, projectName: currentPagesProject, envVars: envVars, kv: kv, d1: d1 });\n  if(r && r.success){ showNotification(\"绑定已保存\"); closePagesBindModal(); } else showNotification((r && r.error) || \"保存失败\", \"error\");\n}\nwindow.refreshPagesProjects = refreshPagesProjects; window.backToPagesProjects = backToPagesProjects;\nwindow.openCreatePagesProject = openCreatePagesProject; window.closeCreatePagesModal = closeCreatePagesModal; window.confirmCreatePagesProject = confirmCreatePagesProject;\nwindow.switchPagesDeployTab = switchPagesDeployTab; window.clearPagesUpload = clearPagesUpload; window.startPagesUpload = startPagesUpload; window.startPagesGithubDeploy = startPagesGithubDeploy; window.refreshPagesUploadList = refreshPagesUploadList;\nwindow.viewPagesDeployments = viewPagesDeployments; window.refreshPagesDeployments = refreshPagesDeployments; window.triggerPagesDeploy = triggerPagesDeploy;\nwindow.retryPagesDeployment = retryPagesDeployment; window.deletePagesDeployment = deletePagesDeployment; window.rollbackPagesDeployment = rollbackPagesDeployment;\nwindow.openPagesDomains = openPagesDomains; window.closePagesDomains = closePagesDomains; window.confirmAddPagesDomain = confirmAddPagesDomain; window.deletePagesProject = deletePagesProject; window.switchPagesDomainTab = switchPagesDomainTab; window.updatePagesDomainPreview = updatePagesDomainPreview;\nwindow.refreshPagesDomainsList = refreshPagesDomainsList; window.loadPagesDomainZones = loadPagesDomainZones; window.updatePagesDomainPreview = updatePagesDomainPreview; window.deletePagesDomain = deletePagesDomain;\nwindow.openPagesBindModal = openPagesBindModal; window.closePagesBindModal = closePagesBindModal; window.switchPagesBindTab = switchPagesBindTab; window.addPagesEnvRow = addPagesEnvRow; window.addPagesKvRow = addPagesKvRow; window.addPagesD1Row = addPagesD1Row; window.savePagesBindings = savePagesBindings;\n// Pages 兼容日期\nvar pagesCompatSelectedDate = \"\";\nasync function openPagesCompatModal(){\n  if(!currentPagesProject) return showNotification(\"请先进入一个项目\", \"error\");\n  el(\"pagesCompatProjectName\").textContent = currentPagesProject;\n  pagesCompatSelectedDate = \"\";\n  el(\"pagesCompatDateInput\").value = \"\";\n  el(\"pagesCompatModal\").style.display = \"flex\";\n  el(\"pagesCompatCurrentVal\").textContent = \"\";\n  renderPagesCompatDateList(\"\");\n  try{\n    var aid = await ensureAccountId();\n    var r = await api(\"get-pages-project-overview\", { accountId: aid, projectName: currentPagesProject });\n    var dc = (r && r.result && r.result.deployment_configs) || {};\n    var cd = ((dc.production || {}).compatibility_date) || ((dc.preview || {}).compatibility_date) || \"\";\n    var m = String(cd).match(/^(\\d{4}-\\d{2}-\\d{2})/);\n    if(m){ pagesCompatSelectedDate = m[1]; el(\"pagesCompatDateInput\").value = m[1]; el(\"pagesCompatCurrentVal\").textContent = \"（当前: \" + m[1] + \"）\"; renderPagesCompatDateList(m[1]); }\n  }catch(e){}\n}\nfunction renderPagesCompatDateList(activeDate){\n  var html = \"\";\n  COMPAT_DATE_LIST.forEach(function(item){\n    var isActive = item.date === activeDate;\n    html += \"<div data-pcdate=\\\"\" + item.date + \"\\\" style=\\\"border:1px solid \" + (isActive ? \"#2563eb\" : \"#e6edf3\") + \";border-radius:8px;padding:12px;margin-bottom:8px;cursor:pointer;background:\" + (isActive ? \"#eff6ff\" : \"#fff\") + \"\\\">\";\n    html += \"<div style=\\\"font-weight:600;font-size:14px\\\">📅 \" + esc(item.date) + \"</div>\";\n    item.changes.forEach(function(c){ html += \"<div class=\\\"small\\\" style=\\\"margin-top:4px\\\">• \" + esc(c) + \"</div>\"; });\n    html += \"</div>\";\n  });\n  el(\"pagesCompatDateList\").innerHTML = html;\n  Array.from(el(\"pagesCompatDateList\").querySelectorAll(\"[data-pcdate]\")).forEach(function(d){\n    d.addEventListener(\"click\", function(){ pagesCompatSelectedDate = this.getAttribute(\"data-pcdate\"); el(\"pagesCompatDateInput\").value = pagesCompatSelectedDate; renderPagesCompatDateList(pagesCompatSelectedDate); });\n  });\n}\nfunction closePagesCompatModal(){ el(\"pagesCompatModal\").style.display = \"none\"; pagesCompatSelectedDate = \"\"; }\nasync function confirmPagesCompatDate(){\n  var d = (pagesCompatSelectedDate || el(\"pagesCompatDateInput\").value || \"\").trim();\n  if(!d) return showNotification(\"请选择兼容日期\", \"error\");\n  if(!/^\\d{4}-\\d{2}-\\d{2}$/.test(d)) return showNotification(\"日期格式不正确\", \"error\");\n  var aid = await ensureAccountId();\n  showNotification(\"正在保存...\", \"success\");\n  var r = await api(\"set-pages-compatibility\", { accountId: aid, projectName: currentPagesProject, compatibilityDate: d });\n  if(r && r.success){ showNotification(\"Pages 兼容日期已更新为 \" + d); closePagesCompatModal(); }\n  else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\n// Pages 兼容性标志\nvar pagesCompatSelectedFlags = [];\nasync function openPagesCompatFlagsModal(){\n  if(!currentPagesProject) return showNotification(\"请先进入一个项目\", \"error\");\n  el(\"pagesCompatFlagsProjectName\").textContent = currentPagesProject;\n  pagesCompatSelectedFlags = [];\n  el(\"pagesCompatFlagsCustom\").value = \"\";\n  el(\"pagesCompatFlagsModal\").style.display = \"flex\";\n  el(\"pagesCompatFlagsCurrent\").textContent = \"\";\n  renderPagesCompatFlagsList();\n  try{\n    var aid = await ensureAccountId();\n    var r = await api(\"get-pages-project-overview\", { accountId: aid, projectName: currentPagesProject });\n    var dc = (r && r.result && r.result.deployment_configs) || {};\n    var flags = ((dc.production || {}).compatibility_flags) || ((dc.preview || {}).compatibility_flags) || [];\n    if(Array.isArray(flags) && flags.length){\n      pagesCompatSelectedFlags = flags.slice();\n      el(\"pagesCompatFlagsCurrent\").textContent = \"（当前: \" + flags.join(\", \") + \"）\";\n      renderPagesCompatFlagsList();\n    }\n  }catch(e){}\n}\nfunction renderPagesCompatFlagsList(){\n  var html = \"\";\n  var allFlags = COMPAT_FLAGS_LIST.slice();\n  pagesCompatSelectedFlags.forEach(function(f){ if(allFlags.indexOf(f) < 0) allFlags.push(f); });\n  allFlags.forEach(function(f){\n    var on = pagesCompatSelectedFlags.indexOf(f) >= 0;\n    html += \"<label style=\\\"display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid \" + (on ? \"#2563eb\" : \"#e6edf3\") + \";border-radius:8px;margin-bottom:6px;cursor:pointer;background:\" + (on ? \"#eff6ff\" : \"#fff\") + \"\\\">\";\n    html += \"<input type=\\\"checkbox\\\" data-pcflag=\\\"\" + escA(f) + \"\\\"\" + (on ? \" checked\" : \"\") + \" onchange=\\\"togglePagesCompatFlag(this)\\\">\";\n    html += \"<span style=\\\"font-family:monospace;font-size:13px\\\">\" + esc(f) + \"</span></label>\";\n  });\n  el(\"pagesCompatFlagsList\").innerHTML = html || \"<div class=\\\"small\\\">无可用标志</div>\";\n}\nfunction togglePagesCompatFlag(cb){\n  var f = cb.getAttribute(\"data-pcflag\");\n  var i = pagesCompatSelectedFlags.indexOf(f);\n  if(cb.checked && i < 0) pagesCompatSelectedFlags.push(f);\n  else if(!cb.checked && i >= 0) pagesCompatSelectedFlags.splice(i, 1);\n  renderPagesCompatFlagsList();\n}\nfunction addCustomPagesCompatFlag(){\n  var f = el(\"pagesCompatFlagsCustom\").value.trim();\n  if(!f) return;\n  if(pagesCompatSelectedFlags.indexOf(f) < 0) pagesCompatSelectedFlags.push(f);\n  el(\"pagesCompatFlagsCustom\").value = \"\";\n  renderPagesCompatFlagsList();\n}\nfunction closePagesCompatFlagsModal(){ el(\"pagesCompatFlagsModal\").style.display = \"none\"; pagesCompatSelectedFlags = []; }\nasync function confirmPagesCompatFlags(){\n  var aid = await ensureAccountId();\n  showNotification(\"正在保存...\", \"success\");\n  var r = await api(\"set-pages-compatibility\", { accountId: aid, projectName: currentPagesProject, flags: pagesCompatSelectedFlags });\n  if(r && r.success){ showNotification(\"Pages 兼容性标志已更新\"); closePagesCompatFlagsModal(); }\n  else showNotification((r && r.error) || \"更新失败\", \"error\");\n}\nwindow.openPagesCompatModal = openPagesCompatModal; window.closePagesCompatModal = closePagesCompatModal; window.confirmPagesCompatDate = confirmPagesCompatDate;\nwindow.openPagesCompatFlagsModal = openPagesCompatFlagsModal; window.closePagesCompatFlagsModal = closePagesCompatFlagsModal;\nwindow.confirmPagesCompatFlags = confirmPagesCompatFlags; window.togglePagesCompatFlag = togglePagesCompatFlag; window.addCustomPagesCompatFlag = addCustomPagesCompatFlag;\nvar _cfSubdomain = \"\";\nasync function loadSubdomainSettings(){\n  // OAuth Client ID 配置回显\n  var ocb = el(\"oauthCbUrl\"); if(ocb) ocb.textContent = location.origin + \"/oauth/callback\";\n  var oinp = el(\"oauthClientIdInput\"); if(oinp) oinp.value = getOAuthClientId();\n  var ohint = el(\"oauthClientIdHint\");\n  if(ohint) ohint.textContent = localStorage.getItem(\"cfm_oauth_client_id\") ? \"已使用自定义 Client ID\" : \"当前使用内置默认 Client ID\";\n  var aid = await ensureAccountId();\n  el(\"currentSubdomain\").textContent = \"加载中...\"; _cfSubdomain = \"\";\n  var r = await api(\"get-workers-subdomain\", { accountId: aid });\n  var inp = el(\"newSubdomain\"), btn = el(\"saveSubdomainBtn\");\n  if(r && r.success && r.result && r.result.subdomain){\n    _cfSubdomain = r.result.subdomain;\n    el(\"currentSubdomain\").textContent = r.result.subdomain + \".workers.dev\";\n    if(inp){ inp.value = r.result.subdomain; inp.disabled = true; }\n    if(btn){ btn.disabled = true; btn.textContent = \"已设置\"; }\n    el(\"subdomainHint\").textContent = \"该账号已设置 workers.dev 子域名，每个账号仅可设置一次，无法修改。\";\n  } else {\n    el(\"currentSubdomain\").textContent = \"未设置\";\n    if(inp) inp.disabled = false;\n    if(btn){ btn.disabled = false; btn.textContent = \"保存设置\"; }\n    el(\"subdomainHint\").textContent = \"设置后，您的 Workers 将通过 https://worker-name.子域名.workers.dev 访问\";\n  }\n}\nasync function saveSubdomain(){\n  var s = el(\"newSubdomain\").value.trim();\n  if(!s) return showNotification(\"请输入子域名\", \"error\");\n  if(_cfSubdomain){\n    if(s === _cfSubdomain) return showNotification(\"子域名已是 \" + s + \"，无需重复设置\");\n    return showNotification(\"该账号已设置子域名 \" + _cfSubdomain + \"，每个账号仅可设置一次，无法修改\", \"error\");\n  }\n  if(!confirm(\"确定将 workers.dev 子域名设置为 \" + s + \" 吗？只能设置一次，设置后无法修改！\")) return;\n  var aid = await ensureAccountId();\n  var r = await api(\"put-workers-subdomain\", { accountId: aid, subdomain: s });\n  if(r && r.success){ showNotification(\"设置成功\"); loadSubdomainSettings(); }\n  else {\n    var msg = (r && r.error) || \"设置失败\";\n    if(msg.indexOf(\"associated subdomain\") >= 0) msg = \"该账号已设置过 workers.dev 子域名，每个账号仅可设置一次，无法修改\";\n    showNotification(msg, \"error\"); loadSubdomainSettings();\n  }\n}\nwindow.saveSubdomain = saveSubdomain;\nwindow.debugOut = debugOut; window.closeOut = closeOut;\nasync function initApp(){\n  if(!getActiveAccount()){ location.href = \"/login\"; return; }\n  // 存量 OAuth 账号标签迁移：把通用的“OAuth 授权”换成真实邮箱（只对旧存档跑一次）\n  try {\n    var _ma = getActiveAccount();\n    if(_ma && _ma.mode === \"oauth\" && (!_ma.label || _ma.label === \"OAuth 授权\")){\n      var _ur = await api(\"oauth-userinfo\", {});\n      if(_ur && _ur.success && _ur.email){\n        var _arr = loadSaved(); var _idx = getActiveIdx();\n        if(_arr[_idx] && _arr[_idx].mode === \"oauth\"){ _arr[_idx].label = _ur.email; saveAccounts(_arr); }\n      }\n    }\n  } catch(e){}\n  var _acc0 = getActiveAccount();\n  if(_acc0){\n    var _label0 = accountTitle(_acc0);\n    var _pill0 = _acc0.mode === \"token\" ? \"blue\" : (_acc0.mode === \"oauth\" ? \"green\" : \"amber\");\n    var _mt0 = _acc0.mode === \"token\" ? \"Token\" : (_acc0.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n    el(\"acctInfo\").innerHTML = \"<span style=\\\"font-weight:600\\\">\" + esc(_label0) + \"</span> <span class=\\\"pill \" + _pill0 + \"\\\">\" + _mt0 + \"</span><br><span class=\\\"small\\\">验证中...</span>\";\n  }\n  var r;\n  try { r = await api(\"validate-credentials\"); } catch(e){ r = null; }\n  if(r && r.success && r.result && r.result.length){\n    var a = getActiveAccount();\n    // 自动修复 token 账号显示名：label 缺失或就是 token 本身时，用 Cloudflare 账号名\n    if(a && a.mode === \"token\" && (!a.label || a.label === a.token) && r.result[0].name){\n      a.label = r.result[0].name;\n      var _arr = loadSaved(); var _idx = getActiveIdx();\n      if(_idx >= 0){ _arr[_idx] = a; saveAccounts(_arr); }\n    }\n    var label = accountTitle(a);\n    var pillCls = a.mode === \"token\" ? \"blue\" : (a.mode === \"oauth\" ? \"green\" : \"amber\");\n    var modeTxt = a.mode === \"token\" ? \"Token\" : (a.mode === \"oauth\" ? \"OAuth\" : \"Key\");\n    el(\"acctInfo\").innerHTML = \"<span style=\\\"font-weight:600\\\">\" + esc(label) + \"</span> <span class=\\\"pill \" + pillCls + \"\\\">\" + modeTxt + \"</span><br><span class=\\\"small\\\">\" + r.result.length + \" 个账号</span>\";\n    localStorage.setItem(\"cfm_accountId\", r.result[0].id);\n    currentAccountId = r.result[0].id;\n    el(\"authModeBadge\").textContent = modeTxt;\n    el(\"authModeBadge\").className = \"pill \" + pillCls;\n    el(\"authModeInfo\").textContent = \"当前使用 \" + (a.mode === \"token\" ? \"API Token（推荐）\" : (a.mode === \"oauth\" ? \"OAuth 2.0 授权\" : \"Global API Key（旧版）\")) + \" 鉴权 · \" + label;\n  }\n  refreshWorkers();\n}\nArray.from(document.querySelectorAll(\".modal\")).forEach(function(m){\n  m.addEventListener(\"click\", function(e){ if(e.target === m) m.style.display = \"none\"; });\n});\ndocument.addEventListener(\"click\", function(e){\n  var t = (e.target && e.target.closest) ? e.target.closest(\"[data-close-modal]\") : null;\n  if(t){ var m = t.closest(\".modal\"); if(m) m.style.display = \"none\"; }\n});\ndocument.addEventListener(\"keydown\", function(e){\n  if(e.key === \"Escape\") Array.from(document.querySelectorAll(\".modal\")).forEach(function(m){ m.style.display = \"none\"; });\n});\ninitApp();\n}\n})();";
}
