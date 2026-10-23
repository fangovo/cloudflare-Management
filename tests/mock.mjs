// 模拟 Cloudflare API + GitHub + R2 S3，用于离线跑 worker 的每一个 action。
// 只实现被 worker 代码读取的字段，其余返回宽松的 success。

export function makeState() {
  const acct = 'a'.repeat(32);
  return {
    accountId: acct,
    accounts: [{ id: acct, name: '测试账号' }],
    zones: [{ id: 'z1', name: 'example.com', status: 'active' }],
    workers: new Map(), // name -> { code, bindings, settings, subdomain, schedules, deployments, versions }
    kv: new Map(), // nsId -> { id, title }
    kvValues: new Map(), // `${nsId}/${key}` -> string
    d1: new Map(), // uuid -> { uuid, name, file_size }
    r2: new Map(), // name -> { name, creation_date }
    dns: new Map(), // zoneId -> [records]
    pages: new Map(), // name -> { name, production_branch, deployment_configs, deployments: [] }
    tunnels: new Map(), // id -> { id, name, ingress }
    calls: [], // 记录所有请求，便于断言
    files: new Map(), // Pages 资源 hash -> 内容
  };
}

// ---------------- 最小 ZIP（STORED，不压缩；本 worker 的解析器不校验 CRC） ----------------
export function makeZip(files) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const f of files) {
    const name = Buffer.from(f.path.replace(/^\//, ''), 'utf8');
    const data = Buffer.from(f.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8); // stored
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(data.length, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt16LE(name.length, 22);
    local.writeUInt16LE(0, 24);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, name, data);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt32LE(0, 12);
    cd.writeUInt32LE(data.length, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt16LE(name.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cd, name]));
    offset += local.length + name.length + data.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return new Uint8Array(Buffer.concat([...chunks, cdBuf, eocd]));
}

const j = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status,
  headers: { 'content-type': 'application/json' },
});
const ok = (result, info) => j({ success: true, result, ...(info ? { result_info: info } : {}) });
const fail = (msg, status = 400) => j({ success: false, errors: [{ code: 10000, message: msg }] }, status);

function multipartBody(boundary, parts) {
  let s = '';
  for (const p of parts) {
    s += `--${boundary}\r\n${p.head}\r\n\r\n${p.body}\r\n`;
  }
  s += `--${boundary}--\r\n`;
  return s;
}

// 把 worker 脚本按 Cloudflare 的 multipart 形式返回
function scriptResponse(name, code, moduleCount = 1) {
  const boundary = '----mockboundary';
  const parts = [];
  for (let i = 0; i < moduleCount; i++) {
    parts.push({
      head: `Content-Disposition: form-data; name="${i === 0 ? 'worker.js' : 'mod' + i + '.js'}"; filename="${i === 0 ? 'worker.js' : 'mod' + i + '.js'}"\r\nContent-Type: application/javascript+module`,
      body: i === 0 ? code : `export const x${i} = ${i};`,
    });
  }
  return new Response(multipartBody(boundary, parts), {
    status: 200,
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
  });
}

async function readForm(body) {
  const out = {};
  if (!body) return out;
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    for (const [k, v] of body.entries()) {
      out[k] = typeof v === 'string' ? v : await v.text();
    }
    return out;
  }
  if (typeof body === 'string') {
    try { return JSON.parse(body); } catch { return { raw: body }; }
  }
  return { raw: String(body) };
}

export function installMock(S) {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, opts = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    const method = (opts.method || 'GET').toUpperCase();
    const u = new URL(url);
    const path = u.pathname;
    S.calls.push({ method, url, path, search: u.search, body: opts.body });

    // ---------- GitHub ----------
    if (u.hostname === 'api.github.com') {
      if (/^\/repos\/[^/]+\/[^/]+$/.test(path)) return j({ default_branch: 'main' });
      return j({});
    }
    if (u.hostname === 'codeload.github.com') {
      const zip = makeZip([
        { path: 'repo-main/index.html', data: '<html>hi</html>' },
        { path: 'repo-main/_worker.js', data: 'export default { fetch(){ return new Response("x") } }' },
        { path: 'repo-main/assets/app.js', data: 'console.log(1)' },
      ]);
      return new Response(zip, { status: 200, headers: { 'content-type': 'application/zip' } });
    }
    if (u.hostname === 'raw.githubusercontent.com') {
      return new Response('export default { async fetch(){ return new Response("hello") } };', { status: 200 });
    }
    if (u.hostname === 'example.com' || u.hostname === 'files.example.com') {
      return new Response('export default { async fetch(){ return new Response("from url") } };', { status: 200 });
    }
    if (u.hostname.endsWith('.r2.cloudflarestorage.com')) {
      // S3 兼容接口
      if (!/^AWS4-HMAC-SHA256 Credential=/.test(opts.headers?.authorization || '')) {
        return new Response('<Error><Message>bad auth</Message></Error>', { status: 403 });
      }
      if (method === 'GET' && u.searchParams.get('list-type') === '2') {
        return new Response(
          '<?xml version="1.0"?><ListBucketResult><IsTruncated>false</IsTruncated><KeyCount>2</KeyCount>' +
          '<Contents><Key>a.txt</Key><Size>3</Size><LastModified>2026-01-01T00:00:00Z</LastModified><ETag>"x"</ETag></Contents>' +
          '<Contents><Key>dir/b.txt</Key><Size>4</Size><LastModified>2026-01-01T00:00:00Z</ETag></Contents>' +
          '<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes></ListBucketResult>',
          { status: 200, headers: { 'content-type': 'application/xml' } });
      }
      return new Response(null, { status: method === 'DELETE' ? 204 : 200 });
    }

    if (u.hostname !== 'api.cloudflare.com') return realFetch(input, opts);

    // ---------- Pages 资源（JWT，无 account 前缀） ----------
    if (path.startsWith('/client/v4/pages/assets/')) {
      if (path.endsWith('check-missing')) return ok([]);
      if (path.endsWith('upload')) return ok({});
      if (path.endsWith('upsert-hashes')) return ok({});
      return ok({});
    }
    if (path === '/client/v4/graphql') {
      return graphql(S, opts);
    }

    const p = path.replace('/client/v4', '');
    const a = S.accountId;

    // ---------- 账号 ----------
    if (p === '/accounts' && method === 'GET') return ok(S.accounts);
    if (p === '/user' && method === 'GET') return ok({ email: 'me@example.com' });
    if (p === '/user/tokens/verify') return ok({ status: 'active' });

    // ---------- Workers 脚本 ----------
    let m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts$/);
    if (m && method === 'GET') {
      return ok([...S.workers.keys()].map((n) => ({ id: n, created_on: '2026-01-01' })));
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)$/);
    if (m) {
      const name = decodeURIComponent(m[2]);
      if (method === 'GET') {
        const w = S.workers.get(name);
        if (!w) return j({ success: false, errors: [{ message: 'not found' }] }, 404);
        return scriptResponse(name, w.code, w.moduleCount || 1);
      }
      if (method === 'PUT') {
        const form = await readForm(opts.body);
        const meta = JSON.parse(form.metadata || '{}');
        const code = form['worker.js'] ?? form.script ?? '';
        const prev = S.workers.get(name) || {};
        S.workers.set(name, {
          ...prev,
          name,
          code,
          bindings: meta.bindings || [],
          settings: {
            compatibility_date: meta.compatibility_date || prev.settings?.compatibility_date || '2024-01-01',
            compatibility_flags: meta.compatibility_flags || prev.settings?.compatibility_flags || [],
            usage_model: meta.usage_model || 'standard',
            observability: meta.observability || prev.settings?.observability || null,
          },
          moduleCount: 1,
        });
        return ok({ id: name, etag: 'e1' });
      }
      if (method === 'DELETE') {
        if (!S.workers.delete(name)) return fail('not found', 404);
        return ok({});
      }
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/(bindings|settings|schedules|content|deployments|subdomain|versions)$/);
    if (m) {
      const name = decodeURIComponent(m[2]);
      const sub = m[3];
      const w = S.workers.get(name);
      if (!w) return fail('not found', 404);
      if (sub === 'bindings' && method === 'GET') return ok(w.bindings || []);
      if (sub === 'settings') {
        if (method === 'GET') return ok({ ...w.settings, bindings: w.bindings });
        if (method === 'PATCH') {
          const form = await readForm(opts.body);
          const st = JSON.parse(form.settings || '{}');
          if (st.compatibility_date) w.settings.compatibility_date = st.compatibility_date;
          if (st.compatibility_flags) w.settings.compatibility_flags = st.compatibility_flags;
          return ok({});
        }
      }
      if (sub === 'schedules') {
        if (method === 'GET') return ok({ schedules: w.schedules || [] });
        if (method === 'PUT') {
          let body = opts.body;
          if (typeof body === 'string') { try { body = JSON.parse(body); } catch { body = []; } }
          w.schedules = Array.isArray(body) ? body : [];
          return ok({ schedules: w.schedules });
        }
      }
      if (sub === 'subdomain') {
        if (method === 'GET') return ok({ enabled: w.subdomain !== false, previews_enabled: false });
        if (method === 'POST') {
          const body = JSON.parse(opts.body || '{}');
          w.subdomain = !!body.enabled;
          return ok({ enabled: w.subdomain });
        }
      }
      if (sub === 'deployments') {
        if (method === 'GET') return ok({ deployments: [{ id: 'dep1', versions: [{ version_id: 'v1' }] }] });
        if (method === 'POST') return ok({ id: 'dep2' });
      }
      if (sub === 'versions' && method === 'GET') return ok([{ id: 'v1', number: 1 }]);
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/workers\/([^/]+)\/versions$/);
    if (m && method === 'GET') return ok([{ id: 'v1', number: 1 }]);
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/secrets$/);
    if (m && method === 'PUT') {
      const body = JSON.parse(opts.body || '{}');
      const w = S.workers.get(decodeURIComponent(m[2]));
      if (!w) return fail('not found', 404);
      w.bindings = (w.bindings || []).filter((b) => b.name !== body.name);
      w.bindings.push({ type: 'secret_text', name: body.name });
      return ok({ name: body.name, type: 'secret_text' });
    }
    m = p.match(/^\/accounts\/([^/]+)\/workers\/scripts\/([^/]+)\/secrets\/([^/]+)$/);
    if (m && method === 'DELETE') {
      const w = S.workers.get(decodeURIComponent(m[2]));
      const n = decodeURIComponent(m[3]);
      if (w) w.bindings = (w.bindings || []).filter((b) => b.name !== n);
      return ok({});
    }
    if (/\/workers\/scripts\/[^/]+\/secrets-bulk$/.test(p) && method === 'PATCH') {
      const body = JSON.parse(opts.body || '{}');
      const name = decodeURIComponent(p.split('/')[5]);
      const w = S.workers.get(name);
      if (!w) return fail('not found', 404);
      for (const s of body.secrets || []) {
        w.bindings = (w.bindings || []).filter((b) => b.name !== s.name);
        if (s.type === 'secret_text' && s.text != null) w.bindings.push({ type: 'secret_text', name: s.name });
      }
      return ok({});
    }
    if (p.match(/^\/accounts\/([^/]+)\/workers\/subdomain$/)) {
      if (method === 'GET') return ok({ subdomain: 'demo' });
      return ok({ subdomain: 'demo2' });
    }
    if (p.match(/^\/accounts\/([^/]+)\/workers\/domains$/)) {
      if (method === 'GET') {
        const out = [];
        for (const [n, w] of S.workers) for (const d of w.domains || []) out.push({ ...d, service: n });
        return ok(out);
      }
      if (method === 'PUT') {
        const body = JSON.parse(opts.body || '{}');
        const w = S.workers.get(body.service) || { domains: [] };
        w.domains = (w.domains || []).filter((x) => x.hostname !== body.hostname);
        w.domains.push({ id: 'dom-' + body.hostname, hostname: body.hostname, zone_name: 'example.com', environment: 'production' });
        S.workers.set(body.service, w);
        return ok({ id: 'dom-x' });
      }
    }
    if (/^\/accounts\/[^/]+\/workers\/domains\/[^/]+$/.test(p) && method === 'DELETE') return ok({});

    // ---------- Zones / DNS / Routes ----------
    if (p === '/zones' && method === 'GET') {
      const nameQ = u.searchParams.get('name');
      const list = nameQ ? S.zones.filter((z) => z.name === nameQ) : S.zones;
      return ok(list, { page: 1, total_pages: 1, count: list.length, total_count: list.length });
    }
    if (p === '/zones' && method === 'POST') return ok({ id: 'z2', name: 'new.com' });
    if (/^\/zones\/[^/]+$/.test(p) && method === 'DELETE') return ok({ id: 'z1' });
    m = p.match(/^\/zones\/([^/]+)\/dns_records$/);
    if (m) {
      const zid = m[1];
      const list = S.dns.get(zid) || [];
      if (method === 'GET') {
        let out = list;
        const nq = u.searchParams.get('name');
        const tq = u.searchParams.get('type');
        if (nq) out = out.filter((r) => r.name === nq);
        if (tq) out = out.filter((r) => r.type === tq);
        return ok(out);
      }
      if (method === 'POST') {
        const body = JSON.parse(opts.body || '{}');
        const rec = { id: 'rec' + (list.length + 1), ...body };
        list.push(rec);
        S.dns.set(zid, list);
        return ok(rec);
      }
    }
    m = p.match(/^\/zones\/([^/]+)\/dns_records\/([^/]+)$/);
    if (m) {
      const list = S.dns.get(m[1]) || [];
      const idx = list.findIndex((r) => r.id === m[2]);
      if (method === 'PATCH') {
        const body = JSON.parse(opts.body || '{}');
        if (idx >= 0) list[idx] = { ...list[idx], ...body };
        return ok(list[idx]);
      }
      if (method === 'DELETE') { if (idx >= 0) list.splice(idx, 1); return ok({ id: m[2] }); }
    }
    if (/\/dns_records\/batch$/.test(p) && method === 'POST') return ok({ posts: [] });
    m = p.match(/^\/zones\/([^/]+)\/workers\/routes$/);
    if (m) {
      if (method === 'GET') return ok([{ id: 'r1', pattern: 'example.com/*', script: 'demo' }]);
      return ok({ id: 'r2', pattern: 'x' });
    }
    if (/\/workers\/routes\/[^/]+$/.test(p) && method === 'DELETE') return ok({});
    if (p === '/graphql' && method === 'POST') return graphql(S, opts);

    // ---------- KV ----------
    if (p.match(/^\/accounts\/[^/]+\/storage\/kv\/namespaces$/) && method === 'GET') {
      return ok([...S.kv.values()]);
    }
    if (p.match(/^\/accounts\/[^/]+\/storage\/kv\/namespaces$/) && method === 'POST') {
      const body = JSON.parse(opts.body || '{}');
      const ns = { id: 'ns' + (S.kv.size + 1), title: body.title };
      S.kv.set(ns.id, ns);
      return ok(ns);
    }
    m = p.match(/^\/accounts\/[^/]+\/storage\/kv\/namespaces\/([^/]+)$/);
    if (m) {
      if (method === 'DELETE') { S.kv.delete(m[1]); return ok({}); }
      if (method === 'PUT') {
        const body = JSON.parse(opts.body || '{}');
        const ns = S.kv.get(m[1]) || { id: m[1] };
        ns.title = body.title;
        S.kv.set(m[1], ns);
        return ok(ns);
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/storage\/kv\/namespaces\/([^/]+)\/keys$/);
    if (m && method === 'GET') {
      const prefix = u.searchParams.get('prefix') || '';
      const keys = [...S.kvValues.keys()].filter((k) => k.startsWith(m[1] + '/')).map((k) => k.slice(m[1].length + 1)).filter((k) => k.startsWith(prefix));
      return ok(keys.map((k) => ({ name: k })));
    }
    m = p.match(/^\/accounts\/[^/]+\/storage\/kv\/namespaces\/([^/]+)\/values\/(.+)$/);
    if (m) {
      const key = m[1] + '/' + decodeURIComponent(m[2]);
      if (method === 'GET') {
        if (!S.kvValues.has(key)) return new Response('not found', { status: 404 });
        return new Response(S.kvValues.get(key), { status: 200 });
      }
      if (method === 'PUT') { S.kvValues.set(key, String(opts.body ?? '')); return ok({}); }
      if (method === 'DELETE') { S.kvValues.delete(key); return ok({}); }
    }
    if (/\/storage\/kv\/namespaces\/[^/]+\/bulk$/.test(p) && method === 'PUT') {
      const body = JSON.parse(opts.body || '[]');
      const ns = p.split('/')[5];
      for (const it of body) S.kvValues.set(ns + '/' + it.key, it.value);
      return ok({ successful_key_count: body.length });
    }
    if (/\/storage\/kv\/namespaces\/[^/]+\/bulk\/delete$/.test(p) && method === 'POST') return ok({});

    // ---------- D1 ----------
    if (/^\/accounts\/[^/]+\/d1\/database$/.test(p)) {
      if (method === 'GET') return ok([...S.d1.values()]);
      if (method === 'POST') {
        const body = JSON.parse(opts.body || '{}');
        const db = { uuid: 'db' + (S.d1.size + 1), name: body.name, file_size: 0 };
        S.d1.set(db.uuid, db);
        return ok(db);
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/d1\/database\/([^/]+)$/);
    if (m && method === 'DELETE') { S.d1.delete(m[1]); return ok({}); }
    m = p.match(/^\/accounts\/[^/]+\/d1\/database\/([^/]+)\/(query|raw|export)$/);
    if (m) {
      if (m[2] === 'query') return ok([{ results: [{ n: 1 }], success: true }]);
      if (m[2] === 'raw') return ok([[1]]);
      return ok({ at_bookmark: 'bm1', status: 'complete', result: { filename: 'dump.sql', signed_url: 'https://x' } });
    }

    // ---------- R2 ----------
    if (/^\/accounts\/[^/]+\/r2\/buckets$/.test(p)) {
      if (method === 'GET') return ok({ buckets: [...S.r2.values()] });
      if (method === 'POST') {
        const body = JSON.parse(opts.body || '{}');
        const b = { name: body.name, creation_date: '2026-01-01T00:00:00Z', location: 'APAC', storage_class: body.storageClass || 'Standard' };
        S.r2.set(b.name, b);
        return ok(b);
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/r2\/buckets\/([^/]+)$/);
    if (m) {
      const n = decodeURIComponent(m[1]);
      if (method === 'GET') return ok(S.r2.get(n) || { name: n });
      if (method === 'PATCH') return ok({});
      if (method === 'DELETE') { S.r2.delete(n); return ok({}); }
    }
    if (/\/r2\/buckets\/[^/]+\/domains\/managed$/.test(p)) {
      return method === 'GET' ? ok({ enabled: true, domain: 'pub.r2.dev' }) : ok({});
    }
    if (/\/r2\/buckets\/[^/]+\/domains\/custom$/.test(p)) {
      return method === 'GET' ? ok([{ domain: 'cdn.example.com', enabled: true }]) : ok({});
    }
    if (/\/r2\/buckets\/[^/]+\/domains\/custom\/.+$/.test(p) && method === 'DELETE') return ok({});
    if (/\/r2\/temp-access-credentials$/.test(p)) return ok({ accessKeyId: 'AK', secretAccessKey: 'SK', sessionToken: 'ST' });
    if (/\/r2-catalog\/[^/]+$/.test(p) && method === 'GET') return ok({ status: 'active', name: 'wh', maintenance_config: {} });
    if (/\/r2-catalog\/[^/]+\/(enable|disable)$/.test(p)) return ok({});

    // ---------- Pages ----------
    if (/^\/accounts\/[^/]+\/pages\/projects$/.test(p)) {
      if (method === 'GET') return ok([...S.pages.values()]);
      if (method === 'POST') {
        const body = JSON.parse(opts.body || '{}');
        const proj = { name: body.name, production_branch: body.production_branch || 'main', deployment_configs: { production: {}, preview: {} }, deployments: [] };
        S.pages.set(proj.name, proj);
        return ok(proj);
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/pages\/projects\/([^/]+)$/);
    if (m) {
      const n = decodeURIComponent(m[1]);
      const proj = S.pages.get(n);
      if (method === 'GET') return proj ? ok(proj) : fail('not found', 404);
      if (method === 'PATCH') {
        const body = JSON.parse(opts.body || '{}');
        if (body.deployment_configs) {
          proj.deployment_configs = { ...proj.deployment_configs, ...body.deployment_configs };
        }
        return ok(proj);
      }
      if (method === 'DELETE') { S.pages.delete(n); return ok({}); }
    }
    m = p.match(/^\/accounts\/[^/]+\/pages\/projects\/([^/]+)\/upload-token$/);
    if (m) return ok({ jwt: 'jwt-token' });
    m = p.match(/^\/accounts\/[^/]+\/pages\/projects\/([^/]+)\/deployments$/);
    if (m) {
      const n = decodeURIComponent(m[1]);
      const proj = S.pages.get(n) || { deployments: [] };
      if (method === 'GET') return ok(proj.deployments);
      if (method === 'POST') {
        const dep = { id: 'dep' + (proj.deployments.length + 1), url: `https://${n}.pages.dev`, latest_stage: { status: 'success' }, aliases: [] };
        proj.deployments.unshift(dep);
        S.pages.set(n, proj);
        return ok(dep);
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/pages\/projects\/([^/]+)\/deployments\/([^/]+)$/);
    if (m) {
      if (method === 'GET') return ok({ id: m[2], url: `https://${m[2]}.${m[1]}.pages.dev`, latest_stage: { status: 'success' } });
      if (method === 'DELETE') return ok({});
    }
    if (/\/deployments\/[^/]+\/retry$/.test(p)) return ok({ id: 'dep9' });
    m = p.match(/^\/accounts\/[^/]+\/pages\/projects\/([^/]+)\/domains$/);
    if (m) {
      if (method === 'GET') return ok([{ name: 'site.example.com' }]);
      return ok({ name: 'new.example.com' });
    }
    if (/\/pages\/projects\/[^/]+\/domains\/.+$/.test(p) && method === 'DELETE') return ok({});

    // ---------- Tunnels ----------
    if (/^\/accounts\/[^/]+\/cfd_tunnel$/.test(p)) {
      if (method === 'GET') return ok([...S.tunnels.values()].map((t) => ({ id: t.id, name: t.name, status: 'healthy' })));
      if (method === 'POST') {
        const body = JSON.parse(opts.body || '{}');
        const t = { id: 'tun' + (S.tunnels.size + 1), name: body.name, ingress: [] };
        S.tunnels.set(t.id, t);
        return ok({ id: t.id, name: t.name });
      }
    }
    m = p.match(/^\/accounts\/[^/]+\/cfd_tunnel\/([^/]+)$/);
    if (m) {
      if (method === 'GET') {
        const t = S.tunnels.get(m[1]);
        return t ? ok({ id: t.id, name: t.name }) : fail('not found', 404);
      }
      if (method === 'DELETE') { S.tunnels.delete(m[1]); return ok({}); }
    }
    m = p.match(/^\/accounts\/[^/]+\/cfd_tunnel\/([^/]+)\/(configurations|token|connections)$/);
    if (m) {
      const id = m[1], sub = m[2];
      const t = S.tunnels.get(id) || { ingress: [] };
      if (sub === 'token') return ok('TUNNEL_TOKEN');
      if (sub === 'connections') return ok({});
      if (sub === 'configurations') {
        if (method === 'GET') return ok({ config: { ingress: t.ingress || [] } });
        const body = JSON.parse(opts.body || '{}');
        t.ingress = (body.config && body.config.ingress) || [];
        S.tunnels.set(id, t);
        return ok({ config: body.config });
      }
    }

    return fail('mock: 未实现的路径 ' + method + ' ' + p, 404);
  };
  return () => { globalThis.fetch = realFetch; };
}

function graphql(S, opts) {
  const body = JSON.parse(opts.body || '{}');
  const q = String(body.query || '');
  const v = body.variables || {};
  const acct = S.accountId;
  const accounts = [{}];
  if (q.includes('httpRequestsAdaptiveGroups')) {
    return j({ data: { viewer: { zones: [{ cur: [{ count: 100, sum: { edgeResponseBytes: 1000, visits: 10 } }], prev: [{ count: 90, sum: { edgeResponseBytes: 900, visits: 9 } }], countries: [{ count: 5, sum: { edgeResponseBytes: 50 }, dimensions: { clientCountryName: 'CN' } }] }] } } });
  }
  if (q.includes('pagesFunctionsInvocationsAdaptiveGroups')) {
    accounts[0] = { pagesFunctionsInvocationsAdaptiveGroups: [{ sum: { requests: 3 } }], workersInvocationsAdaptive: [{ sum: { requests: 7 } }] };
  } else if (q.includes('workersInvocationsAdaptive')) {
    accounts[0] = { workersInvocationsAdaptive: [{ dimensions: { scriptName: 'demo', datetimeHour: '2026-01-01T00:00:00Z' }, sum: { requests: 10, errors: 1 } }] };
  } else if (q.includes('kvOperationsAdaptiveGroups')) {
    accounts[0] = { ops: [{ sum: { requests: 5 }, dimensions: { actionType: 'read' } }, { sum: { requests: 2 }, dimensions: { actionType: 'write' } }], store: [{ max: { byteCount: 100 }, dimensions: { namespaceId: 'ns1' } }] };
  } else if (q.includes('d1AnalyticsAdaptiveGroups')) {
    accounts[0] = { a: [{ sum: { readQueries: 4, writeQueries: 2, rowsRead: 10, rowsWritten: 3 } }] };
  } else if (q.includes('r2OperationsAdaptiveGroups') && /bucketName/.test(q)) {
    // r2-metrics：三个查询各自只取一个节点，且字段名是全名
    accounts[0] = {
      r2StorageAdaptiveGroups: [{ max: { payloadSize: 100, metadataSize: 10, objectCount: 3 } }],
      r2OperationsAdaptiveGroups: [{ sum: { requests: 6 }, dimensions: { actionType: 'PutObject' } }],
      r2BandwidthUsageAdaptiveGroups: [{ sum: { bytesDownload: 10, bytesUpload: 5 } }],
    };
  } else if (q.includes('r2StorageAdaptiveGroups') && /bucketName/.test(q)) {
    accounts[0] = { r2StorageAdaptiveGroups: [{ max: { payloadSize: 100, metadataSize: 10, objectCount: 3 } }] };
  } else if (q.includes('r2BandwidthUsageAdaptiveGroups') && /bucketName/.test(q)) {
    accounts[0] = { r2BandwidthUsageAdaptiveGroups: [{ sum: { bytesDownload: 10, bytesUpload: 5 } }] };
  } else if (q.includes('r2OperationsAdaptiveGroups')) {
    // get-resource-usage：用 ops / store 别名
    accounts[0] = { ops: [{ sum: { requests: 6 }, dimensions: { actionType: 'GetObject' } }], store: [{ max: { payloadSize: 100, metadataSize: 10 } }] };
  } else if (q.includes('r2StorageAdaptiveGroups')) {
    accounts[0] = { r2StorageAdaptiveGroups: [{ max: { payloadSize: 100, metadataSize: 10, objectCount: 3 } }], r2OperationsAdaptiveGroups: [{ sum: { requests: 6 }, dimensions: { actionType: 'PutObject' } }], r2BandwidthUsageAdaptiveGroups: [{ sum: { bytesDownload: 10, bytesUpload: 5 } }] };
  } else {
    accounts[0] = {};
  }
  return j({ data: { viewer: { accounts } } });
}
