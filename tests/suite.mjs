// 功能冒烟测试：把每个 action 真跑一遍（mock CF API），并针对已知 bug 做断言。
import { makeState, installMock, makeZip } from './mock.mjs';

const MODULE = process.argv[2] || './worker.work.mjs';
const mod = await import(MODULE + '?v=' + Date.now());
const worker = mod.default;

function fakeKV() {
  const m = new Map();
  return {
    _m: m,
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async put(k, v) { m.set(k, String(v)); },
    async delete(k) { m.delete(k); },
  };
}

function makeEnv(extra) {
  return { CF_ACCOUNTS_KV: fakeKV(), ...extra };
}

async function call(S, action, payload = {}, env = {}) {
  installMock(S);
  try {
    const req = new Request('https://panel.example.com/api', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ action, authMode: 'token', token: 'tok', accountId: S.accountId, ...payload }),
    });
    const res = await worker.fetch(req, makeEnv(env), {});
    const text = await res.text();
    let body;
    try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 300) }; }
    return { status: res.status, body };
  } finally {
    // mock 会在下次 installMock 时被替换，这里无需还原
  }
}

const results = [];
async function test(name, fn) {
  const S = makeState();
  try {
    const detail = await fn(S);
    results.push({ name, ok: true, detail });
  } catch (e) {
    results.push({ name, ok: false, detail: String(e && e.stack || e).split('\n').slice(0, 3).join(' | ') });
  }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }
function assertSuccess(r, msg) {
  if (!r.body || r.body.success !== true) {
    throw new Error((msg || 'expected success') + ' → ' + JSON.stringify(r.body).slice(0, 240));
  }
}

// ---------- Worker 相关 ----------
await test('validate-credentials', async (S) => {
  const r = await call(S, 'validate-credentials');
  assertSuccess(r);
});
await test('list-accounts', async (S) => {
  const r = await call(S, 'list-accounts');
  assertSuccess(r); assert(r.body.result[0].id === S.accountId, 'account id');
});
await test('list-workers', async (S) => {
  S.workers.set('demo', { code: 'export default {}', bindings: [{ type: 'plain_text', name: 'A', text: '1' }], settings: {}, subdomain: true });
  S.workers.set('demo2', { code: 'export default {}', bindings: [], settings: {}, subdomain: true });
  const r = await call(S, 'list-workers');
  assertSuccess(r);
  assert(r.body.result.length === 2, '2 workers');
  assert(r.body.result[0].bindings.length === 1, 'bindings attached');
  assert(r.body.accountSubdomain === 'demo', 'subdomain');
});
await test('get-worker-script', async (S) => {
  S.workers.set('demo', { code: "export default { fetch(){ return new Response('hi') } }" });
  const r = await call(S, 'get-worker-script', { scriptName: 'demo' });
  assert(r.body.rawScript.indexOf('export default') === 0, 'script body');
  assert(r.body.success === true || r.body.ok === true, 'success flag');
});
await test('deploy-worker (新建)', async (S) => {
  const r = await call(S, 'deploy-worker', { scriptName: 'newbie', scriptSource: "export default { async fetch(){ return new Response('x') } }", metadataBindings: [{ type: 'plain_text', name: 'K', text: 'v' }] });
  assertSuccess(r);
  assert(S.workers.get('newbie').bindings[0].name === 'K', 'binding saved');
});
await test('deploy-worker (保留已有 secret)', async (S) => {
  S.workers.set('demo', {
    code: 'export default {}', settings: {},
    bindings: [{ type: 'secret_text', name: 'SEC' }, { type: 'plain_text', name: 'OLD', text: '1' }],
  });
  const r = await call(S, 'deploy-worker', { scriptName: 'demo', scriptSource: 'export default {}', metadataBindings: [{ type: 'plain_text', name: 'NEW', text: '2' }] });
  assertSuccess(r);
  const b = S.workers.get('demo').bindings;
  assert(b.some((x) => x.name === 'NEW'), 'new binding merged');
});
await test('quick-deploy (text)', async (S) => {
  const r = await call(S, 'quick-deploy', { scriptName: 'q1', sourceKind: 'text', sourceText: 'export default {}', d1List: [{ name: 'mydb', bindName: 'DB' }], kvList: [{ nsName: 'mykv', bindName: 'KV' }], envVars: [{ name: 'A', value: '1' }] });
  assertSuccess(r);
  const b = S.workers.get('q1').bindings;
  assert(b.some((x) => x.type === 'd1' && x.name === 'DB'), 'd1 bound');
  assert(b.some((x) => x.type === 'kv_namespace' && x.name === 'KV'), 'kv bound');
  assert(b.some((x) => x.type === 'plain_text' && x.name === 'A'), 'env bound');
});
await test('quick-deploy (url + zip)', async (S) => {
  const r = await call(S, 'quick-deploy', { scriptName: 'q2', sourceKind: 'url', sourceUrl: 'https://example.com/x.js' });
  assertSuccess(r);
});
await test('quick-deploy (b64zip)', async (S) => {
  const zip = makeZip([{ path: '_worker.js', data: 'export default { async fetch(){return new Response(1)} }' }]);
  const r = await call(S, 'quick-deploy', { scriptName: 'q3', sourceKind: 'b64zip', sourceB64: Buffer.from(zip).toString('base64') });
  assertSuccess(r);
});
await test('delete-worker', async (S) => {
  S.workers.set('demo', { code: 'x', bindings: [] });
  const r = await call(S, 'delete-worker', { scriptName: 'demo' });
  assertSuccess(r); assert(!S.workers.has('demo'), 'deleted');
});
await test('get-worker-settings', async (S) => {
  S.workers.set('demo', { code: 'x', bindings: [], settings: { compatibility_date: '2024-09-01' } });
  const r = await call(S, 'get-worker-settings', { scriptName: 'demo' });
  assertSuccess(r); assert(r.body.result.compatibility_date === '2024-09-01', 'date');
});
await test('set-worker-compatibility', async (S) => {
  S.workers.set('demo', { code: 'x', bindings: [], settings: {} });
  const r = await call(S, 'set-worker-compatibility', { scriptName: 'demo', compatibilityDate: '2025-01-01' });
  assertSuccess(r); assert(S.workers.get('demo').settings.compatibility_date === '2025-01-01', 'date set');
});
await test('set-worker-compat-flags', async (S) => {
  S.workers.set('demo', { code: 'x', bindings: [], settings: {} });
  const r = await call(S, 'set-worker-compat-flags', { scriptName: 'demo', flags: ['nodejs_compat'] });
  assertSuccess(r); assert(S.workers.get('demo').settings.compatibility_flags[0] === 'nodejs_compat', 'flags');
});
await test('get/set-worker-schedules', async (S) => {
  S.workers.set('demo', { code: 'x', bindings: [], settings: {}, schedules: [] });
  const a = await call(S, 'get-worker-schedules', { scriptName: 'demo' });
  assertSuccess(a);
  const b = await call(S, 'set-worker-schedules', { scriptName: 'demo', crons: [{ cron: '*/5 * * * *' }] });
  assertSuccess(b); assert(S.workers.get('demo').schedules.length === 1, 'cron saved');
});
await test('get-worker-variables', async (S) => {
  S.workers.set('demo', { code: 'x', settings: {}, bindings: [{ type: 'plain_text', name: 'A', text: '1' }, { type: 'json', name: 'J', json: { a: 1 } }] });
  const r = await call(S, 'get-worker-variables', { scriptName: 'demo' });
  assertSuccess(r); assert(r.body.result.vars.length === 2, '2 vars');
});
await test('put-worker-variables (保存 + 明文删除)', async (S) => {
  S.workers.set('demo', {
    code: "export default { async fetch(){ return new Response('x') } }",
    settings: { compatibility_date: '2023-05-01', compatibility_flags: ['nodejs_compat'], usage_model: 'bundled' },
    bindings: [{ type: 'plain_text', name: 'KEEP', text: '1' }, { type: 'plain_text', name: 'GONE', text: '2' }, { type: 'kv_namespace', name: 'KV', namespace_id: 'ns1' }],
  });
  const r = await call(S, 'put-worker-variables', {
    scriptName: 'demo',
    variables: [{ name: 'KEEP', type: 'plain_text', value: '1' }, { name: 'ADDED', type: 'plain_text', value: '3' }],
  });
  assertSuccess(r);
  const b = S.workers.get('demo').bindings;
  assert(!b.some((x) => x.name === 'GONE'), '删掉的 plain_text 应该消失');
  assert(b.some((x) => x.name === 'ADDED'), '新增变量');
  assert(b.some((x) => x.name === 'KV'), 'KV 绑定保留');
  const st = S.workers.get('demo').settings;
  assert(st.compatibility_date === '2023-05-01', '兼容日期应保留，实际=' + st.compatibility_date);
  assert(st.usage_model === 'bundled', 'usage_model 应保留，实际=' + st.usage_model);
});
await test('put-worker-variables (多模块应拒绝)', async (S) => {
  S.workers.set('multi', {
    code: 'export default {}', moduleCount: 3, settings: {}, bindings: [],
  });
  const r = await call(S, 'put-worker-variables', { scriptName: 'multi', variables: [{ name: 'A', type: 'plain_text', value: '1' }] });
  assert(r.body.success === false, '多模块 Worker 应拒绝改变量（否则会丢模块），实际: ' + JSON.stringify(r.body).slice(0, 160));
});
await test('patch-worker-secrets', async (S) => {
  S.workers.set('demo', { code: 'x', settings: {}, bindings: [] });
  const r = await call(S, 'patch-worker-secrets', { scriptName: 'demo', secrets: { S1: 'v1', S2: null } });
  assertSuccess(r);
  assert(S.workers.get('demo').bindings.some((x) => x.name === 'S1'), 'secret added');
});
await test('workers subdomain', async (S) => {
  assertSuccess(await call(S, 'get-workers-subdomain'));
  assertSuccess(await call(S, 'put-workers-subdomain', { subdomain: 'demo2' }));
  S.workers.set('demo', { code: 'x', settings: {}, bindings: [] });
  assertSuccess(await call(S, 'toggle-worker-subdomain', { scriptName: 'demo', enabled: false }));
});
await test('worker domains', async (S) => {
  S.workers.set('demo', { code: 'x', settings: {}, bindings: [], domains: [] });
  const a = await call(S, 'add-worker-domain', { scriptName: 'demo', hostname: 'app.example.com' });
  assertSuccess(a);
  const l = await call(S, 'list-worker-domains', { scriptName: 'demo' });
  assertSuccess(l); assert(l.body.result.length === 1, '1 domain');
  assertSuccess(await call(S, 'delete-worker-domain', { domainId: 'dom-app.example.com' }));
});
await test('worker routes', async (S) => {
  const l = await call(S, 'list-worker-routes', { zoneId: 'z1', scriptName: 'demo' });
  assertSuccess(l);
  assertSuccess(await call(S, 'add-worker-route', { zoneId: 'z1', pattern: 'example.com/x/*', scriptName: 'demo' }));
  assertSuccess(await call(S, 'delete-worker-route', { zoneId: 'z1', routeId: 'r1' }));
  const all = await call(S, 'list-worker-routes-all');
  assertSuccess(all); assert(all.body.result.demo, 'grouped by script');
});
await test('worker versions / rollback', async (S) => {
  S.workers.set('demo', { code: 'x', settings: {}, bindings: [] });
  const v = await call(S, 'list-worker-versions', { scriptName: 'demo' });
  assertSuccess(v);
  const c = await call(S, 'get-worker-current-version', { scriptName: 'demo' });
  assertSuccess(c); assert(c.body.currentVersionId === 'v1', 'current version');
  assertSuccess(await call(S, 'rollback-worker-version', { scriptName: 'demo', versionId: 'v1' }));
});

// ---------- KV ----------
await test('KV CRUD', async (S) => {
  S.kv.set('ns1', { id: 'ns1', title: 'demo_kv' });
  const l = await call(S, 'list-kv-namespaces'); assertSuccess(l);
  const c = await call(S, 'create-kv-namespace', { title: 'new_kv', jurisdiction: 'eu' }); assertSuccess(c);
  assertSuccess(await call(S, 'rename-kv-namespace', { namespaceId: 'ns1', title: 'renamed' }));
  assertSuccess(await call(S, 'put-kv-value', { namespaceId: 'ns1', kvKey: 'k', value: 'hello' }));
  const g = await call(S, 'get-kv-value', { namespaceId: 'ns1', kvKey: 'k' });
  assertSuccess(g); assert(g.body.value === 'hello', 'value roundtrip');
  const keys = await call(S, 'list-kv-keys', { namespaceId: 'ns1' }); assertSuccess(keys);
  assertSuccess(await call(S, 'bulk-write-kv', { namespaceId: 'ns1', items: [{ key: 'b1', value: '1' }] }));
  assertSuccess(await call(S, 'bulk-delete-kv', { namespaceId: 'ns1', keys: ['b1'] }));
  assertSuccess(await call(S, 'delete-kv-value', { namespaceId: 'ns1', kvKey: 'k' }));
  assertSuccess(await call(S, 'delete-kv-namespace', { namespaceId: 'ns1' }));
});

// ---------- D1 ----------
await test('D1 CRUD + 查询 + 导出', async (S) => {
  S.d1.set('db1', { uuid: 'db1', name: 'demo', file_size: 10 });
  assertSuccess(await call(S, 'list-d1'));
  assertSuccess(await call(S, 'create-d1-database', { name: 'newdb', primary_location_hint: 'weur' }));
  const q = await call(S, 'execute-d1-query', { databaseId: 'db1', query: 'select 1' });
  assertSuccess(q); assert(q.body.result[0].results[0].n === 1, 'query result');
  assertSuccess(await call(S, 'execute-d1-raw', { databaseId: 'db1', query: 'select 1' }));
  assertSuccess(await call(S, 'd1-export-start', { databaseId: 'db1' }));
  assertSuccess(await call(S, 'd1-export-poll', { databaseId: 'db1', bookmark: 'bm1' }));
  assertSuccess(await call(S, 'delete-d1-database', { databaseId: 'db1' }));
});

// ---------- R2 ----------
await test('R2 桶与对象', async (S) => {
  S.r2.set('bucket1', { name: 'bucket1', creation_date: '2026-01-01' });
  const l = await call(S, 'list-r2-buckets'); assertSuccess(l);
  assertSuccess(await call(S, 'create-r2-bucket', { name: 'b2', storageClass: 'InfrequentAccess' }));
  assertSuccess(await call(S, 'get-r2-bucket', { name: 'bucket1' }));
  assertSuccess(await call(S, 'update-r2-bucket', { name: 'bucket1', storageClass: 'InfrequentAccess' }));
  const creds = { s3: { accessKeyId: 'AK', secretAccessKey: 'SK' } };
  assertSuccess(await call(S, 'r2-s3-test', { name: 'bucket1', ...creds }));
  const objs = await call(S, 'r2-objects-list', { name: 'bucket1', ...creds });
  assertSuccess(objs); assert(objs.body.result.files.length === 2, '2 objects');
  assertSuccess(await call(S, 'r2-object-put', { name: 'bucket1', key: 'up.txt', content: Buffer.from('hi').toString('base64'), contentType: 'text/plain', ...creds }));
  const dl = await call(S, 'r2-object-download-url', { name: 'bucket1', key: 'up.txt', ...creds });
  assertSuccess(dl); assert(/X-Amz-Signature=/.test(dl.body.result.url), 'presigned url');
  assertSuccess(await call(S, 'r2-object-delete', { name: 'bucket1', key: 'up.txt', ...creds }));
  assertSuccess(await call(S, 'r2-temp-credentials', { name: 'bucket1' }));
  assertSuccess(await call(S, 'r2-bucket-domains', { name: 'bucket1' }));
  assertSuccess(await call(S, 'r2-public-url-toggle', { name: 'bucket1', enable: true }));
  assertSuccess(await call(S, 'r2-custom-domain-add', { name: 'bucket1', domain: 'cdn.example.com' }));
  assertSuccess(await call(S, 'r2-custom-domain-remove', { name: 'bucket1', domain: 'cdn.example.com' }));
  assertSuccess(await call(S, 'r2-catalog-get', { name: 'bucket1' }));
  assertSuccess(await call(S, 'r2-catalog-enable', { name: 'bucket1' }));
  assertSuccess(await call(S, 'r2-catalog-disable', { name: 'bucket1' }));
  const mx = await call(S, 'r2-metrics', { name: 'bucket1', range: '7d' });
  assertSuccess(mx); assert(mx.body.result.classA === '6', 'A 类操作聚合');
  assertSuccess(await call(S, 'delete-r2-bucket', { name: 'b2' }));
});

// ---------- DNS / Zones ----------
await test('zones + DNS', async (S) => {
  S.dns.set('z1', [{ id: 'rec1', type: 'A', name: 'www.example.com', content: '1.2.3.4', proxied: true, ttl: 1 }]);
  const z = await call(S, 'list-zones'); assertSuccess(z); assert(z.body.result.length === 1, 'zones');
  assertSuccess(await call(S, 'create-zone', { name: 'new.com' }));
  const l = await call(S, 'list-dns-records', { zoneId: 'z1' }); assertSuccess(l);
  const c = await call(S, 'create-dns-record', { zoneId: 'z1', type: 'CNAME', name: 'a.example.com', content: 'b.example.com', proxied: true });
  assertSuccess(c);
  const up = await call(S, 'update-dns-record', { zoneId: 'z1', recordId: 'rec1', name: 'www.example.com', content: '5.6.7.8', proxied: true });
  assertSuccess(up);
  const rec = S.dns.get('z1').find((x) => x.id === 'rec1');
  assert(rec.proxied === true, 'PATCH 不应把没传的 proxied 改成 false');
  assertSuccess(await call(S, 'delete-dns-record', { zoneId: 'z1', recordId: 'rec1' }));
  assertSuccess(await call(S, 'batch-dns-records', { zoneId: 'z1', posts: [] }));
  const an = await call(S, 'get-zone-analytics', { zoneId: 'z1', rangeSec: 3600 });
  assertSuccess(an); assert(an.body.result.cur.requests === 100, 'analytics');
  assertSuccess(await call(S, 'delete-zone', { zoneId: 'z1' }));
});
await test('update-dns-record 不传 proxied 时保持原值', async (S) => {
  S.dns.set('z1', [{ id: 'rec1', type: 'A', name: 'www.example.com', content: '1.2.3.4', proxied: true, ttl: 1 }]);
  const up = await call(S, 'update-dns-record', { zoneId: 'z1', recordId: 'rec1', content: '5.6.7.8' });
  assertSuccess(up);
  const rec = S.dns.get('z1').find((x) => x.id === 'rec1');
  assert(rec.proxied === true, '未传 proxied 时不应被改成 false，实际=' + rec.proxied);
});

// ---------- Pages ----------
await test('Pages 项目 CRUD + 上传部署', async (S) => {
  const files = [
    { path: '/index.html', content: Buffer.from('<html>hi</html>').toString('base64') },
    { path: '/assets/a.js', content: Buffer.from('console.log(1)').toString('base64') },
  ];
  const d = await call(S, 'pages-deploy-upload', { projectName: 'site1', files, branch: 'main' });
  assertSuccess(d);
  assert(S.pages.get('site1').deployments.length === 1, 'deployment created');
  assertSuccess(await call(S, 'list-pages-projects'));
  assertSuccess(await call(S, 'create-pages-project', { name: 'p2' }));
  const ov = await call(S, 'get-pages-project-overview', { projectName: 'site1' });
  assertSuccess(ov); assert(ov.body.result.name === 'site1', 'overview');
  assertSuccess(await call(S, 'list-pages-deployments', { projectName: 'site1' }));
  assertSuccess(await call(S, 'list-pages-domains', { projectName: 'site1' }));
  assertSuccess(await call(S, 'add-pages-domain', { projectName: 'site1', hostname: 'site.example.com' }));
  assertSuccess(await call(S, 'delete-pages-domain', { projectName: 'site1', hostname: 'site.example.com' }));
  assertSuccess(await call(S, 'delete-pages-deployment', { projectName: 'site1', deploymentId: 'dep1' }));
  assertSuccess(await call(S, 'delete-pages-project', { projectName: 'p2' }));
});
await test('Pages GitHub 仓库部署', async (S) => {
  const d = await call(S, 'pages-deploy-github', { projectName: 'gh1', repoUrl: 'https://github.com/o/r' });
  assertSuccess(d);
  assert(d.body.fileCount === 3, 'zip 解出 3 个文件，实际=' + d.body.fileCount);
});
await test('Pages GitHub 单文件部署', async (S) => {
  const d = await call(S, 'pages-deploy-github', { projectName: 'gh2', repoUrl: 'https://github.com/o/r/blob/main/_worker.js' });
  assertSuccess(d);
  assert(d.body.advancedMode === true, '应是高级模式');
});
await test('Pages 触发/重试/回滚部署', async (S) => {
  S.pages.set('site1', { name: 'site1', production_branch: 'main', source: { type: 'github' }, deployment_configs: { production: {}, preview: {} }, deployments: [{ id: 'dep1', url: 'https://dep1.site1.pages.dev' }] });
  assertSuccess(await call(S, 'trigger-pages-deployment', { projectName: 'site1' }));
  assertSuccess(await call(S, 'retry-pages-deployment', { projectName: 'site1', deploymentId: 'dep1' }));
});
await test('Pages 绑定（生产/预览的删除标记互不污染）', async (S) => {
  S.pages.set('site1', {
    name: 'site1', deployments: [],
    deployment_configs: {
      production: { env_vars: { PROD_ONLY: { type: 'plain_text', value: '1' } }, kv_namespaces: {}, d1_databases: {} },
      preview: { env_vars: { PREVIEW_ONLY: { type: 'plain_text', value: '1' } }, kv_namespaces: {}, d1_databases: {} },
    },
  });
  const r = await call(S, 'set-pages-bindings', { projectName: 'site1', envVars: { KEEP: 'v' }, kv: {}, d1: {} });
  assertSuccess(r);
  // 找到发给 Pages 项目的那次 PATCH，检查两个环境的删除标记有没有串台
  const patch = S.calls.filter((c) => c.method === 'PATCH' && /\/pages\/projects\/site1$/.test(c.path)).pop();
  assert(patch, '没发出 PATCH');
  const body = JSON.parse(patch.body);
  const prod = body.deployment_configs.production.env_vars;
  const prev = body.deployment_configs.preview.env_vars;
  assert(!('PREVIEW_ONLY' in prod), '生产的 payload 里混进了预览独有的删除标记 PREVIEW_ONLY');
  assert(!('PROD_ONLY' in prev), '预览的 payload 里混进了生产独有的删除标记 PROD_ONLY');
  assert(prod.PROD_ONLY === null, '生产里被移除的 PROD_ONLY 应显式置 null');
  assert(prev.PREVIEW_ONLY === null, '预览里被移除的 PREVIEW_ONLY 应显式置 null');
  assert(prod.KEEP && prod.KEEP.value === 'v', '提交的 KEEP 应写入生产');
});
await test('Pages 兼容性设置 + 绑定读取', async (S) => {
  S.pages.set('site1', { name: 'site1', deployments: [], deployment_configs: { production: { env_vars: {} }, preview: {} } });
  assertSuccess(await call(S, 'get-pages-bindings', { projectName: 'site1' }));
  assertSuccess(await call(S, 'set-pages-compatibility', { projectName: 'site1', compatibilityDate: '2025-02-01', flags: ['nodejs_compat'] }));
});

// ---------- Tunnels ----------
await test('Tunnel 生命周期', async (S) => {
  const c = await call(S, 'create-tunnel', { name: 'tn1', hostname: 'tun.example.com', service: 'http://localhost:8080' });
  assertSuccess(c);
  const id = c.body.result.id;
  assert(S.dns.get('z1')?.some((r) => r.name === 'tun.example.com' && r.content === id + '.cfargotunnel.com'), 'CNAME 已创建');
  assert(c.body.result.token === 'TUNNEL_TOKEN', 'token');
  assertSuccess(await call(S, 'list-tunnels'));
  assertSuccess(await call(S, 'get-tunnel', { tunnelId: id }));
  assertSuccess(await call(S, 'update-tunnel-rules', { tunnelId: id, rules: [{ hostname: 'a.example.com', service: 'http://localhost:1' }] }));
  assertSuccess(await call(S, 'delete-tunnel', { tunnelId: id }));
});

// ---------- 用量 / 权限 ----------
await test('get-resource-usage', async (S) => {
  S.kv.set('ns1', { id: 'ns1', title: 'kv' });
  S.d1.set('db1', { uuid: 'db1', name: 'db', file_size: 100 });
  S.r2.set('b1', { name: 'b1' });
  const r = await call(S, 'get-resource-usage');
  assertSuccess(r);
  assert(r.body.kv && r.body.kv.reads === 5, 'kv reads');
  assert(r.body.d1 && r.body.d1.readQueries === 4, 'd1 reads');
  assert(r.body.r2 && r.body.r2.classA === 0 && r.body.r2.classB === 6, 'r2 分类');
});
await test('get-usage-today / per-worker / timeseries', async (S) => {
  const a = await call(S, 'get-usage-today'); assertSuccess(a);
  assert(a.body.data.total === 10, 'total=3+7 实际=' + a.body.data.total);
  const b = await call(S, 'get-usage-per-worker'); assertSuccess(b);
  assert(b.body.result[0].name === 'demo', 'script name');
  assertSuccess(await call(S, 'get-usage-timeseries'));
});
await test('check-token-permissions', async (S) => {
  const r = await call(S, 'check-token-permissions');
  assertSuccess(r); assert(r.body.result.length === 7, '7 probes');
});
await test('load-batch-templates-kv', async (S) => {
  const r = await call(S, 'load-batch-templates-kv');
  assertSuccess(r); assert(r.body.templates.length >= 4, '内置模板');
});

// ---------- 路由 / 鉴权 ----------
await test('路由: / /login /app /static /oauth/callback /404', async (S) => {
  installMock(S);
  const get = async (p) => worker.fetch(new Request('https://panel.example.com' + p), makeEnv({}), {});
  let r = await get('/');
  assert(r.status === 302 && r.headers.get('location').endsWith('/login'), '/ 应跳登录');
  r = await get('/login');
  const html = await r.text();
  assert(r.status === 200 && html.includes('连接您的 Cloudflare 账号'), '/login');
  assert(!/fonts\.googleapis\.com/.test(html), '不应再依赖 Google Fonts');
  r = await get('/app');
  assert(r.status === 200, '/app');
  r = await get('/static-v3.js');
  assert(r.status === 200 && (r.headers.get('content-type') || '').includes('javascript'), 'static');
  r = await get('/oauth/callback');
  assert(r.status === 200, 'oauth callback');
  r = await get('/nope');
  assert(r.status === 404, '404');
});
await test('安全头', async (S) => {
  installMock(S);
  const r = await worker.fetch(new Request('https://panel.example.com/login'), makeEnv({}), {});
  assert(r.headers.get('x-content-type-options') === 'nosniff', 'nosniff');
  assert(r.headers.get('x-frame-options') === 'DENY', 'frame');
  assert((r.headers.get('content-security-policy') || '').includes("default-src 'self'"), 'csp');
});
await test('密码保护: 错误密码 / 正确密码 / 会话', async (S) => {
  installMock(S);
  const env = { ACCESS_PASSWORD: 'p@ss' };
  let r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'check-features' }) }), env, {});
  assert(r.status === 401, '未登录应 401');
  r = await worker.fetch(new Request('https://panel.example.com/auth', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'wrong' }) }), env, {});
  assert(r.status === 401, '错误密码 401');
  r = await worker.fetch(new Request('https://panel.example.com/auth', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'p@ss' }) }), env, {});
  const sc = r.headers.get('set-cookie') || '';
  assert(r.status === 200 && sc.includes('cf_session='), '登录成功');
  assert(sc.includes('HttpOnly'), 'HttpOnly');
  assert(sc.includes('Secure'), 'Secure：https 下应设置');
  const cookie = sc.split(';')[0];
  r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ action: 'check-features' }) }), env, {});
  assert(r.status === 200, '带会话应放行');
  const body = await r.json();
  assert(body.hasPassword === true, 'hasPassword');
});
await test('会话令牌不应是密码的固定派生值', async (S) => {
  installMock(S);
  const env = { ACCESS_PASSWORD: 'p@ss' };
  const login = async () => {
    const r = await worker.fetch(new Request('https://panel.example.com/auth', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'p@ss' }) }), env, {});
    return (r.headers.get('set-cookie') || '').split(';')[0];
  };
  const a = await login(), b = await login();
  assert(a !== b, '两次登录的会话令牌应不同（现在每次都一样，等于永久通行证）');
});
await test('密码比较应走常量时间（行为层：错一位也失败）', async (S) => {
  installMock(S);
  const env = { ACCESS_PASSWORD: 'abcdef' };
  for (const pw of ['abcde', 'abcdefg', 'abcdeg', '']) {
    const r = await worker.fetch(new Request('https://panel.example.com/auth', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: pw }) }), env, {});
    assert(r.status === 401, '错误密码应 401: ' + pw);
  }
});
await test('暴力破解应被限流', async (S) => {
  installMock(S);
  const env = { ACCESS_PASSWORD: 'p@ss' };
  let blocked = 0;
  for (let i = 0; i < 30; i++) {
    const r = await worker.fetch(new Request('https://panel.example.com/auth', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '9.9.9.9' },
      body: JSON.stringify({ password: 'bad' + i }),
    }), env, {});
    if (r.status === 429) blocked++;
  }
  assert(blocked > 0, '连续失败后应出现 429');
});

// ---------- v2.9 新增行为的针对性用例 ----------
await test('SSRF：十进制/十六进制/内网写法都被拒', async (S) => {
  const bad = [
    'http://2130706433/x.js', 'http://0x7f000001/x.js', 'http://0177.0.0.1/x.js',
    'http://127.0.0.1/x.js', 'http://[::1]/x.js', 'http://[::ffff:127.0.0.1]/x.js',
    'http://169.254.169.254/latest/meta-data', 'http://100.64.1.1/x.js', 'http://foo.localhost/x.js',
  ];
  for (const u of bad) {
    const r = await call(S, 'fetch-external-script', { url: u });
    assert(r.body.success === false, '应拒绝 ' + u);
    // 必须是"被规则拦下"，而不是碰巧网络请求失败
    assert(/内网|本地|不允许/.test(String(r.body.error || '')), '应以"内网地址"为由拒绝 ' + u + '，实际：' + r.body.error);
  }
  const good = await call(S, 'fetch-external-script', { url: 'https://example.com/a.js' });
  assert(good.body.success === true, '公网地址应放行');
});
await test('accountId 非法格式直接 400（防路径/查询串注入）', async (S) => {
  const r = await call(S, 'list-workers', { accountId: '../../zones' });
  assert(r.status === 400 && r.body.success === false, '应 400，实际 ' + r.status);
});
await test('会话带过期时间：伪造过期令牌被拒', async (S) => {
  installMock(S);
  const env = { ACCESS_PASSWORD: 'p@ss' };
  const past = Math.floor(Date.now() / 1000) - 10;
  const forged = 'v1.' + past + '.deadbeefdeadbeefdeadbeefdeadbeef.';
  const r = await worker.fetch(new Request('https://panel.example.com/api', {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: 'cf_session=' + forged + 'sig' },
    body: JSON.stringify({ action: 'check-features' }),
  }), env, {});
  assert(r.status === 401, '过期令牌应 401');
});
await test('会话可被 KV 吊销', async (S) => {
  installMock(S);
  const kv = fakeKV();
  const env = { ACCESS_PASSWORD: 'p@ss', SESSIONS: kv };
  const lr = await worker.fetch(new Request('https://panel.example.com/auth', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'p@ss' }) }), env, {});
  const cookie = (lr.headers.get('set-cookie') || '').split(';')[0];
  let r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ action: 'check-features' }) }), env, {});
  assert(r.status === 200, '正常会话应放行');
  kv._m.clear(); // 模拟在别处吊销
  r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: JSON.stringify({ action: 'check-features' }) }), env, {});
  assert(r.status === 401, 'KV 里没有记录后应 401');
});
await test('无密码模式仍可用', async (S) => {
  installMock(S);
  const r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'check-features' }) }), {}, {});
  assert(r.status === 200 && (await r.json()).hasPassword === false, '无密码时应直接放行');
});
await test('API 响应 no-store + 不美化', async (S) => {
  installMock(S);
  const r = await worker.fetch(new Request('https://panel.example.com/api', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'check-features' }) }), {}, {});
  assert((r.headers.get('cache-control') || '').includes('no-store'), 'no-store');
  const t = await r.text();
  assert(t.indexOf('\n') === -1, '不应 pretty-print');
});
await test('static.js 注入 OAUTH_CLIENT_ID 且含前端入口', async (S) => {
  installMock(S);
  const r = await worker.fetch(new Request('https://panel.example.com/static-v3.js'), { OAUTH_CLIENT_ID: '0123456789abcdef0123456789abcdef' }, {});
  const js = await r.text();
  assert(js.includes('0123456789abcdef0123456789abcdef'), 'client id 应被替换');
  assert(js.includes('startOAuthLogin'), '前端入口函数应在');
});
await test('Pages 资源哈希 32 位 hex，同内容稳定', async (S) => {
  const files = [{ path: '/index.html', content: Buffer.from('<html>x</html>').toString('base64') }];
  await call(S, 'pages-deploy-upload', { projectName: 'h1', files });
  await call(S, 'pages-deploy-upload', { projectName: 'h1', files });
  const checks = S.calls.filter((c) => c.path.includes('assets/check-missing'));
  assert(checks.length >= 2, '两次部署都应做 check-missing');
  const h1 = JSON.parse(checks[0].body).hashes[0];
  const h2 = JSON.parse(checks[1].body).hashes[0];
  assert(/^[0-9a-f]{32}$/.test(h1), '哈希应为 32 位 hex，实际=' + h1);
  assert(h1 === h2, '同内容两次部署哈希应一致（否则每次全量重传）');
});
await test('ZIP 里的 ../ 路径被丢弃（zip-slip）', async (S) => {
  const zip = makeZip([{ path: 'repo-main/../../evil.html', data: '<x>' }, { path: 'repo-main/index.html', data: '<y>' }]);
  const q = await call(S, 'quick-deploy-pages', { projectName: 'z2', sourceKind: 'b64zip', sourceB64: Buffer.from(zip).toString('base64') });
  assertSuccess(q);
  assert(q.body.fileCount === 1, '应只保留 index.html，实际文件数=' + q.body.fileCount);
});

// ---------- 输出 ----------
const pass = results.filter((r) => r.ok).length;
const failList = results.filter((r) => !r.ok);
console.log(`\n=== ${pass}/${results.length} 通过 ===`);
for (const r of results) {
  if (r.ok) console.log('  ok   ' + r.name + (r.detail ? '  →  ' + r.detail : ''));
}
for (const r of failList) console.log('  FAIL ' + r.name + '\n       ' + r.detail);
process.exitCode = failList.length ? 1 : 0;
