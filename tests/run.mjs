// 功能冒烟测试入口：node tests/run.mjs [worker 文件路径]
//
// 做法：把待测的 worker 复制成临时 .mjs，注入一个"假的 Cloudflare API"
// （tests/mock.mjs），再把每个 action 真跑一遍，断言返回值和副作用。
// 不需要网络、不需要真实 Token、不会碰你的 Cloudflare 账号。
//
// 覆盖：Workers 部署/变量/密钥/版本/路由/域名、KV、D1、R2(S3)、DNS/Zones、
//      Pages(上传/GitHub/绑定/兼容性)、Tunnel、用量统计、鉴权与安全头等。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

// 找默认被测文件：优先仓库里的发布文件，其次常见命名
function findDefault() {
  const candidates = [
    'cf-panel-worker-v2.9.0.js',
    'worker-v2.9.0.js',
    'worker.js',
    '_worker.js',
    'worker-v2.8.2.js',
  ];
  for (const f of candidates) {
    const p = path.join(process.cwd(), f);
    if (fs.existsSync(p)) return p;
  }
  return path.join(process.cwd(), candidates[0]);
}

const target = path.resolve(process.argv[2] || findDefault());
if (!fs.existsSync(target)) {
  console.error('找不到待测文件：' + target);
  console.error('用法：node tests/run.mjs [worker 文件路径]');
  process.exit(2);
}
const tmp = path.join(os.tmpdir(), 'worker-under-test-' + Date.now() + '.mjs');
fs.copyFileSync(target, tmp);
process.argv[2] = pathToFileURL(tmp).href;
console.log('待测文件：' + target);
await import('./suite.mjs');
