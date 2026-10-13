// 终末地：解密 StreamingAssets/index_*.json（base64 -> ChaCha20）并分析其结构
'use strict';
const fs = require('fs'), path = require('path');
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}
function cblk(k, n, c) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) st[4 + i] = k.readUInt32LE(i * 4);
  st[12] = c >>> 0;
  for (let i = 0; i < 3; i++) st[13 + i] = n.readUInt32LE(i * 4);
  const w = Uint32Array.from(st);
  for (let i = 0; i < 10; i++) { qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15); qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14); }
  const o = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) o.writeUInt32LE((w[i] + st[i]) >>> 0, i * 4);
  return o;
}
function kstream(d, k, n, c = 1) {
  const o = Buffer.alloc(d.length);
  for (let off = 0; off < d.length; off += 64) { const s = cblk(k, n, c++), m = Math.min(64, d.length - off); for (let i = 0; i < m; i++) o[off + i] = d[off + i] ^ s[i]; }
  return o;
}
const key = Buffer.from(process.argv[2], 'base64');
const sa = process.argv[3];
const outDir = process.argv[4];
fs.mkdirSync(outDir, { recursive: true });
for (const n of ['index_initial.json', 'index_main.json']) {
  const p = path.join(sa, n);
  const b64 = fs.readFileSync(p, 'utf8').replace(/[^A-Za-z0-9+/=]/g, '');
  const data = Buffer.from(b64, 'base64');
  console.log('\n########## ' + n + ' (base64 ' + b64.length + ' -> ' + data.length + ' bytes) ##########');
  console.log('文件真实头 32B: ' + data.subarray(0, 32).toString('hex').replace(/(..)/g, '$1 '));
  // 结构假设: 前 12 字节 = ChaCha20 nonce（与 .blc 同构），其余为密文
  const dec = kstream(Buffer.from(data.subarray(12)), key, data.subarray(0, 12), 1);
  console.log('解密后头 96B hex: ' + dec.subarray(0, 96).toString('hex').replace(/(..)/g, '$1 '));
  console.log('解密后头 96B asc: ' + dec.subarray(0, 96).toString('latin1').replace(/[^\x20-\x7e]/g, '.'));
  const asUtf8 = dec.toString('utf8');
  const printable = (asUtf8.match(/[\x20-\x7e\u4e00-\u9fff]/g) || []).length / Math.max(1, asUtf8.length);
  console.log('可打印率(utf8): ' + (printable * 100).toFixed(1) + '%');
  if (printable > 0.9) {
    console.log('--- 完整内容 ---');
    console.log(asUtf8.slice(0, 4000));
    fs.writeFileSync(path.join(outDir, n.replace('.json', '') + '.decrypted.json'), asUtf8);
  } else {
    // 也许是 JSON 但前面有二进制头，尝试找 '{'
    const idx = dec.indexOf(0x7b);
    console.log("首个 '{' 位置: " + idx);
    if (idx >= 0) console.log('从该处起 3000 字符:\n' + dec.subarray(idx, idx + 3000).toString('utf8'));
  }
}
