// 终末地：index_*.json 已知明文攻击 + 结构判定
// 依据: 两文件均为 base64(密文体 + CRC32)，密文前 14 字节相同 -> 疑为固定密钥流(stream cipher, 固定 nonce)
// 手法: 若明文以 '{"' 开头, 则 ks[i] = ct[i] ^ pt[i]; 用同一 ks 解开全文并检查是否为合法 JSON
'use strict';
const fs = require('fs'), path = require('path'), zlib = require('zlib');

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
const xor = (a, b) => { const o = Buffer.alloc(Math.min(a.length, b.length)); for (let i = 0; i < o.length; i++) o[i] = a[i] ^ b[i]; return o; };
const printable = (b) => { let n = 0; for (const c of b) if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13 || c >= 0x80) n++; return n / b.length; };

const sa = process.argv[2], keyB64 = process.argv[3], outDir = process.argv[4];
fs.mkdirSync(outDir, { recursive: true });
const key = Buffer.from(keyB64, 'base64');
const CFG = ['index_initial.json', 'index_main.json'].map(n => {
  const b64 = fs.readFileSync(path.join(sa, n), 'utf8').replace(/[^A-Za-z0-9+/=]/g, '');
  const ct = Buffer.from(b64, 'base64');
  return { n, b64, ct };
});
for (const c of CFG) console.log(c.n + ': base64=' + c.b64.length + ' -> 字节 ' + c.ct.length + ' (mod3=' + (c.b64.length % 3) + ', 密文前缀 ' + c.ct.subarray(0, 8).toString('hex') + ')');

// ---- 1) 尝试 ChaCha20 各种 nonce/counter（先排除标准构造）----
console.log('\n=== 1) ChaCha20 候选 nonce/counter（检查前 2 字节是否 "{ 或 {\\n"）===');
const zero12 = Buffer.alloc(12);
const n1 = Buffer.alloc(12); const cands = [];
cands.push(['nonce=0 ctr=1', kstream(Buffer.from(CFG[1].ct.subarray(0, 64)), key, zero12, 1)]);
cands.push(['nonce=0 ctr=0', kstream(Buffer.from(CFG[1].ct.subarray(0, 64)), key, zero12, 0)]);
const pv = Buffer.alloc(12); pv.writeInt32LE(3, 0);
cands.push(['nonce=ver3+0 ctr=1', kstream(Buffer.from(CFG[1].ct.subarray(0, 64)), key, pv, 1)]);
for (const [label, out] of cands) {
  const pt = xor(Buffer.from(CFG[1].ct.subarray(0, 64)), out);
  console.log('  ' + label.padEnd(20) + ' -> ' + pt.subarray(0, 24).toString('latin1').replace(/[^\x20-\x7e]/g, '.') + '  可打印率=' + (printable(pt) * 100).toFixed(0) + '%');
}

// ---- 2) 已知明文攻击：假设明文以 '{"' 开头，反推密钥流 ----
console.log('\n=== 2) 已知明文攻击（假设明文以 {" 开头）===');
const ctA = CFG[0].ct, ctB = CFG[1].ct;
const ksFromA = Buffer.from(ctA.subarray(0, 14));
const ksFromB = Buffer.from(ctB.subarray(0, 14));
const guess = Buffer.from('{"Version":0,"');  // 猜测的明文头
const ksA = xor(ksFromA, guess.subarray(0, 14));
const ksB = xor(ksFromB, guess.subarray(0, 14));
console.log('  由两文件反推的密钥流(前14B)是否一致: ' + ksA.equals(ksB));
console.log('  ks(A) = ' + ksA.toString('hex'));
// 用该 ks 解开 B 的头部 14 字节 -> 应得到 guess
console.log('  用 ks(A) 解 B 头 -> ' + xor(ksFromB, ksA).toString('latin1').replace(/[^\x20-\x7e]/g, '.'));

// ---- 3) 直接把两份密文相互异或，看是否暴露结构（若为同一密钥流，异或=明文异或）----
console.log('\n=== 3) 密文互异或（同密钥流时应=明文异或，可暴露公共前缀）===');
const x = xor(ctA.subarray(0, 256), ctB.subarray(0, 256));
console.log('  xor 前 64B: ' + x.subarray(0, 64).toString('hex').replace(/(..)/g, '$1 '));
console.log('  xor 可打印率: ' + (printable(x) * 100).toFixed(0) + '%  (若接近 0 说明两明文几乎相同或非流密码)');
let same = 0; for (let i = 0; i < x.length; i++) if (x[i] === 0) same++;
console.log('  相同字节数(前256): ' + same);

// ---- 4) 检查是否为压缩流/其他容器特征（gzip/zlib/lz4 魔数）----
console.log('\n=== 4) 压缩/容器魔数检查 ===');
for (const c of CFG) {
  const h = c.ct.subarray(0, 4).toString('hex');
  const marks = [];
  if (c.ct[0] === 0x1f && c.ct[1] === 0x8b) marks.push('gzip');
  if (c.ct[0] === 0x78 && (c.ct[1] === 0x01 || c.ct[1] === 0x9c || c.ct[1] === 0xda)) marks.push('zlib');
  if (c.ct[0] === 0x04 && c.ct[1] === 0x22 && c.ct[2] === 0x4d && c.ct[3] === 0x18) marks.push('lz4');
  if (c.ct[0] === 0x28 && c.ct[1] === 0xb5 && c.ct[2] === 0x2f && c.ct[3] === 0xfd) marks.push('zstd');
  if (c.ct.subarray(0, 2).toString('latin1') === 'PK') marks.push('zip');
  console.log('  ' + c.n + ' 头=' + h + ' 标记=[' + marks.join(',') + ']  尾部16B=' + c.ct.subarray(c.ct.length - 16).toString('hex'));
  // 最后 4 字节是否可能是 CRC32
  const body = c.ct.subarray(0, c.ct.length - 4);
  const want = c.ct.readUInt32LE(c.ct.length - 4);
  console.log('     末4B(LE)=' + want + '  => 若为 CRC32(体) 则等于 ' + crc32(body) + ' : ' + (want === crc32(body)));
}
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); } return (c ^ 0xFFFFFFFF) >>> 0; }
