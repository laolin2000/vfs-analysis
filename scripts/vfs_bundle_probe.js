// 终末地：读取内层 UnityFS bundle（明文 .ab）的头部 + 从块信息区提取资源路径字符串
// 头部字段顺序依 AnimeStudio VFSUtils.ReadHeader(ArknightsEndfield)；IsValidHeader 已本地验证通过
'use strict';
const fs = require('fs'), path = require('path');
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function rotr(v, c) { return ((v >>> c) | (v << (32 - c))) >>> 0; }
function ror64(v, c) { return ((v >> BigInt(c)) | (v << BigInt(64 - c))) & 0xFFFFFFFFFFFFFFFFn; }
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
function parseBlc(blcPath, key) {
  const raw = fs.readFileSync(blcPath);
  const span = kstream(Buffer.from(raw.subarray(12)), key, raw.subarray(0, 12), 1).subarray(0, raw.length - 16);
  let p = 0;
  const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; };
  const u8 = () => span[p++];
  const str = (n) => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const rv = i32(); if (rv < 11) i32(); str(u16()); i64(); i32(); i64(); u8(); const cc = i32(); const files = [];
  for (let i = 0; i < cc; i++) {
    const md5 = span.subarray(p, p + 16).toString('hex'); p += 32; i64(); u8(); i32(); const fc = i32();
    for (let j = 0; j < fc; j++) { const name = str(u16()); i64(); p += 32; const off = i64(), len = i64(); const bt = u8(), ue = u8() !== 0; let iv = 0; if (ue) iv = i64(); i32(); files.push({ name, off, len, bt, ue, iv, chunk: md5 }); }
  }
  return files;
}
function isValid(b) {
  const a = b.readUInt32BE(0), bb = b.readUInt32BE(4);
  const c1 = (4 * ((a ^ 0x4A92F0CD) >>> 0)) & 0xFFFF0000;
  const c2 = rotr((a ^ 0x4A92F0CD) >>> 0, 14);
  return bb === ((c1 ^ c2 ^ 0xD8B1E637) >>> 0);
}
function decodeHeader(b) {
  let p = 0;
  const U16 = () => { const v = b.readUInt16BE(p); p += 2; return v; };
  const U32 = () => { const v = b.readUInt32BE(p); p += 4; return v; };
  const cbis2 = U16(), flags2 = U32(), encFlags = U32(), size2 = U32(), flags1 = U32();
  const ubis1 = U16(); U32(); const ubis2 = U16(); const size1 = U32(); const cbis1 = U16(); p += 1;
  const cat32 = (hi, lo) => ((((hi & 0xFFFF) * 0x10000 + (lo & 0xFFFF)) >>> 0));
  const cat64 = (hi, lo) => ((BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0));
  let cbis = rotr(cat32(cbis1 ^ cbis2 ^ 0xA121, cbis2), 18) ^ 0xF74324EE;
  let ubis = rotr(cat32(ubis1 ^ ubis2 ^ 0xA121, ubis2), 18) ^ 0xF74324EE;
  let size = ror64(cat64(size1 ^ size2 ^ 0xDAD76848, size2), 18) ^ 0xA4F1A11747816520n;
  return { cbis: cbis >>> 0, ubis: ubis >>> 0, size, flags: (flags1 ^ flags2 ^ 0xA7F49310) >>> 0, encFlags, headLen: p };
}

const key = Buffer.from(process.argv[2], 'base64'), vfs = process.argv[3], outDir = process.argv[4];
fs.mkdirSync(outDir, { recursive: true });
const bundleDir = '7064D8E2';
const files = parseBlc(path.join(vfs, bundleDir, bundleDir + '.blc'), key).filter(f => !f.ue);
console.log('Bundle 块明文文件: ' + files.length);
const chunkCache = new Map();
function readFile(f, maxBytes) {
  const cp = path.join(vfs, bundleDir, f.chunk + '.chk');
  if (!chunkCache.has(cp)) chunkCache.set(cp, fs.openSync(cp, 'r'));
  const fd = chunkCache.get(cp);
  const n = Math.min(f.len, maxBytes || f.len);
  const b = Buffer.alloc(n);
  fs.readSync(fd, b, 0, n, f.off);
  return b;
}
// 按大小分层抽样
const sorted = files.slice().sort((a, b) => b.len - a.len);
const picks = [];
for (const frac of [0, 0.15, 0.3, 0.45, 0.6, 0.75, 0.9, 0.99]) picks.push(sorted[Math.floor(frac * (sorted.length - 1))]);
const seen = new Set();
console.log('\n=== 头部还原结果（抽样 ' + picks.length + ' 个）===');
const pathStrings = [];
for (const f of picks) {
  if (seen.has(f.name)) continue; seen.add(f.name);
  const b = readFile(f, Math.min(f.len, 4 * 1024 * 1024));
  const ok = isValid(b);
  let line = '  ' + (f.len / 1048576).toFixed(2).padStart(7) + 'MB  ' + f.name + '  valid=' + ok;
  if (ok) {
    const h = decodeHeader(b);
    const ctype = h.flags & 0x3f;
    line += '  size=' + h.size + ' flags=0x' + h.flags.toString(16) + ' 压缩类型=' + ctype + ' cbis=' + h.cbis + ' ubis=' + h.ubis + ' 文件长=' + f.len;
    // 提取路径式字符串
    const txt = b.toString('latin1');
    for (const s of (txt.match(/[\x20-\x7e]{10,200}/g) || [])) {
      if (/^(Assets|Packages|Data)\//.test(s) || /\.(prefab|asset|mat|png|fbx|mesh|anim|controller|shader|txt|json|bytes|ab)$/i.test(s)) pathStrings.push(s);
    }
  }
  console.log(line);
}
console.log('\n=== 从块信息区提取到的资源路径类字符串(去重前 ' + pathStrings.length + ') ===');
const uniq = [...new Set(pathStrings)];
console.log('去重后: ' + uniq.length);
for (const s of uniq.slice(0, 60)) console.log('  ' + s);
fs.writeFileSync(path.join(outDir, 'bundle_paths_sample.txt'), uniq.join('\n'));
