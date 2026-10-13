// 终末地：用 VFSFile.cs 的 sanity check 作为约束，暴力定位内层 bundle 头部字段布局
'use strict';
const fs = require('fs'), path = require('path');
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function rotr(v, c) { return ((v >>> c) | (v << (32 - c))) >>> 0; }
function ror64(v, c) { return ((v >> BigInt(c)) | (v << BigInt(64 - c))) & 0xFFFFFFFFFFFFFFFFn; }
function rol64(v, c) { return ((v << BigInt(c)) | (v >> BigInt(64 - c))) & 0xFFFFFFFFFFFFFFFFn; }
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
const cat32 = (hi, lo) => (((((hi & 0xFFFF) * 0x10000) + (lo & 0xFFFF)) >>> 0));
const cat64 = (hi, lo) => ((BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0));
const MAXINFO = 64 * 1024 * 1024;

// 候选 A: VfsParser 常量 (0xA121/ror18/0xF74324EE, 0xDAD76848/rol14/0xA4F1A11747816520)
function candA(b) {
  const cbis2 = b.readUInt16BE(0), flags2 = b.readUInt32BE(2), encFlags = b.readUInt32BE(6);
  const size2 = b.readUInt32BE(10), flags1 = b.readUInt32BE(14), ubis1 = b.readUInt16BE(18);
  b.readUInt32BE(20); const ubis2 = b.readUInt16BE(24), size1 = b.readUInt32BE(26), cbis1 = b.readUInt16BE(30);
  return {
    cbis: (rotr(cat32(cbis1 ^ cbis2 ^ 0xA121, cbis2), 18) ^ 0xF74324EE) >>> 0,
    ubis: (rotr(cat32(ubis1 ^ ubis2 ^ 0xA121, ubis2), 18) ^ 0xF74324EE) >>> 0,
    size: ror64(cat64(size1 ^ size2 ^ 0xDAD76848, size2), 18) ^ 0xA4F1A11747816520n,
    flags: (flags1 ^ flags2 ^ 0xA7F49310) >>> 0, encFlags, headLen: 32,
  };
}
// 候选 B: 同常量但旋转方向改 rol（有些实现用 rol）
function candB(b) {
  const r = candA(b);
  return { ...r, cbis: (rol32(cat32(b.readUInt16BE(30) ^ b.readUInt16BE(0) ^ 0xA121, b.readUInt16BE(0)), 18) ^ 0xF74324EE) >>> 0 };
}
function rol32(v, c) { return (((v << c) | (v >>> (32 - c))) >>> 0); }
// 候选 C: 交换 fields 位置假设（先 size 后 flags 等），仍用 A 的常量
function candC(b) {
  const cbis2 = b.readUInt16BE(0), encFlags = b.readUInt32BE(2), flags2 = b.readUInt32BE(6);
  const flags1 = b.readUInt32BE(10), size2 = b.readUInt32BE(14), ubis1 = b.readUInt16BE(18);
  b.readUInt32BE(20); const ubis2 = b.readUInt16BE(24), cbis1 = b.readUInt16BE(26), size1 = b.readUInt32BE(28), x = b.readUInt32BE(32);
  return {
    cbis: (rotr(cat32(cbis1 ^ cbis2 ^ 0xA121, cbis2), 18) ^ 0xF74324EE) >>> 0,
    ubis: (rotr(cat32(ubis1 ^ ubis2 ^ 0xA121, ubis2), 18) ^ 0xF74324EE) >>> 0,
    size: ror64(cat64(size1 ^ size2 ^ 0xDAD76848, size2), 18) ^ 0xA4F1A11747816520n,
    flags: (flags1 ^ flags2 ^ 0xA7F49310) >>> 0, encFlags, headLen: 36,
  };
}

const key = Buffer.from(process.argv[2], 'base64'), vfs = process.argv[3];
const dir = '7064D8E2';
const files = parseBlc(path.join(vfs, dir, dir + '.blc'), key).filter(f => !f.ue);
// 取中等与小的样本
const sorted = files.slice().sort((a, b) => b.len - a.len);
const picks = [0, Math.floor(sorted.length * 0.1), Math.floor(sorted.length * 0.3), Math.floor(sorted.length * 0.5), Math.floor(sorted.length * 0.7), Math.floor(sorted.length * 0.9), sorted.length - 1].map(i => sorted[i]);
function readB(f, n) {
  const fd = fs.openSync(path.join(vfs, dir, f.chunk + '.chk'), 'r');
  const b = Buffer.alloc(Math.min(f.len, n)); fs.readSync(fd, b, 0, b.length, f.off); fs.closeSync(fd); return b;
}
for (const [name, fn] of [['A(VfsParser常量)', candA], ['C(字段交换假设)', candC]]) {
  console.log('\n===== 候选 ' + name + ' =====');
  for (const f of picks) {
    const b = readB(f, 64);
    if (!isValid(b)) { console.log('  ' + f.name + ' valid=false'); continue; }
    const h = fn(b);
    const okCap = h.cbis <= MAXINFO && h.ubis <= MAXINFO && h.cbis > 0 && h.ubis > 0;
    const okSize = Number(h.size) === f.len;
    console.log('  ' + (f.len / 1048576).toFixed(2).padStart(7) + 'MB ' + f.name +
      ' | cbis=' + h.cbis + ' ubis=' + h.ubis + ' size=' + h.size + ' flags=0x' + h.flags.toString(16) + ' encFlags=' + h.encFlags +
      ' | 尺寸合理=' + okCap + ' 文件长吻合=' + okSize + ' 压缩=' + (h.flags & 0x3f));
  }
}
