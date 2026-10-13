// 终末地：解密 Data/Bundles/Windows/manifest.hgmmap（BundleManifest 块）与 ExtendData 的 bin
// 用文件自身的 ivSeed 跑 ChaCha20（与 .chk 内 UseEncrypt 条目同构）
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
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); } return (c ^ 0xFFFFFFFF) >>> 0; }
function parseBlc(blcPath, key) {
  const raw = fs.readFileSync(blcPath);
  const dec = kstream(Buffer.from(raw.subarray(12)), key, raw.subarray(0, 12), 1);
  const span = dec.subarray(0, dec.length - 4);
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
const key = Buffer.from(process.argv[2], 'base64'), vfs = process.argv[3], outDir = process.argv[4];
fs.mkdirSync(outDir, { recursive: true });
const targets = [['1CDDBF1F', 'manifest.hgmmap'], ['D6E622F7', 'ExtendData bin'], ['3C9D9D2D', 'InitStringPathHash']];
for (const [dir, label] of targets) {
  const files = parseBlc(path.join(vfs, dir, dir + '.blc'), key);
  for (const f of files) {
    const fd = fs.openSync(path.join(vfs, dir, f.chunk + '.chk'), 'r');
    const buf = Buffer.alloc(f.len); fs.readSync(fd, buf, 0, f.len, f.off); fs.closeSync(fd);
    let out = buf, note = '明文';
    if (f.ue) { const nonce = Buffer.alloc(12); nonce.writeInt32LE(3, 0); nonce.writeBigInt64LE(BigInt(f.iv), 4); out = kstream(buf, key, nonce, 1); note = 'ChaCha20 解密(ivSeed=' + f.iv + ')'; }
    console.log('\n===== ' + label + ' :: ' + f.name + ' (' + (f.len / 1048576).toFixed(2) + 'MB, ' + note + ') =====');
    console.log(' 头 64B hex: ' + out.subarray(0, 64).toString('hex').replace(/(..)/g, '$1 '));
    console.log(' 头 64B asc: ' + out.subarray(0, 64).toString('latin1').replace(/[^\x20-\x7e]/g, '.'));
    const strs = (out.subarray(0, Math.min(out.length, 200000)).toString('latin1').match(/[\x20-\x7e]{8,}/g) || []);
    console.log(' 可打印字符串数(前200KB): ' + strs.length + ' 样例: ' + JSON.stringify(strs.slice(0, 6)));
    const safe = f.name.replace(/[^A-Za-z0-9_.-]/g, '_');
    fs.writeFileSync(path.join(outDir, safe + (f.ue ? '.dec' : '.raw')), out);
    console.log(' 已写出: ' + path.join(outDir, safe + (f.ue ? '.dec' : '.raw')));
  }
}
