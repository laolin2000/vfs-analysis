// 终末地 VFS：内层明文类型判定 + 目录名哈希算法反推
'use strict';
const fs = require('fs'), path = require('path');
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function qr(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}
function block(key, nonce, counter) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) st[4 + i] = key.readUInt32LE(i * 4);
  st[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) st[13 + i] = nonce.readUInt32LE(i * 4);
  const w = Uint32Array.from(st);
  for (let i = 0; i < 10; i++) {
    qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15);
    qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14);
  }
  const out = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) out.writeUInt32LE((w[i] + st[i]) >>> 0, i * 4);
  return out;
}
function applyKeystream(data, key, nonce, counter = 1) {
  const out = Buffer.alloc(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const ks = block(key, nonce, counter++), n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}
// ---- 哈希候选 ----
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); } return (c ^ 0xFFFFFFFF) >>> 0; }
function crc32c(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82F63B78 ^ (c >>> 1)) : (c >>> 1); } return (c ^ 0xFFFFFFFF) >>> 0; }
function xxh32(buf, seed = 0) {
  const P1 = 2654435761, P2 = 2246822519, P3 = 3266489917, P4 = 668265263, P5 = 374761393;
  let h, i = 0, len = buf.length;
  const rl = (v, c) => ((v << c) | (v >>> (32 - c))) >>> 0;
  if (len >= 16) {
    let v1 = (seed + P1 + P2) >>> 0, v2 = (seed + P2) >>> 0, v3 = seed >>> 0, v4 = (seed - P1) >>> 0;
    const lim = len - 16;
    do {
      v1 = (rl((v1 + buf.readUInt32LE(i) * P2) >>> 0, 13) * P1) >>> 0; i += 4;
      v2 = (rl((v2 + buf.readUInt32LE(i) * P2) >>> 0, 13) * P1) >>> 0; i += 4;
      v3 = (rl((v3 + buf.readUInt32LE(i) * P2) >>> 0, 13) * P1) >>> 0; i += 4;
      v4 = (rl((v4 + buf.readUInt32LE(i) * P2) >>> 0, 13) * P1) >>> 0; i += 4;
    } while (i <= lim);
    h = (rl(v1, 1) + rl(v2, 7) + rl(v3, 12) + rl(v4, 18)) >>> 0;
  } else h = (seed + P5) >>> 0;
  h = (h + len) >>> 0;
  while (i + 4 <= len) { h = (rl((h + buf.readUInt32LE(i) * P3) >>> 0, 17) * P4) >>> 0; i += 4; }
  while (i < len) { h = (rl((h + buf[i] * P5) >>> 0, 11) * P1) >>> 0; i++; }
  h ^= h >>> 15; h = (h * P2) >>> 0; h ^= h >>> 13; h = (h * P3) >>> 0; h ^= h >>> 16;
  return h >>> 0;
}
const known = { '07A1BB91': 'InitAudio', '0CE8FA57': 'InitBundle', '19E3AE45': 'Lua', '1CDDBF1F': 'BundleManifest', '23D53F5D': 'DynamicStreaming', '24ED34CF': 'Audio', '3C9D9D2D': 'InitialExtendData', '42A8FCA6': 'Table', '55FC21C6': 'Video', '7064D8E2': 'Bundle', '775A31D1': 'JsonData', 'A63D7E6A': 'IV', 'C3442D43': 'Streaming', 'D6E622F7': 'ExtendData', 'DAFE52C9': 'IFixPatchOut', 'F151B649': 'HotfixAudio', 'F84BF5E6': 'Terrain' };
const cands = [
  ['crc32(name)', (n) => crc32(Buffer.from(n))],
  ['crc32c(name)', (n) => crc32c(Buffer.from(n))],
  ['xxh32(name)', (n) => xxh32(Buffer.from(n))],
  ['crc32(name+\\0)', (n) => crc32(Buffer.from(n + '\0'))],
  ['crc32(lower)', (n) => crc32(Buffer.from(n.toLowerCase()))],
];
console.log('=== 目录名哈希算法验证 ===');
for (const [label, fn] of cands) {
  let hit = 0; const misses = [];
  for (const [dir, name] of Object.entries(known)) {
    const h = fn(name).toString(16).toUpperCase().padStart(8, '0');
    if (h === dir) hit++; else misses.push(name + '->' + h + '(want ' + dir + ')');
  }
  console.log(' ' + label + ': 命中 ' + hit + '/' + Object.keys(known).length + (misses.length && hit ? '  例: ' + misses[0] : ''));
}

// ---- 内层明文类型判定 ----
function hex(b, n) { return b.subarray(0, n).toString('hex').replace(/(..)/g, '$1 ').trim(); }
function asc(b, n) { return b.subarray(0, n).toString('latin1').replace(/[^\x20-\x7e]/g, '.'); }
function readInfo(blcPath, key) {
  const raw = fs.readFileSync(blcPath);
  const dec = applyKeystream(Buffer.from(raw.subarray(12)), key, raw.subarray(0, 12), 1);
  const span = dec.subarray(0, dec.length - 4);
  let p = 0;
  const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; };
  const u8 = () => span[p++];
  const str = (n) => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const rv = i32(); if (rv < 11) { i32(); } str(u16()); i64(); i32(); i64();
  u8(); const cc = i32(); const chunks = [];
  for (let i = 0; i < cc; i++) {
    p += 32; i64(); u8(); i32(); const fc = i32(); const files = [];
    for (let j = 0; j < fc; j++) { const name = str(u16()); i64(); p += 32; const off = i64(), len = i64(); const bt = u8(), ue = u8() !== 0; let iv = 0; if (ue) iv = i64(); i32(); files.push({ name, off, len, bt, ue, iv }); }
    chunks.push(files);
  }
  return chunks.flat();
}
