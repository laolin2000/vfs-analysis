// 终末地 VFS：内层 UnityFS 头部反混淆验证（AnimeStudio VFSUtils.IsValidHeader / ReadHeader 的等价实现）
'use strict';
const fs = require('fs'), path = require('path');
function rotl(v, c) { return ((v << c) | (v >>> (32 - c))) >>> 0; }
function rotr(v, c) { return ((v >>> c) | (v << (32 - c))) >>> 0; }
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
  st[12] = c >>> 0; for (let i = 0; i < 3; i++) st[13 + i] = n.readUInt32LE(i * 4);
  const w = Uint32Array.from(st);
  for (let i = 0; i < 10; i++) { qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15); qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14); }
  const o = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) o.writeUInt32LE((w[i] + st[i]) >>> 0, i * 4);
  return o;
}
function kstream(d, k, n, c = 1) { const o = Buffer.alloc(d.length); for (let off = 0; off < d.length; off += 64) { const s = cblk(k, n, c++), m = Math.min(64, d.length - off); for (let i = 0; i < m; i++) o[off + i] = d[off + i] ^ s[i]; } return o; }
function readInfo(dir, vfs, key) {
  const raw = fs.readFileSync(path.join(vfs, dir, dir + '.blc'));
  const span = kstream(Buffer.from(raw.subarray(12)), key, raw.subarray(0, 12), 1).subarray(0, raw.length - 16);
  let p = 0; const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; }; const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; }; const u8 = () => span[p++]; const str = n => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const rv = i32(); if (rv < 11) i32(); str(u16()); i64(); i32(); i64(); u8(); const cc = i32(); const files = [];
  for (let i = 0; i < cc; i++) { const md5 = span.subarray(p, p + 16).toString('hex'); p += 32; i64(); u8(); i32(); const fc = i32();
    for (let j = 0; j < fc; j++) { const name = str(u16()); i64(); p += 32; const off = i64(), len = i64(); const bt = u8(), ue = u8() !== 0; let iv = 0; if (ue) iv = i64(); i32(); files.push({ name, off, len, bt, ue, iv, chunk: md5 }); } }
  return files;
}

// ---- AnimeStudio 的 VFS 内层头部反混淆 ----
function isEndfieldBundle(b) { // b: 至少 8 字节
  const a = b.readUInt32BE(0), bb = b.readUInt32BE(4);
  const c1 = (4 * ((a ^ 0x4A92F0CD) >>> 0)) & 0xFFFF0000;
  const c2 = rotr((a ^ 0x4A92F0CD) >>> 0, 14);
  const c3 = (c1 ^ c2 ^ 0xD8B1E637) >>> 0;
  return bb === c3;
}
function deobfuscateHeader(b) {
  // 依 VFSUtils.ReadHeader 的字段顺序/位运算还原
  let p = 0;
  const rU16 = () => { const v = b.readUInt16BE(p); p += 2; return v; };
  const rU32 = () => { const v = b.readUInt32BE(p); p += 4; return v; };
  const compressedBlocksInfoSize2 = rU16();
  const flags2 = rU32();
  const encFlags = rU32();
  const size2 = rU32();
  const flags1 = rU32();
  const uncompressedBlocksInfoSize1 = rU16();
  rU32();
  const uncompressedBlocksInfoSize2 = rU16();
  const size1 = rU32();
  const compressedBlocksInfoSize1 = rU16();
  const bitConcatU = (a2, b2) => (((a2 >>> 0) * 0x10000 + (b2 >>> 0)) >>> 0);
  const cat64 = (hi, lo) => (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
  const ror64 = (v, c) => ((v >> BigInt(c)) | (v << BigInt(64 - c))) & 0xFFFFFFFFFFFFFFFFn;
  let cbis = bitConcatU((compressedBlocksInfoSize1 ^ compressedBlocksInfoSize2 ^ 0xA121) & 0xFFFF, compressedBlocksInfoSize2);
  cbis = (rotr(cbis, 18) ^ 0xF74324EE) >>> 0;
  let ubis = bitConcatU((uncompressedBlocksInfoSize1 ^ uncompressedBlocksInfoSize2 ^ 0xA121) & 0xFFFF, uncompressedBlocksInfoSize2);
  ubis = (rotr(ubis, 18) ^ 0xF74324EE) >>> 0;
  let size = cat64((size1 ^ size2 ^ 0xDAD76848) >>> 0, size2);
  size = ror64(size, 18) ^ 0xA4F1A11747816520n;
  return { compressedBlocksInfoSize: cbis, uncompressedBlocksInfoSize: ubis, size, flags: (flags1 ^ flags2 ^ 0xA7F49310) >>> 0, encFlags };
}

const key = Buffer.from(process.argv[2], 'base64'), vfs = process.argv[3];
for (const [dir, label, n] of [['7064D8E2', 'Bundle(明文 .ab)', 3], ['0CE8FA57', 'InitBundle', 3]]) {
  const files = readInfo(dir, vfs, key).filter(f => !f.ue);
  console.log('\n===== ' + label + ' (' + files.length + ' 明文文件) =====');
  for (const f of files.slice(0, n)) {
    const fd = fs.openSync(path.join(vfs, dir, f.chunk + '.chk'), 'r');
    const b = Buffer.alloc(64); fs.readSync(fd, b, 0, 64, f.off); fs.closeSync(fd);
    const ok = isEndfieldBundle(b);
    console.log('  ' + f.name + '  (' + f.len + ' B)');
    console.log('    原始头: ' + b.subarray(0, 16).toString('hex').replace(/(..)/g, '$1 '));
    console.log('    IsValidHeader(第二双字 = f(第一双字)): ' + ok);
    if (ok) {
      const h = deobfuscateHeader(b);
      console.log('    还原: size=' + h.size + ' flags=0x' + h.flags.toString(16) + ' compBlocksInfo=' + h.compressedBlocksInfoSize +
                  ' uncompBlocksInfo=' + h.uncompressedBlocksInfoSize + ' encFlags=0x' + h.encFlags.toString(16) +
                  '  文件实际大小=' + f.len + (Number(h.size) === f.len ? '  ✔ size 吻合' : '  (size 与文件长度不符)'));
      console.log('    flags 低 6 位(压缩类型)= ' + (h.flags & 0x3f) + '  (0=None 2=LZ4 3=LZMA)');
    }
  }
}
