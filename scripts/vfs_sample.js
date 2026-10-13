// 终末地 VFS：按 .blc 索引抽取样本文件，验证内层格式（UnityFS 混淆 / 明文）
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
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); } return (c ^ 0xFFFFFFFF) >>> 0; }
const HEAD_LEN = 12, PROTO = 3;
function decryptBlc(p, key) {
  const raw = fs.readFileSync(p);
  return applyKeystream(Buffer.from(raw.subarray(HEAD_LEN)), key, raw.subarray(0, HEAD_LEN), 1);
}
function parse(span) {
  let p = 0;
  const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; };
  const u8 = () => span[p++];
  const str = (n) => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const u128 = () => { const v = span.subarray(p, p + 16).toString('hex'); p += 16; return v; };
  const rawVersion = i32(); let codeVersion, version;
  if (rawVersion < 11) { codeVersion = rawVersion; version = i32(); } else { codeVersion = 3; version = rawVersion; }
  str(u16()); i64(); i32(); i64();
  const blockType = u8(), chunkCount = i32();
  const chunks = [];
  for (let ci = 0; ci < chunkCount; ci++) {
    const md5Name = u128(); u128(); const chunkLen = i64(), cbt = u8();
    if (codeVersion > 3) i32();
    const fileCount = i32(), files = [];
    for (let fi = 0; fi < fileCount; fi++) {
      const name = str(u16()); i64(); u128(); u128();
      const off = i64(), len = i64(), fbt = u8(), useEnc = u8() !== 0;
      const ivSeed = useEnc ? i64() : 0;
      if (codeVersion > 3) i32();
      files.push({ name, off, len, blockType: fbt, useEncrypt: useEnc, ivSeed });
    }
    chunks.push({ md5Name, chunkLen, blockType: cbt, files });
  }
  return { codeVersion, version, blockType, chunks };
}
function hex(b, n) { return b.subarray(0, n).toString('hex').replace(/(..)/g, '$1 ').trim(); }
function asc(b, n) { return b.subarray(0, n).toString('latin1').replace(/[^\x20-\x7e]/g, '.'); }

const key = Buffer.from(process.argv[2], 'base64');
const vfs = process.argv[3];
const plan = [
  ['7064D8E2', 1, 'Bundle'],
  ['0CE8FA57', 2, 'InitBundle'],
  ['55FC21C6', 1, 'Video'],
  ['775A31D1', 3, 'JsonData(加密)'],
  ['42A8FCA6', 3, 'Table(加密)'],
  ['19E3AE45', 3, 'Lua(加密)'],
  ['24ED34CF', 2, 'Audio'],
  ['F84BF5E6', 2, 'Terrain'],
];
for (const [d, want, label] of plan) {
  const blc = path.join(vfs, d, d + '.blc');
  if (!fs.existsSync(blc)) { console.log('## ' + label + ': 无 .blc'); continue; }
  const info = parse(decryptBlc(blc, key).subarray(0, decryptBlc(blc, key).length - 4));
  const files = info.chunks.flatMap(c => c.files);
  console.log('\n================ ' + label + '  (' + d + ', ' + files.length + ' 个文件) ================');
  for (const f of files.slice(0, want)) {
    const chunkFile = path.join(vfs, d, info.chunks.find(c => c.files.includes(f)).md5Name + '.chk');
    const fd = fs.openSync(chunkFile, 'r');
    const buf = Buffer.alloc(f.len);
    fs.readSync(fd, buf, 0, f.len, f.off);
    fs.closeSync(fd);
    let out = buf, note = '明文';
    if (f.useEncrypt) {
      const nonce = Buffer.alloc(12);
      nonce.writeInt32LE(PROTO, 0); nonce.writeBigInt64LE(BigInt(f.ivSeed), 4);
      out = applyKeystream(buf, key, nonce, 1);
      note = 'UseEncrypt(ivSeed=' + f.ivSeed + ') 已解密';
    }
    console.log(' 文件: ' + f.name + '  (' + (f.len / 1024).toFixed(1) + ' KB, ' + note + ')');
    console.log('   头部hex: ' + hex(out, 32));
    console.log('   头部asc: ' + asc(out, 32));
    console.log('   尾部hex: ' + hex(out.subarray(out.length - 16), 16) + '  |  ' + asc(out.subarray(out.length - 16), 16));
    const magic = /^[A-Za-z0-9_\x00-\x7f]{4,}/.exec(asc(out, 8));
    console.log('   内层魔数: ' + JSON.stringify(magic ? magic[0] : asc(out, 4)));
  }
}
