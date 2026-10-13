// 终末地 VFS：全量解密 .blc 索引 -> 汇总块类型 / 文件数 / 加密标志 / 块类型目录名反推
'use strict';
const fs = require('fs'), path = require('path');
const crypto = require('crypto');

// ChaCha20 (RFC8439) —— 与 VfsLoader 一致：nonce 12B，counter 从 1 开始
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

const HEAD_LEN = 12;
function decryptBlc(p, key) {
  const raw = fs.readFileSync(p);
  const dec = applyKeystream(Buffer.from(raw.subarray(HEAD_LEN)), key, raw.subarray(0, HEAD_LEN), 1);
  const body = dec.subarray(0, dec.length - 4);
  return { dec, body, crcOk: dec.readUInt32LE(dec.length - 4) === crc32(body) };
}
// VfsParser.Parse 等价实现（只取需要的字段 + 文件表）
function parse(span) {
  let p = 0;
  const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; };
  const u8 = () => span[p++];
  const str = (n) => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const u128 = () => { const v = span.subarray(p, p + 16).toString('hex'); p += 16; return v; };
  const rawVersion = i32();
  let codeVersion, version;
  if (rawVersion < 11) { codeVersion = rawVersion; version = i32(); } else { codeVersion = 3; version = rawVersion; }
  const gName = str(u16()); const gHash = i64(), fileInfoNum = i32(), chunksLen = i64();
  const blockType = u8(), chunkCount = i32();
  const chunks = [];
  for (let ci = 0; ci < chunkCount; ci++) {
    const md5Name = u128(), contentMd5 = u128(), chunkLen = i64(), cbt = u8();
    if (codeVersion > 3) i32();
    const fileCount = i32(), files = [];
    for (let fi = 0; fi < fileCount; fi++) {
      const name = str(u16()), nh = i64(), fcm = u128(), fdm = u128();
      const off = i64(), len = i64(), fbt = u8(), useEnc = u8() !== 0;
      const ivSeed = useEnc ? i64() : 0;
      if (codeVersion > 3) i32();
      files.push({ name, off, len, blockType: fbt, useEncrypt: useEnc, ivSeed });
    }
    chunks.push({ md5Name, contentMd5, chunkLen, blockType: cbt, files });
  }
  return { version, codeVersion, groupCfgName: gName, groupCfgHashName: gHash, fileInfoNum, chunksLength: chunksLen, blockType, chunks };
}

const key = Buffer.from(process.argv[2], 'base64');
const vfs = process.argv[3];
const dirs = fs.readdirSync(vfs).filter(d => fs.statSync(path.join(vfs, d)).isDirectory());
console.log('VFS 子目录数: ' + dirs.length + '\n');
let allFiles = 0, allEnc = 0, allBytes = 0, allChunkBytes = 0;
const rows = [], extAll = {}, btAll = {};
for (const d of dirs) {
  const blc = path.join(vfs, d, d + '.blc');
  if (!fs.existsSync(blc)) { rows.push([d, '(无 .blc)', '', '', '', '', '']); continue; }
  let info;
  try { const r = decryptBlc(blc, key); info = parse(r.body); rows.push([d, info.groupCfgName, String(info.blockType), String(info.chunks.length), String(info.fileInfoNum), String(info.chunksLength), r.crcOk ? 'CRC OK' : 'CRC BAD']); }
  catch (e) { rows.push([d, 'PARSE FAIL: ' + e.message, '', '', '', '', '']); continue; }
  let f = 0, e2 = 0, by = 0;
  for (const c of info.chunks) for (const x of c.files) {
    f++; by += x.len; if (x.useEncrypt) e2++;
    const m = /\.([A-Za-z0-9]{1,6})$/.exec(x.name); const ext = m ? m[1].toLowerCase() : '(none)';
    extAll[ext] = (extAll[ext] || 0) + 1;
  }
  btAll[info.groupCfgName] = (btAll[info.groupCfgName] || 0) + f;
  allFiles += f; allEnc += e2; allBytes += by; allChunkBytes += info.chunksLength;
  rows.push([d, info.groupCfgName, String(info.blockType), String(info.chunks.length), String(f), (by / 1048576).toFixed(1) + 'MB', (info.chunksLength / 1048576).toFixed(1) + 'MB', 'enc=' + e2]);
}
console.log('目录      块类型名            bt  块数  文件数   载荷大小      chunk字节');
for (const r of rows) console.log(r[0].padEnd(9) + ' ' + String(r[1]).padEnd(20) + String(r[2]).padEnd(4) + String(r[3]).padEnd(6) + String(r[4]).padEnd(9) + String(r[5]).padEnd(12) + (r[6] || '') + ' ' + (r[7] || ''));
console.log('\n合计: 文件 ' + allFiles + ' 个, 其中 UseEncrypt=' + allEnc + ' 个, 载荷 ' + (allBytes / 1073741824).toFixed(2) + ' GB, chunk 总字节 ' + (allChunkBytes / 1073741824).toFixed(2) + ' GB');
console.log('\n扩展名分布: ' + Object.entries(extAll).sort((a, b) => b[1] - a[1]).map(([k, v]) => k + '=' + v).join('  '));

// 反推块类型目录名 = CRC32(BlockTypeName) ?
const names = ["None","InitAudio","InitBundle","InitialExtendData","BundleManifest","IFixPatchOut","AuditStreaming","AuditDynamicStreaming","AuditIV","AuditAudio","AuditVideo","Bundle","Audio","Video","IV","Streaming","DynamicStreaming","Lua","Table","JsonData","ExtendData","HotfixAudio","AudioChinese","AudioEnglish","AudioJapanese","AudioKorean","Raw"];
console.log('\n目录名 = CRC32(块类型名) ?');
for (const n of names) { const h = crc32(Buffer.from(n, 'utf8')).toString(16).toUpperCase().padStart(8, '0'); console.log('  ' + String(crc32(Buffer.from(n, 'utf8'))).padStart(10) + '  0x' + h + '  ' + n); }
