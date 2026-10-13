// 终末地 VFS 结构探针：ChaCha20 解密 .blc 块索引 + 解析 + CRC32 校验
'use strict';
const fs = require('fs');

// ---- ChaCha20 (RFC 8439: 32B key, 12B nonce, 32-bit counter) ----
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
    const ks = block(key, nonce, counter++);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
  }
  return out;
}
// ---- CRC32 (IEEE) ----
const T = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = T[(c ^ buf[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }

// ---- .blc 解密 ----
const HEAD_LEN = 12, PROTO = 3;
function decryptBlc(path, key) {
  const raw = fs.readFileSync(path);
  const nonce = raw.subarray(0, HEAD_LEN);
  const payload = Buffer.from(raw.subarray(HEAD_LEN));
  const dec = applyKeystream(payload, key, nonce, 1);
  const body = dec.subarray(0, dec.length - 4);
  const want = dec.readUInt32LE(dec.length - 4);
  const got = crc32(body);
  return { raw, dec, body, crcOk: want === got, want, got };
}

// ---- 解析索引体（VfsParser.Parse 的等价实现）----
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
  const gLen = u16(), gName = str(gLen), gHash = i64(), fileInfoNum = i32(), chunksLen = i64();
  const bt = u8(), chunkCount = i32();
  const chunks = [];
  for (let ci = 0; ci < chunkCount; ci++) {
    const md5Name = u128(), contentMd5 = u128(), chunkLen = i64(), cbt = u8();
    if (codeVersion > 3) i32();
    const fileCount = i32();
    const files = [];
    for (let fi = 0; fi < fileCount; fi++) {
      const nl = u16(), name = str(nl), nh = i64(), fcm = u128(), fdm = u128();
      const off = i64(), len = i64(), fbt = u8(), useEnc = u8() !== 0;
      const ivSeed = useEnc ? i64() : 0;
      if (codeVersion > 3) i32();
      files.push({ name, off, len, blockType: fbt, useEncrypt: useEnc, ivSeed });
    }
    chunks.push({ md5Name, contentMd5, chunkLen, blockType: cbt, files });
  }
  return { version, codeVersion, groupCfgName: gName, groupCfgHashName: gHash, fileInfoNum, chunksLength: chunksLen, blockType: bt, chunks };
}

// ---- main ----
const keyB64 = process.argv[2];
const files = process.argv.slice(3);
const key = Buffer.from(keyB64, 'base64');
console.log('key bytes:', key.length);
for (const f of files) {
  console.log('\n================ ' + f + ' ================');
  const r = decryptBlc(f, key);
  console.log(' raw=' + r.raw.length + ' nonce=' + r.raw.subarray(0, HEAD_LEN).toString('hex') +
              ' crc=' + (r.crcOk ? 'OK' : 'MISMATCH (want ' + r.want + ', got ' + r.got + ')'));
  console.log(' plaintext head hex: ' + r.dec.subarray(0, 48).toString('hex'));
  console.log(' plaintext head asc: ' + r.dec.subarray(0, 48).toString('latin1').replace(/[^\x20-\x7e]/g, '.'));
  let info;
  try { info = parse(r.body); } catch (e) { console.log(' PARSE FAILED: ' + e.message); continue; }
  console.log(' version=' + info.version + ' codeVersion=' + info.codeVersion +
              ' groupCfgName=' + JSON.stringify(info.groupCfgName) + ' groupCfgHashName=' + info.groupCfgHashName +
              ' fileInfoNum=' + info.fileInfoNum + ' chunksLength=' + info.chunksLength +
              ' blockType=' + info.blockType + ' chunkCount=' + info.chunks.length);
  let tot = 0, enc = 0;
  for (const c of info.chunks) { tot += c.files.length; for (const x of c.files) if (x.useEncrypt) enc++; }
  console.log(' total files=' + tot + ' encrypted=' + enc + ' plain=' + (tot - enc));
  const sample = info.chunks.flatMap(c => c.files).sort((a, b) => b.len - a.len).slice(0, 12);
  for (const s of sample) console.log('   [bt=' + s.blockType + ' enc=' + (s.useEncrypt ? 1 : 0) + '] ' + (s.len / 1048576).toFixed(2) + 'MB  ' + s.name);
  const extCount = {};
  for (const c of info.chunks) for (const x of c.files) { const m = /\.([A-Za-z0-9]+)$/.exec(x.name); const e = m ? m[1].toLowerCase() : '(无扩展名)'; extCount[e] = (extCount[e] || 0) + 1; }
  console.log(' 扩展名分布 top: ' + Object.entries(extCount).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => k + '=' + v).join(' '));
  if (process.env.DUMP_JSON) fs.writeFileSync(process.env.DUMP_JSON, JSON.stringify(info, null, 1));
}
