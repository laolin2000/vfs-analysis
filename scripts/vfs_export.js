// 终末地 VFS 全量清单导出：CSV + 按块类型的路径树/前缀统计
// 用法: node vfs_export.js <keyB64> <vfsPath> <outDir>
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
  const body = dec.subarray(0, dec.length - 4);
  const crcOk = dec.readUInt32LE(dec.length - 4) === crc32(body);
  const span = body;
  let p = 0;
  const i32 = () => { const v = span.readInt32LE(p); p += 4; return v; };
  const i64 = () => { const v = Number(span.readBigInt64LE(p)); p += 8; return v; };
  const u16 = () => { const v = span.readUInt16LE(p); p += 2; return v; };
  const u8 = () => span[p++];
  const str = (n) => { const s = span.toString('utf8', p, p + n); p += n; return s; };
  const u128 = () => { const v = span.subarray(p, p + 16).toString('hex'); p += 16; return v; };
  const rv = i32(); let codeVersion, version;
  if (rv < 11) { codeVersion = rv; version = i32(); } else { codeVersion = 3; version = rv; }
  const groupCfgName = str(u16()); const groupCfgHashName = i64(); const fileInfoNum = i32(); const chunksLength = i64();
  const blockType = u8(); const chunkCount = i32();
  const chunks = [];
  for (let ci = 0; ci < chunkCount; ci++) {
    const md5Name = u128(); const contentMd5 = u128(); const chunkLength = i64(); const cbt = u8();
    if (codeVersion > 3) i32();
    const fileCount = i32(); const files = [];
    for (let fi = 0; fi < fileCount; fi++) {
      const name = str(u16()); const nameHash = i64(); const chunkMd5 = u128(); const dataMd5 = u128();
      const off = i64(), len = i64(), fbt = u8(), useEnc = u8() !== 0;
      const ivSeed = useEnc ? i64() : 0;
      if (codeVersion > 3) i32();
      files.push({ name, off, len, blockType: fbt, useEncrypt: useEnc, ivSeed, chunkMd5, nameHash, dataMd5 });
    }
    chunks.push({ md5Name, contentMd5, chunkLength, blockType: cbt, files });
  }
  return { crcOk, codeVersion, version, groupCfgName, groupCfgHashName, fileInfoNum, chunksLength, blockType, chunks };
}

const key = Buffer.from(process.argv[2], 'base64');
const vfs = process.argv[3];
const outDir = process.argv[4] || '.';
fs.mkdirSync(outDir, { recursive: true });

const dirs = fs.readdirSync(vfs).filter(d => { try { return fs.statSync(path.join(vfs, d)).isDirectory(); } catch { return false; } }).sort();
const csv = fs.createWriteStream(path.join(outDir, 'vfs_filelist.csv'));
csv.write('blockDir,blockName,blockType,filePath,sizeBytes,useEncrypt,ivSeed,chunkFile,chunkOffset\n');

const summary = [];
let totalFiles = 0, totalBytes = 0;
for (const d of dirs) {
  const blc = path.join(vfs, d, d + '.blc');
  if (!fs.existsSync(blc)) { summary.push({ dir: d, name: '(空目录)', files: 0, bytes: 0, chunks: 0 }); continue; }
  let info;
  try { info = parseBlc(blc, key); } catch (e) { summary.push({ dir: d, name: 'PARSE_FAIL: ' + e.message, files: 0, bytes: 0, chunks: 0 }); continue; }
  let n = 0, by = 0;
  for (const c of info.chunks) for (const f of c.files) {
    csv.write([d, info.groupCfgName, info.blockType, JSON.stringify(f.name), f.len, f.useEncrypt ? 1 : 0, f.ivSeed, c.md5Name, f.off].join(',') + '\n');
    n++; by += f.len;
  }
  totalFiles += n; totalBytes += by;
  summary.push({ dir: d, name: info.groupCfgName, bt: info.blockType, crc: info.crcOk, files: n, bytes: by, chunks: info.chunks.length, groupCfgHashName: info.groupCfgHashName, chunksLength: info.chunksLength });

  // 该块的路径结构树 + 前缀统计
  const tree = new Map();   // 一级目录 -> 计数
  const depth2 = new Map(); // 二级目录 -> 计数
  const ext = new Map();
  for (const c of info.chunks) for (const f of c.files) {
    const parts = f.name.split('/');
    const top = parts[0] || '(root)';
    tree.set(top, (tree.get(top) || 0) + 1);
    const two = parts.slice(0, 2).join('/');
    depth2.set(two, (depth2.get(two) || 0) + 1);
    const m = /\.([A-Za-z0-9]{1,6})$/.exec(f.name);
    const e = m ? m[1].toLowerCase() : '(none)';
    ext.set(e, (ext.get(e) || 0) + 1);
  }
  const top5 = [...depth2.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  summary[summary.length - 1].top2 = top5;
  summary[summary.length - 1].ext = [...ext.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
}
csv.end();

setTimeout(() => {
  console.log('=== 块类型汇总 ===');
  console.log('目录      块名                  bt   chunk  文件数      大小          CRC');
  for (const s of summary.filter(x => x.files)) {
    console.log(s.dir + '  ' + String(s.name).padEnd(20) + String(s.bt).padEnd(5) + String(s.chunks).padEnd(8) + String(s.files).padEnd(12) + (s.bytes / 1073741824).toFixed(3).padStart(8) + ' GB   ' + (s.crc ? 'OK' : 'BAD'));
  }
  const empty = summary.filter(x => !x.files);
  console.log('\n空目录(' + empty.length + '): ' + empty.map(x => x.dir + ':' + x.name).join('  '));
  console.log('\n总计: ' + totalFiles + ' 文件, ' + (totalBytes / 1073741824).toFixed(2) + ' GB');
  console.log('\n=== 各块二级路径 TOP ===');
  for (const s of summary.filter(x => x.files && x.top2)) {
    console.log('\n-- ' + s.name + ' (' + s.dir + ', ' + s.files + ' 文件)');
    console.log('   扩展名: ' + s.ext.map(([k, v]) => k + '=' + v).join(' '));
    for (const [k, v] of s.top2) console.log('   ' + String(v).padStart(7) + '  ' + k);
  }
}, 1500);
