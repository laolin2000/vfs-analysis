// 终末地：抽检 bundle 内部明文资源路径字符串 + AKPK 音频包结构
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
const key = Buffer.from(process.argv[2], 'base64'), vfs = process.argv[3], outDir = process.argv[4];
fs.mkdirSync(outDir, { recursive: true });
function grab(dir, f, n) {
  const fd = fs.openSync(path.join(vfs, dir, f.chunk + '.chk'), 'r');
  const len = Math.min(f.len, n); const b = Buffer.alloc(len);
  fs.readSync(fd, b, 0, len, f.off); fs.closeSync(fd); return b;
}
// ---- 1) bundle 明文路径抽检 ----
const bdir = '7064D8E2';
const bfiles = parseBlc(path.join(vfs, bdir, bdir + '.blc'), key).filter(f => !f.ue);
const bsorted = bfiles.slice().sort((a, b) => b.len - a.len);
const sample = [];
for (const frac of [0.02, 0.2, 0.4, 0.6, 0.8, 0.95]) sample.push(bsorted[Math.floor(frac * (bsorted.length - 1))]);
console.log('===== bundle 内明文路径字符串抽检 =====');
const allStrings = new Set();
for (const f of sample) {
  const b = grab(bdir, f, 2 * 1024 * 1024);
  const txt = b.toString('latin1');
  const cand = (txt.match(/[\x20-\x7e]{12,180}/g) || []).filter(s =>
    /\.(prefab|asset|mat|png|fbx|anim|controller|shader|json|bytes|mesh|txt|hlsl)$/i.test(s) || /^(Assets|Packages|Data)\//.test(s));
  const uniq = [...new Set(cand)];
  console.log('  ' + (f.len / 1048576).toFixed(2).padStart(7) + 'MB ' + f.name + ' -> 候选路径字符串 ' + uniq.length);
  for (const s of uniq.slice(0, 5)) console.log('       ' + s);
  uniq.forEach(s => allStrings.add(s));
}
fs.writeFileSync(path.join(outDir, 'bundle_inner_strings.txt'), [...allStrings].join('\n'));
console.log('  合并非重复 ' + allStrings.size + ' 条，已写出');

// ---- 2) AKPK 音频包结构 ----
console.log('\n===== AKPK (.pck) 结构 =====');
const adir = '24ED34CF';
for (const f of parseBlc(path.join(vfs, adir, adir + '.blc'), key)) {
  const b = grab(adir, f, 4096);
  const beU32 = (o) => b.readUInt32BE(o);
  console.log('  ' + f.name + '  ' + (f.len / 1048576).toFixed(1) + 'MB');
  console.log('     头: ' + b.subarray(0, 32).toString('hex').replace(/(..)/g, '$1 '));
  console.log('     sig="' + b.subarray(0, 4).toString('latin1') + '" (BE 0x' + beU32(0).toString(16).toUpperCase() + ')  headerSize?=' + beU32(4) +
              '  md5=' + b.subarray(8, 24).toString('hex') + '  u32@24=' + beU32(24) + ' u32@28=' + beU32(28));
  const strings = (b.subarray(0, 2048).toString('latin1').match(/[\x20-\x7e]{6,}/g) || []);
  console.log('     可打印串样例: ' + JSON.stringify(strings.slice(0, 5)));
}
