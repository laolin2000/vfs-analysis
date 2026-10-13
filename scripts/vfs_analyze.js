// 终末地 VFS 全清单语义分析：目录树 / 命名规律 / 语义关键词 / 分类统计
// 用法: node vfs_analyze.js <vfs_filelist.csv> <outDir>
'use strict';
const fs = require('fs'), readline = require('readline');

const csvPath = process.argv[2], outDir = process.argv[3] || '.';
fs.mkdirSync(outDir, { recursive: true });

// 语义关键词 -> 说明
const KW = [
  ['/Characters/', '角色相关'],
  ['/Chr_', '角色资源'],
  ['/Weapon', '武器'],
  ['/Item', '道具'],
  ['/UI/', '界面'],
  ['/Level', '关卡'],
  ['/Map', '地图'],
  ['/Env', '场景环境'],
  ['/Fac', '基建/工厂'],
  ['/Audio', '音频'],
  ['/Voice', '配音'],
  ['/Music', '音乐'],
  ['/Movie', '过场影片'],
  ['/Video', '视频'],
  ['/Effect', '特效'],
  ['/Skill', '技能'],
  ['/Enemy', '敌人'],
  ['/Npc', 'NPC'],
  ['/Shader', '着色器'],
  ['/Terrain', '地形'],
  ['/Icon', '图标'],
  ['/Texture', '贴图'],
  ['/Anim', '动画'],
  ['/Timeline', '时间轴演出'],
  ['/Cfg', '配置'],
  ['/Table', '数据表'],
  ['/Activity', '活动'],
  ['/Gacha', '抽卡'],
  ['/Guide', '教学引导'],
  ['/Tutorial', '教程'],
  ['/Sns', '社交'],
  ['/AIConfig', 'AI 配置'],
  ['/Spaceship', '飞船'],
  ['/Domain', '领域/据点'],
];

const stats = {
  total: 0, bytes: 0, enc: 0,
  byBlock: new Map(),      // block -> {files, bytes, enc}
  byExt: new Map(),
  byExtBytes: new Map(),
  top1: new Map(), top2: new Map(), top3: new Map(),
  jsonTop2: new Map(), jsonTop3: new Map(),
  bundleTop3: new Map(), bundleTop4: new Map(),
  usmTop3: new Map(),
  kw: new Map(KW.map(([k]) => [k, { n: 0, bytes: 0, ex: [] }])),
  biggest: [],
  jsonSamples: [],
  usmSamples: [],
  streamingSamples: [],
  terrainSamples: [],
  ivSamples: [],
};

const rl = readline.createInterface({ input: fs.createReadStream(csvPath), crlfDelay: Infinity });
let first = true;
const bump = (m, k, bytes) => { const e = m.get(k) || { n: 0, bytes: 0 }; e.n++; e.bytes += bytes; m.set(k, e); };

rl.on('line', (line) => {
  if (first) { first = false; return; }
  // blockDir,blockName,blockType,"path",size,enc,iv,chunk,off
  const m = /^([^,]*),([^,]*),([^,]*),(".*?"|.*?),(\d+),(\d+),(-?\d+),([0-9a-f]*),(\d+)$/.exec(line);
  if (!m) return;
  const block = m[2], pathStr = m[4].replace(/^"|"$/g, ''), size = Number(m[5]), enc = m[6] === '1';
  stats.total++; stats.bytes += size; if (enc) stats.enc++;
  let b = stats.byBlock.get(block); if (!b) { b = { files: 0, bytes: 0, enc: 0 }; stats.byBlock.set(block, b); }
  b.files++; b.bytes += size; if (enc) b.enc++;
  const ext = (/\.([A-Za-z0-9]{1,6})$/.exec(pathStr) || [, '(none)'])[1].toLowerCase();
  bump(stats.byExt, ext, size); 
  const eb = stats.byExtBytes.get(ext) || 0; stats.byExtBytes.set(ext, eb + size);
  const p = pathStr.split('/');
  bump(stats.top1, p[0] || '(root)', size);
  bump(stats.top2, p.slice(0, 2).join('/'), size);
  bump(stats.top3, p.slice(0, 3).join('/'), size);
  if (ext === 'json') {
    bump(stats.jsonTop2, p.slice(0, 2).join('/'), size);
    bump(stats.jsonTop3, p.slice(2, 3).join('') ? p.slice(0, 3).join('/') : p.slice(0, 2).join('/'), size);
    if (stats.jsonSamples.length < 400 && /\/[A-Za-z0-9_]+\.json$/.test(pathStr)) stats.jsonSamples.push({ pathStr, size });
  }
  if (ext === 'ab') { bump(stats.bundleTop3, p.slice(0, 3).join('/'), size); bump(stats.bundleTop4, p.slice(0, 4).join('/'), size); }
  if (ext === 'usm') { bump(stats.usmTop3, p.slice(0, 3).join('/'), size); if (stats.usmSamples.length < 200) stats.usmSamples.push({ pathStr, size }); }
  if (ext === 'bytes') {
    if (pathStr.includes('/Streaming/')) { bump(stats.streamingSamples.__m || (stats.streamingSamples.__m = new Map()), p.slice(0, 3).join('/'), size); if (stats.streamingSamples.length < 200) stats.streamingSamples.push({ pathStr, size }); }
    if (pathStr.includes('/Terrain/')) { if (stats.terrainSamples.length < 200) stats.terrainSamples.push({ pathStr, size }); }
  }
  if (pathStr.includes('/IrradianceVolume/')) { if (stats.ivSamples.length < 100) stats.ivSamples.push({ pathStr, size }); }
  for (const [k] of KW) if (pathStr.includes(k)) { const e = stats.kw.get(k); e.n++; e.bytes += size; if (e.ex.length < 3) e.ex.push(pathStr); }
  if (stats.biggest.length < 40) { stats.biggest.push({ pathStr, size, block }); stats.biggest.sort((a, b2) => b2.size - a.size); }
  else if (size > stats.biggest[stats.biggest.length - 1].size) { stats.biggest[stats.biggest.length - 1] = { pathStr, size, block }; stats.biggest.sort((a, b2) => b2.size - a.size); }
});

const fmt = (n) => (n / 1048576).toFixed(2) + 'MB';
const show = (m, top, label) => {
  console.log('\n-- ' + label);
  for (const [k, v] of [...m.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, top)) console.log('  ' + String(v.n).padStart(8) + '  ' + fmt(v.bytes).padStart(11) + '  ' + k);
};

rl.on('close', () => {
  console.log('=== 总计: ' + stats.total + ' 文件, ' + (stats.bytes / 1073741824).toFixed(2) + ' GB, 加密条目 ' + stats.enc + ' ===');
  console.log('\n=== 按块 ===');
  for (const [k, v] of [...stats.byBlock.entries()].sort((a, b) => b[1].bytes - a[1].bytes)) console.log('  ' + k.padEnd(20) + String(v.files).padStart(8) + ' 文件  ' + fmt(v.bytes).padStart(11) + '  enc=' + v.enc);
  console.log('\n=== 按扩展名 ===');
  for (const [k, v] of [...stats.byExt.entries()].sort((a, b) => b[1].n - a[1].n)) console.log('  ' + k.padEnd(10) + String(v.n).padStart(8) + '  ' + fmt(v.bytes).padStart(11));
  show(stats.top1, 20, '一级目录(Data/ 下)');
  show(stats.top2, 30, '二级目录');
  show(stats.top3, 40, '三级目录');
  show(stats.jsonTop2, 30, 'JSON 二级目录');
  show(stats.jsonTop3, 50, 'JSON 三级目录');
  show(stats.bundleTop3, 25, 'Bundle(.ab) 三级目录');
  show(stats.bundleTop4, 40, 'Bundle(.ab) 四级目录');
  show(stats.usmTop3, 20, 'USM 视频三级目录');
  console.log('\n=== 语义关键词命中 ===');
  for (const [k, v] of [...stats.kw.entries()].sort((a, b) => b[1].n - a[1].n)) console.log('  ' + k.padEnd(18) + String(v.n).padStart(8) + '  ' + fmt(v.bytes).padStart(11) + '   例: ' + v.ex[0]);
  console.log('\n=== 最大的 40 个文件 ===');
  for (const b of stats.biggest) console.log('  ' + fmt(b.size).padStart(11) + '  [' + b.block + '] ' + b.pathStr);
  fs.writeFileSync(outDir + '/json_samples.txt', stats.jsonSamples.map(x => fmt(x.size).padStart(10) + '  ' + x.pathStr).join('\n'));
  fs.writeFileSync(outDir + '/usm_samples.txt', stats.usmSamples.map(x => fmt(x.size).padStart(10) + '  ' + x.pathStr).join('\n'));
  fs.writeFileSync(outDir + '/streaming_samples.txt', stats.streamingSamples.map(x => fmt(x.size).padStart(10) + '  ' + x.pathStr).join('\n'));
  fs.writeFileSync(outDir + '/terrain_samples.txt', stats.terrainSamples.map(x => fmt(x.size).padStart(10) + '  ' + x.pathStr).join('\n'));
  fs.writeFileSync(outDir + '/iv_samples.txt', stats.ivSamples.map(x => fmt(x.size).padStart(10) + '  ' + x.pathStr).join('\n'));
  console.log('\n样本已写入 ' + outDir);
});
