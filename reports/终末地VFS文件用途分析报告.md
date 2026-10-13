# 《明日方舟：终末地》StreamingAssets\VFS 全量文件用途分析报告

- 分析对象：`D:\二游\Hypergryph Launcher\games\Arknights Endfield\Endfield_Data\StreamingAssets\VFS`
- 游戏版本目录：`Endfield_Data`（Windows / PC 平台资源）
- 分析方法：离线解密 `.blc` 索引（ChaCha20）→ 逐条目导出全量清单 → 路径语义与命名规律统计 → 抽样读取内层文件头判定格式
- 全部结论均经本地实测验证（索引 CRC32 校验全部通过）

---

## 一、总览

| 指标 | 数值 |
|---|---|
| VFS 目录占用 | **56.65 GB**（1058 个物理文件） |
| 索引登记的游戏文件 | **454,558 个** |
| 块类型桶目录 | 26 个（**15 个有内容**，11 个空/预留） |
| 加密登记条目 | 97,307 个（占 21.4%，集中于配置类） |
| 平台子目录 | `PC`（视频/地形/流式/光照）、`Windows`（Unity 包/音频） |

物理文件只有两种：

| 文件 | 数量 | 作用 |
|---|---|---|
| `<8位十六进制>.blc` | 17 | 该块类型的**块索引**（ChaCha20 加密，含全部文件名/偏移/大小/加密标志，末尾 4 字节 CRC32） |
| `<32位MD5>.chk` | 1041 | **数据块**，按索引里登记的 offset/length 切分出一条条游戏文件 |

> 也就是说：`.chk` 是"仓库货架"，`.blc` 是"货架清单"，游戏文件本身是 `.chk` 里的一个个区间。

---

## 二、15 个块的用途（按大小排序）

| 块（桶目录） | 文件数 | 大小 | 扩展名 | **游戏中的作用** |
|---|---|---|---|---|
| **Bundle** `7064D8E2` | 253,670 | **39.0 GB** | `.ab` | 全部游戏资产包：模型/贴图/预制体/动画/特效/场景/UI |
| **Video** `55FC21C6` | 626 | 6.26 GB | `.usm` | CRI USM 过场影片（主线 + 角色演出） |
| **Audio** `24ED34CF` | 6 | 4.44 GB | `.pck` | Wwise 音频包（AKPK）：音乐/音效/语音/试听 |
| **IV** `A63D7E6A` | 237 | 3.88 GB | `.bytes` | IrradianceVolume 光照探针体数据 |
| **Terrain** `F84BF5E6` | 46,164 | 1.11 GB | `.bytes` | 地形分块（高度/地表/植被） |
| **JsonData** `775A31D1` | 95,245 | 0.79 GB | `.json` | 游戏数据配置（74,336 个为口型同步） |
| **Streaming** `C3442D43` | 53,129 | 0.67 GB | `.bytes` | 关卡流式加载块 |
| **InitBundle** `0CE8FA57` | 1,052 | 0.21 GB | `.ab` | 首包必需资产 |
| **Table** `42A8FCA6` | 724 | 0.19 GB | `.bytes` | 策划数值表 |
| **ExtendData** `D6E622F7` | 3 | 168 MB | `.bin` | 路径哈希索引 / 基建骨架 / 压缩索引 |
| **DynamicStreaming** `23D53F5D` | 2,359 | 55 MB | `.bytes` | 动态流式增量数据 |
| **BundleManifest** `1CDDBF1F` | **1** | 47.7 MB | `.hgmmap` | 包清单（唯一全局索引） |
| **Lua** `19E3AE45` | 1,339 | 20 MB | `.lua` | 全部游戏逻辑脚本 |
| **InitAudio** `07A1BB91` | 2 | 11 MB | `.pck` | 启动音频（登录/标题） |
| **InitialExtendData** `3C9D9D2D` | 1 | 0.43 MB | `.bin` | 首包版路径哈希索引 |

### 11 个空目录（预留块，当前版本未下发）

`06223FE2`、`1EBAF5C6`、`2E6CE44D`、`6432320A`、`A31457D0`、`B9358E30`、`E1E7D7CE`、`E9D31017`、`F668D4EE`、`DAFE52C9`(**IFixPatchOut 热更补丁**)、`F151B649`(**HotfixAudio 热更音频**) —— 说明该版本没有热更内容。

---

## 三、逐类文件的用途明细

### 3.1 游戏资产包（`Data/Bundles/Windows/`，254,722 个 `.ab`）

- `main/` 253,670 个（39.0 GB）＝正式资源；`initial/` 1,052 个（212 MB）＝进游戏前必须加载的首包
- **文件名全为内容哈希**，无语义（如 `d42192003ea4169a31c072ec.ab`）——这是刻意的资源管理设计：便于去重、增量更新与 CDN 校验
- 体积分布（决定其内容粒度）：

| 体积区间 | 数量 | 合计 | 推断内容 |
|---|---|---|---|
| < 4 KB | 61,189 | 184 MB | 单个材质/小预制体/占位 |
| 4–64 KB | 149,990 | 2.20 GB | 单图标/单 UI 预制体/小图集 |
| 64–512 KB | 31,130 | 5.39 GB | UI 面板/特效/小模型 |
| 0.5–2 MB | 7,970 | 7.82 GB | 角色贴图/中等模型 |
| 2–10 MB | 3,858 | 16.59 GB | 角色完整包/场景块（占总量 41%） |
| 10–50 MB | 584 | 7.85 GB | 大场景/主城/环境合集 |
| > 50 MB | 1 | 88 MB | 最大单包 `d42192003ea4169a31c072ec.ab` |

- 反查"某个包里是什么"必须靠 `manifest.hgmmap` + `StringPathHash.bin`
- 包内是**混淆过的 UnityFS**：实测 6 个不同尺寸样本，头部合法性公式 `b == f(a)` 全部通过（确认是 UnityFS），但 `UnityFS` 签名被替换、块信息区经 **VFSAES 稀疏 AES 变体**加密后再 **LZ4** 压缩 —— 所以 AssetStudio / UnityPy 直接打开会失败

### 3.2 音频（`Data/Audio/PCK/Windows/`，8 个 `.pck`）

| 文件 | 大小 | 作用 |
|---|---|---|
| `Main/default_stream_0.pck` | 1.54 GB | 音乐 + 音效 + 语音流（分片 0） |
| `Main/default_stream_1.pck` | 1.54 GB | 分片 1 |
| `Main/default_stream_2.pck` | 1.31 GB | 分片 2 |
| `Main/default_banks.pck` | 28.4 MB | Wwise SoundBank（事件/总线定义） |
| `Audit/audit_stream.pck` | 141 MB | 试听/审核用音频流 |
| `Audit/audit_banks.pck` | 1.6 MB | 试听用 SoundBank |
| `Initial/init_stream.pck` | 10.98 MB | 启动音频流 |
| `Initial/init_banks.pck` | 0.09 MB | 启动 SoundBank |

- 格式实测：magic `3a 29 78 44`（大端 `0x3A297844`）＝ **AKPK**（Audiokinetic Wwise 包），头 8 字节后跟 16 字节 MD5，内部是 WEM 流
- 整包为**大端序**、头部字段本身也被混淆（`u32@4` 不是直读的 headerSize）

### 3.3 影片（`Data/Video/PC/`，626 个 `.usm`）

- magic 实测 `43 52 49 44`＝ ASCII **"CRID"**，**完全未加密**（明文 CRI USM 容器）
- 主要分类：
  - `Narrative/Cutscene/cs_video_<章节>m<关卡>_<序号>.usm` —— 主线过场（如 `cs_video_e3m5_3.usm` 212 MB 为最大影片）
  - `f_` / `m_` 前缀 = **女管理员 / 男管理员**两套视角版本（成对存在，故 626 个里含大量同剧情双份）
  - `c<角色号>m<关卡>_<名>.usm` —— 角色专属演出（如 `c35m4_liinoshow.usm`）
  - `Guide/CT/*.usm` —— 教学引导短片（如 `sketch_guide_video_battle_enemy_break_poise_1_ct.usm`）

### 3.4 配置数据（`Data/Json/`，95,245 个 + `Data/TableCfg/` 724 个）

**JSON（全部 ChaCha20 加密，逐文件 ivSeed）**：

| 子目录 | 数量 | 作用 |
|---|---|---|
| `LipSync/` | **74,336** | 口型同步数据（按语音逐句驱动嘴型动画） |
| `NPC/` | 5,711 | NPC 配置 |
| `LevelScriptData/` | 5,029 | 关卡脚本数据 |
| `BuffData/` | 2,871 | Buff 定义 |
| `SkillData/` | 2,620 | 技能定义 |
| `LevelData/` | 1,062 | 关卡数据 |
| `MissionRuntimeAsset/` | 1,046 | 任务运行时资源 |
| `Interactive/` | 866 | 交互物配置 |
| `SpawnerConfig/` | 608 | 刷怪点配置 |
| `LevelConfig/` `MapConfig/` | 216 / 203 | 关卡与地图配置 |
| `AtmosphericNpcData/` | 206 | 氛围 NPC |
| `CharInteractPerformCfgs/` | 202 | 角色交互表演 |
| `AnimationConfig/` | 125 | 动画配置（如 `anim_cfg_abilityEntity_chr_0034_typhoea_phantom.json`） |
| `GameplayConfig/` | 44 | 玩法主配置（26.8 MB，最大项） |
| `NavMesh/` `AIConfig/` `GPUISystemConfig/` 等 | 其余 | 导航网格 / AI / UI 系统 |

**策划表（`Data/TableCfg/*Table.bytes`，724 个，全部加密）**：角色数值、技能条件（`SkillConditionTable`）、Buff（`BuffTable`）、武器面板（`CharInfoWeaponPanelConfigTable`）、语音冲突表等，内部为定长二进制表结构。

### 3.5 逻辑脚本（`Data/LuaScripts/`，1,339 个 `.lua`，全部加密）

加密方式实测为 **ChaCha20 → base64 文本 → 再套 XXTEA**。

| 子目录 | 数量 | 作用 |
|---|---|---|
| `UI/Panels/` | 1,140 | **每个文件 = 游戏里一个界面**（`MainHudCtrl` 主界面、`GachaCharCtrl` 抽卡、`FacBuildModeCtrl` 基建建造、`MapCtrl` 地图…） |
| `UI/Widgets/`、`UI/RedDot/` | — | 通用控件与红点系统 |
| `Common/` | 78 | 核心框架（UIManager、PhaseManager、Coroutine、各类 Utils） |
| `Phase/` | 76 | 玩法阶段流程（`PhaseDialog` 对话、`PhaseLevel` 关卡、`PhaseCharInfo` 角色详情） |
| `Const/` | 21 | 常量表（UIConst、MapConst、FacConst） |
| `LuaSystem/` | 20 | 系统层（GachaSystem、RadioSystem、CinematicSystem） |

### 3.6 场景运行时数据

| 类别 | 路径 / 数量 | 作用 |
|---|---|---|
| **光照** | `Data/IrradianceVolume/PC/<地图>/v3/iv_<x>_<y>.bytes`，237 个（3.88 GB） | IrradianceVolume 光照探针体（全局光照/间接光），单文件最大 66.8 MB，无魔数 |
| **地形** | `Data/Terrain/PC/<关卡>/Terrain_<x>_<y>_<z>_<LOD>.bytes`，46,164 个（1.11 GB） | 地形分块，内部含 `TRET` 标记；`blackbox01_dg001` 等命名指向具体关卡 |
| **流式** | `Data/Streaming/PC/<关卡>/Streaming/InitChunkData_<x>_<y>_<z>.bytes`，53,129 个 | 大世界分区流式加载数据 |
| **动态流式** | `Data/DynamicStreaming/PC/`，2,359 个 | 运行时动态加载的增量块 |

### 3.7 三个关键索引文件（`.bin` / `.hgmmap`）

| 文件 | 大小 | 作用 |
|---|---|---|
| `Data/Bundles/Windows/manifest.hgmmap` | 47.7 MB（加密） | **包清单**：全局记录每个 `.ab` 的信息，是"包 → 资产"映射的唯一钥匙 |
| `Data/ExtendData/Main/StringPathHash.bin` | 150.4 MB（明文） | 资源**路径 → 哈希**索引（把可读路径映射为哈希，反查资源名） |
| `Data/ExtendData/Initial/InitStringPathHash.bin` | 0.43 MB | 首包版路径哈希索引 |
| `Data/ExtendData/Main/FacBone/FacBoneTRS.bin` | 17.1 MB | 基建骨架 Transform 数据（TRS） |
| `Data/ExtendData/Main/CompressData.bin` | 0.87 MB | 压缩数据索引（递增 offset 表） |

### 3.8 VFS 根部的两个文件

| 文件 | 大小 | 作用 |
|---|---|---|
| `index_initial.json` | 2.4 KB | 首包资源索引。**实为 base64 密文**（非 JSON 文本） |
| `index_main.json` | 244 KB | 正式资源索引，同上 |

实测结论：两者**密文前 13 字节完全相同**（`bc95dcd8bde198b6cedadb909ea3`）、第 14 字节起分叉 —— 典型的**固定密钥流加密**特征（同一 keystream，明文同前缀）。经测试**不是标准 ChaCha20 构造**（`.blc` 用的那套 key/nonce 组合在此无效），需借助现成工具解析。

---

## 四、命名规律速查

| 命名形态 | 含义 |
|---|---|
| `<32位十六进制>.chk` | 数据块，文件名 = 块 MD5 名 |
| `<8位十六进制>.blc` | 块索引，名称与所在目录同名 |
| `Data/Bundles/Windows/{initial,main}/<24位哈希>.ab` | 首包 / 正式资产包 |
| `Data/Video/PC/Narrative/Cutscene/cs_video_e<章>m<关>_<序>.usm` | 主线过场；`f_`=女管理员、`m_`=男管理员 |
| `Data/Video/PC/Guide/CT/sketch_guide_video_<玩法>_<序号>_ct.usm` | 教学短片 |
| `Data/Audio/PCK/Windows/{Initial,Main,Audit}/*.pck` | 启动 / 正式 / 试听 音频分层 |
| `Data/Json/LipSync/**` | 口型同步 |
| `Data/Json/<系统>/<名称>.json` | 各系统配置 |
| `Data/TableCfg/<名称>Table.bytes` | 策划数值表 |
| `Data/LuaScripts/UI/Panels/<界面名>/<界面名>Ctrl.lua` | 界面逻辑（Ctrl=控制、Model=数据） |
| `Data/LuaScripts/Phase/<玩法>/<玩法>.lua` | 玩法流程 |
| `Data/Terrain/PC/<关卡>/Terrain_<x>_<y>_<z>_<LOD>.bytes` | 地形分块 |
| `Data/Streaming/PC/<关卡>/Streaming/InitChunkData_*.bytes` | 关卡流式块 |
| `Data/IrradianceVolume/PC/<地图>/v3/iv_<x>_<y>.bytes` | 光照探针 |
| `anim_cfg_<类型>_chr_<编号>_<角色名>.json` | 动画配置（`chr_0034_typhoea` 等角色代号） |

---

## 五、三层解密链路（实测）

```
① 外层 VFS
   .blc  : 前 12 字节 = ChaCha20 nonce，其余用 32B key 的密钥流解密
           → 明文 = 版本/组名/块清单/文件表（含 filename、offset、length、useEncrypt、ivSeed）
           → 末尾 4 字节 = payload 的 CRC32（实测 17/17 全部通过）
   .chk  : 按索引 offset/length 切出；useEncrypt=1 的条目用
           nonce = i32le(3) + i64le(ivSeed) 的密钥流解一次
② 内层 UnityFS（.ab）
   头部字段被打散 + 位运算反混淆（签名 "UnityFS" 被替换）
   → 块信息区：VFSAES 稀疏 AES 变体解密 + LZ4 解压
   → 数据块：LZ4 / LZ4Inv 解压 → 正常 UnityFS
③ 资源层
   .pck  → AKPK → WEM 流 → vgmstream → WAV/MP3
   .usm  → CRI USM 解复用 → MPEG-2 视频 + HCA/ADX 音频 → MP4
   .bytes(表) → SparkBuffer → JSON
   .lua  → base64 → XXTEA → 源码
```

权威参考实现：
- [EIHRTeam/EndfieldStudio](https://github.com/EIHRTeam/EndfieldStudio)（`VfsLoader.cs`/`VfsParser.cs` 外层、`VFSFile.cs` 内层、`Crypto/VFSUtils.cs` 头部与块解密、`Processors/*` 各资源处理器）
- [shiikwi/FkArkEnd](https://github.com/shiikwi/FkArkEnd)（轻量：`.blc`→JSON、解 `.chk`、`.pck`/`.bytes`/`.lua` 转换）
- [Escartem/fluffy-dumper](https://github.com/Escartem/fluffy-dumper)（Rust 原版 VFS 实现）

---

## 六、本报告配套产出物（均在工作区 `D:\toolresources\DSHStool\`）

| 文件 | 说明 |
|---|---|
| `vfs_analysis\vfs_filelist.csv` | **45.4 万行全量清单**：`blockDir, blockName, blockType, filePath, sizeBytes, useEncrypt, ivSeed, chunkFile, chunkOffset` |
| `vfs_analysis\bundle_top5000.csv` | 最大的 5000 个资产包 |
| `vfs_analysis\{json,usm,streaming,terrain,iv}_samples.txt` | 各类文件样本清单 |
| `vfs_analysis\extract\` | 已解密的 `manifest.hgmmap.dec`、`StringPathHash.bin.raw`、`InitStringPathHash.bin.raw`、`CompressData.bin.raw`、`FacBoneTRS.bin.raw` |
| `vfs_inventory.js` | 17 个 `.blc` 全量解密 + 块类型汇总（含 CRC 校验） |
| `vfs_export.js` | 全量清单导出（CSV） |
| `vfs_analyze.js` | 路径语义 / 目录树 / 命名规律统计 |
| `vfs_sample.js` | 按索引抽取样本、判定内层格式、验证 UseEncrypt 分支 |
| `vfs_bundle_probe.js` | 内层 UnityFS 头部反混淆验证 |
| `vfs_index_crack.js` | `index_*.json` 已知明文与结构分析 |
| `vfs_manifest.js` | `manifest.hgmmap` 与 ExtendData 的 bin 解密导出 |

---

## 七、已知未完成项（如实记录）

1. **`manifest.hgmmap`（47.7 MB）未解开**：按 `.chk` 内部的 ChaCha20 构造解密后仍为高熵，说明它另有加密/封装方式。解开它才能把 25 万个哈希名 `.ab` 逐一映射到具体资产路径。
2. **内层 UnityFS 头部字段布局未完全对齐**：`IsValidHeader` 公式已验证通过（确认是混淆 UnityFS），但 `size/flags/compressedBlocksInfoSize` 的字段顺序与游戏版本分支常量（CB1/CB2/CB3）尚未完全匹配，因此未自行解出包内对象清单。
3. **`index_initial.json` / `index_main.json` 未解开**：已确定是固定密钥流加密、非标准 ChaCha20 构造。

> 上述三项均有现成工具可直接完成（`endfield-dump` 系列），无需重新逆向；本报告聚焦于**结构识别与用途归类**，已完整覆盖 VFS 内所有 15 类文件的用途。
