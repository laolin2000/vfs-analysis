# 《明日方舟：终末地》VFS 音频提取方案（含初步可行性验证）

- 目标对象：`Endfield_Data\StreamingAssets\VFS`
- 方案性质：**设计 + 可行性验证**（本轮未做批量转写，仅导出 10 条样本用于验证解码链路）
- 已验证深度：从 `.blc` 索引 → `.chk` 切片 → AKPK 头解密 → 条目表 → WEM 解密 → vgmstream 解码，**全链路 10/10 成功**

---

## 一、音频资产盘点（实测）

### 1.1 载体分布

| 来源 | 数量 | 大小 | 说明 |
|---|---|---|---|
| `Audio` 块 + `InitAudio` 块内的 `.pck` | **8 个** | **4.45 GB** | 主音频载体（AKPK/Wwise） |
| `Video` 块内 `.usm` 影片的内嵌音轨 | 626 个 | 6.11 GB | 过场影片音轨（HCA/ADX，需解复用） |
| `Table` 块内音频映射表 | 4 个 | 7.1 MB | 音频 ID → 语义名映射（命名关键） |
| `JsonData` 块内口型数据 | 74,336 个 | 0.67 GB | 语音对应的口型同步（可关联语音文件） |

### 1.2 八个 `.pck` 明细（已解密头部并解析条目表）

| 文件 | 大小 | banks 条目 | sounds 条目 | 采样格式 | 定位 |
|---|---|---|---|---|---|
| `Main/default_stream_0.pck` | 1535.7 MB | 0 | **34,395** | Vorbis | 主音频流分片 0 |
| `Main/default_stream_1.pck` | 1535.6 MB | 0 | **11,637** | Vorbis | 主音频流分片 1 |
| `Main/default_stream_2.pck` | 1308.4 MB | 0 | **10,230** | Vorbis + 0x3041 | 主音频流分片 2 |
| `Main/default_banks.pck` | 28.4 MB | **19,141** | 0 | — | SoundBank（事件/总线/HIRC） |
| `Audit/audit_stream.pck` | 140.9 MB | 1 | **1,634** | Vorbis | 试听音频流 |
| `Audit/audit_banks.pck` | 1.6 MB | **418** | 0 | — | 试听 SoundBank |
| `Initial/init_stream.pck` | 11.0 MB | 0 | **56** | Opus + 0x3041 | 启动音频流 |
| `Initial/init_banks.pck` | 0.1 MB | **40** | 0 | — | 启动 SoundBank |
| **合计** | **4.45 GB** | **19,599** | **57,952** | | |

> **5.8 万个可导出音频条目 + 1.96 万个 BNK 内条目**（BNK 内的 WEM 需解析 DIDX/DATA 子段后才能定位）。

### 1.3 编码格式（vgmstream 实测）

| 格式 | 出现位置 | vgmstream 识别 |
|---|---|---|
| Wwise Vorbis（`fmt=0xFFFF`） | 主音频流主力 | `Custom Vorbis` ✔ |
| **Opus** | `init_stream.pck` | `libopus Opus` ✔ |
| `fmt=0x3041` | 主/启动流部分条目 | vgmstream 可解（exit=0，已出 WAV）|
| 采样率/声道 | 全部实测 | 48 kHz，单声道（语音）或立体声（音乐/音效）|

### 1.4 体积换算（基于实测膨胀比）

实测 WEM → WAV 膨胀约 **9.5–11 倍**（如 10.6 MB → 110.6 MB）：

| 输出形态 | 预计体积 | 说明 |
|---|---|---|
| 原始 WEM（提取不解码） | **≈ 4.4 GB** | 仅解密切片，最快（预估 2–4 分钟） |
| WAV（PCM 16-bit 48 kHz） | **≈ 42–48 GB** | 无损，占盘大（D 盘余 140 GB，可容纳） |
| MP3 192 kbps | **≈ 5.5–7 GB** | 推荐默认（需 ffmpeg，当前**未安装**） |

---

## 二、解密链路（全部实测确认）

```
① VFS 外层（ChaCha20，RFC 8439）
   .blc 索引 : 前 12 字节 = nonce，其余用 32B key 解密 → 明文含文件表（名/偏移/长度/加密标志/ivSeed）
              末尾 4 字节 = CRC32（17/17 通过）
   .chk 数据 : 按索引 offset/length 切片

② AKPK 容器（自研 XOR 流密码）
   头部      : magic ": ) x D" → headerSize = LE u32@4（明文，同时是解密种子）
               对 [12, headerSize) 做 XOR 解密，密钥流从 deriveKey(headerSize) 起 → 得到 "AKPK"
               → 段表: languages / banks / sounds / externals（各段先 4 字节条目数）
   条目(20B) : id(u32) | blockSize(u32) | size(u32) | offset(u32) | langId(u32)
               （offset 若 blockSize≠0 则乘以 blockSize）
   载荷解密  : 对 WEM 数据做 4 字节 LE 整体 XOR，**密钥流起点 = 条目 id**
               即 keyIndex = id + (已处理字节数 / 4)，key = deriveKey(keyIndex)
               deriveKey(seed) = 4 轮 wrapping_mul(81861667) + 逐字节混入，初值 XOR 0x9C5A0B29
   banks 段  : BNK 数据同样 XOR 解密（seed = 该条目 id）→ 解析 BKHd/DIDX/DATA 定位内部 WEM

③ 解码
   WEM → vgmstream-cli → WAV      （已验证）
   WEM → vgmstream → ffmpeg → MP3（需安装 ffmpeg）
```

### 关键验证结果（可复现）

| 验证项 | 方法 | 结果 |
|---|---|---|
| AKPK 头解密 | 6 个包逐一解密取 `AKPK` | **6/6 成功**，段表字段全部合理 |
| WEM 载荷判定 | 4 字节对齐全包扫 `RIFF` | 0 命中 → 确认载荷**整体加密**（无明文 WEM） |
| 密钥公式 | 5 个条目做 keystream 反解 + 数值比对 | `dk(id)` **5/5 命中**；`dk(id+off/4)` **0/5** |
| 端到端解码 | 10 条样本（含 10.3 MB 大条目） | **10/10 解出 WAV**（vgmstream exit=0） |
| 全量条目表 | 8 个包解析 | 57,952 个 sounds 条目 + 19,599 个 banks 条目 |

---

## 三、推荐执行方案（分阶段，可中断可校验）

### 阶段 0：环境准备（约 5 分钟）
- 确认 `vgmstream-cli.exe`（已有：`arknights-audio` 技能目录）
- 安装 `ffmpeg`（MP3 输出需要；当前**缺失**）→ `winget install ffmpeg` 或下载静态包
- 预估磁盘：WEM 模式 4.4 GB / MP3 模式 ~6 GB / WAV 模式 ~45 GB
- 建议输出目录：`D:\EndfieldAudio\`（与工作区分离，避免污染）

### 阶段 1：WEM 提取（推荐先做，风险最低）
1. 解 `.blc` 索引取 8 个 `.pck` 的位置
2. 逐包：解密头部 → 解析段表 → 遍历条目 → 逐条解密写出 `.wem`
3. 产出：`wem/<包名>/<id>.wem` + 一份 `manifest.csv`（id、包、偏移、大小、语言、格式、时长）
4. 预期：**57,952 个 WEM ≈ 4.4 GB，预计 3–8 分钟**（本机 SSD 实测 10.6 MB 条目提取约 0.2 s）
5. 校验：随机抽 50 条用 vgmstream `-m` 验证可解析

### 阶段 2：语义命名映射（决定"哪条是什么"）
1. **解密 `Data/TableCfg/AudioDialog.bytes`**（4.62 MB，ChaCha20，seed=ivSeed）
   → SparkBuffer 二进制表 → JSON，得到 `音频ID ↔ 语义名/台词` 映射
2. 辅以 `AudioDialogChannel.bytes`、`AudioVoiceExtraData.bytes`、`AudioCueTable.bytes`
3. 关联 `Data/Json/LipSync/<Chinese|English|Japanese|Korean>/au_voice_*.json`（74,336 个）
   → 把语音 ID 映射到 `au_voice_c33m2_3_001_f` 这类可读名 + 语言 + 角色 + 剧情位置
4. 产出：`audio_index.csv`（id → 语义名 → 语言 → 角色/关卡 → 时长 → 输出路径）
5. **未映射的条目**（WEM id 不在表内）回退为 `unmapped/<包名>/<id>.wem`

### 阶段 3：格式输出（二选一或都做）
- **WAV**：`vgmstream -o <out>.wav <in>.wem`（无损，占盘 45 GB）
- **MP3**：`vgmstream -o - <in>.wem | ffmpeg -i - -c:a libmp3lame -b:a 192k <out>.mp3`（管道，无中间 WAV）

### 阶段 4：BNK 内音频（可选，覆盖更全）
- 对 19,599 个 banks 条目：XOR 解密 BNK(seed=id) → 解析 `BKHd`/`DIDX`/`DATA`
- 提取 DIDX 表中每个 WEM（offset + DATA 段起点）
- 价值：包含 `default_banks.pck` 里 19,141 个条目对应的音效资源

### 阶段 5：影片音轨（可选，独立子任务）
- 626 个 `.usm`（明文 CRI 容器）→ 解复用出 MPEG-2 视频 + HCA/ADX 音频
- 需要 USM demuxer（EndfieldStudio 有 C# 实现）或 ffmpeg（若支持 CRI USM）

### 阶段 6：校验与报告
- 计数对账：`.pck` 条目数 vs 实际输出文件数
- 抽检：按清单每组随机 20 条，vgmstream 解析 + 时长合理性
- 产出：`audio_extract_report.md`（成功率、失败清单、格式分布、总时长）

---

## 四、风险与依赖清单

| 项 | 状态 | 影响 | 对策 |
|---|---|---|---|
| AKPK 头/WEM 解密 | ✅ **已验证** | 无 | 公式已确认，可直接实现 |
| WEM → 解码 | ✅ **已验证**（10/10） | 无 | vgmstream 已就绪 |
| `AudioDialog.bytes` 映射表解密 | ⚠️ 未验证 | 影响语义命名（不影响提取） | 属 Table 块，加密方式与 JSON 相同，可解；失败则退回 id 命名 |
| BNK 内 DIDX 解析 | ⚠️ 未验证 | 影响 19,599 个 bank 条目 | 有权威实现（`AkpkPackage.ParseBnk`），照做即可 |
| `fmt=0x3041` 条目 | ⚠️ 部分未知 | 少量条目 | vgmstream 实测可解（已出 WAV），暂不需处理 |
| ffmpeg MP3 | ❌ **未安装** | 无法输出 MP3 | `winget install ffmpeg` 或用 WAV 模式 |
| 磁盘空间 | ✅ 充足（D 盘 140 GB） | WAV 模式约 45 GB | 选 WEM/MP3 模式更省 |
| 时长估算准确性 | ⚠️ 不可靠 | 仅参考 | 我的码率估算在 `stream_1` 上得 190,258 分钟（异常），**实际时长需提取后按真实码率统计** |
| 语言/配音覆盖 | ⚠️ 未知 | 本次 8 个包 languages 段只列出 `sfx` | 中/英/日/韩配音可能在其它未下载块或后续版本中，需提取后确认 |

---

## 五、验证产出物（工作区 `D:\toolresources\DSHStool\`）

| 文件 | 说明 |
|---|---|
| `audio_verify_final.js` | **端到端验证脚本**（索引→切片→解密→WEM→vgmstream），10/10 通过 |
| `audio_key_reverse.js` / `audio_key_numeric.js` | 密钥公式反解与数值核对（确立"种子=条目 id"） |
| `audio_probe_pck.js` | AKPK 头部/段表协议探针（只读 4KB） |
| `audio_probe_fields.js` | 20 字节条目字段划分定位 |
| `audio_scan_riff.js` | 全包 RIFF 扫描（证明载荷整体加密） |
| `audio_inventory.js` | **全量音频清单统计**（8 个包、57,952 条目） |
| `audio_extract_sample.js` | 早期抽样脚本（含已修正的头部解密实现） |
| `vfs_analysis/audio_probe_out/` | 10 个验证用 WEM 及其 WAV 解码结果 |

---

## 六、结论与建议

**可行性：已验证可行，无阻断性风险。**

- 解密与解码链路 100% 打通（头 + 载荷 + vgmstream 三步全通）
- 规模明确：**57,952 个可导出音频条目 / 4.45 GB 压缩**（另 19,599 个 BNK 内条目）
- 主要待补：语义命名（`AudioDialog.bytes`）、MP3 输出（装 ffmpeg）、BNK 内条目（照权威实现）

**建议执行顺序**：阶段 1（WEM 提取，3–8 分钟，先拿到 4.4 GB 原始音频）→ 阶段 2（命名映射，把 `<id>.wem` 变成可读文件名）→ 阶段 3（按需转 WAV/MP3）。

**下一步需要你确认两点**：① 输出去向（建议 `D:\EndfieldAudio\`）；② 输出形态（WEM 原样 / MP3 省盘 / WAV 无损）。
