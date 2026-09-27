# 压缩字典的最小访问完美哈希（MPHF）+ 变长内容归档

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，通过槽位中保存的完整键做非成员终检，
并为每个键保存一份**变长二进制内容**（允许空内容）；整张表可序列化为
自校验字节流/文件，重新加载后键的槽位与查询结果与保存前完全一致。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `dataclasses`、`math`、`typing`、`unittest`）。
- 安装 Python 后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 准确命令

```bash
# 必要测试（58 个用例）
python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.1 秒，远低于 8 秒预算；无 sleep、无预录）
python demo.py
```

## 公开接口

导入：

```python
import mphf
table = mphf.build([b"alpha", b"beta", b"gamma"])
mphf.lookup(table, b"beta")      # -> 1
mphf.lookup(table, b"absent")    # -> mphf.NOT_FOUND (-1)
table.lookup(b"alpha")           # 实例方法，等价
table.get(b"absent", default=None)

# 键 -> 变长内容（空内容与不存在严格区分）
table = mphf.build([b"a", b"b"], [b"content-a", b""])
mphf.fetch(table, b"a")          # -> b"content-a"
mphf.fetch(table, b"b")          # -> b""   （空内容，真实命中）
mphf.fetch(table, b"x")          # -> -1   （NOT_FOUND，不存在）
table.get_content(b"x")          # -> None （默认哨兵，三态清晰）

# 保存 / 重新加载（原子写文件；加载做边界与 SHA256 校验）
blob = mphf.dumps(table)          # bytes
t2 = mphf.loads(blob)             # 与 table 逐字段相等
mphf.save(table, "index.mphf")
t3 = mphf.load("index.mphf")
```

### `build(keys, contents=None) -> MPHFTable | CONSTRUCTION_FAILED`

- `keys`：键的**可迭代对象**（list、tuple、生成器等；单个 `bytes` 不被当作
  集合，会抛 `TypeError`）。
- 每个键必须是 bytes-like（`bytes` / `bytearray` / `memoryview`），内容为
  ASCII（每字节 `< 0x80`），允许空字节串 `b""`。
- 空可迭代对象产生空表：`size == 0`，对其任意 `lookup` 一律返回
  `NOT_FOUND`。
- 返回不可变的 `MPHFTable`；全部 256 个 seed 都失败时返回哨兵
  `mphf.CONSTRUCTION_FAILED`（含义见“错误语义”）。
- `contents`：可选、与 `keys` 等长等序的 bytes-like 可迭代对象，作为每个
  键的变长内容；内容可以是任意字节（含 NUL、非 ASCII），允许空字节串
  `b""`。省略时内容全部为 `b""`。长度不一致抛 `ValueError`，元素不是
  bytes-like（含 `bool`）或传入单个 bytes 抛 `TypeError`。

`MPHFTable` 字段（frozen dataclass）：

| 字段 | 含义 |
|---|---|
| `size` | 键数量 `n` |
| `vertex_count` | 超图顶点数 `m = ceil(1.4·n)`，空表为 0 |
| `seed` | 成功使用的 seed，范围 `0..255`（空表为 0） |
| `values` | 每个顶点的赋值 `g`，`0..n-1` 的元组，长度 `m` |
| `keys` | 槽位内容，`keys[i]` 即构造序号为 `i` 的原始键，长度 `n` |
| `attempts` | 成功前尝试的 seed 个数（成功 seed 在内，≥1；空表为 0） |
| `contents` | 与槽位平行的变长内容，`contents[i]` 即 `keys[i]` 的内容，长度 `n`；空表为 `()` |

### `lookup(table, key) -> int`

- 成员：返回其构造序号 `i ∈ 0..n-1`。
- 非成员（含非 ASCII 字节串、空表上的任何查询）：返回 `NOT_FOUND`（`-1`）。
- 命中判定以槽位保存的**完整键逐字节比较**为准：哈希只负责选出槽位，
  **绝不**以“哈希值存在/算出了某个槽位”判定命中。非成员即使哈希恰好
  落到已占用槽位也返回 `NOT_FOUND`。

### `fetch(table, key) -> bytes | NOT_FOUND`

- 成员：返回该键的内容 `bytes`，长度任意，允许为空字节串 `b""`；
- 非成员：返回 `NOT_FOUND`（`-1`，一个 `int`，不可能与任何 `bytes`
  混淆），因此**空内容与不存在是两种可区分的结果**；
- 另有 `table.get_content(key, default=None)`：命中返回内容，非成员返回
  `default`（默认 `None`），有内容/空内容/不存在三态清晰可分。

### `dumps/loads/save/load`：归档与重新加载

`dumps(table) -> bytes` 把整张表序列化为自校验字节流；`loads(data)` 重建，
结果与原表逐字段相等（frozen dataclass 相等），所有键的槽位与
`lookup/fetch` 结果保存前后一致。`save(table, path)` / `load(path)` 是文件
接口：`save` 先写同目录唯一临时文件、`fsync` 后原子 `os.replace`，任何
失败都不留半成品或临时文件。

归档为**公开二进制格式**（多字节整数均为无符号大端）：

```
magic(8)=b"MPHF0001" | n uint32 | m uint32 | seed uint8 | attempts uint32
| n 个 uint32 顶点赋值 g
| n 条记录，每条 = klen uint32 | key 字节 | clen uint32 | content 字节
| 对上述全部字节的 SHA256（32 字节）
```

加载时的校验顺序与保证：

- 先查魔数与最小长度；末尾 32 字节是对前面全部字节的 SHA256，任何字节
  翻转/截断都在解析前被拒绝（`ArchiveFormatError`）；
- `n/m` 必须满足 `m = ceil(1.4n)`、`n ≤ 1000`；每个 `g` 必须 `< n`；
- 每条记录的 `klen/clen` **先与剩余字节数比较再切片**：伪造的巨大长度或
  错位长度（即使重算了合法校验和）只会产生 `ArchiveFormatError`，
  **绝不越界读取，也读不到相邻记录或其他键的内容**；
- 键必须为 ASCII、槽位间不得重复；记录之后不得有多余字节；
- 最后重新独立验证全部成员槽位仍是 `0..n-1` 的双射，才返回表对象。

### 哈希线格式（公开契约）

```
h_t(key) = int(SHA256( seed_be4 ‖ tag ‖ key ), big-endian) mod m
```

- `seed_be4`：seed 的 **4 字节大端**编码；
- `tag`：单字节域标签，三次哈希分别为 `0x00 / 0x01 / 0x02`；
- `m = (14·n + 9) // 10 = ceil(1.4·n)`，**整数精确计算**。

## 算法与设计取舍

1. **三哈希超图（3-uniform hypergraph）剥离**：每个键是一条连接
   `h0,h1,h2` 三个顶点的超边，顶点数 `m=⌈1.4n⌉`。反复删除度为 1 的
   顶点及其唯一邻边（剥离顺序及见证顶点完全确定）；若全部边被剥除，
   超图为无环超图。
2. **逆序赋值**：按剥离顺序逆序处理边。对边 `e`（其键序号即边的目标值
   `i`）要求 `g[h0]+g[h1]+g[h2] ≡ i (mod n)`；见证顶点当时只属于该边、
   必未赋值，解一个一元线性同余方程即可（边上若另有自由顶点则固定为 0；
   见证顶点在三元组中重复出现时系数 `c=1..3`，用 `gcd(c,n)` 判定可解）。
   由此保证成员槽位恰为 `0..n-1` 的一个排列——既是完美哈希又是最小哈希。
3. **确定性 seed 重试**：剥离失败（2-核非空）或同余无解时，seed 从 0 起
   递增，最多尝试 256 个；同一输入构造结果逐位确定（可复现）。
4. **完整键终检**：`MPHFTable.keys` 保存全部原始键，`lookup` 比较
   `keys[slot] == key`。这是以空间换取零误报的标准压缩字典做法；本模块
   不提供“只凭哈希即命中”的模式。
5. **无浮点**：`1.4n` 以有理数 `14/10` 的整数向上取整实现，全模块没有
   浮点运算，因此不存在浮点误差口径问题。
6. **失败即无副作用**：构造是纯函数，校验先于构造；输入非法时在收集阶段
   抛错，不产生部分结果；seed 重试中的中间结构不逃逸；`MPHFTable`
   不可变（frozen）。

## 错误语义

| 情况 | 行为 |
|---|---|
| 重复键 | 抛 `mphf.DuplicateKeyError`（`ValueError` 子类），消息带重复位置 `index` 和键值 |
| 键含非 ASCII 字节 | `ValueError`，消息形如 `keys[i]: non-ASCII byte ...` |
| 键数 > 1000 | `ValueError`（在第 1001 个元素处报错） |
| 键/容器类型错误 | `TypeError`（含把 `str`、`int`、`None`、单 `bytes` 等传入） |
| `bool` | `bool` 虽是 `int` 子类，在键位上一律按 `TypeError` 拒绝，不静默当作 `1/0` |
| 256 个 seed 全部失败 | **返回** `CONSTRUCTION_FAILED`（不抛异常） |
| 对 `CONSTRUCTION_FAILED` 调用 `lookup` | `ValueError` |
| 对非 `MPHFTable` 对象 `lookup` | `TypeError` |
| `contents` 与 `keys` 长度不一致 | `ValueError` |
| `contents` 元素不是 bytes-like（含 `bool`），或把单个 bytes 当内容集合 | `TypeError` |
| 归档截断/魔数错误/校验和不匹配/字段越界/长度越界/记录错位 | `mphf.ArchiveFormatError`（`ValueError` 子类） |
| `loads` 输入不是 bytes-like，或 `dumps` 的不是 `MPHFTable` | `TypeError` |
| `load` 指向不存在的文件 | 标准 `FileNotFoundError`（`OSError`） |

**搜索预算耗尽 ≠ 证明无解**：`CONSTRUCTION_FAILED` 只表示“seed 0..255
在本算法（固定 `m=1.4n`、三哈希、SHA256 线格式）下均未成功”，是**预算
边界**；不代表该键集在数学上不存在完美哈希。本契约不回退到其他算法。
在 n≤1000、m=1.4n 的自然 ASCII 输入下该结果极难触发（构造期随机化检查中
未观察到）；测试通过“真实不可剥离集合 + 把预算压为 1”端到端触发该分支。
本库没有数值型入参，故不存在 NaN/Infinity 输入面；若将来扩展数值参数，
将按同一总则拒绝 NaN/Infinity，并拒绝把 `bool` 当整数。

## 输入上限

- 键数量：`0..1000`（0 合法，表示空集合）。
- 单键长度：题面未设限，仅受可用内存约束；键为任意 ASCII 字节序列。
- 顶点/赋值表大小：`m = ceil(1.4n) ≤ 1400`；另保存 n 个原始键。
- seed：`0..255`，共 256 次尝试。

## 已知限制

- 仅实现本题契约的有限数学子集：固定 3 哈希、固定负载系数 1.4、固定
  SHA256 线格式；**不宣称**与任何行业 MPHF/PHF 标准或互操作格式兼容。
- 静态结构：不支持构造后增删键；变更集合需重新 `build`。
- 归档为本题自定义的有限格式（魔数 `MPHF0001`），**不宣称**与任何行业
  字典/键值归档格式兼容；版本号保留在魔数中。
- 内容只要求是字节串，本模块不解释其编码；键仍限定 ASCII（题面契约）。
- 归档以 SHA256 检出偶然/恶意损坏，但不是加密，不提供机密性或信任锚。
- 非成员判定需要完整键存储（每键一份），属于刻意的设计取舍，不做只存
  指纹的近似模式（那会引入误报率口径）。
- `CONSTRUCTION_FAILED` 时不自动扩大顶点表、不更换哈希族；严格遵守
  题面给定参数与 256 次预算。
- 面向正确性与确定性而非极限吞吐：n=1000 实测构造约 10 ms 量级、
  千次查询约 4 ms（本机数字，仅作量级参考，非性能保证）。

## 测试如何独立于被测核心

`tests/test_mphf.py` 在测试侧按题面线格式**独立**用 `hashlib` 计算哈希
向量和槽位，用它校验双射（槽位为 `0..n-1` 的排列）与赋值方程
（三顶点值之和模 n 等于键序号），不调用被测核心来产生期望值；
build→lookup 的往返一致仅作为补充断言。覆盖：n=1..60 与多个键族的枚举
双射、n=1000 边界、空表、真实 seed-0 不可剥离集合 `{a,b,i}`（seed=2
重试成功）、预算压为 1 时实际触发 `construction_failed`、非成员哈希碰撞
拒绝、非 ASCII、重复键、类型/上限错误、确定性复现、128 个单字节 ASCII
键全集。`tests/test_archive.py` 覆盖：变长内容与“有内容/空内容/不存在”
三态、n=1/3/20/1000 的内存与文件往返一致性（重载后槽位与内容逐字段相等）、
非成员重载后仍 `NOT_FOUND`、截断/魔数/逐字节翻转的校验和拒绝，以及
**重算合法校验和后**伪造巨大 `klen/clen`、长度错位、`n/m` 不一致、
`g` 越界、尾随字节、非 ASCII 键等边界——全部只能得到 `ArchiveFormatError`。

## 仓库布局

```
mphf/__init__.py     # build/lookup/fetch/dumps/loads/save/load 等
tests/test_mphf.py   # 哈希/构造测试（独立参考期望值）
tests/test_archive.py# 内容、往返与归档损坏/越界测试
demo.py              # 固定输入演示：索引+内容+重试+存取重载+拒绝边界
requirements.txt   # 无第三方依赖（说明性注释）
```
