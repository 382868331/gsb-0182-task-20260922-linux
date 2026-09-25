# 压缩字典的最小访问完美哈希（MPHF）

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

在此基础上还提供**自带值的只读快照**：`build_kv` 把键值对（值为 bytes，
每项最多 4096 字节）随索引一起序列化为**单个确定性二进制文件**，发布时
无需另外配置值文件；`KvSnapshot.load` 只做字节解析与全面校验即可查询，
载入后不依赖源文件，适合离线发布小型只读字典。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库，也不使用 pickle 等对象反序列化。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `struct`、`dataclasses`、`math`、`typing`、`collections.abc`、
  `unittest`）。
- 本环境 Python 命令统一使用隔离环境中的 **`./.venv/bin/python`**；
  安装后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 准确命令

```bash
# 全部必要测试（原 mphf 31 个 + 键值快照 41 个，共 72 个用例）
./.venv/bin/python -m unittest discover -s tests -v

# 固定输入演示：MPHF 索引 + 重试 + 拒绝/异常边界（约 0.1 秒）
./.venv/bin/python demo.py

# 键值快照演示：父进程保存单文件快照，另一个进程重新加载并查询
# （实测约 0.2 秒，远低于 90 秒预算；无 sleep、无预录）
./.venv/bin/python demo_kv.py
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
```

### `build(keys) -> MPHFTable | CONSTRUCTION_FAILED`

- `keys`：键的**可迭代对象**（list、tuple、生成器等；单个 `bytes` 不被当作
  集合，会抛 `TypeError`）。
- 每个键必须是 bytes-like（`bytes` / `bytearray` / `memoryview`），内容为
  ASCII（每字节 `< 0x80`），允许空字节串 `b""`。
- 空可迭代对象产生空表：`size == 0`，对其任意 `lookup` 一律返回
  `NOT_FOUND`。
- 返回不可变的 `MPHFTable`；全部 256 个 seed 都失败时返回哨兵
  `mphf.CONSTRUCTION_FAILED`（含义见“错误语义”）。

`MPHFTable` 字段（frozen dataclass）：

| 字段 | 含义 |
|---|---|
| `size` | 键数量 `n` |
| `vertex_count` | 超图顶点数 `m = ceil(1.4·n)`，空表为 0 |
| `seed` | 成功使用的 seed，范围 `0..255`（空表为 0） |
| `values` | 每个顶点的赋值 `g`，`0..n-1` 的元组，长度 `m` |
| `keys` | 槽位内容，`keys[i]` 即构造序号为 `i` 的原始键，长度 `n` |
| `attempts` | 成功前尝试的 seed 个数（成功 seed 在内，≥1；空表为 0） |

### `lookup(table, key) -> int`

- 成员：返回其构造序号 `i ∈ 0..n-1`。
- 非成员（含非 ASCII 字节串、空表上的任何查询）：返回 `NOT_FOUND`（`-1`）。
- 命中判定以槽位保存的**完整键逐字节比较**为准：哈希只负责选出槽位，
  **绝不**以“哈希值存在/算出了某个槽位”判定命中。非成员即使哈希恰好
  落到已占用槽位也返回 `NOT_FOUND`。

### 哈希线格式（公开契约）

```
h_t(key) = int(SHA256( seed_be4 ‖ tag ‖ key ), big-endian) mod m
```

- `seed_be4`：seed 的 **4 字节大端**编码；
- `tag`：单字节域标签，三次哈希分别为 `0x00 / 0x01 / 0x02`；
- `m = (14·n + 9) // 10 = ceil(1.4·n)`，**整数精确计算**。

## 自带值的只读快照（v1）

在同一套完美哈希之上提供键值构建、查询与可持久化的只读快照，发布物为
**单个文件**，值随索引一起携带。

### 接口

```python
import mphf

# 构建：可传无序的 (key, value) 对（list/tuple/生成器），也可直接传 dict
snap = mphf.build_kv([(b"beta", b"B"), (b"alpha", b""), (b"gamma", b"G")])
snap = mphf.build_kv({b"beta": b"B", b"alpha": b""})   # dict 同样可以
hit, value = mphf.find_kv(snap, b"alpha")   # -> (True, b"")  空值是有效命中
mphf.find_kv(snap, b"absent")               # -> (False, None) 未命中另有标志
snap.find(b"beta")                          # 实例方法，等价
snap.get(b"absent", default=b"<none>")
b"alpha" in snap                            # -> True；len(snap) 为键数量

# 持久化与载入
data: bytes = snap.to_bytes()               # 确定性字节
snap.save("dictionary.mphkv")               # 原子写（先写 .tmp 再 rename）
loaded = mphf.KvSnapshot.load("dictionary.mphkv")
loaded = mphf.KvSnapshot.from_bytes(data)   # 也可直接从字节载入
```

- **键**：与 `build` 完全相同的规则——bytes-like、ASCII（每字节 `< 0x80`）、
  允许空键、数量 `0..1000`、重复键抛 `DuplicateKeyError`（**不悄悄覆盖**）。
- **值**：必须是 bytes-like（`bytes`/`bytearray`/`memoryview`），每项
  **至多 4096 字节**；**空值 `b""` 是有效命中**。命中与否由独立布尔标志
  报告，调用方不需要、也不应用“值是否为空”猜测命中。
- **顺序确定性**：构建前按键的**字节序**升序固定顺序，因此同一键值集合
  无论传入顺序如何（含 dict 与各种 bytes-like），快照字节**逐位相同**。
  槽位 `i` 同时存放排序后第 `i` 个键及其值。
- **查询路径**：与 `lookup` 相同——先用完美哈希
  `(g[h0]+g[h1]+g[h2]) mod n` 定位槽位，再与该槽位保存的**完整原键**
  逐字节核对，**不做整表字典查找**；非 ASCII 查询按未命中处理。
- **失败语义**：256 个 seed 全部失败时 `build_kv` 同样**返回**
  `CONSTRUCTION_FAILED`（不抛异常），对其 `find_kv` 抛 `ValueError`；
  1000 键上限与原 `build` 一致。
- **只读**：快照构造后不可变（frozen dataclass），不支持动态增删、
  后台合并或任何数据库行为；变更集合需重新构建。

### 快照字节布局（格式版本 1，大端）

整个文件 = **65 字节定长头部** + **体（body）**，无任何填充。

头部（共 65 字节）：

| 偏移 | 长度 | 字段 | 编码 | 说明 |
|---|---|---|---|---|
| 0 | 7 | `magic` | `7s` | 固定 ASCII `MPHKVDB` |
| 7 | 2 | `version` | `H` | 格式版本，当前为 `1` |
| 9 | 4 | `n` | `I` | 键数量，`0..1000` |
| 13 | 4 | `m` | `I` | 顶点数，必须等于 `(14·n+9)//10` |
| 17 | 4 | `seed` | `I` | 成功 seed（n>0 时 `0..255`；空表为 0） |
| 21 | 4 | `attempts` | `I` | 尝试 seed 数；n>0 时必须等于 `seed+1`，空表为 0 |
| 25 | 8 | `body_len` | `Q` | 体长度（字节），文件长度必须恰为 `65 + body_len` |
| 33 | 32 | `body_sha256` | `32s` | 体的 SHA256（只覆盖体，不含头部） |

体依次为：

1. **顶点赋值表 g**：`m` 个连续的 `I`（大端 uint32），每个值必须在
   `0..n-1`，共 `4·m` 字节；
2. **n 条键值记录**，槽位 `0..n-1` 各一条，每条为
   `klen:I` + `key:klen 字节` + `vlen:I` + `value:vlen 字节`。
   记录中的键必须**严格按字节序升序且互不重复**（相邻比较同时覆盖两者），
   值长度 `vlen ≤ 4096`，键的每个字节必须 `< 0x80`。

空字典（`n=0`）时 `m=0`、体为空（`body_len=0`），校验和为
`SHA256("") = e3b0c4…b855`，文件恰为 65 字节。

### 载入校验顺序（全部通过才返回可查询对象）

载入**只解析字节**：不调用 `build` 重建，不使用 `pickle`/`marshal` 等
对象反序列化，不执行文件中的任何代码。校验顺序：

1. **长度**：总长至少 65；且总长恰为 `65 + body_len`
   （**截断、尾部多余数据都拒绝**）；
2. 魔数正确；`version` 必须是已知版本（**未知版本拒绝**，抛
   `UnknownSnapshotVersionError`）；
3. 体 SHA256 与头部一致（不一致抛 `SnapshotChecksumError`）；
4. **上限与索引参数**：`n ≤ 1000`、`m = ceil(1.4n)`、`seed/attempts`
   合法、g 表每项在 `0..n-1`；
5. 逐条记录解析：长度字段闭合、键 ASCII、`vlen ≤ 4096`（**越界长度
   拒绝**），记录条数恰为 `n`；
6. **键唯一且按键字节序升序**（**重复键拒绝**，不覆盖）；
7. **索引结构**：对每条记录的键独立重算
   `(g[h0]+g[h1]+g[h2]) mod n`，必须等于该键自己的槽位 `i`
   （**错槽位拒绝**）。

**校验和正确不代表内部合法**：第 3 步只证明字节未被意外改动；第 4–7 步
独立验证语义合法性。测试明确包含“篡改后**重新计算并写回正确校验和**，
但仍带错槽位、重复键、键序倒置或越界值长度”的文件，它们都必须被拒绝。

异常类型：所有格式问题抛 `mphf.SnapshotFormatError`（`ValueError`
子类）；其中未知版本为其子类 `UnknownSnapshotVersionError`，校验和不符
为其子类 `SnapshotChecksumError`。

### 载入后不依赖文件

`load` 在 `with open(...)` 内一次性读入并关闭句柄；`KvSnapshot` 的全部
状态（g 表、键、值）驻留内存，载入后即使删除/移走源文件也能正常查询；
`save` 通过同目录临时文件 + 原子替换写入，不留中间文件。

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
| 256 个 seed 全部失败 | **返回** `CONSTRUCTION_FAILED`（不抛异常）；`build` 与 `build_kv` 语义相同 |
| 对 `CONSTRUCTION_FAILED` 调用 `lookup`/`find_kv` | `ValueError` |
| 对非 `MPHFTable` 对象 `lookup` | `TypeError` |
| 对非 `KvSnapshot` 对象 `find_kv` | `TypeError` |
| 值不是 bytes-like 或值长度 > 4096 | `TypeError` / `ValueError` |
| 快照未知版本、截断、尾部多余数据 | `SnapshotFormatError`（未知版本为 `UnknownSnapshotVersionError`） |
| 快照校验和不符 | `SnapshotChecksumError` |
| 快照内部非法（错槽位、重复键、键序倒置、越界值长、g 值越界等） | `SnapshotFormatError`——即使 SHA256 已重算正确 |

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
- 键值快照中每个值：`0..4096` 字节（0 合法，表示空值命中）。
- 快照体积上界（仅作量级参考）：头部 65 字节 + `4m` 字节 g 表 +
  每键值的内容与两个 4 字节长度前缀。

## 已知限制

- 仅实现本题契约的有限数学子集：固定 3 哈希、固定负载系数 1.4、固定
  SHA256 线格式；快照格式为自定义 v1，**不宣称**与任何行业 MPHF/PHF、
  KV 容器标准或互操作格式兼容；版本字段为将来唯一的升级入口。
- 静态结构：不支持构造后增删键，也不提供动态增删、后台合并或数据库；
  变更集合需重新 `build`/`build_kv`。
- 非成员判定需要完整键存储（每键一份），属于刻意的设计取舍，不做只存
  指纹的近似模式（那会引入误报率口径）。
- `CONSTRUCTION_FAILED` 时不自动扩大顶点表、不更换哈希族；严格遵守
  题面给定参数与 256 次预算。
- 面向正确性与确定性而非极限吞吐：n=1000 实测构造约 10 ms 量级、
  千次查询约 4 ms（本机数字，仅作量级参考，非性能保证）。

## 测试如何独立于被测核心

- `tests/test_mphf.py` 在测试侧按题面线格式**独立**用 `hashlib` 计算
  哈希向量和槽位，用它校验双射（槽位为 `0..n-1` 的排列）与赋值方程
  （三顶点值之和模 n 等于键序号），不调用被测核心来产生期望值；
  build→lookup 的往返一致仅作为补充断言。覆盖：n=1..60 与多个键族的
  枚举双射、n=1000 边界、空表、真实 seed-0 不可剥离集合 `{a,b,i}`
  （seed=2 重试成功）、预算压为 1 时实际触发 `construction_failed`、
  非成员哈希碰撞拒绝、非 ASCII、重复键、类型/上限错误、确定性复现、
  128 个单字节 ASCII 键全集。
- `tests/test_kv_snapshot.py` 在测试侧**按本文档用 `struct` 独立解析**
  快照字节（独立的头部布局、记录游走、哈希槽位重算），手动核对键值在
  槽位中的位置，不调用被测解析器。覆盖：往返、n=1000、同一键集的输入
  排列（含 dict、bytes-like）逐位相同、空字典、空值命中、未知键哈希
  碰撞、独立按文档解析小快照逐字段核对、保存后删除源文件仍可查询、
  **另一个进程重新加载**；损坏面覆盖未知版本、截断、尾部多余数据、坏
  魔数、校验和不符，以及**重算正确校验和后**仍带错槽位、重复键、键序
  倒置、越界值长度（4097）、g 值越界、记录数不符的文件。

## 仓库布局

```
mphf/__init__.py          # 核心库：build/lookup + build_kv/find_kv/快照
tests/test_mphf.py        # MPHF 必要测试（独立参考期望值）
tests/test_kv_snapshot.py # 键值快照测试（独立按文档解析 + 损坏文件）
demo.py                   # 固定输入演示：正常索引 + 重试 + 拒绝/异常边界
demo_kv.py                # 快照保存后由另一个进程重新加载的短演示
requirements.txt          # 无第三方依赖（说明性注释）
```
