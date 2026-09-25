# 压缩字典的最小访问完美哈希（MPHF）与自带值只读快照

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

在此核心之上提供**自带值的只读字典层**：键与值打包进同一个可持久化快照
文件，离线发布时无需另配值文件；载入只做字节解析与全量校验，不重建索引、
不做 pickle 反序列化。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `dataclasses`、`math`、`os`、`struct`、`typing`、`unittest`）。
- 安装 Python 后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 准确命令

```bash
# 必要测试（66 个用例）
./.venv/bin/python -m unittest discover -s tests -v

# 完美哈希核心演示（实测约 0.1 秒）
./.venv/bin/python demo.py

# 键值快照演示：本进程保存、另一个进程重新加载查询（实测 <1 秒，预算 90 秒）
./.venv/bin/python demo_kv_snapshot.py
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

## 自带值的只读字典层

在完美哈希核心之上，把键和值打包进同一个只读结构，用于离线发布的小型
只读字典（键值同处一个快照文件，无需另配值文件）。

```python
import mphf

d = mphf.build_kv([(b"beta", b"2"), (b"alpha", b"1"), (b"gamma", b"")])
mphf.find(d, b"alpha")     # -> (True, b"1")
mphf.find(d, b"gamma")     # -> (True, b"")   空值是有效命中
mphf.find(d, b"absent")    # -> (False, None) 未命中有明确标志
d[b"beta"]                 # -> b"2"；未命中抛 KeyError
d.get(b"absent", b"def")   # -> b"def"
b"alpha" in d              # -> True

mphf.dump(d, "dict.mphfkv")          # 保存快照（也可传二进制文件对象）
d2 = mphf.load("dict.mphfkv")        # 另一进程/另一时刻重新载入
blob = mphf.dumps(d); d3 = mphf.loads(blob)   # 纯字节形式
```

### `build_kv(items) -> KVDictionary | CONSTRUCTION_FAILED`

- `items`：`(key, value)` 二元组的可迭代对象，**可以无序**；构建前按键的
  字节序固定排序，因此同一内容集合无论传入顺序如何，得到的对象与快照
  字节完全相同。
- 键规则与 `build` 完全一致（ASCII bytes-like、至多 1000 条）；**重复键
  直接抛 `DuplicateKeyError`，绝不悄悄覆盖**。
- 值限定 `bytes`（不接受 `bytearray`/`memoryview`/`str`），单项至多
  **4096 字节**（`mphf.MAX_VALUE_BYTES`），空值 `b""` 合法。
- 失败语义与 `build` 相同：256 个 seed 全部失败时返回哨兵
  `CONSTRUCTION_FAILED`，不抛异常。

### `find(dictionary, key) -> (found, value)`

- 命中返回 `(True, value)`——**空值也是有效命中**，为 `(True, b"")`；
  未命中（含非 ASCII 查询）返回 `(False, None)`。两种情况靠布尔标志
  明确区分，不靠“值是否为 None”猜测。
- 查询路径：经现有完美哈希定位槽位、核对槽位中的完整键（复用
  `lookup`），**不做整表字典查找**。

### 快照字节布局（格式版本 1）

全部多字节整数为**大端**；除校验和字段外的全部字节参与 SHA-256 校验和
计算，校验和为完整 32 字节摘要，位于头部末尾。

```
头部，固定 64 字节：
  偏移  长度  内容
  0     8     魔数 b"MPHFKV01"（mphf.SNAPSHOT_MAGIC）
  8     4     格式版本 u32，当前唯一合法值 1（mphf.SNAPSHOT_VERSION）
  12    4     n  u32  键数量，0..1000
  16    4     m  u32  顶点数；n>0 时必须恰为 (14n+9)//10，n=0 时必须为 0
  20    4     seed u32  索引参数；n>0 时 0..255，n=0 时必须为 0
  24    4     key_bytes   u32  K 段键净载荷总长（不含各记录 4 字节长度前缀）
  28    4     value_bytes u32  V 段值净载荷总长（不含前缀）
  32    32    校验和：SHA-256(头部其余 32 字节 ‖ G 段 ‖ K 段 ‖ V 段)
G 段：m 个 u16，顶点赋值表 g，每个值必须 < n（n=0 时本段为空）
K 段：n 条键记录，各为 [klen u32][key 字节]；键按槽位号 0..n-1 排列，
      且必须严格递增（字节序）、纯 ASCII、互不重复
V 段：n 条值记录，各为 [vlen u32][value 字节]，vlen ≤ 4096，
      与 K 段同槽位一一对应
```

文件总长度 = `64 + 2m + (4n + key_bytes) + (4n + value_bytes)`。
空字典的快照恰为 64 字节（只有头部）。

### 载入校验（`loads` / `load`）

载入**不**调用 `build` 重建索引，也**不**执行 pickle 之类的对象反序列化，
只做字节解析与校验，顺序为：

1. **长度与上限**：头部 ≥64 字节、魔数、版本号、`n ≤ 1000`、
   `m == ceil(1.4n)`（n=0 时 m=seed=0）、`seed ≤ 255`、
   `value_bytes ≤ n·4096`、文件总长与声明长度精确相等——**截断与尾部
   多余数据都在此拒绝**；
2. **校验和**：重新计算 SHA-256 并与头部存储值比较；
3. **分段解析**：K/V 段记录不得越过各自声明的净载荷边界；
4. **键合法性**：逐键检查 ASCII、严格递增序、无重复；
5. **值长度**：每条 `vlen ≤ 4096`；
6. **索引结构**：每个 `g` 值 `< n`；
7. **逐键落槽**：用快照内的 `seed`/`m`/`g` 独立重算每个键的槽位，
   必须等于它自己的槽位号。

全部通过才返回可查询的 `KVDictionary`；任何一项失败抛
`mphf.SnapshotError`（`ValueError` 子类）。**校验和正确不代表内部合法**：
测试里专门构造了重算校验和后仍带错槽位、重复键、乱序键、越界长度的
快照文件，确认都被拒绝。载入后对象持有全部数据于内存，不依赖打开的
文件句柄，源文件可立即关闭甚至删除。

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
| 值非 `bytes` / 超 4096 字节 | `TypeError` / `ValueError`（`build_kv` 收集阶段） |
| 快照任何格式或一致性违例 | 抛 `mphf.SnapshotError`（`ValueError` 子类），消息带定位上下文 |

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
- 单值长度：`0..4096` 字节（仅键值层；值限定 `bytes`）。
- 顶点/赋值表大小：`m = ceil(1.4n) ≤ 1400`；另保存 n 个原始键。
- seed：`0..255`，共 256 次尝试。
- 快照：格式版本固定为 1；文件总长 = `64 + 2m + (4n+key_bytes) +
  (4n+value_bytes)`，其中 `value_bytes ≤ n·4096`。

## 已知限制

- 仅实现本题契约的有限数学子集：固定 3 哈希、固定负载系数 1.4、固定
  SHA256 线格式；**不宣称**与任何行业 MPHF/PHF 标准或互操作格式兼容。
- 静态结构：不支持构造后增删键或改值；变更集合需重新 `build_kv`。
  没有动态增删、后台合并或数据库。
- 非成员判定需要完整键存储（每键一份），属于刻意的设计取舍，不做只存
  指纹的近似模式（那会引入误报率口径）。
- `CONSTRUCTION_FAILED` 时不自动扩大顶点表、不更换哈希族；严格遵守
  题面给定参数与 256 次预算。
- 快照为自研私有格式，仅本模块同版本可读；未知版本一律拒绝，不做
  前向/后向兼容猜测。
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
键全集。

`tests/test_kv.py` 覆盖键值层：无序输入排序后快照字节逐位一致（含输入
排列枚举）、空字典（64 字节快照）、空值命中与未命中标志区分、重复键
拒绝、值类型/4096 上限、1000 键边界、构造失败哨兵语义、跨进程之外的
文件载入后关闭/删除源文件、确认载入路径不调用 `build`、未知键哈希碰撞
在键值层仍返回 `(False, None)`。快照解析有**独立手工解析器**严格按上文
字节布局切片核对键值位置；损坏文件用测试侧的独立写入器逐字节构造并
**重算校验和**，覆盖错槽位、重复键、乱序键、越界值长、越界 g、非法
m/seed/n、非 ASCII 键、未知版本、截断、尾部多余、随机单比特翻转，
确认全部抛 `SnapshotError`。

## 仓库布局

```
mphf/__init__.py      # 核心库 + 键值层：build/lookup/build_kv/find/快照读写
tests/test_mphf.py    # 完美哈希核心测试（独立参考期望值）
tests/test_kv.py      # 键值层与快照测试（独立手工解析/独立损坏文件写入器）
demo.py               # 完美哈希核心演示
demo_kv_snapshot.py   # 键值快照演示：本进程保存，另一进程重新加载查询
requirements.txt      # 无第三方依赖（说明性注释）
```
