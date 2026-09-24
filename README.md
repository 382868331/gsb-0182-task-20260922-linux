# 压缩字典的最小访问完美哈希（MPHF）

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

本迭代在不可变快照之上增加**增删差量层**（`MutableIndex`）：新增与删除
（墓碑）先记录在差量中，查询先差量后基层；`merge()` 显式把存活键集合并
为新的不可变快照，旧快照与旧索引在合并后仍可照常查询。

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
# 必要测试（54 个用例）
python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.1 秒，远低于 90 秒预算；无 sleep、无预录）
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

# 差量索引：在不可变快照上增删，显式合并
idx = mphf.MutableIndex(table)
idx.delete(b"beta")              # 墓碑
idx.insert(b"delta")             # -> 3（新序号从 n 起单调分配）
idx.lookup(b"beta")              # -> NOT_FOUND（先差量后基层）
new_snapshot = idx.merge()       # 显式合并 → 新 MPHFTable；table 与 idx 仍可查询
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

### `MutableIndex(snapshot)`：增删差量 + 墓碑

在不可变快照上叠加一个有序差量字典（`键 -> 新序号`，或 `键 -> None`
表示**墓碑**）。查询**先看差量再看基层**：差量新增直接命中其分配序号，
墓碑直接判非成员，未触及的键回落基层快照并做完整键终检。

| 方法/属性 | 语义 |
|---|---|
| `insert(key) -> int` | 插入新键并返回分配序号；若该键是基层成员的墓碑（删后重加），撤销墓碑、恢复其基层原序号 |
| `delete(key)` | 删除成员：基层成员留下墓碑，差量新增直接抹除；非成员抛 `KeyError` |
| `lookup(key) -> int` / `get(key, default)` | 先差量后基层；非成员 `NOT_FOUND`；类型/非 ASCII 语义同模块级 `lookup` |
| `merge() -> MPHFTable` | 显式合并：存活键（基层未删者按基层槽位序 + 新增者按插入序）经与 `build` 完全相同的流程重建为新快照；**纯函数**，本索引与旧快照不被修改、仍可查询；存活键为零得空表，预算耗尽返回 `CONSTRUCTION_FAILED` |
| `size` / `len(idx)` | 当前存活键数 |
| `pending` | 未合并的差量条目数（新增 + 墓碑） |
| `snapshot` | 基层快照 |

序号约定（**需要新增状态，特此说明**）：基层成员序号为 `0..n-1`；差量
新增从 `n` 起**单调分配、删除不回收**（合并前序号可能有空洞）；
`merge()` 生成的新快照重新从 0 紧凑编号，**同一键合并前后序号可能
不同**。所有变更方法先校验后修改，失败不留部分变更。

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
7. **差量层叠加而非改写**：`MutableIndex` 把增删记录在一个保持插入序的
   字典里（新增 → 单调分配的序号；删除基层成员 → `None` 墓碑），查询
   先差量后基层。墓碑设计使“删后重加”只需撤销墓碑即可恢复基层原序号，
   无需触碰快照；`merge()` 把存活键集交给与 `build` 相同的确定性构造
   流程，因此合并结果可复现，且合并本身不改写任何现有对象。

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
| `MutableIndex.insert` 重复键 | `DuplicateKeyError`（`index` 属性为 `None`，因无构造输入位置） |
| `MutableIndex.delete` 非成员/重复删除 | `KeyError`，消息带键值 |
| 存活键数达 1000 后再 `insert` | `ValueError`（保证 `merge()` 重建不越上限） |
| `MutableIndex(非 MPHFTable)` / `(CONSTRUCTION_FAILED)` | `TypeError` / `ValueError` |

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
- 快照不可变；增删经 `MutableIndex` 差量层进行，本次迭代**不含**后台
  并发合并、持久化恢复、差量代际自动回收——`merge()` 需显式调用，
  合并前差量只在内存中，进程退出即丢失。
- `merge()` 是一次全量重建（O(n) 构造），不是增量压缩；`MutableIndex`
  非线程安全。
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
键全集。

`tests/test_mutable.py` 覆盖差量层：手算小例（`{a,b,i}` 基层序号 0/1/2
已锚定，差量序号从 n 起单调分配可逐步手推）验证删后重加恢复原序号、
墓碑遮蔽基层、序号不回收；以普通 `set` 作独立参照模型、固定种子操作
序列 400 步逐步比对成员关系与序号唯一性；合并前后一致性（合并为纯
函数、旧索引视图不变、旧快照可查询）、合并键序（基层序 + 插入序）、
合并确定性、全删合并得空表、容量上限、失败不留部分变更、未知键/
重复键/类型/非 ASCII 错误。合并后快照的双射性同样用测试侧独立哈希
重新计算验证。

## 仓库布局

```
mphf/__init__.py     # 核心库：build / lookup / MPHFTable / MutableIndex / 错误与哨兵
tests/test_mphf.py   # 静态构造必要测试（独立参考期望值）
tests/test_mutable.py# 差量层必要测试（手算例 + set 模型 + 独立哈希）
demo.py              # 固定输入演示：索引 + 重试 + 拒绝边界 + 增删/墓碑/合并
requirements.txt     # 无第三方依赖（说明性注释）
```
