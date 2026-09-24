# 压缩字典的最小访问完美哈希（MPHF）

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

在不可变快照之上，另提供**增删差量层与墓碑**：不修改快照即可记录新增与
删除，查询“先差量、后基层”；`merge()` 可显式把当前逻辑集合合并成**新**
快照，旧快照合并后仍可独立查询。

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
# 必要测试（63 个用例：快照 31 + 差量/合并 32）
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
```

### 差量层：增/删、墓碑与显式合并

基层快照永远不可变；增删发生在 `MPHFView` 差量层上：

```python
view = mphf.open_view(table)     # 在快照上打开差量层（快照不变）
view.remove(b"beta")             # 写墓碑遮盖基层键，返回删除前序号 1
view.add(b"delta")               # 差量新增，返回差量序号 3 (= table.size + 0)
mphf.lookup(view, b"beta")       # -> -1（墓碑优先于基层）
mphf.lookup(view, b"delta")      # -> 3（差量优先）
view.add(b"beta")                # 删后重加：墓碑移除，键回到基层序号 1
new_table = mphf.merge(view)     # 显式合并：生成全新紧凑快照
mphf.lookup(new_table, b"delta") # -> 2（当前集合 [alpha,gamma,delta] 重新编号）
mphf.lookup(table, b"beta")      # -> 1（旧快照仍可查询，未被改动）
```

查询顺序固定为**先差量、后基层**：

1. 键在差量新增表中 → 命中（完整键精确匹配），序号为 `base.size + 新增位置`；
2. 键在墓碑集合中 → 返回 `NOT_FOUND`（已删基层键不得被基层哈希“复活”）；
3. 否则查基层快照，命中仍以槽位完整原键逐字节验证。

`MPHFView` 方法/属性：

| 成员 | 含义 |
|---|---|
| `view.base` | 基层不可变快照 |
| `view.size` / `len(view)` | 当前逻辑键数（基层存活数 + 新增数） |
| `view.added` | 新增键元组，按插入顺序 |
| `view.tombstones` | 墓碑键元组，按立碑顺序 |
| `view.keys()` | 当前逻辑键列表：基层存活键（原构造顺序）后接新增键 |
| `view.add(key)` | 新增；已存在抛 `DuplicateViewKeyError`；删后重加则移除墓碑、回到基层序号 |
| `view.remove(key)` | 删除存在的键（基层键立墓碑，新增键直接消失不留碑）；不存在抛 `UnknownKeyError` |
| `view.lookup(key)` / `view.get(key, default)` / `key in view` | 查询 |

合并语义：

- `mphf.merge(view) -> MPHFTable`：按当前逻辑集合调用同一套确定性构造
  算法生成**新**快照；新表序号按 `view.keys()` 顺序从 0 重新分配。
- **旧快照与视图均不被修改**：旧快照合并前后查询结果完全一致；视图的
  差量保留，可继续增删后再次合并，形成多代快照（每代都可独立查询）。
- 合并时若当前集合耗尽 256-seed 预算，抛 `mphf.MergeError`；视图与旧
  快照保持原样、仍可继续使用（与 `build` 返回哨兵的“预算边界”语义同源，
  但合并是显式操作，故用异常报告而非返回哨兵）。
- 同一快照可打开多个独立视图，互不影响。

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

- `table` 可以是 `MPHFTable`（快照）或 `MPHFView`（差量层）。
- 成员：快照上返回构造序号 `i ∈ 0..n-1`；视图中基层存活键返回原构造
  序号，新增键返回 `base.size + 新增位置`（仅差量期有效，合并后重新
  编号）。
- 非成员（含非 ASCII 字节串、空表上的任何查询）：返回 `NOT_FOUND`（`-1`）。
- 命中判定以**完整键**逐字节比较为准：快照层比较槽位保存的原键，差量
  层直接按完整键查新增表/墓碑；哈希只负责选槽位，**绝不**以“哈希值
  存在/算出了某个槽位”判定命中。

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
5. **差量层与墓碑**：`MPHFView` 以有序 dict 存新增、以 set 存墓碑，
   不触碰基层快照。墓碑只遮盖**基层**键（新增键删除后直接消失，不留
   无用墓碑）；“删后重加”基层键时移除墓碑，键干净回到基层原序号。
   所有写操作先做存在性与合法性判断、再改状态，非法操作抛错且不留下
   半更新。
6. **显式合并**：`merge` 以 `view.keys()`（基层存活键原顺序 + 新增键）
   为输入复用同一套确定性 `build`，产出新的不可变快照；它不是增量修补
   哈希表，而是一次完整重建——旧快照因此保持不变，代际快照可并存查询。
7. **无浮点**：`1.4n` 以有理数 `14/10` 的整数向上取整实现，全模块没有
   浮点运算，因此不存在浮点误差口径问题。
8. **失败即无副作用**：构造是纯函数，校验先于构造；输入非法时在收集阶段
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
| 对 `CONSTRUCTION_FAILED` 调用 `open_view` | `ValueError` |
| 对非 `MPHFTable` 对象 `lookup`/`open_view` | `TypeError` |
| 视图新增已存在键（基层存活或差量中） | 抛 `mphf.DuplicateViewKeyError`（`ValueError` 子类），状态不变 |
| 视图删除不存在键（从未存在或已被墓碑遮盖） | 抛 `mphf.UnknownKeyError`（`KeyError` 子类），状态不变 |
| 视图 `add`/`remove` 非 ASCII / 错误类型键 | `ValueError` / `TypeError`，状态不变（变更类操作先校验合法性；查询类 `lookup` 对非 ASCII 仍按非成员返回 -1） |
| 视图逻辑键数已达 1000 再 `add` | `ValueError`，状态不变 |
| `merge` 重建耗尽 seed 预算 | 抛 `mphf.MergeError`；视图与旧快照保持原样可继续使用 |
| `merge` 参数不是 `MPHFView` | `TypeError` |

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
- 快照仍是静态结构：单张快照不支持原地增删；变更通过差量层累积、再
  显式 `merge` 生成新快照。本次迭代**不包含**后台/并发合并、持久化与
  崩溃恢复、差量的自动代际回收。
- `merge` 是整表重建，非增量修补：代价与按当前集合重新 `build` 相当；
  本题规模（n≤1000，约 10 ms 量级）下不是问题，但不保证更大规模的吞吐。
- 非成员判定需要完整键存储（每键一份），属于刻意的设计取舍，不做只存
  指纹的近似模式（那会引入误报率口径）。
- 差量层本身是内存对象，不单独持久化；进程结束后只保留曾显式合并出的
  快照结构（本库同样不提供其磁盘编解码）。
- `CONSTRUCTION_FAILED`/`MergeError` 时不自动扩大顶点表、不更换哈希族；
  严格遵守题面给定参数与 256 次预算。
- 面向正确性与确定性而非极限吞吐：n=1000 实测构造约 10 ms 量级、
  千次查询约 4 ms（本机数字，仅作量级参考，非性能保证）。

## 测试如何独立于被测核心

`tests/test_mphf.py`（快照）与 `tests/test_view.py`（差量/合并）中的
期望值均不由被测实现产生：

* 测试侧按题面线格式**独立**用 `hashlib` 计算哈希向量和槽位，校验双射
  （槽位为 `0..n-1` 的排列）与赋值方程（三顶点值之和模 n 等于键序号）；
  build→lookup 的往返一致仅作为补充断言。
* 差量层用测试侧独立维护的**纯列表集合模型**对拍：枚举小基层上
  add/remove/noop 的全部操作序列（含删后重加、加后删、重复添加、删除
  未知键），每一步核对 `size`、`keys()` 顺序、`added`、墓碑集合与每个
  相关键的成员关系/序号；合并后同样用独立哈希校验新快照契约。
* 手算例子（base=`[a,b,c]`，删 `b`、加 `d` → 当前集合 `[a,c,d]`，
  合并后 a→0、c→1、d→2、b→-1）直接断言。

快照侧覆盖：n=1..60 与多个键族的枚举双射、n=1000 边界、空表、真实
seed-0 不可剥离集合 `{a,b,i}`（seed=2 重试成功）、预算压为 1 时实际触发
`construction_failed`、非成员哈希碰撞拒绝、非 ASCII、重复键、类型/上限
错误、确定性复现、128 个单字节 ASCII 键全集。差量侧覆盖：打开视图与
多视图独立、删除立碑/基层存活、删后重加、未知键与重复添加、类型/非
ASCII/上限失败的原子性、独立模型枚举、手算例子、合并前后一致、旧快照
与视图在合并后不变、空集合与删光、n=1000 边界合并、预算压为 1 时
`MergeError` 真实触发且状态保留、多代快照链。

## 仓库布局

```
mphf/__init__.py    # 核心库：build / lookup / open_view / merge，
                    #         MPHFTable / MPHFView / 错误与哨兵
tests/test_mphf.py  # 快照必要测试（独立参考期望值，31 个）
tests/test_view.py  # 差量增删/墓碑/合并测试（独立集合模型，32 个）
demo.py             # 固定输入演示：索引、重试、拒绝、差量增删与合并
requirements.txt    # 无第三方依赖（说明性注释）
```
