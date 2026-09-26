# 压缩字典的最小访问完美哈希（MPHF）

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。
在完美哈希之上还提供**前缀迭代**：按原始字节键的字典序分页列出任意
前缀（含空前缀）匹配的全部键，查询只访问候选范围，不扫描全表。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `dataclasses`、`math`、`typing`、`unittest`）。
- 安装 Python 后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 隔离 venv 准备

```bash
python3.14 -m venv .venv        # 隔离环境；不污染系统 Python
. .venv/bin/activate
python -V                        # 应为 Python 3.14.7
# 无需 pip install：仅标准库
```

## 准确命令

```bash
# 必要测试（50 个用例：31 个基线回归 + 19 个前缀迭代）
python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.1 秒，远低于 8 秒预算；无 sleep、无预录）
python demo.py

# 前缀迭代演示（真实离线计算，远低于 90 秒；无账号/密钥/sleep/预录）
python demo_iteration.py
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

### 前缀迭代（新增）

```python
page = mphf.iter_prefix(table, b"ab", limit=100)
page.keys          # 按原始字节字典序排列的本页键
page.accessed      # 本次查询实际读取的键次数（候选范围定位 + 输出）
page.next_cursor   # 继续位置的稳定 bytes 编码；None 表示已迭代完
page.done          # 等价于 next_cursor is None

# 跨页 / 跨进程继续：游标是纯内容编码，绑定字典指纹与前缀
rest = mphf.iter_prefix(table, cursor=page.next_cursor)
table.iter_prefix(b"ab")          # 实例方法，等价
```

- 结果按**原始字节键的字典序**返回；哈希槽号不等于排序位置，排序由
  构造期保存的紧凑置换 `table.sorted_slots` 给出，与槽号顺序无关。
- 空前缀 `b""` 匹配全部键；含零字节的键按普通字节参与排序与匹配。
- 查询只访问候选范围：二分定位下界（O(log n) 次读键）后，借助构造期
  保存的相邻键公共前缀数组 `table.lcp` 判定候选边界，只逐条读取实际
  输出的键；`page.accessed` 给出本次读取键数，稀有前缀可直观看到
  没有全表扫描。
- `limit` 为本页最大键数（`None` 表示不限）；`cursor` 为上一页返回的
  继续位置。游标编码为 `MPX1 ‖ 指纹8字节 ‖ 前缀长度 ‖ 前缀 ‖ 位置`，
  不依赖进程地址，跨进程、跨次运行可用；它绑定 `table.fingerprint`
  （排序键内容的 SHA256），**用在其他字典上抛 `mphf.CursorError`**。
- 非 ASCII 前缀必无匹配（返回空页）；`limit < 1`、类型错误、损坏或
  越界游标按“错误语义”一节抛错。

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
| `sorted_slots` | 紧凑排序置换：`keys[sorted_slots[j]]` 为字典序第 j 小的键 |
| `lcp` | 相邻排序键的最长公共前缀字节数，长度 `n-1` |
| `fingerprint` | 字典指纹（排序键内容的 SHA256，32 字节），游标凭它绑定字典 |

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
| 游标损坏 / 越界 / 属于其他字典 | `mphf.CursorError`（`ValueError` 子类） |
| 显式 `prefix` 与游标前缀不一致 | `mphf.CursorError` |
| `limit` 非整数或 `< 1` | `TypeError` / `ValueError`（`bool` 按 `TypeError` 拒绝） |

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

`tests/test_prefix.py` 以**排序后的原字典**（测试侧 `sorted()`）为参照，
覆盖：排序置换与 LCP 数组逐位核对、空前缀全量、跨多页游标迭代
（limit=1/7/100）、精确键同时也是别的键前缀、零字节键按普通字节排序、
空结果、稀有前缀访问键数远小于全表（无全表扫描）、错误字典游标与
损坏游标拒绝、游标跨 build 稳定复现、空表、参数校验，以及旧单键查询
回归。

## 仓库布局

```
mphf/__init__.py   # 核心库：build / lookup / MPHFTable / 错误与哨兵
                   #   及前缀迭代 iter_prefix / PrefixPage / CursorError
tests/test_mphf.py # 基线必要测试（独立参考期望值）
tests/test_prefix.py # 前缀迭代测试（sorted 原字典为参照）
demo.py            # 固定输入演示：正常索引 + 重试 + 拒绝/异常边界
demo_iteration.py  # 前缀迭代演示：分页、游标、访问键数、错误游标
requirements.txt   # 无第三方依赖（说明性注释）
```
