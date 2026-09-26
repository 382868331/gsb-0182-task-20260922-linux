# 压缩字典的最小访问完美哈希（MPHF）

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

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
# 隔离 venv 准备（可选但推荐；仓库根目录的 .venv 即按此创建）
python3.14 -m venv .venv
source .venv/bin/activate   # 之后文中的 python 即 3.14.7

# 必要测试（基线回归 + 前缀迭代，共 59 个用例）
python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.1 秒，远低于 8 秒预算；无 sleep、无预录）
python demo.py

# 前缀迭代演示（同样当场真实计算，远低于 90 秒预算）
python demo_iteration.py
```

适用范围：离线静态只读字典（构造后不增删键），至多 1000 条互不重复的
ASCII 字节串键；单键查询与前缀分页迭代均为进程内调用，不依赖网络、
账号、密钥或外部服务。

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

前缀迭代（在既有完美哈希之上的增量能力）：

```python
page = mphf.iter_prefix(table, b"doc-", limit=100)
page.keys       # 按原始字节字典序排列的本页键
page.total      # 该前缀的全部匹配数
page.accessed   # 本次查询实际访问的键数（稀有前缀远小于 n）
page.cursor     # 下一页游标；None 表示已取完
page2 = mphf.iter_prefix(table, b"doc-", limit=100, cursor=page.cursor)
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
| `order` | 排序置换：`sorted_keys[i] is keys[order[i]]`，把构造序号排列成原始键字典序，长度 `n` |
| `sorted_keys` | 按原始字节字典序排列的全部键（`order` 作用于 `keys` 的结果），长度 `n` |
| `lcp` | 相邻键公共前缀长度；`lcp[0]=0`，`lcp[i]` 为排序后第 i-1 与第 i 个键的最长公共前缀长度，长度 `n` |
| `fingerprint` | 对排序后键集合的确定性 SHA256 十六进制指纹；游标只接受同一指纹，与进程地址无关 |

### `lookup(table, key) -> int`

- 成员：返回其构造序号 `i ∈ 0..n-1`。
- 非成员（含非 ASCII 字节串、空表上的任何查询）：返回 `NOT_FOUND`（`-1`）。
- 命中判定以槽位保存的**完整键逐字节比较**为准：哈希只负责选出槽位，
  **绝不**以“哈希值存在/算出了某个槽位”判定命中。非成员即使哈希恰好
  落到已占用槽位也返回 `NOT_FOUND`。

### `iter_prefix(table, prefix=b"", *, limit=None, cursor=None) -> PrefixPage`

- 按**原始字节键的字典序**返回所有以 `prefix` 开头的成员；哈希槽号不是
  排序位置，迭代完全不使用槽号顺序。
- 空前缀 `b""` 匹配全部；零字节按普通字节参与比较；精确键同时也是别的键
  的前缀时，它本身和其后继都会返回（如 `b"ab"`、`b"abc"` 同在
  `prefix=b"ab"` 的结果中）；含非 ASCII 字节的前缀匹配为空（不报错，与
  `lookup` 的非成员语义一致）。
- `limit`：每页上限，正整数；`None` 表示一次取完；0/负数抛
  `ValueError`，非 int（含 bool）抛 `TypeError`。
- 区间定位只做两次二分：`lo=bisect_left(sk, prefix)`、
  `hi=bisect_left(sk, prefix+b"\x80")`。由于全部键字节 < 0x80，
  `[lo,hi)` 恰好是前缀候选区间——**不扫描全部键**，只读本页键。
- `PrefixPage` 字段：`keys`（本页键元组）、`cursor`（下一页游标，
  取完为 `None`）、`total`（该前缀总匹配数）、`accessed`（本次访问
  的键数 = 两次二分比较次数 + 本页读取的键数，用来直观展示稀有前缀没有
  全表扫描）。
- 游标稳定编码：`mphfcur1.<64 位字典指纹>.<下一排序位置>`，纯文本、
  不含进程地址；跨进程/重新构造的同内容字典（指纹相同）可续翻，绑定其他
  字典时抛 `mphf.CursorError`（`ValueError` 子类），格式损坏同样抛
  `CursorError`。游标不依赖基线已有序列化能力，是独立的小型文本协议。

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
7. **构造期排序索引**：build 成功时额外保存排序置换 `order`、排序键
   `sorted_keys` 与相邻键公共前缀长度数组 `lcp`（LCP 信息随表保存，
   供基于公共前缀的压缩/分析使用），以及对排序后键集合的 SHA256
   `fingerprint`。前缀迭代在 `sorted_keys` 上两次二分定位候选区间，
   只访问候选范围内的本页键，不复用、也不依赖哈希槽号顺序。

## 错误语义

| 情况 | 行为 |
|---|---|
| 重复键 | 抛 `mphf.DuplicateKeyError`（`ValueError` 子类），消息带重复位置 `index` 和键值 |
| 键含非 ASCII 字节 | `ValueError`，消息形如 `keys[i]: non-ASCII byte ...` |
| 键数 > 1000 | `ValueError`（在第 1001 个元素处报错） |
| 键/容器类型错误 | `TypeError`（含把 `str`、`int`、`None`、单 `bytes` 等传入） |
| 游标绑定其他字典指纹 / 游标损坏 | `mphf.CursorError`（`ValueError` 子类） |
| `limit` 为 0 或负数 | `ValueError`；非 int（含 bool）为 `TypeError` |
| `bool` | `bool` 虽是 `int` 子类，在键位上一律按 `TypeError` 拒绝，不静默当作 `1/0` |
| 256 个 seed 全部失败 | **返回** `CONSTRUCTION_FAILED`（不抛异常） |
| 对 `CONSTRUCTION_FAILED` 调用 `lookup` | `ValueError` |
| 对非 `MPHFTable` 对象 `lookup` | `TypeError` |

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

`tests/test_prefix_iteration.py` 覆盖前缀迭代：以 `sorted(原始键列表)`
为独立参照（不调用被测模块的排序/二分），验证跨多页游标迭代、精确键同时
是别的键的前缀、零字节键、空前缀匹配全部、空结果、稀有前缀访问键数远小于
`n`、游标稳定编码与跨字典游标拒绝（`CursorError`）、LCP 与排序置换的
独立校验，以及旧单键 `lookup` 回归。

## 仓库布局

```
mphf/__init__.py              # 核心库：build / lookup / iter_prefix / 错误与哨兵
tests/test_mphf.py            # 基线必要测试（独立参考期望值）
tests/test_prefix_iteration.py# 前缀迭代测试（sorted(原字典) 作独立参照）
demo.py                       # 固定输入演示：正常索引 + 重试 + 拒绝/异常边界
demo_iteration.py             # 前缀迭代演示：跨页、访问键数、游标绑定
requirements.txt              # 无第三方依赖（说明性注释）
```
