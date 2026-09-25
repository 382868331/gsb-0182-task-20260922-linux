# 压缩字典的最小访问完美哈希（MPHF）+ 索引认证

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

索引认证扩展：在只读键集合上再构建**两棵 Merkle 树**（槽位树 + 按键序
排列的认证序列树），两树根与总键数组成**版本清单**；调用方只凭清单即可
**离线核验**某个键的成员证明 / 不存在证明，不必信任查询端。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `hmac`、`dataclasses`、`bisect`、`math`、`typing`、`unittest`）。
- 安装 Python 后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 准确命令

```bash
# 必要测试（70 个用例）
./.venv/bin/python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.1 秒，远低于 90 秒预算；无 sleep、无预录）
./.venv/bin/python demo.py
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

## 索引认证接口（mphf/auth.py，经 `mphf` 统一导出）

动机：索引发布后，调用方想只拿到**某个键的证明**并自行离线核验，而不必
信任查询端。做法是在只读键集合上加两棵 Merkle 树，两树根与总键数组成
版本清单 `Manifest`；清单经可信渠道分发后，所有证明只凭清单核验。

```python
auth = mphf.build_auth(table)          # 从 MPHFTable 派生认证索引（纯函数）
man = auth.manifest()                  # 版本清单：size + slot_root + seq_root + version

p = mphf.prove(auth, b"beta")          # 成员证明；非成员返回 None
mphf.verify_membership(man.slot_root, man.size, b"beta", p)   # -> True

ap = mphf.prove_absence(auth, b"zzz")  # 不存在证明；是成员则返回 None
mphf.verify_absence(man.seq_root, man.size, b"zzz", ap)       # -> True
```

### 两棵树的线格式（公开契约，全部 SHA256）

```
槽位树叶:   SHA256(0x10 ‖ slot:8BE ‖ keylen:8BE ‖ key)        # 叶按槽号 0..n-1 排列
槽位树内点: SHA256(0x11 ‖ left ‖ right)
序列树叶:   SHA256(0x12 ‖ rank:8BE ‖ slot:8BE ‖ keylen:8BE ‖ key)  # 叶按键字节序排列，绑定原槽号
序列树内点: SHA256(0x13 ‖ left ‖ right)
```

- 域前缀 `0x10..0x13` 与 MPHF 顶点哈希标签 `0x00/0x01/0x02` 不相交，
  叶与内点也不同前缀（防第二原像混用）。
- 树形规则：每层节点数为奇时**复制末节点**配对；归约到单节点即根；
  单叶树的根即叶子本身（路径为空）；**空集合的根单独定义**为常量
  `mphf.EMPTY_ROOT = SHA256(b"mphf-auth-v1:empty-set-root")`（两树共用）。
- 规模 `n` 的路径深度完全确定：`n≤1` 为 0，否则为 `ceil(log2 n)`。

### 证明语义与核验顺序

- `prove(key)` **仅为真实成员**返回 `MembershipProof(slot, path)`
  （槽号 + 兄弟路径，自叶向根）；非成员返回 `None`。
- `verify_membership(root, size, key, proof)`：输入根、总槽数和键，
  **先核对路径形状与槽号范围**（槽号 ∈ `0..size-1`、路径长度等于树深、
  每层兄弟 32 字节），再重算根比对（`hmac.compare_digest`）。形状/范围
  不符一律返回 `False` 而非抛异常——证明按不可信输入处理。
- `prove_absence(key)` 对非成员返回 `AbsenceProof(predecessor, successor)`：
  认证序列中前驱与后继的认证路径及**相邻秩**。边界键缺一侧时，核验方
  检查首秩（后继秩为 0）或尾秩（前驱秩为 `size-1`）；空集合两侧皆空。
- `verify_absence(root, size, key, proof)` 要求：两侧都在时
  `pred.key < key < succ.key` 且 `succ.rank == pred.rank + 1`。
  **只给两个存在键的认证路径而没有相邻秩，不能证明不存在**（秩不相邻
  即拒绝）。键是成员时 `prove_absence` 返回 `None`，不存在证明对成员
  查询永不成立。
- 序列树叶同时绑定键与原槽号：调用方如需进一步交叉核验某个邻居键的
  槽位归属，可再对其做槽位树成员证明；本扩展的核验器不强制该步骤。

### 证明/清单编码（确定性、带版本）

`MembershipProof.encode()`、`AbsenceProof.encode()`、`Manifest.encode()`
输出确定性字节串，以格式标签（`MPHF-MEM` / `MPHF-ABS` / `MPHF-MAN`）+
1 字节版本（`mphf.PROOF_VERSION = 1`）开头；对应
`mphf.decode_membership_proof` / `mphf.decode_absence_proof` /
`Manifest.decode` 严格解码：截短、追加字节、未知标志位或版本不符一律
`ValueError`。清单编码布局：`MPHF-MAN ‖ version:1 ‖ size:8BE ‖
slot_root:32 ‖ seq_root:32`（共 81 字节）。

### 认证部分的边界与错误语义

- 沿用原构建上限与 seed 策略：`build_auth` 只接受 `build` 成功返回的
  `MPHFTable`（键数 `0..1000`）；对 `CONSTRUCTION_FAILED` 抛 `ValueError`，
  对非表对象抛 `TypeError`。
- 核验器入参（根/规模/键）类型错误抛 `TypeError`（`bool` 同样拒绝），
  根非 32 字节或规模为负抛 `ValueError`；**证明**对象的形状问题不抛
  异常，一律核验失败 `False`。
- 非 ASCII 查询键：必为非成员，`prove` 返回 `None`，`prove_absence`
  按字节序正常给出前后驱（非 ASCII 键不可能在表内，但其字典序位置
  仍有定义）。
- 认证索引与证明都是纯函数产物；`build_auth` 不修改原表，原 `lookup`
  语义不变（仍以槽位完整键逐字节比较判定命中）。

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
- 认证扩展是**索引认证**而非通用链上证明系统：只覆盖本契约的两棵
  Merkle 树、成员/不存在证明与版本清单，不实现通用累加器、稀疏
  Merkle 树或链上验证合约。
- 清单（两树根 + 总键数）本身需经可信渠道获得；本模块不解决清单的
  分发与签名问题。

## 测试如何独立于被测核心

`tests/test_mphf.py` 在测试侧按题面线格式**独立**用 `hashlib` 计算哈希
向量和槽位，用它校验双射（槽位为 `0..n-1` 的排列）与赋值方程
（三顶点值之和模 n 等于键序号），不调用被测核心来产生期望值；
build→lookup 的往返一致仅作为补充断言。覆盖：n=1..60 与多个键族的枚举
双射、n=1000 边界、空表、真实 seed-0 不可剥离集合 `{a,b,i}`（seed=2
重试成功）、预算压为 1 时实际触发 `construction_failed`、非成员哈希碰撞
拒绝、非 ASCII、重复键、类型/上限错误、确定性复现、128 个单字节 ASCII
键全集。

`tests/test_auth.py`（认证扩展）同样在测试侧独立实现叶/内点编码、
树形归约与兄弟路径，并对 1、3、5 键的槽位树**逐层手算**展开核对根与
路径。覆盖：成员证明往返、换键/换槽号/换兄弟哈希拒绝、截短与追加
路径节点拒绝、非相邻前后驱拒绝（仅两个存在键不能证明不存在）、
边界键首/尾秩核验、空集合（根为单独常量、两侧皆空）、序列树叶绑定
原槽号、证明/清单编码的确定性与版本校验、n=1000 上限规模证明深度。

## 仓库布局

```
mphf/__init__.py   # 核心库：build / lookup / MPHFTable / 错误与哨兵；统一导出认证接口
mphf/auth.py       # 索引认证：两棵 Merkle 树、Manifest、prove/verify、证明编码
tests/test_mphf.py # 核心必要测试（独立参考期望值）
tests/test_auth.py # 认证扩展必要测试（独立参考 + 手算 1/3/5 键树）
demo.py            # 固定输入演示：正常索引 + 重试 + 拒绝/异常边界 + 证明核验
requirements.txt   # 无第三方依赖（说明性注释）
```
