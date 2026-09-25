# 压缩字典的最小访问完美哈希（MPHF）+ 索引认证扩展

为离线静态索引工程提供的可复用模块：给定至多 **1000 条互不重复的 ASCII
字节串**，确定性构造一个**最小完美哈希函数**（Minimal Perfect Hash Function），
把每个键映射到紧凑序号 `0..n-1`，并通过槽位中保存的完整键做非成员终检。

在此之上提供**索引认证扩展**：为只读键集合构建两棵 Merkle 树（槽位树 +
按键字节序排列的认证序列），调用方只需持有**版本清单**（两棵树根 + 总键数），
即可离线验证某个键的成员证明或不存在证明，不必信任查询端。

纯 Python 标准库实现，核心算法（三哈希超图剥离 + 顶点赋值）自行实现，
未使用任何第三方同类库。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；仅使用 3.14 标准库：`hashlib`、
  `bisect`、`dataclasses`、`math`、`typing`、`unittest`）。
- 安装 Python 后**无需安装任何其他依赖**；`requirements.txt` 仅含说明注释。
- 完全离线：不访问网络、账号、数据库、中间件或云服务；示例数据由仓库内
  确定性代码生成。

## 准确命令

```bash
# 必要测试（61 个用例）
./.venv/bin/python -m unittest discover -s tests -v

# 固定输入演示（当场真实计算，实测约 0.2 秒，远低于 90 秒预算；无 sleep、无预录）
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

## 索引认证扩展（成员/不存在证明）

发布索引后，调用方想只拿到某个键的证明而不用信任查询端。扩展在只读
`MPHFTable` 上构建两棵 Merkle 树，树根与总键数组成**版本清单**
（`Manifest`）；证明编码确定且带版本（`PROOF_FORMAT_VERSION == 1`）。
原 `lookup` 行为不变，仍以完整键终检。

### 两棵树（v1 线格式，SHA256，整数一律 8 字节大端）

| 项 | 编码 |
|---|---|
| 槽位树叶 | `SHA256(0x00 ‖ slot_be8 ‖ keylen_be8 ‖ key)`（叶编码槽号、键长度、键字节，按槽位排列） |
| 键序树叶 | `SHA256(0x02 ‖ slot_be8 ‖ keylen_be8 ‖ key)`（按键字节序排列的认证序列，叶同时绑定键与原槽号） |
| 内部节点 | `SHA256(0x01 ‖ left ‖ right)`（两树共用，与叶不同的域前缀） |
| 奇数层 | 末节点**复制**后配对（末节点与自身配对） |
| 空集合根 | `EMPTY_ROOT = SHA256(b"\x03mphf-auth-empty-root-v1")`，两棵空树共用，单独定义 |

### 接口

```python
idx  = mphf.build_authenticated(table)   # 纯函数，确定性；对哨兵/错误类型抛错
man  = idx.manifest                      # Manifest(size, slot_root, sorted_root, version=1)

# 成员证明：仅为真实成员返回 SlotProof(slot, path)，非成员返回 None
p    = idx.prove(b"beta")
ok   = mphf.verify_membership(man.slot_root, man.size, b"beta", p)   # -> bool

# 不存在证明：前驱/后继在键序树中的认证路径 + 相邻秩；成员返回 None
ap   = idx.prove_absence(b"beta!")
ok2  = mphf.verify_absence(man.sorted_root, man.size, b"beta!", ap)  # -> bool
```

- **验证器**输入根、总槽数和键，**先核对路径形状与范围**（路径长度须等于
  该槽数下的树深；槽号/秩须在 `0..size-1`；每步须为合法方位 + 32 字节
  摘要），**再重算根**比较；任何不符返回 `False` 而非抛异常（键类型错误
  与 `lookup` 一致抛 `TypeError`）。
- **不存在证明的相邻秩**：两侧俱在时要求 `succ.rank == pred.rank + 1`；
  边界键缺一侧时核验首秩（`succ.rank == 0`）或尾秩
  （`pred.rank == size - 1`）。**仅给两个存在键而没有相邻秩不能证明不
  存在**——验证器会因秩不相邻而拒绝。
- **空集合**：`prove` 恒返回 `None`；`prove_absence` 返回两侧皆 `None`
  的证明，仅当 `size == 0` 且根为 `EMPTY_ROOT` 时验证通过。
- `Manifest.encode()` / `Manifest.digest()` 与各证明的 `encode()` 为确定
  性编码，首字节版本号为 1；`Manifest.digest()` 即整份清单的承诺。
- 构建上限与 seed 策略不变：认证扩展作用于既有 `MPHFTable`，不改变
  `build` 的 1000 键上限、256 次 seed 预算与确定性。

### 已知边界

- 树深由 `size` 唯一确定，`size` 在验证中作为形状/范围核对；根才是内容
  承诺。清单把 `size` 与两个根绑定在一起，验证时须整份采用同一清单。
- 证明是静态快照：键集变更需重新 `build` 并重新 `build_authenticated`，
  旧清单即作废（靠 `digest` 比对版本）。
- 这是索引认证扩展，不是通用链上证明系统：不支持增量更新、不实现
  通用累加器或链上验证合约。

## 哈希线格式（公开契约）

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

`tests/test_auth.py` 同样按公开线格式在测试侧**独立**用 `hashlib` 拼装
叶/内部节点并独立构树：含 1、3、5 键树的**手算逐步展开**（根与逐条兄弟
路径），以及多规模独立根对照。拒绝面覆盖：换键、换槽号（含越界）、截短
路径、追加节点、非相邻前后驱（两个真实存在键但秩不相邻）、边界首/尾秩
伪造、成员冒充不存在、空集合篡改、错误根/尺寸/类型。验证器形状核对先于
根重算，全部拒绝返回 `False` 而非异常。

## 仓库布局

```
mphf/__init__.py   # 核心库：build / lookup / MPHFTable / 错误与哨兵；再导出认证接口
mphf/auth.py       # 索引认证扩展：两棵 Merkle 树、证明、版本清单、离线验证器
tests/test_mphf.py # 核心必要测试（独立参考期望值）
tests/test_auth.py # 认证扩展测试（手算 1/3/5 键树 + 独立参考 + 拒绝面）
demo.py            # 固定输入演示：正常索引 + 重试 + 拒绝/异常边界 + 证明离线验证
requirements.txt   # 无第三方依赖（说明性注释）
```
