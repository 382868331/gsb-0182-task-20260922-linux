# 压缩字典的最小访问完美哈希（MPHF）

纯 Python 标准库实现的**最小访问完美哈希**（Minimal Access Perfect Hash）可复用库：
给定一个静态 ASCII 字节串集合，构造一个把每个键确定性映射到槽位 `0..n-1`
（无碰撞、无空洞、双射）的只读表；非成员查询一律返回 `not_found`。

## 环境与依赖

- Python **3.14.7**（Linux 原生验证；3.10+ 语法上亦可，但以 3.14.7 为准）
- **无任何第三方依赖**，仅用标准库 `hashlib`（SHA-256）、`collections.deque`、`enum`
- 完全离线：不需要网络、账号、密钥、数据库、中间件、云 API 或 Docker

## 准确命令

```bash
# 必要测试（23 个用例）
python -m unittest discover -s tests -v

# 固定输入演示（真实构造 + 真实触发两类拒绝/异常边界；实测 < 1 秒，远低于 8 秒）
python demo.py
```

## 公开接口

模块文件：`mphf.py`（直接 `import mphf`）。

```python
from mphf import build, lookup, NOT_FOUND

table = build(keys, *, first_seed=0, max_seeds=256)
slot  = lookup(table, key)        # 命中 -> int（0..n-1）；未命中 -> mphf.NOT_FOUND
slot  = table.lookup(key)         # 等价的方法形式
```

### `build(keys, *, first_seed=0, max_seeds=256) -> MinimalPerfectHash`

- `keys`：ASCII 字节串的可迭代对象（元素须为 `bytes`/`bytearray`，每个字节 ≤ `0x7F`）。
  支持空字节串 `b""`。传入单个 `bytes`/`str` 或不可迭代对象会报错。
- 键的**输入顺序即槽位顺序**：构造成功后 `lookup(table, keys[i]) == i`。
- `first_seed`：起始 seed，`int`，范围 `0 .. 2^32-1`，默认 `0`。
- `max_seeds`：尝试 seed 数，`int`，范围 `1 .. 256`，默认 `256`
  （依次尝试 `first_seed .. first_seed+max_seeds-1`，区间须落在 32 位无符号整数内）。

返回不可变对象 `MinimalPerfectHash`，公开字段（只读）：

| 字段 | 含义 |
|---|---|
| `n` | 键数（槽位数），`0 <= n <= 1000` |
| `m` | 超图顶点数，`m = ceil(7n/5) = ceil(1.4n)`，整数精确计算 |
| `seed` | 构造成功使用的 seed |
| `g` | 长度 `m` 的不可变元组，每项在 `0..n-1`，孤立顶点为 `0` |
| `keys` | 长度 `n` 的不可变元组，按槽位顺序保存**完整键** |

### `lookup(table, key)`

- `key` 须为 `bytes`/`bytearray`，否则抛 `InvalidKeyError`。
- 命中返回槽位 `int`；非成员（含非 ASCII 的 bytes 查询）返回 `NOT_FOUND`。
- 空表上任何查询均为 `NOT_FOUND`。
- **成员判定规则**：先用哈希算出候选槽位，再将 `table.keys[slot]` 与查询键做
  **完整字节比较**；哈希同槽绝不构成命中证据。

### 错误语义

| 异常 | 含义 | 分类 |
|---|---|---|
| `InvalidKeyError` | 键容器/键元素类型错误，或构造时含非 ASCII 字节（报错信息含下标与字节位置） | 非法输入 |
| `InvalidParameterError` | `first_seed`/`max_seeds` 类型或范围错误 | 非法输入 |
| `DuplicateKeyError` | 存在重复键。完美哈希**可证明不存在**，立即拒绝，不尝试任何 seed | 证明无解 |
| `KeyLimitExceeded` | 键数超过 1000 | 非法输入 |
| `ConstructionFailed` | 预算内所有 seed 都产生不可剥离超图；`exc.status == "construction_failed"`，并带 `seeds_tried/first_seed/max_seeds` | **搜索预算耗尽，不是无解证明** |

- 整数参数拒绝 `bool`（`True`/`False` 不静默当作 `1`/`0`）；拒绝 `float`，
  其中 `NaN`、`+Infinity`、`-Infinity` 在报错信息中分别点名，不做隐式取整。
- `build` 要么返回完整对象，要么抛异常，不会返回半成品，无部分变更。
- `ConstructionFailed`（预算耗尽）与 `DuplicateKeyError`（证明无解）是两类不同语义。

## 算法（题面契约的固定子集）

1. **三哈希 3-均匀超图**：`m = ceil(7n/5)` 个顶点。对每个键用三个域各算一次：
   `h_i(key) = int_from_bytes_be(SHA256(seed_be4 ‖ tag ‖ key)) mod m`，
   其中 `seed_be4` 是 seed 的 4 字节大端编码，`tag ∈ {0x00, 0x01, 0x02}`。
   键对应连接三个顶点的超边。
2. **度-1 剥离（peeling）**：顶点度按关联次数计数（同一边在同一顶点重复出现
   重复计数）；反复摘除“度为 1”的顶点所关联的唯一边，记录 `(边, 见证顶点)`。
   所有边被摘除则超图可剥离；否则存在非空 2-核。
3. **逆序赋值**：按剥离顺序的逆序，给每条边的见证顶点赋值，使
   `(g[v0] + g[v1] + g[v2]) mod n == 边序号`。见证顶点在赋值时尚未被设定，
   故每条边恰好有一个自由变量，方程恒有唯一解。
4. **seed 重试**：不可剥离则 seed 加 1 重试，最多 256 次；耗尽抛
   `ConstructionFailed`。全过程确定性，不使用随机源。
5. 空集合：直接输出空表（`n=m=0, g=(), keys=()`），不构造超图。

## 输入上限

- 键数：`0 .. 1000`（含边界，测试覆盖 1000 条与 1001 条拒绝）。
- 键内容：非空或空的 ASCII 字节串（字节 `0x00..0x7F`）；键长本身不另设上限
  （受进程内存约束）。
- seed：32 位无符号整数；单次构造最多尝试 256 个 seed。

## 设计取舍

- **保存完整键**：用约 1.4n 个小整数换取 O(1) 查询的同时，表内保留全部原始键，
  非成员由完整字节比较否决；因此查询不会被“哈希槽位存在”欺骗。
- **固定 1.4n 顶点比**：不开放装载率调节；该比率下三哈希超图以极高概率可剥离，
  默认 256 次 seed 重试对 1000 条以内的键集实际足够（但见已知限制）。
- **槽位即输入序号**：边 id 直接采用输入下标，构造结果因此同时给出“索引”，
  无需额外置换表。
- **只读、不可变**：构造后 `seed/g/keys` 等字段不可改写；静态索引没有增量更新。
- **无浮点**：顶点数用整数 `ceil(7n/5)` 精确计算，全模块无任何浮点运算，
  因此不存在浮点误差口径或容差问题。
- 查询成本固定为 3 次 SHA-256；无硬件依赖、无缓存优化。

## 已知限制（不宣称超出本契约的能力）

- 这是题面规定的**有限数学/工程子集**，不宣称兼容任何行业哈希标准或磁盘格式；
  表对象无内置序列化/持久化。
- 理论上可构造（或自然遇到）256 个 seed 全部不可剥离的键集，此时返回
  `construction_failed`——它只表示本次预算未找到解，不证明无解；调用方可在
  明确知情时以更大的 `first_seed` 重新构造（单次仍至多 256 个 seed）。
- 仅接受 ASCII 字节串；`str` 不做隐式编码，请显式 `.encode("ascii")`。
- 构造与查询为单线程、教学级实现；不面向对抗性计时侧信道（SHA-256 本身不依赖
  密钥，但完整键比较是普通字节比较）。
- 非 ASCII bytes 用于 `lookup` 不报错而返回 `NOT_FOUND`（它不可能是成员）；
  非 bytes-like 类型才报错。
- 不提供删除/插入/更新；键集合变化需重新 `build`。

## 测试独立性说明

`tests/test_mphf.py` 中的参照期望**不调用被测核心**取得：顶点用测试内独立的
`hashlib.sha256` 按题面公式重算，剥离判定为独立第二实现，期望槽位直接取自契约
（键的输入序号）。build→lookup 的往返一致仅作为补充断言。测试真实穷举
12 个单字符键的全部 4095 个非空子集验证双射，并在运行时确定性搜索制造
不可剥离超图（非预录结论）。

## 目录

```
mphf.py    # 核心库（build / lookup / 数据结构 / 错误类型）
demo.py    # 固定输入演示
tests/test_mphf.py  # 必要测试
README.md
```
