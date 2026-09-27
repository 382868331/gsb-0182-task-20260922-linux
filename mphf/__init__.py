"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
* ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
  非成员返回 ``NOT_FOUND``。

哈希定义（公开契约）：对 4 字节大端 seed、单字节域标签 ``t in {0,1,2}``：

    h_t(key) = int(SHA256(seed_be4 || bytes([t]) || key), big-endian) mod m

其中 ``m = ceil(1.4 * n)``，使用整数运算 ``(14*n + 9)//10`` 精确得到
（本模块不使用任何浮点输入或浮点运算）。

命中判定：哈希只负责把键映射到槽位 ``slot = (g[h0]+g[h1]+g[h2]) mod n``；
是否命中以槽位中保存的**完整键**逐字节比较为准，绝不以“哈希值存在”判定。

仅使用 Python 3.14 标准库。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from math import gcd
from typing import Final

__all__ = [
    "MAX_KEYS",
    "LOAD_FACTOR_NUM",
    "LOAD_FACTOR_DEN",
    "MAX_SEED_ATTEMPTS",
    "NOT_FOUND",
    "CONSTRUCTION_FAILED",
    "FORMAT_MAGIC",
    "FORMAT_VERSION",
    "MPHFTable",
    "DuplicateKeyError",
    "CorruptDataError",
    "build",
    "build_with_values",
    "lookup",
    "lookup_value",
    "dumps",
    "loads",
]

#: 输入键数量上限（接口边界）。
MAX_KEYS: Final = 1000

#: 负载系数 1.4 的精确有理数表示；m = ceil(p/q * n)。
LOAD_FACTOR_NUM: Final = 14
LOAD_FACTOR_DEN: Final = 10

#: seed 尝试次数上限：seed = 0..255。
MAX_SEED_ATTEMPTS: Final = 256

#: 非成员查询的返回值。
NOT_FOUND: Final = -1

#: 序列化格式的魔数与版本（dumps/loads 的线格式标识）。
FORMAT_MAGIC: Final = b"MPHF"
FORMAT_VERSION: Final = 1


class DuplicateKeyError(ValueError):
    """构造输入中出现重复键。"""

    def __init__(self, key: bytes, index: int):
        super().__init__(
            f"duplicate key at index {index}: {key!r} (keys must be unique)"
        )
        self.key = key
        self.index = index


class CorruptDataError(ValueError):
    """序列化数据损坏或格式不符（loads 抛出）。

    所有边界问题——截断、长度字段越界、尾部多余字节、非法字段值——
    都在读取前检查，绝不发生越界读取。
    """


@dataclass(frozen=True)
class ConstructionFailure:
    """构造预算耗尽的哨兵结果（不是“无解”的数学证明）。

    含义确定性：已按 seed = 0, 1, ..., 255 全部尝试，每个 seed 下要么超图
    不可完全剥离（2-核非空），要么出现当前方案无法赋值的同余方程，
    本契约的搜索预算到此为止；不代表输入集合在数学上不存在 MPHF。
    """

    attempts: int = MAX_SEED_ATTEMPTS

    def __repr__(self) -> str:  # pragma: no cover - 仅展示用
        return "construction_failed"


#: build 的失败返回单例。
CONSTRUCTION_FAILED: Final = ConstructionFailure()


@dataclass(frozen=True)
class MPHFTable:
    """不可变的构造结果。

    属性：
        size:         键数量 n；
        vertex_count: 超图顶点数 m = ceil(1.4 n)；
        seed:         成功使用的 seed（0..255）；
        values:       每个顶点的赋值 g（0..n-1），长度 m；
        keys:         槽位内容，``keys[i]`` 即构造序号为 i 的键，长度 n；
        contents:     每个键对应的变长内容，``contents[i]`` 对应序号为 i
                      的键；空元组表示本表不携带内容（build 的结果）。
        attempts:     成功前尝试的 seed 个数（成功 seed 在内，>=1）。
    """

    size: int
    vertex_count: int
    seed: int
    values: tuple[int, ...]
    keys: tuple[bytes, ...]
    contents: tuple[bytes, ...] = ()
    attempts: int = 0

    def lookup(self, key: bytes) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`。"""
        return lookup(self, key)

    def get(self, key: bytes, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = lookup(self, key)
        return i if i != NOT_FOUND else default

    def lookup_value(self, key: bytes):
        """实例方法形式，语义同模块级 :func:`lookup_value`。"""
        return lookup_value(self, key)

    def get_value(self, key: bytes, default=None):
        """查内容；非成员返回 ``default``。空内容返回 ``b""``。"""
        r = lookup_value(self, key)
        return default if r == NOT_FOUND else r


# --------------------------------------------------------------------- 内部


def _vertex_count(n: int) -> int:
    """m = ceil(1.4 * n)，纯整数运算，无浮点误差口径问题。"""
    return (LOAD_FACTOR_NUM * n + LOAD_FACTOR_DEN - 1) // LOAD_FACTOR_DEN


def _as_ascii_key(raw: object, where: str) -> bytes:
    """校验并归一化单个键；``where`` 给出可定位的上下文。"""
    if isinstance(raw, bool) or not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{where}: key must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(raw).__name__}"
        )
    b = bytes(raw)
    if not all(ch < 0x80 for ch in b):
        raise ValueError(f"{where}: non-ASCII byte in key {b!r}; only ASCII accepted")
    return b


def _hash_vertex(seed: int, tag: int, key: bytes, m: int) -> int:
    """h_t = SHA256(seed_be4 || tag || key) mod m。"""
    digest = hashlib.sha256(seed.to_bytes(4, "big") + bytes((tag,)) + key).digest()
    return int.from_bytes(digest, "big") % m


def _edges_for(
    keys: tuple[bytes, ...], seed: int, m: int
) -> list[tuple[int, int, int]]:
    edges: list[tuple[int, int, int]] = []
    for k in keys:
        edges.append(
            (
                _hash_vertex(seed, 0, k, m),
                _hash_vertex(seed, 1, k, m),
                _hash_vertex(seed, 2, k, m),
            )
        )
    return edges


def _peel(edges: list[tuple[int, int, int]], m: int) -> list[tuple[int, int]]:
    """超图剥离，返回 ``(边索引, 见证顶点)`` 的剥离顺序。

    边按其**不同**顶点的集合参与度统计（边内重复顶点只计一次）。
    剥边时记录当时度恰为 1 的那个顶点作为“见证顶点”：该顶点在剩余图中
    只属于这条边，因此逆序赋值时它必未赋值，而边上其余顶点要么已由
    后剥的边赋值、要么也为自由顶点（可安全置 0）。

    若全部边可剥离，返回长度为 n 的列表；否则长度 < n（2-核非空）。
    队列按顶点编号、邻接按边索引推进，过程完全确定性。
    """
    degree = [0] * m
    incident: list[list[int]] = [[] for _ in range(m)]
    for ei, (v0, v1, v2) in enumerate(edges):
        for v in {v0, v1, v2}:
            degree[v] += 1
            incident[v].append(ei)

    queue = [v for v in range(m) if degree[v] == 1]
    head = 0
    removed = [False] * len(edges)
    order: list[tuple[int, int]] = []

    while head < len(queue):
        v = queue[head]
        head += 1
        if degree[v] != 1:
            continue
        ei = next(e for e in incident[v] if not removed[e])
        removed[ei] = True
        order.append((ei, v))
        for w in {edges[ei][0], edges[ei][1], edges[ei][2]}:
            if w != v:
                degree[w] -= 1
                if degree[w] == 1:
                    queue.append(w)
        degree[v] = 0
    return order


def _assign(
    edges: list[tuple[int, int, int]],
    order: list[tuple[int, int]],
    n: int,
    m: int,
) -> list[int] | None:
    """按剥离顺序的逆序给顶点赋值。

    边 ei（键序号即 ei）要求：

        g[h0] + g[h1] + g[h2] ≡ ei (mod n)

    处理边 e 时，其见证顶点 v 必未赋值；边上若还有其他自由顶点（剥离末段
    整条边的顶点度都为 1 时可能出现），将它们固定为 0 后只解 v：

        c*g(v) ≡ rhs (mod n)，c = v 在三元组中的出现次数（1..3）

    方程不可解（gcd(c,n) 不整除 rhs）时返回 None，由调用方换 seed。
    """
    g = [0] * m
    assigned = [False] * m

    for ei, v in reversed(order):
        vs = edges[ei]
        if assigned[v]:  # pragma: no cover - 剥离算法的内部不变量
            return None
        # 其余自由顶点（见证顶点之外）固定为 0。
        for w in vs:
            if w != v and not assigned[w]:
                g[w] = 0
                assigned[w] = True
        coef = vs.count(v)
        rhs = ei
        for w in vs:
            if assigned[w] and w != v:
                rhs -= g[w]
        rhs %= n

        if n == 1:
            val = 0
        else:
            d = gcd(coef, n)
            if rhs % d != 0:
                return None
            mod = n // d
            inv = pow(coef // d, -1, mod)
            val = (rhs // d * inv) % n
        g[v] = val
        assigned[v] = True
    return g


def _try_seed(
    keys: tuple[bytes, ...], seed: int, n: int, m: int
) -> tuple[list[int], list[tuple[int, int, int]]] | None:
    edges = _edges_for(keys, seed, m)
    order = _peel(edges, m)
    if len(order) != n:
        return None
    values = _assign(edges, order, n, m)
    if values is None:
        return None
    return values, edges


# --------------------------------------------------------------------- 公开


def build(keys):
    """构造最小访问完美哈希表。

    Args:
        keys: 键的可迭代对象，每个键为 ASCII ``bytes``（或 bytearray /
            memoryview），1..1000 条且不得重复；空可迭代对象产生空表
            （``size == 0``，任何查询返回 :data:`NOT_FOUND`）。

    Returns:
        成功返回 :class:`MPHFTable`；全部 256 个 seed 均失败时返回哨兵
        :data:`CONSTRUCTION_FAILED`——表示**搜索预算耗尽**，不是输入无解
        的数学证明。

    Raises:
        TypeError:  ``keys`` 不可迭代、本身是单个 bytes-like，或某个键
            不是 bytes-like（``bool`` 也在此拒绝）。
        ValueError: 键含非 ASCII 字节、数量超过 1000。
        DuplicateKeyError: 存在重复键（ValueError 子类），消息带重复位置。
    """
    if isinstance(keys, (bytes, bytearray, memoryview)):
        raise TypeError(
            "keys must be an iterable of bytes keys, not a single bytes-like object"
        )
    try:
        iterator = iter(keys)
    except TypeError as exc:
        raise TypeError("keys must be an iterable of bytes keys") from exc

    normalized: list[bytes] = []
    seen: set[bytes] = set()
    for idx, raw in enumerate(iterator):
        if idx >= MAX_KEYS:
            raise ValueError(
                f"too many keys: limit is {MAX_KEYS}, input has at least {idx + 1}"
            )
        key = _as_ascii_key(raw, where=f"keys[{idx}]")
        if key in seen:
            raise DuplicateKeyError(key, idx)
        seen.add(key)
        normalized.append(key)

    return _build_from_normalized(tuple(normalized))


def _build_from_normalized(keys_tuple: tuple[bytes, ...]):
    """对已校验的键元组执行构造（build / build_with_values 共用）。"""
    n = len(keys_tuple)

    if n == 0:
        # 空集合：空表。seed/顶点数等字段取确定性零值。
        return MPHFTable(
            size=0,
            vertex_count=0,
            seed=0,
            values=(),
            keys=(),
            contents=(),
            attempts=0,
        )

    m = _vertex_count(n)
    for seed in range(MAX_SEED_ATTEMPTS):
        result = _try_seed(keys_tuple, seed, n, m)
        if result is not None:
            values, _edges = result
            return MPHFTable(
                size=n,
                vertex_count=m,
                seed=seed,
                values=tuple(values),
                keys=keys_tuple,
                contents=(),
                attempts=seed + 1,
            )
    return CONSTRUCTION_FAILED


def _as_content(raw: object, where: str) -> bytes:
    """校验并归一化单条变长内容（任意字节，不限 ASCII）。"""
    if isinstance(raw, bool) or not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{where}: content must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(raw).__name__}"
        )
    return bytes(raw)


def build_with_values(keys, values):
    """构造携带变长内容的完美哈希表。

    Args:
        keys:   与 :func:`build` 相同的键可迭代对象（同样的校验规则）。
        values: 与键一一对应的变长内容，可迭代对象；每条为 bytes-like，
            内容任意（允许非 ASCII、允许空 ``b""``）。长度必须与键数一致。

    Returns:
        成功返回携带 ``contents`` 的 :class:`MPHFTable`；
        构造预算耗尽时返回 :data:`CONSTRUCTION_FAILED`。

    Raises:
        TypeError / ValueError / DuplicateKeyError: 键的校验同 :func:`build`。
        TypeError:  内容不是 bytes-like（bool 同样拒绝），或 values 不可迭代。
        ValueError: 键数与内容数不一致。
    """
    if isinstance(values, (bytes, bytearray, memoryview)):
        raise TypeError(
            "values must be an iterable of bytes-like contents, "
            "not a single bytes-like object"
        )
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise TypeError("values must be an iterable of bytes-like contents") from exc
    contents = tuple(
        _as_content(raw, where=f"values[{idx}]")
        for idx, raw in enumerate(iterator)
    )

    table = build(keys)
    if table is CONSTRUCTION_FAILED:
        return CONSTRUCTION_FAILED
    if len(contents) != table.size:
        raise ValueError(
            f"keys/values length mismatch: {table.size} keys vs {len(contents)} values"
        )
    return MPHFTable(
        size=table.size,
        vertex_count=table.vertex_count,
        seed=table.seed,
        values=table.values,
        keys=table.keys,
        contents=contents,
        attempts=table.attempts,
    )


def lookup(table: "MPHFTable | ConstructionFailure", key) -> int:
    """查询键的序号。

    Args:
        table: :func:`build` 返回的 :class:`MPHFTable`。
        key:   bytes-like；非 ASCII 字节串按必为非成员处理。

    Returns:
        成员返回其构造序号（0..n-1）；非成员返回 :data:`NOT_FOUND`（-1）。
        命中以槽位完整键比较为准：即使非成员的哈希恰好落到某个槽位，
        键不相等仍判定为非成员。

    Raises:
        TypeError:  表对象类型错误，或键不是 bytes-like（bool 同样拒绝）。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 哨兵查询。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot lookup in CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"key must be bytes-like (bytes/bytearray/memoryview), got {type(key).__name__}"
        )
    raw = bytes(key)

    n = table.size
    if n == 0:
        return NOT_FOUND
    if not all(ch < 0x80 for ch in raw):
        return NOT_FOUND

    m = table.vertex_count
    seed = table.seed
    g = table.values
    v0 = _hash_vertex(seed, 0, raw, m)
    v1 = _hash_vertex(seed, 1, raw, m)
    v2 = _hash_vertex(seed, 2, raw, m)
    slot = (g[v0] + g[v1] + g[v2]) % n

    # 完整键终检：槽位中的键与查询键逐字节相等才命中。
    if table.keys[slot] == raw:
        return slot
    return NOT_FOUND


def lookup_value(table: "MPHFTable | ConstructionFailure", key):
    """查询键对应的变长内容。

    Args:
        table: :func:`build_with_values` 返回的 :class:`MPHFTable`。
        key:   bytes-like，规则同 :func:`lookup`。

    Returns:
        成员返回其内容 ``bytes``（空内容返回 ``b""``，与不存在明确
        区分）；非成员返回 :data:`NOT_FOUND`（`-1`）。

    Raises:
        TypeError:  表对象类型错误，或键不是 bytes-like。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 查询，或表不携带内容
            （由 :func:`build` 构造、未经 ``build_with_values``）。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot lookup in CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    if table.size > 0 and not table.contents:
        raise ValueError(
            "table carries no contents; use build_with_values() to attach values"
        )
    slot = lookup(table, key)
    if slot == NOT_FOUND:
        return NOT_FOUND
    return table.contents[slot]


# ------------------------------------------------------------------ 序列化
#
# 线格式（全部大端，无浮点）：
#   magic   4 字节   b"MPHF"
#   version u32      1
#   n       u32      键数量（<= MAX_KEYS）
#   m       u32      顶点数，必须等于 ceil(1.4 n)（n=0 时须为 0）
#   seed    u32      0..255
#   attempts u32     >=0
#   g       m × u32  顶点赋值，每个 < n（n=0 时无此段）
#   keys    n 段     每段 u32 长度 + 原始键字节（ASCII）
#   flag    u8       1 = 携带内容，0 = 不携带
#   contents n 段    仅 flag=1：每段 u64 长度 + 内容字节（任意字节）
# 之后不允许有任何多余字节。

_U32_MAX: Final = 0xFFFFFFFF


def dumps(table: MPHFTable) -> bytes:
    """把表（含内容）序列化为字节串。

    Raises:
        TypeError: 参数不是 :class:`MPHFTable`。
    """
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable, got {type(table).__name__}"
        )
    n, m = table.size, table.vertex_count
    out = bytearray()
    out += FORMAT_MAGIC
    out += FORMAT_VERSION.to_bytes(4, "big")
    out += n.to_bytes(4, "big")
    out += m.to_bytes(4, "big")
    out += table.seed.to_bytes(4, "big")
    out += table.attempts.to_bytes(4, "big")
    for gv in table.values:
        out += gv.to_bytes(4, "big")
    for k in table.keys:
        out += len(k).to_bytes(4, "big")
        out += k
    has_contents = bool(table.contents)
    out += bytes((1 if has_contents else 0,))
    if has_contents:
        for c in table.contents:
            out += len(c).to_bytes(8, "big")
            out += c
    return bytes(out)


class _Reader:
    """带边界检查的字节游标：任何读取前先验证剩余长度。"""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, count: int, what: str) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise CorruptDataError(
                f"truncated data: need {count} bytes for {what} at offset "
                f"{self.pos}, only {len(self.data) - self.pos} left"
            )
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk

    def u32(self, what: str) -> int:
        return int.from_bytes(self.take(4, what), "big")

    def u64(self, what: str) -> int:
        return int.from_bytes(self.take(8, what), "big")


def loads(data) -> MPHFTable:
    """从字节串重建表；损坏数据抛 :class:`CorruptDataError`。

    所有长度字段在使用前与剩余字节数核对，不会发生越界读取；
    字段取值（顶点数、seed、g 值范围、键的 ASCII 与唯一性、flag、
    尾部多余字节）也全部校验。重建后的表与保存前逐字段一致，
    查询行为（键的位置与结果）不变。

    Raises:
        TypeError: 参数不是 bytes-like。
        CorruptDataError: 数据截断、长度越界、字段非法或有多余字节。
    """
    if isinstance(data, bool) or not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"data must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(data).__name__}"
        )
    r = _Reader(bytes(data))

    if r.take(4, "magic") != FORMAT_MAGIC:
        raise CorruptDataError("bad magic: not an MPHF archive")
    version = r.u32("version")
    if version != FORMAT_VERSION:
        raise CorruptDataError(f"unsupported format version: {version}")

    n = r.u32("key count n")
    if n > MAX_KEYS:
        raise CorruptDataError(f"key count {n} exceeds limit {MAX_KEYS}")
    m = r.u32("vertex count m")
    expected_m = _vertex_count(n) if n else 0
    if m != expected_m:
        raise CorruptDataError(
            f"vertex count {m} inconsistent with n={n} (expected {expected_m})"
        )
    seed = r.u32("seed")
    if seed >= MAX_SEED_ATTEMPTS:
        raise CorruptDataError(f"seed {seed} out of range 0..{MAX_SEED_ATTEMPTS - 1}")
    attempts = r.u32("attempts")

    values = []
    for i in range(m):
        gv = r.u32(f"g[{i}]")
        if n and gv >= n:
            raise CorruptDataError(f"g[{i}]={gv} out of range 0..{n - 1}")
        values.append(gv)

    keys = []
    seen: set[bytes] = set()
    for i in range(n):
        klen = r.u32(f"key[{i}] length")
        # 长度先与剩余字节核对（take 内部再次检查），不据此分配超额内存。
        if klen > len(r.data) - r.pos:
            raise CorruptDataError(
                f"key[{i}] length {klen} exceeds remaining "
                f"{len(r.data) - r.pos} bytes"
            )
        k = r.take(klen, f"key[{i}]")
        if not all(ch < 0x80 for ch in k):
            raise CorruptDataError(f"key[{i}] contains non-ASCII bytes")
        if k in seen:
            raise CorruptDataError(f"duplicate key in archive: {k!r}")
        seen.add(k)
        keys.append(k)

    flag = r.take(1, "contents flag")[0]
    if flag not in (0, 1):
        raise CorruptDataError(f"contents flag must be 0 or 1, got {flag}")

    contents: list[bytes] = []
    if flag == 1:
        for i in range(n):
            clen = r.u64(f"content[{i}] length")
            if clen > len(r.data) - r.pos:
                raise CorruptDataError(
                    f"content[{i}] length {clen} exceeds remaining "
                    f"{len(r.data) - r.pos} bytes"
                )
            contents.append(r.take(clen, f"content[{i}]"))

    if r.pos != len(r.data):
        raise CorruptDataError(
            f"trailing garbage: {len(r.data) - r.pos} unexpected bytes at end"
        )

    return MPHFTable(
        size=n,
        vertex_count=m,
        seed=seed,
        values=tuple(values),
        keys=tuple(keys),
        contents=tuple(contents),
        attempts=attempts,
    )
