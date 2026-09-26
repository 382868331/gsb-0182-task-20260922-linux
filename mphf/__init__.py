"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
* ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
  非成员返回 ``NOT_FOUND``。
* ``iter_prefix(table, prefix, limit=..., cursor=...)`` 按原始字节键的
  字典序分页迭代所有以某前缀开头的键；构造时保存排序置换 ``order``、
  排序键 ``sorted_keys``、相邻键公共前缀长度 ``lcp`` 与字典指纹
  ``fingerprint``，查询只做两次二分定位候选区间，不扫描全部键。
  哈希槽号不等于排序位置，迭代顺序与槽号无关。

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
    "MPHFTable",
    "PrefixPage",
    "DuplicateKeyError",
    "CursorError",
    "build",
    "lookup",
    "iter_prefix",
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


class DuplicateKeyError(ValueError):
    """构造输入中出现重复键。"""

    def __init__(self, key: bytes, index: int):
        super().__init__(
            f"duplicate key at index {index}: {key!r} (keys must be unique)"
        )
        self.key = key
        self.index = index


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
        attempts:     成功前尝试的 seed 个数（成功 seed 在内，>=1）；
        order:        排序置换：``sorted_keys[i] is keys[order[i]]``，
                      即把构造序号排列成原始键字典序的置换，长度 n；
        sorted_keys:  按原始字节字典序排列的全部键（``order`` 作用于
                      ``keys`` 的结果），长度 n；
        lcp:          相邻键公共前缀长度，``lcp[0] == 0``，
                      ``lcp[i]``（i>=1）= 排序后第 i-1 与第 i 个键的
                      最长公共前缀长度，长度 n；
        fingerprint:  字典指纹（对排序后键集合的确定性 SHA256 十六进制），
                      游标必须绑定同一指纹；与进程地址无关。
    """

    size: int
    vertex_count: int
    seed: int
    values: tuple[int, ...]
    keys: tuple[bytes, ...]
    attempts: int
    order: tuple[int, ...] = ()
    sorted_keys: tuple[bytes, ...] = ()
    lcp: tuple[int, ...] = ()
    fingerprint: str = ""

    def lookup(self, key: bytes) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`。"""
        return lookup(self, key)

    def get(self, key: bytes, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = lookup(self, key)
        return i if i != NOT_FOUND else default

    def iter_prefix(
        self,
        prefix: bytes = b"",
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> "PrefixPage":
        """实例方法形式，语义同模块级 :func:`iter_prefix`。"""
        return iter_prefix(self, prefix, limit=limit, cursor=cursor)


@dataclass(frozen=True)
class PrefixPage:
    """前缀迭代的一页结果（不可变）。

    属性：
        keys:   按原始字节字典序排列的本页键（均以给定 prefix 开头）；
        cursor: 下一页的稳定游标；没有更多结果时为 ``None``；
        total:  该前缀在字典中的全部匹配数（二分定位得到，不扫描全表）；
        accessed: 本次查询实际访问（比较/读取）的键数，用于展示稀有前缀
                  不会触发全表扫描；包含二分比较次数与本页读取的键数。
    """

    keys: tuple[bytes, ...]
    cursor: str | None
    total: int
    accessed: int


class CursorError(ValueError):
    """游标非法、损坏，或绑定的字典指纹与当前表不一致。"""


#: 游标线格式的版本前缀。
_CURSOR_MAGIC: Final = "mphfcur1"


def _lcp_length(a: bytes, b: bytes) -> int:
    """两个字节串的最长公共前缀长度。"""
    i = 0
    bound = min(len(a), len(b))
    while i < bound and a[i] == b[i]:
        i += 1
    return i


def _fingerprint_of(sorted_keys: tuple[bytes, ...]) -> str:
    """对排序后键集合的确定性指纹；不含任何进程相关量。"""
    h = hashlib.sha256(b"mphf-fingerprint-v1\x00")
    h.update(len(sorted_keys).to_bytes(4, "big"))
    for key in sorted_keys:
        h.update(len(key).to_bytes(4, "big"))
        h.update(key)
    return h.hexdigest()


def _sorted_index(keys_tuple: tuple[bytes, ...]) -> tuple[tuple[int, ...], tuple[bytes, ...], tuple[int, ...], str]:
    """构造排序置换、排序键元组、LCP 数组与字典指纹。"""
    order = tuple(sorted(range(len(keys_tuple)), key=keys_tuple.__getitem__))
    sorted_keys = tuple(keys_tuple[i] for i in order)
    lcp = [0] * len(sorted_keys)
    for i in range(1, len(sorted_keys)):
        lcp[i] = _lcp_length(sorted_keys[i - 1], sorted_keys[i])
    return order, sorted_keys, tuple(lcp), _fingerprint_of(sorted_keys)


def _bisect_left_counted(seq: tuple[bytes, ...], target: bytes) -> tuple[int, int]:
    """与 bisect_left 等价，同时返回二分过程中访问（比较）的键数。"""
    lo, hi = 0, len(seq)
    probes = 0
    while lo < hi:
        mid = (lo + hi) // 2
        probes += 1
        if seq[mid] < target:
            lo = mid + 1
        else:
            hi = mid
    return lo, probes


def _encode_cursor(fingerprint: str, next_rank: int) -> str:
    return f"{_CURSOR_MAGIC}.{fingerprint}.{next_rank}"


def _decode_cursor(cursor: str, fingerprint: str) -> int:
    """校验游标格式与指纹，返回下一起始排序位置。"""
    parts = cursor.split(".")
    if len(parts) != 3 or parts[0] != _CURSOR_MAGIC:
        raise CursorError(f"malformed cursor: {cursor!r}")
    cursor_fp, rank_text = parts[1], parts[2]
    if cursor_fp != fingerprint:
        raise CursorError(
            "cursor is bound to a different dictionary fingerprint "
            f"({cursor_fp[:12]}...); current table is {fingerprint[:12]}..."
        )
    if not rank_text.isdigit():
        raise CursorError(f"malformed cursor rank: {cursor!r}")
    return int(rank_text)


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

    keys_tuple = tuple(normalized)
    n = len(keys_tuple)

    if n == 0:
        # 空集合：空表。seed/顶点数等字段取确定性零值。
        return MPHFTable(
            size=0,
            vertex_count=0,
            seed=0,
            values=(),
            keys=(),
            attempts=0,
            order=(),
            sorted_keys=(),
            lcp=(),
            fingerprint=_fingerprint_of(()),
        )

    m = _vertex_count(n)
    for seed in range(MAX_SEED_ATTEMPTS):
        result = _try_seed(keys_tuple, seed, n, m)
        if result is not None:
            values, _edges = result
            order, sorted_keys, lcp, fingerprint = _sorted_index(keys_tuple)
            return MPHFTable(
                size=n,
                vertex_count=m,
                seed=seed,
                values=tuple(values),
                keys=keys_tuple,
                attempts=seed + 1,
                order=order,
                sorted_keys=sorted_keys,
                lcp=lcp,
                fingerprint=fingerprint,
            )
    return CONSTRUCTION_FAILED


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


def iter_prefix(
    table: "MPHFTable | ConstructionFailure",
    prefix: bytes = b"",
    *,
    limit: int | None = None,
    cursor: str | None = None,
) -> PrefixPage:
    """按键的原始字节字典序分页迭代所有以 ``prefix`` 开头的成员。

    与 :func:`lookup` 共用同一张表；哈希槽号不是排序位置，本函数完全不
    使用槽号顺序，而是在构造时保存的 ``sorted_keys`` 上做两次二分定位：

        lo = bisect_left(sorted_keys, prefix)
        hi = bisect_left(sorted_keys, prefix + b'\\x80')

    因为全部键字节均 < 0x80，``[lo, hi)`` 恰好等于“以 prefix 开头”的
    键区间（对可能含 >= 0x80 字节的 prefix 同样成立，该区间必然为空）。
    空前缀 ``b""`` 的区间为整个排序表，即匹配全部键；零字节按普通字节
    比较。查询只读取候选区间内的本页键，不扫描全部键，实际访问数在
    :attr:`PrefixPage.accessed` 中返回。

    Args:
        table:  :func:`build` 返回的 :class:`MPHFTable`。
        prefix: bytes-like 前缀；空前缀匹配全部键；含非 ASCII 字节时
            匹配为空（与 lookup 的非成员语义一致，不报错）。
        limit:  每页最多返回的键数，正整数；``None`` 表示一次取完。
        cursor: 上一页 :attr:`PrefixPage.cursor`；首次调用传 ``None``。
            游标采用独立稳定编码 ``mphfcur1.<指纹>.<下一位置>``，不含
            任何进程地址，且只在同一字典指纹上有效。

    Returns:
        :class:`PrefixPage`；无匹配时 ``keys == ()``、``cursor is None``。

    Raises:
        TypeError:  表或 prefix 类型错误，limit 不是 int（bool 同样拒绝）。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 查询，或 limit 非正。
        CursorError: 游标格式损坏（ValueError 子类），或其绑定的字典
            指纹与 ``table`` 不一致（例如拿 A 表游标去翻 B 表）。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot iterate in CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    if isinstance(prefix, bool) or not isinstance(
        prefix, (bytes, bytearray, memoryview)
    ):
        raise TypeError(
            "prefix must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(prefix).__name__}"
        )
    prefix = bytes(prefix)
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"limit must be int or None, got {type(limit).__name__}")
        if limit < 1:
            raise ValueError(f"limit must be a positive integer or None, got {limit}")

    sorted_keys = table.sorted_keys
    fingerprint = table.fingerprint

    start = 0
    if cursor is not None:
        if not isinstance(cursor, str):
            raise TypeError(f"cursor must be str or None, got {type(cursor).__name__}")
        start = _decode_cursor(cursor, fingerprint)

    # 候选区间：[lo, hi) 恰为以 prefix 开头的键（见函数文档字符串）。
    lo, probes_lo = _bisect_left_counted(sorted_keys, prefix)
    hi, probes_hi = _bisect_left_counted(sorted_keys, prefix + b"\x80")
    if start < lo:
        start = lo

    total = hi - lo
    end = hi if limit is None else min(start + limit, hi)

    page = tuple(sorted_keys[start:end]) if start < end else ()
    next_cursor = _encode_cursor(fingerprint, end) if end < hi else None
    # 实际访问的键数 = 两次二分的比较次数 + 本页读取的键数；
    # 与 n 无关的部分只有 O(log n) 的二分探测，稀有前缀不会全表扫描。
    accessed = probes_lo + probes_hi + max(0, end - start)
    return PrefixPage(
        keys=page,
        cursor=next_cursor,
        total=total,
        accessed=accessed,
    )
