"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
 * ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
   非成员返回 ``NOT_FOUND``。
 * ``iter_prefix(table, prefix, limit=..., cursor=...)`` 按原始字节键的
   字典序迭代指定前缀的全部键，支持稳定游标分页。

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
         attempts:     成功前尝试的 seed 个数（成功 seed 在内，>=1）。
         sorted_slots: 紧凑排序置换：按键字节字典序排列的槽号，
             ``keys[sorted_slots[j]]`` 即字典序第 j 小的键。槽号本身
             与排序位置无关，必须经此置换才能得到有序输出。
         lcp:          相邻排序键的公共前缀长度，``lcp[j]`` 是字典序第 j
             与第 j+1 个键的最长公共前缀字节数，长度 n-1（n<2 时为空）。
         fingerprint:  字典指纹，SHA256(域标签 + 排序后各键的长度前缀
             编码) 的 32 字节摘要；同一键集在任何进程中的构造结果一致，
             游标凭它绑定字典。
    """

    size: int
    vertex_count: int
    seed: int
    values: tuple[int, ...]
    keys: tuple[bytes, ...]
    attempts: int
    sorted_slots: tuple[int, ...]
    lcp: tuple[int, ...]
    fingerprint: bytes

    def lookup(self, key: bytes) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`。"""
        return lookup(self, key)

    def get(self, key: bytes, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = lookup(self, key)
        return i if i != NOT_FOUND else default

    def iter_prefix(
        self,
        prefix: "bytes | None" = None,
        limit: "int | None" = None,
        cursor: "bytes | None" = None,
    ) -> "PrefixPage":
        """实例方法形式，语义同模块级 :func:`iter_prefix`。"""
        return iter_prefix(self, prefix, limit=limit, cursor=cursor)


# --------------------------------------------------------------------- 内部


def _vertex_count(n: int) -> int:
    """m = ceil(1.4 * n)，纯整数运算，无浮点误差口径问题。"""
    return (LOAD_FACTOR_NUM * n + LOAD_FACTOR_DEN - 1) // LOAD_FACTOR_DEN


def _sorted_permutation(keys: tuple[bytes, ...]) -> tuple[int, ...]:
    """紧凑排序置换：槽号按键字节字典序排列（与槽号顺序无关）。"""
    return tuple(sorted(range(len(keys)), key=keys.__getitem__))


def _lcp_lengths(sorted_keys: tuple[bytes, ...]) -> tuple[int, ...]:
    """相邻排序键的最长公共前缀字节数，长度 n-1。"""
    out: list[int] = []
    for a, b in zip(sorted_keys, sorted_keys[1:]):
        n = min(len(a), len(b))
        i = 0
        while i < n and a[i] == b[i]:
            i += 1
        out.append(i)
    return tuple(out)


def _fingerprint(sorted_keys: tuple[bytes, ...]) -> bytes:
    """字典指纹：仅由排序后的键内容决定，跨进程稳定。"""
    h = hashlib.sha256(b"MPHF-PREFIX-V1")
    h.update(len(sorted_keys).to_bytes(8, "big"))
    for k in sorted_keys:
        h.update(len(k).to_bytes(4, "big"))
        h.update(k)
    return h.digest()


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

    sorted_slots = _sorted_permutation(keys_tuple)
    sorted_keys = tuple(keys_tuple[s] for s in sorted_slots)
    lcp = _lcp_lengths(sorted_keys)
    fingerprint = _fingerprint(sorted_keys)

    if n == 0:
        # 空集合：空表。seed/顶点数等字段取确定性零值。
        return MPHFTable(
            size=0,
            vertex_count=0,
            seed=0,
            values=(),
            keys=(),
            attempts=0,
            sorted_slots=(),
            lcp=(),
            fingerprint=fingerprint,
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
                attempts=seed + 1,
                sorted_slots=sorted_slots,
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


# --------------------------------------------------------------------- 前缀迭代

#: 游标编码魔数（版本标签）。
_CURSOR_MAGIC: Final = b"MPX1"
#: 游标中携带的指纹字节数。
_CURSOR_FP_LEN: Final = 8


class CursorError(ValueError):
    """游标无法解码、结构非法，或不属于当前字典。"""


@dataclass(frozen=True)
class PrefixPage:
    """一次前缀迭代的结果页。

    属性：
        keys:        本页键，按原始字节字典序排列。
        next_cursor: 继续位置的不透明稳定编码（bytes）；本页已是最后一页
            时为 ``None``。游标绑定字典指纹与前缀，不依赖进程地址，
            可跨进程、跨次运行使用。
        accessed:    本次查询实际读取的键次数（二分定位 + 命中校验 +
            逐条输出），用于证明只访问候选范围而非全表扫描。
        prefix:      本页实际使用的前缀。
    """

    keys: tuple[bytes, ...]
    next_cursor: "bytes | None"
    accessed: int
    prefix: bytes

    @property
    def done(self) -> bool:
        """是否已迭代完该前缀的全部键。"""
        return self.next_cursor is None


def _encode_cursor(table: MPHFTable, prefix: bytes, position: int) -> bytes:
    """稳定游标编码：魔数 + 指纹前缀 + 前缀字节 + 排序位置。

    纯内容编码，不含任何进程地址或对象 id，跨进程可复现。
    """
    return (
        _CURSOR_MAGIC
        + table.fingerprint[:_CURSOR_FP_LEN]
        + len(prefix).to_bytes(2, "big")
        + prefix
        + position.to_bytes(4, "big")
    )


def _decode_cursor(table: MPHFTable, cursor: object) -> tuple[bytes, int]:
    """解码并校验游标，返回 ``(前缀, 排序位置)``。"""
    if isinstance(cursor, bool) or not isinstance(cursor, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"cursor must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(cursor).__name__}"
        )
    raw = bytes(cursor)
    header = len(_CURSOR_MAGIC) + _CURSOR_FP_LEN + 2
    if len(raw) < header + 4 or not raw.startswith(_CURSOR_MAGIC):
        raise CursorError(f"malformed cursor: {raw!r}")
    fp = raw[len(_CURSOR_MAGIC):len(_CURSOR_MAGIC) + _CURSOR_FP_LEN]
    if fp != table.fingerprint[:_CURSOR_FP_LEN]:
        raise CursorError(
            "cursor belongs to a different dictionary (fingerprint mismatch)"
        )
    plen = int.from_bytes(raw[len(_CURSOR_MAGIC) + _CURSOR_FP_LEN:header], "big")
    if len(raw) != header + plen + 4:
        raise CursorError(f"malformed cursor: bad length in {raw!r}")
    prefix = raw[header:header + plen]
    position = int.from_bytes(raw[header + plen:], "big")
    if position > table.size:
        raise CursorError(
            f"malformed cursor: position {position} out of range (size={table.size})"
        )
    return prefix, position


def _lower_bound(sorted_keys: tuple[bytes, ...], prefix: bytes, start: int) -> tuple[int, int]:
    """在 ``sorted_keys[start:]`` 中二分定位 ``prefix`` 的下界。

    返回 ``(位置, 读取键次数)``；只读取 O(log n) 个键，不扫描全表。
    """
    lo, hi = start, len(sorted_keys)
    accessed = 0
    while lo < hi:
        mid = (lo + hi) // 2
        accessed += 1
        if sorted_keys[mid] < prefix:
            lo = mid + 1
        else:
            hi = mid
    return lo, accessed


def iter_prefix(
    table: "MPHFTable | ConstructionFailure",
    prefix: "bytes | None" = None,
    limit: "int | None" = None,
    cursor: "bytes | None" = None,
) -> PrefixPage:
    """按字典序列出以 ``prefix`` 开头的键（分页）。

    Args:
        table:  :func:`build` 返回的 :class:`MPHFTable`。
        prefix: 字节前缀，空前缀 ``b""`` 匹配全部键；含零字节按普通
            字节处理；非 ASCII 前缀必无匹配（返回空页）。``None`` 表示
            沿用游标中的前缀。
        limit:  本页最多返回的键数；``None`` 表示不限（返回剩余全部）。
        cursor: 上一页返回的 ``next_cursor``，从该位置继续；游标绑定
            字典指纹，跨字典使用抛 :class:`CursorError`。

    Returns:
        :class:`PrefixPage`，键按原始字节字典序排列；``accessed`` 为
        实际读取的键次数（候选范围定位 + 输出），与字典总量无关。

    Raises:
        TypeError:   表、前缀、limit 或游标类型错误（bool 同样拒绝）。
        ValueError:  对 :data:`CONSTRUCTION_FAILED` 查询；``limit < 1``；
            显式 ``prefix`` 与游标前缀不一致。
        CursorError: 游标损坏、越界或属于其他字典（ValueError 子类）。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot iterate CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    if limit is not None:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError(f"limit must be an int or None, got {type(limit).__name__}")
        if limit < 1:
            raise ValueError(f"limit must be >= 1, got {limit}")
    if prefix is not None:
        if isinstance(prefix, bool) or not isinstance(prefix, (bytes, bytearray, memoryview)):
            raise TypeError(
                f"prefix must be bytes-like (bytes/bytearray/memoryview), "
                f"got {type(prefix).__name__}"
            )
        prefix = bytes(prefix)

    if cursor is not None:
        cur_prefix, start = _decode_cursor(table, cursor)
        if prefix is not None and prefix != cur_prefix:
            raise CursorError(
                f"explicit prefix {prefix!r} does not match cursor prefix {cur_prefix!r}"
            )
        prefix = cur_prefix
    else:
        if prefix is None:
            prefix = b""
        start = 0

    sorted_keys = tuple(table.keys[s] for s in table.sorted_slots)
    n = len(sorted_keys)
    accessed = 0

    if n == 0 or start >= n or any(ch >= 0x80 for ch in prefix):
        # 空表 / 游标已越界 / 非 ASCII 前缀：必无匹配，不读任何键。
        return PrefixPage(keys=(), next_cursor=None, accessed=accessed, prefix=prefix)

    plen = len(prefix)
    if plen == 0:
        first = start  # 空前缀匹配全部，无需定位。
    else:
        first, probe = _lower_bound(sorted_keys, prefix, start)
        accessed += probe
        if first < n:
            accessed += 1
            if not sorted_keys[first].startswith(prefix):
                first = n  # 下界处的键不匹配，则无任何匹配。

    out: list[bytes] = []
    pos = first
    while pos < n and (limit is None or len(out) < limit):
        if plen and pos > first and table.lcp[pos - 1] < plen:
            break  # 相邻公共前缀不足：候选范围结束，无需再读键。
        accessed += 1
        key = sorted_keys[pos]
        if plen and pos == first and not key.startswith(prefix):
            break
        out.append(key)
        pos += 1

    more = pos < n
    if more and plen and pos > first and table.lcp[pos - 1] < plen:
        more = False  # 下一个键已确定不在候选范围内。
    next_cursor = _encode_cursor(table, prefix, pos) if more else None
    return PrefixPage(keys=tuple(out), next_cursor=next_cursor, accessed=accessed, prefix=prefix)
