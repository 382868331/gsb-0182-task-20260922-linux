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
import os
import struct
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
    "DuplicateKeyError",
    "build",
    "lookup",
    "fetch",
    "dumps",
    "loads",
    "save",
    "load",
    "ArchiveFormatError",
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

#: 归档魔数与格式版本（v1 为键 + 变长内容的自描述二进制格式）。
_MAGIC: Final = b"MPHF0001"


class ArchiveFormatError(ValueError):
    """归档字节流损坏、截断、长度越界或自校验失败。

    所有“按文件中的长度字段切片”的操作都先做边界检查：长度信息错误只会
    得到本异常，绝不会造成越界读取或读到其他键的内容。
    """


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
        contents:     与槽位平行的变长内容，``contents[i]`` 即 ``keys[i]``
                      对应的原始字节；未显式给定时全部为空字节串。
    """

    size: int
    vertex_count: int
    seed: int
    values: tuple[int, ...]
    keys: tuple[bytes, ...]
    attempts: int
    contents: tuple[bytes, ...] = ()

    def lookup(self, key: bytes) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`。"""
        return lookup(self, key)

    def get(self, key: bytes, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = lookup(self, key)
        return i if i != NOT_FOUND else default

    def fetch(self, key: bytes):
        """实例方法形式，语义同模块级 :func:`fetch`。"""
        return fetch(self, key)

    def get_content(self, key: bytes, default=None):
        """命中返回内容（可能是 ``b""``）；非成员返回 ``default``。

        与 :meth:`fetch` 的区别仅在于非成员语义：``default`` 默认是
        ``None``，因此空内容 ``b""`` 与不存在（``None``）天然可区分。
        """
        i = lookup(self, key)
        return self.contents[i] if i != NOT_FOUND else default

    def dumps(self) -> bytes:
        """实例方法形式，语义同模块级 :func:`dumps`。"""
        return dumps(self)

    def save(self, path: str | bytes | os.PathLike) -> None:
        """实例方法形式，语义同模块级 :func:`save`。"""
        save(self, path)


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


def build(keys, contents=None):
    """构造最小访问完美哈希表。

    Args:
        keys: 键的可迭代对象，每个键为 ASCII ``bytes``（或 bytearray /
            memoryview），1..1000 条且不得重复；空可迭代对象产生空表
            （``size == 0``，任何查询返回 :data:`NOT_FOUND`）。
        contents: 可选的、与 ``keys`` 等长等序的可迭代对象，每项为
            bytes-like，作为该键的变长内容保存（允许空字节串 ``b""``，
            这是合法内容，与“键不存在”严格区分）。省略时每个键的内容
            为空字节串。

    Returns:
        成功返回 :class:`MPHFTable`；全部 256 个 seed 均失败时返回哨兵
        :data:`CONSTRUCTION_FAILED`——表示**搜索预算耗尽**，不是输入无解
        的数学证明。

    Raises:
        TypeError:  ``keys`` 不可迭代、本身是单个 bytes-like，或某个键
            不是 bytes-like（``bool`` 也在此拒绝）。
        ValueError: 键含非 ASCII 字节、数量超过 1000。
        DuplicateKeyError: 存在重复键（ValueError 子类），消息带重复位置。
        ValueError: ``contents`` 与 ``keys`` 长度不一致。
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

    content_values: tuple[bytes, ...]
    if contents is None:
        content_values = tuple(b"" for _ in normalized)
    else:
        if isinstance(contents, (bytes, bytearray, memoryview)):
            raise TypeError(
                "contents must be an iterable of bytes values, "
                "not a single bytes-like object"
            )
        try:
            citerator = iter(contents)
        except TypeError as exc:
            raise TypeError("contents must be an iterable of bytes values") from exc
        collected: list[bytes] = []
        for cidx, raw_content in enumerate(citerator):
            if cidx >= len(normalized):
                # 不等长是明确的契约错误，立刻中止，不继续消费迭代器。
                raise ValueError(
                    f"contents has at least {cidx + 1} items but keys has "
                    f"{len(normalized)}"
                )
            if isinstance(raw_content, bool) or not isinstance(
                raw_content, (bytes, bytearray, memoryview)
            ):
                raise TypeError(
                    f"contents[{cidx}]: value must be bytes-like "
                    f"(bytes/bytearray/memoryview), got {type(raw_content).__name__}"
                )
            collected.append(bytes(raw_content))
        if len(collected) != len(normalized):
            raise ValueError(
                f"contents length {len(collected)} does not match keys length "
                f"{len(normalized)}"
            )
        content_values = tuple(collected)

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
            contents=(),
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
                contents=content_values,
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


def fetch(table: "MPHFTable | ConstructionFailure", key):
    """查询键对应的变长内容。

    Args:
        table: :func:`build` 返回的 :class:`MPHFTable`。
        key:   bytes-like；非 ASCII 字节串按必为非成员处理。

    Returns:
        成员返回其内容 ``bytes``（内容可以是空字节串 ``b""``）；
        非成员返回 :data:`NOT_FOUND`（``-1``，一个 ``int``，不可能与任何
        ``bytes`` 内容混淆），因此**空内容与不存在被严格区分**。

    Raises:
        TypeError:  表对象或键的类型错误。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 哨兵查询。
    """
    slot = lookup(table, key)
    if slot == NOT_FOUND:
        return NOT_FOUND
    return table.contents[slot]


# --------------------------------------------------------------- 归档格式

# 布局（全部多字节整数均为无符号大端）：
#
#   magic(8)=b"MPHF0001" | n uint32 | m uint32 | seed uint8 | attempts uint32
#   | n 个 uint32 顶点赋值 g
#   | n 条记录，每条 = klen uint32 | key bytes | clen uint32 | content bytes
#   | sha256(body) 32 字节
#
# 长度字段全部在切片前与“剩余可用字节”比较：错误的长度只会触发
# ArchiveFormatError，绝不越界，也不会把下一条记录或其他键的内容读出。


def _check_uint(value: object, name: str, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArchiveFormatError(f"corrupt header: {name} is not an integer")
    if value < 0 or value >= (1 << bits):
        raise ArchiveFormatError(f"corrupt header: {name} out of range")
    return value


def dumps(table: "MPHFTable") -> bytes:
    """把表（含每个键的变长内容）序列化为自校验字节串。

    Raises:
        TypeError:  ``table`` 不是 :class:`MPHFTable`（失败哨兵也被拒绝）。
    """
    if not isinstance(table, MPHFTable):
        raise TypeError(
            "table must be an MPHFTable produced by build(); "
            f"got {type(table).__name__}"
        )

    n = table.size
    m = table.vertex_count
    if len(table.keys) != n or len(table.contents) != n:
        raise ArchiveFormatError("in-memory table has inconsistent record count")
    if len(table.values) != m:
        raise ArchiveFormatError("in-memory table has inconsistent value count")

    out = bytearray()
    out += _MAGIC
    out += struct.pack(">II", n, m)
    out += struct.pack(">BI", table.seed, table.attempts)
    for g in table.values:
        out += struct.pack(">I", g)
    for key, content in zip(table.keys, table.contents):
        out += struct.pack(">I", len(key))
        out += key
        out += struct.pack(">I", len(content))
        out += content
    digest = hashlib.sha256(bytes(out)).digest()
    out += digest
    return bytes(out)


def loads(data) -> "MPHFTable":
    """从 :func:`dumps` 的字节串重建表。

    重建后槽位赋值与查询结果与保存前完全一致；非成员查询仍明确返回
    :data:`NOT_FOUND`，不会读到其他键的内容。

    Raises:
        TypeError:          ``data`` 不是 bytes-like。
        ArchiveFormatError: 截断、魔数/字段错误、长度越界或校验和不匹配。
    """
    if isinstance(data, bool) or not isinstance(
        data, (bytes, bytearray, memoryview)
    ):
        raise TypeError(
            "data must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(data).__name__}"
        )
    blob = bytes(data)

    if len(blob) < len(_MAGIC) + 32:
        raise ArchiveFormatError("archive truncated: shorter than magic + checksum")
    if blob[: len(_MAGIC)] != _MAGIC:
        raise ArchiveFormatError("bad magic: not an MPHF v1 archive")

    body = blob[:-32]
    stored_digest = blob[-32:]
    if hashlib.sha256(body).digest() != stored_digest:
        raise ArchiveFormatError("checksum mismatch: archive is corrupted")

    pos = len(_MAGIC)
    end = len(body)

    def take(count: int, what: str) -> bytes:
        nonlocal pos
        if count < 0 or pos + count > end:
            raise ArchiveFormatError(f"corrupt archive: truncated while reading {what}")
        chunk = body[pos : pos + count]
        pos += count
        return chunk

    n = _check_uint(struct.unpack(">I", take(4, "n"))[0], "n", 32)
    m = _check_uint(struct.unpack(">I", take(4, "m"))[0], "m", 32)
    if n > MAX_KEYS:
        raise ArchiveFormatError(f"corrupt header: n={n} exceeds limit {MAX_KEYS}")
    if n != 0 and m != _vertex_count(n):
        raise ArchiveFormatError(
            f"corrupt header: m={m} inconsistent with n={n} (want {_vertex_count(n)})"
        )
    if n == 0 and m != 0:
        raise ArchiveFormatError("corrupt header: empty table must have m=0")

    seed = _check_uint(struct.unpack(">B", take(1, "seed"))[0], "seed", 8)
    attempts = _check_uint(
        struct.unpack(">I", take(4, "attempts"))[0], "attempts", 32
    )

    values_list: list[int] = []
    for i in range(m):
        g = _check_uint(
            struct.unpack(">I", take(4, f"g[{i}]"))[0], f"g[{i}]", 32
        )
        if n != 0 and g >= n:
            raise ArchiveFormatError(f"corrupt value g[{i}]={g} out of range for n={n}")
        values_list.append(g)

    keys_list: list[bytes] = []
    contents_list: list[bytes] = []
    seen: set[bytes] = set()
    for i in range(n):
        klen = _check_uint(
            struct.unpack(">I", take(4, f"key[{i}].length"))[0],
            f"key[{i}].length",
            32,
        )
        # take 先与剩余长度比较：伪造的巨大 klen 在此被拒绝，不会越界。
        key = take(klen, f"key[{i}] bytes")
        if not all(ch < 0x80 for ch in key):
            raise ArchiveFormatError(f"corrupt key[{i}]: non-ASCII byte in archive")
        if key in seen:
            raise ArchiveFormatError(f"corrupt archive: duplicate key at slot {i}")
        seen.add(key)

        clen = _check_uint(
            struct.unpack(">I", take(4, f"content[{i}].length"))[0],
            f"content[{i}].length",
            32,
        )
        # 长度只用于在边界内切片；绝不会读到相邻记录。
        content = take(clen, f"content[{i}] bytes")
        keys_list.append(key)
        contents_list.append(content)

    if pos != end:
        raise ArchiveFormatError("corrupt archive: trailing bytes after all records")

    table = MPHFTable(
        size=n,
        vertex_count=m,
        seed=seed,
        values=tuple(values_list),
        keys=tuple(keys_list),
        attempts=attempts,
        contents=tuple(contents_list),
    )
    # 强不变量：重载结果的槽位必须仍是 0..n-1 的排列（保存格式被篡改导致
    # 的结构性错误即使通过校验和也无法在此被信任——校验和已排除该情形，
    # 这里做最终一致性确认）。
    if n != 0:
        slots = [lookup(table, k) for k in table.keys]
        if sorted(slots) != list(range(n)):
            raise ArchiveFormatError("corrupt archive: restored slots are not a bijection")
    return table


def save(table: "MPHFTable", path) -> None:
    """把表原子地写入文件：先写同目录临时文件再替换，失败不留半成品。

    Raises:
        TypeError: ``table`` 类型错误或 ``path`` 不是合法路径类型。
        OSError:  文件系统层面的写入/替换失败。
    """
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise TypeError(f"path must be str/bytes/os.PathLike, got {type(path).__name__}")
    payload = dumps(table)
    final = os.fspath(path)
    directory = os.path.dirname(final) or os.curdir
    fd, tmp_path = _mktemp_in(directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, final)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise


def _mktemp_in(directory: str) -> tuple[int, str]:
    """在目标目录创建唯一临时文件（标准库实现，避免引入依赖）。"""
    import uuid

    name = f".mphf-tmp-{os.getpid()}-{uuid.uuid4().hex}"
    path = os.path.join(directory, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, 0o600), path


def load(path) -> "MPHFTable":
    """从文件读取并用 :func:`loads` 校验、重建表。

    Raises:
        TypeError:          ``path`` 不是合法路径类型。
        OSError:           文件无法读取。
        ArchiveFormatError: 内容截断、长度越界、损坏或校验失败。
    """
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise TypeError(f"path must be str/bytes/os.PathLike, got {type(path).__name__}")
    with open(path, "rb") as fh:
        blob = fh.read()
    return loads(blob)
