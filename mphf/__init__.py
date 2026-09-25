"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
* ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
  非成员返回 ``NOT_FOUND``；
* ``build_kv(pairs)`` 在同一套完美哈希之上构造**自带值**的只读键值表
  （值为 bytes，每项至多 :data:`MAX_VALUE_LEN` 字节），构建前按键字节序
  排序，快照字节与传入顺序无关；
* ``find_kv(snap, key)`` 经完美哈希定位并核对完整键，返回
  ``(是否命中, 值)``——空值是有效命中，未命中另有布尔标志；
* :class:`KvSnapshot` 提供确定性二进制快照的 ``to_bytes`` / ``save`` /
  ``from_bytes`` / ``load``。载入只做字节解析与全面校验，**不**调用
  build 重建，也**不**使用 pickle 等对象反序列化。

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
from collections import abc as _abc
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
    # 键值只读快照
    "MAX_VALUE_LEN",
    "SNAPSHOT_MAGIC",
    "SNAPSHOT_VERSION",
    "SNAPSHOT_HEADER_SIZE",
    "KvSnapshot",
    "SnapshotFormatError",
    "UnknownSnapshotVersionError",
    "SnapshotChecksumError",
    "build_kv",
    "find_kv",
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
    """

    size: int
    vertex_count: int
    seed: int
    values: tuple[int, ...]
    keys: tuple[bytes, ...]
    attempts: int

    def lookup(self, key: bytes) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`。"""
        return lookup(self, key)

    def get(self, key: bytes, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = lookup(self, key)
        return i if i != NOT_FOUND else default


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


# ====================================================== 键值只读快照（v1）

#: 单个值的字节长度上限（接口边界）。
MAX_VALUE_LEN: Final = 4096

#: 快照魔数（ASCII "MPHKVDB"）。
SNAPSHOT_MAGIC: Final = b"MPHKVDB"

#: 快照格式版本（当前唯一支持的版本）。
SNAPSHOT_VERSION: Final = 1

#: 快照头部长度：魔数 7 + 版本 2 + n/m/seed/attempts 各 4 + 体长度 8
#: + SHA256 32 = 65 字节（7+2+16+8+32）。
SNAPSHOT_HEADER_SIZE: Final = 65

# 头部固定布局（大端）：magic(7s) version(H) n(I) m(I) seed(I) attempts(I)
# body_len(Q) body_sha256(32s)。7+2+4*4+8+32 = 65。
_HEADER = struct.Struct(">7sHIIIIQ32s")
_U32 = struct.Struct(">I")


class SnapshotFormatError(ValueError):
    """快照字节不合法（截断、尾部多余、字段越界、结构校验失败等）。"""


class UnknownSnapshotVersionError(SnapshotFormatError):
    """快照版本号不在本实现支持范围内。"""

    def __init__(self, version: int):
        super().__init__(
            f"unsupported snapshot version {version}; "
            f"supported versions: {SNAPSHOT_VERSION}"
        )
        self.version = version


class SnapshotChecksumError(SnapshotFormatError):
    """快照体 SHA256 与头部记录不一致。"""


def _as_bytes_value(raw: object, where: str) -> bytes:
    """校验并归一化单个值：必须 bytes-like，长度至多 MAX_VALUE_LEN。"""
    if isinstance(raw, bool) or not isinstance(
        raw, (bytes, bytearray, memoryview)
    ):
        raise TypeError(
            f"{where}: value must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(raw).__name__}"
        )
    b = bytes(raw)
    if len(b) > MAX_VALUE_LEN:
        raise ValueError(
            f"{where}: value is {len(b)} bytes long, limit is {MAX_VALUE_LEN}"
        )
    return b


@dataclass(frozen=True)
class KvSnapshot:
    """自带值的只读键值快照，全部状态在内存中，不持有任何文件句柄。

    键按键字节序排序后交给 :func:`build`，槽位 ``i`` 同时存放
    ``keys[i]`` 与 ``values[i]``（排序后第 i 个键及其值）。索引字段与
    :class:`MPHFTable` 同义。

    属性：
        size:         键数量 n；
        vertex_count: 超图顶点数 m = ceil(1.4 n)；
        seed:         成功使用的 seed（0..255，空表为 0）；
        attempts:     成功前尝试的 seed 个数（空表为 0）；
        values_g:     每个顶点的赋值 g（0..n-1），长度 m；
        keys:         槽位 i 的键，按键字节序升序，长度 n；
        values:       槽位 i 的值（bytes，每项至多 4096 字节），长度 n。
    """

    size: int
    vertex_count: int
    seed: int
    attempts: int
    values_g: tuple[int, ...]
    keys: tuple[bytes, ...]
    values: tuple[bytes, ...]

    # ------------------------------------------------------------ 查询

    def find(self, key) -> tuple[bool, bytes | None]:
        """实例方法形式，语义同模块级 :func:`find_kv`。"""
        return find_kv(self, key)

    def get(self, key, default=None):
        """命中返回值（含空值），未命中返回 ``default``。"""
        hit, value = find_kv(self, key)
        return value if hit else default

    def __contains__(self, key) -> bool:
        return find_kv(self, key)[0]

    def __len__(self) -> int:
        return self.size

    # ------------------------------------------------------------ 持久化

    def to_bytes(self) -> bytes:
        """序列化为确定性 v1 快照字节。

        同一键值集合无论传入 :func:`build_kv` 时的顺序如何，输出字节
        逐位相同（构建前按键字节序排序，序列化按槽位顺序）。
        """
        return _encode_snapshot(self)

    def save(self, path) -> None:
        """把快照原子写入 ``path``（``str``/``os.PathLike``）。"""
        data = self.to_bytes()
        tmp = f"{path}.tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    @classmethod
    def from_bytes(cls, data) -> "KvSnapshot":
        """从快照字节载入；只解析与校验，不 build、不做对象反序列化。"""
        if isinstance(data, bool) or not isinstance(
            data, (bytes, bytearray, memoryview)
        ):
            raise TypeError(
                "snapshot data must be bytes-like "
                f"(bytes/bytearray/memoryview), got {type(data).__name__}"
            )
        return _decode_snapshot(bytes(data))

    @classmethod
    def load(cls, path) -> "KvSnapshot":
        """从文件载入；读完即关闭句柄，返回对象不依赖该文件。"""
        with open(path, "rb") as f:
            data = f.read()
        return cls.from_bytes(data)


# ----------------------------------------------------------- 快照编解码内部


def _encode_snapshot(snap: "KvSnapshot") -> bytes:
    g = b"".join(_U32.pack(x) for x in snap.values_g)
    records = bytearray()
    for key, value in zip(snap.keys, snap.values):
        records += _U32.pack(len(key))
        records += key
        records += _U32.pack(len(value))
        records += value
    body = g + bytes(records)
    digest = hashlib.sha256(body).digest()
    header = _HEADER.pack(
        SNAPSHOT_MAGIC,
        SNAPSHOT_VERSION,
        snap.size,
        snap.vertex_count,
        snap.seed,
        snap.attempts,
        len(body),
        digest,
    )
    return header + body


def _decode_snapshot(data: bytes) -> "KvSnapshot":
    # 1) 长度：至少能放下定长头部。
    if len(data) < SNAPSHOT_HEADER_SIZE:
        raise SnapshotFormatError(
            f"snapshot too short: {len(data)} bytes, "
            f"need at least {SNAPSHOT_HEADER_SIZE}"
        )
    magic, version, n, m, seed, attempts, body_len, digest = _HEADER.unpack(
        data[:SNAPSHOT_HEADER_SIZE]
    )
    # 2) 魔数与版本。
    if magic != SNAPSHOT_MAGIC:
        raise SnapshotFormatError(
            f"bad magic: {magic!r} (expected {SNAPSHOT_MAGIC!r})"
        )
    if version != SNAPSHOT_VERSION:
        raise UnknownSnapshotVersionError(version)

    # 3) 长度闭合：体长度与文件实际长度必须精确一致（截断/多余都拒绝）。
    if len(data) != SNAPSHOT_HEADER_SIZE + body_len:
        raise SnapshotFormatError(
            f"length mismatch: header declares body of {body_len} bytes, "
            f"file has {len(data) - SNAPSHOT_HEADER_SIZE} "
            "(truncated or trailing data)"
        )
    body = data[SNAPSHOT_HEADER_SIZE:]

    # 3.5) 校验和先行：在按体内容做任何结构性解释之前，先确认体 SHA256
    #      与头部一致。注意校验和正确不代表内部合法——上限、唯一性、键序、
    #      槽位归属等结构校验在其后继续进行。
    if hashlib.sha256(body).digest() != digest:
        raise SnapshotChecksumError("body SHA256 does not match header checksum")

    # 4) 上限与索引参数（纯整数比较，先于深层结构解析）。
    if n > MAX_KEYS:
        raise SnapshotFormatError(f"key count {n} exceeds limit {MAX_KEYS}")
    if m != _vertex_count(n):
        raise SnapshotFormatError(
            f"vertex_count {m} inconsistent with key count {n}: "
            f"expected {_vertex_count(n)}"
        )
    if n == 0:
        if seed != 0 or attempts != 0:
            raise SnapshotFormatError(
                f"empty snapshot must carry seed=0 attempts=0, got "
                f"seed={seed} attempts={attempts}"
            )
    else:
        if not 0 <= seed < MAX_SEED_ATTEMPTS:
            raise SnapshotFormatError(
                f"seed {seed} out of range 0..{MAX_SEED_ATTEMPTS - 1}"
            )
        if attempts != seed + 1:
            raise SnapshotFormatError(
                f"attempts {attempts} inconsistent with seed {seed}: "
                f"expected {seed + 1}"
            )

    g_len = m * 4
    if body_len < g_len:
        raise SnapshotFormatError(
            f"body {body_len} bytes shorter than g array ({g_len} bytes)"
        )
    g = tuple(_U32.unpack(body[off : off + 4])[0] for off in range(0, g_len, 4))
    if n > 0 and any(not 0 <= x < n for x in g):
        raise SnapshotFormatError(f"g array contains a value outside 0..{n - 1}")

    # 5) 逐条解析记录：长度、上限、ASCII 规则与闭合。
    keys: list[bytes] = []
    values: list[bytes] = []
    pos = g_len

    def need(inc: int, what: str) -> None:
        if pos + inc > body_len:
            raise SnapshotFormatError(
                f"truncated record at offset {pos}: missing {what}"
            )

    while pos < body_len:
        need(4, "key length")
        klen = _U32.unpack(body[pos : pos + 4])[0]
        pos += 4
        need(klen, "key bytes")
        key = body[pos : pos + klen]
        pos += klen
        if any(ch >= 0x80 for ch in key):
            raise SnapshotFormatError(f"non-ASCII byte in stored key {bytes(key)!r}")
        need(4, "value length")
        vlen = _U32.unpack(body[pos : pos + 4])[0]
        pos += 4
        if vlen > MAX_VALUE_LEN:
            raise SnapshotFormatError(
                f"stored value length {vlen} exceeds limit {MAX_VALUE_LEN}"
            )
        need(vlen, "value bytes")
        values.append(bytes(body[pos : pos + vlen]))
        pos += vlen
        keys.append(bytes(key))
    if pos != body_len:  # pragma: no cover - 循环条件保证等长，留作防御
        raise SnapshotFormatError(f"record section not aligned at offset {pos}")
    if len(keys) != n:
        raise SnapshotFormatError(
            f"record count {len(keys)} does not match declared key count {n}"
        )

    # 6) 键唯一且严格按键字节序升序（相邻比较同时覆盖两者）。
    for i in range(1, n):
        if keys[i - 1] == keys[i]:
            raise SnapshotFormatError(f"duplicate key in snapshot: {keys[i]!r}")
        if keys[i - 1] > keys[i]:
            raise SnapshotFormatError(
                f"keys not in byte order at slot {i}: "
                f"{keys[i - 1]!r} followed by {keys[i]!r}"
            )

    # 7) 索引结构：每个键必须确实经 g 映射到自己的槽位 i。
    for i, key in enumerate(keys):
        slot = (
            g[_hash_vertex(seed, 0, key, m)]
            + g[_hash_vertex(seed, 1, key, m)]
            + g[_hash_vertex(seed, 2, key, m)]
        ) % n
        if slot != i:
            raise SnapshotFormatError(
                f"key {key!r} lives at slot {i} but the index maps it to "
                f"slot {slot}; index structure invalid"
            )

    return KvSnapshot(
        size=n,
        vertex_count=m,
        seed=seed,
        attempts=attempts,
        values_g=g,
        keys=tuple(keys),
        values=tuple(values),
    )


# --------------------------------------------------------------------- 公开


def build_kv(pairs):
    """构造自带值的只读键值快照。

    Args:
        pairs: ``(key, value)`` 对的可迭代对象（list、tuple、生成器、
            ``dict.items`` 等），也可直接传入 ``dict``。键遵守与
            :func:`build` 相同的 ASCII bytes 规则（至多 1000 个、不得
            重复）；值必须是 bytes-like 且每项至多 :data:`MAX_VALUE_LEN`
            （4096）字节，空值 ``b""`` 合法。构建前按键的**字节序**固定
            排序，因此同一键值集合无论传入顺序如何，快照字节完全相同。

    Returns:
        成功返回 :class:`KvSnapshot`；256 个 seed 全部失败时返回哨兵
        :data:`CONSTRUCTION_FAILED`（与 :func:`build` 相同的失败语义）。

    Raises:
        TypeError:  容器/键/值类型错误（``bool`` 同样拒绝）。
        ValueError: 键含非 ASCII 字节、值超长、键数超过 1000。
        DuplicateKeyError: 存在重复键，直接拒绝，不静默覆盖。
    """
    if isinstance(pairs, _abc.Mapping):
        iterator = iter(pairs.items())
    else:
        if isinstance(pairs, (bytes, bytearray, memoryview)):
            raise TypeError(
                "pairs must be an iterable of (key, value) pairs, "
                "not a single bytes-like object"
            )
        try:
            iterator = iter(pairs)
        except TypeError as exc:
            raise TypeError(
                "pairs must be an iterable of (key, value) pairs"
            ) from exc

    normalized: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for idx, pair in enumerate(iterator):
        if idx >= MAX_KEYS:
            raise ValueError(
                f"too many keys: limit is {MAX_KEYS}, input has at least {idx + 1}"
            )
        try:
            raw_key, raw_value = pair
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"pairs[{idx}]: each item must unpack to (key, value)"
            ) from exc
        key = _as_ascii_key(raw_key, where=f"pairs[{idx}] key")
        if key in seen:
            raise DuplicateKeyError(key, idx)
        seen.add(key)
        value = _as_bytes_value(raw_value, where=f"pairs[{idx}] value")
        normalized.append((key, value))

    normalized.sort(key=lambda kv: kv[0])
    ordered_keys = tuple(k for k, _ in normalized)
    ordered_values = tuple(v for _, v in normalized)
    n = len(ordered_keys)

    if n == 0:
        return KvSnapshot(
            size=0,
            vertex_count=0,
            seed=0,
            attempts=0,
            values_g=(),
            keys=(),
            values=(),
        )

    table = build(ordered_keys)
    if table is CONSTRUCTION_FAILED:
        return CONSTRUCTION_FAILED
    return KvSnapshot(
        size=table.size,
        vertex_count=table.vertex_count,
        seed=table.seed,
        attempts=table.attempts,
        values_g=table.values,
        keys=ordered_keys,
        values=ordered_values,
    )


def find_kv(snapshot, key) -> tuple[bool, bytes | None]:
    """在只读快照中按键查询。

    定位方式与 :func:`lookup` 完全一致：经现有完美哈希算出槽位，再与槽位
    中保存的完整原键逐字节核对，不做整表字典查找。

    Args:
        snapshot: :func:`build_kv` 返回或从快照载入的 :class:`KvSnapshot`。
        key:      bytes-like；非 ASCII 字节串按未命中处理。

    Returns:
        ``(True, value)`` 表示命中，``value`` 可能为空字节串；
        ``(False, None)`` 表示未命中。命中与否另有独立布尔标志，调用方
        无需（也不应）用“值是否为空”猜测命中。

    Raises:
        TypeError:  快照或键的类型错误。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 哨兵查询。
    """
    if snapshot is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot find in CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(snapshot, KvSnapshot):
        raise TypeError(
            "snapshot must be a KvSnapshot produced by build_kv() or "
            f"KvSnapshot.load(), got {type(snapshot).__name__}"
        )
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"key must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(key).__name__}"
        )
    raw = bytes(key)

    n = snapshot.size
    if n == 0:
        return False, None
    if any(ch >= 0x80 for ch in raw):
        return False, None

    m = snapshot.vertex_count
    seed = snapshot.seed
    g = snapshot.values_g
    slot = (
        g[_hash_vertex(seed, 0, raw, m)]
        + g[_hash_vertex(seed, 1, raw, m)]
        + g[_hash_vertex(seed, 2, raw, m)]
    ) % n

    # 完整键终检：哈希只负责定位，键不等就是未命中。
    if snapshot.keys[slot] == raw:
        return True, snapshot.values[slot]
    return False, None

