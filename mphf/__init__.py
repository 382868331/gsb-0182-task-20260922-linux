"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
* ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
  非成员返回 ``NOT_FOUND``。

在该核心之上另有**自带值的只读字典层**（离线发布用，键与值同处一个快照
文件，无需另配值文件）：

* ``build_kv(items)`` 接受无序 ``(key, value)`` 对，按键字节序固定顺序后
  复用上面的完美哈希构造；值限定 ``bytes``，单项至多 4096 字节；
* ``find(d, key)`` 经现有完美哈希定位槽位、核对完整键后返回
  ``(found, value)``：空值 ``b""`` 是有效命中 ``(True, b"")``，未命中为
  ``(False, None)``，两种情况不会混淆；
* ``dumps``/``loads``/``dump``/``load`` 使用自研二进制只读快照（格式见
  README“快照字节布局”）；载入只做字节解析与全量结构校验，**不**调用
  ``build`` 重建，也**不**使用 pickle 等对象反序列化。

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
    "MAX_VALUE_BYTES",
    "SNAPSHOT_MAGIC",
    "SNAPSHOT_VERSION",
    "SNAPSHOT_HEADER_SIZE",
    "KVDictionary",
    "SnapshotError",
    "build_kv",
    "find",
    "dumps",
    "loads",
    "dump",
    "load",
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


# =====================================================================
# 自带值的只读字典层（键值构建 / 查询 / 可持久化快照）
#
# 快照字节布局（全部多字节整数为大端；除校验和字段外的全部字节参与
# SHA-256 校验和计算，校验和为完整 32 字节摘要，放在文件末尾）：
#
#   头部，固定 64 字节：
#     0   8   魔数 b"MPHFKV01"
#     8   4   格式版本 u32，当前唯一合法值 1
#     12  4   n  u32  键数量，0..1000
#     16  4   m  u32  顶点数；n>0 时必须恰为 (14n+9)//10，n=0 时必须为 0
#     20  4   seed u32  索引参数；n>0 时 0..255，n=0 时必须为 0
#     24  4   key_bytes u32  K 段键净载荷总长度（不含各记录 4 字节长度前缀）
#     28  4   value_bytes u32  V 段值净载荷总长度（不含前缀）
#     32  32  校验和：对文件其余全部字节（头部其他字段+G/K/V 段）的 SHA-256
#   G 段：m 个 u16，顶点赋值表 g，每个值必须 < n（n=0 时本段为空）
#   K 段：n 条键记录，各为 [klen u32][key 字节]；键按槽位号 0..n-1 排列，
#         且必须严格递增（字节序）、ASCII、互不重复
#   V 段：n 条值记录，各为 [vlen u32][value 字节]，vlen ≤ 4096，
#         与 K 段同槽位一一对应
#
#   文件总长度 = 64 + 2m + (4n + key_bytes) + (4n + value_bytes)，
#   任何截断或尾部多余字节都拒绝。
# =====================================================================

#: 单个值的最大字节数（接口边界）。
MAX_VALUE_BYTES: Final = 4096

#: 快照魔数（头部前 8 字节）。
SNAPSHOT_MAGIC: Final = b"MPHFKV01"

#: 当前快照格式版本。
SNAPSHOT_VERSION: Final = 1

#: 快照头部长度（含校验和字段）。
SNAPSHOT_HEADER_SIZE: Final = 64

_HEADER_STRUCT: Final = struct.Struct(">8sIIIIII")
_CHECKSUM_OFFSET: Final = 32
_U32: Final = struct.Struct(">I")
_U16: Final = struct.Struct(">H")


class SnapshotError(ValueError):
    """快照字节违反格式或内部一致性（ValueError 子类）。

    未知版本、截断、尾部多余数据、校验和不符、键重复/乱序/非 ASCII、
    索引结构非法、键不在自己的槽位等一律抛此异常；消息带可定位的上下文。
    """


class KVDictionary:
    """不可变的只读键值字典：完美哈希索引 + 与槽位一一对应的值。

    查询**只**通过完美哈希定位槽位并核对完整键，不做整表字典查找。
    实例不持有任何文件句柄，载入后源文件即可关闭。
    """

    __slots__ = ("_table", "_values")

    def __init__(self, table: MPHFTable, values: tuple[bytes, ...]):
        if len(values) != table.size:  # 内部不变量，正常路径不会触发
            raise ValueError("values length must equal table size")
        self._table = table
        self._values = values

    @property
    def table(self) -> MPHFTable:
        """底层完美哈希表（含槽位上的完整键）。"""
        return self._table

    @property
    def size(self) -> int:
        """键值对数量 n。"""
        return self._table.size

    def __len__(self) -> int:
        return self._table.size

    def keys(self) -> tuple[bytes, ...]:
        """按槽位序的全部键。"""
        return self._table.keys

    def values(self) -> tuple[bytes, ...]:
        """按槽位序的全部值（与 :meth:`keys` 一一对应）。"""
        return self._values

    def items(self) -> tuple[tuple[bytes, bytes], ...]:
        """按槽位序的 ``(key, value)`` 对。"""
        return tuple(zip(self._table.keys, self._values))

    def find(self, key) -> tuple[bool, "bytes | None"]:
        """成员查询，语义同模块级 :func:`find`。"""
        return find(self, key)

    def get(self, key, default=None):
        """命中返回值（空值 ``b""`` 原样返回），未命中返回 ``default``。"""
        found, value = find(self, key)
        return value if found else default

    def __contains__(self, key) -> bool:
        try:
            found, _ = find(self, key)
        except TypeError:
            return False
        return found

    def __getitem__(self, key) -> bytes:
        found, value = find(self, key)
        if not found:
            raise KeyError(key)
        return value


def _as_value(raw: object, where: str) -> bytes:
    """校验并归一化单个值：严格 bytes，长度 ≤ MAX_VALUE_BYTES。"""
    if isinstance(raw, bool) or not isinstance(raw, bytes):
        raise TypeError(
            f"{where}: value must be bytes, got {type(raw).__name__}"
        )
    if len(raw) > MAX_VALUE_BYTES:
        raise ValueError(
            f"{where}: value too long: {len(raw)} bytes > {MAX_VALUE_BYTES}"
        )
    return raw


def build_kv(items) -> "KVDictionary | ConstructionFailure":
    """由无序 ``(key, value)`` 对构造只读键值字典。

    构造前按键的**字节序**固定排序，因此同一内容集合无论传入顺序如何，
    得到的字典（以及其快照字节）完全相同。重复键直接抛
    :class:`DuplicateKeyError`，绝不悄悄覆盖。

    Args:
        items: ``(key, value)`` 二元组的可迭代对象。键规则同 :func:`build`
            （ASCII bytes-like，至多 1000 条，不得重复）；值必须是
            ``bytes``（不接受 bytearray/memoryview/str），单项至多
            :data:`MAX_VALUE_BYTES`（4096）字节，空值 ``b""`` 合法。

    Returns:
        成功返回 :class:`KVDictionary`；256 个 seed 全部失败时返回哨兵
        :data:`CONSTRUCTION_FAILED`（与 :func:`build` 同一失败语义）。

    Raises:
        TypeError:  容器/项/键/值类型错误（值只接受 bytes）。
        ValueError: 键非 ASCII、键数超上限、值超长。
        DuplicateKeyError: 存在重复键（ValueError 子类）。
    """
    if isinstance(items, (bytes, bytearray, memoryview)):
        raise TypeError(
            "items must be an iterable of (key, value) pairs, "
            "not a single bytes-like object"
        )
    try:
        iterator = iter(items)
    except TypeError as exc:
        raise TypeError("items must be an iterable of (key, value) pairs") from exc

    pairs: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    for idx, raw in enumerate(iterator):
        if idx >= MAX_KEYS:
            raise ValueError(
                f"too many items: limit is {MAX_KEYS}, input has at least {idx + 1}"
            )
        if isinstance(raw, (bytes, bytearray, memoryview)) or not isinstance(
            raw, (tuple, list)
        ):
            raise TypeError(
                f"items[{idx}]: each item must be a (key, value) pair, "
                f"got {type(raw).__name__}"
            )
        if len(raw) != 2:
            raise ValueError(
                f"items[{idx}]: each item must be a (key, value) pair of "
                f"length 2, got length {len(raw)}"
            )
        key = _as_ascii_key(raw[0], where=f"items[{idx}] key")
        value = _as_value(raw[1], where=f"items[{idx}] value")
        if key in seen:
            raise DuplicateKeyError(key, idx)
        seen.add(key)
        pairs.append((key, value))

    # 构建前按键字节序固定排序：快照与输入顺序无关。
    pairs.sort(key=lambda kv: kv[0])
    sorted_keys = tuple(k for k, _ in pairs)
    sorted_values = tuple(v for _, v in pairs)

    table = build(sorted_keys)
    if table is CONSTRUCTION_FAILED:
        return CONSTRUCTION_FAILED
    assert isinstance(table, MPHFTable)  # build 只会返回表或哨兵
    return KVDictionary(table, sorted_values)


def find(dictionary: KVDictionary, key) -> tuple[bool, "bytes | None"]:
    """查询键对应的值。

    经现有完美哈希定位槽位并核对槽位中的完整键（复用 :func:`lookup`，
    不做整表字典查找）。

    Returns:
        ``(True, value)`` 命中——空值 ``b""`` 也是有效命中，返回
        ``(True, b"")``；``(False, None)`` 未命中（含非 ASCII 查询）。
        两种情况有明确标志区分。

    Raises:
        TypeError:  字典或键类型错误（bool 同样拒绝）。
    """
    if not isinstance(dictionary, KVDictionary):
        raise TypeError(
            f"dictionary must be a KVDictionary, got {type(dictionary).__name__}"
        )
    slot = lookup(dictionary._table, key)
    if slot == NOT_FOUND:
        return (False, None)
    return (True, dictionary._values[slot])


# ------------------------------------------------------------------ 快照


def dumps(dictionary: KVDictionary) -> bytes:
    """把只读字典序列化为快照字节（格式见模块 docstring / README）。

    输出完全确定：同一内容集合无论当初以何种顺序传入 :func:`build_kv`，
    快照字节逐位相同。
    """
    if not isinstance(dictionary, KVDictionary):
        raise TypeError(
            f"dictionary must be a KVDictionary, got {type(dictionary).__name__}"
        )
    table = dictionary._table
    n = table.size
    m = table.vertex_count

    g_section = b"".join(_U16.pack(g) for g in table.values)
    k_section = b"".join(_U32.pack(len(k)) + k for k in table.keys)
    v_section = b"".join(_U32.pack(len(v)) + v for v in dictionary._values)

    key_bytes = sum(len(k) for k in table.keys)
    value_bytes = sum(len(v) for v in dictionary._values)
    body = g_section + k_section + v_section

    checksum = hashlib.sha256()
    head_wo_sum = _HEADER_STRUCT.pack(
        SNAPSHOT_MAGIC, SNAPSHOT_VERSION, n, m, table.seed, key_bytes, value_bytes
    )
    checksum.update(head_wo_sum)
    checksum.update(body)
    return head_wo_sum + checksum.digest() + body


def dump(dictionary: KVDictionary, file) -> None:
    """把快照写入路径（str/PathLike）或二进制文件对象。"""
    data = dumps(dictionary)
    if isinstance(file, (str, os.PathLike)):
        with open(file, "wb") as fh:
            fh.write(data)
        return
    write = getattr(file, "write", None)
    if write is None:
        raise TypeError(
            f"file must be a path or a binary file object, got {type(file).__name__}"
        )
    write(data)


def loads(data) -> KVDictionary:
    """从快照字节载入只读字典。

    只做字节解析与全量校验：**不**调用 :func:`build` 重建，**不**执行
    pickle 之类的对象反序列化。校验顺序：先长度与上限，再校验和，然后
    键唯一/键序/索引结构/每键落槽，全部通过才返回可查询对象；任何一项
    失败抛 :class:`SnapshotError`。校验和正确不代表内部合法，内部结构
    一律独立重验。

    Raises:
        TypeError:     ``data`` 不是 bytes-like。
        SnapshotError: 任何格式或一致性违例（ValueError 子类）。
    """
    if isinstance(data, bool) or not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"snapshot data must be bytes-like, got {type(data).__name__}"
        )
    raw = bytes(data)

    # ---- 1. 长度与上限（先于一切内容解释）----
    if len(raw) < SNAPSHOT_HEADER_SIZE:
        raise SnapshotError(
            f"truncated snapshot: {len(raw)} bytes < {SNAPSHOT_HEADER_SIZE} header"
        )
    magic, version, n, m, seed, key_bytes, value_bytes = _HEADER_STRUCT.unpack(
        raw[:_CHECKSUM_OFFSET]
    )
    if magic != SNAPSHOT_MAGIC:
        raise SnapshotError(f"bad magic: {magic!r} (expected {SNAPSHOT_MAGIC!r})")
    if version != SNAPSHOT_VERSION:
        raise SnapshotError(
            f"unsupported snapshot version {version} (expected {SNAPSHOT_VERSION})"
        )
    if n > MAX_KEYS:
        raise SnapshotError(f"key count n={n} exceeds limit {MAX_KEYS}")
    if n == 0:
        if m != 0:
            raise SnapshotError(f"empty snapshot must have m=0, got m={m}")
        if seed != 0:
            raise SnapshotError(f"empty snapshot must have seed=0, got seed={seed}")
        if key_bytes != 0 or value_bytes != 0:
            raise SnapshotError(
                f"empty snapshot must have zero payload, got "
                f"key_bytes={key_bytes}, value_bytes={value_bytes}"
            )
    else:
        expected_m = _vertex_count(n)
        if m != expected_m:
            raise SnapshotError(
                f"vertex count m={m} inconsistent with n={n} (expected {expected_m})"
            )
        if seed >= MAX_SEED_ATTEMPTS:
            raise SnapshotError(f"seed {seed} out of range 0..{MAX_SEED_ATTEMPTS - 1}")
    if value_bytes > n * MAX_VALUE_BYTES:
        raise SnapshotError(
            f"declared value payload {value_bytes} exceeds {n} * {MAX_VALUE_BYTES}"
        )
    expected_total = (
        SNAPSHOT_HEADER_SIZE + 2 * m + 4 * n + key_bytes + 4 * n + value_bytes
    )
    if len(raw) < expected_total:
        raise SnapshotError(
            f"truncated snapshot: {len(raw)} bytes < expected {expected_total}"
        )
    if len(raw) > expected_total:
        raise SnapshotError(
            f"trailing data: {len(raw) - expected_total} extra bytes after snapshot"
        )

    # ---- 2. 校验和（结构界限确认之后、内容解释之前）----
    stored_sum = raw[_CHECKSUM_OFFSET:SNAPSHOT_HEADER_SIZE]
    actual_sum = hashlib.sha256(raw[:_CHECKSUM_OFFSET] + raw[SNAPSHOT_HEADER_SIZE:]).digest()
    if stored_sum != actual_sum:
        raise SnapshotError("checksum mismatch: snapshot bytes are corrupted")

    # ---- 3. 解析各段（界限已确认，切片不会越界；损坏的长度前缀统一转成
    #         SnapshotError，不让 struct.error 等低层异常逃逸）----
    try:
        offset = SNAPSHOT_HEADER_SIZE
        g_section = raw[offset:offset + 2 * m]
        offset += 2 * m
        values_g = tuple(_U16.unpack_from(g_section, 2 * i)[0] for i in range(m))

        k_end = offset + 4 * n + key_bytes
        keys: list[bytes] = []
        for _ in range(n):
            klen = _U32.unpack_from(raw, offset)[0]
            offset += 4
            if offset + klen > k_end:
                raise SnapshotError(
                    f"key record overruns K section (declared key_bytes={key_bytes})"
                )
            keys.append(bytes(raw[offset:offset + klen]))
            offset += klen
        if offset != k_end:
            raise SnapshotError(
                f"K section boundary mismatch: consumed {offset - (SNAPSHOT_HEADER_SIZE + 2 * m)} "
                f"bytes, expected {4 * n + key_bytes}"
            )

        v_end = len(raw)
        vals: list[bytes] = []
        for _ in range(n):
            vlen = _U32.unpack_from(raw, offset)[0]
            offset += 4
            if offset + vlen > v_end:
                raise SnapshotError(
                    f"value record overruns V section (declared value_bytes={value_bytes})"
                )
            vals.append(bytes(raw[offset:offset + vlen]))
            offset += vlen
        if offset != v_end:
            raise SnapshotError("V section boundary mismatch")
    except SnapshotError:
        raise
    except (struct.error, IndexError) as exc:
        raise SnapshotError(f"malformed section encoding: {exc}") from exc

    # ---- 4. 键的合法性、唯一性与顺序 ----
    for i, k in enumerate(keys):
        if not all(ch < 0x80 for ch in k):
            raise SnapshotError(f"key[{i}] contains non-ASCII byte: {k!r}")
        if i > 0 and not (keys[i - 1] < k):
            if keys[i - 1] == k:
                raise SnapshotError(f"duplicate key at slot {i}: {k!r}")
            raise SnapshotError(
                f"keys out of order at slot {i}: {keys[i - 1]!r} !< {k!r}"
            )

    # ---- 5. 值长度上限 ----
    for i, v in enumerate(vals):
        if len(v) > MAX_VALUE_BYTES:
            raise SnapshotError(
                f"value[{i}] too long: {len(v)} bytes > {MAX_VALUE_BYTES}"
            )

    # ---- 6. 索引结构：g 值域 ----
    if n > 0:
        for v_i, g in enumerate(values_g):
            if g >= n:
                raise SnapshotError(
                    f"g[{v_i}]={g} out of range 0..{n - 1} (n={n})"
                )

    # ---- 7. 每个键确实落在自己的槽位（用快照内索引参数独立重算）----
    for i, k in enumerate(keys):
        v0 = _hash_vertex(seed, 0, k, m)
        v1 = _hash_vertex(seed, 1, k, m)
        v2 = _hash_vertex(seed, 2, k, m)
        slot = (values_g[v0] + values_g[v1] + values_g[v2]) % n if n else 0
        if slot != i:
            raise SnapshotError(
                f"key[{i}] {k!r} hashes to slot {slot}, not its own slot {i}"
            )

    table = MPHFTable(
        size=n,
        vertex_count=m,
        seed=seed,
        values=values_g,
        keys=tuple(keys),
        attempts=0,  # 快照不记录构造尝试次数；0 表示“来自快照”
    )
    return KVDictionary(table, tuple(vals))


def load(file) -> KVDictionary:
    """从路径（str/PathLike）或二进制文件对象载入只读字典。

    内容被完整读入内存并解析校验；返回的对象不依赖打开的文件句柄，
    载入后源文件可立即关闭。
    """
    if isinstance(file, (str, os.PathLike)):
        with open(file, "rb") as fh:
            data = fh.read()
    else:
        read = getattr(file, "read", None)
        if read is None:
            raise TypeError(
                f"file must be a path or a binary file object, got {type(file).__name__}"
            )
        data = read()
    return loads(data)
