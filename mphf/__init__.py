"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

确定性三哈希超图剥离方案：

* ``build(keys)`` 在至多 1000 条 ASCII 字节串上构造表；
* ``lookup(table, key)`` 返回键在构造输入中的序号（0..n-1），
  非成员返回 ``NOT_FOUND``；
* ``MutableIndex(table)`` 在不可变快照上叠加增删差量与墓碑，
  查询先差量后基层；``merge()`` 显式合并生成新快照，
  旧快照与新快照各自独立、均可继续查询。

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
    "MutableIndex",
    "DuplicateKeyError",
    "build",
    "lookup",
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
    """键已存在：构造输入中重复，或对 MutableIndex 重复插入。"""

    def __init__(self, key: bytes, index: int | None = None):
        if index is None:
            super().__init__(f"duplicate key: {key!r} (key already present)")
        else:
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


# ------------------------------------------------------------------ 差量索引

#: 差量字典中“无条目”的私有哨兵（None 已用作墓碑标记）。
_MISSING: Final = object()


class MutableIndex:
    """在不可变 :class:`MPHFTable` 快照上叠加增删差量（含墓碑）的索引。

    查询顺序为**先差量、后基层**：差量中的新增键直接返回其分配序号，
    墓碑键直接判非成员；差量未触及的键回落到基层快照，命中仍以槽位
    保存的完整键逐字节比较为准（与 :func:`lookup` 同一终检）。

    序号约定：

    * 基层成员的序号即快照中的构造序号 ``0..n-1``；
    * 新增键的序号从 ``快照.size`` 起单调分配，删除**不回收**序号，
      因此差量未合并前序号可能有空洞；
    * 删除基层成员留下墓碑；对墓碑键重新 :meth:`insert` 撤销墓碑，
      该键恢复其基层原序号；
    * :meth:`merge` 把当前存活键集重建为新的紧凑快照，新快照内序号
      重新从 0 连续编号——**合并前后同一键的序号可能不同**。

    合并是纯函数：本索引、其基层快照在合并后均保持原样、照常可查。
    本类不是线程安全的；如需并发/持久化请在调用方自行协调。
    """

    __slots__ = ("_base", "_delta", "_next_slot")

    def __init__(self, snapshot: MPHFTable):
        if snapshot is CONSTRUCTION_FAILED:
            raise ValueError(
                "cannot build a MutableIndex on CONSTRUCTION_FAILED"
            )
        if not isinstance(snapshot, MPHFTable):
            raise TypeError(
                "snapshot must be an MPHFTable produced by build(), "
                f"got {type(snapshot).__name__}"
            )
        self._base = snapshot
        # 差量：键 -> 分配序号（int）；键 -> None 表示墓碑（已删除）。
        # dict 保持插入序，merge 时新增键按插入顺序进入新快照。
        self._delta: dict[bytes, int | None] = {}
        self._next_slot = snapshot.size

    # ---------------------------------------------------------- 只读属性

    @property
    def snapshot(self) -> MPHFTable:
        """本索引叠加其上的不可变基层快照。"""
        return self._base

    @property
    def size(self) -> int:
        """当前存活键数量（基层未删 + 差量新增）。"""
        tombstones = sum(1 for v in self._delta.values() if v is None)
        added = len(self._delta) - tombstones
        return self._base.size - tombstones + added

    @property
    def pending(self) -> int:
        """尚未合并的差量条目数（新增与墓碑合计）。"""
        return len(self._delta)

    def __len__(self) -> int:
        return self.size

    # -------------------------------------------------------------- 查询

    def lookup(self, key) -> int:
        """查询键的当前序号；非成员返回 :data:`NOT_FOUND`。

        先查差量（新增命中 / 墓碑判非成员），再回落基层快照。
        非 ASCII 字节串按必为非成员处理；键类型错误抛 ``TypeError``。
        """
        if isinstance(key, bool) or not isinstance(
            key, (bytes, bytearray, memoryview)
        ):
            raise TypeError(
                "key must be bytes-like (bytes/bytearray/memoryview), "
                f"got {type(key).__name__}"
            )
        raw = bytes(key)
        entry = self._delta.get(raw, _MISSING)
        if entry is not _MISSING:
            return NOT_FOUND if entry is None else entry
        return lookup(self._base, raw)

    def get(self, key, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = self.lookup(key)
        return i if i != NOT_FOUND else default

    # -------------------------------------------------------------- 变更

    def insert(self, key) -> int:
        """插入新键，返回分配给它的序号。

        若该键是基层成员的墓碑（先删后加），撤销墓碑并恢复其基层原
        序号。校验全部通过后才修改差量，失败不留部分变更。

        Raises:
            TypeError:  键不是 bytes-like（``bool`` 同样拒绝）。
            ValueError: 键含非 ASCII 字节，或存活键数已达
                :data:`MAX_KEYS` 上限。
            DuplicateKeyError: 键当前已是成员（基层或差量新增）。
        """
        raw = _as_ascii_key(key, where="insert(key)")
        entry = self._delta.get(raw, _MISSING)
        if entry is not _MISSING:
            if entry is None:
                # 删后重加：撤销墓碑，恢复基层原序号。
                del self._delta[raw]
                return lookup(self._base, raw)
            raise DuplicateKeyError(raw)
        if lookup(self._base, raw) != NOT_FOUND:
            raise DuplicateKeyError(raw)
        if self.size >= MAX_KEYS:
            raise ValueError(
                f"index full: live keys already at limit {MAX_KEYS}"
            )
        slot = self._next_slot
        self._next_slot += 1
        self._delta[raw] = slot
        return slot

    def delete(self, key) -> None:
        """删除成员键；基层成员留下墓碑，差量新增直接抹除。

        Raises:
            TypeError:  键不是 bytes-like（``bool`` 同样拒绝）。
            ValueError: 键含非 ASCII 字节。
            KeyError:   键不是当前成员（含重复删除同一墓碑）。
        """
        raw = _as_ascii_key(key, where="delete(key)")
        entry = self._delta.get(raw, _MISSING)
        if entry is not _MISSING:
            if entry is None:
                raise KeyError(f"delete: key already deleted: {raw!r}")
            del self._delta[raw]
            return
        if lookup(self._base, raw) == NOT_FOUND:
            raise KeyError(f"delete: key not present: {raw!r}")
        self._delta[raw] = None

    # -------------------------------------------------------------- 合并

    def merge(self) -> "MPHFTable | ConstructionFailure":
        """把当前存活键集显式合并为新的不可变快照。

        新快照的键顺序确定：先是基层中未被删除的键（保持基层槽位
        顺序），再是差量新增键（保持插入顺序）；随后用与 :func:`build`
        完全相同的构造流程重建，因此结果确定性可复现。存活键数为零时
        得到空表；构造预算耗尽时返回 :data:`CONSTRUCTION_FAILED`。

        本索引与旧快照不被修改，合并后仍可照常查询。
        """
        live = [k for k in self._base.keys if self._delta.get(k, 0) is not None]
        live.extend(k for k, v in self._delta.items() if v is not None)
        return build(live)
