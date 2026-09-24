"""压缩字典的最小访问完美哈希（Minimal Perfect Hash Function）。

两层结构：

* **不可变快照**：``build(keys)`` 在至多 1000 条 ASCII 字节串上构造
  :class:`MPHFTable`；``lookup(table, key)`` 返回键在构造输入中的序号
  （0..n-1），非成员返回 ``NOT_FOUND``。
* **增删差量层**：:class:`MPHFView` 在不修改快照的前提下记录新增键与
  墓碑；查询“先差量、后基层”；``merge(view)`` 显式生成新快照，旧快照
  仍可独立查询。

哈希定义（公开契约）：对 4 字节大端 seed、单字节域标签 ``t in {0,1,2}``：

    h_t(key) = int(SHA256(seed_be4 || bytes([t]) || key), big-endian) mod m

其中 ``m = ceil(1.4 * n)``，使用整数运算 ``(14*n + 9)//10`` 精确得到
（本模块不使用任何浮点输入或浮点运算）。

命中判定：哈希只负责把键映射到槽位 ``slot = (g[h0]+g[h1]+g[h2]) mod n``；
是否命中以槽位中保存的**完整键**逐字节比较为准，绝不以“哈希值存在”判定。
差量层同理：新增表是完整键到记录的映射，墓碑是完整键的集合。

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
    "MPHFView",
    "DuplicateKeyError",
    "DuplicateViewKeyError",
    "UnknownKeyError",
    "MergeError",
    "build",
    "lookup",
    "open_view",
    "merge",
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


class DuplicateViewKeyError(ValueError):
    """向差量层新增一个当前逻辑集合中已存在的键。"""

    def __init__(self, key: bytes):
        super().__init__(f"key already present in view: {key!r}")
        self.key = key


class UnknownKeyError(KeyError):
    """从差量层删除一个当前逻辑集合中不存在的键。

    继承自 :class:`KeyError`；消息中给出完整键值。
    """

    def __str__(self) -> str:
        # KeyError 默认 __str__ 会给消息再加引号；统一直接返回消息文本。
        return self.args[0] if self.args else ""


class MergeError(RuntimeError):
    """显式合并未能产生新快照（当前集合触发了构造预算耗尽）。"""


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


class MPHFView:
    """叠加在不可变快照之上的增删差量层。

    基层 :class:`MPHFTable` 永不被修改；本对象记录两类差量：

    * ``added``：相对基层新增的键（有序，按插入先后）；
    * ``tombstones``：相对基层删除的键（墓碑，存完整键）。

    查询顺序固定为**先差量、后基层**：

    1. 键在 ``added`` 中 → 命中（返回其差量序号 ``base.size + 位置``）；
    2. 键在 ``tombstones`` 中 → 已删除，:data:`NOT_FOUND`；
    3. 否则查基层快照，命中须通过槽位内**完整原键**逐字节验证。

    “删后重加”是干净状态：重新插入已删除的基层键时，墓碑被移除，键回到
    基层（重新删除可再次产生墓碑）。

    差量序号仅用于区分命中位置，``merge`` 后新快照会按当前逻辑集合重新
    分配紧凑序号 ``0..n'-1``，不应跨快照比较序号。

    属性:
        base:      基层不可变快照（:class:`MPHFTable`）；
        size:      当前逻辑键数（基层存活数 + 新增数）；
        added:     新增键的元组（按插入顺序）；
        tombstones: 墓碑键的元组（顺序确定，按加入先后）。
    """

    def __init__(self, table: "MPHFTable"):
        if table is CONSTRUCTION_FAILED:
            raise ValueError(
                "cannot open a view on CONSTRUCTION_FAILED: build exhausted its seed budget"
            )
        if not isinstance(table, MPHFTable):
            raise TypeError(
                f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
            )
        # dict 在 Python 3.7+ 保持插入顺序且去重；值仅为占位。
        self._added: dict[bytes, None] = {}
        self._tombstones: set[bytes] = set()
        # 墓碑的稳定展示顺序（集合本身无序）。
        self._tombstone_order: list[bytes] = []
        self.base = table

    # ------------------------------------------------------------ 状态读取

    @property
    def size(self) -> int:
        """当前逻辑集合的键数。"""
        return self.base.size - len(self._tombstones) + len(self._added)

    @property
    def added(self) -> tuple[bytes, ...]:
        return tuple(self._added)

    @property
    def tombstones(self) -> tuple[bytes, ...]:
        return tuple(self._tombstone_order)

    def keys(self) -> list[bytes]:
        """当前逻辑集合的全部键：基层存活键（原构造顺序）后接新增键。"""
        result = [k for k in self.base.keys if k not in self._tombstones]
        result.extend(self._added)
        return result

    def __contains__(self, key) -> bool:
        return self.lookup(key) != NOT_FOUND

    def __len__(self) -> int:
        return self.size

    # ------------------------------------------------------------ 变更操作

    def add(self, key) -> int:
        """新增一个键；键已存在（基层存活或差量中）时抛错，状态不变。

        Returns:
            该键在当前视图中的序号（基层成员为原构造序号；新增键为
            ``base.size + 新增位置``）。

        Raises:
            TypeError: 键不是 bytes-like（``bool`` 同样拒绝）。
            ValueError: 键含非 ASCII 字节，或逻辑集合将超过
                :data:`MAX_KEYS`。
            DuplicateViewKeyError: 键当前已存在。
        """
        b = _as_ascii_key(key, where="view.add")
        if b in self._added:
            raise DuplicateViewKeyError(b)
        if b in self._tombstones:
            # 删后重加：移除墓碑，键回到基层存活状态。逻辑键数会 +1，
            # 因此同样必须先过上限检查（满表且有墓碑时可能超限）。
            if self.size >= MAX_KEYS:
                raise ValueError(
                    f"too many keys: limit is {MAX_KEYS}, view already holds {self.size}"
                )
            self._tombstones.remove(b)
            self._tombstone_order.remove(b)
            return lookup(self.base, b)
        base_slot = lookup(self.base, b)
        if base_slot != NOT_FOUND:
            raise DuplicateViewKeyError(b)
        if self.size >= MAX_KEYS:
            raise ValueError(
                f"too many keys: limit is {MAX_KEYS}, view already holds {self.size}"
            )
        self._added[b] = None
        return self.base.size + len(self._added) - 1

    def remove(self, key) -> int:
        """删除一个当前存在的键并写入墓碑；键不存在时抛错，状态不变。

        Returns:
            被删键在删除前的序号。

        Raises:
            TypeError:  键不是 bytes-like（``bool`` 同样拒绝）。
            UnknownKeyError: 键不在当前逻辑集合中（本就被删或从未存在）。
        """
        b = _as_ascii_key(key, where="view.remove")
        if b in self._added:
            slot = self.base.size + list(self._added).index(b)
            del self._added[b]
            # 新增键从未进入基层：直接消失即可，不留墓碑
            # （墓碑只用于遮盖基层键）。
            return slot
        if b in self._tombstones:
            raise UnknownKeyError(f"unknown key for remove: {b!r} (already deleted)")
        base_slot = lookup(self.base, b)
        if base_slot == NOT_FOUND:
            raise UnknownKeyError(f"unknown key for remove: {b!r}")
        self._tombstones.add(b)
        self._tombstone_order.append(b)
        return base_slot

    # ------------------------------------------------------------ 查询

    def lookup(self, key) -> int:
        """实例方法形式，语义同模块级 :func:`lookup`（支持视图）。"""
        return lookup(self, key)

    def get(self, key, default=None):
        """非成员返回 ``default`` 的便捷方法。"""
        i = self.lookup(key)
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


def _as_key_bytes(key, where: str = "lookup") -> bytes:
    """查询键的类型校验与归一化；非 ASCII 不在此拦截（按非成员处理）。"""
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{where}: key must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(key).__name__}"
        )
    return bytes(key)


def lookup(table: "MPHFTable | MPHFView | ConstructionFailure", key) -> int:
    """查询键的序号。

    Args:
        table: :func:`build` 返回的 :class:`MPHFTable`，或
            :func:`open_view` 得到的 :class:`MPHFView`。视图查询按
            “先差量、后基层”解析：差量新增命中优先，墓碑遮盖基层，
            最后才查基层快照。
        key:   bytes-like；非 ASCII 字节串按必为非成员处理（返回
            :data:`NOT_FOUND`，不抛错）。

    Returns:
        成员返回其序号；非成员返回 :data:`NOT_FOUND`（-1）。快照上为
        构造序号 ``0..n-1``；视图中新增键的序号为
        ``base.size + 新增位置``（合并后会重新编号，勿跨快照比较）。
        命中始终以完整键比较为准：即使非成员的哈希恰好落到某个槽位，
        键不相等仍判定为非成员。

    Raises:
        TypeError:  表对象类型错误，或键不是 bytes-like（bool 同样拒绝）。
        ValueError: 对 :data:`CONSTRUCTION_FAILED` 哨兵查询。
    """
    if isinstance(table, MPHFView):
        raw = _as_key_bytes(key)
        # 1) 差量新增表：完整键精确匹配。
        if raw in table._added:
            return table.base.size + list(table._added).index(raw)
        # 2) 墓碑：已删除的基层键，即使基层哈希命中也不得复活。
        if raw in table._tombstones:
            return NOT_FOUND
        # 3) 基层：完整键终检。
        return _lookup_table(table.base, raw)
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot lookup in CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable or MPHFView, got {type(table).__name__}"
        )
    return _lookup_table(table, _as_key_bytes(key))


def _lookup_table(table: "MPHFTable", raw: bytes) -> int:
    """在不可变快照上查询（``raw`` 已由调用方校验为 bytes）。"""
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


def open_view(table: "MPHFTable") -> "MPHFView":
    """在不可变快照上打开一个增删差量层。

    快照本身永不被修改；多个视图互不影响。详见 :class:`MPHFView`。

    Raises:
        TypeError:  ``table`` 不是 :class:`MPHFTable`。
        ValueError: ``table`` 是 :data:`CONSTRUCTION_FAILED` 哨兵。
    """
    return MPHFView(table)


def merge(view: "MPHFView") -> "MPHFTable":
    """显式合并：把视图的当前逻辑集合构造成**新**的不可变快照。

    视图与其基层快照都不被修改：旧快照在合并后仍可独立查询，视图也可
    继续累积差量。新快照的序号按当前集合（基层存活键原顺序后接新增键）
    从 0 重新分配。

    Returns:
        新的 :class:`MPHFTable`。

    Raises:
        TypeError:  ``view`` 不是 :class:`MPHFView`。
        MergeError: 当前集合在 256 个 seed 下均构造失败
            （:func:`build` 返回 :data:`CONSTRUCTION_FAILED`）；此时视图与
            旧快照保持原样，可继续使用。
    """
    if not isinstance(view, MPHFView):
        raise TypeError(
            f"merge expects an MPHFView, got {type(view).__name__}"
        )
    new_table = build(view.keys())
    if new_table is CONSTRUCTION_FAILED:
        raise MergeError(
            "merge failed: rebuild exhausted the 256-seed budget for the "
            f"current set of {view.size} keys; the view and old snapshot are unchanged"
        )
    return new_table
