"""压缩字典的最小访问完美哈希（Minimal Access Perfect Hash）。

公开接口（详见 README）：

    build(keys, *, first_seed=0, max_seeds=256) -> MinimalPerfectHash
    lookup(table, key) -> int | LookupStatus.NOT_FOUND
    NOT_FOUND                                  # lookup 未命中哨兵

固定方案（本题契约）：

* 键为 ASCII 字节串，条数 1 <= n <= 1000，拒绝重复键。
* 三哈希 3-均匀超图，顶点数 m = ceil(1.4 * n) = ceil(7n/5)（纯整数运算）。
* 每条边（键）的三个顶点：SHA256(seed(4字节大端) ‖ 域标签(单字节 0/1/2) ‖ key)
  转无符号大整数后模 m。
* 对超图做度 1 剥离（peeling）；全部边可剥离时，按剥离顺序的逆序给每个
  见证顶点赋值，使该边三个顶点值之和模 n 等于键的输入序号（0..n-1）。
* 某 seed 下不可完全剥离则 seed 递增重试，默认尝试 seed 0..255（最多 256 次）；
  预算耗尽抛 ConstructionFailed（status == "construction_failed"）。
* 表内保存全部完整键；lookup 命中槽位后必须再做完整字节比较，
  绝不以“哈希值落到某个槽位”判定成员关系。

整个构造过程确定性、无随机数、无浮点。
"""

from __future__ import annotations

import hashlib
from collections import deque
from enum import Enum

__all__ = [
    "build",
    "lookup",
    "peel_hypergraph",
    "MinimalPerfectHash",
    "LookupStatus",
    "NOT_FOUND",
    "MphfError",
    "InvalidKeyError",
    "InvalidParameterError",
    "DuplicateKeyError",
    "KeyLimitExceeded",
    "ConstructionFailed",
    "MAX_KEYS",
    "DEFAULT_MAX_SEEDS",
]

MAX_KEYS = 1000
DEFAULT_MAX_SEEDS = 256
_UINT32_MAX = 0xFFFFFFFF
_VERTEX_RATIO_NUM = 7   # 1.4 = 7/5
_VERTEX_RATIO_DEN = 5
_DOMAIN_TAGS = (b"\x00", b"\x01", b"\x02")


class LookupStatus(Enum):
    """lookup 的非值返回状态。"""

    NOT_FOUND = "not_found"


NOT_FOUND = LookupStatus.NOT_FOUND


# ---------------------------------------------------------------------------
# 错误语义
# ---------------------------------------------------------------------------
class MphfError(Exception):
    """本库所有错误的基类。"""


class InvalidKeyError(MphfError):
    """键不满足契约：不是 bytes/bytearray，或构造时含非 ASCII 字节。"""


class InvalidParameterError(MphfError):
    """数值/标量参数不合法（类型、范围、bool 冒充整数、NaN/Infinity 等）。"""


class DuplicateKeyError(MphfError):
    """存在重复键。

    这属于“可证明无解”：同一键不可能映射到两个不同槽位，任何完美哈希都
    不存在，重试 seed 没有意义，因此与搜索预算耗尽严格区分。
    """


class KeyLimitExceeded(MphfError):
    """键条数超过上限 1000。"""


class ConstructionFailed(MphfError):
    """seed 搜索预算耗尽仍未得到可剥离超图。

    这表示“本次预算内没找到构造”，**不**表示数学上证明无解；换 seed 预算
    理论上可能成功。与 DuplicateKeyError（可证明无解）严格区分。
    """

    status = "construction_failed"

    def __init__(self, seeds_tried: int, first_seed: int, max_seeds: int):
        self.seeds_tried = seeds_tried
        self.first_seed = first_seed
        self.max_seeds = max_seeds
        super().__init__(
            f"construction_failed: {seeds_tried} seed(s) tried "
            f"(first_seed={first_seed}, max_seeds={max_seeds}), "
            f"hypergraph was not peelable"
        )


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------
def _check_int_param(name: str, value: object) -> int:
    """整数参数校验：拒绝 bool、非整数（含 NaN/Infinity 浮点）。"""
    if isinstance(value, bool):
        raise InvalidParameterError(f"{name} must be int, got bool")
    if isinstance(value, float):
        # 显式点出 NaN/Infinity，避免“静默纠正”为某个整数。
        if value != value:
            raise InvalidParameterError(f"{name} must be int, got NaN")
        if value in (float("inf"), float("-inf")):
            raise InvalidParameterError(f"{name} must be int, got Infinity")
        raise InvalidParameterError(f"{name} must be int, got float")
    if not isinstance(value, int):
        raise InvalidParameterError(
            f"{name} must be int, got {type(value).__name__}"
        )
    return value


def _validate_build_params(first_seed: object, max_seeds: object) -> tuple[int, int]:
    first_seed = _check_int_param("first_seed", first_seed)
    max_seeds = _check_int_param("max_seeds", max_seeds)
    if not 0 <= first_seed <= _UINT32_MAX:
        raise InvalidParameterError(
            f"first_seed must fit in unsigned 32 bits "
            f"(0..{_UINT32_MAX}), got {first_seed}"
        )
    if not 1 <= max_seeds <= DEFAULT_MAX_SEEDS:
        raise InvalidParameterError(
            f"max_seeds must be in 1..{DEFAULT_MAX_SEEDS}, got {max_seeds}"
        )
    return first_seed, max_seeds


def _normalize_keys(keys: object) -> list[bytes]:
    """物化并逐键校验：可迭代、bytes/bytearray、ASCII；返回 bytes 列表。"""
    if isinstance(keys, (str, bytes, bytearray)):
        raise InvalidKeyError(
            "keys must be an iterable of bytes-like keys, "
            f"got a single {type(keys).__name__}"
        )
    try:
        iterator = iter(keys)  # type: ignore[arg-type]
    except TypeError as exc:
        raise InvalidKeyError(
            f"keys must be an iterable of bytes-like keys, "
            f"got {type(keys).__name__}"
        ) from exc

    normalized: list[bytes] = []
    for position, raw in enumerate(iterator):
        if isinstance(raw, bool) or not isinstance(raw, (bytes, bytearray)):
            raise InvalidKeyError(
                f"keys[{position}] must be bytes, got {type(raw).__name__}"
            )
        key = bytes(raw)
        for pos, byte in enumerate(key):
            if byte > 0x7F:
                raise InvalidKeyError(
                    f"keys[{position}] is not ASCII: byte 0x{byte:02X} "
                    f"at position {pos}"
                )
        normalized.append(key)
    return normalized


def _vertex_count(n: int) -> int:
    """m = ceil(7n/5) = ceil(1.4n)，纯整数精确计算，无浮点误差。"""
    return (_VERTEX_RATIO_NUM * n + _VERTEX_RATIO_DEN - 1) // _VERTEX_RATIO_DEN


# ---------------------------------------------------------------------------
# 核心算法
# ---------------------------------------------------------------------------
def _edge_vertices(key: bytes, seed: int, m: int) -> tuple[int, int, int]:
    """计算一条边的三个顶点（域标签 0/1/2 各一次 SHA256）。"""
    seed_bytes = seed.to_bytes(4, "big")
    vertices = []
    for tag in _DOMAIN_TAGS:
        digest = hashlib.sha256(seed_bytes + tag + key).digest()
        vertices.append(int.from_bytes(digest, "big") % m)
    return vertices[0], vertices[1], vertices[2]


def peel_hypergraph(
    edges: list[tuple[int, int, int]], m: int
) -> list[tuple[int, int]] | None:
    """度-1 剥离。

    顶点度按“关联次数”计数：同一条边在同一顶点出现几次就计几次
    （邻接表中保留重复边 id）。若某顶点度为 1，则它关联的唯一一条边
    可被剥离。

    返回 [(edge_id, witness_vertex), ...] 的剥离顺序；无法剥离全部边时
    返回 None（表示该超图存在非空 2-核）。
    """
    edge_count = len(edges)
    adjacency: list[list[int]] = [[] for _ in range(m)]
    degree = [0] * m
    for edge_id, vertices in enumerate(edges):
        for vertex in vertices:
            adjacency[vertex].append(edge_id)
            degree[vertex] += 1

    queue = deque(vertex for vertex, d in enumerate(degree) if d == 1)
    removed = bytearray(edge_count)
    order: list[tuple[int, int]] = []

    while queue:
        vertex = queue.popleft()
        if degree[vertex] != 1:
            continue
        edge_id = -1
        for candidate in adjacency[vertex]:
            if not removed[candidate]:
                edge_id = candidate
                break
        if edge_id < 0:
            continue
        removed[edge_id] = 1
        order.append((edge_id, vertex))
        for neighbor in edges[edge_id]:
            degree[neighbor] -= 1
            if degree[neighbor] == 1:
                queue.append(neighbor)

    if len(order) != edge_count:
        return None
    return order


def _assign_values(
    edges: list[tuple[int, int, int]],
    peel_order: list[tuple[int, int]],
    n: int,
    m: int,
) -> tuple[int, ...]:
    """逆剥离顺序赋值，使 (g[v0]+g[v1]+g[v2]) mod n == edge_id。"""
    g = [0] * m
    for edge_id, witness in reversed(peel_order):
        # witness 在剥离时度为 1，此刻尚未赋值，g[witness] == 0。
        current_sum = sum(g[v] for v in edges[edge_id])
        g[witness] = (edge_id - current_sum) % n
    return tuple(g)


def _attempt(
    keys: list[bytes], seed: int, m: int
) -> tuple[int, ...] | None:
    edges = [_edge_vertices(key, seed, m) for key in keys]
    peel_order = peel_hypergraph(edges, m)
    if peel_order is None:
        return None
    return _assign_values(edges, peel_order, len(keys), m)


# ---------------------------------------------------------------------------
# 公开数据结构与接口
# ---------------------------------------------------------------------------
class MinimalPerfectHash:
    """不可变的最小访问完美哈希表。

    属性（公开数据结构，字段固定）：
        n    : 键的数量（槽位数，值域 0..n-1）
        m    : 超图顶点数，ceil(7n/5)
        seed : 构造成功使用的 seed
        g    : 长度 m 的不可变元组，每项 0..n-1，孤立顶点为 0
        keys : 长度 n 的不可变元组，按槽位顺序保存完整键（即输入顺序）
    """

    __slots__ = ("n", "m", "seed", "g", "keys")

    def __init__(
        self,
        n: int,
        m: int,
        seed: int,
        g: tuple[int, ...],
        keys: tuple[bytes, ...],
    ):
        object.__setattr__(self, "n", n)
        object.__setattr__(self, "m", m)
        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "g", g)
        object.__setattr__(self, "keys", keys)

    def __setattr__(self, name, value):
        raise AttributeError(
            f"MinimalPerfectHash is immutable; cannot assign {name!r}"
        )

    def __delattr__(self, name):
        raise AttributeError(
            f"MinimalPerfectHash is immutable; cannot delete {name!r}"
        )

    def lookup(self, key: object):
        """返回键的槽位序号（int）；非成员返回 NOT_FOUND。

        非 ASCII 的 bytes 查询不会被拒（它不可能是成员），正常走哈希后由
        完整键比较否决；非 bytes-like 类型抛 InvalidKeyError。
        """
        if isinstance(key, bool) or not isinstance(key, (bytes, bytearray)):
            raise InvalidKeyError(
                f"lookup key must be bytes, got {type(key).__name__}"
            )
        if self.n == 0:
            return NOT_FOUND
        key = bytes(key)
        v0, v1, v2 = _edge_vertices(key, self.seed, self.m)
        slot = (self.g[v0] + self.g[v1] + self.g[v2]) % self.n
        if self.keys[slot] == key:  # 完整键确认，而非按哈希槽位判命中
            return slot
        return NOT_FOUND

    def __repr__(self) -> str:
        return f"MinimalPerfectHash(n={self.n}, m={self.m}, seed={self.seed})"


def build(
    keys: object, *, first_seed: object = 0, max_seeds: object = DEFAULT_MAX_SEEDS
) -> MinimalPerfectHash:
    """由 ASCII 字节串集合构造最小完美哈希表。

    成功返回 MinimalPerfectHash；重复键抛 DuplicateKeyError（可证明无解）；
    所有 seed 均不可剥离抛 ConstructionFailed（搜索预算耗尽，
    status == "construction_failed"）。失败时本函数不返回任何半成品对象，
    不存在部分变更。
    """
    first_seed, max_seeds = _validate_build_params(first_seed, max_seeds)
    normalized = _normalize_keys(keys)
    n = len(normalized)

    if n > MAX_KEYS:
        raise KeyLimitExceeded(f"too many keys: {n} > {MAX_KEYS}")

    seen: set[bytes] = set()
    for index, key in enumerate(normalized):
        if key in seen:
            raise DuplicateKeyError(
                f"duplicate key at index {index}: {key!r}"
            )
        seen.add(key)

    if n == 0:
        return MinimalPerfectHash(0, 0, first_seed, (), ())

    last_seed = first_seed + max_seeds - 1
    if last_seed > _UINT32_MAX:
        raise InvalidParameterError(
            f"seed range must fit in unsigned 32 bits; "
            f"last seed would be {last_seed}"
        )

    m = _vertex_count(n)
    seeds_tried = 0
    for seed in range(first_seed, first_seed + max_seeds):
        seeds_tried += 1
        g = _attempt(normalized, seed, m)
        if g is not None:
            return MinimalPerfectHash(n, m, seed, g, tuple(normalized))

    raise ConstructionFailed(seeds_tried, first_seed, max_seeds)


def lookup(table: MinimalPerfectHash, key: object):
    """模块级 lookup 等价于 table.lookup(key)。"""
    return table.lookup(key)
