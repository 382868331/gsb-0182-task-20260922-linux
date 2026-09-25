"""索引认证扩展：槽位 Merkle 树与键序认证序列。

在只读键集合（:class:`mphf.MPHFTable`）上提供可离线验证的成员证明与
不存在证明：调用方只需信任**版本清单**（两棵树的根 + 总键数），不必
信任查询端。本模块是索引认证扩展，不重新实现通用链上证明系统。

两棵 Merkle 树（v1 线格式，全部 SHA256，整数一律 8 字节大端）：

* **槽位树**：叶按槽位顺序排列，叶编码槽号、键长度和键字节::

      leaf_slot = SHA256(0x00 ‖ slot_be8 ‖ keylen_be8 ‖ key)

* **键序树**（按键字节序排列的认证序列）：叶同时绑定键与原槽号::

      leaf_sorted = SHA256(0x02 ‖ slot_be8 ‖ keylen_be8 ‖ key)

* **内部节点**（两棵树共用域前缀，与叶前缀不同）::

      internal = SHA256(0x01 ‖ left ‖ right)

* 每层节点数为奇时**复制末节点**配对（末节点与自身配对）；
* **空集合根**单独定义为 ``SHA256(b"\\x03mphf-auth-empty-root-v1")``，
  两棵空树共用该根。

证明对象（``SlotProof`` / ``SortedProof`` / ``AbsenceProof``）与
``Manifest`` 的 ``encode()`` 编码确定且带版本号
``PROOF_FORMAT_VERSION == 1``。

验证器先核对路径形状（路径长度须等于该槽数下的树深）与范围
（槽号/秩须在 ``0..size-1``），再重算根比较；任何形状或范围问题
一律返回 ``False``，不抛异常（键类型错误除外，与 ``lookup`` 一致
抛 ``TypeError``）。
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass
from typing import Final

from . import CONSTRUCTION_FAILED, MPHFTable, NOT_FOUND, lookup

__all__ = [
    "PROOF_FORMAT_VERSION",
    "EMPTY_ROOT",
    "SIDE_LEFT",
    "SIDE_RIGHT",
    "SlotProof",
    "SortedProof",
    "AbsenceProof",
    "Manifest",
    "AuthenticatedIndex",
    "build_authenticated",
    "verify_membership",
    "verify_absence",
]

#: 证明编码格式版本。
PROOF_FORMAT_VERSION: Final = 1

#: 兄弟节点在当前节点左侧（当前节点为右孩子）。
SIDE_LEFT: Final = 0
#: 兄弟节点在当前节点右侧（当前节点为左孩子）。
SIDE_RIGHT: Final = 1

_LEAF_SLOT_PREFIX: Final = b"\x00"
_INTERNAL_PREFIX: Final = b"\x01"
_LEAF_SORTED_PREFIX: Final = b"\x02"

#: 空集合根（两棵空树共用），单独定义，不与任何叶/内部节点编码冲突。
EMPTY_ROOT: Final = hashlib.sha256(b"\x03mphf-auth-empty-root-v1").digest()

_HASH_LEN: Final = 32


# --------------------------------------------------------------------- 编码


def _u64(x: int) -> bytes:
    return x.to_bytes(8, "big")


def _slot_leaf(slot: int, key: bytes) -> bytes:
    """槽位树叶：绑定槽号、键长度与键字节。"""
    return hashlib.sha256(
        _LEAF_SLOT_PREFIX + _u64(slot) + _u64(len(key)) + key
    ).digest()


def _sorted_leaf(slot: int, key: bytes) -> bytes:
    """键序树叶：同时绑定键与原槽号。"""
    return hashlib.sha256(
        _LEAF_SORTED_PREFIX + _u64(slot) + _u64(len(key)) + key
    ).digest()


def _internal(left: bytes, right: bytes) -> bytes:
    """内部节点：与叶不同的域前缀。"""
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


# --------------------------------------------------------------------- 构树


def _tree_levels(leaves: list[bytes]) -> list[list[bytes]]:
    """自叶向上构树，返回各层（第 0 层为叶）。奇数层末节点复制配对。"""
    if not leaves:
        return []
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        if len(cur) % 2 == 1:
            cur = cur + [cur[-1]]
        levels.append(
            [_internal(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
        )
    return levels


def _root_of(levels: list[list[bytes]]) -> bytes:
    return EMPTY_ROOT if not levels else levels[-1][0]


def _depth(size: int) -> int:
    """size 个叶的树深（路径长度）。size<=1 时为 0。"""
    depth, count = 0, size
    while count > 1:
        count = (count + 1) // 2
        depth += 1
    return depth


def _path_for(levels: list[list[bytes]], index: int) -> tuple[tuple[int, bytes], ...]:
    """取叶 ``index`` 的兄弟路径（自叶向根）。末节点复制配对时兄弟即自身。"""
    path: list[tuple[int, bytes]] = []
    for level in levels[:-1]:
        padded = level if len(level) % 2 == 0 else level + [level[-1]]
        sibling = index ^ 1
        side = SIDE_RIGHT if sibling > index else SIDE_LEFT
        path.append((side, padded[sibling]))
        index //= 2
    return tuple(path)


def _encode_path(path: tuple[tuple[int, bytes], ...]) -> bytes:
    out = len(path).to_bytes(4, "big")
    for side, digest in path:
        out += bytes((side,)) + digest
    return out


# --------------------------------------------------------------------- 证明


@dataclass(frozen=True)
class SlotProof:
    """槽位树成员证明：槽号 + 自叶向根的兄弟路径。

    ``path`` 中每步为 ``(side, digest)``，``side`` 取
    :data:`SIDE_LEFT` / :data:`SIDE_RIGHT`，表示兄弟节点的方位。
    """

    slot: int
    path: tuple[tuple[int, bytes], ...]

    def encode(self) -> bytes:
        """确定且带版本的编码。"""
        return (
            b"MPHF-SLOT-PROOF"
            + bytes((PROOF_FORMAT_VERSION,))
            + _u64(self.slot)
            + _encode_path(self.path)
        )


@dataclass(frozen=True)
class SortedProof:
    """键序树（认证序列）中单个键的成员证明。

    叶同时绑定 ``key`` 与原槽号 ``slot``；``rank`` 为该键在键字节序
    排列中的秩（0 起）。
    """

    rank: int
    key: bytes
    slot: int
    path: tuple[tuple[int, bytes], ...]

    def encode(self) -> bytes:
        return (
            b"MPHF-SORTED-PROOF"
            + bytes((PROOF_FORMAT_VERSION,))
            + _u64(self.rank)
            + _u64(self.slot)
            + _u64(len(self.key))
            + self.key
            + _encode_path(self.path)
        )


@dataclass(frozen=True)
class AbsenceProof:
    """不存在证明：前驱与后继在键序树中的认证路径及相邻秩。

    边界键缺一侧：查询键小于所有键时 ``predecessor`` 为 ``None``
    （核验 ``successor.rank == 0``）；大于所有键时 ``successor`` 为
    ``None``（核验 ``predecessor.rank == size - 1``）。空集合两者皆
    ``None``。仅给两个存在键而没有相邻秩（``succ.rank == pred.rank + 1``
    或边界首/尾秩）不能证明不存在。
    """

    predecessor: "SortedProof | None"
    successor: "SortedProof | None"

    def encode(self) -> bytes:
        flags = (self.predecessor is not None) | ((self.successor is not None) << 1)
        out = b"MPHF-ABSENCE-PROOF" + bytes((PROOF_FORMAT_VERSION, flags))
        if self.predecessor is not None:
            out += self.predecessor.encode()
        if self.successor is not None:
            out += self.successor.encode()
        return out


@dataclass(frozen=True)
class Manifest:
    """版本清单：两棵树根及总键数。持有它即可离线验证证明。"""

    size: int
    slot_root: bytes
    sorted_root: bytes
    version: int = PROOF_FORMAT_VERSION

    def encode(self) -> bytes:
        """确定且带版本的编码。"""
        return (
            b"MPHF-MANIFEST"
            + bytes((self.version,))
            + _u64(self.size)
            + self.slot_root
            + self.sorted_root
        )

    def digest(self) -> bytes:
        """清单承诺：``SHA256(encode())``。"""
        return hashlib.sha256(self.encode()).digest()


# ----------------------------------------------------------------- 认证索引


class AuthenticatedIndex:
    """只读键集合上的认证索引：持有两棵 Merkle 树并出具证明。"""

    __slots__ = ("_table", "_slot_levels", "_sorted_keys", "_sorted_entries",
                 "_sorted_levels", "_manifest")

    def __init__(
        self,
        table: MPHFTable,
        slot_levels: list[list[bytes]],
        sorted_entries: tuple[tuple[bytes, int], ...],
        sorted_levels: list[list[bytes]],
    ):
        self._table = table
        self._slot_levels = slot_levels
        self._sorted_entries = sorted_entries
        self._sorted_keys = [k for k, _ in sorted_entries]
        self._sorted_levels = sorted_levels
        self._manifest = Manifest(
            size=table.size,
            slot_root=_root_of(slot_levels),
            sorted_root=_root_of(sorted_levels),
        )

    @property
    def table(self) -> MPHFTable:
        return self._table

    @property
    def manifest(self) -> Manifest:
        """版本清单：两棵树根 + 总键数（含格式版本号）。"""
        return self._manifest

    def prove(self, key) -> "SlotProof | None":
        """成员证明：仅为真实成员返回槽号和兄弟路径，非成员返回 ``None``。

        成员判定沿用原 ``lookup`` 的完整键终检；键类型错误抛 ``TypeError``。
        """
        slot = lookup(self._table, key)
        if slot == NOT_FOUND:
            return None
        return SlotProof(slot=slot, path=_path_for(self._slot_levels, slot))

    def _sorted_proof(self, rank: int) -> SortedProof:
        key, slot = self._sorted_entries[rank]
        return SortedProof(
            rank=rank, key=key, slot=slot,
            path=_path_for(self._sorted_levels, rank),
        )

    def prove_absence(self, key) -> "AbsenceProof | None":
        """不存在证明：前驱/后继的认证路径与相邻秩；成员返回 ``None``。

        边界键缺一侧（只有后继或只有前驱）；空集合两侧皆 ``None``。
        键类型错误抛 ``TypeError``。
        """
        if isinstance(key, bool) or not isinstance(
            key, (bytes, bytearray, memoryview)
        ):
            raise TypeError(
                f"key must be bytes-like (bytes/bytearray/memoryview), "
                f"got {type(key).__name__}"
            )
        raw = bytes(key)
        if lookup(self._table, raw) != NOT_FOUND:
            return None
        rank = bisect.bisect_left(self._sorted_keys, raw)
        predecessor = self._sorted_proof(rank - 1) if rank > 0 else None
        successor = (
            self._sorted_proof(rank) if rank < len(self._sorted_entries) else None
        )
        return AbsenceProof(predecessor=predecessor, successor=successor)


def build_authenticated(table) -> AuthenticatedIndex:
    """在 :func:`mphf.build` 的只读结果上构建认证索引（纯函数，确定性）。

    Raises:
        TypeError:  ``table`` 不是 :class:`mphf.MPHFTable`。
        ValueError: 对 :data:`mphf.CONSTRUCTION_FAILED` 哨兵构建。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot authenticate CONSTRUCTION_FAILED: build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    slot_leaves = [_slot_leaf(i, k) for i, k in enumerate(table.keys)]
    slot_levels = _tree_levels(slot_leaves)
    slot_of = {k: i for i, k in enumerate(table.keys)}
    sorted_entries = tuple((k, slot_of[k]) for k in sorted(table.keys))
    sorted_leaves = [_sorted_leaf(slot, k) for k, slot in sorted_entries]
    sorted_levels = _tree_levels(sorted_leaves)
    return AuthenticatedIndex(table, slot_levels, sorted_entries, sorted_levels)


# --------------------------------------------------------------------- 验证


def _check_key(key) -> bytes:
    if isinstance(key, bool) or not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"key must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(key).__name__}"
        )
    return bytes(key)


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _valid_path_shape(path, depth: int) -> bool:
    """路径形状：长度等于树深，每步为 (合法方位, 32 字节摘要)。"""
    if not isinstance(path, (tuple, list)) or len(path) != depth:
        return False
    for step in path:
        if not isinstance(step, (tuple, list)) or len(step) != 2:
            return False
        side, digest = step
        if side not in (SIDE_LEFT, SIDE_RIGHT):
            return False
        if not isinstance(digest, bytes) or len(digest) != _HASH_LEN:
            return False
    return True


def _fold(leaf: bytes, path) -> bytes:
    h = leaf
    for side, sibling in path:
        h = _internal(sibling, h) if side == SIDE_LEFT else _internal(h, sibling)
    return h


def verify_membership(root, size, key, proof) -> bool:
    """离线验证槽位树成员证明。

    Args:
        root:  槽位树根（取自版本清单）。
        size:  总槽数（键数）。
        key:   待验键（bytes-like；类型错误抛 ``TypeError``）。
        proof: :class:`SlotProof`。

    Returns:
        先核对路径形状与槽号范围，再重算根比较；任何不符返回 ``False``。
    """
    raw = _check_key(key)
    if not isinstance(root, bytes) or len(root) != _HASH_LEN:
        return False
    if not _is_int(size) or size < 1:
        return False
    if not isinstance(proof, SlotProof) or not _is_int(proof.slot):
        return False
    if not 0 <= proof.slot < size:
        return False
    if not _valid_path_shape(proof.path, _depth(size)):
        return False
    return _fold(_slot_leaf(proof.slot, raw), proof.path) == root


def _verify_sorted_membership(root: bytes, size: int, p) -> bool:
    if not isinstance(p, SortedProof):
        return False
    if not _is_int(p.rank) or not _is_int(p.slot) or not isinstance(p.key, bytes):
        return False
    if not 0 <= p.rank < size or not 0 <= p.slot < size:
        return False
    if not _valid_path_shape(p.path, _depth(size)):
        return False
    return _fold(_sorted_leaf(p.slot, p.key), p.path) == root


def verify_absence(root, size, key, proof) -> bool:
    """离线验证不存在证明（键序树根 + 总键数 + 查询键 + 证明）。

    核验：前驱/后继各自的认证路径与范围、``pred.key < key < succ.key``、
    以及**相邻秩**——两侧俱在时 ``succ.rank == pred.rank + 1``；边界键
    缺一侧时核验首秩（``succ.rank == 0``）或尾秩（``pred.rank == size-1``）。
    空集合要求两侧皆 ``None`` 且根为 :data:`EMPTY_ROOT`。
    任何不符返回 ``False``；键类型错误抛 ``TypeError``。
    """
    raw = _check_key(key)
    if not isinstance(root, bytes) or len(root) != _HASH_LEN:
        return False
    if not _is_int(size) or size < 0:
        return False
    if not isinstance(proof, AbsenceProof):
        return False
    pred, succ = proof.predecessor, proof.successor
    if size == 0:
        return pred is None and succ is None and root == EMPTY_ROOT
    if pred is None and succ is None:
        return False
    if pred is not None:
        if not _verify_sorted_membership(root, size, pred):
            return False
        if not pred.key < raw:
            return False
    if succ is not None:
        if not _verify_sorted_membership(root, size, succ):
            return False
        if not raw < succ.key:
            return False
    if pred is not None and succ is not None:
        return succ.rank == pred.rank + 1
    if pred is None:
        return succ.rank == 0
    return pred.rank == size - 1
