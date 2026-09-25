"""索引认证扩展：在只读键集合上构建可离线验证的 Merkle 证明。

两棵 Merkle 树 + 一份版本清单（Manifest）：

1. **槽位树**：叶子按槽位 ``0..n-1`` 排列，叶编码绑定槽号、键长度与键字节；
   证明回答“槽位 i 里确实放着键 k”。
2. **认证序列树**：键按字节序排列，叶编码额外绑定该键在槽位树中的原槽号；
   前驱/后继两条相邻秩的认证路径用来证明“键 k 不存在”。

两棵树根与总键数共同组成 :class:`Manifest`（版本清单）。调用方只需持有
清单即可离线核验证明，不必信任查询端；原 :func:`mphf.lookup` 语义不变，
仍以槽位完整键逐字节比较判定命中。

哈希线格式（公开契约，全部 SHA256，单字节域前缀与 MPHF 顶点哈希的
``0x00/0x01/0x02`` 完全不相交）::

    槽位树叶:   SHA256(0x10 ‖ slot:8BE ‖ keylen:8BE ‖ key)
    槽位树内点: SHA256(0x11 ‖ left ‖ right)
    序列树叶:   SHA256(0x12 ‖ rank:8BE ‖ slot:8BE ‖ keylen:8BE ‖ key)
    序列树内点: SHA256(0x13 ‖ left ‖ right)

树形规则：每层节点数为奇时**复制末节点**配对；归约到单个节点即为根；
单叶树的根就是叶子本身（路径为空）；**空集合的根单独定义**为常量
:data:`EMPTY_ROOT`（两棵树共用），不来自任何叶编码。

证明编码确定性且带版本：``encode()`` 输出以格式标签与
:data:`PROOF_VERSION` 开头，解码严格校验长度与版本，拒绝截短/追加字节。

仅使用 Python 3.14 标准库（hashlib、hmac、dataclasses、bisect、typing）。
"""

from __future__ import annotations

import hashlib
import hmac
from bisect import bisect_left
from dataclasses import dataclass
from typing import Final

from . import CONSTRUCTION_FAILED, MPHFTable, NOT_FOUND, lookup

__all__ = [
    "PROOF_VERSION",
    "EMPTY_ROOT",
    "Manifest",
    "MembershipProof",
    "NeighborProof",
    "AbsenceProof",
    "AuthIndex",
    "build_auth",
    "prove",
    "prove_absence",
    "verify_membership",
    "verify_absence",
    "decode_membership_proof",
    "decode_absence_proof",
]

#: 证明/清单编码版本。编码格式变更时递增，解码方按版本拒绝不认识的格式。
PROOF_VERSION: Final = 1

#: 空集合的树根（两棵树共用），单独定义的常量，不等于任何叶/内点编码。
EMPTY_ROOT: Final = hashlib.sha256(b"mphf-auth-v1:empty-set-root").digest()

# 域前缀：与 MPHF 顶点哈希标签 0x00/0x01/0x02 不相交。
_TAG_SLOT_LEAF: Final = 0x10
_TAG_SLOT_NODE: Final = 0x11
_TAG_SEQ_LEAF: Final = 0x12
_TAG_SEQ_NODE: Final = 0x13

_HASH_LEN: Final = 32  # SHA256 摘要长度
_U64_MAX: Final = 2**64 - 1

_FORMAT_MEMBERSHIP: Final = b"MPHF-MEM"
_FORMAT_ABSENCE: Final = b"MPHF-ABS"
_FORMAT_MANIFEST: Final = b"MPHF-MAN"


# --------------------------------------------------------------------- 编码


def _slot_leaf(slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        bytes((_TAG_SLOT_LEAF,))
        + slot.to_bytes(8, "big")
        + len(key).to_bytes(8, "big")
        + key
    ).digest()


def _seq_leaf(rank: int, slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        bytes((_TAG_SEQ_LEAF,))
        + rank.to_bytes(8, "big")
        + slot.to_bytes(8, "big")
        + len(key).to_bytes(8, "big")
        + key
    ).digest()


def _node(tag: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes((tag,)) + left + right).digest()


def _depth(count: int) -> int:
    """叶子数为 ``count`` 时的路径深度（每层奇数复制末节点后两两配对）。"""
    d = 0
    while count > 1:
        count = (count + 1) // 2
        d += 1
    return d


def _build_levels(leaves: list[bytes], node_tag: int) -> tuple[tuple[bytes, ...], ...]:
    """自叶向上构建各层；``levels[0]`` 为叶层，``levels[-1]`` 为单节点根层。

    每层节点数为奇时复制末节点再配对（复制节点不存入层内，路径取兄弟时
    按同一规则推导）。空集合返回空元组，其根由 :data:`EMPTY_ROOT` 表示。
    """
    if not leaves:
        return ()
    levels: list[tuple[bytes, ...]] = [tuple(leaves)]
    while len(levels[-1]) > 1:
        cur = list(levels[-1])
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        levels.append(
            tuple(_node(node_tag, cur[i], cur[i + 1]) for i in range(0, len(cur), 2))
        )
    return tuple(levels)


def _root_of(levels: tuple[tuple[bytes, ...], ...]) -> bytes:
    return levels[-1][0] if levels else EMPTY_ROOT


def _path_of(levels: tuple[tuple[bytes, ...], ...], index: int) -> tuple[bytes, ...]:
    """取叶 ``index`` 的兄弟路径（自叶层向根排列）。"""
    path: list[bytes] = []
    i = index
    for level in levels[:-1]:
        sib = i + 1 if i % 2 == 0 else i - 1
        # 奇数层末节点的配对对象是它自身的复制品。
        path.append(level[sib] if sib < len(level) else level[i])
        i //= 2
    return tuple(path)


def _fold(leaf: bytes, index: int, path: tuple[bytes, ...], node_tag: int) -> bytes:
    """按路径重算根：索引为偶则当前节点在左，为奇则在右。"""
    h = leaf
    i = index
    for sib in path:
        h = _node(node_tag, h, sib) if i % 2 == 0 else _node(node_tag, sib, h)
        i //= 2
    return h


# --------------------------------------------------------------------- 类型


def _as_bytes(raw: object, where: str) -> bytes:
    """与核心库一致的键类型归一化：非 bytes-like（含 bool）抛 TypeError。"""
    if isinstance(raw, bool) or not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"{where}: key must be bytes-like (bytes/bytearray/memoryview), "
            f"got {type(raw).__name__}"
        )
    return bytes(raw)


def _is_ascii(b: bytes) -> bool:
    return all(ch < 0x80 for ch in b)


def _check_u64(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{where}: expected int, got {type(value).__name__}")
    if not 0 <= value <= _U64_MAX:
        raise ValueError(f"{where}: out of range for 8-byte encoding: {value}")
    return value


def _check_root(root: object, where: str) -> bytes:
    if not isinstance(root, (bytes, bytearray, memoryview)):
        raise TypeError(f"{where}: root must be bytes-like, got {type(root).__name__}")
    r = bytes(root)
    if len(r) != _HASH_LEN:
        raise ValueError(f"{where}: root must be {_HASH_LEN} bytes, got {len(r)}")
    return r


def _check_path_shape(path: object, want_len: int) -> tuple[bytes, ...] | None:
    """形状核对：长度与每层 32 字节。形状不符返回 None（验证失败）。"""
    if not isinstance(path, tuple) or len(path) != want_len:
        return None
    if any(not isinstance(h, bytes) or len(h) != _HASH_LEN for h in path):
        return None
    return path


# --------------------------------------------------------------------- 清单


@dataclass(frozen=True)
class Manifest:
    """版本清单：两棵 Merkle 树的根 + 总键数 + 编码版本。

    调用方只需持有（可信渠道获得的）清单即可离线核验成员/不存在证明。
    """

    size: int
    slot_root: bytes
    seq_root: bytes
    version: int = PROOF_VERSION

    def encode(self) -> bytes:
        """确定性编码：``MPHF-MAN ‖ version:1 ‖ size:8BE ‖ slot_root ‖ seq_root``。"""
        _check_u64(self.size, "manifest.size")
        if self.version != PROOF_VERSION:
            raise ValueError(f"unsupported manifest version: {self.version}")
        return (
            _FORMAT_MANIFEST
            + bytes((self.version,))
            + self.size.to_bytes(8, "big")
            + _check_root(self.slot_root, "manifest.slot_root")
            + _check_root(self.seq_root, "manifest.seq_root")
        )

    @staticmethod
    def decode(data: bytes) -> "Manifest":
        """严格解码；截短、追加字节或版本不符一律 ValueError。"""
        raw = _as_bytes(data, "manifest")  # 仅做类型检查，内容可为任意字节
        header = _FORMAT_MANIFEST + bytes((PROOF_VERSION,))
        want = len(header) + 8 + 2 * _HASH_LEN
        if len(raw) != want or not raw.startswith(header):
            raise ValueError(
                f"malformed manifest encoding (want exactly {want} bytes "
                f"with {_FORMAT_MANIFEST!r} v{PROOF_VERSION} header)"
            )
        off = len(header)
        size = int.from_bytes(raw[off : off + 8], "big")
        off += 8
        return Manifest(
            size=size,
            slot_root=raw[off : off + _HASH_LEN],
            seq_root=raw[off + _HASH_LEN : off + 2 * _HASH_LEN],
        )


# --------------------------------------------------------------------- 证明


@dataclass(frozen=True)
class MembershipProof:
    """成员证明：槽号 + 槽位树兄弟路径（自叶层向根排列）。"""

    slot: int
    path: tuple[bytes, ...]

    def encode(self) -> bytes:
        """确定性编码：``MPHF-MEM ‖ version:1 ‖ slot:8BE ‖ count:4BE ‖ path``。"""
        _check_u64(self.slot, "proof.slot")
        for h in self.path:
            _check_root(h, "proof.path item")
        return (
            _FORMAT_MEMBERSHIP
            + bytes((PROOF_VERSION,))
            + self.slot.to_bytes(8, "big")
            + len(self.path).to_bytes(4, "big")
            + b"".join(self.path)
        )


@dataclass(frozen=True)
class NeighborProof:
    """认证序列树中一个邻居的认证路径：秩、键、原槽号与兄弟路径。"""

    rank: int
    key: bytes
    slot: int
    path: tuple[bytes, ...]

    def _encode(self) -> bytes:
        _check_u64(self.rank, "neighbor.rank")
        _check_u64(self.slot, "neighbor.slot")
        key = _as_bytes(self.key, "neighbor.key")
        for h in self.path:
            _check_root(h, "neighbor.path item")
        return (
            self.rank.to_bytes(8, "big")
            + self.slot.to_bytes(8, "big")
            + len(key).to_bytes(4, "big")
            + key
            + len(self.path).to_bytes(4, "big")
            + b"".join(self.path)
        )


@dataclass(frozen=True)
class AbsenceProof:
    """不存在证明：前驱与后继的认证路径。

    两侧都存在时要求秩相邻（``successor.rank == predecessor.rank + 1``）；
    边界键缺一侧时由核验方检查首秩（0）或尾秩（size-1）。空集合两侧皆空。
    """

    predecessor: NeighborProof | None
    successor: NeighborProof | None

    def encode(self) -> bytes:
        """确定性编码：``MPHF-ABS ‖ version:1 ‖ flags:1 ‖ [pred] ‖ [succ]``。"""
        flags = (self.predecessor is not None) | (self.successor is not None) << 1
        blob = _FORMAT_ABSENCE + bytes((PROOF_VERSION, flags))
        if self.predecessor is not None:
            blob += self.predecessor._encode()
        if self.successor is not None:
            blob += self.successor._encode()
        return blob


def decode_membership_proof(data: bytes) -> MembershipProof:
    """严格解码成员证明；截短、追加字节或版本不符一律 ValueError。"""
    raw = _as_bytes(data, "proof")
    header = _FORMAT_MEMBERSHIP + bytes((PROOF_VERSION,))
    if not raw.startswith(header) or len(raw) < len(header) + 12:
        raise ValueError("malformed membership proof encoding (bad header/length)")
    off = len(header)
    slot = int.from_bytes(raw[off : off + 8], "big")
    count = int.from_bytes(raw[off + 8 : off + 12], "big")
    off += 12
    if len(raw) != off + count * _HASH_LEN:
        raise ValueError("malformed membership proof encoding (path length mismatch)")
    path = tuple(raw[off + i * _HASH_LEN : off + (i + 1) * _HASH_LEN] for i in range(count))
    return MembershipProof(slot=slot, path=path)


def _decode_neighbor(raw: bytes, off: int) -> tuple[NeighborProof, int]:
    if len(raw) < off + 24:
        raise ValueError("malformed absence proof encoding (truncated neighbor)")
    rank = int.from_bytes(raw[off : off + 8], "big")
    slot = int.from_bytes(raw[off + 8 : off + 16], "big")
    klen = int.from_bytes(raw[off + 16 : off + 20], "big")
    off += 20
    if len(raw) < off + klen + 4:
        raise ValueError("malformed absence proof encoding (truncated neighbor key)")
    key = raw[off : off + klen]
    off += klen
    count = int.from_bytes(raw[off : off + 4], "big")
    off += 4
    if len(raw) < off + count * _HASH_LEN:
        raise ValueError("malformed absence proof encoding (truncated neighbor path)")
    path = tuple(raw[off + i * _HASH_LEN : off + (i + 1) * _HASH_LEN] for i in range(count))
    return NeighborProof(rank=rank, key=key, slot=slot, path=path), off + count * _HASH_LEN


def decode_absence_proof(data: bytes) -> AbsenceProof:
    """严格解码不存在证明；截短、追加字节或版本不符一律 ValueError。"""
    raw = _as_bytes(data, "proof")
    header = _FORMAT_ABSENCE + bytes((PROOF_VERSION,))
    if not raw.startswith(header) or len(raw) < len(header) + 1:
        raise ValueError("malformed absence proof encoding (bad header/length)")
    flags = raw[len(header)]
    if flags & ~0b11:
        raise ValueError("malformed absence proof encoding (unknown flags)")
    off = len(header) + 1
    pred = succ = None
    if flags & 0b01:
        pred, off = _decode_neighbor(raw, off)
    if flags & 0b10:
        succ, off = _decode_neighbor(raw, off)
    if off != len(raw):
        raise ValueError("malformed absence proof encoding (trailing bytes)")
    return AbsenceProof(predecessor=pred, successor=succ)


# --------------------------------------------------------------------- 索引


@dataclass(frozen=True)
class AuthIndex:
    """只读键集合的认证索引：两棵 Merkle 树的全部层 + 排序视图。

    由 :func:`build_auth` 从 :class:`mphf.MPHFTable` 派生；原表不可变，
    本索引同样不可变。证明生成在持有方进行，核验只需 :class:`Manifest`。
    """

    table: MPHFTable
    sorted_keys: tuple[bytes, ...]  # 按键字节序排列
    sorted_slots: tuple[int, ...]  # 每个秩对应的原槽号
    slot_levels: tuple[tuple[bytes, ...], ...]
    seq_levels: tuple[tuple[bytes, ...], ...]

    @property
    def slot_root(self) -> bytes:
        return _root_of(self.slot_levels)

    @property
    def seq_root(self) -> bytes:
        return _root_of(self.seq_levels)

    def manifest(self) -> Manifest:
        """版本清单：两树根 + 总键数（+ 编码版本）。"""
        return Manifest(
            size=self.table.size, slot_root=self.slot_root, seq_root=self.seq_root
        )

    def prove(self, key) -> MembershipProof | None:
        """实例方法形式，语义同模块级 :func:`prove`。"""
        return prove(self, key)

    def prove_absence(self, key) -> AbsenceProof | None:
        """实例方法形式，语义同模块级 :func:`prove_absence`。"""
        return prove_absence(self, key)


def build_auth(table: MPHFTable) -> AuthIndex:
    """从已构造的 MPHF 表派生认证索引（纯函数，不改变原表）。

    Raises:
        TypeError:  表对象类型错误。
        ValueError: 对 :data:`mphf.CONSTRUCTION_FAILED` 哨兵派生索引。
    """
    if table is CONSTRUCTION_FAILED:
        raise ValueError(
            "cannot build auth index from CONSTRUCTION_FAILED: "
            "build exhausted its seed budget"
        )
    if not isinstance(table, MPHFTable):
        raise TypeError(
            f"table must be an MPHFTable produced by build(), got {type(table).__name__}"
        )
    keys = table.keys
    order = sorted(range(table.size), key=lambda i: keys[i])
    sorted_keys = tuple(keys[i] for i in order)
    sorted_slots = tuple(order)
    slot_levels = _build_levels(
        [_slot_leaf(i, k) for i, k in enumerate(keys)], _TAG_SLOT_NODE
    )
    seq_levels = _build_levels(
        [_seq_leaf(r, sorted_slots[r], k) for r, k in enumerate(sorted_keys)],
        _TAG_SEQ_NODE,
    )
    return AuthIndex(
        table=table,
        sorted_keys=sorted_keys,
        sorted_slots=sorted_slots,
        slot_levels=slot_levels,
        seq_levels=seq_levels,
    )


# --------------------------------------------------------------------- 证明生成


def prove(auth: AuthIndex, key) -> MembershipProof | None:
    """为真实成员生成成员证明（槽号 + 槽位树兄弟路径）。

    非成员（含非 ASCII 字节串、空表上的任何查询）返回 ``None``——
    本函数只对真实成员返回证明，绝不编造。

    Raises:
        TypeError: 索引或键类型错误（bool 同样拒绝）。
    """
    if not isinstance(auth, AuthIndex):
        raise TypeError(f"auth must be an AuthIndex, got {type(auth).__name__}")
    raw = _as_bytes(key, "key")
    slot = lookup(auth.table, raw)  # 原 lookup 仍以完整键终检
    if slot == NOT_FOUND:
        return None
    return MembershipProof(slot=slot, path=_path_of(auth.slot_levels, slot))


def prove_absence(auth: AuthIndex, key) -> AbsenceProof | None:
    """为非成员生成不存在证明：前驱/后继的认证路径与相邻秩。

    键是成员时返回 ``None``。边界键（小于所有键 / 大于所有键）只给一侧，
    由核验方检查首秩 0 / 尾秩 size-1；空集合两侧皆空。

    Raises:
        TypeError: 索引或键类型错误（bool 同样拒绝）。
    """
    if not isinstance(auth, AuthIndex):
        raise TypeError(f"auth must be an AuthIndex, got {type(auth).__name__}")
    raw = _as_bytes(key, "key")
    n = auth.table.size
    if n == 0:
        return AbsenceProof(predecessor=None, successor=None)
    if lookup(auth.table, raw) != NOT_FOUND:
        return None
    # 非成员（含非 ASCII 键，构造期即被拒绝入表）按字节序定位前后驱。
    pos = bisect_left(auth.sorted_keys, raw)
    pred = _neighbor(auth, pos - 1) if pos > 0 else None
    succ = _neighbor(auth, pos) if pos < n else None
    return AbsenceProof(predecessor=pred, successor=succ)


def _neighbor(auth: AuthIndex, rank: int) -> NeighborProof:
    return NeighborProof(
        rank=rank,
        key=auth.sorted_keys[rank],
        slot=auth.sorted_slots[rank],
        path=_path_of(auth.seq_levels, rank),
    )


# --------------------------------------------------------------------- 核验


def verify_membership(slot_root, size: int, key, proof: MembershipProof) -> bool:
    """离线核验成员证明：输入槽位树根、总槽数和键。

    先核对路径形状与槽号范围，再重算根比对。证明来自不可信方时，
    形状/范围不符一律返回 ``False``（不抛异常）。

    Raises:
        TypeError:  根/键/证明类型错误，或 size 不是 int（bool 拒绝）。
        ValueError: 根不是 32 字节，或 size 为负。
    """
    root = _check_root(slot_root, "slot_root")
    n = _check_u64(size, "size")
    raw = _as_bytes(key, "key")
    if not isinstance(proof, MembershipProof):
        raise TypeError(
            f"proof must be a MembershipProof, got {type(proof).__name__}"
        )
    if n == 0 or not _is_ascii(raw):
        return False
    # 范围核对：槽号必须落在 0..size-1。
    if isinstance(proof.slot, bool) or not isinstance(proof.slot, int):
        return False
    if not 0 <= proof.slot < n:
        return False
    # 形状核对：路径长度必须等于该规模下的树深，每层兄弟 32 字节。
    path = _check_path_shape(proof.path, _depth(n))
    if path is None:
        return False
    leaf = _slot_leaf(proof.slot, raw)
    return hmac.compare_digest(_fold(leaf, proof.slot, path, _TAG_SLOT_NODE), root)


def verify_absence(seq_root, size: int, key, proof: AbsenceProof) -> bool:
    """离线核验不存在证明：输入认证序列树根、总键数和键。

    规则：
      * 两侧都在：前驱键 < 查询键 < 后继键，且秩相邻
        （``succ.rank == pred.rank + 1``）——只给两个存在键而没有相邻秩
        不能证明不存在；
      * 只有后继：查询键 < 后继键，且后继秩为 0（首秩）；
      * 只有前驱：前驱键 < 查询键，且前驱秩为 size-1（尾秩）；
      * 空集合（size == 0）：两侧皆空且根为空集合根。

    每条邻居路径先核对形状与秩/槽号范围，再重算序列树根比对。

    Raises:
        TypeError:  根/键/证明类型错误，或 size 不是 int（bool 拒绝）。
        ValueError: 根不是 32 字节，或 size 为负。
    """
    root = _check_root(seq_root, "seq_root")
    n = _check_u64(size, "size")
    raw = _as_bytes(key, "key")
    if not isinstance(proof, AbsenceProof):
        raise TypeError(f"proof must be an AbsenceProof, got {type(proof).__name__}")
    pred, succ = proof.predecessor, proof.successor
    if pred is not None and not isinstance(pred, NeighborProof):
        raise TypeError("proof.predecessor must be a NeighborProof or None")
    if succ is not None and not isinstance(succ, NeighborProof):
        raise TypeError("proof.successor must be a NeighborProof or None")

    if n == 0:
        return pred is None and succ is None and hmac.compare_digest(root, EMPTY_ROOT)
    if pred is None and succ is None:
        return False
    if pred is not None and not _verify_neighbor(root, n, pred):
        return False
    if succ is not None and not _verify_neighbor(root, n, succ):
        return False

    if pred is not None and succ is not None:
        return (
            pred.key < raw < succ.key and succ.rank == pred.rank + 1
        )
    if succ is not None:
        return raw < succ.key and succ.rank == 0
    return pred.key < raw and pred.rank == n - 1


def _verify_neighbor(root: bytes, n: int, nb: NeighborProof) -> bool:
    # 范围核对：秩与槽号都必须落在 0..n-1；邻居键必须是 ASCII。
    for v in (nb.rank, nb.slot):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < n:
            return False
    if not isinstance(nb.key, bytes) or not _is_ascii(nb.key):
        return False
    # 形状核对：路径长度等于树深，每层 32 字节。
    path = _check_path_shape(nb.path, _depth(n))
    if path is None:
        return False
    leaf = _seq_leaf(nb.rank, nb.slot, nb.key)
    return hmac.compare_digest(_fold(leaf, nb.rank, path, _TAG_SEQ_NODE), root)
