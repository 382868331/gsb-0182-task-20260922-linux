"""mphf 索引认证扩展（mphf/auth.py）的必要测试。

期望值来源（与 tests/test_mphf.py 同一原则）：

* 叶/内点编码、树形归约（奇数层复制末节点配对）、兄弟路径，全部由
  测试侧用 hashlib 按 README 公开线格式**独立**实现，不调用
  mphf.auth 的任何内部函数产生期望值；
* 1、3、5 键的树逐层**手算**展开（显式写出每层哈希），核对 prove
  返回的兄弟路径与树根；
* prove → verify 的往返一致仅作为补充断言。
"""

from __future__ import annotations

import hashlib
import unittest
from unittest.mock import patch

import mphf


# ----------------------------------------------------------- 测试侧独立参考

TAG_SLOT_LEAF = 0x10
TAG_SLOT_NODE = 0x11
TAG_SEQ_LEAF = 0x12
TAG_SEQ_NODE = 0x13

EMPTY = hashlib.sha256(b"mphf-auth-v1:empty-set-root").digest()


def ref_slot_leaf(slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        bytes([TAG_SLOT_LEAF]) + slot.to_bytes(8, "big") + len(key).to_bytes(8, "big") + key
    ).digest()


def ref_seq_leaf(rank: int, slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        bytes([TAG_SEQ_LEAF])
        + rank.to_bytes(8, "big")
        + slot.to_bytes(8, "big")
        + len(key).to_bytes(8, "big")
        + key
    ).digest()


def ref_node(tag: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes([tag]) + left + right).digest()


def ref_root(leaves: list[bytes], tag: int) -> bytes:
    """独立归约：奇数层复制末节点配对；空集合根为单独常量。"""
    if not leaves:
        return EMPTY
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [ref_node(tag, level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def ref_path(leaves: list[bytes], tag: int, index: int) -> tuple[bytes, ...]:
    """独立取兄弟路径（自叶向根）。"""
    path = []
    i = index
    level = list(leaves)
    while len(level) > 1:
        sib = i + 1 if i % 2 == 0 else i - 1
        path.append(level[sib] if sib < len(level) else level[i])
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [ref_node(tag, level[j], level[j + 1]) for j in range(0, len(level), 2)]
        i //= 2
    return tuple(path)


def ref_depth(count: int) -> int:
    d = 0
    while count > 1:
        count = (count + 1) // 2
        d += 1
    return d


def det_keys(n: int, salt: str = "ak") -> list[bytes]:
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


def make_auth(keys):
    table = mphf.build(keys)
    assert isinstance(table, mphf.MPHFTable)
    return mphf.build_auth(table)


# --------------------------------------------------------------------- 测试


class ConstantsTests(unittest.TestCase):
    def test_version_and_empty_root(self):
        self.assertEqual(mphf.PROOF_VERSION, 1)
        self.assertEqual(mphf.EMPTY_ROOT, EMPTY)  # 锚定独立参考
        self.assertEqual(len(mphf.EMPTY_ROOT), 32)

    def test_domain_tags_disjoint_from_mphf_hash_tags(self):
        # 认证域前缀必须与 MPHF 顶点哈希标签 0x00/0x01/0x02 不相交。
        for tag in (TAG_SLOT_LEAF, TAG_SLOT_NODE, TAG_SEQ_LEAF, TAG_SEQ_NODE):
            self.assertNotIn(tag, (0x00, 0x01, 0x02))


class HandComputedSlotTreeTests(unittest.TestCase):
    """手算 1、3、5 键的槽位树：逐层显式展开，核对根与 prove 的路径。"""

    def slot_leaves(self, keys):
        t = mphf.build(keys)
        return t, [ref_slot_leaf(i, k) for i, k in enumerate(t.keys)]

    def test_one_key_tree(self):
        keys = [b"only"]
        t, L = self.slot_leaves(keys)
        auth = mphf.build_auth(t)
        # 单叶树：根即叶子本身，路径为空。
        self.assertEqual(auth.slot_root, L[0])
        self.assertEqual(auth.slot_root, ref_root(L, TAG_SLOT_NODE))
        p = mphf.prove(auth, b"only")
        self.assertEqual(p.slot, 0)
        self.assertEqual(p.path, ())
        self.assertTrue(mphf.verify_membership(auth.slot_root, 1, b"only", p))

    def test_three_key_tree(self):
        keys = det_keys(3)
        t, L = self.slot_leaves(keys)
        auth = mphf.build_auth(t)
        # 手算：A = H(L0,L1)，B = H(L2,L2)（奇数复制末节点），root = H(A,B)。
        A = ref_node(TAG_SLOT_NODE, L[0], L[1])
        B = ref_node(TAG_SLOT_NODE, L[2], L[2])
        root = ref_node(TAG_SLOT_NODE, A, B)
        self.assertEqual(auth.slot_root, root)
        self.assertEqual(auth.slot_root, ref_root(L, TAG_SLOT_NODE))
        # 逐槽位核对 prove 的兄弟路径。
        for i, k in enumerate(t.keys):
            p = mphf.prove(auth, k)
            self.assertEqual(p.slot, i)
        self.assertEqual(mphf.prove(auth, t.keys[0]).path, (L[1], B))
        self.assertEqual(mphf.prove(auth, t.keys[1]).path, (L[0], B))
        self.assertEqual(mphf.prove(auth, t.keys[2]).path, (L[2], A))  # 兄弟是自身复制
        for i, k in enumerate(t.keys):
            self.assertTrue(mphf.verify_membership(root, 3, k, mphf.prove(auth, k)))

    def test_five_key_tree(self):
        keys = det_keys(5)
        t, L = self.slot_leaves(keys)
        auth = mphf.build_auth(t)
        # 手算：A=H(L0,L1) B=H(L2,L3) C=H(L4,L4)；D=H(A,B) E=H(C,C)；root=H(D,E)。
        A = ref_node(TAG_SLOT_NODE, L[0], L[1])
        B = ref_node(TAG_SLOT_NODE, L[2], L[3])
        C = ref_node(TAG_SLOT_NODE, L[4], L[4])
        D = ref_node(TAG_SLOT_NODE, A, B)
        E = ref_node(TAG_SLOT_NODE, C, C)
        root = ref_node(TAG_SLOT_NODE, D, E)
        self.assertEqual(auth.slot_root, root)
        # 路径：slot4 的兄弟依次是 L4（自身复制）、C（自身复制）、D。
        self.assertEqual(mphf.prove(auth, t.keys[4]).path, (L[4], C, D))
        self.assertEqual(mphf.prove(auth, t.keys[2]).path, (L[3], A, E))
        self.assertEqual(mphf.prove(auth, t.keys[0]).path, (L[1], B, E))
        for i, k in enumerate(t.keys):
            p = mphf.prove(auth, k)
            self.assertEqual(len(p.path), ref_depth(5))
            self.assertEqual(p.path, ref_path(L, TAG_SLOT_NODE, i))
            self.assertTrue(mphf.verify_membership(root, 5, k, p))


class SortedSeqTreeTests(unittest.TestCase):
    def test_seq_tree_binds_key_and_original_slot(self):
        # 构造输入故意乱序；序列树按键字节序排列，叶绑定原槽号。
        keys = [b"mango", b"apple", b"kiwi", b"banana"]
        t = mphf.build(keys)
        auth = mphf.build_auth(t)
        sorted_keys = sorted(t.keys)
        self.assertEqual(auth.sorted_keys, tuple(sorted_keys))
        slots_of = {k: mphf.lookup(t, k) for k in t.keys}
        leaves = [
            ref_seq_leaf(r, slots_of[k], k) for r, k in enumerate(sorted_keys)
        ]
        self.assertEqual(auth.seq_root, ref_root(leaves, TAG_SEQ_NODE))
        # 秩 r 的叶子里绑定的槽号必须等于该键在原表中的 lookup 结果。
        for r, k in enumerate(sorted_keys):
            self.assertEqual(auth.sorted_slots[r], slots_of[k])

    def test_seq_root_differs_from_slot_root(self):
        auth = make_auth(det_keys(6))
        self.assertNotEqual(auth.slot_root, auth.seq_root)


class MembershipProofTests(unittest.TestCase):
    def test_roundtrip_all_members(self):
        keys = det_keys(40)
        auth = make_auth(keys)
        man = auth.manifest()
        for k in keys:
            p = mphf.prove(auth, k)
            self.assertIsNotNone(p)
            self.assertTrue(mphf.verify_membership(man.slot_root, man.size, k, p))

    def test_prove_returns_none_for_nonmembers(self):
        auth = make_auth(det_keys(10))
        for q in (b"ak-999", b"", b"nope", b"\xff"):
            self.assertIsNone(mphf.prove(auth, q))

    def test_tampered_key_rejected(self):
        keys = det_keys(8)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[3])
        # 换键：同一条路径、同一个槽号，键不同 → 叶编码不同 → 根不符。
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[4], p))
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, b"ak-03 ", p))

    def test_tampered_slot_rejected(self):
        keys = det_keys(8)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[3])
        # 换槽号：叶编码里的槽号变了，路径位置也变了。
        forged = mphf.MembershipProof(slot=(p.slot + 1) % man.size, path=p.path)
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[3], forged))
        out_of_range = mphf.MembershipProof(slot=man.size, path=p.path)
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[3], out_of_range))

    def test_tampered_sibling_rejected(self):
        keys = det_keys(8)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[3])
        bad = bytearray(p.path[0])
        bad[0] ^= 0x01
        forged = mphf.MembershipProof(slot=p.slot, path=(bytes(bad),) + p.path[1:])
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[3], forged))

    def test_truncated_and_appended_path_rejected(self):
        keys = det_keys(8)  # 深度 3
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[3])
        self.assertEqual(len(p.path), 3)
        truncated = mphf.MembershipProof(slot=p.slot, path=p.path[:-1])
        appended = mphf.MembershipProof(slot=p.slot, path=p.path + (b"\x00" * 32,))
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[3], truncated))
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, keys[3], appended))

    def test_wrong_size_or_root_rejected(self):
        keys = det_keys(8)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[3])
        # 总槽数对不上 → 形状核对失败（8→9 与 8→4 都改变树深）。
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size + 1, keys[3], p))
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size // 2, keys[3], p))
        # 别的集合的根对不上。
        other = make_auth(det_keys(8, salt="bk"))
        self.assertFalse(
            mphf.verify_membership(other.slot_root, other.table.size, keys[3], p)
        )

    def test_verifier_input_validation(self):
        keys = det_keys(4)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[0])
        with self.assertRaises(ValueError):
            mphf.verify_membership(b"\x00" * 31, man.size, keys[0], p)  # 根长度错
        with self.assertRaises(ValueError):
            mphf.verify_membership(man.slot_root, -1, keys[0], p)
        with self.assertRaises(TypeError):
            mphf.verify_membership(man.slot_root, True, keys[0], p)  # bool 拒绝
        with self.assertRaises(TypeError):
            mphf.verify_membership(man.slot_root, man.size, "str-key", p)
        with self.assertRaises(TypeError):
            mphf.verify_membership(man.slot_root, man.size, keys[0], "not a proof")
        # 非 ASCII 查询键按非成员处理，返回 False 而非异常。
        self.assertFalse(mphf.verify_membership(man.slot_root, man.size, b"\xff", p))


class AbsenceProofTests(unittest.TestCase):
    def setUp(self):
        self.keys = det_keys(10)  # ak-00 .. ak-09，构造序即字典序
        self.auth = make_auth(self.keys)
        self.man = self.auth.manifest()

    def test_roundtrip_middle_gap(self):
        q = b"ak-055"  # 介于 ak-05 与 ak-06 之间
        proof = mphf.prove_absence(self.auth, q)
        self.assertIsNotNone(proof)
        self.assertEqual(proof.predecessor.key, b"ak-05")
        self.assertEqual(proof.successor.key, b"ak-06")
        self.assertEqual(proof.successor.rank, proof.predecessor.rank + 1)
        self.assertTrue(mphf.verify_absence(self.man.seq_root, self.man.size, q, proof))

    def test_roundtrip_all_gaps(self):
        for i in range(9):
            q = self.keys[i] + b" "  # 落在 keys[i] 与 keys[i+1] 之间
            proof = mphf.prove_absence(self.auth, q)
            self.assertTrue(
                mphf.verify_absence(self.man.seq_root, self.man.size, q, proof), q
            )

    def test_boundary_below_all(self):
        q = b"aa"  # 小于所有键
        proof = mphf.prove_absence(self.auth, q)
        self.assertIsNone(proof.predecessor)
        self.assertEqual(proof.successor.rank, 0)
        self.assertTrue(mphf.verify_absence(self.man.seq_root, self.man.size, q, proof))
        # 伪造：把后继换成秩 1 的真实邻居路径——首秩核验必须拒绝。
        real_succ = proof.successor
        forged_succ = mphf.NeighborProof(
            rank=1, key=real_succ.key, slot=real_succ.slot, path=real_succ.path
        )
        self.assertFalse(
            mphf.verify_absence(
                self.man.seq_root, self.man.size, q,
                mphf.AbsenceProof(predecessor=None, successor=forged_succ),
            )
        )

    def test_boundary_above_all(self):
        q = b"zz"  # 大于所有键
        proof = mphf.prove_absence(self.auth, q)
        self.assertIsNone(proof.successor)
        self.assertEqual(proof.predecessor.rank, self.man.size - 1)
        self.assertTrue(mphf.verify_absence(self.man.seq_root, self.man.size, q, proof))
        # 伪造：前驱秩不是尾秩 → 拒绝。
        forged_pred = mphf.NeighborProof(
            rank=self.man.size - 2,
            key=proof.predecessor.key,
            slot=proof.predecessor.slot,
            path=proof.predecessor.path,
        )
        self.assertFalse(
            mphf.verify_absence(
                self.man.seq_root, self.man.size, q,
                mphf.AbsenceProof(predecessor=forged_pred, successor=None),
            )
        )

    def test_member_query_returns_none(self):
        for k in self.keys:
            self.assertIsNone(mphf.prove_absence(self.auth, k))

    def test_non_adjacent_ranks_cannot_prove_absence(self):
        """仅给两个真实存在键的认证路径、秩不相邻，不能证明不存在。"""
        q = b"ak-055"  # 真实间隙在 ak-05/ak-06 之间
        real = mphf.prove_absence(self.auth, q)
        pred, succ = real.predecessor, real.successor
        # 把前驱换成秩更小（不相邻）的真实邻居：ak-03 的路径。
        gap = mphf.prove_absence(self.auth, b"ak-035")
        far_pred = gap.predecessor  # ak-03，秩 3
        self.assertEqual(succ.rank - far_pred.rank, 3)
        forged = mphf.AbsenceProof(predecessor=far_pred, successor=succ)
        # 两条路径各自都能通过根核验，但秩不相邻 ⇒ 必须拒绝。
        self.assertFalse(mphf.verify_absence(self.man.seq_root, self.man.size, q, forged))
        # 对称地：后继换成 ak-08（秩不相邻）。
        gap2 = mphf.prove_absence(self.auth, b"ak-085")
        forged2 = mphf.AbsenceProof(predecessor=pred, successor=gap2.successor)
        self.assertFalse(mphf.verify_absence(self.man.seq_root, self.man.size, q, forged2))

    def test_swapped_sides_rejected(self):
        q = b"ak-055"
        real = mphf.prove_absence(self.auth, q)
        swapped = mphf.AbsenceProof(
            predecessor=real.successor, successor=real.predecessor
        )
        self.assertFalse(mphf.verify_absence(self.man.seq_root, self.man.size, q, swapped))

    def test_tampered_neighbor_key_slot_rejected(self):
        q = b"ak-055"
        real = mphf.prove_absence(self.auth, q)
        succ = real.successor
        # 换键：叶编码绑定键字节。
        bad_key = mphf.NeighborProof(
            rank=succ.rank, key=b"ak-07", slot=succ.slot, path=succ.path
        )
        self.assertFalse(
            mphf.verify_absence(
                self.man.seq_root, self.man.size, q,
                mphf.AbsenceProof(real.predecessor, bad_key),
            )
        )
        # 换槽号：叶编码同时绑定原槽号。
        bad_slot = mphf.NeighborProof(
            rank=succ.rank, key=succ.key, slot=(succ.slot + 1) % self.man.size,
            path=succ.path,
        )
        self.assertFalse(
            mphf.verify_absence(
                self.man.seq_root, self.man.size, q,
                mphf.AbsenceProof(real.predecessor, bad_slot),
            )
        )

    def test_neighbor_truncated_and_appended_path_rejected(self):
        q = b"ak-055"
        real = mphf.prove_absence(self.auth, q)
        succ = real.successor
        for bad_path in (succ.path[:-1], succ.path + (b"\x00" * 32,)):
            bad = mphf.NeighborProof(
                rank=succ.rank, key=succ.key, slot=succ.slot, path=bad_path
            )
            self.assertFalse(
                mphf.verify_absence(
                    self.man.seq_root, self.man.size, q,
                    mphf.AbsenceProof(real.predecessor, bad),
                )
            )

    def test_absent_key_equal_to_neighbor_rejected(self):
        # 查询键其实等于某个邻居键（即是成员）时，不存在证明不得成立。
        proof = mphf.AbsenceProof(
            predecessor=mphf.prove_absence(self.auth, b"ak-045").predecessor,
            successor=mphf.prove_absence(self.auth, b"ak-055").successor,
        )
        self.assertFalse(
            mphf.verify_absence(self.man.seq_root, self.man.size, b"ak-05", proof)
        )

    def test_verifier_input_validation(self):
        q = b"ak-055"
        proof = mphf.prove_absence(self.auth, q)
        with self.assertRaises(ValueError):
            mphf.verify_absence(b"\x00" * 10, self.man.size, q, proof)
        with self.assertRaises(TypeError):
            mphf.verify_absence(self.man.seq_root, True, q, proof)
        with self.assertRaises(TypeError):
            mphf.verify_absence(self.man.seq_root, self.man.size, 123, proof)
        with self.assertRaises(TypeError):
            mphf.verify_absence(self.man.seq_root, self.man.size, q, object())


class EmptySetTests(unittest.TestCase):
    def test_empty_manifest_and_proofs(self):
        auth = make_auth([])
        man = auth.manifest()
        self.assertEqual(man.size, 0)
        # 空集合根单独定义：两棵树根都等于 EMPTY_ROOT 常量。
        self.assertEqual(man.slot_root, EMPTY)
        self.assertEqual(man.seq_root, EMPTY)
        self.assertEqual(man.slot_root, mphf.EMPTY_ROOT)
        # 成员证明：任何键都拿不到。
        self.assertIsNone(mphf.prove(auth, b"anything"))
        # 不存在证明：两侧皆空，核验通过。
        proof = mphf.prove_absence(auth, b"anything")
        self.assertIsNone(proof.predecessor)
        self.assertIsNone(proof.successor)
        self.assertTrue(mphf.verify_absence(man.seq_root, man.size, b"anything", proof))

    def test_empty_set_rejects_sided_or_wrong_root(self):
        auth = make_auth([])
        man = auth.manifest()
        one = make_auth([b"solo"])
        succ = mphf.prove_absence(one, b"a").successor
        # 空集合上硬塞一侧邻居 → 拒绝。
        sided = mphf.AbsenceProof(predecessor=None, successor=succ)
        self.assertFalse(mphf.verify_absence(man.seq_root, 0, b"x", sided))
        # 根不是空集合根 → 拒绝。
        both_none = mphf.AbsenceProof(predecessor=None, successor=None)
        self.assertFalse(mphf.verify_absence(one.seq_root, 0, b"x", both_none))
        # 成员证明在空集合上永不成立。
        fake = mphf.MembershipProof(slot=0, path=())
        self.assertFalse(mphf.verify_membership(man.slot_root, 0, b"x", fake))


class ManifestTests(unittest.TestCase):
    def test_manifest_composition(self):
        auth = make_auth(det_keys(7))
        man = auth.manifest()
        self.assertEqual(man.size, 7)
        self.assertEqual(man.slot_root, auth.slot_root)
        self.assertEqual(man.seq_root, auth.seq_root)
        self.assertEqual(man.version, mphf.PROOF_VERSION)

    def test_manifest_encoding_roundtrip_and_layout(self):
        auth = make_auth(det_keys(7))
        man = auth.manifest()
        blob = man.encode()
        self.assertEqual(blob, man.encode())  # 确定性
        self.assertTrue(blob.startswith(b"MPHF-MAN" + bytes([mphf.PROOF_VERSION])))
        # 布局：8 字节标签 + 1 字节版本 + 8 字节 size + 32 + 32。
        self.assertEqual(len(blob), 8 + 1 + 8 + 64)
        self.assertEqual(int.from_bytes(blob[9:17], "big"), 7)
        self.assertEqual(blob[17:49], man.slot_root)
        self.assertEqual(blob[49:81], man.seq_root)
        back = mphf.Manifest.decode(blob)
        self.assertEqual(back, man)
        self.assertEqual(back.encode(), blob)

    def test_manifest_decode_rejects_malformed(self):
        blob = make_auth(det_keys(3)).manifest().encode()
        with self.assertRaises(ValueError):
            mphf.Manifest.decode(blob[:-1])  # 截短
        with self.assertRaises(ValueError):
            mphf.Manifest.decode(blob + b"\x00")  # 追加
        with self.assertRaises(ValueError):
            mphf.Manifest.decode(blob[:8] + b"\x02" + blob[9:])  # 版本不符
        with self.assertRaises(TypeError):
            mphf.Manifest.decode("not bytes")


class ProofEncodingTests(unittest.TestCase):
    def setUp(self):
        self.keys = det_keys(9)
        self.auth = make_auth(self.keys)

    def test_membership_encoding_deterministic_roundtrip(self):
        p = mphf.prove(self.auth, self.keys[4])
        blob = p.encode()
        self.assertEqual(blob, p.encode())
        self.assertTrue(blob.startswith(b"MPHF-MEM" + bytes([mphf.PROOF_VERSION])))
        back = mphf.decode_membership_proof(blob)
        self.assertEqual(back, p)
        self.assertEqual(back.encode(), blob)
        man = self.auth.manifest()
        self.assertTrue(
            mphf.verify_membership(man.slot_root, man.size, self.keys[4], back)
        )

    def test_membership_decode_rejects_malformed(self):
        blob = mphf.prove(self.auth, self.keys[4]).encode()
        with self.assertRaises(ValueError):
            mphf.decode_membership_proof(blob[:-1])  # 截短
        with self.assertRaises(ValueError):
            mphf.decode_membership_proof(blob + b"\x00")  # 追加
        with self.assertRaises(ValueError):
            mphf.decode_membership_proof(blob[:8] + b"\x09" + blob[9:])  # 版本不符
        with self.assertRaises(TypeError):
            mphf.decode_membership_proof(None)

    def test_absence_encoding_roundtrip_all_shapes(self):
        cases = [b"ak-035", b"aa", b"zz"]  # 双侧 / 只有后继 / 只有前驱
        for q in cases:
            with self.subTest(q=q):
                proof = mphf.prove_absence(self.auth, q)
                blob = proof.encode()
                self.assertEqual(blob, proof.encode())
                self.assertTrue(
                    blob.startswith(b"MPHF-ABS" + bytes([mphf.PROOF_VERSION]))
                )
                back = mphf.decode_absence_proof(blob)
                self.assertEqual(back, proof)
                man = self.auth.manifest()
                self.assertTrue(
                    mphf.verify_absence(man.seq_root, man.size, q, back)
                )
        # 空集合（两侧皆空）形状。
        empty_proof = mphf.prove_absence(make_auth([]), b"x")
        back = mphf.decode_absence_proof(empty_proof.encode())
        self.assertEqual(back, empty_proof)

    def test_absence_decode_rejects_malformed(self):
        blob = mphf.prove_absence(self.auth, b"ak-035").encode()
        with self.assertRaises(ValueError):
            mphf.decode_absence_proof(blob[:-5])  # 截短
        with self.assertRaises(ValueError):
            mphf.decode_absence_proof(blob + b"\x00")  # 追加
        with self.assertRaises(ValueError):
            mphf.decode_absence_proof(blob[:8] + b"\x09" + blob[9:])  # 版本不符
        with self.assertRaises(ValueError):
            mphf.decode_absence_proof(blob[:9] + b"\x04" + blob[10:])  # 未知标志位


class AuthIndexBuildTests(unittest.TestCase):
    def test_build_auth_rejects_sentinel_and_bad_types(self):
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            failed = mphf.build([b"a", b"b", b"i"])  # seed=0 真实不可剥离
        self.assertIs(failed, mphf.CONSTRUCTION_FAILED)
        with self.assertRaises(ValueError):
            mphf.build_auth(failed)
        with self.assertRaises(TypeError):
            mphf.build_auth("not a table")
        with self.assertRaises(TypeError):
            mphf.prove("not an index", b"k")
        with self.assertRaises(TypeError):
            mphf.prove_absence(None, b"k")

    def test_auth_index_does_not_mutate_table_and_lookup_unaffected(self):
        keys = det_keys(20)
        t = mphf.build(keys)
        before = (t.seed, t.values, t.keys)
        auth = mphf.build_auth(t)
        self.assertEqual((t.seed, t.values, t.keys), before)
        # 原 lookup 仍核对原键：成员命中、非成员拒绝。
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(t, k), i)
        self.assertEqual(mphf.lookup(t, b"ak-020"), mphf.NOT_FOUND)
        self.assertIs(auth.table, t)

    def test_prove_type_errors(self):
        auth = make_auth(det_keys(3))
        for bad in (1, 1.5, "k", None, True, [b"k"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.prove(auth, bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.prove_absence(auth, bad)

    def test_large_set_proof_depth(self):
        # 上限规模 n=1000：路径长度等于独立计算的树深，核验通过。
        keys = det_keys(1000)
        auth = make_auth(keys)
        man = auth.manifest()
        p = mphf.prove(auth, keys[999])
        self.assertEqual(len(p.path), ref_depth(1000))
        self.assertTrue(mphf.verify_membership(man.slot_root, man.size, keys[999], p))
        q = b"ak-0999 "
        ap = mphf.prove_absence(auth, q)
        self.assertTrue(mphf.verify_absence(man.seq_root, man.size, q, ap))


if __name__ == "__main__":
    unittest.main(verbosity=2)
