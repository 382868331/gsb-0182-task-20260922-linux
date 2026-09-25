"""mphf 索引认证扩展（槽位 Merkle 树 + 键序认证序列）的必要测试。

期望值来源（独立于被测核心）：

* 测试侧按 README 公开的 v1 线格式，直接用 hashlib 独立拼装叶/内部节点
  哈希并独立构树（含 1、3、5 键树的**手算逐步展开**），不调用被测模块
  的内部哈希函数来产生期望值；
* 库出具的证明仅作为被验证对象；验证器的接受/拒绝均与手算或独立参考
  对照。
"""

from __future__ import annotations

import hashlib
import unittest

import mphf


# ----------------------------------------------------------- 测试侧独立参考
# 以下函数按公开线格式直接调用 hashlib，不调用 mphf 的任何内部实现。

def t_leaf_slot(slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        b"\x00" + slot.to_bytes(8, "big") + len(key).to_bytes(8, "big") + key
    ).digest()


def t_leaf_sorted(slot: int, key: bytes) -> bytes:
    return hashlib.sha256(
        b"\x02" + slot.to_bytes(8, "big") + len(key).to_bytes(8, "big") + key
    ).digest()


def t_internal(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


T_EMPTY_ROOT = hashlib.sha256(b"\x03mphf-auth-empty-root-v1").digest()


def t_root(leaves: list[bytes]) -> bytes:
    """独立构树：奇数层末节点复制配对；空集合根单独定义。"""
    if not leaves:
        return T_EMPTY_ROOT
    cur = list(leaves)
    while len(cur) > 1:
        if len(cur) % 2 == 1:
            cur.append(cur[-1])
        cur = [t_internal(cur[i], cur[i + 1]) for i in range(0, len(cur), 2)]
    return cur[0]


def det_keys(n: int, salt: str = "k") -> list[bytes]:
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


# --------------------------------------------------------------------- 测试


class HandComputedTreeTests(unittest.TestCase):
    """1、3、5 键树：手算展开的根与路径。"""

    def test_single_key_tree(self):
        t = mphf.build([b"only"])
        idx = mphf.build_authenticated(t)
        leaf = t_leaf_slot(0, b"only")
        self.assertEqual(idx.manifest.slot_root, leaf)          # 单叶根即叶
        self.assertEqual(idx.manifest.sorted_root, t_leaf_sorted(0, b"only"))
        self.assertEqual(idx.manifest.size, 1)
        p = idx.prove(b"only")
        self.assertEqual(p.slot, 0)
        self.assertEqual(p.path, ())                            # 深度 0，空路径
        self.assertTrue(mphf.verify_membership(leaf, 1, b"only", p))

    def test_three_key_tree(self):
        keys = [b"a", b"b", b"i"]   # 真实集合：seed=2 才构造成功
        t = mphf.build(keys)
        idx = mphf.build_authenticated(t)
        # 手算：L0 L1 L2 → H01=I(L0,L1)，L2 复制配对 H22=I(L2,L2) → R=I(H01,H22)
        L = [t_leaf_slot(i, k) for i, k in enumerate(keys)]
        h01 = t_internal(L[0], L[1])
        h22 = t_internal(L[2], L[2])
        root = t_internal(h01, h22)
        self.assertEqual(idx.manifest.slot_root, root)
        # 手算路径：槽 2（奇数层末节点，兄弟即自身）
        p2 = idx.prove(b"i")
        self.assertEqual(p2.slot, 2)
        self.assertEqual(p2.path, ((mphf.SIDE_RIGHT, L[2]), (mphf.SIDE_LEFT, h01)))
        self.assertTrue(mphf.verify_membership(root, 3, b"i", p2))
        # 手算路径：槽 0
        p0 = idx.prove(b"a")
        self.assertEqual(p0.path, ((mphf.SIDE_RIGHT, L[1]), (mphf.SIDE_RIGHT, h22)))
        self.assertTrue(mphf.verify_membership(root, 3, b"a", p0))
        # 键序树：sorted([a,b,i]) 恰为构造序，槽号随叶绑定
        SL = [t_leaf_sorted(i, k) for i, k in enumerate(keys)]
        s_root = t_internal(t_internal(SL[0], SL[1]), t_internal(SL[2], SL[2]))
        self.assertEqual(idx.manifest.sorted_root, s_root)

    def test_five_key_tree(self):
        keys = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
        t = mphf.build(keys)
        idx = mphf.build_authenticated(t)
        # 手算两层复制配对：
        #   层1: a=I(L0,L1) b=I(L2,L3) c=I(L4,L4)
        #   层2: d=I(a,b)   e=I(c,c)
        #   根:  R=I(d,e)
        L = [t_leaf_slot(i, k) for i, k in enumerate(keys)]
        a = t_internal(L[0], L[1])
        b = t_internal(L[2], L[3])
        c = t_internal(L[4], L[4])
        d = t_internal(a, b)
        e = t_internal(c, c)
        root = t_internal(d, e)
        self.assertEqual(idx.manifest.slot_root, root)
        # 手算路径：槽 4（连续两次末节点复制配对）
        p4 = idx.prove(b"epsilon")
        self.assertEqual(p4.slot, 4)
        self.assertEqual(
            p4.path,
            ((mphf.SIDE_RIGHT, L[4]), (mphf.SIDE_RIGHT, c), (mphf.SIDE_LEFT, d)),
        )
        self.assertTrue(mphf.verify_membership(root, 5, b"epsilon", p4))
        # 手算路径：槽 3
        p3 = idx.prove(b"delta")
        self.assertEqual(
            p3.path,
            ((mphf.SIDE_LEFT, L[2]), (mphf.SIDE_LEFT, a), (mphf.SIDE_RIGHT, e)),
        )
        self.assertTrue(mphf.verify_membership(root, 5, b"delta", p3))

    def test_independent_root_crosscheck_various_sizes(self):
        """独立构树参考与库的根逐一对照（含奇偶各种规模）。"""
        for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 31, 100):
            with self.subTest(n=n):
                keys = det_keys(n)
                t = mphf.build(keys)
                idx = mphf.build_authenticated(t)
                slot_leaves = [t_leaf_slot(i, k) for i, k in enumerate(keys)]
                self.assertEqual(idx.manifest.slot_root, t_root(slot_leaves))
                slot_of = {k: i for i, k in enumerate(keys)}
                sorted_leaves = [
                    t_leaf_sorted(slot_of[k], k) for k in sorted(keys)
                ]
                self.assertEqual(idx.manifest.sorted_root, t_root(sorted_leaves))


class MembershipProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = det_keys(30)
        cls.table = mphf.build(cls.keys)
        cls.idx = mphf.build_authenticated(cls.table)
        cls.man = cls.idx.manifest

    def test_all_members_prove_and_verify(self):
        for i, k in enumerate(self.keys):
            p = self.idx.prove(k)
            self.assertIsNotNone(p)
            self.assertEqual(p.slot, i)
            self.assertTrue(
                mphf.verify_membership(self.man.slot_root, self.man.size, k, p)
            )

    def test_prove_nonmember_returns_none(self):
        self.assertIsNone(self.idx.prove(b"k-30"))
        self.assertIsNone(self.idx.prove(b""))
        self.assertIsNone(self.idx.prove(b"\xff"))   # 非 ASCII 查询按非成员

    def test_swapped_key_fails(self):
        """换键：用键 A 的证明去验键 B，必须失败。"""
        p = self.idx.prove(self.keys[5])
        self.assertFalse(
            mphf.verify_membership(
                self.man.slot_root, self.man.size, self.keys[6], p
            )
        )

    def test_swapped_slot_fails(self):
        """换槽号：同一键配别的槽号（含越界槽号），必须失败。"""
        p = self.idx.prove(self.keys[5])
        forged = mphf.SlotProof(slot=(p.slot + 1) % self.man.size, path=p.path)
        self.assertFalse(
            mphf.verify_membership(
                self.man.slot_root, self.man.size, self.keys[5], forged
            )
        )
        for bad_slot in (self.man.size, -1):
            out = mphf.SlotProof(slot=bad_slot, path=p.path)
            self.assertFalse(
                mphf.verify_membership(
                    self.man.slot_root, self.man.size, self.keys[5], out
                )
            )

    def test_truncated_path_fails(self):
        """截短路径：形状核对（深度不符）直接拒绝。"""
        p = self.idx.prove(self.keys[5])
        self.assertGreater(len(p.path), 0)
        short = mphf.SlotProof(slot=p.slot, path=p.path[:-1])
        self.assertFalse(
            mphf.verify_membership(
                self.man.slot_root, self.man.size, self.keys[5], short
            )
        )

    def test_appended_node_fails(self):
        """追加节点：形状核对（深度不符）直接拒绝。"""
        p = self.idx.prove(self.keys[5])
        long = mphf.SlotProof(
            slot=p.slot, path=p.path + ((mphf.SIDE_LEFT, b"\x00" * 32),)
        )
        self.assertFalse(
            mphf.verify_membership(
                self.man.slot_root, self.man.size, self.keys[5], long
            )
        )

    def test_wrong_root_or_size_fails(self):
        p = self.idx.prove(self.keys[5])
        k = self.keys[5]
        self.assertFalse(mphf.verify_membership(b"\x00" * 32, self.man.size, k, p))
        # size 作为形状/范围核对：树深随 size 变化时，路径形状不符 ⇒ 拒绝。
        # n=30 的深度为 5；16 的深度为 4、33 的深度为 6。
        self.assertFalse(mphf.verify_membership(self.man.slot_root, 16, k, p))
        self.assertFalse(mphf.verify_membership(self.man.slot_root, 33, k, p))
        # 根长度/类型不符、size 非法、证明类型不符：一律 False 而非异常
        self.assertFalse(mphf.verify_membership(b"short", self.man.size, k, p))
        self.assertFalse(mphf.verify_membership(self.man.slot_root, 0, k, p))
        self.assertFalse(mphf.verify_membership(self.man.slot_root, True, k, p))
        self.assertFalse(
            mphf.verify_membership(self.man.slot_root, self.man.size, k, "not a proof")
        )

    def test_malformed_path_steps_fail(self):
        p = self.idx.prove(self.keys[5])
        k, n, root = self.keys[5], self.man.size, self.man.slot_root
        bad_side = mphf.SlotProof(p.slot, ((2, p.path[0][1]),) + p.path[1:])
        bad_len = mphf.SlotProof(p.slot, ((0, b"\x00" * 16),) + p.path[1:])
        self.assertFalse(mphf.verify_membership(root, n, k, bad_side))
        self.assertFalse(mphf.verify_membership(root, n, k, bad_len))


class AbsenceProofTests(unittest.TestCase):
    # 构造序（槽号）与键序不同，检验键序树叶对原槽号的绑定。
    KEYS = [b"g1", b"a1", b"e1", b"c1"]          # 槽: 0  1  2  3
    # 键序: a1(槽1,秩0)  c1(槽3,秩1)  e1(槽2,秩2)  g1(槽0,秩3)

    @classmethod
    def setUpClass(cls):
        cls.table = mphf.build(cls.KEYS)
        cls.idx = mphf.build_authenticated(cls.table)
        cls.man = cls.idx.manifest

    def test_absence_middle_gap(self):
        q = b"d1"                                  # c1 < d1 < e1
        proof = self.idx.prove_absence(q)
        self.assertIsNotNone(proof)
        self.assertEqual((proof.predecessor.key, proof.predecessor.rank,
                          proof.predecessor.slot), (b"c1", 1, 3))
        self.assertEqual((proof.successor.key, proof.successor.rank,
                          proof.successor.slot), (b"e1", 2, 2))
        self.assertTrue(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, proof)
        )

    def test_absence_boundary_low(self):
        """下边界：只有后继，核验首秩 rank == 0。"""
        q = b"0"
        proof = self.idx.prove_absence(q)
        self.assertIsNone(proof.predecessor)
        self.assertEqual(proof.successor.rank, 0)
        self.assertEqual(proof.successor.key, b"a1")
        self.assertTrue(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, proof)
        )
        # 伪造秩：把后继秩改成 1，首尾秩核验必须拒绝
        s = proof.successor
        forged = mphf.AbsenceProof(
            None, mphf.SortedProof(rank=1, key=s.key, slot=s.slot, path=s.path)
        )
        self.assertFalse(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, forged)
        )

    def test_absence_boundary_high(self):
        """上边界：只有前驱，核验尾秩 rank == size-1。"""
        q = b"zz"
        proof = self.idx.prove_absence(q)
        self.assertIsNone(proof.successor)
        self.assertEqual(proof.predecessor.rank, self.man.size - 1)
        self.assertEqual(proof.predecessor.key, b"g1")
        self.assertTrue(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, proof)
        )
        p = proof.predecessor
        forged = mphf.AbsenceProof(
            mphf.SortedProof(rank=p.rank - 1, key=p.key, slot=p.slot, path=p.path),
            None,
        )
        self.assertFalse(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, forged)
        )

    def test_non_adjacent_ranks_fail(self):
        """非相邻前后驱：两个真实存在键、秩不相邻，不能证明不存在。"""
        q = b"d1"                                  # 真实间隙在秩 1..2
        real = self.idx.prove_absence(q)
        low = self.idx.prove_absence(b"0")         # 其后继为秩 0 的真实证明
        rank0 = low.successor                      # a1，秩 0，真实成员
        rank2 = real.successor                     # e1，秩 2，真实成员
        self.assertLess(rank0.key, q)
        self.assertLess(q, rank2.key)
        forged = mphf.AbsenceProof(predecessor=rank0, successor=rank2)
        # 两个证明各自都能通过成员核验，但秩 0 与 2 不相邻 ⇒ 拒绝
        self.assertFalse(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, forged)
        )

    def test_wrong_side_order_fails(self):
        """前驱键不小于查询键 / 后继键不大于查询键时必须拒绝。"""
        q = b"d1"
        real = self.idx.prove_absence(q)
        swapped = mphf.AbsenceProof(real.successor, real.predecessor)
        self.assertFalse(
            mphf.verify_absence(self.man.sorted_root, self.man.size, q, swapped)
        )

    def test_member_cannot_be_proven_absent(self):
        self.assertIsNone(self.idx.prove_absence(b"c1"))
        # 用成员自身的键序证明冒充“后继”：succ.key > key 不成立 ⇒ 拒绝
        low = self.idx.prove_absence(b"c0")        # 后继即 c1
        forged = mphf.AbsenceProof(low.predecessor, low.successor)
        self.assertFalse(
            mphf.verify_absence(self.man.sorted_root, self.man.size, b"c1", forged)
        )

    def test_absence_key_type_errors(self):
        with self.assertRaises(TypeError):
            self.idx.prove_absence("d1")
        with self.assertRaises(TypeError):
            mphf.verify_absence(self.man.sorted_root, self.man.size, 123,
                                self.idx.prove_absence(b"d1"))


class EmptySetAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.idx = mphf.build_authenticated(mphf.build([]))
        cls.man = cls.idx.manifest

    def test_empty_roots_are_the_defined_empty_root(self):
        self.assertEqual(self.man.size, 0)
        self.assertEqual(self.man.slot_root, T_EMPTY_ROOT)
        self.assertEqual(self.man.sorted_root, T_EMPTY_ROOT)
        self.assertEqual(self.man.slot_root, mphf.EMPTY_ROOT)

    def test_empty_prove_and_absence(self):
        self.assertIsNone(self.idx.prove(b"x"))
        ap = self.idx.prove_absence(b"x")
        self.assertIsNone(ap.predecessor)
        self.assertIsNone(ap.successor)
        self.assertTrue(mphf.verify_absence(mphf.EMPTY_ROOT, 0, b"x", ap))

    def test_empty_rejects_any_membership(self):
        self.assertFalse(
            mphf.verify_membership(
                mphf.EMPTY_ROOT, 0, b"x", mphf.SlotProof(slot=0, path=())
            )
        )

    def test_empty_absence_tampering_fails(self):
        ap = self.idx.prove_absence(b"x")
        self.assertFalse(mphf.verify_absence(b"\x00" * 32, 0, b"x", ap))
        # 非空 size 下两侧皆空不能证明不存在
        self.assertFalse(mphf.verify_absence(mphf.EMPTY_ROOT, 3, b"x", ap))


class ManifestAndEncodingTests(unittest.TestCase):
    def test_manifest_determinism_and_version(self):
        keys = det_keys(12)
        m1 = mphf.build_authenticated(mphf.build(keys)).manifest
        m2 = mphf.build_authenticated(mphf.build(keys)).manifest
        self.assertEqual(m1, m2)
        self.assertEqual(m1.version, mphf.PROOF_FORMAT_VERSION)
        self.assertEqual(m1.version, 1)
        enc = m1.encode()
        self.assertTrue(enc.startswith(b"MPHF-MANIFEST\x01"))
        self.assertEqual(len(enc), len(b"MPHF-MANIFEST") + 1 + 8 + 32 + 32)
        self.assertEqual(m1.digest(), hashlib.sha256(enc).digest())
        self.assertEqual(m1.encode(), m2.encode())

    def test_proof_encodings_deterministic_and_versioned(self):
        idx = mphf.build_authenticated(mphf.build(det_keys(7)))
        p = idx.prove(b"k-03")
        self.assertTrue(p.encode().startswith(b"MPHF-SLOT-PROOF\x01"))
        self.assertEqual(p.encode(), p.encode())
        ap = idx.prove_absence(b"k-03x")
        self.assertTrue(ap.encode().startswith(b"MPHF-ABSENCE-PROOF\x01"))
        self.assertTrue(ap.predecessor.encode().startswith(b"MPHF-SORTED-PROOF\x01"))
        self.assertEqual(ap.encode(), ap.encode())

    def test_distinct_sets_distinct_manifests(self):
        a = mphf.build_authenticated(mphf.build([b"a"])).manifest
        b = mphf.build_authenticated(mphf.build([b"b"])).manifest
        self.assertNotEqual(a.digest(), b.digest())


class AuthInputValidationTests(unittest.TestCase):
    def test_build_authenticated_rejects_sentinel_and_wrong_types(self):
        with self.assertRaises(ValueError):
            mphf.build_authenticated(mphf.CONSTRUCTION_FAILED)
        for bad in ("table", None, 123, [b"a"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.build_authenticated(bad)

    def test_prove_key_type_errors(self):
        idx = mphf.build_authenticated(mphf.build([b"a"]))
        for bad in (1, "a", None, True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                idx.prove(bad)
        with self.assertRaises(TypeError):
            mphf.verify_membership(idx.manifest.slot_root, 1, "a",
                                   idx.prove(b"a"))

    def test_original_lookup_unchanged(self):
        """原 lookup 仍核对原键：认证扩展不改变既有行为。"""
        keys = det_keys(10)
        t = mphf.build(keys)
        mphf.build_authenticated(t)  # 构建认证索引不影响原表
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(t, k), i)
        self.assertEqual(mphf.lookup(t, b"k-10"), mphf.NOT_FOUND)


class RoundTripSweepTests(unittest.TestCase):
    """多规模往返：成员证明与不存在证明全部离线验证通过。"""

    def test_sweep(self):
        for n in (1, 2, 3, 5, 8, 13, 40):
            with self.subTest(n=n):
                keys = det_keys(n, salt=f"s{n}")
                idx = mphf.build_authenticated(mphf.build(keys))
                man = idx.manifest
                for k in keys:
                    p = idx.prove(k)
                    self.assertTrue(
                        mphf.verify_membership(man.slot_root, man.size, k, p)
                    )
                    self.assertIsNone(idx.prove_absence(k))
                probes = [f"s{n}-x{i}".encode() for i in range(5)] + [b"", b"~~"]
                for q in probes:
                    self.assertIsNone(idx.prove(q))
                    ap = idx.prove_absence(q)
                    self.assertTrue(
                        mphf.verify_absence(man.sorted_root, man.size, q, ap)
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
