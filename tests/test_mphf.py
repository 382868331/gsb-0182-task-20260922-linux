"""mphf 模块的必要测试。

测试中的期望值来源：

* 哈希向量由**测试侧独立实现**（直接用 hashlib 按题面契约自行拼装
  SHA256(seed_be4 || tag || key)）得到，不调用 mphf 的内部哈希；
* 双射性质（槽位为 0..n-1 的排列、三顶点赋值之和模 n 等于键序号）
  用独立哈希对结果表字段重新计算验证；
* 往返一致（build 后 lookup 成员命中）仅作为补充断言。
"""

from __future__ import annotations

import hashlib
import itertools
import unittest
from collections import Counter
from unittest.mock import patch

import mphf


# ----------------------------------------------------------- 测试侧独立参考


def ref_h(seed: int, tag: int, key: bytes, m: int) -> int:
    """按公开契约独立实现的哈希，不调用被测模块的任何函数。"""
    assert 0 <= seed <= 0xFFFFFFFF
    assert tag in (0, 1, 2)
    digest = hashlib.sha256(seed.to_bytes(4, "big") + bytes([tag]) + key).digest()
    return int.from_bytes(digest, "big") % m


def ref_slot(table: mphf.MPHFTable, key: bytes) -> int:
    """独立根据表字段计算键的槽位。"""
    m, n, g, seed = table.vertex_count, table.size, table.values, table.seed
    return (
        g[ref_h(seed, 0, key, m)]
        + g[ref_h(seed, 1, key, m)]
        + g[ref_h(seed, 2, key, m)]
    ) % n


def det_keys(n: int, salt: str = "k") -> list[bytes]:
    """确定性 ASCII 键生成（仓库内代码生成，无外部语料）。"""
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


# --------------------------------------------------------------------- 测试


class PublicTypesTests(unittest.TestCase):
    def test_constants_contract(self):
        self.assertEqual(mphf.MAX_KEYS, 1000)
        self.assertEqual(mphf.MAX_SEED_ATTEMPTS, 256)
        self.assertEqual(mphf.NOT_FOUND, -1)
        self.assertIsInstance(mphf.CONSTRUCTION_FAILED, mphf.ConstructionFailure)
        self.assertEqual(repr(mphf.CONSTRUCTION_FAILED), "construction_failed")

    def test_vertex_count_is_exact_ceil(self):
        # m = ceil(1.4n)，纯整数；抽查边界值。
        expected = {1: 2, 2: 3, 3: 5, 5: 7, 7: 10, 10: 14, 1000: 1400}
        for n, want in expected.items():
            self.assertEqual(mphf._vertex_count(n), want)
        # 一般性质：对 1..1000 与分数精算式逐一对照
        for n in range(1, 1001):
            self.assertEqual(mphf._vertex_count(n), (14 * n + 9) // 10)


class HashEncodingTests(unittest.TestCase):
    """哈希线格式：seed=4 字节大端，标签=单字节 0/1/2。"""

    def test_independent_hash_vectors(self):
        # 期望值由测试侧直接对 hashlib 结果取模得出（见文件头说明）。
        digest0 = hashlib.sha256(b"\x00\x00\x00\x00" + b"\x00" + b"a").digest()
        self.assertEqual(digest0.hex()[:8], "02c17dbb")  # 锚定独立实现
        self.assertEqual(ref_h(0, 0, b"a", 7), int.from_bytes(digest0, "big") % 7)
        self.assertEqual(ref_h(0, 0, b"a", 7), 0)
        d1 = hashlib.sha256(b"\x00\x00\x00\x01" + b"\x02" + b"abc").digest()
        self.assertEqual(ref_h(1, 2, b"abc", 5), int.from_bytes(d1, "big") % 5)
        self.assertEqual(ref_h(1, 2, b"abc", 5), 3)

    def test_core_matches_wire_contract(self):
        # 被测核心必须与线格式一致（这里才允许与核心对拍编码本身）。
        for seed, tag, key, m in [(0, 0, b"a", 7), (1, 2, b"abc", 5),
                                  (255, 1, b"zzz", 13)]:
            self.assertEqual(mphf._hash_vertex(seed, tag, key, m),
                             ref_h(seed, tag, key, m))


class EmptyTableTests(unittest.TestCase):
    def test_empty_build_and_lookup(self):
        t = mphf.build([])
        self.assertIsInstance(t, mphf.MPHFTable)
        self.assertEqual(t.size, 0)
        self.assertEqual(t.vertex_count, 0)
        self.assertEqual(t.seed, 0)
        self.assertEqual(t.values, ())
        self.assertEqual(t.keys, ())
        self.assertEqual(t.attempts, 0)
        for q in (b"", b"anything", b"\xff"):
            self.assertEqual(mphf.lookup(t, q), mphf.NOT_FOUND)
        self.assertEqual(t.lookup(b"x"), -1)

    def test_empty_from_generator(self):
        t = mphf.build(iter(()))
        self.assertEqual(t.size, 0)
        self.assertEqual(mphf.lookup(t, b"a"), -1)


class BijectionTests(unittest.TestCase):
    """枚举小键集验证双射，并用独立参考验证赋值方程。"""

    def assert_perfect_table(self, keys):
        keys = list(keys)
        n = len(keys)
        t = mphf.build(keys)
        self.assertIsInstance(t, mphf.MPHFTable, f"build failed for n={n}")
        self.assertEqual(t.size, n)
        self.assertEqual(t.vertex_count, (14 * n + 9) // 10)
        self.assertEqual(len(t.values), t.vertex_count)
        self.assertTrue(all(0 <= g < n for g in t.values))
        self.assertEqual(len(t.keys), n)
        # 1) 成员槽位恰为 0..n-1 的排列（双射/最小性）
        slots = [ref_slot(t, k) for k in keys]
        self.assertEqual(sorted(slots), list(range(n)))
        # 2) 独立方程校验：g[h0]+g[h1]+g[h2] ≡ 键序号 (mod n)
        for i, k in enumerate(keys):
            self.assertEqual(ref_slot(t, k), i)
            self.assertEqual(t.keys[i], keys[i])
        # 3) 往返一致（补充断言）
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(t, k), i)

    def test_prefix_sets_n_1_to_60(self):
        for n in range(1, 61):
            with self.subTest(n=n):
                self.assert_perfect_table(det_keys(n))

    def test_single_key_edge_cases(self):
        for k in (b"", b"a", b"zzzzzzzzzz", b"~", b" "):
            t = mphf.build([k])
            self.assertEqual(mphf.lookup(t, k), 0)
            self.assertEqual(t.vertex_count, 2)

    def test_mixed_ascii_family(self):
        # 确定性生成的多种 ASCII 键集
        families = [
            [bytes([c]) for c in range(0x21, 0x7F)],                 # 全部可见 ASCII
            [f"f{i:04d}".encode() for i in range(0, 250, 3)],
            [i.to_bytes(2, "big") for i in range(0, 20000, 137) if max(i.to_bytes(2, "big")) < 0x80],
        ]
        for fam in families:
            self.assert_perfect_table(fam)

    def test_boundary_size_1000(self):
        keys = det_keys(1000)
        t = mphf.build(keys)
        self.assertIsInstance(t, mphf.MPHFTable)
        self.assertEqual(t.size, 1000)
        self.assertEqual(t.vertex_count, 1400)
        slots = [ref_slot(t, k) for k in keys]
        self.assertEqual(sorted(slots), list(range(1000)))
        # 抽查 lookup
        for i in (0, 1, 256, 999):
            self.assertEqual(mphf.lookup(t, keys[i]), i)

    def test_determinism_same_input_same_table(self):
        keys = det_keys(20)
        a, b = mphf.build(keys), mphf.build(keys)
        self.assertEqual((a.seed, a.values, a.keys, a.attempts),
                         (b.seed, b.values, b.keys, b.attempts))


class UnpeelableAndRetryTests(unittest.TestCase):
    """{a,b,i} 在 seed=0 下是真实的不可剥离超图。"""

    UNPEELABLE = [b"a", b"b", b"i"]

    def test_seed0_graph_independently_unpeelable(self):
        # 测试侧独立算出 seed=0 的边，并独立验证其 2-核非空：
        # 所有顶点的（按不同顶点计的）度都不等于 1。
        m = 5
        edges = [tuple(ref_h(0, t, k, m) for t in range(3)) for k in self.UNPEELABLE]
        self.assertEqual(edges, [(1, 1, 1), (2, 4, 4), (2, 4, 1)])
        deg = Counter()
        for e in edges:
            deg.update(set(e))
        self.assertTrue(all(deg[v] != 1 for v in deg))
        # 没有任何度为 1 的顶点 ⇒ 剥离过程一步也不能进行。
        self.assertEqual(mphf._peel(edges, m), [])

    def test_retry_succeeds_at_seed_2(self):
        t = mphf.build(self.UNPEELABLE)
        self.assertIsInstance(t, mphf.MPHFTable)
        self.assertEqual(t.seed, 2)          # seed 0、1 失败，2 成功
        self.assertEqual(t.attempts, 3)
        # 成功后仍满足方程与双射
        for i, k in enumerate(self.UNPEELABLE):
            self.assertEqual(ref_slot(t, k), i)
            self.assertEqual(mphf.lookup(t, k), i)

    def test_retry_budget_exhausted_returns_sentinel(self):
        # 主动把预算压到 1：seed=0 真实不可剥离 ⇒ 预算耗尽。
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            result = mphf.build(self.UNPEELABLE)
        self.assertIs(result, mphf.CONSTRUCTION_FAILED)
        self.assertEqual(result.attempts, 256)  # 规范单例恒定记录满预算语义
        # 失败哨兵不能用于查询
        with self.assertRaises(ValueError):
            mphf.lookup(result, b"a")

    def test_budget_two_still_fails_then_full_succeeds(self):
        # seed 0 与 1 都失败：预算 2 同样耗尽，满预算成功。
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 2):
            self.assertIs(mphf.build(self.UNPEELABLE), mphf.CONSTRUCTION_FAILED)
        self.assertIsInstance(mphf.build(self.UNPEELABLE), mphf.MPHFTable)

    def test_no_partial_state_on_failure(self):
        # 失败是通过返回值报告的；调用方原有对象不受影响（表不可变）。
        t_good = mphf.build(det_keys(4))
        before = (t_good.seed, t_good.values)
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            mphf.build(self.UNPEELABLE)
        self.assertEqual((t_good.seed, t_good.values), before)


class NonMemberTests(unittest.TestCase):
    def test_nonmembers_never_hit(self):
        keys = det_keys(30)
        t = mphf.build(keys)
        for q in [b"", b"k-00 ", b"k-030", b"K-000", b"x", b"k-0000"]:
            self.assertNotIn(q, keys)
            self.assertEqual(mphf.lookup(t, q), mphf.NOT_FOUND, q)

    def test_nonmember_hash_collision_still_rejected(self):
        """非成员即使哈希槽位被占用，也必须因完整键不等而 not_found。"""
        keys = det_keys(8)
        t = mphf.build(keys)
        n = t.size
        # 用独立哈希寻找一个“落到已占用槽位”的真实非成员
        occupied_slots = {ref_slot(t, k) for k in keys}
        self.assertEqual(occupied_slots, set(range(n)))  # 完美哈希：槽位全占
        collider = None
        for x in range(100000):
            cand = f"collide-{x}".encode()
            if cand not in keys and ref_slot(t, cand) in occupied_slots:
                collider = cand
                break
        self.assertIsNotNone(collider, "应能找到槽位碰撞的非成员（n=8 槽位很挤）")
        # 它确实被哈希函数送到某个成员槽位……
        self.assertIn(ref_slot(t, collider), occupied_slots)
        # ……但完整键终检拒绝命中。
        self.assertEqual(mphf.lookup(t, collider), mphf.NOT_FOUND)
        self.assertIsNone(t.get(collider))
        self.assertEqual(t.get(collider, "default"), "default")

    def test_non_ascii_lookup_is_not_found(self):
        t = mphf.build([b"abc", b"def"])
        for q in (b"ab\xff", b"\x80", "café".encode("utf-8"), b"abc\x00\xff"):
            self.assertEqual(mphf.lookup(t, q), mphf.NOT_FOUND)


class InputValidationTests(unittest.TestCase):
    def test_duplicate_rejected_with_location(self):
        with self.assertRaises(mphf.DuplicateKeyError) as cm:
            mphf.build([b"a", b"b", b"a"])
        self.assertEqual(cm.exception.key, b"a")
        self.assertEqual(cm.exception.index, 2)
        self.assertIsInstance(cm.exception, ValueError)

    def test_duplicate_bytearray_vs_bytes(self):
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build([b"same", bytearray(b"same")])

    def test_non_ascii_build_rejected(self):
        with self.assertRaises(ValueError):
            mphf.build([b"ok", b"bad\xff"])
        with self.assertRaises(ValueError):
            mphf.build([b"\x7f", b"\x80"])

    def test_key_type_errors(self):
        for bad in (1, 1.0, "str", None, [b"ok"], True, False, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.build([b"ok", bad])

    def test_bool_not_silently_accepted_as_int(self):
        # bool 是 int 子类，但键位上一律 TypeError；不存在可传 bool 的整数参数。
        with self.assertRaises(TypeError):
            mphf.build([True])

    def test_keys_container_type(self):
        with self.assertRaises(TypeError):
            mphf.build(b"abc")          # 单个 bytes 不是键集合
        with self.assertRaises(TypeError):
            mphf.build(123)
        with self.assertRaises(TypeError):
            mphf.build(None)

    def test_too_many_keys(self):
        keys = det_keys(1001)
        with self.assertRaises(ValueError):
            mphf.build(keys)
        with self.assertRaises(ValueError):
            mphf.build(iter(keys))

    def test_generator_of_keys_accepted(self):
        t = mphf.build((f"g{i}".encode() for i in range(7)))
        self.assertEqual(t.size, 7)
        self.assertEqual(mphf.lookup(t, b"g3"), 3)

    def test_bytes_like_inputs(self):
        t = mphf.build([bytearray(b"a"), memoryview(b"b")])
        self.assertEqual(mphf.lookup(t, bytearray(b"a")), 0)
        self.assertEqual(mphf.lookup(t, memoryview(b"b")), 1)

    def test_lookup_type_errors(self):
        t = mphf.build([b"a"])
        for bad in (1, 1.5, "a", None, True, [b"a"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.lookup(t, bad)
        with self.assertRaises(TypeError):
            mphf.lookup("not a table", b"a")
        with self.assertRaises(TypeError):
            mphf.lookup(None, b"a")

    def test_error_is_before_construction_on_bad_input(self):
        # 非法输入在收集阶段即报错，不存在部分构造结果外泄。
        gen = iter([b"ok", b"bad\xff"])
        with self.assertRaises(ValueError):
            mphf.build(gen)
        gen2 = iter([b"ok", b"ok"])
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build(gen2)


class AllAsciiCoverageTests(unittest.TestCase):
    def test_all_single_ascii_bytes(self):
        keys = [bytes([c]) for c in range(0, 128)]
        t = mphf.build(keys)
        self.assertIsInstance(t, mphf.MPHFTable)
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(t, k), i)
        # 邻近非成员
        self.assertEqual(mphf.lookup(t, b"\x80"), -1)
        self.assertEqual(mphf.lookup(t, b"aa"), -1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
