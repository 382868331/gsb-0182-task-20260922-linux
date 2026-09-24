"""MutableIndex（增删差量 + 墓碑 + 显式合并）的必要测试。

期望值来源（不调用被测核心生成期望）：

* 手算例子：``{a,b,i}`` 的基层快照在既有测试中已锚定 seed=2、序号
  0/1/2（构造输入序），差量序号从 n 起单调分配是公开约定，可逐步手推；
* 解析模型：用一个普通 ``set`` 作为成员关系的独立参照模型，确定性
  （固定种子）操作序列同时作用于被测索引与模型，逐步比对；
* 合并后快照的双射性用测试侧独立实现的哈希线格式重新计算验证
  （与 tests/test_mphf.py 同一公开契约，不调用 mphf 内部函数）。
"""

from __future__ import annotations

import hashlib
import random
import unittest

import mphf


# ----------------------------------------------------------- 测试侧独立参考


def ref_h(seed: int, tag: int, key: bytes, m: int) -> int:
    """按公开契约独立实现的哈希，不调用被测模块的任何函数。"""
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
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


# --------------------------------------------------------------------- 测试


class HandComputedTests(unittest.TestCase):
    """手算小例：基层 {a,b,i}（seed=2，序号 0/1/2 已由既有测试锚定）。"""

    def setUp(self):
        self.base_keys = [b"a", b"b", b"i"]
        self.base = mphf.build(self.base_keys)
        # 既有测试已锚定：该键集 seed=0/1 不可剥离，seed=2 成功
        self.assertEqual((self.base.seed, self.base.attempts), (2, 3))
        self.idx = mphf.MutableIndex(self.base)

    def test_base_members_resolve_through_base_layer(self):
        for i, k in enumerate(self.base_keys):
            self.assertEqual(self.idx.lookup(k), i)
        self.assertEqual(self.idx.size, 3)
        self.assertEqual(self.idx.pending, 0)

    def test_insert_gets_monotonic_slots_from_n(self):
        self.assertEqual(self.idx.insert(b"x"), 3)
        self.assertEqual(self.idx.insert(b"y"), 4)
        self.assertEqual(self.idx.lookup(b"x"), 3)
        self.assertEqual(self.idx.lookup(b"y"), 4)
        self.assertEqual(self.idx.size, 5)
        self.assertEqual(self.idx.pending, 2)

    def test_delete_then_readd_restores_base_slot(self):
        self.idx.delete(b"b")
        self.assertEqual(self.idx.lookup(b"b"), mphf.NOT_FOUND)
        self.assertEqual(self.idx.size, 2)
        # 删后重加：撤销墓碑，恢复基层原序号 1
        self.assertEqual(self.idx.insert(b"b"), 1)
        self.assertEqual(self.idx.lookup(b"b"), 1)
        self.assertEqual(self.idx.pending, 0)  # 墓碑已撤销，差量清空

    def test_delete_of_delta_key_frees_no_slot(self):
        self.assertEqual(self.idx.insert(b"x"), 3)
        self.idx.delete(b"x")
        self.assertEqual(self.idx.lookup(b"x"), mphf.NOT_FOUND)
        # 序号不回收：重新插入得到下一个新序号 4
        self.assertEqual(self.idx.insert(b"x"), 4)
        self.assertEqual(self.idx.lookup(b"x"), 4)

    def test_tombstone_shadows_base_member(self):
        # 查询先看差量：墓碑直接判非成员，不回落基层。
        self.idx.delete(b"a")
        self.assertEqual(self.idx.lookup(b"a"), mphf.NOT_FOUND)
        # 基层快照本身不受影响（旧快照仍可查询）。
        self.assertEqual(mphf.lookup(self.base, b"a"), 0)

    def test_get_default(self):
        self.assertIsNone(self.idx.get(b"absent"))
        self.assertEqual(self.idx.get(b"absent", "d"), "d")
        self.assertEqual(self.idx.get(b"i"), 2)


class UnknownKeyTests(unittest.TestCase):
    def setUp(self):
        self.idx = mphf.MutableIndex(mphf.build(det_keys(10)))

    def test_unknown_lookup_not_found(self):
        for q in (b"k-10", b"", b"K-00", b"k-0", b"k-000"):
            self.assertEqual(self.idx.lookup(q), mphf.NOT_FOUND, q)

    def test_unknown_delete_raises_keyerror(self):
        for q in (b"k-10", b"nope"):
            with self.assertRaises(KeyError, msg=q):
                self.idx.delete(q)

    def test_double_delete_raises_keyerror(self):
        self.idx.delete(b"k-03")
        with self.assertRaises(KeyError):
            self.idx.delete(b"k-03")
        # 差量新增的键删除后再删同样报错
        self.idx.insert(b"tmp")
        self.idx.delete(b"tmp")
        with self.assertRaises(KeyError):
            self.idx.delete(b"tmp")

    def test_non_ascii_lookup_not_found_but_mutation_rejected(self):
        self.assertEqual(self.idx.lookup(b"\xff"), mphf.NOT_FOUND)
        with self.assertRaises(ValueError):
            self.idx.insert(b"bad\xff")
        with self.assertRaises(ValueError):
            self.idx.delete(b"bad\xff")


class MutationValidationTests(unittest.TestCase):
    def setUp(self):
        self.idx = mphf.MutableIndex(mphf.build([b"a", b"b"]))

    def test_duplicate_insert_rejected(self):
        with self.assertRaises(mphf.DuplicateKeyError):
            self.idx.insert(b"a")          # 基层成员
        self.idx.insert(b"c")
        with self.assertRaises(mphf.DuplicateKeyError) as cm:
            self.idx.insert(bytearray(b"c"))  # 差量新增（bytes-like 归一后同键）
        self.assertEqual(cm.exception.key, b"c")
        self.assertIsNone(cm.exception.index)
        self.assertIsInstance(cm.exception, ValueError)

    def test_type_errors(self):
        for bad in (1, 1.0, "str", None, True, False, [b"a"], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.idx.insert(bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.idx.delete(bad)
            with self.assertRaises(TypeError, msg=repr(bad)):
                self.idx.lookup(bad)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            mphf.MutableIndex(mphf.CONSTRUCTION_FAILED)
        for bad in ("x", None, 42, [b"a"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.MutableIndex(bad)

    def test_no_partial_state_on_failed_mutation(self):
        self.idx.insert(b"c")
        before_size, before_pending = self.idx.size, self.idx.pending
        before = {k: self.idx.lookup(k) for k in (b"a", b"b", b"c", b"z")}
        for failing in (
            lambda: self.idx.insert(b"a"),      # 重复
            lambda: self.idx.insert(b"bad\xff"),  # 非 ASCII
            lambda: self.idx.insert("str"),      # 类型
            lambda: self.idx.delete(b"zz"),      # 未知键
            lambda: self.idx.delete(b"bad\xff"),  # 非 ASCII
        ):
            with self.assertRaises((TypeError, ValueError, KeyError)):
                failing()
        self.assertEqual((self.idx.size, self.idx.pending),
                         (before_size, before_pending))
        for k, v in before.items():
            self.assertEqual(self.idx.lookup(k), v, k)

    def test_capacity_limit(self):
        keys = det_keys(mphf.MAX_KEYS)
        idx = mphf.MutableIndex(mphf.build(keys))
        with self.assertRaises(ValueError):
            idx.insert(b"overflow")
        # 删一个腾出席位后即可插入；再次插满后仍拒绝
        idx.delete(keys[0])
        self.assertEqual(idx.insert(b"overflow"), mphf.MAX_KEYS)
        with self.assertRaises(ValueError):
            idx.insert(b"overflow-2")
        # 失败不留部分变更
        self.assertEqual(idx.size, mphf.MAX_KEYS)
        self.assertEqual(idx.lookup(b"overflow-2"), mphf.NOT_FOUND)


class EmptyIndexTests(unittest.TestCase):
    def test_empty_snapshot_roundtrip(self):
        idx = mphf.MutableIndex(mphf.build([]))
        self.assertEqual(idx.size, 0)
        self.assertEqual(idx.lookup(b"anything"), mphf.NOT_FOUND)
        self.assertEqual(idx.insert(b"first"), 0)
        self.assertEqual(idx.lookup(b"first"), 0)
        idx.delete(b"first")
        self.assertEqual(idx.size, 0)
        merged = idx.merge()
        self.assertIsInstance(merged, mphf.MPHFTable)
        self.assertEqual(merged.size, 0)
        self.assertEqual(mphf.lookup(merged, b"first"), mphf.NOT_FOUND)


class ModelBasedChurnTests(unittest.TestCase):
    """确定性操作序列 + 独立 set 模型逐步比对（解析关系核对）。"""

    def test_churn_matches_set_model(self):
        pool = [f"key-{i:03d}".encode() for i in range(60)]
        base_keys = pool[:30]
        base = mphf.build(base_keys)
        idx = mphf.MutableIndex(base)
        model = set(base_keys)

        rng = random.Random(20260924)
        probes = pool + [b"never-1", b"never-2", b""]
        for step in range(400):
            op = rng.randrange(3)
            k = rng.choice(pool)
            if op == 0:
                if k in model:
                    with self.assertRaises(mphf.DuplicateKeyError):
                        idx.insert(k)
                else:
                    idx.insert(k)
                    model.add(k)
            elif op == 1:
                if k in model:
                    idx.delete(k)
                    model.discard(k)
                else:
                    with self.assertRaises(KeyError):
                        idx.delete(k)
            # 每步都全量比对成员关系与序号唯一性
            self.assertEqual(idx.size, len(model), f"step {step}")
            seen_slots = {}
            for q in probes:
                got = idx.lookup(q)
                if q in model:
                    self.assertNotEqual(got, mphf.NOT_FOUND, (step, q))
                    self.assertGreaterEqual(got, 0)
                    # 完美性：存活键的序号两两不同
                    self.assertNotIn(got, seen_slots, (step, q))
                    seen_slots[got] = q
                else:
                    self.assertEqual(got, mphf.NOT_FOUND, (step, q))
        # 基层快照全程未被改动
        for i, k in enumerate(base_keys):
            self.assertEqual(mphf.lookup(base, k), i)


class MergeTests(unittest.TestCase):
    def _churned_index(self):
        base_keys = det_keys(20)
        base = mphf.build(base_keys)
        idx = mphf.MutableIndex(base)
        for k in base_keys[::3]:          # 删 7 个基层键
            idx.delete(k)
        idx.insert(b"new-1")
        idx.insert(b"new-2")
        idx.delete(base_keys[1])          # 再删一个
        idx.insert(base_keys[1])          # 删后重加（撤销墓碑）
        idx.insert(b"new-3")
        idx.delete(b"new-2")              # 删掉一个差量新增
        live = [k for k in base_keys if k not in set(base_keys[::3]) or k == base_keys[1]]
        live += [b"new-1", b"new-3"]
        return base, idx, live

    def test_merge_produces_valid_compact_snapshot(self):
        base, idx, live = self._churned_index()
        merged = idx.merge()
        self.assertIsInstance(merged, mphf.MPHFTable)
        self.assertEqual(merged.size, len(live))
        self.assertEqual(merged.vertex_count, (14 * len(live) + 9) // 10)
        # 独立哈希验证：存活键槽位恰为 0..n-1 的排列（双射/最小性）
        slots = [ref_slot(merged, k) for k in live]
        self.assertEqual(sorted(slots), list(range(len(live))))
        for k in live:
            self.assertEqual(mphf.lookup(merged, k), ref_slot(merged, k))
            self.assertEqual(merged.keys[mphf.lookup(merged, k)], k)

    def test_merge_consistency_before_and_after(self):
        base, idx, live = self._churned_index()
        live_set = set(live)
        probes = det_keys(20) + [b"new-1", b"new-2", b"new-3", b"ghost"]
        before = {q: idx.lookup(q) for q in probes}
        merged = idx.merge()
        # 合并后：旧索引视图不变（merge 是纯函数）
        for q in probes:
            self.assertEqual(idx.lookup(q), before[q], q)
        # 新快照成员关系与合并前索引视图一致
        for q in probes:
            got = mphf.lookup(merged, q)
            if q in live_set:
                self.assertNotEqual(got, mphf.NOT_FOUND, q)
            else:
                self.assertEqual(got, mphf.NOT_FOUND, q)
        # 旧快照完全不受影响，仍可查询
        for i, k in enumerate(det_keys(20)):
            self.assertEqual(mphf.lookup(base, k), i)

    def test_merge_key_order_is_base_then_insertion(self):
        base, idx, live = self._churned_index()
        merged = idx.merge()
        # 合并键序确定：基层存活键（基层槽位序）+ 新增键（插入序）
        self.assertEqual(list(merged.keys), live)

    def test_merge_is_deterministic(self):
        _, idx1, _ = self._churned_index()
        _, idx2, _ = self._churned_index()
        a, b = idx1.merge(), idx2.merge()
        self.assertEqual((a.seed, a.values, a.keys, a.attempts),
                         (b.seed, b.values, b.keys, b.attempts))

    def test_merged_snapshot_can_host_new_index(self):
        _, idx, live = self._churned_index()
        idx2 = mphf.MutableIndex(idx.merge())
        self.assertEqual(idx2.size, len(live))
        slot = idx2.insert(b"gen-2")
        self.assertEqual(slot, len(live))
        self.assertEqual(idx2.lookup(b"gen-2"), slot)

    def test_merge_all_deleted_gives_empty_table(self):
        keys = det_keys(5)
        idx = mphf.MutableIndex(mphf.build(keys))
        for k in keys:
            idx.delete(k)
        merged = idx.merge()
        self.assertIsInstance(merged, mphf.MPHFTable)
        self.assertEqual(merged.size, 0)
        for k in keys:
            self.assertEqual(mphf.lookup(merged, k), mphf.NOT_FOUND)


if __name__ == "__main__":
    unittest.main(verbosity=2)
