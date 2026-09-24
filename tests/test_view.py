"""差量增删层与显式合并的测试。

期望值来源（不调用被测实现生成期望值）：

* 以测试侧独立维护的**纯 Python 集合/列表模型**记录当前逻辑集合，
  视图的成员关系、``size``、``keys()`` 顺序、墓碑与新增清单全部与
  模型逐一对照；
* 小范围**枚举**若干基层键集与全部操作序列（新增/删除/删后重加），
  每一步都把视图与模型对拍；
* 合并后的新表用测试侧独立哈希（与 tests/test_mphf.py 相同的线格式）
  重新验证双射与赋值方程，序号期望值来自手写的当前键列表；
* 手算例子（base=[a,b,c]，删 b、加 d）直接断言 a→0、c→1、d→2、b→-1。
"""

from __future__ import annotations

import hashlib
import itertools
import unittest
from unittest.mock import patch

import mphf


# ----------------------------------------------------------- 测试侧独立参考


def ref_h(seed: int, tag: int, key: bytes, m: int) -> int:
    """按公开契约独立实现的哈希，不调用被测模块的任何函数。"""
    digest = hashlib.sha256(seed.to_bytes(4, "big") + bytes([tag]) + key).digest()
    return int.from_bytes(digest, "big") % m


def ref_slot(table: mphf.MPHFTable, key: bytes) -> int:
    m, n, g, seed = table.vertex_count, table.size, table.values, table.seed
    return (
        g[ref_h(seed, 0, key, m)]
        + g[ref_h(seed, 1, key, m)]
        + g[ref_h(seed, 2, key, m)]
    ) % n


def make_keys(n: int, salt: str = "v") -> list[bytes]:
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


def assert_mphtable_contract(testcase, table, keys):
    """独立校验新快照：槽位为 0..n-1 排列，赋值方程成立，键序一致。"""
    n = len(keys)
    testcase.assertEqual(table.size, n)
    testcase.assertEqual(table.vertex_count, (14 * n + 9) // 10)
    testcase.assertEqual(len(table.keys), n)
    testcase.assertEqual(table.keys, tuple(keys))
    slots = [ref_slot(table, k) for k in keys]
    testcase.assertEqual(sorted(slots), list(range(n)))
    for i, k in enumerate(keys):
        testcase.assertEqual(slots[i], i)
        testcase.assertEqual(mphf.lookup(table, k), i)


# ----------------------------------------------------------------- 打开视图


class OpenViewTests(unittest.TestCase):
    def test_open_view_and_query_base(self):
        keys = make_keys(10)
        t = mphf.build(keys)
        v = mphf.open_view(t)
        self.assertIsInstance(v, mphf.MPHFView)
        self.assertIs(v.base, t)
        self.assertEqual(v.size, 10)
        self.assertEqual(v.added, ())
        self.assertEqual(v.tombstones, ())
        # 基层序号在视图中保持不变
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(v, k), i)
            self.assertEqual(v.lookup(k), i)
            self.assertIn(k, v)
        self.assertEqual(len(v), 10)

    def test_open_view_on_empty_table(self):
        v = mphf.open_view(mphf.build([]))
        self.assertEqual(v.size, 0)
        self.assertEqual(v.keys(), [])
        self.assertEqual(mphf.lookup(v, b"x"), mphf.NOT_FOUND)

    def test_open_view_rejects_bad_arguments(self):
        good = mphf.build([b"a"])
        with self.assertRaises(TypeError):
            mphf.open_view(None)
        with self.assertRaises(TypeError):
            mphf.open_view(b"raw")
        # 视图不能再包一层
        with self.assertRaises(TypeError):
            mphf.open_view(mphf.open_view(good))
        with self.assertRaises(ValueError):
            mphf.open_view(mphf.CONSTRUCTION_FAILED)

    def test_multiple_views_are_independent(self):
        t = mphf.build([b"a", b"b", b"c"])
        v1, v2 = mphf.open_view(t), mphf.open_view(t)
        v1.remove(b"a")
        v1.add(b"d")
        self.assertEqual(v1.size, 3)
        self.assertEqual(v2.size, 3)  # v2 毫不受影响
        self.assertEqual(mphf.lookup(v2, b"a"), 0)
        self.assertEqual(mphf.lookup(v1, b"a"), mphf.NOT_FOUND)


# ----------------------------------------------------------------- 删除/墓碑


class RemoveTests(unittest.TestCase):
    def test_remove_writes_tombstone_base_survives(self):
        keys = make_keys(6)
        t = mphf.build(keys)
        v = mphf.open_view(t)
        removed_slot = v.remove(keys[2])
        self.assertEqual(removed_slot, 2)
        self.assertEqual(v.tombstones, (keys[2],))
        self.assertEqual(v.size, 5)
        # 视图查不到；基层快照仍可查、未改动
        self.assertEqual(mphf.lookup(v, keys[2]), mphf.NOT_FOUND)
        self.assertEqual(mphf.lookup(t, keys[2]), 2)
        self.assertNotIn(keys[2], v)
        # 其余键序号不变
        for i, k in enumerate(keys):
            if i != 2:
                self.assertEqual(mphf.lookup(v, k), i)
        self.assertEqual(v.keys(), [k for i, k in enumerate(keys) if i != 2])

    def test_remove_unknown_raises_and_state_unchanged(self):
        t = mphf.build([b"a", b"b"])
        v = mphf.open_view(t)
        for missing in (b"zzz", b"", b"A"):
            with self.subTest(missing=missing):
                with self.assertRaises(mphf.UnknownKeyError) as cm:
                    v.remove(missing)
                self.assertIsInstance(cm.exception, KeyError)
                self.assertEqual(v.size, 2)
                self.assertEqual(v.tombstones, ())

    def test_remove_twice_is_unknown(self):
        t = mphf.build([b"a", b"b"])
        v = mphf.open_view(t)
        v.remove(b"a")
        with self.assertRaises(mphf.UnknownKeyError):
            v.remove(b"a")
        self.assertEqual(v.tombstones, (b"a",))
        self.assertEqual(v.size, 1)

    def test_remove_added_key_leaves_no_tombstone(self):
        t = mphf.build([b"a"])
        v = mphf.open_view(t)
        v.add(b"new")
        v.remove(b"new")
        self.assertEqual(v.added, ())
        self.assertEqual(v.tombstones, ())  # 新增键不留墓碑
        self.assertEqual(v.size, 1)
        self.assertEqual(mphf.lookup(v, b"new"), mphf.NOT_FOUND)

    def test_remove_type_errors(self):
        v = mphf.open_view(mphf.build([b"a"]))
        for bad in (1, 1.5, "a", None, True, False, [b"a"]):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                v.remove(bad)
        # 非法输入不得留下半更新状态
        self.assertEqual(v.size, 1)
        self.assertEqual(v.tombstones, ())

    def test_remove_non_ascii_is_value_error(self):
        v = mphf.open_view(mphf.build([b"a"]))
        with self.assertRaises(ValueError):
            v.remove(b"bad\xff")
        self.assertEqual(v.size, 1)


# ----------------------------------------------------------------- 新增


class AddTests(unittest.TestCase):
    def test_add_new_key(self):
        keys = make_keys(4)
        t = mphf.build(keys)
        v = mphf.open_view(t)
        slot = v.add(b"new-1")
        self.assertEqual(slot, t.size)  # 差量序号 = base.size + 位置
        self.assertEqual(v.added, (b"new-1",))
        self.assertEqual(v.size, 5)
        self.assertEqual(mphf.lookup(v, b"new-1"), t.size)
        self.assertEqual(v.get(b"new-1"), t.size)
        self.assertEqual(v.keys(), keys + [b"new-1"])
        slot2 = v.add(b"new-2")
        self.assertEqual(slot2, t.size + 1)
        self.assertEqual(v.size, 6)

    def test_add_duplicate_rejected_atomically(self):
        keys = [b"a", b"b", b"c"]
        v = mphf.open_view(mphf.build(keys))
        with self.assertRaises(mphf.DuplicateViewKeyError):
            v.add(b"b")  # 基层存活键
        v.add(b"d")
        with self.assertRaises(mphf.DuplicateViewKeyError):
            v.add(b"d")  # 已新增的键
        # 失败不改变任何状态
        self.assertEqual(v.added, (b"d",))
        self.assertEqual(v.tombstones, ())
        self.assertEqual(v.size, 4)
        self.assertIsInstance(mphf.DuplicateViewKeyError(b"x"), ValueError)

    def test_add_non_ascii_and_type_errors(self):
        v = mphf.open_view(mphf.build([b"a"]))
        with self.assertRaises(ValueError):
            v.add(b"bad\xff")
        for bad in (1, 1.5, "str", None, True, False, object()):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                v.add(bad)
        self.assertEqual(v.size, 1)
        self.assertEqual(v.added, ())

    def test_add_bytearray_memoryview_normalized(self):
        v = mphf.open_view(mphf.build([b"a"]))
        v.add(bytearray(b"b"))
        self.assertEqual(mphf.lookup(v, memoryview(b"b")), 1)

    def test_add_respects_limit(self):
        keys = make_keys(1000)
        t = mphf.build(keys)
        v = mphf.open_view(t)
        with self.assertRaises(ValueError):
            v.add(b"overflow")
        self.assertEqual(v.size, 1000)
        self.assertEqual(v.added, ())
        # 删一个就能再加一个；再加第二个则失败且无半更新
        v.remove(keys[0])
        v.add(b"replacement")
        self.assertEqual(v.size, 1000)
        with self.assertRaises(ValueError):
            v.add(b"overflow2")
        self.assertEqual(v.added, (b"replacement",))

    def test_readd_tombstone_respects_limit(self):
        # 基层 999：删 1（998）后新增 2（1000）；此时删后重加墓碑键会到
        # 1001，必须被上限拦截且墓碑保持原状（无半更新）。
        keys = make_keys(999)
        v = mphf.open_view(mphf.build(keys))
        v.remove(keys[0])
        v.add(b"new-a")
        v.add(b"new-b")
        self.assertEqual(v.size, 1000)
        with self.assertRaises(ValueError):
            v.add(keys[0])
        self.assertEqual(v.tombstones, (keys[0],))
        self.assertEqual(v.size, 1000)
        # 腾出一个位置后删后重加成功，键回到基层序号 0
        v.remove(b"new-b")
        self.assertEqual(v.add(keys[0]), 0)
        self.assertEqual(v.tombstones, ())
        self.assertEqual(mphf.lookup(v, keys[0]), 0)
        self.assertEqual(v.size, 1000)


# ----------------------------------------------------------- 删后重加/查询顺序


class DeleteReaddTests(unittest.TestCase):
    def test_delete_then_readd_base_key_is_clean(self):
        keys = [b"a", b"b", b"c"]
        t = mphf.build(keys)
        v = mphf.open_view(t)
        v.remove(b"b")
        self.assertEqual(mphf.lookup(v, b"b"), mphf.NOT_FOUND)
        slot = v.add(b"b")  # 删后重加
        self.assertEqual(slot, 1)  # 回到基层原序号，而非差量尾部
        self.assertEqual(v.tombstones, ())  # 墓碑被干净移除
        self.assertEqual(v.added, ())
        self.assertEqual(v.size, 3)
        self.assertEqual(mphf.lookup(v, b"b"), 1)
        self.assertEqual(v.keys(), keys)
        # 再次删除应能重新立碑
        v.remove(b"b")
        self.assertEqual(v.tombstones, (b"b",))
        self.assertEqual(mphf.lookup(v, b"b"), mphf.NOT_FOUND)
        v.add(b"b")
        self.assertEqual(v.tombstones, ())

    def test_delete_readd_added_key(self):
        v = mphf.open_view(mphf.build([b"a"]))
        v.add(b"x")
        v.remove(b"x")
        v.add(b"x")  # 重新加入走“全新键”路径
        self.assertEqual(v.tombstones, ())
        self.assertEqual(mphf.lookup(v, b"x"), 1)
        self.assertEqual(v.size, 2)

    def test_lookup_order_delta_then_base(self):
        # 差量优先：墓碑必须遮盖基层；新增优先于基层解析。
        t = mphf.build([b"a", b"b"])
        v = mphf.open_view(t)
        v.remove(b"a")
        v.add(b"c")
        # 非 ASCII 查询在两层都按非成员处理
        for q, want in [(b"a", -1), (b"b", 1), (b"c", 2),
                        (b"nope", -1), (b"\xff", -1), (b"", -1)]:
            self.assertEqual(mphf.lookup(v, q), want, q)
            self.assertEqual(v.get(q), None if want == -1 else want)

    def test_lookup_on_view_type_errors(self):
        v = mphf.open_view(mphf.build([b"a"]))
        for bad in (1, 1.5, None, True, [b"a"]):
            with self.assertRaises(TypeError):
                mphf.lookup(v, bad)
        with self.assertRaises(TypeError):
            mphf.lookup("not a table or view", b"a")
        with self.assertRaises(ValueError):
            mphf.lookup(mphf.CONSTRUCTION_FAILED, b"a")

    def test_base_snapshot_never_mutated(self):
        t = mphf.build(make_keys(8))
        before = (t.size, t.seed, t.values, t.keys, t.attempts)
        v = mphf.open_view(t)
        v.remove(t.keys[0])
        v.remove(t.keys[3])
        v.add(b"new")
        v.add(b"new2")
        v.remove(b"new2")
        after = (t.size, t.seed, t.values, t.keys, t.attempts)
        self.assertEqual(before, after)
        # 旧快照的查询结果始终不变
        for i, k in enumerate(t.keys):
            self.assertEqual(mphf.lookup(t, k), i)


# ----------------------------------------------------- 独立集合模型枚举对拍


class ModelEquivalenceTests(unittest.TestCase):
    """用独立的集合模型枚举操作序列，逐步对拍视图。"""

    def assert_view_matches_model(self, v, model, base_keys):
        # model: list，当前逻辑集合的期望顺序（存活基层键顺序 + 新增顺序）
        self.assertEqual(v.size, len(model))
        self.assertEqual(len(v), len(model))
        self.assertEqual(v.keys(), model)
        # 差量新增 = 模型中不属于基层的键（按序）
        base_set = set(base_keys)
        self.assertEqual(v.added, tuple(k for k in model if k not in base_set))
        # 墓碑 = 基层中不在模型里的键（基层原序对照）
        model_set = set(model)
        self.assertEqual(set(v.tombstones),
                         {k for k in base_keys if k not in model_set})
        # 对全部相关键做成员/序号对拍
        universe = base_keys + [b"x-0", b"x-1", b"y", b"\xff"]
        for k in universe:
            in_view = mphf.lookup(v, k) != mphf.NOT_FOUND
            self.assertEqual(in_view, k in model_set, k)
            self.assertEqual(k in v, k in model_set)
            if k in model_set:
                self.assertEqual(mphf.lookup(v, k),
                                 _model_slot(base_keys, model, k), k)

    def test_enumerated_operation_sequences(self):
        base_keys = [b"a", b"b", b"c", b"d"]
        extras = [b"e", b"f"]
        # 操作：对每个候选键循环 add/remove/noop；覆盖删后重加、加后删、
        # 重复添加、删除未知键等全部组合。
        for nbase in (1, 2, 4):
            base = base_keys[:nbase]
            for seq in itertools.product(("add", "remove", "noop"), repeat=5):
                t = mphf.build(base)
                v = mphf.open_view(t)
                model = list(base)
                candidates = base_keys + extras
                for step, op in enumerate(seq):
                    k = candidates[step % len(candidates)]
                    if op == "add":
                        if k in model:
                            with self.assertRaises(mphf.DuplicateViewKeyError):
                                v.add(k)
                        else:
                            v.add(k)
                            model.append(k)
                    elif op == "remove":
                        if k not in model:
                            with self.assertRaises(mphf.UnknownKeyError):
                                v.remove(k)
                        else:
                            v.remove(k)
                            model.remove(k)
                    self.assert_view_matches_model(v, model, base)

    def test_hand_computed_small_example(self):
        # 手算：base=[a,b,c]，删 b，加 d → 当前集合 [a,c,d]
        t = mphf.build([b"a", b"b", b"c"])
        v = mphf.open_view(t)
        v.remove(b"b")
        v.add(b"d")
        # 合并前：基层序号保留，新增键在尾部
        self.assertEqual([mphf.lookup(v, k) for k in (b"a", b"c", b"d")],
                         [0, 2, 3])
        self.assertEqual(mphf.lookup(v, b"b"), -1)


def _model_slot(base_keys, model, key):
    """视图序号的独立定义：基层键取原构造序号，新增键取 base.size+位置。"""
    if key in base_keys:
        return base_keys.index(key)
    return len(base_keys) + list(k for k in model if k not in base_keys).index(key)


# ----------------------------------------------------------------- 显式合并


class MergeTests(unittest.TestCase):
    def test_merge_hand_computed_example(self):
        t = mphf.build([b"a", b"b", b"c"])
        v = mphf.open_view(t)
        v.remove(b"b")
        v.add(b"d")
        nt = mphf.merge(v)
        self.assertIsInstance(nt, mphf.MPHFTable)
        self.assertIsNot(nt, t)
        # 手写期望：当前键 [a,c,d] 重新紧凑编号
        self.assertEqual(nt.keys, (b"a", b"c", b"d"))
        self.assertEqual(mphf.lookup(nt, b"a"), 0)
        self.assertEqual(mphf.lookup(nt, b"c"), 1)
        self.assertEqual(mphf.lookup(nt, b"d"), 2)
        self.assertEqual(mphf.lookup(nt, b"b"), mphf.NOT_FOUND)
        assert_mphtable_contract(self, nt, [b"a", b"c", b"d"])

    def test_old_snapshot_still_queryable_after_merge(self):
        t = mphf.build([b"a", b"b", b"c"])
        v = mphf.open_view(t)
        v.remove(b"b")
        v.add(b"d")
        nt = mphf.merge(v)
        # 旧快照原样：b 仍在，d 不在
        self.assertEqual(mphf.lookup(t, b"b"), 1)
        self.assertEqual(mphf.lookup(t, b"d"), mphf.NOT_FOUND)
        self.assertEqual(t.keys, (b"a", b"b", b"c"))
        # 视图也未被合并改动：差量仍在
        self.assertEqual(v.size, 3)
        self.assertEqual(v.tombstones, (b"b",))
        self.assertEqual(v.added, (b"d",))
        self.assertEqual(mphf.lookup(v, b"b"), mphf.NOT_FOUND)
        # 新表是独立结构，键集合不同
        self.assertEqual(nt.keys, (b"a", b"c", b"d"))
        self.assertNotEqual(nt.keys, t.keys)

    def test_merge_matches_model_enumeration(self):
        base_keys = [b"a", b"b", b"c", b"d", b"e"]
        extras = [b"f", b"g"]
        for seq in itertools.product(("add", "remove", "noop"), repeat=6):
            base = base_keys
            t = mphf.build(base)
            v = mphf.open_view(t)
            model = list(base)
            candidates = base_keys + extras
            for step, op in enumerate(seq):
                k = candidates[step % len(candidates)]
                if op == "add" and k not in model:
                    v.add(k)
                    model.append(k)
                elif op == "remove" and k in model:
                    v.remove(k)
                    model.remove(k)
            nt = mphf.merge(v)
            self.assertIsInstance(nt, mphf.MPHFTable)
            assert_mphtable_contract(self, nt, model)
            # 视图与新表成员关系一致（序号口径不同，只比成员关系）
            for k in base_keys + extras + [b"zzz"]:
                self.assertEqual(
                    (mphf.lookup(v, k) != mphf.NOT_FOUND),
                    (mphf.lookup(nt, k) != mphf.NOT_FOUND),
                    (seq, k),
                )

    def test_merge_empty_cases(self):
        # 空基层空差量
        nt = mphf.merge(mphf.open_view(mphf.build([])))
        self.assertEqual(nt.size, 0)
        # 空基层 + 新增
        v = mphf.open_view(mphf.build([]))
        v.add(b"only")
        nt = mphf.merge(v)
        assert_mphtable_contract(self, nt, [b"only"])
        # 删光基层
        t = mphf.build([b"a", b"b"])
        v = mphf.open_view(t)
        v.remove(b"a")
        v.remove(b"b")
        nt = mphf.merge(v)
        self.assertEqual(nt.size, 0)
        self.assertEqual(mphf.lookup(nt, b"a"), mphf.NOT_FOUND)

    def test_merge_boundary_size_1000(self):
        keys = make_keys(1000)
        v = mphf.open_view(mphf.build(keys))
        v.remove(keys[0])
        v.remove(keys[999])
        v.add(b"new-a")
        v.add(b"new-b")
        nt = mphf.merge(v)
        expected = keys[1:999] + [b"new-a", b"new-b"]
        self.assertEqual(nt.size, 1000)
        assert_mphtable_contract(self, nt, expected)

    def test_merge_failure_raises_and_preserves_state(self):
        # {a,b,i} 在 seed=0 下真实不可剥离；预算压为 1 时，即使视图本身
        # 没有差量，合并（=按当前集合重建）也必然失败。
        tricky = [b"a", b"b", b"i"]
        t = mphf.build(tricky)  # 满预算下成功（seed=2）
        v = mphf.open_view(t)
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            with self.assertRaises(mphf.MergeError):
                mphf.merge(v)
        # 视图与旧快照完好、仍可查询
        self.assertEqual(v.size, 3)
        for i, k in enumerate(tricky):
            self.assertEqual(mphf.lookup(v, k), i)
            self.assertEqual(mphf.lookup(t, k), i)
        # 满预算下合并恢复成功，且等价于重建同一集合
        nt = mphf.merge(v)
        assert_mphtable_contract(self, nt, tricky)

    def test_merge_failure_with_deltas_preserves_delta_state(self):
        # 带有差量（删后重加，净集合仍是 {a,b,i}）时预算压为 1 同样失败，
        # 墓碑/新增等差量状态必须原样保留。
        tricky = [b"a", b"b", b"i"]
        t = mphf.build(tricky)
        v = mphf.open_view(t)
        v.remove(b"b")
        v.add(b"b")
        self.assertEqual(v.tombstones, ())
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            with self.assertRaises(mphf.MergeError):
                mphf.merge(v)
        self.assertEqual(v.size, 3)
        self.assertEqual(v.keys(), tricky)
        self.assertEqual(mphf.lookup(v, b"b"), 1)

    def test_merge_type_errors(self):
        t = mphf.build([b"a"])
        for bad in (t, None, b"x", 123, [t]):
            with self.assertRaises(TypeError):
                mphf.merge(bad)

    def test_view_continues_after_merge_and_old_snapshots_chain(self):
        t1 = mphf.build([b"a", b"b"])
        v = mphf.open_view(t1)
        v.add(b"c")
        t2 = mphf.merge(v)          # [a,b,c]
        v.add(b"d")
        t3 = mphf.merge(v)          # [a,b,c,d]
        self.assertEqual(t3.keys, (b"a", b"b", b"c", b"d"))
        self.assertEqual(t2.keys, (b"a", b"b", b"c"))
        # 三代快照各自可查、互不影响
        self.assertEqual(mphf.lookup(t1, b"c"), mphf.NOT_FOUND)
        self.assertEqual(mphf.lookup(t2, b"c"), 2)
        self.assertEqual(mphf.lookup(t2, b"d"), mphf.NOT_FOUND)
        self.assertEqual(mphf.lookup(t3, b"d"), 3)
        # 视图仍挂在 t1 上：a,b 序号 0,1；c,d 为差量 2,3
        self.assertEqual(mphf.lookup(v, b"d"), 3)
        self.assertIs(v.base, t1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
