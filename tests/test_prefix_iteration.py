"""mphf 前缀迭代（iter_prefix）的必要测试。

期望值来源：对**原始输入键列表**直接调用 Python 内建 sorted 得到
参照序列，并在测试侧独立计算 LCP 与区间边界，不调用被测模块的内部
排序/二分函数；build→iter_prefix 的往返一致仅作为补充断言。
"""

from __future__ import annotations

import unittest

import mphf


def ref_sorted(keys):
    """独立参照：原始键列表的字典序排序。"""
    return sorted(keys)


def ref_prefix_slice(keys, prefix):
    """独立参照：排序后所有以 prefix 开头的键。"""
    return [k for k in sorted(keys) if k.startswith(prefix)]


def ref_lcp(a, b):
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    return i


def det_keys(n, salt="k"):
    width = max(2, len(str(n - 1)))
    return [f"{salt}-{i:0{width}d}".encode("ascii") for i in range(n)]


def collect_all(table, prefix=b"", limit=None):
    """通过游标翻页收集全部结果，返回 (键列表, 页数, 各页 accessed)。"""
    keys = []
    pages = 0
    accesses = []
    cursor = None
    while True:
        page = mphf.iter_prefix(table, prefix, limit=limit, cursor=cursor)
        keys.extend(page.keys)
        accesses.append(page.accessed)
        pages += 1
        cursor = page.cursor
        if cursor is None:
            return keys, pages, accesses


class SortedIndexStructureTests(unittest.TestCase):
    """构造期保存的排序置换 / LCP / 指纹。"""

    def test_order_is_permutation_and_sorts_keys(self):
        keys = det_keys(50)
        t = mphf.build(keys)
        self.assertEqual(sorted(t.order), list(range(50)))  # 是置换
        self.assertEqual([t.keys[o] for o in t.order], ref_sorted(keys))
        self.assertEqual(list(t.sorted_keys), ref_sorted(keys))

    def test_lcp_matches_independent_reference(self):
        keys = [b"a", b"ab", b"abc", b"abd", b"b", b"ba", b""]
        t = mphf.build(keys)
        sk = ref_sorted(keys)
        want = [0] + [ref_lcp(sk[i - 1], sk[i]) for i in range(1, len(sk))]
        self.assertEqual(list(t.lcp), want)
        self.assertEqual(len(t.lcp), t.size)

    def test_fingerprint_stable_and_content_bound(self):
        keys = det_keys(20)
        a = mphf.build(keys)
        b = mphf.build(list(reversed(keys)))  # 同集合不同输入顺序
        c = mphf.build(det_keys(20, salt="x"))
        self.assertEqual(a.fingerprint, b.fingerprint)   # 只绑定键集合
        self.assertNotEqual(a.fingerprint, c.fingerprint)
        self.assertEqual(len(a.fingerprint), 64)         # SHA256 hex
        int(a.fingerprint, 16)                           # 纯十六进制

    def test_empty_table_structures(self):
        t = mphf.build([])
        self.assertEqual(t.order, ())
        self.assertEqual(t.sorted_keys, ())
        self.assertEqual(t.lcp, ())
        self.assertEqual(len(t.fingerprint), 64)


class PrefixIterationTests(unittest.TestCase):
    def test_empty_prefix_matches_all_sorted(self):
        keys = det_keys(120)
        t = mphf.build(keys)
        page = mphf.iter_prefix(t)
        self.assertEqual(list(page.keys), ref_sorted(keys))
        self.assertEqual(page.total, 120)
        self.assertIsNone(page.cursor)

    def test_prefix_filters_in_sorted_order(self):
        keys = det_keys(200)  # k-000 .. k-199
        t = mphf.build(keys)
        for prefix in (b"k-0", b"k-1", b"k-19", b"k-199"):
            with self.subTest(prefix=prefix):
                page = mphf.iter_prefix(t, prefix)
                self.assertEqual(list(page.keys), ref_prefix_slice(keys, prefix))
                self.assertEqual(page.total, len(ref_prefix_slice(keys, prefix)))

    def test_exact_key_that_is_also_prefix_of_others(self):
        keys = [b"a", b"ab", b"abc", b"abcd", b"b", b"ab "]
        t = mphf.build(keys)
        self.assertEqual(list(mphf.iter_prefix(t, b"a").keys),
                         [b"a", b"ab", b"ab ", b"abc", b"abcd"])
        self.assertEqual(list(mphf.iter_prefix(t, b"ab").keys),
                         [b"ab", b"ab ", b"abc", b"abcd"])
        self.assertEqual(list(mphf.iter_prefix(t, b"abc").keys), [b"abc", b"abcd"])
        self.assertEqual(list(mphf.iter_prefix(t, b"abcd").keys), [b"abcd"])
        # 完整键本身也在结果中（精确键同时是别的键的前缀）
        self.assertIn(b"ab", mphf.iter_prefix(t, b"ab").keys)

    def test_zero_byte_keys_are_ordinary_bytes(self):
        keys = [b"a\x00b", b"a\x00", b"a", b"a\x01", b"\x00", b"\x00\x00"]
        t = mphf.build(keys)
        self.assertEqual(list(mphf.iter_prefix(t).keys), ref_sorted(keys))
        self.assertEqual(list(mphf.iter_prefix(t, b"a\x00").keys),
                         [b"a\x00", b"a\x00b"])
        self.assertEqual(list(mphf.iter_prefix(t, b"\x00").keys),
                         [b"\x00", b"\x00\x00"])

    def test_empty_result_for_absent_prefix(self):
        t = mphf.build(det_keys(100))
        page = mphf.iter_prefix(t, b"zzz")
        self.assertEqual(page.keys, ())
        self.assertIsNone(page.cursor)
        self.assertEqual(page.total, 0)
        # 空结果也不扫描全表：只付出 O(log n) 的二分探测
        self.assertLess(page.accessed, 30)

    def test_non_ascii_prefix_matches_nothing(self):
        t = mphf.build(det_keys(10))
        for prefix in (b"\x80", b"k-\xff", b"\xff"):
            page = mphf.iter_prefix(t, prefix)
            self.assertEqual(page.keys, ())
            self.assertEqual(page.total, 0)

    def test_empty_table_iteration(self):
        t = mphf.build([])
        page = mphf.iter_prefix(t, b"anything")
        self.assertEqual(page.keys, ())
        self.assertIsNone(page.cursor)
        self.assertEqual(page.total, 0)
        self.assertEqual(page.accessed, 0)


class PaginationTests(unittest.TestCase):
    def test_multi_page_iteration_covers_sorted_reference(self):
        keys = det_keys(300)
        t = mphf.build(keys)
        got, pages, _ = collect_all(t, limit=7)
        self.assertEqual(got, ref_sorted(keys))
        self.assertEqual(pages, (300 + 6) // 7)  # 43 页

    def test_multi_page_with_prefix(self):
        keys = det_keys(500)
        t = mphf.build(keys)
        got, pages, _ = collect_all(t, prefix=b"k-1", limit=9)
        self.assertEqual(got, ref_prefix_slice(keys, b"k-1"))
        self.assertEqual(pages, (100 + 8) // 9)

    def test_limit_larger_than_total_single_page(self):
        t = mphf.build(det_keys(30))
        page = mphf.iter_prefix(t, limit=1000)
        self.assertEqual(len(page.keys), 30)
        self.assertIsNone(page.cursor)

    def test_cursor_is_stable_text_without_addresses(self):
        t = mphf.build(det_keys(50))
        page = mphf.iter_prefix(t, limit=10)
        cursor = page.cursor
        self.assertIsInstance(cursor, str)
        self.assertTrue(cursor.startswith("mphfcur1."))
        self.assertIn(t.fingerprint, cursor)
        # 稳定编码：同一位置两次编码完全一致，与进程地址无关
        again = mphf.iter_prefix(t, limit=10)
        self.assertEqual(again.cursor, cursor)
        # 游标可从文本复原同样的下一页
        self.assertEqual(mphf.iter_prefix(t, limit=10, cursor=cursor).keys,
                         mphf.iter_prefix(t, limit=10, cursor=again.cursor).keys)

    def test_cursor_binds_same_dictionary_only(self):
        keys_a = det_keys(50, salt="a")
        keys_b = det_keys(50, salt="b")
        ta = mphf.build(keys_a)
        tb = mphf.build(keys_b)
        foreign = mphf.iter_prefix(ta, limit=10).cursor
        self.assertIsNotNone(foreign)
        with self.assertRaises(mphf.CursorError):
            mphf.iter_prefix(tb, limit=10, cursor=foreign)
        # 同一字典（内容相同、重新构造）则接受
        ta2 = mphf.build(list(reversed(keys_a)))
        page = mphf.iter_prefix(ta2, limit=10, cursor=foreign)
        self.assertEqual(list(page.keys), ref_sorted(keys_a)[10:20])

    def test_malformed_cursors_rejected(self):
        t = mphf.build(det_keys(10))
        good = mphf.iter_prefix(t, limit=3).cursor
        for bad in ("", "nonsense", "mphfcur1", "mphfcur1.xx.3",
                    good[:-1] + "x", "mphfcur1." + t.fingerprint + ".abc",
                    "mphfcur2." + t.fingerprint + ".3"):
            with self.assertRaises(mphf.CursorError, msg=repr(bad)):
                mphf.iter_prefix(t, limit=3, cursor=bad)
        self.assertIsInstance(mphf.CursorError("x"), ValueError)

    def test_cursor_beyond_range_gives_empty_page(self):
        t = mphf.build(det_keys(10))
        cursor = "mphfcur1." + t.fingerprint + ".999"
        page = mphf.iter_prefix(t, cursor=cursor)
        self.assertEqual(page.keys, ())
        self.assertIsNone(page.cursor)


class AccessCountTests(unittest.TestCase):
    """访问键数：稀有前缀不做全表扫描。"""

    def test_rare_prefix_access_is_sublinear(self):
        keys = det_keys(1000)
        t = mphf.build(keys)
        page = mphf.iter_prefix(t, b"k-99")  # 仅 10 个匹配
        self.assertEqual(page.total, 10)
        self.assertEqual(len(page.keys), 10)
        # 访问数 ≈ 2*log2(1000) + 10 ≈ 30，远小于 n=1000
        self.assertLess(page.accessed, 50)
        self.assertLess(page.accessed, t.size)

    def test_empty_prefix_full_scan_only_when_asked(self):
        t = mphf.build(det_keys(1000))
        page = mphf.iter_prefix(t, limit=5)
        self.assertLess(page.accessed, 30)  # 只取一页，不读全部
        full = mphf.iter_prefix(t)
        self.assertEqual(full.accessed - page.accessed, 1000 - 5)

    def test_accessed_counts_page_keys_and_probes(self):
        t = mphf.build(det_keys(100))
        page = mphf.iter_prefix(t, b"k-0", limit=4)
        self.assertEqual(len(page.keys), 4)
        self.assertGreaterEqual(page.accessed, 4)
        self.assertLess(page.accessed, 30)


class ValidationTests(unittest.TestCase):
    def test_limit_validation(self):
        t = mphf.build(det_keys(5))
        for bad in (0, -1, -100):
            with self.assertRaises(ValueError, msg=bad):
                mphf.iter_prefix(t, limit=bad)
        for bad in (1.5, "3", True, False):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.iter_prefix(t, limit=bad)

    def test_prefix_type_errors(self):
        t = mphf.build(det_keys(5))
        for bad in (1, "k", None, True, [b"k"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.iter_prefix(t, bad)

    def test_table_type_errors(self):
        with self.assertRaises(ValueError):
            mphf.iter_prefix(mphf.CONSTRUCTION_FAILED)
        for bad in ("x", None, 123):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.iter_prefix(bad)

    def test_cursor_type_error(self):
        t = mphf.build(det_keys(5))
        with self.assertRaises(TypeError):
            mphf.iter_prefix(t, cursor=123)

    def test_bytes_like_prefix_accepted(self):
        t = mphf.build(det_keys(20))
        page = mphf.iter_prefix(t, bytearray(b"k-1"))
        self.assertEqual(list(page.keys), ref_prefix_slice(det_keys(20), b"k-1"))
        page2 = t.iter_prefix(memoryview(b"k-0"))
        self.assertEqual(list(page2.keys), ref_prefix_slice(det_keys(20), b"k-0"))


class LookupRegressionTests(unittest.TestCase):
    """旧单键查询在新字段加入后照常工作。"""

    def test_lookup_still_exact(self):
        keys = det_keys(100)
        t = mphf.build(keys)
        for i, k in enumerate(keys):
            self.assertEqual(mphf.lookup(t, k), i)
        self.assertEqual(mphf.lookup(t, b"absent"), mphf.NOT_FOUND)
        self.assertEqual(mphf.lookup(t, b"k-050 "), mphf.NOT_FOUND)

    def test_lookup_unaffected_by_iteration(self):
        keys = det_keys(40)
        t = mphf.build(keys)
        collect_all(t, limit=3)
        for i, k in enumerate(keys):
            self.assertEqual(t.lookup(k), i)


if __name__ == "__main__":
    unittest.main(verbosity=2)
