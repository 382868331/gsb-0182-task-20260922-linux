"""前缀迭代的必要测试。

参照值由测试侧对原字典直接 ``sorted()`` 得到，不调用被测核心产生期望；
build→iter_prefix 的往返一致仅作为补充断言。
"""

import random
import unittest

import mphf


def make_keys(seed=20260926, n=1000):
    rng = random.Random(seed)
    keys = set()
    while len(keys) < n - 5:
        length = rng.randrange(1, 10)
        keys.add(bytes(rng.randrange(97, 123) for _ in range(length)))
    # 精确键同时也是别的键的前缀；含零字节键；空键。
    keys.update([b"ab", b"abc", b"abcd", b"a\x00b", b""])
    return list(keys)


KEYS = make_keys()
REF_SORTED = sorted(KEYS)


def ref_prefix(prefix, start=0, limit=None):
    matched = [k for k in REF_SORTED if k.startswith(prefix)]
    page = matched[start:] if limit is None else matched[start:start + limit]
    return page, len(matched)


def drain(table, prefix, limit):
    """用游标跨页取完整个前缀，返回 (键列表, 各页 accessed 列表)。"""
    out, probes, cursor = [], [], None
    while True:
        page = mphf.iter_prefix(table, prefix, limit=limit, cursor=cursor)
        out.extend(page.keys)
        probes.append(page.accessed)
        if page.next_cursor is None:
            return out, probes
        cursor = page.next_cursor


class PrefixIterationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.table = mphf.build(KEYS)
        assert isinstance(cls.table, mphf.MPHFTable)

    def test_sorted_permutation_matches_reference(self):
        t = self.table
        self.assertEqual([t.keys[s] for s in t.sorted_slots], REF_SORTED)
        self.assertEqual(sorted(t.sorted_slots), list(range(t.size)))
        # 槽号顺序不等于排序位置：不能拿槽号凑输出。
        self.assertNotEqual(list(t.sorted_slots), list(range(t.size)))

    def test_lcp_array_matches_reference(self):
        ref = []
        for a, b in zip(REF_SORTED, REF_SORTED[1:]):
            i = 0
            while i < min(len(a), len(b)) and a[i] == b[i]:
                i += 1
            ref.append(i)
        self.assertEqual(list(self.table.lcp), ref)

    def test_fingerprint_stable_across_builds(self):
        other = mphf.build(list(reversed(KEYS)))
        self.assertEqual(self.table.fingerprint, other.fingerprint)
        self.assertEqual(len(self.table.fingerprint), 32)

    def test_empty_prefix_matches_all(self):
        page = mphf.iter_prefix(self.table, b"")
        self.assertEqual(list(page.keys), REF_SORTED)
        self.assertTrue(page.done)
        self.assertIsNone(page.next_cursor)

    def test_prefix_against_sorted_reference(self):
        for prefix in [b"a", b"ab", b"abc", b"q", b"zz", b"a\x00", b"\x00"]:
            with self.subTest(prefix=prefix):
                expected, _ = ref_prefix(prefix)
                page = mphf.iter_prefix(self.table, prefix)
                self.assertEqual(list(page.keys), expected)
                self.assertTrue(page.done)

    def test_exact_key_that_is_also_prefix(self):
        # b"ab" 自身是键，同时是 b"abc"/b"abcd" 的前缀。
        page = mphf.iter_prefix(self.table, b"ab")
        self.assertEqual(list(page.keys), [k for k in REF_SORTED if k.startswith(b"ab")])
        self.assertIn(b"ab", page.keys)
        self.assertLess(list(page.keys).index(b"ab"), list(page.keys).index(b"abc"))

    def test_zero_byte_keys_ordered_as_plain_bytes(self):
        page = mphf.iter_prefix(self.table, b"a\x00")
        self.assertEqual(list(page.keys), [b"a\x00b"])
        all_page = mphf.iter_prefix(self.table, b"")
        keys = list(all_page.keys)
        self.assertEqual(keys, sorted(keys))  # 含零字节也按字节序

    def test_multi_page_iteration_cursor(self):
        for limit in (1, 7, 100):
            with self.subTest(limit=limit):
                out, _ = drain(self.table, b"", limit)
                self.assertEqual(out, REF_SORTED)

    def test_multi_page_with_prefix(self):
        out, _ = drain(self.table, b"a", 3)
        self.assertEqual(out, [k for k in REF_SORTED if k.startswith(b"a")])

    def test_cursor_is_process_independent_encoding(self):
        page = mphf.iter_prefix(self.table, b"ab", limit=1)
        cursor = page.next_cursor
        self.assertIsInstance(cursor, bytes)
        # 纯内容编码：不含 id() 痕迹，同参数再算一次逐位相同。
        again = mphf.iter_prefix(self.table, b"ab", limit=1).next_cursor
        self.assertEqual(cursor, again)
        # 从游标继续等价于参照的剩余部分。
        rest = mphf.iter_prefix(self.table, cursor=cursor)
        expected, _ = ref_prefix(b"ab")
        self.assertEqual(list(rest.keys), expected[1:])

    def test_empty_result(self):
        page = mphf.iter_prefix(self.table, b"\x01\x02\x03")
        self.assertEqual(page.keys, ())
        self.assertTrue(page.done)
        self.assertIsNone(page.next_cursor)

    def test_rare_prefix_does_not_scan_all_keys(self):
        page = mphf.iter_prefix(self.table, b"abcd")
        matched = [k for k in REF_SORTED if k.startswith(b"abcd")]
        self.assertEqual(list(page.keys), matched)
        # 访问键数与候选范围同量级（对数定位 + 输出），远小于全表。
        self.assertLess(page.accessed, 3 * self.table.size.bit_length() + len(matched) + 3)
        self.assertLess(page.accessed, self.table.size // 4)

    def test_wrong_dictionary_cursor_rejected(self):
        other = mphf.build([b"alpha", b"beta", b"gamma"])
        foreign = mphf.iter_prefix(other, b"", limit=1).next_cursor
        self.assertIsNotNone(foreign)
        with self.assertRaises(mphf.CursorError):
            mphf.iter_prefix(self.table, cursor=foreign)
        with self.assertRaises(ValueError):  # CursorError 是 ValueError 子类
            mphf.iter_prefix(self.table, cursor=foreign)

    def test_malformed_cursor_rejected(self):
        for bad in (b"", b"MPX1", b"XXXX" + b"\x00" * 20,
                    mphf.iter_prefix(self.table, b"", limit=1).next_cursor[:-1]):
            with self.subTest(bad=bad):
                with self.assertRaises(mphf.CursorError):
                    mphf.iter_prefix(self.table, cursor=bad)
        with self.assertRaises(TypeError):
            mphf.iter_prefix(self.table, cursor=123)

    def test_prefix_mismatch_with_cursor_rejected(self):
        cursor = mphf.iter_prefix(self.table, b"ab", limit=1).next_cursor
        with self.assertRaises(mphf.CursorError):
            mphf.iter_prefix(self.table, b"zz", cursor=cursor)

    def test_argument_validation(self):
        t = self.table
        with self.assertRaises(TypeError):
            mphf.iter_prefix(t, "ab")
        with self.assertRaises(TypeError):
            mphf.iter_prefix(t, b"a", limit=True)
        with self.assertRaises(TypeError):
            mphf.iter_prefix(t, b"a", limit=1.5)
        with self.assertRaises(ValueError):
            mphf.iter_prefix(t, b"a", limit=0)
        with self.assertRaises(TypeError):
            mphf.iter_prefix("not a table", b"a")
        with self.assertRaises(ValueError):
            mphf.iter_prefix(mphf.CONSTRUCTION_FAILED, b"a")

    def test_non_ascii_prefix_matches_nothing(self):
        page = mphf.iter_prefix(self.table, b"\x80")
        self.assertEqual(page.keys, ())
        self.assertEqual(page.accessed, 0)

    def test_empty_table(self):
        empty = mphf.build([])
        page = mphf.iter_prefix(empty, b"")
        self.assertEqual(page.keys, ())
        self.assertTrue(page.done)
        self.assertEqual(page.accessed, 0)

    def test_instance_method_and_lookup_regression(self):
        page = self.table.iter_prefix(b"abc")
        self.assertEqual(list(page.keys), [k for k in REF_SORTED if k.startswith(b"abc")])
        # 旧单键查询照常工作。
        for k in (b"ab", b"abc", b"a\x00b", b""):
            self.assertEqual(self.table.lookup(k), KEYS.index(k))
        self.assertEqual(self.table.lookup(b"absent"), mphf.NOT_FOUND)


if __name__ == "__main__":
    unittest.main()
