"""内容存储与二进制归档（dumps/loads/save/load）的必要测试。

重点保证：

* 空内容（``b""``）与“键不存在”（``NOT_FOUND``/-1）严格可分；
* 非成员在重载后仍明确返回不存在，不会读到其他键的内容；
* 错误的长度字段即使配合重算的合法校验和，也只能产生
  ``ArchiveFormatError``，绝不造成越界读取；
* 重载后键位置（槽位）与查询结果和保存前完全一致。
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

import mphf
from tests.test_mphf import det_keys, ref_slot


def rebuild_blob(body: bytes) -> bytes:
    """给定（可能已篡改的）body，重算追加 SHA256，绕过校验和直达边界检查。"""
    import hashlib

    return body + hashlib.sha256(body).digest()


class ContentTests(unittest.TestCase):
    def test_build_without_contents_defaults_empty(self):
        t = mphf.build([b"a", b"b"])
        self.assertEqual(t.contents, (b"", b""))
        # 空内容是真实命中，返回空 bytes 而非 NOT_FOUND。
        self.assertEqual(mphf.fetch(t, b"a"), b"")
        self.assertEqual(mphf.fetch(t, b"zzz"), mphf.NOT_FOUND)

    def test_empty_content_distinct_from_missing(self):
        t = mphf.build([b"k", b"empty"], [b"value", b""])
        self.assertEqual(mphf.fetch(t, b"k"), b"value")
        self.assertEqual(mphf.fetch(t, b"empty"), b"")
        self.assertEqual(type(mphf.fetch(t, b"empty")), bytes)
        self.assertEqual(mphf.fetch(t, b"nope"), mphf.NOT_FOUND)
        # get_content 默认哨兵为 None：三态清晰。
        self.assertEqual(t.get_content(b"k"), b"value")
        self.assertEqual(t.get_content(b"empty"), b"")
        self.assertIsNone(t.get_content(b"nope"))

    def test_empty_key_can_have_content(self):
        t = mphf.build([b""], [b"payload-for-empty-key"])
        self.assertEqual(mphf.fetch(t, b""), b"payload-for-empty-key")
        self.assertEqual(mphf.lookup(t, b"x"), mphf.NOT_FOUND)

    def test_variable_length_including_nul_and_binary(self):
        contents = [b"", b"\x00" * 7, bytes(range(256)), b"plain ascii 123"]
        keys = [f"key-{i}".encode() for i in range(4)]
        t = mphf.build(keys, contents)
        for k, c in zip(keys, contents):
            self.assertEqual(mphf.fetch(t, k), c)

    def test_contents_length_mismatch(self):
        with self.assertRaises(ValueError):
            mphf.build([b"a", b"b"], [b"x"])
        with self.assertRaises(ValueError):
            mphf.build([b"a"], [b"x", b"y"])
        # 生成器同样检查
        with self.assertRaises(ValueError):
            mphf.build((f"k{i}".encode() for i in range(3)),
                       (b"c" for _ in range(2)))

    def test_contents_type_errors(self):
        with self.assertRaises(TypeError):
            mphf.build([b"a"], ["str-not-bytes"])
        with self.assertRaises(TypeError):
            mphf.build([b"a"], [123])
        with self.assertRaises(TypeError):
            mphf.build([b"a"], [True])
        with self.assertRaises(TypeError):
            mphf.build([b"a"], b"raw-bytes")

    def test_empty_table_with_and_without_contents(self):
        self.assertEqual(mphf.build([]).contents, ())
        self.assertEqual(mphf.build([], []).contents, ())
        with self.assertRaises(ValueError):
            mphf.build([], [b"x"])


class ArchiveRoundtripTests(unittest.TestCase):
    def assert_roundtrip_identical(self, keys, contents):
        t = mphf.build(keys, contents)
        self.assertIsInstance(t, mphf.MPHFTable)
        t2 = mphf.loads(mphf.dumps(t))
        self.assertEqual(t2, t)
        # 槽位位置与查询结果保存前后一致（独立参考再算一遍槽位）。
        for k, c in zip(keys, contents):
            self.assertEqual(ref_slot(t2, k), mphf.lookup(t2, k))
            self.assertEqual(mphf.lookup(t, k), mphf.lookup(t2, k))
            self.assertEqual(mphf.fetch(t2, k), c)
        return t, t2

    def test_roundtrip_small_with_content(self):
        keys = [b"alpha", b"beta", b"gamma", b"delta"]
        contents = [b"one", b"", b"three-three", b"4" * 100]
        self.assert_roundtrip_identical(keys, contents)

    def test_roundtrip_retry_seed_table(self):
        keys = [b"a", b"b", b"i"]
        self.assert_roundtrip_identical(keys, [b"A", b"B", b"I"])

    def test_roundtrip_boundary_1000(self):
        keys = det_keys(1000)
        contents = [f"content-{i}".encode() * (i % 5) for i in range(1000)]
        self.assert_roundtrip_identical(keys, contents)

    def test_roundtrip_empty_table(self):
        t = mphf.build([])
        t2 = mphf.loads(mphf.dumps(t))
        self.assertEqual(t2, t)
        self.assertEqual(mphf.lookup(t2, b"x"), mphf.NOT_FOUND)
        self.assertEqual(mphf.fetch(t2, b"x"), mphf.NOT_FOUND)

    def test_nonmember_after_reload_never_leaks(self):
        keys = det_keys(20)
        contents = [f"val-{i}".encode() for i in range(20)]
        t = mphf.build(keys, contents)
        t2 = mphf.loads(mphf.dumps(t))
        for q in (b"", b"k-020", b"collision-x"):
            self.assertEqual(mphf.lookup(t2, q), mphf.NOT_FOUND, q)
            self.assertEqual(mphf.fetch(t2, q), mphf.NOT_FOUND, q)
            self.assertIsNone(t2.get_content(q), q)

    def test_save_load_file_roundtrip(self):
        keys = [b"a", b"b", b"i"]
        t = mphf.build(keys, [b"1", b"", b"33"])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "table.mphf")
            os.makedirs(os.path.dirname(path))
            mphf.save(t, path)
            t2 = mphf.load(path)
            self.assertEqual(t2, t)
            # 没有遗留临时文件
            leftovers = [
                n for n in os.listdir(os.path.dirname(path))
                if n.startswith(".mphf-tmp")
            ]
            self.assertEqual(leftovers, [])

    def test_methods_match_functions(self):
        t = mphf.build([b"a"], [b"c"])
        self.assertEqual(t.dumps(), mphf.dumps(t))
        self.assertEqual(t.fetch(b"a"), b"c")

    def test_dumps_rejects_non_table(self):
        with self.assertRaises(TypeError):
            mphf.dumps(mphf.CONSTRUCTION_FAILED)
        with self.assertRaises(TypeError):
            mphf.dumps("x")
        with self.assertRaises(TypeError):
            mphf.loads(123)


class CorruptionTests(unittest.TestCase):
    HEAD_FIXED = 8 + 4 + 4 + 1 + 4  # magic,n,m,seed,attempts

    def setUp(self):
        keys = [b"alpha", b"beta", b"gamma"]
        self.t = mphf.build(keys, [b"111", b"", b"ccc3"])
        self.blob = bytearray(mphf.dumps(self.t))

    def test_truncated_blobs_rejected(self):
        good = bytes(self.blob)
        for cut in (0, 8, 20, len(good) - 1, len(good) - 32):
            with self.assertRaises(mphf.ArchiveFormatError, msg=f"cut={cut}"):
                mphf.loads(good[:cut])

    def test_bad_magic(self):
        bad = bytearray(self.blob)
        bad[0] ^= 0xFF
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(bytes(bad))

    def test_checksum_detects_any_byte_flip(self):
        for idx in (0, 10, self.HEAD_FIXED, len(self.blob) - 33, len(self.blob) - 1):
            bad = bytearray(self.blob)
            bad[idx] ^= 0x01
            with self.assertRaises(mphf.ArchiveFormatError, msg=f"idx={idx}"):
                mphf.loads(bytes(bad))

    def _body(self) -> bytearray:
        return self.blob[:-32]

    def test_huge_key_length_cannot_oob_read(self):
        body = self._body()
        n, m = self.t.size, self.t.vertex_count
        klen_pos = self.HEAD_FIXED + 4 * m
        body[klen_pos : klen_pos + 4] = (0xFFFFFFFF).to_bytes(4, "big")
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_huge_content_length_cannot_oob_read(self):
        body = self._body()
        n, m = self.t.size, self.t.vertex_count
        # 第一条记录：klen(4)+key(5) 后的 clen 字段
        clen_pos = self.HEAD_FIXED + 4 * m + 4 + len(self.t.keys[0])
        body[clen_pos : clen_pos + 4] = (0x7FFFFFFF).to_bytes(4, "big")
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_key_length_overflow_into_next_record_rejected(self):
        # klen 比实际长 1：解析会把后续字节当键，最终在边界处失败，
        # 绝不会静默把内容/下一键错位读出。
        body = self._body()
        n, m = self.t.size, self.t.vertex_count
        klen_pos = self.HEAD_FIXED + 4 * m
        klen = int.from_bytes(body[klen_pos : klen_pos + 4], "big")
        body[klen_pos : klen_pos + 4] = (klen + 1).to_bytes(4, "big")
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_header_n_m_inconsistent(self):
        body = self._body()
        n, m = self.t.size, self.t.vertex_count
        body[8:12] = struct.pack(">I", n)
        body[12:16] = struct.pack(">I", m + 1)
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_header_n_over_limit(self):
        body = self._body()
        body[8:12] = struct.pack(">I", 1001)
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_g_value_out_of_range(self):
        body = self._body()
        gpos = self.HEAD_FIXED
        body[gpos : gpos + 4] = struct.pack(">I", self.t.size + 5)
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_trailing_bytes_rejected(self):
        body = bytearray(self._body())
        body += b"\x00"
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_non_ascii_key_in_archive_rejected(self):
        body = self._body()
        n, m = self.t.size, self.t.vertex_count
        key_pos = self.HEAD_FIXED + 4 * m + 4
        body[key_pos] = 0xFF
        with self.assertRaises(mphf.ArchiveFormatError):
            mphf.loads(rebuild_blob(bytes(body)))

    def test_load_missing_file_raises_oserror(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                mphf.load(os.path.join(d, "nope.mphf"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
