"""键值只读快照（KvSnapshot / build_kv / find_kv）的必要测试。

独立性原则（与 tests/test_mphf.py 一致）：

* 快照字节布局由**测试侧按 README 文档用 struct 独立解析**，不调用
  被测模块的解析器，也不使用其私有编解码函数；
* 槽位由测试侧独立哈希 ``ref_h``（见 test_mphf 的契约实现）+ 头部解析出
  的 seed/m/g 重新计算，手动核对“键 i 确实落在槽位 i、值与键同槽位”；
* 损坏文件测试中，篡改体后会**重新计算 SHA256 写回头部**，专门证明
  “校验和正确 ≠ 内部合法”：错槽位、重复键、越界长度在校验和正确时
  仍必须被拒绝。
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import mphf


# ----------------------------------------------------------- 测试侧独立参考


#: 文档头部布局（大端）：7s magic, H version, I n, I m, I seed,
#: I attempts, Q body_len, 32s sha256 —— 与 README 字节表逐字对应。
REF_HEADER = struct.Struct(">7sHIIIIQ32s")
REF_U32 = struct.Struct(">I")
REF_MAGIC = b"MPHKVDB"
REF_VERSION = 1
REF_HEADER_SIZE = 65
REF_MAX_VALUE_LEN = 4096


def ref_h(seed: int, tag: int, key: bytes, m: int) -> int:
    """按公开哈希契约独立实现（不调用 mphf 内部函数）。"""
    digest = hashlib.sha256(seed.to_bytes(4, "big") + bytes([tag]) + key).digest()
    return int.from_bytes(digest, "big") % m


def ref_vertex_count(n: int) -> int:
    return (14 * n + 9) // 10


def ref_parse(data: bytes) -> dict:
    """**仅按文档**独立解析整张快照，返回各字段与逐条记录（含偏移）。"""
    assert len(data) >= REF_HEADER_SIZE
    magic, version, n, m, seed, attempts, body_len, digest = REF_HEADER.unpack(
        data[:REF_HEADER_SIZE]
    )
    assert len(data) == REF_HEADER_SIZE + body_len
    body = data[REF_HEADER_SIZE:]
    g = [
        REF_U32.unpack(body[off : off + 4])[0]
        for off in range(0, m * 4, 4)
    ]
    records = []
    pos = m * 4
    while pos < body_len:
        koff = pos
        klen = REF_U32.unpack(body[pos : pos + 4])[0]
        pos += 4
        key = body[pos : pos + klen]
        pos += klen
        vlen = REF_U32.unpack(body[pos : pos + 4])[0]
        pos += 4
        value = body[pos : pos + vlen]
        pos += vlen
        records.append(dict(koff=koff, klen=klen, key=key, vlen=vlen, value=value))
    return dict(
        magic=magic, version=version, n=n, m=m, seed=seed, attempts=attempts,
        body_len=body_len, digest=digest, body=body, g=g, records=records,
    )


def ref_slot(parsed: dict, key: bytes) -> int:
    n, m, seed, g = parsed["n"], parsed["m"], parsed["seed"], parsed["g"]
    return (
        g[ref_h(seed, 0, key, m)]
        + g[ref_h(seed, 1, key, m)]
        + g[ref_h(seed, 2, key, m)]
    ) % n


def repack(parsed: dict, *, body: bytes | None = None, **over) -> bytes:
    """用（可能被篡改的）字段/体重组快照并重算校验和。"""
    body = parsed["body"] if body is None else body
    fields = dict(
        magic=parsed["magic"], version=parsed["version"], n=parsed["n"],
        m=parsed["m"], seed=parsed["seed"], attempts=parsed["attempts"],
    )
    fields.update(over)
    return REF_HEADER.pack(
        fields["magic"], fields["version"], fields["n"], fields["m"],
        fields["seed"], fields["attempts"], len(body),
        hashlib.sha256(body).digest(),
    ) + body


def fixed_width_keys(n: int) -> list[bytes]:
    width = max(2, len(str(n - 1)))
    return [f"k{i:0{width}d}".encode("ascii") for i in range(n)]


# ----------------------------------------------------------------- 格式常量


class FormatContractTests(unittest.TestCase):
    def test_documented_constants(self):
        self.assertEqual(mphf.SNAPSHOT_MAGIC, REF_MAGIC)
        self.assertEqual(mphf.SNAPSHOT_VERSION, REF_VERSION)
        self.assertEqual(mphf.SNAPSHOT_HEADER_SIZE, REF_HEADER_SIZE)
        self.assertEqual(REF_HEADER.size, REF_HEADER_SIZE)
        self.assertEqual(mphf.MAX_VALUE_LEN, REF_MAX_VALUE_LEN)

    def test_empty_snapshot_bytes_match_documentation(self):
        # 空字典的快照字节可完全按文档手算：
        # magic(7) + 0001 + 四个 0 + body_len=0 + SHA256("")。
        data = mphf.build_kv([]).to_bytes()
        parsed = ref_parse(data)
        self.assertEqual(parsed["magic"], REF_MAGIC)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual((parsed["n"], parsed["m"], parsed["seed"]), (0, 0, 0))
        self.assertEqual(parsed["attempts"], 0)
        self.assertEqual(parsed["body_len"], 0)
        self.assertEqual(parsed["body"], b"")
        self.assertEqual(parsed["digest"], hashlib.sha256(b"").digest())
        self.assertEqual(len(data), REF_HEADER_SIZE)
        # 载入后一切查询未命中
        snap = mphf.KvSnapshot.from_bytes(data)
        self.assertEqual(len(snap), 0)
        self.assertEqual(mphf.find_kv(snap, b""), (False, None))
        self.assertEqual(mphf.find_kv(snap, b"anything"), (False, None))


# ----------------------------------------------- 独立按文档解析并核对键值位置


class IndependentLayoutTests(unittest.TestCase):
    PAIRS = [
        (b"ccc", b"third-333"),
        (b"a", b""),                # 空值是有效命中
        (b"bb", b"\x00\x01binary"),
    ]

    def setUp(self):
        # 故意乱序传入；文档要求构建前按键字节序排序。
        self.snap = mphf.build_kv(list(reversed(self.PAIRS)))
        self.data = self.snap.to_bytes()
        self.parsed = ref_parse(self.data)

    def test_header_fields(self):
        p = self.parsed
        self.assertEqual(p["magic"], REF_MAGIC)
        self.assertEqual(p["version"], REF_VERSION)
        self.assertEqual(p["n"], 3)
        self.assertEqual(p["m"], ref_vertex_count(3))  # ceil(1.4*3) = 5
        self.assertEqual(0 <= p["seed"] < 256, True)
        self.assertEqual(p["attempts"], p["seed"] + 1)
        self.assertEqual(p["body_len"], len(p["body"]))
        self.assertEqual(len(self.data), REF_HEADER_SIZE + p["body_len"])
        self.assertEqual(p["digest"], hashlib.sha256(p["body"]).digest())

    def test_g_array_length_and_ranges(self):
        p = self.parsed
        self.assertEqual(len(p["g"]), p["m"])
        self.assertTrue(all(0 <= x < p["n"] for x in p["g"]))

    def test_records_sorted_and_collocated_with_values(self):
        p = self.parsed
        # 记录即槽位：第 i 条记录必须是排序后第 i 个键，且携带其值。
        sorted_pairs = sorted(self.PAIRS, key=lambda kv: kv[0])
        self.assertEqual(len(p["records"]), 3)
        for i, rec in enumerate(p["records"]):
            key, value = sorted_pairs[i]
            self.assertEqual(rec["key"], key)
            self.assertEqual(rec["value"], value)
            # 文档长度前缀
            self.assertEqual(rec["klen"], len(key))
            self.assertEqual(rec["vlen"], len(value))

    def test_each_key_independently_maps_to_own_slot(self):
        p = self.parsed
        for i, rec in enumerate(p["records"]):
            self.assertEqual(ref_slot(p, rec["key"]), i)

    def test_loaded_snapshot_queries(self):
        loaded = mphf.KvSnapshot.from_bytes(self.data)
        for key, value in sorted(self.PAIRS, key=lambda kv: kv[0]):
            self.assertEqual(mphf.find_kv(loaded, key), (True, value))
        # 空值命中有独立布尔标志，与未命中可区分
        self.assertEqual(loaded.find(b"a"), (True, b""))
        self.assertEqual(loaded.find(b"missing"), (False, None))
        self.assertIsNone(loaded.get(b"missing"))
        self.assertEqual(loaded.get(b"missing", b"d"), b"d")
        self.assertIn(b"bb", loaded)
        self.assertNotIn(b"b", loaded)


class RoundTripTests(unittest.TestCase):
    def test_input_permutations_produce_identical_bytes(self):
        pairs = [(b"k2", b"v2"), (b"k0", b""), (b"k1", b"x" * 4096),
                 (b"", b"empty-key")]
        ref = mphf.build_kv(pairs).to_bytes()
        for variant in (
            reversed(pairs),
            [pairs[i] for i in (2, 0, 3, 1)],
            {k: v for k, v in pairs},                    # dict 输入
            [(bytearray(k), memoryview(v)) for k, v in pairs],  # bytes-like
        ):
            self.assertEqual(mphf.build_kv(variant).to_bytes(), ref)
        # 载入后查询与内存构建一致
        loaded = mphf.KvSnapshot.from_bytes(ref)
        for k, v in pairs:
            self.assertEqual(mphf.find_kv(loaded, k), (True, v))

    def test_large_1000_keys_roundtrip(self):
        pairs = [(k, f"value-{i}".encode()) for i, k in enumerate(fixed_width_keys(1000))]
        snap = mphf.build_kv(pairs)
        self.assertIsInstance(snap, mphf.KvSnapshot)
        self.assertEqual(snap.size, 1000)
        self.assertEqual(snap.vertex_count, 1400)
        loaded = mphf.KvSnapshot.from_bytes(snap.to_bytes())
        for i in (0, 1, 500, 999):
            self.assertEqual(mphf.find_kv(loaded, pairs[i][0]), (True, pairs[i][1]))
        self.assertEqual(mphf.find_kv(loaded, b"k9999"), (False, None))

    def test_empty_value_is_a_hit(self):
        snap = mphf.build_kv([(b"k", b"")])
        hit, value = mphf.find_kv(snap, b"k")
        self.assertTrue(hit)
        self.assertEqual(value, b"")
        self.assertEqual(snap.get(b"k", b"default"), b"")

    def test_nonmember_hash_collision_still_misses(self):
        """非成员的哈希落到已占用槽位时，完整键终检仍判未命中。"""
        keys = fixed_width_keys(8)
        snap = mphf.build_kv([(k, b"v") for k in keys])
        parsed = ref_parse(snap.to_bytes())
        collider = next(
            f"cand-{x}".encode()
            for x in range(100000)
            if f"cand-{x}".encode() not in keys
            and ref_slot(parsed, f"cand-{x}".encode()) in range(8)
        )
        self.assertEqual(mphf.find_kv(snap, collider), (False, None))

    def test_non_ascii_query_misses(self):
        snap = mphf.build_kv([(b"abc", b"v")])
        for q in (b"ab\xff", b"\x80", "café".encode()):
            self.assertEqual(mphf.find_kv(snap, q), (False, None))


# ------------------------------------------------------------- build_kv 校验


class BuildKvValidationTests(unittest.TestCase):
    def test_duplicate_key_rejected_not_silently_overwritten(self):
        with self.assertRaises(mphf.DuplicateKeyError) as cm:
            mphf.build_kv([(b"a", b"1"), (b"b", b"2"), (b"a", b"3")])
        self.assertEqual(cm.exception.key, b"a")
        self.assertEqual(cm.exception.index, 2)

    def test_dict_duplicate_via_iterable_rejected(self):
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build_kv([(b"same", b"1"), (bytearray(b"same"), b"2")])

    def test_non_ascii_key_rejected(self):
        with self.assertRaises(ValueError):
            mphf.build_kv([(b"ok", b"1"), (b"bad\xff", b"2")])

    def test_value_must_be_bytes(self):
        for bad in ("str", 1, 1.5, None, True, [1], object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.build_kv([(b"ok", bad)])

    def test_value_limit_4096(self):
        mphf.build_kv([(b"ok", b"x" * 4096)])  # 恰好上限合法
        with self.assertRaises(ValueError):
            mphf.build_kv([(b"ok", b"x" * 4097)])

    def test_key_limit_1000(self):
        pairs = [(f"k{i:04d}".encode(), b"v") for i in range(1001)]
        with self.assertRaises(ValueError):
            mphf.build_kv(pairs)
        with self.assertRaises(ValueError):
            mphf.build_kv(iter(pairs))

    def test_container_and_pair_shape_errors(self):
        with self.assertRaises(TypeError):
            mphf.build_kv(b"abc")               # 单个 bytes 不是对序列
        with self.assertRaises(TypeError):
            mphf.build_kv(123)
        with self.assertRaises(TypeError):
            mphf.build_kv(None)
        with self.assertRaises(TypeError):
            mphf.build_kv([b"not-a-pair"])     # 元素无法解包成对
        with self.assertRaises(TypeError):
            mphf.build_kv([(b"only-one",)])    # 元素长度不对

    def test_key_type_errors(self):
        for bad in (1, 1.0, "str", None, True, object()):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.build_kv([(bad, b"v")])

    def test_construction_failure_semantics_preserved(self):
        tricky = [(b"a", b""), (b"b", b""), (b"i", b"")]
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            result = mphf.build_kv(tricky)
        self.assertIs(result, mphf.CONSTRUCTION_FAILED)
        with self.assertRaises(ValueError):
            mphf.find_kv(result, b"a")

    def test_find_type_errors(self):
        snap = mphf.build_kv([(b"a", b"v")])
        for bad in (1, 1.5, "a", None, True, [b"a"]):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.find_kv(snap, bad)
        with self.assertRaises(TypeError):
            mphf.find_kv("not a snapshot", b"a")

    def test_from_bytes_type_error(self):
        for bad in (123, "str", None, True):
            with self.assertRaises(TypeError):
                mphf.KvSnapshot.from_bytes(bad)


# ------------------------------------------------------- 载入校验与损坏文件


class CorruptSnapshotTests(unittest.TestCase):
    def setUp(self):
        # 等宽键集，便于在固定偏移上篡改记录而不移动后续记录。
        keys = fixed_width_keys(5)
        self.orig = mphf.build_kv([(k, f"v{i}".encode()) for i, k in enumerate(keys)])
        self.parsed = ref_parse(self.orig.to_bytes())

    def _set_u32(self, body: bytearray, offset: int, value: int) -> None:
        body[offset : offset + 4] = REF_U32.pack(value)

    # ---------------------------------------------------------- 长度与版本

    def test_truncated_rejected(self):
        data = self.orig.to_bytes()
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(data[:-1])
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(data[: REF_HEADER_SIZE - 1])

    def test_trailing_data_rejected(self):
        data = self.orig.to_bytes() + b"\x00"
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(data)

    def test_bad_magic_rejected(self):
        data = bytearray(self.orig.to_bytes())
        data[0] ^= 0xFF
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(bytes(data))

    def test_unknown_version_rejected(self):
        data = repack(self.parsed, version=999)  # 体与校验和均合法
        with self.assertRaises(mphf.UnknownSnapshotVersionError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertEqual(cm.exception.version, 999)
        self.assertIsInstance(cm.exception, mphf.SnapshotFormatError)

    # ------------------------------------------------------- 校验和本身

    def test_bad_checksum_detected(self):
        data = bytearray(self.orig.to_bytes())
        body_off = REF_HEADER_SIZE + self.parsed["m"] * 4
        data[body_off] ^= 0xFF  # 篡改体但不重算校验和
        with self.assertRaises(mphf.SnapshotChecksumError):
            mphf.KvSnapshot.from_bytes(bytes(data))

    # ---------------------------- 校验和正确仍必须失败：错槽位 / 重复 / 越界

    def test_valid_checksum_but_wrong_slot_mapping_rejected(self):
        """篡改 g[h0(键0)]（保持 0..n-1 范围内）并重算校验和：
        键 0 不再落在槽位 0，必须在“索引结构”步被拒。"""
        p = self.parsed
        n, m, seed = p["n"], p["m"], p["seed"]
        self.assertGreaterEqual(n, 2)
        body = bytearray(p["body"])
        v0 = ref_h(seed, 0, p["records"][0]["key"], m)
        off = v0 * 4
        old = REF_U32.unpack(body[off : off + 4])[0]
        self._set_u32(body, off, (old + 1) % n)  # 仍在 0..n-1 内
        data = repack(p, body=bytes(body))
        # 校验和是重算过的、合法的；失败必须来自结构校验而非校验和。
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertNotIsInstance(cm.exception, mphf.SnapshotChecksumError)
        self.assertIn("slot", str(cm.exception))

    def test_valid_checksum_but_duplicate_key_rejected(self):
        """把槽位 1 的键原样改成槽位 0 的键（等长，偏移不动）并重算
        校验和：必须以重复键拒绝，而不是悄悄载入。"""
        p = self.parsed
        body = bytearray(p["body"])
        r0, r1 = p["records"][0], p["records"][1]
        self.assertEqual(r0["klen"], r1["klen"])
        key_field_1 = r1["koff"] + 4
        body[key_field_1 : key_field_1 + r1["klen"]] = r0["key"]
        data = repack(p, body=bytes(body))
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertNotIsInstance(cm.exception, mphf.SnapshotChecksumError)
        self.assertIn("duplicate", str(cm.exception))

    def test_valid_checksum_but_key_order_violation_rejected(self):
        """交换两条等长记录的键字节并重算校验和：键序破坏必须被拒。"""
        p = self.parsed
        body = bytearray(p["body"])
        r0, r1 = p["records"][0], p["records"][1]
        kf0, kf1 = r0["koff"] + 4, r1["koff"] + 4
        body[kf0 : kf0 + r0["klen"]] = r1["key"]
        body[kf1 : kf1 + r1["klen"]] = r0["key"]
        data = repack(p, body=bytes(body))
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertNotIsInstance(cm.exception, mphf.SnapshotChecksumError)
        self.assertIn("byte order", str(cm.exception))

    def test_valid_checksum_but_value_length_over_limit_rejected(self):
        """把第一条记录的值长度字段改成 4097 并重算校验和：必须在解析
        上限步被拒，不能消费后续字节蒙混过关。"""
        p = self.parsed
        body = bytearray(p["body"])
        r0 = p["records"][0]
        vlen_off = r0["koff"] + 4 + r0["klen"]
        self._set_u32(body, vlen_off, REF_MAX_VALUE_LEN + 1)
        data = repack(p, body=bytes(body))
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertNotIsInstance(cm.exception, mphf.SnapshotChecksumError)
        self.assertIn(str(REF_MAX_VALUE_LEN), str(cm.exception))

    # ----------------------------------------------------------- 索引参数

    def test_n_over_limit_rejected_even_with_valid_checksum(self):
        p = self.parsed
        # n=1001、m 按公式自洽、体留空：长度自洽且校验和合法，
        # 但键数越过 1000 上限必须被拒。
        body = b""
        data = REF_HEADER.pack(
            REF_MAGIC, 1, 1001, ref_vertex_count(1001), 0, 1,
            len(body), hashlib.sha256(body).digest(),
        ) + body
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(data)

    def test_m_inconsistent_with_n_rejected(self):
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(repack(self.parsed, m=self.parsed["m"] + 1))

    def test_attempts_inconsistent_with_seed_rejected(self):
        p = self.parsed
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(repack(p, attempts=p["attempts"] + 1))

    def test_seed_out_of_range_rejected(self):
        with self.assertRaises(mphf.SnapshotFormatError):
            mphf.KvSnapshot.from_bytes(repack(self.parsed, seed=256, attempts=257))

    def test_g_value_out_of_range_rejected_with_valid_checksum(self):
        p = self.parsed
        body = bytearray(p["body"])
        body[0:4] = REF_U32.pack(p["n"])  # g[0] = n，越过 0..n-1
        data = repack(p, body=bytes(body))
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(data)
        self.assertNotIsInstance(cm.exception, mphf.SnapshotChecksumError)

    def test_record_count_mismatch_rejected(self):
        """体中记录条数多于头部声称的 n（n/m/校验和均自洽）也要拒绝。"""
        p = self.parsed
        extra = REF_U32.pack(1) + b"z" + REF_U32.pack(1) + b"w"
        with self.assertRaises(mphf.SnapshotFormatError) as cm:
            mphf.KvSnapshot.from_bytes(repack(p, body=p["body"] + extra))
        self.assertIn("record count", str(cm.exception))


# ----------------------------------------------------------- 文件载入独立性


class FileLoadTests(unittest.TestCase):
    def test_save_load_roundtrip_and_no_handle_dependency(self):
        snap = mphf.build_kv([(b"alpha", b"1"), (b"beta", b"")])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dict.mphkv")
            snap.save(path)
            loaded = mphf.KvSnapshot.load(path)
            # 载入后删除源文件：对象完全驻留内存，不依赖文件句柄。
            os.remove(path)
            self.assertFalse(os.path.exists(path))
        self.assertEqual(loaded.find(b"alpha"), (True, b"1"))
        self.assertEqual(loaded.find(b"beta"), (True, b""))
        self.assertEqual(loaded.find(b"gamma"), (False, None))
        self.assertEqual(loaded.to_bytes(), snap.to_bytes())

    def test_save_is_a_single_file(self):
        snap = mphf.build_kv([(b"a", b"b")])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.mphkv")
            snap.save(path)
            self.assertEqual(os.listdir(d), ["x.mphkv"])  # 无残留 .tmp


# ------------------------------------------------- 另一个进程重新加载的演示


class DemoKvSubprocessTests(unittest.TestCase):
    def test_demo_kv_runs_and_child_reloads(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, os.path.join(repo, "demo_kv.py")],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("child:", proc.stdout)
        self.assertIn("RELOAD OK", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
