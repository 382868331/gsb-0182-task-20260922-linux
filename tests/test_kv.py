"""自带值只读字典层（build_kv / find / 快照）的必要测试。

独立性原则（与 tests/test_mphf.py 一致）：

* 槽位与哈希向量由**测试侧独立实现**（直接拼装
  SHA256(seed_be4 || tag || key)），不调用被测核心的哈希函数产生期望值；
* 快照解析在“手动解析”用例中**只按 README 的字节布局**自行切片/解包，
  不调用 mphf.loads；
* 损坏快照由测试侧的独立写入器 ``manual_snapshot`` 逐字节构造，校验和
  重新计算，确保“校验和正确但内部非法”的文件真的被拒绝。
"""

from __future__ import annotations

import hashlib
import itertools
import os
import struct
import tempfile
import unittest
from unittest.mock import patch

import mphf

HDR = struct.Struct(">8sIIIIII")
MAGIC = b"MPHFKV01"
HEADER_SIZE = 64


# ----------------------------------------------------------- 测试侧独立参考


def ref_h(seed: int, tag: int, key: bytes, m: int) -> int:
    digest = hashlib.sha256(seed.to_bytes(4, "big") + bytes([tag]) + key).digest()
    return int.from_bytes(digest, "big") % m


def ref_slot(g, seed: int, key: bytes, n: int, m: int) -> int:
    return (
        g[ref_h(seed, 0, key, m)]
        + g[ref_h(seed, 1, key, m)]
        + g[ref_h(seed, 2, key, m)]
    ) % n


def manual_snapshot(
    n: int,
    m: int,
    seed: int,
    g: list[int],
    keys: list[bytes],
    values: list[bytes],
    *,
    magic: bytes = MAGIC,
    version: int = 1,
    key_bytes: int | None = None,
    value_bytes: int | None = None,
    bad_checksum: bool = False,
) -> bytes:
    """按文档布局独立构造快照字节（不调用 mphf 的任何序列化代码）。

    可故意制造内部非法但长度/校验和自洽的文件。
    """
    assert len(g) == m and len(keys) == n and len(values) == n
    kb = sum(len(k) for k in keys) if key_bytes is None else key_bytes
    vb = sum(len(v) for v in values) if value_bytes is None else value_bytes
    head = HDR.pack(magic, version, n, m, seed, kb, vb)
    body = b"".join(struct.pack(">H", x) for x in g)
    body += b"".join(struct.pack(">I", len(k)) + k for k in keys)
    body += b"".join(struct.pack(">I", len(v)) + v for v in values)
    digest = hashlib.sha256(head + body).digest()
    if bad_checksum:
        digest = bytes([digest[0] ^ 0xFF]) + digest[1:]
    return head + digest + body


def parse_snapshot(blob: bytes) -> dict:
    """测试侧独立解析器：严格按 README 字节布局手工切片。"""
    assert len(blob) >= HEADER_SIZE
    magic, version, n, m, seed, kb, vb = HDR.unpack(blob[:32])
    checksum = blob[32:64]
    off = HEADER_SIZE
    g = [struct.unpack_from(">H", blob, off + 2 * i)[0] for i in range(m)]
    off += 2 * m
    keys = []
    for _ in range(n):
        klen = struct.unpack_from(">I", blob, off)[0]
        off += 4
        keys.append(blob[off:off + klen])
        off += klen
    values = []
    for _ in range(n):
        vlen = struct.unpack_from(">I", blob, off)[0]
        off += 4
        values.append(blob[off:off + vlen])
        off += vlen
    return {
        "magic": magic, "version": version, "n": n, "m": m, "seed": seed,
        "key_bytes": kb, "value_bytes": vb, "checksum": checksum,
        "g": g, "keys": keys, "values": values, "total": off,
    }


# --------------------------------------------------------------------- 测试


class BuildKVTests(unittest.TestCase):
    def test_basic_find_hit_and_miss_flags(self):
        d = mphf.build_kv([(b"beta", b"2"), (b"alpha", b"1"), (b"gamma", b"")])
        self.assertIsInstance(d, mphf.KVDictionary)
        self.assertEqual(len(d), 3)
        # 按键字节序固定排序后构造
        self.assertEqual(d.keys(), (b"alpha", b"beta", b"gamma"))
        # 空值是有效命中，与未命中标志明确区分
        self.assertEqual(mphf.find(d, b"gamma"), (True, b""))
        self.assertEqual(mphf.find(d, b"alpha"), (True, b"1"))
        self.assertEqual(mphf.find(d, b"absent"), (False, None))
        self.assertEqual(mphf.find(d, b"\xff"), (False, None))
        # 容器式接口
        self.assertEqual(d[b"beta"], b"2")
        self.assertIn(b"alpha", d)
        self.assertNotIn(b"nope", d)
        self.assertIsNone(d.get(b"nope"))
        self.assertEqual(d.get(b"nope", b"def"), b"def")
        self.assertEqual(d.get(b"gamma"), b"")  # 空值不被当成缺失
        with self.assertRaises(KeyError):
            d[b"nope"]

    def test_empty_dictionary(self):
        d = mphf.build_kv([])
        self.assertEqual(len(d), 0)
        self.assertEqual(d.keys(), ())
        self.assertEqual(d.values(), ())
        self.assertEqual(mphf.find(d, b"x"), (False, None))
        self.assertNotIn(b"", d)

    def test_duplicate_keys_rejected_not_overwritten(self):
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build_kv([(b"a", b"1"), (b"a", b"2")])
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build_kv([(b"k", b"1"), (bytearray(b"k"), b"2")])
        # 重复键即使在排序后相邻也必须拒绝（不同传入顺序）
        with self.assertRaises(mphf.DuplicateKeyError):
            mphf.build_kv([(b"z", b""), (b"a", b""), (b"z", b"")])

    def test_value_must_be_bytes_and_limit_4096(self):
        for bad in ("str", 1, None, bytearray(b"x"), memoryview(b"x"), True):
            with self.assertRaises(TypeError, msg=repr(bad)):
                mphf.build_kv([(b"k", bad)])
        with self.assertRaises(ValueError):
            mphf.build_kv([(b"k", b"x" * 4097)])
        # 4096 恰好允许，0 允许
        d = mphf.build_kv([(b"k", b"x" * 4096), (b"e", b"")])
        self.assertEqual(d[b"k"], b"x" * 4096)
        self.assertEqual(d[b"e"], b"")

    def test_item_shape_validation(self):
        for bad in ([b"k", b"v", b"z"], (b"k",), (b"k", b"v", b"q"), 7, b"kv"):
            with self.assertRaises((TypeError, ValueError)):
                mphf.build_kv([bad])

    def test_limit_1000_preserved(self):
        items = [(f"k{i:04d}".encode(), b"v") for i in range(1001)]
        with self.assertRaises(ValueError):
            mphf.build_kv(items)
        d = mphf.build_kv([(f"k{i:04d}".encode(), bytes([i % 256])) for i in range(1000)])
        self.assertEqual(len(d), 1000)
        self.assertEqual(d.table.vertex_count, 1400)

    def test_construction_failure_semantics_preserved(self):
        # {a,b,i} 在 seed=0 真实不可剥离：压预算为 1 必须返回同一哨兵。
        with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
            result = mphf.build_kv([(k, b"") for k in [b"a", b"b", b"i"]])
        self.assertIs(result, mphf.CONSTRUCTION_FAILED)
        d = mphf.build_kv([(k, b"") for k in [b"a", b"b", b"i"]])
        self.assertEqual(d.table.seed, 2)

    def test_keys_are_ascii_rule_preserved(self):
        with self.assertRaises(ValueError):
            mphf.build_kv([(b"ok", b""), (b"bad\xff", b"")])
        with self.assertRaises(TypeError):
            mphf.build_kv(b"ab")

    def test_find_type_errors(self):
        d = mphf.build_kv([(b"a", b"")])
        for bad in (1, "a", None, True):
            with self.assertRaises(TypeError):
                mphf.find(d, bad)
        with self.assertRaises(TypeError):
            mphf.find("not a dict", b"a")


class OrderIndependenceTests(unittest.TestCase):
    def test_snapshot_bytes_identical_under_permutations(self):
        pairs = [(f"key-{i:03d}".encode(), f"val-{i}".encode()) for i in range(12)]
        blobs = set()
        for perm in itertools.islice(itertools.permutations(pairs), 0, 20):
            d = mphf.build_kv(perm)
            blobs.add(mphf.dumps(d))
        self.assertEqual(len(blobs), 1)
        # 同一内容重复构建也逐位相同
        self.assertEqual(
            mphf.dumps(mphf.build_kv(pairs)),
            mphf.dumps(mphf.build_kv(list(reversed(pairs)))),
        )

    def test_sorted_key_order_in_object(self):
        pairs = [(b"z", b""), (b"a", b""), (b"m", b"")]
        d = mphf.build_kv(pairs)
        self.assertEqual(d.keys(), (b"a", b"m", b"z"))
        self.assertEqual(
            d.items(), ((b"a", b""), (b"m", b""), (b"z", b""))
        )


class SnapshotRoundTripTests(unittest.TestCase):
    def test_roundtrip_small_and_boundary(self):
        pairs = [(b"alpha", b"one"), (b"beta", b""), (b"gamma", bytes(range(256))),
                 (b"", b"empty-key")]
        d = mphf.build_kv(pairs)
        d2 = mphf.loads(mphf.dumps(d))
        self.assertEqual(d2.items(), d.items())
        for k, v in pairs:
            self.assertEqual(mphf.find(d2, k), (True, v))
        self.assertEqual(mphf.find(d2, b"delta"), (False, None))
        # 载入对象的索引参数与原表一致
        self.assertEqual((d2.table.seed, d2.table.vertex_count),
                         (d.table.seed, d.table.vertex_count))

    def test_roundtrip_empty_snapshot_is_64_bytes(self):
        blob = mphf.dumps(mphf.build_kv([]))
        self.assertEqual(len(blob), 64)
        parsed = parse_snapshot(blob)
        self.assertEqual((parsed["magic"], parsed["version"], parsed["n"],
                          parsed["m"], parsed["seed"]), (MAGIC, 1, 0, 0, 0))
        self.assertEqual(parsed["key_bytes"], 0)
        self.assertEqual(parsed["value_bytes"], 0)
        self.assertEqual(parsed["total"], 64)
        # 校验和 = SHA256(前 32 字节)（body 为空）
        self.assertEqual(parsed["checksum"], hashlib.sha256(blob[:32]).digest())
        d2 = mphf.loads(blob)
        self.assertEqual(len(d2), 0)

    def test_roundtrip_1000_keys_with_varied_values(self):
        pairs = [(f"doc-{i:04d}".encode(), (b"v" * (i % 33))) for i in range(1000)]
        d = mphf.build_kv(pairs)
        d2 = mphf.loads(mphf.dumps(d))
        self.assertEqual(len(d2), 1000)
        for i in (0, 1, 500, 999):
            k = f"doc-{i:04d}".encode()
            self.assertEqual(mphf.find(d2, k), (True, b"v" * (i % 33)))
        self.assertEqual(mphf.find(d2, b"doc-1000"), (False, None))

    def test_load_from_path_then_close_and_even_delete(self):
        d = mphf.build_kv([(b"a", b"1"), (b"b", b"2")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "dict.snap")
            mphf.dump(d, path)
            loaded = mphf.load(path)
            os.remove(path)  # 载入后对象不依赖文件句柄/文件本身
        self.assertEqual(loaded[b"a"], b"1")
        self.assertEqual(mphf.find(loaded, b"b"), (True, b"2"))

    def test_load_from_open_file_object_then_close(self):
        d = mphf.build_kv([(b"a", b"1")])
        buf = mphf.dumps(d)
        import io
        fh = io.BytesIO(buf)
        loaded = mphf.load(fh)
        fh.close()
        self.assertEqual(loaded[b"a"], b"1")

    def test_loads_does_not_rebuild(self):
        # 载入路径不得调用 build 重建索引。
        d = mphf.build_kv([(b"a", b"1"), (b"b", b"2")])
        blob = mphf.dumps(d)
        with patch.object(mphf, "build", side_effect=AssertionError("build() called")):
            loaded = mphf.loads(blob)
        self.assertEqual(loaded[b"a"], b"1")

    def test_loaded_query_uses_mphf_slot_not_table_dict(self):
        # 载入对象经 mphf.lookup 的完美哈希路径工作：直接验证其表字段满足
        # 方程（独立哈希），且非成员碰撞被完整键终检拒绝。
        d = mphf.loads(mphf.dumps(mphf.build_kv(
            [(f"c-{i}".encode(), b"") for i in range(10)])))
        t = d.table
        for i, k in enumerate(t.keys):
            self.assertEqual(ref_slot(t.values, t.seed, k, t.size, t.vertex_count), i)


class IndependentParseTests(unittest.TestCase):
    def test_parse_small_snapshot_per_document(self):
        pairs = [(b"aa", b"v-aa"), (b"bb", b""), (b"cc", b"v-cc")]
        blob = mphf.dumps(mphf.build_kv(pairs))
        p = parse_snapshot(blob)

        # ---- 头部逐字段核对 ----
        self.assertEqual(p["magic"], MAGIC)
        self.assertEqual(p["version"], 1)
        self.assertEqual(p["n"], 3)
        self.assertEqual(p["m"], 5)  # ceil(1.4*3)
        self.assertIn(p["seed"], range(256))
        self.assertEqual(p["key_bytes"], 6)
        self.assertEqual(p["value_bytes"], 4 + 0 + 4)
        # 总长等式：64 + 2m + (4n+kb) + (4n+vb)
        self.assertEqual(
            len(blob), 64 + 2 * 5 + (12 + 6) + (12 + p["value_bytes"])
        )
        self.assertEqual(p["total"], len(blob))
        # 校验和独立重算
        self.assertEqual(
            p["checksum"], hashlib.sha256(blob[:32] + blob[64:]).digest()
        )

        # ---- 手动按键定位值：独立哈希算出槽位，再取该槽位的键/值 ----
        g, n, m, seed = p["g"], p["n"], p["m"], p["seed"]
        for key, value in pairs:
            s = ref_slot(g, seed, key, n, m)
            self.assertEqual(p["keys"][s], key)   # 键确实在自己的槽位
            self.assertEqual(p["values"][s], value)
        # 空值在其槽位处就是空字节串
        self.assertEqual(p["values"][ref_slot(g, seed, b"bb", n, m)], b"")


class CorruptionTests(unittest.TestCase):
    def _small_blob(self):
        d = mphf.build_kv([(f"k{i}".encode(), f"v{i}".encode()) for i in range(6)])
        return mphf.dumps(d)

    def test_unknown_version_rejected(self):
        blob = self._small_blob()
        bad = blob[:8] + struct.pack(">I", 999) + blob[12:]
        # 重算校验和：证明“校验和正确”救不了未知版本
        digest = hashlib.sha256(bad[:32] + bad[64:]).digest()
        bad = bad[:32] + digest + bad[64:]
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_bad_magic_and_bad_checksum_rejected(self):
        blob = self._small_blob()
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(b"XXXXXXX0" + blob[8:])
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(manual_snapshot(
                1, 2, 0, [0, 0], [b"a"], [b"v"], bad_checksum=True))

    def test_truncation_and_trailing_bytes_rejected(self):
        blob = self._small_blob()
        for cut in (0, 1, 32, 63, 64, len(blob) - 1):
            with self.assertRaises(mphf.SnapshotError, msg=f"cut={cut}"):
                mphf.loads(blob[:cut])
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(blob + b"\x00")          # 尾部多余 1 字节
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(blob + b"trailing")

    def test_rechecksummed_wrong_slot_rejected(self):
        # 改动一个实际被边使用的 g 值并重算校验和：键不再落在自己的槽位。
        blob = self._small_blob()
        p = parse_snapshot(blob)
        n, m, seed = p["n"], p["m"], p["seed"]
        v = ref_h(seed, 0, p["keys"][0], m)     # key0 的 h0 顶点
        g = p["g"]
        g[v] = (g[v] + 1) % n
        rebuilt = manual_snapshot(
            n, m, seed, g, list(p["keys"]), list(p["values"]))
        # 校验和确实有效……
        self.assertEqual(
            rebuilt[32:64], hashlib.sha256(rebuilt[:32] + rebuilt[64:]).digest())
        # ……但槽位结构非法，必须拒绝（不是键序问题，是落槽校验）。
        with self.assertRaises(mphf.SnapshotError) as cm:
            mphf.loads(rebuilt)
        self.assertIn("slot", str(cm.exception))

    def test_rechecksummed_duplicate_key_rejected(self):
        # 手工构造长度自洽、校验和正确、但键重复的快照。
        # 取真实 [aa,bb] 的合法 g，K 段改成 [aa,aa]（等长，总长不变）。
        d = mphf.build_kv([(b"aa", b"1"), (b"bb", b"2")])
        p = parse_snapshot(mphf.dumps(d))
        dup = manual_snapshot(
            p["n"], p["m"], p["seed"], p["g"], [b"aa", b"aa"], [b"1", b"2"])
        self.assertEqual(
            dup[32:64], hashlib.sha256(dup[:32] + dup[64:]).digest())
        with self.assertRaises(mphf.SnapshotError) as cm:
            mphf.loads(dup)
        self.assertIn("duplicate", str(cm.exception))

    def test_rechecksummed_out_of_order_key_rejected(self):
        d = mphf.build_kv([(b"aa", b"1"), (b"bb", b"2")])
        p = parse_snapshot(mphf.dumps(d))
        bad = manual_snapshot(
            p["n"], p["m"], p["seed"], p["g"], [b"bb", b"aa"], [b"1", b"2"])
        with self.assertRaises(mphf.SnapshotError) as cm:
            mphf.loads(bad)
        self.assertIn("order", str(cm.exception))

    def test_rechecksummed_value_too_long_rejected(self):
        # n=2：声明 value_bytes=4097 不超 n*4096 总量上限，但单条 vlen=4097
        # 越过每条 4096 的上限；长度与校验和全部自洽。
        d = mphf.build_kv([(b"aa", b""), (b"bb", b"")])
        p = parse_snapshot(mphf.dumps(d))
        bad = manual_snapshot(
            p["n"], p["m"], p["seed"], p["g"], [b"aa", b"bb"],
            [b"x" * 4097, b""])
        self.assertEqual(
            bad[32:64], hashlib.sha256(bad[:32] + bad[64:]).digest())
        with self.assertRaises(mphf.SnapshotError) as cm:
            mphf.loads(bad)
        self.assertIn("4096", str(cm.exception))

    def test_rechecksummed_g_out_of_range_rejected(self):
        d = mphf.build_kv([(b"a", b""), (b"b", b"")])
        p = parse_snapshot(mphf.dumps(d))
        g = p["g"]
        g[0] = p["n"]  # g 值必须 < n
        bad = manual_snapshot(p["n"], p["m"], p["seed"], g,
                              list(p["keys"]), list(p["values"]))
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_rechecksummed_bad_m_field_rejected(self):
        # 头部声称的 m 与 ceil(1.4n) 不符（用真实 body、重算长度与校验和）。
        d = mphf.build_kv([(b"a", b""), (b"b", b""), (b"c", b"")])
        p = parse_snapshot(mphf.dumps(d))
        # n=3 时合法 m=5；伪造头部 m=6 并补 2 字节 g（值给 0），总长随之自洽。
        bad = manual_snapshot(p["n"], 6, p["seed"], p["g"] + [0],
                              list(p["keys"]), list(p["values"]))
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_rechecksummed_seed_out_of_range_rejected(self):
        d = mphf.build_kv([(b"a", b"")])
        p = parse_snapshot(mphf.dumps(d))
        bad = manual_snapshot(p["n"], p["m"], 300, p["g"],
                              list(p["keys"]), list(p["values"]))
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_rechecksummed_n_over_limit_rejected(self):
        bad = manual_snapshot(1001, 1402, 0, [0] * 1402,
                              [b""] * 1001, [b""] * 1001)
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_non_ascii_key_in_snapshot_rejected(self):
        d = mphf.build_kv([(b"aa", b"")])
        p = parse_snapshot(mphf.dumps(d))
        bad = manual_snapshot(p["n"], p["m"], p["seed"], p["g"],
                              [b"a\xff"], list(p["values"]))
        with self.assertRaises(mphf.SnapshotError):
            mphf.loads(bad)

    def test_snapshot_error_is_value_error(self):
        self.assertTrue(issubclass(mphf.SnapshotError, ValueError))
        with self.assertRaises(ValueError):
            mphf.loads(b"")

    def test_loads_type_error(self):
        for bad in (1, "str", None, True, [1, 2]):
            with self.assertRaises(TypeError):
                mphf.loads(bad)

    def test_random_single_bit_flips_always_rejected(self):
        # 随机翻转一个字节：要么校验和失败，要么（极端情况下）内部校验失败。
        import random
        blob = bytearray(self._small_blob())
        rng = random.Random(20260922)
        for _ in range(20):
            bad = bytearray(blob)
            pos = rng.randrange(len(bad))
            bad[pos] ^= 1 << rng.randrange(8)
            with self.assertRaises(mphf.SnapshotError):
                mphf.loads(bytes(bad))


class CollisionQueryTests(unittest.TestCase):
    def test_unknown_key_hash_collision_at_kv_layer(self):
        keys = [f"c-{i:02d}".encode() for i in range(10)]
        d = mphf.build_kv([(k, b"") for k in keys])  # 成员全部空值
        t = d.table
        occupied = {
            ref_slot(t.values, t.seed, k, t.size, t.vertex_count) for k in keys
        }
        collider = next(
            f"z-{x}".encode() for x in range(100000)
            if f"z-{x}".encode() not in keys
            and ref_slot(t.values, t.seed, f"z-{x}".encode(), t.size,
                        t.vertex_count) in occupied
        )
        # 槽位确实被占（且对应值为空），但未命中标志必须明确
        self.assertEqual(mphf.find(d, collider), (False, None))
        self.assertIsNone(d.get(collider))
        # 成员空值仍是 (True, b"")，不会与未命中混淆
        self.assertEqual(mphf.find(d, keys[0]), (True, b""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
