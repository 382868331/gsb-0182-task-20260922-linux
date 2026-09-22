"""mphf 的必要测试。

独立性说明：
  本文件不调用 mphf 的内部函数来取得“期望值”。验证哈希契约时，测试用
  hashlib 自行按题面公式 SHA256(seed_be4 ‖ tag ‖ key) 独立计算顶点；
  验证双射时，期望槽位就是键在输入序列中的序号（构造契约直接规定）。
  “往返一致”（build 后 lookup 命中）仅作为补充断言。
"""

import hashlib
import math
import unittest

import mphf
from mphf import (
    build,
    lookup,
    ConstructionFailed,
    DuplicateKeyError,
    InvalidKeyError,
    InvalidParameterError,
    KeyLimitExceeded,
    NOT_FOUND,
    MAX_KEYS,
)


# ---------------------------------------------------------------------------
# 独立参照实现（仅使用 hashlib，不调用 mphf 内部）
# ---------------------------------------------------------------------------
def ref_vertices(key: bytes, seed: int, m: int) -> tuple[int, int, int]:
    seed_bytes = seed.to_bytes(4, "big")
    out = []
    for tag in (0, 1, 2):
        digest = hashlib.sha256(seed_bytes + bytes([tag]) + key).digest()
        out.append(int.from_bytes(digest, "big") % m)
    return out[0], out[1], out[2]


def ref_peelable(edges, m: int) -> bool:
    """独立的度-1 剥离判定（度按关联次数计）。"""
    multi = [[] for _ in range(m)]
    degree = [0] * m
    for eid, (a, b, c) in enumerate(edges):
        for v in (a, b, c):
            multi[v].append(eid)
            degree[v] += 1
    removed = set()
    queue = [v for v, d in enumerate(degree) if d == 1]
    while queue:
        v = queue.pop()
        if degree[v] != 1:
            continue
        live = [e for e in multi[v] if e not in removed]
        if len(live) != 1:
            continue
        e = live[0]
        removed.add(e)
        for w in edges[e]:
            degree[w] -= 1
            if degree[w] == 1:
                queue.append(w)
    return len(removed) == len(edges)


def candidate_key(i: int) -> bytes:
    return b"k" + str(i).encode("ascii") + b"!"


def find_seed0_colliding_pair():
    """找一对不同键：seed=0 时三条哈希边完全相同、seed=1 可剥离（独立计算）。

    n=2, m=3。确定性穷举，直到同时满足两个条件，用于精确演示
    “seed 0 失败 → seed 递增 → seed 1 成功”。
    """
    m = mphf._vertex_count(2)  # 仅取公开常量公式的结果做测试编排，不作期望值
    base = candidate_key(0)
    i = 1
    while True:
        other = candidate_key(i)
        if ref_vertices(other, 0, m) == ref_vertices(base, 0, m):
            t1a = ref_vertices(base, 1, m)
            t1b = ref_vertices(other, 1, m)
            if t1a != t1b and ref_peelable([t1a, t1b], m):
                return base, other, ref_vertices(base, 0, m)
        i += 1
        if i > 100000:
            raise AssertionError("deterministic search failed")


def find_all_equal_triple_key():
    """n=1,m=2：找 seed=0 时三个顶点全相同的键（独立计算）。

    单边 (v,v,v) 度为 3，无度-1 顶点，seed 0 必然不可剥离——用于同时
    校验哈希公式与剥离行为。
    """
    m = mphf._vertex_count(1)
    i = 0
    while True:
        key = b"z" + str(i).encode("ascii")
        a, b, c = ref_vertices(key, 0, m)
        if a == b == c:
            return key
        i += 1
        if i > 100000:
            raise AssertionError("deterministic search failed")


class TestVertexCount(unittest.TestCase):
    def test_exact_ceil_ratio(self):
        # m = ceil(7n/5)，纯整数期望值手算
        cases = {0: 0, 1: 2, 2: 3, 3: 5, 4: 6, 5: 7, 10: 14, 7: 10, 1000: 1400}
        for n, expected in cases.items():
            self.assertEqual(mphf._vertex_count(n), expected)
        # 与 math.ceil(1.4*n) 在范围内一致（仅用于交叉核对整数公式）
        for n in range(0, MAX_KEYS + 1):
            self.assertEqual(mphf._vertex_count(n), math.ceil(1.4 * n))


class TestEmpty(unittest.TestCase):
    def test_empty_table(self):
        t = build([])
        self.assertEqual(t.n, 0)
        self.assertEqual(t.m, 0)
        self.assertEqual(t.seed, 0)
        self.assertEqual(t.g, ())
        self.assertEqual(t.keys, ())
        self.assertIs(lookup(t, b"anything"), NOT_FOUND)
        self.assertIs(lookup(t, b""), NOT_FOUND)
        self.assertIs(t.lookup(b"x"), NOT_FOUND)
        # 空表也可以指定 first_seed
        t2 = build([], first_seed=42)
        self.assertEqual(t2.seed, 42)
        self.assertIs(lookup(t2, b"a"), NOT_FOUND)


class TestBijectionSmall(unittest.TestCase):
    """枚举小键集验证完美双射 + 槽位等于输入序号。"""

    def setUp(self):
        self.base = [bytes([ord("a") + i]) for i in range(12)]  # a..l

    def test_all_subsets_of_twelve_keys(self):
        base = self.base
        tried = 0
        for mask in range(1, 1 << len(base)):
            keys = [base[i] for i in range(len(base)) if mask & (1 << i)]
            t = build(keys)
            slots = []
            for index, key in enumerate(keys):
                slot = lookup(t, key)
                # 契约：边 id 即键序号
                self.assertEqual(slot, index)
                slots.append(slot)
            # 完美双射：槽位恰好覆盖 0..n-1
            self.assertEqual(sorted(slots), list(range(len(keys))))
            self.assertEqual(len(set(slots)), len(keys))
            # 表结构公开字段
            self.assertEqual(len(t.g), t.m)
            self.assertEqual(t.keys, tuple(keys))
            self.assertTrue(all(0 <= x < t.n for x in t.g))
            tried += 1
        self.assertEqual(tried, (1 << 12) - 1)

    def test_determined_mixed_keysets(self):
        sets = [
            [b"", b"0"],                       # 含空字节串
            [b"alpha", b"beta", b"gamma"],
            [b"x%03d" % i for i in range(20)],
            [b"id-%d" % i for i in range(50)],
        ]
        for keys in sets:
            t = build(keys)
            seen = set()
            for i, key in enumerate(keys):
                self.assertEqual(lookup(t, key), i)
                seen.add(lookup(t, key))
            self.assertEqual(seen, set(range(len(keys))))


class TestBoundary1000(unittest.TestCase):
    def test_max_size_bijection(self):
        keys = [("key-%08d" % i).encode("ascii") for i in range(MAX_KEYS)]
        t = build(keys)
        self.assertEqual(t.n, MAX_KEYS)
        self.assertEqual(t.m, 1400)
        used = set()
        for i, key in enumerate(keys):
            slot = lookup(t, key)
            self.assertEqual(slot, i)  # 槽位即输入序号
            used.add(slot)
        self.assertEqual(used, set(range(MAX_KEYS)))

    def test_too_many(self):
        keys = [b"k%d" % i for i in range(MAX_KEYS + 1)]
        with self.assertRaises(KeyLimitExceeded):
            build(keys)


class TestDuplicates(unittest.TestCase):
    def test_duplicate_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            build([b"a", b"b", b"a"])
        with self.assertRaises(DuplicateKeyError):
            build([b"x", b"x"])

    def test_duplicate_is_proof_not_budget(self):
        # 重复键即使放宽 seed 预算也立即拒绝，不进行任何尝试。
        try:
            build([b"a", b"a"], max_seeds=256)
        except DuplicateKeyError:
            pass
        else:
            self.fail("expected DuplicateKeyError")


class TestForcedNonPeelableAndRetries(unittest.TestCase):
    """主动制造不可剥离图并测重试上限（真实哈希搜索，非预录）。"""

    def test_seed0_unpeelable_budget_one(self):
        k1, k2, triple = find_seed0_colliding_pair()
        # 独立参照确认 seed 0 下两条边完全相同 → 2-核，不可剥离
        self.assertEqual(ref_vertices(k1, 0, 3), triple)
        self.assertEqual(ref_vertices(k2, 0, 3), triple)
        self.assertFalse(ref_peelable([triple, triple], 3))
        with self.assertRaises(ConstructionFailed) as ctx:
            build([k1, k2], first_seed=0, max_seeds=1)
        err = ctx.exception
        self.assertEqual(err.seeds_tried, 1)
        self.assertEqual(err.first_seed, 0)
        self.assertEqual(err.max_seeds, 1)
        self.assertEqual(err.status, "construction_failed")

    def test_retry_then_success(self):
        k1, k2, _ = find_seed0_colliding_pair()
        # seed 0 失败、seed 1 成功（搜索条件已保证）：构造自动递增重试一次
        t = build([k1, k2], first_seed=0, max_seeds=2)
        self.assertEqual(t.seed, 1)
        self.assertEqual(lookup(t, k1), 0)
        self.assertEqual(lookup(t, k2), 1)

    def test_all_equal_single_edge_unpeelable(self):
        # 单边 (v,v,v)：度 3 无度-1 顶点；独立哈希先定位键，再要求构造失败。
        key = find_all_equal_triple_key()
        a, b, c = ref_vertices(key, 0, 2)
        self.assertEqual((a, b, c), (a, a, a))
        with self.assertRaises(ConstructionFailed) as ctx:
            build([key], first_seed=0, max_seeds=1)
        self.assertEqual(ctx.exception.seeds_tried, 1)

    def test_budget_exhausted_does_not_return_partial(self):
        k1, k2, _ = find_seed0_colliding_pair()
        result = object()
        try:
            result = build([k1, k2], first_seed=0, max_seeds=1)
        except ConstructionFailed:
            pass
        self.assertNotIsInstance(result, mphf.MinimalPerfectHash)


class TestHashContract(unittest.TestCase):
    """哈希方案必须精确为 SHA256(seed_be4 ‖ tag ‖ key) % m。"""

    def test_independent_hash_formula_drives_behavior(self):
        # 选一个在 seed 0 下三边顶点为 (0,1,2) 的 2 键集合的构造行为，
        # 这里用“独立预言 seed 0 可剥离”来预言 build(max_seeds=1) 成功。
        m = mphf._vertex_count(2)
        i = 0
        while True:
            k1 = b"h" + str(i).encode()
            k2 = b"h" + str(i + 1000000).encode()
            e1 = ref_vertices(k1, 0, m)
            e2 = ref_vertices(k2, 0, m)
            if e1 != e2 and ref_peelable([e1, e2], m):
                break
            i += 1
            self.assertLess(i, 100000)
        t = build([k1, k2], first_seed=0, max_seeds=1)
        self.assertEqual(t.seed, 0)
        self.assertEqual(lookup(t, k1), 0)
        self.assertEqual(lookup(t, k2), 1)


class TestNonMemberAndNonAscii(unittest.TestCase):
    def setUp(self):
        self.keys = [b"apple", b"banana", b"cherry", b"date", b"elderberry"]
        self.t = build(self.keys)

    def test_non_member(self):
        for q in [b"APPLE", b"apple ", b"appl", b"fig", b""]:
            if q in self.keys:
                continue
            self.assertIs(lookup(self.t, q), NOT_FOUND)

    def test_non_ascii_build_rejected(self):
        with self.assertRaises(InvalidKeyError):
            build([b"ok", "中文".encode("utf-8")])
        with self.assertRaises(InvalidKeyError):
            build([bytes([0x80])])
        with self.assertRaises(InvalidKeyError):
            build([b"a", bytes([0xFF])])

    def test_non_ascii_lookup_not_found(self):
        # 非 ASCII 查询不可能是成员：走哈希后由完整键比较否决。
        for q in ["香蕉".encode("utf-8"), bytes([0x80]), bytes([0xFF])]:
            self.assertIs(lookup(self.t, q), NOT_FOUND)

    def test_engineered_hash_collision_rejected_by_full_key(self):
        """构造一个槽位哈希碰撞的非成员，验证不能按槽位判命中。"""
        t = self.t
        # 独立计算候选键的槽位，找到与某成员同槽但不相等的非成员。
        member_slots = {lookup(t, k): k for k in self.keys}
        collider = None
        for i in range(2_000_000):
            cand = b"q%d" % i
            v0, v1, v2 = ref_vertices(cand, t.seed, t.m)
            slot = (t.g[v0] + t.g[v1] + t.g[v2]) % t.n
            if slot in member_slots and cand != member_slots[slot]:
                collider = cand
                break
        self.assertIsNotNone(collider, "应能确定性地找到碰撞非成员")
        self.assertNotIn(collider, self.keys)
        # 补充：裸槽位确实碰撞
        v0, v1, v2 = ref_vertices(collider, t.seed, t.m)
        slot = (t.g[v0] + t.g[v1] + t.g[v2]) % t.n
        self.assertIn(slot, member_slots)
        # 核心验收：完整键确认后必须判 not_found
        self.assertIs(lookup(t, collider), NOT_FOUND)


class TestInputValidation(unittest.TestCase):
    def test_key_types(self):
        with self.assertRaises(InvalidKeyError):
            build("abc")                      # 单个 str 而非集合
        with self.assertRaises(InvalidKeyError):
            build(b"abc")                     # 单个 bytes 而非集合
        with self.assertRaises(InvalidKeyError):
            build([b"a", 1])                  # 非 bytes 元素
        with self.assertRaises(InvalidKeyError):
            build([b"a", None])
        with self.assertRaises(InvalidKeyError):
            build([b"a", True])               # bool 不得冒充字节串
        with self.assertRaises(InvalidKeyError):
            build(123)                        # 不可迭代
        with self.assertRaises(InvalidKeyError):
            lookup(build([b"a"]), "a")        # lookup 键类型
        with self.assertRaises(InvalidKeyError):
            lookup(build([b"a"]), 0)
        # bytearray 可用于 lookup（等价字节）
        t = build([b"abc"])
        self.assertEqual(lookup(t, bytearray(b"abc")), 0)

    def test_integer_params_reject_bool(self):
        keys = [b"a", b"b"]
        with self.assertRaises(InvalidParameterError):
            build(keys, first_seed=True)
        with self.assertRaises(InvalidParameterError):
            build(keys, max_seeds=False)

    def test_numeric_params_reject_nan_inf_float(self):
        keys = [b"a", b"b"]
        for bad in (float("nan"), float("inf"), float("-inf"), 1.5, 0.0):
            with self.assertRaises(InvalidParameterError):
                build(keys, first_seed=bad)
            with self.assertRaises(InvalidParameterError):
                build(keys, max_seeds=bad)

    def test_param_ranges(self):
        keys = [b"a", b"b"]
        with self.assertRaises(InvalidParameterError):
            build(keys, first_seed=-1)
        with self.assertRaises(InvalidParameterError):
            build(keys, first_seed=2**32)
        with self.assertRaises(InvalidParameterError):
            build(keys, max_seeds=0)
        with self.assertRaises(InvalidParameterError):
            build(keys, max_seeds=257)
        with self.assertRaises(InvalidParameterError):
            build(keys, first_seed=2**32 - 1, max_seeds=2)
        # 边界合法值：空集合可接受任意合法 seed
        self.assertEqual(build([], first_seed=2**32 - 1).seed, 2**32 - 1)
        # max_seeds=1：用独立参照找一对 seed 0 确实可剥离的键，
        # 然后断言一次尝试即成功（而不是放宽预算掩盖问题）。
        m = mphf._vertex_count(2)
        i = 0
        while True:
            pair = [b"p%d" % i, b"p%d" % (i + 500000)]
            if ref_peelable([ref_vertices(pair[0], 0, m),
                             ref_vertices(pair[1], 0, m)], m):
                break
            i += 1
        t = build(pair, first_seed=0, max_seeds=1)
        self.assertEqual(t.seed, 0)
        self.assertEqual(lookup(t, pair[0]), 0)
        self.assertEqual(lookup(t, pair[1]), 1)

    def test_bytearray_keys_accepted_on_build(self):
        t = build([bytearray(b"a"), bytearray(b"b")])
        self.assertEqual(lookup(t, b"a"), 0)
        self.assertEqual(lookup(t, b"b"), 1)
        self.assertEqual(type(t.keys[0]), bytes)


class TestImmutability(unittest.TestCase):
    def test_public_fields_frozen(self):
        t = build([b"a", b"b", b"c"])
        with self.assertRaises(AttributeError):
            t.seed = 99
        self.assertIsInstance(t.g, tuple)
        self.assertIsInstance(t.keys, tuple)


if __name__ == "__main__":
    unittest.main(verbosity=2)
