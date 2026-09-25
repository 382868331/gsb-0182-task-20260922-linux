"""固定输入的离线演示：真实计算，无 sleep、无预录结果。

运行：./.venv/bin/python demo.py（约 0.2 秒，远低于 90 秒预算）

展示：
1. 正常构造与索引（含 n=1000 接口边界、非成员、哈希碰撞非成员）；
2. seed 重试：真实不可剥离集合 {a,b,i} 在 seed=0 失败、seed=2 成功；
3. 重试上限被实际触发：把预算压为 1，公开 build() 返回 construction_failed；
4. 非法输入实际抛出异常（重复键、非 ASCII、超上限、类型错误）；
5. 索引认证：版本清单、成员证明与不存在证明的离线验证及篡改拒绝。
"""

from __future__ import annotations

import time
from unittest.mock import patch

import mphf


def hr(title: str) -> None:
    print(f"\n=== {title} " + "=" * (60 - len(title)))


def main() -> None:
    # ---------- 1. 正常结果：确定性生成 1000 条 ASCII 键（接口上限规模）----
    hr("1. 正常构造 n=1000（题面接口边界）")
    keys = [f"doc-{i:04d}".encode("ascii") for i in range(1000)]

    t0 = time.perf_counter()
    table = mphf.build(keys)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert table is not mphf.CONSTRUCTION_FAILED

    print(f"size n={table.size}, vertices m={table.vertex_count} "
          f"(= ceil(1.4n)), seed={table.seed}, 尝试 seed 数={table.attempts}")
    print(f"真实构造耗时 {elapsed_ms:.1f} ms（无 sleep、无预录）")

    for i in (0, 1, 2, 998, 999):
        got = mphf.lookup(table, keys[i])
        assert got == i
        print(f"  lookup({keys[i]!r}) -> 序号 {got}")

    # 非成员：即使槽位被成员占满，完整键不等仍拒绝
    for q in (b"doc-0000 ", b"doc-1000", b"DOC-0000", b""):
        print(f"  lookup({q!r}) -> {mphf.lookup(table, q)} （非成员 = -1）")

    # 完美哈希下槽位 0..n-1 全被成员占用；非成员经哈希必然落到某个已占用
    # 槽位，但完整键不等必须拒绝——“不以哈希值存在判命中”。
    n = table.size

    def slot(key: bytes) -> int:
        g = table.values
        return (
            g[mphf._hash_vertex(table.seed, 0, key, table.vertex_count)]
            + g[mphf._hash_vertex(table.seed, 1, key, table.vertex_count)]
            + g[mphf._hash_vertex(table.seed, 2, key, table.vertex_count)]
        ) % n

    collider = b"zzz-not-a-member"
    print(f"  非成员 {collider!r} 的哈希落到已占用槽位 {slot(collider)}，"
          f"lookup 仍返回 {mphf.lookup(table, collider)}（完整键终检）")

    # ---------- 2. 确定性重试：真实的 seed=0 不可剥离集合 ------------------
    hr("2. 超图不可剥离 → seed 递增重试")
    tricky = [b"a", b"b", b"i"]
    t2 = mphf.build(tricky)
    print(f"键集 {tricky}：seed=0 超图无度 1 顶点（2-核非空，不可剥离）")
    print(f"  实际结果：seed={t2.seed} 成功，attempts={t2.attempts}，"
          f"索引 = {{ {', '.join(f'{k.decode()!r}: {mphf.lookup(t2, k)}' for k in tricky)} }}")

    # ---------- 3. 实际触发重试上限：construction_failed -------------------
    hr("3. 重试预算耗尽（上限被真实触发）")
    with patch.object(mphf, "MAX_SEED_ATTEMPTS", 1):
        failed = mphf.build(tricky)  # 唯一允许的 seed=0 确实不可剥离
    print(f"  预算=1 时 build(...) is CONSTRUCTION_FAILED: "
          f"{failed is mphf.CONSTRUCTION_FAILED}（{failed!r}，attempts 语义={failed.attempts}）")
    print("  含义：本契约的 256-seed 搜索预算耗尽；不是'数学上无解'的证明。")
    try:
        mphf.lookup(failed, b"a")
    except ValueError as exc:
        print(f"  对失败哨兵 lookup 抛出 ValueError: {exc}")

    # ---------- 4. 实际触发的拒绝/异常边界 ---------------------------------
    hr("4. 非法输入拒绝（可定位错误，不静默纠正）")

    def show_failure(label, fn):
        try:
            fn()
        except Exception as exc:
            print(f"  {label}: {type(exc).__name__}: {exc}")

    show_failure("重复键 [b'a', b'b', b'a']", lambda: mphf.build([b"a", b"b", b"a"]))
    show_failure("非 ASCII 键", lambda: mphf.build([b"ok", b"bad\xff"]))
    show_failure("1001 条超上限",
                 lambda: mphf.build([f"k{i:04d}".encode() for i in range(1001)]))
    show_failure("键类型为 str/int/bool", lambda: mphf.build([b"ok", "nope"]))
    show_failure("把单个 bytes 当集合", lambda: mphf.build(b"abc"))
    show_failure("lookup 键类型为 int", lambda: mphf.lookup(mphf.build([b"a"]), 123))
    print(f"  空表 lookup(b'\\x80') -> {mphf.lookup(mphf.build([]), b'\x80')}"
          "（非 ASCII 查询按非成员返回 -1，非异常）")

    # ---------- 5. 索引认证：成员证明与不存在证明（离线验证）--------------
    hr("5. 索引认证：Merkle 成员/不存在证明")
    auth = mphf.build_authenticated(table)
    man = auth.manifest
    print(f"  版本清单: version={man.version}, size={man.size}")
    print(f"  槽位树根: {man.slot_root.hex()[:32]}...")
    print(f"  键序树根: {man.sorted_root.hex()[:32]}...")
    print(f"  清单承诺 digest: {man.digest().hex()[:32]}...")

    member = b"doc-0500"
    proof = auth.prove(member)
    print(f"  prove({member!r}) -> 槽号 {proof.slot}，兄弟路径 {len(proof.path)} 步")
    ok = mphf.verify_membership(man.slot_root, man.size, member, proof)
    print(f"  离线验证成员证明: {ok}")
    tampered = mphf.verify_membership(man.slot_root, man.size, b"doc-0501", proof)
    print(f"  换键后验证（应 False）: {tampered}")
    print(f"  非成员 prove(b'nope') -> {auth.prove(b'nope')}")

    absent = b"doc-0500x"
    ap = auth.prove_absence(absent)
    print(f"  prove_absence({absent!r}) -> 前驱 {ap.predecessor.key!r}"
          f"(秩 {ap.predecessor.rank}) / 后继 {ap.successor.key!r}"
          f"(秩 {ap.successor.rank})")
    ok2 = mphf.verify_absence(man.sorted_root, man.size, absent, ap)
    print(f"  离线验证不存在证明: {ok2}")
    # 非相邻秩伪造：两个真实存在键、秩不相邻，不能证明不存在
    forged = mphf.AbsenceProof(
        predecessor=mphf.SortedProof(ap.predecessor.rank - 1 if ap.predecessor.rank else 0,
                                     ap.predecessor.key, ap.predecessor.slot,
                                     ap.predecessor.path),
        successor=ap.successor,
    ) if ap.predecessor.rank else None
    if forged is not None:
        print(f"  非相邻秩伪造验证（应 False）: "
              f"{mphf.verify_absence(man.sorted_root, man.size, absent, forged)}")

    empty_man = mphf.build_authenticated(mphf.build([])).manifest
    print(f"  空集合: 两树根均为 EMPTY_ROOT: "
          f"{empty_man.slot_root == empty_man.sorted_root == mphf.EMPTY_ROOT}")

    print("\n演示完成：以上均为当场真实计算。")


if __name__ == "__main__":
    main()
