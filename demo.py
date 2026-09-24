"""固定输入的离线演示：真实计算，无 sleep、无预录结果。

运行：python demo.py（约 0.1 秒，远低于 8 秒预算）

展示：
1. 正常构造与索引（含 n=1000 接口边界、非成员、哈希碰撞非成员）；
2. seed 重试：真实不可剥离集合 {a,b,i} 在 seed=0 失败、seed=2 成功；
3. 重试上限被实际触发：把预算压为 1，公开 build() 返回 construction_failed；
4. 非法输入实际抛出异常（重复键、非 ASCII、超上限、类型错误）；
5. 增删差量与墓碑：删后重加、未知键、显式合并生成新快照、
   合并前后一致且旧快照仍可查询。
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

    # ---------- 5. 增删差量、墓碑与显式合并 --------------------------------
    hr("5. 不可变快照 + 增删差量（墓碑）与显式合并")
    snap = mphf.build([b"alpha", b"beta", b"gamma", b"delta"])
    idx = mphf.MutableIndex(snap)
    print(f"基层快照 size={snap.size}；索引 size={idx.size}, pending={idx.pending}")

    idx.delete(b"beta")                      # 基层成员 → 墓碑
    s1 = idx.insert(b"epsilon")              # 差量新增
    s2 = idx.insert(b"zeta")
    print(f"delete(b'beta') 后 lookup -> {idx.lookup(b'beta')}（墓碑判非成员）")
    print(f"insert(b'epsilon') -> 序号 {s1}; insert(b'zeta') -> 序号 {s2}"
          f"（从 n={snap.size} 起单调分配）")
    r = idx.insert(b"beta")                  # 删后重加：撤销墓碑
    print(f"删后重加 insert(b'beta') -> 序号 {r}（恢复基层原序号）")
    print(f"未知键 lookup(b'omega') -> {idx.lookup(b'omega')}")
    print(f"当前 size={idx.size}, pending={idx.pending}")
    # 旧快照不受差量影响，仍可查询
    print(f"旧快照 lookup(b'beta') -> {mphf.lookup(snap, b'beta')}（基层原样）")

    merged = idx.merge()                     # 显式合并 → 新快照
    print(f"merge() -> 新快照 size={merged.size}, seed={merged.seed}, "
          f"keys={[k.decode() for k in merged.keys]}")
    for q in (b"alpha", b"beta", b"epsilon", b"zeta", b"omega"):
        print(f"  合并后 lookup({q!r}) -> {mphf.lookup(merged, q)}")
    print(f"合并后旧索引 lookup(b'epsilon') -> {idx.lookup(b'epsilon')}"
          "（旧索引/旧快照仍可查询）")

    show_failure("重复插入 insert(b'alpha')", lambda: idx.insert(b"alpha"))
    show_failure("删除未知键 delete(b'omega')", lambda: idx.delete(b"omega"))
    show_failure("重复删除 delete 后墓碑再删",
                 lambda: (idx.delete(b"gamma"), idx.delete(b"gamma")))
    show_failure("插入非 ASCII 键", lambda: idx.insert(b"bad\xff"))
    show_failure("插入 bool 键", lambda: idx.insert(True))
    show_failure("在失败哨兵上建索引",
                 lambda: mphf.MutableIndex(mphf.CONSTRUCTION_FAILED))

    print("\n演示完成：以上均为当场真实计算。")


if __name__ == "__main__":
    main()
