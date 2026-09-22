"""固定输入演示：真实构造一个最小完美哈希，并真实触发一次构造失败边界。

运行：python demo.py（约 1 秒内，纯离线、纯标准库、无 sleep、无预录结果）。
"""

import time

import mphf
from mphf import build, lookup, NOT_FOUND, ConstructionFailed, DuplicateKeyError


def main() -> None:
    started = time.perf_counter()

    # ------------------------------------------------------------------
    # 1) 正常结果：固定的确定性键集（仓库内代码生成，无外部数据）
    # ------------------------------------------------------------------
    print("=" * 68)
    print("正常构造：ASCII 字节串静态集合 -> 最小访问完美哈希")
    print("=" * 68)
    keys = [("term-%03d" % i).encode("ascii") for i in range(40)] + [
        b"alpha", b"beta", b"gamma", b"", b"index-key!"]
    table = build(keys)
    print(f"键数 n = {table.n}，超图顶点 m = ceil(1.4n) = {table.m}，"
          f"成功 seed = {table.seed}")
    print(f"g 表长度 = {len(table.g)}，每值范围 [0, {table.n - 1}]")
    print("索引（槽位序号即键的输入序号，0..n-1，双射）：")
    for key in [b"alpha", b"term-000", b"term-039", b"", b"index-key!"]:
        print(f"  lookup({key!r:14}) = {lookup(table, key)}")

    non_members = [b"ALPHA", b"term-040", b"term-000 ", "随机非成员".encode("utf-8")]
    print("非成员确认（完整键比较，绝不按哈希槽位判命中）：")
    for key in non_members:
        result = lookup(table, key)
        shown = "not_found" if result is NOT_FOUND else result
        print(f"  lookup({key!r:14}) = {shown}")

    # 空集合边界
    empty = build([])
    assert lookup(empty, b"x") is NOT_FOUND
    print(f"空集合：n={empty.n}, m={empty.m}, g={empty.g}, lookup(b'x') = not_found")

    # ------------------------------------------------------------------
    # 2) 实际触发的异常边界：重复键 = 可证明无解（立即拒绝，不消耗 seed）
    # ------------------------------------------------------------------
    print()
    print("=" * 68)
    print("边界一：重复键（可证明无解，立即拒绝）")
    print("=" * 68)
    try:
        build([b"a", b"b", b"a"])
    except DuplicateKeyError as exc:
        print(f"捕获 {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------
    # 3) 实际触发的异常边界：搜索预算耗尽 -> construction_failed
    #    用独立的 SHA256 计算确定性地找出 seed=0 下边完全相同的两个键，
    #    此时超图存在 2-核、不可剥离；max_seeds=1 令预算只有 1 次。
    # ------------------------------------------------------------------
    print()
    print("=" * 68)
    print("边界二：不可剥离超图 + 重试上限（construction_failed）")
    print("=" * 68)
    import hashlib

    n, m = 2, mphf._vertex_count(2)

    def vertices(key: bytes, seed: int) -> tuple[int, int, int]:
        sb = seed.to_bytes(4, "big")
        return tuple(
            int.from_bytes(hashlib.sha256(sb + bytes([tag]) + key).digest(),
                           "big") % m
            for tag in (0, 1, 2)
        )

    first = b"demo-0"
    partner = None
    for i in range(1, 100_000):
        candidate = b"demo-%d" % i
        if vertices(candidate, 0) == vertices(first, 0):
            partner = candidate
            break
    assert partner is not None, "确定性搜索应找到碰撞对"
    print(f"确定性找到 seed=0 下三边完全相同的两个不同键："
          f"{first!r} 与 {partner!r}")
    print(f"两键在 seed=0 的三个顶点均为 {vertices(first, 0)}，"
          f"超图无法完全剥离")

    try:
        build([first, partner], first_seed=0, max_seeds=1)
    except ConstructionFailed as exc:
        print(f"捕获 {type(exc).__name__}: status={exc.status}, "
              f"seeds_tried={exc.seeds_tried}, "
              f"first_seed={exc.first_seed}, max_seeds={exc.max_seeds}")

    # 放宽预算到 2：seed 递增重试，通常下一个 seed 即可剥离并成功
    table2 = build([first, partner], first_seed=0, max_seeds=256)
    print(f"放宽预算后成功：seed={table2.seed}，"
          f"lookup -> ({lookup(table2, first)}, {lookup(table2, partner)})")

    elapsed = time.perf_counter() - started
    print()
    print(f"演示完成，实际耗时 {elapsed:.3f} 秒（无 sleep、无预录结果）。")


if __name__ == "__main__":
    main()
