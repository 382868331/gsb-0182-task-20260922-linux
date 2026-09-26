"""前缀迭代的固定输入离线演示：真实计算，无 sleep、无预录结果。

运行：python demo_iteration.py（实测约 0.1 秒，远低于 90 秒预算）

展示：
1. 构造 1000 键字典，空前缀分页迭代（跨多页，游标续翻）；
2. 稀有前缀只访问候选范围：打印访问键数，对照全表大小；
3. 精确键同时也是别的键的前缀；含零字节的键按普通字节处理；
4. 空结果前缀；错误字典游标被拒绝（CursorError）；
5. 旧单键 lookup 照常工作。
"""

from __future__ import annotations

import time

import mphf


def hr(title: str) -> None:
    print(f"\n=== {title} " + "=" * (60 - len(title)))


def main() -> None:
    # ---------- 0. 构造：确定性生成 1000 条 ASCII 键 -----------------------
    hr("0. 构造 n=1000 字典（真实计算）")
    keys = [f"doc-{i:04d}".encode("ascii") for i in range(1000)]
    t0 = time.perf_counter()
    table = mphf.build(keys)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert table is not mphf.CONSTRUCTION_FAILED
    print(f"n={table.size}, seed={table.seed}, 构造耗时 {elapsed_ms:.1f} ms")
    print(f"字典指纹 fingerprint = {table.fingerprint[:32]}...（SHA256，与进程地址无关）")
    print(f"排序置换 order 长度={len(table.order)}，LCP 数组长度={len(table.lcp)}")

    # ---------- 1. 空前缀 + 跨多页迭代 -------------------------------------
    hr("1. 空前缀匹配全部，limit=250 跨 4 页")
    cursor = None
    seen = []
    page_no = 0
    while True:
        page = mphf.iter_prefix(table, b"", limit=250, cursor=cursor)
        page_no += 1
        seen.extend(page.keys)
        print(f"  第 {page_no} 页: {len(page.keys)} 键, "
              f"首={page.keys[0]!r}, 访问键数={page.accessed}, "
              f"游标={'...' + page.cursor[-8:] if page.cursor else None}")
        cursor = page.cursor
        if cursor is None:
            break
    assert seen == sorted(keys), "迭代结果必须等于排序后的原字典"
    print(f"  合计 {len(seen)} 键 == sorted(原字典) ✓（字典序，与哈希槽号无关）")

    # ---------- 2. 稀有前缀：访问键数远小于全表 -----------------------------
    hr("2. 稀有前缀不做全表扫描（访问键数对照）")
    for prefix in (b"doc-099", b"doc-9999", b"zzz"):
        page = mphf.iter_prefix(table, prefix)
        print(f"  prefix={prefix!r}: 匹配 {page.total} 键, "
              f"访问键数={page.accessed}（全表 n={table.size}）")
        assert page.accessed < 50

    # ---------- 3. 精确键也是别的键的前缀；零字节键 -------------------------
    hr("3. 精确键同为前缀 / 零字节键")
    tricky = mphf.build([b"ab", b"abc", b"abcd", b"a", b"ab\x00", b"ab\x00x"])
    for prefix in (b"ab", b"ab\x00"):
        page = mphf.iter_prefix(tricky, prefix)
        print(f"  prefix={prefix!r} -> {[k for k in page.keys]}")

    # ---------- 4. 空结果与错误字典游标 -------------------------------------
    hr("4. 空结果与游标绑定校验")
    empty = mphf.iter_prefix(table, b"nope-")
    print(f"  空前缀结果: keys={empty.keys}, total={empty.total}, "
          f"cursor={empty.cursor}, 访问键数={empty.accessed}")
    foreign = mphf.iter_prefix(table, limit=10).cursor
    other = mphf.build([f"other-{i}".encode() for i in range(50)])
    try:
        mphf.iter_prefix(other, limit=10, cursor=foreign)
    except mphf.CursorError as exc:
        print(f"  拿本表游标翻另一字典 -> CursorError: {exc}")

    # ---------- 5. 旧单键查询回归 -------------------------------------------
    hr("5. 旧单键 lookup 照常")
    for q in (b"doc-0000", b"doc-0500", b"absent"):
        print(f"  lookup({q!r}) -> {mphf.lookup(table, q)}")

    print("\n演示完成：以上均为当场真实计算。")


if __name__ == "__main__":
    main()
