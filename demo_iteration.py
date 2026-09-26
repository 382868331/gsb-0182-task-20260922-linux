"""前缀迭代真实离线演示（固定确定性输入，当场计算，无 sleep/预录/网络）。

运行：python demo_iteration.py

演示内容：
1. 构造含 1000 个键的静态字典；
2. 空前缀跨多页迭代，游标跨“进程”解码后继续；
3. 稀有前缀只访问候选范围（打印访问键数，对比全表）；
4. 精确键同时也是别的键前缀、零字节键、空结果、错误字典游标的拒绝；
5. 旧单键查询照常工作。
"""

import random

import mphf

N = 1000
PAGE = 7


def main() -> None:
    rng = random.Random(20260926)
    keys = set()
    while len(keys) < N - 5:
        keys.add(bytes(rng.randrange(97, 123) for _ in range(rng.randrange(1, 10))))
    keys.update([b"ab", b"abc", b"abcd", b"a\x00b", b""])
    keys = list(keys)

    table = mphf.build(keys)
    assert isinstance(table, mphf.MPHFTable), "构造失败"
    reference = sorted(keys)
    print(f"构造完成：n={table.size}，seed={table.seed}，attempts={table.attempts}")
    print(f"字典指纹（SHA256，hex 前 16 字节）：{table.fingerprint[:16].hex()}")

    # 1) 空前缀跨多页，输出页大小与游标；中途“序列化”游标模拟跨进程。
    cursor = None
    pages = 0
    collected = []
    while True:
        page = mphf.iter_prefix(table, b"", limit=PAGE, cursor=cursor)
        collected.extend(page.keys)
        pages += 1
        if pages <= 2 or page.done:
            tail = page.keys[-1] if page.keys else b""
            cur = page.next_cursor.hex() if page.next_cursor else None
            print(f"  第{pages}页: {len(page.keys)} 键，末尾={tail!r}, "
                  f"accessed={page.accessed}, next_cursor={cur}")
        if page.done:
            break
        cursor = page.next_cursor
    print(f"空前缀：共 {pages} 页，拼接 {len(collected)} 键，"
          f"与 sorted(原字典) 一致: {collected == reference}")

    # 2) 稀有前缀：访问键数与 n 无关量级，证明没有全表扫描。
    rare = b"abcd"
    page = mphf.iter_prefix(table, rare)
    print(f"稀有前缀 {rare!r}: 命中 {list(page.keys)}，本次只读取 {page.accessed} 个键 "
          f"（全表 {table.size} 个键）")

    # 3) 精确键同时也是别的键的前缀。
    page = mphf.iter_prefix(table, b"ab")
    print(f"前缀 b'ab'（自身也是键）: {list(page.keys)}")

    # 4) 零字节键按普通字节处理；空结果页。
    print(f"前缀 b'a\\x00': {list(mphf.iter_prefix(table, b'a\x00').keys)}")
    empty = mphf.iter_prefix(table, b"\x01nonexistent")
    print(f"空结果: keys={empty.keys}, done={empty.done}, accessed={empty.accessed}")

    # 5) 错误字典游标被拒绝（指纹绑定）。
    other = mphf.build([b"alpha", b"beta", b"gamma"])
    foreign = mphf.iter_prefix(other, b"", limit=1).next_cursor
    try:
        mphf.iter_prefix(table, cursor=foreign)
    except mphf.CursorError as exc:
        print(f"错误字典游标被拒绝: {exc}")

    # 6) 游标跨进程：游标是稳定字节编码，重新 build 后仍可继续。
    saved_cursor = mphf.iter_prefix(table, b"ab", limit=1).next_cursor
    rebuilt = mphf.build(keys)
    rest = mphf.iter_prefix(rebuilt, cursor=saved_cursor)
    print(f"跨进程继续（b'ab' 跳过首个命中）: {list(rest.keys)}")

    # 7) 旧单键查询能力保留。
    print(f"lookup(b'abc')={table.lookup(b'abc')}（槽号，非排序位置）； "
          f"lookup(b'absent')={table.lookup(b'absent')}（NOT_FOUND）")


if __name__ == "__main__":
    main()
