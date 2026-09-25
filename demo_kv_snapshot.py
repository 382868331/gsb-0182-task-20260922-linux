"""键值只读快照演示：一个进程保存，另一个进程重新加载查询。

运行：./.venv/bin/python demo_kv_snapshot.py（实测 <1 秒，远低于 90 秒预算）

流程（全部真实计算，无 sleep、无预录）：
1. 本进程构建一个无序输入的键值字典，把只读快照写入临时目录；
2. 用 ``sys.executable`` 启动**另一个 Python 进程**，从快照文件重新载入
   （不调用 build 重建、不做 pickle 反序列化），打印若干命中/未命中查询；
3. 校验子进程输出，并演示“校验和正确但槽位被改”的快照被拒绝。
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import sys
import tempfile

import mphf

# 子进程脚本：只负责 mphf.load + 查询打印（独立进程，重新 import mphf）。
_CHILD = r"""
import sys
import mphf

d = mphf.load(sys.argv[1])          # 从快照文件载入，源文件随即可关闭
print("size:", len(d))
for key in (b"alpha", b"beta", b"gamma", b"empty", b"absent"):
    found, value = mphf.find(d, key)
    print(f"find({key!r}) -> found={found} value={value!r}")
"""


def main() -> None:
    print("=== 1. 本进程构建键值字典并保存快照 ===")
    # 无序输入；构建前按键字节序固定排序，快照字节与传入顺序无关。
    items = [
        (b"gamma", b"third"),
        (b"alpha", b"first"),
        (b"empty", b""),              # 空值是有效命中
        (b"beta", b"second"),
    ]
    d = mphf.build_kv(items)
    assert d is not mphf.CONSTRUCTION_FAILED
    print(f"size={len(d)} seed={d.table.seed} m={d.table.vertex_count}")
    print(f"槽位键序: {[k.decode() for k in d.keys()]}")

    tmpdir = tempfile.mkdtemp(prefix="mphf-kv-demo-")
    path = os.path.join(tmpdir, "dict.mphfkv")
    mphf.dump(d, path)
    blob = mphf.dumps(d)
    print(f"快照 {len(blob)} 字节 -> {path}")
    print(f"头部 32 字节: {blob[:32].hex()}")
    print(f"校验和(SHA-256): {blob[32:64].hex()}")

    print("\n=== 2. 另一个进程从快照重新加载并查询 ===")
    child_path = os.path.join(tmpdir, "child.py")
    with open(child_path, "w", encoding="utf-8") as fh:
        fh.write(_CHILD)
    proc = subprocess.run(
        [sys.executable, child_path, path],
        capture_output=True, text=True, timeout=60, check=True,
        env={**os.environ, "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))},
    )
    print(proc.stdout, end="")
    assert "size: 4" in proc.stdout
    assert "find(b'alpha') -> found=True value=b'first'" in proc.stdout
    assert "find(b'empty') -> found=True value=b''" in proc.stdout   # 空值命中
    assert "find(b'absent') -> found=False value=None" in proc.stdout  # 明确未命中
    print("子进程输出校验通过：空值命中与未命中标志明确区分。")

    print("\n=== 3. 校验和正确但槽位被改的快照必须被拒绝 ===")
    # 篡改 g[0] 并重算校验和：校验和有效，但键不再落在自己的槽位。
    bad = bytearray(blob)
    bad[64] ^= 0x01  # G 段第一个 u16 的最低位
    digest = hashlib.sha256(bytes(bad[:32]) + bytes(bad[64:])).digest()
    bad[32:64] = digest
    bad_path = os.path.join(tmpdir, "corrupt.mphfkv")
    with open(bad_path, "wb") as fh:
        fh.write(bytes(bad))
    try:
        mphf.load(bad_path)
        raise AssertionError("corrupt snapshot was accepted")
    except mphf.SnapshotError as exc:
        print(f"拒绝（SnapshotError）: {exc}")

    # 未知版本同样拒绝（重算校验和也救不了）
    bad2 = bytearray(blob)
    bad2[8:12] = struct.pack(">I", 999)
    bad2[32:64] = hashlib.sha256(bytes(bad2[:32]) + bytes(bad2[64:])).digest()
    try:
        mphf.loads(bytes(bad2))
        raise AssertionError("unknown version was accepted")
    except mphf.SnapshotError as exc:
        print(f"拒绝（SnapshotError）: {exc}")

    print("\n演示完成：保存/跨进程加载/损坏拒绝均为当场真实计算。")


if __name__ == "__main__":
    main()
