"""键值只读快照的离线演示：保存后由**另一个进程**重新加载。

运行：python demo_kv.py（实测 1 秒内，远低于 90 秒预算）

流程：

1. 父进程：从无序的 ``(key, value)`` 对构建 :class:`mphf.KvSnapshot`
   （构建前按键字节序排序，含空键、空值、二进制值与 4096 字节上限值），
   写入单个快照文件；
2. 子进程：用 ``subprocess`` 启动一个全新的 Python 解释器，只拿到快照
   文件路径，调用 ``KvSnapshot.load`` 纯字节解析载入（不 build、不
   pickle），查询并把结果打印回父进程；
3. 父进程核对子进程输出，顺手演示：输入排列产生逐位相同的快照字节、
   损坏文件（重算校验和后的错槽位）被拒绝。

所有数据在本地确定性生成，不访问网络或任何外部服务。
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

import mphf


# 子进程入口：只依赖快照文件，不接收任何 Python 对象。
CHILD_SCRIPT = r"""
import sys
import mphf

path = sys.argv[1]
snap = mphf.KvSnapshot.load(path)  # 纯字节载入；载入后文件句柄即关闭
print(f"child: loaded n={len(snap)} seed={snap.seed} m={snap.vertex_count}")
for key in (b"", b"alpha", b"empty", b"bin", b"big", b"missing"):
    hit, value = mphf.find_kv(snap, key)
    shown = value if value is None or len(value) <= 12 else value[:9] + b"..."
    print(f"child: find({key!r}) -> hit={hit} value={shown!r}")
"""


def main() -> None:
    pairs = [
        (b"big", b"x" * 4096),       # 恰好达到单项值上限
        (b"bin", bytes(range(8))),   # 二进制值（含 0x00）
        (b"", b"empty-key"),         # 空键合法
        (b"empty", b""),             # 空值是有效命中
        (b"alpha", b"one"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "dictionary.mphkv")

        # ---- 父进程构建并保存（故意乱序传入） ----
        snap = mphf.build_kv(reversed(pairs))
        assert snap is not mphf.CONSTRUCTION_FAILED
        snap.save(path)
        data = snap.to_bytes()
        print(f"parent: built n={snap.size} m={snap.vertex_count} "
              f"seed={snap.seed}; snapshot {len(data)} bytes -> {path}")

        # 同一键集不同传入顺序（含 dict）必须逐位相同。
        reordered = mphf.build_kv(dict(pairs)).to_bytes()
        assert reordered == data
        print("parent: shuffled/dict input produces byte-identical snapshot")

        # ---- 另一个进程重新加载 ----
        proc = subprocess.run(
            [sys.executable, "-c", CHILD_SCRIPT, path],
            capture_output=True,
            text=True,
            check=True,
        )
        print(proc.stdout, end="")
        assert "hit=True value=b''" in proc.stdout  # 空值命中
        assert "hit=False value=None" in proc.stdout  # 未命中另有标志

        # ---- 校验和正确但槽位结构损坏：必须拒绝 ----
        n, m, seed = snap.size, snap.vertex_count, snap.seed

        def ref_h(tag: int, key: bytes) -> int:
            import hashlib
            d = hashlib.sha256(seed.to_bytes(4, "big") + bytes([tag]) + key).digest()
            return int.from_bytes(d, "big") % m

        corrupted = bytearray(data)
        first_key = snap.keys[0]
        v0 = ref_h(0, first_key)
        g_off = mphf.SNAPSHOT_HEADER_SIZE + v0 * 4
        old = struct.unpack(">I", corrupted[g_off : g_off + 4])[0]
        corrupted[g_off : g_off + 4] = struct.pack(">I", (old + 1) % n)
        # 重算整个体的 SHA256 写回头部：校验和“正确”，结构仍然非法。
        import hashlib
        body = bytes(corrupted[mphf.SNAPSHOT_HEADER_SIZE :])
        corrupted[mphf.SNAPSHOT_HEADER_SIZE - 32 : mphf.SNAPSHOT_HEADER_SIZE] = (
            hashlib.sha256(body).digest()
        )
        bad_path = os.path.join(tmp, "corrupt.mphkv")
        with open(bad_path, "wb") as f:
            f.write(corrupted)
        check = subprocess.run(
            [sys.executable, "-c",
             "import sys,mphf; mphf.KvSnapshot.load(sys.argv[1])", bad_path],
            capture_output=True,
            text=True,
        )
        assert check.returncode != 0
        assert "SnapshotFormatError" in check.stderr
        print("parent: checksum-valid but structurally corrupt snapshot rejected")

    print("RELOAD OK: 子进程已从单文件快照独立载入并查询，源文件随后删除")


if __name__ == "__main__":
    main()
