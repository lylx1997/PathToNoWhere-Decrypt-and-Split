# 2026.5.14 无期迷途 (Path To No Where) 更新后增加对fschunk文件夹内的拼接文件解密与拆分，同时支持过去的单一文件的解密
# -*- coding: utf-8 -*-

import struct
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

# ================= 配置区域 =================
assets = r"E:\资源\com.zy.wqmt.cn\assets"
target_folder = r"E:\资源\com.zy.wqmt.cn\new"

# 是否跨文件并行（各 .bin 相互独立）。文件多时提速明显。
# 先用 False 验证结果，再按需改成 True 并把 max_workers 调成物理核心数。
use_parallel = False
max_workers = 4
# ===========================================

_XOR_TABLE_CACHE: Dict[int, bytes] = {}
_MAX_FS = 1024 * 1024 * 1024
_HDR = b"UnityFS\x00"


def _get_xor_table(key: int) -> bytes:
    tbl = _XOR_TABLE_CACHE.get(key)
    if tbl is None:
        tbl = bytes([i ^ key for i in range(256)])
        _XOR_TABLE_CACHE[key] = tbl
    return tbl


def _read_block(raw: bytes, off: int) -> Optional[bytes]:
    """读取并解密位于 off 的单个块，返回解密后的 UnityFS 数据(bytes)。
    无效或越界返回 None；密钥校验不通过抛 ValueError。"""
    if off + 52 > len(raw):
        return None
    key = raw[off + 50] ^ 0x55
    if key != (raw[off + 51] ^ 0x6E):
        raise ValueError("XOR密钥校验失败")
    tbl = _get_xor_table(key)
    if raw[off + 50:off + 58].translate(tbl) != _HDR:
        return None
    fs = struct.unpack(">Q", raw[off + 80:off + 88].translate(tbl))[0]
    if fs < 128 or fs > _MAX_FS:
        return None
    if off + 50 + fs > len(raw):
        return None
    return raw[off + 50:off + 50 + fs].translate(tbl)


def decrypt(fpath: str, target_dir: str, source_root: str) -> Tuple[bool, int]:
    """解密函数，返回 (是否成功, 拆分出的文件数量)"""
    try:
        with open(fpath, "rb") as f:
            raw = f.read()
    except (IOError, OSError) as e:
        print("\n[读取错误] 无法读取文件: %s | 原因: %s" % (fpath, e))
        return False, 0

    try:
        relative_path = Path(fpath).relative_to(source_root)
        file_size = len(raw)
        original_suffix = Path(fpath).suffix
        stem = Path(fpath).stem

        try:
            first_body = _read_block(raw, 0)
        except ValueError as e:
            print("\n[跳过] 解密头部失败: %s" % e)
            return False, 0

        if first_body is None:
            print("\n[跳过] 未找到有效的 UnityFS 头: %s" % fpath)
            return False, 0

        first_fs = len(first_body)
        is_single = (50 + first_fs == file_size)

        if is_single:
            output_dir = Path(target_dir) / relative_path.parent
        else:
            output_dir = Path(target_dir) / relative_path.parent / stem
        output_dir.mkdir(parents=True, exist_ok=True)

        if is_single:
            save_path = output_dir / (stem + original_suffix)
            with open(save_path, "wb", buffering=8 * 1024 * 1024) as f_out:
                f_out.write(first_body)
            return True, 1

        current_offset = 0
        file_index = 1
        while True:
            try:
                body = _read_block(raw, current_offset)
            except ValueError as e:
                print("\n[跳过] 偏移 %d 处解密失败: %s" % (current_offset, e))
                break
            if body is None:
                break

            save_path = output_dir / (stem + format(file_index, "03d") + original_suffix)
            with open(save_path, "wb", buffering=8 * 1024 * 1024) as f_out:
                f_out.write(body)

            current_offset += 50 + len(body)
            file_index += 1

        return True, file_index - 1

    except Exception as e:
        print("\n[处理错误] %s | 原因: %s: %s" % (fpath, type(e).__name__, e))
        return False, 0


def _decrypt_worker(args):
    fpath_str, target_dir, source_root = args
    return decrypt(fpath_str, target_dir, source_root)


def _make_bar(filled: int, width: int) -> str:
    return chr(0x2588) * filled + "-" * (width - filled)


if __name__ == "__main__":
    assets_path = Path(assets)
    all_files = [f for f in assets_path.rglob('*') if f.is_file()]
    total_files = len(all_files)

    success_count = 0
    total_extracted = 0
    start_time = time.time()
    bar_length = 30

    def _report(pos: int, name: str) -> None:
        percent = pos / total_files * 100.0
        filled = int(bar_length * pos / total_files)
        bar = _make_bar(filled, bar_length)
        sys.stdout.write("\r[%s]%5.1f%% | 文件: %d/%d | 当前: %s"
                         % (bar, percent, pos, total_files, name))
        sys.stdout.flush()

    src_root_str = str(assets_path)

    if use_parallel:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        jobs = [(str(f), target_folder, src_root_str) for f in all_files]
        done = 0
        with ProcessPoolExecutor(max_workers=max_workers) as ex:
            fut_map = {ex.submit(_decrypt_worker, j): j[0] for j in jobs}
            for fut in as_completed(fut_map):
                done += 1
                ok, num = fut.result()
                if ok:
                    success_count += 1
                    total_extracted += num
                nm = Path(fut_map[fut]).name
                if len(nm) > 25:
                    nm = nm[:22] + "..."
                _report(done, nm)
    else:
        for idx, file_path in enumerate(all_files, 1):
            nm = file_path.name
            if len(nm) > 25:
                nm = nm[:22] + "..."
            _report(idx, nm)
            ok, num = decrypt(str(file_path), target_folder, src_root_str)
            if ok:
                success_count += 1
                total_extracted += num

    elapsed = time.time() - start_time
    print("\n\n" + "=" * 50)
    print("处理完成！耗时: %.2f 秒" % elapsed)
    print("成功处理: %d/%d 个文件" % (success_count, total_files))
    print("共提取出: %d 个 UnityFS 文件" % total_extracted)
    print("=" * 50)
