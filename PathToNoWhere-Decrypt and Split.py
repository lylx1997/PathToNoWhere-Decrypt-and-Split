# 2026.5.14 无期迷途 (Path To No Where) 更新后增加对fschunk文件夹内的拼接文件解密与拆分，同时支持过去的单一文件的解密
# -*- coding: utf-8 -*-
import struct
import sys
import time
from pathlib import Path

_XOR_TABLE_CACHE = {}


def _get_xor_table(key):
    if key not in _XOR_TABLE_CACHE:
        _XOR_TABLE_CACHE[key] = bytes([i ^ key for i in range(256)])
    return _XOR_TABLE_CACHE[key]


def xor(data, length):
    if length < 52:
        raise ValueError("文件数据长度不足，无法解密")
    key = data[50] ^ 0x55
    if key != (data[51] ^ 0x6E):
        raise ValueError("XOR密钥校验失败")
    xor_table = _get_xor_table(key)
    return data[50:length].translate(xor_table)


def parse_unity_fs_size(data):
    if len(data) < 38 or not data.startswith(b'UnityFS\x00'):
        return None
    try:
        file_size = struct.unpack('>Q', data[30:38])[0]
        if file_size < 128 or file_size > 1024 * 1024 * 1024:
            return None
        return file_size
    except struct.error:
        return None


def decrypt(fpath, target_dir, source_root):
    """解密函数，返回 (是否成功, 拆分出的文件数量)"""
    try:
        with open(fpath, "rb") as f:
            raw_data = f.read()
    except (IOError, OSError) as e:
        print(f"\n[读取错误] 无法读取文件: {fpath} | 原因: {e}")
        return False, 0

    try:
        relative_path = Path(fpath).relative_to(source_root)
        file_size = len(raw_data)

        original_suffix = Path(fpath).suffix

        # 1. 先尝试解密头部，获取第一个 UnityFS 块的大小
        try:
            decrypted_header = xor(raw_data, len(raw_data))
            first_fs_size = parse_unity_fs_size(decrypted_header)
        except ValueError as e:
            print(f"\n[跳过] 解密头部失败: {e}")
            return False, 0

        if first_fs_size is None:
            print(f"\n[跳过] 未找到有效的 UnityFS 头: {fpath}")
            return False, 0
        assert isinstance(first_fs_size, int)

        # 2. 判断是否为单文件 (50字节头 + UnityFS大小 == 原文件大小)
        is_single_file = (50 + first_fs_size == file_size)

        # 3. 根据单文件/拼接文件决定输出路径
        if is_single_file:
            # 单文件：直接放在输出文件夹的父级目录中
            output_dir = Path(target_dir) / relative_path.parent
        else:
            # 拼接文件：放在以原文件名命名的子目录中
            output_dir = Path(target_dir) / relative_path.parent / Path(fpath).stem

        output_dir.mkdir(parents=True, exist_ok=True)

        # 4. 执行解密与写入
        if is_single_file:
            # 单文件处理：完整解密并保存
            save_path = output_dir / f"{Path(fpath).stem}{original_suffix}"
            with open(save_path, "wb", buffering=8 * 1024 * 1024) as f_out:
                f_out.write(decrypted_header[:first_fs_size])
            return True, 1
        else:
            # 拼接文件处理：循环拆分并保存
            current_offset = 0
            file_index = 1

            while current_offset + 52 <= file_size:
                try:
                    remaining_data = raw_data[current_offset:]
                    decrypted_data = xor(remaining_data, len(remaining_data))
                    fs_size = parse_unity_fs_size(decrypted_data)

                    if fs_size is None:
                        break

                    assert isinstance(fs_size, int)
                    unity_fs_data = decrypted_data[:fs_size]

                    # 拼接文件处理
                    save_path = output_dir / f"{Path(fpath).stem}{file_index:03d}{original_suffix}"
                    with open(save_path, "wb", buffering=8 * 1024 * 1024) as f_out:
                        f_out.write(unity_fs_data)

                    current_offset += 50 + fs_size
                    file_index += 1

                except ValueError as e:
                    print(f"\n[跳过] 偏移 {current_offset} 处解密失败: {e}")
                    break

            return True, file_index - 1

    except Exception as e:
        print(f"\n[处理错误] {fpath} | 原因: {type(e).__name__}: {e}")
        return False, 0


# ================= 配置区域 =================
assets = r"E:\资源\模拟器共享文件夹\新建文件夹\com.zy.wqmt.cn"
target_folder = r"E:\资源\模拟器共享文件夹\新建文件夹\com.zy.wqmt.cn解密"
# ===========================================

if __name__ == "__main__":
    assets_path = Path(assets)

    # 1. 先扫描出所有文件，获取总数（用于计算全局进度）
    all_files = [f for f in assets_path.rglob('*') if f.is_file()]
    total_files = len(all_files)

    success_count = 0
    total_extracted = 0
    start_time = time.time()

    # 2. 遍历处理文件并显示进度条
    for idx, file_path in enumerate(all_files, 1):
        # 计算进度百分比
        percent = (idx / total_files) * 100

        # 构造进度条 UI
        bar_length = 30
        filled = int(bar_length * idx // total_files)
        bar = '█' * filled + '-' * (bar_length - filled)

        # 获取当前处理的文件名（截断过长的名字）
        current_name = file_path.name
        if len(current_name) > 25:
            current_name = current_name[:22] + "..."

        # 动态刷新终端输出 (\r 回到行首，end='' 防止换行)
        sys.stdout.write(f"\r[{bar}] {percent:5.1f}% | 文件: {idx}/{total_files} | 当前: {current_name}")
        sys.stdout.flush()

        # 执行解密
        is_ok, extracted_num = decrypt(str(file_path), target_folder, assets_path)
        if is_ok:
            success_count += 1
            total_extracted += extracted_num

    # 3. 处理完成后的总结输出
    elapsed = time.time() - start_time
    print(f"\n\n{'=' * 50}")
    print(f"✅ 处理完成！耗时: {elapsed:.2f} 秒")
    print(f"📁 成功处理: {success_count}/{total_files} 个文件")
    print(f"📦 共提取出: {total_extracted} 个 UnityFS 文件")
    print(f"{'=' * 50}")