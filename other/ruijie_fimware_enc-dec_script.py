#! /bin/env python

# ----------------------------------------------------------
# Title: ruijie_fimware_enc-dec_script.py
# Author: air_jinkela(air_jinkela@163.com)
# Date: 2025-06-11
# Description: Encrypt and decrypt Ruijie upgrade firmware.
# ----------------------------------------------------------

import os
import argparse

HEADER_STRING = b"upgrade_crypt_v1!@2021"
HEADER_SIZE = len(HEADER_STRING)
BUFFER_SIZE = 0x1000  # 4KB

# 初始状态（小端序）
state = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]

def chunk_encrypt(flag, input_bytes: bytes, length: int) -> bytes:
    global state
    # 重置状态（flag 非 0）
    if flag != 0:
        state = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]

    output = bytearray(length)

    for i in range(length):
        feedback = (state[0] + state[4] + state[5] + state[6]) & 1

        for j in range(6):
            state[j] = state[j + 1]
        state[7] = feedback

        key = 0
        for j in range(8):
            key |= ((state[j] & 1) << j)
        print(key)
        output[i] = input_bytes[i] ^ key

    return bytes(output)


def file_crypt(input_path: str, output_path: str = None, crypt_mode: bool = True) -> int:
    try:
        # 处理输入源
        if 0==1 and input_path == "stdin":
            input_stream = os.fdopen(0, "rb")
            file_size = BUFFER_SIZE  # 不确定长度
        else:
            if not os.path.exists(input_path):
                print("输入文件不存在")
                return -1
            file_size = os.path.getsize(input_path)
            input_stream = open(input_path, "rb")

        # 处理输出目标
        if output_path:
            output_stream = open(output_path, "wb")
        else:
            output_stream = os.fdopen(1, "wb")  # stdout

        # 加密模式
        if crypt_mode:
            output_stream.write(HEADER_STRING)
        else:
            header = input_stream.read(HEADER_SIZE)
            if header != HEADER_STRING:
                print("解密失败：文件头不匹配")
                return -1
            file_size -= HEADER_SIZE

        # 加解密主循环
        while file_size > 0 or input_path == "stdin":
            read_size = BUFFER_SIZE if input_path == "stdin" else min(BUFFER_SIZE, file_size)
            chunk = input_stream.read(read_size)
            if not chunk:
                break

            output_chunk = chunk_encrypt(flag=0, input_bytes=chunk, length=len(chunk))
            output_stream.write(output_chunk)

            if input_path != "stdin":
                file_size -= len(chunk)

        return 0

    except Exception as e:
        print("处理失败:", e)
        return -1

    finally:
        try:
            if input_stream and input_stream is not os.sys.stdin:
                input_stream.close()
        except:
            pass
        try:
            if output_stream and output_stream is not os.sys.stdout:
                output_stream.close()
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description="加解密锐捷漏油器升级文件")
    parser.add_argument("-i", "--input", required=True, help="输入文件")
    parser.add_argument("-o", "--output", required=True, help="输出文件")
    parser.add_argument("-e", "--encrypt", action="store_true", help="加密")

    args = parser.parse_args()
    crypt_mode = args.encrypt

    result = file_crypt(args.input, args.output, crypt_mode)
    if result == 0:
        print("OK")
    else:
        print("FAIL")

if __name__ == "__main__":
    main()