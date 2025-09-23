#! /bin/env python

import os
import argparse
from ruijie_crypt import *
# 这个文件在 瑞捷加解密分析.zip 里面

def file_crypt(input_path: str, output_path: str = None, crypt_mode: bool = True) -> int:
    try:
        # 处理输入源
        if not os.path.exists(input_path):
            print("输入文件不存在")
            return -1
        file_size = os.path.getsize(input_path)
        input_stream = open(input_path, "rb")

        # 处理输出目标
        output_stream = open(output_path, "wb")

        out_stream = rg_crypto_mode_B_decrypto(input_stream.read(file_size))
        output_stream.write(out_stream)

        return 0

    except Exception as e:
        print("处理失败:", e)
        return -1

    finally:
        try:
                input_stream.close()
        except:
            pass
        try:
                output_stream.close()
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="加解密锐捷漏油器升级文件v2")
    parser.add_argument("-i", "--input", required=True, help="输入文件")
    parser.add_argument("-o", "--output", required=True, help="输出文件")
    parser.add_argument("-e", "--encrypt", action="store_true", help="加密")

    args = parser.parse_args()
    crypt_mode = args.encrypt

    result = file_crypt(args.input, args.output, crypt_mode)
    if result == 0:
        print("OK")
        return 0
    else:
        print("FAIL")
        return -1

if __name__ == "__main__":
    main()