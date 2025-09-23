#! /bin/env python

import os
import sys
import argparse
from ruijie_crypt import *
from io import TextIOWrapper

sys.stdout = sys.__stderr__

enc_choices = ["A", "D", "B", "C", "E", "F", "v2-2023", "v1-2021"]
dec_choices = ["B", "C", "E", "F", "v2-2023", "v1-2021"]
sum_choices = ["A", "D"]

HEADER_V2_2023 = b"upgrade_crypt_v2!@2023\n"
HEADER_V1_2021 = b"upgrade_crypt_v1!@2021"

def fw_2021_crypt(data_input: bytes) -> bytes:
    BUFFER_SIZE = 0x1000  # 4KB
    state = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]
    
    def chunk_encrypt(input_bytes: bytes, length: int) -> bytes:
        output = bytearray(length)
        for i in range(length):
            feedback = (state[0] + state[4] + state[5] + state[6]) & 1

            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7] = (
            state[1], state[2], state[3], state[4], state[5], state[6], state[6], feedback
            )

            key = 0
            for j in range(8):
                key |= ((state[j] & 1) << j)
            output[i] = input_bytes[i] ^ key
        return bytes(output)
    
    data_size = len(data_input)
    already_read_size = 0
    output_stream = b""
    while data_size > 0:
        read_size = min(BUFFER_SIZE, data_size)
        chunk = data_input[already_read_size:already_read_size + read_size]
        already_read_size += read_size

        output_chunk = chunk_encrypt(input_bytes=chunk, length=len(chunk))
        output_stream += output_chunk
        data_size -= read_size
    return output_stream

def s_open(path, mode) -> TextIOWrapper:
    if path == "stdin" or path == "-":
        return os.fdopen(0, mode)
    elif path == "stdout":
        return os.fdopen(1, mode)
    else:
        return open(path, mode)

def enc_process(args):
    in_file = args.input
    out_file = args.output
    c_type = args.type

    with s_open(in_file, "rb") as in_buf:
        with s_open(out_file, "wb") as out_buf:
            if c_type == "A":
                out_stream = rg_crypto_mode_A_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "D":
                out_stream = rg_crypto_mode_D_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "B":
                out_stream = rg_crypto_mode_B_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "C":
                out_stream = rg_crypto_mode_C_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "E":
                out_stream = rg_crypto_mode_E_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "F":
                out_stream = rg_crypto_mode_F_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "v2-2023":
                out_buf.write(HEADER_V2_2023)
                out_stream = rg_crypto_mode_E_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "v1-2021":
                out_buf.write(HEADER_V1_2021)
                out_stream = fw_2021_crypt(in_buf.read())
                out_buf.write(out_stream)

def dec_process(args):
    in_file = args.input
    out_file = args.output
    c_type = args.type

    with s_open(in_file, "rb") as in_buf:
        with s_open(out_file, "wb") as out_buf:
            if c_type == "B":
                out_stream = rg_crypto_mode_B_decrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "C":
                out_stream = rg_crypto_mode_C_decrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "E":
                out_stream = rg_crypto_mode_E_decrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "F":
                out_stream = rg_crypto_mode_F_decrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "v2-2023":
                header = in_buf.read(len(HEADER_V2_2023))
                if header != HEADER_V2_2023:
                    sys.__stderr__.write("解密失败：文件头不匹配\n")
                    return
                out_stream = rg_crypto_mode_E_decrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "v1-2021":
                header = in_buf.read(len(HEADER_V1_2021))
                if header != HEADER_V1_2021:
                    sys.__stderr__.write("解密失败：文件头不匹配\n")
                    return
                out_stream = fw_2021_crypt(in_buf.read())
                out_buf.write(out_stream)
                pass

def sum_process(args):
    in_file = args.input
    out_file = args.output
    c_type = args.type

    with s_open(in_file, "rb") as in_buf:
        with s_open(out_file, "wb") as out_buf:
            if c_type == "A":
                out_stream = rg_crypto_mode_A_encrypto(in_buf.read())
                out_buf.write(out_stream)
            elif c_type == "D":
                out_stream = rg_crypto_mode_D_encrypto(in_buf.read())
                out_buf.write(out_stream)

def main():
    parser = argparse.ArgumentParser(description="加解密锐捷漏油器升级文件v2")

    subparsers = parser.add_subparsers(title='子命令', dest='subcommand')

    enc_parsers = subparsers.add_parser('enc', help='加密')
    enc_parsers.add_argument("-t", "--type", required=True, help="类型", choices=enc_choices)
    enc_parsers.add_argument("-i", "--input", "-in",  required=True, help="输入文件")
    enc_parsers.add_argument("-o", "--output", "-out", required=True, help="输出文件")

    dec_parsers = subparsers.add_parser('dec', help='解密')
    dec_parsers.add_argument("-t", "--type", required=True, help="类型", choices=dec_choices)
    dec_parsers.add_argument("-i", "--input", "-in",  required=True, help="输入文件")
    dec_parsers.add_argument("-o", "--output", "-out", required=True, help="输出文件")

    sum_parsers = subparsers.add_parser('sum', help='计算')
    sum_parsers.add_argument("-t", "--type", required=True, help="类型", choices=sum_choices)
    sum_parsers.add_argument("-i", "--input", "-in",  required=False, help="输入 default:stdin", default="stdin")
    sum_parsers.add_argument("-o", "--output", "-out", required=False, help="输出 default:stdout", default="stdout")

    args = parser.parse_args()
    if args.subcommand == 'enc':
        enc_process(args)
    elif args.subcommand == 'dec':
        dec_process(args)
    elif args.subcommand == 'sum':
        sum_process(args)

if __name__ == "__main__":
    main()