#! /bin/env python

import os
import sys
import argparse
from ruijie_crypt import *
from io import TextIOWrapper
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import base64

enc_choices = ["B", "C", "E", "F", "v2-2023", "v1-2021"]
dec_choices = ["B", "C", "E", "F", "v2-2023", "v1-2021"]
sum_choices = ["A", "D"]

HEADER_V2_2023 = b"upgrade_crypt_v2!@2023\n"
HEADER_V1_2021 = b"upgrade_crypt_v1!@2021"

def s_open(path, mode) -> TextIOWrapper:
    if path == "stdin" or path == "-":
        return os.fdopen(0, mode)
    elif path == "stdout":
        return os.fdopen(1, mode)
    else:
        return open(path, mode)

def fw_2021_crypt(data_input: bytes) -> bytes:

    data_size = len(data_input)
    output_stream = bytearray(data_size)
    keys = [232, 116, 250, 253, 126, 255, 127]
    dec_cnt = 0
    for i in keys:
        output_stream[dec_cnt] = data_input[dec_cnt] ^ i
        dec_cnt += 1
    while dec_cnt < data_size:
        output_stream[dec_cnt] = data_input[dec_cnt] ^ 127
        dec_cnt += 1
    
    return bytes(output_stream)

'''
def fw_2021_crypt(data_input: bytes) -> bytes:
    BUFFER_SIZE = 0x1000  # 4KB
    state = [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]

    data_size = len(data_input)
    output = bytearray(data_size)
    for i in range(data_size):
        feedback = (state[0] + state[4] + state[5] + state[6]) & 1

        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7] = (
        state[1], state[2], state[3], state[4], state[5], state[6], state[6], feedback
        )

        key = (
            ((state[0] & 1) << 0) | ((state[1] & 1) << 1) | ((state[2] & 1) << 2) | ((state[3] & 1) << 3) |
            ((state[4] & 1) << 4) | ((state[5] & 1) << 5) | ((state[6] & 1 )<< 6) | ((state[7] & 1) << 7)
        )
        output[i] = data_input[i] ^ key
    return bytes(output)


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
'''

def root_password_sum(serial_number: str) -> str:
    # 盐
    SALT1 = b'\xA2\xAA\x1F\xF6\xE9\xF4\x45\x0F\xF0\xEE\x32\xBB\x47\x62\xA5\xD4'
    SALT2 = b'\x32\x03\x08\x51\x73\x56\x77\x91\xE1\x6F\xA2\x5B\x4C\xC2\xD5\x7D'
    #将输入字符串转换为字节
    input_bytes = serial_number.encode('utf-8')
    
    #SALT1 + input + SALT2
    buffer = bytearray()
    buffer.extend(SALT1)
    buffer.extend(input_bytes)
    buffer.extend(SALT2)
    
    #计算 MD5 哈希
    md5_hash = hashlib.md5(buffer).digest()
    
    #转换为十六进制字符串
    hex_digest = md5_hash.hex()
    
    return hex_digest[:16]

def eweb_password_sum(serial_number: str) -> str:
    def des_cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
        return cipher.encrypt(padded_data)
    def char_to_digit(c: str) -> str:
        ord_c = ord(c)
        if c.isdigit():
            return c
        elif c in ('+', '='):
            return '0'
        elif 0x41 <= ord_c <= 0x45:  # A-E
            return '0'
        elif 0x46 <= ord_c <= 0x4A:  # F-J
            return '1'
        elif 0x4B <= ord_c <= 0x4F:  # K-O
            return '2'
        elif 0x50 <= ord_c <= 0x54:  # P-T
            return '3'
        elif 0x55 <= ord_c <= 0x5A:  # U-Z
            return '4'
        elif 0x61 <= ord_c <= 0x65:  # a-e
            return '5'
        elif 0x66 <= ord_c <= 0x6A:  # f-j
            return '6'
        elif 0x6B <= ord_c <= 0x6F:  # k-o
            return '7'
        elif 0x70 <= ord_c <= 0x74:  # p-t
            return '8'
        elif 0x75 <= ord_c <= 0x7A:  # u-z
            return '9'
        else:
            return '0'
    key = b'ReyeeEhr'
    iv = b'ReyeeEhr'
    ciphertext = des_cbc_encrypt(serial_number, key, iv)
    b64_str = base64.b64encode(ciphertext).decode('utf-8').replace('\n', '')

    # 从索引14截取6个字符
    start_idx = 14
    if len(b64_str) < start_idx + 6:
        start_idx = max(0, len(b64_str) - 6)
    segment = b64_str[start_idx : start_idx + 6]

    pwd = ''.join([char_to_digit(c) for c in segment])
    return f"Re{pwd.ljust(6, '0')[:6]}"

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

def root_process(args):
    sys.stdout = sys.__stdout__
    dev_sn = ""
    if args.sn:
        dev_sn = args.sn
    else:
        dev_sn = input("设备SN:")
    password = root_password_sum(dev_sn)
    print(f"root 密码: {password}")

def eweb_process(args):
    sys.stdout = sys.__stdout__
    dev_sn = ""
    if args.sn:
        dev_sn = args.sn
    else:
        dev_sn = input("设备SN:")
    eweb_password = eweb_password_sum(dev_sn)
    print(f"EWEB 密码: {eweb_password}")

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

    root_parsers = subparsers.add_parser('root', help='计算root密码')
    root_parsers.add_argument("-sn",  required=False, help="设备SN")

    eweb_parsers = subparsers.add_parser('eweb', help='计算eweb密码')
    eweb_parsers.add_argument("-sn",  required=False, help="设备SN")

    args = parser.parse_args()
    sys.stdout = sys.__stderr__

    if args.subcommand == 'enc':
        enc_process(args)
    elif args.subcommand == 'dec':
        dec_process(args)
    elif args.subcommand == 'sum':
        sum_process(args)
    elif args.subcommand == 'root':
        root_process(args)
    elif args.subcommand == 'eweb':
        eweb_process(args)
if __name__ == "__main__":
    main()