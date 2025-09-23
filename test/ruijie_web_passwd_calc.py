#! /bin/env python

description = '''
# ----------------------------------------------------------
# Title: ruijie_web_passwd_calc.py
# Author: air_jinkela(air_jinkela@163.com)
# Date: 2025-06-05
# Description: Calculate password from SN.
# Depends pycryptodome
# ----------------------------------------------------------
'''

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import base64

def des_cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode('utf-8'), DES.block_size)
    return cipher.encrypt(padded_data)

def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8').replace('\n', '')

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

def generate_eweb_password(serial: str) -> str:
    key = b'ReyeeEhr'
    iv = b'ReyeeEhr'
    ciphertext = des_cbc_encrypt(serial, key, iv)
    b64_str = base64_encode(ciphertext)

    # 从索引14截取6个字符
    start_idx = 14
    if len(b64_str) < start_idx + 6:
        start_idx = max(0, len(b64_str) - 6)
    segment = b64_str[start_idx : start_idx + 6]

    serial_number = ''.join([char_to_digit(c) for c in segment])
    return f"Re{serial_number.ljust(6, '0')[:6]}"


if __name__ == "__main__":
    print(description)
    device_serial = input("请输入设备SN:")
    eweb_password = generate_eweb_password(device_serial)
    print(f"EWEB 密码: {eweb_password}")
