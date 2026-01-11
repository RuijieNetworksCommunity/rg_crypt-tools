import hashlib
import base64
import random
from Crypto.Cipher import AES

def process_password(mode: int) -> bytes:
    '''
    这玩意反汇编都卡死，从汇编一个分支一个分支慢慢分析的，分析这个快给我人干废了
    '''
    # 处理 mode=1 的特殊情况
    if mode == 1:
        return ("RjYkh" + "wzx$20" + "18!").encode("utf-8")
    
    # 计算模8值
    v = mode % 8
    
    # 分支1: 根据值范围追加字符串
    if v <= 2:
        buf228 = "TFVx-23"
    else:
        # 根据奇偶性判断
        if v % 2 == 1:
            buf228 = "BR0kh"
        else:
            buf228 = "TFVx-23"
    
    # 分支2: 根据值范围追加字符串
    if v <= 2:
        buf228 += "BR0kh"
    else:
        # 根据奇偶性判断
        if v % 2 == 1:
            buf228 += "BR0kh"
        else:
            buf228 += "4MkNG"
    
    # 分支3: 根据值范围追加字符串
    if (v + 1) <= 2:
        buf228 += "sHi"
    else:
        # 根据奇偶性判断
        if v % 2 == 1:
            buf228 += "sHi"
        else:
            buf228 += "BR0kh"
    
    # 分支4: 根据值范围追加字符串
    if (v - 3) <= 0:
        buf228 += "BR0kh"
    else:
        # 根据奇偶性判断
        if v % 2 == 1:
            buf228 += "4MkNG"
        else:
            buf228 += "BR0kh"
    
    # 分支5: 根据值范围追加字符串
    if (v - 4) <= 0:
        buf228 += "C2rui"
    else:
        # 根据奇偶性判断
        if v % 2 == 1:
            buf228 += "rJ421"
        else:
            buf228 += "C2rui"
    
    # 分支6: 总是追加长字符串
    buf228 += "Yf&j8ceh6yxLmI"
    
    # 返回前32个字符
    return buf228[:0x20].encode("utf-8")

def EVP_BytesToKey(
        password: bytes, 
        salt: bytes, 
        key_len: int, 
        iv_len: int, 
        hash_name: str = "md5", 
        iterations: int = 1
    ) -> tuple[bytes, bytes]:
    """
    OpenSSL EVP_BytesToKey 密钥派生函数的 Python 实现
    
    参数:
    password: 用户密码（字节串）
    salt: 盐值（字节串，通常 8 字节）
    key_len: 所需密钥的长度（如 AES-256 为 32 字节）
    iv_len: 所需初始向量长度（如 AES 为 16 字节）
    hash_name: 使用的哈希算法（默认为 'md5'）
    iterations: 哈希迭代次数（默认为 1）
    
    返回:
    (key, iv) 元组，包含生成的密钥和初始向量
    """
    # 计算所需的总密钥材料
    total_len = key_len + iv_len
    key_iv = b""
    prev_digest = b""
    # 当生成的密钥材料不足时继续迭代
    while len(key_iv) < total_len:
        # 准备新的哈希对象
        digest = hashlib.new(hash_name)
        
        # 添加前一次迭代的结果（除第一次外）
        digest.update(prev_digest)
        
        # 添加密码和盐
        digest.update(password)
        digest.update(salt)
        
        # 执行多次迭代
        prev_digest = digest.digest()
        for _ in range(iterations - 1):
            digest = hashlib.new(hash_name)
            digest.update(prev_digest)
            prev_digest = digest.digest()
        
        # 添加生成的密钥材料
        key_iv += prev_digest
    
    # 分割为密钥和 IV
    key = key_iv[:key_len]
    iv = key_iv[key_len:key_len+iv_len]
    
    return key, iv

def custom_pad(data, block_size=16, padding_char=b'\x0c'):
    """
    使用自定义字符（默认为换行符）进行填充
    
    参数:
    data - 要填充的原始数据(bytes或str)
    block_size - 块大小(默认16)
    padding_char - 填充字符(默认'\n')
    
    返回:
    填充后的bytes数据
    """
    # 如果是字符串，转换为bytes
    if isinstance(data, str):
        data = data.encode()
    
    # 计算需要填充的长度
    padding_length = block_size - (len(data) % block_size)
    
    # 如果长度正好是块大小的倍数，则添加一个完整块
    if padding_length == 0:
        padding_length = block_size
    
    # 创建填充字节序列
    padding = padding_char * padding_length
    
    # 返回填充后的数据
    return data + padding

def custom_unpad(data, padding_char=b'\x0c'):
    padding_char_byte = padding_char
    # 从末尾开始找到第一个非填充字符
    i = len(data) - 1
    while i >= 0 and data[i] == padding_char_byte[0]:
        i -= 1
    return data[:i+1]

def read_salt_from_data(data_input):
    '''
    从检查data_input, 并从data_input读取salt, 正确执行返回盐值, 错误返回-1
    '''
    # 检测输入类型
    if type(data_input) == bytes:
        data_head = data_input[:8].decode("utf-8")
    elif type(data_input) == str:
        data_head = data_input[:8]
    else:
        return -1
    # 判断头部是否符合
    if(data_head == "Salted__"):
        return data_input[8:16]
    else:
        return -1

def write_salt_to_data(data_input: bytes, salt: bytes):
    '''
    添加salt头, 返回拼接后的数据
    '''
    data_ret = "Salted__".encode("utf-8") +salt + data_input
    return data_ret

def base64_decode(input) -> bytes:
    if(type(input)==bytes):
        return base64.b64decode(input)
    elif(type(input)==str):
        return base64.b64decode(input.encode("utf-8"))

def base64_encode(input) -> bytes:
    if(type(input)==bytes):
        return base64.b64encode(input)
    elif(type(input)==str):
        return base64.b64encode(input.encode("utf-8"))

def read_encrypted_data_from_data(input_data: bytes) -> bytes:
    '''
    从数据中读取返回加密的数据
    '''
    # 判断头部
    data_head = input_data[:8].decode("utf-8")
    if not(data_head == "Salted__"):
        return -1
    
    return input_data[16:]
    
def create_cipher(cipher_name: str, salt: bytes, password_data: bytes, iterations: int):
    '''
    创建AES加密

    参数
    cipher_name AES加密模式
    salt 盐（咸的）(用于计算key 和 iv)
    password_data 密码 (用于计算key 和 iv)
    iterations 迭代次数 (用于计算key 和 iv)
    '''
    key = bytearray(32)  # 最大密钥长度
    iv = bytearray(16)   # 标准IV长度
    
    if "AES-128" in cipher_name:
        key_size = 16
        iv_size = 16
        cipher_mode = AES.MODE_CBC
    elif "AES-256" in cipher_name:
        key_size = 32
        iv_size = 16
        cipher_mode = AES.MODE_CBC
    else:
        return None

    key,iv = EVP_BytesToKey(password_data, salt, key_size, iv_size, iterations=iterations)

    cipher = AES.new(key, cipher_mode, iv)

    return cipher

def random_salt_gen(len: int = 8) -> bytes:
    '''生成随机盐'''
    ret = str(random.randint(10**(len-1), (10**len)-1)).encode("utf-8")
    return ret

def rg_crypto_encrypt(data_input: bytes, cipher_name: str, iterations: int, use_base64: int) -> bytes:
    '''
    加密实现
    
    参数：
    data_input 待加密数据输入
    cipher_name 加密方式
    iterations 迭代次数
    use_base64 是否以base64格式输出
    '''
    salt = random_salt_gen() #随机添加适量符合个人口味的盐
    password = process_password(iterations) #根据迭代次数生成密码
    
    cipher = create_cipher(cipher_name, salt, password, iterations) #创建加密函数
    if not cipher:
        return b""
    
    padded_data = custom_pad(data_input, AES.block_size) #自定义填充
    encrypted_data = cipher.encrypt(padded_data) #加密数据
    
    salted_data = write_salt_to_data(encrypted_data, salt) #写数据头
    
    if use_base64:
        return base64_encode(salted_data)
    
    return salted_data

def rg_crypto_decrypt(data_input: bytes, cipher_name: str, iterations: int, use_base64: int) -> bytes:
    '''
    解密实现
    data_input 待解密数据输入
    cipher_name 加密方式
    iterations 迭代次数
    use_base64 是否为base64格式输入
    '''
    if use_base64: #是否为base64格式输入
        data_input = base64_decode(data_input)
    
    salt = read_salt_from_data(data_input) #获取菜品所需的盐量
    if not salt:
        return b""
    password = process_password(iterations) #根据迭代次数生成密码
    
    cipher = create_cipher(cipher_name, salt, password, iterations) #创建加密函数
    if not cipher:
        return b""

    encrypted_data = read_encrypted_data_from_data(data_input) #从输入中获取待解密的数据
    try:
        decrypted_data = cipher.decrypt(encrypted_data) #解密
        return custom_unpad(decrypted_data) #去除填充
    except Exception as e:
        print(f"解密错误: {e}")
        return b""

def rg_crypto_encrypt_to_md5(input: bytes, password: bytes) -> bytes:
    '''
    A 模式
    '''
    md5 = hashlib.md5()
    md5.update(password)
    md5.update(input)
    
    digest = md5.digest()
    return digest[:20]
    
def rg_crypto_encrypt_to_sha1(input: bytes, password: bytes) -> bytes:
    '''
    D 模式
    '''
    sha1 = hashlib.sha1()
    sha1.update(password)
    sha1.update(input)
    
    digest = sha1.digest()
    return digest[:20]

def rg_crypto_mode_B_decrypto(data_input: bytes) -> bytes:
    iterations = 1
    use_base64 = 1
    cipher_name = "AES-128-CBC"
    ret = rg_crypto_decrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_C_decrypto(data_input: bytes) -> bytes:
    iterations = 1
    use_base64 = 1
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_decrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_E_decrypto(data_input: bytes) -> bytes:
    iterations = 2023
    use_base64 = 1
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_decrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_F_decrypto(data_input: bytes) -> bytes:
    iterations = 831
    use_base64 = 0
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_decrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_A_encrypto(data_input: bytes) -> bytes:
    iterations = 1
    key = process_password(iterations)
    ret = rg_crypto_encrypt_to_md5(data_input, key)
    return ret.hex().encode()

def rg_crypto_mode_D_encrypto(data_input: bytes) -> bytes:
    iterations = 1
    key = process_password(iterations)
    ret = rg_crypto_encrypt_to_sha1(data_input, key)
    return ret.hex().encode()

def rg_crypto_mode_B_encrypto(data_input: bytes) -> bytes:
    iterations = 1
    use_base64 = 1
    cipher_name = "AES-128-CBC"
    ret = rg_crypto_encrypt(data_input, cipher_name, iterations, use_base64)
    return ret
    
def rg_crypto_mode_C_encrypto(data_input: bytes) -> bytes:
    iterations = 1
    use_base64 = 1
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_encrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_E_encrypto(data_input: bytes) -> bytes:
    iterations = 2023
    use_base64 = 1
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_encrypt(data_input, cipher_name, iterations, use_base64)
    return ret

def rg_crypto_mode_F_encrypto(data_input: bytes) -> bytes:
    iterations = 831
    use_base64 = 0
    cipher_name = "AES-256-CBC"
    ret = rg_crypto_encrypt(data_input, cipher_name, iterations, use_base64)
    return ret