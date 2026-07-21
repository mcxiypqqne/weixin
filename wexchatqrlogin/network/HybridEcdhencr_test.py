import hmac
import hashlib
import socket
import secrets
import sys
import time
import struct
import re

# 添加项目根目录 D:\weixin，而不是 D:\weixin\wexchatqrlogin
sys.path.append(r"D:\weixin")  # 注意用 raw string，避免反斜杠转义
DEBUG = True

from wexchatqrlogin.crypto import (
    generate_p256_keypair,
    sha256,
    mmtls_ecdh_kdf,
    mmtls_aes_gcm,
    mmtls_hkdf_expand,
    mmtls_random,
    mmtls_zlib,
    compute_hdkdf_salt,
)
from wexchatqrlogin.proto import HybridEcdhEncrypt_pb2 as pb2

# ============================================================
# 辅助函数
# ============================================================

def set_hmac(packet: bytearray, hmac_value: int) -> None:
    """
    将计算好的 HMAC 值写入已生成的 packet 中 (偏移 0x2F, 4 字节 LE)。

    Parameters
    ----------
    packet : bytearray
        57 字节的 packet (由 encode_hybrid_ecdh_header 生成).
    hmac_value : int
        4 字节 HMAC 值 (来自 sub_5F8E0 计算结果).
    """
    struct.pack_into('<I', packet, 0x2F, hmac_value)


def encode_hybrid_ecdh_header(
    uin: int,
    func_type: int,
    a7_param: int,
    cookie_data: bytes,
    a8_data: bytes,
    encrypt_algo: int = 12,
    client_ver: int = 0x28004750,
    flags: int = 0xFF,
    sub_60038_val: int = 2,
    hmac_present: int = 1,
    unknown_4bytes: bytes = None,
    sub_60244_val: int = 0,
    sub_60280_val: int = 0,
    tail_2bytes: bytes = None,
) -> bytes:
    """
    生成 sub_65ECC 输出的 57 字节二进制头部 (type=2, 非加密 Pack)。

    Parameters
    ----------
    uin : int
        用户 UIN (对应 Java packHybridEcdh 的 i17).
    func_type : int
        功能号 (对应 i18).
    a7_param : int
        参数 (对应 i19).
    cookie_data : bytes
        15 字节的设备 cookie (对应 bArr 参数).
    a8_data : bytes
        ECDH 公钥等数据 (对应 bArr2 参数). 只需用其长度.
    encrypt_algo : int
        加密算法标识 (对应 i29). 默认 12.
    client_ver : int
        全局客户端版本号 (来源: dword_EBCBC). 默认 0x28004750.
    flags : int
        标志字节 (对应 TLV 0x3E). 默认 0xFF.
    sub_60038_val : int
        sub_60038 写入的值. type≠1 时总是 2.
    hmac_present : int
        HMAC 存在标志 (sub_601A0). 总是 1.
    unknown_4bytes : bytes | None
        输出偏移 0x2A 处的 4 字节. None 则填零.
        实际来源可能是 sub_6006C (type=1 模式) 写入的残留数据.
    sub_60244_val : int
        a10 参数写入的值 (偏移 0x33, 1 字节). 实际捕获中为 0.
    sub_60280_val : int
        a11 参数写入的值 (偏移 0x34, 2 字节). 实际捕获中为 0.
    tail_2bytes : bytes | None
        偏移 0x36 处的 3 字节尾部填充. None 则填零.

    Returns
    -------
    bytes
        57 字节的序列化头部.
    """
    if unknown_4bytes is None:
        unknown_4bytes = b'\x00\x00\x00\x00'
    if tail_2bytes is None:
        tail_2bytes = b'\x00\x00'

    a8_len = len(a8_data)

    buf = bytearray()

    # ── 0x00: type (2 bytes BIG-endian!) ──
    buf += struct.pack('>H', 2)

    # ── 0x02: encryptAlgo (1 byte) ──
    buf += struct.pack('<B', encrypt_algo)

    # ── 0x03: cookie 长度, 固定 15 (1 byte) ──
    buf += struct.pack('<B', 15)

    # ── 0x04: clientVer (4 bytes LE) ──
    buf += struct.pack('<I', client_ver)

    # ── 0x08: uin (4 bytes LE) ──
    buf += struct.pack('<I', uin)

    # ── 0x0C: cookie 数据 (15 bytes, 不足右补零) ──
    cookie = bytearray(cookie_data[:15])
    cookie.extend(b'\x00' * (15 - len(cookie)))
    buf += bytes(cookie)

    # ── 0x1B: funcType (2 bytes LE) ──
    buf += struct.pack('<H', func_type)

    # ── 0x1D: a8_length1 (2 bytes LE) ──
    buf += struct.pack('<H', a8_len)

    # ── 0x1F: padding (2 bytes) ──
    buf += struct.pack('<H', 0)

    # ── 0x21: a8_length2 (2 bytes LE) ──
    buf += struct.pack('<H', a8_len)

    # ── 0x23: padding (2 bytes) ──
    buf += struct.pack('<H', 0)

    # ── 0x25: a7_param (2 bytes LE) ──
    buf += struct.pack('<H', a7_param)

    # ── 0x27: sub_60038 写入值 (2 bytes LE) ──
    buf += struct.pack('<H', sub_60038_val)

    # ── 0x29: HMAC 存在标志 (1 byte) ──
    buf += struct.pack('<B', hmac_present)

    # ── 0x2A: 未知 4 字节 ──
    buf += unknown_4bytes[:4].ljust(4, b'\x00')

    # ── 0x2E: flags (1 byte) ──
    buf += struct.pack('<B', flags)

    # ── 0x2F: HMAC 占位 (4 bytes LE) — 调用者自行计算并填充 ──
    buf += struct.pack('<I', 0xFFFFFFFF)  # 占位

    # ── 0x33: sub_60244 (a10) 1 byte ──
    buf += struct.pack('<B', sub_60244_val)

    # ── 0x34: padding 1 byte ──
    buf += b'\x00'

    # ── 0x35: sub_60280 (a11) 2 bytes LE ──
    buf += struct.pack('<H', sub_60280_val)

    # ── 0x37: tail 2 bytes ──
    buf += tail_2bytes[:2].ljust(2, b'\x00')

    assert len(buf) == 57, f"Expected 57 bytes, got {len(buf)}"
    return bytes(buf)


def hexdump(data, bytes_per_line=16):
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_str = ' '.join(f"{b:02X}" for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        log(f"{i:08X}  {hex_str:<{bytes_per_line*3}}  {ascii_str}")


def log(*args, **kwargs):
    """DEBUG=True 时打印, DEBUG=False 时什么都不做。"""
    if DEBUG:
        print(*args, **kwargs)


def uleb128_encode(value: int) -> bytearray:
    """无符号 LEB128 编码，返回字节数组"""
    res = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        res.append(byte)
        if value == 0:
            break
    return res


def sub_659d4(data: bytes) -> bytes:
    """模拟 sub_659D4: 对输入的小端 4 字节做 bswap32（即转大端）"""
    if len(data) < 4:
        raise ValueError("sub_659D4 needs 4 bytes")
    return data[0:4][::-1]  # 字节反转


def sub_65a94(val: int) -> bytes:
    """2 字节大端序写入（模拟 sub_65A94）"""
    return struct.pack('>H', val & 0xFFFF)


def pack_data(hex_str) -> bytes:
    """将 57 字节 header 按自定义协议打包，返回 bytes。"""
    # 1. 清理输入并转换为字节
    if isinstance(hex_str, bytes):
        hex_str = hex_str.hex()
    hex_str = re.sub(r'\s+', '', hex_str.strip())
    data = bytes.fromhex(hex_str)

    # 确保长度至少 57 字节（到偏移 55+2）
    if len(data) < 57:
        raise ValueError("输入数据太短，至少需要 57 字节")

    # 2. 解析各字段
    byte0 = data[0]
    byte1 = data[1]
    byte2 = data[2]
    byte3 = data[3]

    # 4-7: 小端 uint32
    val_4_7 = struct.unpack('<I', data[4:8])[0]

    # 8-11: 小端 uint32 用于 sub_659D4
    val_8_11 = data[8:12]  # 直接取原始字节

    # 12 开始数据块长度 = byte3
    data_block = data[12:12+byte3]

    # 27: uint16 小端
    v27 = struct.unpack('<H', data[27:29])[0]
    # 29: uint32 小端
    v29 = struct.unpack('<I', data[29:33])[0]
    # 33: uint32 小端
    v33 = struct.unpack('<I', data[33:37])[0]
    # 37: uint16 小端
    v37 = struct.unpack('<H', data[37:39])[0]
    # 39: uint16 小端
    v39 = struct.unpack('<H', data[39:41])[0]

    byte41 = data[41]

    # 扩展字段（只有当 byte41 != 0 时才读取）
    if byte41:
        v42 = struct.unpack('<I', data[42:46])[0]
        v46 = data[46]
        v47 = struct.unpack('<I', data[47:51])[0]
        v51 = data[51]
        v52 = data[52]
        v53 = struct.unpack('<H', data[53:55])[0]
        v55 = struct.unpack('<H', data[55:57])[0]

    # 3. 开始打包
    output = bytearray()

    # 前置 0xBF
    if byte41:
        output.append(0xBF)
        header_pos = 1  # 帧头位于偏移 1 处
    else:
        header_pos = 0

    # 初始帧头（长度部分先填 0）
    header_low = ((byte0 << 2) & 0xFC) | (byte1 & 3)   # 4*byte0 的低6位 + 低两位
    header_high = (byte3 & 0x0F) | ((byte2 & 0x0F) << 4)
    output.append(header_low)
    output.append(header_high)

    # 4 字节大端整数 (bswap32)
    output.extend(struct.pack('>I', val_4_7))

    # sub_659D4 结果
    output.extend(sub_659d4(val_8_11))

    # 数据块
    output.extend(data_block)

    # 一系列 LEB128
    for v in (v27, v29, v33, v37, v39):
        output.extend(uleb128_encode(v))

    if byte41:
        output.extend(uleb128_encode(v42))
        output.append(v46)
        output.extend(uleb128_encode(v47))
        output.append(v51)
        output.append(v52)
        output.extend(uleb128_encode(v53))
        output.extend(sub_65a94(v55))

    # 4. 回填帧头中的长度字段
    total_len = len(output)  # 整个输出包的长度
    # 长度只取低6位，然后乘以4填入 bit7-2
    length_field = (total_len & 0x3F) << 2
    # 保留原有的最低2位，更新 bit7-2
    output[header_pos] = (output[header_pos] & 0x03) | length_field

    return bytes(output)


# ============================================================
# ECDH 加密 payload 生成
# ============================================================

def _generate_ecdh_payload(use_frida: bool = True) -> bytes:
    """
    生成 HybridEcdhEncrypt 的 protobuf 序列化 payload。
    内部完成: 密钥对生成 → ECDH KDF → AES-GCM 三层加密 → protobuf 打包。
    """
    kp_client = generate_p256_keypair()

    log(f"[2] 新 client pubkey (65B): {kp_client.raw_public.hex()}")

    server_publiv = """
    04 57 ED 16 AC E9 40 7B 93 C0 A6 6E B0 C6 7F 71 46 E2 B4 16 4F 6E 9C 7F 4A 60 3E 4B 6D 14 3C 2D 46 F6 36 05 AD 0F 91 4E 48 9F 57 BB 85 3E B2 25 2A 38 ED 96 8C 1A B1 5F 86 DF 04 5F 80 55 82 A1 94
    """
    server_publiv = bytes.fromhex(server_publiv.replace(" ", ""))
    log(server_publiv.hex())
    client_der_private = kp_client.der_private
    ret, derived = mmtls_ecdh_kdf(415, server_publiv, client_der_private)
    log(ret)
    log(derived)
    hexdump(derived)

    changshu = """
    31
    34 31 35
    """
    changshu = bytes.fromhex(changshu.replace(" ", ""))

    aad = sha256(changshu + kp_client.raw_public)
    log(aad)

    iv = mmtls_random.mmtls_random_bytes(12)
    _, plaintext, plaintext_len = mmtls_zlib.ZLibCompress(mmtls_random.mmtls_random_bytes(32))
    log("plaintext", plaintext)
    key = derived[0:0x18]

    log(len(key))
    ciphertext = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, iv, plaintext, aad)
    log(ciphertext)

    # ── Frida 获取 toProtoBuf ──
    from wexchatqrlogin.frida_proto_buf import call_to_proto_buf

    frida_result = None
    if use_frida:
        try:
            frida_result = call_to_proto_buf("com.tencent.mm")
            print(f"[Frida] 获取到 toProtoBuf 结果: {len(frida_result)} bytes")
        except Exception as e:
            print(f"[Frida] 获取失败: {e}")
            frida_result = None

    if frida_result is None:
        raise RuntimeError("Frida 获取 toProtoBuf 失败，无法继续")

    log(frida_result)
    hexdump(frida_result[0:100])

    key2 = frida_result[0x8:0x8 + 0x18]
    log(key2)
    hexdump(key2)

    iv2 = mmtls_random.mmtls_random_bytes(12)
    ciphertext2 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key2, iv2, plaintext, aad)

    _, plaintext3, plaintext3_len = mmtls_zlib.ZLibCompress(frida_result)

    aad3 = sha256(changshu + kp_client.raw_public + ciphertext + ciphertext2)
    log(aad3)
    iv3 = mmtls_random.mmtls_random_bytes(12)

    # =============================================================================
    # Salt 计算: Salt = HMAC-SHA256("security hdkf expand", ciphertext)
    # =============================================================================
    log("\n" + "=" * 70)
    log("[Salt 计算] Salt = HMAC-SHA256('security hdkf expand', ciphertext)")
    log("=" * 70)

    ciphertext_only = ciphertext[:32]
    log(f"Ciphertext (32 bytes): {ciphertext_only.hex()}")

    salt = compute_hdkdf_salt(ciphertext_only)
    log(f"Computed Salt (32 bytes): {salt.hex()}")
    log(f"Salt length: {len(salt)} bytes")

    # =============================================================================
    # HMAC-KDF: Derived Key = HMAC-KDF(Salt, AAD, 56)
    # =============================================================================
    log("\n" + "=" * 70)
    log("[HMAC-KDF] Derived Key = HMAC-KDF(Salt, AAD, 56)")
    log("=" * 70)

    derived_key = mmtls_hkdf_expand.hmac_kdf_expand(salt, aad3, 56)
    log(f"Derived Key (56 bytes): {derived_key.hex()}")
    log(f"Derived Key length: {len(derived_key)} bytes")

    log("\n[HMAC-KDF 迭代过程]")
    t1 = hmac.new(salt, b'' + aad3 + bytes([1]), hashlib.sha256).digest()
    t2 = hmac.new(salt, t1 + aad3 + bytes([2]), hashlib.sha256).digest()
    log(f"T(1) = HMAC(salt, '' || AAD || 0x01): {t1.hex()}")
    log(f"T(2) = HMAC(salt, T(1) || AAD || 0x02): {t2.hex()}")
    log(f"Result = T(1) || T(2)[:24]: {(t1 + t2[:24]).hex()}")

    log("\n" + "=" * 70)
    log("Salt 和 HMAC-KDF 计算完成")
    log("=" * 70)

    key3 = derived_key[0:0x18]
    log(key3)
    hexdump(key3)
    ciphertext3 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key3, iv3, plaintext3, aad3)
    log(ciphertext3)

    # 用 protobuf 构造消息
    msg = pb2.OuterMessage()
    msg.field1 = 1
    msg.field2.field1 = 415
    msg.field2.field2 = kp_client.raw_public
    msg.field3 = ciphertext
    msg.field4 = ciphertext2
    msg.field5 = ciphertext3
    proto_bytes = msg.SerializeToString()
    log(f"[Protobuf] 序列化后 {len(proto_bytes)} bytes, hex: {proto_bytes.hex()}")

    return proto_bytes

def hkdf_56(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    """HKDF-Extract + Expand → 56B"""
    # Extract: PRK = HMAC-SHA256(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand: T(1) || T(2)[:24]
    t1 = hmac.new(prk, info + bytes([1]), hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + info + bytes([2]), hashlib.sha256).digest()
    return t1 + t2[:24]  # 56B

kp_client = generate_p256_keypair()

log(f"[2] 新 client pubkey (65B): {kp_client.raw_public.hex()}")

server_publiv = """
04 57 ED 16 AC E9 40 7B 93 C0 A6 6E B0 C6 7F 71 46 E2 B4 16 4F 6E 9C 7F 4A 60 3E 4B 6D 14 3C 2D 46 F6 36 05 AD 0F 91 4E 48 9F 57 BB 85 3E B2 25 2A 38 ED 96 8C 1A B1 5F 86 DF 04 5F 80 55 82 A1 94

"""
server_publiv = bytes.fromhex(server_publiv.replace(" ", ""))
log(server_publiv.hex())

client_der_private = """
30 77 02 01 01 04 20 60 CA B5 33 61 DC 65 A0 DC 99 3F 2A 6E 9B E3 3B 01 1F C7 67 CA 29 44 D1 7F B5 48 4E 3E D3 B6 EB A0 0A 06 08 2A 86 48 CE 3D 03 01 07 A1 44 03 42 00 04 EC 4C 3E BA 7D 65 E9 A6 A4 7D 95 9A 12 23 71 9F BB 53 38 2A A9 9F 28 B6 11 3C 73 F3 AB 0D 75 8F 82 97 E0 38 3A B9 D4 A4 87 26 57 5F DB 33 5D 53 AC 3F 80 22 00 EA 14 E9 09 A9 BD FF 5E 2A 1D F2

"""

client_der_private = bytes.fromhex(client_der_private.replace(" ", ""))

# client_der_private = kp_client.der_private



ret, derived = mmtls_ecdh_kdf(415, server_publiv, client_der_private)
log(ret)
log(derived)
hexdump(derived)

changshu = """
31
34 31 35
"""
changshu = bytes.fromhex(changshu.replace(" ", ""))

 
kp_client_raw_publi_hex ='''
04 ec 4c 3e ba 7d 65 e9 a6 a4 7d 95 9a 12 23 71 9f bb 53 38 2a a9 9f 28 b6 11 3c 73 f3 ab 0d 75 8f 82 97 e0 38 3a b9 d4 a4 87 26 57 5f db 33 5d 53 ac 3f 80 22 00 ea 14 e9 09 a9 bd ff 5e 2a 1d f2
'''

# 移除所有空白字符并转换为字节
kp_client_raw_publi_hex = bytes.fromhex(kp_client_raw_publi_hex.replace(" ", "").replace("\n", ""))


aad = sha256(changshu + kp_client_raw_publi_hex)
log(aad)
iv_hex ='''
13 DE 42 B0 0B 08 D8 DF 34 0D 45 06
'''

# 移除所有空白字符并转换为字节
iv = bytes.fromhex(iv_hex.replace(" ", "").replace("\n", ""))

 
plaintext_hex ='''
78 9C 01 20 00 DF FF 1B BA 85 1D 35 99 33 2A C5 4C CE 80 9B C2 EC 9B B2 D9 D3 D2 6B E6 6E 5C A3 A2 74 E5 BA 1E 87 F2 11 82 12 20
'''

# 移除所有空白字符并转换为字节
plaintext = bytes.fromhex(plaintext_hex.replace(" ", "").replace("\n", ""))
# _, plaintext, plaintext_len = mmtls_zlib.ZLibCompress(plaintext)
log("plaintext", plaintext)
key = derived[0:0x18]
# key_hex ='''
# 72 55 55 A9 C1 84 10 8C 50 06 CA 25 C6 07 70 C1 1A 01 C0 2D 8E 2C 06 CE
# '''

# 移除所有空白字符并转换为字节
# key = bytes.fromhex(key_hex.replace(" ", "").replace("\n", ""))

log("key")
hexdump(key)

log("iv")
hexdump(iv)
log("plaintext")
hexdump(plaintext)
log("aad")
hexdump(aad)
ciphertext = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, iv, plaintext, aad)
log("ciphertext")
ciphertext=ciphertext[:-16]+iv+ciphertext[-16:]
hexdump(ciphertext)

# ── Frida 获取 toProtoBuf ──

frida_result_hex ='''
0a6a12240820122004747d5aa95abbb5653babd201ff3d7f2317e4085c4d10e70b2a41d5bac0b2da1a4208c905123d08391239042e50c206916c02ae1e21b543e23facbcc5aa3209a735ab930e3fae64a49f928352a2875e8549810a9cc70887922be5fc427ea29a4c1256fc12ed4d0a340a010010ecb2e39af8ffffffff011a104132303532393433646133623431660020d08e81c0022a0a616e64726f69642d3333300212280a0408001200120c0a0012001a002204080012001a040a0012002204080012002a040800120030001aa402089e02129e020a240820122004747d5aa95abbb5653babd201ff3d7f2317e4085c4d10e70b2a41d5bac0b2da12f50108ef0112ef0108a84e12e301bcf79a701ca3f1201ca95d8b9f9a89346dd53f4bce840ee03956c7e5a2a37228a6edc71007ab39852652911e034d0a06427ecffab86799e8e471ec498751c5e9cf7e67c609879c81d681b7e5a98fe72d06c2708c06ef997ab1425fd6da0e4b68e8412b4d5d6ad5ec1cadf656f759e3fcb9cc57e165740143f8e1d9b84f4534f75e5f3805eccf95d0b2ebc9e61e3b5c61dabea23c7885c0c8bd6285362d70594a3d6ceb6c20e1aa6e5694855a11dc44ba5008bd49dfce729a690665a720e7f8787bcef3fd25d30ea374f02e05b6f80bfb763155a439338409dc21cea3289253be99699d18acb78cca072210313233343536373839304142434445462aec0a3c736f6674747970653e3c6c63746d6f633e303c2f6c63746d6f633e3c6c6576656c3e313c2f6c6576656c3e3c6b32353e30376532376365356264396339646433363061373737336331373738326433303c2f6b32353e3c6b32383e38376365356263343c2f6b32383e3c6b32393e30633365373264333c2f6b32393e3c6b33323e34332e3133372e3133302e3231333c2f6b33323e3c6b313e30203c2f6b313e3c6b323e342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661352c342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661353c2f6b323e3c6b333e31333c2f6b333e3c6b343e313233343536373839304142434445463c2f6b343e3c6b353e3c2f6b353e3c6b363e3c2f6b363e3c6b373e613366616266373966353333663933373c2f6b373e3c6b383e756e6b6e6f776e3c2f6b383e3c6b393e4d323031314b32433c2f6b393e3c6b31303e383c2f6b31303e3c6b31313e56656e7573206261736564206f6e205175616c636f6d6d20546563686e6f6c6f676965732c20496e6320534d383335303c2f6b31313e3c6b31323e3c2f6b31323e3c6b31333e3c2f6b31333e3c6b31343e30323a30303a30303a30303a30303a30303c2f6b31343e3c6b31353e3c2f6b31353e3c6b31363e6670206173696d64206576747374726d2061657320706d756c6c207368613120736861322063726333322061746f6d6963732066706870206173696d646870206370756964206173696d6472646d206c72637063206463706f70206173696d6464703c2f6b31363e3c6b31383e31386338363766303731376161363762326162373334373530356261303765643c2f6b31383e3c6b32313e484f4e4759552d383130322d35473c2f6b32313e3c6b32323e262332303031333b262332323236393b262333313232373b262332313136303b3c2f6b32323e3c6b32343e61323a30393a32653a64393a65623a38363c2f6b32343e3c6b32363e303c2f6b32363e3c6b33303e57692d46693c2f6b33303e3c6b33333e636f6d2e74656e63656e742e6d6d3c2f6b33333e3c6b33343e5869616f6d692f76656e75732f76656e75733a31332f544b51312e3232303832392e3030322f5631342e302e31312e302e544b42434e584d3a757365722f72656c656173652d6b6579733c2f6b33343e3c6b33353e76656e75733c2f6b33353e3c6b33363e756e6b6e6f776e3c2f6b33363e3c6b33373e5869616f6d693c2f6b33373e3c6b33383e76656e75733c2f6b33383e3c6b33393e71636f6d3c2f6b33393e3c6b34303e76656e75733c2f6b34303e3c6b34313e303c2f6b34313e3c6b34323e5869616f6d693c2f6b34323e3c6b34333e6e756c6c3c2f6b34333e3c6b34343e303c2f6b34343e3c6b34353e3c2f6b34353e3c6b34363e313c2f6b34363e3c6b34373e776966693c2f6b34373e3c6b34383e313233343536373839304142434445463c2f6b34383e3c6b34393e2f646174612f757365722f302f636f6d2e74656e63656e742e6d6d2f3c2f6b34393e3c6b35323e303c2f6b35323e3c6b35333e303c2f6b35333e3c6b35373e333038303c2f6b35373e3c6b35383e3c2f6b35383e3c6b35393e303c2f6b35393e3c6b36303e3c2f6b36303e3c6b36313e747275653c2f6b36313e3c6b36323e30303030303030303130323863306531653730666565303637653032653966373c2f6b36323e3c6b36333e413230353239343364613362343166353c2f6b36333e3c6b36343e62336434346137622d383864632d336430622d623165302d3331313732386462646465623c2f6b36343e3c6b36353e323131646663323364663664623366313c2f6b36353e3c2f736f6674747970653e30003a1e413230353239343364613362343166355f31373833393238303731303230422031386338363766303731376161363762326162373334373530356261303765644a0f5869616f6d692d4d323031314b32435289023c646576696365696e666f3e3c4d414e554641435455524552206e616d653d225869616f6d69223e3c4d4f44454c206e616d653d224d323031314b3243223e3c56455253494f4e5f52454c45415345206e616d653d223133223e3c56455253494f4e5f494e4352454d454e54414c206e616d653d225631342e302e31312e302e544b42434e584d223e3c444953504c4159206e616d653d22544b51312e3232303832392e30303220746573742d6b657973223e3c2f444953504c41593e3c2f56455253494f4e5f494e4352454d454e54414c3e3c2f56455253494f4e5f52454c454153453e3c2f4d4f44454c3e3c2f4d414e5546414354555245523e3c2f646576696365696e666f3e5a057a685f434e6204382e303068007a943c088e3c128e3c1a873a08813a12813a40e9c898d3f5330a0930303030303030320010021ae039829985d70fe7e27603b64bf0f651550fdd201b2724316c4e3b77e5b4fa1d2b48ddde1fa71d5d64086539df69464efe1beef9b87c1232ae2b9215415181036daac4ff8033ac6c146a2663d2871e4a19ead5ab56a9f0fc03c2a4cdfbd581573f76574a40c5a9aeb2c511aff2c2376c3654985874b988fed04f213c8cf9c9389ca9961abcde8493dc038aa467f903d62b70d48165757325b4e6beb1b01d00abc2e2a30a643c2dd2092d77307a8feaab180ebbbd87d8fdddc93ea4e5cb1c42fb9c80b707b723ec254cc7999183108747a98e41c24f01f9711677d3f8a6d5047a964f9857370edecf240b4c8ced923b13cc6aa89aa7d55e525b04a89e47b9f9ad019a8ccbb5489062bf61a4b758c1a01eb1f92c17f6aa36972fcdf0c7846f01b2a1acdded7574154690621fa5069ac6ea87ecfc24178b02f60083f2ef78f77ba3797ba5a2906d020cd84666c902743e30e0f922d835d5f7ef1ed8f3ef0a486df26f0568e4e38c819024fee12168de3ebeb2f11eabbb5fa8e53f16f7075cf8c9f025bed8a20ca1004620a1dc19f13e0a9fc10eddaf20cc57e4253bff59b0b2f3132d16a8f3aca628d603b63045b8e4a2788053d7e39cd7d78580e0e154426a4178bdd2147dda47f321d5c10163e269f51d321480687e08e58fb7643f95c62218c4389d26275326f87375b21cb7cbfc8412edc6f176e57700a7e35ad9cb4b3594463a594af0ebe9b5966bf83350921edd0382cc8c020a9714f5a645ea21dcc968b6284b4969a0bae1061c344c20aae2ead39ecf8f3d8754779115c31ad755be99c2f2d52186859114cbb78fad6d86b72f4587496df61dcc3444569e748a14a89e34bb2a33ab76b4034bc8054fa829277424481b161d07dacc72bd96671aa175509484ae49c6a01397689c9d6c6ee7211ce712f7a1aaa2acd3550512d947a891b396d1c81ac71f8a031bf4212f6578def49b1c8f20d6de0dfbc422ad90bf404a6487177cf4df233bd111cf2d3bfdcb41be676f24d11f5442f6473c894ea57fd3591cb45364794aa7cfe122912519410cfe0cedf5959802e220890056b781f7a5be3fbefc4d3d8468963383ed84fc83f2533b667f8c849c6151788191d2fe4eb94ab3e489dc6dcabf4352f45078725695e9c804f561f74c2748a33565b1e46c74136b689fcf0c4a347523dcbd7e702c0e6e25e7b5c73d31c51d596e4d88b00388f8fafab6916187a2d7859b76164c4bd7265bdd8dc6ed82eba42606d3b595ce7a2c09b8c81c23ae18b0de257e925c6739d892c98ad489217f1c6f9c9ad598ea70b22aa7908e709978a61cb6c445d07871ae653eb6b626f908508848754ee6929020194770ea1b1c3601966652d7f10c09e96c6a1c513a7066c525ef8e280d0ab776d26e1f9233c623012d81b8e35d1c8f05038140eb0040f1c2f5bd0f8790eb17b373357fe7eb0222ed598df9403a92fc2108bea39549ef958ae037b2efc8c07c19424afea1ec2390d3366566be3c45de1ff077af27c3179ad070a19e8402432a2363d67daf700cb2bd8e64d6546d0991cd05aa835e469e643a928656341da51c9c4a6f6213438d337019f9da37547d99bfe3f4a47f0858a0fa6325c2ea719d9bcf084eebb5d984513a74c898f6fe343c23270488a68c0500f0b06c353580841285ddf31b2af6f8923b67ac44091113fb6026a2a70eab472f96aab55f758da258bce7cabbf36fc29078cbe73e01f4b4d9e8e76e0b6bd24948332aef2c7c77753108fa6179a08eaaed9b32c1fa7ee3cc0c5412c8f2b79afe1f08f34c5177c13ff4691b704311f2e5d184da1bd63551761018fe9fdb509f76f9dfeebdef60021245e31399301244e44d42b5914ab56e2e64c62c9ea4a83f2f7f2536874554a895e2730f989b908fd1af2cc2c16a27a51ba6e6e0c99c831ad17db7558bbbee735e8b2d1a97a1d17830273b8039599c3205e66e57a8c2dda2e4442507abf5427aa4dbf8a40512e2d4811a33a470065bf808f47cc2ecf245a6bda976b8ca7eb9662e816777228d410affcf968a54926a842dec825a7f12b7e8191fedb5284c2ef5777e13004da0358ae0a126d0f134aba39c94110c9b0312e98b80e5c81b149abf81ccf1ea022cd8be2ec907dd3798563d3073480f3956fadfb450d465fa3290f918083111ff6b29f5e02f3fd0d24a7572a2f77cbd7a93e0790e943fb13db6c08b804264778cacd7963e984fa9f93fef1418493d29c6427fdd5a0c16e4208c63e81e032c268c79253d78ec0cf71f0ef19079cae547916f2bd6a92876cd5ebec044ccde77683844743431dedc736a3df2e5fcb91532539b5bda8baafa94ef558bfe6188429b047422fa6e32f11ae9a20e8d648bb1d31461054147f188c49290ab2c18483e32ec84e968ce9ab4842cf3a513526bda1a6ff8fbad0709bfacdd2b7b749064d0108aa338f563008697386c0a90232590d3c62f129a107b7bbff0baa8c5820dbbbd6c6237dddbcc87d70e6a03fffd7ae712dc846c2e58786df584dda21cf73a2c67c60d8a3fa90aa152043723d7a559998f4c8745fd0ca98526cb413e19174a14d27436562dc0721274ae6538caf81e34811775409f2a2dd0641533aeaff5bbecd851df38240380f662687709579a908865cda56c29cd705d2d9b9c690a9ec9ebb6cdf05fa579d199cb9bf15a3908e3b1b50015e6b48ab86ccd82762e8ac844ac58c79ac2a5938c2e361ba164cfab5102d839dd5e03df89481a8dcce1980c5120d02219f0b893b9ff77fd19729888fd3eab8777f6a5b9c7db65abf4786a246106c3132967d070e9e8d33c9728fb03b2677adc0006c7a1021679e194cceb14589c9c2d2c0757ee7f6e489db0d27480348364942f74a5036c3c2b01e19a18f0ff95d386e895910234ac6d9bd27b60b8719fdaab429ad7baae270bb4127a76b3db6d7733306bf96784590cbfa1caa60f87238f903e1c47be672ac97c7930c89b94df333b8e404a0511835dd00c82f4ce0014bf074286d8b3d88484ee5bdb413d1b72f5eee409504c4b11a1962ce9614160c3fc53714a3e576a5a1ca3a28620a131d117a764667f739b9ea63024ad169e2639e10d8107403ee8a4ce25338b91b8ad19a528c4c0cbc05646836567d4f0ef047952533334023f24fa57b3bc901ebec7223729869af2fe6817b82db4c0fa8025e14c376de9cd83f9e17201f990f2c0bd1922a60f746025f4ffaa6b58b0bed9899e62fd37b85f73396f792104df4f540a27977a62d11f8069305099f7c71dc005864801365ef2987b670c8021c82fa378b139224938a74f0f95a1b7819f0ed987bd66f5bf2a2649686a4d07726a19a6baed685c1c215d9d2d50ab5c76bb204da7f336d5d684d416d96886d77f9b79a90b1a823e56315e30d1807e31c5304541167674fde896b1c08eddb5656456d808a1b0b10a267ce72b2117fdaf91b5f233a0f54a378be90dad8cab59e5eeecaa5d8fc0ddf936a8ead859fcd5268dbcd57d2032025dfe6033071e12d874860b9dd6f7079f9614295899be1b487542dd61690c06973b60999305a0a83829884e0f4c4b31a5301ebaa0a3c419ddbd034c63960b5cfe85f54421bdbea3b9a328fcc9bbf17cb222b1cfd026d828a124cc46547bc8bdf0a0c6946780c3f335bcefd95dfa969d7004f9387e26fbd385aea9ad4bce72446ccb80d9244277e0ccf91c61d9fa50cbcb8cc036a0bf9f47fb5eadcc0ecde8bc5484959423d43a94af50bea08d4d925260c214ede96e77c99955884ba89910d11d28a096f2e2b34fc62b2953071e0e718ef22828d5a3adfe487db2d5247bcaf0218ba7f19b0280cea1ac9260e35f735f437b2c4e2418c1a8a07ee2586b0e2b1245340684b1c4edd97dbccf98b21f7db21eec82b94a75b0867c2365a74ef7a98cedcc9d3eafbca18eae53d0e829094d6ca6d0a6eeec2a6730d36e90726fc24f914f840bf113f28a73f6cbeeb152449f5161ea3a1fd9981f8d5fb3d7dc17c6c9151c3779d0d18ac9e86652f87711fdc62680b7bf427ac68cf0b611528ee9f43d4160bc4f3674b449349ae21dd0cebf2dbe45276277dabed8e829d9b0bc370f519259d7cc8294b5a9a7d74b1c1160c68227e22309a6069ce490569176dffce42d45b8470939b79d578330b44bf138d7ad9f680e15aace275031e5632eca5306a8ae765f997a89fa763a614e64378fbd204237b9f40d26e50ebeaf2cfca95cc4e4738c51115abb922cef054d9af9ce2e21a14881330e488f5443c0955d30ff0474dbfd6745e3a576e24c3d0f6ee6679e58d9efa3b391851b0bd6f312055c73f42cb4c667cf96e7c9fdf4dbc86a1b224ff98d9be9fdd688a4154386284648a057809a4477d78bbad38839a80f05f756ae003fd0c463f5e339d010c6c53a7e4bfbeec3271105d52de047cb5771b52c0b5816c02c7301e80d97b5a7a203e8f3b77df233d2505d2dcb261fb5fae26f5794c505aac8b30de3352226c99517a3530fdfdb8b37fdb3c8adcdacef8f5007a7d3198f4af61e11e81c4775adf2b9f08b45f1566fab4911775783f77d29172cc630d30e64cee0ff1bd5d816efd00ebc2dfcfa8d91911314423561fdb9b4176ac35f40ec887c28e18306a5fc34d94b81d256513ff38298058b3cf736638958c839712538fa5e71edeeac7853eb68d78532e26f94f75371d9e7e7404364db3e87a4d2467b0645820040226faad9999194d7bbcc8b97011f50f07940cfcc65267a4950dbb43be7a6357a7f56e56238a6e2962ceceab5fc2fed443078ec97f2c32ec979618f1f0723bcc14e36f873df10853efb873d6833052a4acee24429f668e05d45dbb173bd2c66fa49d810b4a3b954be766e7acf6bd8c53d720ad3672256127ca550ecfa2801233179e4050ff1189c462a845e9982732da18b86b0ebade4c1cabc938c8e6fb2ae374dff1ff3e6a5933bed0e2bd6331e626a77cc9a36c8b545102c882a61f74440129c2936313bf2c48f3ea38d7ad0d61464b2d4184f6100a0ef9ec57f62b3a40ea539aa16c4a07b2c3d70feafc1d46bb2f8a1281641d20089e88eb255de0b25ffe533e73beabb91136b2875fc32238b51c207d7923b131e567c6565d8e1a1a09bfe0544ef88b533e2baa885dfcbb047df8ba1b1c955fd563c443afa74471a82c0f86d31d753d7ea9041c96fa4976c0a92835314211c0528f63dcb3ba4e1d112fd37d5f4b2a40ff7cf8e45504365fcf309c08793ab752cb198334abfdd9214f2237028efb81efc0cc0f7ec02222f536b4218d067fa3b91e591016f5c5cb68f25b25ef401cb42c844677e059053b20e331751404f411ceb607daca37ddd2a39a8477ec4aa519b5773c374bce904397b6807370ab8828326e6d75016d7b40ef9996cd9122b5adfb91f4b7c20134870ba3de6f1b3a98179c6559cfd8b75a6be4f0a5e83cc0e0a964536eb5b5b68a5a5e82a0b34483c55d968c5d3eb6a7f350e043df5ffe4a8e8a8f6f44a2aa2f15dfc4cde1a22d42f4e6fdc0ea02bd5875b45632347ff799334dcf293469ebb8d9fa1a5ab4e59279a979bbea525659ad36af72948d9e284c9e6a955d4073ff86809daf4cdd71bde97c4cd2b0fed24fef21ce3e498efb96ce2a38bf4dd2fea26ab3a6736625845a8af4346b65efd18f14cd9971cec92abd4465feeacb4491b4e692c69c2584c24a4ba1abbbaa5f875cc6291cd2d1b7fbec96af920b9aad5e66b4bcd1e08fe50997ced1dc11675ec8b1dafd1cba47fa3a71f244121c6364f5db48b57e5ba2a9099b387ff9cd793f4805edbe7e9b67e9a0287810356bf1230c1565a34182d6541ec73a910129b905335dc534a87969737e2375914158d84c60dcd39b3388687010ac2147c3bd77df41819be10acd5b82fba5f910010f92bd658bad901d0d216ac64f27ab56c8dbb8e6af4064f3e4d2ecc9c9ee4c79a1dcbc41640c4cf3fa44d3a27f43299edfe8d73b580266cc6529718cf6252113dc5b3789cc655c375dfb4e6fc2e57458bb0d76c5aeef39594f92579badeaedbe12aca0c59b0a6b4ac193e4162bf912cf70e6ddd6baab7c75cc693523ed18244ba90309e356e3327a8ffa9de17a7788943d3a1f9f0e1a454761af3e67ad815ee40e6a1f804503911d34050d0237e4c7b274f0078d02cc3fab70a2f61fb7ee1d0ca5620f303e4ca7cbb9dc8aea55fdb136ce501684557e567660d25d04aceacf1674e85cda8350be97e8b09342c98a43ad55c6fbb748cfe08d1ec56d03faa3d6657ac26f1daeae16493e76cf28a355ff20f9a967b1479a515571aed9e28f9e4e8cad586c82e3d5a2fc6754f8ebb28c3e9f443473313d587aefa9eccb8f91018e6572d299e9086e39079d13e9040167c5b5b98b710a74c91ae8cde3d38a0e73a2a623d0448ce651dbb8ba7b84e1c6844e4700313b4d091126d39cdf8b6f548fb555750546efb0611a9c8ee3a9e9a60377c80ff3a83289ba42865411a361f7060301ea525e44e77bb1aa4ee768aee2549f21bc9418dec40a3662a798d40d4d0b8bb2965ff539ea78bf874600e305d6f3ca3ecaaf841022ab1f792a23d85050637f605ccef56fd451238869c40dc6143833936f2baed1de489660aa0d13971bf0aa9130d196af64856d893951231d70625b49da94b6685868f14bdb027b4d9f567aae9ad3ea4585fae9cf19ba6b95ede3b6d097011a431d7133c5aa9a1616b5a024f53250ddba98f662ecb81a5726e44563fafcbc5a911537ca4a24fdbb38b82c8564cf2c99618a3a72b1a53fc7a0e28bc1504020e326ac63dec802a283308f887cb417c25b76be4e2db11be9ee3bc32116b39e679025f4d6f7b4ab61c09709197fdd7f21a77d05aca81bcb968407181a619cd68ca11d1220f0494d542734f92ac79b52e770d4eff32a0b2970ae67c1d4f9fa1b6499a08f2621840450ac9cbddf44e348cb8683956cf91156ef1859b5b555cbb45a53628d406d48204ebdf45bcd33632ae0b461be7ed9167eea22fddbb83eaec786c093d7085e237a7b1a8acd4ffec42b95d59dba15c56c777fc305f7a9ef0775f3fbce3ff2bcadd96bf25f89d0cff19f94b6c05b46d81f278e51ac629cef6fc7ed7a282601b459c889d361de08de7888a22a2542d8d463121ad5c827481c33ffe2eb4b81429c80f830430f9394cc05481a358e490df561fb0bd26194c94a197bac8ba2b8880ad14fd18693e55c417e4aae2e03c86c09f18482848bda6d0693f4fad3b68963bed44f381e68a25d79a815209a8fabd37312af00092cbfd0fb4584e943a949948beffbe2ff456322ee5e5de95bf5d3cee7451f22abd0c55c5013f871843475f4dc1161bdab8f9240c6ba2bd4d8bc166e4df0e8eade45e0afe00c302351a4314c1776a8afd0538bc52eb7c92cff7068c6d4a433296b28934754679ce8cf19df45e9194a25e816a03898d21a41d4e334de1e9f6f0dbe9e855dde9ac60bbb5496414b15460063d72e9572128256f8f1681df85a0cab03e2296c2f70b385b445518fccf25f261db63f09ec3da2ead15d57b72781437240b1d5942be144c8f0d78287d16192a148c58fcf45093e589e0eb252a48b204e754c3bf10ba71156a8d159476414fa9f4052a4981c22a71c1b8b10b29a6e52bffe3c019927f99f7dd23f5def441948babb9650950654dc9e1d6f6ca2d0b30ff780cc84604d256df5302b76e669d95f6557884d130fdae89748b3fbd5a5bef6e90ec61ee0a46e6a357987a487119d3db2b978ccdfb4f70e23a8a6008df1b2394d2b2cf7c6a2306e11b563600c0f422298d474afaded8764b82aaa7f3fb998f210983143e479e287792253db1d75adef536652f31918126206cd1ed110c50ad7e91a717d8cb9e3525b9a664cb53d656fcac8043bdb5f326892660dcdfe487c8f6cf63be8b07b756a003817062e05fd52ded221946a947ed4c7b00f0170e1ce6384dd8998c4a12032fbe6101b4dd3e19653a1cd7f559e5180a5ca9fe16bf14002cfadc7bb51bc50ce93689f9f1c3514ccd9deb38cb624fcb28f44eeaabb19d30739a14493b6e73da8790d0f884d9bd20486800b904832b3d7e63dad721318f3206c6d40f11a47c7d73ce3e80b84bbe6f05a8b3b14ac86d24f5778a7bcea80ff8a1ea3e93017e4faa40cb0c9765e3850a2bef0c1991f1d7f0e95b5f82e18278d2dfdb88af41f7a150f9d94e2f5e6935ebeb347717dcfb488546b9bd3dc824aa35dbdc7aad2af80fce0ec4f14e6e291ee813a1493d2ee073fc67cd2ad9da8e504c03e51a9d6668c4fb342d8495bf62604c15f3fe5d91f2de96d14b760345744c2607eadcfb5d03a4a7d5ed9dfca62f4c5c41965244762e3106017cce230e8c11248d281a8ed57de2e517b69ee2adad8f3fed48a5eae7e7970f93f16595d9e7ae8ba396f6d44aab63d8b22f3ef24c9545b3fbe99d9f64e50c093092c96b5187a16b96d42a1e3ff77356820313ed7f1a7a5c9ed5103554607f8090f5010b1dc3ed723ab4f711beff9f2a2b18d7c5cd03f1b80769886bff612a40724d5b26ff09ee0355d1c4b16f8863ad1e983b9ded9fda0c33399b91223f9bdd03831710a7db6ce6d0fe7696b8922e13f251afc9dfbc765a3eccf10741fbad4aeab780344b2ed78eb48eb170ed007ace54c25c00608ef29719f8db362bc4c52bd77583921c69f8a27eeb6b3be026f9f4959932033d90e0c768653734a380c6fb8405b66eea2cb1b33d29a91d78ac7c4588d5e229c943ace254b8f0a8c8189f64bf53c24a26d02e77091b4f7c548e774f7f414125002d741d3296f75f0df38a183af0142e78186234d6ffcde0f3170cefcca69b495e27bb39ce629cc80ca6df6a39b4f5d3f4daa6a532283440fd06b32830bb2abab1f2e2c00bc1fffcf472a972a0ff9d259cca646b552aa455d8ed849a3bf62b69a33cd1dada1bcdf6c77a7475cea076cef7f8044fb1b39bd28ddbd84749df6ef4af4fa6fdb570d72ec6a30bc65ae3e0d4884d75524b247dd4fb8cf1699cdb60769436f3fddac4dafe54b5272472a9c4dc072af0dca48ff5b2f9b8a90f9822a53b9fc20c664f0a8aa67b6db998747f1aea30d82e15e0af675c92f9e1d77afda02be2b747dee6c5575437ffde37252b3b57955870366e399a16b50064e1317b3f9ccc9b404099f6c57c875ea49a91f19754c615d2b738b64d038c321b0e450881ea636690aae8f05182b2dd78403c6818f7be74be1a12ce0a79aba09db6318a9e78dc9054c4b1b25c69702308e95013495d7231f17f7d23475c83dcd778aa6efd013b28f2d5d910edf65e0b050b862063fab3da3edb7411b3d25d348d1be28c57f77b5f8cb4580efbe39f6bd566a41c84cfdd2c8b94c161bf226d2ebf3b36c3810fc1891603fd9d7c6a7e989f5e9a4308ac2b3b227fe787d05d6459aac9b0b68d4f1070badae141d0bd58b6ad8b6de4b36404ff01a26d028265f8dba521c3f0fe13d1e636d3186c82b8b7b3b0141dc4ce3d88ab9238945a43b6adc7ab5cbe08c944a311d597cf394745a00d5233d4dad1a3582143ad1f9e7ee6d9d1e6acf268c4a32d68685c7c3509a09d538784c5590495570afb9c9f18fb181136a9de8e73c0b08bd9e86200536f7dab4c81daeb61c4f8662952cf9007bc878d65502c168d04708ccbfbb539d3554cf9d2d39be3304f68d2cc91a3933f4efc523ad90636080962792ae915ffda4c4ec52d85c99a56a8de0c283337c0a53d4e5e00719bd225d4c10baddc3da9366eb0e529d75fab891b00cb690b6e3e8f506e6f7e3d1e1ec71a4bf94d40b503bc0e6a8e74c90784acc49284531b40f80d17ba6a93faaefcb6d38e0614cd5642ca16c2dc577a57ea8f75375afd0405246770c9cca9c067b5cb2a88134b8b30d54b39102a9cf881745d9b43d8562c523bf54698e03d62c617428af88c5de0d8592ce033752cbc212c59948bcda03575c0291355c7e0254654b330efd9689075039e195a77f9ffa6b35d93ed1220ce6a9bae001ae051618b05f6f55b58ea4b956044b9301e2bde6b7fd21ed42d32122626b7a3cafe9aee6b3b8b47d12b9281138a9de44aea0cef097133ef99bbd55d9deeeb100751077e8cfcc9099043370e31a5e46220b17c2ab0c54892c683a2d68e18e8f61ce391be7fbc344630f7750610c5bf3ed2a52f70c80e16daaefc7f2160a7fc9145e7feb76ac9bd02bf0a1969f4b0eb44bb2dc6e8e2fa17a81b344f086b730399d388405c5821821f18bdccd2c3e6c6481910bcaebbb2bc9a20ef3b25731e17f3aed7dd56044f60d885009587baa5e7458b9dd61dcd150e66055d417450fae8dc980ead542c7ba9cff8aa639ead16af72685c1e56f0ba0ddd7243f1026075a9fd04515b58440774c216929e94d820552c26409164219ddada29da08b85f68267f484843a502bcf600874c742d3d10975152dea8ab1a580f4415a7e134b364eebdb5b8bbadc7ef25394592c543237252db2087aad2d206280530003a810208fb0112fb0140ebc898d3f5330a0010021ae3010ae00130303064323233643365303430303030303130303030303030303030316534326235353164326666626635306666356338613162346536613230303030303030666338653634326362356234393164386130356135303034643439636638623935326331623831396462316464306666303039623032303338613664326163383964626431343764333430616134383231343738663930656630383439623437336537626662613236313263366365626662633730383038643239356664363065333333383939356538646366356365613739633763633734336265313633612087aad2d206280230008a010e636f6d2e74656e63656e742e6d6d92014a089f0312450841124104727cde01e585cfba8f7a50124bfd6225afe281e1d047f618a718af7dbd86f88955d641a2a430c04e8954cf8681bf0ab3faf3d93e82278d3040040b31b5c11639
'''

# 移除所有空白字符并转换为字节
frida_result = bytes.fromhex(frida_result_hex.replace(" ", "").replace("\n", ""))

log("frida_result")
hexdump(frida_result[0:100])

key2 = frida_result[0x8:0x8 + 0x18]
log(key2)
hexdump(key2)
iv2_hex ='''
63 D5 8C E8 EE 9F 95 7A 03 60 24 A4
'''

# 移除所有空白字符并转换为字节
iv2 = bytes.fromhex(iv2_hex.replace(" ", "").replace("\n", ""))

log("key2")
hexdump(key2)

log("iv2")
hexdump(iv2)
log("plaintext")
hexdump(plaintext)
log("aad")
hexdump(aad)
# iv2 = mmtls_random.mmtls_random_bytes(12)
ciphertext2 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key2, iv2, plaintext, aad)
ciphertext2=ciphertext2[:-16]+iv2+ciphertext2[-16:]

log("ciphertext2")
hexdump(ciphertext2)


_, plaintext3, plaintext3_len = mmtls_zlib.ZLibCompress(frida_result)

aad3 = sha256(changshu + kp_client_raw_publi_hex + ciphertext + ciphertext2)
log(aad3)
iv3 = mmtls_random.mmtls_random_bytes(12)

iv3_hex ='''
85 a7 69 b7 41 c7 68 81 10 61 34 36
'''

# 移除所有空白字符并转换为字节
iv3 = bytes.fromhex(iv3_hex.replace(" ", "").replace("\n", ""))
import hashlib
  


# 使用例
salt = b"security hdkf expand"  # 20B 固定常量
ikm  = plaintext[7:7+32]
log("ikm")
hexdump(ikm)
info = aad
derived_key = hkdf_56(salt, ikm, info)
key3 = derived_key[0:24]  # 前 24B

key3 = derived_key[0:0x18]
sha256_de= derived_key[0x18:]

log("key3")
hexdump(key3)
# key3_hex ='''
# c7 a8 94 0e 24 b3 d3 c8 19 02 d9 90 67 08 ae 47 e3 6f 9d 0b 6f 99 3c 9f 
# '''

# # 移除所有空白字符并转换为字节
# key3 = bytes.fromhex(key3_hex.replace(" ", "").replace("\n", ""))
log("iv3")
hexdump(iv3)
log("plaintext")
hexdump(plaintext3)
log("aad3")
hexdump(aad3)
ciphertext3 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key3, iv3, plaintext3, aad3)
log(ciphertext3)

# 用 protobuf 构造消息
msg = pb2.OuterMessage()
msg.field1 = 1
msg.field2.field1 = 415
msg.field2.field2 = kp_client_raw_publi_hex
msg.field3 = ciphertext
msg.field4 = ciphertext2
msg.field5 = ciphertext3
proto_bytes = msg.SerializeToString()
log(f"[Protobuf] 序列化后 {len(proto_bytes)} bytes, hex: {proto_bytes.hex()}")


_svr_pubkey_hex ='''
04 59 60 69 0e c6 17 58 24 ae 76 03 b8 f0 af 9d 34 bd b0 3c 48 68 cf a3 d9 30 32 67 11 4b d4 87 84 24 72 ac c9 75 e5 7d 6c 72 82 bd fe 7d ae 32 72 73 9a 5a f5 ed 16 ea 70 e2 9b a2 b3 e9 28 a4 b0
'''

# 移除所有空白字符并转换为字节
_svr_pubkey=  bytes.fromhex(_svr_pubkey_hex.replace(" ", "").replace("\n", ""))

_svr_cipher_hex ='''
82 ba 4e a7 0f d4 e3 5b b4 f9 01 da 5c d0 5d 01 68 19 2a 01 ce be e4 af 45 db cd e6 b9 2e cc e2 b5 96 5a 80 f3 36 62 38 e9 87 0a 09 44 8f 62 8e 36 8d 8f 4d c8 1f 11 01 3d 2b 1c 14 91 58 83 dc 7d 68 55 9d ba bc 9d ba a8 ac 26 a7 be 03 41 29 12 aa b9 82 96 aa 94 6a fa ec cb 66 d8 e3 f2 02 d0 a5 b5 1a ed 3d 4a b4 c1 c0 02 3e 68 8e 57 e6 bd c8 1d 22 22 a9 f5 1e ac 3e d1 69 7c ca 46 f1 09 f0 68 6f 12 36 4a e1 9e 4d 1d b6 16 70 dd d0 a6 26 f8 fd 7a f0 ff be 67 6a 7f 76 0e 44 5a 20 50 35 41 88 63 74 08 7f 43 dc 57 a1 bd 6e 2d 6b 1a 53 c1 94 16 85 e7 66 e1 c6 a6 1a 43 1f 11 d5 eb c5 bc 6c 90 22 bf 09 cd b2 01 52 e6 13 8c ae 97 ed b6 c1 94 11 48 ee d5 5f 7f aa 11 52 0b e4 bf d6 61 47 b9 fa 28 e7 9b 02 3c f1 8a 5e 22 0b 38 d9 4f 75 66 ef a0 7e 81 06 9d b7 24 77 68 ad a5 44 aa f4 3d 57 98 a6 58 50 3d 09 2e 4a 6c d1 d5 63 28 1b 79 9d 5a 9f 5f 44 d5 42 a9 e3 06 d5 60 50 8f c4 6d be 37 6b 69 02 50 fd f1 c3 75 b5 fa 7b 69 99 c6 89 5a 7a f9 9f 79 85 11 a6 f9 f8 33 d0 26 3d 6a 78 65 93 fe e1 dd 0a 73 0e dd 77 9b 59 9a 62 07 7d bc 86 98 eb 5c b0 a2 38 50 0a 07 c3 90 fe 3c cc 66 8b 11 0e f8 35 2e 7b 3e 56 aa 0a c8 21 e7 3e c5 0b ad 7f 78 69 65 65 b1 6d 3d a1 7a a3 61 b2 99 46 30 01 fb bd 82 69 21 71 fa 91 2d d0 0b 50 8b 49 8e 2f 75 f6 9c db 90 ca 36 26 cf 82 ee 11 79 d3 e6 0f 0e 27 8f 47 77 98 24 17 4b ce c3 2f 80 39 6e 28 fb e2 6a a3 09 3c c6 45 27 c9 2d a3 54 ff b1 47 bc 12 48 2d 0e 68 3c 87 c6 98 c6 04 30 e9 ba c9 5a 1f 7e 50 47 23 4f c2 34 38 bb ee 2f b6 06 ba d4 f9 f7 85 d0 60 6c eb 2c 75 72 6f 2c bb 72 02 8d de 18 6f d0 4f 6f e6 14 da e6 15 83 5e a6 cb 47 54 8d de 0f bd e4 4f 00 86 5b ad cd 3f 0c 2c 68 a2 15 00 e4 a3 fd cb fc dd 40 c0 65 1e 98 57 25 c0 63 7e 03 2f 74 64 7d cf dc d7 f7 aa b1 28 87 43 b4 2e b3 ca 75 5f 96 0e 3f 91 e5 41 46 ee f6 10 f9 13 2d 1d 06 18 28 e1 dd eb 1d 56 e4 6e fa 75 c1 63 9a e0 c6 b9 f4 84 0c 75 09 f4 35 23 00 a7 9b e1 8b e1 31 43 d1 8c 63 51 5e 78 57 d1 df 24 e7 1f 62 9c 58 20 41 31 f1 6c b3 4c 6e 93 77 8c 5d 19 79 12 d3 64 b6 0c 38 a6 85 82 f4 70 17 52 84 d8 30 e8 18 9d 8e bf 5b a7 71 86 ee c4 d8 c0 db 64 fa dc b1 55 fa 99 3f 99 60 8b 0d 02 3f 3d f3 70 11 43 ea e8 17 de 7f 82 f1 0f f8 a7 5c d7 a8 46 af 4b 68 57 08 1e 99 f8 d2 c6 73 aa ba 52 07 5a b8 22 9a cd 6f ee e2 dd 09 a0 0a 1f 73 ac 69 55 d7 f3 6d e8 9f 4a bd 0e 39 ce 4a 9a c0 a4 67 d5 ab 17 05 3b 4b 67 1d 44 e7 a0 56 e2 32 d3 5d 14 21 69 a1 07 d5 30 6c 32 f1 a5 6f 64 ba 4c 28 88 32 cf 2a 26 89 d0 c1 59 48 99 0c c9 dc 47 78 d1 20 17 5d a4 1a 31 1e 6d 5e 86 85 65 02 ad c0 39 89 ce c6 c3 5d 46 62 eb ba 9e 93 4c f2 bd 39 20 78 5b 45 79 dc 16 86 aa f7 b5 f4 91 ff d8 55 fd 5f 79 06 45 bb b9 27 9a b6 9a 59 3c 03 c7 4b 83 37 8b e1 c1 57 8a e0 58 60 ce f7 33 9f d7 cb 79 e4 7b 79 76 8a 92 f4 d6 d1 fd dd af 80 b5 2d 2d a3 ae 92 4c 79 7f 57 f7 f7 62 9a f9 f9 be 50 e9 ae 89 bd 16 d0 e5 80 45 a2 29 04 ce 32 df f0 78 72 71 33 46 0b f5 29 ac ae e7 71 12 4a 37 e2 2a c4 89 39 70 fe 69 f3 51 d5 25 e3 ab af 5f 01 de 11 c8 0e 5b 0e 40 cf f6 3c e8 8e 13 a7 a4 17 0f 88 a5 d6 15 f6 30 57 d4 5a e6 90 dc 78 27 93 77 f8 7e 8e 59 c9 c6 5c 87 dd 35 c3 cc ce 97 49 ac 2a 67 35 3c 78 fb 1b 04 cd 0b 03 3f f6 cd 64 2a fc bc 2e ec f7 60 79 16 85 3d 41 2a 96 ee 02 37 4d 30 55 e5 21 88 fd 6b 52 94 b3 9a 7a 9e 00 ac dd ae 9b 90 7f eb 0a 40 a5 d9 44 51 c1 d8 2c 3c 1d 41 75 f1 ee 55 bf 75 c6 04 61 d9 1e 62 de ea a7 ec b6 b2 a2 68 f1 e9 1d 2a 00 95 cd 65 36 57 cc 92 b2 15 1c 6d 47 50 cd c1 bb 7c 4e 01 15 ac 45 cd 60 a6 e5 71 29 0f 8f 60 30 4e 7c 07 cb 7f bc cd 2f db 0f 62 eb 06 22 a6 54 66 49 cc f2 58 ba 86 cc e0 32 68 00 03 6b 0f cb b5 4a 7d e3 56 fe ad d7 36 e8 de 9b 22 e0 69 65 cc 4a ab e3 80 b6 b6 7e c3 1b 11 6a 36 80 95 41 e4 48 f5 ea 04 8f 59 51 06 86 52 df b7 3e 52 fa 2f 6d 81 3f 44 16 c7 9d 84 d9 69 49 22 40 0a 02 a2 0a 64 86 84 ce eb ed d6 8c 4f bd 7c ac c1 78 d8 8e 1b cc ef 2b 3a 9c f7 50 a6 b1 9f 53 42 b7 51 bb 9a e9 31 b3 df a1 19 6c e3 99 3c ac e3 f7 b3 29 10 36 82 66 46 5c 2b 1e bf ba af b7 23 af cf 78 90 6c 0e da a9 da d5 7f ff f0 36 23 f7 2f d5 67 d2 b9 d0 dd ce b2 d2 4b 3d 2f 35 c5 a0 34 1d 9b ce 65 a8 e0 73 02 92 2d 44 5a 3f 4f 04 83 42 35 b1 ae 0e b9 3b 87 1b 93 36 16 be 82 a8 81 eb b7 da ed 03 7d 33 d1 a4 5b 74 59 7c f2 b4 a1 8d e3 60 07 45 a1 2a 20 ec 0c 44 5e e7 80 5a e9 67 4e c5 0e cc 76 d5 02 12 8e 7d f4 d6 be 9b 62 d1 7b 6d cf 68 7f 1c 4c 8b d9 50 96 99 5d bf a2 df 1f e1 69 6d 47 00 2a 37 16 55 58 72 33 eb 6e 36 42 5a 48 fc 3d 88 a1 c8 13 29 36 d0 bf 76 8a bb 31 73 23 74 ac 0b 90 9a 93 d5 b6 e0 f8 75 a4 48 a6 1d d5 b8 c6 6b 72 70 b0 f2 66 07 93 85 8e 7f 56 c8 f8 2c 61 e1 0c 9a e0 80 f1 62 32 8d 85 83 ae 00 8c ea 36 d9 40 69 96 68 ae b6 fa 09 b7 7a a8 75 1f b0 6f 58 d4 84 93 b7 c9 d3 c0 87 95 fd 52 43 af 79 46 74 dc e7 0a 73 f5 16 f2 6f 41 5f ec 3f a5 72 19 fb 5a 07 3a e0 b7 60 2a bc 2e 3f bc b9 44 70 8c 80 71 75 fa 11 92 24 69 1d 9e 1c 0d 4c f8 32 c6 72 34 fe 20 11 3c f9 d7 e6 1c 40 30 a9 28 27 19 a1 70 dd 67 fc 01 93 83 87 1c 9e cf 95 f7 e9 ef 47 bb 77 6a db 8b 8b c7 6e 93 c4 6a 62 fc ed 65 95 a7 69 a2 f2 07 15 af 29 b2 f0 ad 5c df e2 a0 09 5d 63 3a 3a 44 f3 b9 92 05 9d c3 f1 b2 68 e8 d8 cb eb c2 1b eb e5 3c 91 97 8e e3 16 8b 23 e4 79 d5 b1 f4 b3 4c 16 c8 46 d4 1b c5 b1 20 34 67 fa f1 3f 69 30 13 a7 82 4f 86 64 d6 f3 1f dc e8 70 68 37 7e 0e 56 a9 d3 d3 ee 7a 59 3c 19 13 22 22 40 74 e5 c7 d7 da b4 29 93 09 b4 ae 1d bd b1 fb 9e 5f 18 60 77 5e 09 e7 9a 7a ae f0 dd 02 46 07 c4 93 85 bc d4 ca 3a af fc e3 26 2f a5 7d 2d 5e 02 9f d6 62 2e bf fe d6 6c 2d 54 01 bf 5c 57 77 c6 d5 bd 14 34 d7 9a db ab 00 b6 96 94 33 4a c1 3c b2 0c 30 2e 0d 6c 37 d7 0d 45 74 0c 98 f2 a8 78 eb 2f df 13 56 48 34 b0 88 19 86 97 59 75 c0 bb 63 56 4f 3a 08 53 57 91 3c 06 a8 04 0a 67 78 e1 74 98 03 03 bb 3a 96 db df 8f b6 ec 72 3c 83 fe 52 68 5f fc 19 a3 80 53 d2 0d c9 21 00 02 ef bf 5b 00 69 56 ad a0 c4 63 b5 b8 fe f2 01 a1 f0 0e b5 38 36 4a 58 8b 53 31 ce db f0 83 73 a1 8d da 5d 37 57 46 c4 d7 f0 4b 94 6a f6 90 6a 38 56 1d 4c 49 b1 29 36 0c 7b 89 3a 11 4f 5c 7a fd 02 07 67 74 55 77 02 ce 00 15 a5 61 02 a2 4e 41 79 3c d0 5e 80 a2 77 ee 72 df 62 6c 91 43 dc c6 c9 3a 96 83 fb f6 6f ff 9a 60 15 74 a9 e8 4b 8d 02 cf 43 97 d9 35 22 a7 6f ce 2d 04 e3 c2 b2 0d 46 89 5b 84 81 d9 5c 8b a1 f4 01 2f c7 3c 9e 48 f5 a2 35 f1 20 4c 36 98 01 30 c1 53 9f 99 37 bd 9f 19 a9 8a 7a a8 8c c3 ee 32 46 01 51 0f 74 51 3a 5f 3c 50 4a 05 3b f8 05 5d f8 77 d0 de 9e eb ad 4f bf 27 df 75 25 c3 4d 96 ca f0 a7 7a bc 06 3d 1a e7 1b 10 c2 59 df 74 89 e1 6e 0c c6 7d 2c af 31 77 77 36 50 ff 40 0b a9 cc 2e 2c eb e6 08 96 12 37 60 c5 54 fc c8 a2 f2 60 36 02 c9 24 2c e0 6d 9b 76 bf 1c 14 28 ee 3d 34 0a f4 3c fa 24 8c 90 01 54 e0 b4 0f 87 1a b5 5b 2b e0 96 6e 19 52 b9 76 49 c3 16 1a 40 3a 24 5f 33 70 7f 76 75 a4 50 7b 1a ae 5b a1 fa 3f 32 3c 94 ca a0 56 f0 dc e1 ad 42 84 11 64 00 85 76 12 84 c7 13 a5 03 3a 70 83 3b 36 43 cc c8 54 6a 3a f2 f4 49 0e c9 86 4f c1 48 68 84 69 af 30 85 10 b9 e3 48 ca d9 73 2b 7a dd 18 34 17 4f d0 6d 04 af 54 27 2f 83 ee e0 c0 81 ca e3 0b df e1 25 ec 85 10 af e6 86 b4 23 ee 9b 65 c1 4e d6 dd 01 7c ba 54 00 30 d0 ad 7e 4d 32 5e 24 58 99 58 67 c9 b5 10 9d e0 81 ca 4d 62 ca 19 7e b0 91 7e ce da c3 f0 32 74 37 e1 d8 6d 22 45 4a 76 ad 9b 1f 41 5b d7 9f 0a 65 de c0 a6 b0 7e b5 71 6c 64 1a 3c 72 ab 0c 2b fd bd ed 43 83 7a 75 40 c5 eb 74 95 7a f5 36 34 d0 8b a0 3e ca fe 93 a9 6e af cc 62 1d 72 5d c3 24 ef db af 75 2f 5d 91 65 a8 72 e5 18 51 b4 16 00 b9 b9 03 0d 97 9c aa b9 56 b6 59 e8 fb 74 46 cc a1 10 ca 8e 71 bb c9 00 d8 0e 3c 91 5a 57 73 94 2c ca e7 96 96 49 d2 c4 0d 63 99 88 9c 5b 41 ce 36 ce bd 91 cb 41 6a a7 95 a3 ef 10 c6 13 0c 2a b0 1e ae 86 96 ea 4d 08 c6 3a bc 79 1f 63 4a 0d f0 08 2c bc 75 34 17 a4 05 5b cd 36 aa 94 93 c9 3f f6 d6 dc 65 05 e6 01 30 97 a9 e6 75 89 3e bd bd 59 4a ee e6 4a 4b a7 2c 58 c4 da 0c 7a 4c 97 93 31 1c 37 15 97 c0 02 c5 84 e8 57 16 17 68 c6 91 46 74 08 91 dd 31 f5 b2 6c 33 31 11 79 b2 5e 36 61 e6 c9 28 9e f8 b0 f8 cb 3b 5b 3c c2 29 6e fc 5c 61 46 fa 90 36 21 9c ed b6 33 29 10 0f 99 ac 14 ba 20 74 0f bb 12 8d 56 ae d2 e2 c2 3a 48 0d 23 7b 87 b9 36 42 9e 05 d7 69 36 3f 07 95 76 e1 cc 58 e7 55 8e bc e0 f5 24 64 9c eb a8 b7 2b 4c 4d 12 61 ad 08 90 75 c0 e7 44 67 8e 14 dc 0a 71 97 fd a4 d5 82 07 ce 5a 0b 8a ef db 74 20 84 c8 5b da bb 99 a1 df 73 77 2f 1b f6 a1 6c 75 84 39 27 89 7f 4f 2f e2 ab 23 28 d9 b8 f4 44 f8 7a 34 4f aa 9c 12 dc 64 19 b5 b0 e8 97 af 61 ce 0d 60 97 9e dc 98 09 41 80 9f f0 e7 b7 f2 db 3a 80 82 5d 23 60 f9 ad fd 0b e8 ae 83 a3 e6 68 92 e5 80 9c 9f 47 68 43 6f 4a 97 0d f0 09 48 21 95 a4 f6 76 02 93 72 d7 b0 b4 e9 dc 86 5d 8c 7a b6 e1 1a 51 11 9a 02 c5 91 c4 c6 b5 9c 34 b7 8f 16 d6 bd 0a b0 89 d9 bc fe 4a 17 ff c8 39 fd db 5c 60 ec 91 5f ca b3 07 d9 b0 9c 45 82 ed f3 5e b7 9b 33 90 df d3 24 94 e5 44 87 4b 30 79 6c ea d9 86 ef d1 65 b7 fb ba 27 4f 5a 4b 49 e9 54 49 fa 2a 4a cb d3 d2 3e 7f 1f 79 24 61 5b 38 d7 ed a0 de 9a 21 f1 bc aa 60 ca 9c 5b 6b 51 8a 68 10 36 26 31 8e 8d 8b 96 75 07 45 ae b9 f1 e2 2e ad 68 38 c1 b4 99 19 a2 ed 63 80 e6 1a 02 48 b2 88 77 2c 90 eb e5 55 4d e6 72 83 11 de cb 6a b2 2a 97 47 5f db 26 02 82 bd e2 44 1d d4 24 6f 03 5e 16 3c 83 90 11 a1 63 28 f4 c1 af 3f d9 23 ed eb 49 70 ce 85 4f 00 33 a9 71 6a b3 e0 72 06 38 8e 26 33 63 ef bf 5c 78 3a 91 89 9d 79 4b 10 de 2a 06 ea 13 77 f5 75 8f 89 84 05 d7 e3 8a 55 0c 69 b6 ed 34 b1 41 b4 3d 1f 7d cb 74 b3 71 80 fa c8 e3 19 6a d2 07 34 09 2d 99 2c 75 dd dd 48 81 de 40 69 a5 b2 b1 6b 63 3c d8 96 19 c2 39 2e 25 b1 d7 86 9f 33 db f6 02 18 98 18 3f ad dd 2e c4 b9 f2 7e c3 c2 49 83 d0 9d 64 dc fd 4c 1d b0 30 e7 e4 41 e0 33 ab d6 25 6c 00 f9 5e 9c 7a 99 bd d2 35 56 1d 38 a1 d4 6a aa b0 00 de ad f2 ca 44 43 3d 65 e7 72 a4 74 a9 77 0e ff 0f dc 2f cb b8 3d f4 d4 ff f8 c9 aa e5 01 a5 6c 48 cf ae 5d 69 d2 3b 8a d1 56 58 0a ee 5f 5e 9b 6a 8b ca 67 60 86 26 c4 37 e5 e9 95 8f a3 e6 8a 18 d9 ce 40 a6 89 96 12 b8 aa b8 5a 85 c0 10 ae c3 e0 3b a8 22 01 9c 03 6f c5 53 34 51 1e 2b 33 b5 9f 60 56 01 d5 58 df 7b db 50 ca 8b 97 49 52 af 01 68 03 16 fb bc 4e d3 f4 6f 20 fd 6e 7c ab fc 57 a0 b7 c3 54 7f 6b 37 ce 7a 90 a2 f2 dd fb b3 77 08 e1 6f e8 69 78 7d 22 3a dd f0 33 20 25 43 b8 2f 35 0a 02 5c c2 37 41 3e ec 15 8f bf fc e0 81 d0 06 77 6c f8 3e 5f c6 8e 3a c0 de 95 55 fb 9f a7 4e e4 5e e8 3f 37 cc 5e 6e c7 8b e6 fb 14 16 2e 5e 80 00 a1 09 3a a4 0c 64 1c ee de 18 50 83 5e bf 4e c4 d8 10 56 1d 7b c7 8c 1c 84 ab 44 87 58 b2 10 48 db a3 47 c9 64 7a 24 a9 5d fe c8 f6 dc 74 7b 82 be e3 42 e7 3d 65 d6 5c 8e 79 1d 96 e3 f1 56 c5 b4 05 32 4d f9 43 a2 fb 86 3b 19 0c 7b 44 c7 94 b7 3d 88 4c 59 c2 bc 3d 7e a8 d8 c5 4e a3 b9 79 d5 3c 26 e3 34 71 20 b5 ae bd cf 6a 60 51 9f 1b 4d 6f 44 e7 ab 80 4b a4 c9 a4 b4 54 cd 21 7a 32 97 cf 2e 33 43 51 be d2 cb 56 e6 c5 fd f3 23 ca c2 49 72 70 b7 ce 30 f7 75 f6 33 8e f0 d2 61 3c f3 c6 e1 c6 9e 36 94 28 2c 85 73 17 c9 d6 46 82 d9 54 b2 a2 58 af 84 8c 11 81 0e 2e d1 f4 2d 52 ab b0 15 31 10 10 61 f8 48 59 39 35 92 6b 92 98 6f ab 31 ab cc 85 dc c8 ca 4a 19 5f 8e 1a 46 2d b3 55 98 77 3c eb ef 4f 5b f7 f2 1f aa a4 51 bd 47 0a a3 1f 52 4d 9a 0c 52 09 9c 57 a7 60 ba 47 1b 62 74 6a b5 ee be 98 11 9f 35 1b 2b 26 24 5e dd 98 e6 d6 48 55 1a 05 6c 61 4c 05 9f c7 40 9b 01 53 b2 cf fb cb bb f3 c8 4e 90 18 6c 47 1e ea 5b 5d ef 17 c1 4f 93 e6 36 ab ba c5 02 ac 27 88 46 6e 56 7d 10 60 4d cb ca f3 6e fb 4c a5 c6 47 33 62 fa ab ca a1 33 ec 16 07 33 5e 46 06 e1 81 02 39 6a 60 38 5c 4a d1 fa 28 b6 f3 e4 e5 3e 15 a5 b0 24 ae 60 e4 2e 1f 4b 93 5f cb 80 64 4a cb af f1 7b 61 60 8d f1 58 37 c8 4d b6 af 62 5d 13 0a a0 cb 3c 8e 64 47 e2 4d b5 ba bb 8a 78 fc bf 41 38 9a 14 b4 bb 15 86 e9 84 42 c0 92 72 26 fa 34 75 ca fd e4 2a 5f 1e 4e 2d 72 b8 e3 f2 43 bf 49 2b 9b fd d5 cf 70 74 cb 31 4d 3d 57 5f f7 29 d9 84 dc 6a b7 21 59 7f c0 77 dd df a7 45 d9 84 c2 55 30 69 bc 03 c0 ac e7 99 1f de fc e6 6b 26 a8 cf ed ff e8 bc ca 36 ca 18 9d d0 52 b4 bc b9 86 de ca 7b b5 43 1b 37 05 2c 64 8c 5e 83 f5 6e 1e b9 f7 0b b7 65 b0 e6 df 75 7c cd 2f 00 64 38 c4 ff 25 9b 1d 90 3f 0d 7f ad 97 15 3d ca 98 67 34 f6 04 61 d7 a1 69 2c 04 7e b9 81 b0 c2 e5 30 9b 7f e2 bc c8 7e cc 9b e5 3a 50 92 44 35 1a 56 64 42 2c 35 85 0c 67 5d 53 1e 3b a8 79 9f 1e 35 25 d6 71 f1 58 98 ef 8b df 57 ce aa 99 b4 8f df e8 26 34 40 df a4 aa f5 d3 d9 68 c1 5d 09 ea 1b 11 94 1a 0f 1b e8 dd b1 fe 53 07 b3 fc 2d c1 8b a8 2d d4 fa 07 14 76 9e f7 39 53 88 09 f6 72 82 c9 0e b2 aa 9e 61 04 1f e5 55 11 bd 4d c8 52 14 0b c1 ee fb 79 ca 79 ff 70 79 a3 e6 78 ac 65 89 04 cb 33 d4 a5 b1 7e 8a e1 53 8b 6e 5b 0a 5d c3 59 e1 74 f1 13 1d 5e 5e 11 f3 f7 a1 9c bf f3 6d c6 f7 90 f1 2d 40 24 9f 34 ea 26 d0 bc 96 aa c6 1d 25 4b bd 11 66 b6 d4 6a 9a 57 73 1c 0a 31 53 7a 6a 5f 51 c4 da 45 f4 f4 ad 11 13 63 83 f8 d7 99 e1 e8 e4 25 c2 2b 37 48 dd aa e8 13 25 12 bb 95 f2 39 2e 21 fe 8b b3 ef 5e 2b df 51 bd 74 ea fe 9c b5 46 31 a8 42 2f 3b f7 52 2a 2a e9 4d de 5e db d0 c3 12 ac f9 46 9f 9e 86 9d b6 a5 2a 75 0c 17 23 6a 6e 48 32 16 78 74 e1 aa c9 b2 e2 da 38 32 b1 e0 33 ef b8 8e a7 64 81 2d 24 bc c6 22 8b 59 82 15 cc 99 5b ae 67 d4 92 6d f2 c1 60 57 bd 3b 8c 44 7e 85 9c ad c2 d7 74 ed 7f c2 e8 90 a2 71 aa c8 3b ed 3a 77 4b ae d8 a1 ea ee 39 bf b5 12 95 cf 6b 07 b7 a8 d5 29 f9 c7 88 31 6f be c1 18 52 65 b0 94 26 cd eb 31 bf 4c 78 c7 87 7b f9 62 53 24 ad cb ec 24 ab 8b 93 d2 b5 9b 79 07 19 ea d8 bb ae 97 48 47 d3 3e df f2 26 71 2d 1f 1a 55 6a c8 9c c6 72 55 f7 92 c4 70 13 56 5c 9a 2f 68 45 6d 5f 85 16 48 de f7 77 79 d0 9d f8 55 19 fd 0f 0f 14 01 28 2c 95 c2 46 12 a3 91 6e e2 a2 36 13 74 22 bf 1c fa a9 55 62 fb 74 c3 11 31 1a c1 2c 53 16 e8 10 24 1a 60 14 cc 62 32 fe ae 2a d5 db bd 60 ba e2 99 95 2b 26 8b 81 1b 37 94 fd 04 96 fe b3 84 34 41 a6 33 51 1c 66 f9 ff b3 6f 76 f4 63 96 63 d8 58 a7 8a ef a4 40 9d 76 8c fc 77 71 94 46 54 41 ef 7c 58 74 2c 08 0e 23 4b e7 ad 7b a9 6f 5a 2e 5b 1f 93 c5 29 ee 01 c1 73 d4 83 ac 43 14 64 9a ae 4f b0 a7 68 67 9e 7f 28 a2 78 60 6c 5f 68 c2 d0 87 0b 04 ff 78 58 9e 79 34 f0 b5 7c 8d 88 f6 8f 5e c6 87 74 88 b7 3f 11 5b 63 c7 08 1b 57 a6 92 c3 bf 40 4f 30 99 7f 63 d3 b4 c5 78 e3 7b 36 4e 2f 9e b5 cd 2b b0 3f 29 9d e5 fd 39 a1 c3 f0 20 9c 70 ad ac 1a 27 a3 dc 2d 6a 50 4e 42 db ba 61 96 af 6d f7 f9 ef 03 11 a2 1f c8 81 d8 af 0a 74 91 d1 85 a1 31 23 10 f6 aa 8e d5 00 49 62 17 d8 38 cc e3 b6 b2 6b 6b fb 04 c0 0b 99 0f 78 cf ff 73 16 ad 8c 3f 90 96 b5 54 b4 e7 9b 19 3e 05 2c 89 55 e3 0c 09 ac 47 55 54 8b 4a 6e a4 a8 50 83 33 18 51 29 17 e6 e9 89 01 69 72 98 69 ca 29 a4 06 a6 b6 2e b3 de d1 77 9d b8 19 a8 27 c6 c1 60 1a aa b1 79 19 61 c1 7c 57 4a 96 49 3b d5 25 25 c3 b6 12 8e 68 e0 99 dd 3e d8 9e 8a 6d e6 b7 e7 ea 1e 3a 0c 57 4f a3 ee ea 98 37 8f 1e c2 88 36 60 ba 54 61 7f a2 2f 4a c2 c5 9f f8 70 d0 a9 e0 50 64 9d 74 9e da 34 38 41 9c a4 8e 62 0e a1 fd ea 7b 2a ba 72 b9 c0 ef c0 62 d7 f5 ac 69 eb 03 94 cb f1 bb 80 73 4e 5f de 68 2f 6a d8 76 39 1b 5e 9f a4 77 53 6e a4 f5 96 3e 2e d4 71 8d fc 56 84 2e 29 8d 5e 68 da 50 e2 f3 fb c3 c6 07 ff eb e0 53 f8 68 2b 61 80 e0 48 6a 34 fb b8 31 14 90 07 c9 81 cb 31 89 bf 24 36 6f 7f ec 08 9d a1 2a 7e 5e 9a 46 ef ab 43 9e 83 6b 9b b7 0f eb 19 9c c1 ac 39 11 1d 89 62 c7 ee 40 81 26 e9 e7 e9 0e a8 2d e5 67 66 be 9b e1 e0 0f 68 f3 0a 91 f3 36 5d af 47 1e 8a 76 68 6e 9f 6f 66 30 1c e2 05 31 ca e9 26 53 97 93 90 53 89 49 4d 7f 17 62 e8 01 6f 5c 40 d9 a5 1d 0a 3c b2 c2 02 84 7c 0c aa fa b1 9a f7 c2 8d 4b d4 88 d1 7e c7 a3 c0 4c 09 99 53 e4 5e 14 a3 b8 cf e3 3f 1c fe d3 b1 1d 0d 40 c3 63 94 37 21 68 e8 19 17 f0 96 83 0e 7a 74 48 84 b3 94 a8 68 e8 97 1a 83 ed 78 43 ba 01 27 24 ab f5 3e ce 84 9a d3 ca 9f a3 6c 16 cf 3b 2c e2 29 2f 80 dd a1 23 4f 03 c4 3d 0b 95 93 70 04 39 7b f8 1b 1b 9a 09 d1 58 6f 5e 3c f9 65 61 c1 35 b8 03 74 42 49 b3 9e 03 49 3c f9 90 1a d5 e7 84 65 2e 94 6c 4f 30 b1 68 47 0c 50 2d cf 92 58 ad 99 cb 06 ed 0a bd a4 d7 e6 7e 3e 14 4e f1 c3 ce 32 ea 04 80 ba d4 66 2f 1a 7a 1d 51 25 fe 7a 67 df 85 1b 43 d6 77 bd ea 24 2d f7 5f 28 92 2f 09 78 c5 e9 2e 95 81 bc 7e f0 7e 4a 8f d0 17 dd 96 fa 0b b9 cf 61 5e 04 f0 52 20 98 f7 c1 f9 91 e9 fd c6 92 e3 2f 7b a7 00 b4 b0 ea 34 5e 04 ae b8 27 a8 5e f0 a7 9c b7 4c f0 b9 98 cf 9a 98 6b b0 77 e9 08 ef 07 7c bd f4 f8 f0 64 1b 92 da ec 96 dd 2c 98 ba 11 9f 66 75 fd 56 fd 4b 0c fb 01 e8 e6 a9 f7 98 3c d6 87 77 fe 9d 45 b1 a0 c1 83 09 46 e2 5b a2 f1 66 87 f1 00 26 91 1e 0d 30 25 ff 7d f6 07 0b da 85 96 f9 4e 5d 89 72 46 5c 0c 16 2c 2f 9a 31 a0 41 94 aa ee af cc 4c 8c a6 ac d3 9b 66 66 f3 b6 a4 65 ea 3f 41 b6 5d e6 8c 2b 21 93 bf 4c 88 b7 30 1f aa 61 f1 ec a9 1f 8f ab 3a
'''

_svr_cipher=bytes.fromhex(_svr_cipher_hex.replace(" ", "").replace("\n", ""))
log("server_pubkey")
hexdump( _svr_pubkey)
log("server_ciphertext")
hexdump( _svr_cipher)

iv_de=_svr_cipher[-28:-16]
ciphertext_de=_svr_cipher[:-28]
tag_de=_svr_cipher[-16:]

dechangshu1 = """
34 31 35    
"""
dechangshu1 = bytes.fromhex(dechangshu1.replace(" ", ""))
dechangshu2 = """
32    
"""
dechangshu2 = bytes.fromhex(dechangshu2.replace(" ", ""))
aad_de=sha256(sha256_de+frida_result+dechangshu1+_svr_pubkey+dechangshu2)

client_der_private = """
30 77 02 01 01 04 20 60 CA B5 33 61 DC 65 A0 DC 99 3F 2A 6E 9B E3 3B 01 1F C7 67 CA 29 44 D1 7F B5 48 4E 3E D3 B6 EB A0 0A 06 08 2A 86 48 CE 3D 03 01 07 A1 44 03 42 00 04 EC 4C 3E BA 7D 65 E9 A6 A4 7D 95 9A 12 23 71 9F BB 53 38 2A A9 9F 28 B6 11 3C 73 F3 AB 0D 75 8F 82 97 E0 38 3A B9 D4 A4 87 26 57 5F DB 33 5D 53 AC 3F 80 22 00 EA 14 E9 09 A9 BD FF 5E 2A 1D F2

"""

client_der_private = bytes.fromhex(client_der_private.replace(" ", ""))

ret, derived = mmtls_ecdh_kdf(415, _svr_pubkey, client_der_private)
log("derived")
hexdump(derived)
key_de=derived[:0x18]

paintext_de=mmtls_aes_gcm.mmtls_aes_gcm_decrypt(key_de, iv_de, ciphertext_de+tag_de, aad_de)
print("paintext_de")
hexdump(paintext_de)