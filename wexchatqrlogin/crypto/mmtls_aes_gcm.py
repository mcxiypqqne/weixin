from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def mmtls_aes_gcm_encrypt(key: bytes,
                          nonce: bytes,
                          plaintext: bytes,
                          aad: bytes = b"") -> bytes:
    """
    MMTLS 层的 AES-GCM 加密 (支持 AES-128/192/256)
    :param key:       16/24/32 字节密钥
    :param nonce:     12 字节 nonce
    :param plaintext: 待加密明文
    :param aad:       附加认证数据（可选）
    :return:          密文 + 16 字节认证标签（总长 = len(plaintext) + 16）
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(f"key 长度必须为 16/24/32 字节，当前 {len(key)} 字节")
    if len(nonce) != 12:
        raise ValueError("nonce 长度必须为 12 字节")

    aesgcm = AESGCM(key)
    # encrypt 返回的就是 密文 + 标签
    return aesgcm.encrypt(nonce, plaintext, aad)
def hex_dump(label, data, bytes_per_line=16):
    """以 hex+ASCII 表格打印 data (类似 xxd / Wireshark 的视图)."""
    log(f"  {label} ({hex(len(data))} 字节):")
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        log(f"    {i:04X}: {hex_part:<48} {ascii_part}")

DEBUG = True
# ============================================================


def log(*args, **kwargs):
    """DEBUG=True 时打印, DEBUG=False 时什么都不做。"""
    if DEBUG:
        print(*args, **kwargs)

def mmtls_aes_gcm_decrypt(key: bytes,
                          nonce: bytes,
                          ciphertext_with_tag: bytes,
                          aad: bytes = b"") -> bytes:
    """
    MMTLS 层的 AES-GCM 解密 (支持 AES-128/192/256)
    :param key:                 16/24/32 字节密钥
    :param nonce:               12 字节 nonce
    :param ciphertext_with_tag: 密文 + 16 字节认证标签
    :param aad:                 附加认证数据（可选）
    :return:                    解密后的明文
    :raises InvalidTag:         认证失败（密钥/nonce/AAD/密文不匹配）
    """
    if len(key) not in (16, 24, 32):
        raise ValueError(f"key 长度必须为 16/24/32 字节，当前 {len(key)} 字节")
    if len(nonce) != 12:
        raise ValueError("nonce 长度必须为 12 字节")
    if len(ciphertext_with_tag) < 16:
        raise ValueError("输入数据过短，至少需要 16 字节标签")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)

hex_data ='''
6E 79 73 76 00 00 00 00 82 74 17 6B 85 6D 44 40 FC B6 E3 37 8E 03 00 00 CC E6 00 00 00 00 00 00 BB 83 FD 00 00 00 00 00 00 00 00 00 00 00 00 00 59 B3 09 00 00 00 00 00 FC DA D7 38 8E 03 00 00 FC FE CB 39 8E 03 00 00 5A B3 09 00 00 00 00 00 B7 5E D5 39 8E 03 00 00 B7 82 C9 3A 8E 03 00 00 5B B3 09 00 00 00 00 00 72 E2 D2 3A 8E 03 00 00 72 06 C7 3B 8E 03 00 00 5C B3 09 00 00 00 00 00 2D 66 D0 3B 8E 03 00 00 2D 8A C4 3C 8E 03 00 00 5D B3 09 00 00 00 00 00 E8 E9 CD 3C 8E 03 00 00 E8 0D C2 3D 8E 03 00 00 5E B3 09 00 00 00 00 00 A3 6D CB 3D 8E 03 00 00 A3 91 BF 3E 8E 03 00 00 5F B3 09 00 00 00 00 00 5E F1 C8 3E 8E 03 00 00 5E 15 BD 3F 8E 03 00 00

00 00 00 85 02 04 F1 C0 2B E0 31 DC AB F4 17 51 4E B0 9A 3A 47 16 11 27 78 48 FC 75 17 DA 39 AA 31 83 D8 20 E5 2F 7C 7F E0 00 00 00 5C 02 00 00 00 49 00 11 00 00 00 07 00 41 04 AA 90 48 EA D1 02 77 50 0E C5 41 68 A0 03 A5 41 B2 1A 4E 2C C1 30 4C C1 74 67 AF 42 9B 89 01 94 67 0F F3 57 F4 EB 41 C4 96 B8 E1 D9 C4 EA AB FC 24 F8 5F F3 CB BD 25 95 D9 61 D2 9C CB 72 E2 C9 00 00 00 0A 00 13 00 00 00 01 00 00 00 05

 00 00 00 4A 0F 00 47 30 45 02 20 4C FC 3C B0 13 A7 69 45 B3 43 03 06 76 6D 51 E8 DD 5F D0 D3 E6 6A 48 CB B5 74 96 54 5D AA 2F 4A 02 21 00 C4 2D 9B 46 2F 69 FE AB 5B 9B C5 04 6D 2C F8 47 F9 E8 0A B1 EA 6B 6D 4D 1B 63 5D AF 60 02 16 EF
'''

# 移除所有空白字符并转换为字节
plaintext = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

key="19 e5 28 8b ff 01 77 d0 47 4a d6 1f 06 24 67 74"
key=bytes.fromhex(key.replace(" ", ""))
nonce="7b df 36 07 54 8d 73 4a 52 c0 e5 1c"
nonce=bytes.fromhex(nonce.replace(" ", ""))
aad="00 00 00 00 00 00 00 02 17 f1 04 01 1a"
aad=bytes.fromhex(aad.replace(" ", ""))
ciphertext = mmtls_aes_gcm_encrypt(key, nonce, plaintext, aad)
hex_dump("ciphertext", ciphertext)
plaintext = mmtls_aes_gcm_decrypt(key, nonce, ciphertext, aad)
hex_dump("plaintext", plaintext)