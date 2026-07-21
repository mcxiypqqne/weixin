import zlib
import secrets
from typing import Tuple

from .mmtls_aes_gcm import mmtls_aes_gcm_encrypt, mmtls_aes_gcm_decrypt


def ZLibCompress(data: bytes):
    """
    模拟 sub_49193C / ZLibCompress 的行为

    :param data: 原始数据（bytes）
    :return: (status, compressed_data, compressed_len)
             status == 0 成功，-1 失败
    """
    # 参数校验：data 不能为空
    if not data:
        return -1, None, 0

    try:
        # zlib.compress 内部自动完成 compressBound + compress
        compressed = zlib.compress(data)
        return 0, compressed, len(compressed)
    except zlib.error:
        return -1, None, 0
def ZLibUncompress(compressed_data: bytes) -> tuple:
    """
    模拟 ZLib 解压过程（对应微信 Mars 库中的 ZLibUncompress）
    
    :param compressed_data: 压缩后的数据（bytes）
    :return: (status, uncompressed_data)
             status == 0 成功，-1 失败
    """
    if not compressed_data:
        return -1, None

    try:
        # 内部自动完成 uncompress
        uncompressed = zlib.decompress(compressed_data)
        return 0, uncompressed
    except zlib.error:
        return -1, None


def AesGcmEncryptWithCompress(key: bytes, plaintext: bytes,
                              iv: bytes = None) -> Tuple[bytes, bytes]:
    """
    MMTLS 内层加密: zlib 压缩 + AES-192-GCM 加密 (对应 sub_242944 的加密路径)

    流程:
        原始明文 -> zlib compress -> AES-192-GCM encrypt -> ciphertext+tag

    Args:
        key:       AES-192 密钥 (24 bytes)
        plaintext: 原始明文 (未压缩, protobuf 等)
        iv:        12 字节 nonce, 为 None 时随机生成

    Returns:
        (ciphertext_with_tag, iv):
            ciphertext_with_tag: 密文 + 16 字节认证标签 (与压缩后明文等长 + 16)
            iv:                  12 字节 nonce
    """
    # Step 1: zlib 压缩
    status, compressed, _ = ZLibCompress(plaintext)
    if status != 0:
        raise ValueError("ZLibCompress failed")

    # Step 2: IV (指定或随机)
    if iv is None:
        iv = secrets.token_bytes(12)

    # Step 3: AES-GCM 加密 (AES-128/192/256 自适应)
    ciphertext_with_tag = mmtls_aes_gcm_encrypt(key, iv, compressed, b"")

    return ciphertext_with_tag, iv


def AesGcmDecryptWithUncompress(key: bytes, ciphertext_with_tag: bytes,
                                 iv: bytes) -> bytes:
    """
    MMTLS 内层解密: AES-192-GCM 解密 + zlib 解压 (对应 sub_242944 的解密路径)

    流程:
        ciphertext+tag -> AES-192-GCM decrypt -> zlib decompress -> 原始明文

    Args:
        key:                  AES-192 密钥 (24 bytes)
        ciphertext_with_tag:  密文 + 16 字节认证标签
        iv:                   12 字节 nonce

    Returns:
        解压后的原始明文字节

    Raises:
        InvalidTag: 认证失败
        ValueError: 解压失败
    """
    # Step 1: AES-GCM 解密
    compressed = mmtls_aes_gcm_decrypt(key, iv, ciphertext_with_tag, b"")

    # Step 2: zlib 解压
    status, decompressed = ZLibUncompress(compressed)
    if status != 0:
        raise ValueError("ZLibUncompress failed")

    return decompressed
