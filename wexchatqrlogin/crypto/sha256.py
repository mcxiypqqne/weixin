import hashlib

def sha256_digest(data: bytes) -> bytes:
    """
    计算 bytes 数据的 SHA-256 哈希值
    参数: data - 输入字节串
    返回: 32 字节的哈希值 (bytes)
    """
    return hashlib.sha256(data).digest()