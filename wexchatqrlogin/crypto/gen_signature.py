"""
gen_signature.py
================
genSignature(uin, token, protoBuf) — 完全复现 MMProtocalJni.genSignature (sub_68300)

算法:
  1. MD5(bswap32(uin) || token)                    → hash1 (16B)
  2. MD5(bswap32(len(protoBuf)) || token || hash1) → hash2 (16B)
  3. adler32(adler32(1, hash2), protoBuf)          → signature (u32)

验证: 19 个 dump 样本全部通过 (protoBuf 2~120 字节).
"""
import struct
import hashlib
import zlib


def genSignature(uin: int, token_16bytes: bytes, protoBuf: bytes) -> int:
    """
    计算 MMProtocalJni.genSignature, 返回 32-bit 无符号整数.

    Parameters
    ----------
    uin : int
        用户 UIN (unsigned, 如 0x8358D96C).
    token_16bytes : bytes
        16 字节 ECDH/会话 token, 整个 session 不变.
    protoBuf : bytes
        原始 protobuf 字节 (加密前的明文).

    Returns
    -------
    int
        32-bit 无符号签名值.
    """
    h1 = hashlib.md5(struct.pack('>I', uin) + token_16bytes).digest()
    h2 = hashlib.md5(struct.pack('>I', len(protoBuf)) + token_16bytes + h1).digest()
    return zlib.adler32(protoBuf, zlib.adler32(h2, 1)) & 0xFFFFFFFF


def genSignature_signed(uin: int, token_16bytes: bytes, protoBuf: bytes) -> int:
    """
    同 genSignature, 但返回有符号 int32 (与 Java i5 一致).
    """
    val = genSignature(uin, token_16bytes, protoBuf)
    if val >= 0x80000000:
        return val - 0x100000000
    return val
