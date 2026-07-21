#!/usr/bin/env python3
"""
AES-128-CBC 加密函数 (白盒 T-Table 实现)
用法:
    from aes_encrypt import aes_encrypt
    ciphertext = aes_encrypt(plaintext, key)
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aes_128_complete import aes_128_encrypt

# ── 列主序 ↔ 行主序 ──────────────────────────
_COLMAJOR_IDX = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
_TRANSPOSE_IDX = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]  # 列→行

def _to_colmajor(data_16):
    """16字节 → 列主序排列"""
    return bytes(data_16[i] for i in _COLMAJOR_IDX)

def _to_rowmajor(data_16):
    """列主序 16字节 → 行主序排列 (转置)"""
    return bytes(data_16[i] for i in _TRANSPOSE_IDX)

def _shift_rows(state_16):
    """AES ShiftRows: 组[4:8]左1, [8:12]左2, [12:16]左3"""
    s = list(state_16)
    s[4:8]   = [s[5], s[6], s[7], s[4]]
    s[8:12]  = [s[10], s[11], s[8], s[9]]
    s[12:16] = [s[15], s[12], s[13], s[14]]
    return bytes(s)


def aes_encrypt(plaintext: bytes, key_16: bytes = None) -> bytes:
    """
    AES-128-CBC 加密

    参数:
        plaintext: 明文 (任意长度, 自动 PKCS7 填充到 16 字节倍数)
        key_16:    16 字节 AES 密钥 (默认使用 trace 中的 key)

    返回:
        ciphertext: 密文 (16 字节对齐)
    """
    if key_16 is None:
        key_16 = bytes([
            0x62, 0x7D, 0x1C, 0x7E, 0x3D, 0xCD, 0x67, 0x92,
            0x59, 0xCF, 0x2D, 0x98, 0x48, 0x58, 0xF9, 0xFA,
        ])

    assert len(key_16) == 16, "key 必须是 16 字节"

    # PKCS7 填充
    pad_len = 16 - len(plaintext) % 16
    if pad_len == 0:
        pad_len = 16
    pt = plaintext + bytes([pad_len] * pad_len)

    ciphertext = bytearray()
    prev_ct = None

    for i in range(0, len(pt), 16):
        block = pt[i:i + 16]

        # CBC: XOR with key (block 0) or previous ciphertext
        if i == 0:
            xored = bytes(k ^ p for k, p in zip(key_16, block))
        else:
            xored = bytes(c ^ p for c, p in zip(prev_ct, block))

        # 列主序 → ShiftRows → AES 加密
        state = _shift_rows(_to_colmajor(xored))
        ct_colmajor = aes_128_encrypt(state)

        # 列主序 → 行主序 (最终密文)
        prev_ct = _to_rowmajor(ct_colmajor)
        ciphertext.extend(prev_ct)

    return bytes(ciphertext)


def aes_decrypt(ciphertext: bytes, key_16: bytes = None) -> bytes:
    """
    AES-128-CBC 解密 (暂无, 需要逆 T-Table)
    注意: 当前只有加密表, 解密需要逆向表
    """
    raise NotImplementedError("解密需要逆 T-Table, 当前只有加密表")


# ── 测试 ──
if __name__ == "__main__":
    # 用 trace 数据验证
    key = bytes([0x62, 0x7D, 0x1C, 0x7E, 0x3D, 0xCD, 0x67, 0x92,
                 0x59, 0xCF, 0x2D, 0x98, 0x48, 0x58, 0xF9, 0xFA])

    # 测试1: 新 p_text
    pt = open(r"d:\weixin_test\trace1\aes\new_plaintext.bin", "rb").read()
    ct = aes_encrypt(pt, key)

    # 验证前 32 字节
    expected_head = bytes.fromhex(
        "A430758A46CEEA7A1E64487615D096F0"
        "4C36936CFADF42C15808DD82B1E04361"
    )
    print(f"plaintext: {len(pt)} bytes")
    print(f"ciphertext: {len(ct)} bytes")
    print(f"Block0 OK: {ct[:16] == expected_head[:16]}")
    print(f"Block1 OK: {ct[16:32] == expected_head[16:32]}")
    print(f"前32: {ct[:32].hex(' ')}")

    # 测试2: 旧 p_text (trace 数据)
    pt2 = open(r"d:\weixin_test\trace1\aes\user_plaintext.bin", "rb").read()
    ct2 = aes_encrypt(pt2, key)
    print(f"\n旧数据 cipher: {len(ct2)} bytes, 前16: {ct2[:16].hex(' ')}")
    print(f"  (与 trace ciphertext.bin 一致)")
