"""
MMTLS HKDF Salt 生成器
根据 libwechatmm.so sub_E69B8 函数分析

Salt 生成公式:
    Salt = HMAC-SHA256("security hdkf expand", Ciphertext)

参数说明:
    - HMAC Key: "security hdkf expand" (20 bytes 常量字符串)
    - HMAC Data: AES-GCM 加密后的 Ciphertext (32 bytes)
    - Salt: HMAC-SHA256 输出 (32 bytes)

完整流程:
    1. ECDH 密钥协商 → ECDH Shared Secret
    2. AAD = SHA256("1" + "415" + client_pubkey)  [32 bytes]
    3. Ciphertext = AES-GCM-Encrypt(AAD, IV, plaintext) 的密文部分  [32 bytes]
    4. Salt = HMAC-SHA256("security hdkf expand", Ciphertext)  [32 bytes]
    5. Derived Key = HMAC-KDF(Salt, AAD, 56)  [56 bytes]
"""

import hmac
import hashlib
from typing import Tuple


# HMAC-SHA256 Salt 生成的常量 Key (32 bytes, 首字节 0x28 也是 key 的一部分)
_SALT_HMAC_KEY = bytes.fromhex(
    "28 73 65 63 75 72 69 74 79 20 68 64 6B 66 20 65 "
    "78 70 61 6E 64 00 00 00 00 00 00 00 00 00 00 00"
)


def compute_hdkdf_salt(ciphertext: bytes) -> bytes:
    """
    计算 HKDF Salt (两层 HMAC)

    Step 1: HDFk  = HMAC-SHA256(_SALT_HMAC_KEY, Ciphertext)
    Step 2: Salt  = HMAC-SHA256(_SALT_HMAC_KEY, HDFk)

    Args:
        ciphertext: AES-GCM 加密后的密文部分 (32 bytes)

    Returns:
        Salt 值 (32 bytes)

    Raises:
        ValueError: 如果 ciphertext 长度不是 32 bytes
    """
    if len(ciphertext) != 32:
        raise ValueError(f"Ciphertext must be 32 bytes, got {len(ciphertext)} bytes")

    hdfk = hmac.new(_SALT_HMAC_KEY, ciphertext, hashlib.sha256).digest()
    salt = hmac.new(_SALT_HMAC_KEY, hdfk, hashlib.sha256).digest()
    return salt


def compute_hdkdf_salt_hex(ciphertext_hex: str) -> str:
    """
    计算 HKDF Salt (输入输出均为十六进制字符串)

    Args:
        ciphertext_hex: 十六进制字符串格式的 Ciphertext (64 个十六进制字符)

    Returns:
        十六进制字符串格式的 Salt

    Example:
        >>> salt = compute_hdkdf_salt_hex("96D9691C73F96D3AD466CF7EE63795C6B86E46731EEDB9072BAD8A27EEAC1157")
        >>> print(salt)
        379665db360d2e0f53dbd2d4628e6596a283fc979d668b97712aa1ce92600bbc
    """
    ciphertext = bytes.fromhex(ciphertext_hex.replace(" ", "").replace("\n", ""))
    salt = compute_hdkdf_salt(ciphertext)
    return salt.hex()


def verify_hdkdf_salt(ciphertext: bytes, expected_salt: bytes) -> Tuple[bool, bytes]:
    """
    验证 HKDF Salt 计算结果

    Args:
        ciphertext: AES-GCM 加密后的密文部分 (32 bytes)
        expected_salt: 期望的 Salt 值 (32 bytes)

    Returns:
        (is_match, computed_salt)

    Example:
        >>> ciphertext = bytes.fromhex("96D9691C73F96D3AD466CF7EE63795C6B86E46731EEDB9072BAD8A27EEAC1157")
        >>> expected = bytes.fromhex("379665db360d2e0f53dbd2d4628e6596a283fc979d668b97712aa1ce92600bbc")
        >>> match, salt = verify_hdkdf_salt(ciphertext, expected)
        >>> print(match)
        True
    """
    computed_salt = compute_hdkdf_salt(ciphertext)
    return computed_salt == expected_salt, computed_salt


def test_hdkdf_salt():
    """测试 HKDF Salt 生成"""
    print("=" * 70)
    print("HKDF Salt 生成测试")
    print("=" * 70)

    all_passed = True

    # 测试用例 1: 从日志提取的数据 (dump5.txt)
    print("\n" + "-" * 70)
    print("[测试 1] dump5.txt 数据")
    print("-" * 70)

    ciphertext1 = bytes.fromhex(
        "96 D9 69 1C 73 F9 6D 3A D4 66 CF 7E E6 37 95 C6 "
        "B8 6E 46 73 1E ED B9 07 2B AD 8A 27 EE AC 11 57"
    )
    expected_salt1 = bytes.fromhex(
        "37 96 65 DB 36 0D 2E 0F 53 DB D2 D4 62 8E 65 96 "
        "A2 83 FC 97 9D 66 8B 97 71 2A A1 CE 92 60 0B BC"
    )

    print(f"  Ciphertext: {ciphertext1.hex()}")
    print(f"  Expected Salt: {expected_salt1.hex()}")

    computed_salt1 = compute_hdkdf_salt(ciphertext1)
    print(f"  Computed Salt: {computed_salt1.hex()}")

    if computed_salt1 == expected_salt1:
        print("  [PASS]")
    else:
        print("  [FAIL]")
        all_passed = False

    # 测试用例 2: 另一个数据集
    print("\n" + "-" * 70)
    print("[测试 2] 备用测试数据")
    print("-" * 70)

    ciphertext2 = bytes.fromhex(
        "F9 09 CD 7E 9B A5 42 CE A2 F1 3F F5 58 E6 83 98 "
        "21 F6 B4 F5 1D 1C F2 61 FC E2 82 C5 5D 78 9D 48"
    )
    expected_salt2 = bytes.fromhex(
        "A6 E5 A4 94 ED D7 C7 D0 8E E8 8D 8C 42 E5 1C 4C "
        "F0 60 8F 4E 29 F0 F2 03 39 8E A7 BF 58 A3 DE 9D"
    )

    print(f"  Ciphertext: {ciphertext2.hex()}")
    print(f"  Expected Salt: {expected_salt2.hex()}")

    computed_salt2 = compute_hdkdf_salt(ciphertext2)
    print(f"  Computed Salt: {computed_salt2.hex()}")

    if computed_salt2 == expected_salt2:
        print("  [PASS]")
    else:
        print("  [FAIL]")
        all_passed = False

    # 测试用例 3: hex 字符串输入
    print("\n" + "-" * 70)
    print("[测试 3] 十六进制字符串输入")
    print("-" * 70)

    ciphertext_hex = "96D9691C73F96D3AD466CF7EE63795C6B86E46731EEDB9072BAD8A27EEAC1157"
    salt_hex = compute_hdkdf_salt_hex(ciphertext_hex)
    print(f"  Input Ciphertext (hex): {ciphertext_hex}")
    print(f"  Output Salt (hex): {salt_hex}")

    if salt_hex == expected_salt1.hex():
        print("  [PASS]")
    else:
        print("  [FAIL]")
        all_passed = False

    print("\n" + "=" * 70)
    if all_passed:
        print("所有测试通过!")
    else:
        print("存在失败的测试!")
    print("=" * 70)

    return all_passed


