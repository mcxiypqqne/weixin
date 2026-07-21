"""
EC Key Generator - WeChat QR Login
支持多种椭圆曲线参数生成公钥私钥
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ECCurve(Enum):
    """支持的椭圆曲线参数"""
    # NID = 415 (0x19f) - WeChat mmtls / mmtls 协议主要使用
    P_256_SECP256R1 = "secp256r1"

    # NID = 715 - secp256k1 (Bitcoin/Ethereum curve)
    P_256K1_SECP256K1 = "secp256k1"

    # NID = 714 - secp384r1
    P_384_SECP384R1 = "secp384r1"

    # NID = 716 - secp521r1
    P_521_SECP521R1 = "secp521r1"

    # NID = 713 - brainpoolP256r1
    BRAINPOOL_P256R1 = "brainpoolP256r1"

    # NID = 712 - brainpoolP384r1
    BRAINPOOL_P384R1 = "brainpoolP384r1"


# OpenSSL NID 映射表
CURVE_NID_MAP = {
    415: ("secp256r1", "P-256 / prime256v1 / NID_X9_62_prime256v1"),
    714: ("secp384r1", "P-384 / secp384r1"),
    715: ("secp256k1", "P-256k1 / secp256k1"),
    716: ("secp521r1", "P-521 / secp521r1"),
    713: ("brainpoolP256r1", "Brainpool P-256r1"),
    712: ("brainpoolP384r1", "Brainpool P-384r1"),
}


@dataclass
class ECKeyPair:
    """EC 密钥对容器"""
    curve_name: str
    nid: int
    raw_public: bytes
    raw_public_compressed: bytes
    private: bytes
    der_public: bytes
    der_private: bytes
    native_key: ec.EllipticCurvePrivateKey


def get_curve_by_nid(nid: int):
    """通过 NID 获取椭圆曲线对象"""
    mapping = {
        415: ec.SECP256R1,
        714: ec.SECP384R1,
        715: ec.SECP256K1,
        716: ec.SECP521R1,
        # Brainpool curves - 需要 OpenSSL 1.1.0+
        # 713: ec.BrainpoolP256R1,  # cryptography 可能不支持
        # 712: ec.BrainpoolP384R1,
    }
    curve_cls = mapping.get(nid)
    if curve_cls:
        return curve_cls()
    raise ValueError(f"Unsupported NID: {nid} (0x{nid:x})")


def get_curve_by_name(name: str):
    """通过名称获取椭圆曲线对象"""
    mapping = {
        "secp256r1": ec.SECP256R1(),
        "secp384r1": ec.SECP384R1(),
        "secp256k1": ec.SECP256K1(),
        "secp521r1": ec.SECP521R1(),
        "prime256v1": ec.SECP256R1(),
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "brainpoolP256r1": None,  # 需要 OpenSSL 扩展
        "brainpoolP384r1": None,
    }
    curve = mapping.get(name)
    if curve is None and name in mapping:
        raise ValueError(f"Curve {name} requires OpenSSL with Brainpool support")
    if curve is None:
        raise ValueError(f"Unknown curve: {name}")
    return curve


def generate_keypair(curve_name: str = "secp256r1") -> ECKeyPair:
    """
    生成椭圆曲线密钥对

    Args:
        curve_name: 曲线名称，支持:
            - "secp256r1" / "prime256v1" / "P-256" (NID=415, 0x19f)
            - "secp256k1" (NID=715)
            - "secp384r1" / "P-384" (NID=714)
            - "secp521r1" / "P-521" (NID=716)

    Returns:
        ECKeyPair: 包含所有格式密钥的容器
    """
    curve = get_curve_by_name(curve_name)

    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    raw_public_compressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    private_numbers = private_key.private_numbers()
    private_value = private_numbers.private_value
    private_bytes = private_value.to_bytes(
        (curve.key_size + 7) // 8, byteorder='big'
    )

    der_public = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    der_private = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    nid = {
        "secp256r1": 415, "prime256v1": 415, "P-256": 415,
        "secp256k1": 715,
        "secp384r1": 714, "P-384": 714,
        "secp521r1": 716, "P-521": 716,
    }.get(curve_name, 0)

    return ECKeyPair(
        curve_name=curve_name,
        nid=nid,
        raw_public=raw_public,
        raw_public_compressed=raw_public_compressed,
        private=private_bytes,
        der_public=der_public,
        der_private=der_private,
        native_key=private_key
    )


def generate_p256_keypair() -> ECKeyPair:
    """生成 P-256 (secp256r1) 密钥对 - WeChat mmtls 默认曲线"""
    return generate_keypair("secp256r1")


def generate_p256k1_keypair() -> ECKeyPair:
    """生成 secp256k1 密钥对 - Bitcoin 曲线"""
    return generate_keypair("secp256k1")


def generate_p384_keypair() -> ECKeyPair:
    """生成 P-384 (secp384r1) 密钥对"""
    return generate_keypair("secp384r1")


def generate_p521_keypair() -> ECKeyPair:
    """生成 P-521 (secp521r1) 密钥对"""
    return generate_keypair("secp521r1")


def print_keypair(kp: ECKeyPair):
    """打印密钥对信息"""
    print(f"\n{'='*60}")
    print(f"Curve: {kp.curve_name}")
    print(f"NID: {kp.nid} (0x{kp.nid:x})")
    print(f"{'='*60}")

    print(f"\n[Raw Public Key] - i2o_ECPublicKey 格式")
    print(f"  Uncompressed ({len(kp.raw_public)} bytes): 0x{kp.raw_public.hex()}")
    print(f"  Compressed ({len(kp.raw_public_compressed)} bytes): 0x{kp.raw_public_compressed.hex()}")

    print(f"\n[Private Key]")
    print(f"  ({len(kp.private)} bytes): 0x{kp.private.hex()}")

    print(f"\n[DER Public Key] - SubjectPublicKeyInfo / X.509")
    print(f"  ({len(kp.der_public)} bytes): {kp.der_public.hex()}")

    print(f"\n[DER Private Key] - PKCS8")
    print(f"  ({len(kp.der_private)} bytes): {kp.der_private.hex()}")


def demo():
    """演示所有支持的曲线"""
    curves = [
        ("secp256r1 (P-256)", "secp256r1"),
        ("secp256k1 (P-256k1)", "secp256k1"),
        ("secp384r1 (P-384)", "secp384r1"),
        ("secp521r1 (P-521)", "secp521r1"),
    ]

    print("="*60)
    print("EC Key Generator - 多曲线支持演示")
    print("="*60)

    for name, curve in curves:
        try:
            kp = generate_keypair(curve)
            print_keypair(kp)
        except Exception as e:
            print(f"\n[{name}] 生成失败: {e}")

    print(f"\n{'='*60}")
    print("用法示例:")
    print("="*60)
    print("""
from wechat_ec_generator import generate_keypair, generate_p256_keypair

# 生成 P-256 密钥对 (WeChat mmtls 默认)
kp = generate_p256_keypair()
print(kp.raw_public)      # 65 bytes, i2o_ECPublicKey 格式
print(kp.private)          # 32 bytes, 大端序整数
print(kp.der_public)       # X.509 DER
print(kp.der_private)      # PKCS8 DER

# 指定曲线生成
kp = generate_keypair("secp384r1")

# ECDH 共享密钥
shared = kp.native_key.exchange(ec.ECDH(), peer_public_key)
""")


