"""
WeChat QR Login - Crypto Module
EC Key Generation supporting multiple curves
"""

from .ec_generator import (
    ECKeyPair,
    ECCurve,
    generate_keypair,
    generate_p256_keypair,
    generate_p256k1_keypair,
    generate_p384_keypair,
    generate_p521_keypair,
    get_curve_by_nid,
    get_curve_by_name,
    CURVE_NID_MAP,
)

from .sha256 import sha256_digest as sha256
from .mmtls_ecdh_kdf import sub_258550 as mmtls_ecdh_kdf
from .mmtls_aes_gcm import mmtls_aes_gcm_encrypt, mmtls_aes_gcm_decrypt
from .mmtls_hkdf_expand import hmac_kdf_expand
from .mmtls_random import mmtls_random_bytes
from .mmtls_zlib import ZLibCompress, ZLibUncompress, AesGcmEncryptWithCompress, AesGcmDecryptWithUncompress
from .mmtls_hdkdf_salt import (
    compute_hdkdf_salt,
    compute_hdkdf_salt_hex,
    verify_hdkdf_salt,
)
from .gen_signature import genSignature, genSignature_signed

__all__ = [
    # EC
    "ECKeyPair",
    "ECCurve",
    "generate_keypair",
    "generate_p256_keypair",
    "generate_p256k1_keypair",
    "generate_p384_keypair",
    "generate_p521_keypair",
    "get_curve_by_nid",
    "get_curve_by_name",
    "CURVE_NID_MAP",
    # SHA256
    "sha256",
    # ECDH KDF
    "mmtls_ecdh_kdf",
    # AES-GCM
    "mmtls_aes_gcm",
    # HMAC-KDF
    "mmtls_hkdf_expand",
    # Random
    "mmtls_random",
    # ZLib
    "ZLibCompress",
    "ZLibUncompress",
    "AesGcmEncryptWithCompress",
    "AesGcmDecryptWithUncompress",
    # HKDF Salt
    "compute_hdkdf_salt",
    "compute_hdkdf_salt_hex",
    "verify_hdkdf_salt",
    # genSignature
    "genSignature",
    "genSignature_signed",
]
