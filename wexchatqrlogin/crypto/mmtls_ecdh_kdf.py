import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

NID_TO_CURVE = {
    415: ec.SECP256R1(),  # prime256v1
}

def sub_25913C_kdf(shared_secret: bytes, outlen: int = 32) -> bytes:
    """微信 mmtls 实际使用的 KDF：SHA256(原始共享密钥)"""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()[:outlen]

def sub_258550(a2: int, pubkey_data: bytes, prvkey_data: bytes):
    """
    ECDH 密钥协商（含 KDF）
    返回 (retcode, derived_key)
        成功：retcode=0, derived_key 为 32 字节 bytes
        失败：retcode=-20004, derived_key=None
    """
    if not pubkey_data or not prvkey_data:
        return -20004, None

    curve = NID_TO_CURVE.get(a2)
    if curve is None:
        return -20004, None

    try:
        private_key = serialization.load_der_private_key(
            prvkey_data, password=None, backend=default_backend()
        )
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, pubkey_data)
        shared_key = private_key.exchange(ec.ECDH(), public_key)
    except Exception:
        return -20004, None

    derived = sub_25913C_kdf(shared_key, 32)
    return 0, derived


if __name__ == "__main__":
    # 日志中的真实数据

    expected = "2B 84 72 C9 DE 18 5C C5 33 06 D1 04 F5 B4 A1 3C"
    client_der_private = """
    04 21 88 AE 9B FF CD 53 9F F0 2D 79 B9 9D 9B D8 B5 9F 61 56 55 81 F2 C1 A0 4C 48 45 43 8D 20 92 5B A8 E1 6B D7 6A 37 0D 2E 3E D5 D4 91 B9 8B 9F E3 DA 4E 17 A2 CB 34 C2 42
    """

    pub = bytes.fromhex(client_der_private.replace(" ", ""))
    client_der_private = """
    30 82 01 44 02 01 01 04 1C 7B 4C 02 56 4A 26 AC FC 23 B6 6E E8 AC D4 A7 F9 C2 AC EA E7 B0 81 B1 2A 01 CC 6D 86 A0 81 E2 30 81 DF 02 01 01 30 28 06 07 2A 86 48 CE 3D 01 01 02 1D 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 01 30 53 04 1C FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE FF FF FF FF FF FF FF FF FF FF FF FE 04 1C B4 05 0A 85 0C 04 B3 AB F5 41 32 56 50 44 B0 B7 D7 BF D8 BA 27 0B 39 43 23 55 FF B4 03 15 00 BD 71 34 47 99 D5 C7 FC DC 45 B5 9F A3 B9 AB 8F 6A 94 8B C5 04 39 04 B7 0E 0C BD 6B B4 BF 7F 32 13 90 B9 4A 03 C1 D3 56 C2 11 22 34 32 80 D6 11 5C 1D 21 BD 37 63 88 B5 F7 23 FB 4C 22 DF E6 CD 43 75 A0 5A 07 47 64 44 D5 81 99 85 00 7E 34 02 1D 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D 02 01 01 A1 3C 03 3A 00 04 C5 B1 73 00 95 1F 7B 5B 1F 00 F9 49 74 18 31 2F 3D 77 5E DB 0B F8 28 3B E9 58 18 85 F6 94 3A 8F 0D D7 B8 66 89 7E B8 F0 41 77 A1 D1 6A 89 FF EC F6 0B 18 E3 80 31 78 88
 """

    prv = bytes.fromhex(client_der_private.replace(" ", ""))

    ret, derived = sub_258550(713, pub, prv)
    print(derived)
