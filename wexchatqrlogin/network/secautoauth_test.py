"""
WeChat MMTLS 协议 — 完整握手 + NewDNS CGI 请求

流程:
  1. MMTLS ClientHello (ECDH 密钥交换)
  2. 解密 ServerHello, 派生 PSK_ACCESS 密钥
  3. send_newdns_request() — business_auth + AES-GCM 加密的 newgetdns CGI 四包请求

body 内部布局 (相对于 HTTP body 起始 = packet 偏移 230):
  body[0..4]:    16 f1 04 00 dd            (mmtls record header, 5 字节)
  body[5..14]:   内部头 (10 字节)
  body[15..46]:  32 字节 client random       <-- 替换
  body[47..68]:  block 2 header (22 字节)
  body[69..72]:  00 41 04 marker
  body[73..137]: client pubkey (含 0x04 marker, 65 字节)  <-- 替换
  body[138..147]: 8 字节 end marker
  body[148..212]: server pubkey (含 0x04 marker, 65 字节)  <-- 替换
  body[213..225]: 13 字节 trailer
"""
import time
from datetime import datetime

import hashlib
import hmac
import os
import re
import socket
import secrets
import sys
import time
import struct
import webbrowser
from typing import Optional, Tuple

# 动态添加包根目录（基于当前文件位置，不硬编码绝对路径）
_package_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _package_root not in sys.path:
    sys.path.insert(0, _package_root)

# 动态添加 pack 目录
_pack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pack')
if _pack_dir not in sys.path:
    sys.path.insert(0, _pack_dir)

from pack1 import deserialize_wire, serialize_header

from wexchatqrlogin.crypto import generate_p256_keypair
from wexchatqrlogin.crypto import sha256
from wexchatqrlogin.crypto import mmtls_ecdh_kdf
from wexchatqrlogin.crypto import mmtls_aes_gcm
from wexchatqrlogin.crypto import mmtls_hkdf_expand
from wexchatqrlogin.crypto import mmtls_random_bytes
from wexchatqrlogin.crypto import AesGcmEncryptWithCompress
from wexchatqrlogin.proto.a8key import build as build_a8key_proto
from wexchatqrlogin.crypto import ZLibUncompress
from wexchatqrlogin.crypto import ZLibCompress
from wexchatqrlogin.crypto import compute_hdkdf_salt
from wexchatqrlogin.proto import HybridEcdhEncrypt_pb2 as pb2
from wexchatqrlogin.crypto.aes_encrypt import aes_encrypt
import blackboxprotobuf
import pprint
# 读取二进制数据

def bytes_to_hex(obj):
    if isinstance(obj, dict):
        return {k: bytes_to_hex(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bytes_to_hex(v) for v in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        return obj


import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def computer_key_with_all_str(priv: bytes, pub: bytes) -> bytes:
    """
    priv: 28-byte raw P-224 private key, OR full DER-encoded EC private key
    pub:  57-byte uncompressed public key (04 || X || Y)
    return: 16-byte session key
    """
    if priv[0] == 0x30:  # DER encoded -> extract raw key
        priv = _der_extract(priv)

    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), pub)
    d = int.from_bytes(priv, "big")
    our = ec.derive_private_key(d, ec.SECP224R1(), default_backend())
    shared = our.exchange(ec.ECDH(), peer)
    return hashlib.md5(shared).digest()


def _der_extract(der: bytes) -> bytes:
    """Extract raw private key bytes from DER-encoded EC private key."""
    i = 1  # skip SEQUENCE tag
    if der[i] & 0x80:
        n, i = der[i] & 0x7f, i + 1
        i += n  # skip long-form length bytes
    else:
        i += 1
    while i < len(der):
        tag, i = der[i], i + 1
        if der[i] & 0x80:
            n, i = der[i] & 0x7f, i + 1
            length = int.from_bytes(der[i:i + n], "big"); i += n
        else:
            length, i = der[i], i + 1
        if tag == 0x04:
            return der[i:i + length]
        i += length
    raise ValueError("no OCTET STRING in DER")



# ═══════════════════════════════════════════════════════════════
# 调试开关
# ═══════════════════════════════════════════════════════════════
DEBUG = True

# ═══════════════════════════════════════════════════════════════
# 固定 cookie: None=自动从dump抓取, 或手动写死 bytes
# 设为固定值后每次发包 cookie 不变, 方便测试其他参数
# ═══════════════════════════════════════════════════════════════
FIXED_COOKIE = None
# FIXED_COOKIE = bytes.fromhex("49 03 08 02 00 00 00 00 65 5D 57 0F 97 7D 00")
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


def hex_dump(label: str, data: bytes, bytes_per_line: int = 16):
    """以 hex+ASCII 表格打印 data (类似 xxd / Wireshark 的视图)。"""
    log(f"  {label} ({len(data)} bytes):")
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        log(f"    {i:04X}: {hex_part:<48} {ascii_part}")


def AesGcmDecryptWithUncompress(key: bytes, data: bytes) -> Optional[bytes]:
    """
    从 MMTLS 内层加密包中提取密文/IV/Tag, 完成 AES-GCM 解密 + zlib 解压。

    数据包结构:
        data[0x2a:-28]  → ciphertext (密文)
        data[-28:-16]   → iv (12 字节 nonce)
        data[-16:]      → tag (16 字节认证标签)

    Args:
        key:  AES-192 密钥 (24 bytes)
        data: 原始加密包 (如 plaintexts[1])

    Returns:
        成功: 解压后的明文字节
        失败: None
    """
    ciphertext = data[0x2a:-28]
    iv = data[-28:-16]
    tag = data[-16:]

    hex_dump("AesGcmDecryptWithUncompress - ciphertext", ciphertext)
    hex_dump("AesGcmDecryptWithUncompress - iv", iv)
    hex_dump("AesGcmDecryptWithUncompress - tag", tag)

    ciphertext_with_tag = ciphertext + tag
    try:
        plaintext = mmtls_aes_gcm.mmtls_aes_gcm_decrypt(key, iv, ciphertext_with_tag, b'')
    except Exception as e:
        log(f"[ERROR] AES-GCM decrypt failed: {e}")
        return None

    hex_dump("AesGcmDecryptWithUncompress - decrypted (zlib-compressed)", plaintext)

    status, decompressed = ZLibUncompress(plaintext)
    if status != 0:
        log("[ERROR] ZLib decompress failed")
        return None

    hex_dump("AesGcmDecryptWithUncompress - decompressed", decompressed)
    hex_str = ' '.join(f'{b:02X}' for b in decompressed)
    log("解压成功:", hex_str)
    return decompressed


# ═══════════════════════════════════════════════════════════════
# MMTLS Nonce / IV 工具
# ═══════════════════════════════════════════════════════════════

def get_decrypt_iv(decode_iv: bytes, server_seq: int) -> Tuple[bytes, int]:
    """
    等价 Go: GetDecryptIv
    - decode_iv: DecryptmmtlsIv (12 bytes)，从 HKDF 派生出来的盐
    - server_seq: 当前服务端序列号，从 1 开始
    - 返回: (nonce_12bytes, server_seq + 1)
    """
    last_int = struct.unpack(">I", decode_iv[8:12])[0]
    xor_int = last_int ^ server_seq
    xor_bytes = struct.pack(">I", xor_int)
    nonce = decode_iv[:8] + xor_bytes
    return nonce, server_seq + 1


def get_encrypt_iv(encode_iv: bytes, client_seq: int) -> Tuple[bytes, int]:
    """
    等价 Go: GetEncryptIv
    - encode_iv: EncrptmmtlsIv (12 bytes)，从 HKDF 派生出来的客户端写盐
    - client_seq: 当前客户端序列号，从 1 开始
    - 返回: (nonce_12bytes, client_seq + 1)
    """
    last_int = struct.unpack(">I", encode_iv[8:12])[0]
    xor_int = last_int ^ client_seq
    xor_bytes = struct.pack(">I", xor_int)
    nonce = encode_iv[:8] + xor_bytes
    return nonce, client_seq + 1


# ═══════════════════════════════════════════════════════════════
# HTTP / MMTLS 网络工具
# ═══════════════════════════════════════════════════════════════

def hkdf_56(salt: bytes, ikm: bytes, info: bytes) -> bytes:
    """HKDF-Extract + Expand → 56B"""
    # Extract: PRK = HMAC-SHA256(salt, IKM)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    # Expand: T(1) || T(2)[:24]
    t1 = hmac.new(prk, info + bytes([1]), hashlib.sha256).digest()
    t2 = hmac.new(prk, t1 + info + bytes([2]), hashlib.sha256).digest()
    return t1 + t2[:24]  # 56B


def _generate_ecdh_payload1(use_frida: bool = True) -> bytes:
    kp_client = generate_p256_keypair()

    log(f"[2] 新 client pubkey (65B): {kp_client.raw_public.hex()}")

    server_publiv = """
    04 57 ED 16 AC E9 40 7B 93 C0 A6 6E B0 C6 7F 71 46 E2 B4 16 4F 6E 9C 7F 4A 60 3E 4B 6D 14 3C 2D 46 F6 36 05 AD 0F 91 4E 48 9F 57 BB 85 3E B2 25 2A 38 ED 96 8C 1A B1 5F 86 DF 04 5F 80 55 82 A1 94

    """
    server_publiv = bytes.fromhex(server_publiv.replace(" ", ""))
    log(server_publiv.hex())

    client_der_private = """
    30 77 02 01 01 04 20 37 F7 C6 E5 21 03 5B 98 62 CE C0 4D 79 DA 60 77 C0 0D 96 68 E4 CA 4B 91 A9 10 14 B2 F5 4A 81 3C A0 0A 06 08 2A 86 48 CE 3D 03 01 07 A1 44 03 42 00 04 5B 60 52 6D 8D C9 97 7E 65 07 E1 7A 7A DB 88 F9 B8 D3 2B C8 9F 80 64 91 0C DC A8 CE 3B 87 11 70 E2 17 81 BB D3 59 FE 37 BC 26 6B 1E E5 9D FE 75 D7 D6 49 DA 0E DF 38 A0 A2 81 91 FD FA D2 EC F6

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
    04 5b 60 52 6d 8d c9 97 7e 65 07 e1 7a 7a db 88 f9 b8 d3 2b c8 9f 80 64 91 0c dc a8 ce 3b 87 11 70 e2 17 81 bb d3 59 fe 37 bc 26 6b 1e e5 9d fe 75 d7 d6 49 da 0e df 38 a0 a2 81 91 fd fa d2 ec f6
    '''

    # 移除所有空白字符并转换为字节
    kp_client_raw_publi_hex = bytes.fromhex(kp_client_raw_publi_hex.replace(" ", "").replace("\n", ""))


    aad = sha256(changshu + kp_client_raw_publi_hex)
    log(aad)
    iv_hex ='''
    03 58 A8 53 24 64 94 09 56 9C 80 03
    '''

    # 移除所有空白字符并转换为字节
    iv = bytes.fromhex(iv_hex.replace(" ", "").replace("\n", ""))

    
    plaintext_hex ='''
    78 9C 01 20 00 DF FF 88 63 7A E3 7B 73 FB 8B CB A5 C5 95 AE F6 9A 38 BC 96 BD D3 4C 40 2D 95 71 4A 28 3F 3E BE B3 0A 36 7E 11 08
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

    frida_result =use_frida

    # 移除所有空白字符并转换为字节
  

    log("frida_result")
    hexdump(frida_result[0:100])

    key2 = frida_result[0x8:0x8 + 0x18]
    log(key2)
    hexdump(key2)
    iv2_hex ='''
    F5 DE 27 75 4E B1 3B 45 1B 5E 92 98
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


    _, plaintext3, plaintext3_len = ZLibCompress(frida_result)

    aad3 = sha256(changshu + kp_client_raw_publi_hex + ciphertext + ciphertext2)
    log(aad3)
    # iv3 = mmtls_random_bytes(12)

    iv3_hex ='''
    5d 71 fa 51 eb 05 5b f3 2c 67 01 b1 
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
    sha256_de=derived_key[0x18:]

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
    
    ciphertext3=ciphertext3[:-16]+iv3+ciphertext3[-16:]
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

    return proto_bytes,sha256_de



def recv_http_response(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """从 socket 读取完整的 HTTP 响应（根据 Content-Length 头读完 body）。"""
    sock.settimeout(timeout)
    data = b""
    header_end = b"\r\n\r\n"

    while header_end not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk

    header_part, body_part = data.split(header_end, 1)
    content_length = 0
    for line in header_part.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    while len(body_part) < content_length:
        chunk = sock.recv(min(4096, content_length - len(body_part)))
        if not chunk:
            break
        body_part += chunk

    return header_part + header_end + body_part


def build_mmtls_request(body: bytes, host: str = "dns.weixin.qq.com.cn",
                        random_path: Optional[str] = None) -> bytes:
    """根据 body 自动生成完整的 mmtls HTTP 请求头并拼接返回。

    /mmtls/ 后面的 8 位 hex 随机生成。

    用法:
        body = bytes([0x19, 0xf1, 0x04, ...])   # 你的 body 数据
        request = build_mmtls_request(body)
        sock.sendall(request)

    参数:
        body: 请求体 bytes (从 19 f1 04 开始的部分)
        host: Host 头, 默认 dns.weixin.qq.com.cn
        random_path: /mmtls/ 后的 hex 字符串, 默认随机 8 位
    """
    if random_path is None:
        random_path = secrets.token_hex(4)  # 8 位 hex

    content_length = str(len(body))

    header = (
        f"POST /mmtls/{random_path} HTTP/1.1\r\n"
        "Accept: */*\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: close\r\n"
        f"Content-Length: {content_length}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Host: {host}\r\n"
        "Upgrade: mmtls\r\n"
        "User-Agent: MicroMessenger Client\r\n"
        "\r\n"
    )

    return header.encode() + body


# ═══════════════════════════════════════════════════════════════
# MMTLS Record 解析工具
# ═══════════════════════════════════════════════════════════════

# MMTLS record 中的 cmd 字节含义
MMTLS_CMD_NAMES = {
    0x16: "server_data",       # 服务端握手/加密数据
    0x17: "encrypted_cgi",     # 加密的 CGI 响应/请求
    0x15: "close_marker",      # 关闭/结束标记
    0x19: "business_auth",     # 客户端业务认证
}

RECORD_MARKER = b"\xF1\x04"


def parse_mmtls_body(body: bytes) -> list[dict]:
    """
    从 MMTLS body (HTTP 响应的 body 部分) 中提取所有 mmtls record。

    每条 record 格式:
        [1B cmd] [2B marker: F1 04] [2B length BE] [length bytes payload]

    Args:
        body: HTTP body bytes (二进制, 从 \\r\\n\\r\\n 之后开始)

    Returns:
        list[dict]: 每条 record 一个字典:
            {
                "cmd":       int,        # 命令字节 (0x15/0x16/0x17/0x19)
                "cmd_name":  str,        # 命令名称
                "length":    int,        # payload 长度
                "payload":   bytes,      # payload 原始字节
                "raw":       bytes,      # 完整 record (含头部 5 字节)
            }
    """
    records = []
    offset = 0
    body_len = len(body)

    while offset < body_len:
        # 至少需要 5 字节头部
        if offset + 5 > body_len:
            break

        # 在当前位置查找 marker F1 04
        # 先尝试精确匹配 (标准情况: cmd + F1 04)
        if (offset + 2 <= body_len
                and body[offset + 1:offset + 3] == RECORD_MARKER):
            # 标准格式: [cmd][F1][04][len_hi][len_lo]
            cmd = body[offset]
            length = (body[offset + 3] << 8) | body[offset + 4]
            header_size = 5
        elif (offset + 3 <= body_len
                and body[offset:offset + 2] == RECORD_MARKER):
            # 变体格式: [F1][04][len_hi][len_lo] (缺 cmd 字节)
            # 用 cmd=0x00 占位
            cmd = 0x00
            length = (body[offset + 2] << 8) | body[offset + 3]
            header_size = 4
        else:
            # 没找到 marker, 跳过 1 字节继续搜索
            offset += 1
            continue

        # 检查 payload 是否完整
        if offset + header_size + length > body_len:
            # payload 被截断, 能取多少取多少
            length = body_len - offset - header_size

        payload = body[offset + header_size:offset + header_size + length]
        raw = body[offset:offset + header_size + length]

        records.append({
            "cmd": cmd,
            "cmd_name": MMTLS_CMD_NAMES.get(cmd, f"unknown_0x{cmd:02X}"),
            "length": length,
            "payload": payload,
            "raw": raw,
        })

        # 跳到下一条 record
        offset += header_size + length

    return records


def parse_mmtls_response(response: bytes) -> tuple[bytes, bytes, list[dict]]:
    """
    解析完整的 MMTLS HTTP 响应, 返回 (headers, body, records)。

    Args:
        response: 完整的 HTTP 响应 bytes

    Returns:
        (http_headers, http_body, records):
            http_headers: bytes  — HTTP 头部分 (含尾部 \\r\\n\\r\\n)
            http_body:    bytes  — HTTP body 原始字节
            records:      list[dict] — parse_mmtls_body() 的结果
    """
    header_end = b"\r\n\r\n"
    if header_end in response:
        headers, body = response.split(header_end, 1)
        http_headers = headers + header_end
    else:
        http_headers = response
        body = b""

    records = parse_mmtls_body(body)
    return http_headers, body, records


def extract_mmtls_packets(response: bytes) -> list[bytes]:
    """
    传入完整 HTTP 响应, 返回每个 MMTLS record 的原始 bytes。

    Args:
        response: 完整的 HTTP 响应 bytes

    Returns:
        list[bytes]: 每条 MMTLS record 的原始数据 (含 5 字节头)

    Example:
        >>> packets = extract_mmtls_packets(response)
        >>> for pkt in packets:
        ...     print(pkt.hex())
    """
    header_end = b"\r\n\r\n"
    if header_end in response:
        _, body = response.split(header_end, 1)
    else:
        body = response

    records = parse_mmtls_body(body)
    return [r["raw"] for r in records]


def print_mmtls_response(response: bytes):
    """以可读格式打印 MMTLS 响应的完整结构。"""
    http_headers, body, records = parse_mmtls_response(response)

    log("=" * 70)
    log("MMTLS Response 解析")
    log("=" * 70)

    # HTTP 头
    header_text = http_headers.decode("ascii", errors="replace")
    log(f"\n[HTTP Headers] ({len(http_headers)} bytes):")
    for line in header_text.strip().split("\r\n"):
        log(f"  {line}")

    log(f"\n[Body] {len(body)} bytes, 共 {len(records)} 条 MMTLS record\n")

    # 每条 record
    for i, rec in enumerate(records, 1):
        log(f"── Record {i}: cmd=0x{rec['cmd']:02X} ({rec['cmd_name']}), "
            f"len={rec['length']}, total={len(rec['raw'])} bytes")
        hex_dump(f"  payload", rec["payload"])


# ═══════════════════════════════════════════════════════════════
# MMTLS CGI 请求工具 (通用: 所有 /cgi-bin/micromsg-bin/* 共用一个框架)
# ═══════════════════════════════════════════════════════════════

def build_cgi_sendpack2(cgi_path: str, host_domain: str = "dns.weixin.qq.com.cn") -> bytes:
    """
    构建 sendpack2 的明文 body (CGI 请求通用格式)。

    格式:
        00 00 LL LL  00 F3  [cgi_path ASCII]  00  [host_len]  [host ASCII]  00 00 00 00

    示例:
        body = build_cgi_sendpack2("/cgi-bin/micromsg-bin/newgetdns?uin=...")
        body = build_cgi_sendpack2("/cgi-bin/micromsg-bin/ak8ey?uin=...")
    """
    path_bytes = cgi_path.encode("ascii")
    host_bytes = host_domain.encode("ascii")

    payload = path_bytes + b"\x00" + bytes([len(host_bytes)]) + host_bytes + b"\x00\x00\x00\x00"
    total_len = len(b"\x00\xF3") + len(payload)
    header = b"\x00\x00" + total_len.to_bytes(2, byteorder="big") + b"\x00\xF3"

    return header + payload


def build_newdns_cgi_url(uin: str = "2203638124",
                         client_version: str = "671106896",
                         scene: str = "2",
                         net: str = "1",
                         md5: str = "bbd41f65381cc2e5ea21a07f9c6385ec",
                         devicetype: str = "android-33",
                         lan: str = "zh_CN",
                         sigver: str = "2",
                         xagreementid: str = "0",
                         regctx: str = "680502368") -> str:
    """构建 newgetdns CGI 的 URL 查询字符串 (便捷函数)。"""
    return (
        f"/cgi-bin/micromsg-bin/newgetdns"
        f"?uin={uin}"
        f"&clientversion={client_version}"
        f"&scene={scene}"
        f"&net={net}"
        f"&md5={md5}"
        f"&devicetype={devicetype}"
        f"&lan={lan}"
        f"&sigver={sigver}"
        f"&lasteffecttime="
        f"&xagreementid={xagreementid}"
        f"&networkid="
        f"&networkidctx="
        f"&mccmnc="
        f"&regctx={regctx}"
    )


def send_mmtls_cgi_request(psk_result: bytes,
                           ecdhe_plaintext: bytes,
                           time_bytes: bytes,
                           sendpack2_plaintext: bytes,
                           host: str,
                           port: int,
                           debug: bool = True) -> Optional[Tuple[bytes, bytes]]:
    """
    发送 MMTLS 业务 CGI 请求 (四包结构, 适用于所有 /cgi-bin/micromsg-bin/*)。

    框架 (sendpack0/1/3 固定, 只换 sendpack2):
        sendpack0 = 19 f1 04 [len] [business_auth_sha256]          ← 明文认证
        sendpack1 = 19 f1 04 [len] [AES-GCM(seq=1, 握手确认)]     ← 加密
        sendpack2 = 17 f1 04 [len] [AES-GCM(seq=2, 业务数据)]     ← ★ 唯一变化
        sendpack3 = 15 f1 04 [len] [AES-GCM(seq=3, 结束标记)]     ← 加密

    参数:
        psk_result:           PSK_ACCESS 派生密钥 (32 bytes)
        ecdhe_plaintext:      ECDH 第二步解密的 plaintext (用于 business_auth)
        time_bytes:           struct.pack('>I', timestamp) — 4 字节
        sendpack2_plaintext:  ★ 业务明文 bytes (变化部分)
        host:                 服务器 IP
        port:                 服务器端口
        debug:                是否打印详细日志

    返回:
        成功: 服务器 HTTP 响应 bytes
        失败/超时: None

    用法示例:
        # newgetdns
        body = build_cgi_sendpack2("/cgi-bin/micromsg-bin/newgetdns?uin=...")
        resp = send_mmtls_cgi_request(psk_result, plaintext, time_bytes, body, host, port)

        # ak8ey
        body = build_cgi_sendpack2("/cgi-bin/micromsg-bin/ak8ey?uin=...")
        resp = send_mmtls_cgi_request(psk_result, plaintext, time_bytes, body, host, port)

        # 自定义 body (不使用 CGI 格式)
        body = b"\\x00\\x00\\x01\\x0F..."  # 任意 protobuf / 自定义数据
        resp = send_mmtls_cgi_request(psk_result, plaintext, time_bytes, body, host, port)
    """
    # ── 1. 构建 business_auth_sha256 ──
    business_auth_sha256 = bytes([
        0x00, 0x00, 0x00, 0x9D, 0x01, 0x04, 0xF1, 0x01, 0x00, 0xA8
    ])
    business_auth_sha256 += mmtls_random_bytes(32)
    business_auth_sha256 += time_bytes
    business_auth_sha256 += bytes([
        0x00, 0x00, 0x00, 0x6F, 0x01, 0x00, 0x00, 0x00, 0x6A, 0x00, 0x0F, 0x01
    ])
    business_auth_sha256 += ecdhe_plaintext[6:6 + 0x67]
    hex_dump("business_auth_sha256", business_auth_sha256)

    # ── 2. 派生 business_auth_key → key / iv ──
    business_auth_key = b"early data key expansion" + sha256(business_auth_sha256)
    hex_dump("business_auth_key", business_auth_key)
    business_result = mmtls_hkdf_expand.hmac_kdf_expand(psk_result, business_auth_key, 28)
    hex_dump("business_result", business_result)

    key = business_result[:16]
    iv = business_result[16:]
    hex_dump("key", key)
    hex_dump("iv", iv)

    client_seq = 1

    # ── 3. sendpack0: 明文认证头 ──
    sendpack0 = (b"\x19\xF1\x04"
                 + len(business_auth_sha256).to_bytes(2, byteorder="big")
                 + business_auth_sha256)
    hex_dump("sendpack0", sendpack0)

    # ── 4. sendpack1: 加密握手确认 (seq=1) ──
    sendpack1_plaintext = bytes.fromhex(
        "00 00 00 10 08 00 00 00 0B 01 00 00 00 06 00 12"
    ) + time_bytes
    hex_dump("sendpack1_plaintext", sendpack1_plaintext)

    aad1 = (b"\x00" * 7
            + b"\x01"
            + b"\x19\xF1\x04"
            + (len(sendpack1_plaintext) + 0x10).to_bytes(2, byteorder="big"))
    nonece1, client_seq = get_encrypt_iv(iv, client_seq)
    ciphertext1 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, nonece1, sendpack1_plaintext, aad1)
    hex_dump("sendpack1_ciphertext", ciphertext1)
    sendpack1 = aad1[8:] + ciphertext1
    hex_dump("sendpack1", sendpack1)

    # ── 5. sendpack2: 加密业务数据 ★ (唯一变化的部分) ──
    hex_dump("sendpack2_plaintext", sendpack2_plaintext)

    aad2 = (b"\x00" * 7
            + b"\x02"
            + b"\x17\xF1\x04"
            + (len(sendpack2_plaintext) + 0x10).to_bytes(2, byteorder="big"))
    nonece2, client_seq = get_encrypt_iv(iv, client_seq)
    ciphertext2 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, nonece2, sendpack2_plaintext, aad2)
    hex_dump("sendpack2_ciphertext", ciphertext2)
    sendpack2 = aad2[8:] + ciphertext2
    hex_dump("sendpack2", sendpack2)

    # ── 6. sendpack3: 加密关闭标记 (seq=3) ──
    sendpack3_plaintext = bytes.fromhex("00 00 00 03 00 01 01")
    hex_dump("sendpack3_plaintext", sendpack3_plaintext)

    aad3 = (b"\x00" * 7
            + b"\x03"
            + b"\x15\xF1\x04"
            + (len(sendpack3_plaintext) + 0x10).to_bytes(2, byteorder="big"))
    nonece3, client_seq = get_encrypt_iv(iv, client_seq)
    ciphertext3 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, nonece3, sendpack3_plaintext, aad3)
    hex_dump("sendpack3_ciphertext", ciphertext3)
    sendpack3 = aad3[8:] + ciphertext3
    hex_dump("sendpack3", sendpack3)

    # ── 7. 拼接四包 → HTTP 包装 → 发包 ──
    sendpack = sendpack0 + sendpack1 + sendpack2 + sendpack3
    hex_dump("sendpack (四包合并)", sendpack)

    request = build_mmtls_request(sendpack, host=host)

    log(f"\n{'='*70}")
    log(f"send_mmtls_cgi_request → {host}:{port}")
    log(f"{'='*70}")
    hex_dump("request", request)
    t0 = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect((host, port))
            t_conn = time.time()
            log(f"  [OK] 已连接 ({t_conn - t0:.3f}s)")

            sock.sendall(request)
            t_send = time.time()
            log(f"  [OK] 已发送 ({t_send - t_conn:.3f}s, {len(request)} bytes)")

            try:
                response = recv_http_response(sock)
                t_recv = time.time()
                if response:
                    log(f"  [OK] 收到响应 ({len(response)} bytes, {t_recv - t_send:.3f}s)")
                    hex_dump("newdns_response", response)
                    return response, business_auth_sha256
                else:
                    log(f"  [EMPTY] 收到 0 字节响应 (连接已关闭)")
                    return None
            except socket.timeout:
                log(f"  [TIMEOUT] 10 秒内未收到响应")
                return None

    except Exception as e:
        log(f"  [ERROR] 连接失败: {e}")
        return None


# ── 便捷封装: 直接传 CGI 路径即可 ──

def send_newdns_request(psk_result: bytes,
                        ecdhe_plaintext: bytes,
                        time_bytes: bytes,
                        host: str,
                        port: int,
                        cgi_path: Optional[str] = None,
                        debug: bool = True) -> Optional[bytes]:
    """发送 NewDNS 请求 (send_mmtls_cgi_request 的便捷封装)。"""
    if cgi_path is None:
        cgi_path = build_newdns_cgi_url()
    sendpack2_body = build_cgi_sendpack2(cgi_path)
    return send_mmtls_cgi_request(psk_result, ecdhe_plaintext, time_bytes,
                                  sendpack2_body, host, port, debug)


def recv_mmtls_cgi_response(response: bytes,
                             psk_result: bytes,
                             client_business_auth_sha256: bytes,
                             time_bytes: bytes,
                             debug: bool = True) -> Optional[list[bytes]]:
    """
    send_mmtls_cgi_request 的逆操作 — 解密 MMTLS CGI 响应。

    SHA256 输入 = client_auth + sendpack1_plaintext + server_auth

    Args:
        response:                      完整的 HTTP 响应 bytes
        psk_result:                    PSK_ACCESS 派生密钥 (32 bytes)
        client_business_auth_sha256:   发送端构造的 161 字节 auth
        time_bytes:                    struct.pack('>I', timestamp)
        debug:                         是否打印详细日志

    Returns:
        [plaintext1, plaintext2, plaintext3]: 解密后的三个包
    """
    packets = extract_mmtls_packets(response)
    if len(packets) < 4:
        log(f"  [ERROR] 响应包不足 4 个, 实际: {len(packets)}")
        return None

    for i, pkt in enumerate(packets):
        hex_dump(f"packets[{i}]", pkt)

    # ── 1. business_auth_sha256 = client_auth + sendpack1_plaintext + server_auth ──
    server_auth = packets[0][5:]
    sendpack1_plaintext = bytes.fromhex(
        "00 00 00 10 08 00 00 00 0B 01 00 00 00 06 00 12"
    ) + time_bytes
    business_auth_sha256 = client_business_auth_sha256 + sendpack1_plaintext + server_auth
    hex_dump("business_auth_sha256 (client+server)", business_auth_sha256)

    # ── 2. 派生 business_auth_key → key / iv (与发送端完全一致) ──
    business_auth_key = b"handshake key expansion" + sha256(business_auth_sha256)
    hex_dump("business_auth_key", business_auth_key)
    business_result = mmtls_hkdf_expand.hmac_kdf_expand(psk_result, business_auth_key, 28)
    hex_dump("business_result", business_result)

    key = business_result[:16]
    iv = business_result[16:]
    hex_dump("key", key)
    hex_dump("iv", iv)

    server_seq = 1
    plaintexts = []

    # ── 3. 解密 packets[1..3] ──
    for i in range(1, 4):
        pkt = packets[i]
        cmd_byte = pkt[0:1]
        marker = pkt[1:3]     # F1 04
        length_bytes = pkt[3:5]
        ciphertext = pkt[5:]  # 去掉 5 字节头

        # AAD 构造 (与发送端一致)
        aad = (b"\x00" *7
               + i.to_bytes(1, byteorder="big")
               + cmd_byte + marker
               + length_bytes)
        hex_dump(f'aad{i}', aad)
        
        nonece, server_seq = get_decrypt_iv(iv, server_seq)
        hex_dump(f'nonece{i}', nonece)

        hex_dump(f'ciphertext{i}', ciphertext)
        plaintext = mmtls_aes_gcm.mmtls_aes_gcm_decrypt(key, nonece, ciphertext, aad)

        hex_dump(f"plaintext[{i}] (decrypted)", plaintext)
        plaintexts.append(plaintext)

    return plaintexts


def send_cgi_request(psk_result: bytes,
                     ecdhe_plaintext: bytes,
                     time_bytes: bytes,
                     cgi_path: str,
                     host: str,
                     port: int,
                     host_domain: str = "dns.weixin.qq.com.cn",
                     debug: bool = True) -> Optional[bytes]:
    """发送任意 CGI 请求 (一行调用, 最简接口)。

    用法:
        resp = send_cgi_request(psk, plain, time_bytes,
                                "/cgi-bin/micromsg-bin/newsync?uin=...",
                                "101.227.131.167", 443)
    """
    sendpack2_body = build_cgi_sendpack2(cgi_path, host_domain)
    return send_mmtls_cgi_request(psk_result, ecdhe_plaintext, time_bytes,
                                  sendpack2_body, host, port, debug)


# ═══════════════════════════════════════════════════════════════
# MMTLS 首次握手 (ClientHello / ECDH)
# ═══════════════════════════════════════════════════════════════

# 原始 a.txt 抓包 (HTTP 头 + body, 456 字节)
REQUEST_1_ORIGINAL = bytes([
    0x50, 0x4F, 0x53, 0x54, 0x20, 0x2F, 0x6D, 0x6D, 0x74, 0x6C, 0x73, 0x2F, 0x33, 0x66, 0x66, 0x38,
    0x31, 0x39, 0x36, 0x61, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x0D, 0x0A, 0x41,
    0x63, 0x63, 0x65, 0x70, 0x74, 0x3A, 0x20, 0x2A, 0x2F, 0x2A, 0x0D, 0x0A, 0x43, 0x61, 0x63, 0x68,
    0x65, 0x2D, 0x43, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x3A, 0x20, 0x6E, 0x6F, 0x2D, 0x63, 0x61,
    0x63, 0x68, 0x65, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x3A,
    0x20, 0x63, 0x6C, 0x6F, 0x73, 0x65, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D,
    0x4C, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x3A, 0x20, 0x32, 0x32, 0x36, 0x0D, 0x0A, 0x43, 0x6F, 0x6E,
    0x74, 0x65, 0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A, 0x20, 0x61, 0x70, 0x70, 0x6C, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6F, 0x63, 0x74, 0x65, 0x74, 0x2D, 0x73, 0x74, 0x72,
    0x65, 0x61, 0x6D, 0x0D, 0x0A, 0x48, 0x6F, 0x73, 0x74, 0x3A, 0x20, 0x64, 0x6E, 0x73, 0x2E, 0x77,
    0x65, 0x69, 0x78, 0x69, 0x6E, 0x2E, 0x71, 0x71, 0x2E, 0x63, 0x6F, 0x6D, 0x2E, 0x63, 0x6E, 0x0D,
    0x0A, 0x55, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3A, 0x20, 0x6D, 0x6D, 0x74, 0x6C, 0x73, 0x0D,
    0x0A, 0x55, 0x73, 0x65, 0x72, 0x2D, 0x41, 0x67, 0x65, 0x6E, 0x74, 0x3A, 0x20, 0x4D, 0x69, 0x63,
    0x72, 0x6F, 0x4D, 0x65, 0x73, 0x73, 0x65, 0x6E, 0x67, 0x65, 0x72, 0x20, 0x43, 0x6C, 0x69, 0x65,
    0x6E, 0x74, 0x0D, 0x0A, 0x0D, 0x0A, 0x16, 0xF1, 0x04, 0x00, 0xDD, 0x00, 0x00, 0x00, 0xD9, 0x01,
    0x04, 0xF1, 0x01, 0xC0, 0x2B, 0x9F, 0x27, 0xB5, 0x6F, 0xED, 0x71, 0x4A, 0xB6, 0x7E, 0x27, 0x5A,
    0xD9, 0x43, 0x8F, 0xBA, 0xC7, 0x82, 0x0C, 0xDF, 0xEA, 0x9C, 0x5D, 0x91, 0x94, 0x40, 0x3F, 0x6B,
    0x2F, 0x64, 0x2D, 0x72, 0xCE, 0x6A, 0x2D, 0x40, 0x62, 0x00, 0x00, 0x00, 0xAB, 0x01, 0x00, 0x00,
    0x00, 0xA6, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x00, 0x07, 0x00, 0x41, 0x04,
    0x4A, 0x4F, 0xB4, 0x10, 0x6F, 0x46, 0xAF, 0x45, 0xF6, 0xBD, 0xE0, 0x4F, 0x66, 0x54, 0x21, 0x6F,
    0xF1, 0xB9, 0x4E, 0xF7, 0xFF, 0x70, 0xAA, 0xB1, 0xFB, 0xD6, 0xB0, 0x56, 0x30, 0xA7, 0x55, 0x9C,
    0xFC, 0xBE, 0x1C, 0x92, 0x6F, 0xC5, 0x55, 0x99, 0x45, 0x6C, 0xF6, 0x68, 0x62, 0x70, 0x7F, 0x0B,
    0x2B, 0x99, 0x13, 0xAA, 0x1A, 0x9D, 0x26, 0xD3, 0x14, 0x24, 0x8C, 0xC5, 0x67, 0xF8, 0xB7, 0x43,
    0x00, 0x00, 0x00, 0x47, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x41, 0x04, 0x0D, 0xB6, 0x36, 0xF3, 0xD2,
    0x63, 0xA6, 0x0F, 0xC0, 0x6A, 0xCE, 0x6E, 0x0F, 0x22, 0x81, 0x6E, 0x4E, 0x59, 0x65, 0xB4, 0x81,
    0xF0, 0xF6, 0x8D, 0x13, 0x99, 0x48, 0x9F, 0x25, 0x6C, 0x3B, 0x4D, 0x04, 0x1A, 0x21, 0xBF, 0xF1,
    0xDA, 0x8A, 0x3C, 0x9D, 0xAE, 0x9B, 0xC2, 0xE0, 0x8A, 0x43, 0xE3, 0xE1, 0xE5, 0x8A, 0x77, 0x33,
    0x1E, 0x9D, 0x05, 0xFD, 0x5E, 0x1F, 0x2F, 0xAE, 0xD8, 0xA5, 0x77, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0xE8,
])

# 关键偏移 (相对 packet 起始位置)
PKT_RANDOM_OFFSET = 245        # body[15] = packet[0xF5]
PKT_CLIENT_PUB_OFFSET = 303    # body[73]  = packet[0x12F] (含 0x04 marker)
PKT_SERVER_PUB_OFFSET = 378    # body[148] = packet[0x17A] (含 0x04 marker)


def build_mmtls_client_hello_packet() -> Tuple[bytes, object, object, bytes]:
    """重新生成 client random + 两个 P-256 公钥, 在原 packet 基础上替换。

    返回:
        (packet_bytes, kp_client, kp_server, new_random)
    """
    packet = bytearray(REQUEST_1_ORIGINAL)

    new_random = secrets.token_bytes(32)
    kp_client = generate_p256_keypair()
    kp_server = generate_p256_keypair()

    log(f"[1] 新 client random (32B): {new_random.hex()}")
    log(f"[2] 新 client pubkey (65B): {kp_client.raw_public.hex()}")
    log(f"[3] 新 server pubkey (65B): {kp_server.raw_public.hex()}")
    log(f"\n[替换偏移]")
    log(f"  Client random: packet[{PKT_RANDOM_OFFSET}:{PKT_RANDOM_OFFSET + 32}]")
    log(f"  Client pubkey: packet[{PKT_CLIENT_PUB_OFFSET}:{PKT_CLIENT_PUB_OFFSET + 65}]")
    log(f"  Server pubkey: packet[{PKT_SERVER_PUB_OFFSET}:{PKT_SERVER_PUB_OFFSET + 65}]")

    packet[PKT_RANDOM_OFFSET:PKT_RANDOM_OFFSET + 32] = new_random
    packet[PKT_CLIENT_PUB_OFFSET:PKT_CLIENT_PUB_OFFSET + 65] = kp_client.raw_public
    packet[PKT_SERVER_PUB_OFFSET:PKT_SERVER_PUB_OFFSET + 65] = kp_server.raw_public

    return bytes(packet), kp_client, kp_server, new_random


# ═══════════════════════════════════════════════════════════════
# main — 完整 MMTLS 握手 + NewDNS 请求流程
# ═══════════════════════════════════════════════════════════════



def _generate_ecdh_payload(frida_result) -> bytes:
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

    iv = mmtls_random_bytes(12)
    _, plaintext, plaintext_len = ZLibCompress(mmtls_random_bytes(32))
    hex_dump("iv", iv)
    hex_dump("plaintext1", plaintext)
    log(len(plaintext))
    key = derived[0:0x18]

    log(len(key))
    ciphertext = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key, iv, plaintext, aad)
    ciphertext=ciphertext[:-16]+iv+ciphertext[-16:]
    log(ciphertext)
    hex_dump("ciphertext", ciphertext)

    # ── Frida 获取 toProtoBuf ──
    from wexchatqrlogin.frida_proto_buf import call_to_proto_buf



    if frida_result is None:
        raise RuntimeError("Frida 获取 toProtoBuf 失败，无法继续")

    log(frida_result)
    hexdump(frida_result[0:100])

    key2 = frida_result[0x8:0x8 + 0x18]
    log(key2)
    hexdump(key2)

    iv2 = mmtls_random_bytes(12)
    ciphertext2 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key2, iv2, plaintext, aad)
    ciphertext2=ciphertext2[:-16]+iv2+ciphertext2[-16:]
    _, plaintext3, plaintext3_len = ZLibCompress(frida_result)

    aad3 = sha256(changshu + kp_client.raw_public + ciphertext + ciphertext2)
    log(aad3)
    iv3 = mmtls_random_bytes(12)

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
    sha256_de=derived_key[0x18:]
    log(key3)
    hexdump(key3)
    ciphertext3 = mmtls_aes_gcm.mmtls_aes_gcm_encrypt(key3, iv3, plaintext3, aad3)
    log(ciphertext3)
    ciphertext3=ciphertext3[:-16]+iv3+ciphertext3[-16:]
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

    return proto_bytes,sha256_de


def main():
    HOST = "183.47.121.33"    # 微信内置 IP (builtiniplist)
    PORT = 443

    log("=" * 70)
    log("WeChat MMTLS 完整流程: ClientHello → ECDH → NewDNS")
    log("=" * 70)

    # ── 阶段 1: MMTLS ClientHello (ECDH 密钥交换) ──
    packet, kp_client, kp_server, new_random = build_mmtls_client_hello_packet()
    log(f"\n[OK] ClientHello 构造完成: {len(packet)} bytes")
    log(f"  验证: client random in body: {new_random in packet}")
    log(f"  验证: client pubkey in body: {kp_client.raw_public in packet}")
    log(f"  验证: server pubkey in body: {kp_server.raw_public in packet}")

    log(f"\n{'='*70}")
    log(f"阶段 1: ClientHello → {HOST}:{PORT}")
    log("="*70)

    t0 = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(10.0)
        sock.connect((HOST, PORT))
        t1 = time.time()
        log(f"  [OK] 已连接 ({t1 - t0:.3f}s)")

        sock.sendall(packet)
        t2 = time.time()
        log(f"  [OK] ClientHello 已发送 ({t2 - t1:.3f}s)")

        try:
            response = recv_http_response(sock)
            t3 = time.time()
            if not response:
                log("  [EMPTY] 收到 0 字节响应")
                return
            log(f"  [OK] 收到 ServerHello ({len(response)} bytes, {t3 - t2:.3f}s)")

            # ── 阶段 2: 解密 ServerHello, ECDH 密钥派生 ──
            log(f"\n{'='*70}")
            log("阶段 2: ECDH 密钥派生")
            log("="*70)

            # 提取客户端 request_param1 (在发 packet 之前已提取)
            client_params = packet.split(b'\x16\xF1\x04')
            client_param1 = client_params[1][2:]  # 客户端的第一个 record body

            # 拆解响应: params[1]=server_param1, params[2]=ciphertext1, params[3]=ciphertext2
            params = response.split(b'\x16\xF1\x04')

            server_param1 = params[1][2:]
            hex_dump("server_param1", server_param1)

            response_pub_key = params[1][2:]  # server_param1
            response_pub_key = response_pub_key[0x3A:0x3A + 0x41]  # 从 server_param1 中提取公钥
            hex_dump("response_pub_key", response_pub_key)

            # ECDH 密钥交换
            ret, derived = mmtls_ecdh_kdf(415, response_pub_key, kp_client.der_private)
            log(f"  ECDH ret={ret}")

            # handshake key expansion (客户端 + 服务端 的 param1)
            sha256_1 = b"handshake key expansion" + sha256(client_param1 + server_param1)
            result = mmtls_hkdf_expand.hmac_kdf_expand(derived, sha256_1, 56)

            Decryptmmtlskey = result[16:32]
            DecryptmmtlsIv = result[44:]
            hex_dump("Decryptmmtlskey", Decryptmmtlskey)
            hex_dump("DecryptmmtlsIv", DecryptmmtlsIv)

            # 解密第一个加密块 (seq=1, cmd=16 f1 04)
            server_seq = 1
            nonece, server_seq = get_decrypt_iv(DecryptmmtlsIv, server_seq)
            ciphertext = params[2][2:]
            aad = b'\x00' * 7 + b'\x01' + b'\x16\xF1\x04' + params[2][0:2]
            plaintext = mmtls_aes_gcm.mmtls_aes_gcm_decrypt(Decryptmmtlskey, nonece, ciphertext, aad)
            hex_dump("plaintext (step1)", plaintext)

            # PSK_ACCESS 派生 (客户端 + 服务端 param1 + step1 plaintext)
            sha256_2 = b'PSK_ACCESS' + sha256(client_param1 + server_param1 + plaintext)
            psk_result = mmtls_hkdf_expand.hmac_kdf_expand(derived, sha256_2, 32)
            hex_dump("psk_result", psk_result)

            # 解密第二个加密块 (seq=2, cmd=16 f1 04) — 用于 business_auth
            nonece, server_seq = get_decrypt_iv(DecryptmmtlsIv, server_seq)
            ciphertext2 = params[3][2:]
            aad2 = b'\x00' * 7 + b'\x02' + b'\x16\xF1\x04' + params[3][0:2]
            ecdhe_plaintext2 = mmtls_aes_gcm.mmtls_aes_gcm_decrypt(Decryptmmtlskey, nonece, ciphertext2, aad2)
            hex_dump("ecdhe_plaintext2 (step2)", ecdhe_plaintext2)

            # ── 阶段 3: NewDNS 请求 ──
            log(f"\n{'='*70}")
            log("阶段 3: NewDNS CGI 请求")
            log("="*70)

            timestamp = int(time.time())
            time_bytes = struct.pack('>I', timestamp)

            # 方式 1: 用通用函数, 手动构建 sendpack2
            cgi_path = build_newdns_cgi_url()
            sendpack2_body = build_cgi_sendpack2(cgi_path)
            response, _ = send_mmtls_cgi_request(
                psk_result=psk_result,
                ecdhe_plaintext=ecdhe_plaintext2,
                time_bytes=time_bytes,
                sendpack2_plaintext=sendpack2_body,
                host=HOST,
                port=PORT,
            )

            # 方式 2 (等价的便捷封装):
            # response = send_newdns_request(psk_result, ecdhe_plaintext2, time_bytes, HOST, PORT)

            # 方式 3 (任意 CGI 一行调用):
            # response = send_cgi_request(psk_result, ecdhe_plaintext2, time_bytes,
            #                            "/cgi-bin/micromsg-bin/ak8ey?uin=...",
            #                            HOST, PORT)

            if response:
                log(f"\n[SUCCESS] NewDNS 请求完成!")
            else:
                log(f"\n[FAILED] NewDNS 请求未收到响应")

            # ── 阶段 4: HybridEcdhEncrypt (ak8ey) 请求 ──
            log(f"\n{'='*70}")
            log("阶段 4: HybridEcdhEncrypt (ak8ey) 请求")
            log("="*70)

            timestamp = int(time.time())
            time_bytes = struct.pack('>I', timestamp)

            try:
                # ── 从 dump 提取参考数据: pack_head + protobuf 明文 ──
                # pack_head (0x73 bytes) = CGI 路径/主机/参数头, 不变
                # pack_body = ciphertext(216) + iv(12) + tag(16), 需要动态生成
                hex_data ='''
00 00 26 40 00 21 2F 63 67 69 2D 62 69 6E 2F 6D 69 63 72 6F 6D 73 67 2D 62 69 6E 2F 73 65 63 61 75 74 6F 61 75 74 68 00 13 73 68 6F 72 74 2E 77 65 69 78 69 6E 2E 71 71 2E 63 6F 6D 00 00 26 04 BF BE CF 28 00 47 50 83 58 D9 6C 8D 03 08 02 00 00 00 00 4B B4 DD AA 42 B8 00 FB 05 D5 4B D5 4B A8 4E 02 00 FF 9B C2 C5 91 04 00 00 00 00 00 08 01 12 46 08 9F 03 12 41 04 F1 85 FD B7 01 C0 49 FD 55 8C DD F9 23 AF A5 A7 3F 64 8E CA 7F EF C7 F1 C2 D5 84 55 0D F6 8C E3 62 27 17 8B 2F 12 A7 D3 5E 1E 4C 7A 1C 14 F3 56 1A 0D 40 A2 3D 95 2E 0B 68 E5 EB F0 A4 8D EF D8 1A 45 49 78 43 E9 4A 6B F2 F3 D4 B1 F6 3F 3B 94 2E 30 00 4F 4C AB 19 12 CD 65 2D 67 80 AF 0F F0 1B C8 AE D4 E9 CB 46 93 97 65 21 B4 CE 91 8B 2B DE 5C 8A A4 73 68 9A FA 54 3A 3A FD 06 E9 46 34 1A C2 D6 3D A4 83 73 22 45 E4 DF CE 4B 97 02 2A 42 5B AB 69 29 3D A6 7D EB DD 4E 5D 95 34 61 D6 07 A4 19 79 47 1B 3E A2 22 32 8D 8C 9E A5 57 36 7B 0A C9 A0 FD BF 4C F5 31 F4 E5 9B 16 C5 C9 4C AC 10 E3 CC 36 F7 5F 02 E0 E4 9C 36 45 86 2A FA 49 BF D8 F6 6A B7 D6 F7 CD 17 1A D0 47 06 94 27 5B C1 07 EC 48 27 8C A5 A9 01 FD 28 D5 04 2B 06 8C 74 D8 5F A0 E8 08 9A D4 F4 6E 85 5C D3 00 C2 41 02 C8 BD DC 01 04 FC CD 0F F1 45 AC E2 D1 4C E0 BD 4A E4 86 10 C6 EC 57 41 3E B2 53 11 5F BD 45 9C 52 06 9C 7F BD 85 E4 B0 76 1D B8 98 F3 70 8F 0B 2E 5E 4E F6 90 9B 9F 9E EB FC 79 9D 1F F9 39 CB A7 C9 38 74 26 5A 43 46 8E CA 12 36 39 93 6A 90 CD 60 2E 56 96 90 86 B5 6F FF 2C 04 C6 F7 0E 0D 00 57 F3 14 14 1F 40 8D F6 D1 1B 15 3B 63 A9 87 64 D4 02 00 E5 87 4A 3B 91 5E 51 A6 A5 40 2A CA 55 B6 02 8E 23 27 D0 1A 07 E2 F1 CF 25 F6 83 2F 18 D4 2C D6 2A F6 EB 6B C3 3A CD 5A 38 B1 08 D9 1F B5 16 4F B8 05 8D 57 D0 83 7A 9A 35 FC E4 49 F4 8D 0B FC 3E 48 D0 EB 7E 02 77 53 E8 8F 42 B1 BA 3A C0 7E B9 1C 18 4D 67 13 2A 20 65 F1 A5 CE 51 88 79 25 9C 99 76 77 31 8B 93 81 A4 53 80 05 2F 89 6A 3A FF 5F B4 2E C3 DB 40 24 1A 5C 71 B2 FB 6A 33 9B 5F C8 02 A9 4B C9 A4 F6 7C DF F8 4B 62 6C BC E9 A6 34 FF F5 F3 F3 C4 32 97 0E 53 25 EA AC A0 89 D6 1E 06 36 97 EB A5 3B F7 1F 70 2E A0 0E DA 9B 97 F2 5B 42 D0 12 B7 99 F4 53 B3 8B 19 9A 79 4A C1 54 AC 71 86 6A 73 3A 77 EB A3 80 A7 08 4E 64 EC B8 50 95 F7 FE F1 D5 57 C2 8A E8 1C 9E 93 D5 D1 BE 51 2F AF 62 A1 96 9B 45 99 03 96 F2 9A 0F 65 40 19 79 F3 B0 FD 51 DB B7 44 2B 19 6F D4 D2 2B 3A 34 B3 34 B6 57 12 45 7F F7 59 74 8E 71 A2 13 9D 37 3A F4 68 B3 E4 B3 03 FF 19 AE 8C 2D E1 04 78 BA 1F A8 8B E9 46 67 6F EF 8F EC 75 73 ED 39 AF 78 F2 4C C0 B1 26 31 E5 C3 50 29 DF 69 8B 7F 10 66 A6 8D B6 16 E0 7B 02 0F 40 7B CE 99 E3 AA 21 61 2B DD 02 0D A8 67 5E 80 CD F5 9B BB E3 61 71 E4 65 8D 3A 41 81 62 53 3F 9E 55 13 AC A0 87 C5 C3 58 40 66 CE 77 EC B5 29 2E 6B 2C 47 C0 7C AC 28 38 2F 09 00 DA 59 2A 8F 48 5B 14 C5 47 97 4A 2A B5 D1 D2 C8 8A F1 8E B8 84 9C AB FC B0 D9 62 A3 CF CE B2 E8 A2 AE E1 3B DA B3 8D 3D A2 30 86 F4 2C D5 8C 3B DD 8A BB 08 0D 6A F7 9B AB 65 03 F9 2F 8B 6E FA F5 1A C2 74 66 36 10 21 FC 9F B9 74 9C 1A 4B 23 6F BC BC 87 84 11 2C 05 B5 83 0A 8B 60 25 96 E4 67 93 75 D0 DC E4 28 7E C3 09 21 8C 59 4D E3 7E 57 6E 63 EB AC B0 2C E7 B4 58 63 CE 9D 74 65 BF 2F 15 55 53 E0 AB B3 EE E8 CC 90 AA DC 88 98 38 37 D9 63 7A A4 59 E0 43 34 31 DD 88 25 29 DC E5 21 28 51 10 AD 41 AD 2E C0 D4 FA AB C3 CC 5F 2F 2C 54 62 93 05 10 A5 BE E1 20 CD 79 03 63 AF D7 AB 84 C5 81 84 CF 90 16 28 A2 EA C1 C6 C0 0D 58 F6 1B 48 95 F3 9F DF A7 3B 5E 00 C5 96 D3 7F DA 80 74 CB A4 5F 84 0C CF 53 B9 53 2F C6 36 E4 FF 56 80 4E C6 45 83 9C 2B D7 39 0A 8D 6F 8F 33 40 1A 1E E2 6A 75 AF A2 A7 F4 D7 F2 28 15 1D 63 DA 22 D1 87 F3 19 89 04 7C 78 57 D0 FE DC A4 70 85 8B 26 B6 0B 59 F1 5F 8C 91 D2 17 89 5F DA 14 C0 BB 14 7E BA 96 06 9E D7 E6 D7 10 51 97 B0 EB 37 CC DC 72 2A F1 36 66 25 46 F6 0A B3 DE D6 F1 4E AE D2 60 EF 40 A3 2C 2B 37 60 CA 0F E7 A9 54 74 99 D0 8C D3 BD 1D D6 B9 9E 3A EE AB AF C9 2B F2 D8 6A DB 64 75 A0 21 9B 6B 38 89 6F E4 F6 37 C1 5E 15 A2 51 3E 2F 61 4C A2 A3 F1 D8 E5 0C DB F4 50 FB F8 4C C6 9B A2 27 8B 5B 60 8C DF ED FA E2 2A 6A D7 50 19 28 47 1E AA 08 6B 87 A6 5C A5 FF 20 63 C4 A4 99 16 D9 60 70 95 0E 9D BE 83 14 52 01 29 F5 09 16 1F 24 D9 4A 50 4A 3C 8E B3 70 08 85 7A 18 C0 90 88 A7 4D 50 47 71 A2 F1 4B 32 F4 5D A2 66 12 15 8E 8A 59 17 13 A5 DC C0 05 61 B4 D6 CF 33 67 75 FE 66 1B 4C 12 C5 E2 6A 3C 0D 50 FA D4 A6 E6 71 65 C8 7E 3A 92 98 47 4E B8 0D 5A 83 69 5B 85 77 C3 44 BF 32 76 38 7B E4 E6 59 3A E1 1B 51 B4 87 6D 0F BF 87 6F 04 87 F9 20 A8 6F 58 07 8C AB E0 3F 3A 6A 8F 01 A3 8B 2D 74 7E 2F 59 64 C2 30 45 95 C3 56 19 83 92 76 96 47 7B D7 7E 96 C8 2C 52 38 61 7E 10 37 9C CE 67 39 49 9F 01 2C CD 56 3B B6 89 C1 58 03 01 0E 66 76 30 63 DF 67 20 01 31 09 B1 EB 00 A1 F8 01 5B CE 43 D9 23 9D BE 25 24 8F AA 46 40 6C A7 E1 39 B1 8E D9 FD A7 DA 9B 50 33 4B A7 27 EA 40 A4 2E 7B 02 FD D0 BF 28 C4 3F 94 C7 AF 56 1A 8B C3 4B F0 82 14 CD A8 6E C4 9A 7F B6 44 5B ED F9 20 5C A0 0B DD B9 84 0F 8A 83 25 96 74 DF 15 1A 21 25 B9 56 08 62 2F DF 40 08 CE A3 F8 4F 20 0D 25 67 4B 38 AA 7C C5 1A 29 D1 BA 3A 38 E4 6A 3E C0 C5 D3 DB EB D7 59 45 22 67 56 EB 8F B2 D1 F3 A1 BC 81 4D 15 87 3E 68 22 19 1D 18 7E 2C 39 E3 AD 62 DF EE 76 91 90 FC D8 AC C8 D3 B5 CC 61 09 D4 2D 1C 0C 75 09 35 31 CD F6 47 D1 F3 8E 66 93 FB 02 42 1E 99 FF F7 67 A3 59 0A 77 7A 8E 05 2B 0B 2C C8 F1 E2 4B D9 83 FA 3D 99 1B 12 29 3D BA CB 08 C1 01 98 04 B9 D4 38 D9 91 40 27 A1 FB 3E 17 C1 F8 4C 7E EB D0 DC CA 73 40 6A D8 18 B4 FA 70 71 F0 91 C8 EE 42 7C F7 9A 07 C2 D3 10 18 B4 E8 DB 1A 19 45 3B E0 74 F0 42 DB C8 73 D8 10 BC 9F B1 81 63 84 C2 B2 4F F8 A4 2F 5F 3D 24 4D 84 9B EB D7 59 BC 25 E5 E4 86 04 AB 1B 65 E8 E4 76 4C 43 3E 10 D0 19 4A 6F B1 BA 10 4D 07 3D 3F 8F D4 89 38 50 72 8B AC F1 98 8D CF 94 89 87 E4 28 5C DA 41 70 33 74 1C 40 3D 55 2E 6F 38 6C F0 04 61 0D A1 F2 C0 56 F8 39 CC 8E 21 FB 7E 37 C5 58 C8 88 18 06 81 BC D5 FA 50 EB 44 1D EE 5B 6E E1 D4 BD 9B 1F 36 B3 5A 6B F9 D1 B7 29 9F AC 8D 61 92 AB 94 29 83 F4 F2 44 D2 AD 85 98 78 E4 EB 33 48 1B 86 4B F2 9B 65 2F 6D EC 62 C6 3C DB 7D EB 1A CC 6F A9 FC 15 A0 E4 A5 0E 99 B2 A8 FD AE 08 2D 45 23 94 69 7D 91 D4 64 05 FC 3B C7 9A D9 23 2B 4D AA CA 6A 03 33 70 22 25 FD AD 8E 95 3E FA A9 6B 41 93 22 E6 4D 51 7B 8D DB C2 B3 91 5D F9 A0 A9 28 DA 6E CD 18 63 AB E7 09 F1 A7 A1 DE E6 0B 81 AE 97 A1 72 8C 9D 24 7A E6 F6 94 C9 77 83 12 3F 15 21 D9 BA C1 16 2C 44 D1 EC 8B 9D AF 2D E1 74 2E 30 99 3E 12 E1 9F 09 63 57 A0 66 78 3E F9 67 F6 FE C9 61 30 41 6E F4 B2 22 19 F3 DC 96 33 92 3F 0B 0B CC B2 46 AD C4 30 61 78 A7 27 DA 8B D2 AA 5A CF 49 C7 9E 9B 57 8F 01 15 8D 26 3A ED 16 90 29 DA 1F D4 E5 5E 2B 5E DB 9A D2 D6 64 AD FA 39 2B 18 26 E2 40 10 8A EA 08 86 80 0E 20 A2 A5 06 9A E2 3C 2D 71 AF D2 07 73 C8 55 96 30 35 17 60 AC 31 2A F6 69 44 A6 6F 5C 40 05 81 6C 1A B0 72 C3 DD 2D B3 66 B6 EF E4 A4 3F 2B 3B E8 D6 DA 14 4E 36 F0 9C 18 31 2B C7 EF 4B F9 FC D0 F6 C8 3C AE A1 33 29 4B 12 32 93 00 7F 7C 66 29 AD B9 6F 3C C0 21 C1 E5 A4 51 66 1F E7 C5 09 BB FC B7 13 1A 8A CC 4D 7D 47 1C 70 F6 46 19 9A 37 69 73 3B 03 25 80 DE B4 CB A1 17 00 98 50 75 5D 2C D9 9C BA 1F FD 05 B5 73 4E 00 84 79 CD 3B 9A 26 87 9B CD D0 89 A7 BE B4 44 2E A5 38 4E 8F FE 5B 3A 85 C0 4B 3E AB 91 70 A6 0A 17 BD 5F 33 32 53 68 D5 51 AF 50 AA 27 A6 98 5E 54 9A 8B AB D7 1D 13 0C B6 E7 E2 6D D0 B8 A4 5F 06 8D 0A 33 4D 88 1E CC D8 21 6A 99 78 DD AE 73 D7 9F 3F A2 0F 80 65 84 5E 82 CA 81 62 DB F9 88 41 F8 EB 42 2A 3F 58 7F C2 70 00 56 06 5C C3 D8 9C 8E EB EE 86 4E BC 2B A4 18 C9 5D 5E 53 AC B6 EA 64 3F 35 24 D7 18 8D 6E 9C 97 A1 AB E1 E3 CD 3D 11 EC D8 EE E5 C4 CB A0 D5 A3 E6 CB AA 56 B7 88 5F 9B 90 3F 4C 2E 3F C3 C7 F7 FF A8 83 EF DE 62 00 53 9B 88 E7 F0 C0 CE 81 6F 84 B8 1B 8F B6 73 10 A5 C5 0C 06 0D D3 EB 36 48 74 92 91 3A A3 8F C5 C8 24 8B 70 47 A1 D6 69 BC CE B3 68 BB 2E 0C 44 93 40 26 4D E9 62 2D 3F 24 D5 56 04 02 14 62 C1 D5 8E 61 40 BF 9F 43 2D EB E6 FA F9 12 4C 94 AE 8D 6E 00 4A 12 FA 3C F9 EA 82 16 C2 0E 1B 56 D1 76 85 2A 38 36 38 D6 F4 37 8E A5 8C 33 56 B8 E1 7E E8 40 CB C8 B2 2D DA 9C 36 22 85 AD 9A 8A 4B 1F BA 8A 05 EC 46 D0 3E C9 91 2B B2 55 C2 02 87 58 E8 EF 65 AA C2 8A 41 36 9D 9D E0 E7 6B 17 37 FB F7 48 17 64 CF 96 E3 94 B6 B5 2F 5C E3 38 25 6A E3 D5 66 EE D2 31 54 92 E1 4E 96 7B 30 BB DA 36 69 F3 A6 0F C0 A9 8B 37 E4 9C 00 DC DD E4 06 26 27 F5 FE 14 D0 D8 B0 3F 97 29 93 FD 8A B9 24 3A 18 B8 43 BB BB 64 62 78 4E C4 3A 32 95 3E 92 58 F5 64 3A 46 A2 73 FF B6 B1 5A CB C5 9D 34 30 F0 AC 51 6A 18 E2 8E 98 60 19 CE 90 F0 C4 3B 7F CD 10 20 A8 A9 07 21 40 34 63 30 6E FA C0 46 F8 59 75 FA 17 90 BF A0 80 E4 5F 9C 85 35 02 FE E2 5D E6 31 B4 F3 C1 11 6A C0 F4 3A 68 E6 4E EF 73 6B 0E 5D AE 76 30 06 DA C9 3C 83 E4 46 64 3D A4 77 60 F7 6E 62 68 2F 99 6C 46 CA 7E 61 9C 72 FA 78 37 44 72 07 71 00 CB 31 6E BD D1 8D 9C 76 1A 8F 8D 67 C4 3D 30 4C 65 41 C3 89 43 1F DB CE 66 F3 8B 9F AE 6A 33 71 0A D1 CC 12 82 50 D9 01 46 05 6C 52 4F EF 1F 13 2A 2F 14 BC 28 34 B3 C8 63 53 30 7F 61 BF A6 D0 A7 BA DE 60 6E 0D FB 5F 48 E2 9D 42 F2 ED 86 4F 1D AB EF 03 84 4F 50 D9 A5 61 0C 10 84 F5 B7 19 38 20 65 97 3B 12 47 D4 A4 18 15 D9 A5 9C D3 3D 45 BE D8 AE 21 0F 2D FF 2D 5A 10 35 1F 54 A6 6B B8 5B D3 C2 81 84 F9 5C 5E 8D E4 1C F4 E7 D3 85 A9 17 8E 48 DD 59 AA 85 56 ED 43 1B AA 94 BD F8 E7 26 AD C0 3F DF DF E2 AA 6B DB 9A 1F 1E 71 F5 C6 57 FC 8B 0E BB E7 F5 06 A7 2E F9 29 6C D0 FD 49 6F 7A C0 C2 7C 8A 59 34 92 D6 65 E5 CA 45 C7 69 6F 3F 73 28 6E 35 A9 87 24 4F 4B F2 5D 29 E4 CD F8 05 63 56 C9 53 3F A7 C1 13 5E F8 F3 55 70 C7 15 91 F3 3C 91 51 2E 9A EF 2E 27 3C FB A3 C6 EC 6C E9 C6 BB 90 99 93 29 8B 0A 02 B7 13 13 4A AA C9 C8 A6 0F 73 0D D8 2B 22 EE CC 68 FB B5 2B 72 47 31 C7 4F 74 19 75 E2 F2 EA 50 1C E0 80 DB F1 39 8E 3C 87 87 C0 38 D9 A9 15 77 5D 71 61 BA 46 4F B4 06 7A 1F 9A 0F 92 65 B9 B7 95 FF DC DE 27 7D F6 82 6C 95 42 9B CC B9 EA A9 64 C8 F2 B5 E6 A2 55 26 D7 72 35 16 4B F8 45 56 F8 4D B5 5C 59 6B FF 0F 7F 9B 90 A0 59 C9 B6 B9 4E 75 0C B6 93 46 2D 21 30 BA 91 C5 41 E5 D3 60 BB 9F E3 98 36 67 81 F0 CE 64 6D 74 F7 C3 14 7F 8A 9A 16 3A 6C 18 23 61 9C 77 D3 53 8C 7D A8 C3 F8 3F 8A FF 2F C7 C2 0C DE 00 B2 E3 68 A8 6E 8F 97 1B 39 1A 8A 1C 52 AD 6E 9B 7A FA 41 66 C7 C3 97 95 09 94 FD 6C FF 5F AC C5 BB 25 88 EB 89 5E 38 EB EB 6B 70 D0 D4 EC 5F 68 85 C3 AA C8 3F A7 AD 52 EC D1 94 24 4F 81 7A F3 90 B7 5A 58 77 B8 FC E5 D6 16 82 2C 0E 4F A9 AA 3F E7 F7 CE 4F 31 72 69 9D 04 90 1F 1E 83 63 9B 9D 0E 57 77 C3 07 B9 82 1D 20 6F BD 4D 3A 1C B8 A3 69 8B 83 31 AD C3 95 63 42 A3 E3 7F D8 A0 77 4B 55 4D F7 F2 7C 17 3E A0 56 BD B5 06 1B 90 56 5A 03 91 DA 96 00 CE F6 1D 9E 05 5B C9 53 5E B0 F7 4F 3C DA AF 68 C7 F2 DD A0 8A E7 46 40 9A 7B 57 D5 1A 5E 3D 24 A5 CA 3C 12 6D 86 25 6B 41 B1 E0 56 9E 9F B8 D6 EA AE 3C F6 85 5E 0E 9B 24 1D 02 46 94 58 6D 77 E1 01 95 CC 44 D5 1B 78 E9 73 01 C2 6D A1 F8 AB 5D 0A 4A ED 5B F4 C6 23 93 7F 7C EE B6 23 7A 35 3E C8 DF 23 23 89 A2 F8 D5 9C E7 4C 6E E8 57 FD 0D 73 90 E1 67 1C 68 BE 7D 06 38 45 96 01 45 18 83 18 93 28 A6 A4 97 85 FE 48 13 49 B3 F4 8B EC 6C 16 36 8C 9B 4A 2E 78 1C B0 7F D5 18 5A 7B E0 74 DB DC 8D 61 06 38 91 99 AD 5C 3B 0F EE 03 4B 33 46 56 83 69 B5 83 50 40 29 4B F1 68 FF 87 59 DC 7B A5 9A 73 D3 AA 0A 46 B2 EE 78 B6 70 FB 55 6F E0 2E 9A 96 5C B6 37 C1 3B 2F 53 EF 92 E7 26 FC 97 3C FE 55 22 F6 FD A6 DF 87 1D 41 30 F1 78 7E C5 D6 A3 12 38 A7 03 09 24 5A 3C 97 9B 1F 88 C5 A6 B6 C5 CA 82 4D 5D 7E 87 1B B8 87 56 D1 F3 C5 5F 1D 1A CE BC 29 56 56 9D DA 4B 51 82 54 99 67 CE F2 FF A5 F4 9A 33 CE 5F 1F B6 FD EA 90 93 DC 72 F1 85 F4 CF C5 54 45 1C C6 A0 39 FF EA F1 32 C2 C3 2C C0 6C 49 01 AB 05 77 0F 3C A7 9A A5 E7 04 EA 6B 93 45 80 B2 1E 73 32 20 A4 7E 30 5A 6C 0B 2C 76 A5 2E 44 E8 94 EE 9F DE 4D 6F 7C 97 DB 50 80 BE 4E 2D E0 84 96 09 36 DA 79 7A BF DF E7 09 23 D6 97 12 8E D8 1C 1E 25 94 60 06 D8 F1 30 3A B4 33 36 0C 3A 8B A3 9B 6F 1C 68 D8 2D C9 FE D5 9B 6D D0 B0 59 86 48 29 78 95 CE 32 A6 A5 E1 9C 64 1C 85 83 BB 7B 1E 28 B5 87 DA 50 22 CC 3F C2 0F 6A DD 60 36 6F 28 F7 92 9C 62 3E A5 86 B5 46 2C 14 D6 26 D7 5F 2A A9 10 6D 80 30 89 BA AA D8 29 1F A8 05 FD 15 B0 C2 61 36 C9 61 48 24 1A 8A 33 1B 8E 89 75 84 2A CD 07 7C 87 9E 76 49 7D FC 5F 1A 36 8F E9 6D 0E 80 36 9C 18 B1 3D 47 5D 04 36 EA 3B DF B5 9E 31 1C C2 BE 92 8D E5 E3 D6 F7 C8 46 FF CF 80 56 4A 16 55 22 83 13 22 0D FB E3 BC 8D 9D B7 3E BF EC 0B DB 57 70 F5 A5 5A 7C A4 5D 2C A5 A2 0C 6C 81 01 FD 8A 33 72 AF 6D 5C D5 A8 61 BD BD 97 5B E0 9E F2 41 68 63 CE 6F 2C AB D8 F1 A2 15 91 F2 B3 1F CD B8 26 B7 66 6A 55 48 66 94 6C F9 3D 39 78 7A 75 83 E7 86 5D 0C BF B1 B1 D2 74 E9 01 D0 20 45 B4 98 CB 83 EA 3E 1F A5 97 C1 DD 29 F0 49 CA D5 EF EB 9A D3 B3 44 07 35 CC 4D 80 1D 85 17 C6 FE 18 BF BE 7D BF CB DE 4B 4A C1 E0 10 3A F2 67 15 84 CE 36 8D F8 D4 5C 06 02 5F 62 D0 5B 95 EF 34 5A 53 FD CA EE EB 55 3B 5D 9A 7F 70 40 C9 D9 BF E9 3C 65 DA 84 81 3C 2D BF E8 BB 91 A2 B3 8C E1 95 39 E0 D7 28 C7 36 CB 08 23 72 7F 14 6E FD 82 3F 67 D7 F0 36 F4 07 AF ED 82 D6 62 CE 21 7F 20 FD 7F 75 70 7D 3C 7E 63 63 1A FB EA 83 EB EE 11 93 04 3D 5D 8A 97 AE 97 D6 B7 61 71 9B 07 86 2F C3 A6 1A D7 52 20 2A 5B B8 DE E7 04 0A 03 8B A2 BA AA 94 1A 3A D1 47 06 8F 15 9C 5E F8 AB 56 F3 28 57 FA AD 17 E9 A4 C5 DA 70 4A 4E 73 04 2C 79 F7 60 D2 42 E1 90 F7 27 C7 75 5E BF 39 A3 9C 71 1F 95 58 3C BC 82 CD 43 E8 BD 36 24 E5 45 59 D5 15 A5 E3 89 A4 D8 92 0D 14 B5 40 01 B3 8D 19 9B 0A 55 D1 8D F3 DE CD BD 42 CA D6 6D 9A 58 4B 0D 78 BB BE FE E9 95 F3 E3 CE 12 8A 4B 84 08 BE F2 D0 08 25 83 F8 15 5F E2 7B E7 12 D7 C2 3B 96 FB 03 6D CE 0B 5C A7 F3 26 F5 09 3B A6 BB F4 21 96 62 1B 99 BB 13 EF 45 BF D1 9D 0F F6 D2 5C AD 49 B3 4C 32 F1 FD 52 51 2B 42 C2 D0 CE 59 2D 6C 5E F3 39 1C AA 75 28 C1 3D E3 21 65 FB 9D E7 DF 78 ED FE 68 E1 BA 99 E9 83 60 60 49 10 D6 FF 49 4F AA 9F 0E 69 CE 89 89 60 45 CB A9 C0 73 69 12 1C 8A 94 5D A6 AC 6C 10 33 DD A5 E1 99 64 FE 10 73 60 13 27 26 D2 74 2B 06 44 AB AA AB FD 4F A2 C9 1C 94 60 CA 72 10 FE 60 84 B1 4E AF 72 CA B3 EB 89 A9 1F D9 F2 C9 77 42 98 47 70 50 D9 90 D6 33 F0 6B 58 EF E5 B6 53 EE 60 AD 0E 44 CF 1C DC D4 B5 87 63 FC 56 42 AC A0 F5 93 DB ED 46 7E 31 51 8C FE A5 F0 13 C3 77 7A FF 2C 28 57 EF D7 94 E4 E0 96 37 EA 96 5C D7 18 E2 44 21 94 E6 A2 66 C5 1C 26 15 7A 8E 2E 84 21 E6 56 84 7C CD 23 FE 79 9A EC 02 A2 90 C9 ED DB 5C 6B 45 DB 9D DA 3A B5 9A 01 CC C4 34 51 26 27 BB 95 81 BD A4 CD 66 96 DE B1 97 25 48 D2 B4 41 9D A2 29 0B 89 8C A2 28 10 ED 98 63 CE 83 53 24 05 AA B9 6B 5A E1 9E CA 54 3D 51 68 9D 48 9D BB A0 4E 0C FC C6 15 10 E0 ED F7 2F BC FD C5 90 4E 55 24 36 6A 49 17 ED FF 38 9E E7 C4 05 0B 4F 67 AC 7B C3 14 FE F6 DA 4F 91 4B D4 72 11 E5 92 7B 6A 4F A1 AC 5C 03 CB 0C 81 FD 0A 97 67 83 97 7F 8C 52 88 9A C5 34 43 01 EA 22 F7 74 52 E5 60 F9 20 7A 69 B9 85 4F 51 61 4A C2 CF 56 2C B9 46 1E 94 0F A9 86 F7 A3 90 75 4F D3 5E 0D 81 2F DA 29 04 03 E7 D9 38 B6 59 F1 1E 0B E3 82 C0 93 CE 78 1F DA A8 79 85 87 2C D9 80 67 71 94 DB 32 57 E4 40 4F 50 E9 71 28 0B C5 7A 89 28 11 30 5D A2 F3 B6 C2 AC 11 47 8F E6 16 5F C5 5E 6D 36 1F 2F 6B 2E C3 A4 C6 F2 56 60 8D EF 27 91 FB F0 89 7E 9C 3D 17 03 93 8F CC E5 8D 30 3D 52 68 E0 16 8F 42 E3 CE 37 78 18 4C 7A B6 45 1A 05 13 8B 76 BF A4 D8 FC 7A 1E 43 A7 D2 D3 A3 70 18 D1 5B D7 57 3E 0B 8C 7F 16 85 A8 D4 BB 44 10 3A D7 F4 2E 0A EE 47 E1 02 A1 C0 F6 22 C9 1C B4 9A AC 21 85 A7 59 1E 7D 7F 31 B6 EB 52 F2 F8 93 C1 8D 2E 7D 0F 87 32 FD 11 96 7F FB 7E 89 11 C8 C6 11 56 49 DC 41 E0 83 9D 65 90 01 06 BC AA CC 6F CF 83 FF E1 2E BA 96 A5 69 63 61 A0 F0 36 ED AC 1B 86 AE 5D 8E 64 05 73 01 FC 83 D1 85 96 F0 92 95 64 94 56 98 1B 04 02 8B CB 7F 0D 59 52 71 71 AA FD 84 35 18 61 BF F9 74 1B 3C D0 D3 43 75 30 7E FC E7 F8 6E 66 60 A1 6C F3 8D 05 8B B2 6C 5C 25 CE 35 53 9B CC 04 F3 77 59 C4 FD 4A 82 BA 24 BA 0A EE B2 D7 E9 73 40 C2 B1 78 B7 51 87 EC 21 03 5A B4 B5 80 41 E4 FA FF 5A 86 5D 2A 94 91 CE D4 CE FC D9 86 B4 44 3A 04 56 62 BE 62 37 21 A2 82 B9 21 20 37 BE E3 07 46 44 B5 0B 35 77 99 D2 B0 48 7A B1 85 DA 69 F9 F6 EA 56 B6 25 68 45 2D 1B 1D 16 18 50 0C C3 FE 98 2C CF 22 1F 2E ED E3 B5 3A 8B E7 1B A2 8D 96 F1 5E 31 F5 26 4F F0 6A E2 1A 4B 5B DF 32 CB F1 92 E5 7D 4D 47 AD EB 74 53 11 E7 75 D3 59 B4 81 22 6B A7 21 C1 C2 05 49 B1 99 14 7F BD A6 C2 9E C8 3A EC 5D 91 8A EA 85 58 6E FF 8C 6F AE CD ED 60 AF EC 3C 03 10 9D C6 07 F3 D3 4F 21 67 E4 05 C4 65 C2 18 F4 54 9B 50 28 93 E7 9A C0 22 24 F7 84 81 D4 07 20 6C CF 24 64 81 78 B5 A9 9C 0E 35 8C AA 8B 65 5F 52 0A D1 76 C6 34 53 AE 42 81 5A EB DF D0 BA 99 F6 63 4E A5 BF CD E7 32 8C E6 86 8F 3A A8 D9 A0 E1 80 28 FC EA 74 50 B6 18 10 A0 86 23 5E 5B F6 D6 B4 2E C7 D1 AC 38 76 3A 46 96 9B DB 1C 24 FF 68 13 D6 AC 1D 59 6C AF 17 6E 67 52 2E 4B 93 9A 2B CA ED 44 48 9D 52 82 BB 47 0D 16 50 1E B5 CA F1 19 35 10 35 12 9E 51 B8 DF 34 7C F7 EA FD CE A1 12 62 FF B2 74 A0 32 D2 12 F4 58 58 11 55 E0 A0 3D D1 29 6D 9F 41 6C 37 56 33 3D C5 5B B1 9B 4F 47 92 67 0D 1C 0A C3 C1 85 65 BA 02 62 FD 67 F4 78 E9 45 50 5E 95 4D 54 B6 B2 FA C4 BA 78 E8 ED EA 1C F4 48 3F 97 62 7B E2 A5 C3 51 67 D2 CC 78 2F 60 82 66 C3 2B 24 CF DD 9B C5 9D 31 98 CA 37 6E B0 75 0E BB BB 10 1E D6 C9 4C E7 E8 47 EE EE 06 85 92 EC 3D 9D 8C BF 0A 31 B3 7B 16 8C 00 45 F8 A0 6F 54 C2 98 43 7B 87 A6 9E 57 33 9C 55 7C 33 67 B6 F5 5F 45 8D EB EA DD 5D 27 71 B5 09 E6 1B 4E B0 53 F5 38 FC 35 F1 DD CF 0F A6 CE 28 49 A9 AB 67 6C 70 48 FD F9 F0 90 DD 0E 2C 99 AF 1A 54 E4 E9 2E 50 01 5B 38 CD 2F DD 2B 03 5F 27 5C 19 77 42 80 FE A6 53 1E 90 26 BB 25 47 2C E0 59 96 C3 9F FA D5 06 95 FB 18 63 3D 40 2E 2A CF 3F 72 80 CE 2A 42 84 6D 2A D8 1D 10 97 3D A8 6C E6 FA C5 BE D9 2E 03 F2 7D C7 98 D7 15 4B A9 BD 07 61 5A 2E 90 E1 D8 F1 4D F6 73 68 A8 FA D4 D2 68 C2 96 07 1D 5C 49 95 04 F3 F7 C8 4C CA 5A 58 CA A4 C0 E2 D1 40 F0 4A 1C 94 1E B6 DE C6 C5 C0 AE 23 4D 4F 62 2B 2E C1 53 39 1F 88 AE 5A E9 7C 9B AC D1 D5 3E 92 8F 2C 88 13 39 6D EB B6 D2 93 1C 2C 77 DC D2 5F E1 0F AD 38 B8 37 11 D6 35 3D E4 0B 41 E5 7F 47 6B EC CA D0 EE 93 89 32 BB EA A3 16 8F 8E 1B 5F DB AB 1C 0E 66 64 22 78 F9 BD B4 29 3E 54 F7 FE 8C B2 17 91 C0 98 5D FB 95 07 37 88 42 8C 4E 3C 9A B0 AD 19 AC 32 3E E1 11 22 FB FE 30 2A 08 E4 24 54 6E BC C9 8B 7F F4 70 AB 75 A2 B3 C2 A3 77 CC C2 E5 82 EA 3F 4E C7 6A 68 10 DB 54 A2 B5 0E 0F F3 2E 68 F2 B6 8E C1 1A A0 D4 5B CB 9E 78 D8 AE F7 1C D3 A7 64 44 67 3B 1D 5B 0F DA 13 D3 6B CC B4 3B FA 1E 5C DE 74 B3 8D 75 BF 52 94 9F 8F 2A 59 FE 0B 51 91 F7 17 50 E6 41 D1 75 EC 37 24 9F 81 83 3A BB 22 A8 36 E7 D0 F7 E0 D3 96 74 1B 55 D2 A2 8D E1 73 92 7A 78 7E E5 DA 41 9E BA 64 66 BC 0F 68 AB 71 02 8B C5 CE 49 B9 D2 77 74 D4 89 B1 9E 28 54 09 BB 0D C5 97 19 53 BB 8F 49 76 3A F8 0C 45 E3 5E 40 7D E2 C5 1F AF AE 66 EA B6 61 69 82 7A 3A AC 23 6E AF 89 02 02 AE 03 12 C2 D7 F7 AF 7D EC 19 FC 02 27 54 93 42 AA A8 88 4E 6A F8 BF 95 03 5D F4 0C 2D FA 6F 10 92 22 B8 04 43 63 16 64 82 6E 6F 06 A0 DB 5B 1B CA 1C 2F 37 73 A0 C6 02 A8 DD 8F 1A A8 4B 3F C1 28 10 51 D4 A8 81 B2 01 D5 50 2F 9E A9 90 06 4F 60 4E 34 F7 39 99 97 77 82 DB 38 21 55 9D 15 18 4D 5F 93 70 0B AF 99 51 D5 0D F9 62 1F A0 E5 45 2A BE AB 2E 96 D8 BC BC C2 B4 B6 2B BD 53 47 EA 7D 84 72 E6 13 6E 5C 40 2A 9F 03 1E AB 17 B4 A9 51 19 E3 FC EC 3B 08 32 BF 9F A7 03 96 C1 7F 2F A1 9F A2 4A 01 22 F3 62 64 C9 84 23 60 28 8B B2 E7 54 0E FF C0 93 5B 88 6F 86 8E E1 8F BA E3 4A 11 B0 1A F6 A4 6D 25 CC 21 03 EC 8F DF 26 8F B0 99 93 BE E7 45 8C E5 60 98 96 E8 0D 26 5A DB 39 0F 07 A6 67 9F EB 07 22 33 EF 5B A6 6C 64 59 A7 F1 00 3E EB 04 AA D1 DC 76 59 50 2F 98 B8 3F CE E0 64 F6 C5 3D 2B E8 3D 41 3D 24 6E 55 FB 45 AE 5A B0 86 1B 60 93 EB 3E 35 12 BC 58 41 20 4C 51 44 98 C5 AA 9B A4 B0 96 21 EF 94 1B 0D 14 10 3B 8B DC 33 F2 04 A3 20 DE C2 A6 E6 8C 75 88 22 41 64 D2 C3 E9 23 4C 87 C5 ED AA 62 0C 2E FB 5E F9 B5 C9 1E 82 72 BC 66 2B F3 FA B5 D6 98 B1 48 E3 C3 D9 53 7F 90 3F 35 BB B6 FD 11 4B E7 24 B3 B7 66 6B BB 6F 5E CB 08 34 DB 2A 8C C9 3E 35 75 BC 3D 17 44 82 57 F6 BF 0B EB 6A 17 F4 E7 17 5B DF 17 E5 2B 21 3C 4E 91 42 E7 FE A0 BB 32 49 FD BF 49 BF 85 DF 6A E5 F8 BB BE DC 09 2B 39 60 06 6D 58 BA 0B 47 E5 95 A7 1D BF BE A5 98 98 37 28 55 29 A1 93 12 06 93 65 61 F6 69 15 F3 C8 B6 FA 0C 87 55 98 F6 2C CF A5 2C 5C 34 5C B5 35 2E 1E 87 5E 33 39 D8 27 21 48 F5 56 73 4A 97 03 66 7F 69 B3 58 72 19 0E CC 93 87 28 03 39 9C 78 72 29 4A 70 5A BF E7 19 0B 9F 39 92 3C 9C 83 D8 91 DE 31 96 C7 CA F1 FE D7 16 23 82 35 17 23 58 D9 22 4B 91 E4 53 A8 C2 F1 EA 75 08 95 AD 55 C3 DF 56 87 3B E7 F4 D5 1E 9E DD 3C 38 C3 4B D4 5C 43 21 60 08 22 CF E7 A3 0B D3 BA 04 8F A6 D0 4D 02 B7 1B BE C1 0E 40 BD 95 33 94 41 D5 E3 18 97 16 16 29 D5 45 48 12 DF 65 95 87 45 0D 9D 2E 70 82 45 AB 59 4E 7B 08 B3 E6 EB B9 1B 06 12 79 64 0F DC BF EA 29 64 16 86 5D FD 03 78 05 CF B9 C2 D8 5F 7D A3 62 23 C9 C2 EF BF BF 28 3C 34 53 C9 DC 92 BE 58 3E 9C 47 A5 35 7C B0 5D 90 2E 9D 01 F9 EF AB 32 1E 67 12 53 AA B9 C4 2E DD A6 1E 80 63 1A 4E 89 44 0E 87 6E B5 D0 94 84 9B 77 E1 84 C1 9E C6 13 AB 4E ED D7 5F 71 1E E4 E3 49 5A 33 22 DA 3E 38 AC 2E 13 E5 EF 56 41 3D 0D C1 53 16 33 E1 1D 63 1E 2E 9E FD 5C AF 21 70 66 51 97 0C D4 89 D5 6C 7E E7 4F FD 6E 79 D2 26 54 8F 3F E0 DC B7 7E C7 AE F5 B6 8C 6B 5C 80 C9 D8 62 0D 0E DD FF EE 06 E4 05 25 D8 73 12 EE 63 2D 73 A3 1C 10 00 C6 C2 8C 15 DB 50 44 01 78 63 40 A2 DB 71 9D 71 0D 12 BD 01 AF CC 47 0E 12 E5 DF 02 79 FD 7B 6B F6 4C 7E F4 88 27 F7 F9 B6 B9 66 1F 68 E4 43 63 77 FA DF C3 EE 89 2C 16 6B 9A 51 F5 EB F1 9D 86 2F D3 4C D1 96 2D 35 47 88 DA 7E 3E 0B D1 E3 39 FC C6 51 F2 9E DE 74 B7 7D E3 7C DE CC 36 A5 59 76 AA 35 F3 34 EB 28 A1 B5 C7 11 35 B5 19 1A F7 06 7C 7B E6 BE 54 E1 F9 69 D9 9F 7D E0 69 E4 DA EC 4D AC F5 D2 20 5B 91 61 B8 6E 1B 5C 35 FA 1D EE 06 E6 79 76 FA E0 B5 18 E7 CA CD 01 79 B0 14 55 99 D2 9E 0B 35 87 07 7E 51 F2 8D 34 8B 75 71 82 61 1A 3F D3 E8 F8 92 19 28 0C 89 EB 5A C3 3C F7 73 79 B5 47 07 39 2A 0C 31 9E 5A 3D 4C 1B 3B 1F 01 95 A8 DC F5 A0 77 D8 44 E5 D2 57 7F 97 E0 23 27 65 C8 26 80 0A 1E E5 A6 B7 63 D8 81 7A 11 92 D5 C7 A1 0C ED 1C E0 FF 3C 4A 02 A1 F0 86 83 CF E0 67 24 9A FB 18 3B 59 83 17 68 EC F3 98 92 FA BD 72 32 04 4E 03 4F 69 5D 3B 9C 61 89 FE 5B 2B F7 B7 79 BF 58 AC FF B2 41 26 89 B3 00 33 55 5A 37 23 69 50 6A 9E 28 2C 93 D5 DF 91 E9 EE 89 A8 D9 87 35 AB 53 48 34 6B 0A 3B 94 76 00 E4 2C 48 4B 64 70 D3 53 9D 10 81 80 82 81 3D A5 DB B4 B4 BB 88 79 CF 23 3D 8A EA AD AA 24 04 01 F7 29 16 75 7A 41 07 02 04 BB 7D 8D 78 C8 F4 46 DA A7 99 63 5C C1 1F F7 EE 44 43 D0 B3 8E 5C 51 36 D5 54 EA 41 11 32 7D E3 12 62 D0 F6 32 0C 80 B8 1F F2 79 9F 33 76 13 FC C7 30 A1 4E 01 3B 52 43 DE C6 95 62 87 D3 79 4C 7D E8 0C F6 A4 D4 DA CB 2E 5D 08 02 49 F9 82 FA 0F E6 A4 AE 53 EF 07 86 11 04 89 3C 35 20 C4 16 C5 FE 81 99 4C A2 0D 8F B9 1B C5 A5 B7 47 1E F7 21 E1 CC EF 93 20 ED 79 FB 16 E6 EE CF C3 76 7B B8 80 E8 ED E4 B0 00 4E E9 CE EB A3 21 5B EE AD 78 B3 73 F7 0F C4 CD C6 91 1C 2A 93 D8 17 47 C5 34 16 8E 1C 5A 8B 35 1B 19 37 5B 85 24 3C 88 5E A2 D8 C2 5E DB AF 3A 4A 73 F0 B9 4E 0C 78 3A 15 BA B5 C0 47 76 9C 8B 0F 5E BC 72 4A 55 0D 7F D3 03 47 D7 C1 7C F2 DE 33 C5 F5 72 C3 59 4C 35 B2 AD 43 FC 73 70 D0 34 9B 6F DA 73 1A A1 B3 A7 F1 D5 FC 22 7A E0 ED D9 8B 59 37 5F EB 6A B6 6D F9 F4 44 F2 10 26 4F 78 6D 36 08 AA BC C7 B9 45 C0 FE C1 F1 2B CB 1C 70 B7 AF 52 D2 8C D3 C5 FD B8 5A ED DD 5F 8C D8 62 8C 23 CA 24 38 82 E2 DE C4 3A BA 14 D5 0A 52 9B 23 3F C3 39 D3 38 DE DC 2A FB 29 02 9D E2 D3 15 62 DB 2B 90 34 84 D8 EA 55 24 2D DA D0 7A F8 43 DD 31 E1 AB 7C 1C 64 85 27 86 27 E2 36 BA 98 3C 9B 37 E6 A4 21 02 ED 2E 2F 81 71 67 2B F0 80 DE 41 19 04 61 04 99 DE 5A B6 37 8B 0A 48 9F 79 16 32 DF 52 53 CC 9A 2A 18 5C 0E 0C 21 8A 74 6C C9 43 B5 A6 FD 30 32 52 62 18 EA 20 BC D6 B4 A2 D1 DD FD EB 35 E2 8A 74 0A 3F 30 14 21 12 69 E4 0C 89 DD 8C 24 9C 80 75 94 5C 2C 99 2A AA 2F E6 75 1F A9 FB 43 D5 79 B0 38 EC 3D C6 74 34 2A 21 2A AE 66 C4 C4 39 9C 80 C6 FD 5D 0A 97 66 22 E5 D1 35 B7 8B 1D DB 1C F6 26 53 DB AC BE D9 24 61 9A B8 0A 23 DE 95 39 FC 7C 99 A8 C1 33 C0 1E D7 CA AD 18 EF 02 A4 96 EE F9 D6 71 15 AA EE 0F 5C 7E D7 AC D8 E9 C4 C4 BB CD 68 AC AB 0E 1B 11 85 F3 D9 EB EF E6 97 FC 41 28 1C A0 6F B1 98 97 2C 8C 2C E5 9B E3 A3 CE 77 D7 92 36 35 46 CA A2 82 DC 28 98 98 6D 2C AD AB 8B 00 6C 7C 8A 8F 65 58 B5 5E 5A D1 4D 35 21 F6 35 B7 91 AF 83 95 92 49 E0 75 6E CD C8 94 4B 69 E2 0B E3 D8 E0 32 D9 1A 57 80 64 F2 0C 38 BD 00 A7 F4 59 3A AF DD D9 91 2F DE 92 8E 51 43 91 FA 62 0A A8 AF 87 05 EF C8 D4 C4 1F 37 0B 30 93 A4 8A A2 04 DE E0 B4 B7 C2 26 36 9A A8 97 9C B9 78 B4 90 32 F1 74 A7 F4 08 A6 F2 3A 5D 5F 02 AF 73 8B 63 BE A5 EF 9F D9 1B 98 07 D3 2A 39 BA 1A 1F E7 E6 2C 7E 0A ED 16 D9 89 93 3C B2 06 18 63 1C 6B 81 A4 61 ED F2 F5 D0 E2 BC 99 57 50 46 47 22 5A BA 83 D0 F5 74 D3 9F 7D 6E 57 E0 AD C9 26 C3 EE 1D 95 12 EA 9B 92 8C 57 57 8F 03 15 AF F7 35 08 C4 C7 AE CC 1F 92 65 A1 F8 DC 57 DF 9C F9 73 BA 7B B8 C4 70 A6 B5 D7 88 25 A6 E8 B3 A5 97 E1 43 12 37 38 DB 2B EA 15 E9 C0 14 B9 CE 9D 7C D8 04 74 93 92 AC 9B B7 C9 CB 53 B4 1B A9 00 F5 6B B3 70 4D DE 43 98 BC AA 4A 3B 76 5C CF A7 B0 91 8C A0 40 FB 99 20 A5 22 42 5A 55 5D 5E BC A0 B4 F0 36 88 70 61 44 8F A3 49 4C 62 FD 4F 50 58 01 70 4C A6 34 91 88 99 28 99 F3 80 2E 5C 44 96 64 95 13 E8 13 43 80 97 56 2E AA B3 DC FC 87 FC F8 1D 3E AC 02 69 18 31 54 4D 47 97 BB 00 81 A2 BD 44 C5 BB 73 4F E0 0A 5A 4F 88 02 E9 D2 18 06 0D 7B FD 02 29 FE D4 8A BE 1C A4 9E 1C EA 1C 63 BF B2 F2 DB BC BF A0 E2 61 39 AA 35 61 23 78 52 DA 62 BE 53 B1 E0 B6 77 85 F4 01 F5 F8 73 B4 3E A5 36 2C 8D E6 D1 21 D8 87 8F AD 03 56 63 EF 0A 07 94 76 F4 80 D8 06 D9 B9 97 0B 15 F8 F0 BC 6D A5 FB E0 B5 67 78 3F 82 10 C2 74 3A 93 A3 0A EC 32 5B 7C 86 9F 03 3F 62 2C 38 DA 54 DE C5 C2 78 ED 79 B6 B8 79 16 6B C8 58 CE 45 1A 9A 61 11 01 71 05 7F BD F1 D6 E3 4B 85 60 DF 08 89 A7 E9 FF 7B D6 E1 C0 C4 31 9A 69 DF CE 93 22 42 40 0B 90 2E 84 42 7E 99 FD 7F 81 E0 1F 18 B2 C1 74 25 A6 65 D3 89 EE 70 ED B1 17 59 86 8C 00 24 39 25 7B 42 0F A4 35 1C AB 39 7C 10 7D 60 72 E1 2C E2 80 CD E3 BA 9B 26 38 C6 49 40 68 AB F7 DC B0 0D BA 9E 04 E7 0E ED CC E7 4A A1 50 3C D7 B6 4F 7A 87 BD 7B 69 87 64 65 5C C3 5C 36 B4 4B 2B B0 2C 7A 5E FC 5D FF 91 93 75 A1 A6 2D 24 61 6B DC 24 26 BA 71 42 23 DF 55 E7 EB 6F F9 82 BC 84 9A B0 56 85 94 EA 96 F5 FF 1C 71 48 CF 03 0F 79 D5 46 7F 12 71 EC 09 42 F7 94 9E 2C B3 46 55 83 A6 B6 09 54 E6 61 F2 24 5D 5B 4C EF D1 42 8A C3 9C 03 CA C0 47 E9 E8 75 F9 23 84 C0 68 44 7F 9D 60 21 FD 36 F6 9A ED 7C EA 82 71 2F A8 64 A8 CE 8A B4 45 CF 5D 89 79 DF 73 A4 08 36 BC 05 D3 EF 9A 4B E0 46 8F 3F 9A 3B F9 44 89 CB 48 2C 50 D8 49 55 29 CE CF C9 E9 0B 85 B7 76 0D 50 A8 1E 43 12 18 4C 3C 6D 90 10 C3 84 69 BC 96 90 FB 2D 32 B0 AE 84 4F 95 C7 0D 56 8D AB 8E C2 A7 30 7C 65 F5 FC 7C A4 04 C4 2F F6 6E 3A 5D 39 35 F9 34 86 67 BA 6D 6E D1 45 4A 8A 41 D5 A9 4E 44 CF 19 ED 97 45 AB FC 21 4D CB 39 91 3E 11 24 E2 E3 73 90 95 F5 90 3E 5D 72 BA 14 FC 26 22 A1 C9 13 52 2F BB 32 0A 0E 7B 2F D1 F5 BB 6A ED 95 43 F9 78 D9 52 BE 56 78 7D 08 08 8D DD E9 9F 41 7E 48 85 C3 3A 73 2C 03 61 CD B4 3D 1C 62 BF 20 EE 5F 6F D9 DF 5E 02 AA 94 54 2C FE 15 38 BF 45 C5 EB C5 52 9A 3E 10 EF 21 41 3C CD E4 6B 00 DD E1 60 BE 08 82 A7 7C 9B 48 7D 0C 1A 00 82 F0 1B 04 43 E3 B4 20 17 D1 08 20 27 32 7E 90 D0 2E 31 B5 C2 53 33 09 58 1A 98 66 E8 80 3E 0A 35 F0 34 EB 58 B0 4F 3E 43 8D CE D7 54 6A 6D D1 66 44 93 18 90 3D AF D0 3B 1F 1F 2C AE AB 8F 26 FE 8B 26 AC F2 F9 77 33 C2 C6 5A FE 71 A9 58 47 CA FD 61 5E C6 3A 50 CA 9F 54 0A C9 6B 9E D4 0B BB A2 63 FE F7 09 49 36 B9 67 AE 72 F8 6B E1 E2 80 C6 B3 56 34 DF 6E 83 CF 0F 91 49 0E 5E 15 F7 65 A3 32 14 9B F3 D4 A9 91 CA E6 E4 D6 1B 17 43 3E B4 1A 84 FC 68 7F 5E EF 85 C5 AE 86 84 E1 33 90 87 53 54 B4 DD 24 70 8B F8 51 FF 0B 5B 66 03 01 0F 1B F3 69 84 0C F8 CD DE A8 94 25 A4 07 E1 6D 41 8C 80 55 3B 6B 64 AF B6 FD 83 B9 E4 D9 E6 EC 2B FB BE 0A 9D 2C ED FA F5 1D 28 81 C6 D0 BD 20 D1 44 A7 FC 30 C9 05 DF B0 8A D3 D0 36 72 A3 7C B7 49 8B 27 D4 E2 FB 02 A8 06 94 53 C2 63 95 2E 93 FA 2E D6 18 5B 4E 33 D8 BA 97 5C C9 9B 84 59 6A 90 E0 1B 2E 50 B9 93 AB A7 16 06 66 CF 9A 44 39 60 86 61 98 F1 41 59 91 DD 47 41 98 95 27 91 B5 F8 47 2D 30 58 E0 5E 9C BB 58 7B 30 CC 21 04 F0 65 B1 62 BC F5 25 15 1C C9 93 D7 49 CA A4 A9 97 EC 14 7C A7 B7 CA 23 AB B8 7D 59 8D F1 D0 6F EB 14 91 4C EB 01 BA F8 D3 25 15 5E A0 CD E2 BC E9 1B 30 33 69 E5 71 A2 54 21 7A A0 19 BA 74 7F 4C 6D 51 E9 F1 23 22 B7 A7 D0 48 0D C1 2A AA FB EB 48 83 6F BE B9 C4 F0 61 AC 4F 75 5F EA C5 8D 60 02 A9 B9 99 79 71 7D 09 5D AC 84 A0 13 FF 28 75 00 71 6F 3B B7 00 29 E4 8F FE CE 1F 35 7F 1E 50 55 34 F0 CE 78 90 FF 27 99 80 DB 0C 6C 4E 76 CF 8E E8 CB B1 B3 C8 D0 56 DD 8A 61 BA 20 45 4A CB 82 AE D5 9E 57 D2 DF 9E D9 A6 E7 99 5B 7E 46 A5 C8 03 1D E3 FC AF 3D 38 D1 18 43 34 CF D9 89 68 A4 A1 87 B3 CC AD 43 2F 56 5D 24 BB 3C 34 C3 AA A9 FA 06 3A 60 E8 D1 DE 6E 93 5E 2C 79 24 FF A9 FC 90 77 8F DE C5 AC 14 1C 35 61 D0 91 2E 42 0C BA C2 25 8E 3B 7A 15 84 31 89 01 80 2F C3 37 D9 4B 98 CC 64 E1 4A D4 DA 3E 90 5E 29 9C 05 23 30 F8 FC 30 76 66 4A A9 51 C8 07 16 7D 58 B0 B9 3D 93 DE F5 61 49 3D 6B C0 57 A2 A8 0C 6B 72 26 7B 09 19 E2 29 64 87 E9 65 76 E0 39 1D 70 95 09 30 1F 82 8A 3E E1 0E 24 E5 C9 79 39 66 24 2B EE CE 5D 82 95 D6 DD 70 FB 49 4A 36 F6 D7 F2 86 6A B3 56 43 23 D4 4D 4D CC 1E 0C 6F DE AD 0E 1F 2B 54 FC 11 76 91 31 89 BA 78 CF 8C 01 1D 59 0B 38 57 5C E9 8B C6 D9 68 8D 57 33 E9 28 99 A1 D4 01 E7 86 F2 49 09 CA 1E 94 8C 4D 50 9C 5E 4D 38 23 13 AD 8D F3 72 68 3D 1B BF 68 08 0B 3D 1B 86 E5 0A 10 66 DC 6B 13 EE 0D 55 1F F4 61 69 CB 15 F2 0E F4 48 79 D6 F1 5B 1A 3B A7 40 3B F7 49 09 00 0D C2 AE 78 A3 9C DA 17 7F F9 AF AF 28 F3 98 1C 22 C2 D2 84 84 D0 EE BF 5D DB 34 14 75 F6 AD 25 87 8E FA 3A D7 03 0C 17 29 25 E4 AA 36 C0 57 B8 9F 1C 85 89 A7 C8 16 A9 41 62 72 FB 95 C4 97 F6 9F 67 F4 0F 1F 54 52 4F 92 D7 6C CD 66 18 F9 57 EF B6 66 C9 49 26 CA 83 1C 31 03 C3 7F F1 50 57 6A FA BA 5F FE 2B A2 B8 03 C0 01 FF B2 45 E3 C3 C0 92 45 9E 92 92 B1 F4 E5 A3 57 CA 75 9A 92 84 88 F4 8D 6E 54 67 C5 C1 7D 13 09 C0 05 59 5C 28 9A DF 55 31 AE D5 E6 A3 2C 63 46 69 66 7E 90 F8 D3 70 22 79 7C 05 19 72 3F C8 D9 AF E6 EF FE C7 2A B1 9F AE BD 49 5B 3B 6D 50 6A 78 53 A3 FF 4A 45 21 F0 E7 0B 9C 04 0B 3C A0 2F CD CD

'''

                hybrid_body_dump = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

                hex_dump("hybrid_body_dump",hybrid_body_dump)

                hybrid_body_dump_pack=hybrid_body_dump[:0x6f]
                hybrid_body_dump_body=hybrid_body_dump[0x6f:]

                hybrid_body_dump_pack_header=hybrid_body_dump_pack[:0x40]
                hybrid_body_dump_pack_wire=hybrid_body_dump_pack[0x40:]
                hex_dump("hybrid_body_dump_pack",hybrid_body_dump_pack)
               
                hex_dump("hybrid_body_dump_body",hybrid_body_dump_body)


                data = [
10,106,18,36,8,32,18,32,-27,-11,-91,16,93,53,36,-19,38,-37,116,100,57,-27,-120,112,9,-42,23,-68,-95,-48,-26,34,39,-26,-49,29,-46,-59,41,78,26,66,8,-55,5,18,61,8,57,18,57,4,-114,106,60,45,65,-104,57,-75,-86,-76,-11,-17,45,8,-68,17,-100,118,76,-109,-95,50,-69,90,40,70,52,98,-27,126,66,-117,-63,-66,52,2,8,-77,78,7,2,-113,-13,-93,-19,-14,57,-34,-59,-32,39,14,-3,-20,-1,17,18,-28,79,10,52,10,1,0,16,-20,-78,-29,-102,-8,-1,-1,-1,-1,1,26,16,65,50,48,53,50,57,52,51,100,97,51,98,52,49,102,0,32,-48,-114,-127,-64,2,42,10,97,110,100,114,111,105,100,45,51,51,48,2,18,40,10,4,8,0,18,0,18,12,10,0,18,0,26,0,34,4,8,0,18,0,26,4,10,0,18,0,34,4,8,0,18,0,42,4,8,0,18,0,48,0,26,-92,2,8,-98,2,18,-98,2,10,36,8,32,18,32,-27,-11,-91,16,93,53,36,-19,38,-37,116,100,57,-27,-120,112,9,-42,23,-68,-95,-48,-26,34,39,-26,-49,29,-46,-59,41,78,18,-11,1,8,-17,1,18,-17,1,8,-88,78,18,-29,1,83,-12,125,-54,125,-69,-121,-9,-82,-28,-101,-112,-53,-72,-2,28,127,20,-49,57,-92,-64,-115,-65,71,47,59,67,-90,1,122,101,114,11,-71,120,83,-17,-116,-111,-12,-45,-57,59,75,-97,-111,-6,-20,-28,107,-1,-2,46,43,1,51,65,-47,57,36,51,-81,-56,-103,44,7,-3,39,-122,43,50,-54,15,-77,98,-59,-74,-59,76,9,120,96,-77,11,-4,53,117,99,121,-93,-7,-22,57,-116,-12,36,-8,-89,-128,-22,119,93,39,127,99,123,92,26,29,-19,-13,71,-60,70,-79,-81,48,-128,-116,-48,2,38,95,-78,-35,114,-101,-45,114,49,102,33,-116,29,-112,-36,-126,51,105,-112,-69,124,53,103,-117,-7,-43,57,110,-57,52,88,121,-65,112,0,-105,-126,88,-123,-66,-15,61,-70,-25,65,-66,-55,-85,-44,22,-60,46,31,-111,42,78,11,4,-61,67,12,8,122,-38,63,65,-57,120,104,105,-29,47,105,13,-89,-96,103,-112,75,120,13,99,0,-1,-51,17,-113,-106,-39,44,-67,90,-57,116,-19,-108,-46,107,70,-30,18,43,79,-102,36,24,-118,-73,-40,-81,14,34,16,49,50,51,52,53,54,55,56,57,48,65,66,67,68,69,70,42,-61,10,60,115,111,102,116,116,121,112,101,62,60,108,99,116,109,111,99,62,48,60,47,108,99,116,109,111,99,62,60,108,101,118,101,108,62,49,60,47,108,101,118,101,108,62,60,107,50,53,62,48,55,101,50,55,99,101,53,98,100,57,99,57,100,100,51,54,48,97,55,55,55,51,99,49,55,55,56,50,100,51,48,60,47,107,50,53,62,60,107,50,56,62,56,55,99,101,53,98,99,52,60,47,107,50,56,62,60,107,50,57,62,48,99,51,101,55,50,100,51,60,47,107,50,57,62,60,107,51,50,62,52,51,46,49,51,55,46,49,52,52,46,57,49,60,47,107,51,50,62,60,107,49,62,48,32,60,47,107,49,62,60,107,50,62,52,46,51,67,80,76,50,45,50,55,46,49,45,49,56,54,55,51,46,49,50,45,49,50,50,54,95,48,54,52,50,95,55,52,55,57,50,53,100,101,54,97,53,44,52,46,51,67,80,76,50,45,50,55,46,49,45,49,56,54,55,51,46,49,50,45,49,50,50,54,95,48,54,52,50,95,55,52,55,57,50,53,100,101,54,97,53,60,47,107,50,62,60,107,51,62,49,51,60,47,107,51,62,60,107,52,62,49,50,51,52,53,54,55,56,57,48,65,66,67,68,69,70,60,47,107,52,62,60,107,53,62,60,47,107,53,62,60,107,54,62,60,47,107,54,62,60,107,55,62,97,51,102,97,98,102,55,57,102,53,51,51,102,57,51,55,60,47,107,55,62,60,107,56,62,117,110,107,110,111,119,110,60,47,107,56,62,60,107,57,62,77,50,48,49,49,75,50,67,60,47,107,57,62,60,107,49,48,62,56,60,47,107,49,48,62,60,107,49,49,62,86,101,110,117,115,32,98,97,115,101,100,32,111,110,32,81,117,97,108,99,111,109,109,32,84,101,99,104,110,111,108,111,103,105,101,115,44,32,73,110,99,32,83,77,56,51,53,48,60,47,107,49,49,62,60,107,49,50,62,60,47,107,49,50,62,60,107,49,51,62,60,47,107,49,51,62,60,107,49,52,62,48,50,58,48,48,58,48,48,58,48,48,58,48,48,58,48,48,60,47,107,49,52,62,60,107,49,53,62,60,47,107,49,53,62,60,107,49,54,62,102,112,32,97,115,105,109,100,32,101,118,116,115,116,114,109,32,97,101,115,32,112,109,117,108,108,32,115,104,97,49,32,115,104,97,50,32,99,114,99,51,50,32,97,116,111,109,105,99,115,32,102,112,104,112,32,97,115,105,109,100,104,112,32,99,112,117,105,100,32,97,115,105,109,100,114,100,109,32,108,114,99,112,99,32,100,99,112,111,112,32,97,115,105,109,100,100,112,60,47,107,49,54,62,60,107,49,56,62,49,56,99,56,54,55,102,48,55,49,55,97,97,54,55,98,50,97,98,55,51,52,55,53,48,53,98,97,48,55,101,100,60,47,107,49,56,62,60,107,50,49,62,60,47,107,50,49,62,60,107,50,50,62,38,35,50,48,48,49,51,59,38,35,50,50,50,54,57,59,38,35,51,49,50,50,55,59,38,35,50,49,49,54,48,59,60,47,107,50,50,62,60,107,50,52,62,60,47,107,50,52,62,60,107,50,54,62,48,60,47,107,50,54,62,60,107,51,48,62,60,47,107,51,48,62,60,107,51,51,62,99,111,109,46,116,101,110,99,101,110,116,46,109,109,60,47,107,51,51,62,60,107,51,52,62,88,105,97,111,109,105,47,118,101,110,117,115,47,118,101,110,117,115,58,49,51,47,84,75,81,49,46,50,50,48,56,50,57,46,48,48,50,47,86,49,52,46,48,46,49,49,46,48,46,84,75,66,67,78,88,77,58,117,115,101,114,47,114,101,108,101,97,115,101,45,107,101,121,115,60,47,107,51,52,62,60,107,51,53,62,118,101,110,117,115,60,47,107,51,53,62,60,107,51,54,62,117,110,107,110,111,119,110,60,47,107,51,54,62,60,107,51,55,62,88,105,97,111,109,105,60,47,107,51,55,62,60,107,51,56,62,118,101,110,117,115,60,47,107,51,56,62,60,107,51,57,62,113,99,111,109,60,47,107,51,57,62,60,107,52,48,62,118,101,110,117,115,60,47,107,52,48,62,60,107,52,49,62,48,60,47,107,52,49,62,60,107,52,50,62,88,105,97,111,109,105,60,47,107,52,50,62,60,107,52,51,62,110,117,108,108,60,47,107,52,51,62,60,107,52,52,62,48,60,47,107,52,52,62,60,107,52,53,62,60,47,107,52,53,62,60,107,52,54,62,49,60,47,107,52,54,62,60,107,52,55,62,60,47,107,52,55,62,60,107,52,56,62,49,50,51,52,53,54,55,56,57,48,65,66,67,68,69,70,60,47,107,52,56,62,60,107,52,57,62,47,100,97,116,97,47,117,115,101,114,47,48,47,99,111,109,46,116,101,110,99,101,110,116,46,109,109,47,60,47,107,52,57,62,60,107,53,50,62,48,60,47,107,53,50,62,60,107,53,51,62,48,60,47,107,53,51,62,60,107,53,55,62,51,48,56,48,60,47,107,53,55,62,60,107,53,56,62,60,47,107,53,56,62,60,107,53,57,62,48,60,47,107,53,57,62,60,107,54,48,62,60,47,107,54,48,62,60,107,54,49,62,116,114,117,101,60,47,107,54,49,62,60,107,54,50,62,48,48,48,48,48,48,48,48,49,48,50,56,99,48,101,49,101,55,48,102,101,101,48,54,55,101,48,50,101,57,102,55,60,47,107,54,50,62,60,107,54,51,62,65,50,48,53,50,57,52,51,100,97,51,98,52,49,102,53,60,47,107,54,51,62,60,107,54,52,62,98,51,100,52,52,97,55,98,45,56,56,100,99,45,51,100,48,98,45,98,49,101,48,45,51,49,49,55,50,56,100,98,100,100,101,98,60,47,107,54,52,62,60,107,54,53,62,50,49,49,100,102,99,50,51,100,102,54,100,98,51,102,49,60,47,107,54,53,62,60,47,115,111,102,116,116,121,112,101,62,48,0,58,30,65,50,48,53,50,57,52,51,100,97,51,98,52,49,102,53,95,49,55,56,52,54,48,51,50,51,51,56,55,56,66,32,49,56,99,56,54,55,102,48,55,49,55,97,97,54,55,98,50,97,98,55,51,52,55,53,48,53,98,97,48,55,101,100,74,15,88,105,97,111,109,105,45,77,50,48,49,49,75,50,67,82,-119,2,60,100,101,118,105,99,101,105,110,102,111,62,60,77,65,78,85,70,65,67,84,85,82,69,82,32,110,97,109,101,61,34,88,105,97,111,109,105,34,62,60,77,79,68,69,76,32,110,97,109,101,61,34,77,50,48,49,49,75,50,67,34,62,60,86,69,82,83,73,79,78,95,82,69,76,69,65,83,69,32,110,97,109,101,61,34,49,51,34,62,60,86,69,82,83,73,79,78,95,73,78,67,82,69,77,69,78,84,65,76,32,110,97,109,101,61,34,86,49,52,46,48,46,49,49,46,48,46,84,75,66,67,78,88,77,34,62,60,68,73,83,80,76,65,89,32,110,97,109,101,61,34,84,75,81,49,46,50,50,48,56,50,57,46,48,48,50,32,116,101,115,116,45,107,101,121,115,34,62,60,47,68,73,83,80,76,65,89,62,60,47,86,69,82,83,73,79,78,95,73,78,67,82,69,77,69,78,84,65,76,62,60,47,86,69,82,83,73,79,78,95,82,69,76,69,65,83,69,62,60,47,77,79,68,69,76,62,60,47,77,65,78,85,70,65,67,84,85,82,69,82,62,60,47,100,101,118,105,99,101,105,110,102,111,62,90,5,122,104,95,67,78,98,4,56,46,48,48,104,0,122,-76,62,8,-82,62,18,-82,62,26,-89,60,8,-95,60,18,-95,60,64,-77,-97,-111,-107,-8,51,10,9,48,48,48,48,48,48,48,50,0,16,2,26,-128,60,-3,-121,9,-11,-115,-33,127,-17,6,66,16,103,-94,81,-123,0,96,109,-48,18,-51,-65,-112,-80,10,-28,-9,-23,-78,-53,112,-60,-105,-2,-109,-43,-92,49,7,87,-115,4,-75,78,-113,-98,69,-68,88,-94,49,87,-48,-102,-43,60,127,-36,34,71,15,18,56,65,-10,125,3,-107,-88,33,12,110,-89,84,-14,60,32,-86,-68,-65,-113,27,-21,-42,-38,3,91,-100,118,-89,-48,10,-70,51,-109,98,38,-63,74,-82,23,-25,-19,60,-43,59,51,54,-23,82,55,-65,19,-69,8,60,12,96,75,94,-97,21,-50,86,-17,101,-34,54,-8,-46,-40,-14,23,5,-81,64,-57,105,-31,29,-86,23,40,26,-32,32,-37,46,102,81,12,26,-125,53,-71,95,-78,50,-2,101,2,-52,78,-126,-46,-64,-23,-16,121,72,122,-54,-89,-112,-33,-59,-101,15,10,95,88,-1,-30,44,-86,122,-38,-97,-110,93,38,90,-79,95,27,24,-114,-39,-22,-39,-21,-97,-127,-106,25,64,-47,-91,34,106,-115,5,107,-120,113,23,15,-61,94,29,117,40,-82,-57,123,88,-34,-46,-96,51,10,55,94,-2,-109,54,-3,109,121,11,87,-66,41,-88,22,120,-34,-10,-51,96,11,72,75,-64,-74,-104,-19,120,-92,-11,-51,17,-79,-118,116,-10,39,-56,18,25,-18,100,-97,-50,27,-22,73,-50,-51,-70,-36,-93,-82,23,125,-100,121,-128,106,61,-97,-11,-107,73,47,-43,-4,-9,-79,33,-83,-41,96,57,-37,-9,-99,82,94,85,-33,38,12,121,-94,-50,-39,21,17,-111,7,-121,71,-117,-63,88,116,-49,-89,127,-68,-99,31,32,-90,-90,25,97,104,125,-78,-119,26,123,33,-18,91,46,31,69,-123,-80,-70,-29,6,101,-21,-54,-57,-120,-74,-107,19,-32,24,58,-44,-44,-90,109,-107,-80,-47,56,-50,-67,-125,-76,-47,-95,-28,-123,16,90,73,-43,58,-120,51,61,22,22,-41,-61,-108,110,-18,-17,-120,11,-9,-11,51,106,39,-124,29,115,-52,-85,-54,-7,79,-36,-88,5,52,-14,-47,39,27,-59,69,31,51,-26,-6,47,-121,14,-41,118,-104,67,72,84,86,-69,-24,-13,125,-6,-15,90,-72,87,-7,-22,62,116,84,-7,111,0,50,98,74,39,109,-118,-52,89,-1,33,25,-32,122,-70,-84,42,111,41,1,-57,-2,-14,77,-105,43,47,-11,37,43,121,-127,-78,39,-76,36,-28,43,-2,85,78,79,87,-44,-113,-22,-122,-9,31,91,24,122,-108,31,114,44,12,-113,46,-27,27,-67,119,-99,-69,-4,-81,-122,-117,-29,-124,-100,74,29,60,45,-124,10,31,-60,-89,85,112,-73,89,-26,56,-79,116,25,-2,12,-9,-102,49,-7,-55,-41,51,83,-81,89,-15,-36,-125,-30,-103,84,-40,-71,123,-19,-39,-91,-128,29,23,-48,-46,68,-65,52,76,112,-83,109,68,-11,71,69,-99,48,43,-44,104,-37,44,-84,77,107,86,37,40,61,118,8,-25,53,24,-42,89,24,-21,-78,5,45,3,36,-82,120,-41,30,-6,-52,-37,46,-88,43,-66,20,57,-47,66,-33,14,43,43,-76,-126,-106,17,-43,68,-98,73,-87,-124,41,-86,-45,24,-6,-39,-32,77,89,-5,-65,30,-51,-22,-18,-68,7,121,-107,78,81,-50,-100,-50,-17,19,-79,-61,22,-38,55,-44,56,95,-75,-11,-25,16,50,113,-44,-91,-94,-7,72,86,64,108,-83,-52,23,62,25,94,41,109,42,-85,-77,107,56,33,-53,-47,110,48,-20,-125,41,26,-6,-67,90,24,21,-123,63,-97,52,-112,-7,1,-92,-57,-74,2,119,104,-74,45,52,94,-57,-11,42,-98,-50,-27,24,51,48,-93,-124,-6,-126,-122,-123,-18,112,110,-60,-37,-1,38,82,5,-2,-114,57,-105,29,-46,72,23,-18,84,-22,10,-119,-83,-114,40,-77,-28,62,116,78,-89,29,-114,-29,49,-23,-60,-113,52,-71,109,-98,42,115,88,-56,-29,109,-114,-41,42,39,109,-87,53,-46,67,38,54,83,-85,-37,-126,-49,-6,-37,16,66,41,62,-82,39,-39,104,-99,-76,58,122,2,-125,37,39,-73,-67,69,-64,38,65,-91,41,8,-1,-41,28,118,90,55,-86,-71,-17,-18,-63,-5,-34,-92,-2,-6,-4,-8,-53,-46,121,-118,118,-83,-102,-54,-69,47,117,-60,-26,114,-30,74,-106,-88,-94,27,18,75,-75,72,7,-117,6,-95,1,126,116,36,92,77,-97,-121,-63,31,92,48,-38,-32,60,-115,87,-68,-15,13,70,-17,-121,61,100,-123,17,-61,45,54,101,-3,-40,85,60,10,-82,100,-107,-11,-57,53,105,83,-122,42,-92,-37,5,-124,88,-2,97,36,39,-47,51,123,50,-9,-114,22,-26,13,47,124,-74,-99,-1,-82,87,27,119,116,91,78,-77,96,50,-32,-52,77,21,97,82,-100,121,-81,1,-111,95,-16,-34,23,-46,17,-41,-119,-87,12,43,-3,62,42,-10,-23,17,-10,87,70,-56,-30,80,75,13,56,64,-90,32,-81,-18,-31,-79,-128,20,25,72,-114,105,81,17,110,-95,-93,-7,-106,-86,17,8,-18,63,102,-11,-11,105,98,52,-84,-41,94,-102,-56,-97,-48,3,-116,13,-75,-112,-12,39,-120,17,95,8,57,-38,35,109,-62,32,115,10,106,-110,29,-115,97,-71,113,-44,0,-116,63,-23,77,63,5,-103,-17,105,-1,91,113,-61,45,-112,-91,-79,-117,-3,-66,125,105,45,81,50,-75,-126,-74,-39,61,-27,11,-51,-26,18,-21,96,65,-64,-57,51,114,-93,-40,121,-15,-70,-80,-103,-7,14,-117,-113,9,-41,-36,-102,102,-8,-4,-87,123,115,71,-126,-103,70,-83,-70,79,-3,-89,60,35,-117,33,91,-106,71,115,86,-126,-11,-89,34,-71,6,23,123,-43,34,28,-106,-108,91,-39,-121,-36,-70,-79,61,85,-40,-44,116,-114,-83,-109,-65,20,-90,-30,-36,-14,102,83,-49,54,-57,17,-58,111,28,83,-125,-112,97,-44,-4,-15,-93,-59,-128,-93,93,-7,-81,-25,-18,126,-39,-1,-26,123,-69,-31,-119,3,-113,-51,-31,33,107,-82,42,-22,35,39,31,93,-47,11,112,-37,-76,36,-13,-87,-63,71,19,106,-128,6,6,-115,63,-42,112,-56,16,-20,-109,-42,-33,73,-38,82,-50,-35,-15,101,41,116,-111,117,39,-92,-5,-97,1,117,-60,123,37,-98,66,-60,20,-64,-118,-26,14,49,-105,31,44,31,-4,-116,30,64,-58,119,98,60,67,-72,-91,-39,37,-30,-112,17,47,80,-95,107,-19,1,68,-17,-126,-6,2,120,13,-77,-85,52,92,-71,17,29,46,-11,103,67,-121,10,32,-57,-115,-22,105,-63,106,-106,-71,0,113,82,120,-42,-16,-8,-53,-87,85,14,47,18,-12,33,124,33,21,36,-83,-31,-13,123,91,-118,-40,-40,40,58,-51,46,11,41,41,-111,-24,-45,-10,-90,7,-98,-21,-68,53,-78,19,-88,-91,105,-64,127,-26,10,-98,-125,-33,119,-70,97,-68,13,-112,-125,-8,23,-117,-14,113,-37,76,121,-8,-54,77,120,-86,29,-4,-76,42,-15,-58,-119,-47,94,-16,125,-114,120,83,-45,116,-84,21,-90,119,-65,-46,-124,-78,75,36,32,114,-74,41,11,113,-44,94,92,-44,66,14,7,30,-82,-6,24,33,125,-12,-79,25,20,52,100,83,29,42,70,8,-112,57,53,100,61,-49,-42,20,-37,-97,-84,-88,44,-5,-107,14,118,-105,100,21,27,-32,-102,54,124,41,-119,-47,-36,-60,59,-1,44,27,-45,53,-115,-127,-112,-123,74,-3,-42,123,-48,100,-110,-56,24,81,-36,-55,33,24,123,102,-126,60,-90,-49,127,-11,-23,-105,50,-68,-13,-42,40,-98,-40,-48,8,6,10,-43,64,41,64,63,-100,122,21,-73,96,-54,45,101,-48,-78,-33,-12,-85,9,61,121,56,100,91,-50,-110,31,-80,102,86,14,-1,-61,-3,103,110,-37,3,115,92,113,77,-7,73,-35,70,22,-98,-81,81,58,-104,64,-85,-114,-21,-48,80,116,-27,-30,-127,123,-106,51,109,40,121,-79,-8,47,35,114,127,63,91,-59,-124,30,32,-84,17,-75,-126,54,-66,-43,-64,-120,-69,-40,-21,-64,-121,18,-100,-36,124,-121,-100,121,-64,80,-33,-32,-17,48,-98,53,-59,-88,-100,20,23,-94,52,33,33,5,-96,-31,-68,-17,-100,2,-119,72,-101,96,-112,82,64,123,111,-122,46,-115,51,34,-56,-28,-107,-28,75,31,-117,17,90,102,-64,62,46,-12,-20,-76,-72,-90,103,25,5,121,-1,-88,-41,-102,-118,42,-61,51,-5,119,-60,-7,-105,-99,-91,-70,19,-119,124,-24,83,-9,34,-99,-65,35,117,-10,48,88,-27,-38,80,-35,-58,-50,-45,-94,31,114,11,100,-51,91,37,76,-23,37,-19,-106,-83,17,-2,44,-67,60,-18,-9,-14,-38,74,-100,15,11,-65,-18,-114,29,-38,33,-105,32,18,-23,-103,91,45,62,-11,-11,69,24,86,-29,-42,6,57,-66,125,-31,-32,5,-16,54,46,-90,72,-78,117,-4,-50,93,8,-1,-93,-88,46,85,42,-43,94,88,-16,124,-109,105,-21,-67,37,-80,-103,-82,104,-12,-11,104,-99,-26,-6,110,-67,-86,-117,-96,98,-67,-2,127,91,-107,-116,62,-117,-54,61,-2,-18,3,7,10,39,-72,-2,-63,4,-57,-65,-6,10,-5,-125,-114,36,97,106,86,-4,-85,-101,42,-29,-6,51,24,54,83,60,-74,-76,61,127,110,124,109,-64,50,-86,-87,-58,65,63,1,18,32,45,83,29,84,61,-112,-97,-89,-101,-62,-116,-32,68,-34,92,78,-4,65,-62,-108,65,-106,-103,35,46,122,43,-110,-81,14,-45,76,123,-47,-48,83,13,58,-50,57,94,-9,-109,-57,43,95,109,77,-38,92,20,47,-65,38,-47,40,116,58,-79,-73,121,34,17,-25,97,-97,47,-78,-25,-63,-80,-34,-105,-23,-71,-117,55,61,115,125,32,-43,-31,8,-64,96,-121,-82,114,29,-35,79,77,127,8,-120,-96,-117,-74,127,-89,-24,99,-26,125,-70,68,126,69,-111,86,-102,-2,-62,-32,-57,-88,21,6,-50,-78,19,18,-107,31,-111,-71,-54,74,-92,105,-109,-6,4,1,-34,36,-27,-106,-96,25,-33,-126,44,-37,-123,-11,90,-54,57,66,-97,19,-22,-65,0,-93,112,-121,67,83,24,75,102,-69,46,15,-87,-11,-32,-99,-117,11,-127,-68,-101,-62,116,88,99,61,52,-101,-67,-56,46,-45,-90,96,-47,-77,86,91,108,-128,47,49,17,-11,109,-88,-7,-2,18,-100,32,2,-24,5,-40,-1,-24,-94,61,-19,-5,-104,95,36,117,-83,-7,65,-88,-71,-25,-105,-58,63,-41,-123,29,-56,34,92,62,-106,-124,24,125,34,36,70,22,-104,123,-94,76,-87,-89,-71,103,19,-105,-27,43,-103,35,-84,122,37,51,1,33,-37,-112,-105,122,73,-105,-121,3,52,99,-47,-50,-37,-29,114,-59,-111,30,-123,59,-23,-105,94,-34,19,-9,96,-16,29,-116,-43,-7,109,112,-27,106,-8,-128,49,-19,69,62,-73,-124,75,97,122,-29,119,69,123,-99,10,101,-9,-60,40,-5,34,-35,65,-52,89,-1,102,-102,-104,-77,-106,-49,53,73,25,-62,120,117,-81,-53,-68,106,32,121,104,113,123,68,106,41,121,-53,31,92,57,72,122,99,-36,-9,66,-121,77,-17,-73,85,113,55,2,-104,-69,46,-102,-85,50,72,-15,-66,-23,-83,72,-22,-49,-37,16,3,-3,-29,-66,17,124,-100,-104,6,-6,69,-29,-4,-63,-25,115,41,53,-94,-82,28,7,113,-84,-126,103,-69,122,87,5,22,65,-32,-68,79,-9,-113,-3,113,-1,46,100,127,80,-56,102,-87,43,-48,119,20,29,-58,-80,-4,121,-6,-116,48,-74,12,32,127,-41,-127,-46,-98,59,90,-46,-18,-34,47,56,-102,-35,-28,63,50,-89,-46,-69,-109,53,41,-23,103,37,-100,5,78,28,96,-128,-61,-17,-38,104,54,-113,-53,113,44,13,-27,-47,39,123,-127,17,-47,-76,78,104,-112,39,93,73,-15,51,-109,-28,89,-72,77,-63,44,8,-84,-127,-128,-57,-29,-99,-86,-15,-37,82,59,99,-29,-48,10,-88,-69,-9,6,97,-71,30,-106,89,51,2,60,71,-106,67,-58,48,55,50,111,16,73,49,99,-16,52,-93,98,63,-1,4,117,-20,-76,-35,-8,96,80,-112,61,50,-37,96,100,-16,69,14,-86,-53,-119,18,-53,-50,-78,-83,127,-19,0,43,-102,-43,-128,86,-74,-22,-103,69,40,45,103,71,71,-46,-2,-25,-3,86,-97,69,-32,-45,111,-8,-104,18,-21,18,-57,-5,-102,-4,123,-51,-99,-30,-109,-127,-120,67,-68,44,-74,114,111,0,37,7,-55,93,-51,-55,55,-13,-38,-94,44,-72,60,-69,-90,-40,-31,-76,-40,-55,106,54,95,84,30,99,-91,88,-36,12,-125,-97,38,-58,-23,18,-62,-19,-97,-108,80,-64,-111,94,83,116,-8,-28,85,-102,-125,70,75,101,-35,27,116,109,-7,-33,97,-77,113,74,50,-34,9,-49,-85,93,44,-21,-55,18,7,-107,-55,50,20,73,-127,-125,58,12,-47,-14,-77,-111,-14,-32,44,46,-10,67,107,-45,113,-70,-20,-115,53,-76,75,-25,34,-28,-78,89,35,-109,-103,-51,17,98,47,-71,55,39,70,-55,62,108,-54,-76,25,-104,15,-128,-4,21,-64,-8,-48,20,-50,-35,-98,-59,-73,20,-106,-89,-47,-38,1,-52,-110,52,43,-126,24,118,-61,114,29,4,9,-18,126,-126,6,-121,92,37,32,-121,-91,116,-102,-25,-80,-26,-12,-54,78,-98,-75,-46,66,-18,-79,5,101,45,65,96,33,105,-18,-24,-86,-91,121,89,70,26,52,7,-84,-73,-59,-123,-103,-68,-6,125,-108,-80,-76,13,61,47,85,75,-69,-16,-97,28,-88,54,19,-105,39,-62,91,-57,-107,68,115,31,-57,42,-70,22,-119,-83,8,9,66,26,15,-51,91,-122,76,-117,-54,84,36,-53,-19,-59,-128,-63,-66,-71,-72,-35,46,-60,103,80,-71,-71,22,120,-80,34,-64,15,-116,-4,-120,-71,-109,10,77,-95,52,-108,115,-128,106,-48,-26,-125,56,49,-4,98,17,-104,-64,-41,99,62,41,-105,53,63,-63,118,-23,-45,116,126,-93,-70,-13,-3,-43,2,16,-128,-117,-66,104,46,-41,101,93,-50,-81,-44,-57,-9,57,-28,119,73,-45,-63,59,8,94,83,32,-98,35,37,-87,-44,-127,54,-86,-59,-52,-57,-16,37,6,-65,-48,8,-59,86,70,46,104,-49,70,21,-27,-89,41,-32,-39,85,-53,95,46,-117,81,115,-106,24,23,11,-60,-32,7,-5,4,13,100,108,-106,107,-30,24,-79,81,-103,1,-69,92,-68,33,20,-107,-5,-10,18,-62,-114,-75,82,-96,-79,-14,9,57,95,126,-11,60,-4,-4,43,-86,-128,-34,45,20,-111,64,96,58,13,48,-66,28,-41,72,-91,1,122,109,124,119,24,104,65,-40,-125,-39,46,41,109,-46,97,24,80,13,-126,4,-9,57,-80,94,-38,81,83,-62,-25,-44,41,-69,0,-52,-113,-118,39,-14,-13,4,31,107,49,-121,101,-30,-43,-122,-46,-25,-65,-118,-114,72,87,50,-54,-24,-99,10,18,86,40,-104,-10,-93,-62,30,-20,119,-26,28,-47,16,3,-106,-83,-47,-79,58,-96,-95,127,34,61,12,-19,-80,22,101,106,-69,25,-37,-71,-101,86,9,73,-71,-13,74,-56,107,-46,44,-18,-126,19,-67,112,-119,79,-91,60,-81,-104,-54,-48,-78,79,-90,18,-67,-120,65,-36,82,-25,12,-125,28,90,106,-85,-111,-18,3,8,72,45,-75,57,113,52,29,23,67,105,-67,-21,-9,-26,-115,-60,41,-78,-1,-114,48,-69,72,-13,117,104,-29,54,-10,-89,-111,33,-73,28,124,-51,-2,0,-11,-69,102,77,-15,-88,64,40,-32,37,-21,108,-49,43,-18,-97,56,33,73,90,0,13,65,15,-42,62,-85,3,101,-50,-48,105,-31,109,-27,-7,-122,-22,-33,44,125,-67,12,-79,83,18,-38,65,77,-119,110,63,16,40,4,-80,10,-89,52,-124,127,73,-126,104,-2,-83,71,-74,67,-13,102,50,-17,-18,50,-5,-119,-84,29,11,-92,48,95,-80,43,67,53,-68,45,14,-53,117,28,-51,-53,1,-8,-7,22,-115,-2,-93,-50,79,16,-96,92,-10,87,-31,-85,-64,104,64,-126,62,0,26,101,-14,-22,48,-95,43,-107,-11,-70,28,-38,-107,-15,15,30,45,-79,30,-16,-47,102,-43,88,-77,104,-27,79,40,88,-91,11,123,-117,105,-80,98,-115,3,47,-31,-83,-88,-57,20,-65,53,-126,-67,123,126,105,106,112,-25,8,59,-18,109,-97,-123,68,104,81,74,-113,10,-103,-97,14,-19,54,0,-20,-58,25,39,-121,-17,10,0,-114,-120,-30,60,-9,-60,-13,112,108,-61,67,-80,24,-24,-36,-82,72,59,15,-105,-67,46,-110,-19,-121,84,117,-68,17,38,-125,-119,-72,0,78,104,-41,-114,62,-74,-68,-87,-49,-44,120,36,-128,-54,92,19,-87,-17,113,-43,-38,52,-64,-104,90,-43,-106,-42,-60,-56,60,-57,-42,81,-13,111,17,-112,67,16,-23,-119,19,87,-101,42,-73,69,-87,-43,-33,98,18,45,-59,-7,25,-88,-20,64,9,-51,-60,117,-46,97,-128,-10,-17,-2,-48,119,-36,123,125,-44,-45,75,-74,40,122,82,108,90,-81,-54,-121,22,26,113,-40,-43,-69,-71,84,40,-80,-57,91,-105,-86,-52,-39,-57,-35,-128,117,-56,57,-109,-32,-38,-125,-12,90,104,-13,-78,119,63,56,79,78,73,80,-115,42,22,43,76,91,31,-96,51,114,17,-66,57,-9,-46,120,69,44,89,33,61,30,105,117,52,95,48,9,97,104,-78,90,126,-7,1,-11,-112,121,10,-127,117,93,37,91,-121,-19,85,-48,27,36,-15,10,-38,-72,-40,-90,102,-86,-111,70,51,-20,34,120,-63,-125,-122,30,16,9,-85,22,21,120,122,-64,-104,-17,55,-124,42,-45,82,-41,-106,117,117,-117,121,-112,-41,51,63,74,-115,36,106,-54,46,-71,60,-115,13,-19,-73,108,46,38,-124,-2,119,-109,70,74,-124,83,41,-52,-41,83,115,-4,117,-39,29,-99,-125,-82,-20,-12,-17,52,52,102,108,60,35,59,-82,110,-83,3,0,100,94,-126,102,-32,-21,-77,20,-87,59,-54,-46,118,-92,-22,-7,-61,15,-16,-112,-51,82,-25,-43,103,-61,-85,5,-32,-37,-116,-95,-55,37,102,-21,0,4,-15,-117,-72,-42,-46,-57,-121,-22,57,63,-16,-24,108,23,9,-81,-114,15,-18,-121,108,-107,-10,40,-36,-51,54,50,18,37,-56,103,-4,98,45,94,-57,42,-57,-59,-20,42,-14,82,-52,-78,-81,108,-8,39,-40,46,9,-4,13,94,35,60,-122,12,-71,-82,78,-91,-114,114,-128,-81,-5,9,-97,58,-106,-94,26,98,-51,-6,107,46,10,-105,117,76,17,-128,-14,-41,-19,75,38,-40,-30,52,-26,125,-12,100,-6,8,5,44,-126,-126,85,99,-56,81,-117,-97,8,-41,-34,-22,121,90,32,-84,-2,-110,-73,127,123,70,-92,-81,107,-40,-37,100,65,1,-44,100,66,9,11,-120,77,-50,107,94,63,-47,65,37,88,-59,-76,70,-12,-79,-39,43,29,-13,43,37,-89,-57,-125,73,-79,-14,85,120,-74,-22,72,93,-65,121,87,-78,89,-115,-63,22,-56,-43,9,-16,-128,-9,34,-55,7,-28,103,-9,87,39,-127,11,-11,58,59,-36,124,-62,-77,-39,123,-2,-84,90,92,-58,-109,-79,89,-92,-99,-124,3,122,108,119,-66,-87,-105,-85,81,-88,50,-8,73,-89,-22,-13,76,-37,-33,-38,-116,-112,109,92,-9,-25,4,-73,122,120,28,24,113,98,-41,-76,-58,-103,-13,46,-25,127,109,-70,32,-17,81,-7,-120,36,20,15,99,43,-13,86,-79,121,-69,-28,91,101,-26,16,-128,-92,-30,-58,65,-82,49,-35,-122,92,117,-82,-32,-44,33,97,6,106,12,-61,82,-45,-128,114,-19,-51,5,77,4,9,-77,-46,109,-57,19,-80,61,47,122,-92,46,-21,-111,-73,60,3,46,56,-26,92,92,62,-95,22,-41,-103,108,76,-85,-105,-118,-44,-3,45,-84,-68,-46,-104,86,-11,-108,-114,123,33,-112,96,20,-74,11,-54,-114,23,-31,-27,100,-85,-30,12,-23,-109,-21,87,-40,-112,-104,-108,-92,-13,-61,39,29,-35,109,29,8,23,5,-7,-91,24,-77,29,80,14,-117,-71,19,-118,-21,-125,122,106,-121,-75,37,-77,-92,-35,-100,-54,69,-111,61,55,-122,70,28,92,-70,-42,-59,41,-1,-43,19,16,-32,68,-42,-54,45,110,125,39,-101,-43,85,-66,109,-49,-125,-9,38,91,39,-96,9,76,-25,-41,51,12,87,-45,-6,57,-113,23,-14,-90,54,-10,9,46,16,-38,-104,-55,-31,-34,-7,-39,41,-101,121,47,-18,-98,11,6,-73,50,-54,-39,-43,-98,-6,-24,-119,87,-108,-21,8,-96,-56,74,-83,-60,41,-36,126,-67,122,-119,-16,114,16,-127,115,80,-80,-123,-24,-41,41,15,-69,-107,114,77,-36,82,-38,36,-118,30,-105,-40,48,87,-77,41,45,48,22,-12,101,-102,10,33,-5,-107,71,-6,-28,37,72,11,113,18,91,114,2,-120,8,55,19,-59,-66,114,44,-116,79,-17,104,-77,86,-53,59,54,52,-32,-48,71,-8,-85,40,91,96,-77,-124,19,19,20,-14,18,97,-115,-28,67,-12,-122,-53,65,121,-68,-29,-80,65,53,-7,-107,15,-47,-108,-13,125,127,111,86,-91,-44,46,36,101,107,12,65,105,-60,27,31,97,-106,-122,-64,-53,-6,-14,-120,-92,62,50,-71,-55,-87,-29,-62,-4,-76,1,-12,-115,-6,-108,89,-103,66,94,69,84,123,125,69,-127,-117,-56,19,-44,35,-52,51,-7,-77,-95,110,84,9,19,-10,81,-72,22,35,117,118,-60,122,-87,52,16,78,4,26,-21,-124,97,-109,112,123,-52,-127,-50,-78,-51,78,-114,-83,50,-81,109,-72,-84,36,-2,-84,-28,100,-15,-101,102,1,-58,55,-11,-36,-1,-110,-48,-114,-92,19,26,-118,-119,-56,-74,-24,-126,111,-70,107,119,-11,35,-7,25,-103,4,-89,66,9,-9,104,-48,-8,32,-106,115,-123,51,-104,-69,18,40,100,96,-58,-128,-24,-58,11,102,73,60,93,-18,-81,-113,-20,77,26,30,97,-9,71,127,-110,12,-87,-41,75,81,22,-55,9,-52,105,-54,-57,23,5,117,-7,-38,-95,-47,-57,-97,-36,49,-18,64,-72,-8,12,103,-71,94,-53,-115,115,-117,-48,-5,-105,-49,112,95,-123,-42,-2,-35,11,-51,-12,-35,90,-46,76,-6,79,98,-52,90,-92,90,-15,126,-45,98,-65,-19,33,116,12,-88,46,11,-99,100,-14,-79,-12,42,90,30,6,111,-77,-118,109,-122,95,-20,113,-91,28,-12,79,-61,-111,-67,102,-43,-62,-95,-22,27,-51,76,-47,99,63,-96,-38,109,32,18,8,-84,81,76,2,-122,66,-89,115,29,-23,-114,93,-15,-76,-8,59,66,-21,-10,77,62,-43,-85,-51,-34,-56,-106,-75,29,-73,71,-103,60,124,14,126,59,43,-91,-45,-24,-72,-39,-40,-87,-93,-1,88,39,7,6,94,-41,-126,1,-57,-44,-76,-7,-103,-40,60,123,-122,38,-3,22,-15,-123,43,-108,-32,101,-9,-55,-15,-17,-61,-91,43,-3,9,78,74,122,-72,-115,78,-13,-102,113,-77,-126,10,-25,45,114,4,83,-89,-47,-76,-26,60,6,88,-104,-101,61,-46,27,13,60,-110,-4,124,-53,-14,99,-10,97,-29,-31,-55,-124,62,7,-22,-74,2,-56,-94,-103,121,-85,-101,47,125,106,87,82,69,22,73,-103,23,-70,74,55,-38,103,42,-19,-118,-25,5,-121,-96,-9,-64,34,-80,93,-40,33,33,-127,-46,96,-23,-12,54,15,22,43,-38,30,83,-22,-34,86,-57,58,-108,107,-4,-51,1,125,-122,4,16,-71,27,83,127,-13,-63,-73,79,4,-22,54,-26,-69,10,36,76,-18,33,16,58,108,86,111,-120,117,-53,-110,-46,36,-86,-55,109,-11,-41,42,104,-86,-24,-23,-35,-62,34,23,-1,67,-78,-15,-29,43,25,44,60,-71,66,-28,-121,-64,91,-78,-126,-53,106,24,65,57,-58,9,58,-93,-36,-4,105,-112,-92,-17,7,-25,7,-80,-55,116,109,57,-11,-125,60,-36,-95,55,-126,68,-60,52,85,84,-115,-72,34,101,-80,-31,-60,-23,-74,55,99,-27,28,-106,69,-74,24,6,22,33,91,-69,-99,74,20,78,-65,-66,-6,112,90,-91,31,-30,-3,-97,120,113,-67,-123,-125,58,-19,44,-64,118,105,-104,59,-94,-13,76,-72,115,-54,74,107,85,-28,-118,54,-83,-84,-8,-118,-28,84,55,-63,-96,-2,6,-118,6,9,-23,39,32,92,77,55,-38,-115,18,45,-34,36,103,-43,-42,-40,-69,-73,26,62,-48,27,-60,24,50,-105,46,-57,85,73,-79,-63,82,1,72,21,-9,36,0,92,24,-51,-64,89,-85,-97,-10,-55,-95,-104,-19,66,15,85,1,-46,108,100,108,-92,86,109,-106,-108,-2,-70,-20,-112,111,69,14,-4,-37,126,-95,-54,-40,65,80,30,116,-58,-117,20,-69,6,-45,-14,100,-44,38,-4,-26,-98,43,-70,44,-36,-40,-81,-67,79,68,9,-61,-73,56,-24,4,-80,109,-37,66,-28,95,45,12,-11,30,-4,-66,90,-64,102,-108,-45,-20,100,109,78,89,-120,109,117,16,-122,-108,103,-106,88,11,-56,-50,4,-26,-68,59,-90,-123,-122,-19,-109,-79,70,-66,-71,71,-9,-48,-15,126,14,95,-32,-88,10,-71,-22,-33,-75,-101,13,61,-112,38,85,-47,49,111,74,38,31,-114,49,-95,29,21,-68,-28,-4,75,13,-105,30,68,45,88,-27,-34,-112,9,-124,-9,-21,-10,-69,-52,-104,-54,106,-127,-103,-81,-99,107,-57,31,89,90,-111,-86,-85,16,92,-120,13,108,104,114,119,22,102,-58,-127,93,98,-28,-16,-64,122,-23,-68,22,-113,96,-56,-71,79,15,-7,58,-121,-122,-47,-41,-9,-5,125,-17,-53,59,56,116,114,-15,40,102,127,-29,114,44,82,20,36,66,-64,119,115,109,-82,55,80,-94,-56,117,34,88,25,-113,64,41,34,44,-68,45,-104,34,55,-41,-10,127,11,-126,-6,-21,107,73,6,-53,84,-100,37,-69,93,-93,53,97,87,-53,-80,-60,-100,106,66,-44,31,0,-15,56,97,12,124,44,35,28,-84,-52,82,-47,84,71,-38,-39,-15,48,-8,-16,101,-60,-35,-34,-73,-80,72,-45,16,113,-113,-45,-28,-50,-121,-43,70,110,-10,-3,84,95,95,-61,10,22,75,-23,21,59,-116,90,-37,74,62,127,-3,-59,-20,-34,126,45,-45,47,-18,82,-45,-37,6,-2,-29,-53,-119,-88,85,-33,-106,-107,87,-68,106,2,108,-71,16,-108,-92,-106,71,40,107,108,-92,127,-88,-106,115,90,69,-71,-3,-114,-92,-58,-69,-12,-125,47,-114,-43,-81,-12,-57,-96,-50,75,59,-44,86,106,-97,-50,-38,-50,-88,19,55,-66,56,-1,-84,118,-109,-92,-50,-30,-117,1,-115,98,41,-107,-48,12,-102,-38,45,115,-86,103,102,115,-128,-2,45,-91,-85,8,-102,25,14,-62,83,56,-102,125,114,-50,123,-42,21,-10,42,84,1,20,-66,-22,-95,-75,-64,-109,82,-41,-114,-65,116,-87,24,59,-32,-10,-102,7,98,-25,-81,-76,11,36,34,96,-2,85,-48,80,-97,81,98,-1,-18,-112,21,-74,61,-19,-23,0,105,-81,-88,20,-106,34,36,-112,64,100,-3,-49,20,100,29,52,99,-34,-57,40,-4,-73,121,-71,33,42,-100,74,-82,30,126,52,-15,-115,63,53,-46,117,-20,-62,-121,-18,16,73,25,-92,-85,9,-122,118,-15,76,102,14,-93,-35,-7,-93,60,120,-96,-119,53,124,-115,69,91,-5,43,22,-15,6,98,30,96,46,55,-72,-96,-23,121,-75,-66,106,115,76,109,3,-12,41,12,-109,33,-47,-101,50,-65,39,-88,-88,60,104,-47,41,73,34,105,-121,-82,54,-52,-100,-5,-42,89,2,-26,-9,75,70,-109,122,-74,86,-17,94,-57,-11,-6,-121,62,-121,78,-84,105,22,39,9,-82,-107,14,-78,-90,106,11,-115,-62,41,12,-19,103,54,-36,21,-58,-46,-20,-48,-113,32,95,117,-8,-106,-93,-36,-88,-21,57,85,-91,19,44,81,90,-11,24,65,48,-50,-3,120,-128,87,-107,-31,-74,-44,71,-8,-75,79,-100,-31,-73,93,45,101,-125,-48,72,125,-5,-77,75,-103,-47,-38,99,-29,115,84,12,-31,-103,-128,-40,-95,-44,24,93,42,105,-4,-107,124,-67,121,125,-90,114,95,76,36,-39,-79,-128,117,109,-84,-66,-8,-94,-102,-120,123,-115,-112,52,31,-56,76,-50,-25,-114,121,-7,59,126,-34,-54,89,3,-43,-124,86,115,-109,-54,-51,-94,124,-53,-40,103,28,76,-101,24,-86,33,98,-114,75,123,-72,-14,-39,120,104,-13,42,114,91,-71,-58,-105,-98,-71,9,-12,-22,-124,109,3,-124,-126,-94,-96,-51,16,25,-82,49,85,54,-89,95,64,125,9,8,-65,43,-112,-105,-100,123,40,-117,11,-118,-94,-12,72,49,-113,-17,122,49,-110,-27,70,-120,-37,-11,-27,-97,34,64,72,12,41,119,45,-56,-101,-7,38,-13,111,-28,-24,86,77,-90,43,-127,55,-11,59,77,65,2,-30,-16,-84,-6,89,-27,105,86,63,41,24,-109,12,-100,82,-38,-119,-26,73,-43,-56,4,58,-114,-12,29,49,64,27,-71,122,-20,61,93,74,104,58,29,75,-79,-25,-59,-96,-51,-38,-117,19,16,60,-94,-94,59,-29,6,-60,-98,-77,107,-3,28,-47,-36,-15,-9,49,52,106,-14,99,-48,115,-8,-103,-33,-102,-35,-37,-44,34,111,112,41,-42,-127,13,-108,-15,-29,-111,60,-55,102,44,57,101,-80,-95,-79,63,16,35,102,121,-5,-95,50,-14,13,125,100,-3,127,-40,-43,93,-82,-45,-110,46,-112,-107,-41,55,115,-67,-121,86,-107,-88,112,21,-15,-74,0,-26,-112,-128,116,-46,-126,125,51,-61,98,-72,22,-72,103,28,50,-18,-4,33,97,55,92,-117,-16,1,69,67,-24,114,-90,124,-29,-18,-119,-6,-4,56,110,-101,-46,-2,58,-93,-54,-72,110,10,1,-89,-69,127,-93,-119,77,-40,29,93,115,105,80,120,96,66,5,-89,123,67,116,76,79,111,-105,103,-67,6,-60,48,20,125,74,106,116,-105,102,-128,-48,50,-94,-66,-72,15,-46,69,-75,83,-128,7,-103,18,114,-120,16,57,64,-50,77,-46,86,0,-98,-128,81,-25,25,124,-107,54,96,41,20,-95,94,95,-45,-72,-89,-51,-18,-59,64,-84,60,-106,-26,17,80,58,6,29,-14,-53,115,77,-88,-39,-39,120,-72,-40,-38,70,54,44,-75,-33,-82,105,28,-100,51,-83,-90,59,55,67,-14,88,117,-102,-118,-92,-84,115,77,-9,49,-112,-83,100,4,55,-5,-121,67,67,-55,-102,-32,97,45,7,76,-29,-23,94,63,-10,-101,-64,-127,4,-22,105,-79,-44,25,-93,-92,-111,-105,29,-25,8,76,-123,73,94,-92,-102,23,-69,-27,50,-35,3,56,-127,17,-53,109,-106,-127,70,106,-114,35,110,80,-99,-12,-87,-26,48,47,-80,-84,-100,80,7,-24,114,-73,-102,40,-100,47,-72,8,35,38,-19,84,-118,-57,27,-92,1,72,6,-51,-108,-122,68,35,-59,39,28,-104,102,-79,-43,-59,-71,21,102,-23,72,72,65,-22,-13,-108,-33,-4,127,-8,-52,-85,102,-93,-31,103,-29,83,123,-12,31,-34,27,59,-65,-110,31,119,110,91,78,-11,-93,-8,69,-69,125,-114,98,-76,104,23,24,107,-75,39,-117,110,-4,-18,108,53,87,-83,87,-78,106,78,33,102,-60,12,5,-40,-49,127,122,76,-69,31,24,38,-32,-121,62,-58,-11,-72,32,-2,37,123,82,43,-2,-27,26,24,31,52,-23,103,-60,-77,-62,36,-33,-106,-76,6,12,-6,62,28,100,-54,25,78,-36,-53,-44,-110,-11,76,-17,-12,-10,21,-110,-28,24,87,-114,29,124,124,20,46,52,55,-91,-15,3,118,-10,-25,-114,81,-2,25,32,-30,109,103,-4,-124,-54,42,5,43,-7,-126,-124,35,-117,80,73,14,39,-21,-89,-64,-108,92,-8,9,-4,-83,-51,12,-34,-119,-47,53,-78,-86,12,-27,-110,-102,-41,103,0,73,23,95,-25,-7,54,74,35,-32,-119,-50,11,-27,56,41,124,-93,13,15,58,-84,-94,118,5,1,-82,-121,-61,106,38,-1,41,35,78,-18,-123,101,39,-95,-11,-86,-76,-65,-29,-10,-55,87,17,-50,24,-18,-60,75,107,-74,54,122,122,-94,64,-89,-56,45,122,-110,-26,34,111,49,10,-40,99,-49,-117,-90,70,-99,86,-105,31,-118,56,3,54,113,-50,25,-53,50,-19,55,70,-77,-45,14,83,-17,-61,-28,-40,32,36,0,-67,60,-112,83,-48,35,-92,-122,-75,-36,61,98,2,-91,-119,17,25,-2,53,-116,69,102,-76,-86,120,-104,10,113,-86,9,-102,-89,40,2,-52,124,-90,7,28,80,-81,-88,20,-122,38,82,5,-69,-44,73,121,-112,31,58,61,66,117,68,-59,-49,-35,25,108,3,76,-109,116,8,-128,67,117,60,-92,92,-67,-61,36,-7,33,-100,2,-93,113,112,19,123,96,12,27,60,-42,74,-116,-31,113,37,113,127,78,-34,-17,49,-71,55,55,31,-84,82,-24,-82,68,40,5,11,-18,-109,36,12,-104,52,52,66,99,-58,124,96,89,37,110,-83,121,-74,-47,-83,69,94,-116,69,-51,76,-20,22,70,35,-110,-99,39,-97,19,5,79,-56,21,-112,-84,24,122,66,-10,-86,22,103,-64,-95,67,76,-119,47,-51,35,-38,110,-22,62,-80,50,70,-83,34,-3,-43,-54,-55,104,-100,-125,10,49,32,-81,88,110,-78,63,-123,76,-73,29,-119,82,73,-89,-128,-79,0,-95,74,-50,7,-97,76,100,108,56,76,14,-35,99,113,11,36,-42,118,92,-122,-78,-14,-19,-122,-73,-51,22,103,94,13,74,-29,-15,73,81,42,110,93,99,-61,117,-50,62,-62,29,-81,-38,-122,-100,127,-121,-96,66,87,-121,-128,-125,70,-51,58,-110,-3,-119,-15,37,-50,-121,28,-36,-109,-60,-57,-71,-41,-110,-26,-112,-73,51,-44,-36,-100,94,-34,13,-121,-111,79,83,-89,-111,92,123,-89,101,-12,22,120,27,-37,-51,64,74,30,98,62,90,-12,97,-28,66,-95,-31,-58,-80,100,86,-63,-83,52,20,96,57,-116,-128,-16,-34,-11,82,-42,-88,63,106,113,123,-85,-128,-27,-51,-122,89,37,-65,-101,-16,77,36,-85,115,62,18,-126,-69,-48,42,-29,-113,55,-66,15,-54,103,-8,19,-30,54,48,-44,-93,4,-30,-120,-116,19,51,118,77,-123,-77,-11,74,-93,43,-63,110,55,97,-97,95,-99,-111,44,88,5,-122,-49,-87,121,-2,-69,-54,-40,41,-57,119,-102,9,0,-79,97,-75,-105,45,-113,-11,-124,23,-106,2,-32,-105,-117,-44,74,-68,69,-62,22,-121,43,-71,-44,-116,64,-19,-22,-30,-79,-1,-122,-62,62,64,103,-4,-38,77,96,123,-64,-67,22,69,93,-4,-51,-20,86,-54,-83,-126,-90,-92,-60,-43,-120,62,-8,-104,74,12,55,52,90,33,-11,-2,-50,48,38,0,62,-93,15,-110,26,39,-92,106,77,-22,-84,57,50,-17,98,-37,125,-107,76,-72,45,123,-11,-73,127,106,-127,64,-128,-39,-16,109,-56,-126,9,-8,54,71,-98,69,117,-14,72,-32,-12,59,81,-51,-25,9,-111,-65,-124,-57,44,-63,33,8,48,-6,-18,-12,-26,18,29,5,-113,-18,67,116,37,-65,102,116,27,98,-1,-13,-96,92,-27,122,-72,53,38,-12,56,-79,58,-124,-124,26,-73,-12,-69,84,-9,-28,-20,123,99,22,-36,47,-127,84,-12,-56,-63,-19,11,-56,48,44,113,101,61,-17,62,-45,-2,-57,87,102,-32,53,-37,115,-79,-121,-54,-71,-79,122,-88,51,106,-12,-43,-122,-112,33,119,-3,-1,102,-53,-18,-90,83,127,85,28,-9,118,-116,118,88,-93,-54,-35,101,69,103,41,-44,-46,118,107,-10,-116,9,34,-64,-117,12,-21,-119,-82,26,99,-63,64,-12,36,-40,-30,-17,109,105,-4,-31,71,-55,30,-128,-24,29,-117,-85,10,-61,-82,-31,-111,-5,-84,21,56,80,-45,-106,110,-113,-63,31,-59,78,-64,21,-115,78,107,-43,71,18,69,-89,-8,-9,-99,-34,-13,-30,42,-106,16,44,-13,97,45,-15,-46,4,-42,17,-85,91,22,103,-44,-95,-23,-97,96,-98,46,-5,117,122,63,-114,-22,-61,82,102,-121,-96,-4,-110,-43,89,-21,-32,123,114,-104,-39,-7,-82,-17,-15,-50,-21,-64,-17,-83,-3,123,103,112,-56,19,84,-55,1,-5,-36,-11,-105,-93,-6,98,86,-17,25,4,-110,71,93,-125,51,45,111,1,60,-44,-118,21,-40,122,103,-35,78,124,88,27,63,-25,81,85,-113,2,58,63,117,-63,-26,-9,-63,23,15,-21,44,8,80,-49,54,64,17,-101,-29,43,66,73,110,-71,113,-5,13,-81,9,13,51,12,93,81,-82,-106,-66,19,35,-46,-60,64,-41,-2,35,-111,-125,14,-13,65,-56,101,29,87,-23,18,-102,-24,71,2,-45,5,93,-54,27,-107,-114,50,-30,-11,6,23,-78,-38,116,0,-36,-79,123,15,-36,33,-86,-3,-56,52,-28,-4,114,116,70,-62,107,-43,-51,108,33,-41,-123,21,-1,-60,-37,-69,-65,7,-72,85,99,37,-26,-99,77,18,102,33,-121,-37,-60,46,53,25,-4,9,61,-88,39,-29,32,-112,-17,16,-21,96,-88,113,81,122,10,77,-117,-86,103,-3,50,17,-42,-114,73,5,-36,40,95,-44,-51,-27,71,-109,84,97,-107,1,90,19,-128,109,110,-48,114,-31,-112,-105,-102,-128,-77,-68,26,-92,45,-15,-106,-2,53,-56,-73,32,7,39,96,-18,-32,-45,27,-93,-25,67,-26,-118,118,-61,56,52,112,-12,112,-73,34,101,100,94,102,34,16,38,-18,114,76,59,57,116,-93,-107,-20,25,24,125,-91,4,57,61,-18,30,-52,-28,-39,-2,122,-109,38,-9,-92,-100,-108,74,-92,22,-60,47,33,88,-73,96,88,-17,108,-110,5,-95,24,11,56,-85,-50,125,-16,6,-89,86,117,-73,27,-95,113,19,-18,-42,-102,82,91,14,17,64,81,121,126,-81,117,69,-121,14,69,-50,-114,-49,-15,-104,11,108,67,-90,50,-4,123,32,-30,-60,-5,-46,6,40,5,48,0,58,-127,2,8,-5,1,18,-5,1,64,-59,-97,-111,-107,-8,51,10,0,16,2,26,-29,1,10,-32,1,48,48,48,100,50,50,51,100,51,101,48,52,48,48,48,48,48,49,48,48,48,48,48,48,48,48,48,48,54,56,101,51,50,48,98,52,50,55,52,99,48,98,51,49,55,53,51,54,97,98,101,51,53,98,54,97,50,48,48,48,48,48,48,48,102,99,56,101,54,52,50,99,98,53,98,52,57,49,100,56,97,48,53,97,53,48,48,52,100,52,57,99,102,56,98,57,53,50,99,49,98,56,49,57,100,98,49,100,100,48,102,102,48,48,57,98,48,50,48,51,56,97,54,100,50,97,99,56,57,102,100,100,54,97,56,54,52,48,99,98,56,53,48,51,99,49,49,56,53,98,54,98,100,100,57,101,49,48,52,99,101,52,101,52,54,50,57,97,49,97,102,52,100,55,54,56,99,98,50,55,48,100,98,98,102,51,56,52,56,102,97,54,100,100,102,99,55,52,97,54,50,97,101,101,55,49,98,101,50,101,101,54,99,99,55,48,55,102,53,101,49,48,49,54,32,-30,-60,-5,-46,6,40,2,48,0,-118,1,14,99,111,109,46,116,101,110,99,101,110,116,46,109,109,-110,1,74,8,-97,3,18,69,8,65,18,65,4,4,-88,-52,-73,71,-124,-12,7,71,28,-91,114,-54,80,-1,100,-31,127,78,55,-55,23,31,-95,76,-87,120,-5,-104,13,-89,123,-9,52,30,-49,-31,39,-45,-74,27,-46,39,-2,-42,-90,65,125,-43,89,-93,-74,-11,-69,110,28,-74,-124,-20,-93,-87,93,107,95
]
                hex_str = ''.join(f'{b & 0xff:02x}' for b in data)
                data_back = bytes.fromhex(hex_str)


#                 hex_data ='''
# 0a6a1224082012204116be5eac0a8044b9ec82227824f09f678d6cc0c02112f4bb2f1a86e5f9be371a4208c905123d08391239045b2e7d5e3bea2eccfdb6d04661823ebe512f0740214b2912f522a007329ed94ad8f90919fc651e701d0c1ebad593a06e8db527df7f4aaace128a4a0a340a010010ecb2e39af8ffffffff011a104132303532393433646133623431660020d08e81c0022a0a616e64726f69642d3333300212280a0408001200120c0a0012001a002204080012001a040a0012002204080012002a040800120030001aa402089e02129e020a24082012204116be5eac0a8044b9ec82227824f09f678d6cc0c02112f4bb2f1a86e5f9be3712f50108ef0112ef0108a84e12e3010f31d6e200d42dda6d5f3796d289e6851e4f7fac1597ff436c38d91f8293bd5901855168e5f8fbb1203fc1a7c6c5eb28405f93f51096d76deac6847aeee2acc27cf628db5cc49e828370b4aa4215c0e45ba1faa17522c51c72681381816b1d6844112875614b1b989df73803e2d02134d3062c19dcf0bf08282fffb20da2131d1c99cdce71ec9d5324a891f48c84dc6a68f7df60a5ed1cc117ff88f7cc3de09732474704b9cdefe7c192af5eda2d5eea08ead5adcaef3e4ecd8322e7ad2a56ea04d04791cdf0065b612423f296c8aa64afce92b920b17137060206cf7c58e7d90458371889b6a0be052210313233343536373839304142434445462ae90a3c736f6674747970653e3c6c63746d6f633e303c2f6c63746d6f633e3c6c6576656c3e313c2f6c6576656c3e3c6b32353e30376532376365356264396339646433363061373737336331373738326433303c2f6b32353e3c6b32383e38376365356263343c2f6b32383e3c6b32393e30633365373264333c2f6b32393e3c6b33323e3137352e32372e342e39353c2f6b33323e3c6b313e30203c2f6b313e3c6b323e342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661352c342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661353c2f6b323e3c6b333e31333c2f6b333e3c6b343e313233343536373839304142434445463c2f6b343e3c6b353e3c2f6b353e3c6b363e3c2f6b363e3c6b373e613366616266373966353333663933373c2f6b373e3c6b383e756e6b6e6f776e3c2f6b383e3c6b393e4d323031314b32433c2f6b393e3c6b31303e383c2f6b31303e3c6b31313e56656e7573206261736564206f6e205175616c636f6d6d20546563686e6f6c6f676965732c20496e6320534d383335303c2f6b31313e3c6b31323e3c2f6b31323e3c6b31333e3c2f6b31333e3c6b31343e30323a30303a30303a30303a30303a30303c2f6b31343e3c6b31353e3c2f6b31353e3c6b31363e6670206173696d64206576747374726d2061657320706d756c6c207368613120736861322063726333322061746f6d6963732066706870206173696d646870206370756964206173696d6472646d206c72637063206463706f70206173696d6464703c2f6b31363e3c6b31383e31386338363766303731376161363762326162373334373530356261303765643c2f6b31383e3c6b32313e484f4e4759552d383130322d35473c2f6b32313e3c6b32323e262332303031333b262332323236393b262333313232373b262332313136303b3c2f6b32323e3c6b32343e61323a30393a32653a64393a65623a38363c2f6b32343e3c6b32363e303c2f6b32363e3c6b33303e57692d46693c2f6b33303e3c6b33333e636f6d2e74656e63656e742e6d6d3c2f6b33333e3c6b33343e5869616f6d692f76656e75732f76656e75733a31332f544b51312e3232303832392e3030322f5631342e302e31312e302e544b42434e584d3a757365722f72656c656173652d6b6579733c2f6b33343e3c6b33353e76656e75733c2f6b33353e3c6b33363e756e6b6e6f776e3c2f6b33363e3c6b33373e5869616f6d693c2f6b33373e3c6b33383e76656e75733c2f6b33383e3c6b33393e71636f6d3c2f6b33393e3c6b34303e76656e75733c2f6b34303e3c6b34313e303c2f6b34313e3c6b34323e5869616f6d693c2f6b34323e3c6b34333e6e756c6c3c2f6b34333e3c6b34343e303c2f6b34343e3c6b34353e3c2f6b34353e3c6b34363e313c2f6b34363e3c6b34373e776966693c2f6b34373e3c6b34383e313233343536373839304142434445463c2f6b34383e3c6b34393e2f646174612f757365722f302f636f6d2e74656e63656e742e6d6d2f3c2f6b34393e3c6b35323e303c2f6b35323e3c6b35333e303c2f6b35333e3c6b35373e333038303c2f6b35373e3c6b35383e3c2f6b35383e3c6b35393e303c2f6b35393e3c6b36303e3c2f6b36303e3c6b36313e747275653c2f6b36313e3c6b36323e30303030303030303130323863306531653730666565303637653032653966373c2f6b36323e3c6b36333e413230353239343364613362343166353c2f6b36333e3c6b36343e62336434346137622d383864632d336430622d623165302d3331313732386462646465623c2f6b36343e3c6b36353e323131646663323364663664623366313c2f6b36353e3c2f736f6674747970653e30003a1e413230353239343364613362343166355f31373833393937373237333632422031386338363766303731376161363762326162373334373530356261303765644a0f5869616f6d692d4d323031314b32435289023c646576696365696e666f3e3c4d414e554641435455524552206e616d653d225869616f6d69223e3c4d4f44454c206e616d653d224d323031314b3243223e3c56455253494f4e5f52454c45415345206e616d653d223133223e3c56455253494f4e5f494e4352454d454e54414c206e616d653d225631342e302e31312e302e544b42434e584d223e3c444953504c4159206e616d653d22544b51312e3232303832392e30303220746573742d6b657973223e3c2f444953504c41593e3c2f56455253494f4e5f494e4352454d454e54414c3e3c2f56455253494f4e5f52454c454153453e3c2f4d4f44454c3e3c2f4d414e5546414354555245523e3c2f646576696365696e666f3e5a057a685f434e6204382e303068007ab43808ae3812ae381aa73608a13612a13640dc97b4f4f5330a0930303030303030320010021a80369be3a3c5437608eeb38fd275f0e5d8e030430aa646985eadd18ed95aa05f83a4d9d9d606f5f5683aa26e6c7198b6e95324c247f4f1f2c92252fc8c1799596adad01acabe530c4a46c7c724863ee78b178c3919d2ec9bd33d6de534b4646bc316f2b430d454fc7ee1768890851320b99ac675a7130243a2ab37aefaaa21c25c48f3aec57a87cd13a0be0d52619a9d04be74dfa76b831d73ebafdcc74187e4849f23f55963b6089765807a36149ebfd001865b9ff2d50f425ab4444a30e7bf84e7573470a556a9ff93cb83b1e99ecb69cad77b395f56816dd70a1b7e46035a17d69228e993331b7deb441604e717d723e5c86a273347db736137a6e500666a540062c21ffa79be3381992beb3730486c03210e8aec1253a838646c9176231ab237adc70ba0bdf1d9259ce44f44764d316f0367c9c574a4e7cbc612eeaacd4ac1e151b1aac41cb05a4ca1f360554f0e34197f4032823f4bd3bc88c743b872dbe4ab6de96833f3b9c8eacfb3fbdffa94a1b2bb1d4b3ac6f130bc2fde1c219e6a17fdf621f214ff0940c1bb2d496822b7a011d96ac3e70852c5f32957d18f3e42f8192d9adc831d323023de83bc8f3f4e7b48b429a6ce02cdc2fb6f43ce7a59a3217e181e8067f3ae9ae86397879048b2b94830c662505ee113cbcfeb725cfaf8f8137f3eca13ab570d39fd5f8d587d9ec84bfea281b749585a01c39c970946f5c2ce733295c76f66dd611b1867b656faaf0e039a62024f1f971a1395ff2bc97996e1dbfa9a7a54dd688452a08491407fae62a524da1ed917d0754bbad605d2638df28dadd0dffcd3a46d0cb3c536d304770b396157a773fdfaf8b5f538aef81bccd4c605a18049838882bc214ef4dadf318d9a837e8e40f32781588fadc33a6986e82f132977be2831ce0ddb55a7b68ecdbb1420d4795d0749cff298b929684228108c62a7733fd16c19e305e77e5556920617fee73f3eb4f9f3e6bd20c6e4f3b4e72708a72ceb1a27b97df11f37178a45fc45140e634893d72784f57f53cfcd3d5214b9f61e94ed648e2240c0e75aff13befea888138835c2a5079714395d8e0fc1141dfd19b82f885e9a118e3a6917753eb6fe75a9b34106fafc593b0093318cad309c208587d45890283319b2136395d1990b30d690229de833cd7bc8b7da7aa2792d3bc0ff13b19feca3ccaf10aa4b3636ca2d4810a02cee54598106aa5a6941b268c9a23a59b934e75b3e44d72a06ebe2710d395a7cb04f5e1a8aee230e9769e9c065f81e274b8b8832ea69cb7119de856e2ee2611017e6c995e2edee3aa57cc926184aeac23fdab2cb2440f47cd74fd883cfda7dffe9850b76d843985d445be7eb5398302f051aa67270c5c65631dcc1567fd2e04354109b01f01ca9fbe86ba38993bc5cca0c3e5ac3f5d0830e26cbb43ed7c915f88d06b12f4abbcdf7cc766002f34889af271a1b5ada55f579d53eb2a9926bc2e1bd7d3f30457867ddfed30c89725672d45b9276ab68df40dd2a4f0f4371a14efeb04a6f8fac608bbca4968277868c714c97eb19f61e0a36da44ab67cafc5b655fab587b08e9b8065d4becc724df94f9029e81fc9850e6a76523e8515f2b19c2f715ebdc73faf0159fd26ef8f826039f899dac85862dd3a7f89726f34708f1e44fbe7e59230c99f7c4f26b57f3431a819b2139346643fb3f0fbb9cbafceb26ee93ed7585caa827570126097e31c005c45001102d2360bd9846c67adb5c7b066ea096a7a2179e7a653de2f80ff08d6efdf194a6c600be1d166d56ea803d3fce73c0aa2736fbf02bb2fee7764257927e23df68bce396e81f62b2605fe0dc7ef56c6de74285c63a65d251f2bdae9d71c124b3d9d64115f9bc5582738b64c6ad7f0dbfc3caf0457fbe54f3506967808cf08ea22b1d69b4507fdbdf061265b65f9bf39fb652a893bcce02f7e3994eb04703e67299e1e1864b4f1008ff6355e1a143882333af77aba30da6bf1bed9a290c5645240adfee54f629ae53735e176c029250ab8a84031245777b9649438a58e5a0071a44b3679452360f071b3d6ba478c912fcd0d63af99a94d274c8acb7c37b7c5f1c6e2b1d3bdc94a96270222534d36ba8a9a0dcd4e8507953b51e7117f01dadfe7a00208215df29251b30a1d4527ba0b3aebb49779a170bf42fb5d6c56ef927d383ec4bb2165984ca162fd898a1e51767da4f5831f3f97bc2bdfba3359a9d5e2d79acca2eb78e2e9fed1af5a0cea1858b8af2c205b7c54b8be979b26db133f2a8752a3d8265d3bd2b7f9faeb07c0728bfea5fb6463e84c514eeb05ce96c5c7d9d3d0db7d80eeca052c29bc9d61bb9fee61723503b70c92193f680bc8ea3e30632d1fa10bed496d9b54213ef5b405f0958e43dc9af8cd356e85281add24131f0100e0af49dc970839de8445fb028916d376ea2be15cff465e17d3ce78ca594095cc30b5946cae7db1e5a50230f6de4cd63d4a6532794517e5fa53d17a6a732b49629bcfdfaa1e55e12398ad1706166576c522571b79537ecc447d069dcbcd44529a50c3e4afa4a401d851aa68de87b2959750737a09a2390b15e2efa24d506e88474d686039fc6c67daf13ed2d396e28ff726bfb0252fdc838984ee3b67daef5297e978dbe2e29e958a9cc9094587326e1a907c3e47b11c8ce58daeeaed999907df497c71374ab20291596f3a690293f35a9f1b6c0f9279aade4ea8e02a62500b654f9726500e88a5e3b109f72e32c87de9497ce1696bb2f55c0c2455ec87e95bf0ccfa40de22879ec242c98d3718b28264f8b956a7a51a661816ddac4c2b1d874b4b27fe31d51371df73f3fbbe27255f281c5b79b891e5e52617e3beab79c52028ec67ae1570cb5bef5a9e88d5df36f041c6bdbbccbf5c70cfae01d34fbc4e0b6ca0d41515807e8d7ef0db81a2a3c8171bc8cc2416445249087303494c4391e97cab3098488457ca1622c3415eb5d951c0589395d9d2883ffe74acc8c6eca6277e7a4f84d37834edd2b2b5f2a53430a3c98747fd6b4f8736a7cf3bad183e29d72b1c334877905346b3de5e4a8ccdc44c1d5b1bff1ebe42491bd5e7c3bb5a4030ab9fb003048049aeb03ca55e9fb00739b3aa499acaed2443b746e97b8bc1b1f242b04bc6ebf9ba712c28b197f49f59b71d7cdbfdc9d94a0d6c2357db3982bb3e243c9e66e72cc49a2204b9be0e12cb612a54633dc035544dc3ae6a97d9084a44ddeefaa919d19bea1660d567be4a4150dfc4106a72aa2f8f729f95d034cea7b8334c18aade49c0436e2bdc4099c46bfd5d8dee9fec21d8018365c4292f28aab4d0653d249f58ec4c1e258bae04d6998671865074da8468cf78d1b4b2fa7ba94b65c7eb8b7042a3b16e108ddff94dc681c3577618e4ae51ef5e5e38c2b911d877f287fdafb127446d7c336108c568b96d11322c15c52a7848e83e9354c4ab5156d3d06e415bd977ff4e5a523d83e642e7b7ed764c640a7dcfa3d043a55c27e34eb939b0d89d53de2f346ee6f98ec10192f8a2eeef960881e2f4e3fbe8de3c579d01ba4529768d20b5a249fde36204f6838071fb6bf1ee1b95fcc2f1410d844fc25ad7fa7091560b913b9b1d0e6c4c2488415b9ce93ea547599d9c44a9ac331843660f812048fc06bd1f70574428842b6f3ed2cdb29a74bc9b170ea15482caad1f6fb77e68d8d5febfe84e1b5e90f15e03cf3323988a31ad05767b01d8b2ce988643102d81eafdb4d8adb1ae36d96288d9926b40113e557f1881e2c08e845bf130b5cb89f22988abb96bce5bf27bb94ea508cfe58e2dddd2d8308cabc7d253b550c7039c2a85af67999df1d2245dbdafaddf8725513bd8a0ee34a34e82507c18faec1892e280da0eee990e05829b5a821b48757d2873062064e87e40a56c983f59d0ec549f93633a8d4102c178a0be09c088fe9be75eb91b0f1cddd7b87a9a408c0f64f358e1d6e4add90634a407c83d74e033848730a5d17682ff755047f721a26bf692c648c1c5013fb2cb6a83500fc362ed6f229bcbfaa1fc10c7abe84c66fc6d4653d22d1ecb5653a37c0be78ba35cc2fc8d50cb5275876776a6091b502b92e41257f14f95635f8fa7cdb5bec7b3d15a517a3e672ab6464ae16a019d570cf9bb4d3c9e13dbd45f4a02eebfc0c6465d1578a25682c5c2023681455ab1870977d985aa4687f748ac9ab190fc71ca84fa6a6a822210e9b93d7bf3e704f46a3e50325a1dcdb778c2141aa73f8ee50ce7677d75a79d0c9b04d6a9407a0a2569395e4e5dd44b46e3b77665386df01efad2b92246d3fdc7dd2ebf36891533bd158fa81ecf136577d619a339da0c9951a1168c62a6d8f200478c43f848cfb012bd1dbbb2084af871fb29fcdbdee8618e175753d839a3a861e21ec38a721ebb51b2784254ccbe51e12e4c30df137303ecb151951659c5bd753e9a62beb526b1056f27c42ea280372556419440723fbe87a719f291f40ecfc29cd898c9d266408c2cc6b79d4f9a959df0eba6af71ec4badbb3b897bb21a24652abadedaf7e36ccc80079e6d9c1f806bfea1957875e831c55a38a5875f9af16c2408944936a893935016c0f2ec1725ad3427502a6b0573ae8ddd84e7ba528352074b193dbb0846fb993a900f4da82599d28c375d66fd41bb2855ca64379322af3b9ef12499050b21b644aceef2e17a03ebc8c5bbc1e0d8282c4dfe53b34bdb74b320b5cc2249d9c9c78c47f5e4f81fa5a3341a0fae63efde73cb7db0834e4095406922ca269ec240d21eda656869040223467deca4a0a4f59e847eb40418ed9978e24dd1bbd4774780a94b3e416ae23310a26b4af90582b5a1393586a83a55b051b05c55699a1a84a04cdaa9b60af1f461fb3a44c107cb48e9348a43a358a614e5031a18464056d53c2d09a88a22e02f6c5f0ec6f4c266e85138e9e60ff2bef47194df0c4b088887166ebf849b76330f5981a23b3d415d9e46719e9f3c01d0d23b9f36f403782472419765209a0b6ce4097eaf84370c6bea28a76aa672f261f01ab27a5d0ce9c6f8313ff32264a5b3da5ad57847b7e21a4dd4a8c3f4dfd957ca2d84d74c15d43ba54cc5d79c24a61566b25f7126a39418dd90d3642d388562472cd4518c72bdf92b58229d41ae481a819fcdc4944822189f91aa2d32c972150ce28ab3851b338a7123f4d53655ba6405f64773e92a0a4cbdece5be172d08b729c625d53590fb4cf6aac9dee5a0c8d675667895a72fe9adf86fb92fd8ee5669b83838641abf9f00b33bc12671d964fd4070e05fd82a4191b3d076626d5fbbb201f8b171fbfdbbb56040cbb2b9b01444b71bd0f5a68db4ff3e0dc868ed6f95517a4399c5abab7fb24555aaa66ffc097c1772558430d9d4f7543d0c7122d4f0b350f6c2d357f34d0389f367232ae9641c41764aef92588cec1f8367a8a30082446099e3e1ffc22186b0bc79e9a467b94eb8b54c7d21b821910b87dfa6651d138d87e827ac75a6ae1f37b8dcaa3ca5910f01337793713fd5c885288f476576e29779e5c438a49ffd8135fd6d4322efdbe11ffaca8b28abf9e5a6c951153cc94b4ebf034deebc32650f3070ad86623537c6d5730b935c7f5f538506a146b578fa879b082bdfc7cb8f34a1f8f79e3f6ef698e78023a348b0d41b475b6709cd4d7d346fccbdb23c255a30f3e0f89256a26669e3ae27a18fcdf061416321f42ba6e5708a0628497eb1838b5ad7f45cec260e34d9c7c157a74d43bbee72fda9fc028238ae8f5c0c539095b1e48b2f526c90e5213325705dabbd60daf4ac24e44a45d61f7c98b0b69f73dc4172265c77fb8b5084b99475d6e61095cf2511c54800d0c738a27ac53ac0329f975639e906e69abf4bcc37be00ced7b1b6eda6801ecb62b198782afd054ca48ce95a7ad202eb6e5408a464da1482b704c715fe49ea880cb1d6135179ff5f04d1358a7f686de822d6981583894f6a9feda7a113370b248d2e97ec5f35d94f438c92e05af7da5346839e15f1d412d9eb6427ea9f8916b5e414aa32d345baa5a17ab3f38e47ce123d0f492bd3703012f4fd9198563ee0e61702f3f691ea9f5fcd2adb986fb4f3cf34bd51595d9c9d5ac414077bc889d6519360c041cc0afbbbf98ee928c663f789ceead35d522bf79ea73d71bb30768c903f6ce4d0d9cdb174b2699f46bf2f4340f1e5f59dcae8740f42dc5df302d18dd1bc355ca4cef1a241e653bc073f9ffb8495f14756b18ce21e386470bc928777e00fbdc6324789f07e0fcfd7a3c989841d0df918667e9cb4745214c5a798729ebeff8b974d23fe050d0ddec20aafaa565a9a4204369d0d0f6c4395bc915fd46add8db7f5aecda2cdc6c6c9a0cb46df61c649d2ff9070816f03c6d9aefa888781bf8aa1e45de93bba680f45cf273212a8b8934b5c7386cb7c06a6b20ed2c63843b1a117ced534b3af500867c6057b6fcdaf118de977fa71c1172b634e6c4a70f62ec15f5243c0d18e19e9afa3b95dab4a22835b55ff98d937c7df9707edb26a9a095a2a4798529cc70556a40e51e0d594e98b7a8a3e5b40d33c3d2f10d7a1400e5843c0c6afda11188758af60e466764968bad77d6f817d26f13c4a19b59f37c31e77ae2de4311b948201559ac30aec2289463135aa35946a95465bcc0ea6fd60a30fa98fd0e5b02378a89c6aff4f40437f8065ab5e7852cbc1dc0a560d809849df1a9a4fbbcfdbc75991569db8fba764e8f8257c512b1381613251c35c7fe4797f8fa5f0b47c1d7905fd151b73e7c80a088e43a3aa97ae72d0da5f08f643a3813295e10c560c69c6350c00eba8b4f688c29b3de59f704fc1cd31a5a54c9a1df8fc8e04a9fa5fb477a869af214cc7592b073d47c7a764dbab6bf00adc5128c226e874ea3178c8391ad73951dfbb68ebbdb68604807d13b56007f0f0a9f15b0c305d599a93167f5d2a3790bd7a6ae127fb1a0da1c4a1bd02e046403fe6cfd7aa8d74735cc59b2eaaa522bf62205bf9cc7aa333db88570c7e6e6fccce3a7b6f459598899da84c9c6f58a7afa5f9205870040413a598423e7ecd32a42872b4782fae81c9c78102fb5678cfbcc611138cdf9e6275db4d98f8364db9297f54919b44f197c29b8a035198665266c4405b287ab8b9351a44ecaa8038e235ffa63a511c49586c4dc556ec7d35a78f110a1e152eacc44c479dff3a627dd808cd222dc6812df04f6e54fd43a87c08aceaef7ef1a2de5bd9cf44ef4229c40ac88d8410b80c466659ba54c2770c739bd55225b31ff9eedc50d7a68d29a8d132d4c6b11143da332c8f19defebee98e73e67209ce4317554c139a0b9e6fadb138331e21497ac997f935e8224ade69f0d2e0bab7b5aeaf59a42cbaffd03bfae2e1bc4cfd10cb20b35eb3e06eef17dc1b17bace6c1659db6eb3e1e772b0559ce132c98d90aa44a3c751b706814d18b775e0daba0f6cd7d93cd650d99c495281baae231c492075678d30000a0a095c76a2d09e44805d3dbbfbcd5d4e9019ed7ab960a3199ef9b382d6ff618186561d18b50ce5452b90edd5cfbc8af7c38a5f8bcba12d78c888754d5a92d755289b1967d203ae4e584e6ee0bb6745c3c17c3e7074c081a9421060b3fc2015eb3b069290daa3f7565abc9753d417a80ab205f97a3931f039fec287a61794bc561d3e7e6bdd3ce361785847e74099b97c44508aad7cc50e6f0b24b9ddef6c63a5806ab91e1f6101918d43aa2c2bcbc90fa5363f5d2ae5fb23c6b01c3321650bfb66d3854809950b7e17f55bd1ca37cf9ed854d07d3ec08943605cb1b2ef3f559bd3892ccc4e4f9e1868f6eb0a896fd6b7886390fe790dd70216355e73aa746fcac817196d8780cbce01beaaff3804402788374a55084307f68098419afd227b05c8ae0264a1ba56f0e6d3a81c3f5f05f13353e735c72a2c73e328eaf02ff90f2e71758f3ec98d665d9b64c305b49c8406019dc1421335db4ed032b2fb5e31449be1342eab3e197aeba98547d85a6b3efb0ac7b0bd6d57814bfca23b2b9abf7df7c33c0c24d44d723b83e2685dc6abffc5dcf34453d616675f2858d69e5df4ecdf102a3765c91e75612bff489cd57e6c94170f67bed2b7a0d849d46883bf5b14e03ee1f6d42c0a6b9dad93768478f4bd5c6082f2647866b7719f39ebb549c4d078e27fa38bb579f7c759e7a991800717e1f1b5774d47c97fa6e53276d8396efec3aba6af18432526a8e89bff7587cba803efbda41ecca20aff912be4f07b098507ebbcee0ee08ae8f4bc8631b7e74383bcb4b634ccfa8a78feea4fcce99a693e37b2f2f5704620cf96eb485867be1e5447ac473422ec89a3e3d6582b04e33eda89bf0748a282a01d3feabc2f8e40b66d82e91079c6947cd4713aee2be4cb94728c633d8462f38adf769212ed1275e54feaed0737f85da44a4fe152826254bf4baee4974db095291480a78bee744fdb5b24ead57321734ff6c95ea6ba1d8241f650581bb3941683824d33d062bff0f3c1a98da5b066cf64a66d77ef9a0f3a4cb60a9c317903e9f6bb2b4166ad73d01a537ddfafd75db7bbb3f1654f92570f80801a9714815a239d902006248645655a0a6d0274828627cd6df7bbdfd21ba1bb69ea57cd3381971067ce82c355fa60b387842254eacad5d5a5b041a5c506d6dfaf428f8e915c024b33e01bc9a07e9dcb758bde31fdf632697292854f4fc74f6d0f213dccefe877621a3e93dbdb58d2cfdefe703f16f142ae012e7fe9193a258a6a2fab9f0a613b91476b55eb1d449db9bf1406484336c6c20bed4503c67192d463a861f1d9d9fdfa1ce3f93fc2a4be3e0ee0c6cad7ce68b5f1c3e744b6dd3039453f527382d4c59b626cbe6d0d2ff792ef8e29c9292340196cea1dd66d0d6147dd9ff975af3a549f1a3f8b67f378f3e2d807754099950cf12882bc122c0bca858b1355aeca557f03e8ebdabb993e0fc1ea51ab7efd7093f1784afc3f9f48213fe1033a70c8fbf0bf738d822dc9e980a1b61281bc5364dbd8e5a109b2e21c326af7d5b902a2e78cbe42fd98393989edae11337c6b6a95159801a2f262e5e21882d145a34e9640a3bf5ad3bed1de23c8232f866869764f57025a58a5bd70c6a6b3be2c3ac5e9e8c41fbe40db9e94515ba35b1fd60f09785081b6141771c5e69ac10b8763a5f5e468ffcdfc22cb817802fe30d347cf9922892ca01559fd997c529d3dbc40179dc52337d5d6c2cd9df4e25c2191f9e689687256e54871f547a8a0cf76f95ac4a9625920032afa3d3426458595ab087214e3449b302cd64e31ac26bb8344e196e097bff16b13df980d38974c578944c4b83b07d4a867fcf56d24b262437d7d47a3e846d17f9daa2935350bb34c3f29dc773d69a6d51bca7e443db31c493d1a3199d8f58ef1b7370c18a56d0fa9bdd73e3aa1d5a1de085f7e71ed59bb4bf8224729cd58fc6252e7d7f9d38ae4e731f664c4237b3a6b00cffc77f62ada4f2fb31ad9409796a8fa0de6428a92a1c1a991c9f1604b5d5595e4947f7488d1deefb1586c3fd01acc85eaf36c9889478ed170dc2727a2b1d7bd7dafa4738e36732280d6489d8e67cfd608f37a71c6f510f90ca48f880a37dc1eab9fef980442e756c60403af060a8970524337692ffee043446502efe4c82e79dda417c39bbda0d3e15f92cd2c8e3e1b485bb763a6d6bf83de568d1c92b1853ad720f75635731e3feaa384978da6fb98349ed8fd337a66c8a80ed2a63b598b511a059c524fd2b39e636cb3d87e84f07d3499ad635042bb8f16b531b4f70649f0732ec26a5565353177884f4995132de0520a1cad6d206280530003a810208fb0112fb0140de97b4f4f5330a0010021ae3010ae001303030643232336433653034303030303031303030303030303030303165343262353531643266666266353066663563386131623465366132303030303030306663386536343263623562343931643861303561353030346434396366386239353263316238313964623164643066663030396230323033386136643261633839646264313437643334306161343832313437386639306566303834396234373365376266626132363132633663656266626337303830386432393566643630653333333839393565386463663563656137396337636337343362653136336120a1cad6d206280230008a010e636f6d2e74656e63656e742e6d6d92014a089f031245084112410451beed7a181a19fab56f38fd1205ea24cb89bec393dad00f34b49fe628d61851b140d4bddb7392327441c41bc21051cc539ae878ebfefc1a2aab40332fa097d9'''

#                 data_back = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

                print(data_back)
                print(type(data_back))

                old_deserialized, old_message_type = blackboxprotobuf.decode_message(data_back)

                old_readable = bytes_to_hex(old_deserialized)
                pprint.pprint(old_readable, width=120, sort_dicts=False)


                hex_data ='''
0a24082012207f11510b470ea072f227f03569345c5e95c4b756c0d8465560159a61cef7ce0212f50108ef0112ef0108a84e12e301ed67120e796266f86c36f28dee79a5c0938ea4749e38b836a759dd0a9c16173e5547ae1825ace6083e4bcd464d5fc5acd95db0c1c43ef087aea33caeebc1ea54c751aba5d6d3a1e6aea0b94d4c068dc4fa7b5ba164af607a9f62ed3407136465502d42eea804e92fbe98be675ee8cf5f825b02155ea271281494e3ee191cc6cb18e997d7f19356cdb53f942e42e0b9ef61f8711c0179c947c34fad27fdd094201e71b6bd5db6feefd3b5c8e6d26be69b4adfad8046ff162099677c3859a30f95cbef9f80fec10ab95436de45d295b126e12abbf27b59e154348ec6eb10c9f5c9391ac418f3c0a0e008


               '''

                new_data_back = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))
                new_deserialized, new_message_type = blackboxprotobuf.decode_message(new_data_back)

                new_readable = bytes_to_hex(new_deserialized)
                pprint.pprint(new_readable, width=120, sort_dicts=False)
                cilent_713_pub = """
   04 88 51 d8 31 b2 19 60 25 20 0a d4 71 ea 58 77 39 61 3e 57 47 d2 2c 4e 0b e7 58 08 ca d9 2c c5 a0 c3 5c 51 d8 1b 66 65 d9 01 47 a4 f1 0c 34 42 2f 19 c5 4b 53 a6 6e 9b 8f   """

                cilent_713_pub = bytes.fromhex(cilent_713_pub.replace(" ", ""))
                old_deserialized['1']['3']['2']['2'] = cilent_713_pub

                # ===== 替换：把 hex_data 解出的子消息注入到 old_deserialized 的对应位置 =====
                # new_deserialized 对应 old_deserialized['2']['3']['2']
                old_deserialized['2']['3']['2'] = new_deserialized
                # new_deserialized['1'] 与 old_deserialized['1']['2'] 是同一份数据，同步替换
                old_deserialized['1']['2'] = new_deserialized['1']
                data = [
64,-81,-88,-55,-107,-8,51,10,9,48,48,48,48,48,48,48,50,0,16,2,26,-96,61,-72,-61,51,28,80,40,108,87,-96,-109,7,-128,10,102,103,26,-98,-96,49,-88,-17,-114,-40,-52,81,-58,94,102,-61,41,41,83,-95,-97,26,17,-97,94,-68,-20,-25,-91,-91,84,103,113,-111,13,-28,45,45,38,60,43,-65,92,-68,-128,81,89,50,-56,81,84,19,-30,-80,-57,61,-90,49,118,-70,52,-41,80,69,120,-75,73,71,48,80,-107,13,27,72,-78,112,-52,-17,-111,-48,-20,-72,59,18,-80,-19,-39,120,92,40,-81,75,84,-127,-120,-73,-47,60,-123,-113,-14,-15,26,28,-87,45,-117,111,-91,-122,-102,-11,-108,17,5,66,-94,-83,106,79,-128,24,84,-22,66,-64,50,0,-13,-58,-37,33,-81,25,27,7,-27,43,-71,-93,-128,-51,27,-82,32,58,9,-64,-39,108,61,90,-37,97,100,-78,68,-84,112,-19,88,10,-86,-22,23,-2,15,56,-103,-60,-49,-57,52,127,68,-58,-97,48,63,-72,126,-109,76,-36,44,-60,-42,-41,73,-76,7,63,126,106,54,-82,101,-22,-25,104,-13,-17,47,-125,57,-77,42,-107,14,20,-120,16,-27,-58,55,-121,-120,92,54,79,-44,19,-13,-65,84,-104,-61,-97,57,-33,-101,-2,-127,45,33,49,82,-36,-110,-123,-36,-56,-69,103,35,-53,-40,-127,-36,-41,48,-32,-53,2,-84,120,20,66,-30,125,52,-35,47,-8,86,-20,-121,82,41,-21,-105,-78,121,68,48,102,118,74,102,56,79,-45,-91,33,63,-62,79,49,-60,-94,-105,-50,-37,114,-58,96,-47,-9,127,-97,-58,-107,127,-116,-125,105,-107,-68,16,114,-50,96,117,117,-54,-16,-85,-23,30,-88,-116,72,9,-73,40,95,-66,-113,-111,96,-116,18,-93,-81,92,-67,-13,15,-66,-119,59,-122,-64,-2,-118,93,80,14,-115,-48,-9,-29,75,-53,-87,-112,67,-2,-124,-29,26,104,67,-20,-10,-63,-23,-86,15,-63,47,88,-75,4,21,-83,-28,-96,103,105,70,-12,-101,58,-25,118,93,114,84,-14,95,40,-6,-96,-123,-25,-71,78,-28,-99,-14,-13,60,-68,3,50,-88,22,-16,112,81,75,4,-110,-4,-91,-27,24,-36,-11,8,55,7,101,117,77,52,21,-127,-81,-7,-113,-117,-91,49,-13,-127,-93,-22,64,-58,114,-6,2,-12,-104,-111,82,-107,-74,-85,41,68,-22,-106,-119,33,-125,76,61,-99,74,-101,-116,8,87,-102,-18,37,-13,-114,-15,7,3,-63,-103,-96,-68,-119,111,108,28,-90,15,108,-44,106,-35,-123,-118,79,65,39,116,69,52,66,14,-91,-13,21,-66,-17,-47,62,43,-75,95,-113,24,-35,21,7,103,-10,6,93,-59,-47,-19,-66,-30,35,-4,64,88,122,18,-29,95,-124,88,-58,-127,-96,47,-92,46,31,107,-27,-8,-38,112,68,81,-37,-38,-27,25,47,57,-20,60,-97,104,109,-20,-32,36,-117,96,-35,115,-98,-85,-20,-115,-84,-100,50,-21,101,105,47,22,-37,76,82,-13,-102,-106,-84,111,124,-27,-6,77,-128,-113,27,113,63,-10,15,19,75,97,65,-73,102,28,-10,46,53,76,68,4,30,118,92,-81,-121,88,22,35,-95,-83,-33,-27,41,-17,88,-114,-8,-55,20,13,97,-58,112,104,84,69,63,-36,19,-101,2,-13,72,-123,49,-24,-56,65,-54,8,10,-30,43,-111,-113,-82,-101,-95,-111,-100,12,-116,-121,-105,-47,-98,31,116,34,60,-67,104,-123,-68,34,-126,-111,-58,40,83,-30,-77,117,38,79,116,-71,-111,37,-16,-14,53,103,49,86,79,116,-119,71,120,16,75,-103,113,-113,-68,-84,-41,-4,-22,76,-24,35,-100,19,86,106,73,-63,77,-89,29,54,109,120,119,14,-101,-109,-51,97,51,117,13,82,89,70,-26,-69,34,46,-48,-122,-19,96,77,-100,125,-96,124,-113,-3,-93,-110,27,34,91,-47,-102,-64,-3,22,-122,-14,77,63,-31,-124,-6,-81,-102,116,-125,125,38,-20,-111,116,-36,-26,-79,111,38,126,61,59,39,49,-14,81,-24,-88,42,-32,-1,-2,24,77,77,57,-7,75,-53,11,79,-8,-80,108,-10,101,-68,71,106,110,79,112,-107,-99,54,94,121,106,97,121,86,48,-34,-107,42,-93,-82,123,6,-123,-34,-73,-69,-73,126,23,121,30,66,-114,99,-110,-111,-22,0,81,116,3,13,-86,90,-110,99,32,34,105,92,30,120,29,-102,63,97,11,8,52,-108,71,-31,16,-110,117,114,125,106,76,68,75,-126,-70,-38,16,92,-116,16,-88,44,56,-14,-108,52,-61,103,-120,-46,-86,72,-64,60,32,1,-8,-85,98,65,-103,5,90,-103,-128,97,-57,30,-25,31,123,42,51,-51,-105,-69,-113,-117,-109,-32,111,-117,103,-19,51,47,56,57,103,29,39,-110,-44,-118,67,-26,6,106,-56,-92,33,42,-9,-5,13,104,106,-66,106,-31,49,8,-57,-47,-47,-17,63,109,-122,119,-51,-19,113,-5,101,-103,60,94,59,-122,83,125,-58,85,3,-91,-62,6,-85,29,111,-103,-128,70,88,-118,28,-17,19,85,-110,53,44,36,115,-19,-1,-11,-74,122,-7,-4,-31,-118,107,89,12,118,-36,78,93,-36,-122,38,24,-43,123,-58,-105,-88,-40,-90,-3,-107,9,77,-98,116,57,-86,4,-18,-35,78,-111,-124,-51,-77,-115,-65,-120,-29,10,41,-35,69,-115,-15,-71,45,-39,-26,-122,-102,84,100,-117,-78,23,-90,110,-128,6,63,-51,-23,-114,-107,-17,66,76,-15,24,115,113,110,-9,81,-59,-69,-13,68,65,126,4,39,95,19,-3,-95,102,27,30,78,16,113,28,-27,87,-58,79,-100,-22,80,25,-78,72,-93,73,107,33,-62,-61,75,-28,-113,76,-115,112,35,46,9,96,-86,91,-66,97,76,8,69,-80,98,83,79,100,127,62,59,124,-65,68,-98,2,-116,32,3,-83,-38,-99,-116,118,-98,-57,-121,-19,-26,100,-34,57,14,-3,3,-100,14,109,28,-103,-11,54,-56,-68,90,33,1,56,-56,-31,-116,105,44,-31,-109,-24,56,-33,13,-60,-79,112,-124,19,-104,-4,53,73,87,10,18,-120,-33,-44,106,-6,91,28,72,-54,-117,80,-109,-12,94,96,-19,126,102,-68,-30,-11,18,11,46,119,-10,-99,24,50,-26,51,111,40,-126,-48,-48,97,68,-101,-78,110,-126,70,-80,-54,-64,39,49,-33,108,49,105,107,-125,-21,34,-88,101,-83,-72,-113,6,-103,-112,33,-51,-7,77,30,71,-70,-40,72,-16,21,49,100,68,-16,125,-103,-70,-25,-80,-34,-49,122,27,107,32,-8,110,-73,-56,-88,-121,-96,-70,22,-55,-21,101,-33,86,-36,92,-74,-99,-75,-126,-52,48,-26,-125,7,-72,42,-61,28,-77,-1,-58,41,-2,53,12,58,73,-76,33,21,110,-8,120,-65,40,113,7,-92,62,48,28,93,92,13,98,-30,-96,15,-115,-50,-59,-70,51,29,-96,-69,116,15,-50,-92,69,24,-97,-102,-119,55,80,-27,-102,8,21,25,94,-58,-24,-18,-86,77,-1,-59,127,19,-62,100,-49,-52,-90,46,40,3,-61,39,-53,-19,54,39,-73,-11,-84,88,28,-114,-2,40,-22,-2,50,33,23,-44,-121,69,-19,-3,-93,3,-30,-101,-85,-100,17,73,-106,103,-122,-105,115,-99,119,41,-119,-1,-93,35,-4,-24,14,-101,-56,-88,38,-122,119,24,125,107,-69,-37,122,98,-34,82,112,-14,-99,-15,22,60,-87,76,95,92,-18,45,-95,-115,120,-127,-88,107,-1,46,64,70,58,-21,107,122,127,56,-128,12,-4,70,-63,-102,57,-78,-97,-14,121,-96,-24,24,0,-116,-76,25,-128,124,-37,-73,-103,-112,108,-90,-119,-17,-123,57,44,-54,-31,-118,23,-18,76,-6,50,19,-96,120,-113,49,73,-10,111,-117,77,-33,-62,-107,79,78,2,92,124,16,-54,-6,-19,112,28,-94,-92,41,-20,-107,-85,15,78,85,-73,0,-114,63,126,103,-114,60,-116,-43,-122,29,-76,-100,-31,19,123,51,-95,-17,-42,120,47,27,-97,18,-87,-103,-102,19,-80,-102,-75,-69,13,61,52,54,2,-53,16,-58,69,26,106,14,-71,121,-93,61,43,-50,-28,63,-113,42,95,50,-60,-39,99,38,-74,-12,84,112,112,-59,45,-24,-45,74,-115,-53,82,110,102,-1,34,16,-59,-119,-31,61,126,-54,105,14,1,63,40,-71,78,18,-114,-55,11,-88,111,-31,-65,-23,55,-12,-5,10,21,4,-51,-45,-112,5,59,-71,-67,-61,85,-52,-20,68,-25,-88,-83,-116,36,69,93,-57,-45,-17,57,-27,81,68,32,69,-128,-97,56,39,66,-107,-46,-49,-92,-66,-15,115,47,80,111,84,53,-58,-25,-19,120,17,102,-96,30,2,-104,-89,100,-119,38,-113,53,-15,65,-14,-100,30,55,33,122,13,-32,42,-69,14,32,79,23,-105,122,-28,-102,96,110,-20,112,-23,-90,125,-21,-113,94,41,45,-37,-107,-124,-44,-127,125,-51,-122,-123,98,127,109,25,-128,-39,-8,111,-102,-14,86,-28,-92,102,59,59,-51,-38,76,-126,25,117,-29,26,-108,105,73,-4,125,90,-62,68,-37,112,109,-21,108,-18,-20,116,-1,-82,88,-2,88,21,21,-111,20,-97,-55,-7,83,98,15,-108,-36,31,-8,15,116,55,34,87,4,-35,-54,43,44,38,-109,2,105,7,42,66,-58,56,107,-11,-85,-14,1,101,30,31,-66,-64,-127,110,-111,-43,-52,-11,66,-11,17,-58,18,-24,4,-108,-93,11,-83,121,-28,7,-22,-105,-96,-76,123,122,-12,72,6,-28,16,46,17,112,-36,-44,89,-128,106,-39,-45,-76,-74,-112,-107,-35,-105,74,-99,-83,50,95,25,92,-45,-26,85,-117,120,-21,34,-28,-62,-84,-31,53,18,-58,-39,22,-85,-87,71,-9,-63,-20,61,-121,126,38,52,125,82,-23,121,54,69,51,-38,-21,-38,106,74,-86,-44,-82,39,80,-22,-96,27,120,90,111,-30,122,-125,-34,-80,115,58,23,-27,-42,-77,20,-123,83,-82,123,-115,43,3,-76,-111,-125,-91,110,51,-8,84,10,-66,4,-11,-118,1,96,-42,72,-24,-84,18,23,12,-79,57,66,-48,-33,-114,-114,-80,-57,-24,81,19,-57,69,106,76,-77,56,-114,-51,54,-49,-39,72,72,64,120,-4,73,-25,-90,-62,-6,-100,92,111,43,-6,-5,89,74,60,-35,-42,-93,-123,-116,56,-64,-44,22,-116,50,112,-4,-47,99,27,23,-29,75,54,67,30,48,105,27,16,123,-41,-92,47,2,-74,-28,-91,-105,97,-124,126,-12,-107,-15,15,70,8,-24,-121,116,115,46,62,-48,-96,0,-3,101,12,-70,-84,-93,91,58,-4,-53,-102,51,12,-32,-76,-99,78,59,26,18,97,101,18,-41,-73,-110,-32,52,37,-111,-40,-3,-7,127,39,80,-104,82,115,-111,90,71,-118,30,67,-52,-118,-19,47,48,99,45,-9,4,38,-79,-96,-14,-97,-41,48,20,-107,-14,80,28,-124,-76,-88,-7,10,-106,1,118,-104,-61,-35,-20,47,81,-6,-119,-107,-80,4,51,-31,5,62,38,5,76,50,-62,54,82,-44,-74,24,-36,-5,25,-70,-112,14,114,115,104,-34,-34,21,24,-126,-125,118,-79,8,-35,111,-74,-104,-93,40,-1,12,43,-109,-112,-41,120,94,117,-42,-81,-49,-118,127,2,-63,14,-109,83,1,10,-106,51,-74,-101,1,79,-20,-55,-112,-87,61,56,123,13,113,-82,-102,50,17,22,-113,39,80,62,78,-9,-20,-32,53,-17,-63,60,-76,-57,-54,-8,-102,-118,-83,22,36,39,-17,-105,-128,19,-120,-32,-99,83,27,-124,49,70,-93,-13,-82,120,-47,67,55,110,-98,-61,81,-29,124,100,18,-71,124,-92,-36,-59,-10,-30,36,75,22,21,-32,104,126,-96,-81,-106,83,118,-75,-14,-110,-115,-120,51,-102,101,-62,-73,-9,-80,-5,23,-93,-97,-38,-23,-120,-28,43,-26,90,-25,58,-8,100,57,1,-106,-85,115,10,114,87,-94,-57,73,-116,-72,71,-86,-117,28,-115,98,70,-128,90,-97,-110,-77,91,51,114,-68,80,101,-8,120,-53,-105,-87,-105,82,-105,76,-84,-111,-104,-109,57,-55,-113,-87,-5,5,17,116,-29,-98,10,52,108,16,-55,36,9,-47,-84,88,76,-126,20,-73,-46,-89,-17,15,-29,-22,25,-77,-122,-22,-43,-46,-37,57,81,49,-72,92,-5,47,-40,-109,53,-36,90,-56,-47,81,-75,37,58,109,19,88,-22,-38,44,-7,122,-82,-5,45,-106,-22,84,-12,28,-42,-73,-20,-124,107,-16,48,-92,19,-49,5,92,44,117,104,118,36,-125,82,-35,37,-37,2,126,49,-17,-117,5,113,70,-91,-60,-61,-35,-84,116,-81,-117,-37,1,108,-94,26,11,-41,-35,86,-78,60,-127,-118,-106,69,-58,-42,-26,58,21,-73,-42,33,-35,-61,-103,89,88,119,14,-104,52,-115,51,-75,-41,64,90,93,30,-122,11,40,-50,3,90,-13,86,37,-22,-111,75,67,-127,113,35,117,35,-69,77,73,36,54,-28,5,68,65,-2,-88,-7,5,-82,-34,-56,-102,63,64,127,-45,98,-92,-86,1,47,-90,121,100,-82,30,-125,80,57,-25,74,110,-45,-11,70,12,127,68,-63,49,-113,-64,117,-52,-93,-90,-117,-11,-75,-81,39,29,-12,64,-93,-39,38,-99,32,-47,-49,-70,-81,-47,78,-88,35,-19,-23,-8,67,-59,5,48,-61,69,-56,126,49,-68,-62,-7,-118,101,-73,-53,109,9,87,22,36,63,34,35,-121,124,94,123,-40,-52,-28,-84,11,-53,32,31,-21,-21,-11,105,-127,127,90,-79,1,-89,-66,17,-108,-49,28,19,-116,57,-18,-27,-88,90,-77,0,-2,-110,7,-100,-128,60,-109,38,116,-5,3,108,58,-48,-115,-89,-83,7,-11,104,-62,-21,-33,93,-21,-58,-73,-55,-62,-41,78,22,103,-10,63,-112,115,-10,-97,-103,34,84,-16,-94,-11,63,-56,-92,-31,-30,-17,-59,-20,-55,-37,61,38,-115,127,71,75,40,-10,48,49,76,-101,51,45,85,85,-76,78,-34,-52,-122,-1,86,-124,-75,-97,58,30,-8,92,-46,109,-84,-1,68,-105,123,32,-98,-108,-102,-7,3,29,27,-111,-74,78,-105,-125,107,115,-86,52,-44,-126,-64,67,8,-104,15,85,-104,-10,-78,-128,127,83,54,-64,-50,-24,51,92,-60,22,19,34,25,-101,-62,68,-5,106,19,120,-26,-77,118,97,64,96,61,98,-30,100,-5,-113,-118,-108,108,-82,43,-55,-1,-92,-37,-55,-54,17,-33,-29,-111,-55,48,-69,110,-88,34,-117,-17,16,88,105,46,13,-117,-67,93,-50,-126,-114,-30,-28,113,29,57,122,-61,32,14,-99,-116,-4,-55,1,118,-93,-25,96,113,-2,90,118,-17,-60,-33,55,-109,-111,112,-67,-81,33,-40,85,85,50,58,12,59,115,-11,36,9,-115,103,50,-22,-72,124,-116,-69,-41,-21,-47,114,-125,126,-127,110,69,-128,-16,-126,19,-49,110,-39,68,60,72,74,105,93,32,2,-53,-96,-8,10,-77,60,9,-98,-28,54,-113,29,-30,30,109,-111,13,-111,113,-83,115,-84,118,32,-61,-12,-98,-82,6,-18,33,-77,3,-94,-43,-125,-13,-46,12,-96,65,2,38,-80,-31,71,100,109,-123,31,-11,19,-90,-117,-11,-72,7,52,-120,118,-30,22,-79,19,118,-108,-78,-2,88,-39,59,-41,-4,66,-90,2,-32,-64,-52,121,2,27,-103,-99,84,80,-52,-3,-83,-98,105,-78,-42,-1,-101,79,-127,-45,115,1,-49,122,-37,47,28,66,120,60,100,-123,-98,-99,-53,-60,-38,-32,111,-80,31,17,-7,-104,-48,85,-18,94,-84,100,27,120,-117,88,104,-98,118,-70,71,-5,54,88,-120,123,27,-25,-117,-45,-69,-3,126,10,92,29,3,5,-7,125,-78,-65,-17,56,52,91,-90,-94,74,-70,-40,-15,15,-41,83,1,8,-83,-93,-23,19,109,-109,100,26,-8,78,-63,-32,65,42,-44,84,110,119,122,-39,-19,-59,89,69,25,35,-32,98,71,-114,-43,-12,102,9,-105,-67,-41,101,-15,-72,-18,-113,-3,68,-124,-44,73,-27,-86,35,-56,108,102,-79,-113,-121,-95,39,52,114,-44,119,65,79,46,80,65,127,0,-120,-78,57,-42,-44,113,118,-57,46,-99,-99,2,73,47,-73,-76,-81,-35,-26,-80,-16,-29,-17,24,35,107,-25,82,-126,-73,-76,52,-54,-121,-13,28,-29,-62,27,87,27,-72,91,66,-19,52,123,123,116,73,40,112,-82,11,79,72,-37,127,110,-50,-31,42,-38,-110,48,121,-5,122,100,98,2,103,9,49,123,-76,111,96,99,63,69,-115,81,-53,57,-37,108,108,-54,-109,-69,54,2,-73,-123,-128,-89,29,36,-84,-19,-47,76,-78,-56,-105,40,-121,78,121,25,45,-68,109,-68,-21,-28,-31,-53,-15,-91,-93,-76,119,67,6,-103,-98,15,-76,-28,-60,4,-8,-49,-52,-30,69,115,-113,29,52,-75,29,-83,17,64,16,102,-78,116,69,13,-116,59,-5,-16,-128,122,77,24,111,-30,-74,31,-60,95,-105,105,55,-2,-101,100,22,-120,124,-28,-120,9,-65,-24,112,-127,-96,-31,-5,-61,-75,-72,-52,123,-23,85,50,127,99,-39,-40,8,108,-78,-55,18,-88,-93,-3,83,50,59,-20,72,-82,106,2,-96,43,109,-16,15,94,-101,-111,-23,-118,23,13,-122,-61,-60,-86,-61,-63,-38,-60,-1,17,108,60,52,-38,45,18,61,-67,115,-67,-105,0,-38,124,117,0,-71,-128,39,77,59,-73,-25,19,88,-94,-89,-48,112,86,-43,-120,-120,45,96,-47,74,-46,25,-18,-99,114,70,-126,26,-8,64,-29,2,107,-110,-67,-72,26,41,-50,117,-72,-103,-19,-5,-103,-78,-83,67,-28,68,83,-125,16,17,2,-112,-82,38,71,45,5,-63,101,-73,124,15,42,64,-67,-84,-94,-75,-118,-68,-98,-80,-60,34,101,119,-80,-45,-63,-94,-78,70,-22,-84,-27,35,107,44,7,67,-30,117,30,-17,86,91,-15,79,-28,-128,69,58,88,-44,98,-36,-87,73,115,87,15,-39,-105,26,-106,-122,49,-55,-13,114,-30,116,-31,-104,3,-101,32,-1,76,-27,93,71,-118,-118,87,94,-103,23,105,-112,-56,44,-89,-84,127,81,115,-60,-4,-45,87,83,19,80,-45,4,85,-69,-111,-79,75,64,30,-11,-37,80,74,19,-33,-93,-43,-76,92,-108,77,-117,-113,107,-53,88,37,40,-4,45,-9,-94,32,-23,102,44,4,48,-55,-73,-8,-96,-4,-51,-14,-94,-78,56,-53,15,99,32,54,-62,24,56,-37,88,-57,83,4,-49,-51,-32,61,-105,86,33,92,35,103,86,-52,0,-91,-37,82,24,-117,5,119,71,-111,-95,54,-91,-11,76,85,106,59,86,60,-118,69,-66,-17,-76,-41,-40,68,97,28,-16,63,70,-97,97,65,101,62,88,96,45,115,31,123,10,-65,-108,108,-9,85,-91,109,-62,3,-94,-3,-79,101,87,91,-80,95,59,72,71,104,-106,-10,127,9,-54,-113,-56,108,-126,-77,-57,62,-31,78,-56,121,-120,-69,-10,-10,-83,33,125,-10,63,103,22,113,-107,-24,-125,46,-86,-40,123,-5,15,-76,-112,-53,59,125,1,-54,-112,120,97,7,103,1,-58,120,-54,-1,91,13,-104,-88,-119,-88,44,15,-60,-18,111,-105,52,122,45,33,-71,113,-102,-128,-14,-34,-64,82,106,-112,93,-100,93,61,38,-127,-80,-107,108,-62,61,59,-12,6,126,-123,68,55,105,-89,-57,-33,-70,-93,-64,21,-114,25,-52,-103,109,-110,-15,33,29,106,45,-84,52,123,20,-62,-48,-28,-17,32,11,-87,107,115,-88,-127,-71,-25,-115,-79,127,-106,10,127,-116,-45,67,33,40,-57,-94,10,86,-112,48,-126,-122,92,87,-62,27,120,-85,59,68,-23,20,-8,113,-66,31,-2,8,-128,-101,80,-67,-72,-39,52,-11,-106,93,11,110,37,30,-41,36,-49,-127,8,53,-127,-114,-84,-58,100,119,113,122,-1,-68,32,-32,-41,94,40,29,-75,-127,-93,-126,-108,119,21,-111,26,-53,42,113,-24,104,-53,-51,55,-86,-67,126,-35,114,-50,-125,116,29,73,2,100,-16,38,83,30,-75,80,-60,58,-62,-58,124,-46,-99,0,-121,68,47,-60,-80,12,-105,-71,-54,-47,-70,122,-54,43,-18,123,4,-36,-15,63,26,-45,-38,-76,113,-128,71,-39,-44,-5,15,92,52,-58,-41,-105,-38,-126,77,100,-47,-2,-75,-125,-107,25,-49,79,99,-34,-12,69,112,127,6,-103,16,6,84,-19,-126,-65,71,-42,50,-57,46,60,-83,31,13,93,116,47,21,82,113,68,-9,91,68,-14,72,44,59,90,123,58,71,50,-101,-120,-93,-45,63,63,-69,-96,34,-32,-20,63,104,-104,-44,71,-59,27,-52,-100,20,122,27,-100,99,111,11,-84,41,23,13,-92,-27,108,57,-94,41,2,1,-100,-79,-73,-109,96,55,-122,-119,97,37,-40,-6,-52,-53,-35,84,-75,55,-32,37,122,103,-128,-110,92,-33,14,44,25,43,47,-77,53,82,-61,78,-100,100,93,20,-128,100,113,117,-45,-124,-80,-35,-104,114,42,-96,45,-111,-59,4,-15,-54,30,-56,-108,50,-21,-104,112,-13,79,-108,-25,23,83,-107,-23,-77,-83,91,-126,-44,75,34,76,-64,50,-115,35,96,-74,-40,-2,83,104,66,83,-42,8,18,89,-120,92,44,47,-109,-124,-26,-104,-8,92,-124,112,-122,-36,75,-105,61,-22,45,63,-4,-9,110,-36,114,-33,73,24,69,-16,116,75,100,-29,29,112,83,23,-98,48,-68,37,-39,19,125,25,-55,117,101,-90,-116,-48,21,61,95,118,-19,-106,-80,79,90,-59,10,39,-67,-6,-82,-33,-86,96,-74,-95,82,9,22,-116,-64,-95,-58,-12,117,-16,51,75,33,95,74,31,32,-97,108,13,24,-65,1,31,-61,-112,74,-53,-19,63,-33,-102,-82,7,44,9,91,-96,-71,9,-39,-12,-124,20,53,-116,103,0,-109,89,-59,-68,105,-115,41,-13,-96,-95,31,-65,-104,96,-53,89,-51,49,-126,-3,65,62,-58,57,55,-48,-113,-98,27,106,8,-14,41,84,62,93,-114,-94,-14,117,-104,-59,-16,37,-117,-79,-70,-106,37,41,-45,123,-61,42,61,-64,36,56,46,-120,92,-5,87,32,40,-85,37,35,83,108,106,7,23,67,-33,-38,-16,38,-47,-42,10,110,-89,-122,-22,54,-52,52,87,-115,-32,120,-81,-68,-90,72,108,-5,115,99,83,77,2,31,96,40,122,-48,103,-47,79,-54,26,124,99,-54,-62,-101,-67,5,-66,28,9,107,85,21,107,53,124,115,-113,-16,-125,77,-55,106,-25,10,-6,-67,-33,-104,-89,68,92,93,33,-42,-57,-44,-121,-7,-65,75,-9,-109,121,-85,-72,-54,121,12,-58,-50,41,-104,-32,41,-99,91,-6,34,28,69,-74,77,60,-102,-24,44,-65,-47,-94,-102,-34,122,-54,64,39,-66,69,-68,57,-108,78,31,72,98,-116,-24,120,26,14,-64,-78,93,94,103,-37,117,-117,-34,-113,-45,-11,82,-46,63,18,-86,-54,27,108,-2,82,8,55,107,24,-45,-125,-91,-16,-66,-82,-22,95,57,-41,79,120,-101,-59,-71,-64,-37,-14,-112,100,73,90,33,-48,88,122,55,90,119,126,-58,27,110,-124,-104,31,-40,-46,74,-5,-118,96,11,-6,-89,-17,113,102,33,-9,45,-15,-86,-56,78,-15,-29,13,30,56,-105,-124,-82,66,-110,-41,103,31,-44,102,-28,119,117,45,35,89,-49,65,-126,21,22,64,49,-17,16,3,-108,-71,-127,-61,-52,58,-81,-65,81,-126,-33,103,88,76,-115,-63,82,62,-36,-99,26,35,-62,45,103,85,-68,-103,82,11,47,124,97,-94,30,-57,-78,59,-33,-84,113,89,-70,-95,74,75,-57,82,20,-107,117,10,-120,4,81,28,114,111,-85,71,59,-119,43,72,-58,70,-95,27,-78,-2,-34,-73,16,10,74,-74,-59,-42,35,102,-82,-3,-35,105,-48,-79,93,-47,10,-4,103,-2,23,71,-81,-90,92,45,88,-27,-21,108,-48,-63,-18,-116,117,29,-106,15,-74,33,-59,13,-96,97,37,-87,89,-98,24,-26,-46,119,14,-79,-86,-38,-103,86,-59,73,-16,-108,23,-96,-46,79,41,95,2,-46,-91,-119,71,-63,46,-18,73,78,-38,-23,52,36,18,-81,-88,-88,-44,-99,-93,45,-5,-92,37,-52,-82,104,8,-50,-81,-60,68,96,-116,0,-19,21,-125,90,114,97,9,71,-117,116,62,-84,60,-16,54,89,-83,87,-111,-27,14,-112,-16,91,66,-53,41,-121,-67,15,77,-17,77,20,-119,59,45,-79,120,-5,-70,51,23,33,-5,-38,-92,-106,108,93,-79,87,71,-55,78,-45,18,-34,-71,-7,-82,121,57,-83,22,-29,33,5,46,101,38,112,64,14,79,-13,-41,-36,-36,-6,-57,100,-39,67,73,-122,2,-75,46,-86,112,70,-56,-18,99,-50,-26,-17,0,23,2,8,123,-71,-100,57,109,34,43,-91,6,105,92,-37,-1,17,-45,26,-120,-11,125,-16,-84,-52,-71,24,-94,54,-7,41,15,37,-64,-65,64,40,94,-53,100,104,-24,-37,-36,16,6,-34,-38,21,-7,94,6,-34,-94,-14,54,22,-113,2,57,-85,58,-117,4,-9,-111,-38,-2,59,13,-113,-6,95,-114,-35,-122,-64,85,24,-33,107,-3,-29,64,60,-95,6,57,102,-106,30,58,-11,-110,-96,99,-55,13,-81,96,-18,52,14,49,36,-22,43,-111,32,-75,-101,40,7,-110,18,-37,-27,109,75,-81,102,113,66,-109,123,15,94,-127,114,88,-81,6,14,-119,36,76,-72,21,-42,-30,4,-92,-50,-67,34,34,-117,-37,20,-105,-104,72,95,-76,-80,-108,119,-30,-115,-3,19,120,-84,114,-40,112,58,52,126,-53,-4,69,-74,-127,-127,17,44,45,-93,66,33,-39,8,-66,-46,-95,-69,-114,-43,-110,24,-119,71,-63,-61,-107,20,8,-8,50,74,-55,-43,-54,-64,95,124,17,60,-67,122,91,-47,32,-96,-46,-1,74,5,-38,67,109,-48,101,32,-54,122,-95,-103,-29,105,-49,121,-105,127,86,-16,-71,-22,-33,-120,-8,26,-83,80,-40,1,-84,34,8,-65,-52,33,116,-84,-123,71,115,-31,13,-106,53,-52,119,123,15,67,-73,67,-75,61,-46,10,45,118,20,-66,-65,18,48,-122,-21,-37,61,-47,22,33,-58,62,87,-101,100,-9,-75,-121,57,-106,40,56,-121,-121,70,-76,15,17,-3,126,-45,-46,126,25,87,35,70,-25,-58,48,31,73,-127,33,-4,28,-9,39,-42,29,-71,103,-77,77,-112,13,35,-108,68,75,-46,-69,123,100,121,13,-105,-80,34,-23,-40,11,-80,0,-79,-2,-110,125,-86,76,-53,16,-101,-121,102,-108,73,-73,62,22,-48,-41,-9,-47,-81,-62,-128,76,-37,56,111,26,-65,-105,-31,-1,117,86,-115,-113,-94,-65,88,51,-17,-89,95,-37,-112,-9,-66,11,-46,-71,-71,-54,-112,-21,-115,15,38,-121,122,-75,-64,105,-76,-46,-128,19,67,40,27,-125,94,10,-124,118,-99,127,-86,65,56,-19,18,53,78,-20,95,-119,96,76,3,100,-83,84,-44,-39,-6,-121,-69,-42,-49,20,77,-108,105,-122,7,-115,76,-35,58,105,-19,-82,11,10,33,62,-63,4,-67,114,48,51,-125,-34,-28,-79,38,-111,-57,-55,107,89,76,-99,108,16,-85,27,70,-57,63,-3,-93,-62,75,-94,15,-69,32,-83,80,35,-6,-128,-22,-52,79,-7,-97,-124,-26,-92,80,-106,-2,-52,38,55,120,48,-66,79,55,44,104,79,8,-35,-69,-14,-121,-46,-33,-72,30,-6,-50,-10,85,73,-88,27,-26,-46,-99,71,124,95,55,-116,102,12,94,-48,-106,-3,-84,102,31,-35,11,-16,40,79,-13,-33,98,-30,59,-19,-87,-33,-42,-109,-83,-50,87,-86,9,27,10,8,-71,71,108,94,103,-119,82,63,-13,-39,110,81,18,-105,83,21,-78,-54,64,-2,85,68,-27,-48,-64,-82,-26,-124,53,-20,-58,-25,58,-110,-6,26,-107,126,92,-126,43,-9,-124,11,90,-109,32,-49,35,48,24,38,-96,-32,-112,63,44,-34,43,-116,58,-32,75,72,-87,87,28,60,122,-125,91,-60,-119,66,108,-7,-8,-7,102,61,99,-58,-88,50,55,46,-63,-29,119,-36,-76,65,68,-62,53,-91,-64,89,-79,31,-36,116,32,59,-9,72,8,-47,71,-126,43,63,42,83,84,1,-71,-121,-103,68,41,112,-66,45,-48,-123,80,-76,20,-64,65,-66,-49,-16,-12,-18,-41,-55,54,-16,-87,53,-120,33,-79,58,4,65,7,19,59,108,-37,110,44,34,-112,81,115,37,-71,12,55,18,-3,6,102,101,-38,16,-120,61,57,-18,24,119,-39,-13,24,88,-123,-99,-45,87,115,92,-4,87,72,-56,8,82,7,93,28,15,77,-71,99,17,38,56,-121,-67,114,-97,-19,-71,124,-126,-51,75,-61,-2,2,-122,100,37,125,-37,-36,-53,125,46,-95,-91,-2,61,-113,-58,-15,24,-39,55,14,-126,50,-95,-90,70,23,-97,41,-118,17,-59,-59,-81,-79,82,-13,-109,113,99,114,-109,-11,10,36,95,115,103,45,106,-44,69,21,-65,21,-79,-30,-35,-74,116,-126,76,122,-94,91,-83,95,62,70,-89,104,-93,59,-38,-80,-105,127,-21,-39,96,-45,-52,112,91,49,95,56,-75,25,-123,-112,-20,84,-93,12,-45,-76,63,-86,-60,-49,123,43,-76,111,67,1,66,-35,-85,-99,6,127,49,-4,36,13,73,-77,-88,46,-39,29,-57,-115,-102,-2,51,-76,19,43,68,-99,-88,67,-128,-98,-27,125,-51,69,-26,119,-99,82,-28,-102,121,-15,-4,11,-56,-52,-30,-117,50,-45,-60,67,87,-21,21,89,-123,9,5,-94,-123,-106,118,-93,-111,-44,-56,32,-107,-64,-65,-29,-24,-114,-111,95,80,-34,-3,112,70,113,75,-95,18,-115,-85,48,100,-107,45,82,1,-125,24,37,-18,85,-113,45,51,5,-126,45,116,61,19,-49,-72,-57,-81,-29,22,91,87,34,-61,45,34,-120,106,111,15,96,95,-123,65,-120,-89,1,-114,110,114,102,-86,-115,37,103,-59,-103,81,66,84,98,-30,-113,-41,94,58,-116,-3,-51,-105,4,45,-87,-8,42,-63,-17,25,-30,68,-119,122,-43,-35,86,-125,-48,-72,7,47,54,-1,-110,73,-6,-94,-88,-35,-126,124,-55,-101,-79,-27,4,-104,4,-21,-84,122,-2,24,123,-86,-40,-6,119,117,-7,116,-125,-67,127,-58,-73,75,20,-110,-45,122,-19,46,-75,64,-7,67,-16,52,-119,19,-27,-54,-28,-60,10,-124,-117,-71,-80,-1,15,88,-13,122,-69,-72,65,8,118,-112,12,-81,114,66,-24,72,-36,-22,127,-116,89,-74,-23,-108,-1,-57,-64,-22,63,55,-99,82,-15,97,101,111,87,18,75,84,-93,40,107,78,57,84,103,-55,85,-111,19,-103,-82,112,63,-65,-14,-6,124,-71,-51,-14,-69,56,-10,24,40,-76,91,-110,22,118,-51,10,7,-85,39,-12,14,-33,-82,60,-93,-83,123,-126,-94,-4,-75,45,77,-36,-50,-16,58,112,-52,-6,-30,-82,58,73,57,43,108,-88,-125,-29,72,115,-78,-60,102,93,-69,65,-44,67,105,85,-86,43,37,123,-57,72,-49,-23,-6,-78,81,-14,55,115,7,-16,69,-20,28,-36,126,68,-44,35,-24,95,50,94,-24,35,-55,-20,-62,-64,-16,0,99,26,42,0,94,115,87,-91,-113,-9,-80,74,7,-21,69,93,1,110,-39,-126,-61,-81,-39,-107,74,65,86,-114,62,-23,-39,-37,33,94,52,89,17,-117,20,-51,40,-103,55,-80,88,-70,-15,-86,123,11,-59,30,64,-5,26,7,-79,109,83,-28,27,-67,-68,-27,-74,117,-5,15,-28,125,-84,40,34,122,21,-57,83,42,15,-42,-95,-109,16,40,9,55,71,-26,-36,39,26,43,119,51,-46,-79,26,106,-87,22,-85,-45,116,-21,-48,123,63,-82,103,96,-10,-8,15,78,40,51,-79,100,-19,-64,101,-92,-65,-117,-93,-64,-92,-17,27,6,-70,-74,-47,56,112,68,-70,71,-49,12,77,24,41,-68,-4,-121,32,-54,-101,-113,18,-84,-119,104,-113,-52,48,-24,-15,-53,-56,38,44,73,-37,-31,-108,-127,-25,116,-112,22,-81,-105,44,-4,-63,-60,-78,-42,104,88,81,-45,-12,-58,65,-22,-61,38,79,-19,41,35,16,25,79,16,-127,-94,-94,118,-71,115,-99,-93,54,-70,21,12,-33,-116,-32,3,77,20,-15,-62,7,46,-104,53,-106,71,15,100,23,-27,55,78,75,-42,-5,37,49,32,74,87,-44,72,-123,63,106,126,64,26,87,-39,-125,-35,91,-52,113,109,-107,-29,105,-12,19,60,115,-17,13,-10,-2,-124,-98,34,-54,74,20,-39,-122,-122,-40,4,-121,42,64,-56,-115,42,62,47,13,46,-111,71,18,-46,-10,104,6,-33,-33,-12,-90,-42,49,-41,84,105,-107,-43,-37,14,84,-99,4,115,-33,-36,56,-98,65,-74,-1,124,-39,91,2,-78,-109,-92,126,1,-81,34,46,57,58,-62,86,-60,-125,20,18,-121,84,48,13,-68,115,11,-125,-59,58,-105,12,-33,28,-94,-22,-33,28,-37,6,47,-7,28,-7,41,-21,-92,-15,42,100,4,73,33,-37,-49,-31,-25,29,9,48,-73,12,-126,26,-48,98,75,90,122,60,19,-46,-44,41,-74,-58,108,-108,-83,87,52,-70,40,5,-112,-120,57,81,44,87,-33,52,-34,-66,-47,-113,96,-70,-126,19,-24,-113,-43,4,-14,23,117,-28,121,80,-1,-48,1,-24,26,-49,-9,27,9,32,-124,126,87,42,118,-88,90,-36,-65,126,16,106,-33,-77,-125,-19,106,-2,49,-66,86,65,-45,53,121,86,123,-25,98,52,-98,110,-53,31,22,-3,-81,-22,57,91,-30,69,-34,-14,26,47,68,-115,105,14,122,-66,-90,53,-26,6,59,-65,120,10,82,98,77,-62,79,-73,95,-122,86,58,61,114,-112,-35,-124,-66,61,-2,-68,90,-24,-96,87,-7,-39,73,-88,-95,19,46,-116,76,91,73,-9,95,-75,-24,-44,-14,8,42,28,-101,-113,-122,-7,14,-33,-72,82,-44,-36,32,90,96,-55,8,112,32,-97,-79,-56,-128,-43,100,24,-81,2,46,38,-2,-40,64,57,-6,82,-44,25,27,104,-35,-117,57,-121,-34,-46,-49,-73,23,-27,38,92,0,57,37,127,-120,77,88,63,-84,77,-90,115,-52,-1,111,3,109,116,-20,121,33,18,-40,21,59,-68,-46,21,-54,-56,-113,64,27,49,-5,79,-30,-26,116,79,23,-89,118,-115,-114,-100,122,49,-89,-77,89,119,38,63,-91,-114,74,-121,16,-127,-112,122,78,118,-74,1,70,-102,-27,35,-5,-41,103,-54,55,95,104,-71,-34,-70,-54,-70,-119,118,68,-78,-3,-27,-94,-119,-92,76,6,-71,48,12,-7,-113,-109,-58,-8,-83,0,-88,-48,-83,100,-103,-28,102,53,-16,24,-83,51,63,-77,120,104,84,57,24,-91,-23,9,-117,57,-4,-110,5,93,29,-100,93,101,-54,-18,-110,21,-32,51,36,-90,-101,-68,-24,-116,-97,-4,-94,17,43,-93,108,-60,35,124,67,68,-120,19,-100,26,-111,84,42,-92,20,-64,-29,53,102,42,-34,-121,31,66,-33,-48,-65,-16,-13,-49,102,-48,98,47,43,-110,-84,-79,61,68,-70,36,-16,-38,34,-89,-77,-48,82,-81,120,-55,99,103,6,112,-63,-26,91,-108,-34,-13,-104,72,-108,-121,-12,-23,67,-84,15,7,-79,-128,28,57,4,-37,-44,107,-110,116,27,28,9,-89,59,83,-28,98,-50,78,-8,-23,-75,90,-70,96,-107,89,-18,18,113,-73,-81,-39,-75,-54,-106,-27,-101,-19,27,10,-26,99,-73,87,16,-63,43,88,97,18,104,28,-106,63,25,-13,67,75,68,16,-73,-41,-25,111,-4,-39,67,15,-27,-123,12,-71,54,73,-45,-71,-38,-32,-18,13,94,-35,-9,4,-68,-52,63,-93,116,8,36,-63,-78,-119,96,-27,76,24,36,83,80,-93,101,39,17,94,78,91,86,-92,-51,15,-39,-2,-120,-59,81,-26,54,-27,-61,-124,100,16,34,-51,41,-43,-98,-10,-44,102,103,44,-109,-105,25,120,98,-101,59,27,93,79,-62,-71,34,122,-122,43,-43,-86,-16,14,103,97,-102,-33,-35,108,64,-6,-55,35,2,66,-34,-12,31,10,-39,-95,-105,-85,-56,-119,0,-25,-18,-69,-41,-49,20,76,1,107,57,23,-110,-80,-46,47,-123,20,118,-112,2,-107,-49,-120,100,62,-50,82,101,91,-103,86,3,-48,88,48,23,-84,-107,-15,-104,103,116,-123,65,-119,-123,65,29,-111,-82,93,60,88,46,-61,127,2,24,-84,99,-20,57,23,-90,123,-54,-93,-2,-91,60,38,-93,-106,97,115,-106,98,46,-118,127,-60,57,62,-24,-24,62,-98,-108,-106,103,103,-107,99,50,37,-117,33,-80,-126,-72,-13,-20,-104,111,90,49,39,50,-48,110,53,1,127,-124,16,71,-117,-81,104,68,2,-122,-20,59,-120,-43,93,-126,-95,-35,-121,-6,-35,-48,-125,17,-123,-66,54,-65,-32,67,-54,-13,82,62,5,5,-26,-55,-91,75,-44,-93,-31,-17,-5,8,64,37,14,43,-65,127,23,-49,-26,-81,34,-36,-9,69,76,59,0,-34,55,-69,-30,117,-74,-68,31,83,-33,55,38,9,46,-92,95,-54,-57,122,-68,-48,26,-126,79,118,13,-63,58,71,108,86,41,-91,114,-59,3,-17,-78,66,52,91,67,-117,-42,87,-93,105,-77,94,-120,117,-17,-62,16,-48,6,-82,101,93,-15,-24,68,33,-17,79,-86,-40,11,18,105,109,2,-83,-35,-87,108,101,-60,-56,6,117,-20,118,-5,112,36,-77,-6,18,-27,-37,117,124,-21,9,-60,-111,95,-119,-124,-32,-97,65,-123,33,65,-31,-66,-32,28,112,31,36,-92,-18,-41,122,52,-54,58,20,-21,-85,44,47,53,85,-79,25,-39,-58,-103,-18,-49,41,89,103,-14,56,-128,39,-6,-9,-67,126,18,112,36,97,43,0,70,-28,-72,34,-60,-122,105,-118,78,-27,-90,-66,80,-37,11,8,17,-67,13,12,63,46,-98,110,-27,124,94,85,63,-97,-39,-105,110,-46,53,-91,99,-119,-127,-82,4,-86,89,30,-91,55,85,-90,-41,66,-128,62,-102,1,88,-28,-35,-20,-12,-36,-105,27,34,-86,76,57,20,97,3,120,-117,57,-2,-128,-83,81,-127,57,27,-119,10,19,68,58,-63,20,116,25,95,54,-64,110,-33,-118,-94,88,-67,19,-82,-109,95,-77,-59,-45,75,-34,-78,99,17,13,-31,-4,-127,-11,-116,-31,-59,11,-33,36,116,32,-54,43,-126,53,123,79,-115,65,-44,-76,107,-53,-91,69,-63,-12,-66,21,-30,-53,-31,-21,-21,-23,74,-69,-9,101,58,86,-28,88,-32,-74,-128,-81,-71,112,2,-107,95,67,14,106,51,113,-42,-101,119,-61,-70,-27,-41,80,-84,-67,69,95,-86,-33,23,-13,-104,-68,101,-38,-22,77,20,104,-118,70,48,59,80,105,-117,-23,88,-124,17,-7,40,117,100,10,122,88,-67,61,-35,64,-99,11,-30,-67,108,122,-91,39,-51,-113,-72,-98,25,31,-88,-95,-61,-25,-73,105,82,98,-44,-12,33,-56,49,-36,119,-111,-112,83,74,-41,-91,41,65,123,5,101,108,-50,-43,65,56,75,-25,122,-14,68,60,-2,44,-91,-27,20,-73,-30,-60,-26,108,32,-8,-53,-5,-46,6,40,5,48,0
]
                print("data_len",len(data))
                data_len=len(data)
                hex_str = ''.join(f'{b & 0xff:02x}' for b in data)
                aa_result = bytes.fromhex(hex_str)
                #                 hex_data ='''
                # 0a6a1224082012204116be5eac0a8044b9ec82227824f09f678d6cc0c02112f4bb2f1a86e5f9be371a4208c905123d08391239045b2e7d5e3bea2eccfdb6d04661823ebe512f0740214b2912f522a007329ed94ad8f90919fc651e701d0c1ebad593a06e8db527df7f4aaace128a4a0a340a010010ecb2e39af8ffffffff011a104132303532393433646133623431660020d08e81c0022a0a616e64726f69642d3333300212280a0408001200120c0a0012001a002204080012001a040a0012002204080012002a040800120030001aa402089e02129e020a24082012204116be5eac0a8044b9ec82227824f09f678d6cc0c02112f4bb2f1a86e5f9be3712f50108ef0112ef0108a84e12e3010f31d6e200d42dda6d5f3796d289e6851e4f7fac1597ff436c38d91f8293bd5901855168e5f8fbb1203fc1a7c6c5eb28405f93f51096d76deac6847aeee2acc27cf628db5cc49e828370b4aa4215c0e45ba1faa17522c51c72681381816b1d6844112875614b1b989df73803e2d02134d3062c19dcf0bf08282fffb20da2131d1c99cdce71ec9d5324a891f48c84dc6a68f7df60a5ed1cc117ff88f7cc3de09732474704b9cdefe7c192af5eda2d5eea08ead5adcaef3e4ecd8322e7ad2a56ea04d04791cdf0065b612423f296c8aa64afce92b920b17137060206cf7c58e7d90458371889b6a0be052210313233343536373839304142434445462ae90a3c736f6674747970653e3c6c63746d6f633e303c2f6c63746d6f633e3c6c6576656c3e313c2f6c6576656c3e3c6b32353e30376532376365356264396339646433363061373737336331373738326433303c2f6b32353e3c6b32383e38376365356263343c2f6b32383e3c6b32393e30633365373264333c2f6b32393e3c6b33323e3137352e32372e342e39353c2f6b33323e3c6b313e30203c2f6b313e3c6b323e342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661352c342e3343504c322d32372e312d31383637332e31322d313232365f303634325f37343739323564653661353c2f6b323e3c6b333e31333c2f6b333e3c6b343e313233343536373839304142434445463c2f6b343e3c6b353e3c2f6b353e3c6b363e3c2f6b363e3c6b373e613366616266373966353333663933373c2f6b373e3c6b383e756e6b6e6f776e3c2f6b383e3c6b393e4d323031314b32433c2f6b393e3c6b31303e383c2f6b31303e3c6b31313e56656e7573206261736564206f6e205175616c636f6d6d20546563686e6f6c6f676965732c20496e6320534d383335303c2f6b31313e3c6b31323e3c2f6b31323e3c6b31333e3c2f6b31333e3c6b31343e30323a30303a30303a30303a30303a30303c2f6b31343e3c6b31353e3c2f6b31353e3c6b31363e6670206173696d64206576747374726d2061657320706d756c6c207368613120736861322063726333322061746f6d6963732066706870206173696d646870206370756964206173696d6472646d206c72637063206463706f70206173696d6464703c2f6b31363e3c6b31383e31386338363766303731376161363762326162373334373530356261303765643c2f6b31383e3c6b32313e484f4e4759552d383130322d35473c2f6b32313e3c6b32323e262332303031333b262332323236393b262333313232373b262332313136303b3c2f6b32323e3c6b32343e61323a30393a32653a64393a65623a38363c2f6b32343e3c6b32363e303c2f6b32363e3c6b33303e57692d46693c2f6b33303e3c6b33333e636f6d2e74656e63656e742e6d6d3c2f6b33333e3c6b33343e5869616f6d692f76656e75732f76656e75733a31332f544b51312e3232303832392e3030322f5631342e302e31312e302e544b42434e584d3a757365722f72656c656173652d6b6579733c2f6b33343e3c6b33353e76656e75733c2f6b33353e3c6b33363e756e6b6e6f776e3c2f6b33363e3c6b33373e5869616f6d693c2f6b33373e3c6b33383e76656e75733c2f6b33383e3c6b33393e71636f6d3c2f6b33393e3c6b34303e76656e75733c2f6b34303e3c6b34313e303c2f6b34313e3c6b34323e5869616f6d693c2f6b34323e3c6b34333e6e756c6c3c2f6b34333e3c6b34343e303c2f6b34343e3c6b34353e3c2f6b34353e3c6b34363e313c2f6b34363e3c6b34373e776966693c2f6b34373e3c6b34383e313233343536373839304142434445463c2f6b34383e3c6b34393e2f646174612f757365722f302f636f6d2e74656e63656e742e6d6d2f3c2f6b34393e3c6b35323e303c2f6b35323e3c6b35333e303c2f6b35333e3c6b35373e333038303c2f6b35373e3c6b35383e3c2f6b35383e3c6b35393e303c2f6b35393e3c6b36303e3c2f6b36303e3c6b36313e747275653c2f6b36313e3c6b36323e30303030303030303130323863306531653730666565303637653032653966373c2f6b36323e3c6b36333e413230353239343364613362343166353c2f6b36333e3c6b36343e62336434346137622d383864632d336430622d623165302d3331313732386462646465623c2f6b36343e3c6b36353e323131646663323364663664623366313c2f6b36353e3c2f736f6674747970653e30003a1e413230353239343364613362343166355f31373833393937373237333632422031386338363766303731376161363762326162373334373530356261303765644a0f5869616f6d692d4d323031314b32435289023c646576696365696e666f3e3c4d414e554641435455524552206e616d653d225869616f6d69223e3c4d4f44454c206e616d653d224d323031314b3243223e3c56455253494f4e5f52454c45415345206e616d653d223133223e3c56455253494f4e5f494e4352454d454e54414c206e616d653d225631342e302e31312e302e544b42434e584d223e3c444953504c4159206e616d653d22544b51312e3232303832392e30303220746573742d6b657973223e3c2f444953504c41593e3c2f56455253494f4e5f494e4352454d454e54414c3e3c2f56455253494f4e5f52454c454153453e3c2f4d4f44454c3e3c2f4d414e5546414354555245523e3c2f646576696365696e666f3e5a057a685f434e6204382e303068007ab43808ae3812ae381aa73608a13612a13640dc97b4f4f5330a0930303030303030320010021a80369be3a3c5437608eeb38fd275f0e5d8e030430aa646985eadd18ed95aa05f83a4d9d9d606f5f5683aa26e6c7198b6e95324c247f4f1f2c92252fc8c1799596adad01acabe530c4a46c7c724863ee78b178c3919d2ec9bd33d6de534b4646bc316f2b430d454fc7ee1768890851320b99ac675a7130243a2ab37aefaaa21c25c48f3aec57a87cd13a0be0d52619a9d04be74dfa76b831d73ebafdcc74187e4849f23f55963b6089765807a36149ebfd001865b9ff2d50f425ab4444a30e7bf84e7573470a556a9ff93cb83b1e99ecb69cad77b395f56816dd70a1b7e46035a17d69228e993331b7deb441604e717d723e5c86a273347db736137a6e500666a540062c21ffa79be3381992beb3730486c03210e8aec1253a838646c9176231ab237adc70ba0bdf1d9259ce44f44764d316f0367c9c574a4e7cbc612eeaacd4ac1e151b1aac41cb05a4ca1f360554f0e34197f4032823f4bd3bc88c743b872dbe4ab6de96833f3b9c8eacfb3fbdffa94a1b2bb1d4b3ac6f130bc2fde1c219e6a17fdf621f214ff0940c1bb2d496822b7a011d96ac3e70852c5f32957d18f3e42f8192d9adc831d323023de83bc8f3f4e7b48b429a6ce02cdc2fb6f43ce7a59a3217e181e8067f3ae9ae86397879048b2b94830c662505ee113cbcfeb725cfaf8f8137f3eca13ab570d39fd5f8d587d9ec84bfea281b749585a01c39c970946f5c2ce733295c76f66dd611b1867b656faaf0e039a62024f1f971a1395ff2bc97996e1dbfa9a7a54dd688452a08491407fae62a524da1ed917d0754bbad605d2638df28dadd0dffcd3a46d0cb3c536d304770b396157a773fdfaf8b5f538aef81bccd4c605a18049838882bc214ef4dadf318d9a837e8e40f32781588fadc33a6986e82f132977be2831ce0ddb55a7b68ecdbb1420d4795d0749cff298b929684228108c62a7733fd16c19e305e77e5556920617fee73f3eb4f9f3e6bd20c6e4f3b4e72708a72ceb1a27b97df11f37178a45fc45140e634893d72784f57f53cfcd3d5214b9f61e94ed648e2240c0e75aff13befea888138835c2a5079714395d8e0fc1141dfd19b82f885e9a118e3a6917753eb6fe75a9b34106fafc593b0093318cad309c208587d45890283319b2136395d1990b30d690229de833cd7bc8b7da7aa2792d3bc0ff13b19feca3ccaf10aa4b3636ca2d4810a02cee54598106aa5a6941b268c9a23a59b934e75b3e44d72a06ebe2710d395a7cb04f5e1a8aee230e9769e9c065f81e274b8b8832ea69cb7119de856e2ee2611017e6c995e2edee3aa57cc926184aeac23fdab2cb2440f47cd74fd883cfda7dffe9850b76d843985d445be7eb5398302f051aa67270c5c65631dcc1567fd2e04354109b01f01ca9fbe86ba38993bc5cca0c3e5ac3f5d0830e26cbb43ed7c915f88d06b12f4abbcdf7cc766002f34889af271a1b5ada55f579d53eb2a9926bc2e1bd7d3f30457867ddfed30c89725672d45b9276ab68df40dd2a4f0f4371a14efeb04a6f8fac608bbca4968277868c714c97eb19f61e0a36da44ab67cafc5b655fab587b08e9b8065d4becc724df94f9029e81fc9850e6a76523e8515f2b19c2f715ebdc73faf0159fd26ef8f826039f899dac85862dd3a7f89726f34708f1e44fbe7e59230c99f7c4f26b57f3431a819b2139346643fb3f0fbb9cbafceb26ee93ed7585caa827570126097e31c005c45001102d2360bd9846c67adb5c7b066ea096a7a2179e7a653de2f80ff08d6efdf194a6c600be1d166d56ea803d3fce73c0aa2736fbf02bb2fee7764257927e23df68bce396e81f62b2605fe0dc7ef56c6de74285c63a65d251f2bdae9d71c124b3d9d64115f9bc5582738b64c6ad7f0dbfc3caf0457fbe54f3506967808cf08ea22b1d69b4507fdbdf061265b65f9bf39fb652a893bcce02f7e3994eb04703e67299e1e1864b4f1008ff6355e1a143882333af77aba30da6bf1bed9a290c5645240adfee54f629ae53735e176c029250ab8a84031245777b9649438a58e5a0071a44b3679452360f071b3d6ba478c912fcd0d63af99a94d274c8acb7c37b7c5f1c6e2b1d3bdc94a96270222534d36ba8a9a0dcd4e8507953b51e7117f01dadfe7a00208215df29251b30a1d4527ba0b3aebb49779a170bf42fb5d6c56ef927d383ec4bb2165984ca162fd898a1e51767da4f5831f3f97bc2bdfba3359a9d5e2d79acca2eb78e2e9fed1af5a0cea1858b8af2c205b7c54b8be979b26db133f2a8752a3d8265d3bd2b7f9faeb07c0728bfea5fb6463e84c514eeb05ce96c5c7d9d3d0db7d80eeca052c29bc9d61bb9fee61723503b70c92193f680bc8ea3e30632d1fa10bed496d9b54213ef5b405f0958e43dc9af8cd356e85281add24131f0100e0af49dc970839de8445fb028916d376ea2be15cff465e17d3ce78ca594095cc30b5946cae7db1e5a50230f6de4cd63d4a6532794517e5fa53d17a6a732b49629bcfdfaa1e55e12398ad1706166576c522571b79537ecc447d069dcbcd44529a50c3e4afa4a401d851aa68de87b2959750737a09a2390b15e2efa24d506e88474d686039fc6c67daf13ed2d396e28ff726bfb0252fdc838984ee3b67daef5297e978dbe2e29e958a9cc9094587326e1a907c3e47b11c8ce58daeeaed999907df497c71374ab20291596f3a690293f35a9f1b6c0f9279aade4ea8e02a62500b654f9726500e88a5e3b109f72e32c87de9497ce1696bb2f55c0c2455ec87e95bf0ccfa40de22879ec242c98d3718b28264f8b956a7a51a661816ddac4c2b1d874b4b27fe31d51371df73f3fbbe27255f281c5b79b891e5e52617e3beab79c52028ec67ae1570cb5bef5a9e88d5df36f041c6bdbbccbf5c70cfae01d34fbc4e0b6ca0d41515807e8d7ef0db81a2a3c8171bc8cc2416445249087303494c4391e97cab3098488457ca1622c3415eb5d951c0589395d9d2883ffe74acc8c6eca6277e7a4f84d37834edd2b2b5f2a53430a3c98747fd6b4f8736a7cf3bad183e29d72b1c334877905346b3de5e4a8ccdc44c1d5b1bff1ebe42491bd5e7c3bb5a4030ab9fb003048049aeb03ca55e9fb00739b3aa499acaed2443b746e97b8bc1b1f242b04bc6ebf9ba712c28b197f49f59b71d7cdbfdc9d94a0d6c2357db3982bb3e243c9e66e72cc49a2204b9be0e12cb612a54633dc035544dc3ae6a97d9084a44ddeefaa919d19bea1660d567be4a4150dfc4106a72aa2f8f729f95d034cea7b8334c18aade49c0436e2bdc4099c46bfd5d8dee9fec21d8018365c4292f28aab4d0653d249f58ec4c1e258bae04d6998671865074da8468cf78d1b4b2fa7ba94b65c7eb8b7042a3b16e108ddff94dc681c3577618e4ae51ef5e5e38c2b911d877f287fdafb127446d7c336108c568b96d11322c15c52a7848e83e9354c4ab5156d3d06e415bd977ff4e5a523d83e642e7b7ed764c640a7dcfa3d043a55c27e34eb939b0d89d53de2f346ee6f98ec10192f8a2eeef960881e2f4e3fbe8de3c579d01ba4529768d20b5a249fde36204f6838071fb6bf1ee1b95fcc2f1410d844fc25ad7fa7091560b913b9b1d0e6c4c2488415b9ce93ea547599d9c44a9ac331843660f812048fc06bd1f70574428842b6f3ed2cdb29a74bc9b170ea15482caad1f6fb77e68d8d5febfe84e1b5e90f15e03cf3323988a31ad05767b01d8b2ce988643102d81eafdb4d8adb1ae36d96288d9926b40113e557f1881e2c08e845bf130b5cb89f22988abb96bce5bf27bb94ea508cfe58e2dddd2d8308cabc7d253b550c7039c2a85af67999df1d2245dbdafaddf8725513bd8a0ee34a34e82507c18faec1892e280da0eee990e05829b5a821b48757d2873062064e87e40a56c983f59d0ec549f93633a8d4102c178a0be09c088fe9be75eb91b0f1cddd7b87a9a408c0f64f358e1d6e4add90634a407c83d74e033848730a5d17682ff755047f721a26bf692c648c1c5013fb2cb6a83500fc362ed6f229bcbfaa1fc10c7abe84c66fc6d4653d22d1ecb5653a37c0be78ba35cc2fc8d50cb5275876776a6091b502b92e41257f14f95635f8fa7cdb5bec7b3d15a517a3e672ab6464ae16a019d570cf9bb4d3c9e13dbd45f4a02eebfc0c6465d1578a25682c5c2023681455ab1870977d985aa4687f748ac9ab190fc71ca84fa6a6a822210e9b93d7bf3e704f46a3e50325a1dcdb778c2141aa73f8ee50ce7677d75a79d0c9b04d6a9407a0a2569395e4e5dd44b46e3b77665386df01efad2b92246d3fdc7dd2ebf36891533bd158fa81ecf136577d619a339da0c9951a1168c62a6d8f200478c43f848cfb012bd1dbbb2084af871fb29fcdbdee8618e175753d839a3a861e21ec38a721ebb51b2784254ccbe51e12e4c30df137303ecb151951659c5bd753e9a62beb526b1056f27c42ea280372556419440723fbe87a719f291f40ecfc29cd898c9d266408c2cc6b79d4f9a959df0eba6af71ec4badbb3b897bb21a24652abadedaf7e36ccc80079e6d9c1f806bfea1957875e831c55a38a5875f9af16c2408944936a893935016c0f2ec1725ad3427502a6b0573ae8ddd84e7ba528352074b193dbb0846fb993a900f4da82599d28c375d66fd41bb2855ca64379322af3b9ef12499050b21b644aceef2e17a03ebc8c5bbc1e0d8282c4dfe53b34bdb74b320b5cc2249d9c9c78c47f5e4f81fa5a3341a0fae63efde73cb7db0834e4095406922ca269ec240d21eda656869040223467deca4a0a4f59e847eb40418ed9978e24dd1bbd4774780a94b3e416ae23310a26b4af90582b5a1393586a83a55b051b05c55699a1a84a04cdaa9b60af1f461fb3a44c107cb48e9348a43a358a614e5031a18464056d53c2d09a88a22e02f6c5f0ec6f4c266e85138e9e60ff2bef47194df0c4b088887166ebf849b76330f5981a23b3d415d9e46719e9f3c01d0d23b9f36f403782472419765209a0b6ce4097eaf84370c6bea28a76aa672f261f01ab27a5d0ce9c6f8313ff32264a5b3da5ad57847b7e21a4dd4a8c3f4dfd957ca2d84d74c15d43ba54cc5d79c24a61566b25f7126a39418dd90d3642d388562472cd4518c72bdf92b58229d41ae481a819fcdc4944822189f91aa2d32c972150ce28ab3851b338a7123f4d53655ba6405f64773e92a0a4cbdece5be172d08b729c625d53590fb4cf6aac9dee5a0c8d675667895a72fe9adf86fb92fd8ee5669b83838641abf9f00b33bc12671d964fd4070e05fd82a4191b3d076626d5fbbb201f8b171fbfdbbb56040cbb2b9b01444b71bd0f5a68db4ff3e0dc868ed6f95517a4399c5abab7fb24555aaa66ffc097c1772558430d9d4f7543d0c7122d4f0b350f6c2d357f34d0389f367232ae9641c41764aef92588cec1f8367a8a30082446099e3e1ffc22186b0bc79e9a467b94eb8b54c7d21b821910b87dfa6651d138d87e827ac75a6ae1f37b8dcaa3ca5910f01337793713fd5c885288f476576e29779e5c438a49ffd8135fd6d4322efdbe11ffaca8b28abf9e5a6c951153cc94b4ebf034deebc32650f3070ad86623537c6d5730b935c7f5f538506a146b578fa879b082bdfc7cb8f34a1f8f79e3f6ef698e78023a348b0d41b475b6709cd4d7d346fccbdb23c255a30f3e0f89256a26669e3ae27a18fcdf061416321f42ba6e5708a0628497eb1838b5ad7f45cec260e34d9c7c157a74d43bbee72fda9fc028238ae8f5c0c539095b1e48b2f526c90e5213325705dabbd60daf4ac24e44a45d61f7c98b0b69f73dc4172265c77fb8b5084b99475d6e61095cf2511c54800d0c738a27ac53ac0329f975639e906e69abf4bcc37be00ced7b1b6eda6801ecb62b198782afd054ca48ce95a7ad202eb6e5408a464da1482b704c715fe49ea880cb1d6135179ff5f04d1358a7f686de822d6981583894f6a9feda7a113370b248d2e97ec5f35d94f438c92e05af7da5346839e15f1d412d9eb6427ea9f8916b5e414aa32d345baa5a17ab3f38e47ce123d0f492bd3703012f4fd9198563ee0e61702f3f691ea9f5fcd2adb986fb4f3cf34bd51595d9c9d5ac414077bc889d6519360c041cc0afbbbf98ee928c663f789ceead35d522bf79ea73d71bb30768c903f6ce4d0d9cdb174b2699f46bf2f4340f1e5f59dcae8740f42dc5df302d18dd1bc355ca4cef1a241e653bc073f9ffb8495f14756b18ce21e386470bc928777e00fbdc6324789f07e0fcfd7a3c989841d0df918667e9cb4745214c5a798729ebeff8b974d23fe050d0ddec20aafaa565a9a4204369d0d0f6c4395bc915fd46add8db7f5aecda2cdc6c6c9a0cb46df61c649d2ff9070816f03c6d9aefa888781bf8aa1e45de93bba680f45cf273212a8b8934b5c7386cb7c06a6b20ed2c63843b1a117ced534b3af500867c6057b6fcdaf118de977fa71c1172b634e6c4a70f62ec15f5243c0d18e19e9afa3b95dab4a22835b55ff98d937c7df9707edb26a9a095a2a4798529cc70556a40e51e0d594e98b7a8a3e5b40d33c3d2f10d7a1400e5843c0c6afda11188758af60e466764968bad77d6f817d26f13c4a19b59f37c31e77ae2de4311b948201559ac30aec2289463135aa35946a95465bcc0ea6fd60a30fa98fd0e5b02378a89c6aff4f40437f8065ab5e7852cbc1dc0a560d809849df1a9a4fbbcfdbc75991569db8fba764e8f8257c512b1381613251c35c7fe4797f8fa5f0b47c1d7905fd151b73e7c80a088e43a3aa97ae72d0da5f08f643a3813295e10c560c69c6350c00eba8b4f688c29b3de59f704fc1cd31a5a54c9a1df8fc8e04a9fa5fb477a869af214cc7592b073d47c7a764dbab6bf00adc5128c226e874ea3178c8391ad73951dfbb68ebbdb68604807d13b56007f0f0a9f15b0c305d599a93167f5d2a3790bd7a6ae127fb1a0da1c4a1bd02e046403fe6cfd7aa8d74735cc59b2eaaa522bf62205bf9cc7aa333db88570c7e6e6fccce3a7b6f459598899da84c9c6f58a7afa5f9205870040413a598423e7ecd32a42872b4782fae81c9c78102fb5678cfbcc611138cdf9e6275db4d98f8364db9297f54919b44f197c29b8a035198665266c4405b287ab8b9351a44ecaa8038e235ffa63a511c49586c4dc556ec7d35a78f110a1e152eacc44c479dff3a627dd808cd222dc6812df04f6e54fd43a87c08aceaef7ef1a2de5bd9cf44ef4229c40ac88d8410b80c466659ba54c2770c739bd55225b31ff9eedc50d7a68d29a8d132d4c6b11143da332c8f19defebee98e73e67209ce4317554c139a0b9e6fadb138331e21497ac997f935e8224ade69f0d2e0bab7b5aeaf59a42cbaffd03bfae2e1bc4cfd10cb20b35eb3e06eef17dc1b17bace6c1659db6eb3e1e772b0559ce132c98d90aa44a3c751b706814d18b775e0daba0f6cd7d93cd650d99c495281baae231c492075678d30000a0a095c76a2d09e44805d3dbbfbcd5d4e9019ed7ab960a3199ef9b382d6ff618186561d18b50ce5452b90edd5cfbc8af7c38a5f8bcba12d78c888754d5a92d755289b1967d203ae4e584e6ee0bb6745c3c17c3e7074c081a9421060b3fc2015eb3b069290daa3f7565abc9753d417a80ab205f97a3931f039fec287a61794bc561d3e7e6bdd3ce361785847e74099b97c44508aad7cc50e6f0b24b9ddef6c63a5806ab91e1f6101918d43aa2c2bcbc90fa5363f5d2ae5fb23c6b01c3321650bfb66d3854809950b7e17f55bd1ca37cf9ed854d07d3ec08943605cb1b2ef3f559bd3892ccc4e4f9e1868f6eb0a896fd6b7886390fe790dd70216355e73aa746fcac817196d8780cbce01beaaff3804402788374a55084307f68098419afd227b05c8ae0264a1ba56f0e6d3a81c3f5f05f13353e735c72a2c73e328eaf02ff90f2e71758f3ec98d665d9b64c305b49c8406019dc1421335db4ed032b2fb5e31449be1342eab3e197aeba98547d85a6b3efb0ac7b0bd6d57814bfca23b2b9abf7df7c33c0c24d44d723b83e2685dc6abffc5dcf34453d616675f2858d69e5df4ecdf102a3765c91e75612bff489cd57e6c94170f67bed2b7a0d849d46883bf5b14e03ee1f6d42c0a6b9dad93768478f4bd5c6082f2647866b7719f39ebb549c4d078e27fa38bb579f7c759e7a991800717e1f1b5774d47c97fa6e53276d8396efec3aba6af18432526a8e89bff7587cba803efbda41ecca20aff912be4f07b098507ebbcee0ee08ae8f4bc8631b7e74383bcb4b634ccfa8a78feea4fcce99a693e37b2f2f5704620cf96eb485867be1e5447ac473422ec89a3e3d6582b04e33eda89bf0748a282a01d3feabc2f8e40b66d82e91079c6947cd4713aee2be4cb94728c633d8462f38adf769212ed1275e54feaed0737f85da44a4fe152826254bf4baee4974db095291480a78bee744fdb5b24ead57321734ff6c95ea6ba1d8241f650581bb3941683824d33d062bff0f3c1a98da5b066cf64a66d77ef9a0f3a4cb60a9c317903e9f6bb2b4166ad73d01a537ddfafd75db7bbb3f1654f92570f80801a9714815a239d902006248645655a0a6d0274828627cd6df7bbdfd21ba1bb69ea57cd3381971067ce82c355fa60b387842254eacad5d5a5b041a5c506d6dfaf428f8e915c024b33e01bc9a07e9dcb758bde31fdf632697292854f4fc74f6d0f213dccefe877621a3e93dbdb58d2cfdefe703f16f142ae012e7fe9193a258a6a2fab9f0a613b91476b55eb1d449db9bf1406484336c6c20bed4503c67192d463a861f1d9d9fdfa1ce3f93fc2a4be3e0ee0c6cad7ce68b5f1c3e744b6dd3039453f527382d4c59b626cbe6d0d2ff792ef8e29c9292340196cea1dd66d0d6147dd9ff975af3a549f1a3f8b67f378f3e2d807754099950cf12882bc122c0bca858b1355aeca557f03e8ebdabb993e0fc1ea51ab7efd7093f1784afc3f9f48213fe1033a70c8fbf0bf738d822dc9e980a1b61281bc5364dbd8e5a109b2e21c326af7d5b902a2e78cbe42fd98393989edae11337c6b6a95159801a2f262e5e21882d145a34e9640a3bf5ad3bed1de23c8232f866869764f57025a58a5bd70c6a6b3be2c3ac5e9e8c41fbe40db9e94515ba35b1fd60f09785081b6141771c5e69ac10b8763a5f5e468ffcdfc22cb817802fe30d347cf9922892ca01559fd997c529d3dbc40179dc52337d5d6c2cd9df4e25c2191f9e689687256e54871f547a8a0cf76f95ac4a9625920032afa3d3426458595ab087214e3449b302cd64e31ac26bb8344e196e097bff16b13df980d38974c578944c4b83b07d4a867fcf56d24b262437d7d47a3e846d17f9daa2935350bb34c3f29dc773d69a6d51bca7e443db31c493d1a3199d8f58ef1b7370c18a56d0fa9bdd73e3aa1d5a1de085f7e71ed59bb4bf8224729cd58fc6252e7d7f9d38ae4e731f664c4237b3a6b00cffc77f62ada4f2fb31ad9409796a8fa0de6428a92a1c1a991c9f1604b5d5595e4947f7488d1deefb1586c3fd01acc85eaf36c9889478ed170dc2727a2b1d7bd7dafa4738e36732280d6489d8e67cfd608f37a71c6f510f90ca48f880a37dc1eab9fef980442e756c60403af060a8970524337692ffee043446502efe4c82e79dda417c39bbda0d3e15f92cd2c8e3e1b485bb763a6d6bf83de568d1c92b1853ad720f75635731e3feaa384978da6fb98349ed8fd337a66c8a80ed2a63b598b511a059c524fd2b39e636cb3d87e84f07d3499ad635042bb8f16b531b4f70649f0732ec26a5565353177884f4995132de0520a1cad6d206280530003a810208fb0112fb0140de97b4f4f5330a0010021ae3010ae001303030643232336433653034303030303031303030303030303030303165343262353531643266666266353066663563386131623465366132303030303030306663386536343263623562343931643861303561353030346434396366386239353263316238313964623164643066663030396230323033386136643261633839646264313437643334306161343832313437386639306566303834396234373365376266626132363132633663656266626337303830386432393566643630653333333839393565386463663563656137396337636337343362653136336120a1cad6d206280230008a010e636f6d2e74656e63656e742e6d6d92014a089f031245084112410451beed7a181a19fab56f38fd1205ea24cb89bec393dad00f34b49fe628d61851b140d4bddb7392327441c41bc21051cc539ae878ebfefc1a2aab40332fa097d9'''

                #                 data_back = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))
                print(aa_result)
                print(type(aa_result))
                aa_result_deserialized, aa_result_message_type = blackboxprotobuf.decode_message(aa_result)

                aa_result_readable = bytes_to_hex(aa_result_deserialized)
                pprint.pprint(aa_result_readable, width=120, sort_dicts=False)
                old_deserialized['2']['15']['2']['3']['2'] = aa_result_readable
                old_deserialized['2']['15']['2']['3']['1'] = data_len
                old_deserialized['2']['15']['1'] = data_len+269

                # AES-128-CBC 加密 (白盒 T-Table 实现)
               
                p_text=[
   0x78,0x9C,0xDD,0x98,0x07,0x54,0x13,0x6B,0xB7,0xF7,0x33,0x29,0x93,0x90,0x8A,0x1D,0x2C,0x87,0x28,0x7A,0x44,0x14,0x48,0x25,0x09,0x36,0xA4,0x46,0x04,0xA4,0x23,0x36,0x48,0x05,0x94,0x26,0xC1,0x82,0x28,0x86,0x2E,0x4D,0x02,0x88,0x80,0x8D,0x26,0x20,0x48,0x93,0xA2,0x80,0x48,0x13,0x01,0x45,0x05,0x04,0x15,0x50,0x10,0x41,0x40,0x51,0x01,0x51,0x14,0x03,0xC8,0x8D,0xED,0x9C,0xF3,0x9D,0xEF,0xBE,0xEB,0x7B,0xEF,0xFB,0x7E,0xEB,0xAE,0xBB,0xEE,0xB3,0x92,0x99,0x35,0x33,0x7B,0xEF,0xDF,0x7F,0xEF,0xE7,0x99,0x99,0x67,0x1E,0x62,0xD0,0xB9,0xE8,0xE4,0x49,0x2A,0xEA,0x54,0xE0,0xC7,0x3E,0xBC,0xFC,0xD7,0xC9,0xE9,0x87,0xE0,0xE2,0x5B,0x86,0xA9,0x50,0x6B,0x0D,0x3E,0xC7,0x8B,0xA3,0xC1,0xF1,0xF0,0xD0,0xF0,0xF5,0xF5,0xA2,0xEB,0x91,0xC8,0xDE,0x5B,0xB6,0xF3,0x68,0x3A,0xDE,0xAE,0x86,0x86,0xEE,0x14,0x8A,0x9E,0x8D,0xBB,0xF9,0xC6,0x8D,0x1A,0x3C,0x77,0x57,0x75,0x2F,0x81,0x1B,0x4F,0xE0,0xE6,0xA5,0xEE,0xEA,0xAA,0xB6,0xE3,0xA0,0xF1,0x91,0xFD,0xBA,0xFB,0x5D,0x18,0x07,0xB6,0x7A,0xED,0xA7,0x79,0x93,0x6C,0xBD,0xF4,0x9C,0x9C,0xB7,0xC8,0xEC,0xB8,0x1C,0x91,0x40,0x9D,0xE3,0xB1,0xBF,0x1C,0xAA,0xF6,0xCD,0xC5,0xC5,0xC5,0x4B,0x9D,0xC3,0xE3,0x09,0x44,0x22,0x67,0xAE,0xB3,0x8B,0xB3,0x97,0xB7,0x86,0xBA,0x89,0xF7,0x96,0xBF,0x9E,0xB0,0x14,0x78,0x1E,0x72,0xE6,0x09,0xCA,0xA1,0x3A,0xFF,0xB9,0xFD,0x7F,0x7A,0xF6,0x1F,0x04,0x09,0x43,0x41,0xC2,0x50,0xAB,0xB6,0x67,0xB8,0x1E,0xB6,0x19,0xBA,0x2D,0x85,0xE8,0xB6,0xA8,0x2D,0xBD,0xB8,0x73,0x33,0xB2,0x7F,0x8F,0xCE,0xB5,0x85,0xCB,0xED,0xAD,0xCC,0x82,0xA7,0x7F,0x3B,0x6D,0xB6,0xD6,0xD2,0xFF,0xB8,0xFD,0xF6,0x30,0xD4,0xEF,0x7F,0xB7,0x5B,0xD2,0xBF,0x07,0xFF,0xE9,0x9A,0x04,0x5D,0xE3,0xD7,0x70,0x54,0xFE,0xBC,0x85,0xEB,0x89,0x10,0x9C,0xB2,0x6A,0x6C,0x18,0x4A,0xFD,0x1F,0x19,0xD6,0xFA,0x35,0x48,0xD9,0x5D,0x7B,0xBD,0x6C,0x3F,0x6F,0x5C,0x6B,0xC8,0x85,0x84,0x21,0xFC,0x6C,0x46,0x36,0xFF,0x1E,0x86,0xD2,0xF8,0x67,0x1D,0x6E,0x43,0x0C,0x46,0x8C,0x86,0x02,0xC2,0x50,0xCE,0xDB,0x0B,0xD7,0x50,0x1B,0x06,0x07,0xD0,0x7A,0x70,0x79,0x55,0xFD,0x53,0xCB,0xE6,0x7F,0xB8,0x0E,0xB9,0x55,0xEC,0x28,0xA9,0x64,0x8B,0x6F,0x13,0x99,0x69,0x78,0x0F,0xA5,0x72,0x54,0x93,0xE1,0x21,0x87,0x53,0x62,0x71,0xF0,0x09,0x4C,0x8C,0x21,0x7D,0xE1,0xF3,0x8D,0xC2,0xDB,0x9F,0xFA,0x7C,0xFC,0x23,0x6F,0xE7,0x98,0x24,0x89,0xD4,0xF6,0x7E,0x60,0x2B,0x67,0x58,0x17,0x9C,0x9C,0xEF,0xDF,0x24,0x5D,0xF4,0x48,0x8F,0xE5,0xD3,0xEC,0x40,0xE8,0xD3,0x8C,0x73,0xAB,0xF3,0x0F,0x5C,0xB3,0xCC,0xCF,0x5E,0x55,0x79,0x0A,0x47,0xB5,0x8D,0x49,0x69,0x92,0xE5,0x6D,0xF6,0x8D,0x55,0x3F,0x58,0xB2,0x58,0x37,0x48,0xD7,0x17,0x88,0xD3,0xF7,0xDD,0x35,0xB4,0x67,0xDB,0xF8,0x35,0xC9,0xD1,0x3A,0xBF,0xDB,0x52,0xC5,0x10,0x8B,0x35,0xEE,0x49,0x72,0xA6,0x8E,0xFE,0xE9,0x5A,0x2D,0xD5,0xE6,0x47,0xD1,0x17,0x97,0xD2,0x18,0xE1,0x74,0xD3,0xE0,0xC3,0xD1,0xF8,0x6A,0x40,0x4F,0xCB,0xB4,0xC6,0x94,0xB4,0x2D,0x8A,0xB5,0xF6,0xF7,0x55,0xE4,0xC5,0x12,0x38,0xF2,0x77,0x5C,0x9C,0x31,0x3D,0x0C,0x45,0xDC,0x3E,0xB2,0x55,0x23,0xC6,0x70,0xB9,0xB4,0x7A,0x4B,0xC3,0x3B,0x64,0x92,0xFD,0x66,0xE4,0x73,0x3B,0x9D,0x36,0xFF,0x82,0x1E,0x7F,0x83,0x7A,0xD5,0x65,0x7E,0x73,0xD5,0xC2,0x50,0xCA,0xBF,0x4C,0x6C,0x02,0x00,0xB5,0xA5,0x0F,0x90,0x1B,0xEC,0xA7,0x38,0x27,0x84,0x87,0x96,0x63,0xE0,0x90,0xD0,0xDC,0x39,0x12,0xF6,0xDA,0xEF,0x75,0x58,0xF2,0x77,0xAB,0x13,0x53,0x6B,0x2C,0x33,0x1B,0x48,0x4D,0xDF,0xAF,0x62,0x92,0x32,0x17,0xD8,0x6B,0x5E,0x5B,0xD9,0xB5,0xD6,0x92,0x50,0x8E,0x81,0x79,0x75,0x31,0x64,0x5B,0xAB,0xC5,0x57,0xCB,0x31,0xF0,0x1D,0xD9,0xC2,0x15,0xB2,0x83,0x75,0x5D,0x13,0x52,0xEC,0xE1,0x99,0x18,0xD5,0xA4,0x99,0x5E,0x97,0xE1,0xCB,0x3B,0xC7,0xDE,0xA5,0x4A,0xFD,0xD7,0x4F,0xD9,0x29,0x28,0x40,0x4F,0xAE,0xD6,0x7C,0xEC,0x63,0x17,0x66,0x72,0xD0,0x3D,0x6B,0x83,0xEF,0xB0,0xC8,0xDD,0x32,0x0A,0xF5,0x09,0xA9,0xF6,0xE9,0xF4,0xE3,0xAB,0x7A,0xF3,0x42,0xFD,0x22,0xE9,0x3D,0x7A,0x92,0x88,0x14,0x0B,0x2B,0xE5,0xBD,0x60,0x67,0x44,0xA5,0x69,0x12,0x6A,0x95,0xF1,0x29,0x26,0x76,0xC8,0xE7,0x5D,0xEE,0xD3,0x95,0xA0,0x17,0xCE,0xB5,0xF0,0x0B,0xC5,0x62,0xD1,0xE4,0x83,0x0B,0x86,0xDE,0xDC,0xF7,0xCB,0x82,0xC7,0x2D,0x95,0xB8,0xA7,0x50,0xCA,0x0B,0x4B,0x07,0x02,0x6A,0xAA,0xEC,0x76,0xD5,0x88,0x03,0xDF,0x2D,0x7B,0x27,0xC5,0x8E,0x41,0x67,0x4E,0xA1,0xAF,0xE7,0x7E,0x43,0x9F,0x2D,0x18,0xFD,0x86,0x6E,0x70,0xDE,0xBD,0xB2,0xFF,0xC8,0x13,0x1B,0xC3,0x63,0x51,0x0F,0x8C,0x0E,0x7B,0xBF,0x57,0xDB,0x57,0xB8,0xFA,0x01,0xD5,0x37,0x77,0xA8,0x6E,0x66,0xB9,0xA4,0xE5,0x3A,0x66,0x5B,0x68,0x68,0xB2,0xF5,0xEC,0xCB,0x3A,0x14,0x0D,0xAE,0xED,0xB4,0x5B,0xE7,0xE1,0xFB,0x7A,0xD8,0x63,0xB9,0x14,0x95,0xAA,0xF5,0x49,0x97,0x98,0xD3,0x57,0x9E,0xAD,0xAE,0xC2,0xA9,0x79,0x51,0x8E,0x21,0x79,0xD1,0xBE,0xA1,0xA6,0x5B,0x8F,0x1F,0x2D,0x5E,0x76,0xE8,0xC1,0xA6,0xDF,0x94,0x7D,0xED,0x0E,0x2C,0xAA,0x4C,0x3B,0x7B,0x2B,0x07,0x89,0xB9,0x9A,0x73,0x79,0xE1,0x29,0xC1,0x72,0x02,0x47,0x67,0xC1,0x5A,0x75,0x42,0xEB,0xFB,0x5B,0xBB,0x06,0x4B,0x0F,0xB2,0x47,0xAE,0x44,0x24,0x4B,0xC7,0x32,0x3A,0x6C,0xEF,0xAA,0x2D,0x13,0xB4,0xAD,0x99,0xAB,0xFB,0xE4,0xE6,0xED,0x93,0xA8,0x03,0x47,0xF3,0xD5,0x74,0xEA,0x75,0x6F,0x72,0x47,0xCA,0x1C,0x2D,0x73,0xD3,0x63,0x1A,0xC7,0x11,0x8E,0x65,0x09,0x05,0x74,0xD3,0x4F,0xB4,0x88,0xD5,0xD1,0x21,0xCB,0x95,0xF0,0xDD,0xE2,0xA6,0xA2,0xFA,0x2C,0x04,0xF3,0xEB,0x0D,0x34,0x43,0xDA,0x70,0xB3,0xCE,0x61,0x10,0x8B,0x73,0x15,0xAD,0xE9,0x37,0x68,0x3F,0x1E,0xB5,0x5D,0xDF,0xC7,0xBC,0x92,0xB5,0xBD,0xC7,0xD1,0x2D,0x6D,0x9B,0x5C,0x9A,0xAD,0x34,0x39,0xE1,0xE1,0x0D,0xF9,0x9D,0x41,0x6F,0x2F,0x21,0x46,0xF5,0x0D,0xB7,0xA7,0x98,0xB5,0x1C,0x34,0x34,0xAD,0xCF,0x89,0xDD,0x75,0x31,0xB1,0xF8,0xE4,0xB4,0x46,0x73,0x66,0x65,0xDE,0x54,0xD0,0xE6,0x91,0x1D,0x2A,0x2E,0x45,0x6C,0xCF,0x00,0xBD,0x0D,0xDD,0x5D,0xBA,0x07,0xF6,0xE7,0x19,0xAF,0x1F,0x45,0x4E,0x0D,0xF5,0x2C,0x4D,0x79,0xB4,0x31,0x2D,0xE6,0x71,0x26,0x40,0x28,0x2B,0x6B,0x4F,0x37,0x0D,0x9A,0x7F,0x2B,0x25,0x66,0x81,0x9A,0x31,0xD8,0x9A,0xFC,0x74,0xC9,0x60,0xE9,0x4A,0x63,0xFB,0x8A,0xFB,0xFC,0x2F,0x6F,0x33,0x7B,0x84,0x85,0x75,0x6A,0xE4,0x78,0x94,0xE8,0xE1,0xFC,0xD2,0x53,0xEC,0x6D,0xC7,0xCC,0x0B,0x48,0x06,0xC3,0xC8,0xDF,0x2C,0x92,0xEC,0x78,0x96,0xEF,0xFA,0x82,0x6E,0xDD,0x44,0x48,0xB1,0x49,0xB0,0x99,0x4A,0xD5,0x80,0xEE,0x5E,0x97,0xB3,0x4E,0x0A,0xA4,0x91,0x5F,0x35,0xE7,0x5D,0x16,0x59,0xC0,0xD6,0xA2,0xBB,0xB5,0xF7,0x6D,0x2F,0x52,0x34,0xB8,0x65,0xEB,0xCB,0xFD,0x6A,0x47,0xB6,0xBC,0xE1,0x11,0x70,0xBB,0x0C,0xC3,0x3B,0x7F,0x52,0x7C,0x29,0x6F,0x22,0x28,0x32,0xCD,0x5F,0xEC,0x48,0xC2,0xB6,0x8C,0xF5,0xEF,0xAF,0x97,0x4B,0x71,0x4A,0xBA,0x89,0xA5,0x6D,0x7E,0xF3,0xB2,0xD3,0xF1,0xAE,0xEB,0x46,0x7A,0x5A,0x42,0x9B,0xC5,0xFC,0xA9,0xE6,0x3D,0x7F,0x1D,0x2E,0x87,0x75,0xD5,0x3F,0xB5,0xD6,0xBE,0xDD,0xFA,0xF7,0xE1,0x12,0x79,0x0A,0xFD,0xA4,0xE3,0x74,0xD9,0x92,0x9B,0x11,0x7D,0x33,0xC5,0x29,0x5D,0xAE,0x77,0xBD,0x70,0x6B,0xA8,0x4E,0x30,0x9D,0x45,0x47,0xEC,0x4E,0xD9,0x1C,0x16,0x94,0x2B,0x06,0x67,0x6F,0x1B,0x09,0x7E,0xE0,0x4D,0x3E,0xB3,0x29,0xED,0x7C,0x4D,0xCE,0xFA,0x6D,0x65,0xB9,0x27,0xAD,0xA3,0xD2,0xF5,0x4E,0xF2,0xA0,0xB6,0xAB,0xD5,0xD1,0xAD,0x15,0x49,0x27,0x02,0x9A,0x8A,0x77,0xA8,0xCF,0x18,0x5D,0xFA,0xFA,0xA9,0xFC,0x1C,0x67,0x04,0xB5,0x71,0x59,0x51,0x68,0x32,0x2C,0xF0,0xC8,0xF6,0xBB,0xA8,0x03,0xAE,0x57,0xBF,0xF5,0xD9,0x71,0xDE,0x48,0x59,0x1F,0xBC,0x62,0xE0,0xC2,0xFD,0x02,0x74,0x5A,0xE2,0x65,0xF1,0xAA,0xA4,0x95,0x74,0x25,0xDE,0xC3,0xD6,0xF5,0x8A,0x1B,0x3B,0x73,0xE2,0x2D,0x6B,0x59,0x57,0x27,0x2F,0x5E,0x8F,0xCC,0xDC,0x34,0x76,0xE5,0xF1,0xFE,0xFA,0x75,0x6B,0xE4,0x07,0x99,0xA2,0xDA,0xB6,0xE3,0xE1,0x0F,0xB6,0xD0,0x1C,0xAF,0xD8,0xED,0x95,0x9E,0x78,0x50,0xD0,0xA3,0xA0,0x3C,0xCF,0x99,0xD7,0xFD,0xF8,0x86,0xC5,0xB6,0x9A,0x97,0x1D,0x71,0x17,0xF4,0x02,0xA3,0x56,0x1B,0x40,0x8E,0x1A,0x58,0x45,0x9C,0x3C,0xB3,0xEB,0x6C,0xAE,0x17,0x93,0xF0,0x45,0x81,0x51,0x35,0x7D,0xA3,0x85,0x93,0x66,0xB2,0x9B,0x3F,0x4F,0x65,0x30,0xF8,0xB4,0x77,0xA8,0xF1,0x1E,0x27,0xD7,0x7C,0xAC,0x51,0x9E,0x2E,0x3E,0xE0,0x78,0xD9,0x8B,0x85,0xB3,0xBC,0xB8,0x9A,0x52,0x3B,0x4C,0xD9,0x5B,0x89,0xF9,0xA6,0x81,0xF9,0xC6,0x0E,0xD6,0x8B,0x96,0x2B,0x2D,0x7C,0x13,0xD1,0x84,0xBC,0x9B,0xB5,0x6A,0xE9,0xE8,0xF5,0x30,0xC7,0xF5,0x33,0xE9,0x1D,0x2E,0xE3,0xC6,0x44,0x45,0xAE,0x13,0x8C,0x1A,0xC8,0xDC,0x76,0xF7,0x75,0xE4,0x3A,0x14,0x44,0x1E,0x50,0x80,0xAC,0x20,0x92,0x99,0x3C,0xA6,0x26,0x43,0x48,0x62,0x90,0x19,0x1C,0x8E,0x26,0x83,0x4B,0xE1,0x70,0x19,0x54,0x1A,0x83,0x4E,0xA2,0x73,0x39,0x24,0x86,0x80,0xAF,0x6A,0x4B,0x53,0xA7,0xEA,0x9A,0x19,0x53,0xD4,0x28,0x0C,0x75,0xB2,0x1A,0x59,0x66,0x4C,0x55,0x27,0x53,0xD4,0xC8,0x14,0x8A,0xA6,0x3D,0x49,0x93,0x46,0xB1,0x67,0xD0,0x18,0x2C,0x0A,0x9D,0x2F,0xD0,0xE4,0xD0,0xD7,0xFD,0x17,0x6C,0x29,0x50,0x32,0x55,0x4B,0x9E,0x4C,0xA1,0xD2,0xE8,0x9A,0x0C,0x26,0x8B,0xB4,0x45,0x47,0x57,0x4F,0xDF,0x40,0x47,0x9E,0xC5,0xE0,0x0B,0xB9,0x02,0x12,0x9F,0x4B,0x61,0xF1,0x38,0x34,0x01,0xCD,0x08,0x62,0x81,0x32,0xA1,0x90,0xC8,0xE4,0x6D,0x14,0xDD,0x1D,0x28,0x2E,0xC9,0x46,0xE0,0x76,0x50,0x44,0xFC,0xF6,0x42,0xE3,0x13,0xDD,0xDD,0x88,0xE6,0x07,0x39,0x2E,0xB2,0x97,0x91,0x2B,0xD1,0x4A,0xC0,0x73,0x72,0x73,0x77,0x71,0x77,0x74,0x16,0x88,0xD6,0x11,0xB7,0xBA,0xF1,0x88,0x96,0x26,0x4C,0x2A,0x9D,0xB4,0x8F,0x2B,0xF4,0x20,0x72,0x44,0xCE,0xAE,0x7C,0xA2,0xE0,0x90,0x97,0xC8,0xCB,0xD3,0x95,0xC8,0x11,0x88,0x88,0x1E,0xAE,0x07,0x5D,0x5C,0x88,0x22,0x27,0x0E,0xF9,0xDB,0x86,0x42,0xE4,0x79,0xF2,0xA8,0x14,0x22,0xC7,0xCB,0xDD,0xD5,0x99,0x27,0x22,0x0A,0x3D,0x9C,0x7E,0x3A,0xC9,0xF6,0x3C,0x8F,0x83,0xCE,0xFC,0x1F,0x47,0x9E,0x7C,0x57,0xA2,0x8B,0x27,0xCF,0x83,0x47,0xE4,0xF3,0x3C,0xDC,0x7F,0x9A,0xF0,0x3D,0x3C,0x21,0x47,0xF1,0x1B,0x0E,0xBA,0xED,0x77,0x73,0x3F,0xEC,0x46,0x94,0xBD,0xFE,0xF8,0x9B,0xFC,0x81,0x39,0x24,0x8A,0x16,0x89,0xF4,0xD7,0x5F,0x18,0x80,0x7D,0x59,0x9A,0x3B,0x70,0xEE,0xE6,0x50,0xE6,0x8D,0x81,0xB0,0xCB,0x31,0x00,0xE4,0x2C,0x60,0xB4,0xC3,0x99,0x23,0x43,0x6A,0x1C,0xFA,0x96,0xD5,0x8F,0xAD,0x16,0x99,0xAA,0x61,0xB5,0xCD,0x9C,0xAC,0x4E,0xA1,0x90,0x98,0x14,0x96,0x3A,0x89,0x44,0xD1,0xB0,0x21,0xD3,0xD4,0x49,0xEA,0x64,0xB2,0x6C,0x63,0xB5,0x4D,0x47,0xD7,0x74,0x87,0x89,0xD6,0x41,0x91,0xC0,0x53,0xC3,0x53,0xE0,0x22,0x90,0x55,0x42,0x6D,0xBF,0xC0,0x5B,0x94,0x0A,0x20,0xBE,0xFB,0x67,0x03,0xC8,0x9F,0x52,0x0A,0x01,0xF0,0x47,0xF8,0xF2,0x9F,0x97,0x6A,0x01,0xF8,0x01,0x59,0xB1,0xEE,0xFE,0x3C,0x7C,0xF8,0xEB,0x7A,0x17,0x00,0xE9,0x03,0xE0,0x87,0x9D,0x85,0xCE,0xAF,0x00,0xC8,0x18,0x00,0x99,0x04,0x20,0xFE,0x50,0xFC,0xFF,0x39,0xB9,0x08,0x83,0x82,0x03,0x95,0x79,0x2F,0xAB,0x52,0x62,0xA0,0x4B,0x7E,0xCC,0x4D,0xBE,0x2B,0x20,0xFD,0x6D,0x0E,0x72,0x16,0xBA,0x8A,0xCF,0x71,0x39,0xE4,0xBC,0x5F,0x5D,0xE4,0x2D,0xF2,0x12,0xB8,0xAA,0xEB,0xC9,0x24,0x3A,0x72,0xBC,0x04,0xC6,0x1C,0x91,0x97,0xAE,0x0B,0x47,0x24,0x32,0x76,0xE7,0xF0,0x05,0x9E,0x05,0xD0,0x90,0xA7,0x91,0x73,0x1B,0xA1,0x90,0x87,0x50,0xA2,0x26,0x97,0xAC,0xC9,0x64,0xF2,0x34,0x39,0x34,0x06,0x9F,0xC6,0x24,0x73,0x48,0x34,0x2E,0x53,0x36,0x1E,0x29,0x64,0x3A,0x8D,0xA3,0x49,0xE2,0xF2,0xBB,0xA0,0x68,0xD2,0x11,0x0A,0x93,0x44,0xA2,0xC9,0x86,0x66,0x1F,0x14,0x20,0x0D,0x43,0xF1,0x64,0x16,0x45,0x5D,0xE6,0xA5,0x4E,0x25,0xAB,0x93,0x19,0xAC,0x71,0x28,0xE2,0xA8,0x93,0xBD,0xAE,0xE9,0x24,0x14,0x22,0x86,0x01,0x12,0x18,0x90,0x00,0x83,0x5C,0x86,0x01,0x05,0x30,0x48,0x39,0xEC,0x6F,0x02,0xD5,0x45,0x1E,0x32,0x15,0x4E,0xEA,0x96,0xDF,0x77,0x6C,0x0E,0x6F,0xFF,0x56,0x37,0xD9,0xA8,0x38,0xE8,0x2A,0xBB,0xCC,0xF1,0x72,0x76,0x77,0xAB,0x85,0x2D,0xE4,0xB8,0xF1,0x3D,0xDD,0x9D,0xF9,0xEA,0xEE,0x22,0x75,0x1D,0x67,0x37,0x99,0x5A,0x33,0x4F,0xF7,0x23,0xDE,0x77,0x61,0x7A,0x7F,0x0F,0x25,0x70,0x13,0x39,0x7B,0x39,0x1F,0x12,0xA8,0xEB,0xBA,0xBB,0xC9,0xCE,0x7B,0xC9,0xEC,0x0E,0x39,0xCB,0xEC,0xD9,0xEE,0xEE,0xFB,0x05,0x9E,0x2B,0xBF,0xED,0xB6,0xBA,0x1D,0x72,0xE7,0x7D,0x0F,0xCC,0x96,0x85,0x75,0x11,0x78,0xB6,0xC0,0x20,0x1D,0x30,0x48,0x1F,0x0C,0x32,0x0C,0x83,0x91,0xD7,0x91,0xC6,0x61,0x50,0x9E,0x9B,0x14,0x86,0xA0,0x69,0xCA,0x3A,0xDA,0x1F,0x4E,0x24,0xFD,0x6C,0x64,0x12,0x85,0xC9,0x23,0x09,0xC8,0x02,0x06,0x49,0x28,0x10,0x90,0x34,0x19,0x02,0x12,0x45,0xC0,0x12,0x32,0xC2,0xE0,0x27,0x8C,0x9D,0xDD,0x0E,0x1E,0x39,0xE6,0x22,0x0B,0xEB,0xE2,0xE4,0x2E,0xF2,0x3A,0x46,0x57,0xA7,0xA9,0x53,0xA8,0x54,0xB5,0x03,0x8E,0xFB,0x9D,0xD5,0x1C,0xB9,0x5C,0x06,0x89,0xC7,0x17,0xD0,0x34,0x99,0x2C,0xC6,0x31,0x65,0xB2,0xEC,0x36,0x30,0x23,0x9A,0x59,0xE8,0xEB,0x9B,0x98,0x59,0x11,0xAD,0x0E,0x0A,0x88,0x7A,0x02,0x1E,0x91,0xA2,0x49,0x24,0x31,0xB5,0x28,0x4C,0x2D,0x2A,0x8D,0x68,0x6D,0xA5,0x4B,0xA4,0x90,0x28,0x54,0xA2,0x90,0x22,0x14,0xA9,0x39,0xC9,0x8A,0xA2,0x45,0x16,0x50,0x58,0x34,0x96,0x90,0x4B,0x61,0x1E,0xE3,0x70,0x3C,0x79,0x4E,0x9A,0xB4,0x1F,0x34,0xBE,0xBB,0x2B,0xC7,0xD9,0x4D,0x02,0x87,0x25,0xC3,0xF1,0x97,0xE1,0x65,0x7D,0x9A,0x05,0xF0,0x15,0xA5,0xF0,0x8C,0x33,0x8D,0xD1,0xF0,0x5A,0x38,0x91,0xC7,0xA7,0x0A,0x85,0x5C,0x19,0x97,0xCF,0xA3,0xB2,0x78,0xB2,0x47,0x08,0x87,0xC7,0x61,0x6A,0x52,0x49,0x02,0x1A,0x9F,0xC7,0xA7,0x33,0xC9,0x77,0xE1,0x44,0x16,0x4B,0xC8,0x63,0x68,0x32,0x69,0x0C,0x0E,0x5D,0xD6,0xC5,0x7C,0xBA,0x40,0xF6,0x34,0xE0,0x90,0x04,0x02,0x21,0x9D,0x25,0x20,0x33,0x85,0x8C,0x87,0x70,0x22,0x8D,0xC2,0xA1,0xB3,0x18,0x9A,0x34,0xA1,0x26,0x9F,0xC7,0x62,0xF1,0x85,0x34,0x9E,0x6C,0x48,0x70,0x59,0x02,0x2A,0x89,0x4C,0x23,0xF1,0x04,0xDC,0x2E,0x38,0xA4,0x0F,0x8E,0x20,0x93,0xA8,0x14,0xCD,0x71,0xF8,0x21,0x3A,0x59,0x93,0x44,0x27,0xC9,0xC6,0x02,0x93,0x4E,0x67,0x7D,0x6B,0x0C,0xED,0x6F,0xC5,0x13,0xF2,0x49,0xCC,0x5F,0x85,0x3C,0x46,0xE7,0x31,0x99,0x74,0x8E,0xEC,0x6E,0xA2,0x71,0x19,0x74,0x1E,0x9D,0xCE,0xE3,0x08,0x39,0x24,0x4D,0xA1,0x2C,0x26,0x93,0xC9,0x65,0x72,0xF8,0xDA,0xA4,0xBF,0xB5,0x63,0x0C,0x9A,0x80,0x42,0x16,0x92,0xC9,0x54,0x21,0x9D,0x2B,0x64,0x92,0x78,0x2C,0x0E,0x43,0xC6,0xA6,0x30,0x38,0x9A,0x14,0x1A,0x8D,0xCA,0xE4,0x4B,0xE1,0xF2,0x14,0x32,0x99,0x2F,0xE4,0x51,0xA8,0x7C,0x99,0x4E,0x2E,0x55,0x48,0x16,0x23,0x20,0x09,0x88,0x88,0x8A,0xA7,0xB5,0x60,0x2A,0xA2,0x1D,0xD0,0xB3,0xD3,0x07,0x40,0x08,0x04,0x02,0xB2,0x5D,0xA2,0x9B,0xFA,0x67,0x67,0xD9,0x50,0x4C,0x2E,0x08,0xC1,0xCC,0x07,0x91,0x84,0x78,0x10,0x4A,0x70,0x05,0x41,0xB4,0x3F,0x08,0xA2,0xCC,0xD9,0x08,0xD4,0x5B,0x36,0x0C,0xFD,0x8C,0x0D,0x10,0x16,0x82,0x48,0x39,0x2D,0x10,0x8E,0x29,0x03,0xA1,0x98,0x6A,0x10,0x24,0xE4,0x83,0x30,0x8C,0x02,0x1B,0x4A,0x88,0x60,0x23,0x71,0xBE,0x6C,0x18,0x2A,0x97,0x0D,0x62,0x3F,0xB0,0x11,0xF8,0x87,0x20,0x0C,0xDB,0x27,0xFB,0x1B,0xC8,0x62,0xDE,0x65,0x83,0x78,0x1E,0x08,0x45,0x9B,0xCA,0xFC,0x46,0xD8,0x70,0xCC,0x5C,0x10,0x8E,0x6E,0x92,0xD9,0x4C,0x83,0x00,0x76,0x33,0x1B,0x89,0x2F,0x01,0x11,0xF8,0xAD,0x32,0xA6,0x05,0x1B,0x89,0xBD,0xC4,0x86,0xE0,0x6E,0x83,0x70,0xBC,0x09,0x1B,0xC0,0x3E,0x00,0x91,0xF8,0x3B,0x6C,0x28,0xD6,0x8D,0x8D,0x24,0x34,0xCB,0x78,0x9F,0x41,0x08,0xCE,0x9F,0x8D,0x94,0x1B,0x64,0x43,0xE5,0xDA,0x65,0xB1,0xF6,0x83,0x08,0x8C,0x0A,0x1B,0xC0,0xB7,0x81,0x30,0x82,0x3B,0x08,0x43,0xBF,0xEB,0xBF,0xF8,0x1C,0x92,0x8D,0x10,0x03,0x7B,0x90,0x56,0xB6,0x70,0x08,0x00,0xEE,0xC1,0x9B,0x61,0x77,0x40,0xCD,0x77,0x69,0x6E,0xA4,0xBA,0xAC,0x17,0xF2,0x36,0x30,0x1D,0x1D,0xE8,0x74,0x47,0x2E,0xDF,0x06,0xDC,0x61,0xB1,0x1B,0x6B,0x01,0xB7,0xB0,0xB4,0x06,0xF1,0x80,0x19,0x08,0x31,0xB7,0xB1,0x00,0xCC,0x2D,0xAC,0xAC,0xAD,0xEC,0xCD,0xB0,0x70,0x24,0xDC,0x0A,0x65,0x63,0x8E,0x46,0x58,0xD9,0xB8,0xBA,0x6A,0x6D,0x74,0x14,0xF0,0x85,0x64,0x81,0x50,0x93,0xC5,0xA0,0x73,0xF7,0xC0,0x00,0xC0,0xCC,0xCC,0x06,0xE1,0xBA,0xCF,0xC1,0x71,0xBD,0x03,0x9D,0xCF,0x92,0x0D,0x01,0x3E,0x4F,0x40,0xA6,0x70,0x18,0x14,0x21,0x9F,0x25,0x10,0x70,0xE9,0x7C,0x32,0x8B,0xA9,0x59,0x80,0xB8,0xFC,0x51,0xAD,0x1A,0x31,0xFD,0xED,0x33,0xA9,0x11,0x31,0x3D,0xA0,0xD6,0x82,0x68,0x9A,0xCC,0xCF,0x25,0x74,0x21,0x88,0x88,0x18,0xF5,0xCF,0xC7,0x94,0x73,0xBB,0x2A,0xCE,0x14,0x96,0x0E,0xC7,0x87,0xF1,0x87,0x42,0x49,0x5B,0xD2,0x72,0x1E,0x3D,0xF1,0x9B,0x36,0x4F,0x5C,0xEC,0x02,0x79,0xD1,0x8B,0x68,0x9B,0xAC,0xB8,0x89,0x1A,0x46,0xAC,0x5A,0x31,0xAB,0x68,0xA8,0xD3,0x00,0x79,0xB0,0xC0,0xBF,0x56,0x65,0x7B,0x88,0xFC,0x02,0x86,0xFF,0x1A,0xFB,0xBA,0x79,0xBD,0x46,0x5B,0x17,0x05,0x3B,0xE3,0x07,0x4D,0x56,0x9F,0xC8,0x64,0x5B,0xFA,0x8C,0x21,0x6A,0xA7,0xDB,0xD1,0x52,0x04,0xD1,0xF2,0x2B,0xEF,0x72,0x49,0xED,0xBB,0x15,0xE7,0x42,0x3E,0x24,0x78,0xB4,0x04,0xF5,0xDF,0x6C,0x72,0xD0,0xDB,0x76,0xFB,0x74,0xC3,0xC7,0xC5,0x0B,0xEC,0xCE,0x4F,0xCC,0x1F,0x12,0x83,0xE5,0x15,0xFE,0x6F,0xD1,0x61,0xA0,0xC6,0xFB,0x47,0x08,0xA5,0x2B,0xAE,0x0E,0xAA,0x2F,0x5F,0xEB,0x39,0x3F,0xA1,0xD9,0x7A,0x1B,0x6E,0x50,0xB2,0xA7,0x0F,0x2F,0xEE,0xA9,0xA3,0xBF,0x7B,0xA7,0xB0,0xFD,0x09,0x79,0xFD,0xD3,0xDF,0x8E,0x2F,0x1A,0x8C,0xAC,0xD1,0xD3,0xF6,0x6A,0xE8,0x5C,0xBA,0x56,0x02,0x7E,0xE9,0xCC,0x7B,0x0D,0x9C,0x05,0x17,0x76,0xB6,0xD2,0x4D,0xCE,0xE5,0x48,0x3C,0x5D,0xB3,0x02,0xF6,0x86,0x32,0xAD,0xAE,0x2D,0x58,0x30,0x8A,0xBC,0x39,0x93,0x0C,0xF6,0x96,0xA7,0xDC,0x81,0x65,0x83,0x7A,0x37,0x9A,0x09,0xF9,0x7E,0x70,0xF6,0xF0,0x76,0x93,0x01,0x67,0x9F,0x8C,0x56,0x9F,0xA4,0x15,0xB8,0x65,0x99,0x00,0x34,0x55,0x57,0xA9,0x53,0x6F,0xD1,0xB4,0x77,0xD1,0x16,0x1E,0x69,0x51,0xA5,0xCD,0xC2,0x32,0x5E,0xC0,0x8E,0xEC,0x93,0xDD,0x20,0x74,0x7B,0xAB,0x5D,0x46,0x49,0x92,0x18,0x67,0x2C,0xD0,0x13,0xAD,0xA2,0xEC,0x35,0xCA,0xB8,0xA5,0xF1,0xBC,0x00,0x1C,0x0F,0xB9,0xFB,0x19,0x75,0x17,0x24,0xFA,0x8E,0x38,0x3F,0x28,0xD1,0x91,0x54,0x19,0x83,0x0D,0x6A,0x6A,0x01,0xBB,0x05,0xB3,0x85,0x1B,0x75,0x3F,0x3C,0xAA,0x89,0x82,0x24,0x3C,0xF1,0x36,0xC8,0x52,0x70,0x68,0x01,0xE3,0x7A,0xAF,0x3D,0x25,0x74,0x81,0x44,0xCD,0x78,0xCA,0x85,0x95,0x0C,0xD7,0x90,0xF3,0x21,0x19,0x0A,0x1B,0xC2,0xC2,0x4B,0x5E,0x35,0x98,0xA1,0x2A,0x6B,0x4E,0x3F,0xF9,0xBC,0xC7,0xBA,0xF3,0x5C,0xA5,0xFE,0x48,0x2F,0x98,0x33,0x9A,0x3F,0x0C,0x1B,0x06,0x89,0xBC,0x1B,0xEB,0xB6,0x1A,0xFC,0x1E,0x74,0xBD,0xDD,0xBA,0x2D,0xC2,0x38,0x16,0x51,0x62,0xD6,0xCF,0x9A,0x17,0xAE,0x5B,0xB0,0xF8,0x20,0x00,0x4E,0x26,0x34,0xEE,0xA6,0x8F,0x81,0xD2,0xE0,0xD4,0x8B,0x08,0x29,0x08,0x11,0x23,0x21,0x61,0xC8,0x43,0x99,0xD7,0x1D,0x5A,0x02,0xAD,0xE9,0x43,0x77,0x9A,0x24,0x9D,0xA4,0x34,0xC4,0xDB,0x99,0x45,0xCE,0x0F,0xC3,0xCD,0x63,0x9B,0xAF,0x35,0x2A,0x95,0xDE,0x29,0x73,0x11,0x6E,0x32,0xFE,0xA8,0x24,0x7C,0x53,0x7B,0x07,0x52,0x6C,0xBA,0xDC,0x74,0xC9,0x11,0xF0,0xC4,0x95,0xBC,0xF0,0x6A,0xB0,0xF4,0xFE,0xBD,0x38,0x47,0x0F,0xE5,0xA4,0x90,0x65,0xD2,0x98,0x0D,0x7E,0xED,0x16,0xE9,0x0D,0xEC,0x7B,0x0F,0x13,0x58,0xD9,0xD8,0x81,0x69,0xEA,0xC1,0xB9,0x57,0xAC,0x2C,0x6F,0xD0,0x2E,0x24,0x4D,0xDE,0x1D,0x75,0x75,0x74,0xDC,0xF3,0xC2,0xF6,0x90,0x4F,0xFC,0x9D,0xB8,0x8F,0x5D,0x1C,0x13,0x05,0x6F,0xB8,0x72,0xDE,0xB5,0xF8,0x58,0x89,0x04,0x39,0x36,0x72,0xF3,0x2B,0x90,0x80,0x9C,0x0E,0x42,0x27,0x23,0x13,0xCC,0x2E,0x23,0xA7,0x24,0xE1,0xA8,0x42,0xA4,0xF5,0xCB,0x17,0x2C,0x8D,0xFD,0x97,0x2F,0x1D,0x9D,0xD8,0xB4,0xE0,0x8D,0x3F,0x5F,0x4E,0x7E,0x74,0xA9,0x65,0x5B,0x5D,0x53,0xCF,0x6C,0x28,0x79,0x76,0xD5,0x06,0xFE,0x4B,0x3E,0x21,0x23,0x2D,0x01,0x04,0xEF,0x55,0x07,0x6D,0x61,0xE8,0x2B,0x9D,0x11,0x3F,0xD7,0x6F,0x5E,0x7E,0x3F,0xFC,0x7A,0xCC,0x93,0xD2,0x93,0xF0,0x65,0x99,0xE1,0x87,0x87,0x27,0x92,0x77,0x6C,0x46,0x2F,0x79,0x3F,0x99,0x5E,0xFA,0x60,0x7D,0xCD,0xE6,0xBD,0xF4,0x79,0xC6,0x78,0x8B,0x8F,0xA5,0xC8,0xB8,0x7B,0x11,0x2F,0xC0,0x5A,0xA4,0x75,0xF4,0x1B,0x6A,0x4D,0x85,0x5F,0x44,0xED,0x95,0xC4,0x12,0xCC,0x97,0x2F,0xE1,0x31,0x80,0xB3,0x5D,0xE7,0xB1,0xA5,0x9F,0x9F,0x38,0xBB,0xEF,0x08,0xAA,0x54,0xF2,0x1E,0x44,0xB0,0x1F,0xC7,0xA8,0x57,0x2E,0x79,0xBD,0x2A,0xC5,0xB9,0xEF,0xC2,0xFC,0x29,0x9D,0xED,0xB7,0x9B,0x4B,0x53,0x93,0x54,0x21,0x4A,0x2A,0x2F,0x75,0xB5,0xE4,0x26,0xA2,0xC5,0xD9,0x16,0xAD,0xDD,0x94,0x4E,0xED,0x29,0x25,0xB7,0xA7,0xE5,0xA9,0xCF,0xAE,0xCF,0xB0,0xE0,0x3B,0xC4,0x8D,0xC8,0xD3,0x03,0xA1,0xAF,0x71,0x1D,0x48,0x48,0x1F,0x72,0xF5,0x89,0xF7,0x4B,0xD2,0xAA,0x4D,0x4B,0xEF,0x46,0xF1,0x32,0x73,0xDC,0xE6,0x75,0xAF,0x0C,0x29,0xA7,0x6E,0x59,0x5D,0x72,0x3E,0xB5,0xDA,0xFE,0xB2,0x1C,0x7D,0xA0,0xB1,0xC2,0x1C,0x2A,0x4F,0x3E,0x6C,0x70,0xEB,0x15,0x72,0x3A,0x30,0xA0,0x05,0x9C,0x44,0x5E,0x8E,0xBC,0xDA,0x8B,0x17,0xA3,0x22,0x4E,0x7E,0x10,0x49,0x50,0x05,0x55,0xF7,0x3F,0x20,0x93,0x51,0x90,0xCB,0x28,0x71,0x44,0x42,0x2F,0xA6,0x1A,0x15,0x6C,0xD6,0x81,0x12,0x8B,0x4F,0x65,0x2D,0xED,0x45,0x89,0x4F,0xBB,0xBD,0x42,0xF5,0x66,0xCE,0x2D,0x97,0xB3,0x1D,0x4E,0x78,0x7C,0xF6,0x73,0x0F,0x06,0xA7,0xCD,0x3C,0x54,0xF2,0x9B,0x20,0x51,0xDF,0xD7,0x51,0xB5,0xB1,0xD5,0x06,0x6F,0x7B,0xBB,0xBA,0x72,0x37,0xEF,0x73,0xE9,0x27,0x71,0x4F,0xCA,0x6E,0xD5,0x95,0x71,0x2F,0x07,0xEC,0x81,0x05,0xD5,0x7D,0x6A,0x2D,0xD1,0x0B,0xD8,0xB6,0xAF,0xD0,0x19,0xD2,0xCD,0xE4,0xC5,0xB9,0xB3,0x7B,0x58,0xF4,0x0F,0xA7,0x7B,0xF6,0x3E,0x3E,0xF2,0xEC,0xE9,0xAE,0x2F,0x87,0x28,0x73,0x4E,0x9C,0x37,0xD2,0xF0,0xA4,0xF4,0xF6,0x0D,0x24,0x56,0xCB,0x7D,0x7D,0xF6,0xA4,0x09,0x19,0x83,0x5E,0x56,0x16,0xFB,0x3A,0x3D,0x97,0x68,0x35,0xF6,0xD5,0xF8,0x49,0xED,0xD8,0x25,0xCB,0xC8,0x48,0xC5,0x35,0x23,0xC7,0xBD,0x3F,0x98,0x8E,0x1C,0xBD,0x93,0x9F,0x98,0x80,0xEE,0x6D,0x0E,0x09,0x46,0x24,0xA3,0x67,0x7F,0x35,0xA0,0x10,0x8D,0xCD,0x29,0x7B,0x3B,0xDF,0x5E,0xD5,0xFA,0xBD,0xA3,0x96,0x7E,0x42,0x29,0x3A,0x6F,0x42,0x5A,0x06,0x54,0xA3,0xA1,0x8D,0xE8,0xA5,0x2D,0xE8,0x9A,0xE6,0x95,0xAF,0xD0,0x89,0x55,0xAD,0xF1,0x98,0x31,0x74,0x63,0x5F,0xC5,0x18,0x5A,0x8A,0xC6,0x33,0xFA,0x82,0x9A,0x0A,0x0A,0x1D,0x8E,0x84,0xC6,0x19,0x2E,0xC7,0x2B,0x8B,0x31,0x8F,0x83,0x32,0xFC,0x30,0x27,0x31,0xD7,0xAB,0x3E,0x4A,0x10,0x12,0x4C,0xEE,0xCB,0xCA,0x38,0x6C,0x35,0xA6,0xB0,0x2C,0x2C,0x1F,0xDD,0x88,0x69,0x93,0x64,0xBE,0x44,0xB5,0x60,0xBA,0xBA,0x92,0x24,0x40,0x07,0x26,0x25,0x3A,0xFD,0x23,0xB2,0x17,0x13,0x7A,0xA7,0x39,0x17,0x2F,0xC5,0x40,0xC4,0x58,0x48,0x18,0x16,0x22,0xC1,0x42,0x92,0xB1,0x90,0x6C,0xEC,0x72,0x85,0x37,0x69,0x59,0x89,0x01,0x11,0xE6,0x6E,0xED,0x7D,0x0B,0xBF,0x8A,0xBB,0x2F,0xBC,0x3B,0xEF,0xDA,0x89,0x65,0x0D,0x58,0x0C,0xAF,0xA9,0x26,0xDC,0xF4,0x41,0x97,0x90,0x0A,0xB0,0x29,0xA7,0x27,0x6E,0xA1,0x6B,0xB1,0x2B,0x29,0x43,0x8A,0xE6,0xD7,0x57,0x2C,0xC8,0x0C,0xB4,0xBD,0x9D,0x28,0x17,0x6E,0x38,0xBC,0x72,0x8A,0x6F,0xE3,0xC3,0xBB,0x44,0x38,0x2C,0x79,0xFC,0x2E,0x3A,0x6A,0x29,0x73,0x67,0xBA,0xEB,0xA2,0x46,0xEC,0x9D,0xDC,0xCB,0x2B,0x5A,0xB0,0x90,0x5E,0x6C,0xE1,0xD3,0x84,0x33,0xF8,0x57,0xD8,0x93,0x67,0x02,0x6A,0x08,0x62,0xDC,0xA3,0xAC,0x4B,0x9D,0x98,0x30,0xDC,0x3D,0x68,0x49,0x80,0x4F,0x5D,0x29,0x2D,0xD1,0x30,0x2B,0x32,0xA5,0x67,0x3A,0xBD,0x36,0xE3,0x3C,0x9C,0x3C,0x67,0x09,0x56,0x77,0x35,0xE3,0xA8,0xE9,0xB9,0xA6,0x13,0xF4,0x8C,0x65,0x4E,0xF5,0x3A,0xCF,0xCF,0x45,0x25,0x66,0x7A,0x69,0x7C,0x08,0xB6,0x29,0x43,0x2B,0x5F,0x3D,0xD7,0xF1,0x62,0xAF,0xDC,0x69,0xE3,0xC2,0xF7,0x71,0xAB,0x0C,0xCF,0x3C,0x15,0x17,0xED,0xAA,0x2B,0x0D,0xCC,0xCD,0xF4,0x4D,0xE2,0x74,0x54,0xA4,0x3F,0x1B,0x4D,0x78,0x39,0x31,0xB0,0x24,0x22,0x40,0xF7,0x1A,0x4B,0x7B,0x5B,0xD2,0x01,0x62,0x1A,0x19,0xA8,0x5D,0x4D,0x08,0x1F,0x59,0xC3,0xB9,0xB4,0x39,0xAD,0xC1,0xAA,0x54,0x4E,0x39,0x37,0xAF,0x1A,0xD8,0xBE,0x91,0xBE,0x3D,0xB9,0x20,0x68,0xA3,0x61,0x7C,0xF7,0x23,0xE9,0x89,0x02,0x45,0xF3,0x04,0x65,0xD6,0xBD,0x8F,0xF6,0x15,0x53,0x7E,0x53,0xA7,0x15,0x17,0x1C,0x59,0xAB,0x62,0x90,0xE9,0xF5,0xA9,0x13,0xD7,0x72,0xFC,0x58,0xF6,0x9C,0x0D,0x87,0x0D,0x47,0xD7,0x87,0xB1,0x04,0xB4,0x8A,0x81,0x10,0x33,0x29,0x80,0xB9,0x9A,0x96,0x9C,0x3E,0xDA,0xBD,0xF2,0xDE,0xA5,0x83,0xB6,0x42,0xC5,0x16,0x09,0xE9,0xF3,0x8A,0xF7,0x72,0x25,0x89,0xD4,0x1B,0x91,0x9C,0x25,0xB3,0x19,0x4F,0x33,0xDE,0x62,0xB7,0xC8,0xFB,0x30,0x3F,0xB4,0x7D,0x5A,0x83,0x8E,0x08,0x33,0x3C,0xFA,0x19,0xEE,0x72,0xD1,0xD7,0x27,0xCC,0x6D,0xCD,0xA5,0x43,0x9B,0x79,0x0D,0x5B,0xCB,0xE4,0xC1,0x0B,0xF5,0x39,0xF3,0x93,0x72,0x2E,0xD9,0x73,0xD2,0xF5,0x57,0x23,0xAF,0xDD,0xAB,0x08,0x81,0x4D,0x36,0xAE,0x6A,0xE4,0x7A,0x13,0x94,0x93,0x66,0x52,0x9A,0x32,0x3E,0x7A,0x6D,0xC9,0xF1,0x49,0xEC,0xD7,0x25,0x4F,0x25,0xDE,0x79,0x2C,0x72,0x8D,0xC6,0xED,0xAE,0xB7,0xEF,0x3E,0x37,0xBB,0xC3,0xA1,0x78,0x7A,0xF9,0x43,0xFD,0x72,0xD4,0xE1,0x92,0xC2,0x40,0xC4,0x36,0xB5,0x38,0xA5,0x75,0x45,0xD6,0xEB,0xB0,0x12,0x49,0xCE,0xF3,0x5D,0x63,0xA5,0x06,0x4E,0xF1,0x9B,0xD9,0xDC,0x5D,0x12,0xDC,0x70,0xDE,0x8B,0x44,0xD4,0x59,0x1C,0x71,0xB6,0x32,0xCD,0xF7,0x8C,0x24,0x71,0x7A,0xBE,0x9D,0x03,0x91,0x9D,0x55,0x83,0x74,0x13,0x2D,0xBD,0x17,0x64,0x20,0xEC,0x57,0xB4,0xBA,0xB8,0xCD,0xFB,0xC1,0xA6,0xEC,0x64,0x5C,0xF1,0x44,0xFA,0x45,0x58,0x21,0x4E,0x9E,0x43,0x15,0x72,0xB8,0x42,0x06,0x4B,0x48,0xA7,0x52,0x85,0x2C,0x2A,0xA3,0x1A,0x07,0x6D,0xC4,0xD5,0x0C,0x94,0x7D,0x41,0xB4,0xE0,0x82,0x9A,0x4F,0x8D,0xA0,0x3A,0x70,0xB7,0xCA,0x72,0x1B,0x90,0xBD,0xB8,0xEB,0xE2,0x0F,0xC1,0xE0,0x24,0xAE,0x35,0xB3,0xF8,0x74,0x47,0xF8,0x44,0x59,0x04,0x20,0xC6,0xB7,0x04,0x3C,0x2F,0xC0,0x85,0xE1,0x11,0x3A,0x27,0xE3,0x99,0x42,0x09,0x7E,0xEC,0x4E,0xFA,0xDE,0xB3,0x78,0x39,0xBD,0x2B,0x31,0x12,0xEF,0xA1,0x99,0x76,0x93,0x64,0x7C,0x58,0x74,0x75,0x05,0x26,0x1B,0x0F,0x56,0xE7,0x57,0xDC,0x1A,0x38,0x5F,0x80,0xBF,0xE6,0x27,0xAD,0x40,0x96,0xE2,0xCB,0x72,0x13,0x25,0x1D,0x37,0x0A,0xF2,0x4F,0x01,0xD5,0xF8,0x8E,0xB0,0x9A,0x27,0x88,0x46,0xFC,0xF3,0xF3,0x33,0x63,0xA8,0x16,0xFC,0x87,0xD0,0xE2,0x74,0x68,0x07,0xFE,0x43,0xDA,0x55,0x29,0xBA,0x17,0xFF,0xB5,0x55,0xFA,0x00,0xFA,0x0A,0x3F,0x91,0x7A,0xBD,0x1C,0x31,0x86,0xEF,0x3F,0x37,0xFD,0x08,0x2F,0xC5,0x43,0xC4,0x04,0xC8,0x49,0x42,0x5B,0x67,0xEB,0x2C,0x42,0x42,0xE8,0x0E,0xAC,0x11,0xE3,0x12,0x08,0x90,0x71,0x64,0x2D,0x6E,0x27,0xF1,0x42,0xBD,0x68,0xA1,0xFB,0xE9,0x23,0x49,0xAB,0x76,0xBF,0x64,0x3D,0xEF,0x0D,0x11,0xF8,0x60,0xE7,0xEB,0x17,0xDD,0xF5,0x44,0x6E,0xA1,0x18,0xEF,0xDC,0xB6,0x67,0xDD,0xB0,0xC3,0xF3,0xFE,0xE0,0x69,0xEC,0x3E,0xE2,0x95,0xA7,0xC7,0x4F,0x15,0xDC,0x0E,0x92,0xDA,0x61,0x63,0x72,0xD4,0xA4,0x00,0x75,0x56,0xD5,0xDA,0xB4,0x6D,0x00,0x94,0xB6,0xDB,0xF5,0x94,0xB3,0x2F,0xBB,0xB2,0x3C,0x9E,0x4D,0xCE,0x4C,0xA3,0x8F,0x12,0x5B,0x4E,0xD3,0xD2,0xE5,0x12,0xF4,0x6D,0xAB,0x46,0xE5,0xB1,0xC5,0x44,0xF3,0x97,0x17,0x8C,0x0D,0x0C,0xD6,0x47,0xEC,0x1A,0x25,0xBE,0x39,0x7E,0xF4,0x1C,0xBD,0xCA,0x51,0x0C,0xA4,0xC6,0x45,0x14,0x80,0x61,0x00,0xF1,0x69,0xAD,0x32,0xCC,0xF3,0xD1,0x85,0xEC,0x39,0xCD,0xE4,0xF5,0xA8,0x4B,0x0F,0x1D,0xD6,0x2F,0x41,0xEC,0xF9,0x90,0x6A,0xB3,0x22,0x3E,0x70,0xE9,0x12,0x93,0x67,0xA4,0x57,0x12,0xE0,0x5A,0xF0,0xC7,0x41,0xEC,0x59,0x00,0x4B,0x8E,0xF3,0xBD,0x57,0x11,0x85,0xBB,0xBE,0x66,0xE5,0x98,0x7D,0x32,0x70,0x6E,0x2A,0x76,0x41,0x36,0x80,0x45,0x07,0xB9,0x74,0x99,0x35,0xEB,0x8F,0x26,0xAC,0x6E,0xDD,0x54,0x00,0xBC,0xEB,0xCE,0x29,0xC3,0x97,0x03,0x68,0xAF,0x48,0x8F,0x98,0x3B,0x95,0x82,0x66,0xC5,0x8B,0xD5,0xC0,0xCB,0xA7,0xC1,0x57,0x61,0x77,0x01,0xA3,0xA1,0x49,0xAA,0xE2,0x63,0x1F,0xA7,0x43,0xBA,0xD7,0x1C,0xE5,0xD0,0xA8,0x9A,0x22,0xE3,0x87,0x36,0xF4,0xC8,0x92,0x8E,0x6B,0xA2,0xB6,0x9B,0x5D,0xB5,0x8F,0xDB,0xDE,0x91,0x1A,0x57,0x6E,0x2D,0xCF,0xE5,0x17,0x1E,0xF8,0x68,0x81,0xAF,0xB6,0x9A,0x5B,0x1E,0xB9,0xA7,0x61,0x5E,0xE8,0xB3,0x2B,0x8A,0x2F,0x56,0xF7,0x65,0x3F,0xDA,0xFB,0x40,0x8D,0xD1,0x48,0x75,0xB6,0x5D,0xBF,0x4E,0x87,0x4B,0x69,0x01,0xFC,0xF3,0x1A,0x3E,0x20,0x65,0x5F,0x4C,0xBD,0x00,0x44,0x0A,0x28,0x86,0x11,0x66,0xF4,0x63,0x28,0x81,0x21,0x8F,0xAD,0xE2,0x17,0x9B,0x54,0x2B,0x0C,0x1D,0x0F,0x3F,0xA0,0xB4,0xE9,0x77,0xFE,0xB9,0x45,0x62,0x68,0xC2,0xC0,0xEB,0x74,0x7C,0x18,0x74,0x1E,0x26,0xC4,0x67,0xF9,0xA1,0xA1,0xB3,0x45,0xC6,0x86,0x0E,0x91,0xB0,0xB0,0xFA,0x29,0xD1,0x75,0x88,0x04,0x3A,0xD2,0x75,0xE1,0x1C,0xEE,0x2C,0x94,0x58,0x50,0xCE,0x0B,0x7C,0xEB,0x75,0xC7,0x7F,0x66,0x59,0x5F,0x67,0xC5,0xC0,0xD9,0x81,0x04,0x92,0xC3,0xF2,0xAF,0xAC,0xF1,0xB4,0x17,0xCE,0xBB,0xD8,0x4D,0xEE,0x6B,0x53,0x93,0xA1,0x37,0xBB,0xAF,0x0D,0xA2,0xB2,0xA1,0xC4,0xD1,0x4F,0x47,0x2C,0x32,0x3C,0xE6,0xB8,0xC3,0xEC,0x6A,0x73,0xB6,0x48,0x4D,0x18,0x3B,0xDD,0x3D,0xE6,0xE9,0xDA,0x64,0xE4,0xB5,0x57,0x27,0x55,0x6D,0xAB,0x73,0x53,0x2E,0x80,0x26,0xA4,0xD6,0xF7,0x61,0xBB,0xA0,0x2B,0xAF,0xB4,0x7B,0x15,0x3E,0x7A,0xA6,0x67,0x1F,0xE9,0xB3,0x60,0x52,0x85,0x85,0xDE,0x77,0x96,0x01,0x35,0x52,0xFE,0xB8,0x79,0xFF,0x19,0xAC,0xFB,0xF0,0xA2,0xAC,0x19,0x75,0x0C,0xF7,0xE3,0xCA,0x5E,0xA8,0xFF,0xF8,0x99,0xAB,0x84,0x57,0xD0,0x31,0xFF,0xDE,0x40,0xF1,0x79,0xB3,0x31,0x68,0xD9,0x60,0x56,0x0E,0x28,0x85,0x1A,0x49,0x27,0x0F,0xAC,0x4D,0xF5,0x71,0xA8,0x92,0x5C,0x37,0x54,0x33,0x20,0x6C,0x51,0xF6,0x6D,0xB6,0x39,0xAC,0x57,0xD3,0xD1,0x63,0x0B,0xA9,0x90,0xEE,0x4C,0x78,0xE2,0xE2,0x29,0x55,0xDC,0x5A,0xC8,0x27,0x16,0x9A,0xB7,0xF8,0x11,0xB4,0xEB,0xF6,0xDE,0x8C,0x54,0x9A,0xC0,0x87,0xB6,0x73,0x5D,0x7B,0x91,0xF5,0xDE,0x0F,0x7B,0xF6,0x72,0x54,0x1B,0x0F,0xEC,0x52,0x5E,0xBF,0x32,0xDC,0x57,0x47,0x0C,0xAB,0x09,0xBF,0xD8,0x0F,0x4D,0x80,0x95,0x89,0x5B,0xA5,0xF0,0x64,0x58,0xC5,0x8B,0x3B,0xAD,0xC8,0x18,0x98,0x00,0x0D,0xFC,0x26,0x3F,0x36,0x75,0x63,0x18,0xA1,0x70,0xD3,0xEF,0xDC,0x6C,0xCD,0x83,0x81,0x98,0x41,0x80,0x78,0xB6,0xF8,0x51,0x24,0x5E,0xE5,0x49,0xCD,0xF5,0xF1,0x97,0xE3,0xC1,0xA5,0x55,0x00,0xE9,0xC6,0xEB,0xBE,0x33,0x08,0x66,0xD9,0x64,0x68,0xC8,0xD8,0x95,0xE0,0xB1,0x20,0x40,0x7B,0xF2,0xFD,0xC7,0x7B,0x78,0x76,0xEA,0xD0,0x48,0x6C,0x7A,0xE1,0xA3,0xF6,0x66,0xC0,0xCC,0xAF,0x7E,0xBC,0x55,0x6E,0xA7,0x7C,0x51,0xD1,0x91,0x96,0x62,0xF9,0x64,0xC3,0x5F,0x93,0x01,0x87,0xA2,0xC9,0x5B,0xC3,0x72,0x31,0x30,0x27,0x34,0xE2,0xB7,0xBD,0x72,0xCE,0xAB,0xE5,0x83,0xE2,0xD2,0xDF,0xE1,0x15,0x2A,0xFC,0x2A,0x52,0x1F,0x67,0x4F,0x47,0x4C,0x03,0xC4,0xDA,0xF3,0x95,0x25,0x28,0x95,0xFC,0xEA,0x3F,0x58,0xD2,0xEE,0xD1,0x19,0x34,0x73,0x66,0xC4,0xFF,0xF3,0x4F,0x56,0x5C,0xE8,0x33,0xA9,0x1C,0x3B,0x2B,0x3E,0xEB,0x63,0xD7,0xFD,0xEC,0x2B,0x24,0xB3,0xB2,0xE2,0xE9,0x47,0xD8,0x5F,0x28,0xB1,0xED,0x1F,0xA8,0xFB,0x63,0x93,0x9F,0x50,0x31,0x30,0x2F,0xF4,0x9C,0xDF,0xA0,0x7B,0x10,0x45,0xD7,0xA0,0x94,0x58,0x9B,0x7B,0xC6,0x06,0xFE,0x9E,0x39,0x54,0xF9,0xAF,0x5F,0xAA,0xE3,0x61,0x0A,0x8D,0x23,0xB9,0x6F,0x1E,0x27,0x7F,0xC7,0x96,0x14,0x64,0xE5,0xE2,0x54,0x02,0x1A,0xFE,0xC0,0x76,0x8C,0x3F,0xAF,0x20,0xFC,0x93,0xD8,0x76,0xEB,0x3F,0xA7,0x3B,0x0E,0x2F,0x2E,0x5E,0x7A,0x07,0x8B,0x81,0x09,0xD1,0xF0,0xDF,0xF6,0x2A,0x72,0xE4,0xFB,0x7B,0xAE,0x8E,0x81,0x0A,0xD9,0x45,0x9D,0x11,0xD5,0x81,0xF7,0xE3,0x7D,0x88,0x6D,0x29,0x2F,0xE2,0x09,0x2A,0xF9,0xE2,0x3F,0x40,0x17,0x6A,0x1E,0xF6,0xC9,0x31,0x5F,0x7C,0xA9,0x0F,0xFE,0x09,0x0A,0x69,0xBB,0x74,0x12,0xC5,0xCE,0x4D,0x1E,0x7B,0xF7,0x03,0xF4,0x69,0xF0,0x61,0x39,0xEC,0x1F,0x83,0xDC,0xD0,0x98,0x6F,0x20,0x5E,0x40,0x9F,0x3F,0xB5,0xA1,0x46,0x3E,0x4C,0x5C,0x7A,0x41,0x4E,0xE1,0x56,0x7D,0x73,0xF2,0xD3,0x6B,0xD3,0x25,0x2F,0x01,0x62,0x74,0x42,0x64,0x32,0xA8,0x52,0xF4,0x67,0x41,0x3F,0xC5,0xA4,0x25,0x41,0x99,0xD1,0x35,0x99,0xBF,0x3A,0xAF,0xED,0xC2,0x8D,0x58,0x18,0xBB,0x3B,0x21,0xFA,0xED,0x0F,0x60,0xEA,0xE5,0xFB,0x29,0xA8,0x7F,0x02,0xC8,0xF3,0xA7,0x3A,0x82,0xF2,0xF9,0x1D,0x95,0x55,0x38,0x85,0x9A,0x9E,0xAF,0xC9,0x3D,0xC5,0xDF,0x81,0x9D,0x15,0xEF,0xEA,0xA0,0x2A,0x55,0x7F,0x66,0x38,0xF4,0x4C,0x5A,0x0D,0xFC,0x1B,0x19,0xBA,0xA0,0xE5,0xBE,0x03,0x75,0x57,0xA4,0xCD,0x93,0x0F,0x92,0xBC,0x7B,0x83,0xFC,0xBF,0x71,0xE1,0x7F,0xC1,0x4D,0xE6,0x44,0x81,0xFF,0x06,0x6E,0x3F,0x1A,0xF5,0x0D,0xC7,0xED,0xA7,0x7E,0x90,0xBF,0x1A,0x28,0xCE,0x40,0x29,0x54,0xE7,0x4D,0xE4,0x3F,0xFD,0x41,0x0B,0x48,0x78,0x10,0x8D,0x54,0x69,0x7B,0xF5,0x07,0xAD,0x39,0xE1,0xC6,0x47,0xDC,0xBF,0x9F,0x1C,0x17,0xA6,0xAC,0xA3,0x24,0xDF,0x11,0x5E,0x76,0x8E,0xA0,0x50,0xFD,0xB5,0x75,0xE6,0x27,0xEE,0x7C,0x60,0x62,0x0D,0x46,0x25,0x7F,0xE8,0x0F,0xDC,0xC9,0xE7,0xB1,0x35,0xFF,0x0E,0xEE,0x57,0xE7,0x15,0xE9,0xF4,0x2F,0x6A,0x00,0xE5,0x53,0x2E,0xF7,0xD5,0xCB,0x29,0x54,0x67,0xA4,0xBE,0xF9,0x09,0xFC,0x92,0x7C,0x2D,0x07,0x50,0x79,0x5A,0x57,0xF4,0x0B,0x38,0x2E,0x3D,0x33,0x82,0xF9,0x97,0x81,0x5D,0x58,0x15,0x14,0x64,0x2E,0x76,0x20,0x38,0x68,0xE8,0x66,0xDE,0xC0,0xD5,0xA8,0x81,0xB2,0x38,0x05,0x80,0x08,0x51,0x09,0x00,0xE8,0x10,0x88,0x83,0x36,0x33,0x19,0xA3,0x2D,0x56,0x64,0x03,0x16,0x90,0x1D,0x40,0x1F,0x3A,0x07,0x40,0xA3,0xB5,0xBE,0x3A,0x19,0x8F,0x5B,0xF2,0x9F,0xA8,0xC6,0xCA,0x4F,0x9C,0x1E,0x9E,0x80,0x2F,0x46,0x6B,0x4D,0x1F,0x71,0x18,0xDF,0xB5,0xD2,0x51,0x35,0x96,0x58,0xF4,0x32,0xC5,0x45,0x15,0xBA,0xE9,0x03,0x69,0xBC,0xB8,0xD0,0x0F,0xA1,0x05,0x6C,0xD2,0x6E,0x3C,0x95,0x35,0x8C,0x34,0x02,0xBC,0xCD,0x5E,0x45,0x4E,0x84,0x23,0x76,0xDA,0x27,0x64,0xDD,0xB6,0x54,0x3D,0xF5,0x71,0x0D,0x39,0xAD,0x3E,0xF5,0x89,0x0D,0x1C,0xB2,0xF0,0x92,0xFB,0x95,0x97,0xBE,0x65,0x53,0x11,0x05,0x14,0xAD,0x0D,0x96,0x2D,0xEE,0xF9,0x53,0x68,0x9C,0xB2,0xFE,0x3D,0x9E,0xD8,0xF4,0x5A,0x12,0xAA,0xFC,0x79,0xC5,0x9A,0xFD,0x72,0x0A,0xBE,0x96,0xF5,0xBC,0x92,0xC0,0x8B,0x4A,0x49,0x51,0xCB,0xBF,0x3A,0xDC,0xAF,0xB1,0xE8,0x72,0xD3,0x56,0xCB,0xE0,0x43,0x0E,0x76,0x58,0xD9,0xE3,0xAA,0x3A,0x4E,0x3C,0x5F,0xE5,0xA3,0xD2,0xA4,0x24,0xE2,0x72,0x37,0x46,0xB9,0x3B,0x94,0xBE,0x68,0xF3,0x23,0x38,0x7D,0x4C,0x79,0xFF,0x10,0x39,0x8E,0xCD,0x42,0xEF,0x68,0xBF,0x3F,0x74,0x51,0x0E,0x55,0xD4,0xDB,0x1B,0x0F,0x97,0x8F,0xE8,0x29,0x2C,0xC1,0x2A,0x44,0x4D,0x94,0x5E,0xC7,0x10,0x25,0x3D,0xF9,0xF1,0x30,0x95,0x92,0xF4,0xDE,0x14,0x90,0x34,0x50,0xD9,0x71,0x0A,0x61,0x81,0xCB,0xBD,0x4E,0xD9,0xBB,0xEB,0x60,0x67,0xFE,0xB8,0x89,0x40,0xBD,0x54,0xEB,0x2D,0x80,0x3A,0x57,0xD5,0x1A,0xF3,0x2C,0xA7,0xAC,0x29,0x12,0x90,0x0F,0xF8,0x52,0x7C,0x96,0xA0,0x30,0x5B,0xD9,0x1A,0xD3,0xDF,0x53,0xD6,0x64,0x42,0x0C,0x29,0x7D,0x58,0x80,0x52,0xB5,0x7F,0xDC,0xE5,0x4C,0x98,0xA7,0xAB,0xBF,0xAB,0x3D,0x1E,0x70,0xD2,0x0E,0x52,0x58,0x6B,0x34,0xBC,0x14,0x79,0xC6,0xD0,0xCB,0xC8,0xC0,0x1A,0x9C,0x59,0x54,0x07,0x13,0xC1,0x32,0xF5,0x7C,0x63,0x18,0x13,0x79,0x86,0x81,0x96,0x57,0xE6,0x47,0xB3,0xDD,0x77,0x36,0x58,0xDB,0x14,0xF5,0x15,0xEF,0xF4,0xD3,0xB5,0x92,0x1A,0xC7,0xA2,0x9D,0xD5,0x2B,0x5D,0xF1,0xFD,0x69,0xEF,0xED,0x75,0xCD,0x1A,0xAA,0xB6,0x87,0xE8,0xFE,0xDE,0x7F,0x06,0x2B,0xB2,0xD5,0x19,0x38,0xFA,0xE8,0x8C,0x4D,0xBA,0x67,0xE1,0x39,0xD2,0xD7,0xBB,0xE2,0x5B,0xA0,0x96,0x19,0x3A,0xEA,0xBC,0x6E,0xDB,0x3C,0x4E,0xC7,0x7C,0x73,0xF9,0x83,0x7B,0xEA,0xD0,0x96,0x6B,0x53,0x1D,0xBE,0x92,0xD2,0x04,0x79,0xCD,0x8F,0xE7,0x64,0xD1,0x9E,0xC2,0x84,0x5D,0xA3,0xC6,0xA2,0x22,0xED,0x82,0xE6,0x80,0x26,0x30,0x4F,0xBF,0x48,0x5B,0x80,0xDE,0xA4,0x8F,0x11,0xA5,0x59,0x2E,0x99,0x6F,0xB1,0xDD,0x55,0xE9,0x14,0xCF,0x05,0x5F,0x18,0xB1,0x8B,0xDA,0x32,0xD0,0xD1,0xD0,0x62,0xA5,0x66,0x5E,0x07,0x53,0xD0,0xEE,0xB9,0xD7,0xF7,0x05,0x60,0x47,0x57,0xBD,0x1E,0x02,0xCD,0x24,0xBD,0x51,0x09,0x48,0x9D,0xD0,0xEF,0xE9,0x4A,0x7E,0xA6,0x9B,0x30,0xFD,0x36,0xF0,0x7B,0xBA,0x92,0x1F,0xE9,0x9E,0xBF,0x19,0x96,0x87,0x52,0x55,0xF9,0x6B,0xBA,0x3B,0x82,0x14,0x36,0xAC,0xFD,0xC4,0xD6,0x38,0x14,0xB0,0xC5,0x48,0x77,0x41,0xF4,0xA8,0xF1,0xAD,0xA5,0x9A,0x86,0x99,0x5B,0x4C,0x91,0x9A,0x19,0xEE,0xA4,0xD7,0x99,0xAD,0x26,0x5A,0xAB,0xD0,0xE7,0x3A,0x90,0xBA,0x73,0xE7,0x30,0x6D,0xE3,0x03,0x7E,0xD7,0x6E,0x5E,0x30,0xF7,0x70,0x86,0xC3,0x67,0x2F,0x58,0x7B,0xB8,0x3D,0xD2,0x22,0x9F,0xDA,0x08,0xF0,0x07,0xC7,0x99,0x5C,0xB4,0x76,0xE9,0x70,0xD5,0x30,0xE1,0xAF,0x5A,0x8C,0xFE,0x07,0x69,0xE1,0xCA,0xB4,0x3C,0xFD,0x53,0x4B,0xD1,0x45,0xF1,0x0B,0x94,0x42,0xD5,0x1F,0x5A,0xAE,0x3F,0x1F,0x6C,0x22,0xFC,0x77,0x69,0xF1,0x3C,0x0D,0xA0,0xA2,0xFE,0xD4,0x92,0x3C,0x7D,0xAF,0x1F,0xA6,0xF0,0xE6,0x0F,0x2D,0xE3,0x01,0x17,0xA6,0xB0,0xAA,0x94,0xFF,0xA7,0x96,0x2B,0x5B,0x4C,0x6D,0x19,0x8F,0xDC,0x1B,0x82,0xDA,0xBD,0xED,0xFD,0x17,0xB8,0xEF,0x23,0x92,0xB2,0x87,0x3E,0x57,0xC2,0xFE,0x65,0x59,0x47,0xDF,0xFE,0x13,0xDD,0xF5,0xBF,0xE7,0x4E,0xF1,0x07,0x6A,0xBE,0xE5,0xFB,0xFE,0x57,0xBE,0xB1,0x95,0x0F,0x86,0x31,0xB2,0x7C,0xDF,0xFF,0xCC,0x37,0x7E,0xF6,0x72,0x35,0xF6,0xBF,0x2B,0xDF,0x7F,0xB5,0xCF,0xF6,0xC9,0x6B,0x03,0x28,0x88,0x3C,0x44,0x01,0x22,0x7B,0xD4,0x43,0x48,0x10,0x26,0x90,0x8D,0x0B,0x87,0x2E,0x36,0x5C,0xD9,0xCC,0x6B,0x75,0x9A,0x17,0x51,0x98,0x15,0xDF,0x7B,0xB6,0x37,0xAA,0x3D,0x37,0x2E,0x79,0xAB,0xE2,0x68,0xE3,0x41,0x0B,0xE1,0x48,0x00,0x4E,0x2C,0x9C,0x5B,0xBC,0xCC,0xC5,0x48,0x2B,0x3F,0x5F,0x83,0xA0,0x49,0x1D,0x59,0x53,0x8B,0xCD,0x77,0xE2,0x16,0xCC,0x6E,0x88,0xD9,0x79,0xE4,0x91,0x75,0x32,0xD7,0xFA,0xC4,0xDC,0xBA,0x6A,0xEB,0x98,0xE7,0x65,0x4B,0x8F,0xD2,0xD0,0xAB,0x54,0x9F,0x32,0x1D,0xB9,0xB6,0x81,0xA6,0xF1,0xB5,0x2D,0xAA,0x86,0x41,0x76,0xCB,0x16,0x85,0xE1,0x7C,0xF5,0xA8,0x1E,0x0F,0xB6,0xC5,0xD5,0xFB,0x80,0x23,0xDB,0xDD,0xF6,0x86,0x68,0x1F,0x16,0xC9,0xD7,0x9F,0xBA,0x58,0x4C,0x20,0x96,0xC4,0x87,0xBC,0x41,0xA8,0x74,0x3F,0xAA,0x28,0x43,0x92,0xDE,0x3F,0x19,0xEF,0x83,0x1A,0xFD,0x57,0x57,0x03,0xCD,0xBE,0x2F,0x06,0xEE,0xFC,0xFF,0xB2,0xD6,0xE7,0xF0,0x7D,0xA9,0xAF,0x1C,0x47,0x45,0x83,0x46,0x61,0x8D,0x6F,0x36,0x1D,0x96,0x8F,0x7B,0x51,0x5D,0x8A,0x5C,0xAC,0xA8,0x51,0xB3,0xEF,0xA2,0x60,0x9F,0xDD,0x6C,0x02,0x99,0x53,0x46,0xDC,0x15,0xBB,0x79,0x28,0x0F,0xE9,0x11,0xD0,0xBB,0x94,0xA7,0x41,0xFC,0x1C,0x1C,0xDE,0x8D,0x52,0x95,0x95,0xB1,0x1C,0xC7,0x44,0x63,0xE6,0x0E,0xD7,0x35,0x91,0xE6,0x7D,0x7E,0x8D,0xE6,0xD6,0xCB,0x47,0x85,0x7D,0x28,0x41,0xFF,0x72,0x5D,0x53,0xBE,0x63,0xCC,0x81,0xF5,0xCD,0x55,0x9A,0x87,0xA4,0x0D,0xF6,0x2E,0x15,0xEE,0x23,0xD6,0x4F,0xBD,0x1D,0xC6,0xFD,0x70,0x35,0xF8,0xAB,0x6B,0xB0,0x7C,0xE2,0x9B,0xD1,0x48,0xDC,0xE2,0xD5,0x27,0x02,0xB7,0x95,0x0B,0x8C,0xBC,0x67,0x71,0x24,0xEE,0x0D,0x1F,0xB9,0x3A,0xDE,0xD9,0x7E,0x53,0x7A,0x2C,0x62,0x83,0xC1,0x13,0xC5,0xE2,0xA6,0x79,0xB3,0x4D,0xE9,0xAB,0xB4,0xD6,0x30,0x6D,0x9E,0xCC,0x21,0x4E,0x56,0x49,0x8B,0x10,0x3F,0x02,0xE9,0xA1,0x11,0xE0,0xC8,0xE4,0xD0,0x12,0xF9,0x93,0x39,0x9F,0x07,0x31,0xBF,0xE8,0xAF,0x67,0x8D,0x57,0xC9,0xE8,0x16,0xB1,0x9B,0x3F,0xE7,0x21,0xF9,0x96,0x03,0x2E,0x0B,0x57,0x13,0x63,0xC7,0xA4,0x57,0x71,0xAA,0xF8,0xE8,0x52,0x13,0x94,0x7D,0x68,0x6B,0x66,0x9F,0xAF,0xF8,0xD9,0xC9,0x4E,0xD2,0xB5,0x89,0x5B,0x71,0x88,0x54,0x82,0xAE,0x76,0x61,0x73,0xCD,0x3D,0x38,0xAA,0xB3,0xA4,0xAD,0x6A,0x28,0xBC,0xE2,0xAE,0x9D,0x7C,0x5C,0xD7,0xCC,0x3D,0xEC,0x62,0xB8,0xEF,0x6B,0x5B,0x90,0x98,0x56,0x7D,0x55,0x22,0xA7,0xD2,0xD2,0xDD,0xFA,0x25,0x31,0x34,0xA2,0x49,0x0A,0x90,0x46,0xC3,0x27,0xFC,0x91,0x5A,0x78,0xED,0x4E,0x57,0x53,0x77,0xD3,0xAB,0x5D,0xE9,0x87,0x2D,0x46,0x4A,0x7C,0xB2,0x09,0x74,0xE2,0xF4,0x8D,0x33,0x49,0x04,0x95,0xE6,0x2F,0x25,0xEF,0xF1,0xA4,0x9E,0x82,0xCF,0xED,0xD8,0xC5,0xCB,0x07,0x91,0xB1,0x3A,0x21,0x41,0xBB,0x36,0x18,0x2C,0xBE,0xAC,0xB9,0x30,0x4B,0x6A,0x6F,0xB0,0xBE,0xFB,0x3D,0xE9,0x71,0xB0,0x36,0x3A,0xF0,0xDE,0xED,0x03,0x17,0x45,0x41,0xCD,0xFF,0x01,0xE7,0x64,0x0E,0xB1
]
                aes_key = bytes([0x62,0x7D,0x1C,0x7E,0x3D,0xCD,0x67,0x92,0x59,0xCF,0x2D,0x98,0x48,0x58,0xF9,0xFA])
                data_plain = bytes(p_text)  # list of ints → bytes
                data_encrypted = aes_encrypt(data_plain, aes_key)
                print(f"[AES] plain={len(data_plain)}B → cipher={len(data_encrypted)}B")
                hex_dump("data_encrypted",data_encrypted)


                # # 模拟三个时间戳的生成，间隔分别为 543ms 和 55ms
                # timestamp1 = int(time.time() * 1000)

                # time.sleep(0.543)  # 等待 543ms
                # timestamp2 = int(time.time() * 1000)
                # timestamp21= int(time.time() )
                # time.sleep(0.055)  # 等待 55ms
                # timestamp3 = int(time.time() * 1000)
                # timestamp31= int(time.time() )
                # print(f"第1个时间戳: {timestamp1}")
                # print(f"第2个时间戳: {timestamp2}  间隔: {timestamp2 - timestamp1}ms")
                # print(f"第3个时间戳: {timestamp3}  间隔: {timestamp3 - timestamp2}ms")
                # print(f"总跨度: {timestamp3 - timestamp1}ms")
                # print(old_deserialized['2']['7'] )

                # original_value = old_deserialized['2']['7'].decode()  # b'A2052943da3b41f5_1784094376623'
                # prefix = original_value.split('_')[0]  # 'A2052943da3b41f5'
                # new_value = f"{prefix}_{timestamp1}"  # 'A2052943da3b41f5_当前时间戳'

                # # 更新为新值（转为 bytes）
                # old_deserialized['2']['7'] = new_value.encode()
                # print(old_deserialized['2']['7'])  


                # print(old_deserialized['2']['15']['2']['3']['2']['8'] )

                # old_deserialized['2']['15']['2']['3']['2']['8']=timestamp2

                # print(old_deserialized['2']['15']['2']['3']['2']['8'] )



                # print(old_deserialized['2']['15']['2']['3']['2']['4'] )

                # old_deserialized['2']['15']['2']['3']['2']['4']=timestamp21

                # print(old_deserialized['2']['15']['2']['3']['2']['4'] )


                # print(old_deserialized['2']['15']['2']['7']['2']['8'] )

                # old_deserialized['2']['15']['2']['7']['2']['8']=timestamp3

                # print(old_deserialized['2']['15']['2']['7']['2']['8'] )



                # print(old_deserialized['2']['15']['2']['7']['2']['4'] )

                # old_deserialized['2']['15']['2']['7']['2']['4']=timestamp31

                # print(old_deserialized['2']['15']['2']['7']['2']['4'] )


                # 重编码修改后的消息
                new_buf = blackboxprotobuf.encode_message(old_deserialized, old_message_type)
                print('=== 替换后重编码 ===')
                print(' '.join(f'{b:02x}' for b in new_buf))


                data_back=bytes(new_buf)
                a8_data,sha256_de=_generate_ecdh_payload1(data_back)
                hex_dump("result",a8_data)
                enc_len=len(a8_data)
                hex_str = ' '.join(f'{b:02X}' for b in a8_data)
                print("成功:", hex_str)

                # ── 把 enc_len 写回 wire 协议 ──
                _struct57 = bytearray(deserialize_wire(hybrid_body_dump_pack_wire))
                struct.pack_into('<I', _struct57, 29, enc_len)
                struct.pack_into('<I', _struct57, 33, enc_len)  # enc_len2 同步

                # # ── 换 cookie ──
                # _cookie = bytes.fromhex(" 7a 03 08 02 00 00 00 00 70f9c034a967 00")
                # _struct57[12:12 + len(_cookie)] = _cookie
                # log(f"\n  [cookie] 固定cookie: {_cookie.hex(' ').upper()}")

                output1 = bytes(serialize_header(_struct57))
                hex_dump("hybrid_body_dump_pack_wire", hybrid_body_dump_pack_wire)
                hex_dump("_new_wire", output1)
              



                # ── 步骤 5: 更新 header 两个长度字段 + 拼接 ──


                hex_data ='''

BF BE CF 28 00 47 50 83 58 D9 6C 9C 03 08 02 00 00 00 00 0B F9 D8 A0 40 D3 00 FB 05 F3 4D F3 4D A8 4E 02 00 FF 9B C2 C5 91 04 00 00 00 00 00

'''

                output1 = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))
#                 hex_data ='''
# 08 01 12 46 08 9F 03 12 41 04 1A 9C 4F 1C 12 6D B6 B4 E3 CE 91 12 73 0E F5 2F 7E 10 19 FF 12 D0 A7 6F 96 0B 3C FF 80 25 CC 22 6C B7 A4 D4 42 3F 1F 63 E6 FF D5 8D 90 EB A6 F4 97 8B 24 8E 0B 6A 0A 7F BD 23 85 D5 2A 66 F8 F3 1A 45 D6 11 28 8C 14 D8 D5 49 99 88 9A 34 22 9C AB 1A 84 94 2D 9F 07 C9 08 97 C9 C0 DF AC 0F E4 AC 5F 32 97 F0 B0 24 D6 43 34 59 2F C6 48 FD 08 58 69 92 B1 81 32 5A 9F 56 0A FA 92 E7 14 CE 3D 47 79 59 A4 4E 58 4E 22 45 88 E6 54 7D 5A 41 AC 02 83 79 80 D7 45 2C D2 96 C2 EE A4 8C 02 3E F3 0A AF 13 2A 23 FA D3 BC 83 A4 BC B7 AF 03 B4 90 5B FE 10 CE 9D 1B 5B 5F BD 02 34 73 EF 78 D2 E3 E6 81 6E F0 C6 21 87 7E 7D 57 64 C2 13 D0 2A 9B 48 37 C4 9A 06 FB BB 93 24 E4 0A 7B 21 A8 4A 01 E7 51 65 E9 F2 22 16 9A FE F0 3C EE CA 35 AE 66 51 B9 7F 0B 66 15 CC 36 4B 07 C7 A8 D3 68 68 59 3A D4 07 58 98 D8 D3 0D AD 00 D2 D3 90 91 79 E9 C2 24 6E B5 C0 F6 EA BA D1 AC 3B E0 FC B6 BE B8 D8 95 58 63 21 A9 63 C4 E6 6C 46 E8 07 6B F7 38 13 2A 44 33 3E 27 7A F9 C4 DF D1 4B B2 18 33 4E 6A 88 DD 81 54 DF 42 FE 60 16 2E F4 84 21 2E BF 4E EF DD ED 3E 13 73 24 2F 82 AD D3 86 D4 B0 E8 5F A1 E4 E5 EF E2 7E 7D 3B 2E 2D 63 02 8A DC 89 AD EA E3 6A 2F 20 94 9D 53 F2 63 A5 20 6F E4 AD 3F 05 B6 D0 85 7E DD 00 22 D0 A1 0B 98 1C 73 51 94 CC 76 CA 97 39 C6 4D 49 9F 92 84 F9 8D BA D4 FF 83 D7 31 B5 F4 23 5E 4D 5D 99 0B 98 B2 FC 5A 67 6D 4D BB 94 44 85 57 D5 1C 55 98 BC 67 AB 53 15 16 65 1A B0 7C 7A AE E4 38 48 E3 C7 0D 59 6C 3D A2 CB 48 64 47 52 1C 66 A3 77 D9 65 14 7C 86 B3 3B 7A 4A 86 E7 9D 3C 60 98 1E F9 30 21 80 D0 17 8E 81 EC 72 AE 50 52 15 46 EF BC 4D F7 46 49 43 DE E3 E4 7E DB 04 2F E7 DB 8F 3B 4F CD 15 CC B4 2C 84 2C 31 10 D2 83 04 33 87 EA 7E AF 7D 8A AB 66 F7 17 89 20 46 9A C9 C0 87 D0 0B 4E EF E0 4D FF 80 7E FD 6D 6F 19 EE 75 AE C7 90 2F 04 37 A7 76 0D E8 53 FF 86 74 D9 19 3B 45 6F 34 D7 51 15 15 8C 4C 0F 35 FE 2D 44 74 74 A9 9D 3B 55 B3 4F D7 F1 E5 34 FA 2E 96 41 DC 3A 2B 05 D8 6B 2D 3F F8 60 69 33 C8 D5 D1 4B 57 22 06 A1 55 D5 6E 09 AD 1B 48 A9 B0 96 61 55 3E 2D E6 11 7B AF 62 B2 A6 09 19 40 69 DE F8 D5 C6 DB BC 5E 22 34 F7 DA F2 48 DA F8 D3 FB E1 51 D9 96 FC 77 6C 6D 59 DD B9 74 DF 0D 82 C8 31 05 6F 3F 3A 41 99 60 26 6F 9A 1D F3 07 24 06 E3 53 87 42 79 62 2C 7A DD 4D 4C 91 2C 2D 67 0E 0E 5E A3 34 49 3E 29 58 D3 9D F1 A9 E1 27 F4 80 9B 68 11 F0 CD C4 35 EA B8 0F 58 4B 0E 6B 3C B7 72 D0 EE C5 F1 F1 92 EE DA 38 DC F7 91 E8 42 1D 70 79 BD 53 74 81 5C 00 03 37 01 24 56 E6 21 01 86 DE 4B 95 36 4F F0 1C 1D 08 71 F8 58 4F 64 4A 19 27 8B CF D3 81 EF 1A 4E D8 B2 BB 14 31 C6 A6 E4 BC 29 1D 46 78 2B B2 53 B3 1F C2 16 9D 17 AC 11 C0 CF D1 9D 19 EF 5F DA 69 F4 AF C3 6D 68 2F 8D 19 74 9A 48 FF 75 7E 9B 20 CB 5C 81 23 F9 61 23 A4 E6 20 7C 84 E7 42 6A AD 48 17 B0 CA 8D C7 F5 95 45 DB 8C 37 DA 3F 73 B5 F6 15 B2 65 A1 A8 BB 89 49 5C FC 1C 76 11 8C CB E9 8E 84 9C 68 02 A1 F4 BB 66 49 A0 E8 86 99 75 A9 B6 EE 03 6A 37 93 47 B0 04 87 7C F9 33 BA 1A F2 B0 C3 6E E4 35 AD 82 1A A0 B8 56 FA 19 29 17 6F C1 1D 85 D2 0A 78 AA CB 43 9C 3C 09 E6 99 15 ED BE 3D B9 BC 3B 5E 1F E1 07 A8 12 84 C5 93 06 82 49 4E F8 63 1F ED 0D 5E 26 9D 9F B8 9F D2 77 F2 C5 75 EE B1 A3 BA D8 51 56 CB E6 58 AC A5 39 59 DA 7C E4 40 F5 32 AE 6C CA F8 63 E4 6E 62 1D 38 56 5A C8 C0 21 65 27 4A 3E C8 65 00 E7 96 C8 A8 8B 9D FB 22 5B 2B FD 8D F8 C1 3A 6E 5E 82 D9 02 7F 32 23 3C 11 E1 70 FC 78 C6 7B AD 0F 60 3E F2 25 11 3C 6B 14 E0 C3 2A 66 81 3D AA E9 D7 60 78 57 E6 79 8D 5F 0B 30 38 10 E4 4D A5 E4 D1 88 32 35 00 5B 1A D5 15 41 37 44 7F C8 99 12 5C 1A 1C 27 54 75 A5 10 7E F6 79 AC 0A 2A BA 1D DF 3E C4 F0 C6 68 2C A0 23 18 CD DC 59 35 6D BE 5D 58 43 30 0B E5 EC 84 94 8F 53 14 4B 92 BF 8C 0A FD 15 A0 AE AE 55 DA 00 71 60 D5 D7 E8 B3 73 07 21 40 F7 69 01 4C 9C 48 F6 9B AD 46 7B 2B AF 43 BB 79 5F 58 48 58 9B 68 D9 9F 33 E3 D7 A6 09 2C B5 2B 03 DC 6F 55 32 F5 87 9B 7C 5F C9 89 E1 FF 95 14 C4 F4 03 8C 30 20 CC B9 BB 46 34 62 D4 F6 CB 89 E9 C1 CB D0 0B C7 4F 8B B8 E3 31 43 9E AF 48 56 90 8D E9 1B 1B EE 86 52 9D 2F 0F 22 A4 79 B0 19 4E 0F 48 13 7D 24 46 6E 4A 2B 87 F4 A8 A9 DC 6D DA 4D CA 9F A2 7A F0 51 4E 84 2C FD EC A1 6B 33 DD 61 8B B1 5A 17 BC C1 B3 EC 5C 12 B9 05 4D B1 92 A2 79 C6 CF 68 DA 8A 0B BD 61 32 E1 94 82 EA 40 99 F1 0E 15 B6 3C E0 30 1C F7 BE 72 25 C6 44 8B C1 D7 E0 4B ED F0 38 37 8C 43 C0 0A 0E D7 FC 7F B0 D2 EA D3 01 65 42 70 DF E0 55 F0 59 8A 5A AA 5D A3 07 C1 E1 AC DF 9D 33 37 15 9B 68 5F B9 FB 95 AE 3E E7 3C 37 44 B1 58 2E 7C B6 62 7A F1 A3 A5 CB BA 23 5B 36 17 D3 37 6E 94 24 2C 4A D6 27 E8 B6 DB 48 61 2A 54 5D 4F 50 66 0A A9 BE 2D 4C 40 E5 B0 89 D1 AD 44 82 39 AC F7 64 F9 BC AC FC 11 8C 93 6D 1E 60 F9 E1 DB AF C4 73 AD BB B6 8D 74 9B 25 A8 62 23 E6 EC 3E F5 F8 0A E2 8F F2 17 4D 52 65 D7 99 1D AF CC 22 61 C5 EA 9A 71 53 84 B7 05 5D F7 FE 4B 2C B5 C3 47 4B E3 50 49 8A 31 2A 45 62 EF 9E 17 A8 70 E7 30 6B EF 20 5F FC 8A 6D 6F 38 2C E8 D0 22 59 26 44 B7 2A 02 01 14 04 7D F0 B0 EF 70 62 01 4A E7 AE 18 3B 0C 55 1B 21 B8 68 D0 15 8C B7 9D 7D 8C 9A 44 EF 28 80 72 EF D2 CD 4D 22 13 24 36 44 DF CD AC D9 A7 93 97 33 43 B8 07 58 6B 38 13 8B A4 CB 58 BF 15 39 2D 03 2C 36 6C F9 7A E4 91 27 FC BC 9F C1 BC D3 9D 5A F3 EE 4B 72 6B 64 D3 A7 E6 E6 64 AE 4E 8C 14 E5 8C 9A 85 44 B5 F7 89 8A 33 BC 12 00 9D 9F 29 AE 07 C4 A1 B6 C4 D7 61 4E 85 B0 63 DE A0 1B A3 CA 1E EC 35 EC 9D 78 9F DE CE 09 25 D2 38 A9 64 35 6C 9E FF A1 66 7C F2 E7 3C 6A 0D 2F B3 90 2B DA 59 D0 17 E7 93 BD 4E FC 40 A5 71 AF 33 71 D5 DD 3C 53 E6 E6 70 7A 96 F4 49 4E 48 C3 09 8E A8 3F 9E CE DA B5 9B 07 B9 F6 00 6B CB E4 B8 D4 D6 BE ED 67 59 2B 22 E4 7D 61 B2 29 83 77 D1 F2 AD 1C FC B5 80 55 1F C8 2F 58 70 74 91 B6 2F C6 0F EE 3B 56 C6 43 1D 10 8E 0A 9A 72 6C 07 81 26 B5 11 BC 08 60 71 16 2F 3C 1E 79 BB A5 60 EF CA 62 21 B3 EB 5B D9 A3 59 F7 0B 13 20 97 18 6A AA 9C 88 ED B4 31 83 C1 09 1C 33 BC 62 A0 BE 36 1E AF 78 1D DB CB C3 C4 88 B6 CA B0 38 8B B4 42 E3 08 5F 78 A9 E7 6A 43 02 04 5E E7 1F 17 AF 22 7A F5 02 5D 4F 71 09 56 4A 30 CF 56 8B 62 2A 0C 23 BA 05 98 C4 AC 88 F3 26 46 D4 47 BD 0F 91 80 02 96 57 4A D8 01 B0 51 5B B3 F1 AA B2 BF CC 99 EA 89 53 71 49 E6 92 9B 15 C2 DA 88 F9 6B F1 AA C0 DC 89 7E 4E 5D 25 11 1C C7 26 67 08 56 99 4C A1 51 71 FE 65 48 BD B8 D7 3A 3B CA 5C 44 D3 71 0F 2A BD CD B2 36 C9 37 72 93 E5 33 63 B0 7A 56 1A 32 6C 13 02 6E B3 DB 10 E4 02 ED 79 DB BE 9D 2C 30 D3 C0 DC 5B C0 56 66 EE AB 82 BD DC 3A F6 F4 E9 53 79 F6 FF 74 FE 15 51 CE 6D 16 DD 97 69 4C 32 8E C3 39 08 BB 95 14 BE CF 6E 78 5D E8 BE E4 89 E2 F1 05 D1 8E 04 79 9F 9C D2 8B 00 42 56 BD 50 32 94 C3 0E D3 4B C1 A4 F0 2B F7 CD C6 EE D0 26 0C 38 26 E0 C2 1B F3 DF 35 B2 97 2D 60 1C 37 77 E5 5E 48 E3 EC 2D 8F 8C 1E 42 40 C3 CE E1 86 E2 DE D9 0D 9F A7 91 58 1F 84 FD C7 AF 83 70 58 43 C2 4E BD D4 9A 76 35 E9 6E 63 BE 70 F7 4B A5 8D E6 5F A6 4D D0 2E 37 5B A7 CE C0 C8 73 73 78 79 92 A5 ED 39 BF 6A A1 FF E3 81 ED 9E 12 10 1D A1 32 74 2A 36 1C 50 29 4F 4A 56 01 D4 07 7A 19 5B 1E 70 0F 0C A6 07 B9 2B 09 FC 27 A4 B7 0C D4 A4 D5 7A 88 33 A2 42 A1 B3 76 E7 FD FF A9 AD 07 4F 6D 62 22 96 2B 25 7B E1 83 F0 A3 CA 17 02 01 BD 1C A6 8B AC 48 82 94 51 D3 4C 6B 75 20 6B B9 26 17 01 16 D5 0F F9 CE 2B D3 46 C2 4F 1E 45 B5 36 14 51 1C DD 0A 4A 0F 96 AA DC EB 9C 20 2A 21 A0 71 29 39 F3 E2 44 FE EE D0 66 74 01 8A E2 EC 45 82 DE 73 4D 44 26 D5 42 38 A7 CB D0 60 59 CF 8E 61 1F 9A B9 94 BB 0F DD AF B4 AC 24 30 95 19 0E 28 67 6E 11 12 57 2C 59 4D 5F 89 4F DF EF EB 41 F3 76 1C 3D 37 18 F0 6B 26 74 F1 1A 75 1F A3 A0 13 B8 09 8D 9C 7E 40 98 D2 1D 0C 70 DB 23 E5 F7 5D F9 EE 68 2B 8A 69 BE 57 25 B3 FD 60 91 03 34 67 04 60 19 6B 77 8D 93 11 82 42 EB 3F A3 71 27 E5 2C D6 1E DC 5D A6 47 29 B5 A4 09 7D 94 7D E6 9C 66 99 14 41 59 5B 12 AF BC DC 14 15 DD 09 00 C7 66 3B 02 AF 30 E3 EA D9 3A 5F 0E 0D 18 67 47 2A 37 4C F6 D1 4B 8E 73 02 62 DD 08 2D 6E 3F A5 FA E7 4E 05 B3 24 E3 1F C6 2B 17 F7 4F 7E E6 F8 64 BC 81 ED 71 FB 76 8E 61 25 B5 A6 DE 29 46 F3 92 70 01 26 F3 56 6D 7C 63 D2 1D BF 8E 9E 25 70 84 C9 23 9B 38 07 44 6F 93 8E D5 7D 72 3D 4B BF 91 A3 FC 17 56 6D 8A 7A B8 DC 39 00 91 48 18 D1 77 28 0B ED 19 55 36 D2 3B 7D 1C 17 AB 85 60 E8 6F 8E E0 EF E6 1F 24 69 7B 93 76 2D D0 B6 C6 CC 07 0B 5C 7F 01 CB C0 BA C7 5D FC F8 52 FE 68 47 50 F7 B4 48 15 E4 13 37 48 5F 55 33 76 D2 A9 F3 CD BA EF F3 70 A2 06 FC D8 6D 7C FD E6 8E DE 05 34 0C 4F AD A1 C0 15 D3 1B 9C 58 EA 98 42 3C FA 27 B3 B9 3B 04 06 B1 18 D4 27 C1 AF B5 D9 87 DF 26 D0 CD 7A 53 C4 28 6D A1 29 A8 5B 61 5A 7B 86 DA 29 59 CD A5 C6 81 18 30 42 FF FF 12 3B C8 92 3C 2E 6A 4A 99 1A 2F 44 A1 C9 CE EF 4E EF 22 82 D0 1B 7C B5 E5 A3 2F B1 5B 64 17 07 26 64 7D E4 86 F0 E9 FC 10 6A 11 BE C7 AB 16 BF B1 29 FF A2 92 65 AF EE D1 9A E0 F9 03 6B F0 A0 E2 9D AD 71 00 18 FA 26 66 F3 BA 7D F8 E6 CE F6 0C 6A F2 DE DA 1A BD 62 65 C6 E9 DC 0C 28 D0 F1 62 ED A5 E8 7D 6B AC 6C 01 25 1F 59 5A B2 38 44 E3 DF 3C 2C 1C 96 F0 D3 87 4E FE E0 C4 B5 36 16 1F ED F9 B8 9D AB C0 22 8F B0 F2 05 BB 9A 38 18 70 C9 92 A5 90 22 ED 3B 4A 6E BF 42 DB 96 5F 48 99 8E 6D C6 60 8C B4 FA A5 F1 2B 26 C7 54 A3 88 A2 05 AB 01 DC 5F 54 6D 91 B3 AF 7F 4D 94 7B B6 2D 78 72 A1 C2 AC 64 36 95 E8 1D A4 23 98 20 3F 43 AF 10 1D 64 C3 A9 96 E4 7B 37 92 9B 9A 1F F7 10 47 C7 BE BA 2E 67 FE 8F EC 3B 46 51 B4 1C 6B 42 3E 73 99 86 9B D5 7E 0D B9 71 58 3C 96 74 E2 76 04 91 73 A9 BD F3 39 C6 30 63 5A 2B F1 97 50 ED A2 F5 EC A5 A4 23 D7 1B 1E CA B6 78 68 BF 0E 03 C3 85 C6 27 BE 8B 1B FA E4 10 7C EA A6 C7 D1 D5 34 88 23 6B 51 F1 FF 53 B1 90 54 A4 6E A4 58 60 D6 D7 B6 34 8C ED 6F 24 A5 6D 09 FC 0D D1 00 59 01 80 34 63 52 AA DC 0A 2E 03 40 24 FD 0C D8 7C 38 87 40 B4 78 F8 82 35 5B FB ED 79 CB B1 4A 9D B5 E7 D9 8E 69 C1 F3 FB AF 27 9D 9F 0F C3 FF 61 2C C9 9B CA AD E2 A8 5F 9D 51 FE B7 0B 3B 79 9F 06 1A 18 D8 40 77 C4 8A D1 D4 29 B4 FF 94 97 77 63 E7 8E 6D F4 68 5E 24 26 6B 2D 7C 4D 57 F2 F9 97 4D A8 29 C4 84 78 1D 39 55 F2 FA E3 C6 47 90 30 7D C7 1F 1C 9F 2A AB 42 5B 80 ED 37 0D 9A B1 47 B7 B4 63 6A E0 1C 21 28 22 11 53 D5 FF 90 0D 61 3A 0C EF D8 07 E8 E2 D8 6B 1D 6D CF 58 1C 6F C8 60 D2 73 29 73 43 45 26 AA C3 EE 57 FC 5A 81 05 67 49 0F BD C0 EC E6 B7 BD 91 E0 8F 96 20 B0 C4 46 74 1D AA F8 64 60 0E 7A 21 C5 54 AE 47 CC F9 8C 90 EC B8 73 B0 09 39 E1 6B A0 1E 1B 25 D8 9C A4 DD A0 F8 B9 FC EF AB 62 1E 5B 86 3B CB E7 8A 47 D5 77 C9 D3 47 6E 28 7E 5D C3 96 7D D9 09 EF 87 C5 03 23 E2 18 CC 45 25 A3 89 C7 70 13 83 89 6B 66 18 E5 F7 70 69 AF CF 6E E1 B7 20 D5 81 A7 9A 0C EF 9B A9 93 8A CA B7 22 CE B5 DE 40 AC 5F E8 14 C3 F0 81 4F B3 45 B2 5E 3C C5 A8 09 42 11 6F 4C 87 A3 68 E7 D7 B0 67 D1 09 D3 4E 6B BA A7 98 7E C1 30 11 79 96 1F DE 34 73 EB 99 25 2A 64 5E 9D CE D6 A0 C7 B8 A8 47 E6 71 55 8D 4E 24 51 36 C9 CE 2C 97 A5 39 70 F3 66 99 E2 45 35 6F E6 E3 31 AE 3F FF 5F 51 2B C1 E0 F2 50 46 BF 51 E8 8C 3C EE A6 73 FB 2A FD FC EC 12 37 86 BB 56 F9 0C D3 15 AC 66 E6 7D 90 A3 06 82 D2 0B AD AB A1 37 B7 B9 6C 11 F1 AD 46 3B 83 A7 4E 14 11 5F E9 47 24 8A 7C B9 50 EA 07 C5 8B F3 64 2B 44 15 DA 34 00 6A 5D C3 68 93 18 A5 B1 75 D9 73 71 BA 52 E5 25 D9 CD 85 E6 7C 61 2D 9A D3 3B 6B 3E 99 5D 70 77 FD CF 70 95 7B 3F 9D 9F 04 C1 D5 66 55 FC D3 D9 DC B9 AD CC B2 40 75 FF 9A 58 FC D9 08 B2 F6 07 B2 B5 9B AE 2A 5E 97 FD FD 34 C0 7B C9 88 30 EA 8C 82 1B CB D6 69 82 84 5E 2D 0D FF 11 E4 DA EC DF 6A 96 AE B8 37 66 D3 93 4C F3 1A F6 C7 EF 54 EC 5C AD 6F 3A F9 0D CD 11 16 8B 1A F9 5A AA 16 5D 34 C1 3B D1 06 AC A8 78 EC 22 37 3A C1 F8 F3 38 76 A5 DD 7A F6 C6 D0 8F 0F D9 D3 18 90 DB BD C7 96 CA F4 14 FB 13 11 0D B0 02 64 B5 7E E2 5D BC D1 1E A3 FD F6 05 B6 B8 BF 70 BE 69 40 64 28 E9 BB 75 8B 41 16 EF 44 65 77 4B 89 CF A8 C5 1D E5 DE 0E 0C DB CB C2 D3 7B 95 85 CA 7F DB 41 0A 4F A2 A9 1F 22 CE 26 C8 F1 79 4F 44 15 E0 52 9B 94 B1 FE 99 EE 7F CA B7 0E 01 A5 C6 9F 44 D0 A2 D3 44 EA 8D 8C 9C 43 95 D2 13 4B 48 13 71 33 47 16 6A F5 41 12 88 57 1A E4 A3 EC 53 7C 54 D0 E9 82 03 91 07 65 64 EB DE 98 76 C4 01 0B A7 A5 A5 6D 7B 7B 78 A7 E1 35 BA 9C A6 CE A9 50 75 11 E3 7E B8 97 BF 26 5F 2E 97 AB F7 47 AD D1 BE 66 7A D8 61 46 FC 2B 2F A6 C6 AB 79 62 78 73 AE 19 75 66 CC E3 93 28 AB DE 3E A2 49 A6 05 C3 7C 96 3B 49 EC 9D 07 A4 AF F4 BD 73 07 3B 3E BA 39 6C 09 97 4F 29 91 30 66 66 C5 A3 0A CA C3 5C 3A C7 56 F5 6A E8 4F 62 46 99 47 21 FE FE 49 B4 2E 49 D9 3B D8 91 D9 28 79 F8 91 63 8E DA CF 8C 79 BC 79 A4 2B 93 5E A7 F4 A0 94 93 9A E6 E7 A2 CF D0 09 70 1E 92 0D 4E 21 AC A4 05 17 67 1E 8C E4 7A 91 CA 28 10 20 59 25 D1 7C A9 EE 73 C7 9A 44 3A 70 12 1D B3 5D C6 A9 20 99 55 12 A3 89 87 66 38 0D 4D 9B F7 B5 2D A3 50 04 B4 E7 3E 86 BC DC C7 4C B0 17 6F 94 00 E2 FA 70 AC C9 1B 86 FD 5A 20 6E 33 3D 3E B4 89 37 4A 7B 95 EB A1 77 B2 CE E2 23 CB 48 D3 C6 62 DC 8A 42 EB CB 39 B7 E1 0B AB 70 8F 6E 66 4B F6 A3 7F BF 22 27 FD E2 61 DC 1F DE 5A 8C B3 BB EE 62 77 51 8F FD 85 8C BA DE C2 9B E4 40 21 BC A3 DA 1C 1F 9E DF 70 39 C5 DE C6 5E A1 09 1A BA 4A DE 81 F4 BD C7 8E EF 8E 6F 27 18 1F 34 72 4B 12 92 3C FF B3 46 97 C6 B1 ED 81 71 89 34 4C 91 3A 33 0D D0 72 8F 3D 9A F3 1E 04 61 C6 A6 83 F6 CD A3 47 BE E6 30 01 0A 18 0F E8 08 15 0C 9B 35 65 A8 E8 B4 20 3C A5 33 E9 F6 1C E7 AF A4 85 17 9E 26 B6 37 9C 48 9F 4E 05 91 07 DF 58 7E D4 0F 47 AD 90 EB 39 F6 36 C6 DE C2 02 AB 3D 0C 37 49 8D 79 0C B4 25 93 CC 61 C2 AC 2C 2C 9E 8D 51 EB 91 46 9B 6A 77 70 ED F3 A5 0E 01 08 F3 70 65 3D 30 A6 B9 2B A9 AB 0A 52 58 44 22 32 B5 7E 95 B1 9E 72 F8 74 1A 07 DC 05 2C 7A AB F9 42 16 40 BD 3B 1D 61 81 80 AA 7A FA BC 47 8D 6F 6B 9D E3 EF 3D 26 85 5B 04 33 32 70 AE 32 C9 82 DF EE A0 06 F3 C0 94 DE 5C D7 0E BD 6A C3 8C 9D 0C 22 7D 1C D6 69 F1 33 79 E2 A7 0E 2F 1E 87 90 DF 39 1B F2 1E 91 9F CC 9E 09 CD 41 25 C5 C0 29 53 AC 40 24 B0 25 77 2B 95 23 D0 5D CF 68 AB 5B C5 4C 37 C8 0C 80 68 B6 80 09 8E 1D 27 B0 25 73 90 0A A6 E5 1B 75 E7 3A B9 41 A5 C6 74 F2 9B 15 8D C9 EA 55 BB E1 1A E3 79 FF A9 C9 8F FD BB 25 CE E0 A5 7E 6A 3F 4A 3C F3 45 90 7C 45 D2 12 A8 F1 0B BF 94 88 4D 58 D7 BB 95 D1 D7 63 22 8D 99 A3 FB 7B D5 18 8F D3 FC 3C B7 9D 29 47 18 1E AC 34 DA FF EC 16 FE AB 19 DE 52 02 1B D4 13 13 29 74 3E 09 32 47 8B 96 89 CE 0E 5A F0 D6 02 BC 0C C5 84 E6 A1 99 28 A5 27 AC 56 68 55 C4 6C E9 14 26 8E FC 34 9E 60 73 D8 54 06 13 AB A0 EB 26 02 2F C7 2A EC 1D 37 FC 46 93 2C AD 76 72 9E B1 66 57 8E 61 76 D1 4B C3 E0 6D 39 84 27 E7 3D B2 25 92 DF 0E 1E 6C 63 73 CB 29 6C 79 8D 53 40 7B D8 72 50 88 42 87 67 EF 26 3D D8 4B C8 C4 DC 8D 0E C5 A3 CA 5F 14 BA 3C 6B C5 D9 9E 03 66 08 AF C4 F5 E9 A3 EC FC 5B 2D F2 37 79 4B 74 16 17 3A 83 0E CD 3E 81 85 A5 D6 27 4C AE 0E BB 41 58 5B 94 6A A6 D4 71 C7 61 86 40 CB C9 FA E7 B1 FF E6 14 69 E4 6F FD C1 84 77 F9 5B D4 EC 26 DA 5C 63 3B 54 27 E6 C5 92 8B 38 DE 7F A3 F6 B6 C2 BB 39 47 5F 1E B3 61 4D 7E 6A D9 42 44 A3 FE EE C7 43 02 96 AF 94 C1 63 56 28 3E 3C C3 2B 5E EC 6C 7F B5 39 58 83 EF E6 31 24 6B 00 A3 FE AF 3E 48 7C 13 B1 2B 46 D6 9C E7 F6 5F 76 FE C8 F6 BA 30 4C C1 CA 39 83 C3 26 BC A2 97 26 44 92 F4 1F 95 AE F4 3B E1 F6 0B DA E9 E6 89 C7 B9 52 0F 20 1B F0 34 E9 2D 9C B8 96 FB 2F 24 51 36 1B DC DA FF E7 14 79 4B 0C 7A C6 55 28 B8 90 B7 0A 41 B7 92 69 C7 E4 9A E2 E7 F4 AE D2 84 B2 AF 95 E7 C3 19 4F 5C 00 9D 5E 51 7B 6B 6D 85 F6 CA 87 F4 50 61 70 EF 04 36 0A 8C 8B E6 A0 31 52 CA CB C4 91 FF DF 75 BA 7D CA 5F 13 54 4B 5C 40 25 C0 2A 17 7C 35 B1 84 7F 8C 11 3F C7 68 12 C5 C9 AF FA AA B0 F0 82 95 48 67 AE E9 55 11 57 DE 3B BC 2C 90 A7 CD 7B C8 F8 52 10 BA B3 98 24 A7 E5 B3 83 8B 01 F9 E1 1A BA 5F 0C 91 43 3E DA B3 34 73 80 CA F4 BF 7B 43 B0 AF AE 39 B0 4C 45 05 89 EC 8B 03 38 65 83 48 8D EF A6 9E 17 CD 3D 92 5A 92 88 57 95 8B 55 9E 38 90 5E CE 77 E9 34 67 96 17 B6 C1 72 71 9F 71 C7 DE E9 D6 4A A3 DE 59 68 8E 63 06 C8 CA 03 D8 8B C3 19 32 00 F8 3F 91 0F E9 2B BA 48 53 94 18 CD 41 A5 0D D5 60 F7 83 67 C4 EE 2B A6 AF BC 71 77 C5 27 71 18 41 75 98 DC 4D ED AC 0D E3 2E DD 7A CA 07 10 8B A5 F2 C0 5F 77 D5 66 CE 47 13 43 C5 C8 35 E8 9F 1A 08 42 7B 05 CC 4A E3 D4 64 68 2E 66 5B 14 86 69 13 AF D5 C2 D0 7D FA 46 80 23 3E 00 52 E3 AC 6F 56 1F 43 AE 70 6E 92 51 FA C8 15 1C 11 0A D8 78 A4 DA A7 C5 1C A8 4F 60 3B 4E ED 06 68 42 53 9A 3F C9 EA 77 DA DC C3 9D D0 C2 ED 19 9B 53 46 BD FE 74 84 88 F3 01 86 5C 30 DB 50 62 88 9C C3 74 BE CD 00 31 F3 57 9F D5 AC 31 0C E8 97 D2 8D DA EB 43 D1 58 1A 8B EA 6C D6 58 1D 3C 9E 7E 4D 0A A5 CF 57 52 3F 6A B0 F0 C4 ED 43 FC 63 A2 87 CA 28 AE 47 6D 43 E3 4D 1F 68 2A A6 9C 20 F1 46 5E 80 42 0F 19 AC 82 22 8C BF E3 E7 F4 43 08 48 70 F5 04 DD C1 D4 F4 2D 40 35 C4 05 DA 33 23 52 8E 58 B8 30 57 AC C2 DF 98 1F B2 43 81 81 32 EF E8 80 6B 4A 24 B6 5B 0A B4 7E D3 6F A1 02 FA A2 E6 59 71 4E 3C 1B 67 9C 35 EB 0C 85 BC 05 63 11 79 35 AD 94 41 13 83 71 F5 67 7B AC 6C DF D6 56 8C 3D 2F EF 83 6B 8B 55 19 1E C4 28 A3 CA 6F BF C3 A4 F6 D1 0B 75 AD 01 3E 27 62 D7 D8 5B AC D2 44 C2 B7 AA 7D 3E 61 38 80 DC F0 F3 C1 AF BC 69 1C A1 84 9E D1 DE BF A8 53 19 59 CA CF 45 2C 8F B3 B2 18 2D 68 FF E1 76 AD 42 2F B4 82 8D AA 4D 94 DA A4 73 76 7C 31 BC 5E 85 3C D6 6D 17 C1 94 97 9E A7 A6 A2 9D D1 CC 85 F2 FE 95 D8 96 2C F6 AF 66 F8 04 D2 59 48 06 EA 36 BA CD 37 DD 3F 56 0D 42 8C 16 04 87 54 54 E3 17 F8 E5 0D 39 79 D6 C7 60 90 33 F0 72 34 0D 66 3C 40 75 15 EF 9D 67 A4 E0 7A BD 98 4D 20 8A 50 17 01 0A 7A 91 D2 7D 10 64 20 59 38 93 3C A3 66 6C 6C 7C 7E 04 CC D2 95 01 E4 CF A5 A4 4F D5 E1 C2 C1 80 45 E2 4A E3 55 E7 D6 AC 42 E2 7D 18 4D 7C 44 74 B8 34 83 1C 2C 65 04 96 33 32 3F 45 E4 4D 9F AD B6 92 4F B8 30 B6 3E 08 44 9C A8 E7 F0 84 3E D3 8F 99 EF 09 D6 CC 26 0E 99 48 DF 52 8B F8 0C 31 6E 18 BC 8D 1D BC 66 FB 42 D7 CD B2 99 15 CD 6A 94 61 29 E0 4F BE 42 77 32 55 CC E7 2D 72 D9 45 52 0F 2B C1 A1 7D 34 FA 2A 7E 9F E3 2D A1 24 69 30 34 00 36 2B 9A 53 FE 10 05 B3 63 43 44 97 88 B7 6E 03 8F 4F 63 5F AB 5D D0 F3 12 B2 3B B4 95 A4 1D 0F 4F B5 93 F7 26 82 C2 E6 42 69 F3 EC 58 81 E4 10 4F E4 4C BE 8C 91 AC 3A BD 45 5A A6 10 D0 9A 5B 1A 7A C9 81 DE C7 F6 6D 21 78 B8 15 4B E3 6B CC 14 F3 82 43 0D 18 2B 4E E5 C7 2A C9 E6 CC 22 0C E8 6D F5 8B 36 50 94 8D 56 56 9C 85 F9 6C CF B4 9A B7 57 75 21 B9 14 F0 6E 94 CA AE 3F 34 08 3F B6 A8 BA 70 40 17 C6 FB 1E AD 85 9E 9D 1A A9 74 92 06 B9 62 30 2E ED B5 9B 3D 2D D8 C6 BA A3 F7 A1 52 55 01 A4 35 AF 04 32 61 D7 8E DF FC 3D CC 58 73 6E 19 A3 AA 82 D6 C9 A8 AD 10 C7 84 FC E6 AF AF BE 38 AA 7C 37 86 CA B3 C0 D8 98 B9 1F 16 88 79 A9 48 35 81 E4 EC AE 62 12 61 74 34 39 B9 D3 1A 4B B9 8F 26 22 7A 56 19 47 95 4C F6 B3 B3 A5 F3 61 68 F1 62 3C B4 64 EA D1 26 F4 95 7D 15 61 58 CE 6D DC 41 B1 0C 56 F5 90 52 8B 0E 98 19 A5 3B BB 1B 69 37 83 65 62 F5 47 2F C5 FF 8F F9 9B 4C 56 FF 70 C7 9C 1D B9 29 71 56 6D 36 E9 F1 37 5C B4 6E 1E 3F 2E 1A AB B3 7B 93 4C 1E 80 27 1B 50 42 9D 74 B3 48 74 6F 63 A1 90 86 D3 43 64 11 7D B0 50 6C 80 92 64 82 7B E5 F1 68 42 48 D2 23 A6 55 11 B7 DF A1 29 1F F8 61 8F 45 94 3D 1E F4 74 96 5D EF 63 DA EC 6F C3 59 B3 A2 1B 4B CE 2F E4 88 C7 70 A5 3D 53 1F E7 6D 3E 96 9C A2 57 AC 2E 53 70 A8 5F 2F F7 D3 5D C8 C9 89 A8 45 21 23 14 F7 61 4C B4 72 21 30 E1 05 97 19 3D 84 CE 0C AF 8A A9 F6 B6 3C 78 B2 0A 41 DB 80 48 EF 1D D2 27 B7 F6 0C E0 32 CF E1 AD 92 AF 6C 8F A1 FD 69 BD D1 0E 6B 87 2E CD AE C9 56 74 41 9B FB 92 80 2E 28 7A 28 7D BC BB 29 FB 1F 69 3E B1 0C 1D 13 95 1F 97 44 04 3E 64 09 F8 B8 2B 2A 4A C3 FE F0 7C 85 36 A4 E2 DE A6 2B 78 A6 A4 8F 79 0A BC A7 1F 06 E7 41 0D 0D FA FA C4 B8 2E F1 1C 4F A6 EA 54 6A 37 09 45 48 45 4B 1D 3E 69 46 52 95 BE CF 18 24 FD E6 09 E2 AB 96 A5 52 4D B9 AA 2D 17 E1 5B 73 28 23 F8 EE B9 8D 0B 46 2F EB 13 44 56 8A 66 77 3C 43 8B EF B0 F0 6B FB 26 DE 57 02 DD 42 6C 72 40 C4 C9 38 16 D0 48 0B F0 FF B2 AF 52 16 9D A8 2E 13 A6 3C 1B 47 32 3E 7F 73 3C 88 BE 6B BB 6F 9F 0D 3A 34 B8 2B 87 26 C3 16 B0 65 62 03 65 0D 45 A5 13 B3 10 D6 1F 5F 9E 84 0F 9D 39 F2 27 F7 87 F2 92 E8 A4 3C DD 62 08 AB 59 02 D6 7E 36 99 D6 A5 C4 1A 6D 28 12 4C 77 34 7F 0F 10 F7 5E F8 3A A5 2E F1 C5 D2 B8 3D 9F D4 1B 10 6A 52 B6 EB 85 CF 34 21 19 DF A0 04 75 6E 67 7A 6E 3C C8 02 3D 46 53 7C A9 0F 2D BF 1C 9C 7B 62 07 8D 0B 4B CE 90 D3 1B 32 07 BA B3 B9 16 AF F1 FD FE 05 74 E1 BD A7 B2 E2 CE 9B D6 5B DC 59 DD AD 49 BF 52 37 A1 FF F1 D9 2E AF 70 F4 F4 63 5D C3 2B F2 E3 25 5A 4F 3B AC 5E 63 46 85 F2 B7 B4 98 B2 0F 15 B4 5A 18 41 F0 EF 28 6A 5D C3 79 60 F9 BC A5 EF DA 68 4D 3E DF 53 E3 E9 86 79 F2 F1 8B E1 26 88 6E 45 B4 A9 EC DD 71 88 4A F0 9A 4C 06 8F 17 A7 96 CF 41 68 AA CC 2B EB 71 68 FC 6C 9C E8 3F EE E5 A6 5E F4 58 4C E0 B6 FC AE 3C 80 47 D0 B6 20 84 A7 C4 33 4C 15 52 B5 FE 93 DA 6D 6B 8A 8B 6D 09 B2 EF 11 AC EF AE 5D D5 4C 5A 2B BD AD 78 00 3C CB D3 42 B4 26 60 08 05 89 13 1A 40 B5 F6 0C 07 B9 0D A8 ED 15 5B 86 F6 E0 58 31 6C 05 D8 8C 5A 13 B7 14 EE 5E 34 DC 1B 6B FC F4 9C 2A 94 E0 45 99 40 8A 3E 8A DA A6 66 16 3B 0D E5 9D 04 1E 84 36 8E 39 E9 45 1A 2D E7 77 D9 6C A5 EA 0F F7 B2 AC C2 36 22 46 F4 F1 A2 13 6E 8D 4D 47 1B 3D B3 D1 24 65 32 76 CD A5 49 1C 78 68 38 84 4A 89 34 A9 A5 A2 76 C0 E3 AD 1E 48 E0 75 DE B7 C3 D4 16 70 F3 34 09 C3 4C B4 50 B8 3D 9F 0D 0B 01 E6 F3 6A 6F D9 6C A5 02 53 89 31 03 2E 65 D0 F1 0F E6 59 8E 29 1D 7D B1 32 B3 12 EC 2E E1 1D 8B A2 9A ED 05 98 28 7B 6F 0B 29 FB 33 ED F3 80 2F 3B 58 53 BB E9 AF E6 25 F2 D9 C4 D8 E9 6F 07 00 3C E5 0A 5F 03 3A B2 F9 08 4D D8 5E D1 3A 8D 8C 65 A1 C0 37 F8 43 B5 53 F4 67 65 27 8B 22 A5 61 C5 A1 6C 34 F0 E9 E0 16 44 53 45 D5 5A CF 5C 9D 59 A9 3C 0E F3 37 1D 0A 93 DD BB 3B 87 CC 7B 6F 08 F9 0F E5 D8 10 F6 E0 91 21 4F 81 56 EF 9D FF 0C 6E 03 71 D5 62 9D AE A0 C3 34 03 6A 60 97 8B FA 74 50 B1 91 E6 F3 84 CA 93 E6 61 38 FC C5 1A 53 8F 9E F7 4E 75 D1 86 34 C4 60 C6 CA 32 EF 22 7A 51 53 4A B4 DC E2 B6 E4 E8 50 AC 3F ED C3 C5 8A 38 1E DA 9D B7 F9 CB 84 77 6D 69 F8 95 69 4D EA FD 01 DD 6A 60 9D FF 9D 33 40 32 D7 18 E2 03 B3 7A 71 5C 22 6C C9 06 4E 0A 16 CA B8 F0 01 9D E7 FE 93 87 F4 15 C5 1D 0B 77 B0 26 A3 CE 36 44 63 97 56 A5 28 AB CD 7E 56 60 6A FF 14 20 EA 23 BD 7E BE 49 5B 0A A5 75 0B 22 29 35 53 DD ED 34 7F 83 CD CC 79 D0 69 D5 80 5F E1 85 A3 42 3E 4E 6C 4F CB DC BD D6 4A 8D F1 69 6A AA 24 59 06 DA E0 92 E8 EC 9D 2B 69 93 B5 03 5C F4 C4 E8 BD D4 6C EB F2 80 CE 08 74 F3 EE B5 62 4B A0 4A 5A F1 47 01 91 90 46 49 50 40 75 1F 0E 85 20 84 9E C9 77 DA 56 E2 2D B1 AB 19 F3 49 9D B3 1E CE AC 40 8B A6 22 A6 DB EE A7 9C FF 40 30 EE 90 DF 07 CE 0C AA 0A 4F 33 1D CC CE BC 62 CD 0B C0 A3 71 51 45 A2 63 AB 0E AD 59 B9 B2 C0 19 98 59 42 34 38 D2 EF 01 B8 FC 59 1C F1 DC 2B 2D 5B E1 EF C3 21 E0 51 94 3E B6 34 5F F5 3F E9 05 15 48 44 3A 41 85 5A 2D 5F 02 B8 2E CD 7D C6 5A 5E 56 C8 BC BE 41 F8 FB 42 3B 39 29 C4 60 A5 EE 61 56 E9 6D D2 1F 2C AD 19 E3 11 45 57 F8 F0 F1 03 FE CD 5D 56 37 83 CD 05 79 F7 E0 13 61 28 46 92 CE 6E 82 CA 56 B1 A0 4F A8 E4 FD C8 EC 16 D5 9F BE 53 CC CE C4 83 48 54 2D C8 47 F0 98 F0 62 1B E6 E4 93 58 64 07 8B C2 9D 9E 9C AD 4B 86 BB 65 39 07 35 EC E0 3B F2 34 E5 6D A0 F0 A0 45 AA DC D0 1B B6 32 9A C3 57 6E D9 33 C3 35 44 1A EF 8C C3 EA 72 21 8D C9 9B DB AE C9 5B A2 2F 8D 4D 7A 09 A4 38 AC 31 58 8E 6A BC F3 CA E6 45 E4 48 62 6F 19 EA D4 9B DE 59 CB 70 C4 B2 EF E0 68 32 76 2F B6 92 3C 1E 9E DC C3 9A 57 C9 14 61 9C C2 2F E5 3A F7 27 59 BC 7D 84 9F 6F A8 45 29 72 E8 C9 7E AD 74 43 32 92 E1 85 5E F3 13 20 0F 2B F0 FE BC E4 7B C2 E7 7C 9C EF DD F5 E5 16 D5 F2 1D 9C DA 47 4A 78 10 10 A1 F3 62 E9 A5 D7 3F 92 86 D2 A6 C7 AF 80 9D 75 86 F2 5E 2E BD BC E1 69 C4 CD 0B E4 EA F3 9F C8 7B 4C D8 42 4B 98 17 10 96 BF E5 09 0F 23 0E 78 B2 F2 B0 E9 FF 2D 1F 03 92 22 FB 31 97 27 82 31 A0 DB ED D1 EF 73 D4 1C 73 43 EA 2B 2C 7E 52 D6 6C D8 68 C2 FF 35 6B 00 F6 2E 9A 91 9F 12 E4 CD B0 63 51 35 6F F5 50 4B 5B 82 A0 78 4E CA 08 E7 AE BD 87 DD C8 76 FD 24 48 2A 0E 78 B9 D3 5F 55 D2 BE 8E 47 79 69 48 B5 1C F5 F4 D7 66 36 7B 19 4E 33 15 D0 31 0C 17 13 D7 1B 1A 6D 63 76 CB FF CA FD B5 C4 15 66 A4 4B 0C F3 8A 93 49 94 57 8D 64 5E 1D 88 0A 83 72 0E 7C 02 B0 F1 8C 79 75 84 59 A5 DD D4 15 8D 96 29 BB 07 A2 CF BF 3B 2C C8 1E A2 D1 76 C4 46 F7 57 D6 9B D4 EB A4 95 99 D2 88 80 9C 74 89 C4 32 8A D4 24 11 9E 21 C7 B4 15 8D 08 7F D1 A1 7C C2 4D 10 30 2D 70 6D 3D D4 F6 12 1E EC 1F F3 F3 CB 27 51 32 47 CF FE C7 97 D4 28 F7 E7 B5 40 BC 29 63 D5 2E 87 11 50 C5 AF 30 32 49 4B BC 00 FF DF 8C 15 F2 99 7E A0 90 95 14 AD 64 4D AD 80 7B 3A 8E 3B B4 07 7D BF CD C0 91 70 6A 12 72 C5 91 E5 0D 36 FC 87 44 47 D8 C3 DF 34 A5 CE 86 DC B5 19 38 32 54 88 72 E3 92 19 A1 1B 49 BE D2 FB 6A 97 A0 7D 50 58 BB E8 4D CA 83 F0 69 0D EC 37 4D 66 97 62 63 F7 6A 54 A9 25 E1 D2 97 12 72 55 6A BE 6B 4C F4 31 7A CB 2D 02 D4 67 3D EB C8 B8 8C 9E BC 93 3D 6F 0B 3A 96 94 3B 99 98 51 62 10 5F 8C 31 8C 17 A9 55 01 7A B6 00 70 4D 69 C0 9A 13 5F 9A EF 98 E1 41 C9 DD 5F 5C A3 79 AD C2 D9 51 73 27 9B 00 95 CD 57 1E AE CD 05 0D 33 13 85 E4 65 7F 52 19 55 F8 0F CB 53 3F 56 2D 79 1E 93 16 B4 53 40 CC 62 67 CF 9E A7 F5 00 8E 6E F9 B1 D3 43 47 C4 4B 29 F6 A3 A6 BF 19 16 2B 75 9A 6A 73 71 17 07 DD BB 1C 23 A2 7E 04 FE B5 38 64 DF A2 D8 81 6A 4A 03 BD 8B 40 E1 28 0B A2 56 3B 6D A4 D4 27 2D 65 25 51 3A 47 15 9D 6A 54 5B 90 E6 17 11 58 02 C8 B3 AB 29 46 D9 7F AE F2 20 F3 D4 71 B7 2B B2 C5 E5 17 01 CF 03 2A 12 84 C3 2C 56 6A 0C 08 3D 24 7D B5 6A 97 B2 F6 E4 94 3E 51 DF AD AE BD C1 6C B7 19 13 00 E1 57 C6 6D B4 A7 1B 02 BF C4 45 A1 52 26 47 96 37 20 DC 0E 68 7F 69 8D AD 83 FD 19 F2 3A 21 06 4C DA 5F B3 16 D1 A4 4A BC DA 4B 93 EC 90 D0 A2 96 1B 85 C8 0F 81 6A CD 4B 76 8C A9 DF F1 ED 70 0C 79 66 A7 56 0D 2F F3 71 4D DA 44 B1 9E A0 36 53 36 35 AF 3E 87 49 95 80 89 11 9E 1F 5B D8 29 84 9F BA 22 B3 86 AA 94 68 DF 8E 31 F1 AE CA 24 2E A1 25 25 76 83 49 F1 C0 62 20 B0 A8 EF 3D EA FC 75 B1 BC 33 AB BF AE 20 22 F9 E7 26 A8 E1 91 15 A3 AE 4D 7C 1D FC F8 2E 56 BC 82 CE 21 F3 4B 26 49 9C 09 85 F7 D1 7C 10 39 C3 E2 05 3B A9 AA 4E 48 68 F2 CF 58 90 8D 92 23 3F 10 5D 3F 0C F3 63 2C 1D 46 81 07 14 48 2E D5 58 C6 51 40 0E 20 2C 90 FB D9 71 FB C8 1F AF 7F 3E 53 E1 AF 0A 8E 0B 5D 9F 9C 69 6E F0 E2 DA 52 8B D1 3E 23 79 5B 23 D6 E0 B3 19 42 69 06 E4 F1 B9 B6 BF 0F 17 89 5C F6 09 63 62 73 96 23 02 74 A6 46 91 F1 09 20 C7 4B 9B 4B B7 C2 FC 28 30 3A 15 37 65 9E E3 6E 45 49 75 C3 8E 3C DA B8 E5 4A 09 92 E3 87 BE 0D 39 B2 B3 2D 5B 31 82 F7 FB E8 72 65 8B A5 52 09 FD 35 E6 32 F3 65 DB 9D E8 F7 F5 13 49 BA 28 EF 7C 3D 6A 8C DC AF CD 0B 18 61 20 C2 10 B8 94 B7 B5 0B AC 22 E7 84 7B BD 0D 8A 52 DF C4 D5 8B 30 82 C5 F7 BD EB 6D 6F 1D 3B 59 07 39 02 52 51 67 2D 16 F6 95 01 74 EC DD C8 3A 1B 86 60 28 B3 BF BB 60 9F CC B7 F4 59 E5 02 DE C7 79 B6 B7 C5 2C 15 35 58 81 98 06 E7 BC 3B 72 7B 04 ED D0 27 BC 6A 09 54 8F 0F 56 51 05 73 49 89 B4 18 8E CE 70 EC 3F F5 F0 50 9E 68 6D 1E 1A 6E 1E 8D E0 AD 2A E8 46 3B 27 E5 87 E1 D3 20 79 0E 09 15 25 70 05 91 7E AD B2 DC C0 A6 BF 4F 49 85 5B 4D C1 96 2B 55 E7 E3 D0 6D 99 A9 AB 36 E6 22 EC 20 6E E8 E5 2A 6D F9 8D 3B CB B6 53 A2 AC F8 71 1B 30 3E 9A 74 08 FA EA BC 91 F6 74 03 D1 89 4B CC 72 80 29 F3 A6 F9 E5 BF EF A5 FC C8 ED FD 18 FF A1 5F CE 6C DF BD C4 58 52 64 A4 11 E2 38 F5 6A 99 52 49 A1 A9 09 8F 14 9F 09 AC F2 74 4C 7F C6 0D DA A4 89 EB A9 C5 F0 4E 6C 37 97 40 0F 0F 3D 36 E5 95 F3 EF 39 B8 D7 69 09 92 2C 91 D2 82 20 55 00 67 5F D5 F0 C2 24 4C 3B EA D2 9A AB 32 2D F0 55 AA B7 55 A9 F0 EA 3F 04 DA DA F3 1A 19 7B 4C 50 ED 0D 5A F0 9F 53 C1 3C F4 58 44 3E AF A5 C4 15 FF BC 53 1E D1 74 70 3B 4B 0F BE 28 D5 25 72 19 71 51 7C 43 18 40 BE D1 49 99 A2 ED 38 42 3D D2 3E C0 CB 1E 60 D6 D5 03 E1 AF 8C 4B 59 89 24 07 C9 40 45 14 2C 2D E9 BD 7B 16 E0 39 3F CD 67 FB 44 99 CB C7 0A 4D 85 E8 FF 76 ED 12 85 AD 70 AD D9 C8 4B 54 85 8E 14 B9 15 94 F4 EB E2 B8 A7 DB 9D C4 AC 76 BB 3B A9 63 E5 30 58 20 C0 E7 5A C8 F6 EE 74 9D 29 7B 4D F6 48 48 99 95 FB BF B1 D5 60 D6 07 7D 0B 7A BD CD 4F AE 17 31 94 3C 08 CE 69 07 99 EC 19 C6 BE 6B 0E 48 2D 87 FA D4 79 8F FB C6 FF F0 45 5D D5 7C 99 2A 0B 78 3C 58 4E 88 9D 4A 82 BA A1 8B 6C 59 AA 60 66 68 77 5C A2 02 33 01 EC E2 B5 F0 A7 7D 57 6A 8F 16 39 86 36 C4 77 7D 0C EC D0 73 5B E2 31 61 0E 00 E2 87 43 E8 60 F8 1C C8 DF 3D 11 B8 D1 3C 48 47 2B EA 7A 74 E0 C3 63 2F 31 42 04 61 49 14 29 AD 53 71 9D 36 BE 6D EA 39 5A 02 E8 9A 27 32 5F A8 D5 38 DF E9 DD A3 84 A9 D0 B8 38 BA 94 0F A7 F1 65 11 31 89 B4 5E 24 3B AF EE 36 56 67 9B 73 62 F0 6F A7 2E 60 12 D5 BD 22 1E 16 8E A8 DF B7 43 8B 8F 3E A2 AE A2 87 08 B1 72 58 F4 F4 21 F1 9A 26 19 5C BA 1C AF E1 D6 D6 40 C4 81 DF 11 18 0C 0E A4 D6 50 3A 45 37 A4 6A 31 8D EB FA D2 22 13 C2 F2 DC FE BD C1 4D 48 A2 94 07 B5 CE EE E4 A9 57 95 6C C0 BF DE 24 B8 6D 0C 3F BA C7 79 04 68 2A 92 91 25 A2 D7 D4 CD 6F FD E6 BF 4C 13 39 00 D7 98 A2 83 9F 98 E2 3E 95 3A 22 B6 35 1C 30 AE F9 51 B8 C7 71 A1 B2 1A CE 77 D0 EA E3 B3 FF BF 66 16 D3 7B E3 D7 0A 20 67 A9 A9 7C 48 F0 AD 25 50 37 32 F2 65 87 B5 D0 FA 55 4D 84 95 15 99 79 18 9E 6A 14 C1 EB 26 EF AC 54 0A 0B 3E D3 83 33 31 EB C7 85 99 AC 4D 68 53 F3 69 F7 4D F8 E7 B3 D5 E7 57 0D 03 6C 47 95 B9 8A 17 33 25 DD 47 1C DF D2 D0 66 EE 31 29 25 4A 17 76 DE 69 FE 3D C1 9B BA FF 8E F9 D5 15 25 D6 4A 29 B5 3F 0A E6 9B 13 81 E8 89 6C F7 04 1B 6E DB 69 80 AF B9 1F 1C FD 39 D3 52 DD F5 31 B4 BC 9F AA 13 9F D6 29 05 D0 59 4A CD 0B 06 A5 CC C8 BF A3 87 D4 32 BE E3 EC 23 6F 8B 66 5C A0 66 61 81 5C F9 BE 92 9A 6D 1B 63 7C 3B 37 72 E2 79

# '''

#                 a8_data = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

                _struct57 = bytearray(deserialize_wire(output1))
                enc_len=len(a8_data)
                struct.pack_into('<I', _struct57, 29, enc_len)
                struct.pack_into('<I', _struct57, 33, enc_len)  # enc_len2 同步


                # ── 换 cookie ──
                _cookie = bytes.fromhex(" 3d030802000000002a3979af881d00")
                _struct57[12:12 + len(_cookie)] = _cookie
                log(f"\n  [cookie] 固定cookie: {_cookie.hex(' ').upper()}")

                output1 = bytes(serialize_header(_struct57))
                hex_dump("hybrid_body_dump_pack_wire", hybrid_body_dump_pack_wire)
                hex_dump("_new_wire", output1)


                _wire_body_len = 47 + len(a8_data)   # wire + body 总长
                _new_header = bytearray(hybrid_body_dump_pack_header)
                struct.pack_into('>I', _new_header, 0, 60 + _wire_body_len)  # total_len
                struct.pack_into('>I', _new_header, 60, _wire_body_len)       # wire+body_len
                hybrid_all = bytes(_new_header) + output1 + a8_data

                log(f"  wire+body={_wire_body_len}, total={len(hybrid_all)}")



                hex_dump("hybrid_all", hybrid_all)
                
                SECAUTH_HOST = "43.137.191.78"
                SECAUTH_PORT = 80
                log(f"\n 发送 secautoauth -> {SECAUTH_HOST}:{SECAUTH_PORT} (rebuilt packet)")
                print("psk_result1", psk_result)
                result = send_mmtls_cgi_request(
                    psk_result=psk_result,
                    ecdhe_plaintext=ecdhe_plaintext2,
                    time_bytes=time_bytes,
                    sendpack2_plaintext=hybrid_all,
                    # sendpack2_plaintext=hybrid_body_dump,
                    host=SECAUTH_HOST,
                    port=SECAUTH_PORT,
                )
                if result is None:
                    log(f"\n[FAILED] ak8secautoauthey 请求失败 (无响应)")
                    return
                response2, client_auth2 = result
                print("psk_result2", psk_result)
                plaintexts = recv_mmtls_cgi_response(response2, psk_result, client_auth2, time_bytes)

                if plaintexts:
                    for i, pt in enumerate(plaintexts):
                        hex_dump(f"plaintext[{i}] (secautoauth)", pt)
                        hex_str = ' '.join(f'{b:02X}' for b in pt)  
                        log(111111) 
                        log(hex_str)
                else:
                    log(f"\n[FAILED] 解密 secautoauth 响应失败")
                    return
                
#                 hex_data ='''
# BF 86 C6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FB 05 92 04 92 04 00 00 00 FF 00 00 00 00 00 00 0A 46 08 9F 03 12 41 04 08 2F 53 94 51 49 1B D9 6A 39 1F 30 E3 D0 D7 FC 8B 08 A5 DE E6 3C 37 E8 36 1A 87 B9 8A 9C 5C CF C9 3C 60 17 D3 CF 0E 6E FF CC 6F EC BC 62 61 4E AA 4A 90 72 97 E7 8A C8 3C 9E 3D B3 21 0A E8 3A 10 01 1A 81 03 17 05 C9 D8 64 6B 31 16 6E 8C CB 5C 10 A8 57 2C 87 86 A6 28 92 0E 32 47 CE 6C 04 AE 1B 4E F3 CA FB 64 4D A0 99 16 D9 E5 94 AF EA 0F F5 A6 5E 9A F8 0A 48 9C 8C C4 0A E6 87 FD 5B 1C A7 9C 8E 09 5C 5B F1 16 28 25 8E BA 29 54 56 78 F4 6B CC 26 E4 E3 D1 4C 4E E4 41 37 45 B7 E8 9C 60 29 FD D9 40 FB 5B 48 D1 D5 13 18 83 DE E8 4E 52 D5 52 D0 BB 26 54 C4 53 3D 2F 24 0C 65 94 8A 7B 37 5B 00 C7 23 1F A9 12 73 E0 A3 08 30 DA 84 93 60 FE 14 3F 4D 86 32 D6 21 F5 33 C9 F0 DB C9 20 58 4A AD 43 DA 8A B4 B1 9E FC 2B 4D 0C 01 88 70 AB 34 DA CC 14 48 2D 15 65 6B 5F DE AE 24 FF 36 BF 52 67 36 BD 68 D5 9B B8 20 8B A6 CF BD 6A 58 EE D8 D6 5E 65 FE 3E F6 36 5C EB 11 AC 36 28 6A AC FA 3B F2 4B 01 C6 FC ED 79 2A 33 7D 6A 70 38 49 01 4F F7 7D CF 95 25 63 F3 6A 51 2E B7 33 4F 67 36 9F 01 21 1C 5E EA AE AB 3E F4 4A 13 F8 1A D7 F4 1F 60 19 E2 D8 8C F9 04 BB 82 23 DB 25 1B A2 77 E3 03 92 34 34 59 C9 C7 D3 9B 4F 08 3A 6C 4C ED 21 B0 17 C2 8A CD 78 66 13 9E FB C5 97 70 D5 46 2A B5 85 D5 7B 5D AC 8B CE 94 97 5F 5B 97 55 D4 56 2B B0 EB 9C 2E 80 9A A9 CE 06 7C 99 0E 92 5D 42 02 62 A3 1A 5B 34 00 DE A9 AD C9 D9 9F 65 FA 8D A6 93 89 3B BB 51 42 A6 CB 60 2E AD BD 0D 48 E4 95 22 47 30 45 02 21 00 CB 9E FC EE C7 F0 B3 7A EB D2 08 A3 35 5A 0A 26 C8 E3 01 4F 42 CD AF 20 25 EE 41 34 4A BA 0C 12 02 20 09 BB 83 8A E4 17 7B 8A F3 0E 78 8D F7 B5 4C A2 E1 B7 E0 48 B6 BE 7C 09 6C F1 A1 52 80 C9 E3 39

# '''

                # plaintexts[1] = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

                
                result_header=plaintexts[1][:0x2c]
                hex_dump("result_header",result_header)
                result_protbuf=plaintexts[1][0x2c:]
                hex_dump("result_protbuf",result_protbuf)

                # ── 手动解析: 服务端 field1/2 和客户端相反 ──
                # 服务端: field1=InnerMessage  field2=varint  field3=bytes  field4=bytes
                # 客户端: field1=varint       field2=InnerMessage
                def _read_varint(data, pos):
                    val = 0; shift = 0
                    while pos < len(data):
                        b = data[pos]; pos += 1
                        val |= (b & 0x7F) << shift
                        shift += 7
                        if not (b & 0x80): break
                    return val, pos
                def _read_tag(data, pos):
                    tag, pos = _read_varint(data, pos)
                    return tag >> 3, tag & 7, pos

                _pos = 0
                _svr_pubkey = b""; _svr_cipher = b""; _svr_sig = b""
                while _pos < len(result_protbuf):
                    fn, wt, _pos = _read_tag(result_protbuf, _pos)
                    if wt == 2:  # length-delimited
                        length, _pos = _read_varint(result_protbuf, _pos)
                        val = result_protbuf[_pos:_pos + length]; _pos += length
                    elif wt == 0:  # varint
                        val, _pos = _read_varint(result_protbuf, _pos)
                    else:
                        break

                    if fn == 1:   # field1: InnerMessage → 解析内部 field2
                        _sub = pb2.InnerMessage(); _sub.ParseFromString(val)
                        _svr_pubkey = _sub.field2
                        log(f"  nid={_sub.field1} pubkey={len(_svr_pubkey)}B")
                    elif fn == 2: _svr_status = val;  log(f"  status={val}")
                    elif fn == 3: _svr_cipher = val;  log(f"  ciphertext={len(val)}B")
                    elif fn == 4: _svr_sig = val;     log(f"  signature={len(val)}B")

                hex_dump("server_pubkey", _svr_pubkey)
                hex_dump("server_ciphertext", _svr_cipher)
                hex_dump("server_signature", _svr_sig)
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
                aad_de=sha256(sha256_de+data_back+dechangshu1+_svr_pubkey+dechangshu2)


                client_der_private = """
                30 77 02 01 01 04 20 37 F7 C6 E5 21 03 5B 98 62 CE C0 4D 79 DA 60 77 C0 0D 96 68 E4 CA 4B 91 A9 10 14 B2 F5 4A 81 3C A0 0A 06 08 2A 86 48 CE 3D 03 01 07 A1 44 03 42 00 04 5B 60 52 6D 8D C9 97 7E 65 07 E1 7A 7A DB 88 F9 B8 D3 2B C8 9F 80 64 91 0C DC A8 CE 3B 87 11 70 E2 17 81 BB D3 59 FE 37 BC 26 6B 1E E5 9D FE 75 D7 D6 49 DA 0E DF 38 A0 A2 81 91 FD FA D2 EC F6
                """

                client_der_private = bytes.fromhex(client_der_private.replace(" ", ""))

                ret, derived = mmtls_ecdh_kdf(415, _svr_pubkey, client_der_private)
                log("derived")
                hexdump(derived)
                key_de=derived[:0x18]
                
                paintext_de=mmtls_aes_gcm.mmtls_aes_gcm_decrypt(key_de, iv_de, ciphertext_de+tag_de, aad_de)
                hex_dump("paintext_de",paintext_de)


                hex_str = ' '.join(f'{b:02X}' for b in paintext_de)
                print("解压成功:", hex_str)
                
                ret, original = ZLibUncompress(paintext_de)

                new_deserialized, new_message_type = blackboxprotobuf.decode_message(original)

                new_readable = bytes_to_hex(new_deserialized)
                pprint.pprint(new_readable, width=120, sort_dicts=False)




                # ============================================================
                # 从 new_deserialized['3']['4']['2'] 序列化为 _auth_key
                # ============================================================
                _t = new_message_type['3']['message_typedef']['4']['message_typedef']['2']['message_typedef']
                _auth_key_bytes = blackboxprotobuf.encode_message(new_deserialized['3']['4']['2'], _t)
                _auth_key = _auth_key_bytes.hex()
                pub_715_key=new_deserialized["3"]["2"]["2"]["2"]
                enc_key=new_deserialized["3"]["23"]["2"]
                dec_key=new_deserialized["3"]["24"]["2"]
                print("pub_715_key",pub_715_key.hex())
                print("_auth_key", _auth_key)
                prv = """
30 82 01 44 02 01 01 04 1C 7F 07 6C 3B 68 B9 E4 E6 39 D6 DF 2D 7B 7C B6 EE 00 26 CC 5F 0B 65 70 19 30 05 80 15 A0 81 E2 30 81 DF 02 01 01 30 28 06 07 2A 86 48 CE 3D 01 01 02 1D 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 01 30 53 04 1C FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE FF FF FF FF FF FF FF FF FF FF FF FE 04 1C B4 05 0A 85 0C 04 B3 AB F5 41 32 56 50 44 B0 B7 D7 BF D8 BA 27 0B 39 43 23 55 FF B4 03 15 00 BD 71 34 47 99 D5 C7 FC DC 45 B5 9F A3 B9 AB 8F 6A 94 8B C5 04 39 04 B7 0E 0C BD 6B B4 BF 7F 32 13 90 B9 4A 03 C1 D3 56 C2 11 22 34 32 80 D6 11 5C 1D 21 BD 37 63 88 B5 F7 23 FB 4C 22 DF E6 CD 43 75 A0 5A 07 47 64 44 D5 81 99 85 00 7E 34 02 1D 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D 02 01 01 A1 3C 03 3A 00 04 88 51 D8 31 B2 19 60 25 20 0A D4 71 EA 58 77 39 61 3E 57 47 D2 2C 4E 0B E7 58 08 CA D9 2C C5 A0 C3 5C 51 D8 1B 66 65 D9 01 47 A4 F1 0C 34 42 2F 19 C5 4B 53 A6 6E 9B 8F
"""

                prv = bytes.fromhex(prv.replace(" ", ""))


                token_16bytes = computer_key_with_all_str(prv, pub_715_key)
                print("token_16bytes", token_16bytes.hex())
                cookie=result_header[0xb:0xb+15]
                print("cookie", cookie.hex())
                print("enc_key", enc_key.hex())
                print("dec_key", dec_key.hex())







                if response2:
                    log(f"\n[SUCCESS] secautoauth 请求完成! ({len(response2)} bytes)")
                else:
                    log(f"\n[FAILED] secautoauth 请求未收到响应")
            except Exception as e:
                import traceback
                traceback.print_exc()
                log(f"\n[ERROR] secautoauth 失败: {e}")

        except socket.timeout:
            log("  [TIMEOUT] 10 秒内未收到响应")


if __name__ == "__main__":
    main()
