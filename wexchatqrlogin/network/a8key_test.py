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

import hashlib
import os
import re
import socket
import secrets
import sys
import time
import struct
import webbrowser
from typing import Optional, Tuple

# 添加项目根目录
sys.path.append(r"D:\weixin")

# 添加 pack 目录 (deserialize_wire / serialize_header)
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
from wexchatqrlogin.crypto.gen_signature import genSignature
from wexchatqrlogin.network.HybridEcdhEncrypt import build_hybrid_ecdh_request


# ═══════════════════════════════════════════════════════════════
# 调试开关
# ═══════════════════════════════════════════════════════════════
DEBUG = True


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

00 00 01 3D 00 21 2F 63 67 69 2D 62 69 6E 2F 6D 69 63 72 6F 6D 73 67 2D 62 69 6E 2F 6D 70 2D 67 65 74 61 38 6B 65 79 00 13 73 68 6F 72 74 2E 77 65 69 78 69 6E 2E 71 71 2E 63 6F 6D 00 00 01 01 BF CA DF 28 00 47 50 83 58 D9 6C ED 03 08 02 00 00 00 00 01 00 CD 60 11 A1 00 EE 01 CF 01 CF 01 00 02 C4 FB C4 A4 01 FF 9B C2 C5 91 04 00 00 00 6B 39 A0 CF B4 6C 24 F2 A5 A4 C2 CA 2F 82 F6 EE 8D 0F 03 8D 04 ED DF B8 D3 D7 0D 26 48 BE 88 72 8F 7A CA 8D 92 03 DC 78 2C E9 8C EF FE A3 A3 F2 10 E5 43 74 6B 5D 14 10 C4 94 1C 64 8A C9 6A 1F C2 54 44 FC 38 3D 09 94 C9 91 1C 71 98 2E D2 9A 89 BF 5A 03 56 71 1B 4F 14 48 B8 80 DD A7 2E 30 00 FA E7 E4 F9 34 0D D8 43 7C F4 76 14 85 08 ED 3E D4 3C BB DA F9 48 D9 6A 9B 43 8E 53 D9 4A 31 64 67 1D EC 65 7D 6F 32 F6 68 E5 C2 6B CB D1 12 2C E9 44 20 FF 52 C0 2D 17 97 6D 49 43 1B 1C 25 08 78 C3 63 DA 18 3F 94 15 4D C6 A5 46 D0 BE 25 4B 49 63 90 A7 4B 7C B0 EB 25 B2 10 CE F6 27 97 53 4F 13 4D 90 E1 16 01 3A 15 3B 90 4C 57 D7 C7 34


'''
                hybrid_body_dump = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))
                # header 大小取决于 CGI 路径/主机等可变字段, 找到 body=244 的偏移
                # body = ct(216) + iv(12) + tag(16) = 244 bytes
                header_len =0x72
                pack_head_dump = hybrid_body_dump[:header_len]
                pack_head_cgi=pack_head_dump[:0x40]
                hex_dump("pack_head_cgi",pack_head_cgi)
                pack_head_wire=pack_head_dump[0x40:]
                hex_dump("pack_head_wire",pack_head_wire)
                                # ── 把 enc_len 写回 wire 协议 ──
                                # ★ 动态生成 protobuf 明文 (替代 dump 死数据)
                # UUID 从 QR 扫码 URL 提取, 16 字符, 如:
                #   https://open.weixin.qq.com/connect/confirm?uuid=08171VrI0IwvFa1O
                uuid = "08171VrI0IwvFa1O"  # TODO: 从实际扫码获取
                protobuf_plaintext = build_a8key_proto(uuid=uuid)
                hex_str = ' '.join(f'{b:02X}' for b in protobuf_plaintext)
                log(f"protobuf_plaintext: {hex_str}")
                hex_dump("protobuf_plaintext (a8key build)", protobuf_plaintext)

                hex_data ='''

0A 34 0A 01 00 10 EC B2 E3 9A F8 FF FF FF FF 01 1A 10 41 32 30 35 32 39 34 33 64 61 33 62 34 31 66 00 20 D0 8E 81 C0 02 2A 0A 61 6E 64 72 6F 69 64 2D 33 33 30 00 10 02 1A 04 08 00 12 00 3A 42 0A 40 68 74 74 70 73 3A 2F 2F 6F 70 65 6E 2E 77 65 69 78 69 6E 2E 71 71 2E 63 6F 6D 2F 63 6F 6E 6E 65 63 74 2F 63 6F 6E 66 69 72 6D 3F 75 75 69 64 3D 30 37 31 6D 66 7A 6D 6E 34 6E 65 6F 30 30 30 61 48 00 50 04 6A 04 08 00 12 00 70 00 78 00 80 01 00 90 01 13 98 01 06 A0 01 9A D9 E2 90 03 B0 01 00 BA 01 04 08 00 12 00 C8 01 00 88 02 00 90 02 00
'''
                protobuf_plaintext = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))


                _struct57 = bytearray(deserialize_wire(pack_head_wire))


                # ── 换 cookie ──
                _cookie = bytes.fromhex("a3030802000000003a5dc4ad236b00 ")
                _struct57[12:12 + len(_cookie)] = _cookie
                log(f"\n  [cookie] 固定cookie: {_cookie.hex(' ').upper()}")

                  # ── 换 signature / i5 (offset 42, 4 bytes uint32 LE) ──

                uin=-2091329172
                data = [
10,4,106,52,86,54,-38,-118,79,64,-45,-118,107,-29,-102,-68
]
                hex_str = ''.join(f'{b & 0xff:02x}' for b in data)
                token_16bytes = bytes.fromhex(hex_str)

                token_16bytes ='''

767132028fdbb7b0368d4e9d09e536f6'''
                token_16bytes = bytes.fromhex(token_16bytes.replace(" ", "").replace("\n", ""))

                
                hex_dump(" _struct57[42:46]", _struct57[42:46])
                _uin_unsigned = uin & 0xFFFFFFFF  # Java signed -> Python unsigned
                _new_i5 = genSignature(_uin_unsigned, token_16bytes, protobuf_plaintext)
                # _new_i5 =1554727791
                _struct57[42:46] = struct.pack('<I', _new_i5 & 0xFFFFFFFF)
                log(_new_i5)


                
                pack_head_wire1 = bytes(serialize_header(_struct57))
                hex_dump("hybrid_body_dump_pack_wire", pack_head_wire)
                hex_dump("_new_wire", pack_head_wire1)

                pack_head=pack_head_cgi+pack_head_wire1  



                
                pack_body_dump = hybrid_body_dump[header_len:]
                log(f"header_len={header_len} (0x{header_len:02X}), body={len(pack_body_dump)}")
                hex_dump("pack_head",pack_head)
                hex_dump("pack_body_dump",pack_body_dump)
                # ── 内层密钥 (AES-192, 来自 ECDH/ECDSA) ──
                # 请求加密密钥 (AesGcmEncrypt dump: 55 FD D5 74...)

                inner_encrypt_key ='''
4bd6b15b3ec04e27eef0e66c00f49b0e31fc29974fa2469d
'''
                inner_encrypt_key = bytes.fromhex(inner_encrypt_key.replace(" ", "").replace("\n", ""))
                # 响应解密密钥 (AesGcmDecrypt dump: 2C 8B 2C 2C...)

                inner_decrypt_key_hex ='''
2dd0eabd4575228264de3d673b8c6303d40ef47d35288ab1
'''
                inner_decrypt_key = bytes.fromhex(inner_decrypt_key_hex.replace(" ", "").replace("\n", ""))
               

               
                # ★ 动态生成 pack_body: zlib压缩 + AES-GCM加密, iv 随机
                encrypted_blob, send_iv = AesGcmEncryptWithCompress(
                    inner_encrypt_key, protobuf_plaintext)
                pack_body = encrypted_blob[:-16] + send_iv + encrypted_blob[-16:]
                hex_dump("generated pack_body", pack_body)
                
                hex_dump("original pack_body (dump)", pack_body_dump)
                log(f"pack_body len: generated={len(pack_body)}, dump={len(pack_body_dump)} (iv random, ct differs)")
                
                # ak8ey 走 short.weixin.qq.com
                SECAUTH_HOST = "43.137.191.78"
                SECAUTH_PORT = 80

                log(f"\n 发送 ak8ey -> {SECAUTH_HOST}:{SECAUTH_PORT}")
                print("psk_result1", psk_result)
                result = send_mmtls_cgi_request(
                    psk_result=psk_result,
                    ecdhe_plaintext=ecdhe_plaintext2,
                    time_bytes=time_bytes,
                    sendpack2_plaintext=pack_head + pack_body,
                    # sendpack2_plaintext=pack_head+pack_body_dump,
                    host=SECAUTH_HOST,
                    port=SECAUTH_PORT,
                )
                if result is None:
                    log(f"\n[FAILED] ak8ey 请求失败 (无响应)")
                    return
                response2, client_auth2 = result
                print("psk_result2", psk_result)
                plaintexts = recv_mmtls_cgi_response(response2, psk_result, client_auth2, time_bytes)

                if plaintexts:
                    for i, pt in enumerate(plaintexts):
                        hex_dump(f"plaintext[{i}] (ak8ey)", pt)
                else:
                    log(f"\n[FAILED] 解密 ak8ey 响应失败")
                    return

                # ── 解密服务端响应 ──
                decompressed = AesGcmDecryptWithUncompress(inner_decrypt_key, plaintexts[1])
                if decompressed:
               
                    hex_dump("ak8ey response (decompressed)", decompressed)
                    # 提取 confirm URL 并用浏览器打开
                    urls = re.findall(b'https?://[^\x00-\x1f]+', decompressed)
                    for u in urls:
                        url_str = u.decode('utf-8', errors='replace')
                        end = url_str.find('&wx_header=1')
                        if end > 0:
                            url_str = url_str[:end + len('&wx_header=1')]
                        log(f"\n[CONFIRM URL] {url_str[:120]}...")
                        webbrowser.open(url_str)
                        # log("[OK] 已在浏览器中打开确认页面")
                        break
                else:
                    log("[ERROR] 内层解密失败")

                if response2:
                    log(f"\n[SUCCESS] ak8ey 请求完成! ({len(response2)} bytes)")
                else:
                    log(f"\n[FAILED] ak8ey 请求未收到响应")
            except Exception as e:
                import traceback
                traceback.print_exc()
                log(f"\n[ERROR] ak8ey 失败: {e}")

        except socket.timeout:
            log("  [TIMEOUT] 10 秒内未收到响应")



if __name__ == "__main__":
    main()
