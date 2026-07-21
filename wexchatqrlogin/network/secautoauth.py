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
import re
import socket
import secrets
import sys
import time
import struct
import webbrowser
from typing import Optional, Tuple

# 添加项目根目录
sys.path.append(r"D:\weixin_test")

from wexchatqrlogin.crypto import generate_p256_keypair
from wexchatqrlogin.crypto import sha256
from wexchatqrlogin.crypto import mmtls_ecdh_kdf
from wexchatqrlogin.crypto import mmtls_aes_gcm
from wexchatqrlogin.crypto import mmtls_hkdf_expand
from wexchatqrlogin.crypto import mmtls_random_bytes
from wexchatqrlogin.crypto import AesGcmEncryptWithCompress
from wexchatqrlogin.proto.a8key import build as build_a8key_proto
from wexchatqrlogin.crypto import ZLibUncompress


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
00 00 25 A3 00 21 2F 63 67 69 2D 62 69 6E 2F 6D 69 63 72 6F 6D 73 67 2D 62 69 6E 2F 73 65 63 61 75 74 6F 61 75 74 68 00 13 73 68 6F 72 74 2E 77 65 69 78 69 6E 2E 71 71 2E 63 6F 6D 00 00 25 67 BF BE CF 28 00 47 50 83 58 D9 6C FE 03 08 02 00 00 00 00 76 78 BD D0 77 FF 00 FB 05 B8 4A B8 4A A8 4E 02 00 FF 8D 88 8D 93 04 00 00 00 00 00 08 01 12 46 08 9F 03 12 41 04 C2 8F 26 DD 4C 11 9D 0F 8A B8 00 43 CD 82 C1 38 BE 66 F3 0F 11 E4 29 FE 6F 20 28 86 2D 42 44 F4 94 5D 57 F3 00 98 43 E6 0D 54 2F B4 74 8A 08 21 15 BB 43 7E 04 54 7C 00 5F 0C A4 C3 65 4B B4 EC 1A 45 B3 6C F3 8C 08 E5 72 51 BC DA B3 AF 0A F6 55 AA EC 88 63 29 C4 3E 6F 57 E2 C7 27 4D 63 8E B9 AC 9C 85 03 BF BC 4C F2 3F A9 CC 92 43 F3 A7 D5 B7 DD 2E 40 9B 83 A5 B1 F4 DB 59 07 E1 DA B2 5D D7 49 B9 2C 71 59 22 45 06 7F EC 09 AA CF 81 40 00 51 A8 F7 EB 1D A1 B5 75 A7 B6 CB 7C B5 59 E7 CA 94 35 FF AC 92 10 CE C1 0F 9F 99 08 1F 6F EF BE A8 F3 D4 6B B9 73 3E 22 78 B0 E3 B5 12 BD 84 09 DE 2B 0D 5C 54 82 AA 8A 64 2C 0D 25 2A DD 48 60 DE CA 40 47 F9 A6 8E 74 66 ED 39 65 30 27 E1 E8 0E 47 1A B6 B6 C2 A4 A7 BE 47 D2 DE 5F 1E 4A 61 D2 E5 3E A0 F1 9C 11 F9 50 B3 7A 52 0D BC 6C F7 89 35 92 01 5E 5B 11 F0 F2 8A 51 48 5F BA AF BE 15 59 DC 9B 19 52 9D 78 5E 19 A0 31 8D 97 98 28 81 08 6F 49 92 1C EB EF C8 00 97 04 F0 5E 6B 9E 56 CA 0F 7E 4A 5B 79 F7 D7 C3 9E 81 7A A6 2B 45 53 BF 1F E7 30 C9 EF 04 72 9B 97 ED CE A3 F5 96 A2 ED 44 93 A1 08 8A B1 11 28 9B ED 38 C8 9C 0F DE D5 3E 0A C7 89 01 6C 3F FA 9A 1B 57 C8 91 F7 4B 8A 4F 43 CE D6 AD 3C CE CA 99 2C 95 E8 40 7B 1A B1 2E AE F0 B4 C7 01 EF 09 AB 92 8E 55 18 8A 7D 52 33 81 0E 6C DF 17 52 7E 78 5D 18 8C C6 35 D9 37 F1 C4 15 65 D0 21 0B CC 94 68 3D 0B 36 5E D2 D2 63 43 7E 39 79 1D 7A 5A A2 F0 60 D8 7F EC D5 B8 93 F3 69 1E 15 2E A3 F8 96 39 FC CD 18 46 C0 58 F7 FE 88 04 0C C1 31 D9 9F 43 90 5D F5 8E 96 BF 47 7F AB D6 3F 5A 1C 09 BA CC C7 4C 0C 59 3C BB 0F 65 42 C7 13 42 3D FB 40 AA C6 70 A2 96 F8 DF 5A 34 22 AD CC 7F FD B0 56 CD 66 18 B8 C3 C5 91 55 B3 7B F3 91 AC 0E 8D F8 32 85 38 FB 53 30 82 44 DF 98 36 03 37 0B 7F 68 8D 0F 34 A1 D9 CE 64 F7 F1 3C 82 12 2A C8 17 79 65 AD 75 06 19 16 54 05 3D 52 55 A3 4A B8 3E 53 A9 33 15 BC D6 1D 78 2D E1 22 F0 77 7A 2C 5D DC 28 DE D4 53 CC A1 81 3A BD 38 4C BB 15 76 AD 0F 15 63 1E E5 82 AB 11 E1 9B AF D1 05 5B 77 0F 0A EC BC 90 C9 E8 9C C2 B5 71 18 9F 2E BB BF 85 7E A8 6D AD 85 4D B9 CB 23 B3 4E 26 F3 32 9A 0A 71 C2 57 85 C3 65 EE F0 BE 36 73 69 5F A1 C7 1A 10 53 01 D0 27 1F 32 7B 38 27 1C 1C AD C8 FD 87 99 98 85 00 7C 8E C3 1B BF 21 AF F5 72 71 C9 76 FB 56 53 69 D0 21 71 E3 D2 40 0D D6 0E 2A 56 3F 30 8E C3 EB 95 30 32 7B 89 EC AE A5 8C D6 D6 02 93 81 A4 33 6E AC 9E E0 4C 29 DD E9 02 62 2A A2 94 5A FA 96 0F 8D D1 19 D8 08 48 FA 24 17 A2 C8 B0 B9 C7 12 A4 8A 36 96 F2 60 98 AA 1A 69 51 6F 75 46 F7 BC 7E 88 D4 0D 06 15 F5 C8 05 2B BB 77 AF F2 6B 5D 0B 7B AE CF 8B 1B 64 D9 88 40 86 C1 1C F0 0F E9 CC 82 AE 52 90 67 8E 8E 7B 99 D4 2D B4 A6 6B 17 36 7F 5F 2E 51 BD 58 BE A0 79 D9 B7 B1 EC 88 6B 5A 69 36 5F DE 8C 61 EA 7C 42 E1 37 89 E8 72 6F 86 F3 72 0E 80 AB 6C 18 F7 80 EF DA 98 D9 CF 51 6B AE BE A5 81 E8 0B 67 18 1D 64 91 FE 2C 88 EC 83 29 F2 E5 56 54 95 E8 67 0D C0 C3 45 1E 9F 84 5A 0B 1E F5 9D CD 88 DC DC 6A DA E7 2E 06 2A 7C 8E 58 0C F0 54 5C 08 5E DF 61 5B A0 CD EB 2B AA 44 6B CD 08 0D D0 9A F9 17 34 1F 02 AE 81 D8 95 3B 4E 12 B3 A5 67 70 19 AC F8 43 05 35 18 72 52 8F 2C 49 1B DF 45 6D 2C 15 E9 6D D9 75 AC 37 26 16 FF 2E 2E 0D B6 70 73 51 39 AB 8B A9 C2 6A E3 00 B8 B6 02 EA BB 91 10 5A 97 68 DC 25 A5 DC 93 BA 67 0C 24 34 78 17 CA 4C 05 94 DF 45 55 D2 D1 F7 FC 93 17 69 AB 48 C2 E7 E4 94 FC A5 46 04 C0 07 2C BD C2 A4 10 6E 92 EC 05 37 43 94 D4 9A 19 60 BA AF 65 A2 81 4F 6A 5D 71 D7 A3 46 35 04 F6 93 86 E6 80 A9 9A 62 FC C0 5D CB F0 EB C9 03 70 5A C1 94 C7 75 5A 6C 44 35 50 71 A4 68 F6 0F AF 69 7C 64 BB 3D E2 2F 26 7B DA BC 0E 3B EF 7D 87 C5 AC DD FB 00 B5 49 05 FB 09 B4 A7 E2 49 93 1B 52 52 EE 04 03 29 A4 71 1F 80 6D F7 70 0B 5A 53 80 AE 64 60 DA 2A BF C3 7E 37 9C C4 4C 27 76 D5 C6 18 D4 73 68 4D D4 6D 11 53 E3 3A 59 76 B3 08 5B 9B 83 C0 B6 4B DF DA 2E 53 97 22 D6 70 DC BA 55 6E 2B 2A 11 DD 85 D8 36 C0 2C F7 A4 9F 85 D1 9E 7A F2 22 7E D9 40 35 9F 8F 41 EA 08 DE 09 8F 09 99 32 82 F0 E3 EF 0A 12 E4 7D CE F7 FD BC 14 37 D4 E2 D5 61 76 48 22 44 75 A3 81 29 90 89 50 9F 22 A4 43 ED EA F8 11 4B E1 AF 33 A5 7E B5 A4 E5 1F 85 FD DB A0 D6 60 E3 00 BD 2D CC 10 72 54 33 56 70 55 79 F4 FA BE 24 DA 9B 78 56 35 0B 7E 77 E8 BA 10 24 3D 62 BB 03 98 C4 1C F4 26 7A 8C CF DB EB 80 1B 06 B9 33 CB DB E7 82 0D 0C C9 40 7A 5A 0C 0A 52 82 B5 F2 76 BA C0 53 B0 CF A5 A9 9A 2F 2D C9 58 C4 42 FC E9 42 19 56 5A 19 B8 E8 FD 18 35 49 DB EC FA 82 E1 76 DB C8 B5 D8 CB AA EF 8A CC 18 D8 C3 D2 96 C3 0B A2 5E 84 96 E5 3D A6 6A A6 6E 12 D0 BE 7E 6D AB 4C AA E6 14 39 60 95 7F 24 81 9F C2 2D BE 19 C6 2C B3 A9 CE 7B EE 29 21 EC 5A A9 01 BE E1 3A BC 3B 49 FC 24 56 C2 F0 D1 F5 0E FB 13 D6 EF 38 E8 E0 58 8A 2F C0 F0 9D 0B 14 98 B8 25 17 BC 6E 0B F5 BC 35 D7 12 46 DE 1B A4 7C C7 95 1D 8D BD C9 39 29 DF 54 A3 B8 A1 FA 25 90 32 39 9B E6 7B 16 C8 53 7A 3E 4C 0A CB 00 C3 FD F1 29 92 71 50 74 AA 47 C1 4E D6 76 3B 31 3B A0 E5 B8 17 8C 1F 14 A5 F6 62 F7 F7 D7 E2 B3 EE F1 83 B5 39 44 87 03 C2 6A D4 1C 3C B9 4C B0 F5 69 CC 88 BF 01 9F E8 B6 9E 58 28 5A 4E FC AE DD 68 82 E0 2E 9E 02 E6 65 26 24 BD CF A7 A9 BA C4 37 85 EC 4F EC 1D 7B DD 39 C2 AA 24 EC AC 3E 56 C2 FE 83 84 B2 B1 A4 1F C8 79 61 6E CB 82 2C 55 DE 1F A2 FD E4 3C 5B 00 9C 68 B1 47 4A FB 4C B3 49 C4 A2 3F 15 B3 3B A0 EE BC 7E 8F E8 9C F4 2B D7 C5 9E EF 8A 39 62 4A 15 AA E3 3C DA DB EB DD CA 67 F7 92 F7 8F D2 23 2E 03 9E 41 A6 AD F7 AD 28 E6 7E BD C7 CB AF 48 C8 14 BD 4E 61 D5 7E 04 23 5F E5 35 B8 BD B4 11 C2 7D 20 CC 56 6F A9 95 6F 8C ED 79 AC DE 09 4D 61 9C 76 49 44 45 F3 3D D9 7E EB 30 70 25 34 1A 21 9C 2B 40 05 08 20 0E 1A 3E E0 3E 5B E0 22 C6 41 FC 12 5D 23 B1 07 10 78 2E 80 39 A4 95 D6 A7 45 50 C6 69 4E B8 34 2E 13 3F 1E 5B 15 06 EB 1F 7C EE F9 17 C8 4E 27 63 60 3A CA 22 66 86 55 39 BC 21 E9 43 5B 32 A1 26 37 FB 4D C1 F0 67 5A 1B AD 67 72 F4 81 AD 41 AC 20 4B 25 B8 98 CA E1 45 0E A9 6D C9 8F 09 44 79 FA E8 6B B4 86 C8 F4 26 B5 D0 A0 A2 0F 22 25 D0 B3 78 54 7B 11 26 3F C1 3A 27 3F AF A5 2C E2 B6 A4 95 5A 89 0F FD C5 8B EC 7E CF 28 8A 06 57 D9 86 95 D2 B9 7C D1 AE 5D 59 4F ED 11 5B 1C 14 BB 4A 64 5B 80 CC C0 A0 F2 7B FF 01 4F 7E A4 0D 93 9A C0 A4 B9 7F 9D DB 91 90 FC 53 3D 45 BD 75 CC DA 06 51 B4 66 DA 5F 33 ED 85 70 50 90 F8 21 D0 52 46 81 31 1F 0C C1 4A 9B 66 F8 AD B5 C6 EC DB D6 F1 A1 A2 79 1E 8D 8B 5A 34 5C 22 7E BE 6D 02 B7 AE 29 18 8B 78 57 2C 3B AE CD BC 01 1E EA B3 4B 95 10 75 CF 1B 5F 55 D0 62 C7 8B C8 5A 39 C0 EB 30 90 0F 3D FE 37 C8 BA 66 13 66 FE A6 FA D6 48 47 95 F6 92 E3 EF 13 6C 4B 0F EA 8C E0 76 00 09 20 AD 3B FF 3E DE 24 C3 04 6D E9 B8 76 E6 03 02 46 38 48 7A F7 A2 C9 41 57 68 3B E6 FB BE 8F BA 90 09 83 DE 9B FE 63 58 55 99 B6 73 E4 4D E9 6C F5 E3 24 20 E5 B7 5F 6C C6 E7 B9 4C 34 F9 32 24 AA 8D 2E 0F D8 70 8F F2 EC 76 22 A5 44 8D 1E 22 DC 14 41 A4 F8 7B DF E8 C8 F5 D9 19 FF 1F 55 A0 8B E8 A5 3A 3A 1B 22 52 FD B7 DD 65 F1 50 BE 00 71 73 78 BE 02 0A DE 96 E9 ED 42 9C 0A 6B 5E B8 05 2A 7A 4A B4 3A 8B 19 8C EB D9 9C 57 4D 17 8E EA AE 80 F8 B8 B4 D8 1B DD 78 C0 8A B6 AD F0 D2 BB 0B 27 55 5C EC 11 9D 69 00 1F E7 E4 25 AA 9A DF 5C 02 FC F8 67 0A 78 3D 85 1B 88 88 78 65 EB BC 22 6E 46 B6 17 8E AB D0 14 C7 FC FC 19 B4 6D 0C D1 9B 90 85 3F 01 D2 82 AC BE 55 E1 1D 6A 60 4A 18 0A 56 48 16 1E 3E 14 41 90 5E 34 F0 94 85 2C 81 A6 54 E7 D0 71 68 D3 3F DF 17 8F 45 71 78 56 4C E2 E7 D2 88 5D 3C 56 A3 BA 43 D4 62 EC 10 B6 F7 F8 58 99 3D 90 A9 D6 9C 71 34 45 B9 72 04 A2 BE 4F 86 22 4F 42 73 81 00 F1 58 16 A7 2C 77 66 E4 26 0B D3 29 02 E6 25 7E 62 E8 45 5F 01 1B AB 25 1C F1 9E 7F 56 F2 BD 8E 6E C6 DB 60 1D DA BE A9 46 49 E7 C4 F0 C6 34 EF 4B 38 25 BD 9D EA E9 A9 A5 68 45 EA 5B 17 BB BB 83 4F 9F A0 D3 2B A8 AA BD B6 AE 93 64 41 36 5F D8 D2 5F 2B EC BF 76 1F 51 E1 D6 25 B1 CB 06 4E BE F1 58 55 03 34 36 FD B2 B5 C1 B0 FE D9 5C 6D 09 13 65 49 62 20 2C C6 7F 2A D8 F8 67 1D C4 8E 7A EE BE D3 55 95 03 58 22 DC 0E 81 25 7C EC 81 DE FC 50 73 E7 25 AB EC E1 B9 22 51 0D 48 BE 6E 24 74 10 5B 86 47 47 39 F5 B4 7C 48 B5 54 A3 97 41 EF D8 32 9C 55 67 4E 07 5B A1 68 70 CB 15 CD B0 A0 6C 03 4A 33 01 53 30 D4 49 80 87 61 28 1E E6 E3 8B E8 59 CD 41 C2 5B C2 38 92 97 CA 33 BD 93 D4 DF 82 E5 B8 A5 68 BE 88 35 70 2B A7 A9 89 19 6D 9E AC 96 5D 44 51 B4 FE 55 62 6A 49 CE 0B 00 C6 E1 60 E9 22 DB 7A 12 F4 81 8D C4 65 B7 DA 55 D6 CA D3 77 CB 7A AE E0 26 CE E5 DB 93 E9 90 64 F1 25 6B 54 42 B1 41 65 25 62 32 C9 F4 E0 70 49 26 98 D8 30 AD 88 A5 DB C1 F4 EC 85 3E 0B 5E F6 B5 01 84 FE DE 9B 04 7B 35 62 BC 73 FA C0 3B 9E 8B 3D 25 9A CE F7 77 A3 44 67 33 C9 23 7B B5 FF 03 E0 BF C2 4A AF CB 8F 11 93 3C 29 96 75 96 34 9F 8C AA 1B 2E DE 68 BE 97 6C 93 08 56 40 A2 F6 21 57 6B E7 BA F2 23 AF 8D CB 64 5E A5 EE B6 41 44 9C 63 C2 D5 C9 A6 CD FE A6 6F FC 3C 3C 39 59 9B D1 5C 9D 4B 95 79 63 35 F7 77 FC 0D DF E8 23 35 85 BA 85 4A 01 E1 D2 38 DB 2E D5 E5 AD FA AD 94 50 1F D4 6F BE AC FC BF 20 BA 9E E7 C0 D8 18 ED F8 04 C2 B7 EE E9 9C 3F 5D 4D F6 02 1B EF D4 2D 07 EC 02 67 71 A7 19 F4 C1 E4 EC 6F 40 A7 4B 13 44 9F CA 50 22 A6 D0 C6 B7 86 BE FC F2 32 EB 1F 75 7A 15 B1 D9 8D 44 61 29 EC 41 8D E1 44 3F F2 16 9D 9E 29 7C 3B DB 1F 0D D2 D6 39 FA 12 1F BF 91 BA 04 3C AE 3A 07 D9 88 A1 A6 E9 11 AB 50 C2 D3 31 01 D7 B2 FF 16 F6 54 87 38 91 74 18 F9 52 8A 9A 74 AB AA 99 D7 B1 CA 53 68 C2 BF 4A 13 84 CF 87 38 BF A9 3D D3 86 C4 32 CD 57 D8 98 AD 1A 34 E8 3B AB 02 5C 7F C5 2B 36 01 D1 9D 32 43 D7 18 FA 2A 62 2D E7 87 1C 09 16 0E 5F 30 BE 59 BA 56 73 69 A0 CA 90 29 19 0F 22 F2 51 7E 78 63 D7 9B E6 BC A6 A8 BC 11 E6 C5 27 4A 4E 8A 5E B4 67 04 88 05 B4 FB EA BD 3F 51 CE A7 9B FD 90 F0 99 D7 43 8B 42 05 56 72 0E BF DE DB 6C CA E4 7E 8E 8E A4 7B 4A F0 88 2F AB F1 60 B7 CA A9 35 93 2A ED 8B 73 14 6A 72 82 A4 06 ED 76 74 7A E6 A0 4B B6 8A 6F CA 21 AA 8A B8 D9 FB 12 B5 90 3F 00 08 1C A2 5A A6 E6 A5 DE 61 2C 23 FA A5 21 10 41 AC 18 59 E1 2F F9 83 8D 74 8E 2C 6C 1E 83 CC 1D 72 49 AB 8E 97 17 53 42 17 8A 43 DD C5 6E 62 F3 D4 F1 11 6C 57 CE D6 17 08 1D F9 8D B2 7E 9C 5F 86 95 8D D3 EA 1F 88 51 21 60 79 A6 C2 11 1D D0 55 7C C2 45 52 6E 67 BF A6 7E 91 E7 3D 83 8F 2C 5C 26 20 29 16 DE AE 54 C7 FB 84 53 D3 62 49 6D 7B 5F 8A AC 3A 14 75 7B 5A 2F D9 06 82 E6 9E FC C8 DF E0 2E A2 3B 15 C8 04 FB A8 E2 82 26 FB 71 09 B9 79 D4 C5 93 B6 72 B7 2B F8 3A 37 A6 56 A1 A2 B7 75 51 B7 95 B3 CA 13 FA C6 CF 5C 77 27 8E 89 E1 8B EF 81 21 71 18 51 C4 26 3C 19 47 B0 ED 84 9C 39 A3 7D 96 95 C4 8D 12 57 02 B9 21 46 6E CA E1 D7 BD F9 22 15 18 CD BB 4D CB F4 CB 92 56 0D 85 02 9D 2C E9 86 8D 24 7E 5B E7 04 1D 34 66 10 BC 9C 88 5C D5 C1 19 CA 4A 52 E4 45 09 82 B0 12 B8 D8 7A 0F 88 F6 69 3B 06 4A 97 BC 24 AD F9 34 72 44 BB A3 8D 92 8F 08 C9 64 F1 20 C9 27 51 D2 D7 DC 6E 0D 9E 02 CC 55 FB BB 93 01 79 72 D8 78 A4 D6 4A 4F 50 43 AA 5F E1 E2 BA 75 41 7A 04 2A EB 80 88 68 BA 37 16 91 63 07 56 8E 20 A4 97 22 40 FF D3 D9 7F AE 7F D0 A5 8A 3E FC 4F 0B 99 72 69 93 34 74 35 CB 6A D0 94 B1 C9 25 D7 71 7B 30 42 56 76 E8 EF 69 C5 14 CD 2C 70 F8 A3 22 65 83 61 84 50 3D 15 D2 8A 04 42 8E A3 B4 FD 02 57 58 61 D7 AB B3 5B BA E6 28 EE CB 72 2E 5C 65 78 99 38 F8 A2 26 8F 5C 27 60 55 3F C1 CE 4E E8 E1 D4 2F 3D DE C6 B8 4A 52 10 C2 0D FB 78 AE B8 6A B8 23 DA B5 10 AF 1C 70 23 21 BA 77 79 23 C2 6E FA F6 B8 98 CF 96 E7 00 20 9C A3 DB 8E 61 CA E6 6F 6C 37 3D 56 A2 D2 32 F4 3A 4C 47 74 96 A1 AC 99 76 6F C3 6E 8A 28 49 59 36 AF 5D 74 A2 87 B1 4E 78 AF 6A B3 89 03 3F 93 88 57 91 7C AD DB 4A 83 A6 D2 DB A5 04 DE 38 E3 FE 68 54 7C 05 AA 43 A5 72 CF EA C5 A3 C9 6A 2E 67 1F 08 4C D0 F2 11 FF 23 09 50 A5 05 C3 76 51 52 15 84 2F 41 8C 1D 86 C9 47 B5 B6 20 17 F7 66 13 B4 D4 EA B7 52 4F 00 52 1B 96 47 B6 37 81 B0 CC 3F EC C2 70 5B AB F9 26 20 E0 94 5C 90 0B 8C 2E EF 9D 63 5C ED 24 29 6A 81 5B 71 72 4E AD EC 54 E0 FE 53 62 E3 42 DE 40 29 70 94 4D A3 AF 14 FA E0 22 72 29 EE 99 6A 1E 61 C0 51 F4 AB D8 7A 33 08 86 20 89 8D 29 DA B4 C6 A1 5A AB 2F 0B 4D 92 96 11 CA 14 7C D6 04 FC 00 C3 1F 3B 38 DB A0 3C 80 5D AD F9 26 1D 9F C9 2E 20 0E 74 4F 45 9C 27 9A 60 57 F6 AE 55 73 3F 3B F4 90 08 12 52 EB 81 B0 72 44 40 07 19 CD 3A 31 AB E0 76 17 A8 59 BB 52 70 18 D7 8A 21 72 6B 94 8B 30 0E 9E 64 96 BD 8D 9C 86 4B D7 95 78 3A 0E 8F 81 05 2C 00 65 EB 49 71 93 9D 0A 0D 8C 9A 8B 76 FA E8 30 95 79 07 72 C8 80 EF A0 0B 4D 9B 8B 2F AA 19 AA 29 23 85 40 90 26 FD 1E 32 F8 BB 2A 69 AB 38 4F AB A7 BF AC FA 88 34 F8 2D CA 05 DC AF 13 0D 20 57 D0 B4 ED CF 6C 4C 19 5F 28 FD F3 EC D6 37 2D 1D 14 88 54 25 1D E3 1C 9F 0C C1 D3 8E A2 96 E9 63 B8 F1 2D FA 01 AB E2 E8 D0 D3 87 77 07 09 C6 D8 9F FE 82 3F 7E 06 22 AF 7D E3 95 6A 68 83 B9 3B 6E 63 06 58 E1 A8 B6 06 61 49 C3 A9 09 56 AC 90 8E 76 D7 79 2D A9 B5 46 5E B9 07 0C DC 9D CB E9 49 A7 15 01 65 85 A3 71 FC F6 76 0C FD B2 25 86 20 2D CA 93 07 D5 D8 28 BA C6 32 6E 4D 39 70 14 41 E6 C9 7C 27 11 E1 C0 C1 30 F5 44 D9 E0 06 37 33 0A 67 19 2B 82 D1 DC 4F C7 D5 B0 C4 43 18 6C 60 BD 2E BB 95 A4 CA 5D 9D 68 3B 2C D2 D3 03 B2 81 57 E1 B8 08 E9 BD B4 C4 AD 63 17 3E 88 AB 6A 3B 71 7F 2B CD 00 09 50 6C FE 8D FE 04 6B D8 53 5E 9B 80 F9 2A C1 9C AF A1 42 29 4D FF 30 20 92 C7 07 C4 8E CD 6D E0 35 4D 8B 7D 71 A3 45 12 57 4C 8C 64 C4 D9 1F B9 3D 77 34 02 E1 CB D4 C1 85 44 FA D9 BC F4 29 68 C4 A6 E5 83 37 1C 86 E6 44 D8 EC 8A BD F3 9B BE 68 C4 8D 18 7D E5 FA D0 CD 9C 50 05 F1 1C 2A 98 9E FE 2F 66 FA 70 C3 29 4F 4E 01 46 88 A6 B4 A9 AD 95 04 6B CB 7A E2 16 E3 6D E1 0E 43 02 69 93 91 D3 D4 C1 D4 95 E1 07 DD F7 6E 52 91 15 CB B3 8C BC B9 CC F7 57 02 F8 FD 99 32 59 34 7B A3 15 CF D2 E0 8C E9 27 E4 D1 72 DD D9 5C C9 18 20 82 FC 87 9D 57 05 93 63 28 77 80 18 12 DA 39 E8 A1 5C 34 98 05 D6 70 7E 9C B8 D4 9A AB 6C 6E 22 D9 F1 23 66 6C 3A 84 A8 3F 32 78 8E 4E F5 AE DB DC 24 4A E3 FA 05 69 77 AA E2 D5 B9 94 1B 89 77 5A F5 47 69 81 02 DF B9 4F E7 8A F4 60 5B 68 79 CB AC 16 88 94 05 84 D8 95 96 BE BB 17 0D 0F 4D FC 94 02 B2 E7 16 1B 09 70 D2 97 BB 32 37 B1 89 96 F0 DD 50 B2 D6 0A 89 5F 88 90 D3 2B 0C 38 4A DF E7 6E D8 52 FD 9F 6F 9D C1 E0 EE 46 93 06 8A 29 8D 87 6D 29 DC 55 D0 B7 AE CE AC 38 11 EE 6D CB 9B 05 FD EA 9D 2B E0 47 B5 DB 98 51 E6 DE A0 10 D1 3D A5 F7 79 36 72 8A E7 1C 6D 9A F0 97 44 34 45 0E 5D 5B 9C 7A BD DE 33 8F 76 19 52 D2 6D 72 2D 78 CD F8 A2 DB 99 EA D5 45 CB 8F 38 24 4F 97 66 F2 AB 9D 41 57 FB FD FC F0 03 63 43 BC A0 E8 5F E6 CB D4 37 17 4D FE C3 07 AA A2 A9 4D E1 E9 36 B3 2C 75 21 F2 73 55 AF 19 65 C3 57 6B 0A 99 7D 21 3F EC 56 6F BD 79 AD CE 3F FD 6F 90 28 DA FF 62 CC 3A E4 F3 A5 33 74 30 94 A2 A4 8B 64 15 98 80 75 C8 4A A7 6F 14 8F 84 57 E2 2F 19 AC 6C BE 48 2D 45 9D 5C 96 BC 43 0F 19 B3 A9 F4 ED FF D7 F7 F9 01 3F E2 26 EF 12 0A A1 6D 89 24 A7 86 F1 81 B3 43 47 90 3C C4 66 09 8A B2 01 AB FE 2C 3A 26 DD C0 D7 CB D4 47 55 E5 53 15 2D 93 0B A3 47 FD CD 65 2E F0 A1 3A B3 35 70 4A B6 89 E6 94 CE 81 FD 32 A8 CE C1 DB D9 B2 CC 4A A6 00 95 48 24 5B B0 C1 4B 19 44 89 0D E4 06 37 4C 58 01 A2 17 AA A8 A6 37 20 9F 22 7F B7 98 CC 4A 9C 49 43 5A 9A 33 0A 0F 8E B1 5D FD 6D 0D D9 18 E5 E2 14 74 1F FD 86 CE 03 0A E2 CD 74 31 12 01 13 F7 A1 FA 12 AC 9F 27 CA 0E 0F 8F FD 50 3C 08 9C 81 EF 7A D5 A2 5C 26 41 FB CC 71 D2 2E 22 9B 29 E5 FF AC 16 36 9B 18 FB 1B EC 93 51 DC A8 B0 FD 3C D0 18 C1 D1 CF 18 0B B9 5E B5 8F CE 8A C4 37 76 10 D7 2C 42 83 46 F0 A9 27 EB 4E 47 4F 29 4C 9C 6A 01 0F D6 DC 78 43 6B C9 68 93 30 C8 15 A3 9C 2F 3A 14 6C 37 C5 EA 64 34 08 9B B1 AA 73 80 AD 71 46 FE 05 51 A3 92 7D 2E CC 85 74 75 E6 80 B2 F7 7A 05 9F A8 E9 BB 19 19 63 9D 8A DC DE EC 2E 27 EC 1C 78 C9 9F 27 7F 33 8C 43 E1 08 C0 0A 3B 6D C8 B3 58 A2 21 E7 1D 82 9A E1 31 B2 00 B2 DB 81 F4 85 7E 66 BB 70 A8 6E EC 90 68 DD C7 7B A0 97 B7 9D 13 69 7B 34 B2 60 C3 96 3D 98 40 D7 82 B2 EF 34 8B FA 5B 73 F2 72 B4 77 19 6D 24 D0 F8 51 CA FB EC 11 C6 6B 46 87 83 84 54 19 6F 19 E1 24 22 27 4D 9D BA 07 1C A7 6D 5C 51 47 A9 A7 7E 36 5A 5A 85 E3 D3 5E C7 BA 7F A6 6A 47 28 13 2E D6 29 5A 96 11 1D DE BD 2B F5 A7 FF 5E 2B 8C 34 A3 4F EF 1D D7 5E EC 8F A4 E6 D3 D9 67 22 BA 02 01 6B 9C 96 0D 92 37 CB FD F2 C2 7E D3 86 E0 65 7D 67 85 07 1C 0F 83 08 0A 56 16 24 AB 02 09 D3 C8 2B 0C F9 4F 57 EA 5A FC D0 A5 35 4E AF 0B 2B A9 C1 C6 9C A9 90 B2 37 5D 4B 7F 6C F0 BE D0 F5 61 A4 1A C9 55 3F D7 7D 91 D9 1E C8 64 FB B9 E7 F2 36 3E 21 0B 0E EF AF EC CB 81 86 0B 42 F4 7D 13 85 D2 11 C5 C1 CD B5 30 0C 31 18 09 1F 2C 0A BF 57 3D 43 8C C1 99 51 37 DC 05 E3 10 A3 6E 53 20 B5 9E 40 46 13 C8 3D A1 65 87 E8 FB 19 00 BC 80 52 6D 9C 48 54 E1 9C DC 40 64 87 75 15 E2 AE 5C 4B 14 8C FB 6B 70 D8 6F 88 C4 A6 49 6F 46 72 84 AB C2 3D E8 30 D6 7E 53 15 6E 02 8C D0 B4 E1 8A 89 EB 07 35 B2 5C EA 68 D9 E1 6E E7 DF D5 2F 70 FE 89 73 76 6C C3 CC 1C 6E 34 91 6D F8 64 EC 02 21 98 73 84 C5 BB 6C ED 7B E6 93 B3 4F AD 27 51 F9 04 9D 0A 29 F1 E7 85 6B 79 69 99 2D BE E6 92 EB 1C EA C0 67 0C 60 29 71 6D 4F B8 DC 3F 6C 18 0D BC EF 34 DA 23 BD F2 17 6D A6 0D 2D CF 6C 70 67 9A 51 14 12 D8 F6 C8 2B 19 B0 A4 9B BF 3E AC A9 98 03 8C 32 9B E4 F7 2F E0 A6 A2 D8 99 F8 D2 3C 5E 4A 27 DE 5A AF D4 FE 12 CB D9 78 C4 73 B2 74 5F EC A3 3B 33 C3 F3 56 EB 99 04 44 F4 09 8D 29 B5 59 0B 39 91 8F 1D 1E AF EE 6F 36 83 33 31 BC 76 CB 43 3D FA B0 4E 7B 4F 10 43 FD 61 D3 BE DE 48 6A 03 21 D9 86 D4 82 78 4B 90 55 26 C5 F8 68 51 EF CC DB FB CB C2 E5 9F B7 A2 8E 81 04 B3 5B 09 06 BB 3B 14 50 A6 5F 6B EC 97 04 F7 0B B0 C4 BB AB C0 37 17 D8 E9 B5 86 C4 5F A6 BF 5B 35 51 96 46 18 90 67 5A DA 18 FA B4 0A E8 F3 DE AA DB FA 54 23 1F CF 68 D8 5A 1B 04 21 32 8D 71 3D CB D6 E8 CA 1C B2 2F 6D 2D 2B 6A B9 8A 3A 1D D4 86 50 33 8D 7C 12 C0 12 3B 45 C6 5D CB 94 E2 02 C7 30 2E 41 60 A5 7D 98 0E 5A 89 E5 18 E6 C2 49 38 EE D6 69 21 13 13 9F F8 CD B5 CF 1A DE FE E5 13 B1 73 C6 BD 38 07 65 A1 83 6E 04 67 E1 72 60 D9 3D FB D2 D6 14 47 72 5F CA 19 5D 0C E9 76 FC A9 15 3F 99 41 5C 7E 2F CC 0B E3 BE FD 50 81 94 13 7D CF A9 70 7B 01 3A 26 7A F4 6B F1 F7 20 44 02 6B 50 CE C3 47 06 5A 82 24 C6 33 89 AC 39 0A DC 37 BE 0A D5 13 BE 6B D7 4C DF 0E 06 B6 85 E7 5A 27 39 CD E6 06 CF 4A 73 64 F0 39 D6 B2 08 5F 88 57 93 43 C6 D2 5A 65 E9 48 CE D7 FB 28 57 74 50 EE 3C 79 92 31 AD 6A DC 2E 8F 78 3C 26 3F 8C 9B 86 F7 4F E4 22 F7 A5 E0 57 0C 6E 30 77 A1 87 40 39 66 AC 29 AA 39 C7 0C 60 82 92 D8 A8 D0 CE 1E C1 03 04 18 2B 5F 1C 8C 61 EF B9 83 86 DF 67 3D 4B AD E5 84 71 FB 1B 73 60 ED 39 AE E1 E5 74 52 E1 CE A1 A2 F2 98 E9 51 B6 13 D4 A5 93 8E 35 C0 21 D9 72 6F 47 4B 55 50 17 3F E3 3D FF 09 9B 08 6C B9 0F D3 18 93 5F 6A 29 17 84 A0 1E 3F 5D 87 39 97 77 2C 57 40 1E 78 EE 1B 8C AE 90 24 FF 22 05 90 5F 0D C1 4F D0 B7 F6 09 E2 65 B2 C7 F3 8E AE 8C 34 AA 07 2D 25 2F 39 07 22 E0 86 A5 F4 EF BD 80 F9 29 BD BE D2 3B 20 10 5F 7C 3E 9E 0F 8C EB 14 AB 39 76 DB 4C 22 E0 14 1B 06 4A D5 77 CE 42 9D 88 0E CA 4E FD 2C 82 30 B7 23 80 74 8D 1D 9A 95 62 81 39 A4 1C 5C 14 D8 B6 65 04 B6 D5 CB E1 72 51 04 95 8A 2D B8 49 46 65 10 5B 20 F4 72 69 90 A8 C9 30 E2 39 7F 43 3E 87 58 0B 6E F1 EF B9 66 82 12 3D DF ED B1 5A 6C 75 FB A3 37 3F E8 EA 5A 55 94 9B 71 D3 4A C9 E2 D6 6D C1 90 64 DD 01 6C 93 B2 B2 AD C2 55 3C 87 FE 86 DA 16 92 1C 26 8A 09 C4 38 31 6E FC 53 49 7A 44 8F B6 EF 58 AA 37 E3 74 D5 D4 8F 5A C8 87 F0 66 59 04 D8 EA 0D 61 46 BF 3C F9 55 9F D6 DF BC FD 6B 42 7E 77 86 C6 A6 AF DF 8F 52 6F FB 75 C0 2D 6D F5 33 BF D2 6B AF 33 C0 08 69 47 59 6B 69 7D 0D 5B A6 F0 EA F2 90 E3 8B B1 B3 2F FE 85 94 0B 20 A6 74 B1 D1 E1 3C 92 2D D6 12 93 E2 7C 7F 73 60 90 3A 9A 3C 33 B4 0B C2 80 36 47 99 3E 32 4A 99 AB 7D 79 DE B5 5E 56 BA DD 64 3D 3C 8C 27 C9 64 97 60 40 80 DC 95 81 3A 71 D0 3F F6 7C B1 2C 39 A5 98 F2 10 68 66 68 67 79 91 75 70 18 27 E9 60 C7 78 60 B1 7C 6C EE 25 6F F5 29 52 40 0B B5 1B 01 3E AF 21 49 2A 07 0B 13 79 B0 77 74 5D C4 A4 6F F6 71 ED 1C 7C C4 85 65 C2 89 5E 81 9E 3C E4 E8 DF 17 18 B6 45 32 56 1B 3B 8B 26 37 D2 09 A8 9F E7 7F 39 44 06 8F 25 4C E6 A7 CD 1D F9 62 0E E0 1C 4D 9B FB 96 90 AF 9F 20 1D 98 29 7B 13 81 CE 24 F8 50 FD F0 31 CB 37 17 26 F0 BF 6D C3 B3 84 7A DA 2C 84 3E D0 F5 96 F5 CB 9F 63 AA 15 3B 35 5E BD BB 1A 1C DB E3 4B 26 48 9E 42 FA 99 E7 0B 13 AA E4 18 71 29 99 62 4B F9 DF 9C A4 79 16 52 E5 BB 7B 61 87 90 57 D0 61 8A AF FE 0A 12 84 9D E2 B2 B5 E7 A1 30 B2 FD 49 CE 74 30 31 35 F3 B5 68 DD C9 9E A6 70 12 BC 0E 22 8D 34 26 0A FE 7B 83 FD 77 00 65 07 1B EC A5 F1 51 70 91 AC D8 61 70 45 E3 F6 88 C1 03 96 EC 0B BD D0 D3 13 A2 D8 D5 50 2E 96 3B 93 75 DB 4F E4 A4 FD 46 86 35 DE 70 B1 0F 46 E7 72 A4 4D 42 AC 34 C8 D9 E5 F5 9B CA 06 89 82 59 33 36 35 91 FB EA F6 25 FC 00 F3 3A 33 25 1F A0 8D B1 97 22 DE 71 08 6D 07 CE DC 12 B5 8F F5 A5 14 89 5F 6A 88 84 6C 9E 19 1E 72 A3 5E 5F FF 0C D6 92 C7 A8 F8 08 A6 82 76 3D 57 B3 2A 56 50 2E 22 D3 29 6D 42 8F EA 23 CE 32 A2 6D 64 DD 50 46 D4 DC 7D CD 4A 97 D1 D4 A4 88 AD 55 C7 A4 0A 61 AE 68 1C 50 13 9D 4F 58 6F 02 4F BA 5D 51 50 A4 FE 81 86 6B 5F B1 29 12 AA 03 F6 BC 08 3A 6E 6B CF 19 E4 81 90 97 1E 44 F3 BA 4F 2D 6A 37 9D DC D1 F7 A9 27 48 D2 FA 00 6B E3 C1 5B C1 80 A3 61 0D 94 11 7C 42 33 17 47 69 2D 05 EC 8F AC 27 FF 7B F6 A5 B4 92 41 B4 9D F3 0D 7C 96 1B C4 FE 60 20 DC E1 2E 7C C9 29 53 2E 21 88 57 2D BB 92 92 17 E7 7C D6 20 8C 7B 84 87 82 4D FF 4D 1B 54 CD A9 18 2D 43 97 6E 75 8E C5 38 6B B1 29 5F E6 6E 05 7B 9F F1 6D 9E 7B 85 C7 48 CA B0 00 FE 1E BA B9 C2 F6 F1 9C 5B FD 44 AB 74 F7 B3 CC 47 0A DA 71 0F DA B6 03 4C 68 8E 59 9F 39 EF 57 2A 8D 6E 4F 2C 18 CD 32 7B 08 B7 48 3E 45 3E EF AB 82 E9 93 52 33 C6 97 25 CD BB 71 B8 3B 2A 22 65 D3 02 DB CE 42 DA DA 79 46 19 BF 1F FB BE DC EE 91 1D 9D F1 05 A6 17 7F 43 32 92 4D FF 8A E5 E7 FA 64 63 87 00 0D 0D 9B 0C 50 E9 0D D0 D3 7F 05 FB A4 75 CF F5 F5 79 70 10 C0 DC 92 15 A2 A9 92 66 AB 45 E2 F0 03 C9 B7 71 83 F9 7B 83 90 E1 C4 E4 E5 7A 55 7A 97 FE AD 43 9C 10 D6 28 C8 90 2B 05 A1 19 6F 28 BC BF E8 3B A8 79 C7 7F 95 E1 FB D4 FC D8 61 53 CD 66 DA 1C 0B 77 0D E2 BA EA 75 B4 17 BA 82 3F 7B 82 87 A1 77 25 D0 2C 91 6C 43 49 B3 26 A5 E2 33 21 6F 4F 01 85 0F 8E 05 B7 28 40 F9 64 F6 88 4E 34 29 12 65 94 4C 9A 26 29 01 4B 63 52 C5 51 1E E8 C7 F9 78 CC FE 0E 33 D0 5B 45 AF 3E 25 19 AE 43 BB E2 1A 65 1F 00 97 69 EA D7 3E F3 68 84 85 AC E4 5C 71 39 F0 B9 30 40 C8 2C 87 F1 E7 5E F9 52 2C B2 03 5E D3 1F BF E7 80 EE D9 58 08 89 9E DA 99 5F ED D7 16 7B 05 2A 6A D0 26 D6 57 F0 F9 DE 20 3A F4 0B 3B 7D 66 C1 55 EB 49 48 58 A8 65 66 B1 FB 11 B7 BE CE 82 6D 46 CD 64 42 5D F5 E9 92 EB FB 9E 76 D3 E9 7F 6A D8 85 91 40 7D 7F 83 A3 A6 C0 FA D4 EC 19 85 99 54 26 00 10 CC AB 64 61 6C 88 34 B0 32 AF AC B7 C5 D6 EF 2E 97 DF 8F 7B 10 81 C8 FE 1E 99 6D FD 90 EA 9E 20 38 8B A8 86 69 52 7B 1B 08 88 02 36 6C 5A CD CB 67 A7 01 AB E7 44 0E 76 4A 3E C7 F4 7E 44 EC 57 10 DB BD 47 4B 22 B4 C7 89 54 97 1E 43 65 EB C2 BB 14 C1 5C C9 21 9F A8 17 B4 39 6A 08 23 68 DF 35 22 FE 9B 12 A6 84 AD FD 7D 67 7F A4 48 80 91 0F FB 00 2E 0E 89 31 76 A1 69 80 5F BC E0 A1 23 20 BC 15 5D 73 94 F8 AD C1 C6 39 07 13 E9 31 2B 34 D7 DE 1E DA 01 19 B1 B7 E3 9C 1B D0 77 02 DD 02 40 4A CE 29 15 DD 71 1E 88 5E BE F9 11 9B F9 C5 11 22 C5 8F 58 B9 8B EC BC 91 10 40 CB 12 B2 7B 0F C3 A7 FB C1 E6 54 AE C0 1A 1D 4D 2F B8 99 73 30 7C 34 D2 80 1C 86 99 D2 11 67 B2 30 14 48 FB CD 9B A8 21 6F 4C 75 6B 5C CC 8E 8A A0 2A D4 86 B4 DC DA 99 AD 4F F6 1B A6 A2 EC EF AB AE 5F 0F BE D1 85 65 F0 AC A7 F7 81 50 A5 F7 6E 5F E9 82 79 C5 67 F6 1F C5 9B 8E 61 B2 F5 55 63 41 29 AE 43 7B F2 C8 3F 27 F7 A5 E4 80 21 95 74 90 5B 23 14 E0 4E 8C 3E CA D7 2C 8F 6E AD 3A 87 39 61 2B 22 08 35 8C 56 BC 13 04 41 FD CD BE 93 D7 6F 72 85 D1 78 CF 36 81 BD 1D 52 BE 12 A4 4D 2C 7C 55 26 C7 11 26 1B AC 2A EC 07 E3 83 47 19 5C E8 3D A2 F6 0C 3A 91 BA 4D DA 0D 4E A4 C9 BE F1 3E 8C 71 23 0A E8 67 91 B6 DF 6B 43 AC DD 55 CA 8E 7D B1 CD B8 46 14 31 8D DF 41 E1 17 62 D7 54 02 FC 8B 08 BF 00 CF 1B 37 83 E3 C9 47 7B 31 16 5A E8 60 FB 76 2F C5 C2 64 8F DC 0C D1 7C 51 4F 2B 75 08 D6 C6 7B 5A 7A 20 50 A8 F7 9E 92 DC 8D 1A 0F F3 95 26 7C 4C B0 B1 40 B6 74 86 C2 89 43 20 57 FE 49 43 36 47 C3 8E 58 86 29 86 69 36 78 3E A6 8F 27 8F 81 DC A5 B3 0C 8D 50 7C BF EB 3B EB 38 55 B8 6D FE A9 23 00 D1 FC 07 D2 FF 29 EB 4D 4A 22 FA FC C0 56 83 96 C8 B6 A7 D0 A8 41 E6 42 A8 45 64 9A 6C 4F B4 1E B9 9D 6F CC 4E 6B 40 F9 AA 49 E6 A0 96 5A 92 26 04 69 F2 32 0A 6D 76 6B 30 C6 3A 57 88 A9 EA B6 71 8D 04 39 6E 07 EE 76 1C 63 03 66 A4 56 9C 38 C3 65 E2 5E F8 BD 32 E6 3C 49 54 B8 84 DB A1 38 EC 74 A6 B1 D0 FD 2A 9E 49 1D 39 B9 A9 B9 50 C5 EE 67 C7 51 9D 34 09 9F 4F 9B F1 6C 2A 81 9C 6B 13 2C DA 6E 85 BB 9D C0 EB F3 F5 24 18 C8 61 3B 15 47 68 85 A5 2B 81 0A C8 57 34 38 9A CF 48 CB B6 47 C6 1D 5B 6C A9 0A AB 89 6C 19 F7 31 EB 51 D9 B3 17 90 2C AA 1A 22 7F 2A 3E 8E B4 45 16 FE D5 3B 84 B7 99 48 E9 17 13 70 91 87 08 C1 3A 81 41 36 08 AD 78 B1 C7 25 07 8D B4 A9 9E 48 99 91 EC C0 08 5F 2B 67 6F 8E 0D 1E 9C FA 4A 14 05 7A 88 0A 77 10 54 E2 0A 6D E2 FD 8B 35 96 0C 11 EA 5B 62 EF 17 25 C5 EA CF C4 5A 56 4A B1 0C FA FD AC DB B1 19 93 F5 7D AA 1F 43 55 F0 FD 1E 5D 89 FD 28 9D 3F F1 7A 71 0B 4A AD 8F BE B6 8C A8 FA 78 75 50 17 D9 97 5B F4 77 14 99 20 3A A0 60 B9 07 DC AD 01 58 05 A0 C8 97 08 1E 9B FD 1C 37 31 E5 EC 73 84 FD C6 1C 2C 54 59 59 02 51 47 D9 C7 C8 E8 2B 61 AE EA 32 42 C5 F3 B2 52 7B 65 C9 AB 9B 52 99 B0 3A 95 57 0C 0C C3 F7 FA C3 37 F3 1A D8 AC 97 A0 99 1A 29 D5 C2 72 F3 63 68 1D 1C 24 01 27 78 F5 03 25 D3 10 F2 E3 CD 0F D1 3E 11 25 48 8E DE 6F 81 21 18 C4 8C 6B 83 84 BA B8 5F 67 D0 6D 71 3C 30 AD 05 0A C6 F7 6F 8D 56 13 33 6C D5 84 24 94 66 C2 70 65 C6 96 C5 F7 5F 1A B4 B4 D5 B2 C3 3D 14 DA C2 72 52 8B 90 56 80 C9 28 3F A5 A9 59 4C B8 F0 68 3D AC 87 D0 9E A1 98 9C DA 5B 8B C7 12 D8 61 C4 57 4E 63 1E 69 E6 C6 7A 6B D0 36 97 1C E3 29 4F F2 73 DC E6 90 DB 12 79 2D 38 83 36 E4 06 55 3B EC 25 89 E8 C9 4F 0B E9 74 42 73 D0 CE 57 E9 F0 A4 31 AF 30 9B 7C 00 4F 51 4F DF E0 15 D8 B2 4A C6 54 F4 20 74 0F 07 30 77 01 9B EA B9 64 C5 8C D1 B7 93 A6 E3 1D 98 7D E9 7C BB 95 0D 7D A1 67 CC 5D BD BD 1B E9 FD FC 7F 43 91 C7 B4 5B 4B 77 D6 16 F8 F7 F6 09 2F D2 67 48 9E AC 1C 0E 7D 01 B7 00 36 F9 F0 8E C4 AA A4 17 3A 99 73 F3 6A C5 2F 29 FC 52 E1 D6 B0 84 38 0C AC 0D 49 7D 4F F2 54 64 FF B8 C9 66 35 83 05 3A 83 07 13 6E C9 00 90 C5 02 DA 40 14 47 FB 39 52 B8 F5 A1 7E 7C 38 56 05 F8 6C A2 DE 40 5E 21 F3 4C D5 FF 98 DD 12 74 8F 23 CC E4 7E F9 C3 07 9B 81 F5 00 9E F1 9B 2E 82 AE 9C 19 31 9B 53 B7 B0 10 5E 34 8F 47 94 E1 33 C8 9C B5 8E 73 FC 17 69 A5 51 31 AC F0 63 C0 1E 86 4D 3F F5 43 10 3B 80 D5 2C 40 35 93 F3 60 E6 2D CF 75 2E C3 62 3A 6A 60 B3 39 29 95 BB 55 74 C7 93 EB 04 E4 48 EC 42 38 54 F1 5C 72 D0 32 E1 D6 2D 8F 2E 4F F3 95 0D D8 46 14 FB 2B 07 95 1C 2F 5D CC 13 AE 1E 33 83 50 97 90 93 33 CD 98 4A E7 8F 93 F0 8A 4E 45 F7 CA 9A 26 BE 8C 90 CE C6 3C 71 F7 B1 5E F4 CC 9D 20 56 F0 90 E7 7D 06 53 03 BA C9 3E 13 D4 21 80 9C A5 74 B0 25 57 A5 AF 7D 8D 72 2D 23 13 49 9A B3 CA EF 65 80 4A D9 8B D1 56 4B FB 86 FF 60 9B E2 81 2F D4 48 B3 34 AC FA 38 01 29 F7 94 7A 29 8C DC 86 90 24 95 C8 9D DF DA C6 24 EC 88 8A B2 EB 83 1C A4 67 F2 01 98 2B 62 D7 B9 A4 30 B9 96 9E 9D CA 7A 24 A9 F0 34 F4 CE A1 3A 5E FB C7 4F 8A 8B 75 2D 07 09 B1 D8 95 DE 4F 2C 6F C7 C5 03 3E 06 7C AC B4 75 B4 16 E3 9B 3F 8D 51 14 57 6C 6B 56 55 E2 F2 E9 BD 8A 1C 1B F5 14 89 A5 E5 E8 D5 9C B7 86 25 03 35 26 9C 22 F7 1A B0 32 C1 44 7E 68 FD 28 1A E6 32 4F 10 F4 70 13 B9 B7 28 36 9C 12 99 07 4C 38 97 4F 40 B2 58 BA 1E C7 51 D2 35 9F 44 47 28 03 FA 61 76 3A 5B 8B 4A 9B 84 FB E6 57 4E 96 13 02 1B 04 1D DF 86 34 1A FF F4 2F 23 CA 6D 3F 34 41 59 B1 75 C7 23 95 09 44 64 31 55 B4 E5 47 37 7B DE 57 E8 36 E5 79 58 72 6B 4F DD 1C BC 0A 53 8F 1E BA 36 9B 25 2B EE 72 C6 54 FD 18 AE F6 BF 26 86 8E FD E1 08 93 F7 A9 B9 09 DC 61 E2 5F 8C 32 6C 5F B3 65 06 C4 A7 0A F9 2F 98 C0 D3 B4 1B 7A F0 3A 44 93 4B 45 FE B4 D9 83 70 99 A5 5B 26 6B 88 56 2D 56 FD B0 23 45 F3 CE 33 CE 8F 2C BE DD 39 4C 36 9F 4D E7 ED D1 B7 4B 5E 5F 33 10 36 C4 91 4B 24 96 F4 BF 5D 41 E5 84 8A F2 47 1C 59 CE 20 E1 C2 5D DC 4D 04 CA A0 36 BD 50 CA 33 C7 9F 02 79 95 AE 24 C7 F9 3F D5 88 6F F5 A0 3E AC EE BF 8D C8 82 2D 83 04 FF C6 98 2D 8E CE 1C FA 0C A4 F9 EC 9E 0D 84 0F CB A5 E8 1F E1 0D 89 45 CE 9B 36 52 9E 96 AC 97 7A 12 5E 8A AF C3 53 24 80 B2 AB 0C 0C 6F FC 7B F9 20 66 EA 56 C9 05 4A 8D 71 5C B1 6F CD E0 0E 14 54 A5 99 CD 83 DD C4 A3 85 9B 8B FF 9E 4C 17 55 DF A8 6B C5 62 C0 64 44 D4 73 64 9D 1D 9C D1 7F E5 19 A2 50 19 FE 57 F3 90 13 20 49 E4 24 FF D8 8D B6 98 9D C8 EF AB 40 CD A1 DB 85 D5 DA 00 34 96 71 8E D9 04 09 58 5D 70 EB D5 63 59 A2 81 EE 90 CA 6E 81 BC 9E 90 20 A1 30 1C 20 AD 82 85 28 92 2A F6 AE E9 55 FB F2 D2 E1 5F F9 D3 A7 1C 2C 48 17 8F F6 DC 47 25 9A 0B FC 7D 13 DA 44 8D D9 59 30 09 AB 7F 82 35 5F 0B 3D 70 27 3E 11 DB 59 9A 12 3F 66 BD 6B C7 93 70 B7 5E 94 24 6F EC EC DE 2C 2A 50 6C 11 60 38 24 B5 F3 59 FD F9 86 F2 09 40 B1 15 24 32 D6 61 71 A6 94 7C F8 2B 57 4F 09 7A 91 C5 27 5E 4D B4 5A 9A 40 FB 26 30 DC EE 8A 52 10 48 81 1D A6 5A 08 C2 5B 2A AF CD 6F 15 C5 76 66 41 C7 20 BB 2E 6C C7 BA 43 0B 52 81 6D 4C B3 3A 11 04 46 81 F3 26 84 73 8B C1 52 CA 82 93 02 4C 38 B9 33 B6 7B A5 83 92 D6 F7 9A 6C AE DF 7F DA 84 0B 48 80 2C 66 2D 67 96 3E A4 86 62 D6 96 52 D8 AF A0 15 8F 27 CB 67 67 4B 81 3E 4E AD 67 96 F3 A3 CB E2 D6 CC BC 52 58 34 0D 92 06 DE 60 3E 28 19 41 42 15 D1 D2 40 FD B9 A9 86 36 98 3D BE 97 B7 43 31 73 BD CA 10 59 72 D2 25 F5 F7 C1 17 A9 06 E8 E5 F6 F8 6F BF C1 63 D5 8B 7A B4 E9 EF 6B E6 F1 F0 58 A9 D5 20 3C 34 A5 D0 90 E6 55 BC 2C 6E FD 85 0D F2 08 45 FC A4 0A 9E 2F C8 FD D2 7E
'''

                hybrid_body_dump = bytes.fromhex(hex_data.replace(" ", "").replace("\n", ""))

                hex_dump("hybrid_body_dump",hybrid_body_dump)

                hybrid_body_dump_pack=hybrid_body_dump[:0x6f]
                hybrid_body_dump_body=hybrid_body_dump[0x6f:]

                hybrid_body_dump_pack_header=hybrid_body_dump_pack[:0x40]
                hybrid_body_dump_pack_wire=hybrid_body_dump_pack[0x40:]
                hex_dump("hybrid_body_dump_pack",hybrid_body_dump_pack)
                hex_dump("hybrid_body_dump_pack_wire",hybrid_body_dump_pack_wire)

                # ┌──────────────────────────────────────────────────────────────┐
                # │ 导入两个解析库:                                              │
                # │   pack1           — 47B wire <-> 57B 内部结构体              │
                # │   hybrid_ecdh_pack — 57B 外层 EncodeHybirdEcdhEncryptPack   │
                # └──────────────────────────────────────────────────────────────┘
                import sys, os
                _pack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pack')
                if _pack_dir not in sys.path:
                    sys.path.insert(0, _pack_dir)
                from pack1 import deserialize_wire, serialize_header, print_wire_analysis
                from hybrid_ecdh_pack import (encode_hybrid_ecdh_header,
                                              decode_hybrid_ecdh_header,
                                              set_hmac, print_packet_analysis)

                # ┌─ 第 1 步: pack1 wire(47B) → deserialize → 57B → serialize → wire ─┐
                log("\n========== [pack1] wire(47B) -> deserialize -> 57B header ==========")

                header_57 = bytearray(deserialize_wire(hybrid_body_dump_pack_wire))

                _uin       = struct.unpack_from('<I', header_57, 8)[0]
                _func_type = struct.unpack_from('<H', header_57, 27)[0]
                _enc_algo  = header_57[2]
                _enc_len   = struct.unpack_from('<I', header_57, 29)[0]
                _a7_param  = struct.unpack_from('<H', header_57, 37)[0]
                _dev_id    = struct.unpack_from('<H', header_57, 39)[0]
                _sig       = struct.unpack_from('<I', header_57, 42)[0]
                _f4750     = struct.unpack_from('<I', header_57, 47)[0]
                _cookie    = bytes(header_57[12:12 + header_57[3]])

                log(f"  uin={_uin}(0x{_uin:08X}) func_type={_func_type}(0x{_func_type:04X}) encrypt_algo={_enc_algo} enc_len={_enc_len}")
                log(f"  a7_param={_a7_param}(0x{_a7_param:04X}) device_id={_dev_id} signature=0x{_sig:08X} field_47_50=0x{_f4750:08X}")
                log(f"  cookie: {_cookie.hex(' ').upper()}")

                # ── cookie: 文件不存在→从dump抓取保存; 文件存在→用文件里的 ──
                import os as _os
                _cookie_file = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "fixed_cookie.bin")
                _current_cookie = bytes(header_57[12:12 + header_57[3]])

                if not _os.path.exists(_cookie_file):
                    with open(_cookie_file, "wb") as _f:
                        _f.write(_current_cookie)
                    log(f"\n  [cookie] fixed_cookie.bin 不存在, 从dump抓取并保存: {_current_cookie.hex(' ').upper()}")
                else:
                    with open(_cookie_file, "rb") as _f:
                        _saved = _f.read()
                    header_57[12:12 + 15] = _saved
                    log(f"\n  [cookie] 用 fixed_cookie.bin 覆盖: {_saved.hex(' ').upper()}")
                log(f"  dump自带cookie: {_current_cookie.hex(' ').upper()}")
                _cookie = bytes(header_57[12:12 + header_57[3]])  # 重新读取, 可能已被文件覆盖

                # ╔══════════════════════════════════════════════════════════════╗
                # ║              参数修改区 — 取消注释即可测试                  ║
                # ╠══════════════════════════════════════════════════════════════╣
                # ║  格式: B=byte H=uint16 I=uint32                              ║
                # ║  单字节: header_57[off] = 值                                 ║
                # ║  多字节: struct.pack_into('<fmt', header_57, off, 值)        ║
                # ╚══════════════════════════════════════════════════════════════╝
                #
                # ---- encrypt_algo (1B, offset=2, 当前值=12) ----
                # header_57[2] = 0x05
                #
                # ---- cookie_data (15B, offset=12) 已被上面固定, 无需再改 ----
                # 想改单个字节: header_57[12] = 0x49    # 改 cookie 第1字节
                # 想换整个cookie: FIXED_COOKIE = bytes.fromhex("49 03 08 ...")  # 写在文件顶部
                #
                # ---- func_type (2B, offset=27, LE, 当前值=763) ----
                # struct.pack_into('<H', header_57, 27, 999)
                #
                # ---- enc_len (4B, offset=29, LE, 当前值=9526) ----
                # struct.pack_into('<I', header_57, 29, 5000)
                # struct.pack_into('<I', header_57, 33, 5000)  # enc_len2 同步
                #
                # ---- a7_param (2B, offset=37, LE, 当前值=10024) ----
                # struct.pack_into('<H', header_57, 37, 0)
                #
                # ---- device_id (2B, offset=39, LE, 当前值=2) ----
                # struct.pack_into('<H', header_57, 39, 1)
                #
                # ---- signature (4B, offset=42, LE, 当前值=0) ----
                # struct.pack_into('<I', header_57, 42, 0x12345678)
                #
                # ---- field_47_50 (4B, offset=47, LE, dump1=0x421B4B1F dump2=0x427B2106) ----
                # struct.pack_into('<I', header_57, 47, 0x42790F24)
                #
                # ---- ext_flag (1B, offset=52, 当前值=0) ----
                # header_57[52] = 0x01
                #
                # ---- group_key (2B, offset=53, LE, 当前值=0) ----
                # struct.pack_into('<H', header_57, 53, 1)
                #
                # ---- seq_key (2B, offset=55, LE, 当前值=0) ----
                # struct.pack_into('<H', header_57, 55, 0x1234)
                #
                # ===========================

                # ── 正向: 57B结构体 → 序列化为 wire ──
                re_wire = bytes(serialize_header(header_57))
                log(f"\n  re_serialized wire: {re_wire.hex(' ').upper()}")
                if re_wire == hybrid_body_dump_pack_wire:
                    log("[pack1] roundtrip OK: serialize(deserialize(wire)) == wire")
                else:
                    log("[pack1] roundtrip MISMATCH! (参数被修改过)")

                # ┌─ 第 2 步: hybrid_ecdh 外层 57B header encode → decode → encode ─┐
                _client_ver = struct.unpack_from('<I', header_57, 4)[0]

                hdr57 = encode_hybrid_ecdh_header(
                    uin=_uin, func_type=_func_type, a7_param=_a7_param,
                    cookie_data=_cookie, a8_data=b'\x00' * _enc_len,
                    encrypt_algo=_enc_algo, client_ver=_client_ver,
                )

                decoded_hdr = decode_hybrid_ecdh_header(hdr57)
                log(f"\n[hybrid_ecdh] decode: type=0x{decoded_hdr['type_val']:04X} uin={decoded_hdr['uin']} "
                    f"func_type={decoded_hdr['func_type']} a7_param={decoded_hdr['a7_param']} "
                    f"a8_len={decoded_hdr['a8_length1']} cookie={decoded_hdr['cookie_data'].hex(' ').upper()}")

                re_hdr57 = encode_hybrid_ecdh_header(
                    uin=decoded_hdr['uin'], func_type=decoded_hdr['func_type'],
                    a7_param=decoded_hdr['a7_param'], cookie_data=decoded_hdr['cookie_data'],
                    a8_data=b'\x00' * decoded_hdr['a8_length1'],
                    encrypt_algo=decoded_hdr['encrypt_algo'], client_ver=decoded_hdr['client_ver'],
                    flags=decoded_hdr['flags'], sub_60038_val=decoded_hdr['sub_60038_val'],
                    hmac_present=decoded_hdr['hmac_present'],
                    unknown_4bytes=decoded_hdr['unknown_4bytes'],
                    sub_60244_val=decoded_hdr['sub_60244_val'],
                    sub_60280_val=decoded_hdr['sub_60280_val'],
                    tail_2bytes=decoded_hdr['tail_2bytes'],
                )
                if re_hdr57 == hdr57:
                    log("[hybrid_ecdh] roundtrip OK")
                else:
                    log("[hybrid_ecdh] roundtrip MISMATCH!")

                # ┌──────────────────────────────────────────────────────────────┐
                # │ 第 3 步: 用重建的 wire 替换原始 dump, 发包验证                │
                # │                                                              │
                # │ rebuilt = pack_header(64B) + re_wire(47B) + body(加密数据)   │
                # │   发包 → 服务器返回成功 → 解析/重建全链路正确                 │
                # │   如果第1步改了参数, 发包看服务器是否接受修改值               │
                # └──────────────────────────────────────────────────────────────┘
                hybrid_body_dump_rebuilt = (
                    hybrid_body_dump_pack_header +
                    re_wire +
                    hybrid_body_dump_body
                )
                log(f"\n========== [rebuild] 重建完整包, 发包验证 ==========")
                log(f"  pack_header:  {len(hybrid_body_dump_pack_header)}B")
                log(f"  rebuilt_wire: {len(re_wire)}B")
                log(f"  body:         {len(hybrid_body_dump_body)}B")
                log(f"  total:        {len(hybrid_body_dump_rebuilt)}B")
                log(f"  rebuilt == original: {hybrid_body_dump_rebuilt == hybrid_body_dump}")
                log(f"  rebuilt hex: {hybrid_body_dump_rebuilt[:100].hex(' ').upper()}...")

                SECAUTH_HOST = "43.137.191.78"
                SECAUTH_PORT = 80
                log(f"\n 发送 secautoauth -> {SECAUTH_HOST}:{SECAUTH_PORT} (rebuilt packet)")
                print("psk_result1", psk_result)
                result = send_mmtls_cgi_request(
                    psk_result=psk_result,
                    ecdhe_plaintext=ecdhe_plaintext2,
                    time_bytes=time_bytes,
                    sendpack2_plaintext=hybrid_body_dump_rebuilt,
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

                # ── 解密服务端响应 ──

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
