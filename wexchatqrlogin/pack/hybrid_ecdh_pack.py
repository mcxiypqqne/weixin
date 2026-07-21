"""
hybrid_ecdh_pack.py
===================
根据逆向分析 sub_65ECC (微信 MMProtocalJni 中的序列化函数) 的输出格式，
生成 EncodeHybirdEcdhEncryptPack  type=2 (非加密 Pack) 的 57 字节头部。

对应反编译代码:
  bool __fastcall sub_5D548(
      JNIEnv*  a1,              // x0
      SKBuffer& a2,             // x1  输出缓冲区
      SKBuffer& a3,             // x2  输入缓冲区(含 15 字节 cookie)
      unsigned int a4,          // x3  uin
      const char* a5,           // x4  nonce (16字节, 用于 HMAC, 不直接写入输出)
      int a6,                   // x5  funcType
      int a7,                   // x6  a7_param
      unsigned __int8* a8,      // x7  ECDH 公钥数据 (std::string*)
      int a9,                   // 栈  flags (7)
      unsigned int a10,         // 栈  (0)
      __int16 a11,              // 栈  (0)
      int a12)                  // 栈  encryptAlgo (12/13)

输出格式 (57 字节):
  Offset  Size  Value                  来源
  ──────  ────  ─────────────────────  ──────────────────────────
  0x00    2     type = 2               add_0_2b(v51, 2)
  0x02    1     encryptAlgo            add_0x3_1B(v51, a12)
  0x03    1     cookie_len = 15        固定值
  0x04    4     clientVer              add_4_4B(v51, dword_EBCBC)
  0x08    4     uin                    add_8_4B(v51, a4)
  0x0C    15    cookie 数据             sub_600F8(v51, a3_data, 15)
  0x1B    2     funcType               add_0x1b_2B(v51, a6)
  0x1D    2     a8_length1             add_0x1d_2B(v51, len(a8))
  0x1F    2     padding (0x0000)       对齐
  0x21    2     a8_length2             add_0x21_2B(v51, len(a8))
  0x23    2     padding (0x0000)       对齐
  0x25    2     a7_param               add_0x25_2B(v51, a7)
  0x27    2     sub_60038_val = 2      sub_60038(v51, 2) — type≠1 BYTE 模式
  0x29    1     hmac_flag = 1          sub_601A0(v51, 1) — 表示有 HMAC
  0x2A    4     ???                    sub_6006C 取值 (type=1 才执行, type=2 为残留值)
  0x2E    1     flags (0xFF)           add_0x3e_1B(v51, 0xFF)
  0x2F    4     HMAC                   add_0x2f_4(v51, hmac_result) — sub_5F8E0 计算
  0x33    1     a10 (sub_60244)        sub_60244(v51, a10) — BYTE (v51+0x3B)
  0x34    1     padding                 对齐 (v51+0x3C)
  0x35    2     a11 (sub_60280)        sub_60280(v51, a11) — WORD (v51+0x3D)
  0x37    2     padding / 残留         尾部填充 (v51+0x3F)

注意: 有些字节在不同调用中会变化 (0x2A, 0x36) — 这些可能是未初始化栈数据
      或者来自前一次调用的残留。sub_65ECC 可能直接从 v51 内存 dump 而非严格序列化。
"""

import struct
import hashlib
import hmac


def encode_hybrid_ecdh_header(
    uin: int,
    func_type: int,
    a7_param: int,
    cookie_data: bytes,
    a8_data: bytes,
    encrypt_algo: int = 12,
    client_ver: int = 0x28004750,
    flags: int = 0xFF,
    sub_60038_val: int = 2,
    hmac_present: int = 1,
    unknown_4bytes: bytes = None,
    sub_60244_val: int = 0,
    sub_60280_val: int = 0,
    tail_2bytes: bytes = None,
) -> bytes:
    """
    生成 sub_65ECC 输出的 57 字节二进制头部 (type=2, 非加密 Pack)。

    Parameters
    ----------
    uin : int
        用户 UIN (对应 Java packHybridEcdh 的 i17).
    func_type : int
        功能号 (对应 i18).
    a7_param : int
        参数 (对应 i19).
    cookie_data : bytes
        15 字节的设备 cookie (对应 bArr 参数).
    a8_data : bytes
        ECDH 公钥等数据 (对应 bArr2 参数). 只需用其长度.
    encrypt_algo : int
        加密算法标识 (对应 i29). 默认 12.
    client_ver : int
        全局客户端版本号 (来源: dword_EBCBC). 默认 0x28004750.
    flags : int
        标志字节 (对应 TLV 0x3E). 默认 0xFF.
    sub_60038_val : int
        sub_60038 写入的值. type≠1 时总是 2.
    hmac_present : int
        HMAC 存在标志 (sub_601A0). 总是 1.
    unknown_4bytes : bytes | None
        输出偏移 0x2A 处的 4 字节. None 则填零.
        实际来源可能是 sub_6006C (type=1 模式) 写入的残留数据.
    sub_60244_val : int
        a10 参数写入的值 (偏移 0x33, 1 字节). 实际捕获中为 0.
    sub_60280_val : int
        a11 参数写入的值 (偏移 0x34, 2 字节). 实际捕获中为 0.
    tail_3bytes : bytes | None
        偏移 0x36 处的 3 字节尾部填充. None 则填零.

    Returns
    -------
    bytes
        57 字节的序列化头部.
    """
    if unknown_4bytes is None:
        unknown_4bytes = b'\x00\x00\x00\x00'
    if tail_2bytes is None:
        tail_2bytes = b'\x00\x00'

    a8_len = len(a8_data)

    buf = bytearray()

    # ── 0x00: type (2 bytes BIG-endian!) ──
    buf += struct.pack('>H', 2)

    # ── 0x02: encryptAlgo (1 byte) ──
    buf += struct.pack('<B', encrypt_algo)

    # ── 0x03: cookie 长度, 固定 15 (1 byte) ──
    buf += struct.pack('<B', 15)

    # ── 0x04: clientVer (4 bytes LE) ──
    buf += struct.pack('<I', client_ver)

    # ── 0x08: uin (4 bytes LE) ──
    buf += struct.pack('<I', uin)

    # ── 0x0C: cookie 数据 (15 bytes, 不足右补零) ──
    cookie = bytearray(cookie_data[:15])
    cookie.extend(b'\x00' * (15 - len(cookie)))
    buf += bytes(cookie)

    # ── 0x1B: funcType (2 bytes LE) ──
    buf += struct.pack('<H', func_type)

    # ── 0x1D: a8_length1 (2 bytes LE) ──
    buf += struct.pack('<H', a8_len)

    # ── 0x1F: padding (2 bytes) ──
    buf += struct.pack('<H', 0)

    # ── 0x21: a8_length2 (2 bytes LE) ──
    buf += struct.pack('<H', a8_len)

    # ── 0x23: padding (2 bytes) ──
    buf += struct.pack('<H', 0)

    # ── 0x25: a7_param (2 bytes LE) ──
    buf += struct.pack('<H', a7_param)

    # ── 0x27: sub_60038 写入值 (2 bytes LE) ──
    buf += struct.pack('<H', sub_60038_val)

    # ── 0x29: HMAC 存在标志 (1 byte) ──
    buf += struct.pack('<B', hmac_present)

    # ── 0x2A: 未知 4 字节 ──
    buf += unknown_4bytes[:4].ljust(4, b'\x00')

    # ── 0x2E: flags (1 byte) ──
    buf += struct.pack('<B', flags)

    # ── 0x2F: HMAC 占位 (4 bytes LE) — 调用者自行计算并填充 ──
    buf += struct.pack('<I', 0xFFFFFFFF)  # 占位

    # ── 0x33: sub_60244 (a10) 1 byte ──  (v51+0x3B → output[0x33])
    buf += struct.pack('<B', sub_60244_val)

    # ── 0x34: padding 1 byte ──  (v51+0x3C)
    buf += b'\x00'

    # ── 0x35: sub_60280 (a11) 2 bytes LE ──  (v51+0x3D → output[0x35])
    buf += struct.pack('<H', sub_60280_val)

    # ── 0x37: tail 2 bytes ──  (v51+0x3F)
    buf += tail_2bytes[:2].ljust(2, b'\x00')

    assert len(buf) == 57, f"Expected 57 bytes, got {len(buf)}"
    return bytes(buf)


def set_hmac(packet: bytearray, hmac_value: int) -> None:
    """
    将计算好的 HMAC 值写入已生成的 packet 中 (偏移 0x2F, 4 字节 LE)。

    Parameters
    ----------
    packet : bytearray
        57 字节的 packet (由 encode_hybrid_ecdh_header 生成).
    hmac_value : int
        4 字节 HMAC 值 (来自 sub_5F8E0 计算结果).
    """
    struct.pack_into('<I', packet, 0x2F, hmac_value)


def decode_hybrid_ecdh_header(packet: bytes) -> dict:
    """
    反向解析 57 字节的 hybrid ECDH header，返回所有字段的字典。

    这是 encode_hybrid_ecdh_header() 的逆操作。

    Parameters
    ----------
    packet : bytes
        57 字节的二进制 packet。

    Returns
    -------
    dict
        包含所有解析后字段的字典，key 与 encode 函数的参数名对应:
            - type_val       : int   (BIG-endian)
            - encrypt_algo   : int
            - cookie_len     : int   (应始终为 15)
            - client_ver     : int
            - uin            : int
            - cookie_data    : bytes (15 字节)
            - func_type      : int
            - a8_length1     : int
            - padding_0x1f   : int
            - a8_length2     : int
            - padding_0x23   : int
            - a7_param       : int
            - sub_60038_val  : int
            - hmac_present   : int
            - unknown_4bytes : bytes
            - flags          : int
            - hmac_val       : int
            - sub_60244_val  : int
            - padding_0x34   : int
            - sub_60280_val  : int
            - tail_2bytes    : bytes
    """
    if len(packet) != 57:
        raise ValueError(f"Expected 57 bytes, got {len(packet)}")

    return {
        # ── 0x00: type (2 bytes, BIG-endian!) ──
        'type_val':        struct.unpack_from('>H', packet, 0x00)[0],

        # ── 0x02: encryptAlgo (1 byte) ──
        'encrypt_algo':    packet[0x02],

        # ── 0x03: cookie_len (1 byte) ──
        'cookie_len':      packet[0x03],

        # ── 0x04: clientVer (4 bytes LE) ──
        'client_ver':      struct.unpack_from('<I', packet, 0x04)[0],

        # ── 0x08: uin (4 bytes LE) ──
        'uin':             struct.unpack_from('<I', packet, 0x08)[0],

        # ── 0x0C: cookie_data (15 bytes) ──
        'cookie_data':     bytes(packet[0x0C:0x0C + 15]),

        # ── 0x1B: funcType (2 bytes LE) ──
        'func_type':       struct.unpack_from('<H', packet, 0x1B)[0],

        # ── 0x1D: a8_length1 (2 bytes LE) ──
        'a8_length1':      struct.unpack_from('<H', packet, 0x1D)[0],

        # ── 0x1F: padding (2 bytes) ──
        'padding_0x1f':    struct.unpack_from('<H', packet, 0x1F)[0],

        # ── 0x21: a8_length2 (2 bytes LE) ──
        'a8_length2':      struct.unpack_from('<H', packet, 0x21)[0],

        # ── 0x23: padding (2 bytes) ──
        'padding_0x23':    struct.unpack_from('<H', packet, 0x23)[0],

        # ── 0x25: a7_param (2 bytes LE) ──
        'a7_param':        struct.unpack_from('<H', packet, 0x25)[0],

        # ── 0x27: sub_60038_val (2 bytes LE) ──
        'sub_60038_val':   struct.unpack_from('<H', packet, 0x27)[0],

        # ── 0x29: hmac_present (1 byte) ──
        'hmac_present':    packet[0x29],

        # ── 0x2A: unknown 4 bytes ──
        'unknown_4bytes':  bytes(packet[0x2A:0x2E]),

        # ── 0x2E: flags (1 byte) ──
        'flags':           packet[0x2E],

        # ── 0x2F: HMAC (4 bytes LE) ──
        'hmac_val':        struct.unpack_from('<I', packet, 0x2F)[0],

        # ── 0x33: sub_60244_val (1 byte) ──
        'sub_60244_val':   packet[0x33],

        # ── 0x34: padding (1 byte) ──
        'padding_0x34':    packet[0x34],

        # ── 0x35: sub_60280_val (2 bytes LE) ──
        'sub_60280_val':   struct.unpack_from('<H', packet, 0x35)[0],

        # ── 0x37: tail 2 bytes ──
        'tail_2bytes':     bytes(packet[0x37:0x39]),
    }


def print_packet_analysis(packet: bytes) -> None:
    """打印 packet 的逐字段解析，方便对比 IDA 分析。"""
    d = decode_hybrid_ecdh_header(packet)

    print("=" * 72)
    print("  EncodeHybirdEcdhEncryptPack — Serialized Header Analysis")
    print("=" * 72)
    print(f"  [0x00] type           = 0x{d['type_val']:04X}")
    print(f"  [0x02] encryptAlgo    = 0x{d['encrypt_algo']:02X} ({d['encrypt_algo']})")
    print(f"  [0x03] cookie_len     = 0x{d['cookie_len']:02X} ({d['cookie_len']})")
    print(f"  [0x04] clientVer      = 0x{d['client_ver']:08X} ({d['client_ver']})")
    print(f"  [0x08] uin            = 0x{d['uin']:08X} ({d['uin']})")
    print(f"  [0x0C] cookie         = {d['cookie_data'].hex(' ').upper()}")
    print(f"  [0x1B] funcType       = 0x{d['func_type']:04X} ({d['func_type']})")
    print(f"  [0x1D] a8_length1     = 0x{d['a8_length1']:04X} ({d['a8_length1']})")
    print(f"  [0x1F] padding        = 0x{d['padding_0x1f']:04X}")
    print(f"  [0x21] a8_length2     = 0x{d['a8_length2']:04X} ({d['a8_length2']})")
    print(f"  [0x23] padding        = 0x{d['padding_0x23']:04X}")
    print(f"  [0x25] a7_param       = 0x{d['a7_param']:04X} ({d['a7_param']})")
    print(f"  [0x27] sub_60038_val  = 0x{d['sub_60038_val']:04X} ({d['sub_60038_val']})")
    print(f"  [0x29] hmac_flag      = 0x{d['hmac_present']:02X} ({d['hmac_present']})")
    print(f"  [0x2A] unknown_4bytes = {d['unknown_4bytes'].hex(' ').upper()}")
    print(f"  [0x2E] flags          = 0x{d['flags']:02X}")
    print(f"  [0x2F] HMAC           = 0x{d['hmac_val']:08X} ({d['hmac_val']})")
    print(f"  [0x33] sub_60244(a10) = 0x{d['sub_60244_val']:02X} ({d['sub_60244_val']})")
    print(f"  [0x35] sub_60280(a11) = 0x{d['sub_60280_val']:04X} ({d['sub_60280_val']})")
    print(f"  [0x37] tail           = {d['tail_2bytes'].hex(' ').upper()}")
    print("=" * 72)
    print(f"  Hex: {packet.hex(' ').upper()}")


# ═══════════════════════════════════════════════════════════════════
#  47 字节 Wire Format 反向解析 (委托给 pack1.deserialize_wire)
# ═══════════════════════════════════════════════════════════════════

def decode_wire_packet(wire_hex: str) -> dict:
    """
    输入 hybrid_body_dump_pack_wire (47 字节 hex 字符串),
    解析并输出对应的参数。

    Parameters
    ----------
    wire_hex : str
        47 字节的 hex 字符串 (如 "BF BE CF 28 00 47 ...")

    Returns
    -------
    dict
        解析后的参数字典, 包含:
            - comp_alg, encrypt_algo, body_len
            - client_ver, uin
            - body_data (hex)
            - func_type, enc_len, comp_len, device_id
            - signature, flag_byte, field_47_50, ext_flag, group_key, seq_key
    """
    import sys
    import os
    # 确保 pack1 可导入
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)

    from pack1 import deserialize_wire, print_wire_analysis

    wire = bytes.fromhex(wire_hex.replace(" ", "").replace("\n", ""))
    return print_wire_analysis(wire)


# ═══════════════════════════════════════════════════════════════════
#  验证: 用 dump4.txt 中捕获的第 1 次调用数据复现
# ═══════════════════════════════════════════════════════════════════


