"""
pack1.py - 完整 pack 流程：Java 参数 -> 构造 57 字节头部结构体 -> 序列化 -> 最终 pack 输出

流程对应:
  MMProtocalJni.pack()                       [Java]
    -> Java_com_tencent_mm_protocal_MMProtocalJni_pack  [JNI wrapper, 0x7C4AC]
      -> sub_7782C  (protocal_pack)          [参数整理]
        -> sub_5BA90 (EncodePack)            [构造 v90 SKBuffer]
          -> sub_602BC (pack/serialize)      [序列化]
            -> sub_65ECC                     [type==2 序列化]
              -> sub_65658                   [序列化 57 字节头部结构体]
              -> sub_6EF10                   [追加 body 数据]

v90 SKBuffer 布局 (type==2):
  v90[0..3]   = type = 2
  v90[4..7]   = 内部字段
  v90[8..64]  = 57 字节序列化输入结构体 (a1 for sub_65658)
  v90[72..]   = body 数据缓冲区 (加密/压缩后的 body)

57 字节头部结构体 (v90+8, sub_65658 的输入) 字段映射:
  [0]       byte   标志位, 始终 0
  [1]       byte   压缩算法 compAlg          (sub_60038 写入)
  [2]       byte   加密算法 encryptAlgo       (sub_5FF9C 写入, 来自 i)
  [3]       byte   body 数据长度             (sub_600F8 写入, = len(bArr3), max 15)
  [4..7]    dword  clientVer                (sub_5FEF0 写入)
  [8..11]   dword  uin                      (sub_5FF40 写入, 来自 i2)
  [12..26]  15B    原始 body 数据 (bArr3)     (sub_600F8 memcpy)
  [27..28]  uint16 funcType                 (sub_5FF24 写入, 来自 i3)
  [29..32]  uint32 加密后长度 enc_len         (sub_5FFD0 写入)
  [33..36]  uint32 压缩后长度 compressedLen   (sub_60004 写入, 通常=enc_len)
  [37..38]  uint16 固定 0                   (sub_60170 写入)
  [39..40]  uint16 deviceId                 (sub_6018C 写入, = 2)
  [41]      byte   has_flag = 1             (sub_601A0 写入)
  [42..45]  uint32 signature                (sub_601CC 写入, 来自 i5)
  [46]      byte   flag_byte = 0xFF         (sub_601F4 写入)
  [47..50]  uint32 固定 0x4231611B          (sub_6021C 写入)
  [51]      byte   固定 0                   (sub_60244 写入)
  [52]      byte   extFlag                  (sub_60258 写入, 来自 i4)
  [53..54]  uint16 groupKey                 (sub_60280 写入)
  [55..56]  uint16 seqKey                   (sub_602A8 写入, 来自 i11)
"""

import struct


# ============================================================
# 底层编码函数
# ============================================================

def varint_encode(value: int) -> bytes:
    """sub_65A08: 无符号 Base-128 Varint 编码"""
    if value < 0x80:
        return bytes([value])
    result = []
    while value:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
    return bytes(result)


def write_be16(value: int) -> bytes:
    """sub_65A94: 大端写入 16 位无符号整数"""
    return struct.pack('>H', value & 0xFFFF)


# ============================================================
# sub_65658: 序列化 57 字节头部结构体
# ============================================================

def serialize_header(buf_in: bytes) -> bytearray:
    """
    实现 sub_65658 的序列化逻辑。
    将 57 字节的 SKBuffer 数据区结构体序列化为 wire format。

    buf_in: 57 字节结构体 (v90+8 处的 a1)
    返回: 序列化后的头部字节流
    """
    if len(buf_in) < 57:
        raise ValueError("buffer too short")

    v8 = buf_in[1]       # 偏移 +1
    v9 = buf_in[2]       # 偏移 +2
    v10 = buf_in[3]      # 偏移 +3
    if v8 > 3:
        raise ValueError("v8 > 3")
    if v9 > 0xF:
        raise ValueError("v9 > 0xF")
    if v10 > 0xF:
        raise ValueError("v10 > 0xF")

    out = bytearray()
    idx = 0

    has_flag = (buf_in[41] != 0)

    # --- 如果有 flag，先写 0xBF ---
    if has_flag:
        out.append(0xBF)
        idx += 1

    # --- 16 位组合头 ---
    # head = (v8 & 3) | (4 * buf[0]) | (((v10 & 0xF) << 8) & 0xFFF) | (v9 << 12)
    head = (v8 & 3) | ((4 * buf_in[0]) & 0xFF) | (((v10 & 0xF) << 8) & 0xFFF) | ((v9 & 0xF) << 12)
    out += struct.pack('<H', head)
    idx += 2

    # --- bswap32: 偏移 +4 的 dword ---
    val32 = struct.unpack('<I', buf_in[4:8])[0]
    out += struct.pack('>I', val32)
    idx += 4

    # --- sub_659D4: 偏移 +8 的 dword (big-endian) ---
    val32 = struct.unpack('<I', buf_in[8:12])[0]
    out += struct.pack('>I', val32)
    idx += 4

    # --- memcpy: 偏移 +12, 长度 = buf[3] ---
    data_len = v10
    out += buf_in[12:12 + data_len]
    idx += data_len

    # --- 5 个 Varint 字段 ---
    for fmt, off in [
        ('<H', 27),   # uint16
        ('<I', 29),   # uint32
        ('<I', 33),   # uint32
        ('<H', 37),   # uint16
        ('<H', 39),   # uint16
    ]:
        val = struct.unpack(fmt, buf_in[off:off + struct.calcsize(fmt)])[0]
        enc = varint_encode(val)
        out += enc
        idx += len(enc)

    # --- has_flag 扩展字段 ---
    if has_flag:
        # varint 偏移 +42 (uint32)
        val = struct.unpack('<I', buf_in[42:46])[0]
        enc = varint_encode(val)
        out += enc
        idx += len(enc)

        # byte 偏移 +46
        out.append(buf_in[46])
        idx += 1

        # varint 偏移 +47 (uint32)
        val = struct.unpack('<I', buf_in[47:51])[0]
        enc = varint_encode(val)
        out += enc
        idx += len(enc)

        # byte 偏移 +51
        out.append(buf_in[51])
        idx += 1
        # byte 偏移 +52
        out.append(buf_in[52])
        idx += 1

        # varint 偏移 +53 (uint16)
        val = struct.unpack('<H', buf_in[53:55])[0]
        enc = varint_encode(val)
        out += enc
        idx += len(enc)

        # big-endian uint16 偏移 +55
        val = struct.unpack('<H', buf_in[55:57])[0]
        out += write_be16(val)
        idx += 2

        # --- 回填头部 bit7..2 ---
        if idx <= 64:
            current_head = struct.unpack('<H', out[1:3])[0]
            new_head = (current_head & 0xFF03) | ((idx & 0x3F) << 2)
            out[1:3] = struct.pack('<H', new_head)

    return out


# ============================================================
# 构造 57 字节头部结构体 (模拟 EncodePack / sub_5BA90)
# ============================================================

def build_header(
    encrypt_algo: int,          # i:    加密算法 (13=AES_GCM, 5=..., 0=NONE)
    body_data: bytes,           # bArr3: 原始 body 数据 (protobuf, max 15 bytes)
    func_type: int,             # i3:   功能号
    enc_body_len: int,          #        加密后 body 的长度
    signature: int,             # i5:   签名
    seq_key: int,               # i11:  序列号
    *,
    # --- 以下参数有合理默认值，必要时可覆盖 ---
    uin: int            = 0x8358D96C,    # i2:   uin
    client_ver: int     = 0x28004750,    #       客户端版本
    comp_alg: int       = 2,             #       压缩算法
    ext_flag: int       = 0,             # i4:   扩展标志
    group_key: int      = 0,             #       group key
    device_id: int      = 2,             #       deviceId int (dword_E8468)
    flag_byte: int      = 0xFF,          #       标志字节
    field_47_50: int    = 0x4231611B,    #       sub_6021C 写入的固定值
) -> bytes:
    """
    构造 sub_65658 的 57 字节输入结构体。

    返回: 57 字节的 bytes 对象
    """
    if len(body_data) > 15:
        raise ValueError(f"body_data too long ({len(body_data)} > 15)")

    buf = bytearray(57)

    # [0]     标志位, 始终 0
    buf[0] = 0x00
    # [1]     压缩算法
    buf[1] = comp_alg & 0xFF
    # [2]     加密算法 (来自 pack 参数 i)
    buf[2] = encrypt_algo & 0xFF
    # [3]     body 数据长度
    buf[3] = len(body_data) & 0xFF

    # [4..7]  clientVer (dword LE)
    struct.pack_into('<I', buf, 4, client_ver & 0xFFFFFFFF)
    # [8..11] uin (dword LE, 来自 pack 参数 i2)
    struct.pack_into('<I', buf, 8, uin & 0xFFFFFFFF)

    # [12..]  body 数据 (来自 pack 参数 bArr3)
    body_len = len(body_data)
    buf[12:12 + body_len] = body_data

    # [27..28] funcType (uint16 LE, 来自 pack 参数 i3)
    struct.pack_into('<H', buf, 27, func_type & 0xFFFF)
    # [29..32] 加密后长度 (uint32 LE)
    struct.pack_into('<I', buf, 29, enc_body_len & 0xFFFFFFFF)
    # [33..36] 压缩后长度 (uint32 LE, 通常与加密后长度相同)
    struct.pack_into('<I', buf, 33, enc_body_len & 0xFFFFFFFF)

    # [37..38] 固定 0
    struct.pack_into('<H', buf, 37, 0)
    # [39..40] deviceId int
    struct.pack_into('<H', buf, 39, device_id & 0xFFFF)

    # [41]     has_flag = 1
    buf[41] = 1

    # [42..45] signature (uint32 LE, 来自 pack 参数 i5)
    struct.pack_into('<I', buf, 42, signature & 0xFFFFFFFF)
    # [46]     flag_byte
    buf[46] = flag_byte & 0xFF
    # [47..50] 固定字段
    struct.pack_into('<I', buf, 47, field_47_50 & 0xFFFFFFFF)

    # [51]     固定 0
    buf[51] = 0
    # [52]     extFlag (来自 pack 参数 i4)
    buf[52] = ext_flag & 0xFF
    # [53..54] groupKey (uint16 LE)
    struct.pack_into('<H', buf, 53, group_key & 0xFFFF)
    # [55..56] seqKey (uint16 LE, 来自 pack 参数 i11)
    struct.pack_into('<H', buf, 55, seq_key & 0xFFFF)

    return bytes(buf)


# ============================================================
# deserialize_wire: serialize_header() 的逆操作
# ============================================================

def _read_varint(data: bytes, offset: int) -> tuple:
    """读取一个无符号 varint，返回 (value, new_offset)。"""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
    raise ValueError(f"Truncated varint at offset {offset}")


def deserialize_wire(wire: bytes) -> bytes:
    """
    serialize_header() 的逆操作。
    将 wire format (47 字节左右) 还原为 57 字节的头部结构体。

    Parameters
    ----------
    wire : bytes
        serialize_header() 输出的 wire format 字节流。

    Returns
    -------
    bytes
        57 字节的头部结构体 (可传给 build_header 类函数验证)。
    """
    if len(wire) < 3:
        raise ValueError(f"Wire data too short: {len(wire)} bytes")

    pos = 0

    # --- has_flag 前缀 ---
    has_flag = (wire[pos] == 0xBF)
    if has_flag:
        pos += 1

    # --- 2 字节 head (LE) ---
    head = struct.unpack_from('<H', wire, pos)[0]
    pos += 2

    v8 = head & 3                     # comp_alg
    # buf[0] 被 length 覆盖了，总是 0
    v10 = (head >> 8) & 0xF           # body_len
    v9 = (head >> 12) & 0xF           # encrypt_algo

    # --- 4 字节 bswap32: clientVer ---
    client_ver = struct.unpack_from('>I', wire, pos)[0]
    pos += 4

    # --- 4 字节 BE: uin ---
    uin = struct.unpack_from('>I', wire, pos)[0]
    pos += 4

    # --- body 数据 (v10 字节) ---
    if pos + v10 > len(wire):
        raise ValueError(f"Body data truncated: need {v10} bytes, only {len(wire) - pos} left")
    body_data = wire[pos:pos + v10]
    pos += v10

    # --- 5 个 varint 字段 ---
    varint_fields = []
    for _ in range(5):
        val, pos = _read_varint(wire, pos)
        varint_fields.append(val)
    func_type   = varint_fields[0]   # uint16 @27
    enc_len     = varint_fields[1]   # uint32 @29
    comp_len    = varint_fields[2]   # uint32 @33
    field_37    = varint_fields[3]   # uint16 @37 (固定 0)
    device_id   = varint_fields[4]   # uint16 @39

    # --- 构造 57 字节结构体 ---
    buf = bytearray(57)

    buf[0] = 0x00                         # 标志位, 始终 0
    buf[1] = v8 & 0xFF                    # comp_alg
    buf[2] = v9 & 0xFF                    # encrypt_algo
    buf[3] = v10 & 0xFF                   # body_len

    struct.pack_into('<I', buf, 4, client_ver)
    struct.pack_into('<I', buf, 8, uin)

    # body
    buf[12:12 + v10] = body_data

    struct.pack_into('<H', buf, 27, func_type & 0xFFFF)
    struct.pack_into('<I', buf, 29, enc_len & 0xFFFFFFFF)
    struct.pack_into('<I', buf, 33, comp_len & 0xFFFFFFFF)
    struct.pack_into('<H', buf, 37, field_37 & 0xFFFF)
    struct.pack_into('<H', buf, 39, device_id & 0xFFFF)

    # --- has_flag 扩展字段 ---
    if has_flag:
        buf[41] = 1

        # varint: signature (uint32 @42)
        sig, pos = _read_varint(wire, pos)
        struct.pack_into('<I', buf, 42, sig & 0xFFFFFFFF)

        # byte: flag_byte (@46)
        if pos >= len(wire):
            raise ValueError("Truncated at flag_byte")
        buf[46] = wire[pos]
        pos += 1

        # varint: field_47_50 (uint32 @47)
        f47, pos = _read_varint(wire, pos)
        struct.pack_into('<I', buf, 47, f47 & 0xFFFFFFFF)

        # byte: field_51
        if pos >= len(wire):
            raise ValueError("Truncated at field_51")
        buf[51] = wire[pos]
        pos += 1

        # byte: ext_flag (@52)
        if pos >= len(wire):
            raise ValueError("Truncated at ext_flag")
        buf[52] = wire[pos]
        pos += 1

        # varint: group_key (uint16 @53)
        gk, pos = _read_varint(wire, pos)
        struct.pack_into('<H', buf, 53, gk & 0xFFFF)

        # BE uint16: seq_key (@55)
        if pos + 2 > len(wire):
            raise ValueError("Truncated at seq_key")
        seq_key = struct.unpack_from('>H', wire, pos)[0]
        struct.pack_into('<H', buf, 55, seq_key & 0xFFFF)
    else:
        # has_flag = 0, 扩展字段不存在, 填默认值
        buf[41] = 0
        buf[42:46] = b'\x00\x00\x00\x00'
        buf[46] = 0
        buf[47:51] = b'\x00\x00\x00\x00'
        buf[51] = 0
        buf[52] = 0
        buf[53:55] = b'\x00\x00'
        buf[55:57] = b'\x00\x00'

    return bytes(buf)


def print_wire_analysis(wire: bytes) -> dict:
    """
    解析 wire format 并以结构化字典返回所有参数。
    同时打印人类可读的字段分析。

    Parameters
    ----------
    wire : bytes
        serialize_header() 输出的 wire format 字节流。

    Returns
    -------
    dict
        包含所有解析参数的字典。
    """
    header_57 = deserialize_wire(wire)

    # 从 57 字节结构体中提取字段
    has_flag = (header_57[41] != 0)
    head_val = struct.unpack_from('<H', wire, 1 if has_flag else 0)[0]

    d = {
        'has_flag':      has_flag,
        'head_raw':      f"0x{head_val:04X}",
        'comp_alg':      header_57[1],                        # v8
        'encrypt_algo':  header_57[2],                        # v9
        'body_len':      header_57[3],                        # v10
        'client_ver':    f"0x{struct.unpack_from('<I', header_57, 4)[0]:08X}",
        'uin':           struct.unpack_from('<I', header_57, 8)[0],
        'body_data':     bytes(header_57[12:12 + header_57[3]]).hex(' ').upper(),
        'func_type':     struct.unpack_from('<H', header_57, 27)[0],
        'enc_len':       struct.unpack_from('<I', header_57, 29)[0],
        'comp_len':      struct.unpack_from('<I', header_57, 33)[0],
        'device_id':     struct.unpack_from('<H', header_57, 39)[0],
    }

    if has_flag:
        d['signature']    = struct.unpack_from('<I', header_57, 42)[0]
        d['flag_byte']    = f"0x{header_57[46]:02X}"
        d['field_47_50']  = f"0x{struct.unpack_from('<I', header_57, 47)[0]:08X}"
        d['field_51']     = f"0x{header_57[51]:02X}"
        d['ext_flag']     = f"0x{header_57[52]:02X}"
        d['group_key']    = struct.unpack_from('<H', header_57, 53)[0]
        d['seq_key']      = struct.unpack_from('<H', header_57, 55)[0]

    # 打印
    print("=" * 72)
    print("  Wire Format Analysis — deserialize_wire()")
    print("=" * 72)
    print(f"  Wire length:    {len(wire)} bytes")
    print(f"  has_flag:       {d['has_flag']}")
    print(f"  head (raw):     {d['head_raw']}")
    print(f"  comp_alg:       {d['comp_alg']}")
    print(f"  encrypt_algo:   {d['encrypt_algo']} (0x{d['encrypt_algo']:02X})")
    print(f"  body_len:       {d['body_len']}")
    print(f"  client_ver:     {d['client_ver']}")
    print(f"  uin:            {d['uin']} (0x{d['uin']:08X})")
    print(f"  body_data:      {d['body_data']}")
    print(f"  func_type:      {d['func_type']} (0x{d['func_type']:04X})")
    print(f"  enc_len:        {d['enc_len']} (0x{d['enc_len']:08X})")
    print(f"  comp_len:       {d['comp_len']} (0x{d['comp_len']:08X})")
    print(f"  device_id:      {d['device_id']} (0x{d['device_id']:04X})")
    if has_flag:
        print(f"  signature:      {d['signature']} (0x{d['signature']:08X})")
        print(f"  flag_byte:      {d['flag_byte']}")
        print(f"  field_47_50:    {d['field_47_50']}")
        print(f"  field_51:       {d['field_51']}")
        print(f"  ext_flag:       {d['ext_flag']}")
        print(f"  group_key:      {d['group_key']} (0x{d['group_key']:04X})")
        print(f"  seq_key:        {d['seq_key']} (0x{d['seq_key']:04X})")
    print(f"  Reconstructed 57B: {header_57.hex(' ').upper()}")
    print("=" * 72)

    # 验证: serialize_header(decoded) == wire
    re_serialized = bytes(serialize_header(header_57))
    match = (re_serialized == wire)
    print(f"  Roundtrip verify: {'[OK]' if match else '[MISMATCH]'}")
    if not match:
        print(f"    re_serialized: {re_serialized.hex(' ').upper()}")
        print(f"    original:      {wire.hex(' ').upper()}")
    print("=" * 72)

    return d


# ============================================================
# 完整 pack 流程
# ============================================================

def pack(
    encrypt_algo: int,
    body_data: bytes,
    func_type: int,
    enc_body_len: int,
    signature: int,
    seq_key: int,
    encrypted_body: bytes = b'',   # 加密后的 body (来自 AesGcmEncryptWithCompress 输出)
    **header_kwargs,
) -> bytes:
    """
    完整 pack 流程:
      1. 构造 57 字节头部结构体
      2. 序列化头部 (sub_65658)
      3. 追加加密后的 body 数据 (如果有)

    返回: 最终的 pack 字节流
    """
    header = build_header(
        encrypt_algo=encrypt_algo,
        body_data=body_data,
        func_type=func_type,
        enc_body_len=enc_body_len,
        signature=signature,
        seq_key=seq_key,
        **header_kwargs,
    )
    result = serialize_header(header)
    if encrypted_body:
        result += encrypted_body
    return bytes(result)


# ============================================================
# 测试
# ============================================================

# 所有测试用例 (从 dump8.txt 和 dump8_1.txt 提取的 44 个 v90/输出对 + 1 个用户指定)
ALL_TESTS = [
    # ====== dump8.txt (body: e3 03 08...) ======
    ("d8_7cc21f6120", "00020d0f504700286cd95883e3030802000000007a5b223c7a29008a002a0100002a01000000000200011f5f12e4ff1b613142000000002889",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a29008a01aa02aa0200029fbec9a00eff9bc2c591040000008928"),
    ("d8_7de4dfe120_1", "00020d0f504700286cd95883e3030802000000007a5b223c7a29005e1862000000620000000000020001ee1cb0c4ff1b61314200000000f476",
     "bfc2df280047508358d96ce3030802000000007a5b223c7a2900de3062620002eeb9c0a50cff9bc2c5910400000076f4"),
    ("d8_7de22cc120", "0002050f504700286cd95883e3030802000000007a5b223c7a2900b9453a0000003a00000000000200011c1bf79bff1b61314200000000e2cc",
     "bfc65f280047508358d96ce3030802000000007a5b223c7a2900b98b013a3a00029cb6dcdf09ff9bc2c59104000000cce2"),
    ("d8_7de4dfe120_2", "0001050f504700286cd95883e3030802000000007a5b223c7a2900e221e2010000410100000000020001167ee8b5ff1b613142000000006dec",
     "bfc95f280047508358d96ce3030802000000007a5b223c7a2900e243e203c102000296fca1af0bff9bc2c59104000000ec6d"),
    ("d8_7de4dfe120_3", "00020d0f504700286cd95883e3030802000000007a5b223c7a29005a0fb2040000b204000000000200017246bd84ff1b61314200000000d3e2",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900da1eb209b2090002f28cf5a508ff9bc2c59104000000e2d3"),
    ("d8_7b16b58120_1", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900ed0ddb040000db0400000000020001d72769dcff1b613142000000006e65",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900ed1bdb09db090002d7cfa4e30dff9bc2c59104000000656e"),
    ("d8_7de4dfe120_4", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900a902040100000401000000000200017f2ae715ff1b6131420000000030fa",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900a905840284020002ffd49caf01ff9bc2c59104000000fa30"),
    ("d8_7b16b58120_2", "00020d0f504700286cd95883e3030802000000007a5b223c7a29009c075600000056000000000002000126145063ff1b6131420000000004c3",
     "bfc2df280047508358d96ce3030802000000007a5b223c7a29009c0f56560002a6a8c09a06ff9bc2c59104000000c304"),
    ("d8_7de4b04120_1", "0001050f504700286cd95883e3030802000000007a5b223c7a2900622503040000d701000000000200016f4e6bb3ff1b613142000000004d61",
     "bfc95f280047508358d96ce3030802000000007a5b223c7a2900e24a8308d7030002ef9cad9b0bff9bc2c59104000000614d"),
    ("d8_7b16b58120_3", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900fb001d0100001d0100000000020001f964eae0ff1b6131420000000088da",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900fb019d029d020002f9c9a9870eff9bc2c59104000000da88"),
    ("d8_7de4b04120_2", "0001050f504700286cd95883e3030802000000007a5b223c7a29006225820500002d02000000000200011eb9a49eff1b61314200000000a1b0",
     "bfc95f280047508358d96ce3030802000000007a5b223c7a2900e24a820bad0400029ef292f509ff9bc2c59104000000b0a1"),
    ("d8_7b16b58120_4", "00020d0f504700286cd95883e3030802000000007a5b223c7a29000e7477090000770900000000020001a423d044ff1b61314200000000d40a",
     "bfcedf280047508358d96ce3030802000000007a5b223c7a29008ee801f712f7120002a4c7c0a604ff9bc2c591040000000ad4"),
    ("d8_7de4b04120_3", "00020d0f504700286cd95883e3030802000000007a5b223c7a29007b015d0000005d00000000000200011b1bf69bff1b61314200000000291c",
     "bfc2df280047508358d96ce3030802000000007a5b223c7a2900fb025d5d00029bb6d8df09ff9bc2c591040000001c29"),
    ("d8_7de4b04120_4", "00020d0f504700286cd95883e3030802000000007a5b223c7a29005a0fb3040000b304000000000200017546789cff1b61314200000000d24c",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900da1eb309b3090002f58ce1e309ff9bc2c591040000004cd2"),
    ("d8_7b16b58120_5", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900590eae000000ae00000000000200010621a5cfff1b613142000000008692",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900d91cae01ae01000286c294fd0cff9bc2c591040000009286"),
    ("d8_7de4b04120_5", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900d102340000003400000000000200014a0900d5ff1b613142000000008bb0",
     "bfc2df280047508358d96ce3030802000000007a5b223c7a2900d10534340002ca9280a80dff9bc2c59104000000b08b"),
    ("d8_7de4b04120_6", "0001050f504700286cd95883e3030802000000007a5b223c7a2900b73ac60100003301000000000200012b7575cbff1b61314200000000cd27",
     "bfc95f280047508358d96ce3030802000000007a5b223c7a2900b775c603b3020002abead5db0cff9bc2c5910400000027cd"),
    ("d8_7de4dfe120_5", "00020d0f504700286cd95883e3030802000000007a5b223c7a29008a00250100002501000000000200016e5efd78ff1b61314200000000a0a1",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a29008a01a502a5020002eebcf5c707ff9bc2c59104000000a1a0"),
    ("d8_7de4b04120_7", "0002050f504700286cd95883e3030802000000007a5b223c7a2900dc031d0000001d0000000000020001f5113ebdff1b6131420000000089f4",
     "bfc25f280047508358d96ce3030802000000007a5b223c7a2900dc071d1d0002f5a3f8e90bff9bc2c59104000000f489"),
    ("d8_7de4dfe120_6", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900390392000000920000000000020001b12a9b03ff1b61314200000000f805",
     "bfc6df280047508358d96ce3030802000000007a5b223c7a2900b906920192010002b1d5ec1cff9bc2c5910400000005f8"),
    ("d8_7de4dfe120_7", "00020d0f504700286cd95883e3030802000000007a5b223c7a29000e7491090000910900000000020001aa3c2709ff1b61314200000000d1ac",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a29008ee801911391130002aaf99c49ff9bc2c59104000000acd1"),
    # ====== dump8_1.txt (body: ea 03 08...) ======
    ("d81_7de5433120_1", "00020d0f504700286cd95883ea030802000000006438127b13a1008a002a0100002a0100000000020001e95e283eff1b613142000000002d66",
     "bfcadf280047508358d96cea030802000000006438127b13a1008a01aa02aa020002e9bda1f103ff9bc2c59104000000662d"),
    ("d81_7de5433120_2", "00020d0f504700286cd95883ea030802000000006438127b13a1005a0fb2040000b204000000000200018844e6deff1b61314200000000a469",
     "bfcadf280047508358d96cea030802000000006438127b13a100da1eb209b2090002888999f70dff9bc2c5910400000069a4"),
    ("d81_7de5335120_1", "00020d0f504700286cd95883ea030802000000006438127b13a100fb001d0100001d01000000000200018a66d5d5ff1b61314200000000bc91",
     "bfcadf280047508358d96cea030802000000006438127b13a100fb019d029d0200028acdd5ae0dff9bc2c5910400000091bc"),
    ("d81_7b51e9a120_1", "00020d0f504700286cd95883ea030802000000006438127b13a100a9028000000080000000000002000183473253ff1b613142000000001a86",
     "bfcadf280047508358d96cea030802000000006438127b13a100a905800180010002838fc99905ff9bc2c59104000000861a"),
    ("d81_7de5335120_2", "00020d0f504700286cd95883ea030802000000006438127b13a1009c07560000005600000000000200016e1527b3ff1b6131420000000056a2",
     "bfc2df280047508358d96cea030802000000006438127b13a1009c0f56560002eeaa9c990bff9bc2c59104000000a256"),
    ("d81_7b51e9a120_2", "00020d0f504700286cd95883ea030802000000006438127b13a1000e7476090000760900000000020001cb234215ff1b6131420000000024a7",
     "bfcedf280047508358d96cea030802000000006438127b13a1008ee801f612f6120002cbc788aa01ff9bc2c59104000000a724"),
    ("d81_7b51e9a120_3", "00020d0f504700286cd95883ea030802000000006438127b13a1007b015d0000005d0000000000020001d61b3bcdff1b613142000000001080",
     "bfc2df280047508358d96cea030802000000006438127b13a100fb025d5d0002d6b7ece90cff9bc2c591040000008010"),
    ("d81_7b002b2120_1", "00020d0f504700286cd95883ea030802000000006438127b13a1005a0fb2040000b20400000000020001e0442c97ff1b613142000000009aaf",
     "bfcadf280047508358d96cea030802000000006438127b13a100da1eb209b2090002e089b1b909ff9bc2c59104000000af9a"),
    ("d81_7b51e9a120_4", "00020d0f504700286cd95883ea030802000000006438127b13a10014072600000026000000000002000196052d3eff1b613142000000009518",
     "bfc2df280047508358d96cea030802000000006438127b13a100940e26260002968bb4f103ff9bc2c591040000001895"),
    ("d81_7b002b2120_2", "0002050f504700286cd95883ea030802000000006438127b13a100b9453a0000003a0000000000020001d71b3ccdff1b61314200000000c9ce",
     "bfc65f280047508358d96cea030802000000006438127b13a100b98b013a3a0002d7b7f0e90cff9bc2c59104000000cec9"),
    ("d81_7b1c1a0120_1", "0001050f504700286cd95883ea030802000000006438127b13a100e221e2010000410100000000020001947b8d78ff1b61314200000000f0bb",
     "bfc95f280047508358d96cea030802000000006438127b13a100e243e203c102000294f7b5c407ff9bc2c59104000000bbf0"),
    ("d81_7b51e9a120_5", "0002050f504700286cd95883ea030802000000006438127b13a100dc031d0000001d000000000002000184146c11ff1b6131420000000023f8",
     "bfc25f280047508358d96cea030802000000006438127b13a100dc071d1d000284a9b08b01ff9bc2c59104000000f823"),
    ("d81_7b51e9a120_6", "00020d0f504700286cd95883ea030802000000006438127b13a1005e18e5000000e5000000000002000173432a6cff1b613142000000005667",
     "bfcadf280047508358d96cea030802000000006438127b13a100de30e501e5010002f386a9e106ff9bc2c591040000006756"),
    ("d81_7b51e9a120_7", "00020d0f504700286cd95883ea030802000000006438127b13a100d10251000000510000000000020001784308a4ff1b61314200000000e7e0",
     "bfc2df280047508358d96cea030802000000006438127b13a100d10551510002f886a1a00aff9bc2c59104000000e0e7"),
    ("d81_7b002b2120_3", "00020d0f504700286cd95883ea030802000000006438127b13a100d102360000003600000000000200015e12fa77ff1b6131420000000091ca",
     "bfc2df280047508358d96cea030802000000006438127b13a100d10536360002dea4e8bf07ff9bc2c59104000000ca91"),
    ("d81_7b1c1a0120_2", "00020d0f504700286cd95883ea030802000000006438127b13a100d1027b0000007b0000000000020001d821dfcbff1b6131420000000090e6",
     "bfc2df280047508358d96cea030802000000006438127b13a100d1057b7b0002d8c3fcde0cff9bc2c59104000000e690"),
    ("d81_7b1c1a0120_3", "00020d0f504700286cd95883ea030802000000006438127b13a100b41f74000000740000000000020001a424602eff1b61314200000000e61a",
     "bfc2df280047508358d96cea030802000000006438127b13a100b43f74740002a4c980f302ff9bc2c591040000001ae6"),
    ("d81_7b1c1a0120_4", "00020d0f504700286cd95883ea030802000000006438127b13a100d10234000000340000000000020001c209a7e1ff1b613142000000005345",
     "bfc2df280047508358d96cea030802000000006438127b13a100d10534340002c2939c8d0eff9bc2c591040000004553"),
    ("d81_7b1c1a0120_5", "00020d0f504700286cd95883ea030802000000006438127b13a100ee00f4000000f40000000000020001db43cdbcff1b613142000000001895",
     "bfcadf280047508358d96cea030802000000006438127b13a100ee01f401f4010002db87b5e60bff9bc2c591040000009518"),
    ("d81_7b1c1a0120_6", "00020d0f504700286cd95883ea030802000000006438127b13a100d102bc000000bc000000000002000135fae9b3ff1b6131420000000099a3",
     "bfcadf280047508358d96cea030802000000006438127b13a100d105bc01bc010002b5f4a79f0bff9bc2c59104000000a399"),
    ("d81_7b1c1a0120_7", "00020d0f504700286cd95883ea030802000000006438127b13a100d102360000003600000000000200015109d3d4ff1b6131420000000090f9",
     "bfc2df280047508358d96cea030802000000006438127b13a100d10536360002d192cca60dff9bc2c59104000000f990"),
    ("d81_7b002b2120_4", "00020d0f504700286cd95883ea030802000000006438127b13a100d1027a0000007a00000000000200010c6a03c8ff1b613142000000004e72",
     "bfc2df280047508358d96cea030802000000006438127b13a100d1057a7a00028cd48dc00cff9bc2c59104000000724e"),
    ("d81_7b1c1a0120_8", "00020d0f504700286cd95883ea030802000000006438127b13a100ed0d8204000082040000000002000129fa1dabff1b613142000000005188",
     "bfcadf280047508358d96cea030802000000006438127b13a100ed1b820982090002a9f4f7d80aff9bc2c591040000008851"),
    # ====== dump8.txt 用户选中的 v90 (7de5433220) ======
    ("d8_user_7de5433220", "00020d0f504700286cd95883e3030802000000007a5b223c7a2900ee00f4000000f400000000000200018b440a30ff1b61314200000000d20a",
     "bfcadf280047508358d96ce3030802000000007a5b223c7a2900ee01f401f40100028b89a98003ff9bc2c591040000000ad2"),
]


if __name__ == "__main__":
    print("=" * 60)
    print(f"Running {len(ALL_TESTS)} test cases from dump8.txt + dump8_1.txt")
    print("=" * 60)

    passed = 0
    failed = 0
    for name, inp_hex, exp_hex in ALL_TESTS:
        buf_in = bytes.fromhex(inp_hex)
        expected = bytes.fromhex(exp_hex)
        result = bytes(serialize_header(buf_in))

        if result == expected:
            passed += 1
        else:
            failed += 1
            if failed <= 3:
                print(f"FAIL {name}:")
                print(f"  result: {result.hex()}")
                print(f"  expect: {expected.hex()}")

    print(f"Passed: {passed}/{len(ALL_TESTS)}")
    if failed:
        print(f"FAILED: {failed}")
    else:
        print("ALL PASSED!")

    # ====== build_header 验证 ======
    print()
    print("=" * 60)
    print("build_header 验证 (模拟 dump8.txt pack 调用)")
    print("=" * 60)

    body = bytes([0xe3, 0x03, 0x08, 0x02, 0x00, 0x00, 0x00, 0x00,
                  0x7a, 0x5b, 0x22, 0x3c, 0x7a, 0x29, 0x00])

    built = build_header(
        encrypt_algo=13,          # i=13 (AES_GCM)
        body_data=body,           # bArr3
        func_type=238,            # i3
        enc_body_len=244,         # 0xF4
        signature=805979275,      # i5 = 0x300A448B
        seq_key=2770,             # i11 = 0x0AD2
    )

    dump8_a1 = bytes.fromhex(
        "00020d0f504700286cd95883e3030802000000007a5b223c7a2900"
        "ee00f4000000f400000000000200018b440a30ff1b61314200000000d20a"
    )
    match = (built == dump8_a1)
    print(f"build_header == dump8.txt v90 a1: {match}")
    if not match:
        for i in range(57):
            if built[i] != dump8_a1[i]:
                print(f"  byte[{i:2d}]: built={built[i]:02X} dump={dump8_a1[i]:02X}")

    built_result = bytes(serialize_header(built))
    expected_result = bytes.fromhex(
        "bfcadf280047508358d96ce3030802000000007a5b223c7a2900"
        "ee01f401f40100028b89a98003ff9bc2c591040000000ad2"
    )
    print(f"serialize_header 匹配: {built_result == expected_result}")
