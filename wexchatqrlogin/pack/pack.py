import struct

def varint_encode(value: int) -> bytes:
    """sub_65A08: 无符号 Base-128 Varint 编码"""
    if value < 0x80:
        return bytes([value])
    result = []
    while value:
        # 取低7位，如果还有高位数据则设置 continuation bit
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        result.append(byte)
    return bytes(result)

def write_be16(value: int) -> bytes:
    """sub_65A94: 大端写入16位无符号整数"""
    return struct.pack('>H', value & 0xFFFF)

def serialize(buf_in: bytes) -> bytearray:
    """
    实现 sub_65658 的序列化逻辑。
    buf_in: 结构体基址 a1 处开始的原始字节（至少 57 字节）
    返回序列化后的字节流
    """
    # 基本合法性检查
    if len(buf_in) < 57:
        raise ValueError("buffer too short")
    v8 = buf_in[1]      # 偏移 +1
    v9 = buf_in[2]      # 偏移 +2
    v10 = buf_in[3]     # 偏移 +3
    if v8 > 3:
        raise ValueError("v8 > 3")
    if v9 > 0xF:
        raise ValueError("v9 > 0xF")
    if v10 > 0xF:
        raise ValueError("v10 > 0xF")

    out = bytearray()
    idx = 0  # 模拟 *a3 偏移量

    # 处理标志字节 (偏移 +41)
    has_flag = (buf_in[41] != 0)

    if has_flag:
        out.append(0xBF)
        idx += 1

    # 写入 16 位组合头
    # 注意: v20 回填时会覆盖部分字段，这里先用 buf_in[0] 生成初值
    head = (v8 & 3) | (4 * buf_in[0]) | ((v10 & 0xF) << 8) | (v9 << 12)
    out += struct.pack('<H', head)
    idx += 2

    # 大端写入 32 位 (偏移 +4)
    val32 = struct.unpack('<I', buf_in[4:8])[0]
    out += struct.pack('>I', val32)
    idx += 4

    # sub_659D4: 大端写入偏移 +8 的 32 位值
    val32 = struct.unpack('<I', buf_in[8:12])[0]
    out += struct.pack('>I', val32)
    idx += 4

    # memcpy 定长数据 (长度 = buf_in[3])，从偏移 +12 开始
    data_len = v10
    out += buf_in[12:12 + data_len]
    idx += data_len

    # 连续写入 5 个 Varint 字段 (偏移 +27,+29,+33,+37,+39)
    fields_varint = [
        ('<H', 27),  # uint16
        ('<I', 29),  # uint32
        ('<I', 33),  # uint32
        ('<H', 37),  # uint16
        ('<H', 39),  # uint16
    ]
    for fmt, off in fields_varint:
        val = struct.unpack(fmt, buf_in[off:off + struct.calcsize(fmt)])[0]
        out += varint_encode(val)
        idx += len(varint_encode(val))

    if has_flag:
        # Varint 偏移 +42 (uint32)
        val = struct.unpack('<I', buf_in[42:46])[0]
        enc = varint_encode(val)
        out += enc; idx += len(enc)

        # 单字节 偏移 +46
        out.append(buf_in[46]); idx += 1

        # Varint 偏移 +47 (uint32)
        val = struct.unpack('<I', buf_in[47:51])[0]
        enc = varint_encode(val)
        out += enc; idx += len(enc)

        # 单字节 偏移 +51
        out.append(buf_in[51]); idx += 1
        # 单字节 偏移 +52
        out.append(buf_in[52]); idx += 1

        # Varint 偏移 +53 (uint16)
        val = struct.unpack('<H', buf_in[53:55])[0]
        enc = varint_encode(val)
        out += enc; idx += len(enc)

        # 大端 16 位 偏移 +55
        val = struct.unpack('<H', buf_in[55:57])[0]
        out += write_be16(val)
        idx += 2

        # 末尾回填: 当 idx <= 64 时，修改 16 位头部的 bit7..2
        if idx <= 64:
            # 头部位于偏移 1 处（因为前方有一个 0xBF）
            current_head = struct.unpack('<H', out[1:3])[0]
            # 清除 bit7..2，并用 (idx & 0x3F) << 2 填充
            new_head = (current_head & 0xFF03) | ((idx & 0x3F) << 2)
            out[1:3] = struct.pack('<H', new_head)

    return out

test_cases = [
    {
        "name": "测试组 1 (7de4dfe120)",
        "input_hex": (
            "00 02 0d 0f 50 47 00 28 6c d9 58 83 e3 03 08 02"
            "00 00 00 00 7a 5b 22 3c 7a 29 00 5e 18 62 00 00"
            "00 62 00 00 00 00 00 02 00 01 ee 1c b0 c4 ff 1b"
            "61 31 42 00 00 00 00 f4 76"
        ),
        "expected_hex": (
            "bf c2 df 28 00 47 50 83 58 d9 6c e3 03 08 02 00"
            "00 00 00 7a 5b 22 3c 7a 29 00 de 30 62 62 00 02"
            "ee b9 c0 a5 0c ff 9b c2 c5 91 04 00 00 00 76 f4"
        )
    },
    {
        "name": "测试组 2 (7de22cc120)",
        "input_hex": (
            "00 02 05 0f 50 47 00 28 6c d9 58 83 e3 03 08 02"
            "00 00 00 00 7a 5b 22 3c 7a 29 00 b9 45 3a 00 00"
            "00 3a 00 00 00 00 00 02 00 01 1c 1b f7 9b ff 1b"
            "61 31 42 00 00 00 00 e2 cc"
        ),
        "expected_hex": (
            "bf c6 5f 28 00 47 50 83 58 d9 6c e3 03 08 02 00"
            "00 00 00 7a 5b 22 3c 7a 29 00 b9 8b 01 3a 3a 00"
            "02 9c b6 dc df 09 ff 9b c2 c5 91 04 00 00 00 cc e2"
        )
    },
    {
        "name": "测试组 3 (7de4dfdd08)",
        "input_hex": (
            "00 02 05 0f 50 47 00 28 6c d9 58 83 e3 03 08 02"
            "00 00 00 00 7a 5b 22 3c 7a 29 00 b9 2d 36 00 00"
            "00 36 00 00 00 00 00 02 00 01 7a 19 9f c6 ff 1b"
            "61 31 42 00 00 00 00 e2 dd"
        ),
        "expected_hex": (
            "bf c2 5f 28 00 47 50 83 58 d9 6c e3 03 08 02 00"
            "00 00 00 7a 5b 22 3c 7a 29 00 b9 5b 36 36 00 02"
            "fa b2 fc b4 0c ff 9b c2 c5 91 04 00 00 00 dd e2"
        )
    }
]

# ========== 运行所有测试 ==========
all_passed = True
for tc in test_cases:
    buf_in = bytes.fromhex(tc["input_hex"].replace(" ", ""))
    expected = bytes.fromhex(tc["expected_hex"].replace(" ", ""))
    result = serialize(buf_in)
    
    match = (result == expected)
    if not match:
        all_passed = False
        # 找出第一个不同字节的位置
        for i in range(max(len(result), len(expected))):
            if i >= len(result) or i >= len(expected) or result[i] != expected[i]:
                print(f"\n❌ {tc['name']} 在第 {i} 字节处不匹配")
                print(f"   结果[{i}]: {result[i]:02X}, 期望[{i}]: {expected[i]:02X}" if i < len(expected) else f"   结果超出期望长度")
                break
    
    print(f"{'✅' if match else '❌'} {tc['name']}: {'匹配' if match else '不匹配'}")
    print(f"   结果: {result.hex(' ')}")
    print(f"   期望: {expected.hex(' ')}")
    print()

if all_passed:
    print("🎉 所有测试用例全部通过！")
else:
    print("⚠️  存在不匹配的测试用例，需要进一步排查")

    