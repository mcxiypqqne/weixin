
import struct
import re

def uleb128_encode(value: int) -> bytearray:
    """无符号 LEB128 编码，返回字节数组"""
    res = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        res.append(byte)
        if value == 0:
            break
    return res


def sub_659d4(data: bytes) -> bytes:
    """模拟 sub_659D4: 对输入的小端 4 字节做 bswap32（即转大端）"""
    if len(data) < 4:
        raise ValueError("sub_659D4 needs 4 bytes")
    return data[0:4][::-1]  # 字节反转


def sub_65a94(val: int) -> bytes:
    """2 字节大端序写入（模拟 sub_65A94）"""
    return struct.pack('>H', val & 0xFFFF)


def pack_data(hex_str: str) -> str:
    # 1. 清理输入并转换为字节
    hex_str = re.sub(r'\s+', '', hex_str.strip())
    data = bytes.fromhex(hex_str)

    # 确保长度至少 57 字节（到偏移 55+2）
    if len(data) < 57:
        raise ValueError("输入数据太短，至少需要 57 字节")

    # 2. 解析各字段
    byte0 = data[0]
    byte1 = data[1]
    byte2 = data[2]
    byte3 = data[3]

    # 4-7: 小端 uint32
    val_4_7 = struct.unpack('<I', data[4:8])[0]

    # 8-11: 小端 uint32 用于 sub_659D4
    val_8_11 = data[8:12]  # 直接取原始字节

    # 12 开始数据块长度 = byte3
    data_block = data[12:12+byte3]

    # 27: uint16 小端
    v27 = struct.unpack('<H', data[27:29])[0]
    # 29: uint32 小端
    v29 = struct.unpack('<I', data[29:33])[0]
    # 33: uint32 小端
    v33 = struct.unpack('<I', data[33:37])[0]
    # 37: uint16 小端
    v37 = struct.unpack('<H', data[37:39])[0]
    # 39: uint16 小端
    v39 = struct.unpack('<H', data[39:41])[0]

    byte41 = data[41]

    # 扩展字段（只有当 byte41 != 0 时才读取）
    if byte41:
        v42 = struct.unpack('<I', data[42:46])[0]
        v46 = data[46]
        v47 = struct.unpack('<I', data[47:51])[0]
        v51 = data[51]
        v52 = data[52]
        v53 = struct.unpack('<H', data[53:55])[0]
        v55 = struct.unpack('<H', data[55:57])[0]

    # 3. 开始打包
    output = bytearray()

    # 前置 0xBF
    if byte41:
        output.append(0xBF)
        header_pos = 1  # 帧头位于偏移 1 处
    else:
        header_pos = 0

    # 初始帧头（长度部分先填 0）
    header_low = ((byte0 << 2) & 0xFC) | (byte1 & 3)   # 4*byte0 的低6位 + 低两位
    header_high = (byte3 & 0x0F) | ((byte2 & 0x0F) << 4)
    output.append(header_low)
    output.append(header_high)

    # 4 字节大端整数 (bswap32)
    output.extend(struct.pack('>I', val_4_7))

    # sub_659D4 结果
    output.extend(sub_659d4(val_8_11))

    # 数据块
    output.extend(data_block)

    # 一系列 LEB128
    for v in (v27, v29, v33, v37, v39):
        output.extend(uleb128_encode(v))

    if byte41:
        output.extend(uleb128_encode(v42))
        output.append(v46)
        output.extend(uleb128_encode(v47))
        output.append(v51)
        output.append(v52)
        output.extend(uleb128_encode(v53))
        output.extend(sub_65a94(v55))

    # 4. 回填帧头中的长度字段
    total_len = len(output)  # 整个输出包的长度
    # 长度只取低6位，然后乘以4填入 bit7-2
    length_field = (total_len & 0x3F) << 2
    # 保留原有的最低2位，更新 bit7-2
    output[header_pos] = (output[header_pos] & 0x03) | length_field

    # 5. 输出十六进制字符串
    return ' '.join(f'{b:02X}' for b in output)


# 测试例子1
input1 ='''
 00 02 0C 0F 50 47 00 28 6C D9 58 83 0B 03 08 02 00 00 00 00 10 5F A7 A2 0B 3B 00 FB 02 30 25 00 00 30 25 00 00 28 27 02 00 01 00 00 00 00 FE 01 60 7A 42 00 00 00 00 00 00 
'''
output1 = pack_data(input1)
print("Output 1:", output1)




"""
00 02 0c 0f 50 47 00 28 6c d9 58 83 35 03 08 02  ....PG.(l.X.5...
00 00 00 00 25 1f ba 74 5b 5b 00 fb 02 9c 27 00  ....%..t[[....'.
00 9c 27 00 00 28 27 02 00 01 00 00 00 00 fe 15  ..'..('.........
0f 41 42 00 00 00 00 00 00
"""
'''
00 02 0C 0F 50 47 00 28 6C D9 58 83 CF 03 08 02 00 00 00 00 68 90 23 0E EB AE 00 FB 02 FA 26 00 00 FA 26 00 00 28 27 02 00 01 00 00 00 00 FF 21 49 33 42 00 00 00 00 00 00
             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00 02 0c 0f 50 47 00 28  6c d9 58 83  cf 03 08 02  ....PG.(l.X.....
00 00 00 00 68 90 23 0e eb ae 00 fb 02 fa 26 00  ....h.#.......&.
00 fa 26 00 00 28 27 02 00 01 00 00 00 00 ff 21  ..&..('........!
49 33 42 00 00 00 00 00 00 
'''
