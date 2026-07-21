"""验证 wire (47B) <-> 57B 结构体 的正反向转换"""
from pack1 import deserialize_wire, serialize_header
import struct

wire_hex = (
    "BF BE CF 28 00 47 50 83 58 D9 6C "
    "87 03 08 02 00 00 00 00 57 F4 76 C0 92 67 00 "
    "FB 05 B6 4A B6 4A A8 4E 02 00 "
    "FE 9F 96 ED 90 04 00 00 00 00 00"
)
wire = bytes.fromhex(wire_hex.replace(" ", ""))

print("=" * 64)
print("  1) 反向: wire (47B) --deserialize_wire--> 57B 结构体")
print("=" * 64)
print(f"  wire 长度: {len(wire)} bytes")
print(f"  wire hex:  {wire.hex(' ').upper()}")
print()

header_57 = deserialize_wire(wire)
print(f"  还原 57B:  {header_57.hex(' ').upper()}")
print()

# 逐字段打印 57B 结构体
fields = [
    (0,   1,  "buf[0] 标志位"),
    (1,   1,  "comp_alg"),
    (2,   1,  "encrypt_algo"),
    (3,   1,  "body_len"),
    (4,   4,  "clientVer (LE)"),
    (8,   4,  "uin (LE)"),
    (12, 15,  "body_data"),
    (27,  2,  "funcType (LE)"),
    (29,  4,  "enc_len (LE)"),
    (33,  4,  "comp_len (LE)"),
    (37,  2,  "field_37 (固定0)"),
    (39,  2,  "deviceId (LE)"),
    (41,  1,  "has_flag"),
    (42,  4,  "signature (LE)"),
    (46,  1,  "flag_byte"),
    (47,  4,  "field_47_50 (LE)"),
    (51,  1,  "field_51"),
    (52,  1,  "extFlag"),
    (53,  2,  "groupKey (LE)"),
    (55,  2,  "seqKey (LE)"),
]
for off, size, label in fields:
    if size == 1:
        val = header_57[off]
        print(f"  [{off:2d}] {label:25s} = 0x{val:02X} ({val})")
    elif size == 2:
        val = struct.unpack_from("<H", header_57, off)[0]
        print(f"  [{off:2d}] {label:25s} = 0x{val:04X} ({val})")
    elif size == 4:
        val = struct.unpack_from("<I", header_57, off)[0]
        print(f"  [{off:2d}] {label:25s} = 0x{val:08X} ({val})")
    else:
        val = header_57[off:off + size]
        print(f"  [{off:2d}] {label:25s} = {val.hex(' ').upper()}")

print()
print("=" * 64)
print("  2) 正向: 57B 结构体 --serialize_header--> wire (47B)")
print("=" * 64)
re_wire = bytes(serialize_header(header_57))
print(f"  重新序列化: {re_wire.hex(' ').upper()}")
print()

print("=" * 64)
print("  3) 对比验证")
print("=" * 64)
print(f"  原始 wire:  {wire.hex(' ').upper()}")
print(f"  重新 wire:  {re_wire.hex(' ').upper()}")
print()

if wire == re_wire:
    print("  [OK] 完全一致 -- 反向->正向 往返验证通过!")
else:
    print("  [FAIL] 不匹配!")
    for i in range(len(wire)):
        if wire[i] != re_wire[i]:
            print(f"    offset {i}: orig=0x{wire[i]:02X} re=0x{re_wire[i]:02X}")
