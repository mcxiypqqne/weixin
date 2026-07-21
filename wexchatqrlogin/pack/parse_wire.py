"""解析 dump.py 中硬编码的 pack_head_wire"""
from pack1 import serialize_header
import struct

wire = bytes.fromhex(
    'BF CA DF 28 00 47 50 83 58 D9 6C '
    '01 03 08 02 00 00 00 00 1C BD 34 F0 58 9F 00 '
    'EE 01 F4 01 F4 01 00 02 F0 83 D5 C8 01 FF 9B C2 C5 91 04 00 00 00 05 EF'
)

print('pack_head_wire length:', len(wire), 'bytes')
head = struct.unpack('<H', wire[1:3])[0]
print(f'head: {head:04X}')
print(f'  v8={head & 3}, byte0*4={((head>>2)&0x3F)*4}, v10={(head>>8)&0xF}, v9={(head>>12)&0xF}')

# bswap32 fields
d4 = struct.unpack('>I', wire[3:7])[0]
d8 = struct.unpack('>I', wire[7:11])[0]
print(f'dword4 (bswap): {d4:08X}')
print(f'dword8 (bigE):  {d8:08X}')

# body
v10 = (head >> 8) & 0xF
body = wire[11:11+v10]
print(f'body [{v10}B]: {body.hex()}')

# Parse varints
pos = 11 + v10
remaining = wire[pos:]
print(f'\nRemaining wire: {remaining.hex()}')

vals = []
i = 0
while i < len(remaining):
    result = 0; shift = 0
    while i < len(remaining):
        b = remaining[i]; i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    vals.append(('varint', result))

# Manual parse of fixed bytes
# After 5 varints: funcType, encLen, encLen, 0, deviceId
# Then: varint(sig), byte(FF), varint(0x4231611B), byte(0), byte(0), varint(0), BE16(seqKey)

# Actually let me just find the FF byte
for j in range(len(remaining)):
    if remaining[j] == 0xFF:
        print(f'FF at remaining[{j}]')
        break

# Last 2 bytes are seqKey BE
seqKey = struct.unpack('>H', wire[-2:])[0]
print(f'seqKey: {seqKey} (0x{seqKey:04X})')

print(f'\n=== Varint values ===')
for i, (t, v) in enumerate(vals):
    print(f'  [{i}] {t}: {v} (0x{v:X})')

# Reconstruct 57-byte struct
print(f'\n=== 57-byte struct reconstruction ===')
# We know the fixed fields:
struct_57 = bytearray(57)
struct_57[0] = ((head >> 2) & 0x3F)  # byte0 * 4 was in bits 2-7
struct_57[1] = head & 3               # v8 = compAlg
struct_57[2] = (head >> 12) & 0xF     # v9 = encryptAlgo
struct_57[3] = (head >> 8) & 0xF      # v10 = body_len

# dword4 and dword8
struct.pack_into('<I', struct_57, 4, d4)  # bswap32 back
struct.pack_into('<I', struct_57, 8, d8)

# body
struct_57[12:12+v10] = body

# varints
varint_fields = [(27, '<H'), (29, '<I'), (33, '<I'), (37, '<H'), (39, '<H')]
for idx, (off, fmt) in enumerate(varint_fields):
    if idx < len(vals):
        v = vals[idx][1]
        struct.pack_into(fmt, struct_57, off, v)

# has_flag fields
struct_57[41] = 1
if len(vals) > 5:
    struct.pack_into('<I', struct_57, 42, vals[5][1])  # signature
struct_57[46] = 0xFF
if len(vals) > 6:
    struct.pack_into('<I', struct_57, 47, vals[6][1])  # 0x4231611B
struct_57[51] = 0
struct_57[52] = 0
struct_57[53:55] = b'\x00\x00'
struct.pack_into('<H', struct_57, 55, seqKey)

print(f'Reconstructed 57B: {struct_57.hex()}')

# Verify: serialize and compare
result = bytes(serialize_header(bytes(struct_57)))
print(f'\n=== Verification ===')
print(f'Serialized: {result.hex()}')
print(f'Original:   {wire.hex()}')
print(f'Match: {result == wire}')
