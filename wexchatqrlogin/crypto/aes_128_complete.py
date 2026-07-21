#!/usr/bin/env python3
"""
AES-128 加密完整实现 — 基于 trace 提取的三张 T-Table
"""

import struct

# 加载所有表 (每轮不同)
import os
DIR = os.path.dirname(os.path.abspath(__file__))
EXPAND_TABLES = [open(f"{DIR}/expand_round{r}.bin","rb").read() for r in range(1,10)]
ROUND_TABLES = [open(f"{DIR}/round_round{r}.bin","rb").read() for r in range(1,10)]
FINAL_TABLE = open(f"{DIR}/final.bin","rb").read()

def sub_A7B0A0(state_16, round_idx):
    """
    展开函数 (expand) — 对应 trace 中的 0xa7b0a0
    输入: 16字节 state, 轮序号 (0-8)
    输出: 32+ bytes expanded state
    """
    tbl = EXPAND_TABLES[round_idx]
    # v4_idx starts at 32, max write is v4_idx+28 which at idx 35 = 63
    out = [0] * 64

    v4_idx = 32  # v4 = output + 32
    v5_idx = 3   # v5 = state + 3
    TBL_MASK = len(tbl) - 1  # 0xFFF if table is 4KB, 0x3FFF if 16KB

    def _rd(off):
        """读表, 如果需要 16KB 但只有 4KB, 报错"""
        if off >= len(tbl):
            raise IndexError(f"expand表偏移 0x{off:x} 超出范围 0x{len(tbl):x}, 需要 dump 0x4000")
        return tbl[off]

    for v3 in (0, 0x1000, 0x2000, 0x3000):
        s0 = state_16[v5_idx - 3]
        s1 = state_16[v5_idx - 2]
        s2 = state_16[v5_idx - 1]
        s3 = state_16[v5_idx]

        # T0: offset +0, +1, +2, +3
        out[v4_idx - 32] = _rd(4 * s0 + v3 + 0)
        out[v4_idx - 16] = _rd(4 * s0 + v3 + 1)
        out[v4_idx]      = _rd(4 * s0 + v3 + 2)
        out[v4_idx + 16] = _rd(4 * s0 + v3 + 3)

        # T1: offset +0x400..0x403
        out[v4_idx - 28] = _rd(4 * s1 + v3 + 1024 + 0)
        out[v4_idx - 12] = _rd(4 * s1 + v3 + 1024 + 1)
        out[v4_idx + 4]  = _rd(4 * s1 + v3 + 1024 + 2)
        out[v4_idx + 20] = _rd(4 * s1 + v3 + 1024 + 3)

        # T2: offset +0x800..0x803
        out[v4_idx - 24] = _rd(4 * s2 + v3 + 2048 + 0)
        out[v4_idx - 8]  = _rd(4 * s2 + v3 + 2048 + 1)
        out[v4_idx + 8]  = _rd(4 * s2 + v3 + 2048 + 2)
        out[v4_idx + 24] = _rd(4 * s2 + v3 + 2048 + 3)

        # T3: offset +0xC00..0xC03
        out[v4_idx - 20] = _rd(4 * s3 + v3 + 3072 + 0)
        out[v4_idx - 4]  = _rd(4 * s3 + v3 + 3072 + 1)
        out[v4_idx + 12] = _rd(4 * s3 + v3 + 3072 + 2)
        out[v4_idx + 28] = _rd(4 * s3 + v3 + 3072 + 3)

        v5_idx += 4
        v4_idx += 1

    return bytes(out)


def nibble_lookup(tbl, index, base_offset, v5):
    """
    查 round 表取 nibble (模拟 IDA 中的查表逻辑)
    """
    if index & 0x80:
        return tbl[(index & 0x7F) + v5 + base_offset] >> 4
    else:
        return tbl[index + v5 + base_offset] & 0xF


def sub_A7B378(state_16, expanded, round_idx):
    """
    主轮函数 — 对应 trace 中的 0xa7b378
    输入: state (16字节), expanded (32+字节), 轮序号 (0-8)
    输出: state 原地更新
    """
    tbl = ROUND_TABLES[round_idx]
    state = list(state_16)
    v4 = list(expanded)
    col_base = 0  # a3 offset per column

    def _rb(off):
        if off >= len(tbl):
            raise IndexError(f"round表 offset 0x{off:x} >= 0x{len(tbl):x}")
        return tbl[off]

    # ShiftRows write order per column: group writes go to (row + col) % 4
    shift_map = [(0,1,2,3), (3,0,1,2), (2,3,0,1), (1,2,3,0)]

    for col in range(4):
        v4_ptr = col * 16 + 1
        col_state = [0, 0, 0, 0]  # temp per column

        for gi, group in enumerate((0, 768, 1536, 2304)):  # v5
            base = col_base + group  # a3_offset + v5

            # expanded[2] → ShiftRows
            s2 = v4[v4_ptr + 2]
            # write to temp col_state
            temp = s2  # temp row value

            # lookup 1: offset +512
            s1 = v4[v4_ptr + 1]
            idx1 = (s1 & 0xF0) | ((s2 >> 4) & 0x0F)
            if idx1 & 0x80:
                v11 = tbl[base + ((s1 & 0x70) | ((s2 >> 4) & 0x7F)) + 512] >> 4
            else:
                v11 = tbl[base + idx1 + 512] & 0xF

            # lookup 2: offset +640  (unsigned char wrap!)
            v12 = ((s2 & 0x0F) | (16 * s1)) & 0xFF
            if v12 & 0x80:
                v13 = tbl[base + (v12 & 0x7F) + 640] >> 4
            else:
                v13 = tbl[base + v12 + 640] & 0xF

            temp = (v13 & 0x0F) | (16 * (v11 & 0x0F))

            # lookup 3: offset +256
            s0 = v4[v4_ptr]
            v14 = (v11 & 0x0F) | (s0 & 0xF0)
            if v14 & 0x80:
                v15 = tbl[base + (v14 & 0x7F) + 256] >> 4
            else:
                v15 = tbl[base + v14 + 256] & 0xF

            # lookup 4: offset +384  (unsigned char wrap!)
            v16 = ((v13 & 0x0F) | (16 * s0)) & 0xFF
            if v16 & 0x80:
                v17 = tbl[base + (v16 & 0x7F) + 384] >> 4
            else:
                v17 = tbl[base + v16 + 384] & 0xF

            temp = (v17 & 0x0F) | (16 * (v15 & 0x0F))

            # lookup 5: offset +0
            s_minus1 = v4[v4_ptr - 1]
            v19 = (v15 & 0x0F) | (s_minus1 & 0xF0)
            if v19 & 0x80:
                v20 = tbl[base + (v19 & 0x7F) + 0] >> 4
            else:
                v20 = tbl[base + v19 + 0] & 0xF

            # lookup 6: offset +128  (unsigned char wrap!)
            v21 = ((v17 & 0x0F) | (16 * s_minus1)) & 0xFF
            if v21 & 0x80:
                v8 = tbl[base + (v21 & 0x7F) + 128] >> 4
            else:
                v8 = tbl[base + v21 + 128] & 0xF

            col_state[gi] = (v8 & 0x0F) | (16 * (v20 & 0x0F))
            v4_ptr += 4

        # Write column with ShiftRows permutation
        for gi in range(4):
            state[col * 4 + shift_map[col][gi]] = col_state[gi]

        col_base += 3072  # a3 += 0xC00 per column

    return bytes(state)


def sub_A7BA74(state_16):
    """
    最终轮 — 对应 trace 中的 0xa7ba74
    输入: 16字节 state
    输出: 16字节密文
    """
    tbl = FINAL_TABLE
    s = state_16
    return bytes([
        tbl[0x000 + s[0]],  tbl[0x100 + s[1]],  tbl[0x200 + s[2]],  tbl[0x300 + s[3]],
        tbl[0x400 + s[4]],  tbl[0x500 + s[5]],  tbl[0x600 + s[6]],  tbl[0x700 + s[7]],
        tbl[0x800 + s[8]],  tbl[0x900 + s[9]],  tbl[0xA00 + s[10]], tbl[0xB00 + s[11]],
        tbl[0xC00 + s[12]], tbl[0xD00 + s[13]], tbl[0xE00 + s[14]], tbl[0xF00 + s[15]],
    ])


def aes_128_encrypt(plaintext_16):
    """一次 AES-128 加密 (16字节)"""
    # Initial state (AddRoundKey 已经在外部完成)
    state = bytearray(plaintext_16)

    # 9 轮主轮
    for rnd in range(9):
        expanded = sub_A7B0A0(bytes(state), rnd)
        state = bytearray(sub_A7B378(bytes(state), expanded, rnd))

    # 最终轮
    cipher = sub_A7BA74(bytes(state))
    return cipher


# ============== 测试 ==============
if __name__ == "__main__":
    # 用 trace 中的数据验证
    # 第1个block的初始state (来自trace line 2107237-2107268)
    state_initial = bytes([
        0x1a, 0x3a, 0xee, 0xcc, 0x99, 0x38, 0x7c, 0xe1,
        0x1e, 0x3d, 0xc1, 0x74, 0x80, 0xe6, 0xf9, 0x71
    ])

    # 第1个block的期望密文 (来自trace 0xa7ba74输出)
    expected_cipher = bytes([
        0x76, 0x2e, 0xde, 0x3f, 0x86, 0x22, 0xc9, 0xc6,
        0x1c, 0x27, 0xce, 0x63, 0xb9, 0xb0, 0x06, 0x2b
    ])

    print("=" * 60)
    print("AES-128 完整加密测试")
    print("=" * 60)
    print(f"表: expand×{len(EXPAND_TABLES)}, round×{len(ROUND_TABLES)}, final={len(FINAL_TABLE)}")

    # 逐轮测试 state[0] 变化
    state = bytearray(state_initial)
    print(f"\n初始 state[0]: 0x{state[0]:02x}")

    for rnd in range(9):
        expanded = sub_A7B0A0(bytes(state), rnd)
        state = bytearray(sub_A7B378(bytes(state), expanded, rnd))
        print(f"Round {rnd+1} 后 state[0]: 0x{state[0]:02x}")

    # 最终轮
    cipher = sub_A7BA74(bytes(state))
    print(f"最终轮后 state[0]: 0x{state[0]:02x}")

    print(f"\n密文: {cipher.hex(' ')}")
    print(f"期望: {expected_cipher.hex(' ')}")
    print("✓ 匹配!" if cipher == expected_cipher else "✗ 不匹配")

    # 第二个 block 测试 (如果表足够)
    if cipher == expected_cipher:
        print("\n" + "=" * 60)
        print("加密任意数据测试")
        print("=" * 60)
        # xor_data.py 的 aes_key XOR first 16 bytes of plaintext
        aes_key = bytes([0x62,0x7D,0x1C,0x7E,0x3D,0xCD,0x67,0x92,
                         0x59,0xCF,0x2D,0x98,0x48,0x58,0xF9,0xFA])
        plaintext_16 = bytes([0x78,0x9C,0xDD,0x98,0x07,0x54,0x13,0x6B,
                              0xB7,0xF7,0x33,0x29,0x93,0x90,0x46,0x8E])

        xor_result = bytes([k ^ p for k, p in zip(aes_key, plaintext_16)])
        print(f"AES Key:      {aes_key.hex(' ')}")
        print(f"Plaintext[0]: {plaintext_16.hex(' ')}")
        print(f"XOR result:   {xor_result.hex(' ')}")
        print(f"(trace初始state: 1a 3a ee cc e1 99 38 7c...)")
        print(f"注意: trace的初始state != XOR结果, 中间有额外变换")
