"""
sub_10F9D8 的 Python 复刻
=======================
ARM64 NEON SIMD 解密/变换算法，完全对照 trace.log 逐指令复现。

用法:
    from decrypt_simd import sub_10F9D8
    result = sub_10F9D8(input_bytes, total_int32=9)
"""
import struct

I32 = lambda x: x & 0xFFFFFFFF
I64 = lambda x: x & 0xFFFFFFFFFFFFFFFF
ALL64 = I64(0xFFFFFFFFFFFFFFFF)


# ============================================================
# NEON 指令模拟
# ============================================================

def dup_s32(v):          return [I32(v)] * 4
def dup_s64(v):          return [I64(v)] * 2
def neg_s32(v):          return [I32(~x + 1) for x in v]
def and_s(v1, v2):       return [a & b for a, b in zip(v1, v2)]
def orr_s(v1, v2):       return [a | b for a, b in zip(v1, v2)]
def eor_s(v1, v2):       return [a ^ b for a, b in zip(v1, v2)]
def add_s64(v1, v2):     return [I64(a + b) for a, b in zip(v1, v2)]
def add_s32(v1, v2):     return [I32(a + b) for a, b in zip(v1, v2)]

def ushl_s32(v1, v2):
    """vshlq_u32: 有符号移位值, 正=左移, 负=右移"""
    res = []
    for a, b in zip(v1, v2):
        s = b & 0xFFFFFFFF
        if s >= 0x80000000: s -= 0x100000000
        if s >= 32 or s <= -32: res.append(0)
        elif s >= 0:           res.append(I32(a << s))
        else:                  res.append(I32(a >> (-s)))
    return res

def cmtst_s64(v1, v2): return [ALL64 if (a & b) != 0 else 0 for a, b in zip(v1, v2)]
def cmeqz_s64(v):       return [ALL64 if a == 0 else 0 for a in v]

def bic_s(v1, v2):
    mask_fn = I64 if len(v1) == 2 else I32
    return [mask_fn(a & ~b) for a, b in zip(v1, v2)]

def bit_s(v1, v2, v3):
    """BIT: (mask & new) | (~mask & orig)"""
    mask_fn = I64 if len(v1) == 2 else I32
    return [mask_fn((sel & new) | (~sel & orig)) for orig, new, sel in zip(v1, v2, v3)]

def bif_s(v1, v2, v3):
    """BIF: (~mask & new) | (mask & orig)"""
    mask_fn = I64 if len(v1) == 2 else I32
    return [mask_fn((~sel & new) | (sel & orig)) for orig, new, sel in zip(v1, v2, v3)]

def xtn_s32(v64):      return [I32(x) for x in v64]
def xtn2_s32(lo, v64): return list(lo) + [I32(x) for x in v64]


# ============================================================
# NEON 块处理 (一轮迭代, 处理 4 个 int32 = 16 字节)
# ============================================================

def neon_process_block(state_q0, state_q1, state_q2, input_ints,
                       key_q3, key_q7, step_q01, init_q6,
                       use_hook=False):
    v0, v1, v2 = state_q0, state_q1, state_q2
    v3, v7 = key_q3, key_q7

    v16  = neg_s32(v2)
    v5   = dup_s64(0x1f)
    v17  = and_s(v2, dup_s32(0x1f))
    v16a = and_s(v16, dup_s32(0x1f))
    v6   = dup_s64(init_q6)
    v18  = dup_s64(step_q01)
    v21  = and_s(v0, v5)
    v24  = neg_s32(v17)
    v25  = ushl_s32(v3, v16a)
    v16b = neg_s32(v16a)
    v19  = add_s64(v1, v6)
    v6n  = add_s64(v0, v6)
    v20  = and_s(v1, v5)
    v22  = cmtst_s64(v1, v5)
    v23  = cmtst_s64(v0, v5)
    v17s = ushl_s32(v7, v17)
    v0n  = add_s64(v0, v18)
    v1n  = add_s64(v1, v18)
    v18e = eor_s(v21, v5)
    v24s = ushl_s32(v3, v24)
    v16s = ushl_s32(v7, v16b)
    v24o = orr_s(v24s, v25)
    v25e = eor_s(v20, v5)
    v21c = cmeqz_s64(v21)
    v16o = orr_s(v17s, v16s)
    v17c = cmeqz_s64(v18e)
    v20c = cmeqz_s64(v20)
    v23b = bic_s(v23, v17c)
    v17c2= bic_s(v17c, v21c)
    v21c2= cmeqz_s64(v25e)
    v22b = bic_s(v22, v21c2)
    v20co= bic_s(v21c2, v20c)
    v21a = and_s(v6n, v5)
    v5a  = and_s(v19, v5)
    v5c  = cmeqz_s64(v5a)
    v21ac= cmeqz_s64(v21a)

    v5n  = xtn_s32(v5c)
    v19n = xtn_s32(v19)
    v5n  = xtn2_s32(v5n, v21ac)
    v19n = xtn2_s32(v19n, v6n)
    v6e  = eor_s(v16o, v24o)
    v16nl= xtn_s32(v25e)
    v21nl= xtn_s32(v22b)
    v22a = and_s(v19n, dup_s32(0x1f))
    v19neg=neg_s32(v19n)
    v21n = xtn2_s32(v21nl, v23b)
    v16n = xtn2_s32(v16nl, v18e)
    v18a = and_s(v19neg, dup_s32(0x1f))
    v20nl= xtn_s32(v20co)
    v18neg=neg_s32(v18a)
    v20n = xtn2_s32(v20nl, v17c2)

    v17sh = ushl_s32(input_ints, v22a)
    v18sh = ushl_s32(input_ints, v18neg)
    v17sh = orr_s(v17sh, v18sh)
    if use_hook:
        # hook so版本: BSL=BIT, orig=new映射和trace相反
        v4  = bit_s(input_ints, v17sh, v5n)
        v5e  = eor_s(v6e, v4)
        v4b  = eor_s(v3, v4)
        v16neg = neg_s32(v16n)
        v4b  = eor_s(v4b, v7)
        v19f = and_s(v16neg, dup_s32(0x1f))
        v4  = bit_s(v5e, v4b, v21n)
        v6s = ushl_s32(v4, v19f)
        v4s = ushl_s32(v4, v16neg)
        v4  = orr_s(v4s, v6s)
        v4  = bit_s(v5e, v4, v20n)
    else:
        # trace版本: BIF, orig=new和hook相反
        v4  = bif_s(input_ints, v17sh, v5n)
        v5e  = eor_s(v6e, v4)
        v4b  = eor_s(v3, v4)
        v16neg = neg_s32(v16n)
        v4b  = eor_s(v4b, v7)
        v19f = and_s(v16neg, dup_s32(0x1f))
        v4  = bit_s(v4b, v5e, v21n)
        v6s = ushl_s32(v4, v19f)
        v4s = ushl_s32(v4, v16neg)
        v4  = orr_s(v4s, v6s)
        v4  = bit_s(v4, v5e, v20n)

    return v4, v0n, v1n


# ============================================================
# 尾部字节处理 (ROR/XOR 混合)
# ============================================================

def ror32(val, shift):
    s = shift & 0x1F
    if s == 0: return I32(val)
    return I32((val >> s) | (val << (32 - s)))

def decrypt_tail(input_int, position, w28, w16):
    v59 = I32(input_int)
    pos = position
    shift1 = (-(pos + 1)) & 0x1F
    v61 = ror32(v59, shift1)
    if ((pos + 1) & 0x1F) != 0:
        v59 = v61
    x13 = pos & 0x1F
    if x13 == 0:
        result = v59 ^ w28 ^ w16
    else:
        ror_w28 = ror32(w28, pos & 0x1F)
        ror_w16 = ror32(w16, (-pos) & 0x1F)
        result = ror_w28 ^ ror_w16 ^ v59
    x11 = x13 ^ 0x1F
    if x11 != 0:
        result = ror32(result, x11)
    return I32(result)


# ============================================================
# LABEL_4 尾部字节处理 (字节级 ROL/XOR, 处理 v3&3 个剩余字节)
# ============================================================

def label4_tail(input_bytes: bytes, output_len: int, w28: int, tail_const: int = 5):
    """处理最后 output_len & 3 个字节 (LABEL_4 尾部补丁)
       tail_const: 0x49 for sub_430000/sub_434D3C, 5 for sub_10F9D8, 0x60 for sub_111058"""
    v51 = output_len & 3
    if v51 == 0:
        return b''

    v52 = w28 & 0xFFFFFFFF
    base = output_len & ~3  # aligned byte count (= total_int32 * 4)
    result = bytearray(v51)

    for v53 in range(v51):
        # 读取源字节
        src_pos = base + v53
        if src_pos < len(input_bytes):
            byte = input_bytes[src_pos]
        else:
            byte = 0

        v56 = v53 + 1
        if (v56 & 7) != 0:
            # ROL byte by (v56 & 7)
            s = v56 & 7
            byte = ((byte << s) | (byte >> (8 - s))) & 0xFF

        v57 = (v53 & 7) ^ 7

        if (v53 & 7) != 0:
            # k5 = ROL(tail_const, v53 & 7)  (byte-level)
            s5 = v53 & 7
            k5 = ((tail_const << s5) | (tail_const >> (8 - s5))) & 0xFF
            # kw = ROR(w28 & 0xFF, v53 & 7)  (byte-level)
            kw = v52 & 0xFF
            kw = ((kw >> s5) | (kw << (8 - s5))) & 0xFF
            v54 = k5 ^ kw ^ byte
        else:
            v54 = byte ^ (v52 & 0xFF) ^ tail_const

        v54 &= 0xFF
        # ROR by v57
        if v57 != 0:
            v54 = ((v54 >> v57) | (v54 << (8 - v57))) & 0xFF

        result[v53] = v54

    return bytes(result)


# ============================================================
# 主接口: 复刻 sub_10F9D8
# ============================================================

def sub_10F9D8(input_bytes: bytes, total_int32: int,
               w28=0x6a5f0a6d, w16=0x1b092d05,
               step_q01=4, init_q6=1,
               output_len: int = None, tail_const: int = 5):
    """
    复刻 sub_10F9D8 解密/变换函数。

    参数:
        input_bytes:  输入数据 (密文)
        total_int32:  输入的 int32 个数 (对应 x26 = v3 >> 2)
        w28, w16:     密钥参数 (从 trace 提取, 可能因调用而异)
        step_q01:     状态步进 (x14)
        init_q6:      初始累加值 (x15)
        output_len:   最终输出字节数 (对应 v3/x19), 默认=total_int32*4
        tail_const:   尾部常量 (5=sub_10F9D8, 0x49=sub_430000, 0x60=sub_111058)

    返回:
        bytes: 变换后的输出
    """
    # 归一化输入
    input_ints = []
    for i in range(0, len(input_bytes), 4):
        chunk = input_bytes[i:i+4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        input_ints.append(struct.unpack('<I', chunk)[0])
    while len(input_ints) < total_int32:
        input_ints.append(0)

    # 全局状态初始化
    v0 = [2, 3]         # q0 (从 trace 常量加载)
    v1 = [0, 1]         # q1
    v2 = [0, 1, 2, 3]   # q2
    k3 = [w28] * 4      # q3
    k7 = [w16] * 4      # q7

    aligned = total_int32 & ~3
    output = []

    # NEON 块处理 (每轮 4 个 int32)
    for pos in range(0, aligned, 4):
        block = input_ints[pos:pos+4]
        out, v0, v1 = neon_process_block(v0, v1, v2, block, k3, k7, step_q01, init_q6)
        output.extend(out)
        v2 = add_s32(v2, [4, 4, 4, 4])

    # 尾部处理 (ROR/XOR)
    for pos in range(aligned, total_int32):
        in_val = input_ints[pos] if pos < len(input_ints) else 0
        output.append(decrypt_tail(in_val, pos, w28, w16))

    # NEON+tail 结果
    result = b''.join(struct.pack('<I', v) for v in output)

    # LABEL_4 尾部补丁 (v3 & 3 个字节)
    if output_len is None:
        output_len = total_int32 * 4
    tail_bytes = label4_tail(input_bytes, output_len, w28, tail_const)

    return result + tail_bytes


# ============================================================
# 测试 & 验证
# ============================================================
if __name__ == '__main__':
    path = "/apex/com.android.runtime/lib64/bionic/libc.so"
    path2="/apex/com.android.art/lib64/libart.so"
   

    result = sub_10F9D8(path.encode(), len(path) >> 2 , w28=1784858199, output_len=len(path) )
    short = bytes.fromhex('5b616e6f6e3a6d6d76385d')
    result2 = sub_10F9D8(short, len(short) >> 2 , w28=1784858199, output_len=len(short) )


    result3 = sub_10F9D8(b'com.sohu.inputmethod.sogou.xiaomi', len(b'com.sohu.inputmethod.sogou.xiaomi') >> 2 , w28=1784858199,w16=0x17cc6149, output_len=len(b'com.sohu.inputmethod.sogou.xiaomi'), tail_const=0x49 )
    print(result.hex())
    print(result2.hex())
    
    print(result3.hex())