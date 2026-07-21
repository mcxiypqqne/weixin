"""
从 dump8.txt 和 dump8_1.txt 中按文件顺序提取 (v90, 输出) 测试对。
"""
import re
import sys
import os

os.chdir(r'd:\weixin')


def parse_dump(path):
    with open(path, 'rb') as f:
        content = f.read()
    return content.decode('utf-8', errors='replace').replace('\x00', '')


def extract_ordered_sections(text):
    """
    按文件顺序提取 hex dump 区段。
    每个区段 = 连续的 hex dump 行 (地址相邻, 16字节步进)。
    """
    pattern = re.compile(r'([0-9a-fA-F]{8,16})\s\s((?:(?:[0-9a-fA-F]{2}\s){1,16}))')
    matches = list(re.finditer(pattern, text))

    sections = []
    i = 0
    while i < len(matches):
        start_addr = int(matches[i].group(1).strip(), 16)
        hex_data = bytearray()

        # 收集连续块
        j = i
        expected_addr = start_addr
        while j < len(matches):
            addr = int(matches[j].group(1).strip(), 16)
            if addr == expected_addr:
                hex_str = matches[j].group(2).strip().replace(' ', '')
                hex_data.extend(bytes.fromhex(hex_str))
                expected_addr += 16
                j += 1
            else:
                break

        sections.append({
            'start_addr': start_addr,
            'size': len(hex_data),
            'data': bytes(hex_data),
        })
        i = j

    return sections


def find_test_pairs(sections):
    """
    配对: v90 区段 (size>=64, start ends in 0x120)
         和紧随其后的输出区段 (data starts with 0xBF).
    配对规则: 输出区段在 v90 区段之后, 且中间最多间隔一个其他区段.
    """
    pairs = []
    i = 0
    while i < len(sections):
        s = sections[i]
        # v90 特征: size >= 64, 地址末12位 = 0x120
        is_v90 = (s['size'] >= 64 and (s['start_addr'] & 0xFFF) == 0x120)

        if is_v90 and len(s['data']) >= 65:
            a1 = s['data'][8:65]
            if len(a1) == 57:
                # 在后续 1-3 个区段中找输出
                for k in range(i+1, min(i+4, len(sections))):
                    out_s = sections[k]
                    if out_s['data'] and out_s['data'][0] == 0xBF:
                        pairs.append({
                            'v90_addr': s['start_addr'],
                            'out_addr': out_s['start_addr'],
                            'a1': a1,
                            'expected': out_s['data'],
                        })
                        break
        i += 1

    return pairs


def main():
    all_pairs = []
    for fname in ['dump8.txt', 'dump8_1.txt']:
        print(f"\n=== {fname} ===")
        text = parse_dump(fname)
        sections = extract_ordered_sections(text)
        print(f"  Total sections: {len(sections)}")
        for s in sections:
            print(f"    0x{s['start_addr']:x}: {s['size']}B first_bytes={s['data'][:8].hex()}")

        pairs = find_test_pairs(sections)
        print(f"  Pairs found: {len(pairs)}")
        all_pairs.extend(pairs)

        for i, p in enumerate(pairs):
            print(f"  [{i}] v90=0x{p['v90_addr']:x} -> out=0x{p['out_addr']:x}")

    # 去重
    seen = set()
    unique_pairs = []
    for p in all_pairs:
        key = p['a1'].hex()
        if key not in seen:
            seen.add(key)
            unique_pairs.append(p)

    print(f"\n=== Total unique pairs: {len(unique_pairs)} ===")

    # 生成测试用例
    print("\n# Python test cases:")
    for i, p in enumerate(unique_pairs):
        a1_spaced = ' '.join(p['a1'].hex()[j:j+32] for j in range(0, 114, 32))
        exp_spaced = ' '.join(p['expected'].hex()[j:j+32] for j in range(0, len(p['expected'].hex()), 32))
        print('    {')
        print('        "name": "auto_%d (v90=0x%x)",' % (i, p['v90_addr']))
        print('        "input_hex": "%s",' % a1_spaced.replace(' ', ''))
        print('        "expected_hex": "%s",' % exp_spaced.replace(' ', ''))
        print('    },')

    # 同时生成验证脚本
    print("\n# Quick verify:")
    for i, p in enumerate(unique_pairs):
        print('pair %d: v90=0x%x a1[2]=0x%02x funcType=%d sig=0x%08x seqKey=%d' % (
            i, p['v90_addr'],
            p['a1'][2],
            struct_unpack('<H', p['a1'][27:29]),
            struct_unpack('<I', p['a1'][42:46]),
            struct_unpack('<H', p['a1'][55:57]),
        ))

    return 0


def struct_unpack(fmt, data):
    import struct
    return struct.unpack(fmt, data)[0]


if __name__ == '__main__':
    sys.exit(main())
