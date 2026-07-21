"""
MMTLS HKDF - HMAC Key Derivation Function
模拟 libwechatnetwork.so sub_257810 函数

函数签名 (ARM64):
    int sub_257810(
        void* a1,           // X0: HMAC_CTX* (unused)
        void* a2,           // X1: EVP_MD* (unused, assumes SHA256)
        uint8_t* a3,        // X2: salt ptr (HMAC key)
        uint32_t a4,        // X3: salt_len
        uint8_t* a5,        // X4: key ptr (HMAC input data)
        uint32_t a6,        // X5: key_len
        uint8_t* a7,        // X6: output buf ptr
        uint32_t a8         // X7: output_len
    )

实现: HMAC(salt, previous_output || key || counter)
    - 第一次: HMAC(salt, "" || key || 0x01)
    - 第二次: HMAC(salt, T(1) || key || 0x02)
    - 以此类推...
"""

import hmac
import hashlib
from typing import Tuple, List, Optional
import re

def hex_dump(label: str, data: bytes, bytes_per_line: int = 16):
    """以 hex+ASCII 表格打印 data (类似 xxd / Wireshark 的视图)。"""
    print(f"  {label} ({len(data)} bytes):")
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"    {i:04X}: {hex_part:<48} {ascii_part}")

def hex_to_bytes(hex_str: str) -> bytes:
    """将十六进制字符串转换为字节"""
    hex_str = hex_str.replace(' ', '').replace('\n', '')
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """将字节转换为十六进制字符串"""
    return separator.join(f'{b:02X}' for b in data)


def hmac_kdf_expand(salt: bytes, key: bytes, output_len: int) -> bytes:
    """
    HMAC-based Key Derivation Function (HKDF-like)
    
    实现: HMAC(salt, previous_output || key || counter)
    
    这个算法是 MMTLS 协议中使用的 HMAC-KDF 函数。
    
    Args:
        salt: Salt value (used as HMAC key), 32 bytes typically
        key: Input keying material (appended after previous output)
        output_len: Desired output length in bytes
    
    Returns:
        Derived key material
    
    Example:
        For 56 bytes output:
        - T(1) = HMAC(salt, "" || key || 0x01)  # 32 bytes
        - T(2) = HMAC(salt, T(1) || key || 0x02) # 24 bytes
        - Result = T(1) || T(2)[:24]
    """
    result = b''
    previous = b''  # 初始为空
    counter = 1
    
    while len(result) < output_len:
        # HMAC(salt, previous || key || counter)
        hmac_input = previous + key + bytes([counter])
        hmac_output = hmac.new(salt, hmac_input, hashlib.sha256).digest()
        result += hmac_output
        previous = hmac_output
        counter += 1
    
    return result[:output_len]


def hmac_kdf_expand_simple(salt: bytes, key: bytes, output_len: int) -> bytes:
    """
    简化的 HMAC-KDF 实现: HMAC(salt, key || counter)
    
    注意：这个实现对 32 字节输出有效，但对 56 字节等需要多次迭代的情况
    会产生不同的第二次迭代结果。
    """
    result = b''
    counter = 1
    
    while len(result) < output_len:
        hmac_input = key + bytes([counter])
        result += hmac.new(salt, hmac_input, hashlib.sha256).digest()
        counter += 1
    
    return result[:output_len]


def parse_hmac_kdf_log_entry(lines: List[str], start_idx: int) -> Optional[dict]:
    """从 dump3.txt 日志中解析 HMAC-KDF 调用"""
    entry = {}
    
    start_marker = None
    end_marker = None
    for i in range(start_idx, min(start_idx + 20, len(lines))):
        if '[HMAC-KDF] ============== START ==============' in lines[i]:
            start_marker = i
        if '[HMAC-KDF] =============== END ===============' in lines[i]:
            end_marker = i
            break
    
    if start_marker is None:
        return None
    
    entry['start_line'] = start_marker
    
    for i in range(start_marker, end_marker + 1 if end_marker else start_marker + 15):
        line = lines[i]
        
        if '[HMAC-KDF] Salt hex:' in line:
            hex_str = line.split('Salt hex:')[1].strip()
            entry['salt'] = hex_to_bytes(hex_str)
        
        elif '[HMAC-KDF] Key hex:' in line:
            hex_str = line.split('Key hex:')[1].strip()
            entry['key'] = hex_to_bytes(hex_str)
        
        elif '[HMAC-KDF] Salt ptr=' in line and 'len=' in line:
            match = re.search(r'len=(\d+)', line)
            if match:
                entry['salt_len'] = int(match.group(1))
        
        elif '[HMAC-KDF] Key ptr=' in line and 'len=' in line:
            match = re.search(r'len=(\d+)', line)
            if match:
                entry['key_len'] = int(match.group(1))
        
        elif '[HMAC-KDF] Output buf ptr=' in line and 'requested_len=' in line:
            match = re.search(r'requested_len=(\d+)', line)
            if match:
                entry['output_len'] = int(match.group(1))
        
        elif '[HMAC-KDF] Derived key' in line and 'bytes):' in line:
            match = re.search(r'Derived key \(\d+ bytes\): (.+)', line)
            if match:
                hex_str = match.group(1).strip()
                entry['output'] = hex_to_bytes(hex_str)
    
    entry['end_line'] = end_marker if end_marker else start_marker + 15
    return entry


def parse_hmac_kdf_log(filepath: str) -> List[dict]:
    """解析整个 dump3.txt 文件中的所有 HMAC-KDF 调用"""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    entries = []
    i = 0
    while i < len(lines):
        if '[HMAC-KDF] ============== START ==============' in lines[i]:
            entry = parse_hmac_kdf_log_entry(lines, i)
            if entry:
                entries.append(entry)
                i = entry['end_line']
                continue
        i += 1
    
    return entries


def verify_hmac_kdf(salt: bytes, key: bytes, expected_output: bytes) -> Tuple[bool, bytes]:
    """
    验证 HMAC-KDF 计算
    
    Returns:
        (is_match, computed_output)
    """
    output_len = len(expected_output)
    computed = hmac_kdf_expand(salt, key, output_len)
    is_match = computed == expected_output
    return is_match, computed


def test_manual():
    """手动测试用例"""
    print("=" * 70)
    print("MMTLS HKDF 验证测试")
    print("=" * 70)
    
    all_passed = True
    
    # 测试用例 1: 56 bytes output (需要 2 次 HMAC 迭代)
    print("\n" + "-" * 70)
    print("[测试 1] 第一次调用 (56 bytes output)")
    print("-" * 70)
    salt = hex_to_bytes('50 8A 03 D6 EE 35 06 FA 1B AD ED 15 06 63 89 AF 12 7A C6 99 93 EE 95 53 49 56 1B 1F FA E4 18 8F')
    key = hex_to_bytes('68 61 6E 64 73 68 61 6B 65 20 6B 65 79 20 65 78 70 61 6E 73 69 6F 6E 66 7D 64 67 0E 84 5D 38 5E 7E 45 79 BB FC 83 DD D0 DE 96 A8 E0 FB 74 33 76 81 74 42 7D 37 A6 E9')
    expected = hex_to_bytes('EF D3 04 7F 6D 16 1A 57 D1 57 E1 4A 3C 8B DB 79 1F 93 DF 5E FA 29 3D CA A7 A2 13 32 41 C0 FA 10 03 99 71 8F 44 CC 1F 86 9F 45 94 6E 78 36 FD EC 28 E7 14 16 49 44 4D 8F')
    
    print(f"  Salt: {bytes_to_hex(salt)} ({len(salt)} bytes)")
    print(f"  Key:  {bytes_to_hex(key)} ({len(key)} bytes)")
    print(f"  Expected: {bytes_to_hex(expected)} ({len(expected)} bytes)")
    
    is_match, computed = verify_hmac_kdf(salt, key, expected)
    print(f"  Computed: {bytes_to_hex(computed)} ({len(computed)} bytes)")
    if is_match:
        print(f"  [PASS]")
        # 显示中间步骤
        print(f"\n  调试信息:")
        t1 = hmac.new(salt, b'' + key + bytes([1]), hashlib.sha256).digest()
        t2 = hmac.new(salt, t1 + key + bytes([2]), hashlib.sha256).digest()
        print(f"    T(1) = HMAC(salt, '' || key || 0x01): {bytes_to_hex(t1)}")
        print(f"    T(2) = HMAC(salt, T(1) || key || 0x02): {bytes_to_hex(t2)}")
        print(f"    Result = T(1) || T(2)[:24]: {bytes_to_hex(t1 + t2[:24])}")
    else:
        print(f"  [FAIL]")
        all_passed = False
    
    # 测试用例 2: 32 bytes output
    print("\n" + "-" * 70)
    print("[测试 2] 第二次调用 (32 bytes output)")
    print("-" * 70)
    salt2 = hex_to_bytes('50 8A 03 D6 EE 35 06 FA 1B AD ED 15 06 63 89 AF 12 7A C6 99 93 EE 95 53 49 56 1B 1F FA E4 18 8F')
    key2 = hex_to_bytes('50 53 4B 5F 41 43 43 45 53 53 BE 6E 71 2E 4F DC 03 D6 55 41 69 4F B9 DD 9E EB 38 70 AC 57 1D 6C 33 6F F1 BF E2 8B F4 D3 9B 61')
    expected2 = hex_to_bytes('6D 55 85 F9 8F 06 DF A4 27 14 0A 3F 62 06 60 10 27 2D 5D 01 FA 13 96 C1 95 94 1F 3B 6C 9E C7 58')
    
    print(f"  Salt: {bytes_to_hex(salt2)} ({len(salt2)} bytes)")
    print(f"  Key:  {bytes_to_hex(key2)} ({len(key2)} bytes)")
    print(f"  Expected: {bytes_to_hex(expected2)} ({len(expected2)} bytes)")
    
    is_match2, computed2 = verify_hmac_kdf(salt2, key2, expected2)
    print(f"  Computed: {bytes_to_hex(computed2)} ({len(computed2)} bytes)")
    if is_match2:
        print(f"  [PASS]")
    else:
        print(f"  [FAIL]")
        all_passed = False
    
    # 测试用例 3: 32 bytes output
    print("\n" + "-" * 70)
    print("[测试 3] 第三次调用 (32 bytes output)")
    print("-" * 70)
    salt3 = hex_to_bytes('50 8A 03 D6 EE 35 06 FA 1B AD ED 15 06 63 89 AF 12 7A C6 99 93 EE 95 53 49 56 1B 1F FA E4 18 8F')
    key3 = hex_to_bytes('50 53 4B 5F 52 45 46 52 45 53 48 BE 6E 71 2E 4F DC 03 D6 55 41 69 4F B9 DD 9E EB 38 70 AC 57 1D 6C 33 6F F1 BF E2 8B F4 D3 9B 61')
    expected3 = hex_to_bytes('58 47 70 68 43 5E 11 2D 11 CA 97 77 10 A4 C6 E7 5C B8 1B 37 98 53 37 C5 26 84 C0 89 1A 37 2A E3')
    
    print(f"  Salt: {bytes_to_hex(salt3)} ({len(salt3)} bytes)")
    print(f"  Key:  {bytes_to_hex(key3)} ({len(key3)} bytes)")
    print(f"  Expected: {bytes_to_hex(expected3)} ({len(expected3)} bytes)")
    
    is_match3, computed3 = verify_hmac_kdf(salt3, key3, expected3)
    print(f"  Computed: {bytes_to_hex(computed3)} ({len(computed3)} bytes)")
    if is_match3:
        print(f"  [PASS]")
    else:
        print(f"  [FAIL]")
        all_passed = False
    
    print("\n" + "=" * 70)
    if all_passed:
        print("所有测试通过!")
    else:
        print("存在失败的测试!")
    print("=" * 70)
    
    return all_passed


def test_from_dump3():
    """从 dump3.txt 解析并验证 HMAC-KDF 调用"""
    dump_path = r'd:\weixin\dump3.txt'
    
    print("\n" + "=" * 70)
    print("从 dump3.txt 解析验证")
    print("=" * 70)
    
    try:
        entries = parse_hmac_kdf_log(dump_path)
        print(f"\n找到 {len(entries)} 个 HMAC-KDF 调用\n")
        
        all_passed = True
        
        for i, entry in enumerate(entries):
            print(f"\n{'='*70}")
            print(f"HMAC-KDF 调用 #{i+1}")
            print(f"{'='*70}")
            
            if 'salt' not in entry or 'key' not in entry or 'output' not in entry:
                print(f"  [跳过] 解析不完整")
                continue
            
            salt = entry['salt']
            key = entry['key']
            expected = entry['output']
            output_len = len(expected)
            
            print(f"  Salt: {bytes_to_hex(salt)} ({len(salt)} bytes)")
            print(f"  Key:  {bytes_to_hex(key)} ({len(key)} bytes)")
            print(f"  Expected: {bytes_to_hex(expected)} ({output_len} bytes)")
            
            is_match, computed = verify_hmac_kdf(salt, key, expected)
            print(f"  Computed: {bytes_to_hex(computed)} ({len(computed)} bytes)")
            
            if is_match:
                print(f"  [PASS] 验证通过!")
            else:
                print(f"  [FAIL] 验证失败!")
                all_passed = False
        
        print(f"\n{'='*70}")
        if all_passed:
            print(f"所有 {len(entries)} 个 HMAC-KDF 调用验证通过!")
        else:
            print("存在验证失败的调用!")
        print(f"{'='*70}")
        
        return all_passed
            
    except Exception as e:
        print(f"解析 dump3.txt 失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    # 运行手动测试
    test_manual()
    
    # 从 dump3.txt 解析验证
    test_from_dump3()


    a1 ='''
88 63 7A E3 7B 73 FB 8B CB A5 C5 95 AE F6 9A 38 BC 96 BD D3 4C 40 2D 95 71 4A 28 3F 3E BE B3 0A
'''

    # 移除所有空白字符并转换为字节
    a1 = bytes.fromhex(a1.replace(" ", "").replace("\n", ""))
    a2='''
47 D1 DE EF 7C 7C B3 5C 94 12 57 26 10 FA 09 6B E0 05 1C A4 D7 D8 5A 18 87 5D 08 F1 AC BF 26 2C
'''

    # 移除所有空白字符并转换为字节
    a2 = bytes.fromhex(a2.replace(" ", "").replace("\n", ""))
    a2=b'security hdkf expand'+a2
    computed=hmac_kdf_expand(a1,a2,56)
    hex_dump("computed",computed)
    print(computed)