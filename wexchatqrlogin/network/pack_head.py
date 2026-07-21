"""
pack_head.py
============
拆解 dump.py 的 hex_data 为三段, 再加组装函数验证.
三段: CGI头(65B) + wire(50B) + body(244B)

格式:
  [0:4]   total_len    uint32 BE  = len(后面所有)
  [4:6]   path_len     uint16 BE  = len(cgi_path)
  [6:N]   cgi_path     bytes       = 如 /cgi-bin/micromsg-bin/mp-geta8key
  [N]     null1        uint8      = 0x00
  [N+1]   host_len     uint8      = len(host)
  [N+2:M] host         bytes      = 如 short.weixin.qq.com
  [M]     null2        uint8      = 0x00
  [M+1:M+5] inner_len  uint32 BE  = len(wire) + len(body)
  [M+5:]  wire+body    bytes      = sub_65658输出(50B) + AES加密body(244B)
"""
import struct


# ============================================================
# 组装函数
# ============================================================

def build_pack_head(cgi_path: str, host: str, wire: bytes, body: bytes) -> bytes:
    """
    用三段数据组装完整的 sendpack2 外层包.

    Parameters
    ----------
    cgi_path : str  如 "/cgi-bin/micromsg-bin/mp-geta8key"
    host     : str  如 "short.weixin.qq.com"
    wire     : bytes  sub_65658 输出 (~50B)
    body     : bytes  AES-GCM 加密后的 protobuf (~244B)

    Returns
    -------
    bytes  完整的 sendpack2 = CGI头 + wire + body
    """
    path_b = cgi_path.encode()
    host_b = host.encode()
    inner_data = wire + body

    # CGI头之后的 payload
    payload = (
        struct.pack('>H', len(path_b))   # path_len (2B BE)
        + path_b                          # path
        + b'\x00'                         # null
        + struct.pack('B', len(host_b))   # host_len (1B)
        + host_b                          # host
        + b'\x00'                         # null
        + struct.pack('>I', len(inner_data))  # inner_len (4B BE)
        + inner_data                      # wire + body
    )
    total_len = len(payload)
    return struct.pack('>I', total_len) + payload


def parse_pack_head(data: bytes) -> dict:
    """反向拆解, 返回各段."""
    total_len = struct.unpack('>I', data[0:4])[0]
    path_len  = struct.unpack('>H', data[4:6])[0]
    off = 6
    path = data[off:off+path_len]; off += path_len
    null1 = data[off]; off += 1
    host_len = data[off]; off += 1
    host = data[off:off+host_len]; off += host_len
    null2 = data[off]; off += 1
    inner_len = struct.unpack('>I', data[off:off+4])[0]; off += 4
    inner_data = data[off:off+inner_len]

    # wire 和 body 的分割: wire 以 LEB128 尾部 + BE16 结尾
    # 从 inner_data 末尾反推: body通常是244B (ct 216 + iv 12 + tag 16)
    # 这里用 inner_len 和已知 body 大小推断
    return {
        'total_len': total_len, 'path_len': path_len,
        'path': path.decode(), 'null1': null1,
        'host_len': host_len, 'host': host.decode(), 'null2': null2,
        'inner_len': inner_len, 'inner_data': inner_data,
        'cgi_header': data[:off],
    }


# ============================================================
# 验证: 拆解 + 组装 = 原数据
# ============================================================
def _verify():
    hex_data = (
        "0000016200212f6367692d62696e2f6d6963726f6d73672d62696e2f"
        "6d702d67657461386b6579001373686f72742e77656978696e2e71712e"
        "636f6d0000000126bfcadf280047508358d96c1f030802000000003b69"
        "2f88209700ee01f401f4010002db8485e506ff9bc2c5910400000051db"
        "3186884aefa57c19a8d93a49f0ed0bdac920962e3e2061447a1e1606ed"
        "df0be4ff77943296671ffee1cf305acf2a05c76f66b0c505b7d806c339"
        "6b1490d94866640806d966cb1c34685b335374f7a8b8b498f3f1321ef0"
        "4289ac32d837f4fc270a190b55a0d11fa2c848d446bc883aec3687fa9f"
        "502a386c2cd8290dc80742c409bbcdd4c341a3da14076d31413ab15f7d"
        "0320ca09a59bec37ea25d67fca6f52fdf52c53a78b55bd62a51f7b3690"
        "7b058d5f245a4dc8400de35417f9ba5b381a17eccf80edd91ba7521ffa"
        "191e8ff64b1785dfaaf715cdf0c16421eb44f581f9132068b89a7fa795"
        "8034053ff72eefbf75ae4729"
    )
    data = bytes.fromhex(hex_data)

    body_len = 244  # ct(216) + iv(12) + tag(16)
    wire_len = len(data) - 65 - body_len  # 65 = CGI header bytes
    cgi_header = data[:65]
    wire = data[65:65+wire_len]
    body = data[65+wire_len:]

    print("=== 拆解结果 ===")
    print(f"CGI header : {len(cgi_header)} bytes")
    print(f"  total_len  = {struct.unpack('>I', cgi_header[0:4])[0]} (0x{cgi_header[0:4].hex()})")
    print(f"  path_len   = {struct.unpack('>H', cgi_header[4:6])[0]}")
    print(f"  path       = {cgi_header[6:39].decode()}")
    print(f"  host_len   = {cgi_header[40]}")
    print(f"  host       = {cgi_header[41:60].decode()}")
    print(f"  inner_len  = {struct.unpack('>I', cgi_header[61:65])[0]} (0x{cgi_header[61:65].hex()})")
    print(f"wire       : {wire_len} bytes")
    print(f"  hex       : {wire.hex(' ').upper()}")
    print(f"body       : {len(body)} bytes (AES-GCM encrypted)")

    # 组装回去
    rebuilt = build_pack_head(
        cgi_path=cgi_header[6:39].decode(),
        host=cgi_header[41:60].decode(),
        wire=wire,
        body=body,
    )
    print(f"\n=== 组装验证 ===")
    print(f"rebuilt : {len(rebuilt)} bytes")
    print(f"original: {len(data)} bytes")
    print(f"MATCH: {rebuilt == data}")

    return cgi_header, wire, body


if __name__ == "__main__":
    cgi_header, wire, body = _verify()
