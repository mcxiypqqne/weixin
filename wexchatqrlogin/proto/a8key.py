"""
微信授权请求 (a8key) protobuf 序列化工具

用法:
    # 命令行: 时间戳自动用当前时间
    python a8key.py <uuid>
    python a8key.py 031XHpXy2ZSm100i

    # 命令行: 手动指定时间戳
    python a8key.py 031XHpXy2ZSm100i 552376204

    # 作为模块导入 (时间戳自动生成)
    from a8key import build
    data = build(uuid="031XHpXy2ZSm100i")
    print(data.hex())
"""

import sys
from datetime import datetime, timedelta, timezone


# ═══════════════════════════════════════════════════════════════
#  epoch 配置
#  三个样本, 毫秒级线性递增, 确认是时间戳:
#     data1 = 546,617,990
#     data2 = 552,376,204  (+96 min)
#     data3 = 559,112,618  (+112 min from data2)
#  反推 epoch ≈ 2026-06-25 08:00 UTC
#  对不上就调这个
# ═══════════════════════════════════════════════════════════════

EPOCH = datetime(2026, 6, 25, 8, 0, 0, tzinfo=timezone.utc)

# ═══════════════════════════════════════════════════════════════
#  默认参数
# ═══════════════════════════════════════════════════════════════

UUID_DEFAULT = "031XHpXy2ZSm100i"

DEVICE_FIELD2_HEX = "ecb2e39af8ffffffff01"
DEVICE_ID         = b"A2052943da3b41f\x00"
DEVICE_NUM_ID     = 671106896
PLATFORM          = "android-33"


# ═══════════════════════════════════════════════════════════════
#  时间戳: Python 动态生成, 不再写死
# ═══════════════════════════════════════════════════════════════

def now_timestamp(epoch: datetime = None) -> int:
    """当前时间 → field_20 值 (毫秒 since epoch)"""
    if epoch is None:
        epoch = EPOCH
    now = datetime.now(timezone.utc)
    return int((now - epoch).total_seconds() * 1000)


def datetime_to_timestamp(dt: datetime, epoch: datetime = None) -> int:
    """指定 datetime → field_20 值 (naive datetime 视为 UTC)"""
    if epoch is None:
        epoch = EPOCH
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 1000)


def timestamp_to_datetime(ts: int, epoch: datetime = None) -> datetime:
    """field_20 值 → datetime (调试用)"""
    if epoch is None:
        epoch = EPOCH
    return epoch + timedelta(milliseconds=ts)


# ═══════════════════════════════════════════════════════════════
#  序列化核心
# ═══════════════════════════════════════════════════════════════

def encode_varint(value: int) -> bytes:
    if value == 0:
        return b'\x00'
    result = bytearray()
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value & 0x7f)
    return bytes(result)


def tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def field_bytes(field_number: int, data: bytes) -> bytes:
    return tag(field_number, 2) + encode_varint(len(data)) + data


def field_string(field_number: int, s: str) -> bytes:
    return field_bytes(field_number, s.encode('utf-8'))


def field_varint(field_number: int, value: int) -> bytes:
    return tag(field_number, 0) + encode_varint(value)


# ═══════════════════════════════════════════════════════════════
#  构建
# ═══════════════════════════════════════════════════════════════

def build(uuid: str = None,
          timestamp: int = None,
          device_id: bytes = None,
          device_num_id: int = None,
          platform: str = None) -> bytes:
    """
    构建完整 protobuf.

    参数 (全部可选):
        uuid:          16 字符, URL 中的会话标识
        timestamp:     field_20 varint 值, 不传 → now_timestamp()
        device_id:     16 字节设备标识
        device_num_id: 设备数值 ID
        platform:      平台版本

    返回:
        bytes: 序列化数据 (215 bytes)
    """
    _uuid      = uuid if uuid is not None else UUID_DEFAULT
    _timestamp = timestamp if timestamp is not None else now_timestamp()
    _dev_id    = device_id if device_id is not None else DEVICE_ID
    _dev_num   = device_num_id if device_num_id is not None else DEVICE_NUM_ID
    _platform  = platform if platform is not None else PLATFORM

    # ── device_info (field 1, 52 bytes) ──
    device_field2_raw = bytes.fromhex(DEVICE_FIELD2_HEX)

    device_info = b""
    device_info += field_bytes(1, b"\x00")
    device_info += tag(2, 0) + device_field2_raw
    device_info += field_bytes(3, _dev_id)
    device_info += field_varint(4, _dev_num)
    device_info += field_string(5, _platform)
    device_info += field_varint(6, 0)

    # ── URL (field 7, 嵌套 field 1 string) ──
    url = f"https://open.weixin.qq.com/connect/confirm?uuid={_uuid}"
    assert len(url) == 64, f"URL 必须 64 字节, 当前 {len(url)}. UUID 需要恰好 16 字符."
    url_nested = field_string(1, url)

    # ── 通用嵌套消息 ──
    f3  = field_varint(1, 0) + field_bytes(2, b"")
    f13 = field_varint(1, 0) + field_bytes(2, b"")
    f23 = field_varint(1, 0) + field_bytes(2, b"")
    f35 = bytes.fromhex("08 10 12 10 08 00 10 00 28 00 30 00 3a 00 40 00 4a 00 58 00")

    # ── 外层消息 ──
    result = b""
    result += field_bytes(1, device_info)
    result += field_varint(2, 2)
    result += field_bytes(3, f3)
    result += field_bytes(4, b"")
    result += field_bytes(7, url_nested)
    result += field_varint(9, 0)
    result += field_varint(10, 4)
    result += field_bytes(11, b"")
    result += field_bytes(13, f13)
    result += field_varint(14, 0)
    result += field_varint(15, 0)
    result += field_varint(16, 0)
    result += field_varint(18, 19)
    result += field_varint(19, 6)
    result += field_varint(20, _timestamp)    # ★ 时间戳
    result += field_varint(22, 0)
    result += field_bytes(23, f23)
    result += field_varint(25, 1)
    result += field_bytes(28, b"")
    result += field_bytes(29, b"")
    result += field_bytes(30, b"")
    result += field_varint(33, 0)
    result += field_varint(34, 0)
    result += field_bytes(35, f35)

    return result


# ═══════════════════════════════════════════════════════════════
#  命令行
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    uuid = sys.argv[1] if len(sys.argv) > 1 else UUID_DEFAULT
    ts   = int(sys.argv[2]) if len(sys.argv) > 2 else now_timestamp()

    data = build(uuid=uuid, timestamp=ts)
    print(' '.join(f'{b:02x}' for b in data))
