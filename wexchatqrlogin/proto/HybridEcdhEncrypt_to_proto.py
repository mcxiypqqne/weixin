# Proto module - 兼容层，使用生成的 pb2
from .HybridEcdhEncrypt_pb2 import OuterMessage, InnerMessage

def create_message():
    return OuterMessage()

def parse_message(data):
    msg = OuterMessage()
    msg.ParseFromString(data)
    return msg

def set_cmd_type(msg, cmd_type):
    msg.field1 = cmd_type

def set_client_pubkey(msg, pubkey):
    msg.field2.field2 = pubkey

def set_encrypted_payload(msg, payload):
    msg.field3 = payload

def encode_varint(value):
    """简单 varint 编码"""
    result = []
    while value > 0x7f:
        result.append((value & 0x7f) | 0x80)
        value >>= 7
    result.append(value & 0x7f)
    return bytes(result)

def decode_varint(data):
    """简单 varint 解码"""
    result = 0
    shift = 0
    for b in data:
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result

# 保留旧名称
HybridEcdhEncrypt = OuterMessage

__all__ = [
    "OuterMessage",
    "InnerMessage",
    "HybridEcdhEncrypt",
    "create_message",
    "parse_message",
    "set_cmd_type",
    "set_client_pubkey",
    "set_encrypted_payload",
    "encode_varint",
    "decode_varint",
]
