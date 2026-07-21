"""
WeChat QR Login - 项目结构

wexchatqrlogin/
├── crypto/                    # 密码学模块
│   ├── __init__.py
│   └── ec_generator.py       # EC 密钥生成，支持多种曲线
│
├── network/                  # 网络协议模块
│   ├── __init__.py
│   ├── mmtls_client.py       # mmtls 客户端和分析工具
│   └── mmtls_protocol.py     # 完整的 mmtls 协议实现
│
└── qrlogin/                  # 二维码登录模块 (待实现)
    ├── __init__.py
    └── login_flow.py

mmtls 协议结构分析 (基于 dump2.txt):

1. Record Layer (5 bytes):
   [type: 1 byte = 0x16] [version: 2 bytes = 0xf104] [length: 2 bytes]

2. ClientHello Payload (366 bytes):
   [internal_length: 4 bytes = 0x0000016a] [key_length: 2 bytes = 0x0104] [key_data: 260 bytes] [extra_data: 99 bytes]

3. key_data 结构:
   [curve_id(?): 2 bytes] [params_data: 258 bytes]

4. extra_data 结构:
   [ec_public_key_length: 2 bytes] [ec_public_key: 65 bytes = 0x04 || X || Y]

EC 曲线常量:
- 0x02c0: SECP256R1 (P-256) - 微信 mmtls 默认使用
- 0x019f: NID_X9_62_prime256v1 (相同曲线，不同 ID)

使用示例:

# 1. 生成 EC 密钥对
from crypto import generate_p256_keypair
kp = generate_p256_keypair()
print(kp.raw_public)  # 65 bytes, 0x04 || X || Y

# 2. 发送 mmtls ClientHello
from network import MmtlsClient, parse_and_analyze
client = MmtlsClient()
client.connect()
client.send_client_hello([kp.raw_public])
response = client.recv_response()

# 3. 分析抓包数据
parse_and_analyze()
"""

__version__ = "0.1.0"
