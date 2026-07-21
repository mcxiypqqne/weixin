"""Python implementation of WeChat AutoAuth toProtoBuf — reconstructed from smali.

Source: D:\weixin\base.apk.1.out\smali_classes12\w15\kg.smali (method toProtoBuf)

This module provides both:
  1. A faithful line-by-line translation (AutoAuthBuilder.build_toProtoBuf)
  2. Helper stubs / hooks for all the Android-internal calls so you can
     swap in real implementations (device ID, storage reads, crypto, etc.)
"""

import os
import sys
from typing import Optional

# Ensure the proto package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proto.codec import encode_msg
from proto.autoauth_schemas import (
    AutoAuthRequest,
    AuthRequest,
    AuthSect,
    AuthStatus,
    BaseRequest,
    CCData,
    ECDHInfo,
    ECKey,
    SignKey,
    SKBuiltinBuffer,
)

# ═══════════════════════════════════════════════════════════════════════
#  Stub interface — replace these with real implementations
# ═══════════════════════════════════════════════════════════════════════

class DeviceContext:
    """Stub that mirrors the Android calls in kg.toProtoBuf().

    Override each method with your actual data source (emulator hook,
    Frida output, static extraction, etc.).
    """

    def get_scene_status(self) -> int:
        """Lw15/xg;->getSceneStatus()I — line 74

        If this returns 12 (0xc), the 'scene' branch is taken directly.
        Otherwise the value from config storage (key 0x2e) is used.
        """
        return 0  # default: not scene=12

    def get_uin(self) -> int:
        """Lw15/xg;->getUin()I — line 137"""
        return 0

    def get_client_version(self) -> int:
        """Lw15/xg;->getClientVersion()I (via zg.a)"""
        return 0

    def get_device_id(self) -> str:
        """Lw15/xg;->getDeviceID() (via zg.a)"""
        return ""

    def get_device_type(self) -> str:
        """Lw15/xg;->getDeviceType() (via zg.a)"""
        return ""

    def get_imei(self) -> str:
        """Lko/w0;->g(Z)Ljava/lang/String; — line 155 (IMEI / device id)"""
        return ""

    def get_soft_type(self, scene: int) -> str:
        """Lql3/s;->z3(I)Ljava/lang/String; — line 163 (e.g. android-*)"""
        return ""

    def get_client_seq_id(self) -> str:
        """Ltk0/m;->e()Ljava/lang/String; — line 171"""
        return ""

    def get_signature(self) -> str:
        """Lcom/tencent/mm/sdk/platformtools/t8;->j0(Context) — line 179"""
        return ""

    def get_device_name(self) -> str:
        """Lw15/uf;->d:Ljava/lang/String; — line 185 (static field)"""
        return ""

    def get_device_type_str(self) -> str:
        """Lcom/tencent/mm/storage/la;->E0() — line 189"""
        return ""

    def get_language(self) -> str:
        """Lcom/tencent/mm/sdk/platformtools/m2;->d() — line 195"""
        return ""

    def get_timezone(self) -> str:
        """Lcom/tencent/mm/sdk/platformtools/t8;->k0() — line 205"""
        return ""

    def get_channel_id(self) -> int:
        """Lcom/tencent/mm/sdk/platformtools/a0;->b:I — line 217 (static field)"""
        return 0

    def get_package_name(self) -> str:
        """Lcom/tencent/mm/sdk/platformtools/x2;->b:Ljava/lang/String; — line 221"""
        return "com.tencent.mm"

    # ── config storage ──────────────────────────────────────────────

    def config_get_int(self, key: int, default: int = 0) -> int:
        """Storage key 0x2e (46) → scene override; key 0x12 (18) → extra data.

        Mirrors: Lcom/tencent/mm/storage/j3;->c(II)I  (line 101)
                 Lcom/tencent/mm/storage/j3;->a(I)Object → String (line 237)
        """
        return default

    def config_get_string(self, key: int) -> Optional[str]:
        """Storage key 0x12 (18) → extra device data (auth key)."""
        return None

    # ── RSA info ────────────────────────────────────────────────────

    def get_rsa_info(self):
        """Lw15/ki;->d()Lw15/ki; — line 106

        Returns an object compatible with xg.setRsaInfo().
        """
        return None

    # ── crypto ──────────────────────────────────────────────────────

    def get_client_hmac_key(self) -> bytes:
        """Lql3/s;->h()[B — line 260 (client check key)"""
        return b""

    def get_session_key_bytes(self) -> bytes:
        """Lql3/s;->u9()[B — line 280"""
        return b""

    def get_existing_ec_private_key(self) -> Optional[bytes]:
        """Lw15/sg;->a:[B — line 418 (parent field, EC private key)

        If not None/empty, ECDH is enabled.
        """
        return None

    def generate_ec_key(self, key_type: int) -> tuple:
        """Lcom/tencent/mm/protocal/MMProtocalJni;->generateECKey(I...) — line 462

        Args:
            key_type: 0x2c9 (713) = prime256v1

        Returns:
            (public_key: bytes, private_key: bytes)
        """
        # Default: use Python cryptography or ecdsa library
        raise NotImplementedError("provide EC key generation")

    # ── network / sign key ──────────────────────────────────────────

    def get_public_key_string(self) -> Optional[str]:
        """Lcom/tencent/mm/network/j;->e.a() — line 322"""
        return None

    def get_network_sign_type(self) -> int:
        """Lcom/tencent/mm/network/j;->e.a.d:I — line 337"""
        return 0

    def get_cgi_verify_key_b(self) -> Optional[str]:
        """For CGI verify key field b — line 406"""
        return None

    def get_cgi_verify_key_a(self) -> Optional[str]:
        """For CGI verify key field a — line 410"""
        return None

    # ── global flags ────────────────────────────────────────────────

    @property
    def is_secure_mode(self) -> bool:
        """Lw15/yf;->a:Z — lines 32, 50 (secure vs normal autoauth)"""
        return False

    @property
    def check_special_flag(self) -> bool:
        """d41/o1;->q:I == 0x2712 && d41/o1;->r:I > 0 — lines 112-126"""
        return False


# ═══════════════════════════════════════════════════════════════════════
#  AutoAuth builder — line-by-line translation of kg.smali toProtoBuf()
# ═══════════════════════════════════════════════════════════════════════

class AutoAuthBuilder:
    """Faithful Python port of Lw15/kg;->toProtoBuf()[B.

    Usage:
        ctx = MyDeviceContext()            # your data source
        builder = AutoAuthBuilder(ctx)
        proto_bytes = builder.build()      # → the serialized AutoAuthRequest
    """

    # ── Constants from smali ─────────────────────────────────────────
    SCENE_DIRECT = 12         # 0xc: use scene status directly
    EC_KEY_TYPE  = 0x2c9      # 713 = prime256v1 / secp256r1

    def __init__(self, ctx: DeviceContext):
        self.ctx = ctx
        self._ec_private_key: Optional[bytes] = None  # mirrors sg.a

    # ── public entry point ──────────────────────────────────────────

    def build(self) -> Optional[bytes]:
        """Run the full toProtoBuf flow. Returns serialized protobuf or None."""
        return self._toProtoBuf()

    # ── internal: step-by-step matching smali ───────────────────────

    def _toProtoBuf(self) -> Optional[bytes]:
        # ── lines 70-72: reset global string (side effect) ──────────
        # sput-object v0, Ltk0/m;->x:Ljava/lang/String;   ; v0 = ""

        # ── lines 74-104: determine scene value ─────────────────────
        scene_status = self.ctx.get_scene_status()

        if scene_status == self.SCENE_DIRECT:
            scene_val = 1  # v2 = 1 (true)
        else:
            scene_val = self.ctx.config_get_int(0x2e, 0)

        # ── lines 106-111: set RSA info ─────────────────────────────
        rsa_info = self.ctx.get_rsa_info()
        # self.setRsaInfo(rsa_info)   # xg.setRsaInfo(ki.d())

        # ── lines 112-126: special flag 0x2712 ──────────────────────
        if self.ctx.check_special_flag:
            # sget v3, d41/o1;->r:I → if > 0 → reset to 0
            # ki.f("", "", 0)  — clear RSA info
            pass

        # ── build the protobuf tree ─────────────────────────────────

        # hc = AutoAuthRequest (top-level container, field b of kg)
        hc = AutoAuthRequest()

        # fc = AuthRequest (hc.e)
        fc = AuthRequest()

        # ── line 130-135: build BaseRequest and attach ──────────────
        base_req = self._build_base_request()
        fc["base_request"] = base_req

        # ── line 137-153: log uin ───────────────────────────────────
        uin = self.ctx.get_uin()
        # Log.i("MicroMsg.AutoReq", "summerauth autoauth toProtoBuf uin[%d]", uin)

        # ── line 155-159: fc.f = IMEI ───────────────────────────────
        imei = self.ctx.get_imei()
        fc["imei"] = imei

        # ── line 161-167: fc.g = SoftType ───────────────────────────
        soft_type = self.ctx.get_soft_type(scene_val)
        fc["soft_type"] = soft_type

        # ── line 169: fc.h = 0 ──────────────────────────────────────
        fc["h"] = 0

        # ── line 171-175: fc.i = ClientSeqID ────────────────────────
        client_seq_id = self.ctx.get_client_seq_id()
        fc["client_seq_id"] = client_seq_id

        # ── line 177-183: fc.m = Signature ──────────────────────────
        signature = self.ctx.get_signature()
        fc["signature"] = signature

        # ── line 185-187: fc.n = DeviceName ─────────────────────────
        device_name = self.ctx.get_device_name()
        fc["device_name"] = device_name

        # ── line 189-193: fc.o = DeviceType ─────────────────────────
        device_type_str = self.ctx.get_device_type_str()
        fc["device_type_str"] = device_type_str

        # ── line 195-199: fc.p = Language ───────────────────────────
        language = self.ctx.get_language()
        fc["language"] = language

        # ── line 201-215: fc.q = TimeZone ───────────────────────────
        timezone = self.ctx.get_timezone()
        fc["timezone"] = timezone

        # ── line 217-219: fc.r = Channel ────────────────────────────
        channel = self.ctx.get_channel_id()
        fc["channel"] = channel

        # ── line 221-223: fc.v = PackageName ────────────────────────
        package_name = self.ctx.get_package_name()
        fc["package_name"] = package_name

        # ════════════════════════════════════════════════════════════
        #  lines 225-257: build AuthSect with extra device data
        # ════════════════════════════════════════════════════════════

        auth_sect = AuthSect()   # fc.d

        # Build auth status (sd.e → a37)
        auth_status = AuthStatus()
        extra_data_str = self.ctx.config_get_string(0x12)
        if extra_data_str:
            extra_bytes = extra_data_str.encode("utf-8")
            buf = SKBuiltinBuffer()
            buf["i_len"] = len(extra_bytes)
            buf["buffer"] = extra_bytes
            auth_status["g"] = buf
        auth_sect["e"] = auth_status

        fc["auth_sect"] = auth_sect

        # ════════════════════════════════════════════════════════════
        #  lines 259-313: build CC data (l27 → wq5 → fc.t)
        # ════════════════════════════════════════════════════════════

        try:
            cc = CCData()

            # l27.f (field 3) = client hmac key
            hmac_key = self.ctx.get_client_hmac_key()
            buf_f = SKBuiltinBuffer()
            buf_f["i_len"] = len(hmac_key)
            buf_f["buffer"] = hmac_key
            cc["f"] = buf_f

            # l27.m (field 7) = session key
            sess_key = self.ctx.get_session_key_bytes()
            buf_m = SKBuiltinBuffer()
            buf_m["i_len"] = len(sess_key)
            buf_m["buffer"] = sess_key
            cc["m"] = buf_m

            # Serialize CCData and wrap in wq5
            from proto.codec import encode_msg
            cc_bytes = encode_msg(cc)
            cc_wrapper = SKBuiltinBuffer()
            cc_wrapper["i_len"] = len(cc_bytes)
            cc_wrapper["buffer"] = cc_bytes
            fc["cc_data"] = cc_wrapper
        except Exception:
            # catchall — smali just logs and continues
            # Log.printErrStackTrace("MicroMsg.AutoReq", e, "cc throws exception.")
            pass

        # ════════════════════════════════════════════════════════════
        #  lines 314-397: build SignKey (fc.w → sb5)
        # ════════════════════════════════════════════════════════════

        sign_key = SignKey()
        pub_key_str = self.ctx.get_public_key_string()

        if pub_key_str:
            sign_type = self.ctx.get_network_sign_type()
            sign_key["key_type"] = sign_type

            key_bytes_buf = SKBuiltinBuffer()
            key_bytes = pub_key_str.encode("iso-8859-1")
            key_bytes_buf["i_len"] = len(key_bytes)
            key_bytes_buf["buffer"] = key_bytes
            sign_key["key_data"] = key_bytes_buf
            # Log.i("MicroMsg.AutoReq", "autoauth add public key , length " + len)
        else:
            sign_key["key_type"] = 0
            empty_buf = SKBuiltinBuffer()
            empty_buf["i_len"] = 0
            empty_buf["buffer"] = b""
            sign_key["key_data"] = empty_buf
            # Log.e("MicroMsg.AutoReq", "get sign key failed")

        fc["sign_key"] = sign_key

        # ════════════════════════════════════════════════════════════
        #  lines 398-414: set CGI verify key
        # ════════════════════════════════════════════════════════════
        # self.setCGiVerifyKey(i_obj)  — handled by transport layer

        # ════════════════════════════════════════════════════════════
        #  lines 416-488: ECDH key exchange
        # ════════════════════════════════════════════════════════════

        existing_priv = self.ctx.get_existing_ec_private_key()
        if existing_priv:
            ecdh_info = ECDHInfo()

            # First af0: wrapping existing private key bytes (sg.a)
            # (from smali lines 426-444)
            ec_wrapper = ECKey()
            ec_wrapper["key_type"] = self.EC_KEY_TYPE

            priv_buf = SKBuiltinBuffer()
            priv_buf["i_len"] = len(existing_priv)
            priv_buf["buffer"] = existing_priv
            ec_wrapper["key_data"] = priv_buf
            ecdh_info["e"] = ec_wrapper

            # Generate new EC key pair (lines 446-486)
            try:
                pub_key, new_priv = self.ctx.generate_ec_key(self.EC_KEY_TYPE)
                self._ec_private_key = new_priv  # saved to sg.a

                new_ec = ECKey()
                new_ec["key_type"] = self.EC_KEY_TYPE

                pub_buf = SKBuiltinBuffer()
                pub_buf["i_len"] = len(pub_key)
                pub_buf["buffer"] = pub_key
                new_ec["key_data"] = pub_buf

                ecdh_info["e"] = new_ec   # replaces the previous one
            except NotImplementedError:
                pass  # EC gen not available; keep the initial one

            hc["ecdh_info"] = ecdh_info

        # ════════════════════════════════════════════════════════════
        #  lines 489-537: logging (omitted)
        # ════════════════════════════════════════════════════════════

        # ════════════════════════════════════════════════════════════
        #  Attach fc to hc
        # ════════════════════════════════════════════════════════════
        hc["auth_request"] = fc

        # ════════════════════════════════════════════════════════════
        #  lines 539-567: serialize and return
        # ════════════════════════════════════════════════════════════
        try:
            return encode_msg(hc)
        except Exception:
            return None

    # ── helper: build BaseRequest (mirrors Lw15/zg;->a) ────────────

    def _build_base_request(self) -> BaseRequest:
        """Reconstruct Lw15/zg;->a(Lw15/xg;)Lz15/ae;"""
        br = BaseRequest()

        # Session key — from zg.a: uses " " (null char)
        br["session_key"] = b"\x00"

        # Uin
        br["uin"] = self.ctx.get_uin()

        # Device ID (truncated to 16 bytes)
        dev_id = self.ctx.get_device_id()
        dev_id_bytes = dev_id.encode("utf-8") if dev_id else b""
        br["device_id"] = dev_id_bytes[:16]

        # Client version
        br["client_version"] = self.ctx.get_client_version()

        # Device type (truncated to 132 bytes)
        dev_type = self.ctx.get_device_type()
        dev_type_bytes = dev_type.encode("utf-8") if dev_type else b""
        br["device_type"] = dev_type_bytes[:132]

        # Scene status
        br["scene"] = self.ctx.get_scene_status()

        return br

    # ── accessors ───────────────────────────────────────────────────

    @property
    def ec_private_key(self) -> Optional[bytes]:
        """The generated EC private key (mirrors sg.a after toProtoBuf)."""
        return self._ec_private_key


# ═══════════════════════════════════════════════════════════════════════
#  Demo / test
# ═══════════════════════════════════════════════════════════════════════

def demo():
    """Quick smoke test with fake data."""
    from proto.codec import dump_msg
    from proto.autoauth_schemas import AutoAuthRequest

    class DemoContext(DeviceContext):
        def get_uin(self): return 123456789
        def get_imei(self): return "860123456789012"
        def get_soft_type(self, scene): return "android-9.0"
        def get_client_seq_id(self): return "seq-001"
        def get_signature(self): return "a1b2c3d4e5f6..."
        def get_device_name(self): return "Xiaomi 14"
        def get_device_type_str(self): return "Xiaomi 14 Pro"
        def get_language(self): return "zh_CN"
        def get_timezone(self): return "GMT+08:00"
        def get_channel_id(self): return 1
        def get_package_name(self): return "com.tencent.mm"
        def get_client_hmac_key(self): return b"\x01\x02\x03\x04"
        def get_session_key_bytes(self): return b"\xaa\xbb\xcc\xdd"
        def get_public_key_string(self): return "test-pubkey-12345"
        def get_existing_ec_private_key(self): return b"\x11\x22\x33\x44"

    ctx = DemoContext()
    builder = AutoAuthBuilder(ctx)
    result = builder.build()

    if result:
        print(f"Serialized {len(result)} bytes")
        print(f"Hex: {result.hex()[:200]}...")

        # Decode back to verify
        from proto.codec import decode_msg
        decoded = decode_msg(result, AutoAuthRequest)
        print("\n--- Decoded structure ---")
        print(dump_msg(decoded))
    else:
        print("build() returned None")


if __name__ == "__main__":
    demo()
