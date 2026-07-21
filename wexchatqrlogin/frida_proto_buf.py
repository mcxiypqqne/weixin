"""
frida_proto_buf.py - 通过 Frida 调用 Android 端 w15.kg.toProtoBuf()，返回原始 bytes。

可作为模块导入:
    from wexchatqrlogin.frida_proto_buf import call_to_proto_buf
    data = call_to_proto_buf("com.tencent.mm")   # -> bytes

也可直接运行:
    python frida_proto_buf.py                    # USB 连接设备，自动找微信进程
    python frida_proto_buf.py <包名或PID>         # 指定目标进程
"""

import frida
import sys
import os
import threading
import frida_legacy_compat
frida_legacy_compat.auto_patch()

# ---------------------------------------------------------------------------
# 1. 读取 JS 脚本，把 console.log 桥接到 send()，让 Python 能收到日志
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
JS_PATH = os.path.join(SCRIPT_DIR, "frida_proto_buf.js")

with open(JS_PATH, "r", encoding="utf-8") as f:
    raw_js = f.read()

# 注入桥接代码：console.log 的同时也 send 给 Python（仅日志，不干扰数据通道）
PATCHED_JS = """
// ====== 自动注入：把 console.log 桥接到 send() ======
const _orig_console_log = console.log;
console.log = function (...args) {
    _orig_console_log.apply(this, args);
    send({ type: "console", payload: args.map(String).join(" ") });
};
// ====== 原始 frida_proto_buf.js 开始 ======
""" + raw_js


# ---------------------------------------------------------------------------
# 2. 核心函数 —— 供其他 Python 文件导入使用
# ---------------------------------------------------------------------------
def call_to_proto_buf(target="com.tencent.mm", timeout=90):
    """
    连接到设备上的目标进程，注入 Frida 脚本，
    调用 instance.toProtoBuf() 并返回原始字节。

    Args:
        target: 包名（如 "com.tencent.mm"）或 PID（整数/字符串）
        timeout: 等待结果的超时时间（秒），默认 90（配合 JS 侧重试）

    Returns:
        bytes: toProtoBuf() 返回的原始 protobuf 字节

    Raises:
        RuntimeError: 超时未收到结果，或 JS 侧调用出错
        frida.ProcessNotFoundError: 目标进程不存在
    """
    result_container = []   # [bytes]
    result_event = threading.Event()

    # ---- 消息回调 ----
    def on_message(message, data):
        if message.get("type") == "send":
            payload = message.get("payload", "")

            # console 日志 → 打印
            if isinstance(payload, dict) and payload.get("type") == "console":
                msg = payload.get("payload", "")
                print(f"[JS] {msg}")

            # toProtoBuf 结果 → 捕获 data 中的原始字节
            elif isinstance(payload, dict) and payload.get("type") == "proto_buf_result":
                length = payload.get("length", 0)
                print(f"[*] 收到 toProtoBuf 结果: {length} bytes")
                if data is not None:
                    result_container.append(bytes(data))
                else:
                    result_container.append(b"")
                result_event.set()

            # JS 侧调用出错
            elif isinstance(payload, dict) and payload.get("type") == "proto_buf_error":
                print(f"[!] JS 侧错误: {payload.get('message', 'unknown')}")
                result_container.append(None)
                result_event.set()

            else:
                print(f"[JS send] {payload}")

        elif message.get("type") == "error":
            print(f"[JS error] {message.get('description', message)}")
            if "stack" in message:
                print(f"[JS stack] {message['stack']}")

        else:
            print(f"[Message] {message}")

    # ---- 连接设备 ----
    print(f"[*] 目标: {target}")
    print(f"[*] 脚本: {JS_PATH}")

    try:
        device = frida.get_usb_device()
        print(f"[*] USB 设备: {device.name}")
    except Exception as e:
        print(f"[-] USB 未找到 ({e})，尝试本地设备")
        device = frida.get_local_device()

    # ---- 附加进程 ----
    try:
        pid = int(target)
        session = device.attach(pid)
        print(f"[*] 附加 PID={pid}")
    except ValueError:
        try:
            pid = device.spawn([target])
            session = device.attach(pid)
            device.resume(pid)
            print(f"[*] Spawn + attach: {target} (PID={pid})")
        except Exception:
            session = device.attach(target)
            print(f"[*] 直接附加: {target}")

    # ---- 注入脚本 ----
    script = session.create_script(PATCHED_JS)
    script.on("message", on_message)
    script.load()
    print("[*] 脚本已注入，等待 toProtoBuf 结果...\n")

    # ---- 等待结果 ----
    if not result_event.wait(timeout=timeout):
        session.detach()
        raise RuntimeError(f"等待 toProtoBuf 结果超时（{timeout}秒）")

    session.detach()
    print("[*] 已分离")

    result = result_container[0]
    if result is None:
        raise RuntimeError("JS 侧调用 toProtoBuf 出错，详见上方日志")
    return result


# ---------------------------------------------------------------------------
# 3. CLI 入口 —— 直接运行 python frida_proto_buf.py 时使用
# ---------------------------------------------------------------------------
def main():
    target = "com.tencent.mm"  # 默认微信包名

    if len(sys.argv) > 1:
        target = sys.argv[1]

    try:
        data = call_to_proto_buf(target)
        print(f"\n{'='*60}")
        print(f"  RESULT: {len(data)} bytes")
        print(f"  HEX: {data.hex()}...")
        print(f"{'='*60}\n")
        return data
    except RuntimeError as e:
        print(f"\n[-] 错误: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
