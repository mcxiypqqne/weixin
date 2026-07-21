import os


def mmtls_random_bytes(n: int) -> bytes:
    """
    生成 n 个字节的密码学安全随机数

    :param n: 字节数
    :return:  n 字节随机 bytes
    """
    if n <= 0:
        raise ValueError(f"n 必须为正整数，当前 {n}")
    return os.urandom(n)
