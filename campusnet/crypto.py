"""密码学工具。

两件事：
1. **CSRF 头**：统一身份认证前端只做「自洽校验」——
   `Csrf-Value = MD5(夹心(btoa(Csrf-Key)))`，因此客户端可自行生成，无需服务端下发。
2. **口令加密**：AES-128-ECB + PKCS7，密钥是登录页里的 Base64 字符串（16 字节）。
   等价于 JS 的 `CryptoJS.AES.encrypt(data, CryptoJS.enc.Base64.parse(key),
                                    {mode: ECB, padding: Pkcs7}).toString()`
"""
from __future__ import annotations

import base64
import hashlib
import random
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# --------------------------------------------------------------------------
# CSRF
# --------------------------------------------------------------------------

def csrf_value_from_key(key: str) -> str:
    """由 Csrf-Key 推导 Csrf-Value（与服务端前端算法一致）。"""
    s = base64.b64encode(key.encode()).decode()
    half = len(s) // 2
    return hashlib.md5((s[:half] + s + s[half:]).encode()).hexdigest()


def gen_csrf(length: int = 32) -> tuple[str, str]:
    alphabet = string.ascii_letters + string.digits
    key = "".join(random.choice(alphabet) for _ in range(length))
    return key, csrf_value_from_key(key)


def gen_device_id() -> str:
    """32 位十六进制设备标识（服务端不强制，但部分接口会按设备维度查询）。"""
    return "".join(random.choice("0123456789abcdef") for _ in range(32))


# --------------------------------------------------------------------------
# AES
# --------------------------------------------------------------------------

def aes_encrypt_b64(key_b64: str, plaintext: str) -> str:
    key = base64.b64decode(key_b64)
    if len(key) not in (16, 24, 32):
        raise ValueError("密钥长度不合法（应为 16/24/32 字节）")
    cipher = AES.new(key, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode("utf-8"), 16))).decode()


def aes_decrypt_b64(key_b64: str, ciphertext_b64: str) -> str:
    key = base64.b64decode(key_b64)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)), 16).decode("utf-8")


def self_test() -> list[tuple[str, bool, str]]:
    """离线自检（全部使用合成数据，不含任何真实站点信息）。"""
    out: list[tuple[str, bool, str]] = []

    # CSRF：自生成后应能自洽
    k, v = gen_csrf()
    out.append(("CSRF 生成自洽", csrf_value_from_key(k) == v, k[:8] + "…"))

    # 已知算法特征：btoa 后的长度应为 44（32 字符 -> 44 字符 Base64）
    s = base64.b64encode(("a" * 32).encode()).decode()
    out.append(("Csrf-Value 为 32 位十六进制", len(csrf_value_from_key("a" * 32)) == 32, s[:12] + "…"))

    # AES 往返
    key = base64.b64encode(b"0123456789abcdef").decode()
    for pt in ("short", "a" * 15, "a" * 16, "中文密码测试", "a" * 200):
        ct = aes_encrypt_b64(key, pt)
        out.append(("AES 往返 %d 字节" % len(pt.encode()),
                    aes_decrypt_b64(key, ct) == pt, "%d 字符密文" % len(ct)))

    # 15 字节明文应恰好压成 1 个 AES 块（24 字符 Base64）
    ct15 = aes_encrypt_b64(key, "a" * 15)
    out.append(("15 字节明文 -> 1 个 AES 块（24 字符）",
                len(base64.b64decode(ct15)) == 16, ct15))

    # 非法密钥应被拒绝
    try:
        aes_encrypt_b64(base64.b64encode(b"tooshort").decode(), "x")
        out.append(("非法密钥被拒绝", False, "未抛异常"))
    except ValueError as exc:
        out.append(("非法密钥被拒绝", True, str(exc)))

    return out


if __name__ == "__main__":
    ok = 0
    rows = self_test()
    for name, passed, detail in rows:
        print(("  [OK]   " if passed else "  [FAIL] ") + name + "  -> " + str(detail))
        ok += 1 if passed else 0
    print("\n通过 %d/%d" % (ok, len(rows)))
