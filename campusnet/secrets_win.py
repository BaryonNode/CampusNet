"""Windows DPAPI 凭据保护。

用 CryptProtectData / CryptUnprotectData 加密口令：密文只能由
**同一台机器上的同一个 Windows 用户**解开，拷走文件也没用。

非 Windows 或调用失败时返回 None，由上层决定是否退化为明文并给出警告。
"""
from __future__ import annotations

import base64
import ctypes
import os
import sys
from ctypes import wintypes

_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", ctypes.POINTER(ctypes.c_char))]
else:  # pragma: no cover - 仅为让类型检查通过
    _DATA_BLOB = None  # type: ignore

_CRYPTPROTECT_UI_FORBIDDEN = 0x01


def _blob(data: bytes):
    """构造 DATA_BLOB，并把底层缓冲区一并返回以防被 GC 回收。"""
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    return blob, buf


def _take(blob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob.pbData)


def protect(text: str) -> str | None:
    """加密字符串，返回 Base64 密文；失败返回 None。"""
    if not _IS_WINDOWS or not text:
        return None
    try:
        raw = text.encode("utf-8")
        blob_in, _keep = _blob(raw)
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
        if not ok:
            return None
        return base64.b64encode(_take(blob_out)).decode()
    except Exception:  # noqa: BLE001
        return None


def unprotect(token: str) -> str | None:
    """解密 protect() 产出的 Base64 密文；失败返回 None。"""
    if not _IS_WINDOWS or not token:
        return None
    try:
        raw = base64.b64decode(token)
        blob_in, _keep = _blob(raw)
        blob_out = _DATA_BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None,
            _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(blob_out))
        if not ok:
            return None
        return _take(blob_out).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None


def available() -> bool:
    return _IS_WINDOWS


if __name__ == "__main__":
    sample = "test-secret-123"
    enc = protect(sample)
    if enc:
        print("加密成功，密文长度 %d" % len(enc))
        print("解密结果正确:", unprotect(enc) == sample)
        print("用错误密文:", unprotect("bm90LWEtcmVhbC1ibG9i"))
    else:
        print("DPAPI 不可用（非 Windows 或调用失败）")
    sys.exit(0)
