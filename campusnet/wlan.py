"""L0：无线关联（netsh）。

中文/英文 Windows 的 netsh 输出字段名不同，这里用别名表统一解析。
"""
from __future__ import annotations

import re
import socket
import subprocess
import time

from . import log

_KEYS = {
    "name": ["名称", "name"],
    "state": ["状态", "state"],
    "ssid": ["ssid"],
    "bssid": ["bssid"],
    "signal": ["信号", "signal"],
    "profile": ["配置文件", "profile"],
    "auth": ["身份验证", "authentication"],
    "radio": ["无线电类型", "radio type"],
    "channel": ["信道", "channel"],
}

_CONNECTED = {"已连接", "connected", "已連接"}
_LINE = re.compile(r"^\s*(?P<key>[^:]+?)\s*:\s*(?P<val>.*?)\s*$")
_RE_SSID_HEAD = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$")

_OPEN_AUTH_NAMES = {"开放式", "open", "开放", "无"}


def _run(args: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = p.stdout.decode("utf-8", "replace")
        if not out.strip():
            out = p.stdout.decode("gbk", "replace")
        return p.returncode, out
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 1, ""


def _parse_block(text: str) -> dict[str, str]:
    raw: dict[str, str] = {}
    for line in text.splitlines():
        m = _LINE.match(line)
        if m:
            raw[m.group("key").strip().lower()] = m.group("val").strip()
    out: dict[str, str] = {}
    for norm, aliases in _KEYS.items():
        for a in aliases:
            if a in raw:
                out[norm] = raw[a]
                break
    return out


def show_interfaces() -> list[dict[str, str]]:
    code, out = _run(["netsh", "wlan", "show", "interfaces"])
    if code != 0 or not out.strip():
        return []
    result = []
    for block in re.split(r"\n\s*\n", out):
        parsed = _parse_block(block)
        if parsed.get("name") or parsed.get("ssid"):
            result.append(parsed)
    return result


def current_status() -> dict[str, str] | None:
    ifaces = show_interfaces()
    return ifaces[0] if ifaces else None


def current_ssid() -> str:
    return ((current_status() or {}).get("ssid") or "").strip()


def is_connected_to(ssid: str) -> bool:
    st = current_status()
    if not st:
        return False
    state = (st.get("state") or "").strip().lower()
    connected = state in _CONNECTED or "connected" in state
    return connected and (st.get("ssid") or "").strip() == ssid.strip()


def list_profiles() -> list[str]:
    code, out = _run(["netsh", "wlan", "show", "profiles"])
    if code != 0:
        return []
    names = []
    for line in out.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        key = m.group("key").strip().lower()
        val = m.group("val").strip()
        if val and ("profile" in key or "配置文件" in key):
            names.append(val)
    return names


def has_profile(ssid: str) -> bool:
    return ssid.strip() in [n.strip() for n in list_profiles()]


def scan_networks() -> list[dict[str, str]]:
    """当前可见的无线网络（用于向导里选择 SSID）。"""
    code, out = _run(["netsh", "wlan", "show", "networks"])
    if code != 0:
        return []
    nets: list[dict[str, str]] = []
    cur: dict[str, str] | None = None
    for line in out.splitlines():
        m = _RE_SSID_HEAD.match(line)
        if m:
            if cur is not None:
                nets.append(cur)
            cur = {"ssid": m.group(1).strip()}
            continue
        if cur is None:
            continue
        mm = _LINE.match(line)
        if not mm:
            continue
        key = mm.group("key").strip().lower()
        val = mm.group("val").strip()
        if "身份验证" in key or key == "authentication":
            cur["auth"] = val
        elif "网络类型" in key or key == "network type":
            cur["type"] = val
        elif "加密" in key or key == "encryption":
            cur["encryption"] = val
    if cur is not None:
        nets.append(cur)
    return nets


def network_auth(ssid: str) -> str:
    for n in scan_networks():
        if n.get("ssid") == ssid.strip():
            return n.get("auth", "")
    return ""


_OPEN_PROFILE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""


def add_open_profile(ssid: str) -> bool:
    """为开放式网络创建当前用户范围的配置文件（无需管理员）。"""
    import os
    import tempfile
    from xml.sax.saxutils import escape

    xml = _OPEN_PROFILE_XML.format(ssid=escape(ssid))
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="wlan_profile_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(xml)
        code, _ = _run(["netsh", "wlan", "add", "profile",
                        "filename=%s" % path, "user=current"])
        return code == 0
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def ensure_profile(ssid: str) -> bool:
    """确保目标 SSID 有可用配置；开放式网络（校园网常见）可自动创建。"""
    logger = log.get()
    if has_profile(ssid):
        return True

    auth = network_auth(ssid)
    if not auth:
        logger.warning("系统里没有「%s」的配置，且当前扫不到该网络，无法自动创建。"
                       "请到信号覆盖范围内重试，或先手动连接一次。", ssid)
        return False

    if auth.strip().lower() in _OPEN_AUTH_NAMES:
        logger.info("「%s」是开放式网络且无配置，正在自动创建…", ssid)
        if add_open_profile(ssid):
            time.sleep(1)
            if has_profile(ssid):
                logger.info("已创建无线配置：%s", ssid)
                return True
            logger.warning("添加命令返回成功但查不到配置，请手动确认。")
            return False
        logger.error("创建无线配置失败（可能需要以管理员身份运行一次）。")
        return False

    logger.warning("「%s」是加密网络（%s），无法自动生成配置，请先手动连接一次。", ssid, auth)
    return False


def connect(ssid: str, timeout: int = 20) -> bool:
    if not has_profile(ssid):
        log.get().warning("系统里没有 %s 的无线配置，请先手动连接一次", ssid)
        return False
    code, _ = _run(["netsh", "wlan", "connect", "name=%s" % ssid, "ssid=%s" % ssid],
                   timeout=timeout)
    if code != 0:
        code, _ = _run(["netsh", "wlan", "connect", "name=%s" % ssid], timeout=timeout)
    return code == 0


def wait_for_association(ssid: str, timeout: int = 45, interval: float = 2.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_connected_to(ssid):
            log.get().debug("已关联到 %s，等待地址与路由稳定…", ssid)
            time.sleep(4)
            return True
        time.sleep(interval)
    return False


def get_local_ip_for(host: str, port: int = 80) -> str | None:
    """探测通往目标主机所用的本机出口 IP（不做实际连接）。"""
    if not host:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(2)
        s.connect((host, port))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def ensure_connected(ssid: str, auto_connect: bool = True, timeout: int = 45) -> bool:
    if is_connected_to(ssid):
        log.get().info("无线已连接：%s", ssid)
        return True
    if not auto_connect:
        log.get().warning("未连接到 %s，且已禁用自动关联", ssid)
        return False
    if not ensure_profile(ssid):
        return False
    log.get().info("正在连接无线：%s", ssid)
    if not connect(ssid):
        return False
    return wait_for_association(ssid, timeout=timeout)
