"""CampusNet —— 校园网自动认证（纯 HTTP 请求，无需浏览器）。

分层：
    L0 wlan      无线关联（netsh）
    L1 portal    探测认证门户，自动识别网关与认证服务器
    L2 cas       统一身份认证登录
    L3 eportal   门户网关认证
    L4 verify    真实外网连通性判定
    L5 runner    编排、重试、失败回滚
"""
from __future__ import annotations

import pathlib
import sys

__version__ = "0.2.2"
APP_NAME = "CampusNet"


def app_root() -> pathlib.Path:
    """程序根目录。

    * 打包成 exe 后：exe 所在目录（配置与日志都放在旁边，便于用户查看）
    * 直接跑源码时：项目根目录
    """
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return pathlib.Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))
