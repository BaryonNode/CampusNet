"""日志：统一输出 + 敏感信息脱敏 + 可靠的落盘位置。

落盘策略（按顺序尝试，取第一个能写的）：
    1. 程序目录/logs        —— 便携模式，用户最容易找到
    2. %LOCALAPPDATA%/应用/logs —— 程序目录只读时的兜底
    3. %TEMP%/应用/logs
另外：如果程序是从压缩包里直接双击运行的（程序目录位于临时目录），
会优先选 %LOCALAPPDATA%，避免日志随临时目录被清掉。
"""
from __future__ import annotations

import logging
import os
import pathlib
import re
import sys
import tempfile

from . import APP_NAME, app_root

LOGGER_NAME = "campusnet"
LOG_FILE_PATH: pathlib.Path | None = None

_SECRETS: list[str] = []


def register_secret(value: str) -> None:
    """登记需要脱敏的字面量（如密码、账号）。"""
    if value and len(value) >= 3 and value not in _SECRETS:
        _SECRETS.append(value)


def mask(text: str) -> str:
    out = str(text)
    for s in _SECRETS:
        out = out.replace(s, "***")
    # 兜底：学号/工号样式的连续数字
    out = re.sub(r"\b\d{8,12}\b", "***", out)
    return out


class _MaskFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (mask(v) if isinstance(v, str) else v)
                               for k, v in record.args.items()}
            else:
                # 只脱敏字符串，保留 int/float，否则 "%d" 会因参数变 str 而报错
                record.args = tuple(mask(a) if isinstance(a, str) else a for a in record.args)
        return True


def _localappdata() -> pathlib.Path | None:
    la = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    return pathlib.Path(la) if la else None


def _in_temp(path: pathlib.Path) -> bool:
    tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if not tmp:
        return False
    try:
        path.resolve().relative_to(pathlib.Path(tmp).resolve())
        return True
    except (ValueError, OSError):
        return False


def log_dir_candidates() -> list[pathlib.Path]:
    root = app_root()
    out: list[pathlib.Path] = []
    la = _localappdata()
    if _in_temp(root) and la:                      # 从压缩包里直接运行
        out.append(la / APP_NAME / "logs")
    out.append(root / "logs")
    if la:
        out.append(la / APP_NAME / "logs")
    out.append(pathlib.Path(tempfile.gettempdir()) / APP_NAME / "logs")
    return out


def _open_file_handler(name: str) -> logging.FileHandler | None:
    global LOG_FILE_PATH
    for d in log_dir_candidates():
        try:
            d.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(d / name, encoding="utf-8")
            LOG_FILE_PATH = d / name
            return fh
        except OSError:
            continue
    return None


def setup(level: str = "INFO", log_file: str | None = "campusnet.log") -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    # pythonw.exe 下 sys.stdout 为 None，此时只写文件
    if sys.stdout is not None:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        sh.addFilter(_MaskFilter())
        logger.addHandler(sh)

    if log_file:
        fh = _open_file_handler(log_file)
        if fh is not None:
            fh.setFormatter(fmt)
            fh.addFilter(_MaskFilter())
            logger.addHandler(fh)

    return logger


def get() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
