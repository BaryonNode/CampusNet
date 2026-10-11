# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

用法：
    pip install pyinstaller
    pyinstaller CampusNet.spec --noconfirm --clean

产出 dist/CampusNet/ 目录，包含：
    CampusNet.exe       双击即用（不弹控制台窗口）
    CampusNet-cli.exe   命令行排障用（带控制台输出）
    README.txt          给使用者的说明
"""

import shutil
from pathlib import Path

ROOT = Path(SPECPATH)

# 明确列出子模块：代码里有些是函数内延迟导入，静态分析可能漏掉
HIDDEN = [
    "campusnet",
    "campusnet.wizard",
    "campusnet.selftest",
    "campusnet.taskschd",
    "campusnet.runner",
    "campusnet.portal",
    "campusnet.cas",
    "campusnet.eportal",
    "campusnet.verify",
    "campusnet.wlan",
    "campusnet.crypto",
    "campusnet.config",
    "campusnet.log",
    "campusnet.secrets_win",
    "tkinter",
    "tkinter.ttk",
    "tkinter.scrolledtext",
    "tkinter.messagebox",
    "tkinter.font",
]

# 用不到的重型库，排除以缩小体积
EXCLUDES = [
    "numpy", "pandas", "matplotlib", "scipy", "PIL", "lxml", "bs4",
    "httpx", "cryptography", "pytest", "setuptools", "pip",
    "sqlite3", "unittest", "pydoc", "doctest",
]

a = Analysis(
    ["connect.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

_COMMON = dict(
    exclude_binaries=True,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    icon=str(ROOT / "icon.ico") if (ROOT / "icon.ico").exists() else None,
)

exe_gui = EXE(
    pyz, a.scripts, [],
    name="CampusNet",
    console=False,                 # 双击不弹黑框
    disable_windowed_traceback=False,
    **_COMMON,
)

exe_cli = EXE(
    pyz, a.scripts, [],
    name="CampusNet-cli",
    console=True,                  # 排障时能看到输出
    **_COMMON,
)

coll = COLLECT(
    exe_gui,
    exe_cli,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="CampusNet",
)


def _post_build():
    """把给使用者的说明一起放进发布目录。"""
    out = ROOT / "dist" / "CampusNet"
    if not out.exists():
        return
    readme = ROOT / "dist_readme.txt"
    if readme.exists():
        shutil.copy2(readme, out / "使用说明.txt")


_post_build()
