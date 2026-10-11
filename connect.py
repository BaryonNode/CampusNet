#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""CampusNet 入口。

日常使用（不需要敲命令）：
    * 双击 run.bat / CampusNet.exe
        - 还没配置  -> 弹出图形向导，填账号密码即可
        - 已配置    -> 静默认证，无窗口

命令行（可选，排障用）：
    --check            只看当前是否已联网
    --wlan-scan        列出可见无线网络与已保存配置
    --detect           只做「自动识别认证服务器与网关」
    --dry-run -v       演练全流程，不真正提交
    --selftest         离线自检（不联网、不需要账号）
    --task install     注册「联网即自动认证」计划任务
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

from campusnet import APP_NAME, __version__, config as config_mod, log, runner


def _setup_console() -> None:
    """打包成 exe 后，把控制台切到 UTF-8，避免中文输出乱码。

    （窗口版没有控制台，sys.stdout 为 None，此处自动跳过。）
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:  # noqa: BLE001
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="CampusNet", description="%s —— 校园网自动认证" % APP_NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--gui", action="store_true", help="打开图形向导")
    p.add_argument("--init", action="store_true", help="命令行配置向导")
    p.add_argument("--silent", action="store_true", help="静默认证（供计划任务调用）")
    p.add_argument("--check", action="store_true", help="只检查连通性")
    p.add_argument("--wlan-scan", action="store_true", help="列出可见无线网络")
    p.add_argument("--detect", action="store_true", help="只自动识别认证服务器与网关")
    p.add_argument("--services", action="store_true",
                   help="列出网关提供的服务/运营商（认证提示「服务不能为空」时用）")
    p.add_argument("--selftest", action="store_true", help="离线自检")
    p.add_argument("--gui-smoketest", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--dry-run", action="store_true", help="演练，不提交认证")
    p.add_argument("--force", action="store_true", help="即使当前能上网也强制走一遍")
    p.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    p.add_argument("--config", help="指定配置文件路径")
    p.add_argument("--task", choices=["install", "uninstall", "status", "run"],
                   help="管理开机自动认证任务")
    p.add_argument("--version", action="version", version="%s %s" % (APP_NAME, __version__))
    return p


def _cfg_path(args) -> pathlib.Path | None:
    return pathlib.Path(args.config) if args.config else None


def cmd_check(cfg) -> int:
    from campusnet import verify, wlan
    session = verify.plain_session(cfg)
    ok1, why1 = verify.check_http(cfg, session)
    ok2, why2 = verify.check_https(cfg, session)
    print("探针     : %s  (%s)" % ("通过" if ok1 else "未通过", why1))
    print("HTTPS    : %s  (%s)" % ("通过" if ok2 else "未通过", why2))
    print("结论     : %s" % ("已联网" if (ok1 and ok2) else "尚未联网"))
    st = wlan.current_status()
    if st:
        print("无线     : SSID=%s 状态=%s 信号=%s"
              % (st.get("ssid", "?"), st.get("state", "?"), st.get("signal", "?")))
    enabled, server = runner.proxy_status()
    print("系统代理 : %s" % (("开启（%s）" % server) if enabled else "关闭"))
    return 0 if (ok1 and ok2) else 1


def cmd_detect(cfg) -> int:
    det = runner.detect_and_save(cfg)
    print("认证服务器 : %s" % (det.cas_base or "(未识别)"))
    print("门户网关   : %s" % (det.eportal_base or "(未识别)"))
    if det.chain:
        print("跳转链     :")
        for u in det.chain[:6]:
            print("   %s" % u[:140])
    if det.note:
        print("说明       : %s" % det.note)
    return 0 if det.ok else 1


def cmd_services(cfg) -> int:
    services = runner.fetch_service_list(cfg)
    if not services:
        print("没能取到服务列表（该网关可能不支持，或当前网络未被拦截）。")
        print("若认证时提示「服务不能为空」，请在配置里手动填写服务名。")
        return 1
    print("网关提供的服务（%d 个）：" % len(services))
    for s in services:
        print("  %-28s id=%s" % (s.get("name", "?"), s.get("id", "")))
    print("\n把想要的那个名字填进配置的 service 字段（或向导里的「服务/运营商」）。")
    return 0


def cmd_task(action: str) -> int:
    from campusnet import taskschd
    if action == "install":
        ok, msg = taskschd.install()
    elif action == "uninstall":
        ok, msg = taskschd.uninstall()
    elif action == "run":
        ok, msg = taskschd.run_now()
    else:
        ok, msg = taskschd.status()
    print(msg)
    return 0 if ok else 1


def cmd_selftest() -> int:
    from campusnet import selftest
    return selftest.run_selftest()


def cmd_wlan_scan(cfg) -> int:
    runner.wlan_report(cfg)
    return 0


def main(argv: list[str] | None = None) -> int:
    _setup_console()
    args = build_parser().parse_args(argv)
    cfg_path = _cfg_path(args)

    if args.selftest:
        return cmd_selftest()
    if args.gui_smoketest:
        from campusnet import wizard
        return wizard.smoke_test()

    cfg = config_mod.load(cfg_path, dry_run=args.dry_run, force=args.force)
    if args.verbose:
        cfg.log_level = "DEBUG"

    # --silent 由计划任务调用：pythonw 下没有 stdout，日志只写文件
    log.setup(cfg.log_level, log_file="campusnet.log")
    log.register_secret(cfg.password)
    log.register_secret(cfg.username)

    if args.task:
        return cmd_task(args.task)
    if args.wlan_scan:
        return cmd_wlan_scan(cfg)
    if args.check:
        return cmd_check(cfg)
    if args.detect:
        return cmd_detect(cfg)
    if args.services:
        return cmd_services(cfg)
    if args.init:
        from campusnet import wizard
        return wizard.console_wizard(cfg_path)
    if args.gui:
        from campusnet import wizard
        return wizard.run_wizard(cfg_path)

    # ---- 无参数：没有配置就弹向导，否则静默认证 ----
    if not cfg.ready():
        if args.silent:
            log.get().warning("尚未完成配置，无法自动认证（请先运行一次图形向导）")
            return 2
        from campusnet import wizard
        return wizard.run_wizard(cfg_path)

    ok = runner.connect(cfg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
