"""图形向导：双击即用，不需要敲任何命令。

设计原则：
  * 用户只需要填 **账号 + 密码**，其余（校园网、认证服务器、门户网关）都能自动得到
  * 没有配置时自动弹出；已有配置时程序静默工作，用户无感
"""
from __future__ import annotations

import logging
import pathlib
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from . import APP_NAME, __version__, config as config_mod, log, runner, taskschd, wlan


class _TextHandler(logging.Handler):
    """把日志转发到界面文本框。"""

    def __init__(self, widget):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        try:
            msg = self.format(record)
            self.widget.configure(state="normal")
            self.widget.insert("end", msg + "\n")
            self.widget.see("end")
            self.widget.configure(state="disabled")
        except Exception:  # noqa: BLE001
            pass


class Wizard(tk.Tk):
    def __init__(self, cfg_path: pathlib.Path | None = None):
        super().__init__()
        self.cfg_path = cfg_path
        self.cfg = config_mod.load(cfg_path)
        self._busy = False

        self.title("%s · 校园网自动认证 v%s" % (APP_NAME, __version__))
        self.geometry("620x520")
        self.minsize(560, 460)
        self._build()
        self._attach_log()
        self.after(200, self._refresh_networks)
        self.after(400, self._autodetect_if_needed)

    # ------------------------------------------------------------------
    def _build(self) -> None:
        pad = {"padx": 8, "pady": 4}
        root = ttk.Frame(self, padding=12)
        root.pack(fill="both", expand=True)
        root.columnconfigure(1, weight=1)
        row = 0

        ttk.Label(root, text="账号（学号/工号）").grid(row=row, column=0, sticky="w", **pad)
        self.var_user = tk.StringVar(value=self.cfg.username)
        ttk.Entry(root, textvariable=self.var_user, width=32).grid(
            row=row, column=1, columnspan=2, sticky="ew", **pad)
        row += 1

        ttk.Label(root, text="密码").grid(row=row, column=0, sticky="w", **pad)
        self.var_pwd = tk.StringVar(value=self.cfg.password)
        self.entry_pwd = ttk.Entry(root, textvariable=self.var_pwd, show="●", width=32)
        self.entry_pwd.grid(row=row, column=1, sticky="ew", **pad)
        self.var_show = tk.BooleanVar(value=False)
        ttk.Checkbutton(root, text="显示", variable=self.var_show,
                        command=self._toggle_pwd).grid(row=row, column=2, sticky="w", **pad)
        row += 1

        ttk.Label(root, text="校园网").grid(row=row, column=0, sticky="w", **pad)
        self.var_ssid = tk.StringVar(value=self.cfg.ssid)
        self.cmb_ssid = ttk.Combobox(root, textvariable=self.var_ssid, width=30)
        self.cmb_ssid.grid(row=row, column=1, sticky="ew", **pad)
        ttk.Button(root, text="刷新", width=6, command=self._refresh_networks).grid(
            row=row, column=2, sticky="w", **pad)
        row += 1

        ttk.Separator(root, orient="horizontal").grid(
            row=row, column=0, columnspan=3, sticky="ew", pady=8)
        row += 1

        ttk.Label(root, text="认证服务器").grid(row=row, column=0, sticky="w", **pad)
        self.var_cas = tk.StringVar(value=self.cfg.cas_base)
        ttk.Entry(root, textvariable=self.var_cas, width=32).grid(
            row=row, column=1, columnspan=2, sticky="ew", **pad)
        row += 1

        ttk.Label(root, text="门户网关").grid(row=row, column=0, sticky="w", **pad)
        self.var_ep = tk.StringVar(value=self.cfg.eportal_base)
        ttk.Entry(root, textvariable=self.var_ep, width=32).grid(
            row=row, column=1, columnspan=2, sticky="ew", **pad)
        row += 1

        ttk.Label(root, text="服务/运营商").grid(row=row, column=0, sticky="w", **pad)
        self.var_service = tk.StringVar(value=self.cfg.service)
        self.cmb_service = ttk.Combobox(root, textvariable=self.var_service, width=30,
                                        values=list(config_mod.COMMON_SERVICES))
        self.cmb_service.grid(row=row, column=1, sticky="ew", **pad)
        self.btn_services = ttk.Button(root, text="获取列表", width=8,
                                       command=self._do_services)
        self.btn_services.grid(row=row, column=2, sticky="w", **pad)
        ttk.Label(root, text="默认「移动互联网服务」；不对就在下拉框里改",
                  foreground="#888").grid(row=row + 1, column=1, columnspan=2,
                                          sticky="w", padx=8)
        row += 2

        btns = ttk.Frame(root)
        btns.grid(row=row, column=0, columnspan=3, sticky="ew", pady=10)
        self.btn_detect = ttk.Button(btns, text="自动探测并保存", command=self._do_detect)
        self.btn_detect.pack(side="left", padx=4)
        self.btn_save = ttk.Button(btns, text="保存", command=self._do_save)
        self.btn_save.pack(side="left", padx=4)
        self.btn_test = ttk.Button(btns, text="立即测试连接", command=self._do_test)
        self.btn_test.pack(side="left", padx=4)
        self.btn_task = ttk.Button(btns, text="开机自动认证", command=self._do_task)
        self.btn_task.pack(side="left", padx=4)
        row += 1

        self.lbl_log = ttk.Label(
            root, text="日志：%s" % (log.LOG_FILE_PATH or "（未启用文件日志）"),
            foreground="#666", anchor="w")
        self.lbl_log.grid(row=row, column=0, columnspan=2, sticky="w", padx=8)
        ttk.Button(root, text="打开日志", width=10, command=self._open_log).grid(
            row=row, column=2, sticky="e", **pad)
        row += 1

        self.txt = scrolledtext.ScrolledText(root, height=10, state="disabled",
                                             font=("Consolas", 9))
        self.txt.grid(row=row, column=0, columnspan=3, sticky="nsew", **pad)
        root.rowconfigure(row, weight=1)

    def _open_log(self) -> None:
        """打开日志所在目录（找不到就提示）。"""
        import os
        import subprocess

        target = log.LOG_FILE_PATH
        try:
            if target and target.exists():
                subprocess.Popen(["explorer", "/select,", str(target)])
            else:
                folder = target.parent if target else log.log_dir_candidates()[0]
                folder.mkdir(parents=True, exist_ok=True)
                os.startfile(str(folder))  # noqa: S606
        except Exception as exc:  # noqa: BLE001
            messagebox.showwarning(APP_NAME, "打开日志失败：%s\n日志位置：%s"
                                   % (exc, target))

    def _attach_log(self) -> None:
        """把日志同时显示到界面。

        注意：必须**保留** FileHandler（否则文件日志会失效），只去掉控制台输出。
        """
        handler = _TextHandler(self.txt)
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%H:%M:%S"))
        handler.addFilter(log._MaskFilter())
        logger = log.get()
        logger.handlers = [h for h in logger.handlers
                           if isinstance(h, logging.FileHandler)]
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    def _toggle_pwd(self) -> None:
        self.entry_pwd.configure(show="" if self.var_show.get() else "●")

    # ------------------------------------------------------------------
    def _collect(self) -> None:
        self.cfg.username = self.var_user.get().strip()
        pwd = self.var_pwd.get()
        if pwd != self.cfg.password:
            self.cfg.set_password(pwd)
        self.cfg.ssid = self.var_ssid.get().strip()
        self.cfg.cas_base = self.var_cas.get().strip()
        self.cfg.eportal_base = self.var_ep.get().strip()
        self.cfg.service = self.var_service.get().strip()

    def _busy_on(self, *buttons) -> None:
        self._busy = True
        for b in buttons:
            b.configure(state="disabled")

    def _busy_off(self, *buttons) -> None:
        self._busy = False
        for b in buttons:
            b.configure(state="normal")

    def _bg(self, fn, done, *buttons) -> None:
        if self._busy:
            return
        self._busy_on(*buttons)

        def worker():
            try:
                result = fn()
            except Exception as exc:  # noqa: BLE001
                result = exc
            self.after(0, lambda: (self._busy_off(*buttons), done(result)))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    def _refresh_networks(self) -> None:
        nets = wlan.scan_networks()
        names = [n.get("ssid", "") for n in nets if n.get("ssid")]
        cur = wlan.current_ssid()
        if cur and cur not in names:
            names.insert(0, cur)
        self.cmb_ssid.configure(values=names)
        if not self.var_ssid.get() and cur:
            self.var_ssid.set(cur)
        log.get().info("可见无线网络 %d 个%s", len(names), ("，当前：" + cur) if cur else "")

    def _autodetect_if_needed(self) -> None:
        if not (self.var_cas.get() and self.var_ep.get()):
            self._do_detect()

    # ------------------------------------------------------------------
    def _do_save(self):
        self._collect()
        problems = self.cfg.validate()
        if problems:
            messagebox.showwarning(APP_NAME, "还差一点：\n\n" + "\n".join(problems))
            return False
        try:
            path = self.cfg.save(self.cfg_path)
        except OSError as exc:
            messagebox.showerror(APP_NAME, "保存失败：%s" % exc)
            return False
        log.get().info("配置已保存到 %s", path.name)
        return True

    def _do_services(self) -> None:
        """获取网关提供的服务/运营商列表，填进下拉框。"""
        self._collect()
        if not self.cfg.ssid:
            messagebox.showwarning(APP_NAME, "请先选择校园网（下拉框）")
            return

        def work():
            wlan.ensure_connected(self.cfg.ssid, auto_connect=self.cfg.auto_wlan_connect)
            return runner.fetch_service_list(self.cfg)

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror(APP_NAME, "获取失败：%s" % result)
                return
            names = [s["name"] for s in result if s.get("name")]
            if not names:
                # 自动取不到就给常见候选，保证用户一定能选
                self.cmb_service.configure(values=list(config_mod.COMMON_SERVICES))
                if not self.var_service.get():
                    self.var_service.set(config_mod.DEFAULT_SERVICE)
                messagebox.showinfo(
                    APP_NAME,
                    "没能自动取到服务列表（该网关可能不支持此接口）。\n\n"
                    "已列出常见选项，请在下拉框里选一个：\n"
                    "  · 移动互联网服务（默认）\n"
                    "  · 联通互联网服务\n"
                    "  · 电信互联网服务\n"
                    "  · 校园网\n\n"
                    "选好后点「保存」。如果都不对，可以直接手动输入。")
                return
            merged = names + [c for c in config_mod.COMMON_SERVICES if c not in names]
            self.cmb_service.configure(values=merged)
            if not self.var_service.get():
                self.var_service.set(names[0])
            if len(names) == 1:
                messagebox.showinfo(APP_NAME, "网关只有一个服务，已自动选好：%s" % names[0])
            else:
                messagebox.showinfo(APP_NAME,
                                    "网关提供 %d 个服务，当前选的是「%s」：\n\n%s\n\n"
                                    "如果不对，请在下拉框里换一个再点「保存」。"
                                    % (len(names), self.var_service.get(),
                                       "\n".join("· " + n for n in names)))

        self._bg(work, done, self.btn_services)

    def _do_detect(self) -> None:
        self._collect()
        if not self.cfg.ssid:
            messagebox.showwarning(APP_NAME, "请先选择校园网（下拉框）")
            return

        def work():
            wlan.ensure_connected(self.cfg.ssid, auto_connect=self.cfg.auto_wlan_connect)
            det = runner.detect_and_save(self.cfg)
            services = []
            if not det.already_online:
                services = runner.fetch_service_list(self.cfg)
            return det, services

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror(APP_NAME, "探测出错：%s" % result)
                return
            det, services = result
            self.var_cas.set(det.cas_base or "")
            self.var_ep.set(det.eportal_base or "")
            names = [s["name"] for s in services if s.get("name")]
            if names:
                merged = names + [c for c in config_mod.COMMON_SERVICES if c not in names]
                self.cmb_service.configure(values=merged)
                if not self.var_service.get():
                    self.var_service.set(names[0])

            if det.already_online:
                messagebox.showinfo(APP_NAME, "当前网络未被拦截，可能已经可以上网了。")
            elif det.ok:
                msg = "已识别：\n认证服务器 %s\n门户网关 %s" % (det.cas_base, det.eportal_base)
                if names:
                    msg += "\n\n网关提供的服务（%d 个）：\n%s" % (
                        len(names), "\n".join("· " + n for n in names))
                    msg += "\n\n当前选的是「%s」，不对的话请在下拉框里改。" % self.var_service.get()
                else:
                    msg += ("\n\n没能自动取到服务列表，已用默认值「%s」。\n"
                            "若认证失败提示「服务不能为空」，请在下拉框里换一个。"
                            % self.var_service.get())
                messagebox.showinfo(APP_NAME, msg)
            else:
                messagebox.showwarning(APP_NAME,
                                       "未能自动识别，请手动填写认证服务器与门户网关。\n\n"
                                       "提示：请确认已连上校园网，且当前还没认证。")

        self._bg(work, done, self.btn_detect)

    def _do_test(self) -> None:
        if not self._do_save():
            return
        self.cfg.force = True

        def work():
            return runner.connect(self.cfg)

        def done(result):
            if isinstance(result, Exception):
                messagebox.showerror(APP_NAME, "测试出错：%s" % result)
            elif result:
                messagebox.showinfo(APP_NAME, "连接成功，现在可以正常上网了。")
            else:
                messagebox.showwarning(APP_NAME,
                                       "没能连上。详情见下方日志，或 logs/campusnet.log。")

        self._bg(work, done, self.btn_test)

    def _do_task(self) -> None:
        if not self._do_save():
            return
        installed, _ = taskschd.status()
        if installed:
            if messagebox.askyesno(APP_NAME, "已经注册过自动认证任务。\n要移除它吗？"):
                ok, msg = taskschd.uninstall()
                messagebox.showinfo(APP_NAME, msg)
            return
        if messagebox.askyesno(APP_NAME,
                               "注册计划任务：每次网络一连上就自动认证。\n"
                               "不会常驻后台，也不占内存。\n\n继续吗？"):
            ok, msg = taskschd.install()
            if ok:
                messagebox.showinfo(APP_NAME, msg)
            else:
                messagebox.showerror(APP_NAME, msg)


def smoke_test() -> int:
    """构造向导窗口后立即销毁 —— 用于验证 GUI 与日志在打包环境下可用。"""
    import tempfile

    log.setup("INFO")          # 与真实启动路径一致，顺带验证日志落盘
    try:
        with tempfile.TemporaryDirectory() as td:
            app = Wizard(pathlib.Path(td) / "config.json")
            app.withdraw()
            for _ in range(5):
                app.update()
            need = ("var_user", "var_pwd", "var_ssid", "var_cas", "var_ep", "var_service",
                    "btn_detect", "btn_save", "btn_test", "btn_task", "btn_services",
                    "cmb_ssid", "cmb_service", "txt", "lbl_log")
            missing = [n for n in need if not hasattr(app, n)]
            logger = log.get()
            log.get().info("GUI 自检：窗口构造完成")
            keeps_file = any(isinstance(h, logging.FileHandler) for h in logger.handlers)
            app.destroy()
        if missing:
            print("GUI 控件缺失：%s" % missing)
            return 1
        print("GUI OK")
        print("日志文件：%s" % (log.LOG_FILE_PATH or "（未启用）"))
        print("文件日志处理器保留：%s" % ("是" if keeps_file else "否"))
        return 0 if keeps_file else 1
    except Exception as exc:  # noqa: BLE001
        print("GUI 不可用：%s" % exc)
        return 1


def run_wizard(cfg_path: pathlib.Path | None = None) -> int:
    log.setup("INFO")
    try:
        app = Wizard(cfg_path)
    except tk.TclError as exc:
        print("无法启动图形界面（%s），改用命令行向导。" % exc)
        return console_wizard(cfg_path)
    app.mainloop()
    return 0


def console_wizard(cfg_path: pathlib.Path | None = None) -> int:
    """无图形环境时的降级向导。"""
    cfg = config_mod.load(cfg_path)
    print("=" * 60)
    print("%s 首次配置向导" % APP_NAME)
    print("=" * 60)
    cfg.username = input("账号（学号/工号）: ").strip()
    pwd = input("密码: ").strip()
    cfg.set_password(pwd)

    nets = [n.get("ssid", "") for n in wlan.scan_networks() if n.get("ssid")]
    if nets:
        print("\n可见的无线网络：")
        for i, n in enumerate(nets, 1):
            print("  %2d) %s" % (i, n))
        pick = input("选择校园网序号（直接回车 = %s）: " % nets[0]).strip()
        cfg.ssid = nets[int(pick) - 1] if pick.isdigit() and 1 <= int(pick) <= len(nets) else nets[0]
    else:
        cfg.ssid = input("校园网名称（SSID）: ").strip()

    print("\n正在连接并探测认证服务…")
    wlan.ensure_connected(cfg.ssid, auto_connect=cfg.auto_wlan_connect)
    det = runner.detect_and_save(cfg)
    if det.ok:
        print("  认证服务器: %s" % det.cas_base)
        print("  门户网关  : %s" % det.eportal_base)
    else:
        cfg.cas_base = input("认证服务器地址（如 https://sso.example.edu.cn）: ").strip()
        cfg.eportal_base = input("门户网关地址（如 http://192.0.2.10）: ").strip()

    cfg.save(cfg_path)
    print("\n配置已保存。以后直接运行即可自动认证。")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_wizard())
