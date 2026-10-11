"""计划任务注册：网络链路建立时自动认证（进程零常驻）。

触发源：`Microsoft-Windows-NetworkProfile/Operational` 的 **Event ID 10000**。
做法：生成任务 XML 交给 `schtasks /Create /XML`（XML 必须是 UTF-16LE）。
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

from . import APP_NAME, app_root, is_frozen, log

TASK_NAME = "CampusNet Auto Connect"
_EVENT_LOG = "Microsoft-Windows-NetworkProfile/Operational"

_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="{eventlog}"&gt;&lt;Select Path="{eventlog}"&gt;*[System[(EventID=10000)]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
      <Delay>{delay}</Delay>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
      <WorkingDirectory>{workdir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _launch_command() -> tuple[str, str]:
    """返回 (可执行文件, 参数)。打包成 exe 与源码运行两种情形。"""
    root = app_root()
    if is_frozen():
        # 打包后：直接调用自身，静默模式
        return sys.executable, "--silent"

    exe = sys.executable
    # 优先用 pythonw，避免弹黑框
    cand = pathlib.Path(exe).with_name("pythonw.exe")
    if cand.exists():
        exe = str(cand)
    entry = root / "connect.py"
    return exe, '"%s" --silent' % entry


def _run(args: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = p.stdout.decode("utf-8", "replace") or p.stdout.decode("gbk", "replace")
        err = p.stderr.decode("utf-8", "replace") or p.stderr.decode("gbk", "replace")
        return p.returncode, (out + err).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return 1, str(exc)


def install(delay_seconds: int = 5) -> tuple[bool, str]:
    """注册计划任务。返回 (是否成功, 说明)。"""
    logger = log.get()
    root = str(app_root())
    command, arguments = _launch_command()

    xml = _TASK_XML.format(
        description="%s：网络链路建立时自动完成校园网认证" % APP_NAME,
        eventlog=_EVENT_LOG,
        delay="PT%dS" % max(0, delay_seconds),
        command=command.replace("&", "&amp;"),
        arguments=arguments.replace("&", "&amp;").replace("<", "&lt;"),
        workdir=root.replace("&", "&amp;"),
    )

    fd, path = tempfile.mkstemp(suffix=".xml", prefix="campusnet_task_")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(xml.encode("utf-16"))          # schtasks 要求 UTF-16
        code, out = _run(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", path, "/F"])
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

    if code == 0:
        logger.info("已注册计划任务：%s", TASK_NAME)
        return True, "已注册。网络一连上就会自动认证。"
    logger.error("注册计划任务失败：%s", out[:200])
    return False, "注册失败：%s" % out[:200]


def uninstall() -> tuple[bool, str]:
    code, out = _run(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    if code == 0:
        return True, "已移除计划任务。"
    return False, "移除失败：%s" % out[:200]


def status() -> tuple[bool, str]:
    code, out = _run(["schtasks", "/Query", "/TN", TASK_NAME])
    if code == 0:
        return True, out
    return False, "未注册"


def run_now() -> tuple[bool, str]:
    code, out = _run(["schtasks", "/Run", "/TN", TASK_NAME], timeout=60)
    if code == 0:
        return True, "已触发一次（当前若已联网，会立即退出）"
    return False, "触发失败：%s" % out[:200]


if __name__ == "__main__":
    log.setup("INFO")
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "install":
        print(install())
    elif action == "uninstall":
        print(uninstall())
    elif action == "run":
        print(run_now())
    else:
        ok, msg = status()
        print("已注册" if ok else msg)
        if ok:
            print(msg[:600])
