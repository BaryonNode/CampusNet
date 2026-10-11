"""L5：编排、重试与系统集成。

重试策略（重要）：
    只有「网络类/临时类」失败才重试。
    凭据类失败（账号密码错误、账号锁定）一律立即中止——
    否则重试会白白累加失败次数，触发图形验证码甚至账号锁定。
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import requests

from . import cas, config as config_mod, eportal, log, portal, verify, wlan


# --------------------------------------------------------------------------
# 系统代理（只影响浏览器，脚本自身已用 trust_env=False 绕开）
# --------------------------------------------------------------------------

def proxy_status() -> tuple[bool, str]:
    try:
        import winreg  # type: ignore
    except ImportError:
        return False, ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
            enabled = int(winreg.QueryValueEx(k, "ProxyEnable")[0])
            try:
                server = str(winreg.QueryValueEx(k, "ProxyServer")[0])
            except FileNotFoundError:
                server = ""
        return bool(enabled), server
    except OSError:
        return False, ""


def disable_system_proxy() -> bool:
    try:
        import winreg  # type: ignore
    except ImportError:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                            0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# 认证
# --------------------------------------------------------------------------

@dataclass
class AuthOutcome:
    ok: bool = False
    fatal: bool = False
    detail: str = ""


def _on_target_wlan(cfg) -> bool:
    if not cfg.ssid:
        return True
    return wlan.current_ssid() == cfg.ssid.strip()


def establish_cas_session(cfg, session: requests.Session, info) -> AuthOutcome:
    """L2：完成统一身份认证，拿到票据并让门户网关建立会话。

    **只做一次**。重试时不要再走这里——CAS 已登录的情况下再 GET /login
    会被重定向到注销页，反而把会话弄乱。
    """
    logger = log.get()
    page = cas.fetch_login_page(session, cfg, info.service_url)

    if page.already_authenticated:
        logger.info("统一身份认证会话已有效，跳过登录步骤")
        final_url = page.ticket_url
    else:
        if page.needs_captcha:
            return AuthOutcome(False, False,
                               "登录页要求图形验证码。这通常是密码连错多次导致的，"
                               "请先在浏览器里完成一次登录以清除")
        result = cas.login(session, cfg, page)
        if not result.ok:
            return AuthOutcome(False, result.fatal, result.message)
        final_url = cas.follow_ticket(session, cfg, result)

    portal.refresh(info, final_url)
    return AuthOutcome(True, False, "统一身份认证已通过")


def authorize_gateway(cfg, session: requests.Session, info) -> AuthOutcome:
    """L3：门户网关认证。可安全重试。"""
    eportal.set_operator_cookies(session, cfg, cfg.service)
    auth = eportal.authorize(session, cfg, info, cfg.username)
    if not auth.ok:
        return AuthOutcome(False, False, auth.message or "门户网关未返回成功")
    return AuthOutcome(True, False, "网关认证请求已提交")


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def connect(cfg) -> bool:
    """完整链路：L0 → 自动识别 → L1 → (L2 → L3 → L4) 重试。

    安全网：如果为了认证切换了无线却最终失败，会把原来的网络切回去。
    """
    logger = log.get()
    previous_ssid = wlan.current_ssid()

    ok = _connect_inner(cfg)

    if (not ok and previous_ssid and cfg.ssid
            and previous_ssid != cfg.ssid.strip()
            and wlan.has_profile(previous_ssid)):
        logger.warning("认证未成功，正在恢复原来的网络：%s", previous_ssid)
        try:
            if wlan.connect(previous_ssid) and wlan.wait_for_association(previous_ssid, timeout=30):
                logger.info("已恢复到 %s", previous_ssid)
            else:
                logger.warning("恢复 %s 失败，请手动重新连接", previous_ssid)
        except Exception as exc:  # noqa: BLE001
            logger.warning("恢复网络时出错：%s", exc)

    return ok


def _connect_inner(cfg) -> bool:
    logger = log.get()
    session = portal.new_session(cfg)

    # 0) 也许已经是通的
    if not cfg.force and verify.is_online(cfg, session):
        logger.info("当前已可正常上网，无需认证")
        return True

    # 1) 系统代理提示 / 可选清理
    enabled, server = proxy_status()
    if enabled:
        if cfg.clear_system_proxy:
            if disable_system_proxy():
                logger.info("已关闭系统代理残留（%s）", server)
        else:
            logger.warning("系统代理处于开启状态（%s）——浏览器可能仍打不开网页，"
                           "脚本自身不受影响", server)

    # 2) L0 无线关联
    if cfg.ssid:
        if not wlan.ensure_connected(cfg.ssid, auto_connect=cfg.auto_wlan_connect):
            logger.error("无线未连接到 %s，终止（可用 --wlan-scan 核对 SSID 写法）", cfg.ssid)
            return False
    else:
        logger.warning("未配置校园网（SSID），跳过无线关联")

    # 3) 首次运行时自动识别认证服务器与网关
    if not (cfg.cas_base and cfg.eportal_base):
        det = portal.autodetect(session, cfg)
        if det.already_online:
            logger.info("当前网络未被拦截，无需认证")
            return True
        if det.ok:
            cfg.cas_base = det.cas_base
            cfg.eportal_base = det.eportal_base
            if det.eportal_index:
                cfg.eportal_index = det.eportal_index
            try:
                cfg.save()
                logger.info("已自动识别并保存认证服务地址")
            except OSError as exc:
                logger.debug("保存配置失败：%s", exc)
        else:
            logger.error("无法识别认证服务地址，请在向导里手动填写")
            return False

    # 4) 认证重试
    service_checked = False
    cas_done = False
    for attempt in range(1, max(1, cfg.max_retries) + 1):
        logger.info("第 %d/%d 次尝试认证", attempt, cfg.max_retries)
        try:
            info = portal.capture(session, cfg)
        except requests.RequestException as exc:
            logger.error("门户探测异常：%s", exc)
            info = None

        if info is None:
            if verify.is_online(cfg, session) and _on_target_wlan(cfg):
                logger.info("认证完成，网络已通")
                return True
            logger.warning("未能定位门户地址（当前 SSID=%s）", wlan.current_ssid() or "?")
            outcome = AuthOutcome(False, False, "未定位到门户")
        else:
            # 首次拿到门户后，确认"服务/运营商"是否必须指定
            if not service_checked:
                service_checked = True
                if not cfg.service:
                    services = eportal.fetch_services(session, cfg, info)
                    names = [s["name"] for s in services if s.get("name")]
                    if len(names) == 1:
                        cfg.service = names[0]
                        logger.info("网关仅提供一个服务，已自动选用：%s", cfg.service)
                        try:
                            cfg.save()
                        except OSError:
                            pass
                    elif len(names) > 1:
                        logger.error("该校园网提供多个服务，必须指定其中一个：%s", names)
                        logger.error("请在配置窗口的「服务/运营商」里选一个"
                                     "（命令行可用 --services 查看列表）。")
                        return False

            try:
                if not cas_done:
                    # L2 只做一次；之后只重试 L3
                    out = establish_cas_session(cfg, session, info)
                    if out.fatal:
                        logger.error("服务端明确拒绝：%s", out.detail)
                        logger.error("已立即停止重试——继续重试只会累加失败计数。")
                        return False
                    if not out.ok:
                        outcome = out
                    else:
                        cas_done = True
                        outcome = authorize_gateway(cfg, session, info)
                else:
                    outcome = authorize_gateway(cfg, session, info)
            except requests.RequestException as exc:
                outcome = AuthOutcome(False, False, "认证过程网络异常：%s" % exc)
            except RuntimeError as exc:
                outcome = AuthOutcome(False, False, "认证过程出错：%s" % exc)

        if outcome.fatal:
            logger.error("服务端明确拒绝：%s", outcome.detail)
            logger.error("已立即停止重试——继续重试只会累加失败计数。")
            return False

        # L4：只信真实探测
        for _ in range(3):
            if verify.is_online(cfg, session) and _on_target_wlan(cfg):
                logger.info("联网成功（第 %d 次尝试）", attempt)
                return True
            time.sleep(2)

        logger.warning("第 %d 次尝试后仍未连通%s",
                       attempt, ("（%s）" % outcome.detail) if outcome.detail else "")
        if attempt < cfg.max_retries:
            time.sleep(cfg.retry_delay)

    logger.error("认证失败，请用 -v 查看详细过程，或查看 logs/campusnet.log")
    return False


# --------------------------------------------------------------------------
# 环境自检
# --------------------------------------------------------------------------

def wlan_report(cfg) -> None:
    """打印可见无线网络与已保存配置，便于选择 SSID。"""
    visible = wlan.scan_networks()
    profiles = set(wlan.list_profiles())
    cur = wlan.current_ssid()
    print("=" * 68)
    print("可见的无线网络（%d 个）" % len(visible))
    print("=" * 68)
    if not visible:
        print("  （扫不到任何网络：确认无线网卡已开启）")
    for n in visible:
        mark = "已保存配置" if n.get("ssid") in profiles else ""
        here = "  ← 当前连接" if n.get("ssid") == cur else ""
        print("  %-32s %-20s %-10s%s" % (n.get("ssid", "?"), n.get("auth", "?"), mark, here))
    print("\n已保存的无线配置（%d 个）" % len(profiles))
    print("=" * 68)
    for p in sorted(profiles):
        print("  " + p)


def detect_and_save(cfg) -> portal.Detected:
    """探测并保存认证服务地址（供向导调用）。"""
    session = portal.new_session(cfg)
    det = portal.autodetect(session, cfg)
    if det.ok:
        cfg.cas_base = det.cas_base
        cfg.eportal_base = det.eportal_base
        if det.eportal_index:
            cfg.eportal_index = det.eportal_index
        cfg.save()
    return det


def fetch_service_list(cfg) -> list[dict]:
    """捕获门户并取回服务/运营商列表（供向导调用）。失败返回空列表。"""
    session = portal.new_session(cfg)
    try:
        info = portal.capture(session, cfg)
    except requests.RequestException as exc:
        log.get().debug("获取服务列表时门户探测失败：%s", exc)
        return []
    if info is None:
        return []
    return eportal.fetch_services(session, cfg, info)
