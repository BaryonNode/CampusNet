"""L4：真实外网连通性判定。

绝不采信任何页面提示 —— 只有拿到预期的探测内容才算真正联网。
"""
from __future__ import annotations

import requests

from . import log


def plain_session(cfg) -> requests.Session:
    s = requests.Session()
    # 忽略环境变量与系统代理残留
    s.trust_env = False
    s.proxies = {}
    s.headers.update({
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"),
        "Cache-Control": "no-cache",
    })
    return s


def check_http(cfg, session: requests.Session | None = None) -> tuple[bool, str]:
    """探针请求：期望 200 且正文为预期内容（而不是门户页面）。"""
    s = session or plain_session(cfg)
    try:
        r = s.get(cfg.probe_url, timeout=cfg.connect_timeout, allow_redirects=False)
    except requests.RequestException as exc:
        return False, "探测请求失败：%s" % exc
    body = (r.text or "").strip()
    if r.status_code == 200 and cfg.probe_expect in body and len(body) < 500:
        return True, "探针通过"
    if r.status_code in (301, 302, 303, 307, 308):
        return False, "被重定向到门户：%s" % r.headers.get("Location", "")[:120]
    return False, "探针未通过（HTTP %s，正文 %r）" % (r.status_code, body[:60])


def check_https(cfg, session: requests.Session | None = None) -> tuple[bool, str]:
    """HTTPS 外网站点二次确认。"""
    if not cfg.probe_https_url:
        return True, "已跳过 HTTPS 复核"
    s = session or plain_session(cfg)
    try:
        r = s.get(cfg.probe_https_url, timeout=cfg.connect_timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return False, "HTTPS 复核失败：%s" % exc
    if r.status_code < 400:
        return True, "HTTPS 复核通过（HTTP %s）" % r.status_code
    return False, "HTTPS 复核未通过（HTTP %s）" % r.status_code


def is_online(cfg, session: requests.Session | None = None, verbose: bool = True) -> bool:
    ok1, why1 = check_http(cfg, session)
    if verbose:
        log.get().debug("探针：%s", why1)
    if not ok1:
        return False
    ok2, why2 = check_https(cfg, session)
    if verbose:
        log.get().debug("HTTPS：%s", why2)
    return ok2
