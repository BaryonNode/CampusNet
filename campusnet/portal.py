"""L1：探测认证门户，并**自动识别**认证服务器与网关地址。

为什么能自动识别：校园网未认证时，任何 HTTP 请求都会被网关劫持并 302 到门户。
门户地址里同时带着两样东西——
    * 跳转目标的主机名  => 统一身份认证域名
    * `service=` 参数   => 门户网关（eportal）地址
因此用户**不需要知道**任何域名或 IP。

另外：`wlanuserip / wlanacname / nasip / mac / url` 是网关加密下发、
客户端原样回传的一次性令牌，脚本无法自行构造，每次运行都必须重新获取。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, quote, urljoin, urlparse

import requests

from . import log

_RE_META_REFRESH = re.compile(
    r"""http-equiv=["']?refresh["']?[^>]*content=["'][^"']*?url=([^"'\s>]+)""", re.I)
_RE_JS_LOCATION = re.compile(
    r"""(?:location(?:\.href)?|window\.location(?:\.href)?)\s*=\s*["']([^"']+)["']""", re.I)
_RE_ANY_PORTAL = re.compile(r"""(https?://[\w.:-]+/[^\s"'<>]*(?:eportal|portal|login)[^\s"'<>]*)""", re.I)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0")

# 门户地址的通用特征（厂商中立，不绑定任何具体学校）
_PORTAL_MARKERS = ("eportal", "portal", "srun", "interFace.do",
                   "wlanuserip", "wlanacname", "nasip")


def _looks_like_portal(url: str) -> bool:
    """判断一个地址是否像"网关下发的门户地址"，用于拒绝无关 URL。"""
    if not url:
        return False
    low = url.lower()
    if any(m.lower() in low for m in _PORTAL_MARKERS):
        return True
    # 网关下发的一次性地址几乎总带查询串
    return bool(parse_qsl(urlparse(url).query, keep_blank_values=True))


# --------------------------------------------------------------------------
# 数据结构
# --------------------------------------------------------------------------

@dataclass
class PortalInfo:
    """一次网关会话的门户信息。"""
    redirect_url: str = ""
    service_url: str = ""             # 门户网关首页（含本次会话令牌）
    cas_login_url: str = ""
    query: dict = field(default_factory=dict)
    raw_query: str = ""

    @property
    def query_string(self) -> str:
        """网关认证接口所需的 queryString —— 整条 query 再做一次百分号编码。

        （`=` → %3D、`&` → %26；空值参数如 `ssid=` 必须保留。）
        """
        return quote(self.raw_query, safe="")

    @property
    def gateway_host(self) -> str:
        return urlparse(self.service_url).hostname or ""


@dataclass
class Detected:
    """自动识别结果。"""
    cas_base: str = ""
    eportal_base: str = ""
    eportal_index: str = ""
    service_url: str = ""
    already_online: bool = False
    chain: list = field(default_factory=list)
    note: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.cas_base and self.eportal_base)


# --------------------------------------------------------------------------
# 解析
# --------------------------------------------------------------------------

def _origin(url: str) -> str:
    p = urlparse(url)
    return "%s://%s" % (p.scheme, p.netloc) if p.scheme and p.netloc else ""


def _extract_from_body(text: str) -> str:
    for rx in (_RE_META_REFRESH, _RE_JS_LOCATION, _RE_ANY_PORTAL):
        m = rx.search(text or "")
        if m:
            return m.group(1)
    return ""


def parse_portal_url(redirect_url: str, cfg) -> PortalInfo | None:
    """把网关给出的跳转地址归一化成 PortalInfo。

    两种形态：
      a) 跳转直接指向门户网关  `.../eportal/index.jsp?<token>`
      b) 跳转指向统一认证      `.../login?service=<上面的门户地址>`
    """
    if not redirect_url:
        return None

    info = PortalInfo(redirect_url=redirect_url)
    parsed = urlparse(redirect_url)

    if parsed.path.rstrip("/").endswith("/login") or "service" in dict(
            parse_qsl(parsed.query, keep_blank_values=True)):
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        service = q.get("service", "")
        if service:
            info.service_url = service
            info.cas_login_url = redirect_url
    else:
        info.service_url = redirect_url

    if not info.service_url or not _looks_like_portal(info.service_url):
        log.get().warning("跳转地址不像认证门户，已忽略：%s", (redirect_url or "")[:140])
        return None

    sp = urlparse(info.service_url)
    info.raw_query = sp.query
    # keep_blank_values 必不可少：真实网关会下发 `ssid=`（空值）这类参数
    info.query = dict(parse_qsl(sp.query, keep_blank_values=True))

    if not info.cas_login_url and cfg.cas_base:
        info.cas_login_url = "%s/login?service=%s" % (
            cfg.cas_base.rstrip("/"), quote(info.service_url, safe=""))

    return info


# --------------------------------------------------------------------------
# 自动识别
# --------------------------------------------------------------------------

def _walk(session: requests.Session, url: str, cfg, max_hops: int = 6) -> list[str]:
    """手动跟随重定向链，记录沿途所有 URL（含 JS/meta 跳转）。"""
    chain: list[str] = []
    cur = url
    for _ in range(max_hops):
        if not cur or cur in chain:
            break
        chain.append(cur)
        try:
            r = session.get(cur, timeout=cfg.connect_timeout, allow_redirects=False,
                            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        except requests.RequestException as exc:
            log.get().debug("探测 %s 失败：%s", cur[:80], exc)
            break
        loc = r.headers.get("Location", "")
        if loc:
            cur = urljoin(cur, loc)
            continue
        if r.status_code == 200:
            nxt = _extract_from_body(r.text or "")
            if nxt:
                cur = urljoin(cur, nxt)
                continue
        break
    return chain


def autodetect(session: requests.Session, cfg) -> Detected:
    """连上校园网后自动识别认证服务器与网关。

    返回的 `already_online=True` 表示当前网络没有被拦截（无需认证）。
    """
    logger = log.get()
    det = Detected()

    chain = _walk(session, cfg.probe_url, cfg)
    det.chain = chain

    # 若探测地址直接返回了预期内容，说明没有被劫持
    if chain and chain[-1] == cfg.probe_url:
        try:
            r = session.get(cfg.probe_url, timeout=cfg.connect_timeout, allow_redirects=False)
            if r.status_code == 200 and cfg.probe_expect in (r.text or ""):
                det.already_online = True
                det.note = "当前网络未被拦截，无需认证"
                return det
        except requests.RequestException:
            pass

    # 逐条分析跳转链，提取认证域名与网关地址
    for url in chain:
        if not det.cas_base and urlparse(url).path.rstrip("/").endswith("/login"):
            det.cas_base = _origin(url)

        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        service = q.get("service", "")
        target = service or url
        tp = urlparse(target)
        if "eportal" in target or "eportal" in tp.path:
            if not det.eportal_base:
                det.eportal_base = _origin(target)
                det.eportal_index = tp.path or cfg.eportal_index
                det.service_url = target

    # 只拿到网关、没拿到认证域名时，直接访问网关首页看它跳到哪
    if det.eportal_base and not det.cas_base:
        for url in _walk(session, det.eportal_base + det.eportal_index, cfg):
            if urlparse(url).path.rstrip("/").endswith("/login"):
                det.cas_base = _origin(url)
                break

    if not det.ok:
        det.note = "未能自动识别，请手动填写认证域名与网关地址"
        logger.warning("%s（跳转链：%s）", det.note,
                       " → ".join(u[:60] for u in chain[:4]) or "空")
    else:
        logger.info("已识别认证服务器 %s，网关 %s", det.cas_base, det.eportal_base)
    return det


# --------------------------------------------------------------------------
# 认证流程用的捕获
# --------------------------------------------------------------------------

def capture(session: requests.Session, cfg) -> PortalInfo | None:
    """定位门户。返回 None 表示当前已可上网（无需认证）。"""
    logger = log.get()

    try:
        r = session.get(cfg.probe_url, timeout=cfg.connect_timeout, allow_redirects=False,
                        headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    except requests.RequestException as exc:
        logger.debug("探测失败：%s", exc)
        r = None

    candidate = ""
    if r is not None:
        if r.status_code == 200 and cfg.probe_expect in (r.text or ""):
            logger.info("当前网络已可访问外网，无需认证")
            return None
        candidate = r.headers.get("Location", "") or _extract_from_body(r.text or "")

    if not candidate and cfg.eportal_url:
        try:
            r2 = session.get(cfg.eportal_url, timeout=cfg.connect_timeout,
                             allow_redirects=False)
            candidate = r2.headers.get("Location", "") or _extract_from_body(r2.text or "")
            if not candidate and ("eportal" in (r2.text or "") or "wlanuserip" in (r2.text or "")):
                candidate = cfg.eportal_url
        except requests.RequestException as exc:
            logger.debug("网关探测失败：%s", exc)

    if not candidate:
        logger.warning("未能取得门户跳转地址")
        return None

    # 跳转目标可能是认证页；顺着走一跳拿到带令牌的门户地址
    if candidate != cfg.eportal_url and "eportal" not in candidate:
        for url in _walk(session, candidate, cfg, max_hops=3):
            if "eportal" in url:
                candidate = url
                break

    logger.info("门户跳转地址已捕获")
    info = parse_portal_url(candidate, cfg)
    if info is None:
        logger.warning("跳转地址无法解析：%s", candidate[:140])
        return None
    logger.debug("网关令牌字段：%s", sorted(info.query.keys()))
    return info


def refresh(info: PortalInfo, url: str) -> bool:
    """用回跳后的 URL 刷新网关令牌（网关可能重新签发 url 令牌）。"""
    if not url:
        return False
    q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if "wlanuserip" not in q:
        return False
    changed = {k: (info.query.get(k), v) for k, v in q.items() if info.query.get(k) != v}
    if not changed:
        return False
    log.get().debug("刷新网关令牌：%s", changed)
    info.query = q
    info.raw_query = urlparse(url).query
    return True


def new_session(cfg) -> requests.Session:
    """构造会话：禁用系统代理，使用浏览器 UA。"""
    s = requests.Session()
    # 关键：忽略环境变量与 Windows 注册表里的系统代理
    s.trust_env = False
    s.proxies = {}
    s.headers.update({
        "User-Agent": _UA,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate",
    })
    return s
