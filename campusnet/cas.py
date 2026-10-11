"""L2：统一身份认证登录（金智 LinkID 表单）。

流程（已用真实抓包逐字段校准）：
    GET  {cas}/login?service=<门户地址>     建立会话，并把 service 记入会话
    POST {cas}/login                        ← 注意：不带 ?service= 查询串
    body（form-urlencoded）:
        username / type=UsernamePassword / _eventId=submit / geolocation /
        execution / captcha_code / croypto / password / captcha_payload

要点：
  * `execution` 取自登录页 `#login-page-flowkey`
  * `croypto`  取自登录页 `#login-croypto`（服务端下发的 16 字节 Base64 密钥）
  * `password` = AES-128-ECB(`明文密码`)，密钥即 croypto —— **明文是纯密码，不带时间戳**
  * `captcha_payload` = AES-128-ECB(`"{}"`)
  * 成功判据：HTTP 302，且 Location 里带 `ticket=ST-…`

另有 REST 变体 `POST {cas}/protected/rest/login`（JSON、客户端自生成密钥 + 时间戳），
部分部署使用；本文件保留实现但默认不启用。
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from . import crypto, log

LOGIN_PAGE_PATH = "/login"
REST_LOGIN_PATH = "/protected/rest/login"

# 服务端错误码（取自前端判断分支）
ERR_WRONG_CREDENTIALS = 1030023
ERR_LOCKED = 1030033

_ERR_NAMES = {
    ERR_WRONG_CREDENTIALS: "账号或密码错误",
    ERR_LOCKED: "账号被锁定或需要二次验证",
}

# 表单字段顺序（与真实请求保持一致，便于比对）
FORM_FIELDS = ("username", "type", "_eventId", "geolocation", "execution",
               "captcha_code", "croypto", "password", "captcha_payload")

_CRED_WORDS = ("用户名或密码错误", "密码错误", "账号已锁定", "已锁定", "错误次数过多")


@dataclass
class CasPage:
    url: str = ""
    html: str = ""
    croypto: str = ""
    flowkey: str = ""
    rule_type: str = ""
    current_login_type: str = ""
    frontend_addr: str = ""
    captcha_url: str = ""
    needs_captcha: bool = False
    already_authenticated: bool = False   # 会话已登录（登录页直接跳走了）
    ticket_url: str = ""                  # 已登录时，跳转后的带票据地址

    def hidden(self, element_id: str) -> str:
        m = re.search(r'id=["\']' + re.escape(element_id) + r'["\'][^>]*>(.*?)<',
                      self.html, re.S)
        return m.group(1).strip() if m else ""


@dataclass
class CasResult:
    ok: bool = False
    fatal: bool = False          # 凭据/账号类错误：重试只会累加失败次数，必须停手
    http_status: int | None = None
    code: int | None = None
    message: str = ""
    ticket: str = ""
    redirect: str = ""
    error_code: int | None = None
    error_message: str = ""
    raw: str = ""
    sent_fields: dict = field(default_factory=dict)


def fetch_login_page(session: requests.Session, cfg, service_url: str) -> CasPage:
    """GET 登录页，取回现场参数。"""
    url = cfg.cas_base.rstrip("/") + LOGIN_PAGE_PATH
    r = session.get(url, params={"service": service_url}, timeout=cfg.connect_timeout,
                    allow_redirects=True,
                    headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
    page = CasPage(url=r.url, html=r.text)
    page.croypto = page.hidden("login-croypto")
    page.flowkey = page.hidden("login-page-flowkey")
    page.rule_type = page.hidden("login-rule-type")
    page.current_login_type = page.hidden("current-login-type")
    page.frontend_addr = page.hidden("frontend-addr") or cfg.cas_base
    page.captcha_url = page.hidden("captcha-url")
    page.needs_captcha = bool(page.captcha_url)

    # 会话若已登录，GET /login?service=... 会直接 302 到服务（带票据），
    # 此时页面上没有 #login-croypto —— 这不算错误，应跳过登录步骤。
    # 注意排除注销页：已登录时有些实现会跳到 /logout，那不是票据地址。
    final_path = urlparse(r.url).path.rstrip("/")
    if not page.croypto and not final_path.endswith(LOGIN_PAGE_PATH):
        page.already_authenticated = True
        if "logout" in final_path.lower():
            # 已登录时某些实现会跳到注销页 —— 那不是票据地址，别拿它当回跳目标
            log.get().debug("会话已登录（跳到了注销页），将跳过登录步骤")
        else:
            page.ticket_url = r.url
            log.get().debug("统一身份认证会话已有效，已直接跳转：%s", r.url[:120])
    else:
        log.get().debug("登录页：HTTP %s  rule=%s  type=%s  需要验证码=%s",
                        r.status_code, page.rule_type, page.current_login_type,
                        page.needs_captcha)
    return page


def build_form(cfg, page: CasPage) -> dict:
    """按真实请求构造表单字段。"""
    if not page.croypto:
        raise RuntimeError("登录页未提供加密密钥（#login-croypto），无法加密口令")
    try:
        key = base64.b64decode(page.croypto)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("密钥不是合法 Base64") from exc
    if len(key) not in (16, 24, 32):
        raise RuntimeError("密钥长度不合法（应为 16/24/32 字节）")
    return {
        "username": cfg.username,
        "type": page.current_login_type or "UsernamePassword",
        "_eventId": "submit",
        "geolocation": "",
        "execution": page.flowkey,
        "captcha_code": "",
        "croypto": page.croypto,
        "password": crypto.aes_encrypt_b64(page.croypto, cfg.password),
        "captcha_payload": crypto.aes_encrypt_b64(page.croypto, "{}"),
    }


def login(session: requests.Session, cfg, page: CasPage) -> CasResult:
    """提交登录表单。"""
    logger = log.get()
    data = build_form(cfg, page)
    url = cfg.cas_base.rstrip("/") + LOGIN_PAGE_PATH

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,image/apng,*/*;q=0.8"),
        "Origin": cfg.cas_base.rstrip("/"),
        "Referer": page.url,          # service 只在 Referer 里携带
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
    }

    preview = dict(data)
    preview["password"] = "<%d 字符密文>" % len(data["password"])
    preview["captcha_payload"] = "<%d 字符密文>" % len(data["captcha_payload"])
    if len(preview.get("execution", "")) > 40:
        preview["execution"] = preview["execution"][:32] + "…（%d 字符）" % len(data["execution"])
    res = CasResult(sent_fields=preview)

    if cfg.dry_run:
        logger.info("[dry-run] 将 POST %s（不带 service 查询串）", url)
        logger.info("[dry-run] 字段 = %s", json.dumps(preview, ensure_ascii=False))
        res.ok = True
        res.message = "dry-run 未实际提交"
        return res

    logger.info("提交统一身份认证…")
    try:
        r = session.post(url, data=data, headers=headers,
                         timeout=cfg.connect_timeout, allow_redirects=False)
    except requests.RequestException as exc:
        res.message = "请求异常：%s" % exc
        logger.error(res.message)
        return res

    res.http_status = r.status_code
    res.raw = (r.text or "")[:1000]
    res.redirect = r.headers.get("Location", "") or ""

    if r.status_code in (301, 302, 303, 307, 308):
        m = re.search(r"[?&]ticket=([^&\s]+)", res.redirect)
        if m:
            res.ticket = m.group(1)
            res.ok = True
            logger.info("统一身份认证通过，已获得票据")
            return res
        res.message = "收到重定向但没有票据：%s" % res.redirect[:160]
        logger.error(res.message)
        return res

    text = r.text or ""
    if "500 Internal" in text or "502 Bad" in text:
        res.message = "认证服务返回 %s（请求未被正常处理）" % r.status_code
        logger.error(res.message)
        return res

    m = re.search(r'id="login-error-code"[^>]*>(.*?)<', text, re.S)
    if m and m.group(1).strip():
        try:
            res.error_code = int(m.group(1).strip())
        except ValueError:
            res.error_code = None
    m2 = re.search(r'id="login-error-msg"[^>]*>(.*?)<', text, re.S)
    if m2:
        res.error_message = m2.group(1).strip()

    for w in _CRED_WORDS:
        if w in text:
            res.fatal = True
            res.message = "凭据类错误：%s" % w
            break
    if res.error_code in _ERR_NAMES:
        res.fatal = True
        res.message = "%s（%s）" % (_ERR_NAMES[res.error_code], res.error_code)
    if not res.message:
        res.message = "登录未成功（HTTP %s）" % r.status_code

    logger.error("统一身份认证失败：%s", res.message)
    if res.fatal:
        logger.error("这属于凭据/账号类问题，已停止重试以避免触发验证码或账号锁定。")
    return res


def follow_ticket(session: requests.Session, cfg, result: CasResult) -> str:
    """访问带票据的地址，让门户网关校验票据并建立其会话。"""
    if not result.redirect:
        return ""
    try:
        r = session.get(result.redirect, timeout=cfg.connect_timeout, allow_redirects=True,
                        headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        log.get().debug("票据回跳：HTTP %s -> %s", r.status_code, r.url[:160])
        return r.url
    except requests.RequestException as exc:
        # 校园网外访问不到网关属正常现象
        log.get().debug("票据回跳失败（校园网外属正常）：%s", exc)
        return result.redirect


# --------------------------------------------------------------------------
# REST 变体（部分部署使用；默认不启用）
# --------------------------------------------------------------------------

def generate_aes_key() -> str:
    """随机 16 字节密钥的 Base64（24 字符）。"""
    return base64.b64encode(os.urandom(16)).decode()


def rest_login(session: requests.Session, cfg, page: CasPage) -> CasResult:
    """POST {cas}/protected/rest/login（JSON）。"""
    key = generate_aes_key()
    ts = int(time.time() * 1000)
    body = {
        "username": cfg.username,
        "password": crypto.aes_encrypt_b64(key, "%s,%d" % (cfg.password, ts)),
        "timestamp": ts,
        "croypto": key,
    }
    csrf_key, csrf_value = crypto.gen_csrf()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Csrf-Key": csrf_key, "Csrf-Value": csrf_value,
        "Device-Id": crypto.gen_device_id(),
        "Sid-Language": "zh_CN",
        "Origin": cfg.cas_base.rstrip("/"),
        "Referer": page.url,
    }
    res = CasResult(sent_fields={"username": cfg.username, "timestamp": ts})
    if cfg.dry_run:
        res.ok = True
        res.message = "dry-run 未实际提交"
        return res
    try:
        r = session.post(cfg.cas_base.rstrip("/") + REST_LOGIN_PATH, json=body,
                         headers=headers, timeout=cfg.connect_timeout, allow_redirects=False)
    except requests.RequestException as exc:
        res.message = "请求异常：%s" % exc
        return res
    res.http_status = r.status_code
    try:
        payload = r.json()
    except ValueError:
        res.message = "响应不是 JSON（HTTP %s）" % r.status_code
        return res
    res.code = payload.get("code")
    res.message = str(payload.get("message") or "")
    data = payload.get("data") or {}
    if isinstance(data, dict):
        res.error_code = data.get("errorCode")
        res.error_message = str(data.get("errorMessage") or "")
        if res.code == 200 and data.get("result"):
            res.ok = True
    if res.error_code in _ERR_NAMES:
        res.fatal = True
    return res
