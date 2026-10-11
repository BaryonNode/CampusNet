"""L3：门户网关认证（InterFace.do）。

要点：
  * 运营商/服务选择完全落在 cookie 上，无需前端交互
  * 请求体为 form 编码；`queryString` 是本次会话的网关令牌串（需整串百分号编码）
  * `Referer` 必须带 `;jsessionid=`，且与 Cookie 中的 JSESSIONID 一致
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote, urlparse

import requests

from . import log

_RE_JSON = re.compile(r"[\{\[].*[\}\]]", re.S)
METHOD = "loginOfCas"


@dataclass
class EportalResult:
    ok: bool = False
    result: str = ""
    message: str = ""
    ret_code: int | None = None
    raw: str = ""
    sent: dict = field(default_factory=dict)


def set_operator_cookies(session: requests.Session, cfg, service: str) -> None:
    """把服务/运营商选择写进 cookie —— 这一步完全替代前端下拉框。"""
    if not service or not cfg.eportal_base:
        log.get().debug("未指定服务名，沿用服务器既有 cookie")
        return
    host = urlparse(cfg.eportal_base).hostname or ""
    enc = quote(service)
    jar = session.cookies
    jar.set("EPORTAL_COOKIE_SERVER", enc, domain=host)
    jar.set("EPORTAL_COOKIE_SERVER_NAME", enc, domain=host)
    jar.set("EPORTAL_COOKIE_DOMAIN", "false", domain=host)
    jar.set("EPORTAL_COOKIE_OPERATORPWD", "", domain=host)
    log.get().debug("已设置服务 cookie：%s", service)


def authorize(session: requests.Session, cfg, portal, user_id: str) -> EportalResult:
    """执行网关认证。"""
    logger = log.get()
    url = cfg.interface_url
    if not url:
        return EportalResult(ok=False, message="未配置门户网关地址")

    data = {
        "userId": user_id,
        "flag": "casauthofservicecheck",
        "service": quote(cfg.service) if cfg.service else "",
        "queryString": portal.query_string,
        "operatorPwd": "",
        "operatorUserId": "",
        "passwordEncrypt": "false",
        "rememberService": "false",
    }

    jsid = ""
    if session is not None:
        for c in session.cookies:
            if c.name.upper() == "JSESSIONID":
                jsid = c.value
                break
    referer = portal.service_url
    if jsid and referer:
        p = urlparse(referer)
        referer = "%s://%s%s;jsessionid=%s?%s" % (p.scheme, p.netloc, p.path, jsid, p.query)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "*/*",
        "Origin": cfg.eportal_base.rstrip("/") if cfg.eportal_base else "",
        "Referer": referer,
        "Connection": "keep-alive",
    }

    result = EportalResult(sent=data)
    if cfg.dry_run:
        preview = dict(data)
        preview["queryString"] = "<%d 字符的网关令牌串>" % len(portal.query_string)
        logger.info("[dry-run] 将 POST %s?method=%s", url, METHOD)
        logger.info("[dry-run] body = %s", json.dumps(preview, ensure_ascii=False))
        result.ok = True
        result.message = "dry-run 未实际提交"
        return result

    logger.info("提交门户网关认证…")
    try:
        r = session.post(url, params={"method": METHOD}, data=data, headers=headers,
                         timeout=cfg.connect_timeout, allow_redirects=False)
    except requests.RequestException as exc:
        result.message = "请求异常：%s" % exc
        logger.error(result.message)
        return result

    result.raw = (r.text or "")[:2000]
    payload = parse_payload(r.text or "")
    if payload is None:
        result.message = "响应无法解析（HTTP %s）：%s" % (r.status_code, result.raw[:160])
        logger.error(result.message)
        return result

    result.result = str(payload.get("result", ""))
    result.message = str(payload.get("msg") or payload.get("message") or "")
    if isinstance(payload.get("ret_code"), int):
        result.ret_code = payload["ret_code"]

    # ret_code=2 表示「已在线」，按成功处理
    result.ok = result.result.lower() == "success" or result.ret_code == 2
    if result.ok:
        logger.info("门户网关认证返回成功%s", "（已在线）" if result.ret_code == 2 else "")
        return result

    # 常见且可操作的一类失败：网关提供多个服务，必须指定其一
    if "服务" in result.message and not cfg.service:
        result.message = ("网关提供多个服务（校园网 / 各运营商），必须指定其中一个。"
                          "请在配置里填写「服务/运营商」，可用 --services 查看列表。"
                          "原始返回：%s" % result.message)
    logger.error("门户网关认证失败：result=%s msg=%s ret_code=%s",
                 result.result, result.message, result.ret_code)
    return result


def parse_payload(text: str):
    """容错解析：裸 JSON 或 JSONP（形如 cb({...})）。"""
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    m = _RE_JSON.search(text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# 服务/运营商列表
# --------------------------------------------------------------------------

_NAME_KEYS = ("serviceName", "name", "service", "showName", "serviceShowName")
_ID_KEYS = ("serviceId", "id", "serviceID", "value")


def _extract_services(payload) -> list[dict[str, str]]:
    """从各种可能的返回结构里挑出服务列表。"""
    if isinstance(payload, list):
        candidates = payload
    elif isinstance(payload, dict):
        candidates = None
        for key in ("services", "serviceList", "service", "data", "list"):
            v = payload.get(key)
            if isinstance(v, list):
                candidates = v
                break
            if isinstance(v, dict):
                for k2 in ("services", "serviceList", "list"):
                    if isinstance(v.get(k2), list):
                        candidates = v[k2]
                        break
            if candidates is not None:
                break
        if candidates is None:
            return []
    else:
        return []

    out: list[dict[str, str]] = []
    for item in candidates:
        if isinstance(item, str):
            out.append({"name": item, "id": ""})
            continue
        if not isinstance(item, dict):
            continue
        name = ""
        for k in _NAME_KEYS:
            if item.get(k):
                name = str(item[k])
                break
        if not name:
            continue
        sid = ""
        for k in _ID_KEYS:
            if item.get(k) not in (None, ""):
                sid = str(item[k])
                break
        out.append({"name": name, "id": sid})
    return out


def fetch_services(session: requests.Session, cfg, portal) -> list[dict[str, str]]:
    """获取网关提供的服务/运营商列表。

    标准 eportal 流程：先 `method=pageInfo` 取 userIndex，再 `method=getServices`。
    各校接口略有差异，这里做容错解析；**失败返回空列表，绝不影响主流程**。
    """
    url = cfg.interface_url
    if not url or portal is None:
        return []

    qs = portal.query_string

    def call(method: str, data: dict):
        try:
            r = session.post(url, params={"method": method}, data=data,
                             timeout=cfg.connect_timeout, allow_redirects=False,
                             headers={"Content-Type":
                                      "application/x-www-form-urlencoded; charset=UTF-8"})
            return parse_payload(r.text or "")
        except requests.RequestException as exc:
            log.get().debug("服务列表接口 %s 调用失败：%s", method, exc)
            return None

    page = call("pageInfo", {"queryString": qs})
    user_index = ""
    if isinstance(page, dict):
        for k in ("userIndex", "userindex", "index", "userIndexValue"):
            if page.get(k):
                user_index = str(page[k])
                break

    payload = call("getServices", {"userIndex": user_index, "queryString": qs})
    services = _extract_services(payload)
    if services:
        log.get().debug("网关提供 %d 个服务：%s", len(services),
                        [s["name"] for s in services])
    else:
        log.get().debug("未能取得服务列表（该网关可能不支持此接口）")
    return services
