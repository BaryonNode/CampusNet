"""离线自检：不联网、不需要真实账号。

**全部使用合成数据**（`sso.example.edu.cn` / `192.0.2.10` / `CampusWiFi`），
不含任何真实站点信息，任何人都可以 clone 下来直接验证。
"""
from __future__ import annotations

import base64
import json
import pathlib
import tempfile
from urllib.parse import quote, urlencode

import requests

from . import cas, config as config_mod, crypto, eportal, log, portal, taskschd
from .wlan import _parse_block

# ---- 合成夹具（RFC 5737 文档用 IP + example 域名）----
FAKE_CAS = "https://sso.example.edu.cn"
FAKE_GW = "http://192.0.2.10"
FAKE_SSID = "CampusWiFi"
FAKE_USER = "20230001"
FAKE_PWD = "dummy-password"          # 15 字符，与常见口令同长
FAKE_SERVICE = "移动互联网服务"

FAKE_TOKENS = [
    ("wlanuserip", "0123456789abcdef0123456789abcdef"),
    ("wlanacname", "fedcba9876543210fedcba9876543210"),
    ("ssid", ""),                     # 真实网关确实会下发空值
    ("nasip", "00112233445566778899aabbccddeeff"),
    ("mac", "aabbccddeeff00112233445566778899"),
    ("t", "wireless-v2"),
    ("url", "deadbeef" * 8),
]


def _fake_service_url() -> str:
    return FAKE_GW + "/eportal/index.jsp?" + urlencode(FAKE_TOKENS)


def _fake_redirect() -> str:
    return FAKE_CAS + "/login?" + urlencode({"service": _fake_service_url()})


class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []
        self._shown = 0

    def check(self, name: str, ok, detail: str = "") -> None:
        self.rows.append((name, bool(ok), "" if detail is None else str(detail)))

    def section(self, title: str) -> None:
        print("\n" + title)
        for name, ok, detail in self.rows[self._shown:]:
            print(("  [OK]   " if ok else "  [FAIL] ") + name +
                  ("   -> " + detail if detail else ""))
        self._shown = len(self.rows)

    @property
    def ok_count(self) -> int:
        return sum(1 for _, ok, _ in self.rows if ok)

    @property
    def total(self) -> int:
        return len(self.rows)


def run_selftest() -> int:
    log.setup("ERROR", log_file=None)
    rep = Report()

    print("=" * 70)
    print("离线自检（不联网、不需要账号，全部使用合成数据）")
    print("=" * 70)

    # ---------- 1) 密码学 ----------
    for name, ok, detail in crypto.self_test():
        rep.check(name, ok, detail)
    rep.section("【密码学】")

    # ---------- 2) 凭据保护 ----------
    from . import secrets_win
    if secrets_win.available():
        token = secrets_win.protect("sample-secret")
        rep.check("DPAPI 加密可用", bool(token), "%d 字符密文" % len(token or ""))
        rep.check("DPAPI 解密回原文", secrets_win.unprotect(token or "") == "sample-secret")
        rep.check("DPAPI 拒绝伪造密文", secrets_win.unprotect("bm90LXJlYWw=") is None)
    else:
        rep.check("DPAPI 不可用（非 Windows）", True, "已跳过")
    rep.section("【凭据保护】")

    # ---------- 3) 配置读写 ----------
    with tempfile.TemporaryDirectory() as td:
        path = pathlib.Path(td) / "config.json"
        cfg = config_mod.Config(username=FAKE_USER, ssid=FAKE_SSID)
        cfg.set_password(FAKE_PWD)
        cfg.save(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        rep.check("配置文件不落明文密码",
                  FAKE_PWD not in path.read_text(encoding="utf-8"),
                  "字段：%s" % sorted(k for k in raw if "password" in k))
        back = config_mod.load(path)
        rep.check("配置可完整读回", back.username == FAKE_USER and back.ssid == FAKE_SSID)
        rep.check("密码可解回", back.password == FAKE_PWD)
    rep.section("【配置读写】")

    # ---------- 4) netsh 解析 ----------
    cn = _parse_block("""
    名称                   : WLAN
    状态                   : 已连接
    SSID                   : %s
    信号                   : 90%%
    """ % FAKE_SSID)
    en = _parse_block("""
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : OtherNet
    Signal                 : 78%
    """)
    rep.check("netsh 中文输出解析",
              cn.get("state") == "已连接" and cn.get("ssid") == FAKE_SSID,
              "state=%s ssid=%s" % (cn.get("state"), cn.get("ssid")))
    rep.check("netsh 英文输出解析",
              en.get("state") == "connected" and en.get("ssid") == "OtherNet")
    rep.section("【无线解析】")

    # ---------- 5) L1 门户解析 ----------
    cfg = config_mod.Config(cas_base=FAKE_CAS)
    info = portal.parse_portal_url(_fake_redirect(), cfg)
    rep.check("能从跳转地址反解出门户", info is not None)
    if info is not None:
        rep.check("service 指向门户网关", info.service_url.startswith(FAKE_GW + "/eportal/"),
                  info.service_url[:52] + "…")
        rep.check("解析出 7 个网关令牌字段",
                  set(info.query) == {k for k, _ in FAKE_TOKENS}, str(sorted(info.query)))
        rep.check("空值参数 ssid= 被保留", info.query.get("ssid") == "")
        expect = quote("&".join("%s=%s" % kv for kv in FAKE_TOKENS), safe="")
        rep.check("queryString 为整串百分号编码",
                  info.query_string == expect, info.query_string[:56] + "…")
        rep.check("保留空值片段 %26ssid%3D%26", "%26ssid%3D%26" in info.query_string)
        rep.check("能自行拼出登录页地址",
                  info.cas_login_url.startswith(FAKE_CAS + "/login?service="))

        changed = portal.refresh(info, _fake_service_url().replace(
            "0123456789abcdef0123456789abcdef", "f" * 32))
        rep.check("网关令牌刷新生效", changed and info.query["wlanuserip"] == "f" * 32)

    rep.check("非门户地址被安全拒绝",
              portal.parse_portal_url("http://example.com/foo", config_mod.Config()) is None)
    rep.section("【L1 门户解析】")

    # ---------- 6) L2 登录表单 ----------
    page = cas.CasPage(
        url=_fake_redirect(),
        croypto=base64.b64encode(b"0123456789abcdef").decode(),
        flowkey="00000000-0000-0000-0000-000000000000_ZXlKaGJHY2lPaUpJVXpVeE1p",
        current_login_type="UsernamePassword",
    )
    form = cas.build_form(config_mod.Config(username=FAKE_USER, password=FAKE_PWD), page)
    rep.check("字段与顺序固定", tuple(form.keys()) == cas.FORM_FIELDS, str(list(form.keys())))
    rep.check("含 type / _eventId / geolocation / captcha_code",
              form["type"] == "UsernamePassword" and form["_eventId"] == "submit"
              and form["geolocation"] == "" and form["captcha_code"] == "")
    rep.check("croypto 取自登录页且为 16 字节密钥",
              form["croypto"] == page.croypto
              and len(base64.b64decode(form["croypto"])) == 16)
    recovered = crypto.aes_decrypt_b64(form["croypto"], form["password"])
    rep.check("口令解密后为纯密码（无时间戳、无逗号）",
              recovered == FAKE_PWD and "," not in recovered, repr(recovered))
    rep.check("口令密文恰为 1 个 AES 块（24 字符）",
              len(form["password"]) == 24, "%d 字符" % len(form["password"]))
    rep.check("captcha_payload 解密为 '{}'",
              crypto.aes_decrypt_b64(form["croypto"], form["captcha_payload"]) == "{}")
    rep.check("提交路径不带 service 查询串", cas.LOGIN_PAGE_PATH == "/login")
    rep.section("【L2 登录表单】")

    # ---------- 7) L3 网关认证 ----------
    dry = config_mod.Config(username=FAKE_USER, service=FAKE_SERVICE,
                            eportal_base=FAKE_GW, dry_run=True)
    fresh = portal.parse_portal_url(_fake_redirect(), dry)
    res = eportal.authorize(portal.new_session(dry), dry, fresh, FAKE_USER)
    sent = res.sent
    rep.check("body 含 userId 与 casauthofservicecheck",
              sent.get("userId") == FAKE_USER
              and sent.get("flag") == "casauthofservicecheck")
    rep.check("queryString 为整串百分号编码",
              "wlanuserip%3D" in sent.get("queryString", "")
              and "%26" in sent.get("queryString", ""))
    rep.check("service 单次 URL 编码", sent.get("service") == quote(FAKE_SERVICE),
              sent.get("service", ""))
    rep.check("passwordEncrypt=false 且运营商密码为空",
              sent.get("passwordEncrypt") == "false" and sent.get("operatorPwd") == "")
    rep.check("dry-run 不产生真实请求", res.ok and "dry-run" in res.message)
    prepared = requests.Request("POST", FAKE_GW + "/eportal/InterFace.do", data=sent).prepare()
    body = prepared.body
    if isinstance(body, bytes):
        body = body.decode()
    rep.check("表单编码后 queryString 二次转义（%25）", "queryString=wlanuserip%253D" in body,
              body[:60] + "…")
    rep.section("【L3 网关认证】")

    # ---------- 8) 服务/运营商列表解析 ----------
    rep.check("解析 {services:[{serviceName}]}",
              [s["name"] for s in eportal._extract_services(
                  {"services": [{"serviceName": "校园网", "serviceId": "1"},
                                {"serviceName": "某运营商", "serviceId": "2"}]})]
              == ["校园网", "某运营商"])
    rep.check("解析嵌套 {data:{services:[...]}}",
              [s["name"] for s in eportal._extract_services(
                  {"data": {"services": [{"name": "校园网"}]}})] == ["校园网"])
    rep.check("解析字符串数组",
              [s["name"] for s in eportal._extract_services({"serviceList": ["A", "B"]})]
              == ["A", "B"])
    rep.check("解析裸数组",
              [s["name"] for s in eportal._extract_services([{"showName": "X"}])] == ["X"])
    rep.check("无法识别时返回空列表",
              eportal._extract_services({"foo": 1}) == []
              and eportal._extract_services(None) == [])
    rep.check("解析 JSONP 包装", eportal.parse_payload('cb({"result":"success"})') is not None)
    rep.section("【服务列表解析】")

    # ---------- 9) 日志落盘位置 ----------
    cands = log.log_dir_candidates()
    rep.check("日志目录候选非空", bool(cands), " → ".join(str(c) for c in cands[:3]))
    rep.check("日志目录含程序目录下的 logs",
              any(str(c).endswith("logs") for c in cands))
    rep.section("【日志位置】")

    # ---------- 10) 默认值与配置 ----------
    rep.check("服务/运营商有默认值", config_mod.DEFAULT_SERVICE == "移动互联网服务",
              config_mod.DEFAULT_SERVICE)
    rep.check("常见服务候选不少于 4 个", len(config_mod.COMMON_SERVICES) >= 4,
              "、".join(config_mod.COMMON_SERVICES))
    rep.check("新建配置默认带上服务名",
              config_mod.Config().service == config_mod.DEFAULT_SERVICE)
    rep.section("【默认值】")

    # ---------- 11) 计划任务模板 ----------
    xml = taskschd._TASK_XML.format(
        description="d", eventlog=taskschd._EVENT_LOG, delay="PT5S",
        command="app.exe", arguments="--silent", workdir="%WORKDIR%")
    rep.check("计划任务 XML 可渲染且含 Event ID 10000",
              "EventID=10000" in xml and "NetworkProfile" in xml)
    rep.check("任务名固定", bool(taskschd.TASK_NAME))
    rep.section("【计划任务】")

    print("\n" + "=" * 70)
    print("通过 %d/%d" % (rep.ok_count, rep.total))
    print("=" * 70)
    return 0 if rep.ok_count == rep.total else 1


if __name__ == "__main__":
    raise SystemExit(run_selftest())
