"""配置：读写 config.json，口令用 Windows DPAPI 加密。

**不含任何学校专属的默认值**：认证域名与网关地址留空，
由 `portal.autodetect()` 在连上校园网后自动识别，或在向导里手动填写。
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import asdict, dataclass, field

from . import app_root, log, secrets_win

ROOT = app_root()
CONFIG_FILE = ROOT / "config.json"

# 协议层的默认值（属于厂商产品路径，与具体学校无关）
DEFAULT_EPORTAL_INDEX = "/eportal/index.jsp"
DEFAULT_EPORTAL_INTERFACE = "/eportal/InterFace.do"
DEFAULT_PROBE_URL = "http://www.msftconnecttest.com/connecttest.txt"
DEFAULT_PROBE_EXPECT = "Microsoft Connect Test"

# 网关「服务/运营商」的默认值与常见候选。
# 很多学校的 eportal 同时提供校园网 + 三大运营商，必须指定其一，否则会被拒绝。
# 这里给一个最常见的默认值；自动识别不到时，用户可从下拉框里改。
DEFAULT_SERVICE = "移动互联网服务"
COMMON_SERVICES = [
    "移动互联网服务",
    "联通互联网服务",
    "电信互联网服务",
    "校园网",
]


@dataclass
class Config:
    # ---- 账号 ----
    username: str = ""
    password: str = ""            # 运行时明文（不落盘）
    password_enc: str = ""        # 落盘的 DPAPI 密文
    password_plain: str = ""      # 仅在 DPAPI 不可用时使用的退化字段

    # ---- 网络 ----
    ssid: str = ""

    # ---- 认证服务（留空 => 自动探测）----
    cas_base: str = ""
    eportal_base: str = ""
    eportal_index: str = DEFAULT_EPORTAL_INDEX
    eportal_interface: str = DEFAULT_EPORTAL_INTERFACE
    service: str = DEFAULT_SERVICE   # 运营商/服务名；网关要求必须指定时用这个默认值

    # ---- 连通性判定 ----
    probe_url: str = DEFAULT_PROBE_URL
    probe_expect: str = DEFAULT_PROBE_EXPECT
    probe_https_url: str = "https://www.baidu.com"

    # ---- 运行参数 ----
    connect_timeout: int = 25
    max_retries: int = 3
    retry_delay: int = 8
    auto_wlan_connect: bool = True
    clear_system_proxy: bool = False
    log_level: str = "INFO"

    # ---- 运行时状态（不落盘）----
    dry_run: bool = False
    force: bool = False
    extra: dict = field(default_factory=dict)

    # ---------------------------------------------------------------
    @property
    def eportal_url(self) -> str:
        if not self.eportal_base:
            return ""
        return self.eportal_base.rstrip("/") + self.eportal_index

    @property
    def interface_url(self) -> str:
        if not self.eportal_base:
            return ""
        return self.eportal_base.rstrip("/") + self.eportal_interface

    def validate(self, need_credentials: bool = True) -> list[str]:
        problems = []
        if need_credentials and not self.username:
            problems.append("尚未填写账号")
        if need_credentials and not self.password:
            problems.append("尚未填写密码")
        if not self.ssid:
            problems.append("尚未选择校园网（SSID）")
        return problems

    def ready(self) -> bool:
        """是否已具备自动认证所需的一切。"""
        return not self.validate()

    # ---------------------------------------------------------------
    def set_password(self, plain: str) -> None:
        self.password = plain
        enc = secrets_win.protect(plain)
        if enc:
            self.password_enc = enc
            self.password_plain = ""
        else:
            self.password_enc = ""
            self.password_plain = plain

    def _resolve_password(self) -> str:
        if self.password:
            return self.password
        if self.password_enc:
            got = secrets_win.unprotect(self.password_enc)
            if got:
                return got
        return self.password_plain

    def to_dict(self) -> dict:
        data = asdict(self)
        for k in ("password", "dry_run", "force", "extra"):
            data.pop(k, None)
        return data

    def save(self, path: pathlib.Path | None = None) -> pathlib.Path:
        target = path or CONFIG_FILE
        target.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
                          encoding="utf-8")
        return target


def load(path: pathlib.Path | None = None, dry_run: bool = False,
         force: bool = False) -> Config:
    target = path or CONFIG_FILE
    cfg = Config()
    if target.exists():
        try:
            data = json.loads(target.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError) as exc:
            log.get().warning("配置文件无法解析（%s），将按未配置处理", exc)
            data = {}
        known = {f for f in Config().to_dict()}
        for k, v in data.items():
            if k in known:
                setattr(cfg, k, v)
    cfg.password = cfg._resolve_password()
    cfg.dry_run = dry_run
    cfg.force = force
    return cfg


def exists(path: pathlib.Path | None = None) -> bool:
    return (path or CONFIG_FILE).exists()
