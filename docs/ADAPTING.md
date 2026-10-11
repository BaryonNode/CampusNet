# 适配其他学校的校园网

代码里的协议层是**厂商通用**的，不含任何学校专属的域名或 IP。
但不同学校的认证系统差别很大，本文说明如何判断、以及要改哪里。

---

## 一、先判断你的学校属于哪一类

| 系统 | 特征 | 本项目支持情况 |
|---|---|---|
| 统一身份认证 **金智 LinkID** + 门户网关 **eportal** | 登录页有 `#login-croypto`、`#login-page-flowkey`；网关有 `InterFace.do` | ✅ **开箱即用**（本项目的目标场景） |
| 门户网关 eportal，但用本地账号密码（不走统一认证） | 网关有 `InterFace.do`，登录表单直接收账号密码 | 🟡 需改 `cas.py`（跳过统一认证） |
| Dr.COM / 城市热点 | 认证地址形如 `http://x.x.x.x:801/eportal/`，参数为 `DDDDD`、`upass` 等 | 🟡 需新写一个认证器 |
| 锐捷 / 深澜 等 | 各自的 JSONP 或 JSON 接口 | 🟡 需新写一个认证器 |
| 802.1X / WPA-Enterprise | 连接时直接弹证书或账号密码 | ❌ 不适用（那属于链路层认证） |

**最快的判断方法**：连上校园网、打开浏览器跳到认证页，按 `F12` 看登录请求长什么样。

---

## 二、要改哪里

| 文件 | 职责 | 换学校时要不要改 |
|---|---|---|
| `campusnet/wlan.py` | 无线关联 | ❌ 不用改 |
| `campusnet/portal.py` | 捕获门户、自动识别域名与网关 | ❌ 一般不用改（识别逻辑是通用的） |
| `campusnet/verify.py` | 外网连通性判定 | ❌ 不用改 |
| `campusnet/crypto.py` | CSRF 与 AES | 🟡 换认证系统时要改 |
| `campusnet/cas.py` | **统一身份认证登录** | 🟡 换认证系统时要改 |
| `campusnet/eportal.py` | **门户网关认证** | 🟡 换网关时要改 |
| `campusnet/runner.py` | 编排 | ❌ 不用改 |

---

## 三、动手前先抓包

1. 连上校园网，触发认证页
2. 开发者工具 → Network → **勾选 `Preserve log`**
3. 完整走一遍认证
4. 找到那条**登录请求**，右键 → **Copy as cURL**

有了它，下面三件事都能确定：

- 请求发到哪个 URL（注意：**查询串要不要带**？）
- `Content-Type` 是 `form-urlencoded` 还是 `application/json`
- **字段名清单**（这是最容易出错的地方——少一个字段服务端就可能直接报错）

> ⚠️ 抓包内容里含凭据。分享或提交前，把 `password`、`croypto` 之类的值换成 `XXX`。

---

## 四、改 `cas.py`（换统一身份认证）

把 `build_form()` 里的字段换成你抓到的那些即可，其余逻辑不用动：

```python
def build_form(cfg, page):
    return {
        "username": cfg.username,
        # ... 按你抓到的字段名与顺序填写
        "password": crypto.aes_encrypt_b64(page.croypto, cfg.password),
    }
```

要点：

- **提交 URL 是否带查询串**：有的系统要求带 `?service=...`，有的必须不带（本项目实测的系统属于后者）。
  看抓包里的 `Request URL` 原样照抄。
- **口令明文的格式**：可能是纯密码，也可能是 `密码,时间戳`，还可能带盐。
  **判断技巧**：如果密文是 16 字节（Base64 24 字符），明文必然 ≤15 字节 —— 说明没有附加时间戳。
- **`type` / `_eventId` 之类的字段**：很多系统靠它们决定"这是不是一次登录提交"，
  少一个就可能被静默忽略（返回登录页但没有任何错误提示）。

若你的系统不用统一身份认证，直接在 `runner.authenticate_once()` 里跳过 L2 即可。

---

## 五、改 `eportal.py`（换门户网关）

- **接口路径与方法名**：`InterFace.do?method=loginOfCas` 换成你抓到的
- **字段名**：`userId` / `flag` / `service` / `queryString` 等按抓包改
- **服务/运营商**：很多学校的网关同时提供校园网 + 三大运营商，**必须指定一个**
  （否则报 `服务不能为空`）。本项目默认值是 `移动互联网服务`，
  在 `campusnet/config.py` 的 `DEFAULT_SERVICE` / `COMMON_SERVICES` 里改；
  也可以让用户自己在向导下拉框里选。
  `InterFace.do?method=pageInfo` + `method=getServices` 可自动列出服务，
  但各校接口差异较大，取不到时靠上面的默认值兜底。
- **`queryString` 的编码层级**：这一项最容易错。
  它通常是**整条查询串再做一次百分号编码**（`=` → `%3D`、`&` → `%26`），
  而不是 `urlencode` 那种保留分隔符的形式。用抓包对照即可确认。
- **成功判据**：本项目把 `result == "success"` 或 `ret_code == 2`（已在线）视为成功。
  如果你的系统返回别的字段，改 `authorize()` 末尾那几行。

---

## 六、其他系统的参考做法

很多校园网网关的认证接口非常直白，例如形如：

```
GET http://<网关>:801/eportal/?c=Portal&a=login
        &user_account=<账号>&user_password=<密码>&wlan_user_ip=<本机内网IP>
```

这类系统只需要：

1. 用 UDP socket 探出**通往网关的那张网卡的出口 IP**
2. 按抓到的参数名拼一个 GET 请求

可以仿照 `campusnet/eportal.py` 新写一个认证器，并在 `runner.authenticate_once()` 里替换调用。

---

## 七、验证

改完先跑离线自检（用的是合成数据，能挡住大部分低级错误）：

```bat
python connect.py --selftest
```

再演练一遍，确认发出去的请求和抓包一致：

```bat
python connect.py --dry-run -v
```

最后实跑：

```bat
python connect.py -v
```

如果失败，`logs/campusnet.log` 会告诉你卡在哪一层。
