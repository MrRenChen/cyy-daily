# -*- coding: utf-8 -*-
"""
草原云 · 签到 + 每日阅读（v4 · 账号密码版）

在 草原云.py（v2 动态 code 版）基础上改造：
  1. 只保留「手机号 + 密码」登录（/member/login/memberLogin，tmencrypt 加密），
     彻底移除 code 服务 / YYB Go / 微信 code 链路
  2. 彻底移除提现（额度查询、套餐、滑块提交、相关环境变量全部删除）
  3. 设备号由 md5(手机号) 派生：同号恒定同设备，避免每次登录换设备触发风控
  4. 修复已知缺陷：
     - 纯 Python AES 的 GF(2^8) 约减缺失（0x1B 从未生效）
     - 密钥扩展在每 16 字节重复计算
     - content_info 为字符串时抛 AttributeError
     - 拿不到 task_record_id 仍计为成功
     - 文章 URL 里的 fc_token 明文打印
     - 短 token 脱敏失效
     - sleep 不可中断（停止按钮要等很久）
  5. 代理失败默认不静默回退直连（ENABLE_DIRECT_FALLBACK 默认 False，界面可开）

仅用于自己账号的自动化，违反平台用户协议，后果自负。
"""

import base64

import hashlib

import json

import math

import os

import random

import re

import secrets

import sys

import time

import traceback

import uuid

from datetime import datetime

from io import BytesIO

from typing import Any, Dict, List, Tuple

from urllib.parse import quote, urlencode

import requests

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from PIL import Image
    import numpy as np
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ---------------------------------------------------------------------------
# CA 证书引导
# 打包成单文件 exe 后，certifi 的 cacert.pem 位于 %TEMP%\_MEIxxxx 里。这个目录
# 可能被系统清理或杀毒软件中途删除，于是 requests 报
#   "Could not find a suitable TLS CA certificate bundle, invalid path: ...\certifi\cacert.pem"
# 因此启动时立刻把证书复制到 exe 同目录（或 %LOCALAPPDATA%），后续只用这个稳定副本。
# ---------------------------------------------------------------------------
def _valid_ca_file(path: str) -> bool:
    try:
        if not path or not os.path.isfile(path):
            return False
        if os.path.getsize(path) < 4096:
            return False
        with open(path, "rb") as fh:
            head = fh.read(262144)
        return b"BEGIN CERTIFICATE" in head
    except Exception:
        return False


def _ca_source_candidates() -> Tuple[List[str], str]:
    if getattr(sys, "frozen", False):
        app_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        app_dir = os.path.dirname(os.path.abspath(__file__))

    mei = getattr(sys, "_MEIPASS", "") or ""
    cands: List[str] = []
    if app_dir:
        cands.append(os.path.join(app_dir, "cacert.pem"))
    if mei:
        cands.append(os.path.join(mei, "cacert.pem"))
        cands.append(os.path.join(mei, "certifi", "cacert.pem"))
    try:
        import certifi  # type: ignore
        cands.append(certifi.where())
    except Exception:
        pass
    try:
        import ssl
        cafile = ssl.get_default_verify_paths().cafile
        if cafile:
            cands.append(cafile)
    except Exception:
        pass
    return cands, app_dir


def _install_ca_bundle() -> str:
    import shutil

    cands, app_dir = _ca_source_candidates()

    # 1) 已经放在 exe 目录的证书优先（上次留下的稳定副本）
    if app_dir:
        stable = os.path.join(app_dir, "cacert.pem")
        if _valid_ca_file(stable):
            return stable

    src = next((p for p in cands if _valid_ca_file(p)), "")
    if not src:
        return ""

    # 2) 复制到 exe 同目录；不可写则退到 %LOCALAPPDATA%\草原云4
    targets: List[str] = []
    if app_dir:
        targets.append(os.path.join(app_dir, "cacert.pem"))
    local = os.getenv("LOCALAPPDATA") or os.path.expanduser("~")
    targets.append(os.path.join(local, "草原云4", "cacert.pem"))

    for dst in targets:
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.abspath(dst) != os.path.abspath(src):
                shutil.copyfile(src, dst)
            if _valid_ca_file(dst):
                return dst
        except Exception:
            continue

    return src if _valid_ca_file(src) else ""


CA_BUNDLE = ""
try:
    CA_BUNDLE = _install_ca_bundle()
except Exception:
    CA_BUNDLE = ""

if CA_BUNDLE:
    # trust_env=False 的 session 不会读这些变量，但保留给内部其他库使用
    os.environ["REQUESTS_CA_BUNDLE"] = CA_BUNDLE
    os.environ["SSL_CERT_FILE"] = CA_BUNDLE
    os.environ["CURL_CA_BUNDLE"] = CA_BUNDLE


class CancelledError(Exception):
    """用户点了停止。"""


CANCEL_FLAG = None        # 由界面设置为 threading.Event
CYY_STATIC_PROXY = os.getenv("CYY_STATIC_PROXY", "")  # 全局兜底代理（可用环境变量注入）
CYY_ACCOUNT_PROXIES = {}  # {手机号: 代理URL}，账号级代理优先

APP_NAME = "草原云（内蒙古日报）"

APPID = "wxcf78d47051628692"

PLUSPLUS_TOKEN = os.getenv("PLUSPLUS_TOKEN", "")

PROXY_API = os.getenv("PROXY_API", "")

PROXY_TYPE = os.getenv("PROXY_TYPE", "http").lower()

CYY_READ_SECONDS = int(os.getenv("CYY_READ_SECONDS", "3") or 3)

CYY_MAX_TASKS = int(os.getenv("CYY_MAX_TASKS", "0") or 0)

CYY_NO_SIGNIN = os.getenv("CYY_NO_SIGNIN", "0") == "1"

CYY_ACCOUNT_GAP = int(os.getenv("CYY_ACCOUNT_GAP", "0") or 0)
"""账号之间间隔的基准分钟数，0 表示连跑。实际等待在 0.8~2 倍之间随机。"""

CYY_RANDOMIZE = (os.getenv("CYY_RANDOMIZE") or "1").lower() not in ("0", "false", "no")
"""随机化开关：账号间隔浮动、阅读秒数抖动、任务顺序打乱。"""

PROXY_RETRY_TIMES = 3

PROXY_VALIDATE_URL = os.getenv("PROXY_VALIDATE_URL", "https://myip.ipip.net")

PROXY_FETCH_INTERVAL = 3

ENABLE_DIRECT_FALLBACK = (os.getenv("ENABLE_DIRECT_FALLBACK") or "0").lower() not in ("0", "false", "no")
"""代理失败是否静默改直连。默认 False：宁可报错，也不要偷偷用真实 IP。"""

REQUEST_TIMEOUT = 30

CYY_BASE = "https://cyy.nmgcyy.com.cn"

CYY_API_BASE = "https://ya.iyunxh.com"

CYY_STATIC_BASE = "https://static2-ya.iyunxh.com"

CYY_H5_DOMAIN = "https://nmgrb.y-h5.iyunxh.com"

CYY_APP_ID = "nmgrb"

CYY_ACTIVITY_ID = os.getenv("CYY_ACTIVITY_ID", "11106679")

CYY_MODULE_ID = os.getenv("CYY_MODULE_ID", "41603")

CYY_SIGN_ACTIVITY_ID = int(os.getenv("CYY_SIGN_ACTIVITY_ID", "10609043"))

TENANT_INIT_URL = f"{CYY_STATIC_BASE}/api/aosbase/_auth_h5init/{CYY_APP_ID}.json"

DEVICE_DT_URL = f"{CYY_API_BASE}/api/aosbase/_auth_dt"

APPUSER_INIT_URL = f"{CYY_API_BASE}/api/aosbase/_auth_appuserinit"

SIGN_TIMES_URL = f"{CYY_API_BASE}/api/aossignin/user_times"

SIGN_URL = f"{CYY_API_BASE}/api/aossignin/ac_sub"

USER_INFO_URL = f"{CYY_API_BASE}/api/aosbase/user_info"

OPTIONP_LIST_URL = f"{CYY_API_BASE}/api/aoslearnfoot/_optionp_list"

OPTIONP_DETAIL_URL = f"{CYY_API_BASE}/api/aoslearnfoot/optionp_detail"

TASK_LIST_URL = f"{CYY_API_BASE}/api/aosbasemodule/_task_list"

TASK_CREATE_URL = f"{CYY_API_BASE}/api/aosbasemodule/task_create"

TASK_DONE_URL = f"{CYY_API_BASE}/api/aosbasemodule/task_done"

ADD_FOOTPRINT_URL = f"{CYY_BASE}/fcpublic/Memberfootprint/addfootprint"

COMPLETE_READING_URL = f"{CYY_BASE}/fcpublic/yundian/complateReading"

CAPTCHA_GET_URL = f"{CYY_API_BASE}/api/basemodule/_captcha_get"

CAPTCHA_CHECK_URL = f"{CYY_API_BASE}/api/basemodule/_captcha_check"

CAPTCHA_VERIFY_URL = f"{CYY_API_BASE}/api/aosbasemodule/intelverifcode_check"

WECHAT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 "
    "MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI "
    "MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090a13) "
    "UnifiedPCWindowsWechat(0xf2541c1a) XWEB/25297"
)

CYY_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) TMAppName/caoyuanyun "
    "TMAppName/caoyuanyun tm_language/zh-cn"
)

CYY_APP_USER_AGENT = "TMProject/4.7.0 (iPhone; iOS 17.0; Scale/3.00)"

CAPTCHA_AES_KEY = "7Pf0cfZPHy1L7PS2PfCfP8r2BGi461LG".encode()

CAPTCHA_AES_IV = "8RsVKSCH8mQ4l7cu".encode()

def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sleep(seconds: float) -> None:
    """可被 CANCEL_FLAG 立即打断的 sleep。"""
    end = time.time() + max(0.0, float(seconds))
    while True:
        if CANCEL_FLAG is not None and CANCEL_FLAG.is_set():
            raise CancelledError()
        left = end - time.time()
        if left <= 0:
            return
        time.sleep(min(0.2, left))

def account_gap_seconds() -> int:
    """账号之间要等多少秒。基准 10 分钟 -> 实际 8~20 分钟随机。"""
    if not CYY_ACCOUNT_GAP:
        return 2
    lo = max(1, int(CYY_ACCOUNT_GAP * 0.8)) * 60
    hi = max(int(CYY_ACCOUNT_GAP * 2), int(CYY_ACCOUNT_GAP * 0.8) + 1) * 60
    return random.randint(lo, hi)


def mask(value: Any) -> str:
    """脱敏：短值全打码，长值只留首尾各 3 位。"""
    value = str(value or "")
    if len(value) <= 6:
        return "*" * len(value)
    if len(value) <= 12:
        return value[:2] + "*" * (len(value) - 4) + value[-2:]
    return f"{value[:3]}***{value[-3:]}"

def json_preview(data: Any, limit: int = 800) -> str:
    try:
        return json.dumps(data, ensure_ascii=False)[:limit]
    except Exception:
        return str(data)[:limit]

def to_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0

def safe_data(resp: Dict[str, Any]) -> Dict[str, Any]:
    """Safely extract 'data' from an API response, handling null/missing."""
    data = resp.get("data") or {}
    return data if isinstance(data, dict) else {}

def log_title() -> None:
    print()
    print("╔" + "═" * 50 + "╗")
    print("║ 🌾 草原云 v4 · 签到 + 阅读任务（账密）     ║")
    print(f"║ 🕒 启动时间: {now_text():<32}║")
    print("╚" + "═" * 50 + "╝")

def log_account_header(index: int, total: int, server: str) -> None:
    print()
    print("┌" + "─" * 50 + "┐")
    print(f"│ 🧩 账号 {index} / {total:<37}│")
    print(f"│ 🌍 来源 {server:<40}│")
    print("└" + "─" * 50 + "┘")

def direct_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    # trust_env=False 时 requests 不会读 REQUESTS_CA_BUNDLE，必须显式指定，
    # 否则会回落到 certifi.where()（_MEIPASS 路径），临时目录被清理就报 invalid path。
    if CA_BUNDLE:
        session.verify = CA_BUNDLE
    return session

def parse_proxy_response(text: Any) -> Dict[str, Any] | None:
    if not isinstance(text, str):
        text = json.dumps(text, ensure_ascii=False)

    text = text.strip()
    if not text:
        return None

    try:
        data = json.loads(text)
        proxy_obj = None

        if isinstance(data.get("data"), list) and data["data"]:
            proxy_obj = data["data"][0]
        elif isinstance(data.get("data"), dict):
            proxy_obj = data["data"]
        elif data.get("ip") and data.get("port"):
            proxy_obj = data
        elif isinstance(data.get("result"), dict):
            proxy_obj = data["result"]

        if proxy_obj:
            host = proxy_obj.get("ip") or proxy_obj.get("host")
            port = proxy_obj.get("port")
            if host and port:
                return {
                    "host": str(host),
                    "port": int(port),
                    "username": proxy_obj.get("user") or proxy_obj.get("username") or "",
                    "password": proxy_obj.get("pass") or proxy_obj.get("password") or "",
                }
    except Exception:
        pass

    if ":" in text:
        parts = text.split(":")
        if len(parts) >= 2:
            return {
                "host": parts[0],
                "port": int(parts[1]),
                "username": parts[2] if len(parts) > 2 else "",
                "password": parts[3] if len(parts) > 3 else "",
            }

    return None

def build_proxy_dict(proxy_info: Dict[str, Any] | None) -> Dict[str, str] | None:
    if not proxy_info:
        return None

    host = proxy_info["host"]
    port = proxy_info["port"]
    username = proxy_info.get("username", "")
    password = proxy_info.get("password", "")

    auth = ""
    if username and password:
        auth = f"{quote(username)}:{quote(password)}@"

    scheme = "socks5" if PROXY_TYPE == "socks5" else "http"
    proxy_url = f"{scheme}://{auth}{host}:{port}"

    print(f"🛠️ [代理] 生成 {scheme.upper()} 代理 {host}:{port}")

    return {
        "http": proxy_url,
        "https": proxy_url,
    }

def validate_proxy(proxies: Dict[str, str] | None) -> Tuple[bool, str]:
    if not proxies:
        return False, ""

    try:
        response = requests.get(PROXY_VALIDATE_URL, proxies=proxies, timeout=15,
                                verify=CA_BUNDLE or True)
        if response.status_code == 200:
            text = (response.text or "").strip()
            ip = ""
            try:
                ip = str(response.json().get("origin") or "").strip()
            except Exception:
                found = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
                ip = found.group(1) if found else ""
            if not ip or ip in ("None", "未知"):
                ip = "未知"
            print(f"✅ [代理] 验证通过，出口 IP: {ip}")
            return True, ip
    except Exception as exc:
        print(f"⚠️ [代理] 验证失败: {exc}")

    return False, ""

def proxy_from_url(url: str) -> Tuple[Dict[str, str] | None, str]:
    """把 socks5h://user:pass@ip:port 之类的地址转成 requests 的 proxies 字典。"""
    from urllib.parse import urlparse
    url = (url or "").strip()
    if not url:
        return None, ""
    if "://" not in url:
        url = ("socks5h://" if "@" in url else "http://") + url
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        label = f"{host}:{parsed.port}" if parsed.port else host
    except Exception:
        label = "自定义代理"
    return {"http": url, "https": url}, label


def get_valid_proxy(account_name: str) -> Tuple[Dict[str, str] | None, str]:
    # 优先级：账号专属代理 > 全局代理 > API 自动提取 > 直连
    account_proxy = (CYY_ACCOUNT_PROXIES or {}).get(account_name, "")
    if account_proxy:
        proxies, label = proxy_from_url(account_proxy)
        if proxies:
            print(f"[代理] {account_name} 使用专属代理 {label}")
            return proxies, label

    if CYY_STATIC_PROXY:
        proxies, label = proxy_from_url(CYY_STATIC_PROXY)
        if proxies:
            print(f"[代理] {account_name} 使用全局代理 {label}")
            return proxies, label

    if not PROXY_API:
        return None, ""

    print(f"🌐 [代理] {account_name} 正在获取品赞代理...")

    for index in range(1, PROXY_RETRY_TIMES + 1):
        try:
            response = direct_session().get(PROXY_API, timeout=15)
            proxy_info = parse_proxy_response(response.text)

            if not proxy_info:
                print(f"⚠️ [代理] 第 {index} 次代理解析失败")
                continue

            print(f"✅ [代理] 提取到 {proxy_info['host']}:{proxy_info['port']}")
            proxies = build_proxy_dict(proxy_info)

            ok, ip = validate_proxy(proxies)
            if ok:
                return proxies, ip

            print(f"⚠️ [代理] 第 {index} 次代理不可用")
        except Exception as exc:
            print(f"⚠️ [代理] 第 {index} 次获取代理异常: {exc}")

        if index < PROXY_RETRY_TIMES:
            sleep(2)

    print("⚠️ [代理] 获取失败，使用直连")
    return None, ""

def request_with_proxy(
    method: str,
    url: str,
    *,
    proxies: Dict[str, str] | None = None,
    server: str = "",
    **kwargs,
) -> requests.Response:
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)

    if proxies:
        if CA_BUNDLE:
            kwargs.setdefault("verify", CA_BUNDLE)
        try:
            return requests.request(method, url, proxies=proxies, **kwargs)
        except Exception as exc:
            print(f"⚠️ [代理] {server} 代理请求失败: {exc}")
            if not ENABLE_DIRECT_FALLBACK:
                raise
            print("🔁 [兜底] 切换直连重试")

    session = direct_session()
    return session.request(method, url, **kwargs)

def send_pushplus(title: str, content: str) -> None:
    if not PLUSPLUS_TOKEN:
        print("⚠️ [PushPlus] 未配置 PLUSPLUS_TOKEN，跳过推送")
        return

    try:
        requests.post(
            "https://www.pushplus.plus/send",
            json={
                "token": PLUSPLUS_TOKEN,
                "title": title,
                "content": content,
                "template": "txt",
            },
            timeout=10,
            verify=CA_BUNDLE or True,
        )
        print("✅ [PushPlus] 推送成功")
    except Exception as exc:
        print(f"❌ [PushPlus] 推送失败: {exc}")

def extract_token(data: Any) -> str | None:
    if not isinstance(data, dict):
        return None

    candidates = [
        data.get("token"),
        data.get("accessToken"),
        data.get("access_token"),
        data.get("jwt"),
    ]

    inner = data.get("data")
    if isinstance(inner, dict):
        candidates.extend([
            inner.get("token"),
            inner.get("accessToken"),
            inner.get("access_token"),
            inner.get("jwt"),
        ])

        user = inner.get("user")
        if isinstance(user, dict):
            candidates.extend([
                user.get("token"),
                user.get("accessToken"),
                user.get("access_token"),
                user.get("jwt"),
            ])

    for item in candidates:
        if item and item != "null":
            return str(item)

    return None

MEMBER_ID_KEYS = ("member_id", "memberId", "memberid", "user_id", "userId", "uid", "mid")


def _as_positive_int(value: Any) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return 0
    return num if num > 0 else 0


def _jwt_member_id(token: str) -> int:
    """有些登录 token 是 JWT，payload 里自带 member_id。"""
    try:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return 0
        seg = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg.encode()))
        for key in MEMBER_ID_KEYS:
            num = _as_positive_int(payload.get(key))
            if num:
                return num
    except Exception:
        pass
    return 0


def extract_member_id(raw_login: Any, token: str = "") -> int:
    """从登录响应里挖出 member_id。

    账密登录的 data 本身就是内层结构，code 登录却是 {data:{data:...}}，
    所以这里不能写死层级，逐层下探最多 4 层。
    """
    def search(node: Any, depth: int = 0) -> int:
        if depth > 4 or not isinstance(node, dict):
            return 0
        # 优先看 member_info / user 这类聚合对象
        for holder in ("member_info", "memberInfo", "member", "user", "userInfo"):
            sub = node.get(holder)
            if isinstance(sub, dict):
                for key in MEMBER_ID_KEYS:
                    num = _as_positive_int(sub.get(key))
                    if num:
                        return num
        # 再看当前层
        for key in MEMBER_ID_KEYS:
            num = _as_positive_int(node.get(key))
            if num:
                return num
        # 最后往下钻
        for key in ("data", "result", "info"):
            num = search(node.get(key), depth + 1)
            if num:
                return num
        return 0

    member_id = search(raw_login)
    if not member_id and token:
        member_id = _jwt_member_id(token)
    return member_id


def describe_keys(raw_login: Any, limit: int = 12) -> str:
    """登录结构对不上时，打印字段名（不含值）方便定位。"""
    if not isinstance(raw_login, dict):
        return type(raw_login).__name__
    return ",".join(list(raw_login.keys())[:limit]) or "(空)"

TM_RAND_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

TM_ENCRYPT_POST = os.getenv("CYY_TM_ENCRYPT", "0") == "1"

SENSITIVE_KEYS = {
    "token", "access_token", "app_user_token", "accesstoken", "password", "passwd",
    "openid", "unionid", "secret", "session_key", "ticket", "cookie", "jwt",
    "app_secret", "appsecret", "signature", "idcard", "phone", "mobile",
}

def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def tm_make_keys(time_diff_ms: int = 0) -> Tuple[str, str, str]:
    """返回 (tmtimestamp, tmrandomnum, tmencryptkey)"""
    ts = str(int(time.time() * 1000) + int(time_diff_ms))
    rnd = "".join(random.choice(TM_RAND_ALPHABET) for _ in range(16))
    tmk = md5(_b64(md5(ts) + rnd) + rnd)
    return ts, rnd, tmk

def tm_request_key_iv(ts: str, rnd: str) -> Tuple[bytes, bytes]:
    key = md5(_b64(ts) + md5(rnd))[:16]
    iv = md5(_b64(rnd) + md5(ts))[:16]
    return key.encode("utf-8"), iv.encode("utf-8")

def tm_response_key_iv(ts: str, rnd: str) -> Tuple[bytes, bytes]:
    key = md5(_b64(ts) + md5(ts))[:16]
    iv = md5(rnd)[:16]
    return key.encode("utf-8"), iv.encode("utf-8")

def _aes_cbc(mode: str, data: bytes, key: bytes, iv: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    op = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor() if mode == "e" \
        else Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return op.update(data) + op.finalize()

def tm_encrypt_payload(payload: Any, keys: Tuple[str, str, str] | None = None):
    """加密请求体，返回 (加密后的 body, keys)"""
    ts, rnd, tmk = keys or tm_make_keys()
    key, iv = tm_request_key_iv(ts, rnd)
    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    n = 16 - len(plain) % 16
    plain += bytes([n]) * n
    cipher = _aes_cbc("e", plain, key, iv)
    return {"tm_encrypt_data": base64.b64encode(cipher).decode("ascii")}, (ts, rnd, tmk)

def tm_decrypt_response(data: Any, ts: str, rnd: str) -> Any:
    if not isinstance(data, str) or not data:
        return data
    key, iv = tm_response_key_iv(ts, rnd)
    raw = _aes_cbc("d", base64.b64decode(data), key, iv)
    if raw:
        n = raw[-1]
        if 1 <= n <= 16 and raw[-n:] == bytes([n]) * n:
            raw = raw[:-n]
    text = raw.decode("utf-8", "replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text

def tm_header_set(keys: Tuple[str, str, str]) -> Dict[str, str]:
    ts, rnd, tmk = keys
    return {
        "tmencrypt": "1",
        "tmtimestamp": ts,
        "tmrandomnum": rnd,
        "tmencryptkey": tmk,
    }

def redact_json(data: Any, limit: int = 500) -> str:
    """脱敏预览：敏感键名打码，长串截断。用于日志和推送，避免泄露凭证。"""
    def walk(obj: Any, depth: int = 0) -> Any:
        if depth > 4:
            return "..."
        if isinstance(obj, dict):
            return {
                k: ("[隐藏]" if str(k).lower() in SENSITIVE_KEYS else walk(v, depth + 1))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [walk(x, depth + 1) for x in obj[:5]]
        if isinstance(obj, str) and len(obj) > 40:
            return obj[:8] + "…[长标识]"
        return obj

    try:
        return json.dumps(walk(data), ensure_ascii=False)[:limit]
    except Exception:
        return "<无法序列化>"

def clean_msg(exc: BaseException) -> str:
    """异常消息脱敏：去掉 URL、长串和敏感值。"""
    text = f"{type(exc).__name__}: {exc}"
    text = re.sub(r"https?://[^\s'\"<>]+", "[链接]", text)
    text = re.sub(r"[A-Za-z0-9_\-+/=]{24,}", "[长标识]", text)
    return text[:200]

def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def guid32() -> str:
    """前端 $u.guid(32,false): 32位随机字符串"""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "".join(random.choice(alphabet) for _ in range(32))

def get_aas_key(appkey: str) -> str:
    """getAASkey(appkey) = md5(偶数位 + 奇数位)"""
    if not appkey:
        return ""
    even = "".join(appkey[i] for i in range(0, len(appkey), 2))
    odd = "".join(appkey[i] for i in range(1, len(appkey), 2))
    return md5(even + odd)

def urlencode_component(value: Any) -> str:
    """前端 urlencode: encodeURIComponent 后把 !'()* 转 %XX, 空格转 +"""
    text = quote(str(value), safe="~")
    text = text.replace("!", "%21").replace("'", "%27").replace("(", "%28").replace(")", "%29") \
        .replace("*", "%2A").replace("%20", "+")
    return text

def ksort(params: Dict[str, Any]) -> Dict[str, Any]:
    return {k: params[k] for k in sorted(params.keys())}

def obj_to_query(params: Dict[str, Any], leading_qmark: bool = False) -> str:
    """前端 objToQueryParams: a=b&c=d（按 key 升序、urlencode 后的值）"""
    parts = []
    for k in sorted(params.keys()):
        parts.append(k + "=" + urlencode_component(params[k]))
    query = "&".join(parts)
    return ("?" if leading_qmark else "") + query

def make_signature(tenant: Dict[str, Any]) -> str:
    aaskey = get_aas_key(tenant.get("appkey", ""))
    nonce = guid32()
    ts = int(time.time() * 1000)
    sig = md5(tenant["appid"] + nonce + str(ts) + aaskey)
    return f"{tenant['appid']};{nonce};{ts};{sig}"

def tenant_init(server: str, proxies: Dict[str, str] | None) -> Dict[str, Any]:
    print("🏢 [租户] 获取租户配置")
    response = request_with_proxy(
        "GET",
        TENANT_INIT_URL,
        headers={
            "Access-T-Id": "2433",
            "Access-T-Id-In": "2433",
            "User-Agent": CYY_USER_AGENT,
        },
        proxies=proxies,
        server=server,
    )
    try:
        data = response.json()
    except Exception:
        raise RuntimeError("租户初始化响应非 JSON: HTTP %d" % response.status_code)
    if data.get("code") not in ("0", 0):
        raise RuntimeError("租户初始化失败: %s" % (data.get("msg") or json_preview(data, 300)))

    raw = base64.b64decode(data["data"]).decode("utf-8")
    tenant = json.loads(raw)
    print(f"✅ [租户] appid={tenant.get('appid')} t_id={tenant.get('t_id')}")
    return tenant

def fetch_device_dt(server: str, tenant: Dict[str, Any], proxies: Dict[str, str] | None) -> str:
    print("📱 [设备] 获取设备令牌 Access-Api-Dt")
    device_id = str(int(time.time() * 1000)) + str(random.randint(10 ** 8, 10 ** 9 - 1))[:9]
    response = request_with_proxy(
        "GET",
        DEVICE_DT_URL,
        headers={
            "Access-T-Id": str(tenant.get("t_id", 2433)),
            "Access-T-Id-In": str(tenant.get("t_id_in", 2433)),
            "Access-Api-Unique-Token": "1",
            "Access-Api-Dt": device_id,
            "User-Agent": CYY_USER_AGENT,
        },
        proxies=proxies,
        server=server,
    )
    try:
        data = response.json()
    except Exception:
        raise RuntimeError("获取设备令牌响应非 JSON: HTTP %d" % response.status_code)
    if data.get("code") not in ("0", 0):
        raise RuntimeError("获取设备令牌失败: %s" % (data.get("msg") or json_preview(data, 300)))

    token = data.get("data") or ""
    if len(token) < 68:
        raise RuntimeError("设备令牌异常(长度 %d)" % len(token))
    access_api_dt = token[32:68]
    print(f"✅ [设备] Access-Api-Dt: {mask(access_api_dt)}")
    return access_api_dt

def appuser_init(
    server: str,
    tenant: Dict[str, Any],
    app_user_token: str,
    proxies: Dict[str, str] | None,
) -> Tuple[str, int]:
    print("🔐 [登录] 使用 token 换 access_token")
    params = {
        "app_user_token": app_user_token,
        "appid": tenant["appid"],
        "noncestr": guid32(),
        "phone": "",
        "portrait_url": "/images/default/head.jpg",
        "timestamp": int(time.time()),
        "user_id": 0,
        "user_name": "微信用户",
        "wx_openid": "",
        "wx_unionid": "",
    }
    params = ksort(params)
    sign_src = obj_to_query(params) + "&appkey=" + tenant["appkey"]
    params["signature"] = md5(sign_src)

    headers = {
        "Access-T-Id": str(tenant.get("t_id", 2433)),
        "Access-T-Id-In": str(tenant.get("t_id_in", 2433)),
        "Access-Api-Unique-Token": "1",
        "Access-Wxclient-Type": "wx_app",
        "Access-Api-Signature": make_signature(tenant),
        "Content-Type": "application/json",
        "User-Agent": CYY_USER_AGENT,
        "Origin": CYY_H5_DOMAIN,
        "Referer": CYY_H5_DOMAIN + "/",
    }
    response = request_with_proxy(
        "POST",
        APPUSER_INIT_URL,
        headers=headers,
        json=params,
        proxies=proxies,
        server=server,
    )
    try:
        data = response.json()
    except Exception:
        raise RuntimeError("appuserinit 响应非 JSON: HTTP %d" % response.status_code)
    if data.get("code") not in ("0", 0):
        raise RuntimeError("appuserinit 失败: %s" % (data.get("msg") or json_preview(data, 300)))

    payload = data.get("data") or {}
    access_token = payload.get("access_token", "")
    info = payload.get("data") or {}
    user_id = info.get("user_id") or 0
    if not access_token:
        raise RuntimeError("未识别 access_token 字段: %s" % json_preview(data, 300))
    print(f"✅ [登录] access_token 获取成功: {mask(access_token)}")
    return access_token, user_id

def iyunxh_headers(
    tenant: Dict[str, Any],
    access_token: str,
    user_id: int,
    access_api_dt: str,
) -> Dict[str, str]:
    return {
        "Access-Token": access_token,
        "Access-User-Id": str(user_id),
        "Access-T-Id": str(tenant.get("t_id", 2433)),
        "Access-T-Id-In": str(tenant.get("t_id_in", 2433)),
        "Access-Api-Unique-Token": "1",
        "Access-Wxclient-Type": "wx_app",
        "Access-Api-Signature": make_signature(tenant),
        "Access-Api-Dt": access_api_dt,
        "Origin": CYY_H5_DOMAIN,
        "Referer": CYY_H5_DOMAIN + "/",
    }

def api_get(server: str, url: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> Dict[str, Any]:
    response = request_with_proxy(
        "GET",
        url,
        headers=headers,
        proxies=proxies,
        server=server,
    )
    try:
        return response.json()
    except Exception:
        return {
            "code": -1,
            "msg": f"JSON解析失败: {response.text[:300]}",
        }

def api_post(
    server: str,
    url: str,
    headers: Dict[str, str],
    proxies: Dict[str, str] | None,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """POST 统一出口：可选 tmencrypt 加密 + 自动解密响应。

    实测（2026-10-20）：
      · /fcpublic/*  ← 只接受明文；加密后服务端解不出来，回「code请求参数错误」
      · /system/*    ← 强制加密；明文回「解密数据失败」
    所以 CYY_TM_ENCRYPT=1 时只对非 /fcpublic/ 路径加密。默认关闭。
    """
    headers = dict(headers)
    body: Any = payload
    keys: Tuple[str, str, str] | None = None

    # 实测：/fcpublic/ 只收明文（加密后回 code请求参数错误），
    #       /system/  强制加密（明文回 解密数据失败）。按路径区分。
    if TM_ENCRYPT_POST and "/fcpublic/" not in url:
        body, keys = tm_encrypt_payload(payload)
        headers.update(tm_header_set(keys))

    response = request_with_proxy(
        "POST",
        url,
        headers=headers,
        json=body,
        proxies=proxies,
        server=server,
    )
    try:
        data = response.json()
    except Exception:
        return {
            "code": -1,
            "msg": f"JSON解析失败: {response.text[:300]}",
        }

    # 响应若被加密（tmencrypt=1），按解密规则还原
    if isinstance(data, dict) and str(data.get("tmencrypt")) == "1" and keys:
        try:
            data["data"] = tm_decrypt_response(data.get("data"), keys[0], keys[1])
        except Exception as exc:
            print(f"⚠️ [tm] 响应解密失败: {clean_msg(exc)}")
    return data

def signin_times(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> Dict[str, Any]:
    sign_headers = dict(headers)
    sign_headers["X-Requested-With"] = "com.innermongoliadaily.activity"
    url = f"{SIGN_TIMES_URL}?{urlencode({'activity_id': CYY_SIGN_ACTIVITY_ID})}"
    return api_get(server, url, sign_headers, proxies)

def signin(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> Dict[str, Any]:
    sign_headers = dict(headers)
    sign_headers["X-Requested-With"] = "com.innermongoliadaily.activity"
    return api_post(server, SIGN_URL, sign_headers, proxies, {
        "id": CYY_SIGN_ACTIVITY_ID,
        "afs_tokenid": "",
        "collect_info": "",
        "longitude": 0,
        "latitude": 0,
    })

def get_user_info(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> Dict[str, Any]:
    return api_get(server, USER_INFO_URL, headers, proxies)

def get_gold(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> int:
    resp = get_user_info(server, headers, proxies)
    if resp.get("code") in ("0", 0):
        try:
            return int(safe_data(resp).get("gold") or 0)
        except (TypeError, ValueError):
            return 0
    return 0

def get_optionp_list(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> Dict[str, Any]:
    url = f"{OPTIONP_LIST_URL}?{urlencode({'activity_id': CYY_ACTIVITY_ID})}"
    return api_get(server, url, headers, proxies)

def get_optionp_detail(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None, option_id: Any) -> Dict[str, Any]:
    url = f"{OPTIONP_DETAIL_URL}?{urlencode({'id': option_id})}"
    return api_get(server, url, headers, proxies)

def get_task_list(
    server: str,
    headers: Dict[str, str],
    proxies: Dict[str, str] | None,
    module_id: Any,
    activity_id: Any,
) -> Dict[str, Any]:
    url = f"{TASK_LIST_URL}?{urlencode({'offset': 0, 'count': 30, 'module_id': module_id, 'activity_id': activity_id})}"
    return api_get(server, url, headers, proxies)

def task_create(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None, task_id: Any) -> Dict[str, Any]:
    return api_post(server, TASK_CREATE_URL, headers, proxies, {"task_id": task_id})

def task_done(
    server: str,
    headers: Dict[str, str],
    proxies: Dict[str, str] | None,
    task_record_id: str,
    afs_tokenid: str = "",
) -> Dict[str, Any]:
    return api_post(server, TASK_DONE_URL, headers, proxies, {
        "task_record_id": task_record_id,
        "collect_info": "",
        "afs_tokenid": afs_tokenid,
        "device_token": "",
    })

def add_footprint(
    server: str,
    app_user_token: str,
    member_id: int,
    article_id: int,
    title: str,
    news_url: str,
    proxies: Dict[str, str] | None,
) -> Dict[str, Any]:
    param = {"h5url": news_url, "type": 1}
    body = {
        "app_id": "fcinformation",
        "native": 1,
        "src": "NewsI004WKDetailViewController",
        "paramStr": json.dumps(param, ensure_ascii=False),
        "title": title,
        "pic": "",
        "member_id": member_id,
        "intro": " ",
        "article_id": article_id,
        "article_type": "1",
        "wwwFolder": "wwwFolder",
    }
    # v2: 按 transcode.js 的真实规则生成 tm* 头
    # 老版本用秒级时间戳 + 随机 hex 当 tmencryptkey，与服务端算法对不上
    tm_ts, tm_rnd, tm_key = tm_make_keys()
    headers = {
        "token": app_user_token,
        "User-Agent": CYY_APP_USER_AGENT,
        "tmencrypt": "1",
        "tmencryptkey": tm_key,
        "tmencryptkeynew": tm_key,
        "tmrandomnum": tm_rnd,
        "tmrandomnumnew": tm_rnd,
        "tmtimestamp": tm_ts,
        "tmtimestampnew": tm_ts,
    }
    return api_post(server, ADD_FOOTPRINT_URL, headers, proxies, body)

def complete_reading(
    server: str,
    app_user_token: str,
    member_id: int,
    article_id: int,
    proxies: Dict[str, str] | None,
) -> Dict[str, Any]:
    headers = {
        "token": app_user_token,
        "guid": str(uuid.uuid4()),
        "User-Agent": CYY_APP_USER_AGENT,
    }
    return api_post(server, COMPLETE_READING_URL, headers, proxies, {
        "content_id": article_id,
        "member_id": member_id,
    })

def parse_rule(rule: Any) -> Dict[str, Any]:
    """解析任务 rule -> {news_url, article_id, title, action}"""
    try:
        rule = rule if isinstance(rule, dict) else json.loads(rule or "{}")
    except Exception:
        return {}
    news_url = (rule.get("news_id") or "").strip()
    match = re.search(r"ArticleDetail(\d+)", news_url)
    article_id = int(match.group(1)) if match else 0
    content_info = rule.get("content_info")
    if isinstance(content_info, str):
        try:
            content_info = json.loads(content_info)
        except Exception:
            content_info = {}
    title = (content_info or {}).get("title") if isinstance(content_info, dict) else ""
    title = title or ""
    return {"news_url": news_url, "article_id": article_id,
            "title": title, "action": rule.get("action") or ""}

def simulate_read(rule: Any, app_user_token: str, member_id: int, read_seconds: int = 0) -> None:
    """访问任务文章 H5 页（触发页面 JS 倒计时上报），再 sleep read_seconds"""
    try:
        rule = rule if isinstance(rule, dict) else json.loads(rule)
    except Exception:
        return
    news_id = (rule.get("news_id") or "").strip()
    action = rule.get("action") or ""
    match = re.search(r"second=(\d+)", news_id)
    rule_need = int(match.group(1)) if match else 0
    # 界面填的秒数只当下限：任务链接里写了几秒就必须读够几秒，
    # 否则服务端在 task_done 复核时直接判「未完成该任务」。
    base = max(read_seconds or 0, rule_need) or 60
    if CYY_RANDOMIZE:
        # 只往上浮动 0~12 秒：既不会低于任务要求，也不会每条都一样长
        need = base + random.randint(0, 12)
    else:
        need = base
    if news_id and news_id.startswith("http"):
        try:
            base = news_id.split("#")[0]
            fragment = news_id.split("#")[1] if "#" in news_id else ""
            if fragment:
                frag = re.sub(r"(ArticleDetail/\d+)/(undefined|\d+)",
                              r"\1/%s" % member_id, fragment)
                if "fc_token=" not in frag:
                    sep = "&" if "?" in frag else "?"
                    frag += f"{sep}fc_token={app_user_token or ''}"
                full_url = base + "#" + frag
            else:
                full_url = base
            direct_session().get(full_url, headers={
                "User-Agent": CYY_APP_USER_AGENT,
                "Accept-Language": "zh-Hans-CN;q=1",
            }, timeout=15)
            safe_url = re.sub(r"(fc_token=)[^&#]+", r"\1***", full_url)
            print(f"  [*] 已打开文章页: {safe_url[:120]}")
        except Exception as exc:
            print(f"  [warn] 文章页访问失败: {exc}")
    print(f"  [*] 阅读文章 {need} 秒 (action={action})...")
    step = 10
    while need > 0:
        sleep(min(step, need))
        need -= step
        print(f"  [*] 已阅读, 剩余约 {max(need, 0)} 秒")

def pure_aes_cbc_encrypt(plaintext: bytes) -> bytes:
    """纯 python AES-256-CBC（无 pycryptodome 时兜底，兼容 CryptoJS）"""
    SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ]
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    def _xtime(a):
        # 左移后若溢出 8 位，必须按 AES 规范模 0x11B 约减
        a <<= 1
        return (a ^ 0x11B) & 0xFF if a & 0x100 else a

    def _expand_key(key):
        nk, nr = 8, 14
        w = [[key[4*i+j] for j in range(4)] for i in range(nk)]
        for i in range(nk, 4*(nr+1)):
            temp = w[i-1][:]
            if i % nk == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i//nk - 1]
            elif nk > 6 and i % nk == 4:
                temp = [SBOX[b] for b in temp]
            w.append([w[i-nk][j] ^ temp[j] for j in range(4)])
        return w

    def _block_encrypt(block, w):
        state = [[block[4*j+i] for j in range(4)] for i in range(4)]
        def ark(r):
            for i in range(4):
                for j in range(4):
                    state[i][j] ^= w[r*4+j][i]
        def sb():
            for i in range(4):
                for j in range(4):
                    state[i][j] = SBOX[state[i][j]]
        def sr():
            for i in range(1, 4):
                state[i] = state[i][i:] + state[i][:i]
        def mc():
            for j in range(4):
                col = [state[i][j] for i in range(4)]
                state[0][j] = _xtime(col[0]) ^ (_xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3]
                state[1][j] = col[0] ^ _xtime(col[1]) ^ (_xtime(col[2]) ^ col[2]) ^ col[3]
                state[2][j] = col[0] ^ col[1] ^ _xtime(col[2]) ^ (_xtime(col[3]) ^ col[3])
                state[3][j] = (_xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ _xtime(col[3])
        ark(0)
        for rnd in range(1, 14):
            sb(); sr(); mc(); ark(rnd)
        sb(); sr(); ark(14)
        return b"".join(bytes([state[i][j] for j in range(4)]) for i in range(4))

    pad_len = 16 - (len(plaintext) % 16)
    data = plaintext + bytes([pad_len]) * pad_len
    w = _expand_key(CAPTCHA_AES_KEY)
    out = b""
    iv = CAPTCHA_AES_IV
    for i in range(0, len(data), 16):
        block = bytes(data[i+j] ^ iv[j] for j in range(16))
        enc = _block_encrypt(block, w)
        out += enc
        iv = enc
    return out

def solve_captcha(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> str:
    """自动滑块验证码求解：返回 afs_tokenid
    逆向自前端 yundian-slide-captcha 组件：
      _captcha_get -> 拼图缺口识别 -> _captcha_check -> intelverifcode_check
    """
    if not HAS_PIL:
        raise RuntimeError("需要 pillow/numpy 才能自动求解滑块(pip install pillow numpy)")

    def _aes_cbc_encrypt(plaintext: bytes) -> bytes:
        if HAS_CRYPTO:
            cipher = AES.new(CAPTCHA_AES_KEY, AES.MODE_CBC, CAPTCHA_AES_IV)
            return cipher.encrypt(pad(plaintext, 16))
        return pure_aes_cbc_encrypt(plaintext)

    def _aes_encrypt_b64(obj: Any, url_quote: bool = False) -> str:
        text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        value = base64.b64encode(_aes_cbc_encrypt(text)).decode()
        return quote(value) if url_quote else value

    def _random_string(n: int) -> str:
        alphabet = "twxyz2345678"
        return "".join(random.choice(alphabet) for _ in range(n))

    def _find_gap(bg_img: Any, block_img: Any) -> Tuple[int, int, Any]:
        """返回缺口左上角 x（自然像素坐标）：NCC 模板匹配 + 亮度低谷"""
        bg = np.asarray(bg_img.convert("RGB"), dtype=np.float64)
        rgba = np.asarray(block_img.convert("RGBA"), dtype=np.float64)
        alpha = rgba[:, :, 3:4] / 255.0
        piece = rgba[:, :, :3]
        bw = rgba.shape[1]
        h, width = bg.shape[0], bg.shape[1]
        scores = []
        for x in range(0, width - bw + 1):
            win = bg[:, x:x + bw]
            m = alpha
            num = (m * piece * win).sum()
            d1 = (m * piece * piece).sum()
            d2 = (m * win * win).sum()
            scores.append(num / math.sqrt(d1 * d2) if d1 > 0 and d2 > 0 else 0.0)
        x_max = int(np.argmax(scores))
        colmean = bg.mean(axis=(0, 2))
        from numpy.lib.stride_tricks import sliding_window_view
        sw = sliding_window_view(colmean, min(bw, 20)).mean(axis=1)
        x_bright = int(np.argmin(sw))
        return x_max, x_bright, scores

    def _build_track(target_x: float, width: int) -> List[Dict[str, Any]]:
        """生成类人手拖拽轨迹：每 100ms 采样，长度 <= 100"""
        track = []
        x = 0.0
        accel = random.uniform(1.4, 1.8)
        decel_start = target_x * 0.72
        while x < target_x - 0.5 and len(track) < 99:
            if x < decel_start:
                v = accel + random.uniform(-0.2, 0.2)
                x += v * 1.0
            else:
                x += max(0.2, accel * (target_x - x) / (target_x - decel_start + 1)) + random.uniform(-0.15, 0.15)
            track.append({"x": round(x, 1), "y": 0, "time": 100})
        if track:
            track[-1]["x"] = target_x
        else:
            track.append({"x": target_x, "y": 0, "time": 100})
        return track

    referer = CYY_H5_DOMAIN + "/module-study/pass-detail/pass-detail"
    now = int(time.time())
    params = {"once": _random_string(10), "referer": referer,
              "timestamp": now, "type": "1"}
    sig = _aes_encrypt_b64(params, url_quote=True)
    url = CAPTCHA_GET_URL + "?" + urlencode({
        "once": params["once"], "referer": referer,
        "timestamp": now, "type": "1", "signature": sig})

    get_resp = api_get(server, url, headers, proxies)
    if get_resp.get("code") not in ("0", 0):
        raise RuntimeError("获取验证码失败: %s" % json_preview(get_resp, 300))
    data = get_resp.get("data") or {}
    token = data.get("token")
    bg_url = data.get("background")
    blk_url = data.get("block")
    if not token or not bg_url or not blk_url:
        raise RuntimeError("验证码数据不完整: %s" % json_preview(data, 300))

    session = direct_session()
    bg = Image.open(BytesIO(session.get(bg_url, timeout=30).content))
    blk = Image.open(BytesIO(session.get(blk_url, timeout=30).content))

    x_max, x_bright, scores = _find_gap(bg, blk)
    bg_w = bg.width
    candidates = [("ncc_max", x_max), ("bright_min", x_bright),
                  ("ncc_min", int(np.argmin(scores)))]
    for name, x in candidates:
        if x + 60 > bg_w - 1:
            continue
        print(f"    [*] 尝试 {name}: x={x}")
        track = _build_track(x, bg_w)
        payload = {"x": x, "width": bg_w, "track": track}
        enc = _aes_encrypt_b64(payload)
        check_body = {"token": token, "data": enc,
                      "referer": referer, "type": "1"}
        check_resp = api_post(server, CAPTCHA_CHECK_URL, headers, proxies, check_body)
        if check_resp.get("code") in ("0", 0) and safe_data(check_resp).get("result"):
            validate = safe_data(check_resp).get("token") or ""
            print(f"    [OK] 滑块验证通过, validate={mask(validate)}")
            verify_resp = api_post(server, CAPTCHA_VERIFY_URL, headers, proxies, {
                "validate": validate, "verif_type": 3,
                "afs_uuid": "", "source": "yundian"})
            if verify_resp.get("code") in ("0", 0):
                tokenid = safe_data(verify_resp).get("tokenid") or ""
                print(f"    [OK] 智能验证通过, afs_tokenid={mask(tokenid)}")
                return str(tokenid)
            print(f"    [warn] intelverifcode_check: {json_preview(verify_resp, 200)}")
        else:
            print(f"    [x] {check_resp.get('msg') or json_preview(check_resp, 200)}")
    raise RuntimeError("全部候选位置验证失败")

def do_signin(server: str, headers: Dict[str, str], proxies: Dict[str, str] | None) -> str:
    if CYY_NO_SIGNIN:
        print("⏭️ [签到] 已配置 CYY_NO_SIGNIN=1，跳过签到")
        return "跳过签到"

    try:
        times_resp = signin_times(server, headers, proxies)
        if times_resp.get("code") in ("0", 0):
            remain = safe_data(times_resp).get("day_remain")
            print(f"📅 [签到] 签到次数查询: day_remain={remain}")
            if not remain:
                print("📅 [签到] day_remain=0 (可能已签), 尝试签到...")
    except Exception as exc:
        print(f"⚠️ [签到] 签到次数查询失败(可忽略): {exc}")

    sign_resp = signin(server, headers, proxies)
    if sign_resp.get("code") in ("0", 0):
        data = safe_data(sign_resp)
        msg = f"签到成功! 金币+{data.get('gold')} 积分+{data.get('integral')} (第{data.get('times')}次)"
        print(f"✅ [签到] {msg}")
        return msg
    if str(sign_resp.get("code")) == "1007" or "已签到" in str(sign_resp.get("msg", "")):
        msg = "今日已签到"
        print(f"📅 [签到] {msg}")
        return msg
    msg = sign_resp.get("msg") or sign_resp.get("message") or "签到失败"
    print(f"⚠️ [签到] {msg}")
    return msg

DUP_HINTS = ("重复数据", "已经存在", "已存在", "重复提交", "已打卡", "已完成", "重复")


def _is_dup_msg(msg: Any) -> bool:
    """服务端说「已经有这条记录了」。对打卡和阅读上报来说，这等于已经就绪。"""
    text = str(msg or "")
    return any(hint in text for hint in DUP_HINTS)


def do_tasks(
    server: str,
    tenant: Dict[str, Any],
    app_user_token: str,
    access_api_dt: str,
    headers: Dict[str, str],
    proxies: Dict[str, str] | None,
    member_id: int,
) -> str:
    if not member_id:
        print("❌ [任务] member_id 为空，打卡和阅读上报都会被服务端拒绝（member_id不能为空）")
        print("   → 这是登录响应解析问题，先看上面的登录字段提示")
        return "缺少 member_id（任务无法提交）"

    opt_resp = get_optionp_list(server, headers, proxies)
    if opt_resp.get("code") not in ("0", 0):
        print(f"⚠️ [任务] 获取任务活动失败: {opt_resp.get('msg') or json_preview(opt_resp, 300)}")
        return "获取任务活动失败"

    opts = opt_resp.get("data") or []
    if not isinstance(opts, list) or not opts:
        print("⚠️ [任务] 当前没有进行中的任务活动")
        return "无任务活动"

    opt = opts[0]
    opt_id = opt.get("id")
    module_id = opt.get("m_id") or CYY_MODULE_ID
    print(f"🎯 [任务] 任务活动: {opt.get('title')} "
          f"(option_id={opt_id}, 任务数={opt.get('task_num')})")

    try:
        detail_resp = get_optionp_detail(server, headers, proxies, opt_id)
        if detail_resp.get("code") in ("0", 0):
            detail = safe_data(detail_resp)
            done_n = detail.get("user_done_num") or 0
            undone_n = detail.get("user_undone_num") or 0
            print(f"📊 [任务] 今日已完成 {done_n}/{done_n + undone_n}")
    except Exception as exc:
        print(f"⚠️ [任务] 任务详情查询失败(可忽略): {exc}")

    tasks_resp = get_task_list(server, headers, proxies, module_id, opt_id)
    if tasks_resp.get("code") not in ("0", 0):
        print(f"⚠️ [任务] 获取任务列表失败: {tasks_resp.get('msg') or json_preview(tasks_resp, 300)}")
        return "获取任务列表失败"

    tasks = tasks_resp.get("data") or []
    if not isinstance(tasks, list):
        return "任务列表为空"
    undone = [t for t in tasks if not t.get("user_done")]
    print(f"📋 [任务] 共 {len(tasks)} 个任务, 未完成 {len(undone)} 个")
    if not undone:
        print("✅ [任务] 今日任务已全部完成, 收工")
        return "今日任务已全部完成"

    # 先打乱再截断，这样「任务上限」截下来的也是随机的几条
    pool = list(undone)
    if CYY_RANDOMIZE:
        random.shuffle(pool)
        print("🔀 [任务] 顺序已随机打乱")
    limit = CYY_MAX_TASKS or len(pool)
    queue = pool[:limit]
    done_count = 0
    for idx, task in enumerate(queue, 1):
        task_id = task.get("id")
        title = task.get("title") or ""
        print(f"\n[+] 任务 {idx}/{len(queue)} (#{task_id}): {title}")
        try:
            rule = task.get("rule") or {}
            if isinstance(rule, str):
                rule = json.loads(rule)
        except Exception:
            rule = {}

        # 1. 创建任务
        record_id = ""
        try:
            created = task_create(server, headers, proxies, task_id)
            record_id = safe_data(created).get("task_record_id") or ""
            print(f"  任务记录: {record_id}")
        except Exception as exc:
            print(f"⚠️ [任务] 任务创建失败: {exc}")
            continue

        # 2. 阅读足迹打卡
        info = parse_rule(rule)
        footprint_ok = False
        if info.get("article_id"):
            try:
                footprint = add_footprint(server, app_user_token, member_id,
                                          info["article_id"], info.get("title") or title,
                                          info.get("news_url", ""), proxies)
                if str(footprint.get("code")) in ("200", "0"):
                    footprint_ok = True
                    print(f"  打卡成功 footprint_id={safe_data(footprint).get('footprint_id') or '-'}")
                elif _is_dup_msg(footprint.get("msg")):
                    # 今天已经给这篇文章打过卡，服务端只是拒绝重复写入。
                    # 足记本来就该存在，这不是错误，继续走阅读上报。
                    footprint_ok = True
                    print("  该文章今日已有足迹（重复数据），跳过打卡直接阅读")
                else:
                    print(f"  [x] 打卡失败: {footprint.get('msg') or json_preview(footprint, 200)}")
            except Exception as exc:
                print(f"  [x] 打卡异常: {exc}")
        else:
            print("  [!] 该任务 rule 里没有文章 ID，可能不是阅读类任务")

        # 3. 模拟阅读
        simulate_read(rule, app_user_token, member_id, CYY_READ_SECONDS)

        # 4. 上报阅读完成（60 秒倒计时信号）
        reading_ok = False
        if info.get("article_id"):
            try:
                reading_resp = complete_reading(server, app_user_token, member_id, info["article_id"], proxies)
                if str(reading_resp.get("code")) in ("200", "0"):
                    reading_ok = True
                    print("  阅读完成上报成功")
                elif _is_dup_msg(reading_resp.get("msg")):
                    reading_ok = True
                    print("  阅读记录已存在（重复数据），继续提交")
                else:
                    print(f"  [x] 阅读完成上报失败: "
                          f"{reading_resp.get('msg') or json_preview(reading_resp, 200)}")
            except Exception as exc:
                print(f"  [x] 阅读完成上报异常: {exc}")
            if not reading_ok:
                # 上报没成功，task_done 必然回「未完成该任务」，
                # 再解一次滑块纯属白费，还多一次风控暴露。
                print("  [!] 阅读未上报成功，跳过该任务的提交")
                continue

        # 5. 刷新 access_token 后一次提交（服务端限制每个 access_token 仅支持一枚滑块验证码）
        if not record_id:
            print("  [!] 未拿到任务记录，跳过提交（不计入成功）")
            continue

        print("  [*] 刷新 access_token, 获取本任务滑块验证码")
        try:
            access_token, user_id = appuser_init(server, tenant, app_user_token, proxies)
            fresh_headers = iyunxh_headers(tenant, access_token, user_id, access_api_dt)
        except Exception as exc:
            print(f"⚠️ [任务] 刷新 access_token 失败: {exc}")
            continue

        try:
            tokenid = solve_captcha(server, fresh_headers, proxies)
        except Exception as exc:
            print(f"⚠️ [任务] 自动破解失败: {exc}")
            tokenid = ""

        if not tokenid:
            print("⚠️ [任务] 自动验证失败, 跳过该任务")
            continue

        done_resp = task_done(server, fresh_headers, proxies, record_id, tokenid)
        done_msg = str(done_resp.get("msg") or "")
        if done_resp.get("code") in ("0", 0):
            option = safe_data(done_resp).get("option") or {}
            print(f"  [OK] 完成任务! 奖励: {option.get('goods_title') or option.get('title') or '-'}")
            done_count += 1
        elif "已完成" in done_msg and "未完成" not in done_msg:
            # 之前那次已经把这条做完了，只是列表缓存没刷新
            print(f"  [OK] 该任务此前已完成: {done_msg}")
            done_count += 1
        else:
            print(f"⚠️ [任务] 任务完成失败: {done_msg or json_preview(done_resp, 300)}")

    print(f"\n✅ [任务] 完成 {done_count}/{len(queue)} 个任务")

    # 闭环校验：接口返回成功 != 服务端真记账。
    # 活动换期后旧 activity_id 会「壳还在、任务空」，task_done 照样返回 0，
    # 但 user_undone_num 一动不动 —— 这里复核一次，别让脚本假装成功。
    if done_count:
        print("🔍 [校验] 复核服务端记账情况 ...")
        try:
            check = get_optionp_list(server, headers, proxies)
            for it in (check.get("data") or []):
                if it.get("id") != opt_id:
                    continue
                left = it.get("user_undone_num")
                total = it.get("task_num")
                print(f"   服务端未完成 {left}/{total}（本次提交 {done_count} 个）")
                try:
                    if left is not None and int(left) >= int(total or 0):
                        print("   ⚠️ 接口全部返回成功，但服务端一个都没记账")
                        print("   → 活动大概率已结束或换期，提交无效；请更新 CYY_ACTIVITY_ID")
                        return f"提交 {done_count} 个但服务端未记账（活动可能已结束）"
                except (TypeError, ValueError):
                    pass
                break
        except Exception as exc:
            print(f"   复核失败(可忽略): {clean_msg(exc)}")

    return f"完成 {done_count} 个任务"

def build_notify(results: List[Dict[str, Any]]) -> str:
    success_count = sum(1 for item in results if item["success"])
    fail_count = len(results) - success_count

    content = f"""🌾 草原云自动签到 + 每日阅读任务结果

━━━━━━━━━━━━━━━━━━━━
🏁 总结：{success_count} 成功 / {fail_count} 失败
🕒 时间：{now_text()}
━━━━━━━━━━━━━━━━━━━━
"""

    for idx, res in enumerate(results, 1):
        icon = "✅" if res["success"] else "❌"

        content += f"""
🧩 账号 {idx}
🌍 账号：{mask(res.get("phone") or res.get("server") or "-")}
🌐 代理：{res["proxyStatus"]}
📡 出口IP：{res["proxyIp"]}
🔐 Token：{res["token"]}
📝 签到：{res["signMsg"]}
📚 任务：{res["tasksMsg"]}
💰 金币：{res["goldMsg"]}
{icon} 结果：{"成功" if res["success"] else "失败"}
"""

        if not res["success"]:
            content += f"❌ 原因：{res['error']}\n"

        content += "━━━━━━━━━━━━━━━━━━━━\n"

    return content


# ==================== 账号密码登录（v4 新增） ====================
PASSWORD_LOGIN_URL = "https://cyy.nmgcyy.com.cn/member/login/memberLogin"

# 站点固定值：来自 App 抓包，state=2 表示账号密码登录
LOGIN_STATE = 2
LOGIN_SITE_CODE = "00000000000000000000000000000000"
LOGIN_CHANNEL = "Default"


def device_identity(account: str) -> Tuple[str, str, str]:
    """由手机号派生 (device_num, device_no, mac_no)。

    同一个号永远是同一台「设备」，换号即换设备——比每次随机更像真机。
    """
    seed = (account or "").strip()
    return (
        md5(seed + "|cyy|device")[:16],
        md5(seed + "|cyy|no")[:16],
        md5(seed + "|cyy|mac").upper(),
    )


def login_by_password(
    account: str,
    password: str,
    proxies: Dict[str, str] | None = None,
) -> Tuple[str | None, Dict[str, Any] | None]:
    """手机号 + 密码登录，返回 (token, raw_login_data)。"""
    account = (account or "").strip()
    if not account or not password:
        print("❌ [登录] 账号或密码为空")
        return None, None

    print(f"🔐 [登录] 手机号 + 密码: {mask(account)}")
    device_num, device_no, mac_no = device_identity(account)
    login_data = {
        "mobile": account,
        "state": LOGIN_STATE,
        "site_code": LOGIN_SITE_CODE,
        "code": "",
        "password": password,
        "channel_sources": LOGIN_CHANNEL,
        "device_num": device_num,
        "device_no": device_no,
        "imei_no": "",
        "mac_no": mac_no,
    }

    keys = tm_make_keys()
    body, keys = tm_encrypt_payload(login_data, keys)

    headers = {
        "Host": "cyy.nmgcyy.com.cn",
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/3.12.13",
    }
    headers.update(tm_header_set(keys))

    try:
        response = request_with_proxy(
            "POST", PASSWORD_LOGIN_URL,
            headers=headers, json=body, proxies=proxies, server="登录",
        )
    except Exception as exc:
        print(f"❌ [登录] 请求异常: {clean_msg(exc)}")
        return None, None

    try:
        resp_json = response.json()
    except Exception:
        print(f"❌ [登录] 响应非 JSON: HTTP {response.status_code}")
        return None, None

    try:
        if isinstance(resp_json, dict) and str(resp_json.get("tmencrypt")) == "1":
            resp_json["data"] = tm_decrypt_response(resp_json.get("data"), keys[0], keys[1])
    except Exception as exc:
        print(f"❌ [登录] 响应解密失败: {clean_msg(exc)}")
        return None, None

    code = resp_json.get("code") if isinstance(resp_json, dict) else None
    if str(code) not in ("200", "0"):
        msg = (resp_json.get("msg") if isinstance(resp_json, dict) else "") or ""
        hint = ""
        if str(code) == "299" or "299" in str(msg):
            hint = "  <- 今日密码错误次数已用尽，明天再试，别再重试"
        print(f"❌ [登录] 登录失败: code={code} msg={msg}{hint}")
        return None, None

    data = resp_json.get("data") or {}
    token = extract_token(data)
    if not token:
        print(f"❌ [登录] 未识别 token 字段: {redact_json(data, 300)}")
        return None, None

    print(f"✅ [登录] token 获取成功: {mask(token)}")
    return token, data


# ==================== 单账号流程（v4 重写） ====================
def run_account(index: int, total: int, phone: str, password: str) -> Dict[str, Any]:
    account = (phone or "").strip()
    result: Dict[str, Any] = {
        "phone": account,
        "success": False,
        "proxyStatus": "未使用代理",
        "proxyIp": "-",
        "token": "-",
        "signMsg": "-",
        "tasksMsg": "-",
        "goldMsg": "-",
        "error": "",
    }

    log_account_header(index, total, mask(account))

    if not account or not password:
        result["error"] = "账号或密码为空"
        print(f"❌ [账号] {result['error']}")
        return result

    proxies, proxy_ip = get_valid_proxy(account)
    result["proxyStatus"] = "使用代理" if proxies else "使用直连"
    result["proxyIp"] = proxy_ip or "-"

    delay = random.randint(2, 6)
    print(f"⏳ [延迟] 启动延迟 {delay}s")
    sleep(delay)

    token, raw_login = login_by_password(account, password, proxies)
    if not token:
        result["error"] = "登录失败"
        return result

    result["token"] = mask(token)
    member_id = extract_member_id(raw_login, token)
    if not member_id:
        print(f"ℹ️ [账号] 登录响应里没有 member_id（顶层字段: {describe_keys(raw_login)}）")
        print("   改用 access_token 会话里的 user_id")

    try:
        tenant = tenant_init("", proxies)
        access_api_dt = fetch_device_dt("", tenant, proxies)
        access_token, user_id = appuser_init("", tenant, token, proxies)
        if not member_id and user_id:
            member_id = int(user_id)
            print(f"✅ [账号] member_id 取自会话: {member_id}")
        headers = iyunxh_headers(tenant, access_token, user_id, access_api_dt)

        # member_id 三路兜底：登录响应 > 会话 user_id > user_info 接口
        # 少了它，打卡和阅读上报都会被拒（member_id不能为空），任务必然失败。
        if not member_id:
            try:
                info_resp = get_user_info("", headers, proxies)
                if info_resp.get("code") in ("0", 0):
                    member_id = extract_member_id(info_resp)
                    if member_id:
                        print(f"✅ [账号] member_id 取自 user_info: {member_id}")
                else:
                    print(f"⚠️ [账号] user_info 返回: {info_resp.get('msg') or ''}")
            except Exception as exc:
                print(f"⚠️ [账号] user_info 查询失败: {clean_msg(exc)}")

        if not member_id:
            print("❌ [账号] 三处都拿不到 member_id，任务无法提交（会出现 member_id不能为空）")
            result["error"] = "无法确定 member_id"
            return result

        result["signMsg"] = do_signin("", headers, proxies)
        result["tasksMsg"] = do_tasks("", tenant, token, access_api_dt, headers, proxies, member_id)

        gold = get_gold("", headers, proxies)
        result["goldMsg"] = str(gold)
        print(f"💰 [金币] 当前金币: {gold}")

        result["success"] = True
    except CancelledError:
        result["error"] = "已手动停止"
        print("⏹ [账号] 已手动停止")
    except Exception as exc:
        result["error"] = clean_msg(exc)
        print(f"❌ [账号] 执行失败: {clean_msg(exc)}")

    return result


# ==================== 自检（不登录） ====================
def run_selfcheck() -> None:
    print("=" * 56)
    print(" v4 自检：加密往返 / 设备号 / 租户配置 / 任务列表")
    print("=" * 56)
    ok = True

    print(f"\n[0/4] CA 证书: {CA_BUNDLE or '未找到（可能报 invalid path）'}")

    print("\n[1/4] tmencrypt 加密往返")
    try:
        sample = {"mobile": "13800138000", "state": 2, "password": "test"}
        keys = tm_make_keys()
        body, keys = tm_encrypt_payload(sample, keys)
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa
        dec = _aes_cbc(
            "d", base64.b64decode(body["tm_encrypt_data"]),
            *tm_request_key_iv(keys[0], keys[1])
        )
        dec = dec[:-dec[-1]]
        print(f"   明文密文往返: {'OK' if dec.startswith(b'{') else 'FAIL'}")
    except Exception as exc:
        ok = False
        print(f"   FAIL: {clean_msg(exc)}")

    print("\n[2/4] 设备号派生")
    a = device_identity("13800138000")
    b = device_identity("13800138000")
    c = device_identity("13900139000")
    print(f"   device_num={a[0]} mac={a[2][:12]}...")
    print(f"   同号一致: {a == b}  异号不同: {a != c}")
    ok = ok and a == b and a != c

    print("\n[3/4] 租户配置")
    try:
        tenant = tenant_init("", None)
        print(f"   appkey={mask(tenant.get('appkey'))} t_id={tenant.get('t_id')} "
              f"domain={tenant.get('domain') or '-'}")
    except Exception as exc:
        ok = False
        print(f"   FAIL: {clean_msg(exc)}")

    print("\n[4/4] 任务活动列表（不需要登录）")
    try:
        headers = {
            "User-Agent": CYY_USER_AGENT,
            "Referer": f"{CYY_H5_DOMAIN}/",
        }
        resp = direct_session().get(
            f"{OPTIONP_LIST_URL}?activity_id={CYY_ACTIVITY_ID}",
            headers=headers, timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        opts = data.get("data") or []
        print(f"   code={data.get('code')} 活动数={len(opts) if isinstance(opts, list) else 0}")
    except Exception as exc:
        ok = False
        print(f"   FAIL: {clean_msg(exc)}")

    print("\n" + "=" * 56)
    print(" 自检结果: " + ("全部通过，可以正式运行" if ok else "存在失败项，请先排查"))
    print("=" * 56)


# ==================== 命令行入口 ====================
def load_accounts_file(path: str) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    if not path or not os.path.exists(path):
        return items
    for raw in open(path, encoding="utf-8", errors="replace"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("#", ",", "|", " "):
            if sep in line:
                phone, _, pwd = line.partition(sep)
                items.append((phone.strip(), pwd.strip()))
                break
    return items


def parse_accounts_env(text: str) -> List[Tuple[str, str]]:
    items: List[Tuple[str, str]] = []
    for chunk in re.split(r"[;\n]+", text or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        for sep in ("#", ":", ",", "|"):
            if sep in chunk:
                phone, _, pwd = chunk.partition(sep)
                items.append((phone.strip(), pwd.strip()))
                break
    return items


def main() -> None:
    if "--check" in sys.argv:
        run_selfcheck()
        return

    accounts: List[Tuple[str, str]] = []
    arg_accounts = os.getenv("CYY_ACCOUNTS", "")
    if arg_accounts:
        accounts = parse_accounts_env(arg_accounts)
    if not accounts:
        for candidate in ("accounts.txt", os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.txt")):
            accounts = load_accounts_file(candidate)
            if accounts:
                break
    if not accounts:
        print("❌ [主程序] 没有账号。请在 accounts.txt 里写 `手机号#密码`（每行一个），")
        print("   或设置环境变量 CYY_ACCOUNTS='手机号#密码;手机号#密码'")
        return

    log_title()
    results = []
    total = len(accounts)
    for idx, (phone, pwd) in enumerate(accounts, 1):
        try:
            results.append(run_account(idx, total, phone, pwd))
        except CancelledError:
            break
        except Exception as exc:
            print(f"❌ [主程序] {clean_msg(exc)}")
            results.append({"phone": phone, "success": False, "error": clean_msg(exc),
                            "proxyStatus": "-", "proxyIp": "-", "token": "-",
                            "signMsg": "-", "tasksMsg": "-", "goldMsg": "-"})
        if idx < total:
            gap = account_gap_seconds()
            print(f"⏳ [间隔] 等待 {gap // 60} 分 {gap % 60} 秒后处理下一个账号")
            sleep(gap)

    success = sum(1 for r in results if r["success"])
    print("\n" + "=" * 56)
    print(f" 🏁 完成：{success} 成功 / {len(results) - success} 失败")
    print("=" * 56)
    send_pushplus("草原云任务结果", build_notify(results))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹ 已中断")
