"""
ARTEX CyberGuard — Session Authentication & Auth-Gate Detection
Supports CSRF-aware HTML form login, JSON login, raw Cookie/Header injection,
and strict auth-barrier detection so gated apps are never mislabeled SECURE.
"""

from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
from html.parser import HTMLParser
import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
import urllib.parse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
CSRF_TOKEN_NAMES = ("user_token", "csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken", "xsrf", "authenticity_token")
LOGIN_PATH_KEYWORDS = ("login", "signin", "sign-in", "auth", "logon")


class _LoginFormParser(HTMLParser):
    """Extracts form actions, methods, hidden tokens, and input names."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.forms: List[Dict[str, Any]] = []
        self._curr: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs):
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            action = ad.get("action", "")
            self._curr = {
                "action": urllib.parse.urljoin(self.base_url, action) if action else self.base_url,
                "method": ad.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "button", "select", "textarea") and self._curr is not None:
            name = ad.get("name", "")
            itype = ad.get("type", "text").lower() if tag == "input" else tag
            if name:
                self._curr["inputs"].append({"name": name, "type": itype, "value": ad.get("value", "")})

    def handle_endtag(self, tag: str):
        if tag == "form" and self._curr is not None:
            self.forms.append(self._curr)
            self._curr = None


def parse_custom_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """Converts CLI 'Key: Value' headers into a clean dictionary."""
    out: Dict[str, str] = {}
    for item in header_list or []:
        if ":" in item:
            k, v = item.split(":", 1)
            k_clean = k.strip()
            if k_clean and k_clean.lower() != "host":
                out[k_clean] = v.strip()
    return out


def extract_jwts_from_text(text: str) -> List[str]:
    """Returns deduplicated JWT strings observed in headers, cookies, or JSON."""
    if not text:
        return []
    seen = set()
    tokens: List[str] = []
    for m in JWT_RE.findall(text):
        if m not in seen:
            seen.add(m)
            tokens.append(m)
    return tokens


def build_scoped_opener(validate_fn: Optional[Callable[[str], Any]] = None, cookie_jar: Optional[CookieJar] = None):
    """Builds a urllib opener that validates every redirect against scope rules."""

    class _SafeRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if validate_fn:
                validate_fn(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    handlers = [_SafeRedirect()]
    if cookie_jar is not None:
        handlers.append(HTTPCookieProcessor(cookie_jar))
    return build_opener(*handlers)


def _merge_cookie_header(existing: str, jar: CookieJar) -> str:
    merged: Dict[str, str] = {}
    for c in jar:
        merged[c.name] = c.value
    if existing:
        sc = SimpleCookie()
        sc.load(existing)
        for k, m in sc.items():
            merged[k] = m.value
    return "; ".join(f"{k}={v}" for k, v in merged.items())


def _is_login_page(url: str, body: str) -> bool:
    path_low = urllib.parse.urlparse(url).path.lower()
    if any(k in path_low for k in LOGIN_PATH_KEYWORDS):
        return True
    low = (body or "").lower()
    return 'type="password"' in low or "type='password'" in low


def _cookie_domain_matches(cookie_domain: str, target_host: str) -> bool:
    if not cookie_domain or not target_host:
        return True
    cd = cookie_domain.lstrip(".").lower()
    th = target_host.lower()
    return th == cd or th.endswith("." + cd) or cd in ("127.0.0.1", "localhost") and th in ("127.0.0.1", "localhost")


def load_playwright_storage_state(storage_state_path: str, target_url: str) -> Dict[str, Any]:
    """
    Loads a Playwright storageState JSON file (cookies + origin localStorage) for SSO/2FA bypass.
    Returns matching cookies, cookie_header, local_storage dict, bearer candidate, and extracted JWTs.
    """
    if not storage_state_path or not os.path.exists(storage_state_path):
        raise FileNotFoundError(f"Playwright storageState file not found: {storage_state_path}")

    with open(storage_state_path, "r", encoding="utf-8-sig") as fh:
        state = json.load(fh)
    if not isinstance(state, dict):
        raise ValueError("Invalid storageState JSON: expected top-level object with 'cookies'/'origins'.")

    parsed_t = urllib.parse.urlparse(target_url)
    target_host = (parsed_t.hostname or "").lower()
    now_ts = time.time()

    matching_cookies: List[Dict[str, Any]] = []
    cookie_pairs: Dict[str, str] = {}
    for c in state.get("cookies") or []:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name") or "").strip()
        val = c.get("value")
        if not name or val is None:
            continue
        exp = c.get("expires", -1)
        try:
            if isinstance(exp, (int, float)) and exp > 0 and exp < now_ts:
                continue
        except Exception:
            pass
        dom = str(c.get("domain") or "")
        if dom and not _cookie_domain_matches(dom, target_host):
            continue
        matching_cookies.append({
            "name": name,
            "value": str(val),
            "domain": dom or target_host,
            "path": str(c.get("path") or "/"),
            "httpOnly": bool(c.get("httpOnly", False)),
            "secure": bool(c.get("secure", False)),
        })
        cookie_pairs[name] = str(val)

    local_storage: Dict[str, str] = {}
    bearer_candidate = ""
    captured_jwts: List[str] = []
    for orig_entry in state.get("origins") or []:
        if not isinstance(orig_entry, dict):
            continue
        orig_url = str(orig_entry.get("origin") or "")
        orig_host = (urllib.parse.urlparse(orig_url).hostname or "").lower()
        if orig_host and not _cookie_domain_matches(orig_host, target_host):
            continue
        for item in orig_entry.get("localStorage") or []:
            if not isinstance(item, dict) or "name" not in item or "value" not in item:
                continue
            k = str(item["name"])
            v = str(item["value"])
            local_storage[k] = v
            for tok in extract_jwts_from_text(v):
                if tok not in captured_jwts:
                    captured_jwts.append(tok)
            if not bearer_candidate and any(h in k.lower() for h in ("token", "jwt", "access_token", "id_token", "auth")) and len(v) >= 12:
                # Extract clean raw token if wrapped in quotes or Bearer prefix
                clean_v = v.strip().strip('"')
                if clean_v.lower().startswith("bearer "):
                    clean_v = clean_v.split(" ", 1)[1].strip()
                if "." in clean_v and len(clean_v.split(".")) == 3:
                    bearer_candidate = clean_v

    cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookie_pairs.items())
    for tok in extract_jwts_from_text(cookie_hdr):
        if tok not in captured_jwts:
            captured_jwts.append(tok)

    return {
        "cookies": matching_cookies,
        "cookie_header": cookie_hdr,
        "local_storage": local_storage,
        "bearer_candidate": bearer_candidate,
        "captured_jwts": captured_jwts,
    }


def authenticate_session(
    target_url: str,
    cookie_str: str = "",
    extra_headers: Optional[Dict[str, str]] = None,
    login_url: str = "",
    username: str = "",
    password: str = "",
    storage_state_path: str = "",
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """
    Establishes and verifies an authenticated HTTP session context.
    Supports Playwright storageState JSON (SSO/2FA), pre-supplied Cookie/Header auth,
    and CSRF-aware HTML form or JSON login.
    """
    headers: Dict[str, str] = dict(extra_headers or {})
    cookie_header = cookie_str.strip() or headers.pop("Cookie", headers.pop("cookie", "")).strip()
    captured_jwts: List[str] = []
    storage_state_ctx: Optional[Dict[str, Any]] = None

    if storage_state_path:
        loaded_ss = load_playwright_storage_state(storage_state_path, target_url)
        storage_state_ctx = {
            "cookies": loaded_ss["cookies"],
            "local_storage": loaded_ss["local_storage"],
        }
        for tok in loaded_ss["captured_jwts"]:
            if tok not in captured_jwts:
                captured_jwts.append(tok)
        if loaded_ss["cookie_header"]:
            if cookie_header:
                # Preserve explicit --cookie precedence over storageState
                sc_ss = SimpleCookie()
                sc_ss.load(loaded_ss["cookie_header"])
                sc_ov = SimpleCookie()
                sc_ov.load(cookie_header)
                merged_map = {k: m.value for k, m in sc_ss.items()}
                merged_map.update({k: m.value for k, m in sc_ov.items()})
                cookie_header = "; ".join(f"{k}={v}" for k, v in merged_map.items())
            else:
                cookie_header = loaded_ss["cookie_header"]
        if loaded_ss["bearer_candidate"] and not any(k.lower() == "authorization" for k in headers):
            headers["Authorization"] = f"Bearer {loaded_ss['bearer_candidate']}"

    for src in (cookie_header, json.dumps(headers)):
        for tok in extract_jwts_from_text(src):
            if tok not in captured_jwts:
                captured_jwts.append(tok)

    if not (username and password) and (cookie_header or any(k.lower() == "authorization" for k in headers) or (storage_state_ctx and (storage_state_ctx["cookies"] or storage_state_ctx["local_storage"]))):
        return {
            "authenticated": True,
            "method": "storage_state" if storage_state_ctx else "header_or_cookie",
            "cookie_header": cookie_header,
            "extra_headers": headers,
            "captured_jwts": captured_jwts,
            "login_url": login_url or "",
            "storage_state": storage_state_ctx,
            "error": None,
        }

    if not (username and password):
        return {
            "authenticated": False,
            "method": "none",
            "cookie_header": "",
            "extra_headers": headers,
            "captured_jwts": captured_jwts,
            "login_url": login_url or "",
            "storage_state": None,
            "error": None,
        }

    jar = CookieJar()
    opener = build_scoped_opener(validate_fn=validate_fn, cookie_jar=jar)
    parsed_t = urllib.parse.urlparse(target_url)
    origin = f"{parsed_t.scheme}://{parsed_t.netloc}"

    cand_urls = []
    if login_url:
        cand_urls.append(login_url if login_url.startswith("http") else urllib.parse.urljoin(target_url, login_url))
    else:
        cand_urls.append(target_url)
        base_path = parsed_t.path.rstrip("/")
        if base_path:
            cand_urls.append(f"{origin}{base_path}/login")
        cand_urls.extend([f"{origin}/login", f"{origin}/login.php"])

    last_error = "Unable to authenticate against discovered login endpoints"
    for cand in cand_urls:
        try:
            if validate_fn:
                validate_fn(cand)
            get_req = Request(cand, headers={**headers, "User-Agent": "ARTEX-CyberGuard-Auth/3.0"})
            with opener.open(get_req, timeout=8) as r_get:
                landing_url = r_get.geturl()
                landing_body = r_get.read(65536).decode("utf-8", errors="replace")

            parser = _LoginFormParser(landing_url)
            parser.feed(landing_body)
            login_form = None
            for f in parser.forms:
                f_names = [i["name"].lower() for i in f["inputs"]]
                if any(i["type"] == "password" for i in f["inputs"]) or any(k in f_names for k in ("username", "user", "email", "login")):
                    login_form = f
                    break

            if login_form:
                action_url = login_form["action"]
                if validate_fn:
                    validate_fn(action_url)
                payload: Dict[str, str] = {}
                for inp in login_form["inputs"]:
                    nm = inp["name"]
                    low = nm.lower()
                    if inp["type"] == "hidden" or any(t in low for t in CSRF_TOKEN_NAMES):
                        payload[nm] = inp["value"]
                    elif inp["type"] == "password" or any(p in low for p in ("pass", "pwd")):
                        payload[nm] = password
                    elif any(u in low for u in ("user", "email", "login", "account")):
                        payload[nm] = username
                    elif inp["type"] in ("submit", "button") and inp["value"]:
                        payload[nm] = inp["value"]
                    elif inp["value"]:
                        payload[nm] = inp["value"]
                encoded = urllib.parse.urlencode(payload).encode("utf-8")
                post_req = Request(
                    action_url,
                    data=encoded,
                    headers={**headers, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ARTEX-CyberGuard-Auth/3.0"},
                )
            else:
                if validate_fn:
                    validate_fn(cand)
                post_req = Request(
                    cand,
                    data=json.dumps({"username": username, "email": username, "password": password}).encode("utf-8"),
                    headers={**headers, "Content-Type": "application/json", "User-Agent": "ARTEX-CyberGuard-Auth/3.0"},
                )

            try:
                with opener.open(post_req, timeout=8) as r_post:
                    p_status = r_post.status
                    p_url = r_post.geturl()
                    p_body = r_post.read(32768).decode("utf-8", errors="replace")
            except HTTPError as he:
                p_status = he.code
                p_url = cand
                p_body = he.read(8192).decode("utf-8", errors="replace")

            merged_cookie = _merge_cookie_header(cookie_header, jar)
            for tok in extract_jwts_from_text(p_body + " " + merged_cookie):
                if tok not in captured_jwts:
                    captured_jwts.append(tok)

            low_body = p_body.lower()
            explicit_fail = any(err in low_body for err in ("login failed", "invalid credentials", "incorrect username", "bad credentials", "unauthorized"))
            bounced_to_login = _is_login_page(p_url, p_body) and not any(m in low_body for m in ("logout", "sign out", "welcome to damn vulnerable"))

            bearer_token = ""
            try:
                jbody = json.loads(p_body)
                if isinstance(jbody, dict):
                    bearer_token = str(jbody.get("token") or jbody.get("access_token") or (jbody.get("authentication") or {}).get("token") or "")
            except Exception:
                pass
            if bearer_token and not any(k.lower() == "authorization" for k in headers):
                headers["Authorization"] = f"Bearer {bearer_token}"

            if p_status in (200, 302, 303) and (merged_cookie or bearer_token) and not explicit_fail and not bounced_to_login:
                return {
                    "authenticated": True,
                    "method": "form_login" if login_form else "json_login",
                    "cookie_header": merged_cookie,
                    "extra_headers": headers,
                    "captured_jwts": captured_jwts,
                    "login_url": cand,
                    "post_login_url": p_url,
                    "error": None,
                }
            last_error = f"Login attempt at {cand} returned HTTP {p_status} without leaving auth gate"
        except Exception as ex:
            last_error = str(ex)

    return {
        "authenticated": False,
        "method": "failed",
        "cookie_header": cookie_header,
        "extra_headers": headers,
        "captured_jwts": captured_jwts,
        "login_url": login_url or "",
        "error": last_error,
    }


def detect_auth_gate(
    target_url: str,
    landing_url: str,
    discovered_endpoints: List[str],
    discovered_forms: List[Dict[str, Any]],
    authenticated: bool,
) -> Tuple[bool, str]:
    """
    Determines whether crawling stopped at an authentication wall.
    Prevents reporting SECURE when only pre-auth login/registration forms were reachable.
    """
    if authenticated:
        return False, ""

    target_path = urllib.parse.urlparse(target_url).path.rstrip("/") or "/"
    landing_path = urllib.parse.urlparse(landing_url).path.rstrip("/") or "/"

    redirected_to_login = (landing_path != target_path) and any(k in landing_path.lower() for k in LOGIN_PATH_KEYWORDS)
    non_auth_forms = []
    login_forms = []
    for f in discovered_forms:
        action_path = urllib.parse.urlparse(f.get("action", "")).path.lower()
        input_names = [i.get("name", "").lower() for i in f.get("inputs", [])]
        has_pwd = any(i.get("type") == "password" for i in f.get("inputs", []))
        if has_pwd or any(k in action_path for k in LOGIN_PATH_KEYWORDS + ("register", "signup")):
            login_forms.append(action_path)
        elif input_names:
            non_auth_forms.append(action_path)

    non_trivial_eps = [
        ep for ep in discovered_endpoints
        if not any(k in ep.lower() for k in LOGIN_PATH_KEYWORDS + ("register", "registr", "signup", "setup", "password-reset", "about", "css", "js", "favicon", "start.mvc", "welcome"))
        and ep not in ("/", target_path)
    ]

    if redirected_to_login and not non_auth_forms:
        return True, f"Target redirected to authentication gate ({landing_path}); application interior requires credentials."
    if login_forms and not non_auth_forms and len(non_trivial_eps) == 0:
        return True, f"Discovered surface is gated behind login/registration forms ({', '.join(sorted(set(login_forms)))}); inner routes unreached."
    return False, ""
