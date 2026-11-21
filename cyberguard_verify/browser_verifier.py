"""Headless Chromium browser verifier for Reflected, DOM, and Stored XSS proof."""

import glob
import json
import logging
import os
import secrets
from typing import Any, Dict, List, Optional
import urllib.parse
from urllib.request import Request

from .config import PLAYWRIGHT_SERVICE_URL
from .guardrails import get_safe_opener, validate_target

logger = logging.getLogger("cyberguard-verify")


def _find_chromium_executable() -> Optional[str]:
    """Discovers locally installed Playwright Chromium or Edge browser binary on host OS."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidates = sorted(
            glob.glob(os.path.join(local_app, "ms-playwright", "chromium_headless_shell-*", "*", "*.exe"))
            + glob.glob(os.path.join(local_app, "ms-playwright", "chromium-*", "*", "chrome.exe")),
            reverse=True,
        )
        if candidates:
            return candidates[0]
    for win_edge in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ):
        if os.path.exists(win_edge):
            return win_edge
    return None


def _launch_browser(playwright_obj):
    kwargs = {
        "headless": True,
        "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    }
    try:
        return playwright_obj.chromium.launch(**kwargs)
    except Exception:
        exe = _find_chromium_executable()
        if exe:
            return playwright_obj.chromium.launch(executable_path=exe, **kwargs)
        raise


def _apply_session(context, target_url: str, session_ctx: Optional[Dict[str, Any]]) -> None:
    if not session_ctx:
        return
    cookies: List[Dict[str, Any]] = []
    cookie_raw = str(session_ctx.get("cookie_header") or "").strip()
    if cookie_raw:
        from http.cookies import SimpleCookie
        sc = SimpleCookie()
        sc.load(cookie_raw)
        cookies.extend([{"name": k, "value": m.value, "url": target_url} for k, m in sc.items()])

    storage_state = session_ctx.get("storage_state") or {}
    if isinstance(storage_state, dict):
        for c in storage_state.get("cookies") or []:
            if isinstance(c, dict) and c.get("name") and c.get("value") is not None:
                cookies.append({"name": str(c["name"]), "value": str(c["value"]), "url": target_url})
        ls_map = storage_state.get("local_storage") or {}
        if isinstance(ls_map, dict) and ls_map:
            parsed_u = urllib.parse.urlparse(target_url)
            origin_clean = f"{parsed_u.scheme}://{parsed_u.netloc}"
            ls_json = json.dumps(ls_map)
            context.add_init_script(
                f"(() => {{ if (window.location.origin === {json.dumps(origin_clean)}) {{ "
                f"const items = {ls_json}; for (const [k, v] of Object.entries(items)) {{ window.localStorage.setItem(k, String(v)); }} }} }})();"
            )

    if cookies:
        context.add_cookies(cookies)
    hdrs = {
        k: v
        for k, v in (session_ctx.get("extra_headers") or {}).items()
        if str(k).lower() not in ("host", "content-length", "cookie")
    }
    if hdrs:
        context.set_extra_http_headers(hdrs)


class BrowserXSSVerifier:
    """Executes non-destructive Playwright checks to prove JavaScript execution in the DOM."""

    BENIGN_MARKER_ID = "cg_exec_marker"
    BENIGN_DOM_ATTR = "data-cg-xss"
    BENIGN_DOM_VALUE = "confirmed_execution"
    BENIGN_CONSOLE_MSG = "CYBERGUARD_BENIGN_XSS_VERIFIED"

    @classmethod
    def get_test_payload(cls) -> str:
        return (
            f'<script id="{cls.BENIGN_MARKER_ID}">'
            f'window.__cg_executed = true;'
            f'if(document.body) document.body.setAttribute("{cls.BENIGN_DOM_ATTR}", "{cls.BENIGN_DOM_VALUE}");'
            f'console.log("{cls.BENIGN_CONSOLE_MSG}");'
            f'</script>'
        )

    @classmethod
    def _remote_verify(cls, endpoint: str, payload: Dict[str, Any], session_ctx: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        if not PLAYWRIGHT_SERVICE_URL:
            return None
        try:
            body = dict(payload)
            if (session_ctx or {}).get("storage_state"):
                body["storage_state"] = session_ctx["storage_state"]
            if (session_ctx or {}).get("workflow"):
                body["workflow"] = session_ctx["workflow"]
            url = f"{PLAYWRIGHT_SERVICE_URL.rstrip('/')}/{endpoint.lstrip('/')}"
            req = Request(url, data=json.dumps(body).encode("utf-8"), headers={"Content-Type": "application/json"})
            with get_safe_opener().open(req, timeout=15) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            logger.debug("Remote Playwright service fallback unavailable: %s", exc)
        return None

    @classmethod
    def browser_discover(cls, target_url: str, session_ctx: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Renders SPA/web pages in Chromium to capture client routes, lazy XHR APIs, and DOM inputs."""
        validate_target(target_url)
        remote = cls._remote_verify(
            "browser-discover",
            {
                "url": target_url,
                "cookie": (session_ctx or {}).get("cookie_header", ""),
                "headers": (session_ctx or {}).get("extra_headers", {}),
            },
            session_ctx=session_ctx,
        )
        if remote:
            return remote

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"available": False, "client_routes": [], "api_endpoints_observed": [], "interactive_inputs": []}

        parsed_t = urllib.parse.urlparse(target_url)
        base_origin = f"{parsed_t.scheme}://{parsed_t.netloc}"
        api_observed: List[Dict[str, Any]] = []
        client_routes = set()
        interactive_inputs: List[Dict[str, Any]] = []
        dom_forms: List[Dict[str, Any]] = []
        seen_dom_forms = set()
        final_url = target_url
        is_spa = False

        try:
            with sync_playwright() as p:
                browser = _launch_browser(p)
                context = browser.new_context(ignore_https_errors=True, service_workers="block")
                _apply_session(context, target_url, session_ctx)
                page = context.new_page()

                def on_req(req):
                    if req.resource_type in ("xhr", "fetch") and req.url.startswith(base_origin):
                        if "/socket.io" in req.url:
                            return
                        post_keys: List[str] = []
                        if req.post_data:
                            try:
                                parsed_pd = json.loads(req.post_data)
                                if isinstance(parsed_pd, dict):
                                    post_keys = [str(k) for k in parsed_pd.keys()][:15]
                            except Exception:
                                post_keys = list(urllib.parse.parse_qs(req.post_data).keys())[:15]
                        api_observed.append({"url": req.url, "method": req.method, "post_keys": post_keys})

                page.on("request", on_req)
                page.goto(target_url, timeout=12000, wait_until="networkidle")
                page.wait_for_timeout(600)

                for st in ((session_ctx or {}).get("workflow") or [])[:25]:
                    if not isinstance(st, dict):
                        continue
                    act = str(st.get("action") or "").lower()
                    sel = str(st.get("selector") or "")
                    val = str(st.get("value") or "")
                    u_st = str(st.get("url") or "")
                    t_st = min(int(st.get("timeout_ms", 4000)), 8000)
                    try:
                        if act == "goto" and u_st:
                            validate_target(u_st)
                            page.goto(u_st, timeout=t_st, wait_until="domcontentloaded")
                        elif act == "click" and sel:
                            page.locator(sel).first.click(timeout=t_st)
                        elif act == "fill" and sel:
                            page.locator(sel).first.fill(val, timeout=t_st)
                        elif act == "press" and sel and val:
                            page.locator(sel).first.press(val, timeout=t_st)
                        elif act == "wait":
                            page.wait_for_timeout(min(int(val or 500), 3000))
                        page.wait_for_timeout(200)
                    except Exception:
                        pass

                def _harvest_dom_forms():
                    try:
                        extracted = page.evaluate("""() => {
                            return Array.from(document.querySelectorAll('form')).slice(0, 20).map(f => ({
                                action: f.action || window.location.href.split('#')[0],
                                method: (f.method || 'GET').toUpperCase(),
                                inputs: Array.from(f.querySelectorAll('input,textarea,select,button')).slice(0, 25).map(i => ({
                                    name: i.name || i.id || '',
                                    type: (i.type || i.tagName || 'text').toLowerCase(),
                                    value: i.value || ''
                                })).filter(i => i.name)
                            }));
                        }""")
                        for fm in extracted or []:
                            k = (fm.get("action", ""), fm.get("method", "GET"), tuple(i.get("name", "") for i in fm.get("inputs", [])))
                            if k not in seen_dom_forms and fm.get("inputs"):
                                seen_dom_forms.add(k)
                                dom_forms.append(fm)
                    except Exception:
                        pass

                _harvest_dom_forms()
                final_url = page.url
                html = page.content()
                if any(m in html for m in ("<app-root", "ng-version", "react-root", "data-v-")):
                    is_spa = True

                for lnk in page.locator("a[href]").all()[:60]:
                    try:
                        href = lnk.get_attribute("href") or ""
                        if href.startswith(("#/", "/#/")) or (href.startswith("#") and "/" in href):
                            client_routes.add(href)
                        elif href.startswith("/") and not href.startswith("//"):
                            client_routes.add(href)
                    except Exception:
                        pass

                for hr in [r for r in sorted(client_routes) if r.startswith(("#/", "/#/", "#")) and "/" in r][:4]:
                    try:
                        nav_u = f"{base_origin}{parsed_t.path or '/'}{hr}" if hr.startswith("#") else f"{base_origin}/{hr.lstrip('/')}"
                        page.goto(nav_u, timeout=5000, wait_until="domcontentloaded")
                        page.wait_for_timeout(300)
                        _harvest_dom_forms()
                    except Exception:
                        pass

                for inp in page.locator("input, textarea, select").all()[:30]:
                    try:
                        nm = inp.get_attribute("name") or inp.get_attribute("id") or inp.get_attribute("placeholder") or "unnamed"
                        tp = inp.get_attribute("type") or "text"
                        interactive_inputs.append({"name": nm, "type": tp})
                    except Exception:
                        pass

                context.close()
                browser.close()
        except Exception as exc:
            return {"available": False, "error": str(exc), "client_routes": [], "api_endpoints_observed": [], "dom_forms": [], "interactive_inputs": []}

        return {
            "available": True,
            "final_url": final_url,
            "is_spa": is_spa,
            "client_routes": sorted(client_routes),
            "api_endpoints_observed": api_observed[:30],
            "dom_forms": dom_forms[:25],
            "interactive_inputs": interactive_inputs,
        }

    @classmethod
    def verify_url_xss(
        cls,
        target_url: str,
        param_name: str = "q",
        session_ctx: Optional[Dict[str, Any]] = None,
        hash_route: Optional[str] = None,
        dom_mode: bool = False,
    ) -> Dict[str, Any]:
        """Tests reflected or hash-based DOM XSS execution inside real Chromium."""
        validate_target(target_url)

        if hash_route or dom_mode:
            remote = cls._remote_verify(
                "verify-dom-xss",
                {
                    "url": target_url,
                    "hash_route": hash_route,
                    "param_name": param_name,
                    "cookie": (session_ctx or {}).get("cookie_header", ""),
                    "headers": (session_ctx or {}).get("extra_headers", {}),
                },
                session_ctx=session_ctx,
            )
            if remote:
                return remote
        else:
            remote = cls._remote_verify(
                "verify-xss",
                {
                    "url": target_url,
                    "param_name": param_name,
                    "cookie": (session_ctx or {}).get("cookie_header", ""),
                    "headers": (session_ctx or {}).get("extra_headers", {}),
                },
                session_ctx=session_ctx,
            )
            if remote:
                return remote

        marker = f"CG_XSS_{secrets.token_hex(4)}"
        if hash_route:
            payload = f'<iframe src="javascript:console.log(\'{marker}\');window.__cg_dom_executed=true">'
            clean_hash = hash_route.split("?")[0]
            parsed = urllib.parse.urlparse(target_url)
            base_u = f"{parsed.scheme}://{parsed.netloc}/"
            test_url = f"{base_u}{clean_hash}?{urllib.parse.urlencode({param_name: payload})}"
        elif dom_mode:
            payload = f'<img src="x" onerror="window.__cg_dom_executed=true;if(document.body)document.body.setAttribute(\'{cls.BENIGN_DOM_ATTR}\',\'{cls.BENIGN_DOM_VALUE}\');console.log(\'{marker}\')"><iframe src="javascript:console.log(\'{marker}\')">'
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param_name] = [payload]
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(qs, doseq=True), parsed.fragment))
        else:
            payload = cls.get_test_payload()
            parsed = urllib.parse.urlparse(target_url)
            qs = urllib.parse.parse_qs(parsed.query)
            qs[param_name] = [payload]
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urllib.parse.urlencode(qs, doseq=True), parsed.fragment))

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"target_url": target_url, "tested_url": test_url, "executed_in_browser": False, "is_vulnerability": False, "verdict": "PLAYWRIGHT_UNAVAILABLE"}

        console_msgs: List[str] = []
        try:
            with sync_playwright() as p:
                browser = _launch_browser(p)
                context = browser.new_context(ignore_https_errors=True, service_workers="block")
                _apply_session(context, target_url, session_ctx)
                page = context.new_page()
                page.on("console", lambda m: console_msgs.append(f"[{m.type}] {m.text}"))
                resp = page.goto(test_url, timeout=8000, wait_until="domcontentloaded")
                http_status = resp.status if resp else None
                page.wait_for_timeout(400)
                window_flag = page.evaluate("() => Boolean(window.__cg_executed || window.__cg_dom_executed)")
                dom_attr = page.evaluate(f"() => document.body ? document.body.getAttribute('{cls.BENIGN_DOM_ATTR}') : null")
                marker_el = page.evaluate(f"() => Boolean(document.getElementById('{cls.BENIGN_MARKER_ID}'))")
                iframe_hit = False
                if hash_route:
                    iframe_hit = page.evaluate(f"() => Array.from(document.querySelectorAll('iframe')).some(f => (f.getAttribute('src') || '').includes('{marker}'))")
                console_hit = any(cls.BENIGN_CONSOLE_MSG in m or marker in m for m in console_msgs)
                context.close()
                browser.close()

            executed = bool(window_flag or dom_attr == cls.BENIGN_DOM_VALUE or console_hit or iframe_hit)
            return {
                "target_url": target_url,
                "tested_url": test_url,
                "parameter": param_name,
                "http_status": http_status,
                "executed_in_browser": executed,
                "is_vulnerability": executed,
                "is_vulnerable": executed,
                "severity": "HIGH" if executed else "INFO",
                "verdict": "CONFIRMED_BROWSER_DOM_EXECUTION" if executed else "EXECUTION_PREVENTED (Safe Context or Properly Encoded)",
                "evidence": {
                    "window_exec_flag": bool(window_flag),
                    "dom_attribute_value": dom_attr,
                    "marker_element_in_dom": bool(marker_el),
                    "console_triggered": console_hit,
                    "console_messages_count": len(console_msgs),
                    "console_snippets": console_msgs[:5],
                },
            }
        except Exception as exc:
            return {"target_url": target_url, "tested_url": test_url, "parameter": param_name, "error": str(exc), "executed_in_browser": False, "is_vulnerability": False, "verdict": f"BROWSER_ERROR: {type(exc).__name__}"}

    @classmethod
    def verify_stored_xss(
        cls,
        target_url: str,
        marker: str,
        session_ctx: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Re-loads a target page in real Chromium to verify persistent Stored XSS execution."""
        validate_target(target_url)
        remote = cls._remote_verify(
            "verify-stored-xss",
            {
                "url": target_url,
                "marker": marker,
                "cookie": (session_ctx or {}).get("cookie_header", ""),
                "headers": (session_ctx or {}).get("extra_headers", {}),
            },
            session_ctx=session_ctx,
        )
        if remote:
            return remote

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {"target_url": target_url, "executed_in_browser": False, "verdict": "PLAYWRIGHT_UNAVAILABLE"}

        console_msgs: List[str] = []
        try:
            with sync_playwright() as p:
                browser = _launch_browser(p)
                context = browser.new_context(ignore_https_errors=True, service_workers="block")
                _apply_session(context, target_url, session_ctx)
                page = context.new_page()
                page.on("console", lambda m: console_msgs.append(f"[{m.type}] {m.text}"))
                resp = page.goto(target_url, timeout=8000, wait_until="domcontentloaded")
                page.wait_for_timeout(450)
                stored_val = page.evaluate("() => window.__cg_stored || null")
                console_hit = any(marker in m for m in console_msgs)
                executed = bool((stored_val and marker in str(stored_val)) or console_hit)
                context.close()
                browser.close()
                return {
                    "target_url": target_url,
                    "http_status": resp.status if resp else None,
                    "executed_in_browser": executed,
                    "is_vulnerability": executed,
                    "verdict": "CONFIRMED_STORED_XSS_EXECUTION" if executed else "NOT_EXECUTED",
                }
        except Exception as exc:
            return {"target_url": target_url, "executed_in_browser": False, "error": str(exc), "verdict": f"BROWSER_ERROR: {type(exc).__name__}"}

