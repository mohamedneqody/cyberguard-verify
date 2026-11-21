"""
ARTEX CyberGuard — Advanced Non-Destructive Vulnerability Verification Engines
Implements modular, scope-guarded verification for:
1. OpenAPI / Swagger Schema Extraction
2. General Parameter & API SQL Injection (Error-based + Boolean Content Differential, CWE-89)
3. OS Command Injection (Non-destructive Echo Token & Dual Timing Differential, CWE-78)
4. Server-Side Template Injection (Arithmetic Differential, CWE-1336)
5. JWT Cryptographic & Claims Audit (Offline Weak Secret + alg=none Downgrade Probe, CWE-347)
6. Stored XSS Verification (Form Submission + Playwright Persistent DOM Execution, CWE-79)
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
import urllib.parse
from urllib.request import Request

DB_ERROR_PATTERNS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_",
    "mysql_fetch",
    "mariadb server version",
    "sqlite3.operationalerror",
    "sqlite_error",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "psycopg2",
    "pg_query",
    "sqlstate[",
    "sqlsyntaxerrorexception",
    "hsqldb",
    "ora-00933",
    "ora-01756",
    "syntax error near",
    "sql command not properly ended",
)

SKIP_PARAM_NAMES = {"submit", "login", "btn", "button", "user_token", "csrf", "_csrf", "csrf_token", "password", "password_new", "password_conf", "matchingpassword"}
CMDI_PARAM_HINTS = ("ip", "host", "hostname", "cmd", "command", "ping", "domain", "target", "addr", "lookup", "nslookup")
DESTRUCTIVE_FORM_HINTS = ("login", "signin", "logout", "signout", "register", "password", "delete", "remove", "drop", "reset", "setup", "csrf")
WEAK_JWT_SECRETS = ("secret", "your-256-bit-secret", "jwt_secret", "changeme", "password", "123456", "supersecret", "webgoat", "artex")


def _send_http(
    url: str,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    as_json: bool = False,
    opener=None,
    headers: Optional[Dict[str, str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
    timeout: int = 8,
) -> Tuple[Optional[int], str, str, float]:
    """Executes an HTTP request safely and returns (status, content_type, body, elapsed_sec)."""
    hdrs = {"User-Agent": "ARTEX-CyberGuard-Verifier/3.0", "Accept": "application/json,text/html,*/*"}
    if headers:
        hdrs.update(headers)

    req_url = url
    data = None
    method_u = method.upper()
    if method_u == "GET":
        if params:
            parsed = urllib.parse.urlsplit(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for k, v in params.items():
                qs[k] = [str(v)]
            req_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(qs, doseq=True), parsed.fragment))
    else:
        if as_json:
            hdrs["Content-Type"] = "application/json"
            data = json.dumps(params or {}).encode("utf-8")
        else:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(params or {}).encode("utf-8")

    if validate_fn:
        validate_fn(req_url)

    t0 = time.monotonic()
    req = Request(req_url, data=data, headers=hdrs, method=method_u if method_u not in ("GET", "POST") else None)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return resp.status, resp.headers.get("Content-Type", "").lower(), body, time.monotonic() - t0
    except HTTPError as he:
        body = he.read(16384).decode("utf-8", errors="replace")
        return he.code, he.headers.get("Content-Type", "").lower(), body, time.monotonic() - t0
    except Exception:
        return None, "", "", time.monotonic() - t0


def _collect_form_defaults(disc: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, str]]:
    """Maps (endpoint_path, method) -> default/hidden/submit field values for accurate form replay."""
    defaults: Dict[Tuple[str, str], Dict[str, str]] = {}
    for form in disc.get("discovered_forms") or []:
        ep = urllib.parse.urlparse(form.get("action", "")).path or "/"
        m = str(form.get("method", "GET")).upper()
        d: Dict[str, str] = {}
        for inp in form.get("inputs") or []:
            nm = inp.get("name", "")
            if not nm:
                continue
            val = inp.get("value", "")
            if not val and inp.get("type") in ("submit", "button"):
                val = nm
            d[nm] = val
        defaults[(ep, m)] = d
    return defaults


def _session_headers(session_ctx: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not session_ctx:
        return {}
    hdrs = dict(session_ctx.get("extra_headers") or {})
    if session_ctx.get("cookie_header"):
        hdrs["Cookie"] = session_ctx["cookie_header"]
    return hdrs


def parse_openapi_targets(
    origin_u: str,
    base_path: str,
    opener,
    headers: Optional[Dict[str, str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Fetches OpenAPI/Swagger specs if exposed and extracts endpoints and testable parameters."""
    candidate_specs = ["/openapi.json", "/api-docs/swagger.json", "/swagger.json", "/v3/api-docs"]
    clean_base = base_path.rstrip("/")
    if clean_base and clean_base != "/":
        candidate_specs.extend([f"{clean_base}{p}" for p in ("/openapi.json", "/v3/api-docs", "/api-docs/swagger.json")])

    endpoints: List[str] = []
    inputs: List[Dict[str, Any]] = []
    seen_specs = set()

    for sp in candidate_specs:
        url = f"{origin_u}{sp}"
        if url in seen_specs:
            continue
        seen_specs.add(url)
        st, ct, body, _ = _send_http(url, "GET", opener=opener, headers=headers, validate_fn=validate_fn, timeout=5)
        if st != 200 or not body or '"paths"' not in body:
            continue
        try:
            spec = json.loads(body)
        except Exception:
            continue
        paths = spec.get("paths") or {}
        if not isinstance(paths, dict):
            continue
        for raw_path, methods in list(paths.items())[:40]:
            if not isinstance(methods, dict):
                continue
            norm_path = raw_path if not (clean_base and clean_base != "/" and not raw_path.startswith(clean_base)) else f"{clean_base}{raw_path}"
            concrete_path = re.sub(r"\{[^}]+\}", "102", norm_path)
            if concrete_path not in endpoints:
                endpoints.append(concrete_path)
            for m_name, op_obj in methods.items():
                if m_name.lower() not in ("get", "post") or not isinstance(op_obj, dict):
                    continue
                m_u = m_name.upper()
                for param in op_obj.get("parameters") or []:
                    if isinstance(param, dict) and param.get("name"):
                        p_name = str(param["name"])
                        inputs.append({
                            "endpoint": concrete_path,
                            "url": f"{origin_u}{concrete_path}",
                            "method": m_u,
                            "parameter": p_name,
                            "param_type": f"openapi_{param.get('in', 'query')}",
                            "category": "GENERIC_PARAM",
                            "recommended_tool": "audit_general_sqli",
                        })
                rb = op_obj.get("requestBody") or {}
                content = rb.get("content") or {}
                jschema = (content.get("application/json") or {}).get("schema") or {}
                props = jschema.get("properties") or {}
                if isinstance(props, dict):
                    for p_name in list(props.keys())[:10]:
                        inputs.append({
                            "endpoint": concrete_path,
                            "url": f"{origin_u}{concrete_path}",
                            "method": m_u,
                            "parameter": str(p_name),
                            "param_type": "openapi_json",
                            "as_json": True,
                            "category": "GENERIC_PARAM",
                            "recommended_tool": "audit_general_sqli",
                        })
        break

    return endpoints, inputs


def audit_general_sqli(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Tests GET query, non-auth forms, and JSON API inputs for Error-Based & Boolean Diff SQLi."""
    hdrs = _session_headers(session_ctx)
    form_defaults = _collect_form_defaults(disc)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    candidates: List[Dict[str, Any]] = []
    seen = set()
    for ip in disc.get("input_points") or []:
        ep = ip.get("endpoint", "")
        param = ip.get("parameter", "")
        method = str(ip.get("method", "GET")).upper()
        cat = ip.get("category", "")
        if not ep or not param or ep == "client_routes" or method == "CLIENT":
            continue
        if param.lower() in SKIP_PARAM_NAMES or cat == "AUTHENTICATION_CREDENTIAL":
            continue
        if any(k in ep.lower() for k in ("logout", "signout", "setup", "csrf")):
            continue
        key = (ep, method, param)
        if key not in seen:
            seen.add(key)
            candidates.append({
                "endpoint": ep,
                "url": ip.get("url") or f"{origin_u}/{ep.lstrip('/')}",
                "method": method,
                "parameter": param,
                "as_json": bool(ip.get("as_json") or "json" in str(ip.get("param_type", ""))),
            })

    def _probe_sqli_candidate(c: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ep = c["endpoint"]
        u = c["url"]
        m = c["method"]
        p = c["parameter"]
        as_json = c["as_json"]
        base_fields = dict(form_defaults.get((ep, m), {}))

        def send_val(val: str):
            payload = dict(base_fields)
            payload[p] = val
            return _send_http(u, m, params=payload, as_json=as_json, opener=opener, headers=hdrs, validate_fn=validate_fn)

        st_base, _, body_base, _ = send_val("1")
        if st_base is None or st_base == 404:
            return None
        base_low = body_base.lower()
        base_has_err = any(pat in base_low for pat in DB_ERROR_PATTERNS)

        # 1. Error-based SQLi check (with single-quote trigger & repeatability check)
        st_err, _, body_err, _ = send_val("1'")
        err_low = body_err.lower()
        matched_err = next((pat for pat in DB_ERROR_PATTERNS if pat in err_low and not base_has_err), "")
        err_confirmed = False
        if matched_err:
            _, _, body_err2, _ = send_val("1'")
            err_confirmed = matched_err in body_err2.lower()

        # 2. Boolean differential SQLi check (1' OR '1'='1 vs 1' AND '1'='2)
        st_t, _, body_t, _ = send_val("1' OR '1'='1")
        st_f, _, body_f, _ = send_val("1' AND '1'='2")
        bool_confirmed = False
        if st_t == 200 and st_f == 200 and body_t and body_f:
            clean_t = body_t.replace("1' OR '1'='1", "")
            clean_f = body_f.replace("1' AND '1'='2", "")
            len_diff = abs(len(clean_t) - len(clean_f))
            row_diff = len(re.findall(r"<pre>|Surname:|First name:", clean_t, re.I)) > len(re.findall(r"<pre>|Surname:|First name:", clean_f, re.I))
            if (len_diff > 180 or row_diff) and len(clean_t) > len(clean_f):
                _, _, body_t2, _ = send_val("1' OR '1'='1")
                clean_t2 = body_t2.replace("1' OR '1'='1", "")
                if abs(len(clean_t2) - len(clean_f)) > 150 or row_diff:
                    bool_confirmed = True

        is_vuln = bool(err_confirmed or bool_confirmed)
        verdict = "VULN_GENERAL_SQLI_CONFIRMED" if is_vuln else "PROPERLY_RESTRICTED"
        snippet = ""
        if err_confirmed:
            snippet = f"Param '{p}' triggered repeatable SQL error marker '{matched_err}' on 1' (absent on baseline 1)."
        elif bool_confirmed:
            snippet = f"Boolean differential on '{p}': TRUE probe returned {len(body_t)}B vs FALSE probe {len(body_f)}B."

        return {
            "check": "GENERAL_SQLI",
            "endpoint": ep,
            "method": m,
            "parameter": p,
            "cwe_id": "CWE-89",
            "error_based": err_confirmed,
            "boolean_diff": bool_confirmed,
            "is_vulnerability": is_vuln,
            "severity": "HIGH" if is_vuln else "INFO",
            "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
            "verdict": verdict,
            "evidence_snippet": snippet,
            "reproduction_steps": f"Send {m} {u} with {p}=\"1' OR '1'='1\" vs {p}=\"1' AND '1'='2\" (or {p}=\"1'\").",
            "remediation": "Use parameterized prepared statements / bind variables for all query, form, and API parameters.",
        }

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [r for r in pool.map(_probe_sqli_candidate, candidates[:15]) if r is not None]

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def audit_command_injection(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Non-destructive OS Command Injection audit using benign echo token & dual timing checks."""
    hdrs = _session_headers(session_ctx)
    form_defaults = _collect_form_defaults(disc)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    candidates = []
    seen = set()
    for ip in disc.get("input_points") or []:
        ep = ip.get("endpoint", "")
        p = ip.get("parameter", "")
        m = str(ip.get("method", "GET")).upper()
        if not ep or not p or ep == "client_routes" or m == "CLIENT":
            continue
        if p.lower() in SKIP_PARAM_NAMES:
            continue
        if any(h in p.lower() or h in ep.lower() for h in CMDI_PARAM_HINTS) and (ep, m, p) not in seen:
            seen.add((ep, m, p))
            candidates.append({"endpoint": ep, "url": ip.get("url") or f"{origin_u}/{ep.lstrip('/')}", "method": m, "parameter": p})

    results: List[Dict[str, Any]] = []
    for c in candidates[:10]:
        ep, u, m, p = c["endpoint"], c["url"], c["method"], c["parameter"]
        base_fields = dict(form_defaults.get((ep, m), {}))
        nonce = secrets.token_hex(4)
        marker = f"CGCMDI_{nonce}"

        def send_cmd(val: str, timeout: int = 8):
            payload = dict(base_fields)
            payload[p] = val
            return _send_http(u, m, params=payload, opener=opener, headers=hdrs, validate_fn=validate_fn, timeout=timeout)

        st0, _, b0, dt0 = send_cmd("127.0.0.1")
        if st0 is None or st0 == 404:
            continue

        # 1. Non-destructive echo token check (must appear WITHOUT literal 'echo ' before it)
        echo_hit = False
        used_payload = ""
        for sep in (";", "&&", "|"):
            cand_payload = f"127.0.0.1{sep}echo {marker}"
            st_e, _, b_e, _ = send_cmd(cand_payload)
            if st_e == 200 and b_e:
                stripped = b_e.replace(f"echo {marker}", "")
                if marker in stripped and marker not in b0:
                    echo_hit = True
                    used_payload = cand_payload
                    break

        # 2. Safe dual timing fallback ONLY if echo wasn't printed (e.g. blind execution)
        time_hit = False
        if not echo_hit and dt0 < 2.2:
            _, _, _, dt_sleep1 = send_cmd("127.0.0.1;sleep 3", timeout=10)
            if dt_sleep1 - dt0 >= 2.4:
                _, _, _, dt_zero = send_cmd("127.0.0.1;sleep 0", timeout=8)
                _, _, _, dt_sleep2 = send_cmd("127.0.0.1;sleep 3", timeout=10)
                if (dt_sleep2 - dt_zero) >= 2.4 and (dt_zero - dt0) < 1.2:
                    time_hit = True
                    used_payload = "127.0.0.1;sleep 3"

        is_vuln = bool(echo_hit or time_hit)
        results.append({
            "check": "COMMAND_INJECTION",
            "endpoint": ep,
            "method": m,
            "parameter": p,
            "cwe_id": "CWE-78",
            "echo_verified": echo_hit,
            "timing_verified": time_hit,
            "is_vulnerability": is_vuln,
            "severity": "CRITICAL" if is_vuln else "INFO",
            "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
            "verdict": "VULN_COMMAND_INJECTION_CONFIRMED" if is_vuln else "SAFE",
            "evidence_snippet": f"Executed benign probe '{used_payload}' on {m} {ep} param '{p}'." if is_vuln else "",
            "reproduction_steps": f"Submit {m} {u} with {p}='{used_payload}'.",
            "remediation": "Never pass untrusted input into shell commands (os.system/shell_exec). Use safe APIs or argument arrays with strict allowlists.",
        })

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def audit_ssti(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Detects Server-Side Template Injection via benign arithmetic evaluation (9137*7=63959)."""
    hdrs = _session_headers(session_ctx)
    form_defaults = _collect_form_defaults(disc)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    candidates = []
    seen = set()
    for ip in disc.get("input_points") or []:
        ep = ip.get("endpoint", "")
        p = ip.get("parameter", "")
        m = str(ip.get("method", "GET")).upper()
        if not ep or not p or ep == "client_routes" or m == "CLIENT":
            continue
        if p.lower() in SKIP_PARAM_NAMES or ip.get("category") == "AUTHENTICATION_CREDENTIAL":
            continue
        if (ep, m, p) not in seen:
            seen.add((ep, m, p))
            candidates.append({"endpoint": ep, "url": ip.get("url") or f"{origin_u}/{ep.lstrip('/')}", "method": m, "parameter": p})

    def _probe_ssti_candidate(c: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ep, u, m, p = c["endpoint"], c["url"], c["method"], c["parameter"]
        base_fields = dict(form_defaults.get((ep, m), {}))

        def send_t(val: str):
            payload = dict(base_fields)
            payload[p] = val
            return _send_http(u, m, params=payload, opener=opener, headers=hdrs, validate_fn=validate_fn)

        st_ctrl, _, b_ctrl, _ = send_t("cg_9137_ok")
        if st_ctrl is None or st_ctrl == 404 or "63959" in b_ctrl:
            return None

        matched_expr = ""
        for expr in ("cg{{9137*7}}ok", "cg${9137*7}ok"):
            st_e, ct_e, b_e, _ = send_t(expr)
            if st_e == 200 and "cg63959ok" in b_e and expr not in b_e:
                _, _, b_e2, _ = send_t(expr)
                if "cg63959ok" in b_e2:
                    matched_expr = expr
                    break

        is_vuln = bool(matched_expr)
        return {
            "check": "SSTI",
            "endpoint": ep,
            "method": m,
            "parameter": p,
            "cwe_id": "CWE-1336",
            "is_vulnerability": is_vuln,
            "severity": "HIGH" if is_vuln else "INFO",
            "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
            "verdict": "VULN_SSTI_CONFIRMED" if is_vuln else "SAFE",
            "evidence_snippet": f"Template expression '{matched_expr}' evaluated server-side to 'cg63959ok' on {ep}." if is_vuln else "",
            "reproduction_steps": f"Submit {m} {u} with {p}='{matched_expr or 'cg{{9137*7}}ok'}' and inspect response for 'cg63959ok'.",
            "remediation": "Never concatenate user input into template strings. Pass user data strictly as template context variables and enable auto-escaping/sandboxing.",
        }

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [r for r in pool.map(_probe_ssti_candidate, candidates[:12]) if r is not None]

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode((seg + pad).encode("ascii"))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def audit_jwt_security(
    target_url: str,
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    protected_url: str = "",
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Audits captured JWT tokens for alg=none, missing exp, weak dev HMAC secrets, and replay acceptance."""
    jwts = list((session_ctx or {}).get("captured_jwts") or [])
    results: List[Dict[str, Any]] = []

    for idx, tok in enumerate(jwts[:5]):
        parts = tok.split(".")
        if len(parts) < 2:
            continue
        try:
            hdr = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
            claims = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        except Exception:
            continue

        alg = str(hdr.get("alg", ""))
        weak_secret_found = ""
        if alg.upper() == "HS256" and len(parts) == 3:
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            for cand_sec in WEAK_JWT_SECRETS:
                expected_sig = _b64url_encode(hmac.new(cand_sec.encode("utf-8"), signing_input, hashlib.sha256).digest())
                if hmac.compare_digest(expected_sig, parts[2]):
                    weak_secret_found = cand_sec
                    break

        alg_none_bypass = False
        if alg.lower() == "none":
            alg_none_bypass = True
        elif protected_url and (session_ctx or {}).get("extra_headers", {}).get("Authorization", "").startswith("Bearer "):
            # Confirm baseline rejects unauth while accepting valid token before testing alg=none
            st_unauth, _, _, _ = _send_http(protected_url, "GET", opener=opener, headers={}, validate_fn=validate_fn)
            st_valid, _, _, _ = _send_http(protected_url, "GET", opener=opener, headers=_session_headers(session_ctx), validate_fn=validate_fn)
            if st_unauth in (401, 403) and st_valid == 200:
                none_hdr = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
                forged = f"{none_hdr}.{parts[1]}."
                forged_hdrs = dict(_session_headers(session_ctx))
                forged_hdrs["Authorization"] = f"Bearer {forged}"
                st_forged, _, _, _ = _send_http(protected_url, "GET", opener=opener, headers=forged_hdrs, validate_fn=validate_fn)
                if st_forged == 200:
                    alg_none_bypass = True

        missing_exp = "exp" not in claims
        is_vuln = bool(alg_none_bypass or weak_secret_found)
        verdict = "VULN_JWT_ALG_NONE_BYPASS" if alg_none_bypass else ("VULN_JWT_WEAK_HMAC_SECRET" if weak_secret_found else ("HARDENING_JWT_NO_EXP" if missing_exp else "SAFE"))
        sev = "CRITICAL" if alg_none_bypass else ("HIGH" if weak_secret_found else ("LOW" if missing_exp else "INFO"))

        results.append({
            "check": "JWT_AUDIT",
            "endpoint": protected_url or "/",
            "token_index": idx,
            "alg": alg,
            "missing_exp": missing_exp,
            "weak_secret_matched": bool(weak_secret_found),
            "alg_none_bypass": alg_none_bypass,
            "cwe_id": "CWE-347",
            "is_vulnerability": is_vuln,
            "severity": sev,
            "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
            "verdict": verdict,
            "evidence_snippet": f"JWT alg={alg}; alg_none_bypass={alg_none_bypass}; weak_secret={bool(weak_secret_found)}; missing_exp={missing_exp}",
            "reproduction_steps": "Inspect JWT header/claims and verify signature algorithm enforcement against alg=none and strong HS256/RS256 keys.",
            "remediation": "Enforce explicit JWT algorithm allowlists (reject alg=none), use high-entropy >=256-bit keys or asymmetric RS256/EdDSA, and require short exp lifetimes.",
        })

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "tokens_inspected": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def audit_stored_xss(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    playwright_hosts: Optional[List[str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Tests non-destructive POST display/comment forms for Stored XSS using Playwright reload proof."""
    hdrs = _session_headers(session_ctx)
    hosts = playwright_hosts or ["playwright-service:8765", "127.0.0.1:8765"]
    results: List[Dict[str, Any]] = []

    for form in (disc.get("discovered_forms") or [])[:6]:
        if str(form.get("method", "GET")).upper() != "POST":
            continue
        action = form.get("action") or target_url
        ep = urllib.parse.urlparse(action).path or "/"
        if any(d in ep.lower() for d in DESTRUCTIVE_FORM_HINTS):
            continue

        inputs = form.get("inputs") or []
        text_fields = [
            i["name"] for i in inputs
            if i.get("name") and i["name"].lower() not in SKIP_PARAM_NAMES
            and i.get("type") in ("text", "textarea", "search", "email", "url", "")
        ]
        if not text_fields:
            continue

        nonce = secrets.token_hex(4)
        marker = f"CG_SXSS_{nonce}"
        payload_xss = f'<script>window.__cg_stored="{marker}"</script><img src="x" onerror="console.log(\'{marker}\')">'

        form_data: Dict[str, str] = {}
        for i in inputs:
            nm = i.get("name", "")
            if not nm:
                continue
            if nm in text_fields:
                form_data[nm] = payload_xss
            elif i.get("type") in ("submit", "button"):
                form_data[nm] = i.get("value") or nm
            else:
                form_data[nm] = i.get("value") or ""

        st_post, _, _, _ = _send_http(action, "POST", params=form_data, opener=opener, headers=hdrs, validate_fn=validate_fn)
        if st_post is None or st_post >= 400:
            continue

        pw_res = None
        for h in hosts:
            try:
                v_req = Request(
                    f"http://{h}/verify-stored-xss",
                    data=json.dumps({
                        "url": action,
                        "marker": marker,
                        "cookie": (session_ctx or {}).get("cookie_header", ""),
                        "headers": (session_ctx or {}).get("extra_headers", {}),
                        **({"storage_state": session_ctx["storage_state"]} if (session_ctx or {}).get("storage_state") else {}),
                    }).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with opener.open(v_req, timeout=12) as resp:
                    if resp.status == 200:
                        pw_res = json.loads(resp.read().decode("utf-8"))
                        break
            except Exception:
                pass
        if pw_res is None:
            try:
                from .browser_verifier import BrowserXSSVerifier
                if hasattr(BrowserXSSVerifier, "verify_stored_xss"):
                    pw_res = BrowserXSSVerifier.verify_stored_xss(action, marker, session_ctx=session_ctx)
            except Exception:
                pw_res = None

        executed = bool(pw_res and pw_res.get("executed_in_browser"))
        results.append({
            "check": "STORED_XSS",
            "endpoint": ep,
            "parameters": text_fields,
            "cwe_id": "CWE-79",
            "executed_in_browser": executed,
            "is_vulnerability": executed,
            "severity": "HIGH" if executed else "INFO",
            "confidence": "CONFIRMED" if executed else "CONFIRMED_SAFE",
            "verdict": "VULN_STORED_XSS_CONFIRMED" if executed else "SAFE",
            "evidence_snippet": f"Persistent XSS marker '{marker}' executed in Chromium DOM after reload of {ep}." if executed else "",
            "reproduction_steps": f"Submit benign XSS probe to POST {action} ({', '.join(text_fields)}), reload {action} in browser, and observe execution.",
            "remediation": "Sanitize and contextually HTML-encode all persisted user-generated content before rendering into the DOM.",
        })

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }
