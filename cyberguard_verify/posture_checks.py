"""Modular Web Security Posture Engine (CORS, Open Redirect, Exposures, Path Traversal, CSRF) with Concurrent Probing."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
import urllib.parse
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class _NoRedirectHandler(HTTPRedirectHandler):
    """Captures 3xx Location headers without following external redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _session_headers(session_ctx: Optional[Dict[str, Any]]) -> Dict[str, str]:
    hdrs = {"User-Agent": "CyberGuard-Posture/3.2"}
    if not session_ctx:
        return hdrs
    for k, v in (session_ctx.get("extra_headers") or {}).items():
        hdrs[k] = v
    if session_ctx.get("cookie_header"):
        hdrs["Cookie"] = session_ctx["cookie_header"]
    return hdrs


def _is_spa_html_fallback(ct: str, body: str) -> bool:
    low = body.lower()
    return "text/html" in ct and any(s in low for s in ("<app-root", '<div id="root"', '<div id="__next"', "<!doctype html"))


def probe_cors(origin_u: str, opener) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for test_origin in ("https://evil-cors-probe.invalid", "null"):
        try:
            req = Request(origin_u, headers={"User-Agent": "CyberGuard-Posture/3.2", "Origin": test_origin})
            try:
                with opener.open(req, timeout=8) as resp:
                    status = resp.status
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
            except HTTPError as e:
                status = e.code
                hdrs = {k.lower(): v for k, v in e.headers.items()}

            acao = hdrs.get("access-control-allow-origin", "").strip()
            acac = hdrs.get("access-control-allow-credentials", "").strip().lower()
            exploitable = (acao == test_origin) and (acac == "true")
            findings.append({
                "check": "CORS",
                "endpoint": "/",
                "origin_sent": test_origin,
                "status_code": status,
                "acao": acao,
                "acac": acac,
                "cwe_id": "CWE-942",
                "is_vulnerability": exploitable,
                "severity": "HIGH" if exploitable else "INFO",
                "confidence": "CONFIRMED" if exploitable else "CONFIRMED_SAFE",
                "verdict": "VULN_CORS_CREDENTIALED_REFLECTION" if exploitable else ("INFO_CORS_WILDCARD" if acao == "*" else "SAFE"),
                "evidence_snippet": f"Origin: {test_origin} -> ACAO: {acao}, ACAC: {acac}",
                "reproduction_steps": f"GET {origin_u} with header 'Origin: {test_origin}' and verify ACAO/ACAC headers.",
                "remediation": "Restrict Access-Control-Allow-Origin to trusted allowlisted origins and never combine Access-Control-Allow-Credentials: true with dynamic Origin reflection or null.",
            })
        except Exception as e:
            findings.append({"check": "CORS", "endpoint": "/", "origin_sent": test_origin, "error": str(e), "is_vulnerability": False})
    return findings


def probe_open_redirects(origin_u: str, disc: Dict[str, Any], validate_fn: Optional[Callable[[str], Any]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    no_redir_opener = build_opener(_NoRedirectHandler())
    redir_names = {"redirect", "next", "url", "return", "returnurl", "redirect_uri", "continue", "goto", "dest", "target", "to"}
    probe_dest = "https://evil-redirect-probe.invalid/poc"
    candidates: List[Tuple[str, str]] = []
    seen = set()

    for ip in disc.get("input_points") or []:
        p_name = ip.get("parameter", "")
        ep = ip.get("endpoint", "/")
        if ep == "client_routes" or p_name.lower() not in redir_names:
            continue
        key = (ep, p_name)
        if key not in seen:
            seen.add(key)
            candidates.append((ep, p_name))

    for ep in ("/", "/login"):
        if (ep, "next") not in seen:
            seen.add((ep, "next"))
            candidates.append((ep, "next"))

    for ep, param in candidates[:8]:
        test_url = f"{origin_u}/{ep.lstrip('/')}?{urllib.parse.urlencode({param: probe_dest})}"
        try:
            if validate_fn:
                validate_fn(test_url)
            req = Request(test_url, headers={"User-Agent": "CyberGuard-Posture/3.2"})
            loc = ""
            status = 0
            try:
                with no_redir_opener.open(req, timeout=6) as resp:
                    status = resp.status
                    loc = resp.headers.get("Location", "")
            except HTTPError as e:
                status = e.code
                loc = e.headers.get("Location", "")

            loc_host = (urlparse(loc).hostname or "").lower() if loc else ""
            is_vuln = (300 <= status < 400) and (loc_host == "evil-redirect-probe.invalid")
            findings.append({
                "check": "OPEN_REDIRECT",
                "endpoint": ep,
                "parameter": param,
                "status_code": status,
                "location": loc,
                "cwe_id": "CWE-601",
                "is_vulnerability": is_vuln,
                "severity": "MEDIUM" if is_vuln else "INFO",
                "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
                "verdict": "VULN_OPEN_REDIRECT_CONFIRMED" if is_vuln else "SAFE",
                "evidence_snippet": f"GET {test_url} -> HTTP {status} Location: {loc}" if is_vuln else "",
                "reproduction_steps": f"Send non-following GET to {test_url} and inspect Location response header.",
                "remediation": "Validate redirect targets against an allowlist of relative internal paths or trusted domains before issuing 3xx redirects.",
            })
        except Exception as e:
            findings.append({"check": "OPEN_REDIRECT", "endpoint": ep, "parameter": param, "error": str(e), "is_vulnerability": False})
    return findings


def probe_exposures_and_traversal(
    origin_u: str,
    disc: Dict[str, Any],
    opener,
    base_path: str = "",
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sess_hdrs = _session_headers(session_ctx)
    exposure_specs = [
        ("/.env", "ENV_FILE_EXPOSURE", "HIGH", "CWE-200", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and any(k in b for k in ("DB_PASSWORD=", "POSTGRES_PASSWORD=", "API_KEY=", "SECRET_KEY=", "GEMINI_API_KEY="))),
        ("/.git/HEAD", "GIT_REPO_EXPOSURE", "HIGH", "CWE-527", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and b.lstrip().startswith("ref: refs/")),
        ("/metrics", "PROMETHEUS_METRICS_EXPOSURE", "MEDIUM", "CWE-200", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and ("# HELP " in b and "# TYPE " in b)),
        ("/actuator/env", "ACTUATOR_ENV_EXPOSURE", "HIGH", "CWE-200", lambda b, ct: "application/json" in ct and ('"propertySources"' in b or '"activeProfiles"' in b)),
        ("/actuator/health", "ACTUATOR_HEALTH_EXPOSURE", "INFO", "CWE-200", lambda b, ct: "application/json" in ct and '"status"' in b),
        ("/api-docs/swagger.json", "OPENAPI_SPEC_EXPOSURE", "INFO", "CWE-200", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and ('"paths"' in b and ('"openapi"' in b or '"swagger"' in b))),
        ("/openapi.json", "OPENAPI_SPEC_EXPOSURE", "INFO", "CWE-200", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and ('"paths"' in b and ('"openapi"' in b or '"swagger"' in b))),
        ("/v3/api-docs", "OPENAPI_SPEC_EXPOSURE", "INFO", "CWE-200", lambda b, ct: (not _is_spa_html_fallback(ct, b)) and ('"paths"' in b and ('"openapi"' in b or '"swagger"' in b))),
    ]

    bases_to_probe = [""]
    clean_base = base_path.rstrip("/")
    if clean_base and clean_base != "/":
        bases_to_probe.append(clean_base)

    tasks = []
    seen_urls = set()
    for base_prefix in bases_to_probe:
        for rel_path, label, sev, cwe, matcher in exposure_specs:
            path = f"{base_prefix}{rel_path}"
            url = f"{origin_u}{path}"
            if url not in seen_urls:
                seen_urls.add(url)
                tasks.append((path, url, label, sev, cwe, matcher))

    def _check_one_exposure(task_item):
        path, url, label, sev, cwe, matcher = task_item
        try:
            if validate_fn:
                validate_fn(url)
            req = Request(url, headers=sess_hdrs)
            try:
                with opener.open(req, timeout=6) as resp:
                    status = resp.status
                    ct = resp.headers.get("Content-Type", "").lower()
                    body = resp.read(16384).decode("utf-8", errors="replace")
            except HTTPError as e:
                status = e.code
                ct = e.headers.get("Content-Type", "").lower()
                body = e.read(4096).decode("utf-8", errors="replace")

            matched = (status == 200) and matcher(body, ct)
            is_vuln = matched and sev in ("CRITICAL", "HIGH", "MEDIUM")
            if matched or (status == 200 and not _is_spa_html_fallback(ct, body)):
                return {
                    "check": label,
                    "endpoint": path,
                    "status_code": status,
                    "cwe_id": cwe,
                    "is_vulnerability": is_vuln,
                    "severity": sev if matched else "INFO",
                    "confidence": "CONFIRMED" if matched else "CONFIRMED_SAFE",
                    "verdict": f"VULN_{label}" if is_vuln else (f"INFO_{label}" if matched else "SAFE"),
                    "evidence_snippet": body[:200].strip() if matched else "",
                    "reproduction_steps": f"GET {url} returned HTTP {status} with matching exposure signature.",
                    "remediation": "Restrict internal diagnostics, OpenAPI docs, environment files, and VCS metadata from public routes.",
                }
            return None
        except Exception as e:
            return {"check": label, "endpoint": path, "error": str(e), "is_vulnerability": False}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_check_one_exposure, t) for t in tasks]
        for fut in as_completed(futures):
            res_item = fut.result()
            if res_item:
                findings.append(res_item)

    trav_names = {"file", "path", "doc", "template", "download", "page", "dir", "filepath"}
    seen_trav = set()
    for ip in disc.get("input_points") or []:
        p_name = ip.get("parameter", "")
        ep = ip.get("endpoint", "/")
        if ep == "client_routes" or p_name.lower() not in trav_names or (ep, p_name) in seen_trav:
            continue
        seen_trav.add((ep, p_name))
        for trav_payload in ("../../../../etc/passwd", "/etc/passwd"):
            test_url = f"{origin_u}/{ep.lstrip('/')}?{urllib.parse.urlencode({p_name: trav_payload})}"
            try:
                if validate_fn:
                    validate_fn(test_url)
                req = Request(test_url, headers=sess_hdrs)
                try:
                    with opener.open(req, timeout=6) as resp:
                        status = resp.status
                        body = resp.read(8192).decode("utf-8", errors="replace")
                except HTTPError as e:
                    status = e.code
                    body = e.read(4096).decode("utf-8", errors="replace")
                is_vuln = (status == 200 and "root:x:0:0:" in body)
                if is_vuln or trav_payload == "/etc/passwd":
                    findings.append({
                        "check": "PATH_TRAVERSAL",
                        "endpoint": ep,
                        "parameter": p_name,
                        "status_code": status,
                        "cwe_id": "CWE-22",
                        "is_vulnerability": is_vuln,
                        "severity": "HIGH" if is_vuln else "INFO",
                        "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
                        "verdict": "VULN_PATH_TRAVERSAL_CONFIRMED" if is_vuln else "SAFE",
                        "evidence_snippet": body[:200].strip() if is_vuln else "",
                        "reproduction_steps": f"GET {test_url} and inspect response for /etc/passwd signatures.",
                        "remediation": "Canonicalize file paths with realpath and enforce strict base-directory prefix checks.",
                    })
                    if is_vuln:
                        break
            except Exception as e:
                findings.append({"check": "PATH_TRAVERSAL", "endpoint": ep, "parameter": p_name, "error": str(e), "is_vulnerability": False})
    return findings


def probe_csrf_forms(disc: Dict[str, Any], headers_and_cookies: Tuple[Dict[str, Any], Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    _, cookies_res = headers_and_cookies
    cookies = cookies_res.get("cookies") or cookies_res.get("raw_set_cookie") or []
    has_strict_samesite = any(
        (str(c.get("samesite", "")).lower() in ("strict", "lax") if isinstance(c, dict) else ("samesite=strict" in str(c).lower() or "samesite=lax" in str(c).lower()))
        for c in cookies
    )
    auth_like_paths = ("/login", "/signin", "/register", "/search", "/logout", "/password-reset")
    csrf_names = ("csrf", "_token", "xsrf", "authenticity_token", "nonce", "user_token")

    for form in disc.get("discovered_forms") or []:
        if str(form.get("method", "")).upper() != "POST":
            continue
        action_ep = urlparse(form.get("action", "")).path or "/"
        if any(action_ep.lower().startswith(p) for p in auth_like_paths):
            continue
        input_names = [str(i.get("name", "")).lower() for i in form.get("inputs") or []]
        has_csrf_token = any(any(tok in nm for tok in csrf_names) for nm in input_names)
        if not has_csrf_token and cookies and not has_strict_samesite:
            findings.append({
                "check": "CSRF_POSTURE",
                "endpoint": action_ep,
                "cwe_id": "CWE-352",
                "is_vulnerability": True,
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "verdict": "VULN_CSRF_TOKEN_MISSING",
                "evidence_snippet": f"State-changing POST form {action_ep} lacks anti-CSRF token and session cookies lack SameSite=Lax/Strict.",
                "reproduction_steps": f"Inspect POST form {action_ep} and Set-Cookie SameSite attributes.",
                "remediation": "Include unpredictable per-session CSRF tokens on state-changing forms and set SameSite=Lax or Strict on session cookies.",
            })
    return findings


def run_web_posture_checks(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    headers_and_cookies: Tuple[Dict[str, Any], Dict[str, Any]],
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    if validate_fn:
        validate_fn(target_url)
    parsed = urlparse(target_url)
    origin_u = f"{parsed.scheme}://{parsed.netloc}"
    results: List[Dict[str, Any]] = []
    results.extend(probe_cors(origin_u, opener))
    results.extend(probe_open_redirects(origin_u, disc, validate_fn=validate_fn))
    results.extend(probe_exposures_and_traversal(origin_u, disc, opener, base_path=parsed.path, session_ctx=session_ctx, validate_fn=validate_fn))
    results.extend(probe_csrf_forms(disc, headers_and_cookies))
    confirmed = [r for r in results if r.get("is_vulnerability") is True]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }
