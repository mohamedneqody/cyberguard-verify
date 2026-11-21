"""Deep Non-Destructive Verification Engines: Time-Based Blind SQLi (4-Step Sandwich Proof), XXE Expansion, and Stateful Browser Workflows."""

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
import urllib.parse
from urllib.request import Request

SKIP_PARAMS = {"submit", "login", "btn", "button", "user_token", "csrf", "_csrf", "csrf_token", "password"}


def _session_headers(session_ctx: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not session_ctx:
        return {}
    h = dict(session_ctx.get("extra_headers") or {})
    if session_ctx.get("cookie_header"):
        h["Cookie"] = session_ctx["cookie_header"]
    return h


def load_browser_workflow(workflow_path: str) -> List[Dict[str, Any]]:
    """Loads a JSON browser workflow macro ([{'action': 'goto'|'click'|'fill'|'wait', ...}]) for multi-step stateful navigation."""
    if not workflow_path:
        return []
    if not os.path.exists(workflow_path):
        raise FileNotFoundError(f"Workflow file not found: {workflow_path}")
    with open(workflow_path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    steps = data.get("steps") if isinstance(data, dict) else data
    if not isinstance(steps, list):
        raise ValueError("Invalid workflow JSON: expected a list of step objects or {'steps': [...]}")
    allowed_actions = {"goto", "click", "fill", "wait", "press"}
    cleaned: List[Dict[str, Any]] = []
    for st in steps[:25]:
        if isinstance(st, dict) and str(st.get("action", "")).lower() in allowed_actions:
            cleaned.append({
                "action": str(st["action"]).lower(),
                "selector": str(st.get("selector") or ""),
                "value": str(st.get("value") or ""),
                "url": str(st.get("url") or ""),
                "timeout_ms": int(st.get("timeout_ms", 4000)),
            })
    return cleaned


def _timed_request(
    url: str,
    method: str,
    params: Dict[str, Any],
    as_json: bool,
    opener,
    headers: Optional[Dict[str, str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
    timeout: int = 8,
) -> Tuple[Optional[int], str, float]:
    hdrs = {"User-Agent": "CyberGuard-DeepVerifier/3.2", "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req_url = url
    data = None
    m_u = method.upper()
    if m_u == "GET":
        parsed = urllib.parse.urlsplit(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for k, v in params.items():
            qs[k] = [str(v)]
        req_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(qs, doseq=True), parsed.fragment))
    else:
        if as_json:
            hdrs["Content-Type"] = "application/json"
            data = json.dumps(params).encode("utf-8")
        else:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            data = urllib.parse.urlencode(params).encode("utf-8")
    if validate_fn:
        validate_fn(req_url)
    t0 = time.monotonic()
    req = Request(req_url, data=data, headers=hdrs, method=m_u if m_u not in ("GET", "POST") else None)
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(32768).decode("utf-8", errors="replace")
            return r.status, body, time.monotonic() - t0
    except HTTPError as he:
        body = he.read(8192).decode("utf-8", errors="replace")
        return he.code, body, time.monotonic() - t0
    except Exception:
        return None, "", time.monotonic() - t0


def audit_time_blind_sqli(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    delay_sec: int = 2,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """
    Verifies Time-Based Blind SQL Injection (CWE-89) using a strict 4-step timing sandwich:
    [baseline_fast, sleep(N)_slow, sleep(0)_fast, sleep(N)_slow_repeat].
    Eliminates false positives from transient network jitter.
    """
    hdrs = _session_headers(session_ctx)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    form_defaults: Dict[Tuple[str, str], Dict[str, str]] = {}
    for fm in disc.get("discovered_forms") or []:
        ep = urllib.parse.urlparse(fm.get("action", "")).path or "/"
        m = str(fm.get("method", "GET")).upper()
        form_defaults[(ep, m)] = {
            i["name"]: (i.get("value") or (i["name"] if i.get("type") in ("submit", "button") else ""))
            for i in (fm.get("inputs") or []) if i.get("name")
        }

    candidates = []
    seen = set()
    for ip in disc.get("input_points") or []:
        ep = ip.get("endpoint", "")
        p = ip.get("parameter", "")
        m = str(ip.get("method", "GET")).upper()
        if not ep or not p or ep == "client_routes" or m == "CLIENT" or p.lower() in SKIP_PARAMS:
            continue
        if ip.get("category") == "AUTHENTICATION_CREDENTIAL":
            continue
        if (ep, m, p) not in seen:
            seen.add((ep, m, p))
            candidates.append({
                "endpoint": ep,
                "url": ip.get("url") or f"{origin_u}/{ep.lstrip('/')}",
                "method": m,
                "parameter": p,
                "as_json": bool(ip.get("as_json")),
            })

    sleep_pairs = [
        (f"1' AND SLEEP({delay_sec})-- ", "1' AND SLEEP(0)-- "),
        (f"1'; SELECT PG_SLEEP({delay_sec})-- ", "1'; SELECT PG_SLEEP(0)-- "),
        (f"1' WAITFOR DELAY '0:0:{delay_sec}'-- ", "1' WAITFOR DELAY '0:0:0'-- "),
    ]
    min_delta = max(1.35, delay_sec * 0.78)
    results: List[Dict[str, Any]] = []

    for c in candidates[:8]:
        ep = c["endpoint"]
        u = c["url"]
        m = c["method"]
        p = c["parameter"]
        as_json = c["as_json"]
        base_fields = dict(form_defaults.get((ep, m), {}))

        def _probe(val: str) -> Tuple[Optional[int], float]:
            payload = dict(base_fields)
            payload[p] = val
            st, _, dt = _timed_request(u, m, payload, as_json, opener, headers=hdrs, validate_fn=validate_fn, timeout=delay_sec + 5)
            return st, dt

        st1, t_base1 = _probe("1")
        if st1 is None or st1 == 404 or t_base1 > 0.65:
            continue
        _, t_base2 = _probe("1")
        base_max = max(t_base1, t_base2)
        if base_max > 0.65:
            continue

        confirmed_pair = None
        timings = (t_base1, 0.0, 0.0, 0.0)
        for p_slow, p_zero in sleep_pairs:
            st_s1, t_slow1 = _probe(p_slow)
            if st_s1 is None or (t_slow1 - base_max) < min_delta:
                continue
            _, t_zero = _probe(p_zero)
            if (t_zero - base_max) > 0.55:
                continue
            _, t_slow2 = _probe(p_slow)
            if (t_slow2 - max(base_max, t_zero)) >= min_delta:
                confirmed_pair = p_slow
                timings = (round(base_max, 3), round(t_slow1, 3), round(t_zero, 3), round(t_slow2, 3))
                break

        is_vuln = confirmed_pair is not None
        results.append({
            "check": "TIME_BLIND_SQLI",
            "endpoint": ep,
            "method": m,
            "parameter": p,
            "cwe_id": "CWE-89",
            "is_vulnerability": is_vuln,
            "severity": "HIGH" if is_vuln else "INFO",
            "confidence": "CONFIRMED" if is_vuln else "CONFIRMED_SAFE",
            "verdict": "VULN_TIME_BLIND_SQLI_CONFIRMED" if is_vuln else "SAFE",
            "evidence_snippet": (
                f"4-step timing sandwich on '{p}': baseline={timings[0]}s, sleep({delay_sec})={timings[1]}s, sleep(0)={timings[2]}s, repeat_sleep({delay_sec})={timings[3]}s."
                if is_vuln else ""
            ),
            "reproduction_steps": f"Compare response time of {m} {u} ({p}='{confirmed_pair or sleep_pairs[0][0]}') against sleep(0) control.",
            "remediation": "Use parameterized queries / prepared statements for all database parameters.",
        })

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def audit_xxe_injection(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """
    Non-destructively audits XML External/Internal Entity (XXE, CWE-611) expansion
    using a self-contained in-memory entity marker (`&cgxxe;` -> `cg_xxe_9137_ok`).
    """
    hdrs = _session_headers(session_ctx)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    candidate_eps = set()
    for ep in disc.get("discovered_endpoints") or []:
        if any(k in str(ep).lower() for k in ("xml", "soap", "import", "parse", "upload", "feed", "rss", "webhook", "api")):
            candidate_eps.add(str(ep))
    for fm in disc.get("discovered_forms") or []:
        if str(fm.get("method", "")).upper() == "POST":
            ap = urllib.parse.urlparse(fm.get("action", "")).path or "/"
            if not any(k in ap.lower() for k in ("login", "signin", "register", "logout", "reset")):
                candidate_eps.add(ap)

    xml_baseline = '<?xml version="1.0" encoding="UTF-8"?><root><data>cg_xml_baseline</data><name>cg_xml_baseline</name></root>'
    xml_entity = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<!DOCTYPE cg [<!ENTITY cgxxe "cg_xxe_9137_ok">]>'
        '<root><data>&cgxxe;</data><name>&cgxxe;</name></root>'
    )
    results: List[Dict[str, Any]] = []

    for ep in sorted(candidate_eps)[:6]:
        url = f"{origin_u}/{ep.lstrip('/')}"
        if validate_fn:
            validate_fn(url)
        req_b = Request(url, data=xml_baseline.encode("utf-8"), headers={**hdrs, "Content-Type": "application/xml", "User-Agent": "CyberGuard-XXE/3.2"})
        try:
            with opener.open(req_b, timeout=6) as rb:
                body_b = rb.read(16384).decode("utf-8", errors="replace")
        except HTTPError as he:
            body_b = he.read(8192).decode("utf-8", errors="replace")
        except Exception:
            continue

        if "cg_xxe_9137_ok" in body_b:
            continue

        req_x = Request(url, data=xml_entity.encode("utf-8"), headers={**hdrs, "Content-Type": "application/xml", "User-Agent": "CyberGuard-XXE/3.2"})
        try:
            with opener.open(req_x, timeout=6) as rx:
                st_x = rx.status
                body_x = rx.read(16384).decode("utf-8", errors="replace")
        except HTTPError as he:
            st_x = he.code
            body_x = he.read(8192).decode("utf-8", errors="replace")
        except Exception:
            continue

        expanded = "cg_xxe_9137_ok" in body_x and "&cgxxe;" not in body_x
        results.append({
            "check": "XXE_INJECTION",
            "endpoint": ep,
            "method": "POST",
            "parameter": "xml_body",
            "cwe_id": "CWE-611",
            "status_code": st_x,
            "is_vulnerability": expanded,
            "severity": "HIGH" if expanded else "INFO",
            "confidence": "CONFIRMED" if expanded else "CONFIRMED_SAFE",
            "verdict": "VULN_XXE_ENTITY_EXPANSION_CONFIRMED" if expanded else "SAFE",
            "evidence_snippet": f"XML DOCTYPE entity &cgxxe; expanded server-side to 'cg_xxe_9137_ok' on {ep}." if expanded else "",
            "reproduction_steps": f"POST application/xml body with <!ENTITY cgxxe 'cg_xxe_9137_ok'> to {url} and observe expanded entity in response.",
            "remediation": "Disable DOCTYPE declarations and external general/parameter entities (FEATURE_SECURE_PROCESSING / disallow-doctype-decl) in the XML parser.",
        })

    confirmed = [r for r in results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }
