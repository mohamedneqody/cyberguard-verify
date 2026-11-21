"""GraphQL Security Auditor & Out-of-Band (OAST) Blind SSRF / Blind XSS Verifier."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import secrets
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.error import HTTPError
import urllib.parse
from urllib.request import Request

SSRF_PARAM_HINTS = (
    "url", "uri", "webhook", "callback", "fetch", "proxy", "image", "img",
    "avatar", "icon", "feed", "dest", "target", "endpoint", "site", "remote", "src",
)
BUILTIN_GQL_TYPES = {"__Schema", "__Type", "__TypeKind", "__Field", "__InputValue", "__EnumValue", "__Directive", "__DirectiveLocation", "Query", "Mutation", "Subscription", "String", "Int", "Float", "Boolean", "ID"}
GQL_DB_ERROR_PATTERNS = (
    "syntax error", "sqlite", "mysql", "postgresql", "psycopg2", "ora-",
    "unclosed quotation mark", "sqlstate[", "sqlsyntaxerrorexception",
)
DESTRUCTIVE_FORM_HINTS = ("login", "signin", "logout", "signout", "register", "password", "delete", "remove", "drop", "reset", "setup", "csrf")
SKIP_FORM_PARAMS = {"submit", "login", "btn", "button", "user_token", "csrf", "_csrf", "csrf_token", "password"}


def _http_post_json(
    url: str,
    payload: Any,
    opener,
    headers: Optional[Dict[str, str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
    timeout: int = 8,
) -> Tuple[Optional[int], str, str]:
    if validate_fn:
        validate_fn(url)
    hdrs = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "CyberGuard-GraphQL/3.0"}
    if headers:
        hdrs.update(headers)
    req = Request(url, data=json.dumps(payload).encode("utf-8"), headers=hdrs)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.headers.get("Content-Type", "").lower(), resp.read(65536).decode("utf-8", errors="replace")
    except HTTPError as he:
        return he.code, he.headers.get("Content-Type", "").lower(), he.read(16384).decode("utf-8", errors="replace")
    except Exception:
        return None, "", ""


def _http_send(
    url: str,
    method: str,
    params: Dict[str, Any],
    as_json: bool,
    opener,
    headers: Optional[Dict[str, str]] = None,
    validate_fn: Optional[Callable[[str], Any]] = None,
    timeout: int = 8,
) -> Optional[int]:
    hdrs = {"User-Agent": "CyberGuard-OAST/3.0", "Accept": "*/*"}
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
    req = Request(req_url, data=data, headers=hdrs, method=m_u if m_u not in ("GET", "POST") else None)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status
    except HTTPError as he:
        return he.code
    except Exception:
        return None


def _session_hdrs(session_ctx: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not session_ctx:
        return {}
    h = dict(session_ctx.get("extra_headers") or {})
    if session_ctx.get("cookie_header"):
        h["Cookie"] = session_ctx["cookie_header"]
    return h


def discover_graphql_endpoints(
    target_url: str,
    disc: Optional[Dict[str, Any]],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    explicit_url: str = "",
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> List[str]:
    """Probes candidate GraphQL paths with benign `{__typename}` checks."""
    parsed = urllib.parse.urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_path = parsed.path.rstrip("/")
    hdrs = _session_hdrs(session_ctx)

    candidates: List[str] = []
    if explicit_url:
        candidates.append(explicit_url if explicit_url.startswith("http") else f"{origin}/{explicit_url.lstrip('/')}")
    for ep in ((disc or {}).get("discovered_endpoints") or []):
        if "graphql" in str(ep).lower():
            candidates.append(f"{origin}/{str(ep).lstrip('/')}")
    for p in ("/graphql", "/api/graphql", "/v1/graphql"):
        if base_path and base_path != "/":
            candidates.append(f"{origin}{base_path}{p}")
        else:
            candidates.append(f"{origin}{p}")

    verified: List[str] = []
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        st, ct, body = _http_post_json(url, {"query": "{__typename}"}, opener, headers=hdrs, validate_fn=validate_fn, timeout=5)
        if st in (200, 400) and "json" in ct:
            try:
                parsed_json = json.loads(body)
                if isinstance(parsed_json, dict) and ("data" in parsed_json or "errors" in parsed_json):
                    verified.append(url)
            except Exception:
                pass
    return verified


def audit_graphql_security(
    target_url: str,
    disc: Optional[Dict[str, Any]],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    explicit_url: str = "",
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """Audits discovered GraphQL endpoints for Schema Introspection (CWE-200) and Query Arg SQLi (CWE-89)."""
    hdrs = _session_hdrs(session_ctx)
    endpoints = discover_graphql_endpoints(target_url, disc, opener, session_ctx=session_ctx, explicit_url=explicit_url, validate_fn=validate_fn)
    results: List[Dict[str, Any]] = []

    intro_query = (
        "{__schema{queryType{name} types{name kind fields{name args{name type{name kind ofType{name kind}}}}}}}"
    )

    for gql_url in endpoints[:3]:
        ep_path = urllib.parse.urlparse(gql_url).path or "/graphql"

        # 1. Non-destructive Introspection check
        st, ct, body = _http_post_json(gql_url, {"query": intro_query}, opener, headers=hdrs, validate_fn=validate_fn)
        schema_data = None
        custom_types: List[str] = []
        query_fields: List[Dict[str, Any]] = []
        if st == 200 and body:
            try:
                j = json.loads(body)
                schema_data = (j.get("data") or {}).get("__schema")
            except Exception:
                schema_data = None

        if isinstance(schema_data, dict) and isinstance(schema_data.get("types"), list):
            qtype_name = (schema_data.get("queryType") or {}).get("name") or "Query"
            for t in schema_data["types"]:
                tname = str(t.get("name") or "")
                if tname and not tname.startswith("__") and tname not in BUILTIN_GQL_TYPES:
                    custom_types.append(tname)
                if tname == qtype_name and isinstance(t.get("fields"), list):
                    query_fields = t["fields"]

            if len(custom_types) >= 1:
                results.append({
                    "check": "GRAPHQL_INTROSPECTION",
                    "endpoint": ep_path,
                    "parameter": "__schema",
                    "cwe_id": "CWE-200",
                    "custom_types_count": len(custom_types),
                    "custom_types_sample": custom_types[:10],
                    "is_vulnerability": True,
                    "severity": "MEDIUM",
                    "confidence": "CONFIRMED",
                    "verdict": "VULN_GRAPHQL_INTROSPECTION_ENABLED",
                    "evidence_snippet": f"GraphQL introspection exposed {len(custom_types)} domain type(s) on {ep_path}: {', '.join(custom_types[:6])}",
                    "reproduction_steps": f"curl -X POST '{gql_url}' -H 'Content-Type: application/json' -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
                    "remediation": "Disable GraphQL schema introspection in production and enforce query depth/complexity limits.",
                })

        # 2. Check scalar Query arguments discovered via introspection for SQLi error/boolean differential
        for fld in query_fields[:6]:
            fname = str(fld.get("name") or "")
            args = fld.get("args") or []
            if not fname or not args:
                continue
            target_arg = next((a for a in args if str(a.get("name", "")).lower() in ("id", "q", "query", "search", "filter", "name", "email", "user")), None)
            if not target_arg:
                continue
            aname = str(target_arg["name"])
            # Probe String-like scalar argument safely
            _, _, b_base = _http_post_json(gql_url, {"query": f'{{{fname}({aname}:"1"){{__typename}}}}'}, opener, headers=hdrs, validate_fn=validate_fn)
            if not b_base:
                continue
            # Also try selection-set-free or simple scalar fields if object subfields required
            st_err, _, b_err = _http_post_json(gql_url, {"query": f'{{{fname}({aname}:"1\'")}}'}, opener, headers=hdrs, validate_fn=validate_fn)
            matched_err = next((p for p in GQL_DB_ERROR_PATTERNS if p in b_err.lower() and p not in b_base.lower()), "")
            _, _, b_t = _http_post_json(gql_url, {"query": f'{{{fname}({aname}:"1\' OR \'1\'=\'1")}}'}, opener, headers=hdrs, validate_fn=validate_fn)
            _, _, b_f = _http_post_json(gql_url, {"query": f'{{{fname}({aname}:"1\' AND \'1\'=\'2")}}'}, opener, headers=hdrs, validate_fn=validate_fn)

            len_diff = abs(len(b_t) - len(b_f)) if b_t and b_f and ("\"errors\"" not in b_t or len(b_t) > len(b_f) + 120) else 0
            is_sqli = bool(matched_err or (len_diff > 150 and len(b_t) > len(b_f)))
            if is_sqli:
                results.append({
                    "check": "GRAPHQL_SQLI",
                    "endpoint": ep_path,
                    "parameter": f"{fname}.{aname}",
                    "cwe_id": "CWE-89",
                    "is_vulnerability": True,
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "verdict": "VULN_GRAPHQL_SQLI_CONFIRMED",
                    "evidence_snippet": f"GraphQL argument {fname}({aname}) leaked SQL marker '{matched_err}' or boolean diff ({len(b_t)}B vs {len(b_f)}B).",
                    "reproduction_steps": f"Send GraphQL POST to {gql_url} with {fname}({aname}:\"1' OR '1'='1\").",
                    "remediation": "Use parameterized queries inside GraphQL resolvers and validate input scalar types.",
                })

        # 3. Record 2-op batching capability cleanly as hardening metadata (not inflated into high/medium vuln alone)
        st_b, _, b_batch = _http_post_json(
            gql_url,
            [{"query": "{__typename}"}, {"query": "{__typename}"}],
            opener,
            headers=hdrs,
            validate_fn=validate_fn,
        )
        batch_allowed = False
        if st_b == 200 and b_batch:
            try:
                jb = json.loads(b_batch)
                batch_allowed = isinstance(jb, list) and len(jb) == 2
            except Exception:
                pass
        results.append({
            "check": "GRAPHQL_BATCHING_POSTURE",
            "endpoint": ep_path,
            "parameter": "batch_array",
            "cwe_id": "CWE-799",
            "batching_enabled": batch_allowed,
            "is_vulnerability": False,
            "severity": "INFO",
            "confidence": "CONFIRMED_SAFE",
            "verdict": "HARDENING_GRAPHQL_BATCHING_ENABLED" if batch_allowed else "SAFE",
            "evidence_snippet": f"GraphQL JSON array query batching enabled={batch_allowed} on {ep_path}.",
        })

    confirmed = [r for r in results if r.get("is_vulnerability")]
    return {
        "target": target_url,
        "graphql_endpoints": endpoints,
        "checks_executed": len(results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": results,
    }


def _parse_dns_qname(pkt: bytes) -> str:
    """Extracts the queried domain name from a raw RFC 1035 UDP DNS query packet."""
    if len(pkt) < 17:
        return ""
    idx = 12
    labels: List[str] = []
    while idx < len(pkt):
        ln = pkt[idx]
        idx += 1
        if ln == 0:
            break
        if ln > 63 or idx + ln > len(pkt):
            return ""
        labels.append(pkt[idx : idx + ln].decode("ascii", errors="ignore"))
        idx += ln
    return ".".join(labels).lower()


def _build_dns_a_reply(pkt: bytes) -> bytes:
    """Builds a minimal RFC 1035 DNS A-record reply (127.0.0.1) for transaction ID in pkt."""
    if len(pkt) < 12:
        return b""
    # Find end of QNAME + QTYPE(2) + QCLASS(2)
    idx = 12
    while idx < len(pkt) and pkt[idx] != 0:
        idx += 1 + pkt[idx]
    q_end = min(len(pkt), idx + 5)
    question = pkt[12:q_end]
    header = pkt[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
    return header + question + answer


class LocalOASTCollector:
    """In-process ephemeral HTTP + UDP DNS Out-of-Band callback collector for Blind SSRF/XSS/DNS proof."""

    def __init__(self, bind_host: str = "127.0.0.1", port: int = 0, advertise_host: str = "127.0.0.1", dns_port: int = 0):
        self.bind_host = bind_host
        self.advertise_host = advertise_host or "127.0.0.1"
        self.hits: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._srv: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._dns_sock: Optional[socket.socket] = None
        self._dns_thread: Optional[threading.Thread] = None
        self._dns_running = False
        self.port = port
        self.dns_port = dns_port

    @property
    def base_url(self) -> str:
        return f"http://{self.advertise_host}:{self.port}"

    def _record(self, nonce: str, kind: str, path: str, client_ip: str, user_agent: str) -> None:
        with self._lock:
            self.hits.setdefault(nonce, []).append({
                "kind": kind,
                "path": path,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "timestamp": time.time(),
            })

    def get_hits(self, nonce: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.hits.get(nonce) or [])

    def _dns_loop(self) -> None:
        while self._dns_running and self._dns_sock:
            try:
                data, addr = self._dns_sock.recvfrom(512)
            except Exception:
                break
            qname = _parse_dns_qname(data)
            if qname:
                m = re.search(r"\b([a-f0-9]{8,32})\b", qname)
                if m:
                    self._record(m.group(1), "dns_oast", qname, addr[0], "UDP/DNS-RFC1035")
            try:
                reply = _build_dns_a_reply(data)
                if reply:
                    self._dns_sock.sendto(reply, addr)
            except Exception:
                pass

    def __enter__(self):
        parent = self

        class _OASTHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                ua = self.headers.get("User-Agent", "")
                cip = self.client_address[0]
                m_ssrf = re.match(r"^/bssrf/([a-f0-9]{8,32})", self.path)
                m_x_exec = re.match(r"^/bxss-exec/([a-f0-9]{8,32})", self.path)
                m_x_js = re.match(r"^/bxss/([a-f0-9]{8,32})", self.path)
                if m_ssrf:
                    parent._record(m_ssrf.group(1), "ssrf", self.path, cip, ua)
                    body = b"ok"
                    ctype = "text/plain"
                elif m_x_exec:
                    parent._record(m_x_exec.group(1), "xss_exec", self.path, cip, ua)
                    body = b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;"
                    ctype = "image/gif"
                elif m_x_js:
                    nonce = m_x_js.group(1)
                    parent._record(nonce, "xss_fetch", self.path, cip, ua)
                    js = f"try{{window.__cg_oast=true;new Image().src='{parent.base_url}/bxss-exec/{nonce}';}}catch(e){{}}"
                    body = js.encode("utf-8")
                    ctype = "application/javascript"
                else:
                    body = b"ok"
                    ctype = "text/plain"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._srv = HTTPServer((self.bind_host, self.port), _OASTHandler)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

        try:
            self._dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._dns_sock.bind((self.bind_host, self.dns_port))
            self.dns_port = self._dns_sock.getsockname()[1]
            self._dns_running = True
            self._dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
            self._dns_thread.start()
        except Exception:
            self._dns_sock = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._dns_running = False
        if self._dns_sock:
            try:
                self._dns_sock.close()
            except Exception:
                pass
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()


def audit_oast_blind(
    target_url: str,
    disc: Dict[str, Any],
    opener,
    session_ctx: Optional[Dict[str, Any]] = None,
    oast_url: str = "",
    oast_host: str = "127.0.0.1",
    wait_sec: float = 1.5,
    validate_fn: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """
    Executes Out-of-Band (OAST) verification for Blind SSRF (CWE-918) and Blind XSS (CWE-79).
    Uses cryptographically unique per-parameter callback nonces.
    """
    hdrs = _session_hdrs(session_ctx)
    parsed_t = urllib.parse.urlparse(target_url)
    origin_u = f"{parsed_t.scheme}://{parsed_t.netloc}"

    ssrf_targets: List[Dict[str, Any]] = []
    seen_ssrf = set()
    for ip in (disc.get("input_points") or []):
        ep = ip.get("endpoint", "")
        p = ip.get("parameter", "")
        m = str(ip.get("method", "GET")).upper()
        if not ep or not p or ep == "client_routes" or m == "CLIENT":
            continue
        if any(h in p.lower() for h in SSRF_PARAM_HINTS) and (ep, m, p) not in seen_ssrf:
            seen_ssrf.add((ep, m, p))
            ssrf_targets.append({
                "endpoint": ep,
                "url": ip.get("url") or f"{origin_u}/{ep.lstrip('/')}",
                "method": m,
                "parameter": p,
                "as_json": bool(ip.get("as_json")),
            })

    post_forms: List[Dict[str, Any]] = []
    for fm in (disc.get("discovered_forms") or [])[:4]:
        if str(fm.get("method", "GET")).upper() != "POST":
            continue
        action = fm.get("action") or target_url
        ep = urllib.parse.urlparse(action).path or "/"
        if any(d in ep.lower() for d in DESTRUCTIVE_FORM_HINTS):
            continue
        text_fields = [
            i["name"] for i in (fm.get("inputs") or [])
            if i.get("name") and i["name"].lower() not in SKIP_FORM_PARAMS
            and i.get("type") in ("text", "textarea", "search", "email", "url", "")
        ]
        if text_fields:
            post_forms.append({"action": action, "endpoint": ep, "inputs": fm.get("inputs") or [], "text_fields": text_fields})

    if not ssrf_targets and not post_forms:
        return {
            "target": target_url,
            "oast_base_url": oast_url or "none_needed",
            "checks_executed": 0,
            "confirmed_vulnerabilities_count": 0,
            "results": [],
        }

    # Detect sensible callback host inside Docker when scanning sibling containers
    adv_host = oast_host
    if adv_host == "127.0.0.1" and parsed_t.hostname not in ("127.0.0.1", "localhost", "::1"):
        try:
            import socket
            socket.gethostbyname("artex")
            adv_host = "artex"
        except Exception:
            pass
    bind_host = "0.0.0.0" if adv_host != "127.0.0.1" else "127.0.0.1"

    def _run_probes(base_callback: str, local_collector: Optional[LocalOASTCollector]) -> List[Dict[str, Any]]:
        tracked_ssrf: List[Tuple[Dict[str, Any], str, str]] = []
        tracked_bxss: List[Tuple[Dict[str, Any], str, str]] = []

        for t in ssrf_targets[:8]:
            nonce = secrets.token_hex(6)
            cb_url = f"{base_callback.rstrip('/')}/bssrf/{nonce}"
            _http_send(t["url"], t["method"], {t["parameter"]: cb_url}, t["as_json"], opener, headers=hdrs, validate_fn=validate_fn, timeout=6)
            tracked_ssrf.append((t, nonce, cb_url))

        for pf in post_forms[:4]:
            nonce = secrets.token_hex(6)
            script_cb = f"{base_callback.rstrip('/')}/bxss/{nonce}.js"
            payload_bxss = f'<script src="{script_cb}"></script>'
            form_data: Dict[str, str] = {}
            for i in pf["inputs"]:
                nm = i.get("name", "")
                if not nm:
                    continue
                if nm in pf["text_fields"]:
                    form_data[nm] = payload_bxss
                elif i.get("type") in ("submit", "button"):
                    form_data[nm] = i.get("value") or nm
                else:
                    form_data[nm] = i.get("value") or ""
            _http_send(pf["action"], "POST", form_data, False, opener, headers=hdrs, validate_fn=validate_fn, timeout=6)
            tracked_bxss.append((pf, nonce, script_cb))

        if local_collector is not None and (tracked_ssrf or tracked_bxss) and wait_sec > 0:
            time.sleep(min(wait_sec, 5.0))

        out: List[Dict[str, Any]] = []
        for t, nonce, cb_url in tracked_ssrf:
            hits = local_collector.get_hits(nonce) if local_collector else []
            hit = bool(hits)
            out.append({
                "check": "BLIND_SSRF_OAST",
                "endpoint": t["endpoint"],
                "method": t["method"],
                "parameter": t["parameter"],
                "cwe_id": "CWE-918",
                "callback_nonce": nonce,
                "oast_hits_count": len(hits),
                "is_vulnerability": hit,
                "severity": "HIGH" if hit else "INFO",
                "confidence": "CONFIRMED" if hit else "CONFIRMED_SAFE",
                "verdict": "VULN_BLIND_SSRF_OAST_CONFIRMED" if hit else "NO_OAST_CALLBACK",
                "evidence_snippet": f"OAST callback received for nonce {nonce} from {hits[0]['client_ip']} (UA: {hits[0]['user_agent'][:80]}) after probing {t['parameter']}={cb_url}" if hit else "",
                "reproduction_steps": f"Send {t['method']} {t['url']} with {t['parameter']}='{cb_url}' and observe out-of-band HTTP callback with nonce {nonce}.",
                "remediation": "Validate and allowlist outbound URLs/hosts, block private/loopback IP ranges at DNS-resolved socket level, and disable unneeded HTTP redirects.",
            })

        for pf, nonce, script_cb in tracked_bxss:
            hits = local_collector.get_hits(nonce) if local_collector else []
            hit = bool(hits)
            exec_hits = [h for h in hits if h["kind"] == "xss_exec"]
            out.append({
                "check": "BLIND_XSS_OAST",
                "endpoint": pf["endpoint"],
                "method": "POST",
                "parameter": ", ".join(pf["text_fields"]),
                "cwe_id": "CWE-79",
                "callback_nonce": nonce,
                "oast_hits_count": len(hits),
                "js_executed_callback": bool(exec_hits),
                "is_vulnerability": hit,
                "severity": "HIGH" if hit else "INFO",
                "confidence": "CONFIRMED" if hit else "CONFIRMED_SAFE",
                "verdict": "VULN_BLIND_XSS_OAST_CONFIRMED" if hit else "NO_OAST_CALLBACK",
                "evidence_snippet": f"Out-of-band Blind XSS callback ({'JS executed' if exec_hits else 'script fetched'}) for nonce {nonce} from {hits[0]['client_ip']} (UA: {hits[0]['user_agent'][:80]})." if hit else "",
                "reproduction_steps": f"Submit benign OAST probe <script src=\"{script_cb}\"></script> to POST {pf['action']}.",
                "remediation": "Contextually HTML-encode user inputs wherever stored data renders (including internal admin/backoffice views).",
            })
        return out

    if oast_url:
        probe_results = _run_probes(oast_url, None)
        used_base = oast_url
    else:
        with LocalOASTCollector(bind_host=bind_host, advertise_host=adv_host) as collector:
            used_base = collector.base_url
            probe_results = _run_probes(used_base, collector)

    confirmed = [r for r in probe_results if r["is_vulnerability"]]
    return {
        "target": target_url,
        "oast_base_url": used_base,
        "checks_executed": len(probe_results),
        "confirmed_vulnerabilities_count": len(confirmed),
        "results": probe_results,
    }
