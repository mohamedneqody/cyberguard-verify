"""Comprehensive standalone unit & integration tests for cyberguard-verify v3.0."""

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import re
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request

from cyberguard_verify.advanced_checks import (
    audit_command_injection,
    audit_general_sqli,
    audit_jwt_security,
    audit_ssti,
    parse_openapi_targets,
)
from cyberguard_verify.baseline_diff import compute_baseline_diff
from cyberguard_verify.browser_verifier import BrowserXSSVerifier
from cyberguard_verify.cli import main as cli_main
from cyberguard_verify.engine import run_verification
from cyberguard_verify.graphql_oast import audit_graphql_security, audit_oast_blind
from cyberguard_verify.guardrails import SecurityBoundaryViolation, get_safe_opener, validate_target
from cyberguard_verify.report_export import build_html_report, build_sarif_report
from cyberguard_verify.session_auth import authenticate_session, detect_auth_gate, extract_jwts_from_text


def _make_hs256_jwt(payload: dict, secret: str) -> str:
    h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
    return f"{h}.{p}.{sig}"


class _MockVulnHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send(self, code: int, body: str, ctype: str = "text/html", extra_headers=None):
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        cookies = self.headers.get("Cookie", "")

        # Auth-gated subtree
        if parsed.path == "/gated":
            self.send_response(302)
            self.send_header("Location", "/gated/login")
            self.end_headers()
            return
        if parsed.path == "/gated/login":
            self._send(200, (
                '<html><body><form method="POST" action="/gated/login">'
                '<input type="hidden" name="user_token" value="csrf_tok_999"/>'
                '<input type="text" name="username"/>'
                '<input type="password" name="password"/>'
                '<button type="submit" name="Login" value="Login">Login</button>'
                '</form></body></html>'
            ))
            return
        if parsed.path == "/gated/panel":
            if "CG_SESS=ok" not in cookies:
                self.send_response(302)
                self.send_header("Location", "/gated/login")
                self.end_headers()
                return
            self._send(200, '<html><body><p>Welcome admin</p><a href="/gated/ping?ip=127.0.0.1">Ping</a></body></html>')
            return
        if parsed.path == "/gated/ping":
            ip_v = (qs.get("ip") or [""])[0]
            out = ""
            if "echo " in ip_v:
                tok = ip_v.split("echo ", 1)[1].split(";")[0].split("&")[0].strip()
                out = f"<pre>PING {ip_v}\n{tok}</pre>"
            self._send(200, f'<html><body><form method="GET" action="/gated/ping"><input name="ip" value="{ip_v}"/></form>{out}</body></html>')
            return

        # Full mock app root (links + query endpoints)
        if parsed.path == "/":
            self._send(200, (
                '<html><body>'
                '<a href="/sqli?id=1">SQLi Item</a>'
                '<a href="/tmpl?name=alice">Template</a>'
                '<a href="/ping?host=127.0.0.1">Ping</a>'
                '</body></html>'
            ))
            return

        if parsed.path == "/sqli":
            id_v = (qs.get("id") or ["1"])[0]
            if "'" in id_v and "OR" not in id_v:
                self._send(500, "SQLite3.OperationalError: unclosed quotation mark after ''")
                return
            if "OR" in id_v:
                self._send(200, "<html><body><pre>Surname: Admin | Secret row</pre>" * 5 + "</body></html>")
                return
            self._send(200, "<html><body><pre>Item 1</pre></body></html>")
            return

        if parsed.path == "/tmpl":
            nm = (qs.get("name") or ["guest"])[0]
            rendered = nm.replace("{{9137*7}}", "63959")
            self._send(200, f"<html><body>Hello {rendered}</body></html>")
            return

        if parsed.path == "/ping":
            hv = (qs.get("host") or ["127.0.0.1"])[0]
            extra = ""
            if "echo " in hv:
                tok = hv.split("echo ", 1)[1].split(";")[0].split("&")[0].strip()
                extra = f"\n{tok}"
            self._send(200, f"<html><body>PING {hv}{extra}</body></html>")
            return

        if parsed.path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "paths": {
                    "/api/orders/{id}": {
                        "get": {"parameters": [{"name": "filter", "in": "query"}]},
                        "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"note": {"type": "string"}}}}}}},
                    }
                },
            }
            self._send(200, json.dumps(spec), ctype="application/json")
            return

        if parsed.path == "/api/me":
            auth_h = self.headers.get("Authorization", "")
            if auth_h.startswith("Bearer "):
                tok = auth_h.split(" ", 1)[1].strip()
                hdr = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==").decode())
                if hdr.get("alg") == "none":
                    self._send(200, '{"user":"forged"}', ctype="application/json")
                    return
                if tok == _make_hs256_jwt({"sub": "1"}, "secret"):
                    self._send(200, '{"user":"alice"}', ctype="application/json")
                    return
            self._send(401, '{"error":"unauthorized"}', ctype="application/json")
            return

        if parsed.path == "/sso":
            auth_h = self.headers.get("Authorization", "")
            if "SSO_SESS=ok" not in cookies and "Bearer " not in auth_h:
                self.send_response(302)
                self.send_header("Location", "/gated/login")
                self.end_headers()
                return
            self._send(200, (
                '<html><body><h1>SSO Portal</h1>'
                '<a href="/webhook?url=http://127.0.0.1">Webhook</a>'
                '<form method="POST" action="/feedback"><input type="text" name="comment"/><button type="submit">Send</button></form>'
                '</body></html>'
            ))
            return

        if parsed.path == "/webhook":
            target_cb = (qs.get("url") or [""])[0]
            if target_cb.startswith("http://127.0.0.1:"):
                def _bg_fetch(cb=target_cb):
                    try:
                        urllib.request.urlopen(cb, timeout=3).read()
                    except Exception:
                        pass
                threading.Thread(target=_bg_fetch, daemon=True).start()
            self._send(200, "<html><body>Webhook queued</body></html>")
            return

        self._send(404, "Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = urllib.parse.parse_qs(body)
        if self.path == "/gated/login":
            if (form.get("user_token") or [""])[0] == "csrf_tok_999" and (form.get("username") or [""])[0] == "admin":
                self._send(
                    200,
                    '<html><body><p>Welcome admin! <a href="/gated/logout">Logout</a></p></body></html>',
                    extra_headers=[("Set-Cookie", "CG_SESS=ok; Path=/")],
                )
            else:
                self._send(200, "<html><body>Invalid credentials</body></html>")
            return
        if self.path == "/feedback":
            comment = (form.get("comment") or [""])[0]
            m = re.search(r"http://127\.0\.0\.1:[0-9]+/bxss/[a-f0-9]+\.js", comment)
            if m:
                js_url = m.group(0)
                exec_url = js_url.replace("/bxss/", "/bxss-exec/").replace(".js", "")
                def _bg_admin():
                    try:
                        urllib.request.urlopen(js_url, timeout=3).read()
                        urllib.request.urlopen(exec_url, timeout=3).read()
                    except Exception:
                        pass
                threading.Thread(target=_bg_admin, daemon=True).start()
            self._send(200, "<html><body>Thanks for your feedback</body></html>")
            return
        if self.path == "/graphql":
            try:
                req_json = json.loads(body)
            except Exception:
                self._send(400, '{"errors":[{"message":"bad json"}]}', ctype="application/json")
                return
            if isinstance(req_json, list):
                self._send(200, json.dumps([{"data": {"__typename": "Query"}} for _ in req_json]), ctype="application/json")
                return
            q = str(req_json.get("query") or "")
            if "__schema" in q:
                schema = {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {"name": "User", "kind": "OBJECT", "fields": [{"name": "email"}]},
                                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "user", "args": [{"name": "id", "type": {"name": "String", "kind": "SCALAR"}}]}]},
                            ],
                        }
                    }
                }
                self._send(200, json.dumps(schema), ctype="application/json")
                return
            if "user(" in q:
                if "1'" in q and "OR" not in q and "AND" not in q:
                    self._send(500, '{"errors":[{"message":"SQLite syntax error near 1\'"}]}', ctype="application/json")
                    return
                if "OR" in q:
                    self._send(200, json.dumps({"data": {"user": [{"id": "1"}, {"id": "2"}] * 10}}), ctype="application/json")
                    return
                self._send(200, json.dumps({"data": {"user": {"id": "1"}}}), ctype="application/json")
                return
            self._send(200, json.dumps({"data": {"__typename": "Query"}}), ctype="application/json")
            return
        self._send(404, "Not found")


class TestCyberGuardVerifyEngines(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _MockVulnHandler)
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_01_guardrails_block_metadata_and_external_hosts(self):
        with self.assertRaises(SecurityBoundaryViolation):
            validate_target("http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(SecurityBoundaryViolation):
            validate_target("https://example.com/")
        host, port = validate_target("http://127.0.0.1:8767")
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 8767)

    def test_02_unauthenticated_auth_gate_never_emits_secure(self):
        report = run_verification(f"{self.base}/gated")
        cv = report["composite_verdict"]
        cov = report["coverage_evaluation"]
        self.assertEqual(cv["overall_verdict"], "INCONCLUSIVE_AUTH_GATED")
        self.assertEqual(cov["coverage_status"], "PREAUTH_ONLY")
        self.assertFalse(cov["coverage_complete"])

    def test_03_csrf_aware_login_and_cookie_override_merge(self):
        sess = authenticate_session(
            target_url=f"{self.base}/gated/panel",
            login_url=f"{self.base}/gated/login",
            username="admin",
            password="pw",
            cookie_str="security=low",
        )
        self.assertTrue(sess["authenticated"])
        self.assertEqual(sess["method"], "form_login")
        self.assertIn("CG_SESS=ok", sess["cookie_header"])
        self.assertIn("security=low", sess["cookie_header"])

    def test_04_openapi_general_sqli_cmdi_ssti_jwt_detection(self):
        opener = get_safe_opener()
        oa_eps, oa_ips = parse_openapi_targets(self.base, "/", opener)
        self.assertIn("/api/orders/102", oa_eps)
        self.assertTrue(any(ip["parameter"] == "note" and ip.get("as_json") for ip in oa_ips))

        disc = {
            "input_points": [
                {"endpoint": "/sqli", "url": f"{self.base}/sqli", "method": "GET", "parameter": "id"},
                {"endpoint": "/ping", "url": f"{self.base}/ping", "method": "GET", "parameter": "host"},
                {"endpoint": "/tmpl", "url": f"{self.base}/tmpl", "method": "GET", "parameter": "name"},
            ],
            "discovered_forms": [],
        }

        sqli_r = audit_general_sqli(self.base, disc, opener)
        self.assertEqual(sqli_r["confirmed_vulnerabilities_count"], 1)

        cmdi_r = audit_command_injection(self.base, disc, opener)
        self.assertEqual(cmdi_r["confirmed_vulnerabilities_count"], 1)

        ssti_r = audit_ssti(self.base, disc, opener)
        self.assertEqual(ssti_r["confirmed_vulnerabilities_count"], 1)

        weak_jwt = _make_hs256_jwt({"sub": "1"}, "secret")
        jwt_r = audit_jwt_security(
            self.base,
            opener,
            session_ctx={"extra_headers": {"Authorization": f"Bearer {weak_jwt}"}, "captured_jwts": extract_jwts_from_text(weak_jwt)},
            protected_url=f"{self.base}/api/me",
        )
        self.assertEqual(jwt_r["confirmed_vulnerabilities_count"], 1)
        self.assertEqual(jwt_r["results"][0]["verdict"], "VULN_JWT_ALG_NONE_BYPASS")

    def test_05_full_verdict_sarif_html_and_ci_exit(self):
        report = run_verification(self.base)
        cv = report["composite_verdict"]
        self.assertEqual(cv["overall_verdict"], "VULNERABLE")
        cats = {v["category"] for v in cv["confirmed_vulnerabilities"]}
        self.assertTrue({"GENERAL_SQLI", "CMDI", "SSTI"}.issubset(cats))

        sarif = build_sarif_report(self.base, report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 3)

        html_doc = build_html_report(self.base, report)
        self.assertIn("CyberGuard", html_doc)
        self.assertIn("VULNERABLE", html_doc)
        self.assertIn("CWE-89", html_doc)

        with tempfile.TemporaryDirectory() as td:
            out_sarif = os.path.join(td, "out.sarif")
            rc = cli_main([f"{self.base}/gated", "--format", "sarif", "--out", out_sarif, "--ci"])
            self.assertEqual(rc, 1)
            self.assertTrue(os.path.exists(out_sarif))

    def test_06_playwright_storage_state_sso_and_localstorage_jwt(self):
        sso_jwt = _make_hs256_jwt({"sub": "sso_admin"}, "secret")
        storage_doc = {
            "cookies": [{"name": "SSO_SESS", "value": "ok", "domain": "127.0.0.1", "path": "/", "expires": -1}],
            "origins": [{"origin": self.base, "localStorage": [{"name": "token", "value": sso_jwt}]}],
        }
        with tempfile.TemporaryDirectory() as td:
            ss_path = os.path.join(td, "auth.json")
            with open(ss_path, "w", encoding="utf-8") as fh:
                json.dump(storage_doc, fh)

            sess = authenticate_session(target_url=f"{self.base}/sso", storage_state_path=ss_path)
            self.assertTrue(sess["authenticated"])
            self.assertEqual(sess["method"], "storage_state")
            self.assertIn("SSO_SESS=ok", sess["cookie_header"])
            self.assertIn("Bearer ", sess["extra_headers"].get("Authorization", ""))
            self.assertIn(sso_jwt, sess["captured_jwts"])

            # Verify SSO page reached cleanly without hitting /gated/login barrier
            rep = run_verification(f"{self.base}/sso", storage_state_path=ss_path)
            self.assertNotEqual(rep["composite_verdict"]["overall_verdict"], "INCONCLUSIVE_AUTH_GATED")
            cats = {v["category"] for v in rep["composite_verdict"].get("confirmed_vulnerabilities") or []}
            self.assertTrue({"JWT", "BLIND_SSRF", "BLIND_XSS"}.intersection(cats))

            # Also confirm browser discovery loads without error with storage_state active
            b_disc = BrowserXSSVerifier.browser_discover(f"{self.base}/sso", session_ctx=sess)
            self.assertTrue(b_disc.get("available"))
            self.assertNotIn("/gated/login", b_disc.get("final_url", ""))

    def test_07_baseline_diffing_and_pr_only_new_ci_gate(self):
        vuln_a = {"category": "XSS", "cwe": "CWE-79", "severity": "HIGH", "evidence": {"endpoint": "/search", "parameter": "q"}}
        vuln_b = {"category": "SQLI", "cwe": "CWE-89", "severity": "HIGH", "evidence": {"endpoint": "/login", "parameter": "username"}}
        vuln_c = {"category": "CMDI", "cwe": "CWE-78", "severity": "CRITICAL", "evidence": {"endpoint": "/ping", "parameter": "ip"}}

        baseline_rep = {
            "target": self.base,
            "timestamp": "2026-11-18 10:00:00 UTC",
            "composite_verdict": {"overall_verdict": "VULNERABLE", "confirmed_vulnerabilities": [dict(vuln_a), dict(vuln_b)]},
            "coverage_evaluation": {"coverage_complete": True, "covered_count": 2, "total_planned": 2, "coverage_percentage": 100.0},
        }
        curr_rep = {
            "target": self.base,
            "timestamp": "2026-11-18 12:00:00 UTC",
            "composite_verdict": {"overall_verdict": "VULNERABLE", "confirmed_vulnerabilities": [dict(vuln_b), dict(vuln_c)]},
            "coverage_evaluation": {"coverage_complete": True, "covered_count": 2, "total_planned": 2, "coverage_percentage": 100.0},
        }

        diff = compute_baseline_diff(curr_rep, baseline_rep)
        self.assertEqual(diff["new_count"], 1)
        self.assertEqual(diff["persisting_count"], 1)
        self.assertEqual(diff["fixed_count"], 1)

        sarif = build_sarif_report(self.base, curr_rep)
        states = [r.get("baselineState") for r in sarif["runs"][0]["results"]]
        self.assertEqual(sorted(states), ["new", "unchanged"])

        html_doc = build_html_report(self.base, curr_rep)
        self.assertIn("Baseline Regression Diff", html_doc)
        self.assertIn("PRE-EXISTING", html_doc)
        self.assertIn("NEW", html_doc)

        # CLI --only-new --ci against self baseline must pass (0 new vulns) even though target is VULNERABLE
        with tempfile.TemporaryDirectory() as td:
            base_file = os.path.join(td, "baseline.json")
            out_file = os.path.join(td, "current.json")
            rc1 = cli_main([f"{self.base}/ping?host=127.0.0.1", "--no-oast", "--out", base_file])
            self.assertEqual(rc1, 0)
            rc2 = cli_main([f"{self.base}/ping?host=127.0.0.1", "--no-oast", "--baseline", base_file, "--only-new", "--ci", "--out", out_file])
            self.assertEqual(rc2, 0)

    def test_08_graphql_and_oast_blind_ssrf_blind_xss(self):
        opener = get_safe_opener()
        gql_r = audit_graphql_security(self.base, {"discovered_endpoints": ["/graphql"]}, opener)
        gql_verdicts = {r["verdict"] for r in gql_r["results"]}
        self.assertIn("VULN_GRAPHQL_INTROSPECTION_ENABLED", gql_verdicts)
        self.assertIn("VULN_GRAPHQL_SQLI_CONFIRMED", gql_verdicts)

        disc = {
            "input_points": [{"endpoint": "/webhook", "url": f"{self.base}/webhook", "method": "GET", "parameter": "url"}],
            "discovered_forms": [{"action": f"{self.base}/feedback", "method": "POST", "inputs": [{"name": "comment", "type": "text", "value": ""}]}],
        }
        oast_r = audit_oast_blind(self.base, disc, opener, wait_sec=0.8)
        oast_verdicts = {r["verdict"] for r in oast_r["results"] if r["is_vulnerability"]}
        self.assertEqual(oast_verdicts, {"VULN_BLIND_SSRF_OAST_CONFIRMED", "VULN_BLIND_XSS_OAST_CONFIRMED"})


    def test_09_time_blind_sqli_xxe_dns_oast_and_workflow(self):
        """Verify v3.2: Time-Blind SQLi 4-step sandwich, XXE entity expansion, RFC 1035 UDP DNS OAST, workflow loader, and modular posture checks."""
        import socket
        import struct
        import tempfile
        import time
        import urllib.parse
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from cyberguard_verify.deep_checks import (
            audit_time_blind_sqli,
            audit_xxe_injection,
            load_browser_workflow,
        )
        from cyberguard_verify.graphql_oast import LocalOASTCollector
        from cyberguard_verify.posture_checks import run_web_posture_checks

        # 1. Verify RFC 1035 UDP DNS OAST Collector
        with LocalOASTCollector() as oast:
            self.assertGreater(oast.port, 0)
            self.assertGreater(oast.dns_port, 0)
            nonce = "9f8e7d6c5b4a"
            qname = f"ssrf.{nonce}.oast.local"
            header = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
            qbytes = b"".join(
                bytes([len(lbl)]) + lbl.encode("ascii") for lbl in qname.split(".")
            ) + b"\x00" + struct.pack("!HH", 1, 1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                sock.sendto(header + qbytes, ("127.0.0.1", oast.dns_port))
                reply, _ = sock.recvfrom(512)
                self.assertTrue(len(reply) > 16)
                self.assertEqual(reply[-4:], b"\x7f\x00\x00\x01")
            finally:
                sock.close()
            time.sleep(0.05)
            hits = oast.get_hits(nonce)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["kind"], "dns_oast")
            self.assertIn(nonce, hits[0]["path"])

        # 2. Verify load_browser_workflow
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(
                [
                    {"action": "goto", "url": "http://127.0.0.1:8767/login"},
                    {"action": "fill", "selector": "#user", "value": "admin"},
                    {"action": "click", "selector": "button[type=submit]"},
                    {"action": "wait", "ms": 200},
                    {"action": "invalid_ignored", "selector": "#noop"},
                ],
                tf,
            )
            wf_path = tf.name
        try:
            steps = load_browser_workflow(wf_path)
            self.assertEqual(len(steps), 4)
            self.assertEqual([s["action"] for s in steps], ["goto", "fill", "click", "wait"])
        finally:
            os.remove(wf_path)

        # 3. Ephemeral server for Time-Blind SQLi, XXE, and modular Posture checks
        class V32Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                return

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/item":
                    val = qs.get("id", [""])[0]
                    if "SLEEP(1)" in val.upper():
                        time.sleep(1.5)
                    body = b'{"item": "ok"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if parsed.path == "/redirect":
                    nxt = qs.get("next", [""])[0]
                    if nxt:
                        self.send_response(302)
                        self.send_header("Location", nxt)
                        self.end_headers()
                        return
                origin = self.headers.get("Origin")
                self.send_response(200)
                if origin:
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>ok</body></html>")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                if self.path == "/api/xml":
                    if "<!ENTITY cgxxe" in raw and "&cgxxe;" in raw:
                        out = "<resp>Parsed: cg_xxe_9137_ok</resp>"
                    else:
                        out = "<resp>Parsed: cg_base_9137</resp>"
                    self.send_response(200)
                    self.send_header("Content-Type", "application/xml")
                    self.end_headers()
                    self.wfile.write(out.encode("utf-8"))
                    return
                self.send_response(404)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), V32Handler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base_url = f"http://127.0.0.1:{port}"
            opener = urllib.request.build_opener()
            disc = {
                "discovered_endpoints": ["/item", "/redirect", "/api/xml"],
                "discovered_forms": [
                    {
                        "page": base_url,
                        "action": f"{base_url}/api/xml",
                        "method": "POST",
                        "inputs": [{"name": "xml", "type": "text"}],
                    }
                ],
                "input_points": [
                    {"endpoint": "/item", "url": f"{base_url}/item", "method": "GET", "parameter": "id"},
                    {"endpoint": "/redirect", "url": f"{base_url}/redirect", "method": "GET", "parameter": "next"},
                ],
            }

            time_res = audit_time_blind_sqli(base_url, disc, opener, delay_sec=1)
            self.assertEqual(time_res["confirmed_vulnerabilities_count"], 1)
            vuln_t = [r for r in time_res["results"] if r["is_vulnerability"]]
            self.assertEqual(vuln_t[0]["cwe_id"], "CWE-89")
            self.assertEqual(vuln_t[0]["verdict"], "VULN_TIME_BLIND_SQLI_CONFIRMED")

            xxe_res = audit_xxe_injection(base_url, disc, opener)
            self.assertEqual(xxe_res["confirmed_vulnerabilities_count"], 1)
            vuln_x = [r for r in xxe_res["results"] if r["is_vulnerability"]]
            self.assertEqual(vuln_x[0]["cwe_id"], "CWE-611")
            self.assertEqual(vuln_x[0]["verdict"], "VULN_XXE_ENTITY_EXPANSION_CONFIRMED")

            posture_res = run_web_posture_checks(base_url, disc, opener, ({}, {"cookies": [{"name": "sid"}]}))
            self.assertGreaterEqual(posture_res["confirmed_vulnerabilities_count"], 2)
            checks_found = {r["check"] for r in posture_res["results"] if r.get("is_vulnerability")}
            self.assertIn("CORS", checks_found)
            self.assertIn("OPEN_REDIRECT", checks_found)
            self.assertIn("CSRF_POSTURE", checks_found)

            # 4. Verify v3.3 White-Label HTML/SARIF, A4 PDF Export, and Turnkey Packaging
            from cyberguard_verify.report_export import (
                build_html_report,
                build_sarif_report,
                export_pdf_report,
            )

            sample_data = {
                "coverage_evaluation": {
                    "total_planned": 2,
                    "covered_count": 2,
                    "coverage_percentage": 100.0,
                    "coverage_matrix": [
                        {
                            "test_id": "COV-TIME-01",
                            "category": "TIME_BLIND_SQLI",
                            "method": "GET",
                            "endpoint": "/item",
                            "parameter": "id",
                            "execution_status": "EXECUTED",
                            "evidence_status": "TOOL_EXECUTED",
                        }
                    ],
                },
                "composite_verdict": {
                    "overall_verdict": "VULNERABLE",
                    "confidence": "CONFIRMED",
                    "rationale": "Confirmed time-blind SQLi and XXE expansion.",
                    "confirmed_vulnerabilities": [
                        {
                            "category": "TIME_BLIND_SQLI",
                            "cwe": "CWE-89",
                            "severity": "HIGH",
                            "rationale": vuln_t[0]["evidence_snippet"],
                            "evidence_id": "EV-TIME-001",
                            "evidence": vuln_t[0],
                            "evidence_record": {
                                "evidence_id": "EV-TIME-001",
                                "target_endpoint": "/item",
                                "integrity_hash": "a" * 64,
                            },
                        }
                    ],
                },
            }

            html_doc = build_html_report(base_url, sample_data, brand_name="AcmeSec Labs", client_name="GlobalBank")
            self.assertIn("AcmeSec Labs", html_doc)
            self.assertIn("GlobalBank", html_doc)

            sarif_doc = build_sarif_report(base_url, sample_data, brand_name="AcmeSec Labs", client_name="GlobalBank")
            self.assertEqual(sarif_doc["runs"][0]["tool"]["driver"]["name"], "AcmeSec Labs")
            self.assertEqual(sarif_doc["runs"][0]["tool"]["driver"]["organization"], "AcmeSec Labs")

            pdf_fd, pdf_path = tempfile.mkstemp(suffix=".pdf")
            os.close(pdf_fd)
            try:
                pdf_bytes = export_pdf_report(
                    base_url,
                    sample_data,
                    out_path=pdf_path,
                    brand_name="AcmeSec Labs",
                    client_name="GlobalBank",
                )
                self.assertTrue(pdf_bytes.startswith(b"%PDF-1."))
                self.assertGreater(len(pdf_bytes), 1000)
                with open(pdf_path, "rb") as pf:
                    disk_bytes = pf.read()
                self.assertTrue(disk_bytes.startswith(b"%PDF-1."))
                self.assertGreater(len(disk_bytes), 1000)
            finally:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)

            pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            self.assertTrue(os.path.exists(os.path.join(pkg_root, "Dockerfile")))
            self.assertTrue(os.path.exists(os.path.join(pkg_root, "action.yml")))
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
