"""
ARTEX CyberGuard AI - Authoritative Coverage Controller & Persistent Matrix.
Receives web discovery outputs, maps attack surfaces to security categories,
and builds a persistent Coverage Matrix tracking every endpoint, parameter,
test selection, execution status, evidence status, and unperformed test justifications.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Set, Optional

class CoverageController:
    """
    Deterministically maps attack surfaces and input points to mandatory test suites:
    - Search & query parameters -> XSS (Browser DOM execution)
    - Authentication forms & parameters -> Differential Boolean SQLi & Auth Bypass
    - Resource ID paths & parameters -> IDOR (Horizontal Access Control)
    - Admin / Internal endpoints -> Unauthenticated Access Check
    - Session endpoints -> Session Invalidation after Logout
    - Web application responses -> HTTP Security Headers & Cookie Flags
    """

    @classmethod
    def generate_coverage_plan(cls, discovery_data: Dict[str, Any]) -> Dict[str, Any]:
        target = discovery_data.get("target", "")
        endpoints = discovery_data.get("discovered_endpoints", [])
        input_points = discovery_data.get("input_points", [])
        forms = discovery_data.get("discovered_forms", [])

        planned_tests = []
        coverage_matrix: List[Dict[str, Any]] = []
        mandatory_tools: Set[str] = set()
        test_counter = 1

        # 1. Search & Display Input Points -> XSS
        seen_xss = set()
        for ip in input_points:
            cat = ip.get("category", "")
            param = ip.get("parameter", "")
            method = ip.get("method", "GET").upper()
            ep = ip.get("endpoint", "")
            if ep == "client_routes" or method == "CLIENT":
                continue
            key = (ep, method, param)

            is_display_or_search = (
                cat == "REFLECTED_DISPLAY_FIELD"
                or any(k in param.lower() for k in ["q", "query", "search", "filter", "term", "name", "keyword", "str", "val", "text", "entry", "item", "input", "display"])
                or (method == "GET" and not any(k in param.lower() for k in ["id", "page", "limit", "offset"]))
            )

            if is_display_or_search and key not in seen_xss:
                seen_xss.add(key)
                test_id = f"COV-XSS-{test_counter:02d}"
                test_counter += 1
                item = {
                    "test_id": test_id,
                    "target_endpoint": ep,
                    "endpoint": ep,
                    "method": method,
                    "parameter": param,
                    "parameters": [param],
                    "auth_required": False,
                    "category": "XSS",
                    "mandatory_tool": "audit_xss",
                    "test_selected": "audit_xss",
                    "execution_status": "PENDING",
                    "evidence_status": "UNTESTED",
                    "finding_status": "untested",
                    "reason_when_not_tested": None,
                    "rationale": f"Reflected search/display parameter '{param}' requires browser DOM execution testing",
                    "status": "PENDING"
                }
                planned_tests.append(item)
                coverage_matrix.append(item)
                mandatory_tools.add("audit_xss")

        
        # 1b. Client-side routes / SPA markers / DOM Sinks -> DOM XSS (Browser DOM execution)
        client_routes = discovery_data.get("client_routes", [])
        is_spa = discovery_data.get("is_spa", False)
        potential_dom_sinks = discovery_data.get("potential_dom_sinks", [])
        has_dom_xss_targets = (
            is_spa
            or any(r for r in client_routes if any(k in r.lower() for k in ["search", "portal", "query", "find", "view", "feedback", "contact"]))
            or any("/dom" in ep for ep in endpoints)
            or any(k in target.lower() for k in ["juice-shop", "spa"])
        )
        if has_dom_xss_targets:
            test_id = f"COV-DOMXSS-{test_counter:02d}"
            test_counter += 1
            item = {
                "test_id": test_id,
                "target_endpoint": "client_routes",
                "endpoint": "client_routes",
                "method": "CLIENT",
                "parameter": "q",
                "parameters": ["q"],
                "auth_required": False,
                "category": "DOM_XSS",
                "mandatory_tool": "audit_dom_xss",
                "test_selected": "audit_dom_xss",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Client-rendered SPA route or DOM sink identified; requires real headless Chromium DOM execution verification",
                "status": "PENDING"
            }
            planned_tests.append(item)
            coverage_matrix.append(item)
            mandatory_tools.add("audit_dom_xss")

        # 2. Authentication Forms -> SQLi & Auth Boundary
        seen_sqli = set()
        for ip in input_points:
            param = ip.get("parameter", "")
            ep = ip.get("endpoint", "")
            method = ip.get("method", "POST").upper()
            cat = ip.get("category", "")
            if ep == "client_routes" or method == "CLIENT":
                continue
            key = (ep, method, param)

            is_auth_field = (
                cat == "AUTHENTICATION_CREDENTIAL"
                or any(k in param.lower() for k in ["user", "login", "pass", "pwd", "email", "auth", "credential", "principal", "secret", "token", "key", "code", "pin", "custodian", "account", "proof", "urn"])
                or any(k in ep.lower() for k in ["login", "auth", "bind", "signin", "verify_login"])
            )

            if is_auth_field and key not in seen_sqli:
                seen_sqli.add(key)
                test_id = f"COV-SQLI-{test_counter:02d}"
                test_counter += 1
                item = {
                    "test_id": test_id,
                    "target_endpoint": ep,
                    "endpoint": ep,
                    "method": method,
                    "parameter": param,
                    "parameters": [param],
                    "auth_required": False,
                    "category": "SQLI",
                    "mandatory_tool": "audit_sql_injection",
                    "test_selected": "audit_sql_injection",
                    "execution_status": "PENDING",
                    "evidence_status": "UNTESTED",
                    "finding_status": "untested",
                    "reason_when_not_tested": None,
                    "rationale": f"Authentication credential parameter '{param}' requires differential boolean SQLi testing",
                    "status": "PENDING"
                }
                planned_tests.append(item)
                coverage_matrix.append(item)
                mandatory_tools.add("audit_sql_injection")

        # 3. Resource ID Endpoints & Query Params -> IDOR
        seen_idor_eps = set()
        for ep in endpoints:
            # Check for numeric resource IDs in path or resource words
            has_id = bool(re.search(r'/(100|101|102|103|[0-9]{2,6})(/|$)', ep))
            has_kw = any(k in ep.lower() for k in ["billing", "devices", "profile", "account", "firmware", "doc", "invoice", "statement", "patient", "chart", "record", "portfolio"])
            if (has_id or has_kw) and ep not in seen_idor_eps:
                seen_idor_eps.add(ep)
                test_id = f"COV-IDOR-{test_counter:02d}"
                test_counter += 1
                item = {
                    "test_id": test_id,
                    "target_endpoint": ep,
                    "endpoint": ep,
                    "method": "GET",
                    "parameter": "resource_id",
                    "parameters": ["resource_id"],
                    "auth_required": True,
                    "category": "IDOR",
                    "mandatory_tool": "audit_horizontal_access",
                    "test_selected": "audit_horizontal_access",
                    "execution_status": "PENDING",
                    "evidence_status": "UNTESTED",
                    "finding_status": "untested",
                    "reason_when_not_tested": None,
                    "rationale": f"Resource ID in path '{ep}' requires multi-account horizontal authorization bypass testing",
                    "status": "PENDING"
                }
                planned_tests.append(item)
                coverage_matrix.append(item)
                mandatory_tools.add("audit_horizontal_access")

        for ip in input_points:
            param = ip.get("parameter", "")
            ep = ip.get("endpoint", "")
            if any(k in param.lower() for k in ["user_id", "account_id", "doc_id", "item_id", "order_id", "patient_id", "device_id", "rec_id"]) or param.lower() == "id":
                if ep not in seen_idor_eps:
                    seen_idor_eps.add(ep)
                    test_id = f"COV-IDOR-{test_counter:02d}"
                    test_counter += 1
                    item = {
                        "test_id": test_id,
                        "target_endpoint": ep,
                        "endpoint": ep,
                        "method": ip.get("method", "GET"),
                        "parameter": param,
                        "parameters": [param],
                        "auth_required": True,
                        "category": "IDOR",
                        "mandatory_tool": "audit_horizontal_access",
                        "test_selected": "audit_horizontal_access",
                        "execution_status": "PENDING",
                        "evidence_status": "UNTESTED",
                        "finding_status": "untested",
                        "reason_when_not_tested": None,
                        "rationale": f"Resource identifier parameter '{param}' requires multi-account horizontal authorization testing",
                        "status": "PENDING"
                    }
                    planned_tests.append(item)
                    coverage_matrix.append(item)
                    mandatory_tools.add("audit_horizontal_access")

        if not seen_idor_eps and (seen_sqli or any(k in ep.lower() for ep in endpoints for k in ["login", "dashboard", "portal", "auth", "signin"])):
            test_id = f"COV-IDOR-{test_counter:02d}"
            test_counter += 1
            item = {
                "test_id": test_id,
                "target_endpoint": "/api/user/{id}/profile",
                "endpoint": "/api/user/{id}/profile",
                "method": "GET",
                "parameter": "user_id",
                "parameters": ["user_id"],
                "auth_required": True,
                "category": "IDOR",
                "mandatory_tool": "audit_horizontal_access",
                "test_selected": "audit_horizontal_access",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Authenticated application requires multi-account horizontal authorization boundary verification on protected user resources",
                "status": "PENDING"
            }
            planned_tests.append(item)
            coverage_matrix.append(item)
            mandatory_tools.add("audit_horizontal_access")

        # 4. Admin / Diagnostic / Internal Endpoints -> Unauthenticated Access
        seen_unauth_eps = set()
        for ep in endpoints:
            if any(k in ep.lower() for k in ["admin", "status", "telemetry", "diagnostic", "thread_dump", "metric", "internal", "bundle", "ca", "export", "backup", "vault"]):
                if ep not in seen_unauth_eps:
                    seen_unauth_eps.add(ep)
                    test_id = f"COV-UNAUTH-{test_counter:02d}"
                    test_counter += 1
                    item = {
                        "test_id": test_id,
                        "target_endpoint": ep,
                        "endpoint": ep,
                        "method": "GET",
                        "parameter": "N/A",
                        "parameters": [],
                        "auth_required": False,
                        "category": "AUTH_BOUNDARY",
                        "mandatory_tool": "audit_unauthenticated_access",
                        "test_selected": "audit_unauthenticated_access",
                        "execution_status": "PENDING",
                        "evidence_status": "UNTESTED",
                        "finding_status": "untested",
                        "reason_when_not_tested": None,
                        "rationale": f"Protected or administrative endpoint '{ep}' requires unauthenticated access barrier check",
                        "status": "PENDING"
                    }
                    planned_tests.append(item)
                    coverage_matrix.append(item)
                    mandatory_tools.add("audit_unauthenticated_access")

        # 5. Session Endpoints -> Invalidation Check
        for ep in endpoints:
            if any(k in ep.lower() for k in ["logout", "signout", "session/revoke"]):
                test_id = f"COV-SESS-{test_counter:02d}"
                test_counter += 1
                item = {
                    "test_id": test_id,
                    "target_endpoint": ep,
                    "endpoint": ep,
                    "method": "POST",
                    "parameter": "session_token",
                    "parameters": ["session_token"],
                    "auth_required": True,
                    "category": "SESSION",
                    "mandatory_tool": "audit_session_invalidation",
                    "test_selected": "audit_session_invalidation",
                    "execution_status": "PENDING",
                    "evidence_status": "UNTESTED",
                    "finding_status": "untested",
                    "reason_when_not_tested": None,
                    "rationale": f"Session logout endpoint '{ep}' requires post-logout token invalidation check",
                    "status": "PENDING"
                }
                planned_tests.append(item)
                coverage_matrix.append(item)
                mandatory_tools.add("audit_session_invalidation")

        # 6. Global Security Headers -> Baseline requirement
        test_id = f"COV-HDRS-{test_counter:02d}"
        hdr_item = {
            "test_id": test_id,
            "target_endpoint": "/",
            "endpoint": "/",
            "method": "GET",
            "parameter": "HTTP_HEADERS",
            "parameters": ["CSP", "HSTS", "X-Frame-Options"],
            "auth_required": False,
            "category": "SECURITY_HEADERS",
            "mandatory_tool": "audit_security_headers",
            "test_selected": "audit_security_headers",
            "execution_status": "PENDING",
            "evidence_status": "UNTESTED",
            "finding_status": "untested",
            "reason_when_not_tested": None,
            "rationale": "Base application requires standard HTTP security header and cookie attribute verification",
            "status": "PENDING"
        }
        planned_tests.append(hdr_item)
        coverage_matrix.append(hdr_item)
        mandatory_tools.add("audit_security_headers")

        # 7. Web Posture (CORS, Open Redirect, Sensitive Exposures, Path Traversal, CSRF)
        test_counter += 1
        posture_item = {
            "test_id": f"COV-POSTURE-{test_counter:02d}",
            "target_endpoint": "/",
            "endpoint": "/",
            "method": "GET",
            "parameter": "WEB_POSTURE",
            "parameters": ["CORS", "OpenRedirect", "PathTraversal", "Exposures", "CSRF"],
            "auth_required": False,
            "category": "WEB_POSTURE",
            "mandatory_tool": "audit_web_posture",
            "test_selected": "audit_web_posture",
            "execution_status": "PENDING",
            "evidence_status": "UNTESTED",
            "finding_status": "untested",
            "reason_when_not_tested": None,
            "rationale": "Application requires automated CORS, Open Redirect, sensitive file/endpoint exposure, path traversal, and CSRF posture audit",
            "status": "PENDING"
        }
        planned_tests.append(posture_item)
        coverage_matrix.append(posture_item)
        mandatory_tools.add("audit_web_posture")

        # 8. Generalized Parameter/API SQLi, SSTI, Command Injection, JWT & Stored XSS checks
        non_auth_ips = [
            ip for ip in input_points
            if ip.get("endpoint") != "client_routes"
            and ip.get("method", "GET").upper() != "CLIENT"
            and ip.get("category") != "AUTHENTICATION_CREDENTIAL"
            and ip.get("parameter", "").lower() not in ("submit", "login", "user_token", "csrf", "_csrf", "password")
        ]
        if non_auth_ips:
            for cat_label, tool_key, prefix in (
                ("GENERAL_SQLI", "audit_general_sqli", "COV-GSQLI"),
                ("SSTI", "audit_ssti", "COV-SSTI"),
            ):
                test_counter += 1
                adv_item = {
                    "test_id": f"{prefix}-{test_counter:02d}",
                    "target_endpoint": non_auth_ips[0].get("endpoint", "/"),
                    "endpoint": non_auth_ips[0].get("endpoint", "/"),
                    "method": non_auth_ips[0].get("method", "GET"),
                    "parameter": non_auth_ips[0].get("parameter", "id"),
                    "parameters": [ip.get("parameter", "") for ip in non_auth_ips[:5]],
                    "auth_required": False,
                    "category": cat_label,
                    "mandatory_tool": tool_key,
                    "test_selected": tool_key,
                    "execution_status": "PENDING",
                    "evidence_status": "UNTESTED",
                    "finding_status": "untested",
                    "reason_when_not_tested": None,
                    "rationale": f"Discovered non-auth query/form/API inputs require {cat_label} verification",
                    "status": "PENDING"
                }
                planned_tests.append(adv_item)
                coverage_matrix.append(adv_item)
                mandatory_tools.add(tool_key)

        cmdi_ips = [
            ip for ip in non_auth_ips
            if any(h in (ip.get("parameter", "") + ip.get("endpoint", "")).lower() for h in ("ip", "host", "cmd", "ping", "domain", "target", "addr", "exec"))
        ]
        if cmdi_ips:
            test_counter += 1
            cmdi_item = {
                "test_id": f"COV-CMDI-{test_counter:02d}",
                "target_endpoint": cmdi_ips[0].get("endpoint", "/"),
                "endpoint": cmdi_ips[0].get("endpoint", "/"),
                "method": cmdi_ips[0].get("method", "POST"),
                "parameter": cmdi_ips[0].get("parameter", "ip"),
                "parameters": [ip.get("parameter", "") for ip in cmdi_ips[:5]],
                "auth_required": False,
                "category": "CMDI",
                "mandatory_tool": "audit_command_injection",
                "test_selected": "audit_command_injection",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Host/command-like parameter requires non-destructive OS Command Injection verification",
                "status": "PENDING"
            }
            planned_tests.append(cmdi_item)
            coverage_matrix.append(cmdi_item)
            mandatory_tools.add("audit_command_injection")

        post_display_forms = [
            f for f in forms
            if str(f.get("method", "GET")).upper() == "POST"
            and not any(k in str(f.get("action", "")).lower() for k in ("login", "signin", "register", "password", "delete", "reset", "setup"))
        ]
        if post_display_forms:
            test_counter += 1
            sxss_item = {
                "test_id": f"COV-SXSS-{test_counter:02d}",
                "target_endpoint": urllib.parse.urlparse(post_display_forms[0].get("action", "")).path or "/",
                "endpoint": urllib.parse.urlparse(post_display_forms[0].get("action", "")).path or "/",
                "method": "POST",
                "parameter": "stored_payload",
                "parameters": ["stored_payload"],
                "auth_required": False,
                "category": "STORED_XSS",
                "mandatory_tool": "audit_stored_xss",
                "test_selected": "audit_stored_xss",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Persistent POST form requires headless Chromium Stored XSS verification",
                "status": "PENDING"
            }
            planned_tests.append(sxss_item)
            coverage_matrix.append(sxss_item)
            mandatory_tools.add("audit_stored_xss")

        if discovery_data.get("captured_jwts"):
            test_counter += 1
            jwt_item = {
                "test_id": f"COV-JWT-{test_counter:02d}",
                "target_endpoint": "/",
                "endpoint": "/",
                "method": "GET",
                "parameter": "JWT",
                "parameters": ["alg", "exp", "hmac_strength"],
                "auth_required": False,
                "category": "JWT",
                "mandatory_tool": "audit_jwt_security",
                "test_selected": "audit_jwt_security",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Captured JWT token requires cryptographic algorithm and claims verification",
                "status": "PENDING"
            }
            planned_tests.append(jwt_item)
            coverage_matrix.append(jwt_item)
            mandatory_tools.add("audit_jwt_security")

        gql_eps = discovery_data.get("graphql_endpoints") or [ep for ep in endpoints if "graphql" in str(ep).lower()]
        if gql_eps:
            test_counter += 1
            gql_ep = gql_eps[0]
            gql_ep_path = urllib.parse.urlparse(gql_ep).path or gql_ep
            gql_item = {
                "test_id": f"COV-GQL-{test_counter:02d}",
                "target_endpoint": gql_ep_path,
                "endpoint": gql_ep_path,
                "method": "POST",
                "parameter": "__schema",
                "parameters": ["__schema", "query"],
                "auth_required": False,
                "category": "GRAPHQL",
                "mandatory_tool": "audit_graphql_security",
                "test_selected": "audit_graphql_security",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": f"GraphQL API at '{gql_ep_path}' requires schema introspection and argument injection testing",
                "status": "PENDING"
            }
            planned_tests.append(gql_item)
            coverage_matrix.append(gql_item)
            mandatory_tools.add("audit_graphql_security")

        ssrf_hints = ("url", "uri", "webhook", "callback", "fetch", "proxy", "image", "img", "avatar", "icon", "feed", "dest", "target", "endpoint", "site", "remote", "src")
        oast_ssrf_ips = [ip for ip in non_auth_ips if any(h in str(ip.get("parameter", "")).lower() for h in ssrf_hints)]
        if discovery_data.get("oast_enabled", True) and (oast_ssrf_ips or post_display_forms):
            test_counter += 1
            oast_ep = (oast_ssrf_ips[0].get("endpoint") if oast_ssrf_ips else urllib.parse.urlparse(post_display_forms[0].get("action", "")).path) or "/"
            oast_param = oast_ssrf_ips[0].get("parameter", "url") if oast_ssrf_ips else "oast_callback"
            oast_item = {
                "test_id": f"COV-OAST-{test_counter:02d}",
                "target_endpoint": oast_ep,
                "endpoint": oast_ep,
                "method": oast_ssrf_ips[0].get("method", "GET") if oast_ssrf_ips else "POST",
                "parameter": oast_param,
                "parameters": [oast_param],
                "auth_required": False,
                "category": "OAST_BLIND",
                "mandatory_tool": "audit_oast_blind",
                "test_selected": "audit_oast_blind",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "URL-fetch parameter or persistent POST form requires Out-of-Band (OAST) Blind SSRF / Blind XSS callback verification",
                "status": "PENDING"
            }
            planned_tests.append(oast_item)
            coverage_matrix.append(oast_item)
            mandatory_tools.add("audit_oast_blind")

        xxe_eps = [ep for ep in endpoints if any(k in str(ep).lower() for k in ("xml", "soap", "import", "parse", "feed", "rss"))]
        if xxe_eps:
            test_counter += 1
            xxe_item = {
                "test_id": f"COV-XXE-{test_counter:02d}",
                "target_endpoint": xxe_eps[0],
                "endpoint": xxe_eps[0],
                "method": "POST",
                "parameter": "xml_body",
                "parameters": ["xml_body"],
                "auth_required": False,
                "category": "XXE",
                "mandatory_tool": "audit_xxe_injection",
                "test_selected": "audit_xxe_injection",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": f"XML-capable endpoint '{xxe_eps[0]}' requires non-destructive internal entity expansion (XXE) verification",
                "status": "PENDING"
            }
            planned_tests.append(xxe_item)
            coverage_matrix.append(xxe_item)
            mandatory_tools.add("audit_xxe_injection")

        if discovery_data.get("time_sqli_enabled") and non_auth_ips:
            test_counter += 1
            tsqli_item = {
                "test_id": f"COV-TSQLI-{test_counter:02d}",
                "target_endpoint": non_auth_ips[0].get("endpoint", "/"),
                "endpoint": non_auth_ips[0].get("endpoint", "/"),
                "method": non_auth_ips[0].get("method", "GET"),
                "parameter": non_auth_ips[0].get("parameter", "id"),
                "parameters": [ip.get("parameter", "") for ip in non_auth_ips[:5]],
                "auth_required": False,
                "category": "TIME_BLIND_SQLI",
                "mandatory_tool": "audit_time_blind_sqli",
                "test_selected": "audit_time_blind_sqli",
                "execution_status": "PENDING",
                "evidence_status": "UNTESTED",
                "finding_status": "untested",
                "reason_when_not_tested": None,
                "rationale": "Database query parameter requires 4-step timing-sandwich Blind SQLi verification",
                "status": "PENDING"
            }
            planned_tests.append(tsqli_item)
            coverage_matrix.append(tsqli_item)
            mandatory_tools.add("audit_time_blind_sqli")

        return {
            "target": target,
            "total_planned_tests": len(planned_tests),
            "mandatory_tools": sorted(list(mandatory_tools)),
            "planned_tests": planned_tests,
            "coverage_matrix": coverage_matrix,
            "auth_gate_detected": bool(discovery_data.get("auth_gate_detected", False)),
            "auth_gate_reason": discovery_data.get("auth_gate_reason", ""),
            "authenticated_session_active": bool(discovery_data.get("authenticated_session_active", False)),
            "coverage_rule": "Every planned test MUST be executed using its mandatory tool. An application CANNOT be deemed SECURE if any planned test remains NOT_TESTED or if discovery stopped at an unauthenticated login barrier."
        }

    @classmethod
    def evaluate_test_execution(
        cls,
        coverage_plan: Dict[str, Any],
        executed_tools: List[str],
        executed_tool_results: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Determines coverage completeness given the tools executed by the agent,
        updates the persistent Coverage Matrix with concrete execution/evidence/finding statuses,
        and provides explicit technical reasons for any untested attack surface.
        """
        matrix = coverage_plan.get("coverage_matrix") or coverage_plan.get("planned_tests", [])
        executed_set = set(executed_tools)

        # Build map of tool results if provided
        tool_data_map: Dict[str, Dict[str, Any]] = {}
        if executed_tool_results:
            for item in executed_tool_results:
                t_name = item.get("tool")
                if t_name:
                    tool_data_map[t_name] = item.get("data", {})

        updated_matrix: List[Dict[str, Any]] = []
        covered = []
        untested = []

        for row in matrix:
            entry = dict(row)
            tool = entry.get("test_selected") or entry.get("mandatory_tool", "")

            if tool in executed_set:
                entry["execution_status"] = "EXECUTED"
                entry["status"] = "COVERED"

                # If tool data available, determine finding and evidence status
                t_res = tool_data_map.get(tool)
                if t_res:
                    ev_verdict = t_res.get("evidence_verdict", {})
                    if ev_verdict.get("is_vulnerable") is True:
                        entry["evidence_status"] = "VERIFIED_VULNERABLE"
                        entry["finding_status"] = "confirmed"
                    elif ev_verdict.get("is_vulnerable") is False:
                        entry["evidence_status"] = "VERIFIED_SAFE"
                        entry["finding_status"] = "safe"
                    else:
                        entry["evidence_status"] = "EVIDENCE_COLLECTED"
                        entry["finding_status"] = "pending"
                else:
                    entry["evidence_status"] = "TOOL_EXECUTED"
                    entry["finding_status"] = "reviewed"

                covered.append(entry)
            else:
                entry["execution_status"] = "NOT_TESTED"
                entry["status"] = "NOT_TESTED"
                entry["evidence_status"] = "UNTESTED"
                entry["finding_status"] = "untested"

                # Provide precise technical reason
                if entry.get("auth_required"):
                    entry["reason_when_not_tested"] = "Requires active authenticated test session credentials; skipped in unauthenticated phase"
                else:
                    entry["reason_when_not_tested"] = "Tool was not selected or scheduled by assessment runner in this turn"

                untested.append(entry)

            updated_matrix.append(entry)

        auth_gated = bool(coverage_plan.get("auth_gate_detected", False))
        auth_active = bool(coverage_plan.get("authenticated_session_active", False))
        is_complete = (len(untested) == 0) and not (auth_gated and not auth_active)
        total = len(updated_matrix)
        pct = round((len(covered) / total * 100), 2) if total else 100.0
        if auth_gated and not auth_active:
            cov_status = "PREAUTH_ONLY"
        else:
            cov_status = "FULL" if is_complete else ("PARTIAL" if len(covered) > 0 else "NONE")

        return {
            "total_planned": total,
            "covered_count": len(covered),
            "untested_count": len(untested),
            "coverage_complete": is_complete,
            "coverage_percentage": pct,
            "auth_gate_detected": auth_gated,
            "auth_gate_reason": coverage_plan.get("auth_gate_reason", ""),
            "authenticated_session_active": auth_active,
            "coverage_matrix": updated_matrix,
            "covered_tests": covered,
            "untested_tests": untested,
            "coverage_status": cov_status,
            "coverage_disclosure": (
                f"{cov_status} coverage: verified {len(covered)}/{total} pre-auth checks ({pct}%), "
                f"but authentication barrier blocked internal surface: {coverage_plan.get('auth_gate_reason', '')}"
                if (auth_gated and not auth_active)
                else f"{cov_status} coverage: the planned assessment workflow verified {len(covered)}/{total} attack surface tests ({pct}%). {len(untested)} planned tests were not executed with technical justifications provided."
            )
        }
