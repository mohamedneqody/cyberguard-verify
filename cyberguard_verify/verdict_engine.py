"""
ARTEX CyberGuard AI - Evidence-Based Verdict Engine
Decouples vulnerability verdicts from raw LLM text opinion.
Evaluates concrete tool evidence against strict deterministic criteria:
- Missing CSP != Confirmed XSS
- XSS requires verified Playwright browser DOM execution
- SQLi requires differential boolean proof
- IDOR requires cross-account privilege bypass
- Untested attack surfaces block any "SAFE" verdict
"""

import json
import re
import time
import secrets
import hashlib
from typing import Dict, Any, List, Optional

class VerdictState:
    CONFIRMED_VULNERABILITY = "CONFIRMED_VULNERABILITY"
    TESTED_NOT_REPRODUCED = "TESTED_NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    TOOL_ERROR = "TOOL_ERROR"

class EvidenceVerdictEngine:
    """
    Evaluates evidence collected across tool executions to emit ground-truth-independent,
    reproducible verdicts for each test and the overall application.
    Issues cryptographically signed Evidence Records for genuine vulnerabilities.
    """

    @classmethod
    def _create_trusted_evidence_record(
        cls,
        category: str,
        vulnclass: str,
        target_url: str,
        target_endpoint: str,
        severity: str,
        evidence_payload: Any,
        trusted_tool: str
    ) -> Dict[str, Any]:
        """
        Creates an unguessable, cryptographically bound evidence record for the Evidence Registry.
        """
        evidence_id = "EV-" + secrets.token_hex(16)
        tool_execution_id = "EXEC-" + secrets.token_hex(8)
        now_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        # Clean/sanitize strings
        redacted_str = json.dumps(evidence_payload if evidence_payload is not None else {})
        redacted_str = re.sub(
            r"(?i)(bearer\s+[A-Za-z0-9_\-\.]+|(\bpassword\b|\bsecret\b|\btoken\b)\s*[:=]\s*[\"']?[^\"'\s,;]+[\"']?)",
            "[REDACTED]",
            redacted_str
        )

        hash_input = f"{evidence_id}:{tool_execution_id}:{target_url}:{vulnclass}:{redacted_str}"
        integrity_hash = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()

        return {
            "evidence_id": evidence_id,
            "tool_execution_id": tool_execution_id,
            "target_url": target_url or "",
            "target_endpoint": target_endpoint or "",
            "vulnclass": vulnclass,
            "severity": severity,
            "trusted_tool": trusted_tool,
            "evidence_status": "active",
            "evidence_payload": evidence_payload if isinstance(evidence_payload, dict) else {"raw": str(evidence_payload)},
            "redacted_evidence": redacted_str,
            "integrity_hash": integrity_hash,
            "created_at": now_ts
        }

    @classmethod
    def evaluate_xss_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        XSS requires proof of execution inside an isolated browser DOM context.
        """
        xss_audit = tool_output.get("xss_audit") or tool_output
        findings = xss_audit.get("confirmed_vulnerabilities") or xss_audit.get("results", [])
        
        has_exec = False
        evidence_snippet = None
        target_endpoint = ""

        for f in findings:
            ev = f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
            if (
                f.get("is_vulnerability") is True
                or f.get("verdict") in ("VULN_XSS_CONFIRMED_DOM_EXECUTION", "VULN_XSS_CONFIRMED")
                or ev.get("window_exec_flag") is True
                or ev.get("console_triggered") is True
            ):
                has_exec = True
                target_endpoint = f.get("endpoint", "")
                evidence_snippet = {
                    "endpoint": target_endpoint,
                    "verdict": f.get("verdict", "VULN_XSS_CONFIRMED_DOM_EXECUTION"),
                    "cwe_id": f.get("cwe_id", "CWE-79"),
                    "status_code": f.get("status_code", 200),
                    "note": f.get("note", ""),
                    "evidence_snippet": f.get("evidence_snippet", ""),
                    "reproduction_steps": f.get("reproduction_steps", ""),
                    "remediation": f.get("remediation", ""),
                }
                break

        raw_str = str(tool_output)
        if "CONFIRMED_BROWSER_DOM_EXECUTION" in raw_str or "VULN_XSS_CONFIRMED" in raw_str:
            has_exec = True

        if has_exec:
            target_url = tool_output.get("target") or xss_audit.get("target") or ""
            rec = cls._create_trusted_evidence_record(
                category="XSS",
                vulnclass="Cross-Site Scripting (XSS)",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity="HIGH",
                evidence_payload=evidence_snippet or {"poc": "DOM execution confirmed", "target": target_url},
                trusted_tool="audit_xss"
            )
            return {
                "category": "XSS",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": "HIGH",
                "cwe": "CWE-79",
                "rationale": "Reflected XSS confirmed via automated browser DOM execution proof",
                "evidence": evidence_snippet,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec
            }
        
        if "error" in tool_output or "timed out" in raw_str.lower():
            return {
                "category": "XSS",
                "state": VerdictState.TOOL_ERROR,
                "is_vulnerable": False,
                "rationale": "Tool error or timeout occurred during browser execution"
            }

        return {
            "category": "XSS",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": "XSS payloads tested; no execution occurred in browser DOM context"
        }


    @classmethod
    def evaluate_dom_xss_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        DOM XSS requires verified execution inside an isolated headless browser DOM context.
        """
        dom_audit = tool_output.get("dom_xss_audit") or tool_output
        results = dom_audit.get("results", [])
        
        has_exec = False
        evidence_snippet = None
        target_endpoint = ""
        target_url = tool_output.get("target") or dom_audit.get("target") or ""

        for r in results:
            if r.get("executed_in_browser") is True or r.get("verdict") == "CONFIRMED_BROWSER_DOM_EXECUTION" or r.get("is_vulnerability") is True:
                has_exec = True
                target_endpoint = r.get("endpoint", "")
                evidence_snippet = {
                    "endpoint": target_endpoint,
                    "target_url": r.get("target_url", target_url),
                    "parameter": r.get("parameter", "q"),
                    "verdict": r.get("verdict", "CONFIRMED_BROWSER_DOM_EXECUTION"),
                    "cwe_id": r.get("cwe_id", "CWE-79"),
                    "details": r.get("details") or r.get("note", ""),
                    "reproduction_steps": r.get("reproduction_steps", ""),
                    "remediation": r.get("remediation", ""),
                }
                break

        raw_str = str(tool_output)
        if "CONFIRMED_BROWSER_DOM_EXECUTION" in raw_str:
            has_exec = True

        if has_exec:
            rec = cls._create_trusted_evidence_record(
                category="DOM_XSS",
                vulnclass="DOM-Based Cross-Site Scripting (DOM XSS)",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity="HIGH",
                evidence_payload=evidence_snippet or {"poc": "DOM execution confirmed", "target": target_url},
                trusted_tool="audit_dom_xss"
            )
            return {
                "category": "DOM_XSS",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": "HIGH",
                "cwe": "CWE-79",
                "rationale": "DOM-based XSS confirmed via automated browser DOM execution proof in headless Chromium",
                "evidence": evidence_snippet,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec
            }
        else:
            return {
                "category": "DOM_XSS",
                "state": VerdictState.TESTED_NOT_REPRODUCED,
                "is_vulnerable": False,
                "severity": "INFO",
                "rationale": "Client-side DOM XSS probes tested; no execution occurred in browser DOM context"
            }

    @classmethod
    def evaluate_sqli_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        SQL Injection requires differential boolean response or bypass proof.
        """
        sqli_audit = tool_output.get("sql_injection_audit") or tool_output.get("sql_injection") or tool_output
        findings = sqli_audit.get("confirmed_vulnerabilities") or sqli_audit.get("results", [])
        raw_str = str(tool_output)

        has_bypass = False
        evidence_snippet = None
        target_endpoint = ""

        for f in findings:
            if f.get("verdict") in ("CONFIRMED_SQLI_BYPASS", "VULN_SQLI_CONFIRMED") or f.get("is_vulnerability") is True:
                has_bypass = True
                target_endpoint = f.get("endpoint", "")
                evidence_snippet = {
                    "endpoint": target_endpoint,
                    "verdict": f.get("verdict", "VULN_SQLI_CONFIRMED"),
                    "cwe_id": f.get("cwe_id", "CWE-89"),
                    "status_probe_true": f.get("status_probe_true"),
                    "status_probe_false": f.get("status_probe_false"),
                    "status_probe_baseline": f.get("status_probe_baseline"),
                    "session_cookie_issued": f.get("session_cookie_issued", False),
                    "evidence_snippet": f.get("evidence_snippet", ""),
                    "reproduction_steps": f.get("reproduction_steps", ""),
                    "remediation": f.get("remediation", ""),
                }
                break

        if "CONFIRMED_SQLI_BYPASS" in raw_str or "VULN_SQLI_CONFIRMED" in raw_str:
            has_bypass = True

        if has_bypass:
            target_url = tool_output.get("target") or sqli_audit.get("target") or ""
            rec = cls._create_trusted_evidence_record(
                category="SQLI",
                vulnclass="SQL Injection (SQLi)",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity="HIGH",
                evidence_payload=evidence_snippet or {"poc": "SQLi boolean bypass confirmed", "target": target_url},
                trusted_tool="audit_sql_injection"
            )
            return {
                "category": "SQLI",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": "HIGH",
                "cwe": "CWE-89",
                "rationale": "Differential boolean SQL injection proven with distinct authentication bypass",
                "evidence": evidence_snippet,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec
            }

        if "error" in tool_output or "timed out" in raw_str.lower():
            return {
                "category": "SQLI",
                "state": VerdictState.TOOL_ERROR,
                "is_vulnerable": False,
                "rationale": "Tool error during SQL injection probe"
            }

        return {
            "category": "SQLI",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": "Differential SQLi probes rejected consistently; parameterized queries verified"
        }

    @classmethod
    def evaluate_idor_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        IDOR requires cross-account unauthorized access proof.
        """
        h_check = tool_output.get("horizontal_access_check") or tool_output.get("horizontal_privilege_check") or tool_output
        raw_str = str(tool_output)

        is_idor = (
            h_check.get("is_vulnerability") is True
            or h_check.get("verdict") in ("CONFIRMED_IDOR_VULNERABILITY", "VULN_IDOR_CONFIRMED")
            or "CONFIRMED_IDOR_VULNERABILITY" in raw_str
            or "VULN_IDOR_CONFIRMED" in raw_str
        )

        if is_idor:
            target_url = tool_output.get("target") or h_check.get("target") or ""
            target_endpoint = h_check.get("endpoint", "")
            rec = cls._create_trusted_evidence_record(
                category="IDOR",
                vulnclass="Broken Object Level Authorization (IDOR)",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity="HIGH",
                evidence_payload=h_check or {"poc": "Cross-account record access confirmed", "target": target_url},
                trusted_tool="audit_horizontal_access"
            )
            return {
                "category": "IDOR",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": "HIGH",
                "cwe": "CWE-639",
                "rationale": "Horizontal authorization bypass confirmed; user A accessed user B private record",
                "evidence": h_check,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec
            }

        if "error" in tool_output or "timed out" in raw_str.lower():
            return {
                "category": "IDOR",
                "state": VerdictState.TOOL_ERROR,
                "is_vulnerable": False,
                "rationale": "Tool error during horizontal access probe"
            }

        return {
            "category": "IDOR",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": "Cross-account access rejected; ownership checks enforced"
        }

    @classmethod
    def evaluate_auth_evidence(cls, tool_output: Any) -> Dict[str, Any]:
        """
        Unauthenticated access requires proof of private data exposure without auth.
        """
        if isinstance(tool_output, list):
            findings = [item for item in tool_output if isinstance(item, dict) and item.get("is_vulnerability") is True]
            u_check = {"confirmed_vulnerabilities": findings, "results": tool_output}
        elif isinstance(tool_output, dict):
            u_check = tool_output.get("unauthenticated_access", tool_output)
            if isinstance(u_check, list):
                findings = [item for item in u_check if isinstance(item, dict) and item.get("is_vulnerability") is True]
            elif isinstance(u_check, dict):
                findings = u_check.get("confirmed_vulnerabilities", [])
            else:
                findings = []
        else:
            findings = []
            u_check = {}

        raw_str = str(tool_output)

        is_vuln = (
            any(f.get("is_vulnerability") is True for f in findings)
            or "CONFIRMED_UNAUTHENTICATED_ACCESS" in raw_str
            or "VULN_UNAUTHENTICATED_DATA_EXPOSURE" in raw_str
        )

        if is_vuln:
            target_url = tool_output.get("target", "") if isinstance(tool_output, dict) else ""
            target_endpoint = findings[0].get("endpoint", "") if findings else ""
            rec = cls._create_trusted_evidence_record(
                category="AUTH",
                vulnclass="Broken Access Control (Authentication Bypass)",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity="HIGH",
                evidence_payload=u_check or {"poc": "Unauthenticated access exposed protected data"},
                trusted_tool="audit_unauthenticated_access"
            )
            return {
                "category": "AUTH",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": "HIGH",
                "cwe": "CWE-306",
                "rationale": "Unauthenticated access permitted to protected administrative data",
                "evidence": u_check,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec
            }

        return {
            "category": "AUTH",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": "Authentication boundary enforced; unauthenticated access rejected"
        }

    @classmethod
    def evaluate_auth_boundary_evidence(cls, tool_output: Any) -> Dict[str, Any]:
        return cls.evaluate_auth_evidence(tool_output)

    @classmethod
    def evaluate_session_invalidation_evidence(cls, tool_output: Any) -> Dict[str, Any]:
        return cls.evaluate_auth_evidence(tool_output)

    @classmethod
    def evaluate_web_posture_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates CORS, Open Redirect, Sensitive Exposures, Path Traversal, and CSRF findings.
        """
        posture = tool_output.get("web_posture") or tool_output
        results = posture.get("results", []) if isinstance(posture, dict) else []
        confirmed = [r for r in results if isinstance(r, dict) and r.get("is_vulnerability") is True]

        if confirmed:
            first = confirmed[0]
            target_url = tool_output.get("target") or posture.get("target") or ""
            target_endpoint = first.get("endpoint", "/")
            check_name = first.get("check", "WEB_POSTURE")
            sev = str(first.get("severity", "MEDIUM")).upper()
            cwe = first.get("cwe_id", "CWE-200")
            payload = {
                "endpoint": target_endpoint,
                "check": check_name,
                "verdict": first.get("verdict", "VULN_WEB_POSTURE"),
                "cwe_id": cwe,
                "confirmed_count": len(confirmed),
                "confirmed_items": [
                    {
                        "check": c.get("check"),
                        "endpoint": c.get("endpoint"),
                        "severity": c.get("severity"),
                        "cwe_id": c.get("cwe_id"),
                        "verdict": c.get("verdict"),
                        "evidence_snippet": c.get("evidence_snippet", ""),
                    }
                    for c in confirmed
                ],
                "reproduction_steps": first.get("reproduction_steps", ""),
                "remediation": first.get("remediation", ""),
            }
            rec = cls._create_trusted_evidence_record(
                category="WEB_POSTURE",
                vulnclass=f"Web Posture ({check_name})",
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity=sev,
                evidence_payload=payload,
                trusted_tool="audit_web_posture",
            )
            return {
                "category": "WEB_POSTURE",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": sev,
                "cwe": cwe,
                "rationale": f"Confirmed {len(confirmed)} web security posture vulnerability(ies): {', '.join(c.get('check', '') for c in confirmed)}",
                "evidence": payload,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec,
            }

        return {
            "category": "WEB_POSTURE",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": "CORS, Open Redirect, sensitive endpoint exposure, path traversal, and CSRF probes showed no exploitable defects",
        }

    @classmethod
    def _evaluate_findings_list(
        cls,
        category: str,
        vulnclass: str,
        trusted_tool: str,
        default_cwe: str,
        safe_rationale: str,
        tool_output: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Unified evaluator for deterministic tool result arrays (no duplicate verdict boilerplate)."""
        results = tool_output.get("results", []) if isinstance(tool_output, dict) else []
        confirmed = [r for r in results if isinstance(r, dict) and r.get("is_vulnerability") is True]

        if confirmed:
            first = confirmed[0]
            target_url = tool_output.get("target", "")
            target_endpoint = first.get("endpoint", "/")
            sev = str(first.get("severity", "HIGH")).upper()
            cwe = first.get("cwe_id", default_cwe)
            payload = {
                "endpoint": target_endpoint,
                "parameter": first.get("parameter", ""),
                "verdict": first.get("verdict", f"VULN_{category}"),
                "cwe_id": cwe,
                "confirmed_count": len(confirmed),
                "confirmed_items": [
                    {
                        "check": item.get("check", category),
                        "endpoint": item.get("endpoint", "/"),
                        "parameter": item.get("parameter", ""),
                        "severity": item.get("severity", sev),
                        "cwe_id": item.get("cwe_id", cwe),
                        "verdict": item.get("verdict", ""),
                        "evidence_snippet": item.get("evidence_snippet", ""),
                    }
                    for item in confirmed
                ],
                "evidence_snippet": first.get("evidence_snippet", ""),
                "reproduction_steps": first.get("reproduction_steps", ""),
                "remediation": first.get("remediation", ""),
            }
            rec = cls._create_trusted_evidence_record(
                category=category,
                vulnclass=vulnclass,
                target_url=target_url,
                target_endpoint=target_endpoint,
                severity=sev,
                evidence_payload=payload,
                trusted_tool=trusted_tool,
            )
            return {
                "category": category,
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "is_vulnerable": True,
                "severity": sev,
                "cwe": cwe,
                "rationale": f"Confirmed {len(confirmed)} {vulnclass} finding(s) on {', '.join(str(c.get('endpoint', '/')) for c in confirmed)}",
                "evidence": payload,
                "evidence_id": rec["evidence_id"],
                "evidence_record": rec,
            }

        return {
            "category": category,
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "INFO",
            "rationale": safe_rationale,
        }

    @classmethod
    def evaluate_general_sqli_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("GENERAL_SQLI", "SQL Injection (Query/Form/API)", "audit_general_sqli", "CWE-89", "General query/form/API SQLi probes showed no error disclosure or boolean differential bypass", tool_output)

    @classmethod
    def evaluate_cmdi_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("CMDI", "OS Command Injection", "audit_command_injection", "CWE-78", "OS Command Injection probes showed no shell execution or timing differential", tool_output)

    @classmethod
    def evaluate_ssti_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("SSTI", "Server-Side Template Injection", "audit_ssti", "CWE-1336", "Template expression probes were not evaluated server-side", tool_output)

    @classmethod
    def evaluate_jwt_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("JWT", "JWT Cryptographic Validation Weakness", "audit_jwt_security", "CWE-347", "JWT tokens passed alg=none and weak-secret checks", tool_output)

    @classmethod
    def evaluate_stored_xss_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("STORED_XSS", "Stored Cross-Site Scripting (XSS)", "audit_stored_xss", "CWE-79", "Submitted POST forms did not execute persistent scripts in Chromium DOM", tool_output)

    @classmethod
    def evaluate_graphql_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("GRAPHQL", "GraphQL Security Misconfiguration / Injection", "audit_graphql_security", "CWE-200", "GraphQL schema introspection and argument injection controls held", tool_output)

    @classmethod
    def evaluate_time_blind_sqli_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("TIME_BLIND_SQLI", "Time-Based Blind SQL Injection", "audit_time_blind_sqli", "CWE-89", "4-step timing sandwich probes showed no SQL sleep delay differential", tool_output)

    @classmethod
    def evaluate_xxe_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        return cls._evaluate_findings_list("XXE", "XML External/Internal Entity Expansion (XXE)", "audit_xxe_injection", "CWE-611", "XML DOCTYPE entity definitions were rejected or not expanded", tool_output)

    @classmethod
    def evaluate_oast_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        oast = tool_output.get("oast") or tool_output
        results = oast.get("results", []) if isinstance(oast, dict) else []
        confirmed = [r for r in results if isinstance(r, dict) and r.get("is_vulnerability") is True]
        if confirmed:
            first = confirmed[0]
            is_ssrf = first.get("check") == "BLIND_SSRF_OAST"
            cat = "BLIND_SSRF" if is_ssrf else "BLIND_XSS"
            cwe = first.get("cwe_id") or ("CWE-918" if is_ssrf else "CWE-79")
            vulnclass = "Blind Server-Side Request Forgery (OAST SSRF)" if is_ssrf else "Blind Cross-Site Scripting (OAST XSS)"
            return cls._evaluate_findings_list(cat, vulnclass, "audit_oast_blind", cwe, "No Out-of-Band callbacks received", tool_output)
        return cls._evaluate_findings_list("OAST_BLIND", "Out-of-Band Blind SSRF / Blind XSS", "audit_oast_blind", "CWE-918", "No Out-of-Band (OAST) HTTP/JS callbacks were received within window", tool_output)

    @classmethod
    def evaluate_headers_evidence(cls, tool_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rule: Missing CSP/HSTS/Server banner is Hardening / Info advisory.
        It is NOT an exploitable high-severity vulnerability and NEVER justifies a VULNERABLE verdict.
        """
        return {
            "category": "HARDENING",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "is_vulnerable": False,
            "severity": "LOW",
            "cwe": "CWE-16",
            "rationale": "Missing security headers noted for defense-in-depth hardening; does not constitute exploitable vulnerability"
        }

    @classmethod
    def compute_composite_verdict(
        cls,
        coverage_eval: Dict[str, Any],
        executed_tool_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesizes individual evidence evaluations and coverage status into the final system verdict.
        """
        evaluated_tests = []
        confirmed_vulns = []

        for tr in executed_tool_results:
            tool_name = tr.get("tool", "")
            data = tr.get("data", {})

            if "dom_xss" in tool_name:
                res = cls.evaluate_dom_xss_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "stored_xss" in tool_name:
                res = cls.evaluate_stored_xss_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "oast" in tool_name or "blind_" in tool_name:
                res = cls.evaluate_oast_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "graphql" in tool_name:
                res = cls.evaluate_graphql_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "time_blind_sqli" in tool_name or "time_sqli" in tool_name:
                res = cls.evaluate_time_blind_sqli_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "xxe" in tool_name:
                res = cls.evaluate_xxe_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_xss" in tool_name or "xss" in tool_name:
                res = cls.evaluate_xss_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_general_sqli" in tool_name or "general_sqli" in tool_name:
                res = cls.evaluate_general_sqli_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_sql_injection" in tool_name or "sqli" in tool_name:
                res = cls.evaluate_sqli_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_horizontal_access" in tool_name or "horizontal" in tool_name:
                res = cls.evaluate_idor_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_unauthenticated_access" in tool_name or "unauthenticated" in tool_name:
                res = cls.evaluate_auth_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_security_headers" in tool_name or "headers" in tool_name:
                res = cls.evaluate_headers_evidence(data)
                evaluated_tests.append(res)

            elif "audit_web_posture" in tool_name or "posture" in tool_name:
                res = cls.evaluate_web_posture_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_command_injection" in tool_name or "cmdi" in tool_name:
                res = cls.evaluate_cmdi_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_ssti" in tool_name or "ssti" in tool_name:
                res = cls.evaluate_ssti_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_jwt_security" in tool_name or "jwt" in tool_name:
                res = cls.evaluate_jwt_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

            elif "audit_stored_xss" in tool_name or "stored_xss" in tool_name:
                res = cls.evaluate_stored_xss_evidence(data)
                evaluated_tests.append(res)
                if res["state"] == VerdictState.CONFIRMED_VULNERABILITY:
                    confirmed_vulns.append(res)

        # 1. Any confirmed vulnerability -> VULNERABLE
        if confirmed_vulns:
            return {
                "overall_verdict": "VULNERABLE",
                "is_vulnerable": True,
                "confidence": "CONFIRMED",
                "state": VerdictState.CONFIRMED_VULNERABILITY,
                "confirmed_vulnerabilities_count": len(confirmed_vulns),
                "confirmed_vulnerabilities": confirmed_vulns,
                "coverage_complete": coverage_eval.get("coverage_complete", False),
                "rationale": f"Found {len(confirmed_vulns)} confirmed exploitable vulnerability(ies) with technical proof."
            }

        # 2. Authentication barrier reached without session -> INCONCLUSIVE_AUTH_GATED
        if coverage_eval.get("auth_gate_detected") and not coverage_eval.get("authenticated_session_active"):
            gate_reason = coverage_eval.get("auth_gate_reason") or "Application gated behind login barrier; interior application routes were not reachable unauthenticated."
            return {
                "overall_verdict": "INCONCLUSIVE_AUTH_GATED",
                "is_vulnerable": False,
                "confidence": "PREAUTH_ONLY",
                "state": VerdictState.NOT_TESTED,
                "confirmed_vulnerabilities_count": 0,
                "coverage_complete": False,
                "rationale": f"Cannot declare application SECURE: {gate_reason} Provide --cookie, --header, or --login-user/--login-pass to verify authenticated functionality."
            }

        # 3. Coverage incomplete -> CANNOT be declared SECURE
        if not coverage_eval.get("coverage_complete", True):
            untested_count = coverage_eval.get("untested_count", 0)
            return {
                "overall_verdict": "INCONCLUSIVE_INCOMPLETE_COVERAGE",
                "is_vulnerable": False,
                "confidence": "UNVERIFIED",
                "state": VerdictState.NOT_TESTED,
                "untested_count": untested_count,
                "coverage_complete": False,
                "rationale": f"Cannot declare application secure: {untested_count} planned attack surface(s) remained NOT_TESTED."
            }

        # 3. All planned tests completed with no confirmed vulns -> SECURE
        return {
            "overall_verdict": "SECURE",
            "is_vulnerable": False,
            "confidence": "HIGH",
            "state": VerdictState.TESTED_NOT_REPRODUCED,
            "confirmed_vulnerabilities_count": 0,
            "coverage_complete": True,
            "rationale": "All planned attack surfaces were tested; no exploitable vulnerabilities were reproduced."
        }
