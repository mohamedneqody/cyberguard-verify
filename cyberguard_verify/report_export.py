"""
ARTEX CyberGuard — SARIF 2.1.0, White-Label HTML & Executive PDF Report Exporters
Produces CI-consumable OASIS SARIF 2.1.0 JSON, white-label HTML, and A4 PDF reports
with CWE/OWASP Top 10 mappings, SHA-256 evidence IDs, PoC curl commands, and coverage details.
"""

import glob
import html
import os
import time
from typing import Any, Dict, List, Optional

OWASP_MAP = {
    "SQLI": "A03:2021 Injection",
    "GENERAL_SQLI": "A03:2021 Injection",
    "TIME_BLIND_SQLI": "A03:2021 Injection",
    "CMDI": "A03:2021 Injection",
    "SSTI": "A03:2021 Injection",
    "XXE": "A05:2021 Security Misconfiguration",
    "XSS": "A03:2021 Injection",
    "DOM_XSS": "A03:2021 Injection",
    "STORED_XSS": "A03:2021 Injection",
    "BLIND_XSS": "A03:2021 Injection",
    "IDOR": "A01:2021 Broken Access Control",
    "AUTH_BOUNDARY": "A01:2021 Broken Access Control",
    "JWT": "A07:2021 Identification and Authentication Failures",
    "SESSION": "A07:2021 Identification and Authentication Failures",
    "WEB_POSTURE": "A05:2021 Security Misconfiguration",
    "GRAPHQL": "A05:2021 Security Misconfiguration",
    "BLIND_SSRF": "A10:2021 Server-Side Request Forgery",
    "OAST_BLIND": "A10:2021 Server-Side Request Forgery",
}


def extract_confirmed_vulnerabilities(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Collects confirmed vulnerability records from composite or single-mode outputs."""
    cv = data.get("composite_verdict") or {}
    vulns = list(cv.get("confirmed_vulnerabilities") or [])
    if not vulns and isinstance(data.get("evidence_verdict"), dict):
        ev = data["evidence_verdict"]
        if ev.get("is_vulnerable"):
            vulns = [ev]
    return vulns


def build_sarif_report(
    target_url: str,
    data: Dict[str, Any],
    brand_name: str = "",
    client_name: str = "",
) -> Dict[str, Any]:
    """Converts composite_verdict or single-mode output into OASIS SARIF 2.1.0 JSON."""
    vulns = extract_confirmed_vulnerabilities(data)
    branding = data.get("branding") or {}
    brand = str(brand_name or branding.get("brand_name") or "CyberGuard Verification Engine").strip()
    client = str(client_name or branding.get("client_name") or "").strip()
    level_map = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for v in vulns:
        cat = v.get("category", "SECURITY")
        cwe = v.get("cwe", "CWE-200")
        rule_id = f"CG-{cat}"
        sev = str(v.get("severity", "HIGH")).upper()
        ev = v.get("evidence") or {}
        ep = ev.get("endpoint") or (v.get("evidence_record") or {}).get("target_endpoint") or "/"
        owasp = OWASP_MAP.get(cat, "OWASP Top 10")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": cat,
                "shortDescription": {"text": f"{cat} ({cwe})"},
                "fullDescription": {"text": f"{v.get('rationale', cat)} [{owasp}]"},
                "properties": {
                    "cwe": cwe,
                    "owasp": owasp,
                    "security-severity": "9.0" if sev == "CRITICAL" else ("8.0" if sev == "HIGH" else "5.5"),
                },
            }

        res_entry = {
            "ruleId": rule_id,
            "level": level_map.get(sev, "warning"),
            "message": {"text": f"{v.get('rationale', cat)} [endpoint: {ep}] (evidence_id: {v.get('evidence_id', 'none')})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"{target_url.rstrip('/')}{ep if str(ep).startswith('/') else '/' + str(ep)}"}
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": v.get("fingerprint") or f"{rule_id}:{ep}:{ev.get('parameter', '')}",
            },
            "properties": {
                "category": cat,
                "cwe": cwe,
                "owasp": owasp,
                "severity": sev,
                "evidence_id": v.get("evidence_id", ""),
                "integrity_hash": (v.get("evidence_record") or {}).get("integrity_hash", ""),
                "fingerprint": v.get("fingerprint", ""),
            },
        }
        if v.get("baseline_status") in ("new", "unchanged", "absent", "updated"):
            res_entry["baselineState"] = v["baseline_status"]
        results.append(res_entry)

    driver: Dict[str, Any] = {
        "name": brand,
        "version": "3.3.0",
        "rules": list(rules.values()),
    }
    if brand_name or branding.get("brand_name"):
        driver["organization"] = brand
    run_obj: Dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }
    if client:
        run_obj["properties"] = {"clientName": client}

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run_obj],
    }


def build_html_report(
    target_url: str,
    data: Dict[str, Any],
    brand_name: str = "",
    client_name: str = "",
) -> str:
    """Generates a self-contained executive white-label HTML security audit report."""
    cv = data.get("composite_verdict") or {}
    cov = data.get("coverage_evaluation") or {}
    branding = data.get("branding") or {}
    brand = str(brand_name or branding.get("brand_name") or "CyberGuard").strip()
    client = str(client_name or branding.get("client_name") or "").strip()
    vulns = extract_confirmed_vulnerabilities(data)
    matrix = cov.get("coverage_matrix") or []
    verdict = str(cv.get("overall_verdict", "UNKNOWN"))
    conf = str(cv.get("confidence", "UNKNOWN"))
    rationale = str(cv.get("rationale", ""))
    auth_gated = bool(cov.get("auth_gate_detected"))
    auth_active = bool(cov.get("authenticated_session_active"))
    now_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    badge_cls = "badge-vuln" if verdict == "VULNERABLE" else ("badge-safe" if verdict == "SECURE" else "badge-warn")
    client_sub = f"Prepared for: <strong>{html.escape(client)}</strong> &middot; " if client else ""
    footer_for = f" for <strong>{html.escape(client)}</strong>" if client else ""

    vuln_cards = []
    for idx, v in enumerate(vulns, 1):
        cat = str(v.get("category", "SECURITY"))
        sev = str(v.get("severity", "HIGH")).upper()
        cwe = str(v.get("cwe", "CWE-200"))
        owasp = OWASP_MAP.get(cat, "OWASP Top 10")
        ev = v.get("evidence") or {}
        rec = v.get("evidence_record") or {}
        ep = str(ev.get("endpoint") or rec.get("target_endpoint") or "/")
        repro = str(ev.get("reproduction_steps") or "")
        remed = str(ev.get("remediation") or "Apply input validation, contextual encoding, and strict server-side authorization.")
        snippet = str(ev.get("evidence_snippet") or rec.get("redacted_evidence") or "")[:500]
        ev_id = str(v.get("evidence_id") or rec.get("evidence_id") or "")
        ihash = str(rec.get("integrity_hash") or "")
        full_ep = f"{target_url.rstrip('/')}{ep if ep.startswith('/') else '/' + ep}"
        curl_poc = repro if "curl " in repro else f"curl -i '{full_ep}'"
        bstatus = v.get("baseline_status", "")
        b_badge = '<span class="sev" style="background:#7c3aed;color:#fff">NEW</span>' if bstatus == "new" else ('<span class="sev" style="background:#334155;color:#cbd5e1">PRE-EXISTING</span>' if bstatus == "unchanged" else "")

        vuln_cards.append(f"""
        <div class="card finding">
          <div class="finding-head">
            <span class="sev sev-{html.escape(sev.lower())}">{html.escape(sev)}</span>
            <strong>#{idx} {html.escape(cat)}</strong>
            {b_badge}
            <span class="meta">{html.escape(cwe)} &middot; {html.escape(owasp)}</span>
          </div>
          <p><strong>Endpoint:</strong> <code>{html.escape(ep)}</code></p>
          <p>{html.escape(str(v.get('rationale', '')))}</p>
          <div class="meta-box">
            <div><strong>Evidence ID:</strong> <code>{html.escape(ev_id)}</code></div>
            <div><strong>SHA-256 Integrity:</strong> <code>{html.escape(ihash)}</code></div>
          </div>
          <details open>
            <summary>Verified Evidence &amp; PoC Reproduction</summary>
            <pre>{html.escape(snippet)}</pre>
            <p><strong>PoC / Reproduction:</strong></p>
            <pre>{html.escape(curl_poc)}</pre>
            <p><strong>Remediation:</strong> {html.escape(remed)}</p>
          </details>
        </div>""")

    matrix_rows = []
    for row in matrix:
        matrix_rows.append(
            f"<tr><td><code>{html.escape(str(row.get('test_id','')))}</code></td>"
            f"<td>{html.escape(str(row.get('category','')))}</td>"
            f"<td><code>{html.escape(str(row.get('method','')))} {html.escape(str(row.get('endpoint','')))}</code></td>"
            f"<td><code>{html.escape(str(row.get('parameter','')))}</code></td>"
            f"<td>{html.escape(str(row.get('execution_status','')))}</td>"
            f"<td>{html.escape(str(row.get('evidence_status','')))}</td></tr>"
        )

    findings_html = "\n".join(vuln_cards) if vuln_cards else (
        '<div class="card"><p>No confirmed exploitable vulnerabilities were reproduced within the executed scope.</p></div>'
    )

    bdiff = data.get("baseline_diff")
    bdiff_html = ""
    if isinstance(bdiff, dict):
        bdiff_html = f"""
  <h2>Baseline Regression Diff</h2>
  <div class="card">
    <div class="grid" style="margin-top:0">
      <div class="stat"><label>New Vulnerabilities</label><span style="color:#f87171">{bdiff.get('new_count', 0)}</span></div>
      <div class="stat"><label>Persisting (Baseline)</label><span>{bdiff.get('persisting_count', 0)}</span></div>
      <div class="stat"><label>Fixed Since Baseline</label><span style="color:#34d399">{bdiff.get('fixed_count', 0)}</span></div>
    </div>
    <p style="margin-top:12px;color:#94a3b8">Compared against baseline target <code>{html.escape(str(bdiff.get('baseline_target', '')))}</code> ({html.escape(str(bdiff.get('summary', '')))})</p>
  </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{html.escape(brand)} Security Verification Report — {html.escape(target_url)}</title>
<style>
  * {{ box-sizing: border-box; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 32px; line-height: 1.5; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; }}
  .hero {{ background: linear-gradient(135deg, #111827, #1e293b); border: 1px solid #334155; border-radius: 14px; padding: 24px 28px; margin-bottom: 24px; }}
  .brand-pill {{ display: inline-block; padding: 3px 10px; border-radius: 999px; background: rgba(56, 189, 248, 0.14); border: 1px solid rgba(56, 189, 248, 0.45); color: #38bdf8; font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 10px; }}
  .hero h1 {{ margin: 0 0 8px; font-size: 24px; }}
  .badge {{ display: inline-block; padding: 5px 12px; border-radius: 999px; font-weight: 700; font-size: 13px; }}
  .badge-vuln {{ background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }}
  .badge-safe {{ background: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }}
  .badge-warn {{ background: #78350f; color: #fde68a; border: 1px solid #f59e0b; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 16px; }}
  .stat {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 14px; }}
  .stat label {{ display: block; font-size: 12px; color: #94a3b8; }}
  .stat span {{ font-size: 18px; font-weight: 700; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 18px 20px; margin-bottom: 16px; break-inside: avoid; page-break-inside: avoid; }}
  .finding-head {{ display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 10px; }}
  .sev {{ padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 700; }}
  .sev-critical {{ background: #991b1b; color: #fff; }}
  .sev-high {{ background: #dc2626; color: #fff; }}
  .sev-medium {{ background: #d97706; color: #fff; }}
  .sev-low {{ background: #2563eb; color: #fff; }}
  .meta {{ color: #94a3b8; font-size: 13px; }}
  .meta-box {{ background: #0f172a; border-radius: 8px; padding: 10px 12px; font-size: 12px; margin: 10px 0; }}
  pre {{ background: #020617; border: 1px solid #1e293b; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; color: #cbd5e1; white-space: pre-wrap; word-break: break-word; }}
  code {{ color: #38bdf8; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid #1f2937; }}
  th {{ color: #94a3b8; font-weight: 600; }}
  .footer {{ margin-top: 24px; text-align: center; color: #94a3b8; font-size: 12px; border-top: 1px solid #1e293b; padding-top: 16px; }}
  @media print {{ body {{ padding: 14px; background: #0b1120; }} }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <div class="brand-pill">{html.escape(brand)} Security Verification</div>
    <h1>{html.escape(brand)} &mdash; Evidence-Based Security Verification Report</h1>
    <div>{client_sub}Target: <code>{html.escape(target_url)}</code> &middot; Generated: {html.escape(now_utc)}</div>
    <p style="margin-top:12px"><span class="badge {badge_cls}">{html.escape(verdict)} ({html.escape(conf)})</span></p>
    <p>{html.escape(rationale)}</p>
    <div class="grid">
      <div class="stat"><label>Confirmed Exploitable Findings</label><span>{len(vulns)}</span></div>
      <div class="stat"><label>Coverage Executed</label><span>{cov.get('covered_count', 0)}/{cov.get('total_planned', 0)} ({cov.get('coverage_percentage', 0)}%)</span></div>
      <div class="stat"><label>Session Mode</label><span>{'Authenticated' if auth_active else ('Auth-Gated (Pre-Auth Only)' if auth_gated else 'Unauthenticated')}</span></div>
      <div class="stat"><label>Engine Version</label><span>{html.escape(brand)} 3.3</span></div>
    </div>
  </div>
{bdiff_html}
  <h2>1. Confirmed Vulnerabilities</h2>
  {findings_html}

  <h2>2. Coverage &amp; Execution Matrix</h2>
  <div class="card" style="overflow-x:auto">
    <table>
      <thead><tr><th>Test ID</th><th>Category</th><th>Endpoint</th><th>Parameter</th><th>Execution</th><th>Evidence Status</th></tr></thead>
      <tbody>{''.join(matrix_rows) if matrix_rows else '<tr><td colspan="6">No coverage matrix entries</td></tr>'}</tbody>
    </table>
  </div>
  <div class="footer">
    Prepared by <strong>{html.escape(brand)}</strong>{footer_for} &middot; Zero-False-Positive Evidence Verification Engine v3.3
  </div>
</div>
</body>
</html>"""


def _pdf_escape(text: str) -> str:
    ascii_txt = text.encode("latin-1", errors="replace").decode("latin-1")
    return ascii_txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_fallback_pdf_bytes(
    target_url: str,
    data: Dict[str, Any],
    brand_name: str = "",
    client_name: str = "",
) -> bytes:
    """Pure-stdlib valid %PDF-1.4 executive report generator used when Chromium PDF is unavailable."""
    cv = data.get("composite_verdict") or {}
    cov = data.get("coverage_evaluation") or {}
    branding = data.get("branding") or {}
    brand = str(brand_name or branding.get("brand_name") or "CyberGuard").strip()
    client = str(client_name or branding.get("client_name") or "").strip()
    vulns = extract_confirmed_vulnerabilities(data)
    verdict = str(cv.get("overall_verdict", "UNKNOWN"))
    conf = str(cv.get("confidence", "UNKNOWN"))
    now_utc = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    lines: List[str] = [
        f"{brand} - Evidence-Based Security Verification Report",
        f"Prepared for: {client}" if client else "Prepared for: Security Engineering & QA",
        f"Target URL: {target_url}",
        f"Generated: {now_utc}",
        f"Verdict: {verdict} ({conf}) | Confirmed Findings: {len(vulns)} | Coverage: {cov.get('coverage_percentage', 0)}%",
        "-" * 78,
    ]
    if not vulns:
        lines.append("No confirmed exploitable vulnerabilities were reproduced within the executed scope.")
    else:
        for idx, v in enumerate(vulns, 1):
            ev = v.get("evidence") or {}
            rec = v.get("evidence_record") or {}
            ep = str(ev.get("endpoint") or rec.get("target_endpoint") or "/")
            ev_id = str(v.get("evidence_id") or rec.get("evidence_id") or "")
            lines.append(f"#{idx} [{v.get('severity', 'HIGH')}] {v.get('category', 'SECURITY')} ({v.get('cwe', 'CWE-200')}) -> {ep}")
            lines.append(f"   Rationale: {str(v.get('rationale', ''))[:86]}")
            lines.append(f"   Evidence ID: {ev_id}")
            remed = str(ev.get("remediation") or "").strip()
            if remed:
                lines.append(f"   Remediation: {remed[:84]}")

    stream_cmds = ["BT", "/F1 11 Tf", "45 760 Td", "15 TL"]
    for i, ln in enumerate(lines[:44]):
        op = "Tj" if i == 0 else "T* (" + _pdf_escape(ln) + ") Tj"
        if i == 0:
            stream_cmds.append(f"({_pdf_escape(ln)}) Tj")
        else:
            stream_cmds.append(op)
    stream_cmds.append("ET")
    stream_bytes = ("\n".join(stream_cmds)).encode("latin-1", errors="replace")

    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii") + stream_bytes + b"\nendstream\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for ob in objs:
        offsets.append(len(out))
        out.extend(ob)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii"))
    return bytes(out)


def _find_pdf_chromium_executable() -> Optional[str]:
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        candidates = sorted(
            glob.glob(os.path.join(local_app, "ms-playwright", "chromium_headless_shell-*", "*", "*.exe"))
            + glob.glob(os.path.join(local_app, "ms-playwright", "chromium-*", "*", "chrome.exe")),
            reverse=True,
        )
        if candidates:
            return candidates[0]
    for edge in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ):
        if os.path.exists(edge):
            return edge
    return None


def export_pdf_report(
    target_url: str,
    data: Dict[str, Any],
    out_path: str = "",
    brand_name: str = "",
    client_name: str = "",
) -> bytes:
    """
    Renders the white-label executive HTML report to an A4 PDF via Playwright headless Chromium,
    with automatic fallback to a pure-stdlib valid %PDF-1.4 document if Chromium is unavailable.
    """
    html_doc = build_html_report(target_url, data, brand_name=brand_name, client_name=client_name)
    pdf_bytes: Optional[bytes] = None
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            kwargs = {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]}
            try:
                browser = p.chromium.launch(**kwargs)
            except Exception:
                exe = _find_pdf_chromium_executable()
                if not exe:
                    raise
                browser = p.chromium.launch(executable_path=exe, **kwargs)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 900})
                page.set_content(html_doc, wait_until="load")
                pdf_bytes = page.pdf(
                    format="A4",
                    print_background=True,
                    margin={"top": "12mm", "bottom": "12mm", "left": "10mm", "right": "10mm"},
                )
            finally:
                browser.close()
    except Exception:
        pdf_bytes = build_fallback_pdf_bytes(target_url, data, brand_name=brand_name, client_name=client_name)

    if out_path:
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(pdf_bytes)
    return pdf_bytes
