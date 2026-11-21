"""CLI entry point for standalone CyberGuard Verify engine."""

import argparse
import json
import sys

from .engine import run_verification
from .report_export import build_html_report, build_sarif_report, export_pdf_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cyberguard-verify",
        description="CyberGuard Verify v3.3 — Evidence-Based Non-Destructive Security Verification Engine",
    )
    parser.add_argument("target", help="Authorized target URL (e.g. http://127.0.0.1:8767)")
    parser.add_argument("--mode", choices=["verdict", "discover", "graphql", "oast", "time_sqli", "xxe"], default="verdict")
    parser.add_argument("--format", choices=["json", "sarif", "html", "pdf"], default="json", help="Output report format")
    parser.add_argument("--out", default="", help="Optional output file path")
    parser.add_argument("--brand-name", default="", help="Custom brand/company name for white-label HTML/PDF/SARIF reports")
    parser.add_argument("--client-name", default="", help="Client/organization name for white-label HTML/PDF/SARIF reports")
    parser.add_argument("--cookie", default="", help="Authenticated Cookie header (e.g. 'session=...; security=low')")
    parser.add_argument("--header", action="append", default=[], help="Custom HTTP header 'Key: Value' (repeatable)")
    parser.add_argument("--storage-state", default="", help="Playwright storageState JSON file for SSO/2FA session replay")
    parser.add_argument("--workflow", default="", help="Playwright multi-step browser workflow JSON macro")
    parser.add_argument("--login-url", default="", help="Optional login endpoint URL")
    parser.add_argument("--login-user", default="", help="Username/email for automated CSRF-aware login")
    parser.add_argument("--login-pass", default="", help="Password for automated login")
    parser.add_argument("--baseline", default="", help="Previous verdict JSON report for PR baseline diffing")
    parser.add_argument("--fail-on", choices=["all", "new"], default="all", help="CI gate failure policy")
    parser.add_argument("--only-new", action="store_true", help="Alias for --fail-on new when --baseline is set")
    parser.add_argument("--graphql-url", default="", help="Explicit GraphQL endpoint URL (optional)")
    parser.add_argument("--oast-url", default="", help="External OAST callback listener URL (optional)")
    parser.add_argument("--oast-host", default="127.0.0.1", help="Callback host advertised by built-in OAST collector")
    parser.add_argument("--no-oast", action="store_true", help="Disable Out-of-Band (OAST) probing in verdict mode")
    parser.add_argument("--time-sqli", action="store_true", help="Enable 4-step timing-sandwich Time-Based Blind SQLi verification")
    parser.add_argument("--allow-host", action="append", default=[], help="Additional staging/authorized host to permit")
    parser.add_argument("--ci", action="store_true", help="Exit 1 on confirmed vulns (or new regressions with --only-new) or auth/coverage gates")

    args = parser.parse_args(argv)
    try:
        report = run_verification(
            target_url=args.target,
            mode=args.mode,
            cookie=args.cookie,
            headers=args.header,
            login_url=args.login_url,
            login_user=args.login_user,
            login_pass=args.login_pass,
            storage_state_path=args.storage_state,
            workflow_path=args.workflow,
            baseline_path=args.baseline,
            graphql_url=args.graphql_url,
            oast_url=args.oast_url,
            oast_host=args.oast_host,
            no_oast=args.no_oast,
            time_sqli=args.time_sqli,
            allow_hosts=args.allow_host,
        )
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    if args.brand_name or args.client_name:
        report["branding"] = {"brand_name": args.brand_name, "client_name": args.client_name}

    if args.format == "pdf":
        pdf_bytes = export_pdf_report(
            args.target,
            report,
            out_path=args.out,
            brand_name=args.brand_name,
            client_name=args.client_name,
        )
        summary_msg = json.dumps({
            "format": "pdf",
            "bytes": len(pdf_bytes),
            "out": args.out or "(stdout omitted binary)",
            "brand_name": args.brand_name or "CyberGuard",
            "client_name": args.client_name,
        }, indent=2)
        print(summary_msg)
    else:
        if args.format == "sarif":
            rendered = json.dumps(build_sarif_report(args.target, report, brand_name=args.brand_name, client_name=args.client_name), indent=2)
        elif args.format == "html":
            rendered = build_html_report(args.target, report, brand_name=args.brand_name, client_name=args.client_name)
        else:
            rendered = json.dumps(report, indent=2)

        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(rendered)
        else:
            print(rendered)

    if args.ci and args.mode == "verdict":
        cv = report.get("composite_verdict") or {}
        cov = report.get("coverage_evaluation") or {}
        diff = report.get("baseline_diff") or {}
        unverified_gate = (
            not cov.get("coverage_complete", True)
            or cv.get("overall_verdict") in ("INCONCLUSIVE_AUTH_GATED", "INCONCLUSIVE_INCOMPLETE_COVERAGE")
        )
        fail_on_new = (args.only_new or args.fail_on == "new") and bool(args.baseline)
        if fail_on_new:
            if unverified_gate or diff.get("new_count", 0) > 0:
                return 1
        elif cv.get("is_vulnerable") or unverified_gate:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
