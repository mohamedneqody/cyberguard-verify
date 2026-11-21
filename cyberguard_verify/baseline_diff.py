"""Deterministic Finding Fingerprinting & Scan Baseline Diffing Engine."""

import hashlib
import json
from typing import Any, Dict, List


def finding_fingerprint(vuln: Dict[str, Any]) -> str:
    """Computes a stable SHA-256 fingerprint across category, CWE, endpoint, parameter, and check."""
    cat = str(vuln.get("category") or "SECURITY").upper()
    cwe = str(vuln.get("cwe") or vuln.get("cwe_id") or "").upper()
    ev = vuln.get("evidence") or {}
    rec = vuln.get("evidence_record") or {}
    ep = str(ev.get("endpoint") or vuln.get("endpoint") or rec.get("target_endpoint") or "/")
    param = str(ev.get("parameter") or vuln.get("parameter") or "")
    check = str(ev.get("check") or vuln.get("check") or "")
    raw_key = f"{cat}|{cwe}|{ep}|{param}|{check}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:24]


def attach_fingerprints(report: Dict[str, Any]) -> None:
    """Assigns deterministic fingerprints in-place on all confirmed vulnerabilities."""
    cv = report.get("composite_verdict")
    if not isinstance(cv, dict):
        return
    for v in cv.get("confirmed_vulnerabilities") or []:
        if isinstance(v, dict) and not v.get("fingerprint"):
            v["fingerprint"] = finding_fingerprint(v)


def _compact_finding(v: Dict[str, Any], status: str) -> Dict[str, Any]:
    ev = v.get("evidence") or {}
    rec = v.get("evidence_record") or {}
    return {
        "fingerprint": v.get("fingerprint") or finding_fingerprint(v),
        "baseline_status": status,
        "category": v.get("category", "SECURITY"),
        "cwe": v.get("cwe", "CWE-200"),
        "severity": v.get("severity", "HIGH"),
        "endpoint": ev.get("endpoint") or rec.get("target_endpoint") or "/",
        "parameter": ev.get("parameter") or "",
        "rationale": v.get("rationale", ""),
    }


def compute_baseline_diff(current_report: Dict[str, Any], baseline_report: Dict[str, Any]) -> Dict[str, Any]:
    """Compares current scan findings against a saved baseline JSON report for PR regression gating."""
    attach_fingerprints(current_report)
    attach_fingerprints(baseline_report)

    curr_vulns: List[Dict[str, Any]] = (current_report.get("composite_verdict") or {}).get("confirmed_vulnerabilities") or []
    base_vulns: List[Dict[str, Any]] = (baseline_report.get("composite_verdict") or {}).get("confirmed_vulnerabilities") or []

    base_map: Dict[str, Dict[str, Any]] = {}
    for bv in base_vulns:
        if isinstance(bv, dict):
            fp = bv.get("fingerprint") or finding_fingerprint(bv)
            base_map[fp] = bv

    curr_map: Dict[str, Dict[str, Any]] = {}
    new_list: List[Dict[str, Any]] = []
    persisting_list: List[Dict[str, Any]] = []

    for cv_item in curr_vulns:
        if not isinstance(cv_item, dict):
            continue
        fp = cv_item.get("fingerprint") or finding_fingerprint(cv_item)
        curr_map[fp] = cv_item
        if fp in base_map:
            cv_item["baseline_status"] = "unchanged"
            persisting_list.append(_compact_finding(cv_item, "unchanged"))
        else:
            cv_item["baseline_status"] = "new"
            new_list.append(_compact_finding(cv_item, "new"))

    fixed_list: List[Dict[str, Any]] = [
        _compact_finding(bv, "absent")
        for fp, bv in base_map.items()
        if fp not in curr_map
    ]

    summary = f"{len(new_list)} new, {len(persisting_list)} persisting, {len(fixed_list)} fixed"
    diff_block = {
        "baseline_target": baseline_report.get("target", ""),
        "baseline_timestamp": baseline_report.get("timestamp", ""),
        "new_count": len(new_list),
        "persisting_count": len(persisting_list),
        "fixed_count": len(fixed_list),
        "new_vulnerabilities": new_list,
        "persisting_vulnerabilities": persisting_list,
        "fixed_vulnerabilities": fixed_list,
        "summary": summary,
    }
    current_report["baseline_diff"] = diff_block
    return diff_block


def load_baseline_report(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid baseline JSON in '{path}'")
    return data
