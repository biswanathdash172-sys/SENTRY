"""
services/sca_service.py
------------------------
Real Software Composition Analysis (SCA) scanning via the OSV.dev public
API (https://api.osv.dev) — free, no API key, no signup, no cost. This is
the actual live vulnerability data source; there is no mock/demo mode for
the scan results themselves (per explicit "no dummy data" requirement).

WHAT "FIXED TEST PAYLOAD" MEANS HERE (confirmed with the user): the
*packages we scan* are a fixed, hardcoded list (so a judge can reliably
trigger the same demo scan on demand) — but the *vulnerability data
returned for them* is 100% real, live-queried from OSV.dev every time.
Nothing about the scan result is fabricated; only the input package list
is fixed for demo repeatability.

FLOW (mirrors media_integrity_service.py's shape: verify -> evidence):
  1. query_osv() hits the real OSV.dev API for one package+version.
  2. _extract_worst_cvss() finds the highest CVSS score among any
     vulnerabilities OSV returned (worst case wins — same "many small
     clues" philosophy as correlation_engine.py's noisy-OR).
  3. risk_classifier.classify_cvss() maps that score to a tier, fail-safe
     defaulting to high_risky on anything missing/malformed.
  4. risk_classifier.can_auto_approve() checks the org's own runtime rules
     (never true for high_risky, no matter what).
  5. Everything is written to Supabase: scan_results, risk_flags, and a
     scan_audit_log entry — real persisted rows, not in-memory-only state.

FAIL-SAFE ON NETWORK ERRORS: if OSV.dev is unreachable or returns a
malformed response, we do NOT silently skip the package or invent a
score. We record it as high_risky with cvss_score=None and a clear
reason, exactly like a missing CVSS score — an unreachable scanner is
exactly as dangerous as an unscanned package, so it must fail toward
"needs a human," never toward "looks fine."
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional
import logging

import requests

from services.risk_classifier import classify_cvss, can_auto_approve, RiskTier

logger = logging.getLogger("sentry.sca_service")

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_REQUEST_TIMEOUT_SECONDS = 10

# ---------------------------------------------------------------------------
# Fixed test payload (Q4, confirmed): a hardcoded set of real packages/
# versions for judges to trigger on demand. Every one of these has been
# manually verified to have real, published vulnerability history on
# OSV.dev at the time of writing — the SCORES/TIERS are NOT hardcoded,
# only which packages get queried. OSV.dev's live data decides the tier
# every single time this runs.
# ---------------------------------------------------------------------------
FIXED_TEST_PAYLOAD = [
    {"name": "pyyaml", "version": "5.3.1", "ecosystem": "PyPI"},
    {"name": "django", "version": "2.2.0", "ecosystem": "PyPI"},
    {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
]


@dataclass
class ScanResult:
    package_name: str
    package_version: Optional[str]
    ecosystem: str
    vuln_id: Optional[str]
    cvss_score: Optional[float]
    summary: Optional[str]
    tier: RiskTier
    reason: str
    raw_osv_response: dict


def query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Real, live call to the OSV.dev public API. No key required, no cost.
    Raises requests.RequestException on network failure — the caller
    (scan_package below) is responsible for treating that as fail-safe
    high_risky, not for swallowing it silently here.
    """
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }
    response = requests.post(OSV_API_URL, json=payload, timeout=OSV_REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()


def _extract_worst_cvss(osv_response: dict) -> tuple[Optional[float], Optional[str], Optional[str]]:
    """
    Scans every vulnerability OSV returned for this package+version and
    returns the WORST (highest) CVSS score found, along with that vuln's
    id and summary. Returns (None, None, None) if OSV returned vulns but
    none had a parseable CVSS score (which classify_cvss() will then
    fail-safe to high_risky, exactly as it should — a known vulnerability
    with an unreadable severity is not a green light).

    OSV's schema nests CVSS under severity[].type == "CVSS_V3" as a
    vector string (e.g. "CVSS:3.1/AV:N/AC:L/.../S:U/C:H/I:H/A:H"), not a
    bare numeric score — OSV does not always compute the numeric base
    score for us, so we parse it from the 'score' field when present,
    which OSV does populate for most GHSA/PYSEC entries.
    """
    vulns = osv_response.get("vulns", [])
    if not vulns:
        return None, None, None

    worst_score: Optional[float] = None
    worst_id: Optional[str] = None
    worst_summary: Optional[str] = None

    for vuln in vulns:
        vuln_id = vuln.get("id")
        summary = vuln.get("summary") or vuln.get("details", "")[:200]

        for severity_entry in vuln.get("severity", []):
            if severity_entry.get("type") != "CVSS_V3":
                continue
            score_str = severity_entry.get("score", "")
            # OSV sometimes gives the raw vector string instead of a bare
            # number in 'score' — only accept it if it's actually numeric.
            try:
                score = float(score_str)
            except (TypeError, ValueError):
                continue
            if worst_score is None or score > worst_score:
                worst_score = score
                worst_id = vuln_id
                worst_summary = summary

        # Some OSV entries (esp. GHSA-sourced) put severity as a plain
        # "database_specific.severity" string (LOW/MODERATE/HIGH/CRITICAL)
        # instead of a numeric CVSS. Map that conservatively if we found
        # no numeric score anywhere for this vuln, so we don't fail-safe
        # to high_risky on entries OSV *did* actually rate.
        if worst_score is None:
            db_severity = (vuln.get("database_specific", {}) or {}).get("severity", "")
            severity_floor = {
                "CRITICAL": 9.0, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0,
            }.get(str(db_severity).upper())
            if severity_floor is not None:
                worst_score = severity_floor
                worst_id = vuln_id
                worst_summary = summary

    return worst_score, worst_id, worst_summary


def scan_package(package_name: str, version: str, ecosystem: str = "PyPI") -> ScanResult:
    """
    Full scan of one package: real OSV.dev query -> worst-CVSS extraction
    -> fail-safe classification. Never raises — a network/parsing failure
    becomes a high_risky ScanResult with an explanatory reason, matching
    this codebase's "never crash, fail toward safety" philosophy
    (db/database.py, risk_classifier.py, media_integrity_service.py all
    follow the same pattern).
    """
    try:
        osv_response = query_osv(package_name, version, ecosystem)
    except requests.RequestException as exc:
        logger.warning(f"OSV.dev query failed for {package_name}=={version} ({exc}) "
                        f"— failing safe to high_risky.")
        classification = classify_cvss(None)
        return ScanResult(
            package_name=package_name, package_version=version, ecosystem=ecosystem,
            vuln_id=None, cvss_score=None,
            summary=f"OSV.dev was unreachable ({exc}) — could not verify this "
                    f"package's safety, so it is flagged for human review.",
            tier=classification.tier, reason=classification.reason,
            raw_osv_response={"error": str(exc)},
        )

    cvss_score, vuln_id, summary = _extract_worst_cvss(osv_response)
    classification = classify_cvss(cvss_score)

    if not osv_response.get("vulns"):
        # OSV found zero known vulnerabilities for this exact package+
        # version — this is a genuine "clean" result, not a missing-data
        # fail-safe case. classify_cvss(None) would say high_risky (correct
        # for "we don't know"), but here we DO know: OSV checked and found
        # nothing. This is the one legitimate case where we report
        # not_risky with no CVSS score.
        return ScanResult(
            package_name=package_name, package_version=version, ecosystem=ecosystem,
            vuln_id=None, cvss_score=None,
            summary=f"OSV.dev found no known vulnerabilities for "
                    f"{package_name}=={version}.",
            tier=RiskTier.NOT_RISKY,
            reason="No known vulnerabilities in the OSV.dev database for this "
                   "exact package and version.",
            raw_osv_response=osv_response,
        )

    return ScanResult(
        package_name=package_name, package_version=version, ecosystem=ecosystem,
        vuln_id=vuln_id, cvss_score=cvss_score,
        summary=summary or f"{len(osv_response.get('vulns', []))} known "
                            f"vulnerabilit(y/ies) found for {package_name}=={version}.",
        tier=classification.tier, reason=classification.reason,
        raw_osv_response=osv_response,
    )


def scan_fixed_payload() -> List[ScanResult]:
    """Runs scan_package() against every entry in FIXED_TEST_PAYLOAD."""
    return [
        scan_package(pkg["name"], pkg["version"], pkg["ecosystem"])
        for pkg in FIXED_TEST_PAYLOAD
    ]


# ---------------------------------------------------------------------------
# Real arbitrary-file scanning (Item B): org uploads a real requirements.txt,
# every EXACTLY-PINNED package in it gets scanned live via OSV.dev.
# ---------------------------------------------------------------------------
import re

# Matches "package==1.2.3" (with optional whitespace), the only form we can
# safely resolve to one exact version for a real vulnerability lookup.
# Deliberately does NOT match extras like "package[extra]==1.2.3" fully
# stripped — the base package name is still extracted correctly via the
# regex's own boundary, extras are just ignored for scanning purposes.
_PINNED_REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:;.*)?$"
)


def parse_requirements_txt(content: str) -> tuple[list[dict], list[str]]:
    """
    Parses requirements.txt content into (pinned_packages, skipped_lines).

    FAIL-SAFE: any line that isn't an EXACT `==` pin (e.g. `requests>=2.0`,
    a bare `requests` with no version, a `-r other.txt` include, or a git/
    URL requirement) is NOT silently dropped — it's returned in
    skipped_lines so the caller can surface it to the admin AND record it
    as a high_risky finding (an unpinned dependency means we genuinely
    cannot know which exact version will be installed, so we cannot
    verify its safety — exactly the same "unknown -> high_risky" logic as
    risk_classifier.classify_cvss(None)).
    """
    pinned: list[dict] = []
    skipped: list[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r") or line.startswith("--"):
            skipped.append(line)
            continue

        match = _PINNED_REQUIREMENT_RE.match(line)
        if not match:
            skipped.append(line)
            continue

        name, version = match.group(1), match.group(2)
        pinned.append({"name": name, "version": version, "ecosystem": "PyPI"})

    return pinned, skipped


def scan_requirements_content(content: str) -> tuple[List[ScanResult], List[ScanResult]]:
    """
    Full pipeline for an uploaded requirements.txt: parse -> scan every
    pinned package via real OSV.dev calls -> also produce an explicit
    fail-safe ScanResult for every skipped/unpinned line, so nothing in
    the uploaded file is silently ignored from the report.

    Returns (results, skipped_results) — both lists of real ScanResult
    objects; skipped_results always carry tier=HIGH_RISKY with a reason
    explaining exactly why (unpinned version), never fabricated data.
    """
    from services.risk_classifier import classify_cvss

    pinned, skipped_lines = parse_requirements_txt(content)

    results = [scan_package(pkg["name"], pkg["version"], pkg["ecosystem"]) for pkg in pinned]

    skipped_results = []
    for line in skipped_lines:
        classification = classify_cvss(None)  # fail-safe -> high_risky
        skipped_results.append(ScanResult(
            package_name=line[:200], package_version="unpinned", ecosystem="PyPI",
            vuln_id=None, cvss_score=None,
            summary=f"Line could not be resolved to an exact pinned version "
                    f"('{line}') — cannot verify safety without a fixed "
                    f"version, so flagged for human review.",
            tier=classification.tier, reason=classification.reason,
            raw_osv_response={"skipped_reason": "unpinned_or_unsupported_line"},
        ))

    return results, skipped_results


# ---------------------------------------------------------------------------
# Persistence — writes real rows to Supabase (scan_results, risk_flags,
# scan_audit_log), and applies the org's own auto-approval rules.
# ---------------------------------------------------------------------------
def persist_scan_result(
    result: ScanResult,
    org_id: str,
    employee_id: Optional[str],
    source_type: str = "sca_scan",
    app_name: Optional[str] = None,
    notification_text: Optional[str] = None,
) -> dict:
    from services.supabase_service import _get_client

    client = _get_client()
    now = datetime.now(timezone.utc).isoformat()

    scan_row = {
        "org_id": org_id,
        "employee_id": employee_id,
        "package_name": result.package_name,
        "package_version": result.package_version,
        "ecosystem": result.ecosystem,
        "vuln_id": result.vuln_id,
        "cvss_score": result.cvss_score,
        "summary": result.summary,
        "tier": result.tier.value,
        "raw_osv_response": result.raw_osv_response,
        "source_type": source_type,
        "app_name": app_name,
        "notification_text": notification_text,
    }
    scan_insert = client.table("scan_results").insert(scan_row).execute()
    scan_result_id = scan_insert.data[0]["id"]

    auto_ok = can_auto_approve(org_id, result.tier)
    flag_row = {
        "scan_result_id": scan_result_id,
        "org_id": org_id,
        "employee_id": employee_id,
        "tier": result.tier.value,
        "status": "completed" if auto_ok else "pending",
        "resolution": "auto_approved" if auto_ok else None,
        "approved_by": None,
        "approved_at": now if auto_ok else None,
    }
    flag_insert = client.table("risk_flags").insert(flag_row).execute()
    risk_flag = flag_insert.data[0]

    audit_message = (
        f"Scanned {result.package_name}"
        + (f"=={result.package_version}" if result.package_version else "")
        + f" [{source_type}]: tier={result.tier.value}, cvss={result.cvss_score}. "
        + (f"Auto-approved per org auto_approval_rules."
           if auto_ok else "Requires manual admin review (fail-safe or org rule).")
    )
    client.table("scan_audit_log").insert({
        "org_id": org_id,
        "risk_flag_id": risk_flag["id"],
        "message": audit_message,
        "actor": "system",
    }).execute()

    return risk_flag