#!/usr/bin/env python3
"""Shared deterministic anonymization helpers."""
import hashlib
import re
from datetime import datetime, timedelta

# -365 days shifts 2026-11-13 -> 2025-11-13
SHIFT_2026_TO_2025 = timedelta(days=-365)
SHIFT_2020_TO_2015 = timedelta(days=-1827)
SHIFT_2016_TO_2015 = timedelta(days=-366)

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
ISO_TS_RE = re.compile(r"\b(20\d{2})-(\d{2})-(\d{2})([T ])(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+\-]\d{2}:?\d{2})?\b")
SLASH_TS_RE = re.compile(r"\b(\d{2})/(\d{2})/(20\d{2})\b")

# Ordered longest/most-specific first
LITERAL_REPLACEMENTS = [
    # GitHub / Azure / Runner artifacts
    ("runnervmm7ud1", "win-eng-01"),
    ("pkrvmt4pz24vvt2", "win-img-01"),
    ("runnervmwuk1x", "lin-app-01"),
    ("runnervmccnms", "lin-app-02"),
    ("runneradmin", "svc_opsadmin"),
    ("actions/runner", "corp/ci-agent"),
    ("github.com", "git.internal.corp"),
    ("githubusercontent.com", "git-assets.internal.corp"),
    ("github", "internal-git"),
    ("WALinuxAgent", "CloudGuestAgent"),
    # Simulation / Lab / Eval wording
    ("atomic-red-team", "sec-audit-suite"),
    ("Atomic Red Team", "Security Audit Suite"),
    ("AtomicRedTeam", "SecurityAuditSuite"),
    ("simulated", "observed"),
    ("simulation", "exercise"),
    ("Simulated", "Observed"),
    ("Simulation", "Exercise"),
    ("freetrialorgcreator", "idp.bootstrap"),
    ("lab.pool.", "corp.staff."),
    # OTRF / Dunder Mifflin
    ("NEWYORK.dmevals.local", "dc-east-01.northbridge.local"),
    ("SCRANTON.dmevals.local", "ws-fin-01.northbridge.local"),
    ("NASHUA.dmevals.local", "ws-ops-01.northbridge.local"),
    ("UTICA.dmevals.local", "ws-hr-01.northbridge.local"),
    ("dmevals.local", "northbridge.local"),
    ("DMEVALS.LOCAL", "NORTHBRIDGE.LOCAL"),
    ("DMEVALS", "NORTHBRIDGE"),
    ("NEWYORK", "DC-EAST-01"),
    ("SCRANTON", "WS-FIN-01"),
    ("NASHUA", "WS-OPS-01"),
    ("UTICA", "WS-HR-01"),
    # Splunk BOTS / Wayne Enterprises
    ("suricata-ids.waynecorpinc.local", "ids-sensor-01.meridianhq.local"),
    ("waynecorpinc.local", "meridianhq.local"),
    ("WAYNECORPINC", "MERIDIANHQ"),
    ("waynecorpinc", "meridianhq"),
    ("wayneenterprises", "meridiancorp"),
    ("imreallynotbatman.com", "meridian-portal.com"),
    ("gotham-fortigate", "hq-edge-fw01"),
    ("gotham", "metro-hq"),
    ("batman", "m_portal"),
    # Okta / Personal names
    ("joseph", "alex.mercer"),
    ("Joseph", "Alex Mercer"),
    # LANL
    ("win.alnl.gov", "win.oakridge-corp.local"),
    ("lanl.gov392-3080", "oakridge-corp.local"),
    ("lanl.gov", "oakridge-corp.local"),
    ("DOM1", "CORP1"),
]

_CI_PATTERNS = [
    (re.compile(re.escape(k), re.IGNORECASE), v) for k, v in LITERAL_REPLACEMENTS
]


def _anon_local(local: str) -> str:
    h = hashlib.sha256(local.encode("utf-8", errors="ignore")).hexdigest()[:8]
    return f"u_{h}"


def rewrite_emails(text: str) -> str:
    def _repl(m):
        local = m.group(1)
        return f"{_anon_local(local)}@irtranscripts.com"
    return EMAIL_RE.sub(_repl, text)


def shift_iso_timestamps(text: str, delta: timedelta) -> str:
    def _repl(m):
        yr, mo, dy, sep, hh, mm, ss, frac, tz = m.groups()
        try:
            dt = datetime(int(yr), int(mo), int(dy), int(hh), int(mm), int(ss))
            shifted = dt + delta
            return f"{shifted.strftime('%Y-%m-%d')}{sep}{shifted.strftime('%H:%M:%S')}{frac or ''}{tz or ''}"
        except ValueError:
            return m.group(0)
    return ISO_TS_RE.sub(_repl, text)


def shift_slash_dates(text: str, delta: timedelta) -> str:
    def _repl(m):
        mo, dy, yr = m.groups()
        try:
            dt = datetime(int(yr), int(mo), int(dy))
            shifted = dt + delta
            return shifted.strftime("%m/%d/%Y")
        except ValueError:
            return m.group(0)
    return SLASH_TS_RE.sub(_repl, text)


def anonymize_text(text: str, date_delta: timedelta = SHIFT_2026_TO_2025) -> str:
    if not text:
        return text
    text = rewrite_emails(text)
    for pat, repl in _CI_PATTERNS:
        text = pat.sub(repl, text)
    if date_delta:
        text = shift_iso_timestamps(text, date_delta)
        text = shift_slash_dates(text, date_delta)
    return text
