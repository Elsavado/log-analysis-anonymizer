#!/usr/bin/env python3
"""Anonymize Okta, Linux, timeline, and OTRF APT29 logs."""
import gzip
import json
import re
import sys
import zipfile
from pathlib import Path

from anon_common import (
    SHIFT_2020_TO_2015,
    SHIFT_2026_TO_2025,
    anonymize_text,
)


def anon_okta(in_dir: Path, out_dir: Path):
    # Summary CSV
    csv_in = in_dir / "okta_summary_2026-11.csv"
    if csv_in.exists():
        txt = anonymize_text(csv_in.read_text(encoding="utf-8", errors="ignore"), SHIFT_2026_TO_2025)
        (out_dir / "env3_idp_summary_2025-11.csv").write_text(txt, encoding="utf-8")

    # JSONL.GZ logs
    for idx, p in enumerate(sorted(in_dir.glob("okta_system_log_*.jsonl.gz")), start=1):
        out_name = f"env3_idp_system_log_2025-11_part{idx:02d}.jsonl.gz"
        with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as fin, \
             gzip.open(out_dir / out_name, "wt", encoding="utf-8") as fout:
            for line in fin:
                if not line.strip():
                    continue
                fout.write(anonymize_text(line, SHIFT_2026_TO_2025))


def anon_linux(in_dir: Path, out_dir: Path):
    for p in sorted(in_dir.glob("linux_g*_*")):
        if p.stat().st_size == 0:
            continue
        m = re.match(r"linux_(g\d+)_\d{8}-\d{6}_(.+)$", p.name)
        if not m:
            continue
        grp, suffix = m.group(1), m.group(2)
        out_name = f"env4_lin_{grp}_20251113_{suffix}"
        with open(p, "r", encoding="utf-8", errors="ignore") as fin, \
             open(out_dir / out_name, "w", encoding="utf-8") as fout:
            for line in fin:
                fout.write(anonymize_text(line, SHIFT_2026_TO_2025))


def anon_timelines(in_dir: Path, out_dir: Path):
    for p in sorted(in_dir.glob("g*_timeline.txt")):
        m = re.match(r"(g\d+)_\d{8}-\d{6}_timeline\.txt$", p.name)
        if not m:
            continue
        grp = m.group(1)
        out_name = f"env4_win_{grp}_20251113_timeline.txt"
        txt = anonymize_text(p.read_text(encoding="utf-8", errors="ignore"), SHIFT_2026_TO_2025)
        (out_dir / out_name).write_text(txt, encoding="utf-8")


def anon_otrf(in_dir: Path, out_dir: Path):
    for idx, zp in enumerate(sorted(in_dir.glob("otrf_apt29_*.zip")), start=1):
        out_name = f"env2_corp_day{idx}_2015-05.jsonl.gz"
        with zipfile.ZipFile(zp) as zf, \
             gzip.open(out_dir / out_name, "wt", encoding="utf-8") as fout:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                with zf.open(name) as fin:
                    for raw in fin:
                        line = raw.decode("utf-8", errors="ignore")
                        fout.write(anonymize_text(line, SHIFT_2020_TO_2015))


def main():
    in_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    anon_okta(in_dir, out_dir)
    anon_linux(in_dir, out_dir)
    anon_timelines(in_dir, out_dir)
    anon_otrf(in_dir, out_dir)
    print("Small + OTRF anonymization complete.")


if __name__ == "__main__":
    main()
