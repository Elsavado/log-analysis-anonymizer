#!/usr/bin/env python3
"""Anonymize Windows EVTX files (g0-g6) into renamed .jsonl.gz files."""
import gzip
import json
import re
import sys
from pathlib import Path

from evtx import PyEvtxParser

from anon_common import SHIFT_2026_TO_2025, anonymize_text


def main():
    in_dir = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    for p in sorted(in_dir.glob("g*_*.evtx")):
        m = re.match(r"(g\d+)_\d{8}-\d{6}_(.+)\.evtx$", p.name)
        if not m:
            continue
        grp, channel = m.group(1), m.group(2)
        out_name = f"env4_win_{grp}_20251113_{channel}.jsonl.gz"
        print(f"Anonymizing {p.name} -> {out_name}", flush=True)
        parser = PyEvtxParser(str(p))
        with gzip.open(out_dir / out_name, "wt", encoding="utf-8") as fout:
            for rec in parser.records():
                obj = {
                    "record_id": rec.get("event_record_id"),
                    "timestamp": anonymize_text(str(rec.get("timestamp", "")), SHIFT_2026_TO_2025),
                    "xml": anonymize_text(rec.get("data", ""), SHIFT_2026_TO_2025),
                }
                fout.write(json.dumps(obj) + "\n")
    print("EVTX anonymization complete.")


if __name__ == "__main__":
    main()
