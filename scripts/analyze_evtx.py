#!/usr/bin/env python3
"""Analyze Windows EVTX files (g0-g6) for hosts, domains, AD/DC indicators, dates, and GitHub refs."""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

from evtx import PyEvtxParser


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def analyze_evtx_file(path: Path, max_events: int = 200000):
    parser = PyEvtxParser(str(path))
    computers = Counter()
    event_ids = Counter()
    channels = Counter()
    providers = Counter()
    domains = Counter()
    users = Counter()
    ips = Counter()
    github_hits = Counter()
    min_ts = None
    max_ts = None
    total = 0

    dc_indicators = Counter()  # e.g., 4768, 4769, 4770, 4771, 4776, 4662, 5136, NTDS, KDC
    dc_event_computers = Counter()

    for rec in parser.records():
        total += 1
        if total > max_events:
            break
        xml_str = rec["data"]
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            continue

        sys_el = root.find("e:System", NS)
        if sys_el is not None:
            comp_el = sys_el.find("e:Computer", NS)
            if comp_el is not None and comp_el.text:
                computers[comp_el.text] += 1
                comp = comp_el.text
            else:
                comp = ""

            eid_el = sys_el.find("e:EventID", NS)
            eid = eid_el.text if eid_el is not None else ""
            if eid:
                event_ids[eid] += 1

            ch_el = sys_el.find("e:Channel", NS)
            if ch_el is not None and ch_el.text:
                channels[ch_el.text] += 1

            prov_el = sys_el.find("e:Provider", NS)
            if prov_el is not None:
                pname = prov_el.attrib.get("Name", "")
                if pname:
                    providers[pname] += 1

            tc_el = sys_el.find("e:TimeCreated", NS)
            if tc_el is not None:
                ts = tc_el.attrib.get("SystemTime", "")
                if ts:
                    if min_ts is None or ts < min_ts:
                        min_ts = ts
                    if max_ts is None or ts > max_ts:
                        max_ts = ts

            if eid in {"4768", "4769", "4770", "4771", "4776", "4662", "5136", "5137", "5141"}:
                dc_indicators[eid] += 1
                if comp:
                    dc_event_computers[f"{comp}:{eid}"] += 1

        # Extract EventData fields
        ed_el = root.find("e:EventData", NS)
        if ed_el is not None:
            for d in ed_el.findall("e:Data", NS):
                name = d.attrib.get("Name", "")
                val = d.text or ""
                if not val:
                    continue
                if "Domain" in name and val not in {"-", "NT AUTHORITY", "BUILTIN", "Window Manager", "Font Driver Host"}:
                    domains[val] += 1
                if name in {"TargetUserName", "SubjectUserName", "User"} and val not in {"-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}:
                    users[val] += 1
                if name in {"IpAddress", "SourceIp", "DestinationIp"} and val not in {"-", "::1", "127.0.0.1"}:
                    ips[val] += 1

        lower = xml_str.lower()
        for kw in ("github", "runnervm", "actions", "runneradmin"):
            if kw in lower:
                github_hits[kw] += 1

    return {
        "file": path.name,
        "events_sampled": total,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "computers": dict(computers.most_common(30)),
        "top_event_ids": dict(event_ids.most_common(20)),
        "channels": dict(channels.most_common(10)),
        "top_providers": dict(providers.most_common(15)),
        "domains": dict(domains.most_common(20)),
        "top_users": dict(users.most_common(20)),
        "top_ips": dict(ips.most_common(20)),
        "dc_indicators": dict(dc_indicators),
        "dc_event_computers": dict(dc_event_computers.most_common(20)),
        "github_hits": dict(github_hits),
    }


def main():
    log_dir = Path(sys.argv[1])
    out_file = Path(sys.argv[2])
    results = []
    for p in sorted(log_dir.glob("*.evtx")):
        print(f"Analyzing {p.name}...", flush=True)
        results.append(analyze_evtx_file(p))
    out_file.write_text(json.dumps(results, indent=2))
    print(f"Wrote {out_file}")


if __name__ == "__main__":
    main()
