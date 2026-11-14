#!/usr/bin/env python3
"""Analyze Okta, Linux, OTRF APT29, LANL cyber1, and Splunk BOTS v1 datasets."""
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from collections import Counter
from pathlib import Path


def analyze_okta(log_dir: Path):
    actors = Counter()
    domains = Counter()
    os_types = Counter()
    device_types = Counter()
    apps = Counter()
    ips = Counter()
    github_hits = Counter()
    min_ts = None
    max_ts = None
    total = 0
    unique_devices = set()

    for p in sorted(log_dir.glob("okta_system_log_*.jsonl.gz")):
        with gzip.open(p, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                total += 1
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = ev.get("published", "")
                if ts:
                    if min_ts is None or ts < min_ts:
                        min_ts = ts
                    if max_ts is None or ts > max_ts:
                        max_ts = ts
                actor = ev.get("actor", {}).get("alternateId", "")
                if actor:
                    actors[actor] += 1
                    if "@" in actor:
                        domains[actor.split("@", 1)[1]] += 1
                client = ev.get("client", {})
                ua = client.get("userAgent", {}) or {}
                os_name = ua.get("os", "Unknown")
                os_types[os_name] += 1
                dev = client.get("device", "Unknown")
                device_types[dev] += 1
                ip = client.get("ipAddress", "")
                if ip:
                    ips[ip] += 1
                # Track unique client/device fingerprints
                if actor and os_name:
                    unique_devices.add((actor, os_name, ua.get("browser", ""), ip))
                for tgt in ev.get("target", []) or []:
                    if tgt.get("type") == "AppInstance":
                        apps[tgt.get("displayName", "")] += 1
                low = line.lower()
                for kw in ("github", "runner", "actions"):
                    if kw in low:
                        github_hits[kw] += 1

    return {
        "dataset": "okta",
        "total_events": total,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "unique_email_domains": dict(domains.most_common(20)),
        "top_actors": dict(actors.most_common(25)),
        "os_types": dict(os_types.most_common(20)),
        "device_types": dict(device_types.most_common(20)),
        "unique_actor_os_browser_ip_combos": len(unique_devices),
        "apps": dict(apps.most_common(25)),
        "github_hits": dict(github_hits),
    }


def analyze_linux(log_dir: Path):
    results = []
    for p in sorted(log_dir.glob("linux_g*_journal.log")):
        hosts = Counter()
        users = Counter()
        github_hits = Counter()
        min_ts = None
        max_ts = None
        lines = 0
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lines += 1
                m = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+", line)
                if m:
                    ts, host = m.group(1), m.group(2)
                    hosts[host] += 1
                    if min_ts is None or ts < min_ts:
                        min_ts = ts
                    if max_ts is None or ts > max_ts:
                        max_ts = ts
                low = line.lower()
                for kw in ("github", "runnervm", "actions", "runneradmin"):
                    if kw in low:
                        github_hits[kw] += 1
        results.append({
            "file": p.name,
            "lines": lines,
            "min_ts": min_ts,
            "max_ts": max_ts,
            "hosts": dict(hosts.most_common(20)),
            "github_hits": dict(github_hits),
        })
    return results


def analyze_otrf(log_dir: Path):
    results = []
    for zp in sorted(log_dir.glob("otrf_apt29_*.zip")):
        hosts = Counter()
        channels = Counter()
        event_ids = Counter()
        domains = Counter()
        dc_events = Counter()
        min_ts = None
        max_ts = None
        total = 0
        with zipfile.ZipFile(zp) as zf:
            names = zf.namelist()
            for name in names:
                if not name.endswith(".json"):
                    continue
                with zf.open(name) as f:
                    for raw in f:
                        total += 1
                        try:
                            ev = json.loads(raw)
                        except Exception:
                            continue
                        host = ev.get("Hostname") or ev.get("host") or ev.get("Computer") or ""
                        if host:
                            hosts[host] += 1
                        ch = ev.get("Channel") or ev.get("SourceName") or ""
                        if ch:
                            channels[ch] += 1
                        eid = str(ev.get("EventID") or "")
                        if eid:
                            event_ids[eid] += 1
                        dom = ev.get("TargetDomainName") or ev.get("SubjectDomainName") or ""
                        if dom and dom not in {"-", "NT AUTHORITY", "BUILTIN"}:
                            domains[dom] += 1
                        ts = ev.get("@timestamp") or ev.get("EventTime") or ""
                        if ts:
                            if min_ts is None or ts < min_ts:
                                min_ts = ts
                            if max_ts is None or ts > max_ts:
                                max_ts = ts
                        if eid in {"4768", "4769", "4770", "4771", "4776", "4662", "5136"}:
                            dc_events[f"{host}:{eid}"] += 1
        results.append({
            "file": zp.name,
            "json_files": [n for n in names if n.endswith(".json")],
            "total_events": total,
            "min_ts": min_ts,
            "max_ts": max_ts,
            "hosts": dict(hosts.most_common(30)),
            "channels": dict(channels.most_common(20)),
            "top_event_ids": dict(event_ids.most_common(20)),
            "domains": dict(domains.most_common(20)),
            "dc_events": dict(dc_events.most_common(20)),
        })
    return results


def analyze_lanl_stream(drive_id: str, remote: str = "shintiru:"):
    """Stream-inspect LANL cyber1 files via rclone cat without storing 11GB+ uncompressed."""
    out = {}
    # 1. redteam.txt.gz (small)
    # 2. auth.txt.gz, dns.txt.gz, flows.txt.gz, proc.txt.gz: count unique hosts/computers, domains, timestamps
    for fname in ["lanl_cyber1_redteam.txt.gz", "lanl_cyber1_dns.txt.gz", "lanl_cyber1_flows.txt.gz", "lanl_cyber1_proc.txt.gz", "lanl_cyber1_auth.txt.gz"]:
        print(f"Streaming {fname}...", flush=True)
        cmd = ["rclone", "cat", f"{remote}{fname}", "--drive-root-folder-id", drive_id]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        computers = set()
        domains = set()
        auth_types = Counter()
        min_t = None
        max_t = None
        lines = 0
        sample_lines = []
        with gzip.GzipFile(fileobj=p.stdout) as gz:
            for raw in gz:
                lines += 1
                line = raw.decode("utf-8", errors="ignore").strip()
                if lines <= 5:
                    sample_lines.append(line)
                parts = line.split(",")
                if parts and parts[0].isdigit():
                    t = int(parts[0])
                    if min_t is None or t < min_t:
                        min_t = t
                    if max_t is None or t > max_t:
                        max_t = t
                if fname == "lanl_cyber1_auth.txt.gz" and len(parts) >= 9:
                    # time,src_user@dom,dst_user@dom,src_comp,dst_comp,auth_type,logon_type,auth_orient,success
                    for u in (parts[1], parts[2]):
                        if "@" in u:
                            domains.add(u.split("@", 1)[1])
                    computers.add(parts[3])
                    computers.add(parts[4])
                    auth_types[parts[5]] += 1
                elif fname == "lanl_cyber1_dns.txt.gz" and len(parts) >= 3:
                    computers.add(parts[1])
                    computers.add(parts[2])
                elif fname == "lanl_cyber1_flows.txt.gz" and len(parts) >= 5:
                    computers.add(parts[2])
                    computers.add(parts[4])
                elif fname == "lanl_cyber1_proc.txt.gz" and len(parts) >= 3:
                    computers.add(parts[2])
        p.wait()
        out[fname] = {
            "lines": lines,
            "min_t": min_t,
            "max_t": max_t,
            "unique_computers_or_ips": len(computers),
            "sample_computers": sorted(list(computers))[:20],
            "unique_domains": sorted(list(domains))[:20],
            "auth_types": dict(auth_types.most_common(15)),
            "sample_lines": sample_lines,
        }
    return out


def main():
    mode = sys.argv[1]
    log_dir = Path(sys.argv[2])
    out_file = Path(sys.argv[3])
    if mode == "okta_linux":
        res = {"okta": analyze_okta(log_dir), "linux": analyze_linux(log_dir)}
    elif mode == "otrf":
        res = analyze_otrf(log_dir)
    elif mode == "lanl":
        res = analyze_lanl_stream(sys.argv[4])
    else:
        raise ValueError(f"Unknown mode: {mode}")
    out_file.write_text(json.dumps(res, indent=2))
    print(f"Wrote {out_file}")


if __name__ == "__main__":
    main()
