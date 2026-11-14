#!/usr/bin/env python3
"""Analyze Splunk BOTS v1 .tgz directly from bucket metadata & journal.gz."""
import gzip
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from collections import Counter
from pathlib import Path


def main():
    drive_id = sys.argv[1]
    out_file = Path(sys.argv[2])
    remote = "shintiru:"

    cmd = ["rclone", "cat", f"{remote}splunk_bots_v1_data_set.tgz", "--drive-root-folder-id", drive_id]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    hosts_data = []
    sourcetypes_data = []
    sources_data = []
    sample_files = []
    journal_samples = {}
    win_hosts = Counter()
    all_hosts = Counter()
    sourcetypes = Counter()
    domains = Counter()
    dc_hits = Counter()

    # Stream tar.gz without writing 6.5GB to disk
    with tarfile.open(fileobj=p.stdout, mode="r|gz") as tf:
        for member in tf:
            if len(sample_files) < 60:
                sample_files.append(f"{member.name} ({member.size})")
            if not member.isfile():
                continue
            bname = os.path.basename(member.name)
            if bname in {"Hosts.data", "hosts.data", "SourceTypes.data", "Sources.data"}:
                f = tf.extractfile(member)
                if f:
                    txt = f.read().decode("utf-8", errors="ignore")
                    if "host" in bname.lower():
                        hosts_data.append({"path": member.name, "lines": txt.splitlines()[:50]})
                        for line in txt.splitlines():
                            parts = line.split("\t")
                            if parts and parts[0] and not parts[0].startswith("#"):
                                all_hosts[parts[0]] += 1
                    elif "sourcetype" in bname.lower():
                        sourcetypes_data.append({"path": member.name, "lines": txt.splitlines()[:50]})
                        for line in txt.splitlines():
                            parts = line.split("\t")
                            if parts and parts[0] and not parts[0].startswith("#"):
                                sourcetypes[parts[0]] += 1
                    else:
                        sources_data.append({"path": member.name, "lines": txt.splitlines()[:30]})
            elif bname == "journal.gz" and len(journal_samples) < 5:
                f = tf.extractfile(member)
                if f:
                    try:
                        with gzip.GzipFile(fileobj=f) as gz:
                            lines = []
                            for i, raw in enumerate(gz):
                                s = raw.decode("utf-8", errors="ignore").strip()
                                if i < 20:
                                    lines.append(s[:300])
                                # Look for Windows Security / DC / domain clues
                                if "4768" in s or "4769" in s or "Wayne" in s or "wayne" in s or "batman" in s or "DC" in s:
                                    if len(dc_hits) < 30:
                                        dc_hits[s[:200]] += 1
                                if i >= 5000:
                                    break
                            journal_samples[member.name] = lines
                    except Exception as e:
                        journal_samples[member.name] = [f"error: {e}"]

    p.wait()
    res = {
        "sample_files": sample_files,
        "all_hosts_from_meta": dict(all_hosts.most_common(100)),
        "sourcetypes_from_meta": dict(sourcetypes.most_common(100)),
        "hosts_data_samples": hosts_data[:5],
        "sourcetypes_data_samples": sourcetypes_data[:5],
        "sources_data_samples": sources_data[:5],
        "journal_samples": journal_samples,
        "dc_or_domain_hits": dict(dc_hits),
    }
    out_file.write_text(json.dumps(res, indent=2))
    print(f"Wrote {out_file}")


if __name__ == "__main__":
    main()
