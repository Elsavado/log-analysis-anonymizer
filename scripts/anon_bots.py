#!/usr/bin/env python3
"""Stream-anonymize Splunk BOTS v1 journal.gz raw logs and upload to Google Drive."""
import gzip
import os
import re
import subprocess
import sys
import tarfile

from anon_common import SHIFT_PLUS_1_YEAR, anonymize_text

WE_HOST_RE = re.compile(r"\bwe(\d{4})(srv|desk)\b", re.IGNORECASE)


def anon_bots_line(line: str) -> str:
    line = anonymize_text(line, SHIFT_PLUS_1_YEAR)
    line = WE_HOST_RE.sub(r"mh\1\2", line)
    return line


def main():
    drive_id = sys.argv[1]
    remote = "shintiru:"

    in_proc = subprocess.Popen(
        ["rclone", "cat", f"{remote}splunk_bots_v1_data_set.tgz", "--drive-root-folder-id", drive_id],
        stdout=subprocess.PIPE,
    )

    part_idx = 1
    lines_in_part = 0
    max_lines_per_part = 1_000_000
    out_proc = None
    gz_out = None

    def open_next_part():
        nonlocal part_idx, lines_in_part, out_proc, gz_out
        if gz_out is not None:
            gz_out.close()
            out_proc.stdin.close()
            rc = out_proc.wait()
            if rc != 0:
                raise RuntimeError(f"rclone rcat failed with {rc}")
        dst_name = f"env1_corp_logs_2017-08_part{part_idx:03d}.log.gz"
        print(f"Opening upload stream -> anonymized/{dst_name}", flush=True)
        out_proc = subprocess.Popen(
            ["rclone", "rcat", f"{remote}anonymized/{dst_name}", "--drive-root-folder-id", drive_id],
            stdin=subprocess.PIPE,
        )
        gz_out = gzip.GzipFile(fileobj=out_proc.stdin, mode="wb", compresslevel=6)
        part_idx += 1
        lines_in_part = 0

    open_next_part()

    with tarfile.open(fileobj=in_proc.stdout, mode="r|gz") as tf:
        for member in tf:
            if not member.isfile():
                continue
            if os.path.basename(member.name) != "journal.gz":
                continue
            f = tf.extractfile(member)
            if not f:
                continue
            try:
                with gzip.GzipFile(fileobj=f) as gz_in:
                    for raw in gz_in:
                        txt = raw.decode("utf-8", errors="ignore")
                        if not txt.strip():
                            continue
                        gz_out.write(anon_bots_line(txt).encode("utf-8"))
                        lines_in_part += 1
                        if lines_in_part >= max_lines_per_part:
                            open_next_part()
            except Exception as e:
                print(f"Warning reading {member.name}: {e}", flush=True)

    if gz_out is not None:
        gz_out.close()
        out_proc.stdin.close()
        rc = out_proc.wait()
        if rc != 0:
            raise RuntimeError(f"rclone rcat failed with {rc}")

    in_proc.wait()
    print("BOTS v1 anonymization complete.", flush=True)


if __name__ == "__main__":
    main()
