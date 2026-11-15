#!/usr/bin/env python3
"""Stream-anonymize LANL cyber1 files and upload renamed files to Google Drive."""
import gzip
import os
import subprocess
import sys

from anon_common import anonymize_text

TIME_OFFSET = 86400  # uniform +1 day shift on relative epoch seconds


def stream_one(src_name: str, dst_name: str, drive_id: str, remote: str = "shintiru:"):
    print(f"Streaming {src_name} -> anonymized/{dst_name}", flush=True)
    in_proc = subprocess.Popen(
        ["rclone", "cat", f"{remote}{src_name}", "--drive-root-folder-id", drive_id],
        stdout=subprocess.PIPE,
    )
    out_proc = subprocess.Popen(
        [
            "rclone", "rcat", f"{remote}anonymized/{dst_name}",
            "--drive-root-folder-id", drive_id,
            "--drive-chunk-size", "64M",
        ],
        stdin=subprocess.PIPE,
    )

    # Fast-path for billion-line LANL files: only invoke full regexes if email/lanl/alnl appears
    with gzip.GzipFile(fileobj=in_proc.stdout, mode="rb") as gz_in, \
         gzip.GzipFile(fileobj=out_proc.stdin, mode="wb", compresslevel=3) as gz_out:
        for raw in gz_in:
            line = raw.decode("utf-8", errors="ignore")
            comma = line.find(",")
            if comma > 0 and line[:comma].isdigit():
                t_shifted = int(line[:comma]) + TIME_OFFSET
                rest = line[comma + 1:]
                low = rest.lower()
                if "lanl" in low or "alnl" in low or ("@" in rest and "." in rest[rest.find("@"):]):
                    rest = anonymize_text(rest, date_delta=None)
                else:
                    rest = rest.replace("DOM1", "CORP1")
                out_line = f"{t_shifted},{rest}"
            else:
                out_line = anonymize_text(line, date_delta=None)
            gz_out.write(out_line.encode("utf-8"))

    out_proc.stdin.close()
    rc_in = in_proc.wait()
    rc_out = out_proc.wait()
    if rc_in != 0 or rc_out != 0:
        raise RuntimeError(f"rclone failed for {src_name}: in={rc_in}, out={rc_out}")
    print(f"Finished {dst_name}", flush=True)


def main():
    drive_id = sys.argv[1]
    kind = sys.argv[2]  # redteam | dns | flows | proc | auth
    mapping = {
        "redteam": ("lanl_cyber1_redteam.txt.gz", "env5_events_red.txt.gz"),
        "dns": ("lanl_cyber1_dns.txt.gz", "env5_dns.txt.gz"),
        "flows": ("lanl_cyber1_flows.txt.gz", "env5_flows.txt.gz"),
        "proc": ("lanl_cyber1_proc.txt.gz", "env5_proc.txt.gz"),
        "auth": ("lanl_cyber1_auth.txt.gz", "env5_auth.txt.gz"),
    }
    src, dst = mapping[kind]
    stream_one(src, dst, drive_id)


if __name__ == "__main__":
    main()
