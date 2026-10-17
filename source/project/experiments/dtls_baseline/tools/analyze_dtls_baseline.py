#!/usr/bin/env python3
"""Parse BL602 DTLS baseline logs and write reproducible CSV/JSON summaries."""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path
from typing import Iterable

LINE_RE = re.compile(r"\[(DTLS_SESSION|DTLS_HANDSHAKE|DTLS_BENCH|DTLS_SUMMARY)\]\s+(.*)")
KV_RE = re.compile(r"([A-Za-z0-9_]+)=([^=\s]*?)(?=(?:[A-Za-z0-9_]+=)|\s|$)")


def parse_value(value: str):
    for cast in (int, float):
        try:
            return cast(value)
        except ValueError:
            pass
    return value


def parse_log(path: Path) -> list[dict]:
    rows: list[dict] = []
    session=0
    for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        match = LINE_RE.search(line)
        if not match:
            continue
        kind, body = match.groups()
        row = {"kind": kind, "source_file": path.name, "line_no": line_no}
        row.update({k: parse_value(v) for k, v in KV_RE.findall(body) if v != ""})
        if kind=="DTLS_SESSION":session=int(row.get("session",session+1))
        elif kind=="DTLS_HANDSHAKE" and row.get("role")=="receiver":session+=1
        row["session_local"]=session
        rows.append(row)
    return rows


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * pct
    lo = math.floor(index)
    hi = math.ceil(index)
    if lo == hi:
        return ordered[lo]
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (index - lo)


def metric(rows: Iterable[dict], field: str) -> dict:
    values = [float(row[field]) for row in rows if isinstance(row.get(field), (int, float))]
    if not values:
        return {"count": 0, "mean": None, "median": None, "stdev": None,
                "min": None, "max": None, "p95": None}
    return {
        "count": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
        "p95": percentile(values, 0.95),
    }


def build_summary(rows: list[dict]) -> dict:
    sender_bench = [r for r in rows if r.get("kind") == "DTLS_BENCH" and r.get("role") == "sender"]
    receiver_bench = [r for r in rows if r.get("kind") == "DTLS_BENCH" and r.get("role") == "receiver"]
    handshakes = [r for r in rows if r.get("kind") == "DTLS_HANDSHAKE"]
    sender_success = sum(int(r.get("success", 0)) for r in sender_bench)
    receiver_success = sum(int(r.get("success", 0)) for r in receiver_bench)
    return {
        "profile": "DTLS-1.2/ECDHE-P-256/ECDSA/AES-256-CCM",
        "sender_samples": len(sender_bench),
        "sender_success": sender_success,
        "sender_failed": len(sender_bench) - sender_success,
        "receiver_samples": len(receiver_bench),
        "receiver_success": receiver_success,
        "receiver_failed": len(receiver_bench) - receiver_success,
        "sender_handshake_ms": metric([r for r in handshakes if r.get("role")=="sender"], "handshake_ms"),
        "receiver_handshake_ms": metric([r for r in handshakes if r.get("role")=="receiver"], "handshake_ms"),
        "scope": "RTT uses successful sender records only; receiver_process excludes DTLS read/decrypt. Session IDs are local to each log.",
        "rtt_ms": metric([r for r in sender_bench if r.get("success")==1], "rtt_ms"),
        "receiver_process_ms": metric([r for r in receiver_bench if r.get("success")==1], "process_ms"),
        "coap_len": metric(sender_bench, "coap_len"),
        "estimated_dtls_record_len": metric(sender_bench, "estimated_dtls_record_len"),
    }


def write_raw_csv(path: Path, rows: list[dict]) -> None:
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_summary_csv(path: Path, summary: dict) -> None:
    flat: list[dict] = []
    for key, value in summary.items():
        if isinstance(value, dict):
            for statistic, number in value.items():
                flat.append({"metric": key, "statistic": statistic, "value": number})
        else:
            flat.append({"metric": key, "statistic": "value", "value": value})
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "statistic", "value"])
        writer.writeheader()
        writer.writerows(flat)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender-log", type=Path, required=True)
    parser.add_argument("--receiver-log", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("results"))
    parser.add_argument("--warmup", type=int, default=0, help="Exclude the first N run numbers of every session")
    args = parser.parse_args()
    if args.warmup<0:parser.error("warmup must be nonnegative")

    rows = parse_log(args.sender_log)
    if args.receiver_log:
        rows.extend(parse_log(args.receiver_log))
    if not rows:
        raise SystemExit("No [DTLS_*] benchmark records were found in the supplied logs.")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    selected=[r for r in rows if r.get("kind")!="DTLS_BENCH" or r.get("run",0)>args.warmup]
    summary = build_summary(selected)
    summary["excluded_warmup_runs_per_session"]=args.warmup
    write_raw_csv(args.out_dir / "dtls_baseline_samples.csv", rows)
    write_summary_csv(args.out_dir / "dtls_baseline_summary.csv", summary)
    (args.out_dir / "dtls_baseline_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
