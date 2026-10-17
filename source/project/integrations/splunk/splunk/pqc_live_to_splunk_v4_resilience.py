#!/usr/bin/env python3
"""Live BL602 PQC serial capture + Splunk HEC forwarding for resilience research.

This extends the research bridge with explicit network-condition metadata and
parsing of firmware [BENCH] lines into host-derived PQC_BENCH events.  Raw
serial text and firmware [EVENT] JSON are preserved on disk.

Every forwarded event is tagged with:
  run_id, network_profile, impairment_direction, impairment_target,
  configured_delay_ms, configured_jitter_ms, configured_loss_pct.

The bridge also emits NETWORK_PROFILE_START / NETWORK_PROFILE_END markers and
periodic CAPTURE_HEALTH events.  PQC_BENCH events are host-derived from the
firmware's textual [BENCH] line and are marked origin=host_parser so they cannot
be confused with native firmware [EVENT] records.
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] if len(Path(__file__).resolve().parents) >= 4 else Path.cwd()
BENCH_RE = re.compile(r"^\[BENCH\]\s+(?P<body>.*)$")
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)=([^\s,;]+)")


@dataclass
class Counters:
    captured: int = 0
    invalid: int = 0
    queued: int = 0
    sent: int = 0
    failed: int = 0
    health_failed: int = 0
    derived_bench: int = 0


def load_project_modules(project_root: Path):
    tools = project_root / "tools"
    if str(tools) not in sys.path:
        sys.path.insert(0, str(tools))
    try:
        from evidence import parse_event  # type: ignore
        from project_config import read_env  # type: ignore
    except ImportError as exc:
        raise SystemExit(f"Cannot import project tools from {tools}: {exc}")
    return parse_event, read_env


def normalize_hec_url(url: str) -> str:
    url = url.rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("SPLUNK_HEC_URL must use http:// or https://")
    if not parsed.hostname:
        raise ValueError("SPLUNK_HEC_URL must include a hostname")
    if parsed.path.endswith("/services/collector/event"):
        return url
    return url + "/services/collector/event"


def as_number(value: str):
    v = value.strip()
    try:
        if re.fullmatch(r"[-+]?\d+", v):
            return int(v)
        if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)", v):
            return float(v)
    except ValueError:
        pass
    return v


def parse_bench_line(line: str, role: str, experiment_id: str) -> dict | None:
    m = BENCH_RE.match(line)
    if not m:
        return None
    fields = {k: as_number(v) for k, v in KV_RE.findall(m.group("body"))}
    if not fields:
        return None
    event = {
        "event_type": "PQC_BENCH",
        "origin": "host_parser",
        "role": role,
        "device_id": f"{role}-bench-parser",
        "experiment_id": experiment_id,
        "severity": "info",
        "action": "firmware_bench_parsed",
        "source_line_type": "BENCH",
    }
    event.update(fields)
    return event


def add_context(event: dict, context: dict) -> dict:
    event.update(context)
    return event


def serial_reader(
    *,
    role: str,
    port_name: str,
    baud: int,
    experiment_id: str,
    out_dir: Path,
    event_queue: "queue.Queue[tuple[str, dict] | None]",
    stop_event: threading.Event,
    parse_event,
    counters: Counters,
    context: dict,
) -> None:
    try:
        import serial  # type: ignore
    except ImportError:
        print("ERROR: pyserial is not installed; run: python3 -m pip install -r requirements-host.txt", file=sys.stderr)
        stop_event.set()
        return

    role_dir = out_dir / role
    role_dir.mkdir(parents=True, exist_ok=True)
    raw_path = role_dir / "serial.log"
    events_path = role_dir / "events.jsonl"
    derived_path = role_dir / "derived_bench.jsonl"
    capture_id = uuid.uuid4().hex
    seq = 0
    derived_seq = 0

    try:
        with (
            raw_path.open("a", buffering=1) as raw,
            events_path.open("a", buffering=1) as events,
            derived_path.open("a", buffering=1) as derived,
            serial.Serial(port_name, baudrate=baud, timeout=0.5) as port,
        ):
            print(f"[{role}] serial open: {port_name} @ {baud}", flush=True)
            while not stop_event.is_set():
                chunk = port.read_until(b"\n", size=8192)
                if not chunk:
                    continue
                line = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
                raw.write(line + "\n")

                bench = parse_bench_line(line, role, experiment_id)
                if bench is not None:
                    derived_seq += 1
                    now = time.time()
                    bench.update(
                        event_id=f"{capture_id}:bench:{derived_seq}",
                        capture_id=capture_id,
                        captured_unix=now,
                        capture_origin="serial_host_bench_parser",
                    )
                    add_context(bench, context)
                    derived.write(json.dumps(bench, separators=(",", ":")) + "\n")
                    counters.derived_bench += 1
                    event_queue.put((role, bench))
                    counters.queued += 1

                try:
                    obj = parse_event(line)
                except ValueError as exc:
                    counters.invalid += 1
                    print(f"[{role}] invalid event: {exc}", file=sys.stderr, flush=True)
                    continue
                if obj is None:
                    continue
                if obj.get("origin") != "firmware":
                    counters.invalid += 1
                    print(f"[{role}] rejected non-firmware event", file=sys.stderr, flush=True)
                    continue
                if obj.get("experiment_id") != experiment_id:
                    counters.invalid += 1
                    print(
                        f"[{role}] experiment_id mismatch: firmware={obj.get('experiment_id')!r} expected={experiment_id!r}",
                        file=sys.stderr,
                        flush=True,
                    )
                    continue

                seq += 1
                obj.update(
                    event_id=f"{capture_id}:{seq}",
                    capture_id=capture_id,
                    captured_unix=time.time(),
                    capture_origin="serial_host",
                )
                add_context(obj, context)
                events.write(json.dumps(obj, separators=(",", ":")) + "\n")
                counters.captured += 1
                event_queue.put((role, obj))
                counters.queued += 1
    except Exception as exc:
        print(f"[{role}] SERIAL ERROR: {exc}", file=sys.stderr, flush=True)
        stop_event.set()


def post_hec_event(
    *,
    endpoint: str,
    token: str,
    index: str,
    sourcetype: str,
    source: str,
    event: dict,
    ssl_context: ssl.SSLContext | None,
) -> tuple[bool, Exception | None]:
    envelope = {"index": index, "source": source, "sourcetype": sourcetype, "event": event}
    data = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Authorization": "Splunk " + token, "Content-Type": "application/json"},
        method="POST",
    )

    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            if ssl_context is None:
                response_ctx = urllib.request.urlopen(request, timeout=10)
            else:
                response_ctx = urllib.request.urlopen(request, context=ssl_context, timeout=10)
            with response_ctx as response:
                result = json.load(response)
            if result.get("code") != 0:
                raise ValueError(f"HEC rejected event: code={result.get('code')} text={result.get('text')}")
            return True, None
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(min(2 ** (attempt - 1), 4))
    return False, last_error


def hec_worker(
    *, endpoint: str, token: str, index: str, sourcetype: str,
    ssl_context: ssl.SSLContext | None,
    event_queue: "queue.Queue[tuple[str, dict] | None]", counters: Counters,
) -> None:
    while True:
        item = event_queue.get()
        if item is None:
            event_queue.task_done()
            return
        role, event = item
        sent, last_error = post_hec_event(
            endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
            source=f"pqc_resilience_serial:{role}", event=event, ssl_context=ssl_context,
        )
        if sent:
            counters.sent += 1
        else:
            counters.failed += 1
            print(f"[HEC] delivery failed after 3 attempts; event preserved on disk: {last_error}", file=sys.stderr, flush=True)
        event_queue.task_done()


def append_host_event(out_dir: Path, event: dict) -> None:
    path = out_dir / "host_events.jsonl"
    with path.open("a", buffering=1) as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")


def emit_host_event(
    *, endpoint: str, token: str, index: str, sourcetype: str,
    ssl_context: ssl.SSLContext | None, out_dir: Path, event: dict, counters: Counters,
) -> bool:
    append_host_event(out_dir, event)
    sent, last_error = post_hec_event(
        endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
        source="pqc_resilience_host", event=event, ssl_context=ssl_context,
    )
    if not sent:
        counters.health_failed += 1
        print(f"[HOST] HEC delivery failed after 3 attempts: {last_error}", file=sys.stderr, flush=True)
    return sent


def host_base(experiment_id: str, host_capture_id: str, context: dict) -> dict:
    base = {
        "origin": "host",
        "experiment_id": experiment_id,
        "role": "capture_host",
        "device_id": "host-capture",
        "captured_unix": time.time(),
        "capture_origin": "serial_host",
        "capture_id": host_capture_id,
    }
    base.update(context)
    return base


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sender-port")
    ap.add_argument("--receiver-port")
    ap.add_argument("--baud", type=int, default=921600)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--run-id", help="Unique resilience run ID; autogenerated when omitted")
    ap.add_argument("--network-profile", default="baseline", help="e.g. baseline, delay_200ms, jitter_100_30, targeted_loss_20pct")
    ap.add_argument("--configured-delay-ms", type=float, default=0.0)
    ap.add_argument("--configured-jitter-ms", type=float, default=0.0)
    ap.add_argument("--configured-loss-pct", type=float, default=0.0)
    ap.add_argument("--impairment-direction", default="none", help="e.g. sender_to_receiver")
    ap.add_argument("--impairment-target", default="none", help="e.g. udp_5683_all or protected_data_918B")
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--env-file", type=Path)
    ap.add_argument("--project-root", type=Path)
    ap.add_argument("--ca-file")
    ap.add_argument("--hec-url", help="Override SPLUNK_HEC_URL from .env")
    ap.add_argument("--health-interval", type=int, default=30)
    args = ap.parse_args()

    if not args.sender_port and not args.receiver_port:
        ap.error("provide --sender-port and/or --receiver-port")
    if args.baud <= 0:
        ap.error("--baud must be positive")
    if args.health_interval < 5:
        ap.error("--health-interval must be at least 5 seconds")
    for value, name in (
        (args.configured_delay_ms, "--configured-delay-ms"),
        (args.configured_jitter_ms, "--configured-jitter-ms"),
        (args.configured_loss_pct, "--configured-loss-pct"),
    ):
        if value < 0:
            ap.error(f"{name} cannot be negative")

    project_root = (args.project_root or ROOT).resolve()
    env_file = (args.env_file or (project_root / ".env")).resolve()
    parse_event, read_env = load_project_modules(project_root)
    cfg = read_env(env_file)

    url = (args.hec_url or cfg.get("SPLUNK_HEC_URL", "")).strip()
    token = cfg.get("SPLUNK_HEC_TOKEN", "").strip()
    if not url:
        raise SystemExit("ERROR: configure SPLUNK_HEC_URL in .env")
    if not token or token.startswith("YOUR_") or token == "REPLACE_WITH_YOUR_SPLUNK_HEC_TOKEN":
        raise SystemExit("ERROR: configure a real SPLUNK_HEC_TOKEN in .env")

    endpoint = normalize_hec_url(url)
    parsed_endpoint = urllib.parse.urlsplit(endpoint)
    ca_file = args.ca_file or cfg.get("SPLUNK_CA_FILE") or None
    ssl_context = ssl.create_default_context(cafile=ca_file) if parsed_endpoint.scheme == "https" else None
    if parsed_endpoint.scheme == "http" and parsed_endpoint.hostname not in ("localhost", "127.0.0.1", "::1"):
        print("WARNING: HEC uses plaintext HTTP to a non-loopback host; prefer HTTPS.", file=sys.stderr, flush=True)

    index = cfg.get("SPLUNK_INDEX", "pqc_iot")
    sourcetype = cfg.get("SPLUNK_SOURCETYPE", "pqc:iot:event")
    run_id = args.run_id or f"{args.network_profile}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    context = {
        "run_id": run_id,
        "network_profile": args.network_profile,
        "configured_delay_ms": args.configured_delay_ms,
        "configured_jitter_ms": args.configured_jitter_ms,
        "configured_loss_pct": args.configured_loss_pct,
        "impairment_direction": args.impairment_direction,
        "impairment_target": args.impairment_target,
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "run_context.json").write_text(json.dumps({
        "experiment_id": args.experiment_id,
        **context,
        "baud": args.baud,
        "sender_port": args.sender_port,
        "receiver_port": args.receiver_port,
        "started_utc": datetime.now(timezone.utc).isoformat(),
    }, indent=2) + "\n")

    event_queue: "queue.Queue[tuple[str, dict] | None]" = queue.Queue()
    stop_event = threading.Event()
    counters = Counters()
    started_unix = time.time()
    host_capture_id = uuid.uuid4().hex
    health_seq = 0

    hec = threading.Thread(target=hec_worker, kwargs=dict(
        endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
        ssl_context=ssl_context, event_queue=event_queue, counters=counters,
    ), name="hec-worker", daemon=True)
    hec.start()

    start_event = host_base(args.experiment_id, host_capture_id, context)
    start_event.update(event_type="NETWORK_PROFILE_START", severity="info", action="network_profile_start",
                       event_id=f"{host_capture_id}:profile:start")
    emit_host_event(endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
                    ssl_context=ssl_context, out_dir=args.out_dir, event=start_event, counters=counters)

    readers: list[threading.Thread] = []
    for role, port_name in (("sender", args.sender_port), ("receiver", args.receiver_port)):
        if not port_name:
            continue
        t = threading.Thread(target=serial_reader, kwargs=dict(
            role=role, port_name=port_name, baud=args.baud, experiment_id=args.experiment_id,
            out_dir=args.out_dir, event_queue=event_queue, stop_event=stop_event,
            parse_event=parse_event, counters=counters, context=context,
        ), name=f"serial-{role}", daemon=True)
        t.start()
        readers.append(t)

    print(f"[LIVE] experiment={args.experiment_id} run_id={run_id} profile={args.network_profile}")
    print(f"[LIVE] HEC={endpoint} index={index}")
    print("[LIVE] Ctrl+C stops capture. Evidence directory:", args.out_dir)

    next_health = time.monotonic()
    try:
        while not stop_event.is_set():
            time.sleep(5)
            print(
                f"[STATS] firmware={counters.captured} bench={counters.derived_bench} queued={counters.queued} "
                f"sent={counters.sent} failed={counters.failed} invalid={counters.invalid}", flush=True,
            )
            if time.monotonic() >= next_health:
                health_seq += 1
                event = host_base(args.experiment_id, host_capture_id, context)
                severity = "high" if counters.failed else ("medium" if counters.invalid else "info")
                event.update(
                    event_type="CAPTURE_HEALTH", severity=severity, action="capture_health",
                    captured=counters.captured, derived_bench=counters.derived_bench,
                    queued=counters.queued, splunk_sent=counters.sent, splunk_failed=counters.failed,
                    invalid_or_mismatched=counters.invalid,
                    capture_uptime_seconds=round(time.time() - started_unix, 3),
                    event_id=f"{host_capture_id}:health:{health_seq}",
                )
                emit_host_event(endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
                                ssl_context=ssl_context, out_dir=args.out_dir, event=event, counters=counters)
                next_health = time.monotonic() + args.health_interval
    except KeyboardInterrupt:
        print("\n[LIVE] stopping...", flush=True)
        stop_event.set()

    for t in readers:
        t.join(timeout=2)
    event_queue.put(None)
    hec.join(timeout=30)

    end_event = host_base(args.experiment_id, host_capture_id, context)
    end_event.update(
        event_type="NETWORK_PROFILE_END", severity="info", action="network_profile_end",
        capture_uptime_seconds=round(time.time() - started_unix, 3),
        captured=counters.captured, derived_bench=counters.derived_bench,
        splunk_sent=counters.sent, splunk_failed=counters.failed,
        invalid_or_mismatched=counters.invalid,
        event_id=f"{host_capture_id}:profile:end",
    )
    emit_host_event(endpoint=endpoint, token=token, index=index, sourcetype=sourcetype,
                    ssl_context=ssl_context, out_dir=args.out_dir, event=end_event, counters=counters)

    summary = {
        "experiment_id": args.experiment_id,
        **context,
        "captured_firmware_events": counters.captured,
        "derived_bench_events": counters.derived_bench,
        "queued": counters.queued,
        "splunk_sent": counters.sent,
        "splunk_failed": counters.failed,
        "invalid_or_mismatched": counters.invalid,
        "host_event_hec_failed": counters.health_failed,
        "host_capture_id": host_capture_id,
        "capture_uptime_seconds": round(time.time() - started_unix, 3),
        "ended_utc": datetime.now(timezone.utc).isoformat(),
    }
    (args.out_dir / "live_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if counters.failed == 0 and counters.invalid == 0 and counters.health_failed == 0 and (counters.captured + counters.derived_bench) > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
