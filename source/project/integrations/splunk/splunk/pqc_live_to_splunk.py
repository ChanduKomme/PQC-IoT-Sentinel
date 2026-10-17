#!/usr/bin/env python3
"""Live BL602 PQC serial capture + Splunk HEC forwarding.

Reads one or two serial ports, preserves raw serial and exact firmware [EVENT]
records on disk, adds host capture metadata/event_id, and forwards only valid
firmware-origin events with the requested experiment_id to Splunk HEC.

For research runs it also emits a periodic host-origin CAPTURE_HEALTH event so
Splunk can display serial-validation and HEC-delivery health. Firmware events
remain separately identifiable with origin=firmware.

If HEC delivery fails, the firmware event is still preserved in events.jsonl so
the project's existing serial_to_hec.py can upload it later.
"""

from __future__ import annotations

import argparse
import json
import queue
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] if len(Path(__file__).resolve().parents) >= 4 else Path.cwd()
# When copied to integrations/splunk/splunk/, ROOT resolves to the project root.
# When run elsewhere, use --project-root.


@dataclass
class Counters:
    captured: int = 0
    invalid: int = 0
    queued: int = 0
    sent: int = 0
    failed: int = 0
    health_failed: int = 0


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
    capture_id = uuid.uuid4().hex
    seq = 0

    try:
        with raw_path.open("a", buffering=1) as raw, events_path.open("a", buffering=1) as events, serial.Serial(
            port_name, baudrate=baud, timeout=0.5
        ) as port:
            print(f"[{role}] serial open: {port_name} @ {baud}", flush=True)
            while not stop_event.is_set():
                chunk = port.read_until(b"\n", size=8192)
                if not chunk:
                    continue
                line = chunk.decode("utf-8", errors="replace").rstrip("\r\n")
                raw.write(line + "\n")

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
    envelope = {
        "index": index,
        "source": source,
        "sourcetype": sourcetype,
        "event": event,
    }
    data = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Authorization": "Splunk " + token,
            "Content-Type": "application/json",
        },
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
                raise ValueError(
                    f"HEC rejected event: code={result.get('code')} text={result.get('text')}"
                )
            return True, None
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
            time.sleep(min(2 ** (attempt - 1), 4))
    return False, last_error


def hec_worker(
    *,
    endpoint: str,
    token: str,
    index: str,
    sourcetype: str,
    ssl_context: ssl.SSLContext | None,
    event_queue: "queue.Queue[tuple[str, dict] | None]",
    counters: Counters,
) -> None:
    while True:
        item = event_queue.get()
        if item is None:
            event_queue.task_done()
            return
        role, event = item
        sent, last_error = post_hec_event(
            endpoint=endpoint,
            token=token,
            index=index,
            sourcetype=sourcetype,
            source=f"pqc_live_serial:{role}",
            event=event,
            ssl_context=ssl_context,
        )
        if sent:
            counters.sent += 1
        else:
            counters.failed += 1
            print(
                f"[HEC] delivery failed after 3 attempts; event preserved on disk: {last_error}",
                file=sys.stderr,
                flush=True,
            )
        event_queue.task_done()


def emit_capture_health(
    *,
    endpoint: str,
    token: str,
    index: str,
    sourcetype: str,
    ssl_context: ssl.SSLContext | None,
    experiment_id: str,
    out_dir: Path,
    counters: Counters,
    host_capture_id: str,
    health_seq: int,
    started_unix: float,
) -> int:
    now = time.time()
    health_seq += 1
    severity = "info"
    if counters.failed > 0:
        severity = "high"
    elif counters.invalid > 0:
        severity = "medium"

    event = {
        "event_type": "CAPTURE_HEALTH",
        "origin": "host",
        "experiment_id": experiment_id,
        "role": "capture_host",
        "device_id": "host-capture",
        "severity": severity,
        "action": "capture_health",
        "captured": counters.captured,
        "queued": counters.queued,
        "splunk_sent": counters.sent,
        "splunk_failed": counters.failed,
        "invalid_or_mismatched": counters.invalid,
        "capture_uptime_seconds": round(now - started_unix, 3),
        "captured_unix": now,
        "capture_origin": "serial_host",
        "capture_id": host_capture_id,
        "event_id": f"{host_capture_id}:health:{health_seq}",
    }

    health_path = out_dir / "capture_health.jsonl"
    with health_path.open("a", buffering=1) as fh:
        fh.write(json.dumps(event, separators=(",", ":")) + "\n")

    sent, last_error = post_hec_event(
        endpoint=endpoint,
        token=token,
        index=index,
        sourcetype=sourcetype,
        source="pqc_live_host:capture",
        event=event,
        ssl_context=ssl_context,
    )
    if not sent:
        counters.health_failed += 1
        print(
            f"[HEALTH] CAPTURE_HEALTH HEC delivery failed after 3 attempts: {last_error}",
            file=sys.stderr,
            flush=True,
        )
    return health_seq


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sender-port")
    ap.add_argument("--receiver-port")
    ap.add_argument("--baud", type=int, default=2_000_000)
    ap.add_argument("--experiment-id", required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--env-file", type=Path)
    ap.add_argument("--project-root", type=Path)
    ap.add_argument("--ca-file")
    ap.add_argument("--hec-url", help="Override SPLUNK_HEC_URL from .env")
    ap.add_argument("--health-interval", type=int, default=30, help="Seconds between CAPTURE_HEALTH events (default: 30)")
    args = ap.parse_args()

    if not args.sender_port and not args.receiver_port:
        ap.error("provide --sender-port and/or --receiver-port")
    if args.baud <= 0:
        ap.error("--baud must be positive")
    if args.health_interval < 5:
        ap.error("--health-interval must be at least 5 seconds")

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
    if parsed_endpoint.scheme == "http":
        if parsed_endpoint.hostname not in ("localhost", "127.0.0.1", "::1"):
            print(
                "WARNING: HEC is using plaintext HTTP to a non-loopback host. "
                "Use HTTPS for remote Splunk.",
                file=sys.stderr,
                flush=True,
            )
        else:
            print("[LIVE] Local Splunk HEC is using HTTP on loopback (no TLS).", flush=True)
    index = cfg.get("SPLUNK_INDEX", "pqc_iot")
    sourcetype = cfg.get("SPLUNK_SOURCETYPE", "pqc:iot:event")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    event_queue: "queue.Queue[tuple[str, dict] | None]" = queue.Queue()
    stop_event = threading.Event()
    counters = Counters()
    started_unix = time.time()
    host_capture_id = uuid.uuid4().hex
    health_seq = 0

    hec = threading.Thread(
        target=hec_worker,
        kwargs=dict(
            endpoint=endpoint,
            token=token,
            index=index,
            sourcetype=sourcetype,
            ssl_context=ssl_context,
            event_queue=event_queue,
            counters=counters,
        ),
        name="hec-worker",
        daemon=True,
    )
    hec.start()

    readers: list[threading.Thread] = []
    for role, port_name in (("sender", args.sender_port), ("receiver", args.receiver_port)):
        if not port_name:
            continue
        t = threading.Thread(
            target=serial_reader,
            kwargs=dict(
                role=role,
                port_name=port_name,
                baud=args.baud,
                experiment_id=args.experiment_id,
                out_dir=args.out_dir,
                event_queue=event_queue,
                stop_event=stop_event,
                parse_event=parse_event,
                counters=counters,
            ),
            name=f"serial-{role}",
            daemon=True,
        )
        t.start()
        readers.append(t)

    print(f"[LIVE] experiment={args.experiment_id} HEC={endpoint} index={index}")
    print("[LIVE] Ctrl+C stops capture. Raw serial/events are preserved under:", args.out_dir)

    next_health = time.monotonic()
    try:
        while not stop_event.is_set():
            time.sleep(5)
            print(
                f"[STATS] captured={counters.captured} queued={counters.queued} "
                f"sent={counters.sent} failed={counters.failed} invalid={counters.invalid}",
                flush=True,
            )
            if time.monotonic() >= next_health:
                health_seq = emit_capture_health(
                    endpoint=endpoint,
                    token=token,
                    index=index,
                    sourcetype=sourcetype,
                    ssl_context=ssl_context,
                    experiment_id=args.experiment_id,
                    out_dir=args.out_dir,
                    counters=counters,
                    host_capture_id=host_capture_id,
                    health_seq=health_seq,
                    started_unix=started_unix,
                )
                next_health = time.monotonic() + args.health_interval
    except KeyboardInterrupt:
        print("\n[LIVE] stopping...", flush=True)
        stop_event.set()

    for t in readers:
        t.join(timeout=2)

    event_queue.put(None)
    hec.join(timeout=30)

    health_seq = emit_capture_health(
        endpoint=endpoint,
        token=token,
        index=index,
        sourcetype=sourcetype,
        ssl_context=ssl_context,
        experiment_id=args.experiment_id,
        out_dir=args.out_dir,
        counters=counters,
        host_capture_id=host_capture_id,
        health_seq=health_seq,
        started_unix=started_unix,
    )

    summary = {
        "experiment_id": args.experiment_id,
        "captured": counters.captured,
        "queued": counters.queued,
        "splunk_sent": counters.sent,
        "splunk_failed": counters.failed,
        "invalid_or_mismatched": counters.invalid,
        "capture_health_hec_failed": counters.health_failed,
        "host_capture_id": host_capture_id,
        "capture_uptime_seconds": round(time.time() - started_unix, 3),
    }
    (args.out_dir / "live_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if counters.failed == 0 and counters.invalid == 0 and counters.health_failed == 0 and counters.captured > 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
