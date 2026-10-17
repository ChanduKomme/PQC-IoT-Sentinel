#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import signal
import ssl
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import serial


KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)=([^\s,;]+)")
STOP_ITEM = object()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}

    if not path.exists():
        return values

    for raw in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        line = raw.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")

    return values


def normalize_hec_url(url: str) -> str:
    url = url.rstrip("/")

    if url.endswith("/services/collector/event"):
        return url

    if url.endswith("/services/collector"):
        return url + "/event"

    return url + "/services/collector/event"


def parse_value(value: str) -> Any:
    value = value.strip("[](){}<>\"'")

    if re.fullmatch(r"-?\d+", value):
        return int(value)

    if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", value):
        return float(value)

    return value


def parse_fields(line: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}

    for key, value in KV_RE.findall(line):
        normalized_key = key.lower().replace("-", "_")
        fields[normalized_key] = parse_value(value)

    return fields


def classify_line(
    line: str,
) -> tuple[str | None, dict[str, Any]]:
    fields = parse_fields(line)

    # Preserve the long firmware profile string separately. The dashboard
    # profile must always remain "dtls_aes256".
    if "profile" in fields:
        fields["firmware_profile"] = fields.pop("profile")

    if "[DTLS_HANDSHAKE]" in line:
        success = int(fields.get("success", 0)) == 1

        return (
            "DTLS_HANDSHAKE_OK"
            if success
            else "DTLS_HANDSHAKE_FAIL"
        ), fields

    if "[DTLS_BENCH]" in line:
        success = int(fields.get("success", 0)) == 1

        return (
            "DTLS_MESSAGE_OK"
            if success
            else "DTLS_MESSAGE_FAIL"
        ), fields

    if "[DTLS_SUMMARY]" in line:
        return "DTLS_SUMMARY", fields

    lower = line.lower()

    if "profile=" in lower and "dtls" in lower:
        return "DTLS_PROFILE", fields

    if (
        "receiver listening" in lower
        or "waiting_for_client=1" in lower
    ):
        return "DTLS_LISTENING", fields

    if "baseline_session_complete" in lower:
        return "DTLS_SESSION_CLOSED", fields

    error_markers = (
        "handshake failed",
        "ssl error",
        "dtls error",
        "certificate parse",
        "connection reset",
        "peer unreachable",
        "send failed",
        "receive failed",
        "timeout",
    )

    if any(marker in lower for marker in error_markers):
        fields.setdefault("reason", "runtime_error")
        return "DTLS_ERROR", fields

    return None, fields


def severity_and_action(event_type: str) -> tuple[str, str]:
    if event_type in {
        "DTLS_HANDSHAKE_FAIL",
        "DTLS_MESSAGE_FAIL",
        "DTLS_ERROR",
        "DTLS_SERIAL_ERROR",
    }:
        return "high", "rejected"

    if event_type in {
        "DTLS_HANDSHAKE_OK",
        "DTLS_MESSAGE_OK",
        "DTLS_SESSION_CLOSED",
        "DTLS_RUN_COMPLETE",
    }:
        return "low", "accepted"

    return "info", "monitoring"


class HecWorker(threading.Thread):
    def __init__(
        self,
        event_queue: queue.Queue[object],
        url: str,
        token: str,
        batch_size: int,
        flush_seconds: float,
        insecure: bool,
    ) -> None:
        super().__init__(daemon=True)

        self.event_queue = event_queue
        self.url = normalize_hec_url(url)
        self.token = token
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.sent_events = 0
        self.failed_events = 0

        if self.url.startswith("https://"):
            if insecure:
                self.context = ssl._create_unverified_context()
            else:
                self.context = ssl.create_default_context()
        else:
            self.context = None

    def send_batch(
        self,
        events: list[dict[str, Any]],
    ) -> None:
        if not events:
            return

        # Splunk HEC accepts multiple event envelopes in one request.
        body = "\n".join(
            json.dumps(
                event,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            for event in events
        ).encode("utf-8")

        last_error: Exception | None = None

        for attempt in range(5):
            request = urllib.request.Request(
                self.url,
                data=body,
                method="POST",
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type": "application/json",
                },
            )

            try:
                kwargs: dict[str, Any] = {"timeout": 15}

                if self.context is not None:
                    kwargs["context"] = self.context

                with urllib.request.urlopen(
                    request,
                    **kwargs,
                ) as response:
                    response_text = response.read().decode(
                        "utf-8",
                        errors="replace",
                    )

                    result = json.loads(response_text)

                    if response.status == 200 and result.get("code") == 0:
                        self.sent_events += len(events)
                        return

                    raise RuntimeError(
                        f"HEC HTTP {response.status}: {response_text}"
                    )

            except Exception as exc:
                last_error = exc
                time.sleep(min(2 ** attempt, 10))

        self.failed_events += len(events)

        print(
            f"[HEC_ERROR] events={len(events)} error={last_error}",
            file=sys.stderr,
            flush=True,
        )

    def run(self) -> None:
        batch: list[dict[str, Any]] = []
        next_flush = time.monotonic() + self.flush_seconds

        while True:
            timeout = max(
                0.05,
                next_flush - time.monotonic(),
            )

            try:
                item = self.event_queue.get(timeout=timeout)
            except queue.Empty:
                item = None

            if item is STOP_ITEM:
                self.send_batch(batch)
                return

            if isinstance(item, dict):
                batch.append(item)

            now = time.monotonic()

            if (
                len(batch) >= self.batch_size
                or now >= next_flush
            ):
                self.send_batch(batch)
                batch.clear()
                next_flush = now + self.flush_seconds


def build_envelope(
    *,
    event_type: str,
    role: str,
    device: str,
    run_id: str,
    fields: dict[str, Any],
    raw_line: str,
    index: str,
    sourcetype: str,
) -> dict[str, Any]:
    severity, action = severity_and_action(event_type)

    event: dict[str, Any] = {
        **fields,

        # Reserved dashboard fields are written last so firmware fields
        # cannot overwrite them.
        "event_type": event_type,
        "profile": "dtls_aes256",
        "role": role,
        "device": device,
        "run_id": run_id,
        "severity": severity,
        "action": action,
        "protocol": "DTLS-1.2",
        "key_exchange": "ECDHE-P-256",
        "authentication": "ECDSA-P-256",
        "encryption": "AES-256-CCM",
        "transport": "CoAP-UDP",
        "udp_port": 5684,
        "message": raw_line[:4000],
    }

    return {
        "time": time.time(),
        "host": device,
        "source": f"bl602:dtls:{role}",
        "sourcetype": sourcetype,
        "index": index,
        "event": event,
    }


class RunClock:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.lock = threading.Lock()
        self.start_monotonic = 0.0
        self.start_utc = ""

    def mark_started(
        self,
        role: str,
        event_type: str,
    ) -> bool:
        valid_start_events = {
            "DTLS_HANDSHAKE_OK",
            "DTLS_HANDSHAKE_FAIL",
            "DTLS_MESSAGE_OK",
        }

        if role != "sender" or event_type not in valid_start_events:
            return False

        with self.lock:
            if self.started.is_set():
                return False

            self.start_monotonic = time.monotonic()
            self.start_utc = utc_now()
            self.started.set()
            return True

    def elapsed_seconds(self) -> float:
        if not self.started.is_set():
            return 0.0

        return time.monotonic() - self.start_monotonic


def serial_reader(
    *,
    role: str,
    device: str,
    port: str,
    baud: int,
    output_file: Path,
    stop_event: threading.Event,
    run_clock: RunClock,
    event_queue: queue.Queue[object],
    run_id: str,
    index: str,
    sourcetype: str,
    health_seconds: float,
    counters: dict[str, int],
) -> None:
    try:
        serial_port = serial.Serial(
            port,
            baud,
            timeout=0.5,
        )
    except Exception as exc:
        fields = {
            "reason": "serial_open_failed",
            "error": str(exc),
            "serial_port": port,
        }

        event_queue.put(
            build_envelope(
                event_type="DTLS_SERIAL_ERROR",
                role=role,
                device=device,
                run_id=run_id,
                fields=fields,
                raw_line=str(exc),
                index=index,
                sourcetype=sourcetype,
            )
        )

        print(
            f"[SERIAL_ERROR] role={role} port={port} error={exc}",
            file=sys.stderr,
            flush=True,
        )
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)

    started_local = time.monotonic()
    next_health = time.monotonic() + health_seconds

    with serial_port, output_file.open(
        "w",
        encoding="utf-8",
        buffering=1,
    ) as log:
        header = (
            f"# start_utc={utc_now()} "
            f"role={role} "
            f"device={device} "
            f"profile=dtls_aes256 "
            f"port={port} "
            f"baud={baud} "
            f"run_id={run_id}"
        )

        print(header, flush=True)
        log.write(header + "\n")

        event_queue.put(
            build_envelope(
                event_type="DTLS_BRIDGE_START",
                role=role,
                device=device,
                run_id=run_id,
                fields={"serial_port": port},
                raw_line=header,
                index=index,
                sourcetype=sourcetype,
            )
        )

        while not stop_event.is_set():
            raw = serial_port.readline()
            now = time.monotonic()

            if raw:
                text = raw.decode(
                    "utf-8",
                    errors="replace",
                ).rstrip("\r\n")

                timestamped = f"[{utc_now()}] {text}"

                print(
                    f"[{role}] {timestamped}",
                    flush=True,
                )
                log.write(timestamped + "\n")

                counters["serial_lines"] += 1

                event_type, fields = classify_line(text)

                if event_type is not None:
                    if run_clock.mark_started(
                        role,
                        event_type,
                    ):
                        print(
                            f"[RUN] ten-hour timer started at "
                            f"{run_clock.start_utc}",
                            flush=True,
                        )

                    if event_type == "DTLS_HANDSHAKE_OK":
                        counters["handshakes_success"] += 1

                    elif event_type == "DTLS_HANDSHAKE_FAIL":
                        counters["handshakes_failed"] += 1

                    elif event_type == "DTLS_MESSAGE_OK":
                        counters["messages_success"] += 1

                    elif event_type == "DTLS_MESSAGE_FAIL":
                        counters["messages_failed"] += 1

                    elif event_type == "DTLS_SUMMARY":
                        counters["session_summaries"] += 1

                    event_queue.put(
                        build_envelope(
                            event_type=event_type,
                            role=role,
                            device=device,
                            run_id=run_id,
                            fields={
                                **fields,
                                "serial_port": port,
                            },
                            raw_line=text,
                            index=index,
                            sourcetype=sourcetype,
                        )
                    )

            if run_clock.started.is_set() and now >= next_health:
                health_fields = {
                    **counters,
                    "elapsed_seconds": round(
                        run_clock.elapsed_seconds(),
                        3,
                    ),
                    "serial_port": port,
                }

                event_queue.put(
                    build_envelope(
                        event_type="DTLS_HEALTH",
                        role=role,
                        device=device,
                        run_id=run_id,
                        fields=health_fields,
                        raw_line="Periodic DTLS health event",
                        index=index,
                        sourcetype=sourcetype,
                    )
                )

                next_health = now + health_seconds

        elapsed = (
            run_clock.elapsed_seconds()
            if run_clock.started.is_set()
            else time.monotonic() - started_local
        )

        trailer = (
            f"# end_utc={utc_now()} "
            f"elapsed_seconds={elapsed:.3f} "
            f"messages_success={counters['messages_success']} "
            f"messages_failed={counters['messages_failed']} "
            f"handshakes_success={counters['handshakes_success']} "
            f"handshakes_failed={counters['handshakes_failed']} "
            f"session_summaries={counters['session_summaries']}"
        )

        print(trailer, flush=True)
        log.write(trailer + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--receiver-port",
        default="/dev/ttyUSB0",
    )
    parser.add_argument(
        "--sender-port",
        default="/dev/ttyUSB1",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=2_000_000,
    )
    parser.add_argument(
        "--duration-hours",
        type=float,
        default=10.0,
    )
    parser.add_argument(
        "--start-timeout-minutes",
        type=float,
        default=30.0,
    )
    parser.add_argument(
        "--health-seconds",
        type=float,
        default=10.0,
    )
    parser.add_argument(
        "--out-dir",
        required=True,
    )
    parser.add_argument(
        "--env-file",
        default=".env",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
    )

    args = parser.parse_args()

    env = {
        **load_env(Path(args.env_file)),
        **os.environ,
    }

    hec_url = env.get("SPLUNK_HEC_URL", "").strip()
    hec_token = env.get("SPLUNK_HEC_TOKEN", "").strip()
    index = env.get("SPLUNK_INDEX", "pqc_iot").strip()
    sourcetype = env.get(
        "SPLUNK_SOURCETYPE",
        "pqc:iot:event",
    ).strip()

    if not hec_url or not hec_token:
        print(
            "[ERROR] SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN "
            "must exist in .env.",
            file=sys.stderr,
        )
        return 2

    output_dir = Path(args.out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = env.get("DTLS_RUN_ID", "").strip() or datetime.now(timezone.utc).strftime(
        "dtls10h-%Y%m%dT%H%M%SZ"
    )

    stop_event = threading.Event()
    run_clock = RunClock()

    event_queue: queue.Queue[object] = queue.Queue(
        maxsize=50_000
    )

    hec_worker = HecWorker(
        event_queue=event_queue,
        url=hec_url,
        token=hec_token,
        batch_size=25,
        flush_seconds=0.25,
        insecure=args.insecure,
    )
    hec_worker.start()

    states = {
        "sender": {
            "messages_success": 0,
            "messages_failed": 0,
            "handshakes_success": 0,
            "handshakes_failed": 0,
            "session_summaries": 0,
            "serial_lines": 0,
        },
        "receiver": {
            "messages_success": 0,
            "messages_failed": 0,
            "handshakes_success": 0,
            "handshakes_failed": 0,
            "session_summaries": 0,
            "serial_lines": 0,
        },
    }

    def stop_handler(
        _signum: int,
        _frame: Any,
    ) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    receiver_thread = threading.Thread(
        target=serial_reader,
        kwargs={
            "role": "receiver",
            "device": "dtls-gateway-01",
            "port": args.receiver_port,
            "baud": args.baud,
            "output_file": output_dir / "receiver.log",
            "stop_event": stop_event,
            "run_clock": run_clock,
            "event_queue": event_queue,
            "run_id": run_id,
            "index": index,
            "sourcetype": sourcetype,
            "health_seconds": args.health_seconds,
            "counters": states["receiver"],
        },
        daemon=True,
    )

    sender_thread = threading.Thread(
        target=serial_reader,
        kwargs={
            "role": "sender",
            "device": "dtls-sender-01",
            "port": args.sender_port,
            "baud": args.baud,
            "output_file": output_dir / "sender.log",
            "stop_event": stop_event,
            "run_clock": run_clock,
            "event_queue": event_queue,
            "run_id": run_id,
            "index": index,
            "sourcetype": sourcetype,
            "health_seconds": args.health_seconds,
            "counters": states["sender"],
        },
        daemon=True,
    )

    receiver_thread.start()
    sender_thread.start()

    print(
        "[INFO] Both serial ports are open.",
        flush=True,
    )
    print(
        "[ACTION] Reset the receiver first.",
        flush=True,
    )
    print(
        "[ACTION] Wait for 'receiver listening udp/5684', "
        "then reset the sender.",
        flush=True,
    )
    print(
        "[INFO] The ten-hour timer starts on the first sender "
        "DTLS handshake or message event.",
        flush=True,
    )

    timeout_deadline = (
        time.monotonic()
        + args.start_timeout_minutes * 60.0
    )

    while (
        not stop_event.is_set()
        and not run_clock.started.wait(timeout=1)
    ):
        if time.monotonic() >= timeout_deadline:
            print(
                "[ERROR] No sender DTLS event was observed "
                "before the start timeout.",
                file=sys.stderr,
            )
            stop_event.set()
            break

    requested_seconds = args.duration_hours * 3600.0

    while (
        not stop_event.is_set()
        and run_clock.started.is_set()
        and run_clock.elapsed_seconds() < requested_seconds
    ):
        time.sleep(1)

    stop_event.set()

    receiver_thread.join(timeout=30)
    sender_thread.join(timeout=30)

    elapsed = run_clock.elapsed_seconds()

    for role, device in (
        ("sender", "dtls-sender-01"),
        ("receiver", "dtls-gateway-01"),
    ):
        event_queue.put(
            build_envelope(
                event_type="DTLS_RUN_COMPLETE",
                role=role,
                device=device,
                run_id=run_id,
                fields={
                    **states[role],
                    "elapsed_seconds": round(elapsed, 3),
                    "duration_hours": round(
                        elapsed / 3600.0,
                        6,
                    ),
                },
                raw_line="DTLS ten-hour run complete",
                index=index,
                sourcetype=sourcetype,
            )
        )

    time.sleep(1)
    event_queue.put(STOP_ITEM)
    hec_worker.join(timeout=120)

    summary = {
        "run_id": run_id,
        "start_utc": run_clock.start_utc,
        "elapsed_seconds": elapsed,
        "duration_hours": elapsed / 3600.0,
        "sender": states["sender"],
        "receiver": states["receiver"],
        "splunk_sent_events": hec_worker.sent_events,
        "splunk_failed_events": hec_worker.failed_events,
    }

    (output_dir / "live_run_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    print(
        json.dumps(summary, indent=2),
        flush=True,
    )

    if hec_worker.failed_events:
        return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
