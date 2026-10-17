#!/usr/bin/env python3
"""Detect the BL602 receiver IPv4 address from USB serial output.

The receiver firmware prints a line similar to:
    [wifi] IP  : 192.168.1.75

By default this helper updates both values used by the project:
    PQC_RECEIVER_IP=<detected address>
    DTLS_SERVER_HOST=<detected address>

It preserves all other .env entries and sets the file mode to 0600 when
possible. Use --quiet when invoking it from another script; only the detected
IPv4 address is then written to stdout.
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV = ROOT / ".env"
IP_RE = re.compile(r"(?:\[wifi\]\s*)?IP\s*:?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.I)


def log(message: str, quiet: bool) -> None:
    print(message, file=sys.stderr if quiet else sys.stdout)


def ensure_pyserial() -> None:
    if importlib.util.find_spec("serial") is None:
        raise RuntimeError("pyserial is not installed; run: python3 -m pip install pyserial")


def parse_ipv4(line: str) -> str | None:
    match = IP_RE.search(line)
    if not match:
        return None
    try:
        address = ipaddress.ip_address(match.group(1))
    except ValueError:
        return None
    if (
        address.version != 4
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
    ):
        return None
    return str(address)


def detect_ip(port: str, baud: int, timeout: int, echo: bool, quiet: bool) -> str:
    ensure_pyserial()
    import serial  # type: ignore

    log(f"[INFO] Listening for receiver IP on {port} @ {baud} baud", quiet)
    log("[INFO] Reset the receiver now so it prints its Wi-Fi address.", quiet)
    deadline = time.time() + timeout

    with serial.Serial(port, baudrate=baud, timeout=0.5) as serial_port:
        while time.time() < deadline:
            raw = serial_port.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            if echo:
                log(f"[SERIAL] {line}", quiet)
            detected = parse_ipv4(line)
            if detected:
                return detected

    raise TimeoutError(f"Timed out after {timeout}s waiting for the receiver IP on {port}")


def set_env_values(env_file: Path, values: dict[str, str]) -> None:
    env_file.parent.mkdir(parents=True, exist_ok=True)
    existing = env_file.read_text(encoding="utf-8").splitlines() if env_file.exists() else []
    pending = dict(values)
    output: list[str] = []

    assignment = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
    for line in existing:
        match = assignment.match(line)
        if match and match.group(1) in pending:
            key = match.group(1)
            output.append(f"{key}={pending.pop(key)}")
        else:
            output.append(line)

    if pending:
        if output and output[-1].strip():
            output.append("")
        output.append("# Automatically detected receiver address")
        output.extend(f"{key}={value}" for key, value in pending.items())

    env_file.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    try:
        os.chmod(env_file, 0o600)
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect receiver IP from serial and update .env")
    parser.add_argument("--port", default=os.getenv("DTLS_RECEIVER_PORT", "/dev/ttyUSB0"))
    parser.add_argument("--baud", type=int, default=int(os.getenv("SERIAL_BAUDRATE", "2000000")))
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV)
    parser.add_argument("--echo", action="store_true")
    parser.add_argument("--no-write", action="store_true", help="Detect only; do not modify .env")
    parser.add_argument("--quiet", action="store_true", help="Print only the IP to stdout; diagnostics go to stderr")
    args = parser.parse_args()

    try:
        detected_ip = detect_ip(args.port, args.baud, args.timeout, args.echo, args.quiet)
        if not args.no_write:
            set_env_values(
                args.env_file,
                {
                    "PQC_RECEIVER_IP": detected_ip,
                    "DTLS_SERVER_HOST": detected_ip,
                },
            )
            log(f"[OK] Updated {args.env_file}", args.quiet)
        log(f"[OK] Receiver IP: {detected_ip}", args.quiet)
        print(detected_ip)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
