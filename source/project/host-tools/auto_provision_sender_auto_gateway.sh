#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 1 ]] || { echo "Usage: $0 <receiver-port> [sender-id] [options]" >&2; exit 2; }
port="$1"; shift
args=()
if [[ $# -gt 0 && "$1" != --* ]]; then args+=(--sender-id "$1"); shift; fi
exec python3 "$(dirname "$0")/auto_provision_from_receiver_serial.py" --receiver-port "$port" --ip-mode discovery "${args[@]}" "$@"
