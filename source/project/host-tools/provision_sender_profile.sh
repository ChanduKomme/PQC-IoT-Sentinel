#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 2 ]] || { echo "Usage: $0 <fingerprint> <IPv4> [sender-id] [--allow-discovery]" >&2; exit 2; }
fp="$1"; ip="$2"; shift 2
args=()
for arg in "$@"; do
  case "$arg" in
    --allow-discovery) args+=("$arg");;
    0x*|[0-9]*) args+=(--sender-id "$arg");;
    *) echo "Unknown argument: $arg" >&2; exit 2;;
  esac
done
exec python3 "$(dirname "$0")/provision_fingerprint.py" --fingerprint-hex "$fp" --gateway-ip "$ip" "${args[@]}"
