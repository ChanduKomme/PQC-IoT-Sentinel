#!/usr/bin/env bash
set -euo pipefail
iface=${1:?interface required}
out=${2:?output pcap required}
mkdir -p "$(dirname "$out")"
echo "Capturing $iface -> $out. Ctrl-C to stop."
exec tcpdump -i "$iface" -s 0 -U -w "$out"
