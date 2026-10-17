#!/usr/bin/env bash
set -euo pipefail
# Controlled laboratory network impairment helper using Linux tc/netem.
# Use ONLY on an isolated interface you own/control.
cmd=${1:-}; iface=${2:-}
if [[ -z "$cmd" || -z "$iface" ]]; then
  echo "Usage: sudo $0 show|clear <iface> | set <iface> [--delay-ms N] [--loss-pct P] [--duplicate-pct P] [--reorder-pct P]" >&2; exit 2
fi
shift 2 || true
case "$cmd" in
 show) tc qdisc show dev "$iface" ;;
 clear) tc qdisc del dev "$iface" root 2>/dev/null || true ;;
 set)
   delay=0; loss=0; dup=0; reorder=0
   while [[ $# -gt 0 ]]; do
     case "$1" in
       --delay-ms) delay="$2"; shift 2;;
       --loss-pct) loss="$2"; shift 2;;
       --duplicate-pct) dup="$2"; shift 2;;
       --reorder-pct) reorder="$2"; shift 2;;
       *) echo "Unknown arg: $1" >&2; exit 2;;
     esac
   done
   args=(netem)
   [[ "$delay" != 0 ]] && args+=(delay "${delay}ms")
   [[ "$loss" != 0 ]] && args+=(loss "${loss}%")
   [[ "$dup" != 0 ]] && args+=(duplicate "${dup}%")
   if [[ "$reorder" != 0 ]]; then
      [[ "$delay" != 0 ]] || { echo "reorder requires non-zero delay" >&2; exit 2; }
      args+=(reorder "${reorder}%")
   fi
   tc qdisc replace dev "$iface" root "${args[@]}"
   tc qdisc show dev "$iface"
   ;;
 *) echo "Unknown command: $cmd" >&2; exit 2;;
esac
