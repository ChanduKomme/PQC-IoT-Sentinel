# Claim-to-evidence matrix

Paths beginning with a bundle root become available under `.reproduce/raw/` after extraction. Each public archive is listed in [BUNDLES.json](BUNDLES.json).

| Claim | Primary evidence | Reproduction / limitation |
|---|---|---|
| PQC delivers 32,790 sender outcomes; parsed receiver count is 32,789 | `PQC_24H_FINAL/sender/events.jsonl`, `receiver/events.jsonl` | `analysis/reproduce.py`; a one-event count difference is not proof of data loss |
| PQC successful RTT median 152 ms; P95 503 ms | `PQC_24H_FINAL/sender/serial.log`, `[BENCH]` records | Successes only; excludes preparation and key/metadata retrieval |
| DTLS delivers 42,346 with 2 failed message samples | `DTLS_24H_FINAL/sender.log` and archived `analysis/` | Independent raw parsing cross-checks the archived summary |
| DTLS successful RTT median 10 ms | `DTLS_24H_FINAL/sender.log`, `[DTLS_BENCH]` | Established session exchange; not a full-cycle key-establishment comparison |
| Delivery gaps reach 15.747 / 159.184 s | PQC host-stamped success events; DTLS timestamped success lines | Host-observed gaps; `delivery_gaps.csv`, per-minute maxima figure |
| DTLS has 29 sender and 2 receiver raw handshake-call errors | Both DTLS role logs, `ssl_handshake failed rc=` | `dtls_handshake_errors.csv`; structured handshake failures remain zero |
| Five official network windows contain 1,000 structured terminal outcomes each | Official `analysis_window/` directories, original run seals | Network seals verified by the script; excluded captures are not pooled |
| Metadata failures change completed-cycle denominators | Official sender serial logs, `ERROR: failed to get gateway metadata` | 4 at 20% and 126 at 50%; these are completed failures missing from structured telemetry |
| At 50%, key/metadata acquisition causes 288 of 387 observed failed completed cycles | 162 `pk_fetch_failed` outcomes plus 126 metadata failures; 99 `cycle_failed` outcomes | Descriptive stage attribution for the selected window; no general causal estimate |
| Retry exhaustion means 3 transmissions | Raw BENCH attempts plus `MSG_RETRY` and `SEND_FAILED`; sender retry loop | Final timeout emits `MSG_RETRY`; retry-event count + 1 overcounts exhausted attempts |
| Captures show configured forward loss / delay | Per-run `pi1/udp5683.pcap`, tcpdump rendering and qdisc state | Direct SLL2 PCAP parser cross-checks archived text; capture-wide counts |
| PQC runtime heap/stack observations cover the endurance run | PQC receiver serial `[MEM]` lines; resource screenshots | DTLS observations come from a separate short run, not an equal-duration comparison |
| Firmware source orders persistent acceptance before positive ACK | Sanitized receiver `main.cpp` and storage tests | Source and simulated-flash evidence; no physical crash-atomicity guarantee |
| Code and binary sizes differ | [Resource identities and section totals](../evidence/resources/README.md) | Historical binaries excluded for credentials; source-to-flashed-image mapping remains incomplete |
| Local host checks pass | [HOST_CHECKS.json](HOST_CHECKS.json) | RNG fixture, parser/state and storage tests; not target cryptographic validation |

Screenshots and historical narrative reports support navigation and interpretation. They do not override raw evidence or demonstrate independent replication.
