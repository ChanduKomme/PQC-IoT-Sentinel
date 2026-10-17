# PQC IoT Sentinel — Network Resilience Evidence + Splunk Workflow

This toolkit turns the Pi 1 routed topology into paper-grade evidence. It keeps
raw serial logs and packet captures, adds explicit network-condition metadata to
Splunk, parses firmware `[BENCH]` lines into structured `PQC_BENCH` events, and
builds a frozen SHA-256 evidence archive after the runs.

## Files

- `pqc_live_to_splunk_v4_resilience.py` — laptop serial/Splunk capture bridge.
- `PQC_IoT_SENTINEL_Splunk_Dashboard_v6_resilience.xml` — v5 dashboard plus a dedicated Network Resilience section.
- `pqc_pi1_resilience_capture.sh` — Pi 1 network-state + UDP/5683 PCAP capture.
- `archive_pqc_network_resilience.sh` — final laptop evidence archive/tarball/manifest.

## Important capture rule

Close `miniterm` before starting the v4 bridge. Only one process can own each
BL602 serial port. The bridge should own `/dev/ttyUSB0` (sender) and
`/dev/ttyUSB2` (receiver) during publication-quality reruns.

## Install on the laptop

From the project root:

```bash
cd ~/sdk/bl602_iot_sdk/PQC_IoT_SENTINEL_UPDATED
mkdir -p integrations/splunk/splunk splunk tools/network_resilience
cp /path/to/pqc_live_to_splunk_v4_resilience.py integrations/splunk/splunk/
cp /path/to/PQC_IoT_SENTINEL_Splunk_Dashboard_v6_resilience.xml splunk/
cp /path/to/archive_pqc_network_resilience.sh tools/network_resilience/
chmod +x integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py
chmod +x tools/network_resilience/archive_pqc_network_resilience.sh
```

Copy `pqc_pi1_resilience_capture.sh` to Pi 1 and make it executable.

## Recommended short standardized rerun matrix

Do not rely only on screenshots from the exploratory tests. Re-run each profile
for 60–120 seconds with the v4 bridge so the paper result has raw serial logs,
structured Splunk events and profile markers.

### Baseline

Pi 1 should have clean `fq_codel` on `wlan0`, no temporary FORWARD drop rule.
On the laptop:

```bash
cd ~/sdk/bl602_iot_sdk/PQC_IoT_SENTINEL_UPDATED
pyenv activate bl_venv
RUN="baseline_$(date -u +%Y%m%dT%H%M%SZ)"
python3 integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
  --sender-port /dev/ttyUSB0 \
  --receiver-port /dev/ttyUSB2 \
  --baud 921600 \
  --experiment-id pqc-experiment \
  --run-id "$RUN" \
  --network-profile baseline \
  --impairment-direction none \
  --impairment-target none \
  --out-dir "results/network_resilience/$RUN" \
  --env-file .env
```

Stop with `Ctrl+C` after the chosen interval.

### Delay: 200 ms sender → receiver

Apply the already validated `wlan0` selective UDP/5683 netem profile on Pi 1,
then capture with:

```bash
RUN="delay_200ms_$(date -u +%Y%m%dT%H%M%SZ)"
python3 integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
  --sender-port /dev/ttyUSB0 --receiver-port /dev/ttyUSB2 --baud 921600 \
  --experiment-id pqc-experiment --run-id "$RUN" \
  --network-profile delay_200ms \
  --configured-delay-ms 200 \
  --impairment-direction sender_to_receiver \
  --impairment-target udp_5683_all \
  --out-dir "results/network_resilience/$RUN" --env-file .env
```

### Jitter: 100 ms ± 30 ms sender → receiver

```bash
RUN="jitter_100_30_$(date -u +%Y%m%dT%H%M%SZ)"
python3 integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
  --sender-port /dev/ttyUSB0 --receiver-port /dev/ttyUSB2 --baud 921600 \
  --experiment-id pqc-experiment --run-id "$RUN" \
  --network-profile jitter_100_30 \
  --configured-delay-ms 100 --configured-jitter-ms 30 \
  --impairment-direction sender_to_receiver \
  --impairment-target udp_5683_all \
  --out-dir "results/network_resilience/$RUN" --env-file .env
```

### Targeted protected-data loss

For the validated 918-byte IPv4 / 890-byte UDP protected data packet profile,
use a profile name that records the exact condition, for example:

```bash
RUN="targeted_loss_20pct_$(date -u +%Y%m%dT%H%M%SZ)"
python3 integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
  --sender-port /dev/ttyUSB0 --receiver-port /dev/ttyUSB2 --baud 921600 \
  --experiment-id pqc-experiment --run-id "$RUN" \
  --network-profile targeted_loss_20pct \
  --configured-loss-pct 20 \
  --impairment-direction sender_to_receiver \
  --impairment-target protected_data_918B \
  --out-dir "results/network_resilience/$RUN" --env-file .env
```

### Deterministic alternate protected-data drop

Use the previously validated iptables `nth every 2` rule on Pi 1. The run label
explicitly distinguishes deterministic loss from random netem loss:

```bash
RUN="deterministic_alt_data_drop_$(date -u +%Y%m%dT%H%M%SZ)"
python3 integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
  --sender-port /dev/ttyUSB0 --receiver-port /dev/ttyUSB2 --baud 921600 \
  --experiment-id pqc-experiment --run-id "$RUN" \
  --network-profile deterministic_alt_data_drop \
  --configured-loss-pct 50 \
  --impairment-direction sender_to_receiver \
  --impairment-target protected_data_918B_nth2 \
  --out-dir "results/network_resilience/$RUN" --env-file .env
```

This profile is the cleanest place to demonstrate `MSG_RETRY` followed by a
`PQC_BENCH` record with `attempts=2 ok=1`, while separate retry-exhaustion runs
show `SEND_FAILED` and fail-closed behavior.

## Pi 1 evidence capture

While a profile is running, use:

```bash
./pqc_pi1_resilience_capture.sh PROFILE_NAME 60
```

It saves pre/post `tc` and `iptables` state plus a full UDP/5683 PCAP and text
rendering under `~/pqc_resilience_evidence/`.

## Splunk dashboard

Import or paste the source from
`PQC_IoT_SENTINEL_Splunk_Dashboard_v6_resilience.xml` into a Classic/Simple XML
dashboard. Set:

- Experiment ID: `pqc-experiment`
- Network Profile: `*` for all or a specific profile
- Resilience Run ID: `*` for all or a specific run

The Network Resilience section includes:

- successful retry recoveries (`attempts>1, ok=1`)
- retry events and terminal `SEND_FAILED` events
- profile-level delivery/retry/failure/RTT summary
- RTT-over-time by profile
- attempts distribution
- retry-recovery evidence table
- start/end profile markers with configured impairment parameters

`PQC_BENCH` is deliberately marked `origin=host_parser`; it is derived from the
firmware's textual `[BENCH]` line and is not presented as a native firmware JSON
event.

## Final archive

Copy the Pi 1 evidence directory back to the laptop, for example into
`results/pi1_resilience_evidence/`, then run:

```bash
cd ~/sdk/bl602_iot_sdk/PQC_IoT_SENTINEL_UPDATED
bash tools/network_resilience/archive_pqc_network_resilience.sh \
  "$PWD" \
  "$PWD/results/network_resilience" \
  "$PWD/results/pi1_resilience_evidence"
```

The script creates a timestamped `research_archive/PQC_NETWORK_RESILIENCE_*`
directory, a `.tar.gz`, SHA-256 manifests, firmware copies, configuration
snapshots, and sanitized environment files. It verifies the manifest and makes
the archive directory read-only.
