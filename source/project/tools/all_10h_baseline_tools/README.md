> See the root RUN_STEPS.md for the current workflow and measurement limits.
> This retained component documentation describes inherited utilities.

# Unified ten-hour measurement tools

Profiles:
1. Plain CoAP
2. Classical P-256 ECDH + HKDF-SHA-256 + AES-CCM over CoAP
3. DTLS 1.2 + ECDHE P-256 + ECDSA + AES-256-CCM
4. ML-KEM-512-style + HKDF-SHA-256 + AES-256-CCM over CoAP

Run these as four independent ten-hour tests. They require different firmware images and cannot be measured simultaneously. Use the same boards, Wi-Fi, 22-byte payload, USB mapping, and logger for all tests.

## Install
```bash
cd ~/sdk/bl602_iot_sdk/PQC_IoT_Updated
source .venv/bin/activate
mkdir -p tools/all_10h
unzip -o ~/Downloads/all_10h_baseline_tools.zip -d tools/all_10h
python3 -m py_compile tools/all_10h/*.py
```

## Log one profile
Receiver terminal:
```bash
python3 -u tools/all_10h/serial_log_10h.py \
  --profile PROFILE --role receiver --port /dev/ttyUSB0 --baud 2000000 \
  --duration-hours 10 --output "$RUN_DIR/receiver.log"
```
Sender terminal:
```bash
python3 -u tools/all_10h/serial_log_10h.py \
  --profile PROFILE --role sender --port /dev/ttyUSB1 --baud 2000000 \
  --duration-hours 10 --output "$RUN_DIR/sender.log"
```
PROFILE is plain, classical, dtls, or pqc.

## Analyze one profile
```bash
python3 tools/all_10h/analyze_10h.py \
  --profile PROFILE --sender-log "$RUN_DIR/sender.log" \
  --receiver-log "$RUN_DIR/receiver.log" --out-dir "$RUN_DIR/analysis"
```

Plain/classical firmware should emit machine-readable `[BASELINE]` rows with key=value fields. Recognized fields include rtt_ms, process_ms, payload_len, wire_len, ecdh_keygen_ms, ecdh_shared_ms, hkdf_ms, and aes_ms. PQC recognizes the current `[BENCH] path=pqc` rows plus MSG_DELIVERED and MSG_DECRYPTED. DTLS recognizes `[DTLS_HANDSHAKE]` and `[DTLS_BENCH]`.

Missing fields remain blank and are reported in the diagnostics file; the tool does not invent values.

## Validate all four summaries
```bash
python3 tools/all_10h/validate_10h_results.py \
  "$PLAIN_DIR/analysis/plain_10h_summary.csv" \
  "$CLASSICAL_DIR/analysis/classical_10h_summary.csv" \
  "$DTLS_DIR/analysis/dtls_10h_summary.csv" \
  "$PQC_DIR/analysis/pqc_10h_summary.csv"
```

## Generate the report table
```bash
python3 tools/all_10h/combine_10h_results.py \
  --plain "$PLAIN_DIR/analysis/plain_10h_summary.csv" \
  --classical "$CLASSICAL_DIR/analysis/classical_10h_summary.csv" \
  --dtls "$DTLS_DIR/analysis/dtls_10h_summary.csv" \
  --pqc "$PQC_DIR/analysis/pqc_10h_summary.csv" \
  --out-dir results/ten_hour_comparison
```

Generated report files:
- ten_hour_comparison.csv
- ten_hour_comparison.md
- ten_hour_comparison_table.tex

Do not insert the LaTeX table until every diagnostics file has been reviewed and all four durations pass the validator.
