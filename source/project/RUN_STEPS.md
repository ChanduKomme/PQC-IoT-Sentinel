# Complete execution steps

This guide applies to **PQC IoT Sentinel 2.0.0**, wire v3 / security profile v4.
Run commands from the extracted `PQC_IoT_SENTINEL_UPDATED` directory unless a
step explicitly changes directory. Use a path without spaces for the legacy
firmware Makefiles. The commands below use Ubuntu Linux; WSL2 also works for
host checks, but USB forwarding must be configured separately for physical boards.

## 1. What you need

| Item | Minimum or purpose |
|---|---|
| Host | Linux, Python 3.10–3.12, GCC/G++, GNU Make, Git |
| Board A | BL602/PineCone receiver, USB cable |
| Board B | BL602/PineCone Sender A, USB cable |
| Optional board C | A second legitimate sender with its own credential |
| Network | One controlled 2.4 GHz Wi-Fi network, reachable UDP 5683 between boards |
| Firmware SDK | Legacy Makefile-style BL IoT SDK with `make_scripts_riscv/project.mk` |
| Toolchain | RISC-V compiler supplied/recommended for that SDK revision |
| Flasher | `blflash`, with the correct board flash layout |
| Optional services | Splunk HEC on 8088 and search API on 8089; Pi network emulator |
| Optional OLED | SSD1306, disabled by default; verify board wiring before enabling |

A third board can be used as an inherited driver-based sniffer, but it cannot
simultaneously be Sender B. Two senders plus receiver plus sniffer require four
boards. A host/Pi packet capture can replace the extra sniffer.

This archive contains the complete maintained source tree and built dashboard.
The SDK, toolchain, Node dependencies and device-specific firmware binaries are
not bundled. The old nested archive of unrelated build objects is omitted.

## 2. Install host dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential git unzip
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` also installs the runtime dependencies. The basic
command-line checks use Python's standard library plus a C/C++ compiler;
NumPy enables the trace-screening tests. Keep this virtual environment active
in every terminal used for Python commands. Do not install dependencies into
the SDK's own Python environment unless its documentation requires that.

Before modifying the pristine download, optionally verify the shipped hashes:

```bash
python3 tools/validate_project.py --manifest
```

Then run the regression suite:

```bash
python3 tools/doctor.py
python3 tools/validate_project.py
python3 tools/run_host_checks.py
```

Expected: checks marked PASS and a report in `validation/host_checks.json`.
The report lists skipped optional checks and the hardware checks not performed.
The package checksum manifest will naturally differ after provisioning, builds,
or replacement of the test report; it checks the original download, not a
configured working directory. Host tests create temporary, disposable credentials
and do not provision your actual sender headers.

## 3. Start the dashboard immediately (boards optional)

The production frontend is already built in `dashboard/frontend/dist`:

```bash
python3 tools/run_dashboard.py
```

Open **http://127.0.0.1:8090**. With no Splunk credentials, OFFLINE and empty
telemetry are expected. The risk-register view should still load. Stop with Ctrl+C.
The launcher binds to loopback; this dashboard has no application login and is
intended for local use.

To change the frontend, install Node.js 22 and npm, then rebuild:

```bash
cd dashboard/frontend
npm ci
npm run build
cd ../..
python3 tools/run_dashboard.py
```

For frontend development, run the backend in one terminal and `npm run dev`
from `dashboard/frontend` in another. Vite proxies `/api` to port 8090.
Use `npm ci` so versions match the supplied lockfile. A large-JavaScript-chunk
notice from Vite is informational, not a failed build.

## 4. Set up the BL602 SDK and flasher

Prefer the SDK checkout used for your previous working board build. The original
upload did not identify a verified SDK commit or compiler release, so no exact
hardware compatibility claim is possible from the source alone. This project
uses the [vendor BL IoT SDK](https://github.com/bouffalolab/bl_iot_sdk) layout.
The newer `bouffalo_sdk` layout is not a drop-in replacement for these Makefiles.

If you do not have the old SDK, a starting checkout is:

```bash
mkdir -p "$HOME/iot"
git clone --recursive https://github.com/bouffalolab/bl_iot_sdk.git "$HOME/iot/bl_iot_sdk"
export BL60X_SDK_PATH="$HOME/iot/bl_iot_sdk"
test -f "$BL60X_SDK_PATH/make_scripts_riscv/project.mk"
git -C "$BL60X_SDK_PATH" rev-parse HEAD
```

Follow that checkout's toolchain/environment instructions, build one of its
BL602 examples first, and record its compiler version. This newly cloned SDK
is a starting point, not a tested revision for this release. The PQC code needs
Mbed TLS SHA-256, HMAC, HKDF, AES-CCM, CTR-DRBG and a functioning hardware entropy
source. The hash adapter requires a checked SHA-256 API from Mbed TLS >=2.7.
The DTLS baseline additionally needs DTLS 1.2, ECDHE/ECDSA P-256, AES-256-CCM,
X.509 and the SDK's lwIP network port. The adapter handles several Mbed TLS 2.x/3.x
API differences; it does not supply missing SDK modules.

With a Rust/Cargo environment installed, build the flasher using its
[upstream source](https://github.com/spacemeowx2/blflash):

```bash
git clone https://github.com/spacemeowx2/blflash.git "$HOME/iot/blflash"
cargo install --locked --path "$HOME/iot/blflash/blflash"
export PATH="$HOME/.cargo/bin:$PATH"
blflash --help
blflash flash --help
```

Check that the selected SDK's `.bin` format and your board's partition layout
match the flasher command. Do not substitute an arbitrary factory/full-flash image
when updating an already provisioned receiver: replay state depends on preserving
the SDK-managed EasyFlash partition.

## 5. Configure this project

```bash
cp .env.example .env
chmod 600 .env
```

Edit these values in `.env`:

```dotenv
BL60X_SDK_PATH=/absolute/path/to/bl_iot_sdk
WIFI_SSID=YOUR_ACTUAL_2_4_GHZ_WIFI_NAME
WIFI_PW=YOUR_ACTUAL_WIFI_PASSWORD
MAX_MAKE_JOBS=2
PQC_EXPERIMENT_ID=pqc-lab-001
PQC_ENABLE_OLED=0
```

Replace the example values. The build tool reads `KEY=value` as data; it does
not execute shell substitutions. Spaces can be enclosed in matching quotes.
Use one assignment per key. The helper generates a private `build_config.h`
for each role instead of placing credentials in command-line `-D` strings.
Generated headers and configured firmware images contain secrets; keep them local.

Use a distinct experiment ID for each measurement campaign. The build helper
accepts letters, digits, dot, underscore and hyphen, up to 64 characters.

Identify board ports by disconnecting and reconnecting one board at a time:

```bash
ls /dev/ttyUSB* /dev/ttyACM*
python3 tools/doctor.py --hardware
```

The rest of the guide assumes receiver `/dev/ttyUSB0`, Sender A `/dev/ttyUSB1`,
and optional Sender B `/dev/ttyUSB2`. Substitute your actual ports. On Linux,
add your user to the appropriate serial-access group if access is denied; a new
login is usually required. Only one application can own each port at a time.

## 6. Enroll the two credential slots

Enrollment is an offline operation. `pi2_trust_authority/state/device_registry.json`
contains randomly generated HMAC keys and must be backed up privately.

```bash
python3 pi2_trust_authority/trust_authority.py init
python3 pi2_trust_authority/trust_authority.py enroll --slot 1 --sender-id 0x53454E31 --name sender-A
python3 pi2_trust_authority/trust_authority.py enroll --slot 2 --sender-id 0x53454E32 --name sender-B
python3 pi2_trust_authority/trust_authority.py list
python3 tools/provision_device_identity.py receiver --registry pi2_trust_authority/state/device_registry.json
```

Expected: both slots generation 1, active, with distinct IDs. Secret values are
not printed. If you only use Sender A, leave Sender B disconnected; you may revoke
slot 2 before exporting the receiver registry to disable that unused credential.
The registry exporter requires both slots to exist. Enrollment never silently
replaces an occupied slot; use `rotate` for a replacement credential.

## 7. Build and flash the receiver first

```bash
python3 tools/build.py --role receiver --clean
mkdir -p firmware-local
cp Receiver/build_out/Receiver.bin firmware-local/receiver_initial.bin
sha256sum firmware-local/receiver_initial.bin
```

The build helper accepts `receiver` or `Receiver`. It creates an SDK customer-app
symlink for the selected project and refuses to overwrite an unrelated existing
application. Use a separate SDK checkout if that name is already in use.

For a standard PineCone boot jumper, verify the board labels: put IO8 in the
high/download position and reset before flashing; return IO8 to low/run and
reset afterwards. Other BL602 boards may use buttons or a different procedure.
Close all serial monitors before the command:

```bash
blflash flash firmware-local/receiver_initial.bin --port /dev/ttyUSB0
python3 -m serial.tools.miniterm /dev/ttyUSB0 2000000
```

Exit miniterm with Ctrl+] when finished. Boot should show Wi-Fi addressing,
enabled sender slots, `[Receiver] PUBLIC KEY FINGERPRINT`, a six-digit pairing
code and `GATEWAY_LISTENING`. Record the **complete 32-byte / 64-hex-character
fingerprint from this physically identified receiver's trusted USB serial port**.
It may wrap across several lines.

If using an OLED, set `PQC_ENABLE_OLED=1` and rebuild after verifying wiring.
The supplied driver uses address 0x3C; its source comments use SDA GPIO3 / SCL GPIO4.
Check the actual board/SDK pin definitions and voltage requirements. The default
headless build requires no OLED and does not start its display loop task.

## 8. Provision, build and flash Sender A

First bind the correct device credential, then pin the receiver:

```bash
python3 tools/provision_device_identity.py sender --registry pi2_trust_authority/state/device_registry.json --slot 1
python3 host-tools/provision_fingerprint.py --fingerprint-hex "REPLACE_WITH_64_HEX_FROM_RECEIVER" --gateway-ip "REPLACE_WITH_RECEIVER_IPV4"
python3 tools/build.py --role sender --clean
cp sender/build_out/sender.bin firmware-local/sender_A.bin
sha256sum firmware-local/sender_A.bin
blflash flash firmware-local/sender_A.bin --port /dev/ttyUSB1
```

Put Sender A into download mode before flashing and run mode afterwards. The
fingerprint command rejects placeholder values. Omitting `--sender-id` preserves
the enrolled identity; do not manually assign an ID belonging to another key.

Alternatively, after enrolling the sender, the serial-assisted provisioner can
read the fingerprint/IP from the receiver when you reset it:

```bash
python3 host-tools/auto_provision_from_receiver_serial.py --receiver-port /dev/ttyUSB0 --ip-mode static --echo
```

Close the receiver monitor first. Confirm the board identity and pairing prompt,
then build/flash the sender. This helper preserves the enrolled sender ID. The
six-digit code is only an operator confirmation aid, not cryptographic proof of
the receiver; the trusted USB fingerprint is the pinning evidence.

## 9. Optional Sender B

The same source folder is reused, so save A's binary **before** provisioning B:

```bash
python3 tools/provision_device_identity.py sender --registry pi2_trust_authority/state/device_registry.json --slot 2
python3 tools/build.py --role sender --clean
cp sender/build_out/sender.bin firmware-local/sender_B.bin
sha256sum firmware-local/sender_B.bin
blflash flash firmware-local/sender_B.bin --port /dev/ttyUSB2
```

The existing receiver fingerprint/IP remain pinned. If slot 2 was revoked,
rotate it first and export/reflash the receiver registry before building B.
Never flash A's credential-bearing image onto B and then claim independent
physical identities. A copied valid key can authenticate as the same logical node.

## 10. Verify communication and collect evidence

Run the receiver and Sender A on the configured Wi-Fi. The sender sends the
22-byte demonstration text repeatedly, normally with a two-second delay between
cycles. Verify:

- Sender: `PK_AUTH_OK`, `DEVICE_AUTH_ACTIVE`, `MSG_DELIVERED`.
- Receiver: `DEVICE_AUTH_OK`, `AEAD_DECRYPT_OK`, `MSG_DECRYPTED`.
- IDs and generations match the intended credential.
- The sender only reports `MSG_DELIVERED` after verifying the authenticated ACK.

Capture receiver evidence in one terminal and sender evidence in another:

```bash
python3 tools/capture_serial.py --port /dev/ttyUSB0 --seconds 120 --experiment-id pqc-lab-001 --out-dir results/pqc-lab-001/receiver
```

```bash
python3 tools/capture_serial.py --port /dev/ttyUSB1 --seconds 120 --experiment-id pqc-lab-001 --out-dir results/pqc-lab-001/sender_A
```

Output directories must be empty/new. Each contains `serial.log`, `events.jsonl`
and `capture_summary.json`. The capture tool rejects mismatched experiment IDs
and invalid JSON events. `event_id` is a host-assigned capture identity; firmware
logs are evidence from the trusted serial connection, not signed attestations.

Verify exact receiver event names and deduplicated IDs:

```bash
python3 pi2_trust_authority/independent_verifier.py --experiment-id pqc-lab-001 --event MSG_DECRYPTED --expected-min 1 --receiver-log results/pqc-lab-001/receiver/events.jsonl --out results/pqc-lab-001/receiver_check.json
```

Use `--expected-max N` with a justified expected count. The verifier returns 0
for a count match, 1 for a failed assertion, and 2 for invalid/inconclusive input.
A zero count only establishes absence in the supplied evidence, not proof that
an attack campaign occurred or that a system resisted it.

Record firmware/evidence hashes:

```bash
python3 tools/create_experiment_manifest.py --id pqc-lab-001 --profile pqc-wire3-profile4 --messages 40 --file firmware-local/receiver_initial.bin --file firmware-local/sender_A.bin --file results/pqc-lab-001/receiver/events.jsonl --out results/pqc-lab-001/manifest.json
```

`--messages` is planned intent; it does not alter the firmware loop or replace
measured counts. The manifest is unsigned provenance, not a signature.

## 11. Connect Splunk (optional)

Create an index (default `pqc_iot`) and an HEC token authorized for it. Configure
trusted HTTPS certificates for HEC and the management API, and set `.env`:

```dotenv
SPLUNK_HEC_URL=https://YOUR_SPLUNK_HOST:8088
SPLUNK_HEC_TOKEN=YOUR_LOCAL_TOKEN
SPLUNK_HOST=YOUR_SPLUNK_HOST
SPLUNK_PORT=8089
SPLUNK_USER=YOUR_SEARCH_USER
SPLUNK_PASS=YOUR_SEARCH_PASSWORD
SPLUNK_INDEX=pqc_iot
SPLUNK_VERIFY_TLS=true
SPLUNK_CA_FILE=/absolute/path/to/your_trusted_ca.pem
```

For a publicly trusted certificate, leave `SPLUNK_CA_FILE` empty. Check the
[Splunk HEC documentation](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.4/get-data-with-http-event-collector/set-up-and-use-http-event-collector-in-splunk-web)
for server-side setup. The updated firmware emits serial JSON; it no longer
blocks cryptographic processing on direct unencrypted HEC connections.

```bash
python3 integrations/splunk/splunk/serial_to_hec.py --input results/pqc-lab-001/receiver/events.jsonl --dry-run
python3 integrations/splunk/splunk/serial_to_hec.py --input results/pqc-lab-001/receiver/events.jsonl
python3 integrations/splunk/splunk/serial_to_hec.py --input results/pqc-lab-001/sender_A/events.jsonl
python3 tools/run_dashboard.py
```

The bridge reports a failed HEC response as an error and does not create replacement
success events. Re-uploading a capture can duplicate indexed records; the dashboard
filters `origin="firmware"` and deduplicates `event_id`. Receiver acceptances and
sender acknowledgements are distinct observations, not two delivered messages.
The risk register is a supplied research register, not an automatically proven
compliance assessment. Old governance output and sample datasets are historical.

## 12. Reboots, revocation and replacement

1. Capture a normal accepted message and its sender sequence.
2. Reboot only the sender. Its next sequence should jump forward because it skips
   the previously reserved range of 256 counters; gaps are expected.
3. Reboot only the receiver. Its key fingerprint and per-sender last counters
   should survive. Confirm this on real hardware; host flash tests cannot prove
   the board's power-loss behavior.
4. Operate A and B together. Their sequence spaces must remain independent.

For a controlled revocation, stop A, revoke its slot, export the registry, then
rebuild/reflash the receiver while preserving EasyFlash:

```bash
python3 pi2_trust_authority/trust_authority.py revoke --slot 1 --reason controlled_lab_revocation
python3 tools/provision_device_identity.py receiver --registry pi2_trust_authority/state/device_registry.json
python3 tools/build.py --role receiver --clean
blflash flash Receiver/build_out/Receiver.bin --port /dev/ttyUSB0
```

Restart old A: new messages must be rejected. Verify B still works. Record the
receiver fingerprint again; an unexpected change indicates state/layout loss
and requires investigation and deliberate repinning, not blind acceptance.

Replace A by rotating, exporting receiver credentials and building a new A image:

```bash
python3 pi2_trust_authority/trust_authority.py rotate --slot 1
python3 tools/provision_device_identity.py receiver --registry pi2_trust_authority/state/device_registry.json
python3 tools/build.py --role receiver --clean
blflash flash Receiver/build_out/Receiver.bin --port /dev/ttyUSB0
python3 tools/provision_device_identity.py sender --registry pi2_trust_authority/state/device_registry.json --slot 1
python3 tools/build.py --role sender --clean
cp sender/build_out/sender.bin firmware-local/sender_A_generation2.bin
blflash flash firmware-local/sender_A_generation2.bin --port /dev/ttyUSB1
```

Record the actual generation (it may be higher than 2 on later repetitions).
The new generation has a new HMAC key and a separate sender counter namespace;
the receiver resets that identity's counter only for a higher generation.
A same-generation revoke/re-enable preserves the counter. Old firmware/registry
rollback is not a hardware-enforced protection; this is an application-level check.

Authenticated byte-identical retries of the most recent accepted packet are
acknowledged without another acceptance. A replay of an older sequence is rejected.
The firmware's durable replay checkpoint does not provide transactional, exactly-once
execution of a separate physical actuator.

## 13. Optional network measurement

Use a host/Pi capture on the actual traffic path. Merely sharing Wi-Fi does not
mean an interface sees other clients' unicast traffic. Confirm visibility first.
The scripts in `pi1_network_emulator` operate on an explicitly selected, isolated
lab interface; inspect its existing queue configuration before replacing it.

```bash
sudo bash pi1_network_emulator/capture.sh LAB_INTERFACE results/pqc-lab-001/traffic.pcap
```

For a small controlled delay experiment on that lab interface:

```bash
sudo bash pi1_network_emulator/net_profile.sh show LAB_INTERFACE
sudo bash pi1_network_emulator/net_profile.sh set LAB_INTERFACE --delay-ms 20
sudo bash pi1_network_emulator/net_profile.sh show LAB_INTERFACE
sudo bash pi1_network_emulator/net_profile.sh clear LAB_INTERFACE
```

Replace `LAB_INTERFACE`. Measure the actual impairment with packet timestamps;
remove the test queue after collection. This helper does not configure bridges,
AP routing or bidirectional shaping automatically. The retained sniffer firmware
is optional and SDK-driver dependent; inspect its monitor tool `--help` before use.

## 14. Separate DTLS baseline

Use the same physical receiver/sender pair sequentially for comparisons, or a
separate matched pair. DTLS runs on UDP 5684. The included development certificates
and private key are public fixtures and unsuitable for deployment. Server identity
verification stays enabled; this baseline does not provide the PQC application's
per-device client HMAC authentication. Cookies remain disabled in the inherited
SDK port, so it is not an equivalent denial-of-service baseline.

```bash
python3 tools/build.py --profile dtls --role receiver --clean
blflash flash experiments/dtls_baseline/dtls_receiver/build_out/dtls_receiver.bin --port /dev/ttyUSB0
```

Boot the DTLS receiver and note its IPv4 address. Set `DTLS_SERVER_HOST` in `.env`
to that address, then:

```bash
python3 tools/build.py --profile dtls --role sender --clean
blflash flash experiments/dtls_baseline/dtls_sender/build_out/dtls_sender.bin --port /dev/ttyUSB1
```

Alternatively add `--receiver-port /dev/ttyUSB0` to the sender build to force fresh
serial IP detection even if an old numeric address was saved. Close other serial
monitors first. Capture the receiver and sender logs in separate terminals before
resetting the sender:

```bash
python3 tools/all_10h_baseline_tools/serial_log_10h.py --port /dev/ttyUSB0 --role receiver --profile dtls --duration-hours 0.1 --output results/dtls-001/receiver.log
```

```bash
python3 tools/all_10h_baseline_tools/serial_log_10h.py --port /dev/ttyUSB1 --role sender --profile dtls --duration-hours 0.1 --output results/dtls-001/sender.log
```

Despite the logger's historical filename, duration is the value you pass. The
updated DTLS sender defaults to **one session, up to 300 attempted messages**.
Early failure can stop it sooner. Set `DTLS_REPEAT_SESSIONS=1` and rebuild only if
you intend repeated sessions. Summaries distinguish attempted from unattempted
messages. After collecting a complete session:

```bash
python3 experiments/dtls_baseline/tools/analyze_dtls_baseline.py --sender-log results/dtls-001/sender.log --receiver-log results/dtls-001/receiver.log --warmup 0 --out-dir results/dtls-001/analysis
```

The analyzer separates sender/receiver handshake timing and uses successful
sender records for RTT statistics. Receiver process timing starts after DTLS read,
so it excludes record decryption. Local session IDs are not cross-board correlation
IDs. Use separate, clearly bounded captures for each comparison. Choose warm-up
exclusion before collection; do not tune it to improve a result. The `plain` and
`classical` options in the inherited aggregate logger do not mean those firmware
profiles are implemented in this package.

Restore the saved PQC application images afterwards, preserving EasyFlash.
If a different flash procedure or partition layout erased state, provision fresh
credentials/receiver keys and capture the new fingerprint deliberately.

## 15. Physical-measurement analysis

These commands analyze measurements you supply; they do not operate fault,
laser, debug or invasive equipment. Hardware secure boot, debug locks, encrypted
flash, side-channel resistance and fault resistance are not established here.
Use qualified hardware procedures and record those states separately.

Trace CSVs contain one trace per row and one time sample per column, without a
header. Use aligned, finite matrices with at least two traces per class and a
predeclared acquisition/analysis window:

```bash
python3 hardware_security/tvla_screen.py --fixed results/physical/fixed.csv --random results/physical/random.csv --threshold 4.5 --out results/physical/tvla.json --t-values results/physical/t_values.csv
```

Exit 0 means first-order screening passed for this dataset; 1 means the threshold
was reached/exceeded; 2 means invalid input. Constant zero-variance columns,
nonfinite numbers and insufficient traces are invalid, not clean passes.
A screening pass does not prove absence of leakage.

The recorded-outcome CSV requires these columns:

```csv
trial,boot_ok,auth_bypass,secret_exposed,reset_detected
```

Fill actual trial outcomes using 0/1, true/false or yes/no. Do not prefill desired
results. Then run, with your real planned trial count:

```bash
python3 hardware_security/fault_campaign_analyzer.py results/physical/trials.csv --expected-trials 100 --out results/physical/fault_summary.json
```

Exit 1 indicates an observed bypass/exposure; exit 2 indicates invalid/incomplete
input. `NO_BYPASS_OBSERVED` is limited to the recorded campaign.

## 16. Troubleshooting

| Symptom | Action |
|---|---|
| SDK/toolchain missing | Follow step 4; `doctor --hardware` is a prerequisite check, not an SDK installer |
| `project.mk` missing | Use the legacy BL IoT SDK layout, not an unrelated/new SDK tree |
| HMAC macros missing | Ensure both roles and the fingerprint tool come from this release |
| Sender build says unprovisioned | Run identity export and trusted fingerprint pinning first |
| `BAD_PROTO` / old packet lengths | Rebuild both endpoints; wire v2 is incompatible with v3 |
| `BAD_SENDER` / `DEVICE_AUTH_FAIL` | Compare selected slot, ID, generation, enabled state and saved binary hashes |
| `PK_AUTH_FAIL` | Compare the full trusted receiver fingerprint; investigate key/state changes |
| `STATE_PERSIST_FAIL` / startup store failure | Stop; check EasyFlash configuration, capacity and power integrity; do not reset counters under an old key to hide it |
| Sequence jumps after reboot | Expected range reservation; never decrement counters manually |
| Fresh replacement remains behind counter | Rotate the credential generation and update the receiver registry first |
| ACK lost | Latest valid identical retry is acknowledged without duplicate acceptance; inspect both captures |
| No serial JSON / wrong experiment | Flash current image built with the expected `PQC_EXPERIMENT_ID`; do not mix old logs |
| Dashboard is OFFLINE | Check actual Splunk status, credentials, index permissions and trusted HTTPS CA |
| No telemetry after upload | Search for `origin=firmware`, correct experiment ID, event ID and index |
| Serial port busy | Close miniterm/logger/auto-provisioner before another process opens that port |
| DTLS API/link failure | Confirm SDK/Mbed TLS features; adapter does not replace missing crypto/network modules |
| DTLS certificate failure | Check CA/name/time settings and development certificate validity; keep verification enabled |
| Key message limit reached | Stop and perform deliberate receiver-key lifecycle reprovisioning; no automatic KEM-key rotation command is implemented |
| Old `run_all.py` options no longer work | Use `tools/run_host_checks.py`; the misleading live injection harness was retired |

The accepted completion gate is a fresh, attributable board run with the actual
SDK/compiler, binary hashes, receiver fingerprint, active generations, capture
duration and measured outcomes. The bundled host report does not substitute for it.
