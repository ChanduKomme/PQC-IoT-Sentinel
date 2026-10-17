# PQC IoT Sentinel — updated source project

Release: **2.0.0 · 12 September 2026**  
Wire protocol: **3** · Security profile: **4**

Start with **[RUN_STEPS.md](RUN_STEPS.md)**. It contains the complete host setup,
BL602 build/flash order, enrollment, fingerprint pinning, Sender A/B operation,
serial evidence, dashboard, rotation, DTLS baseline and troubleshooting steps.

For the code review and limitations, read [PROJECT_ANALYSIS.md](PROJECT_ANALYSIS.md).
For the format changes, read [docs/PROTOCOL.md](docs/PROTOCOL.md).
For packaging-time checks, read [the conference host report](../../artifact/HOST_CHECKS.json).

## Quick start on Ubuntu / WSL2

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
python3 tools/run_host_checks.py
python3 tools/run_dashboard.py
```

Open **http://127.0.0.1:8090**. The frontend source is included; build it locally before starting this launcher. Without Splunk,
the dashboard reports OFFLINE and shows the supplied risk register; it does not
invent traffic or successful tests.

Firmware operation additionally requires the compatible BL602 SDK/toolchain,
physical boards and local provisioning. No ready-to-flash device images or
provisioned device secrets are included. Both endpoints must be rebuilt for
this release; old wire-v2 senders are incompatible.

## Contents

| Path | Purpose |
|---|---|
| `sender/`, `Receiver/` | Current authenticated PQC application firmware |
| `common/` | Shared wire format, CoAP parser, state helpers and hash adapter |
| `sniffer/` | Optional inherited BL602 driver-based monitor firmware |
| `pi2_trust_authority/` | Offline enrollment, rotation and evidence verifier |
| `host-tools/`, `tools/` | Provisioning, builds, capture, checks and launchers |
| `dashboard/` | React frontend source and FastAPI backend |
| `integrations/splunk/` | Capture forwarding, dashboard assets and risk register |
| `experiments/dtls_baseline/` | Separate classical DTLS research baseline |
| `hardware_security/` | Strict trace-screening and recorded-outcome analyzers |
| `tests/`, `validation/` | Reproducible host checks and actual release results |
| `reference_results/` | Historical supplied measurements, not updated-firmware results |

See the conference host report for completed checks and optional skips. SDK compilation, flashing, radio,
physical flash persistence and physical security have not been verified here.
