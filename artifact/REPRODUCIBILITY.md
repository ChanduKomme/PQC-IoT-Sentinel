# Reproduce Version 1

## Numerical reproduction

Use Python 3.10+ on a machine with roughly 700 MB free disk space. The numerical scripts use only the standard library. Clone or download this repository and run from its root:

```bash
python3 analysis/verify_integrity.py
python3 analysis/extract_evidence.py
python3 analysis/reproduce.py --check
```

The first command checks the actual published files, excluding the manifest's own hash. The second verifies and safely extracts all nine public bundles into `.reproduce/raw/`. The third reconstructs primary and network observations and compares them with [results/reproduced_summary.json](../results/reproduced_summary.json), using numeric tolerances for floating-point arithmetic.

No SDK, board, Wi-Fi connection, Splunk account, or website availability is required for this analysis. Python assertions are used for integrity gates; do not run the scripts with `python -O`.

Outputs go to `.reproduce/results/`:

| File | Meaning |
|---|---|
| `reproduced_summary.json` | Complete reconstructed numerical summary and quantile method |
| `rtt_samples.csv` | Successful primary message RTT samples |
| `delivery_gaps.csv` | Host-observed intervals between successive deliveries |
| `hourly_delivery.csv` | Delivery counts by hour from each run's first success |
| `dtls_handshake_errors.csv` | Raw handshake-call errors absent from structured totals |
| `network_completed_cycles.csv` | Structured and reconstructed completed-cycle denominators |
| `retry_outcomes.csv` | Corrected transmission-attempt outcomes |
| `network_seals.csv` | Original official network manifest hashes and verified member counts |

The same small tables are committed under [results/derived/](../results/derived/). The full RTT/gap tables are generated locally to avoid duplicating the raw datasets in Git.

## Figures

For Python with Matplotlib installed:

```bash
python3 -m pip install -r analysis/requirements-figures.txt
python3 analysis/make_figures.py
```

This renders PNG and SVG versions of successful RTT distributions, delivery continuity, and network denominator/failure-stage comparisons. The continuity plot shows the maximum observed gap per one-minute bin; raw gaps remain in the generated CSV. SVG/PNG export bytes can vary by renderer version; numerical reconstruction is the result-validation gate.

## Host source checks

With GCC, G++, and Python 3.12+ available, run:

```bash
python3 source/project/tools/run_host_checks.py --report .reproduce/host_checks.json
```

These are the inherited project's parser, state, RNG failure-path/round-trip, and simulated-storage tests. The inherited serial-monitor helpers use Python 3.12 f-string syntax, so the source-wide syntax gate and CI use Python 3.12. The numerical analysis commands above remain compatible with Python 3.10+. The test RNG is a fixture. The committed [host report](HOST_CHECKS.json) distinguishes passing checks, optional dashboard skips, and hardware checks that were not run. Full optional dashboard checks additionally need its Python dependencies and a built frontend.

## Hardware repetition is a separate task

See [source build/provisioning instructions](../source/BUILD_AND_PROVISION.md) and [firmware provenance](FIRMWARE_PROVENANCE.md). The archive does not contain the external BL602 SDK/toolchain or deployable secrets. Provision new Wi-Fi, device authentication, and DTLS credentials before rebuilding. Sanitization changes source/binary identity; a new build is not a retroactive reproduction of the flashed historical image.

The current artifact reproduces the archived analysis. It does not claim an independent hardware campaign, byte-identical target builds, ML-KEM conformance testing, or controlled physical power-cut validation.
