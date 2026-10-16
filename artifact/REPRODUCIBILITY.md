# Version 1 reproducibility guide

## Scope

This guide describes how to inspect and reproduce the software/analysis workflow associated with **Beyond the Handshake: A 24-Hour Study of Post-Quantum Messaging and DTLS on BL602**.

The paper reanalyses archived campaigns. This repository does not imply that a fresh hardware campaign was performed during packaging.

## Integrity checks

The publication PDF and sanitized public source snapshot are identified in `SHA256SUMS.txt`.

Expected SHA-256 values:

```text
9b6b7862cacc96f0b14a8b6789b6c08d5eebcf1344fd9680ce2b195cc35ccaf9  Beyond_the_Handshake_Conference_Paper.pdf
3335e0706a920db0a282023b07e0db95b464c8d979ad793b0f4953fad693e272  PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip
```

After placing both files in their documented locations, verify locally with:

```bash
sha256sum paper/Beyond_the_Handshake_Conference_Paper.pdf
sha256sum source/PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip
```

## Source package

Unpack the sanitized source archive:

```bash
unzip PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip
cd PQC_IoT_SENTINEL_UPDATED
```

Recommended reading order:

1. `README.md`
2. `PROJECT_ANALYSIS.md`
3. `RUN_STEPS.md`
4. protocol/source documentation
5. `experiments/dtls_baseline/`
6. network-emulation helpers
7. validation and analysis tooling

## Sanitization

The public package intentionally excludes live credentials and the DTLS development server private key. Example environment files contain placeholders only. Generate fresh local credentials for any reproduction build.

Never publish:

- real Wi-Fi passwords;
- Splunk HEC tokens/passwords;
- provisioned per-device authentication secrets;
- development private keys;
- local `.env` files containing secrets.

## Historical evidence boundary

The manuscript reports results reconstructed from author-supplied experiment archives. The public source snapshot does not by itself prove that every archived firmware image was built from exactly this source revision with identical compiler/configuration inputs. This is a known Version 1 limitation and must remain visible.

## Reproduction levels

### Level A — artifact integrity

Verify checksums and inspect the manuscript, machine-readable result tables, protocol definitions, source, and analysis notes.

### Level B — host-side software checks

Create an isolated Python environment and run the host-side validation/tests documented by the source package. Synthetic fixtures should not be interpreted as hardware measurements.

### Level C — short hardware reproduction

Using your own BL602 boards and fresh local credentials:

1. freeze source revision, SDK revision, compiler version and build flags;
2. build sender and receiver;
3. record binary/ELF hashes;
4. flash boards and record role mapping;
5. run a short baseline capture;
6. reconcile sender/receiver structured events and raw serial;
7. compare basic packet lengths and timing ranges with the manuscript.

### Level D — independent experiment replication

For a new scientific campaign, use independently restarted runs, frozen source-to-binary provenance, one terminal record per application cycle, full-cycle timing, and a priori stopping rules. Do not merge those new results into Version 1 evidence.

## Network study semantics

Publication reporting must keep these distinct:

- original sealed structured-terminal-event view;
- post-hoc completed-cycle view from raw serial + source semantics;
- packet-level routed UDP loss;
- successful-only RTT distributions.

Packet loss is not identical to application-cycle loss, and successful-only RTT does not represent failed/censored cycle latency.

## Live evidence portal

Project evidence website: https://pqcsecrity.live/evidence

The website is a dissemination layer. Exact paper reproduction should rely on archived records and analysis scripts rather than treating live dashboard counters as primary experimental data.
