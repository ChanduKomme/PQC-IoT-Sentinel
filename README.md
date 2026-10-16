# PQC-IoT Sentinel — Conference Version 1

[![Status](https://img.shields.io/badge/status-conference%20v1-blue)](#version-1-scope)
[![Platform](https://img.shields.io/badge/platform-BL602%20%2F%20RISC--V-informational)](#system-under-study)
[![Transport](https://img.shields.io/badge/transport-CoAP%20%2F%20UDP-lightgrey)](#system-under-study)
[![PQC](https://img.shields.io/badge/PQC-Kyber--derived%20512--parameter-orange)](#cryptographic-scope)
[![Baseline](https://img.shields.io/badge/baseline-DTLS%201.2-green)](#primary-24-hour-comparison)
[![Evidence](https://img.shields.io/badge/evidence-24h%20%2B%20network%20resilience-purple)](#headline-results)

## Beyond the Handshake

**Conference manuscript:** *Beyond the Handshake: A 24-Hour Study of Post-Quantum Messaging and DTLS on BL602*

This repository is the public **Version 1 research artifact** for the PQC-IoT Sentinel conference study. It separates the conference evidence package from the older development repository and records the manuscript scope, quantitative results, reproducibility notes, evidence boundaries, and public project website in one place.

> **Live research/evidence website:** https://pqcsecrity.live/evidence
>
> The website is a presentation and evidence portal. Publication statistics should be taken from the archived experiment analysis described by the manuscript and this repository, not from live dashboard totals alone.

## Headline results

### Primary 24-hour comparison

| Metric | PQC-IoT Sentinel | DTLS 1.2 baseline |
|---|---:|---:|
| Host capture duration | 86,400.172 s | 86,400.820 s |
| Successful sender messages | 32,790 | 42,346 |
| Failed sender message outcomes | 0 | 2 |
| Observed message success | 100.0000% | 99.9953% |
| Parsed/recorded receiver successes | 32,789 | 42,346 |
| Successful RTT mean | 213.830 ms | 11.979 ms |
| Successful RTT median / P95 | 152 / 503 ms | 10 / 18 ms |
| Successful RTT P99 / maximum | 566 / 6,810 ms | 29.55 / 2,458 ms |
| Longest observed inter-delivery gap | 15.747 s | 159.184 s |
| Successful handshakes | N/A | 143 sender / 143 receiver |
| Raw handshake-call errors | N/A | 29 sender / 2 receiver |

The central interpretation is deliberately narrower than a primitive benchmark. The established DTLS exchange is faster in the evaluated configuration, but the two applications perform different authentication, persistence, key-lifecycle, and acknowledgement work. The observed latency ratio is therefore a **complete-system application comparison**, not a measured KEM-versus-ECDHE penalty.

The longitudinal analysis also shows why successful-message RTT alone is incomplete: the DTLS run has a 10 ms median successful RTT while its longest interval between successful deliveries is 159.184 s during session recovery. Raw-log reconstruction further found 29 sender and 2 receiver DTLS handshake errors absent from structured handshake-failure totals.

### Secondary PQC network-resilience study

| Profile | Delivered | Structured delivery | Completed cycles | Completed-cycle delivery | RTT median | RTT P95 |
|---|---:|---:|---:|---:|---:|---:|
| Network baseline | 1,000 | 100.0% | 1,000 | 100.00% | 130.0 ms | 548.00 ms |
| +200 ms forward delay | 1,000 | 100.0% | 1,000 | 100.00% | 337.0 ms | 748.00 ms |
| 10% random loss | 1,000 | 100.0% | 1,000 | 100.00% | 129.5 ms | 6,535.35 ms |
| 20% targeted loss | 991 | 99.1% | 1,004 | 98.71% | 132.0 ms | 6,912.00 ms |
| 50% targeted loss | 739 | 73.9% | 1,126 | 65.63% | 546.0 ms | 13,300.40 ms |

The completed-cycle view comes from a post-hoc audit of preserved raw serial evidence and firmware semantics. It does **not** overwrite the original sealed structured-terminal-event analyses. At 50% targeted loss, public-key and metadata acquisition account for 288 of 387 observed failed completed cycles; 99 failures occur after exhaustion of the protected-data retry loop.

Packet-level checks observed forward missing fractions of approximately 9.55%, 19.95%, and 50.54% in the corresponding loss profiles, with matching reverse-path counts in the selected captures.

## System under study

The primary experiments use BL602/PineCone-compatible RISC-V sender and receiver roles running FreeRTOS/lwIP and CoAP/UDP.

### PQC-IoT Sentinel profile

The evaluated application performs:

1. receiver public-key retrieval;
2. SHA-256 fingerprint pinning;
3. metadata retrieval and cross-checking;
4. fresh Kyber-derived 512-parameter KEM encapsulation per send cycle;
5. HKDF-SHA-256 key derivation;
6. AES-256-CCM payload protection;
7. a separately provisioned device HMAC over the protected request;
8. persistent sender sequence and receiver freshness state;
9. persistence before positive acknowledgement;
10. request-bound authenticated ACK validation at the sender.

For the recorded 22-byte application plaintext, the protected application payload is 874 bytes. The corresponding minimal `/pqkem-data` CoAP message is 890 bytes at the UDP payload level before IP/link-layer overhead.

### DTLS baseline

The classical profile uses DTLS 1.2 with ECDHE P-256 key establishment, ECDSA P-256 server authentication, and AES-256-CCM record protection. The client verifies the server certificate; the server does not require a client certificate. Sessions request 300 application messages and reuse the established channel.

The baseline is intentionally reported as a **classical application reference**, not as a security-equivalent replacement for the PQC profile. In particular, it does not implement the same provisioned sender credential or equivalent persistent application commit-before-ACK semantics.

## Cryptographic scope

The post-quantum implementation is described conservatively as **Kyber-derived, 512-parameter** code. Version 1 does not claim:

- FIPS 203 / ML-KEM conformance;
- a FIPS-validated cryptographic module;
- a formal proof of the composed application protocol;
- forward secrecy after later compromise of the long-lived receiver decapsulation key;
- side-channel, fault-injection, target-entropy, or physical-tamper resistance.

Matching sizes and successful round trips alone are not treated as proof of ML-KEM conformance.

## Endurance cryptographic observations

PQC endurance benchmark rows report approximately:

| Operation | Sender mean / median | Receiver mean / median |
|---|---:|---:|
| KEM | 9.24 / 9 ms | 10.52 / 11 ms |
| HKDF-SHA-256 | 0.77 / 1 ms | 0.76 / 1 ms |
| AES-256-CCM | 0.69 / 1 ms | 0.66 / 1 ms |

The firmware timer has millisecond resolution, so zero-valued samples represent sub-millisecond intervals rather than zero-cost operations.

DTLS successful sender handshake timing is approximately 1,926.68 ms mean and 1,743 ms median in the recorded run. The 143 successful sender handshake intervals sum to 275,515 ms, corresponding to **6.506 ms of successful establishment time per delivered DTLS message under the observed reuse policy**. This is an accounting ratio, not a per-request latency and not directly comparable to a local KEM microtimer.

## Resource observations

Archived binary lengths for the identified builds are:

| Role | PQC | DTLS |
|---|---:|---:|
| Sender | 398,384 B | 591,064 B |
| Receiver | 401,872 B | 602,236 B |

The corresponding resource-characterisation ELF BSS totals move in the opposite direction: approximately 103,652 / 107,324 B for PQC sender/receiver versus 94,102 B for each DTLS role. Binary file length, BSS, heap, and stack are distinct quantities and should not be combined as though they represent one memory metric.

## Repository map

```text
PQC-IoT-Sentinel/
├── README.md
├── VERSION
├── .gitignore
├── paper/
│   └── README.md
├── results/
│   ├── README.md
│   ├── primary_24h.csv
│   └── network_resilience.csv
├── artifact/
│   ├── ARTIFACT_SCOPE.md
│   ├── REPRODUCIBILITY.md
│   ├── REVIEWER_GUIDE.md
│   └── SHA256SUMS.txt
├── docs/
│   ├── LIVE_WEBSITE.md
│   ├── MEASUREMENT_NOTES.md
│   └── SECURITY_SCOPE.md
└── source/
    └── README.md
```

## Version 1 scope

This repository records the evidence underlying the present conference manuscript. It should not be silently rewritten to incorporate future matched-baseline, FIPS-conformance, power-cut, energy, or independent repeated-campaign results. Those experiments belong to a subsequent version so that Version 1 remains identifiable.

The current study is best understood as an **empirical embedded-systems and measurement-integrity study**. Its strongest lesson is that message outcomes, session establishment, recovery, continuity, and telemetry completeness require separate denominators and records.

## Important limitations

- one principal 24-hour campaign per configuration;
- one observed sender/receiver board pair;
- one 22-byte application payload;
- no matched DTLS impairment campaign;
- unequal runtime-memory evidence duration between PQC and DTLS;
- incomplete historical source-to-flashed-image build lock;
- different security contracts and timer boundaries between the two profiles;
- no energy measurement, flash-lifetime study, mobility study, multi-device contention study, or formal security proof.

These limitations are part of the paper's interpretation rather than hidden assumptions.

## Live website

Research/evidence portal: **https://pqcsecrity.live/evidence**

See [`docs/LIVE_WEBSITE.md`](docs/LIVE_WEBSITE.md) for how the website relates to the archived publication evidence.

## Artifact files

The manuscript PDF and sanitized public source archive are identified by SHA-256 in [`artifact/SHA256SUMS.txt`](artifact/SHA256SUMS.txt). The GitHub integration used to prepare this repository cannot directly attach local binary files, so the checksums and placement instructions are recorded under `paper/` and `source/`. Once the two binaries are uploaded to those locations, the repository is self-contained at the publication-artifact level.

## Responsible use

This repository describes a controlled research testbed. Development credentials, private keys, Wi-Fi secrets, Splunk credentials, and device authentication secrets must not be committed. Experimental configurations are not presented as production security guidance.
