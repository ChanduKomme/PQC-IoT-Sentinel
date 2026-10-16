# Artifact scope and claim boundaries

## Included claims

Version 1 supports an implementation-level systems study of two BL602 security profiles and a secondary PQC network-resilience study. It supports statements about recorded application behavior, measured timing boundaries, packet-capture observations, persistence ordering in inspected source, and telemetry/accounting discrepancies described in the manuscript.

## Not claimed

This artifact does **not** establish:

- FIPS 203 / ML-KEM conformance;
- cryptographic-module certification;
- a formal proof of the composed protocol;
- side-channel, fault-injection, entropy-quality, or physical-tamper resistance;
- secure boot or hardware anti-rollback guarantees;
- exactly-once physical actuation;
- fleet-scale behavior;
- energy efficiency;
- universal PQC-vs-DTLS performance superiority.

## Comparison boundary

The PQC and DTLS profiles perform different work. Authentication, persistence, key reuse, acknowledgement semantics, and timing endpoints differ. Results characterize the complete recorded implementations; they do not isolate the causal cost of replacing ECDHE with a post-quantum KEM.

## Evidence versions

The network-resilience archive contains original sealed structured-terminal-event analyses. A later audit reconstructs completed cycles from preserved raw serial evidence and source semantics. The corrected cycle-level results are an additional analysis layer, not a rewrite of the sealed evidence.

## Sanitization

The public source archive excludes real local credentials and private key material. Placeholders are used where needed to document configuration paths.

## Versioning

Future matched-security baselines, conformance work, repeated 24-hour campaigns, energy measurements, or redesigned instrumentation should be released as Version 2 or later rather than silently rewriting Version 1 evidence.
