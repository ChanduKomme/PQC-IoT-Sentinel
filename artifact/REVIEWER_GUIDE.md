# Reviewer quick guide

## Paper

**Beyond the Handshake: A 24-Hour Study of Post-Quantum Messaging and DTLS on BL602**

## What to verify first

1. Read the root `README.md` for the study boundary and headline results.
2. Inspect `results/primary_24h.csv` for the primary 24-hour comparison.
3. Inspect `results/network_resilience.csv` for the secondary delay/loss study.
4. Read `artifact/ARTIFACT_SCOPE.md` before interpreting any performance ratio.
5. Read `artifact/REPRODUCIBILITY.md` for evidence and source-to-binary limitations.
6. Use the live website only as a supporting evidence portal: https://pqcsecrity.live/evidence

## Core claims

The artifact supports four main empirical points:

- both evaluated BL602 configurations operated for approximately 24 hours under their recorded workloads;
- established DTLS application exchanges were much shorter than the PQC application's protected-data exchange in these implementations, but the systems do not implement equivalent security/lifecycle work;
- service continuity and setup/recovery behavior can differ from successful-message RTT distributions;
- structured telemetry can omit real failure paths, so raw logs, firmware semantics, and packet evidence must be reconciled before drawing reliability conclusions.

## Important non-claims

Please do not interpret this artifact as:

- a proof that DTLS is universally faster or better than PQC;
- a primitive-only KEM-versus-ECDHE benchmark;
- a FIPS 203 conformance claim;
- a formal security proof;
- an energy-efficiency evaluation;
- a statistically replicated multi-deployment study.

## Network study note

At 20% and 50% targeted loss, completed-cycle delivery differs from the original structured-terminal-event percentage because raw-log reconstruction found metadata-fetch failures that completed without a structured terminal failure record.

The sealed original analyses are preserved conceptually as the **structured-terminal-event view**. The corrected figures are the **completed-cycle view**.

## Artifact integrity

See `artifact/SHA256SUMS.txt` for the conference PDF and sanitized source archive identities.
