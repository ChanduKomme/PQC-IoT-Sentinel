# Reviewer guide

This is the public Version 1 artifact for *Beyond the Handshake: A 24-Hour Study of Post-Quantum Messaging and DTLS on BL602*. The final conference PDF was not in the supplied archives; [paper/README.md](../paper/README.md) states that gap explicitly.

## A ten-minute route

1. Read the [README result tables](../README.md) and [comparison boundaries](../docs/MEASUREMENT_NOTES.md).
2. Inspect the [claim-to-evidence matrix](CLAIM_EVIDENCE_MATRIX.md) to locate the record behind each central claim.
3. Run the three [reproduction commands](REPRODUCIBILITY.md). No hardware or service account is required.
4. Inspect [raw handshake errors](../results/derived/dtls_handshake_errors.csv), [network completed cycles](../results/derived/network_completed_cycles.csv), and [retry outcomes](../results/derived/retry_outcomes.csv).
5. Read the [experiment exclusions](EXPERIMENT_INDEX.md), [sanitization record](SANITIZATION.json), and [provenance caveat](FIRMWARE_PROVENANCE.md).

## What the artifact supports

The archived runs support a descriptive complete-system comparison, sustained-operation observations, recovery/continuity analysis, and a reconstruction of telemetry denominator gaps. The source helps explain what each implementation is intended to do. These are separate evidence classes.

## What remains open

The principal design has one campaign per profile, unequal application authentication/persistence semantics, and incomplete historical source-to-binary locking. A matched classical/PQC application, independent endurance repetitions, standardized KEM validation, and physical crash testing are future work. The artifact does not turn those omissions into verified claims.

The public GitHub account and live website identify the author. Use the target venue's artifact submission mechanism if anonymous review is required.
