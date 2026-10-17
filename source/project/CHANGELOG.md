# Changelog

## 2.0.0 — 2026-09-12

- New wire v3/security profile v4 with credential generation and authenticated positive ACKs.
- Persistent duplicate acknowledgement support for the latest committed message.
- EasyFlash sender counter reservation, CRC/readback and fail-closed storage handling.
- Receiver registry reconciliation and checked persistence before acceptance.
- Fail-closed RNG propagation through the KEM wrapper; fixed 512-only parameter contract.
- Shared strict CoAP parser, peer aging and a global datagram limit.
- Optional headless receiver and shorter acknowledgement path.
- Atomic validated offline registry lifecycle; provisioning preserves Sender A/B identity.
- Configuration-as-data build helper and bounded default Make parallelism.
- Structured serial telemetry and verified HTTPS forwarding from the host.
- Retired obsolete live injection scripts and invented receiver evidence.
- Fixed governance lookup, event mapping, API origin, observation counts and event deduplication.
- Included a freshly built dashboard and pinned frontend dependency declarations.
- Corrected DTLS attempt accounting, default one-session execution, analyzer timing selection and API adapter.
- Strict physical-data analyzers, exact event verifier and hashed experiment manifests.
- Host regression tests, SDK-stub storage tests, API checks, current documentation and package checksums.

Migration requires rebuilding both roles and repinning the newly initialized
receiver fingerprint. Read RUN_STEPS.md before flashing; no tested board binary
is included.
