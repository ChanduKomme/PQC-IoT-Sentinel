# Sanitized source snapshot

Browse [project/](project/) or download [PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip](PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip). The ZIP contains the same source tree, with one `PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE/` top-level directory.

The source includes PQC sender/receiver firmware, the DTLS reference, CoAP/state helpers, KEM-derived code, host capture/provisioning tools, network-emulation utilities, dashboard and Splunk integration sources, and existing host checks. External SDK/toolchains and installed dependencies are not bundled.

Local Wi-Fi settings are placeholders, provisioned HMAC keys are zeroed/disabled, and the embedded DTLS private key is removed. New credentials are required before deployment. See [BUILD_AND_PROVISION.md](BUILD_AND_PROVISION.md) and [the exact sanitization ledger](../artifact/SANITIZATION.json).

The inherited application release label is 2.0.0; this does not denote a second research campaign. This repository's evidence release is Conference Version 1. Historical source-to-flashed-image provenance is incomplete, and a sanitized rebuild will have a different identity from the archived image.

Loose `sender/*.log` and `sender/*.jsonl` files are inherited development snapshots. The primary publication evidence is identified by the official run bundles and experiment index; these loose snapshots are not additional endurance campaigns.
