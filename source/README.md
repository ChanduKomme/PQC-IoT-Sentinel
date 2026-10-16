# Sanitized public source snapshot

The Version 1 sanitized source archive is expected at:

```text
source/PQC_IoT_SENTINEL_V1_PUBLIC_SOURCE.zip
```

Expected SHA-256:

```text
3335e0706a920db0a282023b07e0db95b464c8d979ad793b0f4953fad693e272
```

## Contents

The prepared archive contains the Version 1 source project and supporting material, including application firmware, host tooling, DTLS baseline code, dashboard/integration code, network-emulation helpers, validation notes, and analysis documentation.

## Sanitization

The public package excludes or replaces sensitive local material, including:

- real Wi-Fi credentials;
- Splunk HEC tokens/passwords;
- provisioned per-device authentication secrets;
- the DTLS development server private key;
- local `.env` content containing secrets.

The archive should still be reviewed before redistribution in a formal artifact process, especially for third-party license notices and locally generated development fixtures.

## Historical provenance limitation

This source snapshot supports code inspection and reproduction work, but Version 1 does not claim a complete historical source-to-flashed-binary build lock for every archived experiment. The manuscript keeps that limitation explicit.

## Rebuilding new experiments

For a new campaign, freeze and record:

- source commit;
- SDK/dependency revisions;
- compiler/toolchain version and digest;
- build flags and generated configuration;
- firmware/ELF hashes;
- flashed board role/build identity;
- run ID and analysis version.

New experiments should be published as a later artifact version rather than silently replacing Version 1 evidence.
