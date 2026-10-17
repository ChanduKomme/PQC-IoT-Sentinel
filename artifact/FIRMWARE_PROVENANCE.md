# Firmware and build provenance notes

Version 1 distinguishes **known archived binary identities** from **source-build assertions**. Historical source-to-flashed-image provenance is incomplete, so the artifact must not claim that one inspected source revision generated every recorded campaign binary.

## Known firmware hashes

### Sender used after the routed Wi-Fi path correction

SHA-256:

```text
bbf32d7c73f204c96a1b22bcf69fad788af8461100167e7663a4601b785bc511
```

The supplied diagnostic archive identified this sender image with the corrected BL602-LAB routing path. The public package retains its identity; the compiled image is excluded because it may embed local credentials.

### Controlled-rotation receiver firmware

SHA-256:

```text
d7b320e894e938f019d53caf0d52cc6fa47025f3bdc0411f5d12da78eae9e4fe
```

### Historical receiver firmware

SHA-256:

```text
ea61020d698a6899c7f3a646d3ad9c4a2d08c32dd963bbf1d2130793042e6316
```

## Receiver key lifecycle evidence

The receiver persistent KEM key reached its configured 99,999-message limit and was deliberately rotated while replay/freshness state was preserved.

Current post-rotation public-key fingerprint recorded for the experiment:

```text
07595E1C83A7E673DB316866C78D74470639F9C340C63DC7B756F4284597BE47
```

The rotation created `key_id=2` while retaining the accepted sender counter rather than resetting replay state.

## Source/toolchain caveat

The inspected BL602 SDK/source environment and archived binaries do not form a complete cryptographically locked source-to-flashed-image chain for every historical campaign. Builds may also embed compile date/time, so identical source does not necessarily produce byte-identical binaries without deterministic-build controls.

The conference manuscript therefore treats these as separate evidence classes:

1. inspected source behavior;
2. archived runtime evidence;
3. identified firmware/binary hashes;
4. compiler/toolchain observations;
5. derived analysis outputs.

## Requirement for future campaigns

A Version 2 campaign should record, before flashing:

- source Git commit;
- SDK/dependency commits;
- compiler/toolchain digest;
- build flags and generated configuration;
- binary, ELF, and linker-map hashes;
- firmware build ID printed at boot;
- board role/serial mapping;
- run ID and analysis-script revision.

Those future controls should not be retroactively asserted for Version 1.

## Public packaging note

Compiled images and ELF files are not published in this sanitized release. See [excluded file identities](EXCLUDED_PRIVATE_BUILD_FILES.json) and [resource build identities](../evidence/resources/build_identities.csv). A SHA-256 identity does not prove that the inspected source produced that image.
