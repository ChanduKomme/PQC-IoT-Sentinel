# Artifact scope

Version 1 packages supplied historical evidence and a sanitized source snapshot. It includes two primary 24-hour runs, five official PQC network windows, excluded/diagnostic attempts, a separate DTLS memory characterization, screenshots, historical reports, analysis scripts, derived tables, figures, hashes, and reviewer documentation.

The original supplied uploads are identified in [INPUT_ARCHIVES.json](INPUT_ARCHIVES.json). They are not published verbatim because they contain local configuration, credentials, dependency caches and compiled images. Public bundles have their own hashes in [BUNDLES.json](BUNDLES.json).

The source snapshot's inherited software-release label “2.0.0” is not a claim that Version 2 research experiments were performed. “Conference Version 1” identifies this evidence release; these are different version namespaces.

## Publication differences

[SANITIZATION.json](SANITIZATION.json) lists source changes and every redacted evidence file. The DTLS Wi-Fi driver printed the local pre-shared Wi-Fi password; public copies replace that credential string while preserving timing and outcome records. Two aborted network baseline logs also require the same redaction. Official network run contents and their sealed manifests remain unchanged.

Compiled images and ELF files are excluded because they can embed credentials. Their filenames, lengths and SHA-256 identities are retained where applicable; original manifests may consequently mention excluded files. These records establish file identity, not complete source-to-flashed-build provenance.

The final conference manuscript is absent. Historical reports are labeled accordingly. No independent experimental data or missing manuscript content has been invented.
