# Evidence collection

Public compressed archives are in [bundles/](bundles/). All nine are indexed with exact sizes, member counts and SHA-256 hashes in [artifact/BUNDLES.json](../artifact/BUNDLES.json). Use `python3 analysis/extract_evidence.py` from the repository root to verify and extract them.

| Bundle | Contents / status |
|---|---|
| `PQC_24H_FINAL_PUBLIC.tar.xz` | Primary PQC serial logs, structured events, capture health and original manifests |
| `DTLS_24H_FINAL_PUBLIC.tar.gz` | Primary DTLS role logs, archived analyses, bridge output, configuration and original manifests; Wi-Fi password redacted |
| Five `*_official_*.tar.gz` bundles | Official baseline, delay, random-loss and targeted-loss runs, including PCAPs, traffic-control state, sample windows and original seals |
| `DTLS_MEMORY_CHARACTERIZATION_PUBLIC.tar.gz` | Separate short-run memory report and instrumented source/build logs; images and ELF files excluded |
| `NETWORK_DIAGNOSTICS_PUBLIC.tar.gz` | Invalid/aborted attempts and lifecycle diagnostics; excluded from headline results |

[index/](index/) mirrors small original summaries, manifests and notes so reviewers can browse them without unpacking logs. [resources/](resources/) records binary/ELF identities and memory observations. [screenshots/](screenshots/README.md) contains supporting visual records.

Historical manifests describe original experiment files and may reference excluded binaries or pre-redaction logs. The current public-file manifest is [artifact/SHA256SUMS.txt](../artifact/SHA256SUMS.txt); publication differences are explicit in the [redaction ledger](../artifact/SANITIZATION.json). Original official network manifests still verify completely.
