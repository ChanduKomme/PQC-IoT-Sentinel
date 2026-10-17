# Resource evidence

| Record | Meaning |
|---|---|
| [build_identities.csv](build_identities.csv) | Original resource-characterization binary/ELF lengths and SHA-256 identities; ELF text/data/BSS totals |
| [elf_size_output.txt](elf_size_output.txt) | Section totals extracted from the supplied ELF files with GNU `size` |
| [MEMORY_RESULTS.txt](MEMORY_RESULTS.txt) | Supplied short DTLS memory report and PQC endurance reference |
| [Supporting screenshots](../screenshots/README.md) | Terminal/source observations, stack-unit and configuration records |

The input ELF/binary files are omitted from the public copy because compiled images may contain provisioned secrets. Their identities and extracted section totals are retained; reviewers cannot re-extract those totals from absent images in this public release.

PQC post-session heap observations cover the 24-hour receiver run. DTLS memory samples come from a separate short repeated-session experiment. Stack units use 4-byte `StackType_t` in the recorded environment. Binary file length, ELF section totals, free heap, minimum-ever free heap, and stack high-water mark are different quantities.

These records do not establish equal-duration peak-memory comparisons or complete historical source-to-binary locking.
