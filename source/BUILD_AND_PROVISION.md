# Build and provision a new lab copy

This is a source reconstruction path. It does not certify that the current snapshot generated every historical experiment image.

Use Python 3.12+ for the source tools and host-check suite. The inherited monitor helpers use Python 3.12 f-string syntax. The separate numerical-analysis scripts support Python 3.10+.

1. Start from [project/RUN_STEPS.md](project/RUN_STEPS.md). Install the compatible external BL602 SDK/toolchain and set the local SDK configuration required by `project/tools/build.py`.
2. Copy `project/.env.example` to a local `.env`, then fill in new Wi-Fi settings, board serial ports, receiver address and optional service settings. Keep local credentials out of Git.
3. Use the included trust-authority/enrollment and provisioning tools to create fresh sender authentication keys and a receiver registry. Public sender keys are all zero and receiver slots disabled. Pin the newly created receiver public-key fingerprint before sending.
4. For DTLS, generate a new local CA/server certificate and matching private key, with the configured server name, and provision `kDtlsCaCertPem`, `kDtlsServerCertPem`, and `kDtlsServerKeyPem` in all relevant local credential headers. The archived certificate text is public historical material, not an included private identity.
5. Review the complete runbook, then build/flash both roles using the project tools. Generated `build_config.h` settings are source examples; choose the intended experiment profile deliberately rather than assuming defaults reproduce the archived campaign.
6. Run short local smoke checks and retain the exact source/SDK/compiler/configuration/build identity before collecting new evidence.

Useful entry points:

```bash
cd source/project
python3 tools/build.py --help
python3 tools/provision_device_identity.py --help
python3 pi2_trust_authority/trust_authority.py --help
python3 tools/run_host_checks.py --report ../../.reproduce/new_host_checks.json
```

The repository's [host report](../artifact/HOST_CHECKS.json) covers local software checks. BL602 cross compilation, physical flashing, Wi-Fi operation and arbitrary power-loss behavior were not tested during this packaging update.

The frontend source is included, but generated frontend build assets and `node_modules` are omitted. Follow the frontend package scripts to install dependencies and build before using a launcher that expects `dashboard/frontend/dist/`.
