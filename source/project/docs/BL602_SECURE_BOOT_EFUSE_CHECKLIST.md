# BL602 Secure-Boot / eFuse Checklist

This project deliberately does **not** auto-program BL602 eFuses. Security eFuses can be irreversible and a wrong setting can permanently lock or brick a development board.

Before claiming malicious-firmware resistance:

1. Reserve one sacrificial PineCone for hardening experiments.
2. Obtain the exact Bouffalo BL602 SDK/chip revision documentation for secure boot, flash encryption and debug/JTAG disable.
3. Read and archive the current eFuse state before any write.
4. Confirm recovery/bootloader implications and key-backup procedure.
5. Enable signed-image verification using the vendor-supported boot chain, not a custom application-only check.
6. Verify that a correctly signed image boots.
7. Verify that a one-byte-modified/unsigned image is rejected.
8. Verify debug/JTAG policy on the actual board.
9. Record commands, SDK version, chip revision and results in the experiment bundle.
10. Only then describe secure boot as implemented.

The host-side firmware manifest/signing helpers in this project are useful evidence management but **do not replace boot-ROM enforcement**.
