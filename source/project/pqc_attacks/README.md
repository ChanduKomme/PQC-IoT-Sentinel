# Local regression checks

Run `python3 tools/run_host_checks.py` from the project root.
The old network injection scripts have been replaced because they used obsolete
wire formats and could log host-generated events as receiver rejections.
This directory does not generate traffic or claim hardware attack resistance.
Use the controlled verification procedure in `RUN_STEPS.md` for board evidence.
