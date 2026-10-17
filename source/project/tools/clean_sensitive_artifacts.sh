#!/bin/sh
# Read-only release check: preserve local credentials and flash evidence.
set -eu
echo "Use a pristine, unprovisioned source copy for redistribution. This command only checks."
exec python3 "$(dirname "$0")/validate_project.py" --release
