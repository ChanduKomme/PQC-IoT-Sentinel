#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-$HOME/sdk/bl602_iot_sdk/PQC_IoT_SENTINEL_UPDATED}"
CAPTURE_ROOT="${2:-$PROJECT_ROOT/results/network_resilience}"
PI1_ROOT="${3:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE="$PROJECT_ROOT/research_archive/PQC_NETWORK_RESILIENCE_${STAMP}"

cd "$PROJECT_ROOT"
mkdir -p "$ARCHIVE"

mkdir -p "$ARCHIVE/laptop_captures" "$ARCHIVE/config" "$ARCHIVE/firmware" "$ARCHIVE/tools"
if [[ -d "$CAPTURE_ROOT" ]]; then
  cp -a "$CAPTURE_ROOT"/. "$ARCHIVE/laptop_captures/"
else
  echo "WARNING: capture root not found: $CAPTURE_ROOT" > "$ARCHIVE/MISSING_CAPTURE_ROOT.txt"
fi

if [[ -n "$PI1_ROOT" && -d "$PI1_ROOT" ]]; then
  mkdir -p "$ARCHIVE/pi1_evidence"
  cp -a "$PI1_ROOT"/. "$ARCHIVE/pi1_evidence/"
fi

for f in sender/sender/include/security_profile.h sender/sender/include/build_config.h Receiver/Receiver/include/build_config.h; do
  [[ -f "$f" ]] && cp -a "$f" "$ARCHIVE/config/"
done

# Save a sanitized environment snapshot; never archive passwords or HEC tokens.
for envf in .env .env.pi1lab; do
  if [[ -f "$envf" ]]; then
    sed -E \
      -e 's/^(WIFI_PW|WIFI_PASSWORD|SPLUNK_HEC_TOKEN|.*PASSWORD|.*SECRET|.*TOKEN)=.*/\1=REDACTED/' \
      "$envf" > "$ARCHIVE/config/${envf#.}.sanitized"
  fi
done

for f in sender/build_out/sender.bin sender/build_out/sender.elf Receiver/build_out/Receiver.bin Receiver/build_out/Receiver.elf; do
  [[ -f "$f" ]] && cp -a "$f" "$ARCHIVE/firmware/"
done

for f in integrations/splunk/splunk/pqc_live_to_splunk_v4_resilience.py \
         integrations/splunk/splunk/pqc_live_to_splunk.py \
         splunk/PQC_IoT_SENTINEL_Splunk_Dashboard_v6_resilience.xml \
         PQC_IoT_SENTINEL_Splunk_Dashboard_v6_resilience.xml; do
  [[ -f "$f" ]] && cp -a "$f" "$ARCHIVE/tools/"
done

{
  echo "archive_created_utc=$(date -u --iso-8601=seconds)"
  echo "project_root=$PROJECT_ROOT"
  echo "capture_root=$CAPTURE_ROOT"
  echo "pi1_root=${PI1_ROOT:-not_provided}"
  echo "hostname=$(hostname)"
  echo "kernel=$(uname -srmo)"
  echo "python=$(python3 --version 2>&1)"
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "git_commit=$(git rev-parse HEAD)"
  fi
} > "$ARCHIVE/ARCHIVE_MANIFEST.txt"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git status --short > "$ARCHIVE/git_status.txt" || true
fi

(
  cd "$ARCHIVE"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

TAR="${ARCHIVE}.tar.gz"
tar -C "$(dirname "$ARCHIVE")" -czf "$TAR" "$(basename "$ARCHIVE")"
sha256sum "$TAR" > "${TAR}.sha256"

# Verify the manifest before freezing the directory.
(
  cd "$ARCHIVE"
  sha256sum -c SHA256SUMS
)

chmod -R a-w "$ARCHIVE"

echo "Archive: $ARCHIVE"
echo "Tarball: $TAR"
cat "${TAR}.sha256"
