#!/usr/bin/env bash
# Determine the module version used by DKMS.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -r "$SCRIPT_DIR/.module-version" ]]; then
  sed -n '1p' "$SCRIPT_DIR/.module-version"
elif git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$SCRIPT_DIR" rev-parse HEAD
else
  echo "1.0"
fi
