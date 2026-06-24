#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

usage() {
  cat <<'EOF'
Usage: ./scripts/test-qemu.sh [options]

Options:
  --skip-local-build  Skip the local host build step.
  --keep-workdir      Preserve the temporary QEMU workspace.
  --help              Show this help text.

Environment:
  KERNEL_MODULE_CI_ROOT
                      Path to shared kernel-module-ci checkout. Default: ci/kernel-module-ci, then ../kernel-module-ci
  X4B_KERNEL_ARTIFACT_DIR
                      Path to a prebuilt kernel artifact directory. Default: use /runner/kernel cache
  VMIP                Guest VM IPv4 address. Default: 192.168.224.2
EOF
}

if [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

resolve_dir() {
  local input="$1"

  (cd "$input" 2>/dev/null && pwd)
}

resolve_shared_root() {
  local input="${KERNEL_MODULE_CI_ROOT:-$REPO_ROOT/ci/kernel-module-ci}"
  local root

  if root="$(resolve_dir "$input")" && [[ -x "$root/scripts/test-qemu.sh" ]]; then
    echo "$root"
    return 0
  fi

  if root="$(resolve_dir "$REPO_ROOT/../kernel-module-ci")" && [[ -x "$root/scripts/test-qemu.sh" ]]; then
    echo "$root"
    return 0
  fi

  echo "error: missing shared kernel-module-ci checkout; set KERNEL_MODULE_CI_ROOT or initialize ci/kernel-module-ci" >&2
  exit 1
}

if [[ ! -x "$REPO_ROOT/build.sh" ]]; then
  echo "error: missing executable build script at $REPO_ROOT/build.sh" >&2
  exit 1
fi

SHARED_ROOT="$(resolve_shared_root)"

export KMOD_CI_MODULE_NAME="xt-setset"
export KMOD_CI_ENV_NAME="setset-local"
export KMOD_CI_REPO_ROOT="$REPO_ROOT"
export KMOD_CI_HOST_BUILD_COMMAND="./build.sh"

exec "$SHARED_ROOT/scripts/test-qemu.sh" "$@"
