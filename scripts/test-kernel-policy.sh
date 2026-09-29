#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
check="$repo_root/src/check-banset-kernel.sh"

if "$check" 6.11.99-test >/dev/null 2>&1; then
  echo "xt_banset must reject Linux 6.11" >&2
  exit 1
fi
"$check" 6.12.0-test
"$check" 7.0.0

(
  cd "$repo_root/src"
  kernelver=6.11.99-test
  kernel_source_dir=/tmp/kernel-source
  source ./dkms.conf >/dev/null
  [[ "${BUILT_MODULE_NAME[0]}" == xt_setset ]]
  [[ ! -v 'BUILT_MODULE_NAME[1]' ]]
  [[ "${MAKE[0]}" == *X4B_BUILD_BANSET=0* ]]
)
(
  cd "$repo_root/src"
  kernelver=6.12.0-test
  kernel_source_dir=/tmp/kernel-source
  source ./dkms.conf >/dev/null
  [[ "${BUILT_MODULE_NAME[1]}" == xt_banset ]]
  [[ "${MAKE[0]}" == *X4B_BUILD_BANSET=1* ]]
)

echo "kernel policy tests passed"
