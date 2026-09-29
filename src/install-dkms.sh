#!/usr/bin/env bash
# Cleanly reinstall the module into the DKMS tree.

set -euo pipefail

PATH=$PATH:/bin:/usr/bin:/usr/sbin:/sbin:/usr/local/sbin
MODULE_NAME=xt_setset
TARGET_KERNEL="${KVERSION:-}"

case "${1:-}" in
  --uninstall)
    echo "Uninstalling from DKMS..."
    ;;
  --install)
    echo "Installing into DKMS..."
    ;;
  *)
    exit 1
    ;;
esac

if ! command -v dkms >/dev/null 2>&1; then
  echo "! You don't have DKMS accessible in system."
  exit 1
fi

if [[ ! -e dkms.conf ]]; then
  echo "! You don't have DKMS configured for this module."
  exit 1
fi

MVERSION="$(./version.sh)"
SOURCE_ROOT="${DKMS_SOURCE_ROOT:-/usr/src}"
STATE_ROOT="${DKMS_STATE_ROOT:-/var/lib/dkms}"

contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    [[ "$item" == "$needle" ]] && return 0
  done
  return 1
}

versions=()
for path in "$SOURCE_ROOT"/${MODULE_NAME}-*; do
  if [[ -d "$path" ]]; then
    version="${path#"$SOURCE_ROOT/${MODULE_NAME}-"}"
    if ! contains "$version" "${versions[@]}"; then
      versions+=("$version")
    fi
  fi
done

for path in "$STATE_ROOT"/${MODULE_NAME}/*; do
  if [[ -d "$path" ]]; then
    version="${path#"$STATE_ROOT/${MODULE_NAME}/"}"
    if ! contains "$version" "${versions[@]}"; then
      versions+=("$version")
    fi
  fi
done

while IFS= read -r line; do
  version="$(printf '%s' "$line" | sed -n "s#^${MODULE_NAME}[/,[:space:]]*\\([^,[:space:]]*\\).*#\\1#p")"
  if [[ -n "$version" ]] && ! contains "$version" "${versions[@]}"; then
    versions+=("$version")
  fi
done < <(dkms status | grep "^${MODULE_NAME}" || true)

nodepmod=
if grep -qs no-depmod "$(command -v dkms)"; then
  nodepmod=--no-depmod
fi

for version in "${versions[@]}"; do
  [[ "$1" == "--install" && "$version" == "$MVERSION" ]] && continue
  echo "! Removing existing ${MODULE_NAME}/$version from DKMS..."
  dkms $nodepmod remove "${MODULE_NAME}/$version" --all || echo "! Warning: failed to remove ${MODULE_NAME}/$version"
  rm -rf "$SOURCE_ROOT/${MODULE_NAME}-$version"
done

if [[ "$1" == "--uninstall" ]]; then
  exit 0
fi

if [[ -z "$TARGET_KERNEL" ]]; then
  echo "! KVERSION must identify the target kernel."
  exit 1
fi

# Remove the target build while its registered source tree still exists.
dkms $nodepmod remove "${MODULE_NAME}/$MVERSION" -k "$TARGET_KERNEL" >/dev/null 2>&1 || true

echo "! Installing $MVERSION into DKMS..."
install_root="$SOURCE_ROOT/${MODULE_NAME}-$MVERSION"
rm -rf "$install_root"
mkdir -p "$install_root"
cp -p ./*.[ch] Makefile.in configure dkms.conf check-banset-kernel.sh version.sh install-dkms.sh gen_compat_def "$install_root/"
chmod 0755 "$install_root/check-banset-kernel.sh" "$install_root/configure" "$install_root/install-dkms.sh" "$install_root/version.sh"

rm -f "$install_root"/Makefile "$install_root"/Module.symvers "$install_root"/modules.order
rm -f "$install_root"/*.ko "$install_root"/*.so "$install_root"/*_sh.o
rm -f "$install_root"/*.o "$install_root"/*.cmd "$install_root"/.*.cmd "$install_root"/.*.o.d
rm -f "$install_root"/*.mod "$install_root"/*.mod.c "$install_root"/*.mod.o
printf '%s\n' "$MVERSION" > "$install_root/.module-version"
touch "$install_root/.automatic"

if dkms status "${MODULE_NAME}/$MVERSION" 2>/dev/null | grep -q "^${MODULE_NAME}"; then
  :
elif [[ -d "$STATE_ROOT/$MODULE_NAME/$MVERSION" ]]; then
  echo "! Reusing existing ${MODULE_NAME}/$MVERSION DKMS tree not reported by dkms status."
else
  dkms add -m "$MODULE_NAME" -v "$MVERSION"
fi

dkms build -m "$MODULE_NAME" -v "$MVERSION" -k "$TARGET_KERNEL"
dkms install -m "$MODULE_NAME" -v "$MVERSION" -k "$TARGET_KERNEL"
