# xt_setset Agent Notes

## Local build

Run the host build from the repo root:

```sh
./build.sh
```

Useful variants:

```sh
./build.sh --deps-only
./build.sh --configure-only
./build.sh --clean
./build.sh --kver "$(uname -r)"
./build.sh --kver "$(uname -r)" --kdir "/lib/modules/$(uname -r)/build"
```

The supported host target is Debian/Ubuntu with `apt`. The default build is
non-installing: it regenerates `src/Makefile`, then builds the kernel match
module and xtables userspace library in `src/`.

## QEMU test flow

Prerequisites:

- shared `ci/kernel-module-ci` submodule, or sibling `../kernel-module-ci`
  checkout
- Docker on the host
- `sudo` on the host
- optional preferred guest IP via `VMIP`

The shared harness dynamically leases a non-overlapping `/24` from
`192.168.224.0/19`. `VMIP` is a preferred address and falls back to a free
subnet unless `X4B_QEMU_STRICT_VMIP=1` is set.

Run the CI-parity guest build and smoke-test flow from the repo root:

```sh
./scripts/test-qemu.sh
```

Useful variants:

```sh
./scripts/test-qemu.sh --skip-local-build
./scripts/test-qemu.sh --keep-workdir
X4B_KERNEL_ARTIFACT_DIR=/path/to/kernel-patches/artifacts/6.1.106 VMIP=192.168.224.2 ./scripts/test-qemu.sh
KERNEL_MODULE_CI_ROOT=/path/to/kernel-module-ci VMIP=192.168.224.2/24 ./scripts/test-qemu.sh
```

The QEMU harness delegates shared Docker, patched-kernel, reboot, and guest
lifecycle work to `kernel-module-ci`, while this repository keeps the setset
setup and test playbooks under `scripts/qemu/`. The module checkout is mounted
at `/module-src` so uncommitted local changes are tested. When
`X4B_KERNEL_ARTIFACT_DIR` is set, the harness skips the shared `/runner/kernel`
download cache and mounts the provided local kernel artifact set at
`/root/kernel` instead.

The guest setup builds this module from the mounted checkout. The guest smoke
test loads `xt_setset`, verifies xtables registration, creates disposable ipsets,
and verifies that a `-m setset` rule can be parsed, saved, and removed.

## Architecture map

- `src/xt_setset.c`: kernel xtables match module. It can add packets to ipsets,
  delete packets from ipsets, optionally test membership, and update set element
  timeout/counter metadata.
- `src/xt_setset.h`: shared option payload between the kernel match and xtables
  plugin.
- `src/libxt_setset.c`: xtables userspace match plugin for `-m setset`.
- `src/configure` and `src/Makefile.in`: legacy configure/build flow used by
  local builds and CI.
- `src/dkms.conf`, `src/install-dkms.sh`, and `src/version.sh`: DKMS packaging
  helpers used by `make install` when DKMS is available.

## Style and change rules

- Preserve the existing low-churn legacy C style in kernel and xtables files.
  Match nearby formatting and naming instead of normalizing old code wholesale.
- Prefer the smallest compatibility fix that restores the current build on the
  target kernel. Fix build/configuration glue before changing set behavior.
- Keep host build automation in `build.sh`; keep module-specific guest tests in
  `scripts/qemu/`; keep shared QEMU harness work in `ci/kernel-module-ci`.
- Keep source files under `src/`; adapt wrappers and scripts around that layout
  rather than relocating the module.
- Keep the QEMU local setup building from `/module-src` so uncommitted local
  changes are tested instead of the remote GitHub branch.
