# ipset enhanced modules

## xt_setset

match module that does the job of `-j SET`

match module can be used to bump the timeout (ipset can now be an xt_recent replacement) using the `--ss-exist` flag

Returns on match if `--ss-match` flag provided

### Installation

#### Traditional Build and Install

```bash
cd src
./configure
make
sudo make install
```

#### DKMS Installation (Recommended)

DKMS (Dynamic Kernel Module Support) automatically rebuilds the kernel module when the kernel is upgraded.

**Prerequisites:**
- Install DKMS: `sudo apt-get install dkms` (Ubuntu/Debian) or equivalent for your distribution
- Install kernel headers: `sudo apt-get install linux-headers-$(uname -r)`

**Installation Steps:**

1. Configure and install via DKMS:
```bash
cd src
./configure
sudo make dinstall
```

2. Check DKMS status:
```bash
./install-dkms.sh --status
```

**Manual DKMS Management:**

```bash
# Install module via DKMS
sudo ./install-dkms.sh --install

# Remove module from DKMS
sudo ./install-dkms.sh --uninstall

# Check current status
./install-dkms.sh --status
```

**DKMS Configuration Options:**

You can disable DKMS during configuration if needed:
```bash
./configure --disable-dkms           # Disable DKMS entirely
./configure --disable-dkms-install   # Build with DKMS support but don't auto-install
```

## xt_setban

a single rule banning module