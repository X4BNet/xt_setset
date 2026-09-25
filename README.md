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

## xt_banset

`xt_banset` owns the exact-pair `hash:ip,ip,flag` ipset type and supplies a
packet lookup path that does not enter the ipset core. Sets must have a positive
timeout and accept only scalar source/destination addresses, an 8-bit flag, and
IPv4 or IPv6 families.

```bash
ipset create ban hash:ip,ip,flag family inet timeout 600 maxelem 2097152
ipset add ban 192.0.2.1,198.51.100.10,7 timeout 600
iptables -t raw -A PREROUTING \
  -m banset --ban-set ban --ban-mode refresh --ban-probability 0.01 \
  -j DROP
```

The direct match modes are `match`, `refresh`, and `add`. Probability applies
to refresh/add mutations; a refresh rule still reports the membership result
on every packet. Ranges, networks, permanent entries, counters, comments,
skbinfo, and force-add are intentionally unsupported.

## XDP acceleration

The XDP-capable branch builds `src/x4b_banset_xdp.bpf.o`. Its production
program is in section `xdp/x4b_banset`; it looks up the live `ban`/`ban6`
tables through `bpf_x4b_banset_match`, refreshes hits with a 1% sample, records
NetFlow status 32 through `bpf_x4b_netflow_xdp_record`, and drops the packet.
Lookup errors, malformed packets, unsupported protocols, and misses pass to the
normal stack, where a direct netfilter rule should remain installed as fallback.

The object also contains `xdp/x4b_banset_lookup` (drop hits without NetFlow)
and `xdp/x4b_pass` sections for controlled benchmarks. Per-CPU pass, hit, drop,
lookup-error, and NetFlow-error counters are exposed in the
`x4b_banset_stats` map.

## Native receive-hook experiments

On a kernel carrying the X4B receive-hook patch, `x4b_banset_hook.ko` can run
the same direct backend either on GRO-normal NAPI lists or in the i40e receive
loop before skb allocation. The latter supports descriptor look-ahead batches
of up to 16 packets. IPv4 batch lookups can compare all eight keys in each
candidate bucket with AVX2 inside one kernel-FPU section per batch; IPv6 and
unsupported SIMD contexts use the scalar implementation.

```bash
modprobe x4b_banset_hook stage=napi batch_size=1 simd=0 netflow=1
modprobe x4b_banset_hook stage=napi batch_size=16 simd=1 netflow=1
modprobe x4b_banset_hook stage=i40e batch_size=1 simd=0 netflow=1
modprobe x4b_banset_hook stage=i40e batch_size=16 simd=1 netflow=1
```

Only one native hook may be registered. Hits are recorded as NetFlow status
32 with ports suppressed and are then dropped. The normal netfilter banset
rule should remain installed as a fallback while this experimental interface
is evaluated. Aggregate counters are available in `/proc/x4b_banset_hook`.
