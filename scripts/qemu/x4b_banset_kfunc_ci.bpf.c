// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern int bpf_x4b_banset_match(struct xdp_md *ctx,
				__u32 refresh_threshold) __ksym;

SEC("xdp")
int x4b_banset_kfunc_ci(struct xdp_md *ctx)
{
	int flag = bpf_x4b_banset_match(ctx, 0);

	return flag > 0 ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
