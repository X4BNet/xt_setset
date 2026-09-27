// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define X4B_BANSET_REFRESH_1_PERCENT 42949673U

enum x4b_banset_stat {
	X4B_BANSET_PASS,
	X4B_BANSET_HIT,
	X4B_BANSET_DROP,
	X4B_BANSET_LOOKUP_ERROR,
	X4B_BANSET_NETFLOW_ERROR,
	X4B_BANSET_STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, X4B_BANSET_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} x4b_banset_stats SEC(".maps");

extern int bpf_x4b_banset_match(struct xdp_md *ctx,
					__u32 refresh_threshold) __ksym;
extern int bpf_x4b_netflow_xdp_record(struct xdp_md *ctx, __u8 fw_status,
					     _Bool noports) __ksym;

static __always_inline void x4b_count(enum x4b_banset_stat statistic)
{
	__u32 key = statistic;
	__u64 *value = bpf_map_lookup_elem(&x4b_banset_stats, &key);

	if (value)
		(*value)++;
}

static __always_inline int x4b_banset_lookup(struct xdp_md *ctx,
					     _Bool record_netflow)
{
	int flag = bpf_x4b_banset_match(ctx, X4B_BANSET_REFRESH_1_PERCENT);

	if (flag < 0) {
		if (flag != -ENOENT)
			x4b_count(X4B_BANSET_LOOKUP_ERROR);
		x4b_count(X4B_BANSET_PASS);
		return XDP_PASS;
	}
	x4b_count(X4B_BANSET_HIT);
	if (record_netflow && bpf_x4b_netflow_xdp_record(ctx, 32, 1))
		x4b_count(X4B_BANSET_NETFLOW_ERROR);
	x4b_count(X4B_BANSET_DROP);
	return XDP_DROP;
}

SEC("xdp/x4b_banset")
int x4b_banset(struct xdp_md *ctx)
{
	return x4b_banset_lookup(ctx, 1);
}

SEC("xdp/x4b_banset_lookup")
int x4b_banset_lookup_only(struct xdp_md *ctx)
{
	return x4b_banset_lookup(ctx, 0);
}

SEC("xdp/x4b_pass")
int x4b_banset_pass(struct xdp_md *ctx)
{
	x4b_count(X4B_BANSET_PASS);
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
