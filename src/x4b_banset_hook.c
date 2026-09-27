// SPDX-License-Identifier: GPL-2.0-only
/* Native NAPI/i40e receive hook for the X4B banset backend. */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/x4b_rx_hook.h>
#include <net/xdp.h>
#if defined(CONFIG_X86_64)
#include <asm/msr.h>
#endif

#include "x4b_banset_native.h"

#define X4B_STATUS_BANNED 32
#define X4B_REFRESH_ONE_PERCENT 42949673U

extern int x4b_netflow_record_skb_native(struct sk_buff *skb, u8 fw_status,
					 bool noports);
extern int x4b_netflow_record_xdp_native(struct xdp_buff *xdp, u8 fw_status,
					 bool noports);
extern int x4b_netflow_record_frame_batch_native(
	const struct x4b_rx_frame_batch *batch, u64 hit_mask, u8 fw_status,
	bool noports);

static char *stage = "off";
module_param(stage, charp, 0444);
MODULE_PARM_DESC(stage, "receive stage: off, napi, i40e, early, or fused");

static uint batch_size = 1;
module_param(batch_size, uint, 0444);
MODULE_PARM_DESC(batch_size, "lookup batch size (1-64)");

static uint lookup_mode;
module_param(lookup_mode, uint, 0444);
MODULE_PARM_DESC(lookup_mode, "lookup: 0 scalar, 1 XMM keys, 2 YMM keys, 3 XMM signatures");

static bool netflow = true;
module_param(netflow, bool, 0444);
MODULE_PARM_DESC(netflow, "record status-32 NetFlow for hits");

static bool shared_parse = true;
module_param(shared_parse, bool, 0644);
MODULE_PARM_DESC(shared_parse, "reuse banset parse results in native NetFlow");

static uint refresh_threshold = X4B_REFRESH_ONE_PERCENT;
module_param(refresh_threshold, uint, 0644);
MODULE_PARM_DESC(refresh_threshold, "u32 sampled-expiry refresh threshold");

struct x4b_hook_stats {
	u64 packets;
	u64 batches;
	u64 hits;
	u64 netflow_errors;
	u64 raw_hits;
	u64 raw_misses;
	u64 direct_hits;
	u64 upstream_hits;
	u64 exceptional_fallbacks;
	u64 tsc_driver_samples;
	u64 tsc_driver_scan;
	u64 tsc_driver_consume;
	u64 tsc_netflow_samples;
	u64 tsc_netflow;
	u64 timing_calls;
	u64 batch_width[X4B_BANSET_NATIVE_MAX_BATCH + 1];
};

struct x4b_hook_scratch {
	struct x4b_rx_parse parsed[X4B_BANSET_NATIVE_MAX_BATCH];
};

static struct x4b_hook_stats __percpu *hook_stats;
static struct x4b_hook_scratch __percpu *hook_scratch;
static struct proc_dir_entry *stats_proc;
static int (*netflow_skb_fn)(struct sk_buff *, u8, bool);
static int (*netflow_xdp_fn)(struct xdp_buff *, u8, bool);
static int (*netflow_frame_batch_fn)(const struct x4b_rx_frame_batch *, u64,
				    u8, bool);

static u64 x4b_hook_skb_batch(struct sk_buff **packets, u32 count)
{
	u64 drops = 0;
	u32 base;

	for (base = 0; base < count; base += batch_size) {
		u32 i, n = min_t(u32, batch_size, count - base);
		u64 hits = x4b_banset_match_skb_batch(packets + base, n,
						       READ_ONCE(refresh_threshold),
						       lookup_mode);
		struct x4b_hook_stats *stats = this_cpu_ptr(hook_stats);

		stats->packets += n;
		stats->batches++;
		stats->batch_width[n]++;
		stats->hits += hweight64(hits);
		for (i = 0; netflow_skb_fn && i < n; i++)
			if ((hits & BIT_ULL(i)) &&
			    netflow_skb_fn(packets[base + i], X4B_STATUS_BANNED,
					   true))
				stats->netflow_errors++;
		drops |= hits << base;
	}
	return drops;
}

static u64 x4b_hook_xdp_batch(struct xdp_buff **packets, u32 count)
{
	u64 drops = 0;
	u32 base;

	for (base = 0; base < count; base += batch_size) {
		u32 n = min_t(u32, batch_size, count - base);
		u64 hits = x4b_banset_match_xdp_batch(packets + base, n,
						       READ_ONCE(refresh_threshold),
						       lookup_mode);
		struct x4b_hook_stats *stats = this_cpu_ptr(hook_stats);

		stats->packets += n;
		stats->batches++;
		stats->batch_width[n]++;
		drops |= hits << base;
	}
	return drops;
}

static u64 x4b_hook_frame_batch(const struct x4b_rx_frame_batch *batch)
{
	struct x4b_hook_stats *stats = this_cpu_ptr(hook_stats);
	struct x4b_hook_scratch *scratch = this_cpu_ptr(hook_scratch);
	struct x4b_rx_frame_batch netflow_batch = *batch;
	u64 netflow_started = 0;
	bool sample;
	u64 hits;
	u32 hit_count;

	stats->timing_calls++;
	sample = !(stats->timing_calls & 1023);
	hits = x4b_banset_match_frame_batch(batch,
					       shared_parse ? scratch->parsed : NULL,
					       READ_ONCE(refresh_threshold),
					       lookup_mode);
	hit_count = hweight64(hits);
	stats->packets += batch->count;
	stats->batches++;
	stats->batch_width[batch->count]++;
	stats->hits += hit_count;
	stats->raw_hits += hit_count;
	stats->raw_misses += batch->count - hit_count;
	if (batch->timing_sample) {
		stats->tsc_driver_samples++;
		stats->tsc_driver_scan += batch->scan_cycles;
	}
	if (!strcmp(stage, "fused"))
		stats->direct_hits += hit_count;
	else
		stats->upstream_hits += hit_count;
	if (netflow_frame_batch_fn && hits) {
		int errors;

		if (sample)
			netflow_started = rdtsc_ordered();
		netflow_batch.parsed = shared_parse ? scratch->parsed : NULL;
		errors = netflow_frame_batch_fn(&netflow_batch, hits, X4B_STATUS_BANNED,
						true);
		if (sample) {
			stats->tsc_netflow_samples++;
			stats->tsc_netflow += rdtsc_ordered() - netflow_started;
		}

		if (errors > 0)
			stats->netflow_errors += errors;
		else if (errors < 0)
			stats->netflow_errors++;
	}
	return hits;
}

static void x4b_hook_frame_consume_cycles(u64 cycles)
{
	this_cpu_ptr(hook_stats)->tsc_driver_consume += cycles;
}

static void x4b_hook_frame_fallback(u32 count)
{
	this_cpu_ptr(hook_stats)->exceptional_fallbacks += count;
}

static void x4b_hook_xdp_drop(struct xdp_buff *packet)
{
	struct x4b_hook_stats *stats = this_cpu_ptr(hook_stats);

	stats->hits++;
	if (netflow_xdp_fn &&
	    netflow_xdp_fn(packet, X4B_STATUS_BANNED, true))
		stats->netflow_errors++;
}

static struct x4b_rx_hook_ops hook_ops;

static int x4b_hook_stats_show(struct seq_file *seq, void *unused)
{
	struct x4b_hook_stats total = {};
	struct x4b_banset_native_timing timing;
	int cpu, width;

	for_each_possible_cpu(cpu) {
		const struct x4b_hook_stats *stats = per_cpu_ptr(hook_stats, cpu);

		total.packets += READ_ONCE(stats->packets);
		total.batches += READ_ONCE(stats->batches);
		total.hits += READ_ONCE(stats->hits);
		total.netflow_errors += READ_ONCE(stats->netflow_errors);
		total.raw_hits += READ_ONCE(stats->raw_hits);
		total.raw_misses += READ_ONCE(stats->raw_misses);
		total.direct_hits += READ_ONCE(stats->direct_hits);
		total.upstream_hits += READ_ONCE(stats->upstream_hits);
		total.exceptional_fallbacks +=
			READ_ONCE(stats->exceptional_fallbacks);
		total.tsc_driver_samples += READ_ONCE(stats->tsc_driver_samples);
		total.tsc_driver_scan += READ_ONCE(stats->tsc_driver_scan);
		total.tsc_driver_consume += READ_ONCE(stats->tsc_driver_consume);
		total.tsc_netflow_samples += READ_ONCE(stats->tsc_netflow_samples);
		total.tsc_netflow += READ_ONCE(stats->tsc_netflow);
		for (width = 1; width <= X4B_BANSET_NATIVE_MAX_BATCH; width++)
			total.batch_width[width] +=
				READ_ONCE(stats->batch_width[width]);
	}
	seq_printf(seq, "stage %s\nbatch_size %u\nlookup_mode %u\nnetflow %u\n",
		   stage, batch_size, lookup_mode, netflow);
	seq_printf(seq, "shared_parse %u\n", shared_parse);
	seq_printf(seq, "packets %llu\nbatches %llu\nhits %llu\nnetflow_errors %llu\n",
		   total.packets, total.batches, total.hits,
		   total.netflow_errors);
	seq_printf(seq, "raw_hits %llu\nraw_misses %llu\ndirect_hits %llu\n",
		   total.raw_hits, total.raw_misses, total.direct_hits);
	seq_printf(seq, "upstream_hits %llu\nexceptional_fallbacks %llu\n",
		   total.upstream_hits, total.exceptional_fallbacks);
	seq_printf(seq, "seq_retries %llu\n", x4b_banset_native_seq_retries());
	seq_printf(seq, "tsc_driver_samples %llu\ntsc_driver_scan %llu\n",
		   total.tsc_driver_samples, total.tsc_driver_scan);
	seq_printf(seq, "tsc_driver_consume %llu\ntsc_netflow_samples %llu\n",
		   total.tsc_driver_consume, total.tsc_netflow_samples);
	seq_printf(seq, "tsc_netflow %llu\n", total.tsc_netflow);
	x4b_banset_native_timing_read(&timing);
	seq_printf(seq, "tsc_calls %llu\ntsc_samples %llu\n",
		   timing.calls, timing.samples);
	seq_printf(seq, "tsc_parse %llu\ntsc_hash %llu\ntsc_primary %llu\n",
		   timing.parse, timing.hash, timing.primary);
	seq_printf(seq, "tsc_secondary %llu\ntsc_refresh %llu\ntsc_total %llu\n",
		   timing.secondary, timing.refresh, timing.total);
	for (width = 1; width <= X4B_BANSET_NATIVE_MAX_BATCH; width++)
		if (total.batch_width[width])
			seq_printf(seq, "batch_width_%d %llu\n", width,
				   total.batch_width[width]);
	return 0;
}

static int x4b_hook_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, x4b_hook_stats_show, NULL);
}

static const struct proc_ops x4b_hook_stats_ops = {
	.proc_open = x4b_hook_stats_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init x4b_banset_hook_init(void)
{
	int ret;

	hook_stats = alloc_percpu(struct x4b_hook_stats);
	if (!hook_stats)
		return -ENOMEM;
	hook_scratch = alloc_percpu(struct x4b_hook_scratch);
	if (!hook_scratch) {
		free_percpu(hook_stats);
		return -ENOMEM;
	}
	batch_size = clamp_t(uint, batch_size, 1,
			     X4B_BANSET_NATIVE_MAX_BATCH);
	lookup_mode = min_t(uint, lookup_mode, 3);
	if (netflow) {
		netflow_skb_fn = symbol_get(x4b_netflow_record_skb_native);
		netflow_xdp_fn = symbol_get(x4b_netflow_record_xdp_native);
		netflow_frame_batch_fn =
			symbol_get(x4b_netflow_record_frame_batch_native);
		if (!netflow_skb_fn || !netflow_xdp_fn ||
		    !netflow_frame_batch_fn) {
			ret = -ENODEV;
			goto put_symbols;
		}
	}
	if (!strcmp(stage, "napi"))
		hook_ops.skb_batch = x4b_hook_skb_batch;
	else if (!strcmp(stage, "i40e"))
		hook_ops.xdp_batch = x4b_hook_xdp_batch;
	else if (!strcmp(stage, "early") || !strcmp(stage, "early-prefetch") ||
		 !strcmp(stage, "fused"))
		hook_ops.frame_batch = x4b_hook_frame_batch;
	else if (strcmp(stage, "off")) {
		ret = -EINVAL;
		goto put_symbols;
	}
	hook_ops.xdp_batch_size = batch_size;
	hook_ops.frame_fallback = x4b_hook_frame_fallback;
	hook_ops.frame_consume_cycles = x4b_hook_frame_consume_cycles;
	if (!strcmp(stage, "early-prefetch") || !strcmp(stage, "fused"))
		hook_ops.frame_flags |= X4B_RX_FRAME_F_PREFETCH_HEADER;
	if (!strcmp(stage, "fused"))
		hook_ops.frame_flags |= X4B_RX_FRAME_F_DIRECT_CONSUME;
	hook_ops.xdp_drop = x4b_hook_xdp_drop;
	if (hook_ops.skb_batch || hook_ops.xdp_batch || hook_ops.frame_batch) {
		ret = x4b_rx_hook_register(&hook_ops);
		if (ret)
			goto put_symbols;
	}
	stats_proc = proc_create("x4b_banset_hook", 0444, NULL,
				 &x4b_hook_stats_ops);
	if (!stats_proc) {
		ret = -ENOMEM;
		goto unregister;
	}
	pr_info("stage=%s batch=%u lookup_mode=%u netflow=%u\n",
		stage, batch_size, lookup_mode, netflow);
	return 0;

unregister:
	if (hook_ops.skb_batch || hook_ops.xdp_batch || hook_ops.frame_batch)
		x4b_rx_hook_unregister(&hook_ops);
put_symbols:
	if (netflow_frame_batch_fn)
		symbol_put(x4b_netflow_record_frame_batch_native);
	if (netflow_xdp_fn)
		symbol_put(x4b_netflow_record_xdp_native);
	if (netflow_skb_fn)
		symbol_put(x4b_netflow_record_skb_native);
	free_percpu(hook_scratch);
	free_percpu(hook_stats);
	return ret;
}

static void __exit x4b_banset_hook_exit(void)
{
	proc_remove(stats_proc);
	if (hook_ops.skb_batch || hook_ops.xdp_batch || hook_ops.frame_batch)
		x4b_rx_hook_unregister(&hook_ops);
	if (netflow_frame_batch_fn)
		symbol_put(x4b_netflow_record_frame_batch_native);
	if (netflow_xdp_fn)
		symbol_put(x4b_netflow_record_xdp_native);
	if (netflow_skb_fn)
		symbol_put(x4b_netflow_record_skb_native);
	free_percpu(hook_scratch);
	free_percpu(hook_stats);
}

module_init(x4b_banset_hook_init);
module_exit(x4b_banset_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X4B.Net");
MODULE_DESCRIPTION("X4B native banset receive hook" " (" X4B_GIT_COMMIT ")");
MODULE_SOFTDEP("pre: xt_banset ipt_NETFLOW");
