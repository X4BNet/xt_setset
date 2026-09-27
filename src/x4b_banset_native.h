/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X4B_BANSET_NATIVE_H
#define _X4B_BANSET_NATIVE_H

#include <linux/types.h>

#include "compat_def.h"

#ifdef HAVE_X4B_HPFW_PROVIDER
#include <linux/x4b_hpfw.h>
#include <linux/x4b_rx_hook.h>

struct sk_buff;
struct xdp_buff;

#define X4B_BANSET_NATIVE_MAX_BATCH 64

struct x4b_banset_native_timing {
	u64 calls;
	u64 samples;
	u64 parse;
	u64 hash;
	u64 primary;
	u64 secondary;
	u64 refresh;
	u64 total;
};

u64 x4b_banset_match_skb_batch(struct sk_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode);
u64 x4b_banset_match_xdp_batch(struct xdp_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode);
u64 x4b_banset_match_frame_batch(const struct x4b_rx_frame_batch *batch,
					 struct x4b_rx_parse *parsed,
					 u32 refresh_threshold, u8 lookup_mode);
u64 x4b_banset_native_seq_retries(void);
u64 x4b_banset_native_refreshes(void);
void x4b_banset_native_timing_read(struct x4b_banset_native_timing *timing);
const struct x4b_hpfw_banset_provider *x4b_banset_hpfw_provider(void);
#endif

#endif
