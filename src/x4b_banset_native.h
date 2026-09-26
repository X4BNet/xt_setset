/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _X4B_BANSET_NATIVE_H
#define _X4B_BANSET_NATIVE_H

#include <linux/types.h>
#include <linux/x4b_rx_hook.h>

struct sk_buff;
struct xdp_buff;

#define X4B_BANSET_NATIVE_MAX_BATCH 64

u64 x4b_banset_match_skb_batch(struct sk_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode);
u64 x4b_banset_match_xdp_batch(struct xdp_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode);
u64 x4b_banset_match_frame_batch(const struct x4b_rx_frame *packets,
					 u32 count, u32 refresh_threshold,
					 u8 lookup_mode);
u64 x4b_banset_native_seq_retries(void);

#endif
