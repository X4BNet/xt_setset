/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _XT_BANSET_H
#define _XT_BANSET_H

#include <linux/types.h>
#include <linux/netfilter/ipset/ip_set.h>

enum xt_banset_mode {
	XT_BANSET_MATCH = 0,
	XT_BANSET_REFRESH,
	XT_BANSET_ADD,
};

struct xt_banset_mtinfo {
	char setname[IPSET_MAXNAMELEN];
	__u32 probability;
	__u8 mode;
	__u8 flag;
	__u16 index;
	__u16 family;
	__u16 pad;

	/* Kernel-private state: excluded by userspacesize. */
	__aligned_u64 backend;
};

#endif /* _XT_BANSET_H */
