/* Xtables module to match packets using a BPF filter.
 * Copyright 2013 Google Inc.
 * Written by Willem de Bruijn <willemb@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <linux/net.h>
#include <linux/netfilter/xt_set.h>
#include <linux/netfilter/x_tables.h>
#include "xt_setset.h"

MODULE_AUTHOR("Mathew Heard <mheard@x4b.net>");
MODULE_DESCRIPTION("Xtables: Additional ipset matches");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_setset");
MODULE_ALIAS("ip6t_setset");

#define ADT_OPT(n, f, d, fs, cfs, t, p, b, po, bo)	\
struct ip_set_adt_opt n = {				\
	.family	= f,					\
	.dim = d,					\
	.flags = fs,					\
	.cmdflags = cfs,				\
	.ext.timeout = t,				\
	.ext.packets = p,				\
	.ext.bytes = b,					\
	.ext.packets_op = po,				\
	.ext.bytes_op = bo,				\
}

#define MOPT(opt, member)	((opt).ext.skbinfo.member)

static inline int
match_set(ip_set_id_t index, const struct sk_buff *skb,
	  const struct xt_action_param *par,
	  struct ip_set_adt_opt *opt, int inv)
{
	if (ip_set_test(index, skb, par, opt))
		inv = !inv;
	return inv;
}

static inline bool
setset_nth(__u32 nth){
	return (random32() & 0x7FFFFFFF) < nth;
}

static bool
setset_match(const struct sk_buff *_skb, struct xt_action_param *par)
{
	const struct xt_setset_info_target *info = par->targinfo;
	struct sk_buff *skb = (struct sk_buff *)_skb;
	int ret = 1;

	ADT_OPT(add_opt, xt_family(par), info->add_set.dim,
		info->add_set.flags, info->flags, info->timeout,
		0, 0, 0, 0);
		
	if (info->ssflags & SS_MATCH) {
		ret = match_set(info->add_set.index, skb, par, &add_opt,
				info->flags & IPSET_INV_MATCH);
	}

	if (info->add_set.index != IPSET_INVALID_ID && (ret || !(info->ssflags & SS_MATCH)) && setset_nth(info->nth)) {
		/* Normalize to fit into jiffies */
		if (add_opt.ext.timeout != IPSET_NO_TIMEOUT && add_opt.ext.timeout > IPSET_MAX_TIMEOUT)
			add_opt.ext.timeout = IPSET_MAX_TIMEOUT;

		ip_set_add(info->add_set.index, skb, par, &add_opt);
	}

	if (ret && info->del_set.index != IPSET_INVALID_ID){
		ADT_OPT(del_opt, xt_family(par), info->del_set.dim,
			info->del_set.flags, 0, UINT_MAX,
			0, 0, 0, 0);

		ip_set_del(info->del_set.index, skb, par, &del_opt);
	}

	
	if(!(info->ssflags & SS_MATCH)){
		ret = 1;
	}
	return ret;
}

static int
setset_match_checkentry(const struct xt_mtchk_param *par)
{
	struct xt_setset_info_target *info = par->matchinfo;
	ip_set_id_t index;
	int ret = 0;

	if (info->add_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(par->net,
						info->add_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_info_ratelimited("Cannot find add_set index %u as target\n",
					    info->add_set.index);
			return -ENOENT;
		}
	}

	if (info->del_set.index != IPSET_INVALID_ID) {
		index = ip_set_nfnl_get_byindex(par->net,
						info->del_set.index);
		if (index == IPSET_INVALID_ID) {
			pr_info_ratelimited("Cannot find del_set index %u as target\n",
					    info->del_set.index);
			ret = -ENOENT;
			goto cleanup_add;
		}
	}


	if (info->add_set.dim > IPSET_DIM_MAX ||
	    info->del_set.dim > IPSET_DIM_MAX) {
		pr_info_ratelimited("SET target dimension over the limit!\n");
		ret = -ERANGE;
		goto cleanup_del;
	}

	return 0;
cleanup_del:
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->del_set.index);
cleanup_add:
	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->add_set.index);
	return ret;
}

static void
setset_match_destroy(const struct xt_mtdtor_param *par)
{
	struct xt_setset_info_target *info = par->matchinfo;

	if (info->add_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->add_set.index);
	if (info->del_set.index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->del_set.index);
}


static struct xt_match setset_mt_reg[] __read_mostly = {
	{
		.name		= "setset",
		.family		= NFPROTO_IPV4,
		.revision	= 0,
		.match		= setset_match,
		.matchsize	= sizeof(struct xt_setset_info_target),
		.checkentry	= setset_match_checkentry,
		.destroy	= setset_match_destroy,
		.me		= THIS_MODULE
	},
	{
		.name		= "setset",
		.family		= NFPROTO_IPV6,
		.revision	= 0,
		.match		= setset_match,
		.matchsize	= sizeof(struct xt_setset_info_target),
		.checkentry	= setset_match_checkentry,
		.destroy	= setset_match_destroy,
		.me		= THIS_MODULE
	}
};

static int __init setset_mt_init(void)
{
	return xt_register_matches(setset_mt_reg, ARRAY_SIZE(setset_mt_reg));
}

static void __exit setset_mt_exit(void)
{
	xt_unregister_matches(setset_mt_reg, ARRAY_SIZE(setset_mt_reg));
}

module_init(setset_mt_init);
module_exit(setset_mt_exit);