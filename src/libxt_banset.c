/* SPDX-License-Identifier: GPL-2.0-only */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <xtables.h>

#include "xt_banset.h"

enum {
	O_SET = 0,
	O_MODE,
	O_PROBABILITY,
	O_FLAG,
};

static int banset_get_version(unsigned int *version)
{
	struct ip_set_req_version request;
	socklen_t size = sizeof(request);
	int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	if (fd < 0)
		xtables_error(OTHER_PROBLEM, "banset: cannot open ipset socket");
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
		xtables_error(OTHER_PROBLEM, "banset: cannot set close-on-exec");
	request.op = IP_SET_OP_VERSION;
	if (getsockopt(fd, SOL_IP, SO_IP_SET, &request, &size))
		xtables_error(OTHER_PROBLEM, "banset: ipset kernel API unavailable");
	*version = request.version;
	return fd;
}

static void banset_resolve(const char *name, struct xt_banset_mtinfo *info)
{
	struct ip_set_req_get_set_family request = {};
	socklen_t size = sizeof(request);
	unsigned int version;
	int fd = banset_get_version(&version);

	request.op = IP_SET_OP_GET_FNAME;
	request.version = version;
	snprintf(request.set.name, sizeof(request.set.name), "%s", name);
	if (getsockopt(fd, SOL_IP, SO_IP_SET, &request, &size)) {
		int saved = errno;

		close(fd);
		xtables_error(PARAMETER_PROBLEM,
			      "banset: cannot resolve set %s: %s", name,
			      strerror(saved));
	}
	close(fd);
	if (request.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM, "banset: set %s does not exist", name);
	info->index = request.set.index;
	info->family = request.family;
}

static const struct xt_option_entry banset_opts[] = {
	{ .name = "ban-set", .id = O_SET, .type = XTTYPE_STRING,
	  .flags = XTOPT_MAND },
	{ .name = "ban-mode", .id = O_MODE, .type = XTTYPE_STRING },
	{ .name = "ban-probability", .id = O_PROBABILITY,
	  .type = XTTYPE_DOUBLE, .min = 0, .max = 1 },
	{ .name = "ban-flag", .id = O_FLAG, .type = XTTYPE_UINT8 },
	XTOPT_TABLEEND,
};

static void banset_help(void)
{
	printf(
		"banset match options:\n"
		"  --ban-set name\n"
		"  --ban-mode match|refresh|add\n"
		"  --ban-probability 0..1\n"
		"  --ban-flag 0..255\n");
}

static void banset_init(struct xt_entry_match *match)
{
	struct xt_banset_mtinfo *info = (void *)match->data;

	info->mode = XT_BANSET_MATCH;
	info->probability = UINT32_MAX;
}

static void banset_parse(struct xt_option_call *cb)
{
	struct xt_banset_mtinfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_SET:
		if (strlen(cb->arg) >= sizeof(info->setname))
			xtables_error(PARAMETER_PROBLEM, "banset: set name is too long");
		strcpy(info->setname, cb->arg);
		banset_resolve(info->setname, info);
		break;
	case O_MODE:
		if (!strcmp(cb->arg, "match"))
			info->mode = XT_BANSET_MATCH;
		else if (!strcmp(cb->arg, "refresh"))
			info->mode = XT_BANSET_REFRESH;
		else if (!strcmp(cb->arg, "add"))
			info->mode = XT_BANSET_ADD;
		else
			xtables_error(PARAMETER_PROBLEM,
				      "banset: mode must be match, refresh, or add");
		break;
	case O_PROBABILITY:
		if (cb->val.dbl >= 1.0)
			info->probability = UINT32_MAX;
		else
			info->probability = (__u32)(cb->val.dbl * 4294967296.0);
		break;
	case O_FLAG:
		info->flag = cb->val.u8;
		break;
	}
}

static void banset_check(struct xt_fcheck_call *cb)
{
	const struct xt_banset_mtinfo *info = cb->data;

	if (!info->setname[0])
		xtables_error(PARAMETER_PROBLEM, "banset: --ban-set is required");
	if (info->mode == XT_BANSET_MATCH &&
	    (cb->xflags & ((1U << O_PROBABILITY) | (1U << O_FLAG))))
		xtables_error(PARAMETER_PROBLEM,
			      "banset: probability and flag require refresh or add mode");
	if (info->mode == XT_BANSET_REFRESH && (cb->xflags & (1U << O_FLAG)))
		xtables_error(PARAMETER_PROBLEM,
			      "banset: --ban-flag is valid only in add mode");
}

static const char *banset_mode_name(__u8 mode)
{
	switch (mode) {
	case XT_BANSET_REFRESH:
		return "refresh";
	case XT_BANSET_ADD:
		return "add";
	default:
		return "match";
	}
}

static void banset_print_common(const struct xt_banset_mtinfo *info,
				bool save)
{
	const char *prefix = save ? " --" : " ";

	printf("%sban-set %s%sban-mode %s", prefix, info->setname,
	       prefix, banset_mode_name(info->mode));
	if (info->mode != XT_BANSET_MATCH)
		printf("%sban-probability %.11f", prefix,
		       info->probability == UINT32_MAX ? 1.0 :
		       (double)info->probability / 4294967296.0);
	if (info->mode == XT_BANSET_ADD)
		printf("%sban-flag %u", prefix, info->flag);
}

static void banset_print(const void *ip, const struct xt_entry_match *match,
			 int numeric)
{
	banset_print_common((const void *)match->data, false);
}

static void banset_save(const void *ip, const struct xt_entry_match *match)
{
	banset_print_common((const void *)match->data, true);
}

static struct xtables_match banset_mt_reg = {
	.family = NFPROTO_UNSPEC,
	.name = "banset",
	.version = XTABLES_VERSION,
	.size = XT_ALIGN(sizeof(struct xt_banset_mtinfo)),
	.userspacesize = XT_ALIGN(offsetof(struct xt_banset_mtinfo, backend)),
	.help = banset_help,
	.init = banset_init,
	.x6_parse = banset_parse,
	.x6_fcheck = banset_check,
	.print = banset_print,
	.save = banset_save,
	.x6_options = banset_opts,
};

void _init(void)
{
	xtables_register_match(&banset_mt_reg);
}
