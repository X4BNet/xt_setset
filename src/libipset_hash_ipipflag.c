/* SPDX-License-Identifier: GPL-2.0-only */
#include <libipset/data.h>
#include <libipset/parse.h>
#include <libipset/print.h>
#include <libipset/types.h>
#include <stdlib.h>

#define BANSET_REVISIONS 6

static struct ipset_type *banset_types[BANSET_REVISIONS];

static void banset_type_init(struct ipset_type *type, unsigned int revision)
{
	*type = (struct ipset_type) {
		.name = "hash:ip,ip,flag",
		.revision = revision,
		.family = NFPROTO_IPSET_IPV46,
		.dimension = IPSET_DIM_THREE,
		.elem = {
			[IPSET_DIM_ONE - 1] = {
				.parse = ipset_parse_ip4_single6,
				.print = ipset_print_ip,
				.opt = IPSET_OPT_IP,
			},
			[IPSET_DIM_TWO - 1] = {
				.parse = ipset_parse_single_ip,
				.print = ipset_print_ip,
				.opt = IPSET_OPT_IP2,
			},
			[IPSET_DIM_THREE - 1] = {
				.parse = ipset_parse_single_tcp_port,
				.print = ipset_print_port,
				.opt = IPSET_OPT_PORT,
			},
		},
		.cmd = {
			[IPSET_CREATE] = {
				.args = {
					IPSET_ARG_FAMILY,
					IPSET_ARG_INET,
					IPSET_ARG_INET6,
					IPSET_ARG_HASHSIZE,
					IPSET_ARG_MAXELEM,
					IPSET_ARG_TIMEOUT,
					IPSET_ARG_PROBES,
					IPSET_ARG_RESIZE,
					IPSET_ARG_NONE,
				},
				.help = "family inet|inet6 timeout VALUE [maxelem VALUE]",
			},
			[IPSET_ADD] = {
				.args = { IPSET_ARG_TIMEOUT, IPSET_ARG_NONE },
				.need = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.full = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.help = "IP,IP,FLAG",
			},
			[IPSET_DEL] = {
				.args = { IPSET_ARG_NONE },
				.need = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.full = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.help = "IP,IP,FLAG",
			},
			[IPSET_TEST] = {
				.args = { IPSET_ARG_NONE },
				.need = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.full = IPSET_FLAG(IPSET_OPT_IP) |
					IPSET_FLAG(IPSET_OPT_IP2) |
					IPSET_FLAG(IPSET_OPT_PORT),
				.help = "IP,IP,FLAG",
			},
		},
		.usage = "Exact source IP, destination IP, and 8-bit flag. "
			 "A positive timeout is mandatory.",
		.description = "X4B direct banset compatibility type",
	};
}

void _init(void);
void _init(void)
{
	unsigned int revision;

	for (revision = 0; revision < BANSET_REVISIONS; revision++) {
		struct ipset_type *type;

		type = calloc(1, sizeof(*type) + 2 * sizeof(type->alias[0]));
		if (!type)
			return;
		banset_types[revision] = type;
		banset_type_init(type, revision);
		type->alias[0] = "ipipflaghash";
		ipset_type_add(type);
	}
}
