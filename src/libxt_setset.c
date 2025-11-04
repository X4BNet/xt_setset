/*
 * Xtables BPF extension
 *
 * Mathew Heard (mheard@x4b.net)
*/

#include <linux/netfilter/xt_set.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <xtables.h>
#include <math.h>
#include "xt_setset.h"

#define SET_TARGET_ADD		0x1
#define SET_TARGET_DEL		0x2
#define SET_TARGET_EXIST	0x4
#define SET_TARGET_TIMEOUT	0x8
#define SET_TARGET_MAP		0x10
#define SET_TARGET_MAP_MARK	0x20
#define SET_TARGET_MAP_PRIO	0x40
#define SET_TARGET_MAP_QUEUE	0x80

static void
setset_match_help(void)
{
	printf("setset match options:\n"
	       " --ss-add-set name flags [--ss-exist] [--ss-timeout n]\n"
	       " --ss-del-set name flags\n"
			" [--ss-nocreate] [--ss-match] [--ss-probability nth] [--ss-packets-gt pkts]\n"
	       " [--ss-map-mark] [--ss-map-prio] [--ss-map-queue] [--ss-flag flag]\n"
	       "		add/del src/dst IP/port from/to named sets,\n"
	       "		where flags are the comma separated list of\n"
	       "		'src' and 'dst' specifications.\n");
}

enum {
	O_ADD_SET,
	O_DEL_SET,
	O_EXIST,
	O_TIMEOUT,
	O_MATCH,
	O_PROBABILITY,
	O_GT,
	O_NOCREATE,
	O_FLAG
};

static const struct xt_option_entry setset_match_opts[] = {
	{.name = "ss-add-set",	.type = XTTYPE_STRING,  .id = O_ADD_SET},
	{.name = "ss-del-set",	.type = XTTYPE_STRING,  .id = O_DEL_SET},
	{.name = "ss-exist",	.type = XTTYPE_NONE, .id = O_EXIST},
	{.name = "ss-timeout",	.type = XTTYPE_UINT32,  .id = O_TIMEOUT},
	/*{.name = "ss-map-set",	.has_arg = true,  .id = '5'},
	{.name = "ss-map-mark",	.has_arg = false, .id = '6'},
	{.name = "ss-map-prio",	.has_arg = false, .id = '7'},
	{.name = "ss-map-queue",	.has_arg = false, .id = '8'}*/
	{.name = "ss-flag",	.type = XTTYPE_UINT8, .id = O_FLAG},
	{.name = "ss-packets-gt",	.type = XTTYPE_UINT32, .id = O_GT},
	{.name = "ss-match",	.type = XTTYPE_NONE, .id = O_MATCH},
	{.name = "ss-probability",	.type = XTTYPE_STRING, .id = O_PROBABILITY},
	{.name = "ss-nocreate",	.type = XTTYPE_NONE, .id = O_NOCREATE},
	XTOPT_TABLEEND,
};

static int
get_version(unsigned *version)
{
	int res, sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	struct ip_set_req_version req_version;
	socklen_t size = sizeof(req_version);
	
	if (sockfd < 0)
		xtables_error(OTHER_PROBLEM,
			      "Can't open socket to ipset.\n");

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		xtables_error(OTHER_PROBLEM,
			      "Could not set close on exec: %s\n",
			      strerror(errno));
	}

	req_version.op = IP_SET_OP_VERSION;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req_version, &size);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			      "Kernel module xt_set is not loaded in.\n");

	*version = req_version.version;
	
	return sockfd;
}


static void
get_set_byid(char *setname, ip_set_id_t idx)
{
	struct ip_set_req_get_set req;
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res, sockfd;

	sockfd = get_version(&req.version);
	req.op = IP_SET_OP_GET_BYINDEX;
	req.set.index = idx;
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.name[0] == '\0')
		xtables_error(PARAMETER_PROBLEM,
			"Set with index %i in kernel doesn't exist.\n", idx);

	strncpy(setname, req.set.name, IPSET_MAXNAMELEN);
}

static void
get_set_byname_only(const char *setname, struct xt_set_info *info,
		    int sockfd, unsigned int version)
{
	struct ip_set_req_get_set req = { .version = version };
	socklen_t size = sizeof(struct ip_set_req_get_set);
	int res;

	req.op = IP_SET_OP_GET_BYNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);
	close(sockfd);

	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set), (size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);

	info->index = req.set.index;
}

static void
get_set_byname(const char *setname, struct xt_set_info *info)
{
	struct ip_set_req_get_set_family req;
	socklen_t size = sizeof(struct ip_set_req_get_set_family);
	int res, sockfd, version;

	sockfd = get_version(&req.version);
	version = req.version;
	req.op = IP_SET_OP_GET_FNAME;
	strncpy(req.set.name, setname, IPSET_MAXNAMELEN);
	req.set.name[IPSET_MAXNAMELEN - 1] = '\0';
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, &req, &size);

	if (res != 0 && errno == EBADMSG)
		/* Backward compatibility */
		return get_set_byname_only(setname, info, sockfd, version);

	close(sockfd);
	if (res != 0)
		xtables_error(OTHER_PROBLEM,
			"Problem when communicating with ipset, errno=%d.\n",
			errno);
	if (size != sizeof(struct ip_set_req_get_set_family))
		xtables_error(OTHER_PROBLEM,
			"Incorrect return size from kernel during ipset lookup, "
			"(want %zu, got %zu)\n",
			sizeof(struct ip_set_req_get_set_family),
			(size_t)size);
	if (req.set.index == IPSET_INVALID_ID)
		xtables_error(PARAMETER_PROBLEM,
			      "Set %s doesn't exist.\n", setname);

	info->index = req.set.index;
}


static void
parse_dirs(const char *opt_arg, struct xt_set_info *info)
{
	char *saved = strdup(opt_arg);
	char *ptr, *tmp = saved;
	
	while (info->dim < IPSET_DIM_MAX && tmp != NULL) {
		info->dim++;
		ptr = strsep(&tmp, ",");
		if (strncmp(ptr, "src", 3) == 0)
			info->flags |= (1 << info->dim);
		else if (strncmp(ptr, "dst", 3) != 0)
			xtables_error(PARAMETER_PROBLEM,
				"You must spefify (the comma separated list of) 'src' or 'dst'.");
	}

	if (tmp)
		xtables_error(PARAMETER_PROBLEM,
			      "Can't be more src/dst options than %i.", 
			      IPSET_DIM_MAX);

	free(saved);
}

static void
setset_match_check(unsigned int flags)
{
	if (!(flags & (SET_TARGET_ADD|SET_TARGET_DEL|SET_TARGET_MAP)))
		xtables_error(PARAMETER_PROBLEM,
			      "You must specify either `--ss-add-set' or "
			      "`--ss-del-set'");
	if (!(flags & SET_TARGET_ADD)) {
		if (flags & SET_TARGET_EXIST)
			xtables_error(PARAMETER_PROBLEM,
				"Flag `--ss-exist' can be used with `--ss-add-set' only");
		if (flags & SET_TARGET_TIMEOUT)
			xtables_error(PARAMETER_PROBLEM,
				"Option `--ss-timeout' can be used with `--ss-add-set' only");
	}
}

static void
setset_match_init(struct xt_entry_match *target)
{
	struct xt_setset_info_target *info =
		(struct xt_setset_info_target *) target->data;

	info->add_set.index = info->del_set.index = IPSET_INVALID_ID;
	info->timeout = UINT32_MAX;
}

static void
parse_target(char **argv, int invert, struct xt_set_info *info,
	     const char *what)
{
	if (info->dim)
		xtables_error(PARAMETER_PROBLEM,
			      "--%s can be specified only once", what);
	if (!argv[optind]
	    || argv[optind][0] == '-' || argv[optind][0] == '!')
		xtables_error(PARAMETER_PROBLEM,
			      "--%s requires two args.", what);

	if (strlen(optarg) > IPSET_MAXNAMELEN - 1)
		xtables_error(PARAMETER_PROBLEM,
			      "setname `%s' too long, max %d characters.",
			      optarg, IPSET_MAXNAMELEN - 1);

	get_set_byname(optarg, info);
	parse_dirs(argv[optind], info);
	optind++;
}


static int
setset_match_parse(int c, char **argv, int invert, unsigned int *flags,
		    const void *entry, struct xt_entry_match **target)
{
	struct xt_setset_info_target *myinfo =
		(struct xt_setset_info_target *) (*target)->data;
	unsigned int timeout, gt;

	switch (c) {
	case O_ADD_SET:		/* --add-set <set> <flags> */
		parse_target(argv, invert, &myinfo->add_set, "ss-add-set");
		*flags |= SET_TARGET_ADD;
		break;
	case O_DEL_SET:		/* --del-set <set>[:<flags>] <flags> */
		parse_target(argv, invert, &myinfo->del_set, "ss-del-set");
		*flags |= SET_TARGET_DEL;
		break;
	case O_EXIST:
		myinfo->flags |= IPSET_FLAG_EXIST;
		*flags |= SET_TARGET_EXIST;
		break;
	case O_TIMEOUT:
		if (!xtables_strtoui(optarg, NULL, &timeout, 0, UINT32_MAX - 1))
			xtables_error(PARAMETER_PROBLEM,
				      "Invalid value for option --timeout "
				      "or out of range 0-%u", UINT32_MAX - 1);
		myinfo->timeout = timeout;
		*flags |= SET_TARGET_TIMEOUT;
		break;
	case O_MATCH:
		myinfo->ssflags |= SS_MATCH;
		if(invert){
			myinfo->ssflags |= SS_INV;
		}
		break;
	case O_FLAG:
		if (!xtables_strtoui(optarg, NULL, &timeout, 0, UINT8_MAX - 1)){
			xtables_error(PARAMETER_PROBLEM,
				      "Invalid value for option --ss-flag "
				      "or out of range 0-%u", UINT8_MAX - 1);
					  return 0;
		}
		myinfo->flag = (uint8_t)timeout;
		myinfo->ssflags |= SS_FLAG;
		break;
	case O_PROBABILITY:
  		myinfo->probability = lround(0x80000000 * strtod(optarg, NULL));
		break;
	case O_NOCREATE:
  		myinfo->ssflags |= SS_NOCREATE;
		break;
	case O_GT:
		if (!xtables_strtoui(optarg, NULL, &gt, 0, UINT32_MAX - 1))
				xtables_error(PARAMETER_PROBLEM,
						"Invalid value for option --ss-packets-gt "
						"or out of range 0-%u", UINT32_MAX - 1);
		myinfo->gt = gt;
		break;
	}
	return 1;
}

static void
print_match(const char *prefix, const struct xt_set_info *info)
{
	int i;
	char setname[IPSET_MAXNAMELEN];
	
	if (info->index == IPSET_INVALID_ID)
		return;

	get_set_byid(setname, info->index);
	printf(" %s %s",
	       prefix,
	       setname); 
	for (i = 1; i <= info->dim; i++) {		
		printf("%s%s",
		       i == 1 ? " " : ",",
		       info->flags & (1 << i) ? "src" : "dst");
	}
}

static void
setset_match_print(const void *ip, const struct xt_entry_match *target,
		    int numeric)
{
	const struct xt_setset_info_target *info = (const void *)target->data;

	print_match("ss-add-set", &info->add_set);
	if (info->flags & IPSET_FLAG_EXIST)
		printf(" ss-exist");
	if (info->timeout != UINT32_MAX)
		printf(" ss-timeout %u", info->timeout);
	print_match("ss-del-set", &info->del_set);
	if (info->flags & IPSET_FLAG_MAP_SKBMARK)
		printf(" ss-map-mark");
	if (info->flags & IPSET_FLAG_MAP_SKBPRIO)
		printf(" ss-map-prio");
	if (info->flags & IPSET_FLAG_MAP_SKBQUEUE)
		printf(" ss-map-queue");
	if(info->ssflags & SS_MATCH)
		printf(" ss-match");
	if(info->ssflags & SS_INV)
		printf("-inv");
	if (info->ssflags & SS_NOCREATE)
		printf(" ss-nocreate");
	if(info->probability != 0)
		printf(" ss-probability %.11f", 
		       1.0 * info->probability / 0x80000000);
	if(info->gt)
		printf(" ss-packets-gt %u", info->gt);

	if(info->ssflags & SS_FLAG){
		printf(" ss-flag %u", info->flag);
	}
}

static void
setset_match_save(const void *ip, const struct xt_entry_match *target)
{
	const struct xt_setset_info_target *info = (const void *)target->data;

	print_match("--ss-add-set", &info->add_set);
	if (info->flags & IPSET_FLAG_EXIST)
		printf(" --ss-exist");
	if (info->timeout != UINT32_MAX)
		printf(" --ss-timeout %u", info->timeout);
	print_match("--ss-del-set", &info->del_set);
	if (info->flags & IPSET_FLAG_MAP_SKBMARK)
		printf(" --ss-map-mark");
	if (info->flags & IPSET_FLAG_MAP_SKBPRIO)
		printf(" --ss-map-prio");
	if (info->flags & IPSET_FLAG_MAP_SKBQUEUE)
		printf(" --ss-map-queue");
	if (info->ssflags & SS_INV)
		printf(" !");
	if (info->ssflags & SS_MATCH)
		printf(" --ss-match");
	if (info->ssflags & SS_NOCREATE)
		printf(" --ss-nocreate");
	if(info->probability != 0)
		printf(" --ss-probability %.11f", 
		       1.0 * info->probability / 0x80000000);
	if(info->gt)
		printf(" --ss-packets-gt %u", info->gt);
	if(info->ssflags & SS_FLAG){
		printf(" --ss-flag %u", info->flag);
	}
}

static struct xtables_match setset_match[] = {
	{
		.name		= "setset",
		.revision	= 0,
		.version	= XTABLES_VERSION,
		.family		= NFPROTO_UNSPEC,
		.size		= XT_ALIGN(sizeof(struct xt_setset_info_target)),
		.userspacesize	= offsetof(struct xt_setset_info_target, cooldown),
		.init       = setset_match_init,
		.help		= setset_match_help,
		.parse		= setset_match_parse,
		.final_check	= setset_match_check,
		.print		= setset_match_print,
		.save		= setset_match_save,
		.x6_options	= setset_match_opts,
	},
};

static void __attribute__((constructor)) _init(void)
{
	xtables_register_match(setset_match);
}
