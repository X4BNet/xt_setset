#include <linux/netfilter/xt_set.h>

struct xt_setset_info_target {
	struct xt_set_info add_set;
	struct xt_set_info del_set;
	__u32 flags;
	__u32 timeout;
    __u32 ssflags;
	__u32 nth;
};


enum {
	SS_MATCH = 1
};