// SPDX-License-Identifier: GPL-2.0-only
/* X4B exact source/destination ban table and direct xtables match. */

#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/hash.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/seqlock.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "compat_def.h"

#ifdef HAVE_X4B_HPFW_PROVIDER
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/x4b_hpfw.h>
#endif

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#ifdef HAVE_X4B_HPFW_PROVIDER
#include <net/xdp.h>
#endif

#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#include <asm/msr.h>
#include <asm/simd.h>
#endif

#include "xt_banset.h"
#ifdef HAVE_X4B_HPFW_PROVIDER
#include "x4b_banset_native.h"
#endif

#define BANSET_REV_MIN 0
#define BANSET_REV_MAX 5
#define BANSET_SLOTS 8U
#define BANSET_INITIAL_CAPACITY (1U << 18)
#define BANSET_MAX_CAPACITY (1U << 21)
#define BANSET_BFS_MAX 1000U
#define BANSET_EPOCH_SHIFT 5
#define BANSET_EPOCH_SECONDS (1U << BANSET_EPOCH_SHIFT)
/* u16 epochs are compared as s16; reserve one partial starting epoch. */
#define BANSET_MAX_TIMEOUT \
	((u32)S16_MAX * BANSET_EPOCH_SECONDS - (BANSET_EPOCH_SECONDS - 1U))
#define BANSET_DEFAULT_TTL 600U

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X4B.Net");
MODULE_DESCRIPTION("X4B direct exact-pair ban set" " (" X4B_GIT_COMMIT ")");
MODULE_ALIAS("ip_set_hash:ip,ip,flag");
MODULE_ALIAS("ip_set_hash_ipipflag");
MODULE_ALIAS("ipt_banset");
MODULE_ALIAS("ip6t_banset");

struct banset4_key {
	__be32 src;
	__be32 dst;
};

struct banset6_key {
	struct in6_addr src;
	struct in6_addr dst;
};

union banset_key {
	struct banset4_key v4;
	struct banset6_key v6;
};

struct banset4_bucket {
	struct banset4_key key[BANSET_SLOTS];
} __aligned(64);

/* One cache line supplies all filters and live state for an IPv4 bucket. */
struct banset4_meta {
	u16 signature[BANSET_SLOTS];
	u32 state[BANSET_SLOTS];
	u8 padding[16];
} __aligned(64);

struct banset_bfs_node {
	u32 bucket;
	s32 parent;
	u8 parent_slot;
};

struct banset_table {
	spinlock_t lock;
	seqcount_spinlock_t seq;
	refcount_t refs;
	u32 seed;
	u32 capacity;
	u32 bucket_mask;
	u8 family;
	struct banset_table *growing;
	struct banset4_bucket *v4;
	struct banset4_meta *v4_meta;
	struct banset6_key *v6;
	u16 *signature;
	u32 *state;
	u16 *expires;
	u8 *flags;
	u8 *occupied;
	struct banset_bfs_node *bfs;
};

struct banset {
	struct banset_table __rcu *table;
	struct mutex resize_mutex;
	spinlock_t update_lock;
	struct work_struct grow_work;
	struct delayed_work gc_work;
	atomic_t elements;
	u32 maxelem;
	u32 timeout;
	u8 family;
};

struct banset_binding {
	/* Keep ipset name ownership independent of backend storage across swap. */
	struct ip_set *set;
	struct net *net;
	u8 family;
	struct list_head bindings;
};

struct banset4_elem {
	__be32 src;
	__be32 dst;
	u8 flag;
};

struct banset6_elem {
	struct in6_addr src;
	struct in6_addr dst;
	u8 flag;
};

static LIST_HEAD(banset_bindings);
static DEFINE_MUTEX(banset_bindings_lock);
static bool full_alt = true;
module_param(full_alt, bool, 0444);
MODULE_PARM_DESC(full_alt, "spread alternate buckets across the full table");
static bool packed_meta;
module_param(packed_meta, bool, 0644);
MODULE_PARM_DESC(packed_meta, "co-locate IPv4 signatures and state by bucket");
#ifdef HAVE_X4B_HPFW_PROVIDER
static uint prefetch_distance = 8;
module_param(prefetch_distance, uint, 0644);
MODULE_PARM_DESC(prefetch_distance, "IPv4 batch lookup prefetch distance");
static bool primary_first = true;
module_param(primary_first, bool, 0644);
MODULE_PARM_DESC(primary_first, "batch primary buckets before secondary misses");
static bool homogeneous_batch = true;
module_param(homogeneous_batch, bool, 0644);
MODULE_PARM_DESC(homogeneous_batch, "specialize raw batches for one IPv4 table");
static bool fast_prng = true;
module_param(fast_prng, bool, 0644);
MODULE_PARM_DESC(fast_prng, "use a securely seeded per-CPU PRNG for refresh sampling");
static uint timing_shift = 10;
module_param(timing_shift, uint, 0644);
MODULE_PARM_DESC(timing_shift, "sample one native batch in 2^N for TSC accounting");
static atomic64_t native_seq_retries = ATOMIC64_INIT(0);

struct banset_native_timing_cpu {
	u64 calls;
	u64 samples;
	u64 refreshes;
	u64 parse;
	u64 hash;
	u64 primary;
	u64 secondary;
	u64 refresh;
	u64 total;
};

static struct banset_native_timing_cpu __percpu *banset_native_timing;

static __always_inline u64 banset_cycles(void)
{
#if defined(CONFIG_X86_64)
	return rdtsc_ordered();
#else
	return 0;
#endif
}
#endif

static inline u16 banset_epoch(void)
{
	return (u16)(ktime_get_boottime_seconds() >> BANSET_EPOCH_SHIFT);
}

static inline u16 banset_expiry(u32 timeout)
{
	u64 expires = ktime_get_boottime_seconds() + timeout;

	return (u16)((expires + BANSET_EPOCH_SECONDS - 1) >>
		     BANSET_EPOCH_SHIFT);
}

static inline bool banset_expired(u16 expires, u16 now)
{
	return (s16)(expires - now) <= 0;
}

static inline u32 banset_state_pack(u16 expires, u8 flag)
{
	return expires | ((u32)flag << 16);
}

static inline u16 banset_expires_read(const struct banset_table *table,
				      u32 index)
{
	if (table->v4_meta)
		return (u16)READ_ONCE(table->v4_meta[index / BANSET_SLOTS].
					 state[index % BANSET_SLOTS]);
	if (table->family == NFPROTO_IPV4)
		return (u16)READ_ONCE(table->state[index]);
	return READ_ONCE(table->expires[index]);
}

static inline u8 banset_flag_read(const struct banset_table *table, u32 index)
{
	if (table->v4_meta)
		return READ_ONCE(table->v4_meta[index / BANSET_SLOTS].
				 state[index % BANSET_SLOTS]) >> 16;
	if (table->family == NFPROTO_IPV4)
		return READ_ONCE(table->state[index]) >> 16;
	return READ_ONCE(table->flags[index]);
}

static inline void banset_state_write(struct banset_table *table, u32 index,
				      u16 expires, u8 flag)
{
	if (table->v4_meta)
		WRITE_ONCE(table->v4_meta[index / BANSET_SLOTS].
			   state[index % BANSET_SLOTS],
			   banset_state_pack(expires, flag));
	else if (table->family == NFPROTO_IPV4)
		WRITE_ONCE(table->state[index], banset_state_pack(expires, flag));
	else {
		WRITE_ONCE(table->expires[index], expires);
		WRITE_ONCE(table->flags[index], flag);
	}
}

static inline void banset_expiry_write(struct banset_table *table, u32 index,
				       u16 expires)
{
	banset_state_write(table, index, expires, banset_flag_read(table, index));
}

static size_t banset_table_memsize(const struct banset_table *table)
{
	u32 buckets = table->bucket_mask + 1;
	size_t size = sizeof(*table) + BANSET_BFS_MAX * sizeof(*table->bfs);

	if (table->family == NFPROTO_IPV4) {
		size += (size_t)buckets * sizeof(*table->v4);
		if (table->v4_meta)
			size += (size_t)buckets * sizeof(*table->v4_meta);
		else
			size += (size_t)table->capacity *
				(sizeof(*table->signature) + sizeof(*table->state)) +
				(size_t)buckets * sizeof(*table->occupied);
	} else
		size += (size_t)table->capacity *
			(sizeof(*table->v6) + sizeof(*table->expires) +
			 sizeof(*table->flags) + sizeof(*table->signature)) +
			 (size_t)buckets * sizeof(*table->occupied);
	return size;
}

static void banset_table_free(struct banset_table *table)
{
	if (!table)
		return;
	kvfree(table->v4);
	kvfree(table->v4_meta);
	kvfree(table->v6);
	kvfree(table->signature);
	kvfree(table->state);
	kvfree(table->expires);
	kvfree(table->flags);
	kvfree(table->occupied);
	kfree(table->bfs);
	kfree(table);
}

static void banset_table_put(struct banset_table *table)
{
	if (table && refcount_dec_and_test(&table->refs))
		banset_table_free(table);
}

static struct banset_table *
banset_table_create(u8 family, u32 capacity, u32 seed)
{
	struct banset_table *table;
	u32 buckets;

	capacity = roundup_pow_of_two(max_t(u32, capacity, BANSET_SLOTS));
	capacity = min_t(u32, capacity, BANSET_MAX_CAPACITY);
	buckets = capacity / BANSET_SLOTS;
	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return NULL;
	if (family == NFPROTO_IPV4) {
		table->v4 = kvcalloc(buckets, sizeof(*table->v4), GFP_KERNEL);
		if (packed_meta)
			table->v4_meta = kvcalloc(buckets,
						 sizeof(*table->v4_meta), GFP_KERNEL);
		else
			table->state = kvcalloc(capacity, sizeof(*table->state),
						 GFP_KERNEL);
	} else {
		table->v6 = kvcalloc(capacity, sizeof(*table->v6), GFP_KERNEL);
		table->expires = kvcalloc(capacity, sizeof(*table->expires),
					  GFP_KERNEL);
		table->flags = kvcalloc(capacity, sizeof(*table->flags), GFP_KERNEL);
	}
	if (family != NFPROTO_IPV4 || !packed_meta) {
		table->signature = kvcalloc(capacity, sizeof(*table->signature),
					    GFP_KERNEL);
		table->occupied = kvcalloc(buckets, sizeof(*table->occupied),
					   GFP_KERNEL);
	}
	table->bfs = kcalloc(BANSET_BFS_MAX, sizeof(*table->bfs), GFP_KERNEL);
	if ((family == NFPROTO_IPV4 &&
	     (!table->v4 || (packed_meta ? !table->v4_meta : !table->state))) ||
	    (family == NFPROTO_IPV6 &&
	     (!table->v6 || !table->expires || !table->flags)) ||
	    ((family != NFPROTO_IPV4 || !packed_meta) &&
	     (!table->signature || !table->occupied)) || !table->bfs) {
		banset_table_free(table);
		return NULL;
	}
	spin_lock_init(&table->lock);
	seqcount_spinlock_init(&table->seq, &table->lock);
	refcount_set(&table->refs, 1);
	table->seed = seed;
	table->capacity = capacity;
	table->bucket_mask = buckets - 1;
	table->family = family;
	return table;
}

static inline u32 banset_hash(const struct banset_table *table,
			      const union banset_key *key)
{
	if (table->family == NFPROTO_IPV4)
		return jhash2((const u32 *)&key->v4, 2, table->seed);
	return jhash2((const u32 *)&key->v6, 8, table->seed);
}

static inline u16 banset_signature(u32 hash)
{
	return (u16)(hash >> 16) | 1;
}

static inline u32 banset_alt(const struct banset_table *table, u32 bucket,
			     u16 signature)
{
	u32 delta = signature;

	if (full_alt)
		delta = hash_32(signature, ilog2(table->bucket_mask + 1)) | 1;
	return (bucket ^ delta) & table->bucket_mask;
}

static inline u32 banset_index(u32 bucket, u8 slot)
{
	return bucket * BANSET_SLOTS + slot;
}

static inline u16 banset_signature_read(const struct banset_table *table,
					u32 bucket, u8 slot)
{
	if (table->v4_meta)
		return READ_ONCE(table->v4_meta[bucket].signature[slot]);
	return READ_ONCE(table->signature[banset_index(bucket, slot)]);
}

static inline void banset_signature_write(struct banset_table *table,
					  u32 bucket, u8 slot, u16 signature)
{
	if (table->v4_meta)
		table->v4_meta[bucket].signature[slot] = signature;
	else
		table->signature[banset_index(bucket, slot)] = signature;
}

static inline const u16 *banset_signatures(const struct banset_table *table,
					   u32 bucket)
{
	if (table->v4_meta)
		return table->v4_meta[bucket].signature;
	return &table->signature[banset_index(bucket, 0)];
}

static inline u8 banset_occupied_read(const struct banset_table *table,
				      u32 bucket)
{
	u8 occupied = 0;
	u8 slot;

	if (!table->v4_meta)
		return READ_ONCE(table->occupied[bucket]);
	for (slot = 0; slot < BANSET_SLOTS; slot++)
		if (READ_ONCE(table->v4_meta[bucket].signature[slot]))
			occupied |= BIT(slot);
	return occupied;
}

static inline void banset_occupied_set(struct banset_table *table,
				       u32 bucket, u8 slot)
{
	if (!table->v4_meta)
		table->occupied[bucket] |= BIT(slot);
}

static inline void banset_occupied_clear(struct banset_table *table,
					 u32 bucket, u8 slot)
{
	if (!table->v4_meta)
		table->occupied[bucket] &= ~BIT(slot);
}

static bool banset_key_equal(const struct banset_table *table, u32 bucket,
			     u8 slot, const union banset_key *key, u16 signature)
{
	u32 index = banset_index(bucket, slot);

	if (banset_signature_read(table, bucket, slot) != signature)
		return false;
	if (table->family == NFPROTO_IPV4)
		return READ_ONCE(*(const u64 *)&table->v4[bucket].key[slot]) ==
		       get_unaligned((const u64 *)&key->v4);
	return ipv6_addr_equal(&table->v6[index].src, &key->v6.src) &&
	       ipv6_addr_equal(&table->v6[index].dst, &key->v6.dst);
}

static void banset_key_read(const struct banset_table *table, u32 bucket,
			    u8 slot, union banset_key *key)
{
	u32 index = banset_index(bucket, slot);

	if (table->family == NFPROTO_IPV4)
		key->v4 = table->v4[bucket].key[slot];
	else
		key->v6 = table->v6[index];
}

static void banset_key_write(struct banset_table *table, u32 bucket, u8 slot,
			     const union banset_key *key, u16 signature)
{
	u32 index = banset_index(bucket, slot);

	if (table->family == NFPROTO_IPV4)
		table->v4[bucket].key[slot] = key->v4;
	else {
		table->v6[index] = key->v6;
	}
	banset_signature_write(table, bucket, slot, signature);
}

static void banset_slot_clear(struct banset_table *table, u32 bucket, u8 slot)
{
	u32 index = banset_index(bucket, slot);

	banset_signature_write(table, bucket, slot, 0);
	if (table->family == NFPROTO_IPV4)
		memset(&table->v4[bucket].key[slot], 0,
		       sizeof(table->v4[bucket].key[slot]));
	else {
		memset(&table->v6[index], 0, sizeof(table->v6[index]));
	}
	banset_state_write(table, index, 0, 0);
	banset_occupied_clear(table, bucket, slot);
}

static int banset_empty_slot(const struct banset_table *table, u32 bucket)
{
	u8 occupied = banset_occupied_read(table, bucket);
	int slot;

	for (slot = 0; slot < BANSET_SLOTS; slot++)
		if (!(occupied & BIT(slot)))
			return slot;
	return -1;
}

static int banset_find_locked(const struct banset_table *table,
			      const union banset_key *key, u32 hash,
			      u32 *bucket_out, u8 *slot_out)
{
	u16 signature = banset_signature(hash);
	u32 primary = hash & table->bucket_mask;
	u32 secondary = banset_alt(table, primary, signature);
	u32 candidates[2] = { primary, secondary };
	int candidate, slot;

	for (candidate = 0; candidate < 2; candidate++) {
		u32 bucket = candidates[candidate];
		u8 occupied;

		if (candidate && secondary == primary)
			break;
		occupied = banset_occupied_read(table, bucket);
		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			if (!(occupied & BIT(slot)))
				continue;
			if (!banset_key_equal(table, bucket, slot, key, signature))
				continue;
			*bucket_out = bucket;
			*slot_out = slot;
			return banset_index(bucket, slot) + 1;
		}
	}
	return 0;
}

static int banset_make_space(struct banset_table *table, u32 primary,
			     u32 secondary, u32 *root_bucket, u8 *root_slot)
{
	u32 head = 0, tail = 0;

	table->bfs[tail++] = (struct banset_bfs_node) {
		.bucket = primary, .parent = -1,
	};
	if (secondary != primary)
		table->bfs[tail++] = (struct banset_bfs_node) {
			.bucket = secondary, .parent = -1,
		};

	while (head < tail && tail < BANSET_BFS_MAX - BANSET_SLOTS) {
		u32 node_index = head++;
		struct banset_bfs_node node = table->bfs[node_index];
		u8 slot;

		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			union banset_key key;
			u32 hash, other;
			u16 signature;
			int empty;

			if (!(banset_occupied_read(table, node.bucket) & BIT(slot)))
				continue;
			banset_key_read(table, node.bucket, slot, &key);
			hash = banset_hash(table, &key);
			signature = banset_signature(hash);
			other = banset_alt(table, node.bucket, signature);
			if (other == node.bucket)
				continue;
			empty = banset_empty_slot(table, other);
			if (empty >= 0) {
				u32 dst_bucket = other;
				u8 dst_slot = empty;
				s32 current_node = node_index;
				u8 source_slot = slot;

				for (;;) {
					u32 source_bucket = table->bfs[current_node].bucket;
					u32 source_index = banset_index(source_bucket,
									 source_slot);
					u32 destination_index = banset_index(dst_bucket,
									      dst_slot);
					union banset_key moved;
					u16 moved_signature;

					banset_key_read(table, source_bucket, source_slot,
							& moved);
					moved_signature = banset_signature(
						banset_hash(table, &moved));
					banset_key_write(table, dst_bucket, dst_slot,
							 &moved, moved_signature);
					banset_state_write(table, destination_index,
						banset_expires_read(table, source_index),
						banset_flag_read(table, source_index));
					banset_occupied_set(table, dst_bucket, dst_slot);
					banset_slot_clear(table, source_bucket, source_slot);
					dst_bucket = source_bucket;
					dst_slot = source_slot;
					if (table->bfs[current_node].parent < 0)
						break;
					source_slot = table->bfs[current_node].parent_slot;
					current_node = table->bfs[current_node].parent;
				}
				*root_bucket = dst_bucket;
				*root_slot = dst_slot;
				return 0;
			}
			table->bfs[tail++] = (struct banset_bfs_node) {
				.bucket = other,
				.parent = node_index,
				.parent_slot = slot,
			};
		}
	}
	return -ENOSPC;
}

static int __banset_upsert_locked(struct banset_table *table,
				  const union banset_key *key, u8 flag,
				  u16 expires, bool update_existing, bool *created)
{
	u32 hash = banset_hash(table, key);
	u16 signature = banset_signature(hash);
	u32 primary = hash & table->bucket_mask;
	u32 secondary = banset_alt(table, primary, signature);
	u32 bucket, index;
	u8 slot;
	int found, empty;

	*created = false;
	found = banset_find_locked(table, key, hash, &bucket, &slot);
	if (found) {
		index = found - 1;
		if (!banset_expired(banset_expires_read(table, index),
				    banset_epoch()) &&
		    !update_existing)
			return -EEXIST;
		banset_state_write(table, index, expires, flag);
		return 0;
	}

	bucket = primary;
	empty = banset_empty_slot(table, primary);
	if (empty < 0) {
		bucket = secondary;
		empty = banset_empty_slot(table, secondary);
	}
	if (empty < 0) {
		if (banset_make_space(table, primary, secondary, &bucket, &slot))
			return -ENOSPC;
	} else {
		slot = empty;
	}
	index = banset_index(bucket, slot);
	banset_key_write(table, bucket, slot, key, signature);
	banset_state_write(table, index, expires, flag);
	banset_occupied_set(table, bucket, slot);
	*created = true;
	return 0;
}

static int __banset_delete_locked(struct banset_table *table,
				  const union banset_key *key, bool *deleted)
{
	u32 bucket, hash = banset_hash(table, key);
	u8 slot;
	int found;

	*deleted = false;
	found = banset_find_locked(table, key, hash, &bucket, &slot);
	if (!found)
		return -ENOENT;
	banset_slot_clear(table, bucket, slot);
	*deleted = true;
	return 0;
}

static int banset_lookup_bucket(const struct banset_table *table,
				const union banset_key *key, u16 signature,
				u32 bucket, u16 now, u8 *flag)
{
	int slot;

	if (table->v4_meta) {
		const struct banset4_meta *meta = &table->v4_meta[bucket];
		u64 wanted = get_unaligned((const u64 *)&key->v4);

		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			u32 state;

			if (READ_ONCE(meta->signature[slot]) != signature ||
			    READ_ONCE(*(const u64 *)&table->v4[bucket].key[slot]) !=
				wanted)
				continue;
			state = READ_ONCE(meta->state[slot]);
			if (!banset_expired((u16)state, now)) {
				*flag = state >> 16;
				return 0;
			}
			break;
		}
		return -ENOENT;
	}

	{
		u8 occupied = banset_occupied_read(table, bucket);

		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			u32 index;
			u16 expires;

			if (!(occupied & BIT(slot)) ||
			    !banset_key_equal(table, bucket, slot, key, signature))
				continue;
			index = banset_index(bucket, slot);
			expires = banset_expires_read(table, index);
			if (!banset_expired(expires, now)) {
				*flag = banset_flag_read(table, index);
				return 0;
			}
			break;
		}
	}
	return -ENOENT;
}

static int banset_lookup_prehashed(const struct banset_table *table,
				   const union banset_key *key, u32 hash,
				   u16 now, u8 *flag)
{
	u16 signature = banset_signature(hash);
	u32 primary = hash & table->bucket_mask;
	u32 secondary;

	if (!banset_lookup_bucket(table, key, signature, primary, now, flag))
		return 0;
	secondary = banset_alt(table, primary, signature);
	if (secondary == primary)
		return -ENOENT;
	return banset_lookup_bucket(table, key, signature, secondary, now, flag);
}

static int banset_lookup_table(const struct banset_table *table,
			       const union banset_key *key, u8 *flag)
{
	u32 hash = banset_hash(table, key);
	u32 sequence;
	u16 now = banset_epoch();
	int result;

	do {
		sequence = read_seqcount_begin(&table->seq);
		result = banset_lookup_prehashed(table, key, hash, now, flag);
	} while (read_seqcount_retry(&table->seq, sequence));
	return result;
}

#if defined(CONFIG_X86_64) && defined(HAVE_X4B_HPFW_PROVIDER)
/* kernel_fpu_begin() must bracket this helper. */
static __always_inline u8
banset4_bucket_matches_xmm(const struct banset4_bucket *bucket,
			   const struct banset4_key *key)
{
	u32 m0, m1, m2, m3;

	asm volatile(
		"vpbroadcastq %[key], %%xmm0\n\t"
		"vpcmpeqq 0(%[bucket]), %%xmm0, %%xmm1\n\t"
		"vmovmskpd %%xmm1, %[m0]\n\t"
		"vpcmpeqq 16(%[bucket]), %%xmm0, %%xmm1\n\t"
		"vmovmskpd %%xmm1, %[m1]\n\t"
		"vpcmpeqq 32(%[bucket]), %%xmm0, %%xmm1\n\t"
		"vmovmskpd %%xmm1, %[m2]\n\t"
		"vpcmpeqq 48(%[bucket]), %%xmm0, %%xmm1\n\t"
		"vmovmskpd %%xmm1, %[m3]"
		: [m0] "=&r" (m0), [m1] "=&r" (m1),
		  [m2] "=&r" (m2), [m3] "=&r" (m3)
		: [key] "m" (*(const u64 *)key), [bucket] "r" (bucket)
		: "memory");
	return m0 | (m1 << 2) | (m2 << 4) | (m3 << 6);
}

static __always_inline u8
banset4_bucket_matches_ymm(const struct banset4_bucket *bucket,
			   const struct banset4_key *key)
{
	u32 low, high;

	asm volatile(
		"vpbroadcastq %[key], %%ymm0\n\t"
		"vpcmpeqq 0(%[bucket]), %%ymm0, %%ymm1\n\t"
		"vmovmskpd %%ymm1, %[low]\n\t"
		"vpcmpeqq 32(%[bucket]), %%ymm0, %%ymm1\n\t"
		"vmovmskpd %%ymm1, %[high]"
		: [low] "=&r" (low), [high] "=&r" (high)
		: [key] "m" (*(const u64 *)key), [bucket] "r" (bucket)
		: "memory");
	return low | (high << 4);
}

static __always_inline u8
banset4_signature_matches_xmm(const u16 *signatures, u16 signature)
{
	u32 mask;
	u8 matches = 0;
	int slot;

	asm volatile(
		"vpbroadcastw %[signature], %%xmm0\n\t"
		"vpcmpeqw (%[signatures]), %%xmm0, %%xmm1\n\t"
		"vpmovmskb %%xmm1, %[mask]"
		: [mask] "=&r" (mask)
		: [signature] "m" (signature), [signatures] "r" (signatures)
		: "memory");
	for (slot = 0; slot < BANSET_SLOTS; slot++)
		if (mask & BIT(slot * 2))
			matches |= BIT(slot);
	return matches;
}

static int banset_lookup_vector_prehashed(const struct banset_table *table,
					  const union banset_key *key,
					  u32 hash, u16 now, u8 *flag,
					  u8 lookup_mode)
{
	u32 primary, secondary;
	u16 signature;
	int result, candidate;

	if (table->family != NFPROTO_IPV4)
		return banset_lookup_prehashed(table, key, hash, now, flag);
	signature = banset_signature(hash);
	primary = hash & table->bucket_mask;
	secondary = banset_alt(table, primary, signature);
	result = -ENOENT;
	for (candidate = 0; candidate < 2 && result < 0; candidate++) {
		u32 bucket = candidate ? secondary : primary;
		u8 matches;

		if (candidate && secondary == primary)
			break;
		if (lookup_mode == 1)
			matches = banset4_bucket_matches_xmm(&table->v4[bucket],
							     &key->v4);
		else if (lookup_mode == 2)
			matches = banset4_bucket_matches_ymm(&table->v4[bucket],
							     &key->v4);
		else
			matches = banset4_signature_matches_xmm(
				banset_signatures(table, bucket), signature);
		matches &= banset_occupied_read(table, bucket);
		while (matches) {
			u8 slot = __ffs(matches);
			u32 index = banset_index(bucket, slot);
			u16 expires = banset_expires_read(table, index);

			if (lookup_mode == 3 &&
			    !banset_key_equal(table, bucket, slot, key,
					      signature)) {
				matches &= ~BIT(slot);
				continue;
			}

			if (!banset_expired(expires, now)) {
				*flag = banset_flag_read(table, index);
				result = 0;
				break;
			}
			matches &= ~BIT(slot);
		}
	}
	return result;
}

static int banset_lookup_table_vector(const struct banset_table *table,
				      const union banset_key *key, u8 *flag,
				      u8 lookup_mode)
{
	u32 hash = banset_hash(table, key);
	u32 sequence;
	u16 now = banset_epoch();
	int result;

	do {
		sequence = read_seqcount_begin(&table->seq);
		result = banset_lookup_vector_prehashed(table, key, hash, now,
						  flag, lookup_mode);
	} while (read_seqcount_retry(&table->seq, sequence));
	return result;
}
#endif

static int banset_lookup(struct banset *set, const union banset_key *key,
			 u8 *flag)
{
	struct banset_table *table;
	int ret;

	rcu_read_lock_bh();
	table = rcu_dereference_bh(set->table);
	ret = table ? banset_lookup_table(table, key, flag) : -ENOENT;
	rcu_read_unlock_bh();
	return ret;
}

static int banset_upsert(struct banset *set, const union banset_key *key,
			 u8 flag, u32 timeout, bool update_existing)
{
	struct banset_table *table, *growing;
	u16 expires = banset_expiry(timeout);
	u32 capacity = 0;
	bool created = false, ignored;
	int ret;

	spin_lock_bh(&set->update_lock);
	rcu_read_lock_bh();
	table = rcu_dereference_bh(set->table);
	if (!table) {
		ret = -ENOENT;
		goto out_rcu;
	}
	spin_lock_bh(&table->lock);
	write_seqcount_begin(&table->seq);
	capacity = table->capacity;
	ret = __banset_upsert_locked(table, key, flag, expires,
				     update_existing, &created);
	if (!ret && created && atomic_read(&set->elements) >= set->maxelem) {
		bool deleted;

		__banset_delete_locked(table, key, &deleted);
		ret = -ENOSPC;
		created = false;
	}
	growing = table->growing;
	if (!ret && growing) {
		spin_lock(&growing->lock);
		write_seqcount_begin(&growing->seq);
		ret = __banset_upsert_locked(growing, key, flag, expires, true,
					     &ignored);
		write_seqcount_end(&growing->seq);
		spin_unlock(&growing->lock);
	}
	write_seqcount_end(&table->seq);
	spin_unlock_bh(&table->lock);
	if (!ret && created)
		atomic_inc(&set->elements);
out_rcu:
	rcu_read_unlock_bh();
	spin_unlock_bh(&set->update_lock);
	if (ret == -ENOSPC && capacity < set->maxelem)
		schedule_work(&set->grow_work);
	else if (!ret && atomic_read(&set->elements) > capacity * 4 / 5 &&
		 capacity < set->maxelem)
		schedule_work(&set->grow_work);
	return ret;
}

static int banset_delete(struct banset *set, const union banset_key *key)
{
	struct banset_table *table, *growing;
	bool deleted = false, ignored;
	int ret;

	spin_lock_bh(&set->update_lock);
	rcu_read_lock_bh();
	table = rcu_dereference_bh(set->table);
	if (!table) {
		ret = -ENOENT;
		goto out_rcu;
	}
	spin_lock_bh(&table->lock);
	write_seqcount_begin(&table->seq);
	ret = __banset_delete_locked(table, key, &deleted);
	growing = table->growing;
	if (growing) {
		spin_lock(&growing->lock);
		write_seqcount_begin(&growing->seq);
		__banset_delete_locked(growing, key, &ignored);
		write_seqcount_end(&growing->seq);
		spin_unlock(&growing->lock);
	}
	write_seqcount_end(&table->seq);
	spin_unlock_bh(&table->lock);
	if (deleted)
		atomic_dec(&set->elements);
out_rcu:
	rcu_read_unlock_bh();
	spin_unlock_bh(&set->update_lock);
	return ret;
}

static int banset_refresh(struct banset *set, const union banset_key *key,
			  u32 timeout)
{
	struct banset_table *table, *growing;
	u32 bucket, hash;
	u8 slot;
	int found, ret = -ENOENT;

	spin_lock_bh(&set->update_lock);
	rcu_read_lock_bh();
	table = rcu_dereference_bh(set->table);
	if (!table)
		goto out_rcu;
	hash = banset_hash(table, key);
	spin_lock_bh(&table->lock);
	/*
	 * Refresh changes only the naturally aligned packed state word.  Keys,
	 * signatures, and occupancy remain fixed, so publishing a seqcount write
	 * would make concurrent readers retry needlessly.  The table lock still
	 * serializes refresh with add/delete/resize and protects the lookup used
	 * to find the state word.
	 */
	found = banset_find_locked(table, key, hash, &bucket, &slot);
	if (found && !banset_expired(banset_expires_read(table, found - 1),
				      banset_epoch())) {
		banset_expiry_write(table, found - 1, banset_expiry(timeout));
		ret = 0;
	}
	growing = table->growing;
	if (!ret && growing) {
		u32 grow_bucket, grow_hash = banset_hash(growing, key);
		u8 grow_slot;

		spin_lock(&growing->lock);
		found = banset_find_locked(growing, key, grow_hash,
					   &grow_bucket, &grow_slot);
		if (found)
			banset_expiry_write(growing, found - 1,
					    banset_expiry(timeout));
		spin_unlock(&growing->lock);
	}
	spin_unlock_bh(&table->lock);
out_rcu:
	rcu_read_unlock_bh();
	spin_unlock_bh(&set->update_lock);
	return ret;
}

static int banset_grow(struct banset *set)
{
	struct banset_table *old, *new;
	u32 bucket, target;
	int ret = 0;

	mutex_lock(&set->resize_mutex);
	old = rcu_dereference_protected(set->table,
					lockdep_is_held(&set->resize_mutex));
	if (!old || old->capacity >= set->maxelem)
		goto out_unlock;
	/*
	 * A synchronous retry and the queued worker can observe the same full
	 * generation.  Once either has enlarged it, do not let the stale second
	 * request immediately enlarge a lightly occupied replacement again.
	 */
	if (old->capacity > min_t(u32, set->maxelem,
					 BANSET_INITIAL_CAPACITY) &&
	    atomic_read(&set->elements) <= old->capacity * 4 / 5)
		goto out_unlock;
	target = min(old->capacity << 1, set->maxelem);
	new = banset_table_create(set->family, target, old->seed);
	if (!new) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	spin_lock_bh(&old->lock);
	write_seqcount_begin(&old->seq);
	old->growing = new;
	write_seqcount_end(&old->seq);
	spin_unlock_bh(&old->lock);

	for (bucket = 0; bucket <= old->bucket_mask && !ret; bucket++) {
		u8 occupied, slot;

		spin_lock_bh(&old->lock);
		occupied = banset_occupied_read(old, bucket);
		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			union banset_key key;
			bool created;
			u32 index;

			if (!(occupied & BIT(slot)))
				continue;
			index = banset_index(bucket, slot);
			banset_key_read(old, bucket, slot, &key);
			spin_lock(&new->lock);
			write_seqcount_begin(&new->seq);
			/*
			 * Packet/control-plane updates are mirrored into growing while
			 * the walk is in progress.  Reaching one of those keys later is
			 * therefore expected, not a migration failure.
			 */
			ret = __banset_upsert_locked(new, &key,
						     banset_flag_read(old, index),
						     banset_expires_read(old, index), true,
						     &created);
			write_seqcount_end(&new->seq);
			spin_unlock(&new->lock);
			if (ret)
				break;
		}
		spin_unlock_bh(&old->lock);
		cond_resched();
	}

	spin_lock_bh(&set->update_lock);
	spin_lock_bh(&old->lock);
	write_seqcount_begin(&old->seq);
	if (!ret)
		rcu_assign_pointer(set->table, new);
	else
		old->growing = NULL;
	write_seqcount_end(&old->seq);
	spin_unlock_bh(&old->lock);
	spin_unlock_bh(&set->update_lock);
	synchronize_rcu();
	if (ret)
		banset_table_put(new);
	else {
		banset_table_put(old);
		pr_info("banset family %u: grew to %u slots (%zu bytes)\n",
			set->family, new->capacity, banset_table_memsize(new));
	}
out_unlock:
	mutex_unlock(&set->resize_mutex);
	return ret;
}

static void banset_grow_work(struct work_struct *work)
{
	struct banset *set = container_of(work, struct banset, grow_work);

	if (banset_grow(set))
		pr_warn_ratelimited("banset family %u: unable to grow table\n",
				    set->family);
}

static void banset_gc_work(struct work_struct *work)
{
	struct banset *set = container_of(to_delayed_work(work), struct banset,
					  gc_work);
	struct banset_table *table, *growing;
	u16 now = banset_epoch();
	u32 bucket;

	rcu_read_lock();
	table = rcu_dereference(set->table);
	if (table && !refcount_inc_not_zero(&table->refs))
		table = NULL;
	rcu_read_unlock();
	if (!table)
		goto out_reschedule;
	for (bucket = 0; bucket <= table->bucket_mask; bucket++) {
		u8 occupied, slot;

		spin_lock_bh(&set->update_lock);
		if (table != rcu_access_pointer(set->table)) {
			spin_unlock_bh(&set->update_lock);
			break;
		}
		spin_lock_bh(&table->lock);
		write_seqcount_begin(&table->seq);
		occupied = banset_occupied_read(table, bucket);
		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			union banset_key key;
			u32 index;
			bool ignored;

			if (!(occupied & BIT(slot)))
				continue;
			index = banset_index(bucket, slot);
			if (!banset_expired(banset_expires_read(table, index), now))
				continue;
			banset_key_read(table, bucket, slot, &key);
			banset_slot_clear(table, bucket, slot);
			atomic_dec(&set->elements);
			growing = table->growing;
			if (growing) {
				spin_lock(&growing->lock);
				write_seqcount_begin(&growing->seq);
				__banset_delete_locked(growing, &key, &ignored);
				write_seqcount_end(&growing->seq);
				spin_unlock(&growing->lock);
			}
		}
		write_seqcount_end(&table->seq);
		spin_unlock_bh(&table->lock);
		spin_unlock_bh(&set->update_lock);
		if (!(bucket & 1023))
			cond_resched();
	}
	banset_table_put(table);
out_reschedule:
	queue_delayed_work(system_power_efficient_wq, &set->gc_work,
			   (1U << BANSET_EPOCH_SHIFT) * HZ);
}

static bool banset_probability(u32 threshold)
{
	return threshold == U32_MAX ||
	       (threshold && get_random_u32() < threshold);
}

static int banset_packet_key(u8 family, const struct sk_buff *skb,
			     union banset_key *key)
{
	if (family == NFPROTO_IPV4) {
		if (!pskb_may_pull((struct sk_buff *)skb, sizeof(struct iphdr)))
			return -EINVAL;
		key->v4.src = ip_hdr(skb)->saddr;
		key->v4.dst = ip_hdr(skb)->daddr;
		return 0;
	}
	if (family == NFPROTO_IPV6) {
		if (!pskb_may_pull((struct sk_buff *)skb, sizeof(struct ipv6hdr)))
			return -EINVAL;
		key->v6.src = ipv6_hdr(skb)->saddr;
		key->v6.dst = ipv6_hdr(skb)->daddr;
		return 0;
	}
	return -EAFNOSUPPORT;
}

static int banset_adt_add(struct ip_set *ipset, void *value,
			  const struct ip_set_ext *ext,
			  struct ip_set_ext *mext, u32 flags)
{
	struct banset *set = ipset->data;
	union banset_key key = {};
	u8 flag;
	int ret;

	if (set->family == NFPROTO_IPV4) {
		const struct banset4_elem *element = value;

		key.v4.src = element->src;
		key.v4.dst = element->dst;
		flag = element->flag;
	} else {
		const struct banset6_elem *element = value;

		key.v6.src = element->src;
		key.v6.dst = element->dst;
		flag = element->flag;
	}
	if (!ext->timeout || ext->timeout == IPSET_NO_TIMEOUT)
		return -IPSET_ERR_PROTOCOL;
	if (ext->timeout > BANSET_MAX_TIMEOUT)
		return -IPSET_ERR_TIMEOUT;
	ret = banset_upsert(set, &key, flag, ext->timeout,
			    !!(flags & IPSET_FLAG_EXIST));
	if (ret == -EEXIST)
		return -IPSET_ERR_EXIST;
	if (ret == -ENOSPC)
		return -IPSET_ERR_HASH_FULL;
	return ret;
}

static int banset_adt_del(struct ip_set *ipset, void *value,
			  const struct ip_set_ext *ext,
			  struct ip_set_ext *mext, u32 flags)
{
	struct banset *set = ipset->data;
	union banset_key key = {};
	int ret;

	if (set->family == NFPROTO_IPV4) {
		const struct banset4_elem *element = value;

		key.v4.src = element->src;
		key.v4.dst = element->dst;
	} else {
		const struct banset6_elem *element = value;

		key.v6.src = element->src;
		key.v6.dst = element->dst;
	}
	ret = banset_delete(set, &key);
	return ret == -ENOENT ? -IPSET_ERR_EXIST : ret;
}

static int banset_adt_test(struct ip_set *ipset, void *value,
			   const struct ip_set_ext *ext,
			   struct ip_set_ext *mext, u32 flags)
{
	struct banset *set = ipset->data;
	union banset_key key = {};
	u8 flag;

	if (set->family == NFPROTO_IPV4) {
		const struct banset4_elem *element = value;

		key.v4.src = element->src;
		key.v4.dst = element->dst;
	} else {
		const struct banset6_elem *element = value;

		key.v6.src = element->src;
		key.v6.dst = element->dst;
	}
	return banset_lookup(set, &key, &flag) ? 0 : 1;
}

static int banset4_kadt(struct ip_set *ipset, const struct sk_buff *skb,
			const struct xt_action_param *par, enum ipset_adt adt,
			struct ip_set_adt_opt *opt)
{
	struct banset4_elem element = {};
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, ipset);

	ip4addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &element.src);
	ip4addrptr(skb, opt->flags & IPSET_DIM_TWO_SRC, &element.dst);
	if ((unsigned long)opt->ext.comment < 256)
		element.flag = (u8)(unsigned long)opt->ext.comment;
	return ipset->variant->adt[adt](ipset, &element, &ext, &opt->ext,
					       opt->cmdflags);
}

static int banset6_kadt(struct ip_set *ipset, const struct sk_buff *skb,
			const struct xt_action_param *par, enum ipset_adt adt,
			struct ip_set_adt_opt *opt)
{
	struct banset6_elem element = {};
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, ipset);

	ip6addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &element.src);
	ip6addrptr(skb, opt->flags & IPSET_DIM_TWO_SRC, &element.dst);
	if ((unsigned long)opt->ext.comment < 256)
		element.flag = (u8)(unsigned long)opt->ext.comment;
	return ipset->variant->adt[adt](ipset, &element, &ext, &opt->ext,
					       opt->cmdflags);
}

static int banset_uadt(struct ip_set *ipset, struct nlattr *tb[],
		       enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	struct ip_set_ext ext = IP_SET_INIT_UEXT(ipset);
	struct banset4_elem element4 = {};
	struct banset6_elem element6 = {};
	void *element;
	u16 port = 0;
	int ret;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);
	if (!tb[IPSET_ATTR_IP] || !tb[IPSET_ATTR_IP2])
		return -IPSET_ERR_PROTOCOL;
	if (tb[IPSET_ATTR_IP_TO] || tb[IPSET_ATTR_IP2_TO] ||
	    tb[IPSET_ATTR_CIDR] || tb[IPSET_ATTR_CIDR2] ||
	    tb[IPSET_ATTR_BYTES] || tb[IPSET_ATTR_PACKETS] ||
	    tb[IPSET_ATTR_COMMENT] || tb[IPSET_ATTR_SKBMARK] ||
	    tb[IPSET_ATTR_SKBPRIO] || tb[IPSET_ATTR_SKBQUEUE])
		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;
	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!ip_set_attr_netorder(tb, IPSET_ATTR_TIMEOUT))
			return -IPSET_ERR_PROTOCOL;
		ext.timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
	}
	if (!ext.timeout || ext.timeout == IPSET_NO_TIMEOUT)
		return -IPSET_ERR_PROTOCOL;
	if (tb[IPSET_ATTR_PORT]) {
		if (!ip_set_attr_netorder(tb, IPSET_ATTR_PORT))
			return -IPSET_ERR_PROTOCOL;
		port = ntohs(nla_get_be16(tb[IPSET_ATTR_PORT]));
		if (port > U8_MAX)
			/* A raw errno is treated as a resize retry by ipset(8). */
			return -IPSET_ERR_PROTOCOL;
	}

	if (ipset->family == NFPROTO_IPV4) {
		ret = ip_set_get_ipaddr4(tb[IPSET_ATTR_IP], &element4.src);
		if (!ret)
			ret = ip_set_get_ipaddr4(tb[IPSET_ATTR_IP2], &element4.dst);
		element4.flag = (u8)port;
		element = &element4;
	} else {
		union nf_inet_addr address;

		ret = ip_set_get_ipaddr6(tb[IPSET_ATTR_IP], &address);
		if (!ret)
			element6.src = address.in6;
		if (!ret)
			ret = ip_set_get_ipaddr6(tb[IPSET_ATTR_IP2], &address);
		if (!ret)
			element6.dst = address.in6;
		element6.flag = (u8)port;
		element = &element6;
	}
	if (ret)
		return ret;
	ret = ipset->variant->adt[adt](ipset, element, &ext, &ext, flags);
	if (ret == -IPSET_ERR_HASH_FULL && adt == IPSET_ADD && !retried &&
	    !banset_grow(ipset->data))
		return -EAGAIN;
	return ip_set_eexist(ret, flags) ? 0 : ret;
}

static int banset_head(struct ip_set *ipset, struct sk_buff *skb)
{
	struct banset *set = ipset->data;
	struct banset_table *table;
	struct nlattr *nested;
	u32 capacity = 0, memsize = sizeof(*set);

	rcu_read_lock();
	table = rcu_dereference(set->table);
	if (table) {
		capacity = table->capacity;
		memsize += banset_table_memsize(table);
	}
	rcu_read_unlock();
	nested = nla_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		return -EMSGSIZE;
	if (nla_put_net32(skb, IPSET_ATTR_HASHSIZE, htonl(capacity / BANSET_SLOTS)) ||
	    nla_put_net32(skb, IPSET_ATTR_MAXELEM, htonl(set->maxelem)) ||
	    nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(ipset->ref)) ||
	    nla_put_net32(skb, IPSET_ATTR_MEMSIZE, htonl(memsize)) ||
	    nla_put_net32(skb, IPSET_ATTR_ELEMENTS,
			  htonl(atomic_read(&set->elements))) ||
	    nla_put_net32(skb, IPSET_ATTR_TIMEOUT, htonl(set->timeout)) ||
	    ip_set_put_flags(skb, ipset)) {
		nla_nest_cancel(skb, nested);
		return -EMSGSIZE;
	}
	nla_nest_end(skb, nested);
	return 0;
}

static void banset_uref(struct ip_set *ipset, struct netlink_callback *cb,
			bool start)
{
	struct banset *set = ipset->data;
	struct banset_table *table;

	if (start) {
		rcu_read_lock();
		table = rcu_dereference(set->table);
		if (table && refcount_inc_not_zero(&table->refs))
			cb->args[IPSET_CB_PRIVATE] = (unsigned long)table;
		rcu_read_unlock();
	} else if (cb->args[IPSET_CB_PRIVATE]) {
		table = (void *)cb->args[IPSET_CB_PRIVATE];
		cb->args[IPSET_CB_PRIVATE] = 0;
		banset_table_put(table);
	}
}

static int banset_list(const struct ip_set *ipset, struct sk_buff *skb,
		       struct netlink_callback *cb)
{
	const struct banset *set = ipset->data;
	struct banset_table *table = (void *)cb->args[IPSET_CB_PRIVATE];
	struct nlattr *adt, *nested;
	u32 cursor = cb->args[IPSET_CB_ARG0];
	u32 bucket = cursor / BANSET_SLOTS;
	u8 slot = cursor % BANSET_SLOTS;
	u16 now = banset_epoch();

	if (!table)
		return 0;
	adt = nla_nest_start(skb, IPSET_ATTR_ADT);
	if (!adt)
		return -EMSGSIZE;
	for (; bucket <= table->bucket_mask; bucket++, slot = 0) {
		for (; slot < BANSET_SLOTS; slot++) {
			u32 index = banset_index(bucket, slot);
			u16 expires;
			union banset_key key;
			void *tail;

			spin_lock_bh(&table->lock);
			if (!(banset_occupied_read(table, bucket) & BIT(slot))) {
				spin_unlock_bh(&table->lock);
				continue;
			}
			expires = banset_expires_read(table, index);
			if (banset_expired(expires, now)) {
				spin_unlock_bh(&table->lock);
				continue;
			}
			banset_key_read(table, bucket, slot, &key);
			tail = skb_tail_pointer(skb);
			nested = nla_nest_start(skb, IPSET_ATTR_DATA);
			if (!nested ||
			    (set->family == NFPROTO_IPV4 &&
			     (nla_put_ipaddr4(skb, IPSET_ATTR_IP, key.v4.src) ||
			      nla_put_ipaddr4(skb, IPSET_ATTR_IP2, key.v4.dst))) ||
			    (set->family == NFPROTO_IPV6 &&
			     (nla_put_ipaddr6(skb, IPSET_ATTR_IP, &key.v6.src) ||
			      nla_put_ipaddr6(skb, IPSET_ATTR_IP2, &key.v6.dst))) ||
			    nla_put_net16(skb, IPSET_ATTR_PORT,
					  htons(banset_flag_read(table, index))) ||
			    nla_put_net32(skb, IPSET_ATTR_TIMEOUT,
					  htonl((u16)(expires - now) <<
						BANSET_EPOCH_SHIFT))) {
				nlmsg_trim(skb, tail);
				spin_unlock_bh(&table->lock);
				cb->args[IPSET_CB_ARG0] =
					banset_index(bucket, slot);
				nla_nest_end(skb, adt);
				return 0;
			}
			nla_nest_end(skb, nested);
			spin_unlock_bh(&table->lock);
		}
	}
	nla_nest_end(skb, adt);
	cb->args[IPSET_CB_ARG0] = 0;
	return 0;
}

static void banset_flush(struct ip_set *ipset)
{
	struct banset *set = ipset->data;
	struct banset_table *table, *growing;

	spin_lock_bh(&set->update_lock);
	rcu_read_lock_bh();
	table = rcu_dereference_bh(set->table);
	if (!table)
		goto out_rcu;
	spin_lock_bh(&table->lock);
	write_seqcount_begin(&table->seq);
	if (table->v4_meta) {
		memset(table->v4_meta, 0,
		       (table->bucket_mask + 1) * sizeof(*table->v4_meta));
	} else {
		memset(table->occupied, 0, table->bucket_mask + 1);
		memset(table->signature, 0,
		       table->capacity * sizeof(*table->signature));
		if (table->state)
			memset(table->state, 0,
			       table->capacity * sizeof(*table->state));
	}
	growing = table->growing;
	if (growing) {
		spin_lock(&growing->lock);
		write_seqcount_begin(&growing->seq);
		if (growing->v4_meta) {
			memset(growing->v4_meta, 0,
			       (growing->bucket_mask + 1) *
			       sizeof(*growing->v4_meta));
		} else {
			memset(growing->occupied, 0,
			       growing->bucket_mask + 1);
			memset(growing->signature, 0,
			       growing->capacity *
			       sizeof(*growing->signature));
			if (growing->state)
				memset(growing->state, 0,
				       growing->capacity *
				       sizeof(*growing->state));
		}
		write_seqcount_end(&growing->seq);
		spin_unlock(&growing->lock);
	}
	atomic_set(&set->elements, 0);
	write_seqcount_end(&table->seq);
	spin_unlock_bh(&table->lock);
out_rcu:
	rcu_read_unlock_bh();
	spin_unlock_bh(&set->update_lock);
}

static bool banset_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct banset *left = a->data;
	const struct banset *right = b->data;

	/*
	 * The ipset core implements swap without a type callback.  Name-bound
	 * direct and XDP lookups therefore deliberately follow the core's swapped
	 * names.  same_set() is used only by CREATE ... -exist.
	 */
	return a->family == b->family && left->maxelem == right->maxelem &&
	       left->timeout == right->timeout;
}

static void banset_cancel_gc(struct ip_set *ipset)
{
	struct banset *set = ipset->data;
	struct banset_binding *binding, *removed = NULL;

	cancel_delayed_work_sync(&set->gc_work);
	cancel_work_sync(&set->grow_work);
	mutex_lock(&banset_bindings_lock);
	list_for_each_entry(binding, &banset_bindings, bindings) {
		if (binding->set != ipset)
			continue;
		list_del_rcu(&binding->bindings);
		removed = binding;
		break;
	}
	mutex_unlock(&banset_bindings_lock);
	if (removed) {
		synchronize_rcu();
		kfree(removed);
	}
}

static void banset_destroy(struct ip_set *ipset)
{
	struct banset *set = ipset->data;
	struct banset_table *table;

	table = rcu_dereference_protected(set->table, 1);
	RCU_INIT_POINTER(set->table, NULL);
	banset_table_put(table);
	kfree(set);
}

static int banset_resize(struct ip_set *ipset, bool retried)
{
	return banset_grow(ipset->data);
}

static const struct ip_set_type_variant banset4_variant = {
	.kadt = banset4_kadt,
	.uadt = banset_uadt,
	.adt = {
		[IPSET_ADD] = banset_adt_add,
		[IPSET_DEL] = banset_adt_del,
		[IPSET_TEST] = banset_adt_test,
	},
	.destroy = banset_destroy,
	.flush = banset_flush,
	.head = banset_head,
	.list = banset_list,
	.uref = banset_uref,
	.resize = banset_resize,
	.same_set = banset_same_set,
	.cancel_gc = banset_cancel_gc,
};

static const struct ip_set_type_variant banset6_variant = {
	.kadt = banset6_kadt,
	.uadt = banset_uadt,
	.adt = {
		[IPSET_ADD] = banset_adt_add,
		[IPSET_DEL] = banset_adt_del,
		[IPSET_TEST] = banset_adt_test,
	},
	.destroy = banset_destroy,
	.flush = banset_flush,
	.head = banset_head,
	.list = banset_list,
	.uref = banset_uref,
	.resize = banset_resize,
	.same_set = banset_same_set,
	.cancel_gc = banset_cancel_gc,
};

static int banset_create(struct net *net, struct ip_set *ipset,
			 struct nlattr *tb[], u32 flags)
{
	struct banset_binding *binding;
	struct banset_table *table;
	struct banset *set;
	u32 cadt_flags = 0;
	u32 maxelem = IPSET_DEFAULT_MAXELEM, capacity, seed;

	if (ipset->family != NFPROTO_IPV4 && ipset->family != NFPROTO_IPV6)
		return -IPSET_ERR_INVALID_FAMILY;
	if (!tb[IPSET_ATTR_TIMEOUT] ||
	    !ip_set_attr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
	    !ip_set_optattr_netorder(tb, IPSET_ATTR_HASHSIZE) ||
	    !ip_set_optattr_netorder(tb, IPSET_ATTR_MAXELEM) ||
	    !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS))
		return -IPSET_ERR_PROTOCOL;
	if (tb[IPSET_ATTR_CADT_FLAGS])
		cadt_flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);
	if (cadt_flags & (IPSET_FLAG_WITH_COUNTERS | IPSET_FLAG_WITH_COMMENT |
			  IPSET_FLAG_WITH_FORCEADD | IPSET_FLAG_WITH_SKBINFO))
		return -EOPNOTSUPP;
	ipset->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
	if (!ipset->timeout || ipset->timeout == IPSET_NO_TIMEOUT)
		return -IPSET_ERR_PROTOCOL;
	if (ipset->timeout > BANSET_MAX_TIMEOUT)
		return -IPSET_ERR_TIMEOUT;
	if (tb[IPSET_ATTR_MAXELEM])
		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);
	maxelem = clamp_t(u32, maxelem, BANSET_SLOTS, BANSET_MAX_CAPACITY);
	capacity = min_t(u32, maxelem, BANSET_INITIAL_CAPACITY);
	get_random_bytes(&seed, sizeof(seed));
	table = banset_table_create(ipset->family, capacity, seed);
	if (!table)
		return -ENOMEM;
	set = kzalloc(sizeof(*set), GFP_KERNEL);
	if (!set) {
		banset_table_put(table);
		return -ENOMEM;
	}
	binding = kzalloc(sizeof(*binding), GFP_KERNEL);
	if (!binding) {
		banset_table_put(table);
		kfree(set);
		return -ENOMEM;
	}
	mutex_init(&set->resize_mutex);
	spin_lock_init(&set->update_lock);
	INIT_WORK(&set->grow_work, banset_grow_work);
	INIT_DELAYED_WORK(&set->gc_work, banset_gc_work);
	atomic_set(&set->elements, 0);
	set->maxelem = maxelem;
	set->timeout = ipset->timeout;
	set->family = ipset->family;
	binding->set = ipset;
	binding->net = net;
	binding->family = ipset->family;
	INIT_LIST_HEAD(&binding->bindings);
	RCU_INIT_POINTER(set->table, table);
	ipset->data = set;
	ipset->variant = ipset->family == NFPROTO_IPV4 ?
		&banset4_variant : &banset6_variant;
	ipset->dsize = ip_set_elem_len(ipset, tb,
		ipset->family == NFPROTO_IPV4 ? sizeof(struct banset4_elem) :
						 sizeof(struct banset6_elem),
		__alignof__(struct banset6_elem));
	if (ipset->extensions != IPSET_EXT_TIMEOUT) {
		banset_table_put(table);
		kfree(binding);
		kfree(set);
		ipset->data = NULL;
		return -EOPNOTSUPP;
	}
	mutex_lock(&banset_bindings_lock);
	list_add_tail_rcu(&binding->bindings, &banset_bindings);
	mutex_unlock(&banset_bindings_lock);
	queue_delayed_work(system_power_efficient_wq, &set->gc_work,
			   (1U << BANSET_EPOCH_SHIFT) * HZ);
	pr_info("set %s: family %u, %u/%u slots, %zu bytes\n",
		ipset->name, ipset->family, table->capacity, maxelem,
		banset_table_memsize(table));
	return 0;
}

static struct ip_set_type banset_type __read_mostly = {
	.name = "hash:ip,ip,flag",
	.protocol = IPSET_PROTOCOL,
	.features = IPSET_TYPE_IP | IPSET_TYPE_IP2 | IPSET_TYPE_PORT,
	.dimension = IPSET_DIM_THREE,
	.family = NFPROTO_UNSPEC,
	.revision_min = BANSET_REV_MIN,
	.revision_max = BANSET_REV_MAX,
	.create = banset_create,
	.create_policy = {
		[IPSET_ATTR_HASHSIZE] = { .type = NLA_U32 },
		[IPSET_ATTR_MAXELEM] = { .type = NLA_U32 },
		[IPSET_ATTR_RESIZE] = { .type = NLA_U8 },
		[IPSET_ATTR_TIMEOUT] = { .type = NLA_U32 },
		[IPSET_ATTR_CADT_FLAGS] = { .type = NLA_U32 },
	},
	.adt_policy = {
		[IPSET_ATTR_IP] = { .type = NLA_NESTED },
		[IPSET_ATTR_IP_TO] = { .type = NLA_NESTED },
		[IPSET_ATTR_IP2] = { .type = NLA_NESTED },
		[IPSET_ATTR_IP2_TO] = { .type = NLA_NESTED },
		[IPSET_ATTR_PORT] = { .type = NLA_U16 },
		[IPSET_ATTR_CIDR] = { .type = NLA_U8 },
		[IPSET_ATTR_CIDR2] = { .type = NLA_U8 },
		[IPSET_ATTR_TIMEOUT] = { .type = NLA_U32 },
		[IPSET_ATTR_LINENO] = { .type = NLA_U32 },
		[IPSET_ATTR_BYTES] = { .type = NLA_U64 },
		[IPSET_ATTR_PACKETS] = { .type = NLA_U64 },
		[IPSET_ATTR_COMMENT] = {
			.type = NLA_NUL_STRING, .len = IPSET_MAX_COMMENT_SIZE,
		},
		[IPSET_ATTR_SKBMARK] = { .type = NLA_U64 },
		[IPSET_ATTR_SKBPRIO] = { .type = NLA_U32 },
		[IPSET_ATTR_SKBQUEUE] = { .type = NLA_U16 },
	},
	.me = THIS_MODULE,
};

static struct banset *banset_find_binding(const char *name, u8 family,
					  const struct net *net)
{
	struct banset_binding *binding;

	list_for_each_entry(binding, &banset_bindings, bindings)
		if (binding->family == family && binding->net == net &&
		    !strncmp(binding->set->name, name, IPSET_MAXNAMELEN))
			return READ_ONCE(binding->set->data);
	return NULL;
}

static struct banset *banset_find_binding_rcu(const char *name, u8 family,
					      const struct net *net);

static bool banset_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_banset_mtinfo *info = par->matchinfo;
	struct banset_table *table;
	struct banset *set;
	union banset_key key = {};
	u8 flag;
	bool hit;

	if (unlikely(banset_packet_key(info->family, skb, &key)))
		return false;
	rcu_read_lock_bh();
	set = banset_find_binding_rcu(info->setname, info->family, xt_net(par));
	if (unlikely(!set)) {
		rcu_read_unlock_bh();
		return false;
	}
	table = rcu_dereference_bh(set->table);
	hit = table && !banset_lookup_table(table, &key, &flag);
	switch (info->mode) {
	case XT_BANSET_REFRESH:
		if (hit && banset_probability(info->probability))
			banset_refresh(set, &key, set->timeout);
		break;
	case XT_BANSET_ADD:
		if (banset_probability(info->probability))
			banset_upsert(set, &key, info->flag, set->timeout, true);
		hit = true;
		break;
	default:
		break;
	}
	rcu_read_unlock_bh();
	return hit;
}

static int banset_mt_check(const struct xt_mtchk_param *par)
{
	struct xt_banset_mtinfo *info = par->matchinfo;
	struct banset *set;
	ip_set_id_t index;

	if (!info->setname[0] || info->index == IPSET_INVALID_ID ||
	    info->mode > XT_BANSET_ADD)
		return -EINVAL;
	index = ip_set_nfnl_get_byindex(par->net, info->index);
	if (index == IPSET_INVALID_ID)
		return -ENOENT;
	mutex_lock(&banset_bindings_lock);
	set = banset_find_binding(info->setname, par->family, par->net);
	if (set)
		info->backend = (unsigned long)set;
	mutex_unlock(&banset_bindings_lock);
	if (!set) {
		ip_set_nfnl_put(par->net, info->index);
		return -EINVAL;
	}
	info->family = par->family;
	return 0;
}

static void banset_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_banset_mtinfo *info = par->matchinfo;

	if (info->index != IPSET_INVALID_ID)
		ip_set_nfnl_put(par->net, info->index);
}

static struct xt_match banset_matches[] __read_mostly = {
	{
		.name = "banset",
		.family = NFPROTO_IPV4,
		.match = banset_mt,
		.matchsize = sizeof(struct xt_banset_mtinfo),
		.usersize = offsetof(struct xt_banset_mtinfo, backend),
		.checkentry = banset_mt_check,
		.destroy = banset_mt_destroy,
		.me = THIS_MODULE,
	},
	{
		.name = "banset",
		.family = NFPROTO_IPV6,
		.match = banset_mt,
		.matchsize = sizeof(struct xt_banset_mtinfo),
		.usersize = offsetof(struct xt_banset_mtinfo, backend),
		.checkentry = banset_mt_check,
		.destroy = banset_mt_destroy,
		.me = THIS_MODULE,
	},
};

static struct banset *banset_find_binding_rcu(const char *name, u8 family,
					      const struct net *net)
{
	struct banset_binding *binding;

	list_for_each_entry_rcu(binding, &banset_bindings, bindings)
		if (binding->family == family && binding->net == net &&
		    !strncmp(binding->set->name, name, IPSET_MAXNAMELEN))
			return READ_ONCE(binding->set->data);
	return NULL;
}

#ifdef HAVE_X4B_HPFW_PROVIDER
static int banset_frame_key(const void *frame_data, const void *frame_data_end,
			    union banset_key *key, u8 *family,
			    struct x4b_rx_parse *parsed)
{
	const unsigned char *data = frame_data;
	const unsigned char *data_end = frame_data_end;
	const struct ethhdr *eth;
	__be16 protocol;
	u32 offset = sizeof(*eth);
	int vlan;

	if (data + sizeof(*eth) > data_end)
		return -EINVAL;
	if (parsed)
		memset(parsed, 0, sizeof(*parsed));
	eth = (const struct ethhdr *)data;
	protocol = eth->h_proto;
	for (vlan = 0; vlan < 2 && eth_type_vlan(protocol); vlan++) {
		const struct vlan_hdr *header;

		if (data + offset + sizeof(*header) > data_end)
			return -EINVAL;
		header = (const struct vlan_hdr *)(data + offset);
		protocol = header->h_vlan_encapsulated_proto;
		offset += sizeof(*header);
	}
	if (eth_type_vlan(protocol))
		return -EOPNOTSUPP;
	if (protocol == htons(ETH_P_IP)) {
		const struct iphdr *iph = (const struct iphdr *)(data + offset);
		u32 available, total_len;

		if ((const unsigned char *)(iph + 1) > data_end ||
		    iph->version != 4 || iph->ihl < 5 ||
		    data + offset + iph->ihl * 4 > data_end)
			return -EINVAL;
		available = data_end - (data + offset);
		total_len = ntohs(iph->tot_len);
		if (total_len < iph->ihl * 4 || total_len > available)
			return -EINVAL;
		key->v4.src = iph->saddr;
		key->v4.dst = iph->daddr;
		*family = NFPROTO_IPV4;
		if (parsed) {
			parsed->addr.v4.src = iph->saddr;
			parsed->addr.v4.dst = iph->daddr;
			parsed->network_offset = offset;
			parsed->packet_len = total_len;
			parsed->ethernet_type = protocol;
			parsed->family = NFPROTO_IPV4;
			parsed->ip_protocol = iph->protocol;
		}
		return 0;
	}
	if (protocol == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h =
			(const struct ipv6hdr *)(data + offset);
		u32 total_len;

		if ((const unsigned char *)(ip6h + 1) > data_end ||
		    ip6h->version != 6)
			return -EINVAL;
		total_len = sizeof(*ip6h) + ntohs(ip6h->payload_len);
		if (data + offset + total_len > data_end)
			return -EINVAL;
		key->v6.src = ip6h->saddr;
		key->v6.dst = ip6h->daddr;
		*family = NFPROTO_IPV6;
		if (parsed) {
			parsed->addr.v6.src = ip6h->saddr;
			parsed->addr.v6.dst = ip6h->daddr;
			parsed->network_offset = offset;
			parsed->packet_len = total_len;
			parsed->flow_label = (ip6h->flow_lbl[0] << 16) |
				(ip6h->flow_lbl[1] << 8) | ip6h->flow_lbl[2];
			parsed->ethernet_type = protocol;
			parsed->family = NFPROTO_IPV6;
			parsed->ip_protocol = ip6h->nexthdr;
		}
		return 0;
	}
	return -EAFNOSUPPORT;
}

static __always_inline int
banset_frame4_key(const void *frame_data, const void *frame_data_end,
		  union banset_key *key, struct x4b_rx_parse *parsed)
{
	const unsigned char *data = frame_data;
	const unsigned char *data_end = frame_data_end;
	const struct ethhdr *eth;
	const struct iphdr *iph;
	__be16 protocol;
	u32 offset = sizeof(*eth);
	int vlan;

	if (data + sizeof(*eth) > data_end)
		return -EINVAL;
	if (parsed)
		memset(parsed, 0, sizeof(*parsed));
	eth = (const struct ethhdr *)data;
	protocol = eth->h_proto;
	for (vlan = 0; vlan < 2 && eth_type_vlan(protocol); vlan++) {
		const struct vlan_hdr *header;

		if (data + offset + sizeof(*header) > data_end)
			return -EINVAL;
		header = (const struct vlan_hdr *)(data + offset);
		protocol = header->h_vlan_encapsulated_proto;
		offset += sizeof(*header);
	}
	if (protocol != htons(ETH_P_IP))
		return -EAFNOSUPPORT;
	iph = (const struct iphdr *)(data + offset);
	if ((const unsigned char *)(iph + 1) > data_end || iph->version != 4 ||
	    iph->ihl < 5 || data + offset + iph->ihl * 4 > data_end)
		return -EINVAL;
	if (ntohs(iph->tot_len) < iph->ihl * 4 ||
	    data + offset + ntohs(iph->tot_len) > data_end)
		return -EINVAL;
	key->v4.src = iph->saddr;
	key->v4.dst = iph->daddr;
	if (parsed) {
		parsed->addr.v4.src = iph->saddr;
		parsed->addr.v4.dst = iph->daddr;
		parsed->network_offset = offset;
		parsed->packet_len = ntohs(iph->tot_len);
		parsed->ethernet_type = protocol;
		parsed->family = NFPROTO_IPV4;
		parsed->ip_protocol = iph->protocol;
	}
	return 0;
}

static __always_inline int
banset_preparsed_key(const struct x4b_rx_parse *parsed, union banset_key *key,
		      u8 *family)
{
	/* HPFW has already bounds-checked these addresses against the raw frame. */
	if (parsed->family == NFPROTO_IPV4) {
		key->v4.src = parsed->addr.v4.src;
		key->v4.dst = parsed->addr.v4.dst;
		*family = NFPROTO_IPV4;
		return 0;
	}
	if (parsed->family == NFPROTO_IPV6) {
		key->v6.src = parsed->addr.v6.src;
		key->v6.dst = parsed->addr.v6.dst;
		*family = NFPROTO_IPV6;
		return 0;
	}
	return -EAFNOSUPPORT;
}

static int banset_xdp_key(struct xdp_buff *xdp, union banset_key *key,
			  u8 *family)
{
	return banset_frame_key(xdp->data, xdp->data_end, key, family, NULL);
}

struct banset_native_scratch {
	union banset_key keys[X4B_BANSET_NATIVE_MAX_BATCH];
	struct banset_table *tables[X4B_BANSET_NATIVE_MAX_BATCH];
	struct banset *sets[X4B_BANSET_NATIVE_MAX_BATCH];
	u32 random[X4B_BANSET_NATIVE_MAX_BATCH];
	u32 hash[X4B_BANSET_NATIVE_MAX_BATCH];
	u32 secondary[X4B_BANSET_NATIVE_MAX_BATCH];
	u8 miss_index[X4B_BANSET_NATIVE_MAX_BATCH];
	u8 families[X4B_BANSET_NATIVE_MAX_BATCH];
};

static struct banset_native_scratch __percpu *banset_native_scratch;
static struct rnd_state __percpu *banset_native_prng;

static __always_inline void
banset_prefetch_bucket(const struct banset_table *table, u32 bucket)
{
	if (table->v4_meta)
		prefetch(&table->v4_meta[bucket]);
	else
		prefetch(banset_signatures(table, bucket));
	prefetch(&table->v4[bucket]);
}

static u64 banset_native_batch(struct sk_buff **skbs,
			       struct xdp_buff **xdps,
			       const struct x4b_rx_frame *frames,
			       struct net_device *frame_dev,
			       const struct x4b_rx_parse *preparsed,
			       struct x4b_rx_parse *parsed, u32 count,
			       u32 refresh_threshold, u8 lookup_mode)
{
	struct banset_native_scratch *scratch;
	struct banset_native_timing_cpu *timing;
	struct banset *cached_sets[2] = {};
	struct banset_table *cached_tables[2] = {};
	struct banset_table *common_table = NULL;
	bool cached[2] = {};
	struct net_device *cached_dev = NULL;
	u64 valid = 0, hits = 0;
	bool homogeneous_v4 = true;
	bool use_simd = false;
	bool sample;
	u64 total_start = 0, stage_start = 0;
	u64 parse_cycles = 0, hash_cycles = 0;
	u64 primary_cycles = 0, secondary_cycles = 0, refresh_cycles = 0;
	u32 shift;
	u32 i;

	if (!count || count > X4B_BANSET_NATIVE_MAX_BATCH)
		return 0;
	timing = this_cpu_ptr(banset_native_timing);
	timing->calls++;
	shift = min_t(u32, READ_ONCE(timing_shift), 30);
	sample = !(timing->calls & ((1ULL << shift) - 1));
	if (sample)
		total_start = stage_start = banset_cycles();
	rcu_read_lock_bh();
	scratch = this_cpu_ptr(banset_native_scratch);
	/* Raw i40e batches are homogeneous by construction: resolve once. */
	if (homogeneous_batch && frames && frame_dev) {
		struct net_device *dev = frame_dev;
		struct banset *set;
		struct banset_table *table;

		set = banset_find_binding_rcu("ban", NFPROTO_IPV4, dev_net(dev));
		table = set ? rcu_dereference_bh(set->table) : NULL;
		if (table && table->family == NFPROTO_IPV4) {
			for (i = 0; i < count; i++) {
				u8 family;

				if (preparsed &&
				    !banset_preparsed_key(&preparsed[i],
							  &scratch->keys[i], &family) &&
				    family == NFPROTO_IPV4) {
					if (parsed)
						parsed[i] = preparsed[i];
				} else if (banset_frame4_key(
						   frames[i].data, frames[i].data_end,
						   &scratch->keys[i],
						   parsed ? &parsed[i] : NULL))
					break;
				scratch->sets[i] = set;
				scratch->tables[i] = table;
				scratch->families[i] = NFPROTO_IPV4;
			}
			if (i == count) {
				valid = count == 64 ? U64_MAX : BIT_ULL(count) - 1;
				common_table = table;
				goto parsed;
			}
		}
	}
	for (i = 0; i < count; i++) {
		struct net_device *dev;
		u8 family_index;
		u8 family;

		if (frames) {
			dev = frame_dev;
			if (!dev)
				continue;
			if (preparsed &&
			    !banset_preparsed_key(&preparsed[i], &scratch->keys[i],
						    &family)) {
				if (parsed)
					parsed[i] = preparsed[i];
			} else if (banset_frame_key(frames[i].data,
						    frames[i].data_end,
						    &scratch->keys[i], &family,
						    parsed ? &parsed[i] : NULL))
				continue;
		} else if (xdps) {
			if (banset_xdp_key(xdps[i], &scratch->keys[i], &family) ||
			    !xdps[i]->rxq || !(dev = xdps[i]->rxq->dev))
				continue;
		} else {
			dev = skbs[i]->dev;
			if (!dev)
				continue;
			if (skbs[i]->protocol == htons(ETH_P_IP))
				family = NFPROTO_IPV4;
			else if (skbs[i]->protocol == htons(ETH_P_IPV6))
				family = NFPROTO_IPV6;
			else
				continue;
			if (banset_packet_key(family, skbs[i], &scratch->keys[i]))
				continue;
		}
		if (dev != cached_dev) {
			memset(cached, 0, sizeof(cached));
			cached_dev = dev;
		}
		family_index = family == NFPROTO_IPV4 ? 0 : 1;
		if (!cached[family_index]) {
			const char *name = family_index ? "ban6" : "ban";

			cached_sets[family_index] =
				banset_find_binding_rcu(name, family, dev_net(dev));
			cached_tables[family_index] = cached_sets[family_index] ?
				rcu_dereference_bh(cached_sets[family_index]->table) :
				NULL;
			cached[family_index] = true;
		}
		scratch->sets[i] = cached_sets[family_index];
		if (!scratch->sets[i])
			continue;
		scratch->tables[i] = cached_tables[family_index];
		if (!scratch->tables[i])
			continue;
		scratch->families[i] = family;
		if (family != NFPROTO_IPV4)
			homogeneous_v4 = false;
		if (!common_table)
			common_table = scratch->tables[i];
		else if (common_table != scratch->tables[i])
			homogeneous_v4 = false;
		valid |= BIT_ULL(i);
	}

parsed:
	if (sample) {
		u64 stamp = banset_cycles();

		parse_cycles += stamp - stage_start;
		stage_start = stamp;
	}

#if defined(CONFIG_X86_64)
	use_simd = !primary_first && lookup_mode && count > 1 &&
		   boot_cpu_has(X86_FEATURE_AVX2) &&
		   may_use_simd();
	if (use_simd)
		kernel_fpu_begin();
#endif
	if (common_table && homogeneous_v4) {
		u32 distance = min_t(u32, prefetch_distance, count);
		u32 sequence;
		u16 now = banset_epoch();
		bool retry;

		for (i = 0; i < count; i++)
			if (valid & BIT_ULL(i))
				scratch->hash[i] = banset_hash(common_table,
							       &scratch->keys[i]);
		if (sample) {
			u64 stamp = banset_cycles();

			hash_cycles += stamp - stage_start;
			stage_start = stamp;
		}
		do {
			u32 pf;
			u64 misses = 0;

			sequence = read_seqcount_begin(&common_table->seq);
			hits = 0;
			for (pf = 0; pf < distance; pf++) {
				u32 primary;

				if (!(valid & BIT_ULL(pf)))
					continue;
				primary = scratch->hash[pf] & common_table->bucket_mask;
				banset_prefetch_bucket(common_table, primary);
			}
			for (i = 0; i < count; i++) {
				u8 flag;
				int ret;

				pf = i + distance;
				if (pf < count && (valid & BIT_ULL(pf))) {
					u32 primary = scratch->hash[pf] &
						      common_table->bucket_mask;

					banset_prefetch_bucket(common_table, primary);
				}
				if (!(valid & BIT_ULL(i)))
					continue;
				if (primary_first) {
					u32 hash = scratch->hash[i];
					u16 signature = banset_signature(hash);
					u32 primary = hash & common_table->bucket_mask;

					ret = banset_lookup_bucket(common_table,
						&scratch->keys[i], signature, primary,
						now, &flag);
					if (ret)
						misses |= BIT_ULL(i);
					else
						hits |= BIT_ULL(i);
					continue;
				}
#if defined(CONFIG_X86_64)
				ret = use_simd ? banset_lookup_vector_prehashed(
					common_table, &scratch->keys[i],
					scratch->hash[i], now, &flag, lookup_mode) :
					banset_lookup_prehashed(common_table,
						&scratch->keys[i], scratch->hash[i],
						now, &flag);
#else
				ret = banset_lookup_prehashed(common_table,
					&scratch->keys[i], scratch->hash[i], now,
					&flag);
#endif
				if (!ret)
					hits |= BIT_ULL(i);
			}
			if (sample) {
				u64 stamp = banset_cycles();

				primary_cycles += stamp - stage_start;
				stage_start = stamp;
			}
			if (primary_first && misses) {
				u32 miss_count = 0;

				for (i = 0; i < count; i++) {
					u16 signature;
					u32 primary;

					if (!(misses & BIT_ULL(i)))
						continue;
					signature = banset_signature(scratch->hash[i]);
					primary = scratch->hash[i] &
						  common_table->bucket_mask;
					scratch->secondary[i] = banset_alt(common_table,
									  primary,
									  signature);
					scratch->miss_index[miss_count++] = i;
				}
				for (i = 0; i < min(distance, miss_count); i++) {
					u32 index = scratch->miss_index[i];

					banset_prefetch_bucket(common_table,
							       scratch->secondary[index]);
				}
				for (i = 0; i < miss_count; i++) {
					u8 flag;
					u16 signature;
					u32 primary;
					u32 index = scratch->miss_index[i];
					u32 pf = i + distance;

					if (pf < miss_count) {
						u32 pf_index = scratch->miss_index[pf];

						banset_prefetch_bucket(common_table,
							       scratch->secondary[pf_index]);
					}
					signature = banset_signature(scratch->hash[index]);
					primary = scratch->hash[index] &
						  common_table->bucket_mask;
					if (scratch->secondary[index] != primary &&
					    !banset_lookup_bucket(common_table,
						&scratch->keys[index], signature,
						scratch->secondary[index], now, &flag))
						hits |= BIT_ULL(index);
				}
			}
			if (sample) {
				u64 stamp = banset_cycles();

				secondary_cycles += stamp - stage_start;
				stage_start = stamp;
			}
			retry = read_seqcount_retry(&common_table->seq, sequence);
			if (retry)
				atomic64_inc(&native_seq_retries);
		} while (retry);
	} else {
		for (i = 0; i < count; i++) {
			u8 flag;
			int ret;

			if (!(valid & BIT_ULL(i)))
				continue;
#if defined(CONFIG_X86_64)
			ret = use_simd && scratch->families[i] == NFPROTO_IPV4 ?
				banset_lookup_table_vector(scratch->tables[i],
					&scratch->keys[i], &flag, lookup_mode) :
				banset_lookup_table(scratch->tables[i],
					&scratch->keys[i], &flag);
#else
			ret = banset_lookup_table(scratch->tables[i],
						  &scratch->keys[i], &flag);
#endif
			if (!ret)
				hits |= BIT_ULL(i);
		}
		if (sample) {
			u64 stamp = banset_cycles();

			primary_cycles += stamp - stage_start;
			stage_start = stamp;
		}
	}
#if defined(CONFIG_X86_64)
	if (use_simd) {
		asm volatile("vzeroupper" ::: "memory");
		kernel_fpu_end();
	}
#endif
	if (hits && refresh_threshold && refresh_threshold != U32_MAX) {
		if (fast_prng) {
			struct rnd_state *prng = this_cpu_ptr(banset_native_prng);

			for (i = 0; i < count; i++)
				scratch->random[i] = prandom_u32_state(prng);
		} else {
			get_random_bytes(scratch->random,
					 count * sizeof(scratch->random[0]));
		}
	}
	if (refresh_threshold)
		for (i = 0; i < count; i++)
			if ((hits & BIT_ULL(i)) &&
			    (refresh_threshold == U32_MAX ||
			     scratch->random[i] < refresh_threshold)) {
				if (!banset_refresh(scratch->sets[i], &scratch->keys[i],
						    scratch->sets[i]->timeout))
					timing->refreshes++;
			}
	if (sample) {
		u64 stamp = banset_cycles();

		refresh_cycles += stamp - stage_start;
		timing->samples++;
		timing->parse += parse_cycles;
		timing->hash += hash_cycles;
		timing->primary += primary_cycles;
		timing->secondary += secondary_cycles;
		timing->refresh += refresh_cycles;
		timing->total += stamp - total_start;
	}
	rcu_read_unlock_bh();
	return hits;
}

u64 x4b_banset_match_skb_batch(struct sk_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode)
{
	return banset_native_batch(packets, NULL, NULL, NULL, NULL, NULL, count,
				   refresh_threshold, lookup_mode);
}
EXPORT_SYMBOL_GPL(x4b_banset_match_skb_batch);

u64 x4b_banset_match_xdp_batch(struct xdp_buff **packets, u32 count,
				       u32 refresh_threshold, u8 lookup_mode)
{
	return banset_native_batch(NULL, packets, NULL, NULL, NULL, NULL, count,
				   refresh_threshold, lookup_mode);
}
EXPORT_SYMBOL_GPL(x4b_banset_match_xdp_batch);

u64 x4b_banset_match_frame_batch(const struct x4b_rx_frame_batch *batch,
					 struct x4b_rx_parse *parsed,
					 u32 refresh_threshold, u8 lookup_mode)
{
	return banset_native_batch(NULL, NULL, batch->frames, batch->dev,
				   batch->parsed, parsed, batch->count,
				   refresh_threshold, lookup_mode);
}
EXPORT_SYMBOL_GPL(x4b_banset_match_frame_batch);

u64 x4b_banset_native_seq_retries(void)
{
	return atomic64_read(&native_seq_retries);
}
EXPORT_SYMBOL_GPL(x4b_banset_native_seq_retries);

u64 x4b_banset_native_refreshes(void)
{
	u64 refreshes = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		refreshes += READ_ONCE(per_cpu_ptr(banset_native_timing,
						      cpu)->refreshes);
	return refreshes;
}
EXPORT_SYMBOL_GPL(x4b_banset_native_refreshes);

void x4b_banset_native_timing_read(struct x4b_banset_native_timing *out)
{
	int cpu;

	memset(out, 0, sizeof(*out));
	for_each_possible_cpu(cpu) {
		const struct banset_native_timing_cpu *timing =
			per_cpu_ptr(banset_native_timing, cpu);

		out->calls += READ_ONCE(timing->calls);
		out->samples += READ_ONCE(timing->samples);
		out->parse += READ_ONCE(timing->parse);
		out->hash += READ_ONCE(timing->hash);
		out->primary += READ_ONCE(timing->primary);
		out->secondary += READ_ONCE(timing->secondary);
		out->refresh += READ_ONCE(timing->refresh);
		out->total += READ_ONCE(timing->total);
	}
}
EXPORT_SYMBOL_GPL(x4b_banset_native_timing_read);

static u64 banset_hpfw_match_frame_batch(
	const struct x4b_rx_frame_batch *batch, u32 refresh_threshold)
{
	return x4b_banset_match_frame_batch(batch, NULL, refresh_threshold, 0);
}

static const struct x4b_hpfw_banset_provider banset_hpfw_provider = {
	.abi_version = X4B_HPFW_PROVIDER_ABI_V1,
	.struct_size = sizeof(struct x4b_hpfw_banset_provider),
	.match_frame_batch = banset_hpfw_match_frame_batch,
	.seq_retries = x4b_banset_native_seq_retries,
	.refreshes = x4b_banset_native_refreshes,
};

const struct x4b_hpfw_banset_provider *x4b_banset_hpfw_provider(void)
{
	return &banset_hpfw_provider;
}
EXPORT_SYMBOL_GPL(x4b_banset_hpfw_provider);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_x4b_banset_match(struct xdp_md *ctx,
				     u32 refresh_threshold)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	union banset_key key = {};
	struct banset_table *table;
	struct banset *set;
	const char *name;
	u8 family, flag;
	int ret;

	ret = banset_xdp_key(xdp, &key, &family);
	if (ret)
		return ret;
	if (!xdp->rxq || !xdp->rxq->dev)
		return -ENODEV;
	name = family == NFPROTO_IPV4 ? "ban" : "ban6";
	rcu_read_lock_bh();
	set = banset_find_binding_rcu(name, family, dev_net(xdp->rxq->dev));
	if (!set) {
		ret = -ENODEV;
		goto out_rcu;
	}
	table = rcu_dereference_bh(set->table);
	ret = table ? banset_lookup_table(table, &key, &flag) : -ENODEV;
	if (!ret && (refresh_threshold == U32_MAX ||
		     (refresh_threshold &&
		      get_random_u32() < refresh_threshold)))
		banset_refresh(set, &key, set->timeout);
out_rcu:
	rcu_read_unlock_bh();
	return ret ? ret : flag;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(x4b_banset_kfunc_ids)
BTF_ID_FLAGS(func, bpf_x4b_banset_match, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(x4b_banset_kfunc_ids)

static const struct btf_kfunc_id_set x4b_banset_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &x4b_banset_kfunc_ids,
};
#endif

static int __init banset_init(void)
{
	int ret;

#ifdef HAVE_X4B_HPFW_PROVIDER
	banset_native_timing = alloc_percpu(struct banset_native_timing_cpu);
	if (!banset_native_timing)
		return -ENOMEM;
	banset_native_scratch = alloc_percpu(struct banset_native_scratch);
	if (!banset_native_scratch) {
		ret = -ENOMEM;
		goto free_timing;
	}
	banset_native_prng = alloc_percpu(struct rnd_state);
	if (!banset_native_prng) {
		ret = -ENOMEM;
		goto free_scratch;
	}
	prandom_init_once(banset_native_prng);
#endif
	ret = ip_set_type_register(&banset_type);
	if (ret)
#ifdef HAVE_X4B_HPFW_PROVIDER
		goto free_prng;
#else
		return ret;
#endif
	ret = xt_register_matches(banset_matches, ARRAY_SIZE(banset_matches));
	if (ret) {
		ip_set_type_unregister(&banset_type);
#ifdef HAVE_X4B_HPFW_PROVIDER
		goto free_prng;
#else
		return ret;
#endif
	}
#ifdef HAVE_X4B_HPFW_PROVIDER
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &x4b_banset_kfunc_set);
	if (ret) {
		xt_unregister_matches(banset_matches, ARRAY_SIZE(banset_matches));
		ip_set_type_unregister(&banset_type);
		goto free_prng;
	}
	return 0;

free_prng:
	free_percpu(banset_native_prng);
free_scratch:
	free_percpu(banset_native_scratch);
free_timing:
	free_percpu(banset_native_timing);
	return ret;
#else
	return 0;
#endif
}

static void __exit banset_exit(void)
{
	xt_unregister_matches(banset_matches, ARRAY_SIZE(banset_matches));
	ip_set_type_unregister(&banset_type);
	rcu_barrier();
#ifdef HAVE_X4B_HPFW_PROVIDER
	free_percpu(banset_native_prng);
	free_percpu(banset_native_scratch);
	free_percpu(banset_native_timing);
#endif
}

module_init(banset_init);
module_exit(banset_exit);
