// SPDX-License-Identifier: GPL-2.0-only
/* X4B exact source/destination ban table and direct xtables match. */

#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
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

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/xdp.h>

#if defined(CONFIG_X86_64)
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#include <asm/simd.h>
#endif

#include "xt_banset.h"
#include "x4b_banset_native.h"

#define BANSET_REV_MIN 0
#define BANSET_REV_MAX 5
#define BANSET_SLOTS 8U
#define BANSET_INITIAL_CAPACITY (1U << 18)
#define BANSET_MAX_CAPACITY (1U << 21)
#define BANSET_BFS_MAX 1000U
#define BANSET_EPOCH_SHIFT 5
#define BANSET_DEFAULT_TTL 600U

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X4B.Net");
MODULE_DESCRIPTION("X4B direct exact-pair ban set" " (" X4B_GIT_COMMIT ")");
MODULE_ALIAS("ip_set_hash:ip,ip,flag");
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
	struct banset6_key *v6;
	u16 *signature;
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
	bool bound;
	struct net *net;
	struct ip_set *set;
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

static inline u16 banset_epoch(void)
{
	return (u16)(ktime_get_boottime_seconds() >> BANSET_EPOCH_SHIFT);
}

static inline u16 banset_expiry(u32 timeout)
{
	u32 epochs = DIV_ROUND_UP(timeout, 1U << BANSET_EPOCH_SHIFT);

	epochs = clamp_t(u32, epochs, 1, S16_MAX);
	return banset_epoch() + epochs;
}

static inline bool banset_expired(u16 expires, u16 now)
{
	return (s16)(expires - now) <= 0;
}

static size_t banset_table_memsize(const struct banset_table *table)
{
	u32 buckets = table->bucket_mask + 1;
	size_t size = sizeof(*table) +
		(size_t)table->capacity * (sizeof(*table->expires) +
					  sizeof(*table->flags)) +
		(size_t)buckets * sizeof(*table->occupied) +
		BANSET_BFS_MAX * sizeof(*table->bfs);

	if (table->family == NFPROTO_IPV4)
		size += (size_t)buckets * sizeof(*table->v4);
	else
		size += (size_t)table->capacity *
			(sizeof(*table->v6) + sizeof(*table->signature));
	return size;
}

static void banset_table_free(struct banset_table *table)
{
	if (!table)
		return;
	kvfree(table->v4);
	kvfree(table->v6);
	kvfree(table->signature);
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
	if (family == NFPROTO_IPV4)
		table->v4 = kvcalloc(buckets, sizeof(*table->v4), GFP_KERNEL);
	else {
		table->v6 = kvcalloc(capacity, sizeof(*table->v6), GFP_KERNEL);
		table->signature = kvcalloc(capacity, sizeof(*table->signature),
					    GFP_KERNEL);
	}
	table->expires = kvcalloc(capacity, sizeof(*table->expires), GFP_KERNEL);
	table->flags = kvcalloc(capacity, sizeof(*table->flags), GFP_KERNEL);
	table->occupied = kvcalloc(buckets, sizeof(*table->occupied), GFP_KERNEL);
	table->bfs = kcalloc(BANSET_BFS_MAX, sizeof(*table->bfs), GFP_KERNEL);
	if ((family == NFPROTO_IPV4 && !table->v4) ||
	    (family == NFPROTO_IPV6 && (!table->v6 || !table->signature)) ||
	    !table->expires || !table->flags || !table->occupied || !table->bfs) {
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
	return (bucket ^ signature) & table->bucket_mask;
}

static inline u32 banset_index(u32 bucket, u8 slot)
{
	return bucket * BANSET_SLOTS + slot;
}

static bool banset_key_equal(const struct banset_table *table, u32 bucket,
			     u8 slot, const union banset_key *key, u16 signature)
{
	u32 index = banset_index(bucket, slot);

	if (table->family == NFPROTO_IPV4)
		return READ_ONCE(*(const u64 *)&table->v4[bucket].key[slot]) ==
		       get_unaligned((const u64 *)&key->v4);
	if (READ_ONCE(table->signature[index]) != signature)
		return false;
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
		table->signature[index] = signature;
	}
}

static void banset_slot_clear(struct banset_table *table, u32 bucket, u8 slot)
{
	u32 index = banset_index(bucket, slot);

	if (table->family == NFPROTO_IPV4)
		memset(&table->v4[bucket].key[slot], 0,
		       sizeof(table->v4[bucket].key[slot]));
	else {
		memset(&table->v6[index], 0, sizeof(table->v6[index]));
		table->signature[index] = 0;
	}
	table->expires[index] = 0;
	table->flags[index] = 0;
	table->occupied[bucket] &= ~BIT(slot);
}

static int banset_empty_slot(const struct banset_table *table, u32 bucket)
{
	u8 occupied = table->occupied[bucket];
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
		occupied = table->occupied[bucket];
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

			if (!(table->occupied[node.bucket] & BIT(slot)))
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
					table->expires[destination_index] =
						table->expires[source_index];
					table->flags[destination_index] =
						table->flags[source_index];
					table->occupied[dst_bucket] |= BIT(dst_slot);
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
		if (!banset_expired(table->expires[index], banset_epoch()) &&
		    !update_existing)
			return -EEXIST;
		table->flags[index] = flag;
		table->expires[index] = expires;
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
	table->flags[index] = flag;
	table->expires[index] = expires;
	table->occupied[bucket] |= BIT(slot);
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

static int banset_lookup_table(const struct banset_table *table,
			       const union banset_key *key, u8 *flag)
{
	u32 hash, primary, secondary, sequence;
	u16 signature, now = banset_epoch();
	int result, candidate, slot;

	hash = banset_hash(table, key);
	signature = banset_signature(hash);
	primary = hash & table->bucket_mask;
	secondary = banset_alt(table, primary, signature);
	do {
		u32 candidates[2] = { primary, secondary };

		sequence = read_seqcount_begin(&table->seq);
		result = -ENOENT;
		for (candidate = 0; candidate < 2 && result < 0; candidate++) {
			u32 bucket = candidates[candidate];
			u8 occupied;

			if (candidate && secondary == primary)
				break;
			occupied = READ_ONCE(table->occupied[bucket]);
			for (slot = 0; slot < BANSET_SLOTS; slot++) {
				u32 index;
				u16 expires;

				if (!(occupied & BIT(slot)) ||
				    !banset_key_equal(table, bucket, slot, key,
						      signature))
					continue;
				index = banset_index(bucket, slot);
				expires = READ_ONCE(table->expires[index]);
				if (!banset_expired(expires, now)) {
					*flag = READ_ONCE(table->flags[index]);
					result = 0;
				}
				break;
			}
		}
	} while (read_seqcount_retry(&table->seq, sequence));
	return result;
}

#if defined(CONFIG_X86_64)
/* kernel_fpu_begin() must bracket this helper. */
static __always_inline u8
banset4_bucket_matches_avx2(const struct banset4_bucket *bucket,
			    const struct banset4_key *key)
{
	u32 low, high;

	asm volatile(
		"vpbroadcastq %[key], %%ymm0\n\t"
		"vpcmpeqq 0(%[bucket]), %%ymm0, %%ymm1\n\t"
		"vpmovmskb %%ymm1, %[low]\n\t"
		"vpcmpeqq 32(%[bucket]), %%ymm0, %%ymm1\n\t"
		"vpmovmskb %%ymm1, %[high]\n\t"
		"vzeroupper"
		: [low] "=&r" (low), [high] "=&r" (high)
		: [key] "m" (*(const u64 *)key), [bucket] "r" (bucket)
		: "memory");
	low = (low & 1) | ((low >> 7) & 2) | ((low >> 14) & 4) |
	      ((low >> 21) & 8);
	high = (high & 1) | ((high >> 7) & 2) | ((high >> 14) & 4) |
	       ((high >> 21) & 8);
	return low | (high << 4);
}

static int banset_lookup_table_avx2(const struct banset_table *table,
				    const union banset_key *key, u8 *flag)
{
	u32 hash, primary, secondary, sequence;
	u16 signature, now = banset_epoch();
	int result, candidate;

	if (table->family != NFPROTO_IPV4)
		return banset_lookup_table(table, key, flag);
	hash = banset_hash(table, key);
	signature = banset_signature(hash);
	primary = hash & table->bucket_mask;
	secondary = banset_alt(table, primary, signature);
	do {
		u32 candidates[2] = { primary, secondary };

		sequence = read_seqcount_begin(&table->seq);
		result = -ENOENT;
		for (candidate = 0; candidate < 2 && result < 0; candidate++) {
			u32 bucket = candidates[candidate];
			u8 matches;

			if (candidate && secondary == primary)
				break;
			matches = banset4_bucket_matches_avx2(&table->v4[bucket],
							 &key->v4) &
				  READ_ONCE(table->occupied[bucket]);
			while (matches) {
				u8 slot = __ffs(matches);
				u32 index = banset_index(bucket, slot);
				u16 expires = READ_ONCE(table->expires[index]);

				if (!banset_expired(expires, now)) {
					*flag = READ_ONCE(table->flags[index]);
					result = 0;
					break;
				}
				matches &= ~BIT(slot);
			}
		}
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
	write_seqcount_begin(&table->seq);
	found = banset_find_locked(table, key, hash, &bucket, &slot);
	if (found && !banset_expired(table->expires[found - 1], banset_epoch())) {
		table->expires[found - 1] = banset_expiry(timeout);
		ret = 0;
	}
	growing = table->growing;
	if (!ret && growing) {
		u32 grow_bucket, grow_hash = banset_hash(growing, key);
		u8 grow_slot;

		spin_lock(&growing->lock);
		write_seqcount_begin(&growing->seq);
		found = banset_find_locked(growing, key, grow_hash,
					   &grow_bucket, &grow_slot);
		if (found)
			growing->expires[found - 1] = banset_expiry(timeout);
		write_seqcount_end(&growing->seq);
		spin_unlock(&growing->lock);
	}
	write_seqcount_end(&table->seq);
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
		occupied = old->occupied[bucket];
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
			ret = __banset_upsert_locked(new, &key, old->flags[index],
						     old->expires[index], true,
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
		pr_info("set %s: grew to %u slots (%zu bytes)\n",
			set->set->name, new->capacity, banset_table_memsize(new));
	}
out_unlock:
	mutex_unlock(&set->resize_mutex);
	return ret;
}

static void banset_grow_work(struct work_struct *work)
{
	struct banset *set = container_of(work, struct banset, grow_work);

	if (banset_grow(set))
		pr_warn_ratelimited("set %s: unable to grow table\n", set->set->name);
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
		occupied = table->occupied[bucket];
		for (slot = 0; slot < BANSET_SLOTS; slot++) {
			union banset_key key;
			u32 index;
			bool ignored;

			if (!(occupied & BIT(slot)))
				continue;
			index = banset_index(bucket, slot);
			if (!banset_expired(table->expires[index], now))
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
			if (!(table->occupied[bucket] & BIT(slot))) {
				spin_unlock_bh(&table->lock);
				continue;
			}
			expires = table->expires[index];
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
					  htons(table->flags[index])) ||
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
	memset(table->occupied, 0, table->bucket_mask + 1);
	growing = table->growing;
	if (growing) {
		spin_lock(&growing->lock);
		write_seqcount_begin(&growing->seq);
		memset(growing->occupied, 0, growing->bucket_mask + 1);
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
	bool synchronize = false;

	cancel_delayed_work_sync(&set->gc_work);
	cancel_work_sync(&set->grow_work);
	mutex_lock(&banset_bindings_lock);
	if (set->bound) {
		list_del_rcu(&set->bindings);
		set->bound = false;
		synchronize = true;
	}
	mutex_unlock(&banset_bindings_lock);
	if (synchronize)
		synchronize_rcu();
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
	mutex_init(&set->resize_mutex);
	spin_lock_init(&set->update_lock);
	INIT_WORK(&set->grow_work, banset_grow_work);
	INIT_DELAYED_WORK(&set->gc_work, banset_gc_work);
	INIT_LIST_HEAD(&set->bindings);
	atomic_set(&set->elements, 0);
	set->maxelem = maxelem;
	set->timeout = ipset->timeout;
	set->family = ipset->family;
	set->net = net;
	set->set = ipset;
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
		kfree(set);
		ipset->data = NULL;
		return -EOPNOTSUPP;
	}
	mutex_lock(&banset_bindings_lock);
	list_add_tail_rcu(&set->bindings, &banset_bindings);
	set->bound = true;
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
	struct banset *set;

	list_for_each_entry(set, &banset_bindings, bindings)
		if (set->family == family && set->net == net &&
		    !strncmp(set->set->name, name,
							 IPSET_MAXNAMELEN))
			return set;
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
	struct banset *set;

	list_for_each_entry_rcu(set, &banset_bindings, bindings)
		if (set->family == family && set->net == net &&
		    !strncmp(set->set->name, name, IPSET_MAXNAMELEN))
			return set;
	return NULL;
}

static int banset_xdp_key(struct xdp_buff *xdp, union banset_key *key,
			  u8 *family)
{
	const unsigned char *data = xdp->data;
	const unsigned char *data_end = xdp->data_end;
	const struct ethhdr *eth;
	__be16 protocol;
	u32 offset = sizeof(*eth);
	int vlan;

	if (data + sizeof(*eth) > data_end)
		return -EINVAL;
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

		if ((const unsigned char *)(iph + 1) > data_end ||
		    iph->version != 4 || iph->ihl < 5 ||
		    data + offset + iph->ihl * 4 > data_end)
			return -EINVAL;
		key->v4.src = iph->saddr;
		key->v4.dst = iph->daddr;
		*family = NFPROTO_IPV4;
		return 0;
	}
	if (protocol == htons(ETH_P_IPV6)) {
		const struct ipv6hdr *ip6h =
			(const struct ipv6hdr *)(data + offset);

		if ((const unsigned char *)(ip6h + 1) > data_end ||
		    ip6h->version != 6)
			return -EINVAL;
		key->v6.src = ip6h->saddr;
		key->v6.dst = ip6h->daddr;
		*family = NFPROTO_IPV6;
		return 0;
	}
	return -EAFNOSUPPORT;
}

static u64 banset_native_batch(struct sk_buff **skbs,
			       struct xdp_buff **xdps, u32 count,
			       u32 refresh_threshold, bool simd)
{
	union banset_key keys[X4B_BANSET_NATIVE_MAX_BATCH];
	struct banset_table *tables[X4B_BANSET_NATIVE_MAX_BATCH] = {};
	struct banset *sets[X4B_BANSET_NATIVE_MAX_BATCH] = {};
	struct banset *cached_sets[2] = {};
	struct banset_table *cached_tables[2] = {};
	bool cached[2] = {};
	struct net_device *cached_dev = NULL;
	u8 families[X4B_BANSET_NATIVE_MAX_BATCH] = {};
	u64 valid = 0, hits = 0;
	bool use_simd = false;
	u32 i;

	if (!count || count > X4B_BANSET_NATIVE_MAX_BATCH)
		return 0;
	memset(keys, 0, sizeof(keys[0]) * count);
	rcu_read_lock_bh();
	for (i = 0; i < count; i++) {
		struct net_device *dev;
		u8 family_index;
		u8 family;

		if (xdps) {
			if (banset_xdp_key(xdps[i], &keys[i], &family) ||
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
			if (banset_packet_key(family, skbs[i], &keys[i]))
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
		sets[i] = cached_sets[family_index];
		if (!sets[i])
			continue;
		tables[i] = cached_tables[family_index];
		if (!tables[i])
			continue;
		families[i] = family;
		valid |= BIT_ULL(i);
	}

#if defined(CONFIG_X86_64)
	use_simd = simd && count > 1 && boot_cpu_has(X86_FEATURE_AVX2) &&
		   may_use_simd();
	if (use_simd)
		kernel_fpu_begin();
#endif
	for (i = 0; i < count; i++) {
		u8 flag;
		int ret;

		if (!(valid & BIT_ULL(i)))
			continue;
#if defined(CONFIG_X86_64)
		ret = use_simd && families[i] == NFPROTO_IPV4 ?
			banset_lookup_table_avx2(tables[i], &keys[i], &flag) :
			banset_lookup_table(tables[i], &keys[i], &flag);
#else
		ret = banset_lookup_table(tables[i], &keys[i], &flag);
#endif
		if (!ret)
			hits |= BIT_ULL(i);
	}
#if defined(CONFIG_X86_64)
	if (use_simd)
		kernel_fpu_end();
#endif
	if (refresh_threshold)
		for (i = 0; i < count; i++)
			if ((hits & BIT_ULL(i)) &&
			    (refresh_threshold == U32_MAX ||
			     get_random_u32() < refresh_threshold))
				banset_refresh(sets[i], &keys[i], sets[i]->timeout);
	rcu_read_unlock_bh();
	return hits;
}

u64 x4b_banset_match_skb_batch(struct sk_buff **packets, u32 count,
				       u32 refresh_threshold, bool simd)
{
	return banset_native_batch(packets, NULL, count, refresh_threshold, simd);
}
EXPORT_SYMBOL_GPL(x4b_banset_match_skb_batch);

u64 x4b_banset_match_xdp_batch(struct xdp_buff **packets, u32 count,
				       u32 refresh_threshold, bool simd)
{
	return banset_native_batch(NULL, packets, count, refresh_threshold, simd);
}
EXPORT_SYMBOL_GPL(x4b_banset_match_xdp_batch);

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

static int __init banset_init(void)
{
	int ret;

	ret = ip_set_type_register(&banset_type);
	if (ret)
		return ret;
	ret = xt_register_matches(banset_matches, ARRAY_SIZE(banset_matches));
	if (ret) {
		ip_set_type_unregister(&banset_type);
		return ret;
	}
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &x4b_banset_kfunc_set);
	if (ret) {
		xt_unregister_matches(banset_matches, ARRAY_SIZE(banset_matches));
		ip_set_type_unregister(&banset_type);
	}
	return ret;
}

static void __exit banset_exit(void)
{
	xt_unregister_matches(banset_matches, ARRAY_SIZE(banset_matches));
	ip_set_type_unregister(&banset_type);
	rcu_barrier();
}

module_init(banset_init);
module_exit(banset_exit);
