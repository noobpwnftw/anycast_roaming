
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <net/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <net/netfilter/nf_conntrack_core.h>

//#define LOCAL_POC

rwlock_t g_addr_rwlock;

struct anycast_roaming_notify_list_entry {
	struct list_head list;
	__u32 addr;
} __attribute__((__packed__));

struct anycast_roaming_addr_entry {
	struct list_head list;
	__u32 anycast_ip;
	__u32 my_notify_addr;
	int mode;
	int reroute;
	struct list_head notify_list;
} __attribute__((__packed__));

struct anycast_roaming_notify_addr_entry {
	struct list_head list;
	__u32 saddr;
	__u32 daddr;
} __attribute__((__packed__));

struct anycast_roaming_tuple {
	__u32 saddr;
	__u32 daddr;
} __attribute__((__packed__));

struct anycast_roaming_notify_entry {
	struct list_head list;
	struct anycast_roaming_tuple tuple;
	__u32 origin;
	atomic_t refcnt;
	struct timer_list timer;
	unsigned long timeout;
	volatile __u16 flags;
} __attribute__((__packed__));

struct anycast_roaming_sent_notify_entry {
	struct list_head list;
	struct anycast_roaming_tuple tuple;
	atomic_t refcnt;
	struct timer_list timer;
	unsigned long timeout;
	volatile __u16 flags;
} __attribute__((__packed__));

struct anycast_roaming_rpath_entry {
	struct list_head list;
	struct anycast_roaming_tuple tuple;
	__u32 origin;
	atomic_t refcnt;
	struct timer_list timer;
	unsigned long timeout;
	volatile __u16 flags;
} __attribute__((__packed__));

static struct list_head *anycast_roaming_addr_tab;
static struct list_head *anycast_roaming_notify_tab;
static struct list_head *anycast_roaming_notify_addr_tab;
static struct list_head *anycast_roaming_sent_notify_tab;
static struct list_head *anycast_roaming_rpath_tab;
static struct kmem_cache *anycast_roaming_cachep_a __read_mostly;
static struct kmem_cache *anycast_roaming_cachep_l __read_mostly;
static struct kmem_cache *anycast_roaming_cachep_na __read_mostly;
static struct kmem_cache *anycast_roaming_cachep_n __read_mostly;
static struct kmem_cache *anycast_roaming_cachep_s __read_mostly;
static struct kmem_cache *anycast_roaming_cachep_r __read_mostly;
static atomic_t anycast_roaming_notify_count = ATOMIC_INIT(0);
static atomic_t anycast_roaming_sent_notify_count = ATOMIC_INIT(0);
static atomic_t anycast_roaming_rpath_count = ATOMIC_INIT(0);
static unsigned int anycast_roaming_notify_rnd;

enum {
	ANYCAST_ROAMING_NOTIFY = 0,
	ANYCAST_ROAMING_ENCAP_IN,
	ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM,
	ANYCAST_ROAMING_ENCAP_OUT,
	ANYCAST_ROAMING_REROUTE_IN,
	ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM
};

enum {
	ANYCAST_ROAMING_IDLE_TIMEOUT = 0,
	ANYCAST_ROAMING_NOTIFY_INTERVAL,
	ANYCAST_ROAMING_LAST
};

enum {
	ANYCAST_ROAMING_MODE_ROAMING = 0,
	ANYCAST_ROAMING_MODE_FORWARD,
	ANYCAST_ROAMING_MODE_TUNNEL,
	ANYCAST_ROAMING_MODE_RELAY
};

static struct ctl_table_header *sysctl_header;

int sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_LAST] = {
	[ANYCAST_ROAMING_IDLE_TIMEOUT]    = 310 * HZ,
	[ANYCAST_ROAMING_NOTIFY_INTERVAL] = 130 * HZ,
};

enum {
	ANYCAST_ROAMING_FORWARD_IN_CNT = 1,
	ANYCAST_ROAMING_FORWARD_OUT_CNT,
	ANYCAST_ROAMING_RELAY_IN_CNT,
	ANYCAST_ROAMING_RELAY_OUT_CNT,
	ANYCAST_ROAMING_DECAPSULATE_IN_CNT,
	ANYCAST_ROAMING_DECAPSULATE_OUT_CNT,
	ANYCAST_ROAMING_REROUTE_IN_CNT,
	ANYCAST_ROAMING_RECV_NOTIFY_CNT,
	ANYCAST_ROAMING_SENT_NOTIFY_CNT,
	ANYCAST_ROAMING_STAT_LAST
};

struct anycast_roaming_stats_entry {
	char *name;
	int entry;
};

#define ANYCAST_ROAMING_STAT_ITEM(_name, _entry) { \
	.name = _name,		\
	.entry = _entry,	\
}

#define ANYCAST_ROAMING_STAT_END {	\
	NULL,		\
	0,		\
}

struct anycast_roaming_stat_mib {
	unsigned long mibs[ANYCAST_ROAMING_STAT_LAST];
};

#define DEFINE_ANYCAST_ROAMING_STAT(type, name)       \
	(__typeof__(type) *name)

#define ANYCAST_ROAMING_INC_STATS(mib, field)         \
	(per_cpu_ptr(mib, smp_processor_id())->mibs[field]++)

struct anycast_roaming_stats_entry anycast_roaming_stats[] = {
	ANYCAST_ROAMING_STAT_ITEM("FORWARD_IN", ANYCAST_ROAMING_FORWARD_IN_CNT),
	ANYCAST_ROAMING_STAT_ITEM("FORWARD_OUT", ANYCAST_ROAMING_FORWARD_OUT_CNT),
	ANYCAST_ROAMING_STAT_ITEM("RELAY_IN", ANYCAST_ROAMING_RELAY_IN_CNT),
	ANYCAST_ROAMING_STAT_ITEM("RELAY_OUT", ANYCAST_ROAMING_RELAY_OUT_CNT),
	ANYCAST_ROAMING_STAT_ITEM("DECAPSULATE_IN", ANYCAST_ROAMING_DECAPSULATE_IN_CNT),
	ANYCAST_ROAMING_STAT_ITEM("DECAPSULATE_OUT", ANYCAST_ROAMING_DECAPSULATE_OUT_CNT),
	ANYCAST_ROAMING_STAT_ITEM("REROUTE_IN", ANYCAST_ROAMING_REROUTE_IN_CNT),
	ANYCAST_ROAMING_STAT_ITEM("RECV_NOTIFY", ANYCAST_ROAMING_RECV_NOTIFY_CNT),
	ANYCAST_ROAMING_STAT_ITEM("SENT_NOTIFY", ANYCAST_ROAMING_SENT_NOTIFY_CNT),
	ANYCAST_ROAMING_STAT_END
};

struct anycast_roaming_stat_mib *ext_stats;

#define ANYCAST_ROAMING_ADDR_TAB_BITS 8
#define ANYCAST_ROAMING_ADDR_TAB_SIZE (1 << ANYCAST_ROAMING_ADDR_TAB_BITS)
#define ANYCAST_ROAMING_ADDR_TAB_MASK (ANYCAST_ROAMING_ADDR_TAB_SIZE - 1)

#define ANYCAST_ROAMING_LOCKARRAY_BITS  8
#define ANYCAST_ROAMING_LOCKARRAY_SIZE  (1 << ANYCAST_ROAMING_LOCKARRAY_BITS)
#define ANYCAST_ROAMING_LOCKARRAY_MASK  (ANYCAST_ROAMING_LOCKARRAY_SIZE - 1)

#define ANYCAST_ROAMING_NOTIFY_TAB_BITS 12
#define ANYCAST_ROAMING_NOTIFY_TAB_SIZE (1 << ANYCAST_ROAMING_NOTIFY_TAB_BITS)
#define ANYCAST_ROAMING_NOTIFY_TAB_MASK (ANYCAST_ROAMING_NOTIFY_TAB_SIZE - 1)

#define ANYCAST_ROAMING_NOTIFY_F_HASHED	0x0040

struct anycast_roaming_aligned_lock {
	spinlock_t l;
} __attribute__ ((__aligned__(SMP_CACHE_BYTES)));

static struct anycast_roaming_aligned_lock anycast_roaming_notifytbl_lock_array[ANYCAST_ROAMING_LOCKARRAY_SIZE] __cacheline_aligned;
static struct anycast_roaming_aligned_lock anycast_roaming_sentnotifytbl_lock_array[ANYCAST_ROAMING_LOCKARRAY_SIZE] __cacheline_aligned;
static struct anycast_roaming_aligned_lock anycast_roaming_rpathtbl_lock_array[ANYCAST_ROAMING_LOCKARRAY_SIZE] __cacheline_aligned;

static inline void anycast_roaming_notify_lock(unsigned key)
{
	spin_lock_bh(&anycast_roaming_notifytbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static inline void anycast_roaming_notify_unlock(unsigned key)
{
	spin_unlock_bh(&anycast_roaming_notifytbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static inline void anycast_roaming_sent_notify_lock(unsigned key)
{
	spin_lock_bh(&anycast_roaming_sentnotifytbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static inline void anycast_roaming_sent_notify_unlock(unsigned key)
{
	spin_unlock_bh(&anycast_roaming_sentnotifytbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static inline void anycast_roaming_rpath_lock(unsigned key)
{
	spin_lock_bh(&anycast_roaming_rpathtbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static inline void anycast_roaming_rpath_unlock(unsigned key)
{
	spin_unlock_bh(&anycast_roaming_rpathtbl_lock_array[key & ANYCAST_ROAMING_LOCKARRAY_MASK].l);
}

static unsigned int anycast_roaming_tuple_hash(struct anycast_roaming_tuple *tuple)
{
	return jhash_2words((__force u32) tuple->saddr, (__force u32) tuple->daddr, anycast_roaming_notify_rnd) & ANYCAST_ROAMING_NOTIFY_TAB_MASK;
}

static int anycast_roaming_hash_n(struct anycast_roaming_notify_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_notify_lock(hash);

	if (!(entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED)) {
		list_add(&entry->list, &anycast_roaming_notify_tab[hash]);
		entry->flags |= ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_inc(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_notify_unlock(hash);

	return ret;
}

static int anycast_roaming_unhash_n(struct anycast_roaming_notify_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_notify_lock(hash);

	if ((entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED) && (atomic_read(&entry->refcnt) == 2)) {
		list_del(&entry->list);
		entry->flags &= ~ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_dec(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_notify_unlock(hash);

	return ret;
}

static int anycast_roaming_hash_s(struct anycast_roaming_sent_notify_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_sent_notify_lock(hash);

	if (!(entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED)) {
		list_add(&entry->list, &anycast_roaming_sent_notify_tab[hash]);
		entry->flags |= ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_inc(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_sent_notify_unlock(hash);

	return ret;
}

static int anycast_roaming_unhash_s(struct anycast_roaming_sent_notify_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_sent_notify_lock(hash);

	if ((entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED) && (atomic_read(&entry->refcnt) == 2)) {
		list_del(&entry->list);
		entry->flags &= ~ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_dec(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_sent_notify_unlock(hash);

	return ret;
}


static int anycast_roaming_hash_r(struct anycast_roaming_rpath_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_rpath_lock(hash);

	if (!(entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED)) {
		list_add(&entry->list, &anycast_roaming_rpath_tab[hash]);
		entry->flags |= ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_inc(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_rpath_unlock(hash);

	return ret;
}

static int anycast_roaming_unhash_r(struct anycast_roaming_rpath_entry *entry)
{
	unsigned hash;
	int ret;

	hash = anycast_roaming_tuple_hash(&entry->tuple);

	anycast_roaming_rpath_lock(hash);

	if ((entry->flags & ANYCAST_ROAMING_NOTIFY_F_HASHED) && (atomic_read(&entry->refcnt) == 2)) {
		list_del(&entry->list);
		entry->flags &= ~ANYCAST_ROAMING_NOTIFY_F_HASHED;
		atomic_dec(&entry->refcnt);
		ret = 1;
	} else {
		ret = 0;
	}

	anycast_roaming_rpath_unlock(hash);

	return ret;
}

void anycast_roaming_notify_put(struct anycast_roaming_notify_entry *entry)
{
	atomic_dec(&entry->refcnt);
}

void anycast_roaming_sent_notify_put(struct anycast_roaming_sent_notify_entry *entry)
{
	atomic_dec(&entry->refcnt);
}

void anycast_roaming_rpath_put(struct anycast_roaming_rpath_entry *entry)
{
	atomic_dec(&entry->refcnt);
}

void anycast_roaming_notify_expire_now(struct anycast_roaming_notify_entry *entry)
{
	if (del_timer(&entry->timer))
		mod_timer(&entry->timer, jiffies);
}

void anycast_roaming_sent_notify_expire_now(struct anycast_roaming_sent_notify_entry *entry)
{
	if (del_timer(&entry->timer))
		mod_timer(&entry->timer, jiffies);
}

void anycast_roaming_rpath_expire_now(struct anycast_roaming_rpath_entry *entry)
{
	if (del_timer(&entry->timer))
		mod_timer(&entry->timer, jiffies);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static void anycast_roaming_expire_n(unsigned long data)
{
	struct anycast_roaming_notify_entry *entry = (struct anycast_roaming_notify_entry *)data;
#else
static void anycast_roaming_expire_n(struct timer_list *t)
{
	struct anycast_roaming_notify_entry *entry = (struct anycast_roaming_notify_entry *)from_timer(entry, t, timer);
#endif
	atomic_inc(&entry->refcnt);

	if (!anycast_roaming_unhash_n(entry))
		goto expire_later;

	if (likely(atomic_read(&entry->refcnt) == 1)) {
		if (timer_pending(&entry->timer))
			del_timer(&entry->timer);
		
		atomic_dec(&anycast_roaming_notify_count);
		kmem_cache_free(anycast_roaming_cachep_n, entry);
		return;
	}

	anycast_roaming_hash_n(entry);

expire_later:
	mod_timer(&entry->timer, jiffies + 2 * HZ);
	anycast_roaming_notify_put(entry);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static void anycast_roaming_expire_s(unsigned long data)
{
	struct anycast_roaming_sent_notify_entry *entry = (struct anycast_roaming_sent_notify_entry *)data;
#else
static void anycast_roaming_expire_s(struct timer_list *t)
{
	struct anycast_roaming_sent_notify_entry *entry = (struct anycast_roaming_sent_notify_entry *)from_timer(entry, t, timer);
#endif
	atomic_inc(&entry->refcnt);

	if (!anycast_roaming_unhash_s(entry))
		goto expire_later;

	if (likely(atomic_read(&entry->refcnt) == 1)) {
		if (timer_pending(&entry->timer))
			del_timer(&entry->timer);
		
		atomic_dec(&anycast_roaming_sent_notify_count);
		kmem_cache_free(anycast_roaming_cachep_s, entry);
		return;
	}

	anycast_roaming_hash_s(entry);

expire_later:
	mod_timer(&entry->timer, jiffies + 2 * HZ);
	anycast_roaming_sent_notify_put(entry);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static void anycast_roaming_expire_r(unsigned long data)
{
	struct anycast_roaming_rpath_entry *entry = (struct anycast_roaming_rpath_entry *)data;
#else
static void anycast_roaming_expire_r(struct timer_list *t)
{
	struct anycast_roaming_rpath_entry *entry = (struct anycast_roaming_rpath_entry *)from_timer(entry, t, timer);
#endif
	atomic_inc(&entry->refcnt);

	if (!anycast_roaming_unhash_r(entry))
		goto expire_later;

	if (likely(atomic_read(&entry->refcnt) == 1)) {
		if (timer_pending(&entry->timer))
			del_timer(&entry->timer);
		
		atomic_dec(&anycast_roaming_rpath_count);
		kmem_cache_free(anycast_roaming_cachep_r, entry);
		return;
	}

	anycast_roaming_hash_r(entry);

expire_later:
	mod_timer(&entry->timer, jiffies + 2 * HZ);
	anycast_roaming_rpath_put(entry);
}

struct anycast_roaming_notify_entry *anycast_roaming_notify_new(struct anycast_roaming_tuple *tuple, __u32 origin)
{
	struct anycast_roaming_notify_entry *entry;

	entry = kmem_cache_zalloc(anycast_roaming_cachep_n, GFP_ATOMIC);
	if (entry == NULL) {
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	setup_timer(&entry->timer, anycast_roaming_expire_n, (unsigned long)entry);
#else
	timer_setup(&entry->timer, anycast_roaming_expire_n, 0);
#endif
	entry->tuple = *tuple;
	entry->origin = origin;
	entry->flags = 0;

	atomic_set(&entry->refcnt, 1);
	atomic_inc(&anycast_roaming_notify_count);

	entry->timeout = sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_IDLE_TIMEOUT];

	anycast_roaming_hash_n(entry);

	mod_timer(&entry->timer, jiffies + entry->timeout);
	return entry;
}

struct anycast_roaming_sent_notify_entry *anycast_roaming_sent_notify_new(struct anycast_roaming_tuple *tuple)
{
	struct anycast_roaming_sent_notify_entry *entry;

	entry = kmem_cache_zalloc(anycast_roaming_cachep_s, GFP_ATOMIC);
	if (entry == NULL) {
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	setup_timer(&entry->timer, anycast_roaming_expire_s, (unsigned long)entry);
#else
	timer_setup(&entry->timer, anycast_roaming_expire_s, 0);
#endif
	entry->tuple = *tuple;
	entry->flags = 0;

	atomic_set(&entry->refcnt, 1);
	atomic_inc(&anycast_roaming_sent_notify_count);

	entry->timeout = sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_NOTIFY_INTERVAL];

	anycast_roaming_hash_s(entry);

	mod_timer(&entry->timer, jiffies + entry->timeout);
	return entry;
}

struct anycast_roaming_rpath_entry *anycast_roaming_rpath_new(struct anycast_roaming_tuple *tuple, __u32 origin)
{
	struct anycast_roaming_rpath_entry *entry;

	entry = kmem_cache_zalloc(anycast_roaming_cachep_r, GFP_ATOMIC);
	if (entry == NULL) {
		return NULL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	setup_timer(&entry->timer, anycast_roaming_expire_r, (unsigned long)entry);
#else
	timer_setup(&entry->timer, anycast_roaming_expire_r, 0);
#endif
	entry->tuple = *tuple;
	entry->origin = origin;
	entry->flags = 0;

	atomic_set(&entry->refcnt, 1);
	atomic_inc(&anycast_roaming_rpath_count);

	entry->timeout = sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_IDLE_TIMEOUT];

	anycast_roaming_hash_r(entry);

	mod_timer(&entry->timer, jiffies + entry->timeout);
	return entry;
}

struct anycast_roaming_addr_entry *anycast_roaming_addr_lookup(__u32 addr)
{
	struct anycast_roaming_addr_entry *entry;

	list_for_each_entry(entry, &anycast_roaming_addr_tab[jhash_1word(addr, anycast_roaming_notify_rnd) & ANYCAST_ROAMING_ADDR_TAB_MASK], list) {
		if (entry->anycast_ip == addr) {
			return entry;
		}
	}
	return NULL;
}

bool anycast_roaming_is_notify_addr(__u32 saddr, __u32 daddr)
{
	struct anycast_roaming_notify_addr_entry *entry;

	read_lock_bh(&g_addr_rwlock);
	list_for_each_entry(entry, &anycast_roaming_notify_addr_tab[jhash_2words(saddr, daddr, anycast_roaming_notify_rnd) & ANYCAST_ROAMING_ADDR_TAB_MASK], list) {
		if (entry->saddr == saddr && entry->daddr == daddr) {
			read_unlock_bh(&g_addr_rwlock);
			return true;
		}
	}
	read_unlock_bh(&g_addr_rwlock);
	return false;
}

struct anycast_roaming_notify_entry *anycast_roaming_notify_get(struct anycast_roaming_tuple *tuple)
{
	unsigned hash;
	struct anycast_roaming_notify_entry *entry;

	hash = anycast_roaming_tuple_hash(tuple);

	anycast_roaming_notify_lock(hash);
	list_for_each_entry(entry, &anycast_roaming_notify_tab[hash], list) {
		if (!memcmp(&entry->tuple, tuple, sizeof(struct anycast_roaming_tuple))) {
			atomic_inc(&entry->refcnt);
			anycast_roaming_notify_unlock(hash);
			return entry;
		}
	}
	anycast_roaming_notify_unlock(hash);
	return NULL;
}

struct anycast_roaming_sent_notify_entry *anycast_roaming_sent_notify_get(struct anycast_roaming_tuple *tuple)
{
	unsigned hash;
	struct anycast_roaming_sent_notify_entry *entry;

	hash = anycast_roaming_tuple_hash(tuple);

	anycast_roaming_sent_notify_lock(hash);
	list_for_each_entry(entry, &anycast_roaming_sent_notify_tab[hash], list) {
		if (!memcmp(&entry->tuple, tuple, sizeof(struct anycast_roaming_tuple))) {
			atomic_inc(&entry->refcnt);
			anycast_roaming_sent_notify_unlock(hash);
			return entry;
		}
	}
	anycast_roaming_sent_notify_unlock(hash);
	return NULL;
}

struct anycast_roaming_rpath_entry *anycast_roaming_rpath_get(struct anycast_roaming_tuple *tuple)
{
	unsigned hash;
	struct anycast_roaming_rpath_entry *entry;

	hash = anycast_roaming_tuple_hash(tuple);

	anycast_roaming_rpath_lock(hash);
	list_for_each_entry(entry, &anycast_roaming_rpath_tab[hash], list) {
		if (!memcmp(&entry->tuple, tuple, sizeof(struct anycast_roaming_tuple))) {
			atomic_inc(&entry->refcnt);
			anycast_roaming_rpath_unlock(hash);
			return entry;
		}
	}
	anycast_roaming_rpath_unlock(hash);
	return NULL;
}

static void anycast_roaming_notify_flush(void)
{
	int idx;
	struct anycast_roaming_notify_entry *entry;

flush_again:
	for (idx = 0; idx < ANYCAST_ROAMING_NOTIFY_TAB_SIZE; idx++) {
		anycast_roaming_notify_lock(idx);

		list_for_each_entry(entry, &anycast_roaming_notify_tab[idx], list) {
			anycast_roaming_notify_expire_now(entry);
		}
		anycast_roaming_notify_unlock(idx);
	}
	if (atomic_read(&anycast_roaming_notify_count) != 0) {
		schedule();
		goto flush_again;
	}
}

static void anycast_roaming_sent_notify_flush(void)
{
	int idx;
	struct anycast_roaming_sent_notify_entry *entry;

flush_again:
	for (idx = 0; idx < ANYCAST_ROAMING_NOTIFY_TAB_SIZE; idx++) {
		anycast_roaming_sent_notify_lock(idx);

		list_for_each_entry(entry, &anycast_roaming_sent_notify_tab[idx], list) {
			anycast_roaming_sent_notify_expire_now(entry);
		}
		anycast_roaming_sent_notify_unlock(idx);
	}
	if (atomic_read(&anycast_roaming_sent_notify_count) != 0) {
		schedule();
		goto flush_again;
	}
}

static void anycast_roaming_rpath_flush(void)
{
	int idx;
	struct anycast_roaming_rpath_entry *entry;

flush_again:
	for (idx = 0; idx < ANYCAST_ROAMING_NOTIFY_TAB_SIZE; idx++) {
		anycast_roaming_rpath_lock(idx);

		list_for_each_entry(entry, &anycast_roaming_rpath_tab[idx], list) {
			anycast_roaming_rpath_expire_now(entry);
		}
		anycast_roaming_rpath_unlock(idx);
	}
	if (atomic_read(&anycast_roaming_rpath_count) != 0) {
		schedule();
		goto flush_again;
	}
}

int __init anycast_roaming_notify_init(void)
{
	int idx;

	anycast_roaming_notify_tab = vmalloc(ANYCAST_ROAMING_NOTIFY_TAB_SIZE * (sizeof(struct list_head)));
	if (!anycast_roaming_notify_tab) {
		return -ENOMEM;
	}

	anycast_roaming_sent_notify_tab = vmalloc(ANYCAST_ROAMING_NOTIFY_TAB_SIZE * (sizeof(struct list_head)));
	if (!anycast_roaming_sent_notify_tab) {
		vfree(anycast_roaming_notify_tab);
		return -ENOMEM;
	}

	anycast_roaming_rpath_tab = vmalloc(ANYCAST_ROAMING_NOTIFY_TAB_SIZE * (sizeof(struct list_head)));
	if (!anycast_roaming_rpath_tab) {
		vfree(anycast_roaming_notify_tab);
		vfree(anycast_roaming_sent_notify_tab);
		return -ENOMEM;
	}

	anycast_roaming_cachep_n = kmem_cache_create("anycast_roaming_notify", sizeof(struct anycast_roaming_notify_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_n) {
		vfree(anycast_roaming_notify_tab);
		vfree(anycast_roaming_sent_notify_tab);
		vfree(anycast_roaming_rpath_tab);
		return -ENOMEM;
	}

	anycast_roaming_cachep_s = kmem_cache_create("anycast_roaming_sent_notify", sizeof(struct anycast_roaming_sent_notify_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_s) {
		kmem_cache_destroy(anycast_roaming_cachep_n);
		vfree(anycast_roaming_notify_tab);
		vfree(anycast_roaming_sent_notify_tab);
		vfree(anycast_roaming_rpath_tab);
		return -ENOMEM;
	}

	anycast_roaming_cachep_r = kmem_cache_create("anycast_roaming_rpath", sizeof(struct anycast_roaming_rpath_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_r) {
		kmem_cache_destroy(anycast_roaming_cachep_n);
		kmem_cache_destroy(anycast_roaming_cachep_s);
		vfree(anycast_roaming_notify_tab);
		vfree(anycast_roaming_sent_notify_tab);
		vfree(anycast_roaming_rpath_tab);
		return -ENOMEM;
	}

	for (idx = 0; idx < ANYCAST_ROAMING_NOTIFY_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&anycast_roaming_notify_tab[idx]);
		INIT_LIST_HEAD(&anycast_roaming_sent_notify_tab[idx]);
		INIT_LIST_HEAD(&anycast_roaming_rpath_tab[idx]);
	}

	for (idx = 0; idx < ANYCAST_ROAMING_LOCKARRAY_SIZE; idx++) {
		spin_lock_init(&anycast_roaming_notifytbl_lock_array[idx].l);
		spin_lock_init(&anycast_roaming_sentnotifytbl_lock_array[idx].l);
		spin_lock_init(&anycast_roaming_rpathtbl_lock_array[idx].l);
	}

	return 0;
}

void anycast_roaming_notify_cleanup(void)
{
	anycast_roaming_rpath_flush();
	anycast_roaming_sent_notify_flush();
	anycast_roaming_notify_flush();
	kmem_cache_destroy(anycast_roaming_cachep_n);
	kmem_cache_destroy(anycast_roaming_cachep_s);
	kmem_cache_destroy(anycast_roaming_cachep_r);
	vfree(anycast_roaming_notify_tab);
	vfree(anycast_roaming_sent_notify_tab);
	vfree(anycast_roaming_rpath_tab);
}

static void send_notify(struct net *net, struct anycast_roaming_addr_entry *addr_entry, struct anycast_roaming_tuple *tuple)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct icmphdr *icmph;
	struct anycast_roaming_tuple *tuple_hdr;
	struct anycast_roaming_notify_list_entry *notify_entry;
	unsigned int icmp_offset;
	struct rtable *rt;
	struct flowi4 fl4 = {};
	unsigned int hh_len;
	fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
	fl4.saddr = addr_entry->my_notify_addr;

	list_for_each_entry(notify_entry, &addr_entry->notify_list, list) {
#if !defined(LOCAL_POC)
		if (notify_entry->addr == addr_entry->my_notify_addr) {
			struct anycast_roaming_notify_entry *entry, *new_entry;
			entry = anycast_roaming_notify_get(tuple);
			new_entry = anycast_roaming_notify_new(tuple, addr_entry->my_notify_addr);
			if (new_entry) {
				anycast_roaming_notify_put(new_entry);
			}
			if (entry) {
				anycast_roaming_notify_expire_now(entry);
				anycast_roaming_notify_put(entry);
			}
			continue;
		}
#endif
		fl4.daddr = notify_entry->addr;
		rt = ip_route_output_key(net, &fl4);
		if (IS_ERR(rt)) {
			continue;
		}
		hh_len = rt->dst.dev->hard_header_len;
		skb = alloc_skb(hh_len + sizeof(*iph) + sizeof(*icmph) + sizeof(*tuple_hdr), GFP_ATOMIC);

		if (skb == NULL) {
			ip_rt_put(rt);
			return;
		}
		skb_reserve(skb, hh_len);
		skb_set_network_header(skb, 0);
		iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
		iph->version    = 4;
		iph->ihl        = sizeof(*iph) >> 2;
		iph->tos        = 0;
		iph->id         = 0;
		iph->frag_off   = htons(IP_DF);
		iph->ttl        = 60;
		iph->protocol   = IPPROTO_ICMP;
		iph->check      = 0;
		iph->saddr      = addr_entry->my_notify_addr;
		iph->daddr      = notify_entry->addr;
		iph->tot_len    = htons(sizeof(*iph) + sizeof(*icmph) + sizeof(*tuple_hdr));
		ip_send_check(iph);

		icmph = (struct icmphdr *)skb_put(skb, sizeof(*icmph));
		icmph->type = ICMP_ECHOREPLY;
		icmph->code = 0;
		icmph->un.echo.id = 0xACAC;
		icmph->un.echo.sequence = ANYCAST_ROAMING_NOTIFY;
		icmp_offset = (unsigned char *)icmph - skb->data;

		tuple_hdr = (struct anycast_roaming_tuple*)skb_put(skb, sizeof(*tuple_hdr));
		memcpy(tuple_hdr, tuple, sizeof(*tuple_hdr));

		icmph->checksum = 0;
		icmph->checksum = csum_fold(skb_checksum(skb, icmp_offset, skb->len - icmp_offset, 0));
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_dst_set(skb, &rt->dst);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
		dst_output(skb);
#else
		dst_output(net, NULL, skb);
#endif
		ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_SENT_NOTIFY_CNT);
	}
}

static void send_encapsulated(struct net *net, __u32 my_notify_addr, __u32 origin, struct sk_buff *skb, __u8 type)
{
	struct iphdr *iph;
	struct icmphdr *icmph;
	int data_len = ntohs(ip_hdr(skb)->tot_len);
	struct rtable *rt;
	struct flowi4 fl4 = {};
	unsigned int head_len;
	fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
	fl4.saddr = my_notify_addr;
	fl4.daddr = origin;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(skb);
		return;
	}
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);
	/*
	if (likely(ip_hdr(skb)->frag_off & htons(IP_DF))) {
		int mtu = dst_mtu(&rt->dst);
		if (sizeof(*iph) + sizeof(*icmph) + data_len > mtu) {
			if (type != ANYCAST_ROAMING_ENCAP_OUT) {
				if (inet_addr_type(net, ip_hdr(skb)->daddr) == RTN_LOCAL) {
					rt->rt_flags |= RTCF_LOCAL;
				}
			}
			icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu - sizeof(*iph) - sizeof(*icmph)));
			kfree_skb(skb);
			return;
		}
	} else {
		skb->ignore_df = 1;
	}
	*/
	skb->ignore_df = 1;
	head_len = rt->dst.dev->hard_header_len + sizeof(*iph) + sizeof(*icmph);
	if (skb_headroom(skb) < head_len && pskb_expand_head(skb, ALIGN(head_len - skb_headroom(skb), NET_SKB_PAD), 0, GFP_ATOMIC)) {
		kfree_skb(skb);
		return;
	}
	icmph = (struct icmphdr *)skb_push(skb, sizeof(*icmph));
	icmph->type = ICMP_ECHOREPLY;
	icmph->code = 0;
	icmph->un.echo.id = 0xACAC;
	icmph->un.echo.sequence = type;

	iph = (struct iphdr *)skb_push(skb, sizeof(*iph));
	iph->version    = 4;
	iph->ihl        = sizeof(*iph) >> 2;
	iph->tos        = 0;
	iph->frag_off   = htons(IP_DF);
	iph->ttl        = 60;
	iph->protocol   = IPPROTO_ICMP;
	iph->check      = 0;
	iph->saddr      = my_notify_addr;
	iph->daddr      = origin;
	iph->tot_len    = htons(sizeof(*iph) + sizeof(*icmph) + data_len);
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, iph->ihl << 2);
	ip_select_ident(net, skb, NULL);
	ip_send_check(iph);

	icmph->checksum = 0;
	icmph->checksum = csum_fold(skb_checksum(skb, sizeof(*iph), data_len + sizeof(*icmph), 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	dst_output(skb);
#else
	dst_output(net, NULL, skb);
#endif
	switch (type) {
	case ANYCAST_ROAMING_ENCAP_IN:
	case ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM:
		ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_FORWARD_IN_CNT);
		break;
	case ANYCAST_ROAMING_REROUTE_IN:
	case ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM:
		ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_REROUTE_IN_CNT);
		break;
	default:
		ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_FORWARD_OUT_CNT);
		break;
	}
}

static void send_relay(struct net *net, __u32 my_notify_addr, __u32 origin, struct sk_buff *skb)
{
	struct iphdr *iph;
	struct rtable *rt;
	struct flowi4 fl4 = {};

	if (ip_hdr(skb)->ttl <= 1) {
		kfree_skb(skb);
		return;
	}

	if (!skb_make_writable(skb, sizeof(struct iphdr))) {
		kfree_skb(skb);
		return;
	}

	fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
	fl4.saddr = my_notify_addr;
	fl4.daddr = origin;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt)) {
		kfree_skb(skb);
		return;
	}

	skb->ignore_df = 1;

	iph = ip_hdr(skb);
	iph->ttl--;
	iph->check = 0;
	iph->saddr = my_notify_addr;
	iph->daddr = origin;
	ip_send_check(iph);

	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb_dst_drop(skb);
	skb_dst_set(skb, &rt->dst);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	dst_output(skb);
#else
	dst_output(net, NULL, skb);
#endif
}

static void relay_notify(struct net *net, __u32 origin, struct anycast_roaming_addr_entry *addr_entry, struct anycast_roaming_tuple *tuple)
{
	struct sk_buff *skb;
	struct iphdr *iph;
	struct icmphdr *icmph;
	struct anycast_roaming_tuple *tuple_hdr;
	struct anycast_roaming_notify_list_entry *notify_entry;
	unsigned int icmp_offset;
	struct rtable *rt;
	struct flowi4 fl4 = {};
	unsigned int hh_len;
	fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
	fl4.saddr = addr_entry->my_notify_addr;

	list_for_each_entry(notify_entry, &addr_entry->notify_list, list) {
		if (notify_entry->addr == addr_entry->my_notify_addr || notify_entry->addr == origin) {
			continue;
		}
		fl4.daddr = notify_entry->addr;
		rt = ip_route_output_key(net, &fl4);
		if (IS_ERR(rt)) {
			continue;
		}
		hh_len = rt->dst.dev->hard_header_len;
		skb = alloc_skb(hh_len + sizeof(*iph) + sizeof(*icmph) + sizeof(*tuple_hdr), GFP_ATOMIC);

		if (skb == NULL) {
			ip_rt_put(rt);
			return;
		}
		skb_reserve(skb, hh_len);
		skb_set_network_header(skb, 0);
		iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
		iph->version    = 4;
		iph->ihl        = sizeof(*iph) >> 2;
		iph->tos        = 0;
		iph->id         = 0;
		iph->frag_off   = htons(IP_DF);
		iph->ttl        = 60;
		iph->protocol   = IPPROTO_ICMP;
		iph->check      = 0;
		iph->saddr      = addr_entry->my_notify_addr;
		iph->daddr      = notify_entry->addr;
		iph->tot_len    = htons(sizeof(*iph) + sizeof(*icmph) + sizeof(*tuple_hdr));
		ip_send_check(iph);

		icmph = (struct icmphdr *)skb_put(skb, sizeof(*icmph));
		icmph->type = ICMP_ECHOREPLY;
		icmph->code = 0;
		icmph->un.echo.id = 0xACAC;
		icmph->un.echo.sequence = ANYCAST_ROAMING_NOTIFY;
		icmp_offset = (unsigned char *)icmph - skb->data;

		tuple_hdr = (struct anycast_roaming_tuple*)skb_put(skb, sizeof(*tuple_hdr));
		memcpy(tuple_hdr, tuple, sizeof(*tuple_hdr));

		icmph->checksum = 0;
		icmph->checksum = csum_fold(skb_checksum(skb, icmp_offset, skb->len - icmp_offset, 0));
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_dst_set(skb, &rt->dst);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
		dst_output(skb);
#else
		dst_output(net, NULL, skb);
#endif
		ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_SENT_NOTIFY_CNT);
	}
}

inline bool is_notify_tcp(struct tcphdr *th)
{
	if (!(th->syn && th->ack) && !th->fin && !th->rst) {
		return true;
	} else {
		return false;
	}
}

inline bool is_notify_udp(struct net *net, struct udphdr *uh)
{
	int low, high;
	inet_get_local_port_range(net, &low, &high);
	if (uh->source >= low && uh->source <= high) {
		return true;
	} else {
		return false;
	}
}

inline bool is_notify_icmp(struct icmphdr *icmph)
{
	if (icmph->type == ICMP_ECHO || icmph->type == ICMP_TIMESTAMP || icmph->type == ICMP_INFO_REQUEST || icmph->type == ICMP_ADDRESS) {
		return true;
	} else {
		return false;
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static unsigned int
anycast_roaming_in_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			const struct nf_hook_state * state)
#else
static unsigned int
anycast_roaming_in_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#endif
{
	struct iphdr *ih;
	int hdr_len;

	if (skb->pkt_type != PACKET_HOST) {
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		goto out;
	}

	if (ip_is_fragment(ip_hdr(skb))) {
		int err;
		local_bh_disable();
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
		err = ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER);
#else
		err = ip_defrag(state->net, skb, IP_DEFRAG_LOCAL_DELIVER);
#endif
		local_bh_enable();
		if (err) {
			return NF_STOLEN;
		}
	}

	ih = ip_hdr(skb);
	hdr_len = ih->ihl << 2;

	if (ih->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmph;
		if (!pskb_may_pull(skb, hdr_len + sizeof(struct icmphdr))) {
			goto out;
		}
		icmph = icmp_hdr(skb);
		if (icmph->type == ICMP_DEST_UNREACH && icmph->code == ICMP_FRAG_NEEDED) {
			struct anycast_roaming_addr_entry* addr_entry;
			read_lock_bh(&g_addr_rwlock);
			addr_entry = anycast_roaming_addr_lookup(ih->daddr);
			if (!addr_entry) {
				read_unlock_bh(&g_addr_rwlock);
				goto out;
			}
			if (addr_entry->mode == ANYCAST_ROAMING_MODE_FORWARD || addr_entry->mode == ANYCAST_ROAMING_MODE_TUNNEL) {
				struct anycast_roaming_notify_list_entry* notify_entry;
				notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
#if !defined(LOCAL_POC)
				if (notify_entry->addr == addr_entry->my_notify_addr) {
					struct iphdr _fake_ih, *fake_ih;
					struct anycast_roaming_tuple tuple;
					struct anycast_roaming_rpath_entry *rpath_entry;
					read_unlock_bh(&g_addr_rwlock);
					fake_ih = skb_header_pointer(skb, hdr_len + sizeof(*icmph), sizeof(_fake_ih), &_fake_ih);
					if (unlikely(fake_ih == NULL)) {
						goto out;
					}
					tuple.saddr = fake_ih->daddr;
					tuple.daddr = fake_ih->saddr;
					rpath_entry = anycast_roaming_rpath_get(&tuple);
					if (rpath_entry) {
						anycast_roaming_rpath_expire_now(rpath_entry);
						anycast_roaming_rpath_put(rpath_entry);
					}
					goto out;
				}
#endif
				memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
				IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
				nf_reset(skb);
				if (!skb_is_gso(skb)) {
					send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, skb_csum_unnecessary(skb) ? ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM : ANYCAST_ROAMING_ENCAP_IN);
				} else {
					struct sk_buff *segs;
					segs = skb_gso_segment(skb, 0);
					if (unlikely(IS_ERR(segs))) {
						read_unlock_bh(&g_addr_rwlock);
						return NF_DROP;
					}
					kfree_skb(skb);
					do {
						struct sk_buff *nskb = segs->next;
						segs->next = NULL;
						send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM);
						segs = nskb;
					} while (segs);
				}
				read_unlock_bh(&g_addr_rwlock);
				return NF_STOLEN;
			} else {
				struct iphdr _fake_ih, *fake_ih;
				struct anycast_roaming_tuple tuple;
				struct anycast_roaming_notify_entry *entry;
				struct anycast_roaming_rpath_entry *rpath_entry;
				fake_ih = skb_header_pointer(skb, hdr_len + sizeof(*icmph), sizeof(_fake_ih), &_fake_ih);
				if (unlikely(fake_ih == NULL)) {
					read_unlock_bh(&g_addr_rwlock);
					goto rx_out2;
				}
				tuple.saddr = fake_ih->daddr;
				tuple.daddr = fake_ih->saddr;
				rpath_entry = anycast_roaming_rpath_get(&tuple);
				if (rpath_entry) {
					anycast_roaming_rpath_expire_now(rpath_entry);
					anycast_roaming_rpath_put(rpath_entry);
				}
				entry = anycast_roaming_notify_get(&tuple);
				if (entry) {
					if (entry->origin != addr_entry->my_notify_addr) {
						memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
						IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
						nf_reset(skb);
						if (!skb_is_gso(skb)) {
							send_encapsulated(state->net, addr_entry->my_notify_addr, entry->origin, skb, skb_csum_unnecessary(skb) ? ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM : ANYCAST_ROAMING_ENCAP_IN);
						} else {
							struct sk_buff *segs;
							segs = skb_gso_segment(skb, 0);
							if (unlikely(IS_ERR(segs))) {
								read_unlock_bh(&g_addr_rwlock);
								anycast_roaming_notify_put(entry);
								return NF_DROP;
							}
							kfree_skb(skb);
							do {
								struct sk_buff *nskb = segs->next;
								segs->next = NULL;
								send_encapsulated(state->net, addr_entry->my_notify_addr, entry->origin, segs, ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM);
								segs = nskb;
							} while (segs);
						}
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_notify_put(entry);
						return NF_STOLEN;
					}
					anycast_roaming_notify_put(entry);
				}
				read_unlock_bh(&g_addr_rwlock);
			}
		} else if (icmph->type == ICMP_ECHOREPLY && icmph->code == 0 && icmph->un.echo.id == 0xACAC) {
			if (anycast_roaming_is_notify_addr(ih->saddr, ih->daddr)) {
				int data_len = ntohs(ih->tot_len) - hdr_len;
				if (csum_fold(skb_checksum(skb, hdr_len, data_len, 0))) {
					return NF_DROP;
				}
				switch(icmph->un.echo.sequence) {
				case ANYCAST_ROAMING_NOTIFY:
				{
					struct anycast_roaming_addr_entry* addr_entry;
					struct anycast_roaming_notify_entry *entry, *new_entry;
					struct anycast_roaming_tuple _tuple_hdr, *tuple_hdr;
					tuple_hdr = skb_header_pointer(skb, hdr_len + sizeof(*icmph), sizeof(_tuple_hdr), &_tuple_hdr);
					if (unlikely(tuple_hdr == NULL)) {
						goto out;
					}
					read_lock_bh(&g_addr_rwlock);
					addr_entry = anycast_roaming_addr_lookup(tuple_hdr->daddr);
					if (!addr_entry) {
						read_unlock_bh(&g_addr_rwlock);
						goto out;
					}
					if (addr_entry->mode == ANYCAST_ROAMING_MODE_RELAY) {
						struct anycast_roaming_notify_list_entry* notify_entry;
						notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
						if (notify_entry->addr == addr_entry->my_notify_addr) {
							read_unlock_bh(&g_addr_rwlock);
							goto out;
						}
						if (ih->saddr == notify_entry->addr) {
							relay_notify(state->net, ih->saddr, addr_entry, tuple_hdr);
							read_unlock_bh(&g_addr_rwlock);
							return NF_DROP;
						} else {
							memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
							IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
							nf_reset(skb);
							send_relay(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb);
							read_unlock_bh(&g_addr_rwlock);
							ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_SENT_NOTIFY_CNT);
							return NF_STOLEN;
						}
					}
					read_unlock_bh(&g_addr_rwlock);
					entry = anycast_roaming_notify_get(tuple_hdr);
					new_entry = anycast_roaming_notify_new(tuple_hdr, ih->saddr);
					if (new_entry) {
						anycast_roaming_notify_put(new_entry);
					}
					if (entry) {
						anycast_roaming_notify_expire_now(entry);
						anycast_roaming_notify_put(entry);
					}
					ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_RECV_NOTIFY_CNT);
					return NF_DROP;
				}
				case ANYCAST_ROAMING_ENCAP_IN:
				case ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM:
				case ANYCAST_ROAMING_REROUTE_IN:
				case ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM:
				{
					struct iphdr _inner_ih, *inner_ih;
					struct anycast_roaming_tuple tuple;
					struct anycast_roaming_rpath_entry *rpath_entry, *new_rpath_entry;
					int err;
					struct anycast_roaming_addr_entry* addr_entry;
					inner_ih = skb_header_pointer(skb, hdr_len + sizeof(*icmph), sizeof(_inner_ih), &_inner_ih);
					if (unlikely(inner_ih == NULL)) {
						goto out;
					}
					read_lock_bh(&g_addr_rwlock);
					addr_entry = anycast_roaming_addr_lookup(inner_ih->daddr);
					if (!addr_entry) {
						read_unlock_bh(&g_addr_rwlock);
						goto out;
					}
					if (inner_ih->protocol == IPPROTO_ICMP) {
						struct icmphdr _inner_icmph, *inner_icmph;
						inner_icmph = skb_header_pointer(skb, hdr_len + sizeof(*icmph) + (inner_ih->ihl << 2), sizeof(_inner_icmph), &_inner_icmph);
						if (unlikely(inner_icmph == NULL)) {
							read_unlock_bh(&g_addr_rwlock);
							goto out;
						}
						if (inner_icmph->type == ICMP_DEST_UNREACH && inner_icmph->code == ICMP_FRAG_NEEDED) {
							struct iphdr _fake_ih, *fake_ih;
							fake_ih = skb_header_pointer(skb, hdr_len + sizeof(*icmph) + (inner_ih->ihl << 2) + sizeof(_inner_icmph), sizeof(_fake_ih), &_fake_ih);
							if (unlikely(fake_ih == NULL)) {
								goto rx_out;
							}
							tuple.saddr = fake_ih->daddr;
							tuple.daddr = fake_ih->saddr;
							rpath_entry = anycast_roaming_rpath_get(&tuple);
							if (rpath_entry) {
								if(rpath_entry->origin != ih->saddr && rpath_entry->origin != addr_entry->my_notify_addr) {
									anycast_roaming_rpath_expire_now(rpath_entry);
									new_rpath_entry = anycast_roaming_rpath_new(&tuple, ih->saddr);
									if (new_rpath_entry) {
										anycast_roaming_rpath_put(new_rpath_entry);
									}
								} else {
									mod_timer(&rpath_entry->timer, jiffies + rpath_entry->timeout);
								}
								anycast_roaming_rpath_put(rpath_entry);
							} else {
								if (icmph->un.echo.sequence == ANYCAST_ROAMING_ENCAP_IN || icmph->un.echo.sequence == ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM) {
									new_rpath_entry = anycast_roaming_rpath_new(&tuple, ih->saddr);
								} else {
									new_rpath_entry = anycast_roaming_rpath_new(&tuple, addr_entry->my_notify_addr);
								}
								if (new_rpath_entry) {
									anycast_roaming_rpath_put(new_rpath_entry);
								}
							}
							goto rx_out1;
						}
					}
rx_out:
					tuple.saddr = inner_ih->saddr;
					tuple.daddr = inner_ih->daddr;
					rpath_entry = anycast_roaming_rpath_get(&tuple);
					if (rpath_entry) {
						if(rpath_entry->origin != ih->saddr && rpath_entry->origin != addr_entry->my_notify_addr) {
							anycast_roaming_rpath_expire_now(rpath_entry);
							new_rpath_entry = anycast_roaming_rpath_new(&tuple, ih->saddr);
							if (new_rpath_entry) {
								anycast_roaming_rpath_put(new_rpath_entry);
							}
						} else {
							mod_timer(&rpath_entry->timer, jiffies + rpath_entry->timeout);
						}
						anycast_roaming_rpath_put(rpath_entry);
					} else {
						if (icmph->un.echo.sequence == ANYCAST_ROAMING_ENCAP_IN || icmph->un.echo.sequence == ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM) {
							new_rpath_entry = anycast_roaming_rpath_new(&tuple, ih->saddr);
						} else {
							new_rpath_entry = anycast_roaming_rpath_new(&tuple, addr_entry->my_notify_addr);
						}
						if (new_rpath_entry) {
							anycast_roaming_rpath_put(new_rpath_entry);
						}
					}
rx_out1:
					if (addr_entry->mode == ANYCAST_ROAMING_MODE_RELAY) {
						struct anycast_roaming_notify_list_entry* notify_entry;
						notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
						if (notify_entry->addr == addr_entry->my_notify_addr) {
							read_unlock_bh(&g_addr_rwlock);
							goto out;
						}
						memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
						IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
						nf_reset(skb);
						send_relay(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb);
						read_unlock_bh(&g_addr_rwlock);
						ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_RELAY_IN_CNT);
						return NF_STOLEN;
					}
					read_unlock_bh(&g_addr_rwlock);
					if (icmph->un.echo.sequence == ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM || icmph->un.echo.sequence == ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM) {
						skb->ip_summed = CHECKSUM_UNNECESSARY;
					} else {
						skb->ip_summed = CHECKSUM_NONE;
					}
					if (unlikely(skb_linearize(skb))) {
						return NF_DROP;
					}
					nf_reset(skb);
					skb_pull(skb, hdr_len + sizeof(*icmph));
					skb_reset_network_header(skb);
					skb_set_transport_header(skb, ip_hdr(skb)->ihl << 2);
					do {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
						err = nf_conntrack_in(state->net, AF_INET, NF_INET_PRE_ROUTING, skb);
#else
						err = nf_conntrack_in(skb, state);
#endif
					} while (err == NF_REPEAT);
					if (err != NF_ACCEPT) {
						return NF_DROP;
					}
					ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_DECAPSULATE_IN_CNT);
					goto out;
				}
				case ANYCAST_ROAMING_ENCAP_OUT:
				{
					struct rtable *rt;
					struct flowi4 fl4 = {};
					struct iphdr _inner_ih, *inner_ih;
					struct anycast_roaming_addr_entry* addr_entry;
					inner_ih = skb_header_pointer(skb, hdr_len + sizeof(*icmph), sizeof(_inner_ih), &_inner_ih);
					if (unlikely(inner_ih == NULL)) {
						goto out;
					}
					read_lock_bh(&g_addr_rwlock);
					addr_entry = anycast_roaming_addr_lookup(inner_ih->saddr);
					if (!addr_entry) {
						read_unlock_bh(&g_addr_rwlock);
						goto out;
					}
					if (addr_entry->mode == ANYCAST_ROAMING_MODE_RELAY) {
						struct anycast_roaming_tuple tuple;
						struct anycast_roaming_rpath_entry *rpath_entry;
						struct anycast_roaming_notify_list_entry* notify_entry;
						tuple.saddr = inner_ih->daddr;
						tuple.daddr = inner_ih->saddr;
						rpath_entry = anycast_roaming_rpath_get(&tuple);
						if (rpath_entry) {
							memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
							IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
							nf_reset(skb);
							send_relay(state->net, addr_entry->my_notify_addr, rpath_entry->origin, skb);
							read_unlock_bh(&g_addr_rwlock);
							anycast_roaming_rpath_put(rpath_entry);
							ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_RELAY_OUT_CNT);
							return NF_STOLEN;
						} else {
							notify_entry = list_last_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
							if (notify_entry->addr == addr_entry->my_notify_addr) {
								read_unlock_bh(&g_addr_rwlock);
								goto out;
							}
							memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
							IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
							nf_reset(skb);
							send_relay(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb);
							read_unlock_bh(&g_addr_rwlock);
							ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_RELAY_OUT_CNT);
							return NF_STOLEN;
						}
					}
					read_unlock_bh(&g_addr_rwlock);
					fl4.flowi4_flags = FLOWI_FLAG_ANYSRC;
					fl4.saddr = inner_ih->saddr;
					fl4.daddr = inner_ih->daddr;
					rt = ip_route_output_key(state->net, &fl4);
					if (IS_ERR(rt)) {
						return NF_DROP;
					}
					if (unlikely(skb_linearize(skb))) {
						ip_rt_put(rt);
						return NF_DROP;
					}
					memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
					IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
					nf_reset(skb);
					skb_pull(skb, hdr_len + sizeof(*icmph));
					skb_reset_network_header(skb);
					skb_set_transport_header(skb, ip_hdr(skb)->ihl << 2);
					skb_dst_drop(skb);
					skb_dst_set(skb, &rt->dst);
					IPCB(skb)->flags |= IPSKB_REROUTED;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
					dst_output(skb);
#else
					dst_output(state->net, NULL, skb);
#endif
					ANYCAST_ROAMING_INC_STATS(ext_stats, ANYCAST_ROAMING_DECAPSULATE_OUT_CNT);
					return NF_STOLEN;
				}
				default:
					break;
				}
			}
		}
	}
rx_out2:
	if (ih->protocol == IPPROTO_TCP || ih->protocol == IPPROTO_UDP || ih->protocol == IPPROTO_ICMP) {
		struct anycast_roaming_addr_entry* addr_entry;
		read_lock_bh(&g_addr_rwlock);
		addr_entry = anycast_roaming_addr_lookup(ih->daddr);
		if (!addr_entry) {
			read_unlock_bh(&g_addr_rwlock);
			goto out;
		}
		if (addr_entry->mode == ANYCAST_ROAMING_MODE_FORWARD || addr_entry->mode == ANYCAST_ROAMING_MODE_TUNNEL) {
			struct anycast_roaming_notify_list_entry* notify_entry;
			notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
#if !defined(LOCAL_POC)
			if (notify_entry->addr == addr_entry->my_notify_addr) {
				struct anycast_roaming_tuple tuple;
				struct anycast_roaming_rpath_entry *rpath_entry;
				read_unlock_bh(&g_addr_rwlock);
				tuple.saddr = ih->saddr;
				tuple.daddr = ih->daddr;
				rpath_entry = anycast_roaming_rpath_get(&tuple);
				if (rpath_entry) {
					anycast_roaming_rpath_expire_now(rpath_entry);
					anycast_roaming_rpath_put(rpath_entry);
				}
				goto out;
			}
#endif
			memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
			IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
			nf_reset(skb);
			if (!skb_is_gso(skb)) {
				send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, skb_csum_unnecessary(skb) ? ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM : ANYCAST_ROAMING_ENCAP_IN);
			} else {
				struct sk_buff *segs;
				segs = skb_gso_segment(skb, 0);
				if (unlikely(IS_ERR(segs))) {
					read_unlock_bh(&g_addr_rwlock);
					return NF_DROP;
				}
				kfree_skb(skb);
				do {
					struct sk_buff *nskb = segs->next;
					segs->next = NULL;
					send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM);
					segs = nskb;
				} while (segs);
			}
			read_unlock_bh(&g_addr_rwlock);
			return NF_STOLEN;
		} else {
			struct anycast_roaming_tuple tuple;
			struct anycast_roaming_notify_entry *entry;
			struct anycast_roaming_rpath_entry *rpath_entry;
			tuple.saddr = ih->saddr;
			tuple.daddr = ih->daddr;
			rpath_entry = anycast_roaming_rpath_get(&tuple);
			if (rpath_entry) {
				anycast_roaming_rpath_expire_now(rpath_entry);
				anycast_roaming_rpath_put(rpath_entry);
			}
			entry = anycast_roaming_notify_get(&tuple);
			if (entry) {
				if (entry->origin != addr_entry->my_notify_addr) {
					memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
					IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
					nf_reset(skb);
					if (!skb_is_gso(skb)) {
						send_encapsulated(state->net, addr_entry->my_notify_addr, entry->origin, skb, skb_csum_unnecessary(skb) ? ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM : ANYCAST_ROAMING_ENCAP_IN);
					} else {
						struct sk_buff *segs;
						segs = skb_gso_segment(skb, 0);
						if (unlikely(IS_ERR(segs))) {
							read_unlock_bh(&g_addr_rwlock);
							anycast_roaming_notify_put(entry);
							return NF_DROP;
						}
						kfree_skb(skb);
						do {
							struct sk_buff *nskb = segs->next;
							segs->next = NULL;
							send_encapsulated(state->net, addr_entry->my_notify_addr, entry->origin, segs, ANYCAST_ROAMING_ENCAP_IN_NO_CHECKSUM);
							segs = nskb;
						} while (segs);
					}
					read_unlock_bh(&g_addr_rwlock);
					anycast_roaming_notify_put(entry);
					return NF_STOLEN;
				}
				anycast_roaming_notify_put(entry);
			} else if (addr_entry->reroute > 0) {
				unsigned long rand;
				get_random_bytes(&rand, sizeof(rand));
		 		if (rand % 100 <= addr_entry->reroute) {
					struct anycast_roaming_notify_list_entry* notify_entry;
					notify_entry = list_last_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
					if (notify_entry->addr == addr_entry->my_notify_addr) {
						read_unlock_bh(&g_addr_rwlock);
						goto out;
					}
					memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
					IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
					nf_reset(skb);
					if (!skb_is_gso(skb)) {
						send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, skb_csum_unnecessary(skb) ? ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM : ANYCAST_ROAMING_REROUTE_IN);
					} else {
						struct sk_buff *segs;
						segs = skb_gso_segment(skb, 0);
						if (unlikely(IS_ERR(segs))) {
							read_unlock_bh(&g_addr_rwlock);
							return NF_DROP;
						}
						kfree_skb(skb);
						do {
							struct sk_buff *nskb = segs->next;
							segs->next = NULL;
							send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_REROUTE_IN_NO_CHECKSUM);
							segs = nskb;
						} while (segs);
					}
					read_unlock_bh(&g_addr_rwlock);
					return NF_STOLEN;
				}
			}
			read_unlock_bh(&g_addr_rwlock);
		}
	}
out:
	return NF_ACCEPT;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
static unsigned int
anycast_roaming_out_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			const struct nf_hook_state * state)
#else
static unsigned int
anycast_roaming_out_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#endif
{
	struct iphdr *ih;
	int hdr_len;
	struct anycast_roaming_tuple tuple;
	struct anycast_roaming_rpath_entry *rpath_entry;
	struct anycast_roaming_sent_notify_entry *sent_entry;
	struct anycast_roaming_addr_entry* addr_entry;

	if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
		goto out;
	}

	ih = ip_hdr(skb);
	hdr_len = ih->ihl << 2;

	if (ih->saddr == ih->daddr) {
		goto out;
	}

	read_lock_bh(&g_addr_rwlock);
	addr_entry = anycast_roaming_addr_lookup(ih->saddr);
	if (!addr_entry) {
		read_unlock_bh(&g_addr_rwlock);
		goto out;
	}

	tuple.saddr = ih->daddr;
	tuple.daddr = ih->saddr;

	if (ih->protocol == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, hdr_len + sizeof(struct tcphdr))) {
			read_unlock_bh(&g_addr_rwlock);
			goto out;
		}
		if (addr_entry->mode == ANYCAST_ROAMING_MODE_ROAMING && is_notify_tcp(tcp_hdr(skb))) {
			sent_entry = anycast_roaming_sent_notify_get(&tuple);
			if (!sent_entry) {
				send_notify(state->net, addr_entry, &tuple);
				sent_entry = anycast_roaming_sent_notify_new(&tuple);
			}
			if (sent_entry) {
				anycast_roaming_sent_notify_put(sent_entry);
			}
		}
		rpath_entry = anycast_roaming_rpath_get(&tuple);
		if (rpath_entry) {
			if (rpath_entry->origin == addr_entry->my_notify_addr) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				goto out;
			}
			if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				return NF_DROP;
			}
			memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
			IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
			nf_reset(skb);
			if (!skb_is_gso(skb)) {
				if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
					int data_len = ntohs(ih->tot_len) - hdr_len;
					if (!skb_make_writable(skb, hdr_len + sizeof(struct tcphdr))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					tcp_hdr(skb)->check = 0;
					tcp_hdr(skb)->check = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, data_len, ip_hdr(skb)->protocol, skb_checksum(skb, hdr_len, data_len, 0));
				}
				send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, skb, ANYCAST_ROAMING_ENCAP_OUT);
			} else {
				struct sk_buff *segs;
				segs = skb_gso_segment(skb, 0);
				if (unlikely(IS_ERR(segs))) {
					read_unlock_bh(&g_addr_rwlock);
					anycast_roaming_rpath_put(rpath_entry);
					return NF_DROP;
				}
				kfree_skb(skb);
				do {
					struct sk_buff *nskb = segs->next;
					segs->next = NULL;
					send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, segs, ANYCAST_ROAMING_ENCAP_OUT);
					segs = nskb;
				} while (segs);
			}
			read_unlock_bh(&g_addr_rwlock);
			anycast_roaming_rpath_put(rpath_entry);
			return NF_STOLEN;
		} else if(addr_entry->mode == ANYCAST_ROAMING_MODE_TUNNEL) {
#if !defined(LOCAL_POC)
			struct anycast_roaming_notify_list_entry* notify_entry;
			notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
			if (notify_entry->addr == addr_entry->my_notify_addr) {
				notify_entry = list_last_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
				if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
					read_unlock_bh(&g_addr_rwlock);
					return NF_DROP;
				}
				memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
				IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
				nf_reset(skb);
				if (!skb_is_gso(skb)) {
					if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
						int data_len = ntohs(ih->tot_len) - hdr_len;
						if (!skb_make_writable(skb, hdr_len + sizeof(struct tcphdr))) {
							read_unlock_bh(&g_addr_rwlock);
							anycast_roaming_rpath_put(rpath_entry);
							return NF_DROP;
						}
						tcp_hdr(skb)->check = 0;
						tcp_hdr(skb)->check = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, data_len, ip_hdr(skb)->protocol, skb_checksum(skb, hdr_len, data_len, 0));
					}
					send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, ANYCAST_ROAMING_ENCAP_OUT);
				} else {
					struct sk_buff *segs;
					segs = skb_gso_segment(skb, 0);
					if (unlikely(IS_ERR(segs))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					kfree_skb(skb);
					do {
						struct sk_buff *nskb = segs->next;
						segs->next = NULL;
						send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_ENCAP_OUT);
						segs = nskb;
					} while (segs);
				}
				read_unlock_bh(&g_addr_rwlock);
				return NF_STOLEN;
			}
#endif
		}
	} else if (ih->protocol == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, hdr_len + sizeof(struct udphdr))) {
			read_unlock_bh(&g_addr_rwlock);
			goto out;
		}
		if (addr_entry->mode == ANYCAST_ROAMING_MODE_ROAMING && is_notify_udp(state->net, udp_hdr(skb))) {
			sent_entry = anycast_roaming_sent_notify_get(&tuple);
			if (!sent_entry) {
				send_notify(state->net, addr_entry, &tuple);
				sent_entry = anycast_roaming_sent_notify_new(&tuple);
			}
			if (sent_entry) {
				anycast_roaming_sent_notify_put(sent_entry);
			}
		}
		rpath_entry = anycast_roaming_rpath_get(&tuple);
		if (rpath_entry) {
			if (rpath_entry->origin == addr_entry->my_notify_addr) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				goto out;
			}
			if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				return NF_DROP;
			}
			memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
			IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
			nf_reset(skb);
			if (!skb_is_gso(skb)) {
				if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
					int data_len = ntohs(ih->tot_len) - hdr_len;
					if (!skb_make_writable(skb, hdr_len + sizeof(struct udphdr))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					udp_hdr(skb)->check = 0;
					udp_hdr(skb)->check = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, data_len, ip_hdr(skb)->protocol, skb_checksum(skb, hdr_len, data_len, 0));
				}
				send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, skb, ANYCAST_ROAMING_ENCAP_OUT);
			} else {
				struct sk_buff *segs;
				segs = skb_gso_segment(skb, 0);
				if (unlikely(IS_ERR(segs))) {
					read_unlock_bh(&g_addr_rwlock);
					anycast_roaming_rpath_put(rpath_entry);
					return NF_DROP;
				}
				kfree_skb(skb);
				do {
					struct sk_buff *nskb = segs->next;
					segs->next = NULL;
					send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, segs, ANYCAST_ROAMING_ENCAP_OUT);
					segs = nskb;
				} while (segs);
			}
			read_unlock_bh(&g_addr_rwlock);
			anycast_roaming_rpath_put(rpath_entry);
			return NF_STOLEN;
		} else if(addr_entry->mode == ANYCAST_ROAMING_MODE_TUNNEL) {
#if !defined(LOCAL_POC)
			struct anycast_roaming_notify_list_entry* notify_entry;
			notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
			if (notify_entry->addr == addr_entry->my_notify_addr) {
				notify_entry = list_last_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
				if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
					read_unlock_bh(&g_addr_rwlock);
					return NF_DROP;
				}
				memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
				IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
				nf_reset(skb);
				if (!skb_is_gso(skb)) {
					if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
						int data_len = ntohs(ih->tot_len) - hdr_len;
						if (!skb_make_writable(skb, hdr_len + sizeof(struct udphdr))) {
							read_unlock_bh(&g_addr_rwlock);
							anycast_roaming_rpath_put(rpath_entry);
							return NF_DROP;
						}
						udp_hdr(skb)->check = 0;
						udp_hdr(skb)->check = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr, data_len, ip_hdr(skb)->protocol, skb_checksum(skb, hdr_len, data_len, 0));
					}
					send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, ANYCAST_ROAMING_ENCAP_OUT);
				} else {
					struct sk_buff *segs;
					segs = skb_gso_segment(skb, 0);
					if (unlikely(IS_ERR(segs))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					kfree_skb(skb);
					do {
						struct sk_buff *nskb = segs->next;
						segs->next = NULL;
						send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_ENCAP_OUT);
						segs = nskb;
					} while (segs);
				}
				read_unlock_bh(&g_addr_rwlock);
				return NF_STOLEN;
			}
#endif
		}
	} else if (ih->protocol == IPPROTO_ICMP) {
		if (!pskb_may_pull(skb, hdr_len + sizeof(struct icmphdr))) {
			read_unlock_bh(&g_addr_rwlock);
			goto out;
		}
		if (addr_entry->mode == ANYCAST_ROAMING_MODE_ROAMING && is_notify_icmp(icmp_hdr(skb))) {
			sent_entry = anycast_roaming_sent_notify_get(&tuple);
			if (!sent_entry) {
				send_notify(state->net, addr_entry, &tuple);
				sent_entry = anycast_roaming_sent_notify_new(&tuple);
			}
			if (sent_entry) {
				anycast_roaming_sent_notify_put(sent_entry);
			}
		}
		rpath_entry = anycast_roaming_rpath_get(&tuple);
		if (rpath_entry) {
			if (rpath_entry->origin == addr_entry->my_notify_addr) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				goto out;
			}
			if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
				read_unlock_bh(&g_addr_rwlock);
				anycast_roaming_rpath_put(rpath_entry);
				return NF_DROP;
			}
			memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
			IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
			nf_reset(skb);
			if (!skb_is_gso(skb)) {
				if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
					int data_len = ntohs(ih->tot_len) - hdr_len;
					if (!skb_make_writable(skb, hdr_len + sizeof(struct icmphdr))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					icmp_hdr(skb)->checksum = 0;
					icmp_hdr(skb)->checksum = csum_fold(skb_checksum(skb, hdr_len, data_len, 0));
				}
				send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, skb, ANYCAST_ROAMING_ENCAP_OUT);
			} else {
				struct sk_buff *segs;
				segs = skb_gso_segment(skb, 0);
				if (unlikely(IS_ERR(segs))) {
					read_unlock_bh(&g_addr_rwlock);
					anycast_roaming_rpath_put(rpath_entry);
					return NF_DROP;
				}
				kfree_skb(skb);
				do {
					struct sk_buff *nskb = segs->next;
					segs->next = NULL;
					send_encapsulated(state->net, addr_entry->my_notify_addr, rpath_entry->origin, segs, ANYCAST_ROAMING_ENCAP_OUT);
					segs = nskb;
				} while (segs);
			}
			read_unlock_bh(&g_addr_rwlock);
			anycast_roaming_rpath_put(rpath_entry);
			return NF_STOLEN;
		} else if(addr_entry->mode == ANYCAST_ROAMING_MODE_TUNNEL) {
#if !defined(LOCAL_POC)
			struct anycast_roaming_notify_list_entry* notify_entry;
			notify_entry = list_first_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
			if (notify_entry->addr == addr_entry->my_notify_addr) {
				notify_entry = list_last_entry(&addr_entry->notify_list, struct anycast_roaming_notify_list_entry, list);
				if (nf_conntrack_confirm(skb) != NF_ACCEPT) {
					read_unlock_bh(&g_addr_rwlock);
					return NF_DROP;
				}
				memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
				IPCB(skb)->flags &= ~(IPSKB_XFRM_TUNNEL_SIZE | IPSKB_XFRM_TRANSFORMED | IPSKB_REROUTED);
				nf_reset(skb);
				if (!skb_is_gso(skb)) {
					if (skb->ip_summed != CHECKSUM_NONE && skb->ip_summed != CHECKSUM_UNNECESSARY) {
						int data_len = ntohs(ih->tot_len) - hdr_len;
						if (!skb_make_writable(skb, hdr_len + sizeof(struct icmphdr))) {
							read_unlock_bh(&g_addr_rwlock);
							anycast_roaming_rpath_put(rpath_entry);
							return NF_DROP;
						}
						icmp_hdr(skb)->checksum = 0;
						icmp_hdr(skb)->checksum = csum_fold(skb_checksum(skb, hdr_len, data_len, 0));
					}
					send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, skb, ANYCAST_ROAMING_ENCAP_OUT);
				} else {
					struct sk_buff *segs;
					segs = skb_gso_segment(skb, 0);
					if (unlikely(IS_ERR(segs))) {
						read_unlock_bh(&g_addr_rwlock);
						anycast_roaming_rpath_put(rpath_entry);
						return NF_DROP;
					}
					kfree_skb(skb);
					do {
						struct sk_buff *nskb = segs->next;
						segs->next = NULL;
						send_encapsulated(state->net, addr_entry->my_notify_addr, notify_entry->addr, segs, ANYCAST_ROAMING_ENCAP_OUT);
						segs = nskb;
					} while (segs);
				}
				read_unlock_bh(&g_addr_rwlock);
				return NF_STOLEN;
			}
#endif
		}
	}
	read_unlock_bh(&g_addr_rwlock);
out:
	return NF_ACCEPT;
}

static struct nf_hook_ops anycast_roaming_ops[] __read_mostly = {
	{
		.hook     = anycast_roaming_in_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
		.owner    = THIS_MODULE,
#endif
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
		.hook     = anycast_roaming_out_hook,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
		.owner    = THIS_MODULE,
#endif
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
};

static int is_valid_ip(const char *ip)
{
	int section = 0;
	int dot = 0;

	if (!ip)
		return 0;

	while (*ip) {
		if (*ip == '.') {
			dot++; 
			if (dot > 3) {
				return 0;
			} 

			if (section >= 0 && section <=255) {
				section = 0;
			} else {
				return 0;
			} 

			if (*(ip+1) == '0') {
				return 0;
			}

		} else if (*ip >= '0' && *ip <= '9') {
			section = section * 10 + *ip - '0';
		} else {
			return 0;
		}

		ip++;
	}

	if (section < 0 || section > 255) {
		section = 0;
		return 0;
	} 

	if (dot != 3)
		return 0;

	return 1;
}

#define ANYCAST_ROAMING_CONFIG_MAX ((17+2+3+17*128+1)*255+1)

static void anycast_roaming_addr_get_config(char *buf, size_t maxlen)
{
	int idx;
	struct anycast_roaming_addr_entry *entry;
	size_t offs = 0;

	*buf = '\0';
	read_lock_bh(&g_addr_rwlock);
	for (idx = 0; idx < ANYCAST_ROAMING_ADDR_TAB_SIZE; idx++) {
		list_for_each_entry(entry, &anycast_roaming_addr_tab[idx], list) {
			struct anycast_roaming_notify_list_entry *entry2;
			size_t start_offs;
			offs += snprintf(buf + offs, maxlen - offs, "%s%pI4:%d:%d:", offs == 0 ? "" : ";", &entry->anycast_ip, entry->mode, entry->reroute);
			start_offs = offs;
			list_for_each_entry_reverse(entry2, &entry->notify_list, list) {
				offs += snprintf(buf + offs, maxlen - offs, "%s%pI4", offs == start_offs ? "" : ",", &entry2->addr);
			}
		}
	}
	read_unlock_bh(&g_addr_rwlock);
}

static int anycast_roaming_addr_set_config(char* configstr)
{
	int idx;
	struct net_device *dev;
	struct in_device* in_dev;
	struct in_ifaddr* if_info;
	const char* delim1 = ";";
	const char* delim2 = ":";
	const char* delim3 = ",";
	char *token1, *cur1, *token2, *cur2;
	write_lock_bh(&g_addr_rwlock);
	for (idx = 0; idx < ANYCAST_ROAMING_ADDR_TAB_SIZE; idx++) {
		struct anycast_roaming_addr_entry *entry, *tmp;
		struct anycast_roaming_notify_addr_entry *na_entry, *na_tmp;
		list_for_each_entry_safe(entry, tmp, &anycast_roaming_addr_tab[idx], list) {
			struct anycast_roaming_notify_list_entry *entry2, *tmp2;
			list_for_each_entry_safe(entry2, tmp2, &entry->notify_list, list) {
				list_del(&entry2->list);
				kmem_cache_free(anycast_roaming_cachep_l, entry2);
			}
			list_del(&entry->list);
			kmem_cache_free(anycast_roaming_cachep_a, entry);
		}
		list_for_each_entry_safe(na_entry, na_tmp, &anycast_roaming_notify_addr_tab[idx], list) {
			list_del(&na_entry->list);
			kmem_cache_free(anycast_roaming_cachep_na, na_entry);
		}
	}
	if (!configstr || strlen(configstr) == 0) {
		write_unlock_bh(&g_addr_rwlock);
		return 0;
	}
	cur1 = configstr;
	while ((token1 = strsep(&cur1, delim1))) {
		struct anycast_roaming_addr_entry *entry;
		struct anycast_roaming_notify_addr_entry *na_entry;
		struct anycast_roaming_notify_list_entry *entry2;
		entry = kmem_cache_zalloc(anycast_roaming_cachep_a, GFP_ATOMIC);
		cur2 = token1;
		token2 = strsep(&cur2, delim2);
		if (is_valid_ip(token2)) {
			entry->anycast_ip = in_aton(token2);
		}
		token2 = strsep(&cur2, delim2);
		if (kstrtoint(token2, 0, &entry->mode) || entry->mode < ANYCAST_ROAMING_MODE_ROAMING || entry->mode > ANYCAST_ROAMING_MODE_RELAY) {
			write_unlock_bh(&g_addr_rwlock);
			printk("invalid mode!\n");
			return -EINVAL;
		}
		token2 = strsep(&cur2, delim2);
		if (kstrtoint(token2, 0, &entry->reroute) || entry->reroute < 0 || entry->reroute > 100) {
			write_unlock_bh(&g_addr_rwlock);
			printk("invalid reroute rate!\n");
			return -EINVAL;
		}
		INIT_LIST_HEAD(&entry->notify_list);
		while ((token2 = strsep(&cur2, delim3))) {
			if (is_valid_ip(token2)) {
				struct anycast_roaming_notify_list_entry *entry2;
				entry2 = kmem_cache_zalloc(anycast_roaming_cachep_l, GFP_ATOMIC);
				entry2->addr = in_aton(token2);
				list_add(&entry2->list, &entry->notify_list);
			}
		}
		read_lock(&dev_base_lock);
		dev = first_net_device(&init_net);
		while (dev) {
			if (dev->ip_ptr) {
				in_dev = (struct in_device *)dev->ip_ptr;
				if (in_dev) {
					if_info = in_dev->ifa_list;
					for (;if_info;if_info=if_info->ifa_next) {
						list_for_each_entry(entry2, &entry->notify_list, list) {
							if (if_info->ifa_address == entry2->addr) {
								entry->my_notify_addr = entry2->addr;
								goto found;
							}
						}
					}
				}
			}
			dev = next_net_device(dev);
		}
found:
		read_unlock(&dev_base_lock);

		list_add(&entry->list, &anycast_roaming_addr_tab[jhash_1word(entry->anycast_ip, anycast_roaming_notify_rnd) & ANYCAST_ROAMING_ADDR_TAB_MASK]);
		if (entry->my_notify_addr == 0) {
			write_unlock_bh(&g_addr_rwlock);
			printk("local unicast address not found!\n");
			return -EINVAL;
		}
		list_for_each_entry(entry2, &entry->notify_list, list) {
			na_entry = kmem_cache_zalloc(anycast_roaming_cachep_na, GFP_ATOMIC);
			na_entry->saddr = entry2->addr;
			na_entry->daddr = entry->my_notify_addr;
			list_add(&na_entry->list, &anycast_roaming_notify_addr_tab[jhash_2words(na_entry->saddr, na_entry->daddr, anycast_roaming_notify_rnd) & ANYCAST_ROAMING_ADDR_TAB_MASK]);
		}
	}
	write_unlock_bh(&g_addr_rwlock);
	return 0;
}

static int proc_anycast_roaming_config(struct ctl_table *ctl, int write,
				       void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table tbl = { .maxlen = ANYCAST_ROAMING_CONFIG_MAX };
	int ret;

	tbl.data = vmalloc(tbl.maxlen);
	if (!tbl.data)
		return -ENOMEM;

	anycast_roaming_addr_get_config(tbl.data, tbl.maxlen);
	ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
	if (write && ret == 0)
		ret = anycast_roaming_addr_set_config(tbl.data);
	vfree(tbl.data);
	return ret;
}

static struct ctl_table anycast_roaming_vars[] = {
	{
		.procname     = "idle_timeout",
		.data         = &sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_IDLE_TIMEOUT],
		.maxlen       = sizeof(int),
		.mode         = 0644,
		.proc_handler = proc_dointvec_jiffies,
	 },
	{
		.procname     = "notify_interval",
		.data         = &sysctl_anycast_roaming_timeouts[ANYCAST_ROAMING_NOTIFY_INTERVAL],
		.maxlen       = sizeof(int),
		.mode         = 0644,
		.proc_handler = proc_dointvec_jiffies,
	 },
	{
		.procname     = "config",
		.maxlen       = ANYCAST_ROAMING_CONFIG_MAX,
		.mode         = 0644,
		.proc_handler = proc_anycast_roaming_config,
	},
	{.procname = 0}
};

const struct ctl_path net_anycast_roaming_ctl_path[] = {
	{
		.procname = "net",
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		.ctl_name = CTL_NET,
#endif
	},
	{.procname = "anycast_roaming"},
	{.procname = 0}
};

EXPORT_SYMBOL_GPL(net_anycast_roaming_ctl_path);

static int anycast_roaming_stats_show(struct seq_file *seq, void *v)
{
	int i, j, cpu_nr;
	unsigned long tmp;
	cpu_nr = num_possible_cpus();

	i = 0;
	while (NULL != anycast_roaming_stats[i].name) {
		tmp = 0;
		for (j = 0; j < cpu_nr; j++) {
			if (cpu_online(j)) {
				tmp += *(((unsigned long *)per_cpu_ptr(ext_stats, j)) + anycast_roaming_stats[i].entry);
			}
		}
		seq_printf(seq, "%-20s:%21lu\n", anycast_roaming_stats[i].name, tmp);
		i++;
	}
	seq_printf(seq, "%-20s:%21d\n", "ACTIVE_NOTIFY", atomic_read(&anycast_roaming_notify_count));
	seq_printf(seq, "%-20s:%21d\n", "ACTIVE_SENT_NOTIFY", atomic_read(&anycast_roaming_sent_notify_count));
	seq_printf(seq, "%-20s:%21d\n", "ACTIVE_RPATH", atomic_read(&anycast_roaming_rpath_count));
	return 0;
}

static int anycast_roaming_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, anycast_roaming_stats_show, NULL);
}

static const struct file_operations anycast_roaming_stats_fops = {
	.owner = THIS_MODULE,
	.open = anycast_roaming_stats_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

int __init anycast_roaming_addr_init(void)
{
	int idx;

	anycast_roaming_addr_tab = vmalloc(ANYCAST_ROAMING_ADDR_TAB_SIZE * (sizeof(struct list_head)));
	if (!anycast_roaming_addr_tab) {
		return -ENOMEM;
	}
	anycast_roaming_notify_addr_tab = vmalloc(ANYCAST_ROAMING_ADDR_TAB_SIZE * (sizeof(struct list_head)));
	if (!anycast_roaming_notify_addr_tab) {
		vfree(anycast_roaming_addr_tab);
		return -ENOMEM;
	}
	anycast_roaming_cachep_a = kmem_cache_create("anycast_roaming_addr", sizeof(struct anycast_roaming_addr_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_a) {
		vfree(anycast_roaming_notify_addr_tab);
		vfree(anycast_roaming_addr_tab);
		return -ENOMEM;
	}
	anycast_roaming_cachep_na = kmem_cache_create("anycast_roaming_notify_addr", sizeof(struct anycast_roaming_notify_addr_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_na) {
		kmem_cache_destroy(anycast_roaming_cachep_a);
		vfree(anycast_roaming_notify_addr_tab);
		vfree(anycast_roaming_addr_tab);
		return -ENOMEM;
	}
	anycast_roaming_cachep_l = kmem_cache_create("anycast_roaming_notify_list", sizeof(struct anycast_roaming_notify_list_entry), 0, SLAB_HWCACHE_ALIGN, NULL);
	if (!anycast_roaming_cachep_l) {
		kmem_cache_destroy(anycast_roaming_cachep_na);
		kmem_cache_destroy(anycast_roaming_cachep_a);
		vfree(anycast_roaming_notify_addr_tab);
		vfree(anycast_roaming_addr_tab);
		return -ENOMEM;
	}
	for (idx = 0; idx < ANYCAST_ROAMING_ADDR_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&anycast_roaming_addr_tab[idx]);
		INIT_LIST_HEAD(&anycast_roaming_notify_addr_tab[idx]);
	}

	return 0;
}

void anycast_roaming_addr_cleanup(void)
{
	anycast_roaming_addr_set_config(NULL);
	kmem_cache_destroy(anycast_roaming_cachep_l);
	kmem_cache_destroy(anycast_roaming_cachep_na);
	kmem_cache_destroy(anycast_roaming_cachep_a);
	vfree(anycast_roaming_notify_addr_tab);
	vfree(anycast_roaming_addr_tab);
}

int __init anycast_roaming_control_init(void)
{
	ext_stats = alloc_percpu(struct anycast_roaming_stat_mib);
	if (!ext_stats) {
		return -ENOMEM;
	}
	proc_create("anycast_roaming_stats", 0, init_net.proc_net, &anycast_roaming_stats_fops);

	sysctl_header = register_sysctl_paths(net_anycast_roaming_ctl_path, anycast_roaming_vars);
	return 0;
}

void anycast_roaming_control_cleanup(void)
{
	unregister_sysctl_table(sysctl_header);
	remove_proc_entry("anycast_roaming_stats",init_net.proc_net);
	if (ext_stats) {
		free_percpu(ext_stats);
		ext_stats = NULL;
	}
}

static int __init anycast_roaming_init(void)
{
	int ret;
	rwlock_init(&g_addr_rwlock);
	get_random_bytes(&anycast_roaming_notify_rnd, sizeof(anycast_roaming_notify_rnd));
	ret = anycast_roaming_addr_init();
	if (ret < 0){
		return ret;
	}
	ret = anycast_roaming_notify_init();
	if (ret < 0){
		goto cleanup_addr;
	}
	ret = anycast_roaming_control_init();
	if (ret < 0){
		goto cleanup_notify;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	ret = nf_register_hooks(anycast_roaming_ops, ARRAY_SIZE(anycast_roaming_ops));
#else
	ret = nf_register_net_hooks(&init_net, anycast_roaming_ops, ARRAY_SIZE(anycast_roaming_ops));
#endif
	if (ret < 0){
		goto cleanup_control;
	}
	return ret;

cleanup_control:
	anycast_roaming_control_cleanup();
cleanup_notify:
	anycast_roaming_notify_cleanup();
cleanup_addr:
	anycast_roaming_addr_cleanup();
	return ret;
}

static void __exit anycast_roaming_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	nf_unregister_hooks(anycast_roaming_ops, ARRAY_SIZE(anycast_roaming_ops));
#else
	nf_unregister_net_hooks(&init_net, anycast_roaming_ops, ARRAY_SIZE(anycast_roaming_ops));
#endif
	anycast_roaming_control_cleanup();
	anycast_roaming_notify_cleanup();
	anycast_roaming_addr_cleanup();
}

module_init(anycast_roaming_init);
module_exit(anycast_roaming_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("noobpwnftw");
