/*
 * SLUB: A slab allocator that limits cache line use instead of queuing
 * objects in per cpu and per node lists.
 *
 * The allocator synchronizes using per slab locks and only
 * uses a centralized lock to manage a pool of partial slabs.
 *
 * (C) 2007 SGI, Christoph Lameter
 */

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmemtrace.h>
#include <linux/kmemcheck.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>
#include <linux/math64.h>
#include <linux/fault-inject.h>
#include <linux/kmemleak.h>
#include <linux/kernel.h>

#ifdef CONFIG_SILKWORM_SLUG
#include <linux/module.h>
#endif
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
#include <linux/mlt_kl_inc.h>
#endif

/*
 * Lock order:
 *   1. slab_lock(page)
 *   2. slab->list_lock
 *
 *   The slab_lock protects operations on the object of a particular
 *   slab and its metadata in the page struct. If the slab lock
 *   has been taken then no allocations nor frees can be performed
 *   on the objects in the slab nor can the slab be added or removed
 *   from the partial or full lists since this would mean modifying
 *   the page_struct of the slab.
 *
 *   The list_lock protects the partial and full list on each node and
 *   the partial slab counter. If taken then no new slabs may be added or
 *   removed from the lists nor make the number of partial slabs be modified.
 *   (Note that the total number of slabs is an atomic value that may be
 *   modified without taking the list lock).
 *
 *   The list_lock is a centralized lock and thus we avoid taking it as
 *   much as possible. As long as SLUB does not have to handle partial
 *   slabs, operations can continue without any centralized lock. F.e.
 *   allocating a long series of objects that fill up slabs does not require
 *   the list lock.
 *
 *   The lock order is sometimes inverted when we are trying to get a slab
 *   off a list. We take the list_lock and then look for a page on the list
 *   to use. While we do that objects in the slabs may be freed. We can
 *   only operate on the slab if we have also taken the slab_lock. So we use
 *   a slab_trylock() on the slab. If trylock was successful then no frees
 *   can occur anymore and we can use the slab for allocations etc. If the
 *   slab_trylock() does not succeed then frees are in progress in the slab and
 *   we must stay away from it for a while since we may cause a bouncing
 *   cacheline if we try to acquire the lock. So go onto the next slab.
 *   If all pages are busy then we may allocate a new slab instead of reusing
 *   a partial slab. A new slab has noone operating on it and thus there is
 *   no danger of cacheline contention.
 *
 *   Interrupts are disabled during allocation and deallocation in order to
 *   make the slab allocator safe to use in the context of an irq. In addition
 *   interrupts are disabled to ensure that the processor does not change
 *   while handling per_cpu slabs, due to kernel preemption.
 *
 * SLUB assigns one slab for allocation to each processor.
 * Allocations only occur from these slabs called cpu slabs.
 *
 * Slabs with free elements are kept on a partial list and during regular
 * operations no list for full slabs is used. If an object in a full slab is
 * freed then the slab will show up again on the partial lists.
 * We track full slabs for debugging purposes though because otherwise we
 * cannot scan all objects.
 *
 * Slabs are freed when they become empty. Teardown and setup is
 * minimal so we rely on the page allocators per cpu caches for
 * fast frees and allocs.
 *
 * Overloading of page flags that are otherwise used for LRU management.
 *
 * PageActive 		The slab is frozen and exempt from list processing.
 * 			This means that the slab is dedicated to a purpose
 * 			such as satisfying allocations for a specific
 * 			processor. Objects may be freed in the slab while
 * 			it is frozen but slab_free will then skip the usual
 * 			list operations. It is up to the processor holding
 * 			the slab to integrate the slab into the slab lists
 * 			when the slab is no longer needed.
 *
 * 			One use of this flag is to mark slabs that are
 * 			used for allocations. Then such a slab becomes a cpu
 * 			slab. The cpu slab may be equipped with an additional
 * 			freelist that allows lockless access to
 * 			free objects in addition to the regular freelist
 * 			that requires the slab lock.
 *
 * PageError		Slab requires special handling due to debug
 * 			options set. This moves	slab handling out of
 * 			the fast path and disables lockless freelists.
 */

#ifdef CONFIG_SLUB_DEBUG
#define SLABDEBUG 1
#else
#define SLABDEBUG 0
#endif

/*
 * Issues still to be resolved:
 *
 * - Support PAGE_ALLOC_DEBUG. Should be easy to do.
 *
 * - Variable sizing of the per node arrays
 */

/* Enable to test recovery from slab corruption on boot */
#undef SLUB_RESILIENCY_TEST

/*
 * Mininum number of partial slabs. These will be left on the partial
 * lists even if they are empty. kmem_cache_shrink may reclaim them.
 */
#define MIN_PARTIAL 5

/*
 * Maximum number of desirable partial slabs.
 * The existence of more partial slabs makes kmem_cache_shrink
 * sort the partial list by the number of objects in the.
 */
#define MAX_PARTIAL 10

#define DEBUG_DEFAULT_FLAGS (SLAB_DEBUG_FREE | SLAB_RED_ZONE | \
				SLAB_POISON | SLAB_STORE_USER)


/*
 * Debugging flags that require metadata to be stored in the slab.  These get
 * disabled when slub_debug=O is used and a cache's min order increases with
 * metadata.
 */
#define DEBUG_METADATA_FLAGS (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER)

/*
 * Set of flags that will prevent slab merging
 */
#define SLUB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
		SLAB_TRACE | SLAB_DESTROY_BY_RCU | SLAB_NOLEAKTRACE | \
		SLAB_FAILSLAB)

#define SLUB_MERGE_SAME (SLAB_DEBUG_FREE | SLAB_RECLAIM_ACCOUNT | \
		SLAB_CACHE_DMA | SLAB_NOTRACK)

#ifndef ARCH_KMALLOC_MINALIGN
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#endif

#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#endif

#define OO_SHIFT	16
#define OO_MASK		((1 << OO_SHIFT) - 1)
#define MAX_OBJS_PER_PAGE	65535 /* since page.objects is u16 */

/* Internal SLUB flags */
#define __OBJECT_POISON		0x80000000 /* Poison object */
#define __SYSFS_ADD_DEFERRED	0x40000000 /* Not yet visible via sysfs */

static int kmem_size = sizeof(struct kmem_cache);

#ifdef CONFIG_SMP
static struct notifier_block slab_notifier;
#endif

#ifdef CONFIG_SILKWORM_SLUG
#define CONFIG_DFREE_ON			1	/* enable deferred free without needing slub debug */
#define SLUG_DEBUG_MAX_PRINT_SIZE	64
#define SLUG_STACK_SIZE			8
#define SLUG_DFREE_TMOUT		(300 * HZ)	/* 5 minutes to timeout min_partial growth */

#define KMALLOC_PRIME_SIZE 		(4096 * 1024)	/* 4 MB */

static inline void *get_slug_alloc(struct kmem_cache *s, void *object);
static inline void *get_slug_free(struct kmem_cache *s, void *object);
static inline void *get_cold_pointer(struct kmem_cache *s, void *object);
void *__kmalloc_brcd(size_t size, gfp_t flags);
void *vmalloc_brcd(unsigned long size);
void vfree_brcd(const void *addr);
static int slub_validate_off = 0;
#endif
#ifdef CONFIG_SILKWORM
void kick_watchdog(void);
#endif


#ifdef CONFIG_SILKWORM_MLT
#ifdef CONFIG_SILKWORM_MLT_DEFAULT_ENABLE
int mlt_enabled = CONFIG_SILKWORM_MLT_DEFAULT_ENABLE;
#else 
int mlt_enabled = 1;
#endif

atomic_t kmalloc_large_cnt = ATOMIC_INIT(0);
int mlt_km_enabled = 0;
#endif 
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
int mlt_kl_enabled = 0;
int console_mlt_kl=0;
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
int console_mlt_vm=0;
#endif

int console_mlt = 0, no_oom_tmpdir = 0, no_oom_mem = 0, no_oom_task = 0;


static enum {
	DOWN,		/* No slab functionality available */
	PARTIAL,	/* kmem_cache_open() works but kmalloc does not */
	UP,		/* Everything works but does not show up in sysfs */
	SYSFS		/* Sysfs up */
} slab_state = DOWN;

/* A list of all slab caches on the system */
static DECLARE_RWSEM(slub_lock);
static LIST_HEAD(slab_caches);

/*
 * Tracking user of a slab.
 */
struct track {
	unsigned long addr;	/* Called from address */
	int cpu;		/* Was running on cpu */
	int pid;		/* Pid context */
	unsigned long when;	/* When did the operation occur */
};

enum track_item { TRACK_ALLOC, TRACK_FREE };

#ifdef CONFIG_SLUB_DEBUG
#ifdef CONFIG_ESLUB_DEBUG

#define ESLUB_POISON 0xdeadbeef
#define ESLUB_XTRACK_INTERNAL 0x00000100UL
#define ESLUB_XTRACK_EXTERNAL 0x00000200UL
/* stack entries should be multiple of 2 for alloc and free */
#define ESLUB_MAX_STACK_ENTRY 6
#define ESLUB_NUM_NEIGHS      3
#define ESLUB_NUM_CTX         3

extern void save_stack(void **stack, int depth);

#if defined(CONFIG_ESLUB_DEBUG_ON) || defined(CONFIG_DEBUG_WATCHPOINT)
static int eslub_debug_flags = ESLUB_XTRACK_INTERNAL;
#else
static int eslub_debug_flags = 0;
#endif
static int eslub_num_neighs = ESLUB_NUM_NEIGHS;
static int eslub_num_ctx = ESLUB_NUM_CTX;
static char *eslub_debug_slabs = NULL;
static atomic_long_t eslub_total = ATOMIC_INIT(0);

struct xtrack_item {
	int redzone;
	int type;
	int cpu;
	int pid;
	unsigned long when;
	void *stack[ESLUB_MAX_STACK_ENTRY];
};

struct xtrack {
	int idx;
	struct xtrack_item track[0];
};


#define XTRACK_SIZE (sizeof(struct xtrack) + eslub_num_ctx * sizeof(struct xtrack_item))
static inline void set_xtrack(struct kmem_cache *s, void *object,
			 enum track_item alloc, unsigned long addr);
static inline void init_xtrack(struct kmem_cache *s, void *object);
#endif

static int sysfs_slab_add(struct kmem_cache *);
static int sysfs_slab_alias(struct kmem_cache *, const char *);
static void sysfs_slab_remove(struct kmem_cache *);
#else
static inline int sysfs_slab_add(struct kmem_cache *s) { return 0;}
static inline int sysfs_slab_alias(struct kmem_cache *s, const char *p)
{ return 0;}
static inline void sysfs_slab_remove(struct kmem_cache *s)
{
	kfree(s);
}

#endif

static struct page *get_object_page(const void *x);

static inline void stat(struct kmem_cache *s, enum stat_item si)
{
#ifdef CONFIG_SLUB_STATS
	__this_cpu_inc(s->cpu_slab->stat[si]);
#endif
}

/********************************************************************
 * 			Core slab cache functions
 *******************************************************************/

int slab_is_available(void)
{
	return slab_state >= UP;
}

static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node) 
{
#ifdef CONFIG_NUMA
	return s->node[node];
#else
	return &s->local_node;
#endif
}

/* Verify that a pointer has an address that is valid within a slab page */
static inline int check_valid_pointer(struct kmem_cache *s,
				      struct page *page, const void *object)
{
	void *base;

	if (!object)
		return 1;

	base = page_address(page);
	if (object < base || object >= base + page->objects * s->size ||
	    (object - base) % s->size) {
		return 0;
	}

	return 1;
}

static inline void *get_freepointer(struct kmem_cache *s, void *object)
{
	return *(void **)(object + s->offset);
}

static inline void set_freepointer(struct kmem_cache *s, void *object, void *fp)
{
	*(void **)(object + s->offset) = fp;
}

/* Loop over all objects in a slab */
#define for_each_object(__p, __s, __addr, __objects) \
	for (__p = (__addr); __p < (__addr) + (__objects) * (__s)->size;\
			__p += (__s)->size)

/* Scan freelist */
#define for_each_free_object(__p, __s, __free) \
	for (__p = (__free); __p; __p = get_freepointer((__s), __p))

/* Determine object index from a given position */
static inline int slab_index(void *p, struct kmem_cache *s, void *addr)
{
	return(p - addr) / s->size;
}

static inline struct kmem_cache_order_objects oo_make(int order,
						      unsigned long size)
{
	struct kmem_cache_order_objects x = {
		(order << OO_SHIFT) + (PAGE_SIZE << order) / size
	};

	return x;
}

static inline int oo_order(struct kmem_cache_order_objects x)
{
	return x.x >> OO_SHIFT;
}

static inline int oo_objects(struct kmem_cache_order_objects x)
{
	return x.x & OO_MASK;
}

#ifdef CONFIG_SILKWORM
/* external api to return the number of objects per slab */
int kmem_cache_objects(struct kmem_cache *s)
{
	return (oo_objects(s->oo));
}
#endif

#ifdef CONFIG_SLUB_DEBUG
/*
 * Debug settings:
 */
#if defined(CONFIG_SLUB_DEBUG_ON) || defined(CONFIG_DEBUG_WATCHPOINT)
static int slub_debug = DEBUG_DEFAULT_FLAGS;
#else
static int slub_debug;
#endif

static char *slub_debug_slabs;
static int disable_higher_order_debug;

int slub_debug_enabled(void)
{
		return (slub_debug);
}
EXPORT_SYMBOL(slub_debug_enabled);

/*
 * Object debugging
 */

#ifdef CONFIG_SILKWORM_SLUG
int is_dfree_on(void)
{
#ifdef CONFIG_DFREE_ON
	return 1;
#else
	if (slub_debug & SLAB_POISON)
		return 1;
	return 0;
#endif
}

static inline void print_slug_free(struct kmem_cache *s, void *object)
{	
	int i;
	void **x;

	x = (void **)get_slug_free(s, object);

	printk(KERN_EMERG "KFREE Stack: for %d bytes starting at 0x%p from cache 0x%p:\n", s->objsize, object, s);
	for(i=0; i<SLUG_STACK_SIZE; i++) {
		if (*(x+i) == 0)
			break;
		printk(KERN_EMERG "0x%8p [%8p] %pS", (x+i), *(x+i), *(x+i)); 		
	}
	printk(KERN_EMERG "\n");	
}

static inline void print_slug_alloc(struct kmem_cache *s, void *object)
{	
	int i;
	void **x;

	x = (void **)get_slug_alloc(s, object);

	printk(KERN_EMERG "KMALLOC Stack: for %d bytes starting at 0x%p from cache 0x%p:\n", s->objsize, object, s); 
	for(i=0; i<SLUG_STACK_SIZE; i++) {
		if (*(x+i) == 0)
			break;
		printk(KERN_EMERG "0x%8p [%8p] %pS", (x+i), *(x+i), *(x+i)); 		
	}
	printk(KERN_EMERG "\n");	
}

static inline void print_slug(struct kmem_cache *s, void *object)
{	
	printk(KERN_EMERG "\n");
	print_slug_alloc(s, object);
	print_slug_free(s, object);
}

#define SLUB_MAX_STK 30
void set_slug_stack(void *ptr, void *object)
{
        unsigned long sp;
	unsigned long slub_stk_trace[SLUB_MAX_STK];
        int i, stk_offset, stk_cnt, depth;

	memset(slub_stk_trace, 0, sizeof(slub_stk_trace));
        asm("mr %0,1" : "=r" (sp));

        for (stk_cnt=0; stk_cnt< SLUB_MAX_STK; stk_cnt++)
        {
		if (!validate_sp(sp, current, STACK_FRAME_OVERHEAD))
                        break;

                slub_stk_trace[stk_cnt] = ((unsigned long *)sp)[STACK_FRAME_LR_SAVE];
                sp = ((unsigned long *)sp)[0];
        }

	/* find module stack frame */
	stk_offset = 0;
	for (i=0; i<stk_cnt; i++)
	{
		if (is_vmalloc_or_module_addr((void *)slub_stk_trace[i]))
		{
			/* back up one on stack */
			if (i != 0)
				stk_offset = i - 1;

			/* back up some more if we don't fill up the stack buffer */
			depth = stk_cnt - i;
			if (depth < SLUG_STACK_SIZE)
			{
				if (i > (SLUG_STACK_SIZE - depth))
					stk_offset = i - (SLUG_STACK_SIZE - depth);
				else
					stk_offset = 0;
			}
			break;
		}
	}

	if (stk_offset < 0)
		stk_offset = 0;
	memcpy(ptr, &slub_stk_trace[stk_offset], sizeof(void *) * SLUG_STACK_SIZE);
}

static inline void set_cold_free_pointer_from_page(struct page *page, void *fp) {	
	void *x;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif
	
	// BUG if not a slab page
	BUG_ON(!PageSlab(page));

	x = page_address(page);
	if (page->slab->offset)
		x += page->slab->offset + sizeof(void *) + mlt_off;
	else
		x += page->slab->inuse + mlt_off;
	
	*(void **)x = fp;
	return;
	
}

// return *(page->coldpointer);
static inline void *get_cold_free_pointer_from_page(struct page *page) {	
	void *x;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif
	
	if (unlikely(ZERO_OR_NULL_PTR(page)))
		return NULL;

	// BUG if not a slab page
	BUG_ON(!PageSlab(page));

	x = page_address(page);
	if (page->slab->offset)
		x += page->slab->offset + sizeof(void *) + mlt_off;
	else
		x += page->slab->inuse + mlt_off;
	
	return *(void **)x;
}


static inline void set_cold_pointer(struct kmem_cache *s, void *object, void *fp)
{	
	void **p;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif

	if (s->offset)
		p = (void **)(object + s->offset + sizeof(void *) + mlt_off + sizeof(void *));
	else
		p = (void **)(object + s->inuse + mlt_off + sizeof(void *));

	*p = fp;
}


static inline void *get_cold_pointer(struct kmem_cache *s, void *object)
{
	void **p;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif

	if (s->offset)
		p = (void **)(object + s->offset + sizeof(void *) + mlt_off + sizeof(void *));
	else
		p = (void **)(object + s->inuse + mlt_off + sizeof(void *));

	return *p;
}

static inline void *get_slug_alloc(struct kmem_cache *s, void *object)
{
	void *p;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif

	if (s->offset)
		p = (void *)(object + s->offset + sizeof(void *) + mlt_off + (sizeof(void *) * 2));
	else
		p = (void *)(object + s->inuse + mlt_off + (sizeof(void *) * 2));

	return p;
}

static inline void *get_slug_free(struct kmem_cache *s, void *object)
{
	void *p;
	int mlt_off = 0;

#ifdef CONFIG_SILKWORM_MLT
	mlt_off = sizeof(MLT_book_keeping_info_t);
#endif

	if (s->offset)
		p = (void *)(object + s->offset + sizeof(void *) + mlt_off + (sizeof(void *) * 2) + (sizeof(void *) * SLUG_STACK_SIZE));
	else
		p = (void *)(object + s->inuse + mlt_off + (sizeof(void *) * 2) + (sizeof(void *) * SLUG_STACK_SIZE));

	return p;
}
#endif


static void print_section(char *text, u8 *addr, unsigned int length)
{
	int i, offset;
	int newline = 1;
	char ascii[17];

	ascii[16] = 0;

	for (i = 0; i < length; i++) {
		if (newline) {
			printk(KERN_ERR "%8s 0x%p: ", text, addr + i);
			newline = 0;
		}
		printk(KERN_CONT " %02x", addr[i]);
		offset = i % 16;
		ascii[offset] = isgraph(addr[i]) ? addr[i] : '.';
		if (offset == 15) {
			printk(KERN_CONT " %s\n", ascii);
			newline = 1;
		}
	}
	if (!newline) {
		i %= 16;
		while (i < 16) {
			printk(KERN_CONT "   ");
			ascii[i] = ' ';
			i++;
		}
		printk(KERN_CONT " %s\n", ascii);
	}
}

static struct track *get_track(struct kmem_cache *s, void *object,
			       enum track_item alloc)
{
	struct track *p;

#ifdef CONFIG_SILKWORM_MLT
	if (s->offset)
		p = object + s->offset + sizeof(void *) + sizeof(MLT_book_keeping_info_t);
	else
		p = object + s->inuse + sizeof(MLT_book_keeping_info_t);
#else
	if (s->offset)
		p = object + s->offset + sizeof(void *);
	else
		p = object + s->inuse;
#endif

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		p = (struct track *)((void *)p + (sizeof(void *) * 2));
		if (slub_debug & SLAB_POISON)
			p = (struct track *)((void *)p + (sizeof(void *) * SLUG_STACK_SIZE * 2));
	}
#endif

	return p + alloc;
}

static void set_track(struct kmem_cache *s, void *object,
		      enum track_item alloc, unsigned long addr)
{
	struct track *p = get_track(s, object, alloc);

	if (addr) {
		p->addr = addr;
		p->cpu = smp_processor_id();
		p->pid = current->pid;
		p->when = jiffies;
	} else
		memset(p, 0, sizeof(struct track));
}

#ifdef CONFIG_ESLUB_DEBUG
static int eslub_debug_enabled(struct kmem_cache *s)
{
	/* add custom funciton to reduce granularity
	   || (!eslub_debug_slabs ||
	  strncmp(eslub_debug_slabs, s->name, strlen(eslub_debug_slabs)))
	*/
	if (!eslub_debug_flags) 
		return 0;
	return 1;
}
#endif

static void init_tracking(struct kmem_cache *s, void *object)
{
	if (s->flags & SLAB_STORE_USER) {
		set_track(s, object, TRACK_FREE, 0UL);
		set_track(s, object, TRACK_ALLOC, 0UL);
	}

#ifdef CONFIG_ESLUB_DEBUG   
	if (eslub_debug_enabled(s)) {
		init_xtrack(s, object); 
	}
#endif   
}

static void print_track(const char *s, struct track *t)
{
	if (!t->addr)
		return;

	printk(KERN_ERR "INFO: %s in %pS age=%lu cpu=%u pid=%d\n",
	       s, (void *)t->addr, jiffies - t->when, t->cpu, t->pid);
}

static void print_tracking(struct kmem_cache *s, void *object)
{
	if (!(s->flags & SLAB_STORE_USER))
		return;

	print_track("Allocated", get_track(s, object, TRACK_ALLOC));
	print_track("Freed", get_track(s, object, TRACK_FREE));
}

#ifdef CONFIG_ESLUB_DEBUG
static void print_track_ex(struct kmem_cache *c, const u8 *obj)
{
	struct xtrack_item *it = NULL;
	struct xtrack *t = NULL;
	struct page *page = NULL;
	int off = 0, i = 0, j = 0;
	u8 *s = NULL;
	
	if (eslub_debug_flags & ESLUB_XTRACK_EXTERNAL) {
		page = get_object_page(obj);
		s = page_address(page);
		off = (obj - s)/c->size;
		s = page_address(page->trace_page);
		s += off * XTRACK_SIZE;
		t = (struct xtrack *)s;
	} else {
		t = (struct xtrack *)(obj + c->xtrack);
	}

	printk(KERN_ERR "INFO: Slab object=0x%p\n", obj);	

	for (i = 0, off = t->idx - 1; i < eslub_num_ctx; i++, off--) {
		if (off < 0)
			off = eslub_num_ctx - 1;

		it = (struct xtrack_item *)(t->track + off);
		if (it->type == -1)
			continue;
		
		printk (KERN_ERR "\t(%d)INFO: type = %s age=%luus cpu=%u pid=%d\n",
		       i+1, it->type == TRACK_ALLOC ? "alloc" : "free",
			(get_cycles() - it->when)/tb_ticks_per_usec, it->cpu, it->pid);
		
		for (j = 0; j < ESLUB_MAX_STACK_ENTRY; j++)
			if (it->stack[j])
				printk(KERN_ERR "\t\t[<%p> (%pS)]\n", it->stack[j], it->stack[j]);
	}


	printk(KERN_ERR "\n");
} 

static void print_neigh_tracking(struct kmem_cache *s, struct page *page, u8 *object)
{
	u8 *addr;
	u8 *start, *end;
	int n;

	if (!eslub_debug_enabled(s))
		return;

	addr = page_address(page);
	n = s->size * eslub_num_neighs;
	start = object - n;
	end = object + n;
	if (object - n < addr)
		start = addr;

	if (object + n > addr + page->objects * s->size)
		end = addr + page->objects * s->size;
	
	while (start < end) {
		print_track_ex(s, start);
		start += s->size;
	}
}
#endif

static void print_page_info(struct page *page)
{
#ifdef CONFIG_SILKWORM_SLUG
	void *start, *end;
	unsigned long length;

	start = page_address(page);
	length = (PAGE_SIZE << compound_order(page));
	end = start + length;
	printk(KERN_ERR "INFO: Slab 0x%p objects=%u used=%u fp=0x%p flags=0x%04lx start=%p end=%p\n",
	       page, page->objects, page->inuse, page->freelist, page->flags, start, end);

#else
	printk(KERN_ERR "INFO: Slab 0x%p objects=%u used=%u fp=0x%p flags=0x%04lx\n",
	       page, page->objects, page->inuse, page->freelist, page->flags);
#endif

}

static void slab_bug(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "========================================"
	       "=====================================\n");
	printk(KERN_ERR "BUG %s: %s\n", s->name, buf);
	printk(KERN_ERR "----------------------------------------"
	       "-------------------------------------\n\n");
}

static void slab_fix(struct kmem_cache *s, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	printk(KERN_ERR "FIX %s: %s\n", s->name, buf);
}

#ifdef CONFIG_SILKWORM_SLUG
static void print_trailer(struct kmem_cache *s, struct page *page, u8 *p, unsigned long fault)
#else
static void print_trailer(struct kmem_cache *s, struct page *page, u8 *p)
#endif
{
	unsigned int off;   /* Offset of last byte */
	u8 *addr = page_address(page);
#ifdef CONFIG_SILKWORM_SLUG
	u8 *start;
#endif

	print_tracking(s, p);

	print_page_info(page);

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & (SLAB_DFREE | SLAB_RED_ZONE))
		start = p + cache_line_size();
	else
		start = p;
	printk(KERN_ERR "INFO: Object 0x%p User start=0x%p @offset=%tu fp=0x%p\n\n",
	       p, start, p - addr, get_freepointer(s, p));
#else
	printk(KERN_ERR "INFO: Object 0x%p @offset=%tu fp=0x%p\n\n",
	       p, p - addr, get_freepointer(s, p));
#endif

	if (p > addr + 16)
		print_section("Bytes b4", p - 16, 16);

#ifdef CONFIG_SILKWORM_SLUG
	fault &= ~0xf;
	print_section("Object", (u8 *)((unsigned long)(p) + fault), min_t(unsigned long, s->objsize - fault, SLUG_DEBUG_MAX_PRINT_SIZE));
#else
	print_section("Object", p, min_t(unsigned long, s->objsize, PAGE_SIZE));
#endif

	if (s->flags & SLAB_RED_ZONE)
		print_section("Redzone", p + s->objsize,
			      s->inuse - s->objsize);

	if (s->offset)
		off = s->offset + sizeof(void *);
	else
		off = s->inuse;

#ifdef CONFIG_SILKWORM_MLT
	off += sizeof(MLT_book_keeping_info_t);
#endif

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		off += 2*sizeof(void *);	/* cold free pointer and cold pointer */
		if (slub_debug & SLAB_POISON)
			off += sizeof(void *) * SLUG_STACK_SIZE * 2;	/* alloc and free stack frames */
	}
#endif

	if (s->flags & SLAB_STORE_USER)
		off += 2 * sizeof(struct track);

	if (off != s->size)
		/* Beginning of the filler is the free pointer */
		print_section("Padding", p + off, s->size - off);

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		int save_message_loglevel;
		save_message_loglevel = default_message_loglevel;
		default_message_loglevel = minimum_console_loglevel;
		if (slub_debug & SLAB_POISON)
			print_slug(s, p);
		printk(KERN_EMERG "The following is the CURRENT Stack:\n");
		dump_stack();
		default_message_loglevel = save_message_loglevel;
	}
	else
		dump_stack();
#else
	dump_stack();
#endif
}

static void object_err(struct kmem_cache *s, struct page *page,
		       u8 *object, char *reason)
{
	slab_bug(s, "%s", reason);
#ifdef CONFIG_SILKWORM_SLUG
	print_trailer(s, page, object, 0);
#else
	print_trailer(s, page, object);
#endif
}
static void slab_err(struct kmem_cache *s, struct page *page, char *fmt, ...)
{
	va_list args;
	char buf[100];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
	slab_bug(s, "%s", buf);
	print_page_info(page);
#ifdef CONFIG_SILKWORM
	{
		int save_message_loglevel;
		save_message_loglevel = default_message_loglevel;
		default_message_loglevel = minimum_console_loglevel;
		printk(KERN_EMERG "The following is the CURRENT Stack:\n");
		dump_stack();
		default_message_loglevel = save_message_loglevel;
	}
#else
	dump_stack();
#endif
}

static void init_object(struct kmem_cache *s, void *object, int active)
{
	u8 *p = object;

	if (s->flags & __OBJECT_POISON) {
		memset(p, POISON_FREE, s->objsize - 1);
		p[s->objsize - 1] = POISON_END;
	}

	if (s->flags & SLAB_RED_ZONE)
		memset(p + s->objsize,
		       active ? SLUB_RED_ACTIVE : SLUB_RED_INACTIVE,
		       s->inuse - s->objsize);
}

static u8 *check_bytes(u8 *start, unsigned int value, unsigned int bytes)
{
	while (bytes) {
		if (*start != (u8)value)
			return start;
		start++;
		bytes--;
	}
	return NULL;
}

static void restore_bytes(struct kmem_cache *s, char *message, u8 data,
			  void *from, void *to)
{
	slab_fix(s, "Restoring 0x%p-0x%p=0x%x\n", from, to - 1, data);
	memset(from, data, to - from);
}

static int check_bytes_and_report(struct kmem_cache *s, struct page *page,
				  u8 *object, char *what,
				  u8 *start, unsigned int value, unsigned int bytes)
{
	u8 *fault;
	u8 *end;
#ifdef CONFIG_SILKWORM_SLUG
	unsigned long offset = 0;
#endif

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		/* check header */
		if (start != object)
		{
			fault = check_bytes(object, POISON_FREE, cache_line_size());
			if (fault)
			{
				slab_bug(s, "Object underrun");
				value = POISON_FREE;
				end = object + cache_line_size();
				goto print_err;
			}
		}
	}
#endif
	fault = check_bytes(start, value, bytes);
	if (!fault)
		return 1;

	end = start + bytes;
	while (end > fault && end[-1] == value)
		end--;

	slab_bug(s, "%s overwritten", what);
#ifdef CONFIG_SILKWORM_SLUG
	offset = (unsigned long)fault-(unsigned long)object;
	print_err:
#endif
	printk(KERN_ERR "INFO: 0x%p-0x%p. First byte 0x%x instead of 0x%x\n",
		fault, end - 1, fault[0], value);	
#ifdef CONFIG_SILKWORM_SLUG
	print_trailer(s, page, object, offset);
#else
	print_trailer(s, page, object);
#endif

	restore_bytes(s, what, value, fault, end);
	return 0;
}

/*
 * Object layout:
 *
 * object address
 * 	Bytes of the object to be managed.
 * 	If the freepointer may overlay the object then the free
 * 	pointer is the first word of the object.
 *
 * 	Poisoning uses 0x6b (POISON_FREE) and the last byte is
 * 	0xa5 (POISON_END)
 *
 * object + s->objsize
 * 	Padding to reach word boundary. This is also used for Redzoning.
 * 	Padding is extended by another word if Redzoning is enabled and
 * 	objsize == inuse.
 *
 * 	We fill with 0xbb (RED_INACTIVE) for inactive objects and with
 * 	0xcc (RED_ACTIVE) for objects in use.
 *
 * object + s->inuse
 * 	Meta data starts here.
 *
 * 	A. Free pointer (if we cannot overwrite object on free)
 * 	B. MLT Book keeping data
 *	B0 Cold Free Pointer
 *	B1 Cold Pointer
 *	B3 Slug pointers	
 * 	C. Tracking data for SLAB_STORE_USER
 * 	D. Padding to reach required alignment boundary or at mininum
 * 		one word if debugging is on to be able to detect writes
 * 		before the word boundary.
 *
 *	Padding is done using 0x5a (POISON_INUSE)
 *
 * object + s->size
 * 	Nothing is used beyond s->size.
 *
 * If slabcaches are merged then the objsize and inuse boundaries are mostly
 * ignored. And therefore no slab options that rely on these boundaries
 * may be used with merged slabcaches.
 */

static int check_pad_bytes(struct kmem_cache *s, struct page *page, u8 *p)
{
	unsigned long off = s->inuse;	/* The end of info */
	
	if (s->offset)
		/* Freepointer is placed after the object. */
		off += sizeof(void *);

#ifdef CONFIG_SILKWORM_MLT
	off += sizeof(MLT_book_keeping_info_t);
#endif

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		off += 2 * sizeof(void *);	/* cold free pointer and cold pointer */
		if (slub_debug & SLAB_POISON)
			off += sizeof(void *) * SLUG_STACK_SIZE * 2;	/* alloc and free stack frames */
	}
#endif

#ifdef CONFIG_ESLUB_DEBUG
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_INTERNAL))
		off += XTRACK_SIZE;
#endif

	if (s->flags & SLAB_STORE_USER)
		/* We also have user information there */
		off += 2 * sizeof(struct track);

	if (s->size == off)
		return 1;

	return check_bytes_and_report(s, page, p, "Object padding",
				      p + off, POISON_INUSE, s->size - off);
}

/* Check the pad bytes at the end of a slab page */
static int slab_pad_check(struct kmem_cache *s, struct page *page)
{
	u8 *start;
	u8 *fault;
	u8 *end;
	int length;
	int remainder;

	if (!(s->flags & SLAB_POISON))
		return 1;

	start = page_address(page);
	length = (PAGE_SIZE << compound_order(page));
	end = start + length;
	remainder = length % s->size;
	if (!remainder)
		return 1;

	fault = check_bytes(end - remainder, POISON_INUSE, remainder);
	if (!fault)
		return 1;
	while (end > fault && end[-1] == POISON_INUSE)
		end--;

	slab_err(s, page, "Padding overwritten. 0x%p-0x%p", fault, end - 1);
#ifdef CONFIG_SILKWORM_SLUG
	fault = (u8 *)((unsigned int)(fault) & ~0xf);
	print_section("Padding", fault, min_t(unsigned long, end - fault, SLUG_DEBUG_MAX_PRINT_SIZE));
#else
	print_section("Padding", end - remainder, remainder);
#endif

#ifdef CONFIG_SILKWORM_SLUG
	restore_bytes(s, "slab padding", POISON_INUSE, fault, end);
#else
	restore_bytes(s, "slab padding", POISON_INUSE, end - remainder, end);
#endif
	return 0;
}

static int check_object(struct kmem_cache *s, struct page *page,
			void *object, int active)
{
	u8 *p = object;
	u8 *endobject = object + s->objsize;

	if (s->flags & SLAB_RED_ZONE) {
		unsigned int red =
		active ? SLUB_RED_ACTIVE : SLUB_RED_INACTIVE;

		if (!check_bytes_and_report(s, page, object, "Redzone",
					    endobject, red, s->inuse - s->objsize)) {
			return 0;
		}
	} else {
		if ((s->flags & SLAB_POISON) && s->objsize < s->inuse) {
			if (!check_bytes_and_report(s, page, p, "Alignment padding",
					       endobject, POISON_INUSE, s->inuse - s->objsize)) {
				return 0;
			}
		}
	}


	if (s->flags & SLAB_POISON) {
		if (!active && (s->flags & __OBJECT_POISON) &&
		    (!check_bytes_and_report(s, page, p, "Poison", p,
					     POISON_FREE, s->objsize - 1) ||
		     !check_bytes_and_report(s, page, p, "Poison",
					     p + s->objsize - 1, POISON_END, 1)))
			return 0;

		/*
		 * check_pad_bytes cleans up on its own.
		 */
		if (!check_pad_bytes(s, page, p))
			return 0;
	}

	if (!s->offset && active)
		/*
		 * Object and freepointer overlap. Cannot check
		 * freepointer while object is allocated.
		 */
		return 1;

	/* Check free pointer validity */
	if (!check_valid_pointer(s, page, get_freepointer(s, p))) {
		object_err(s, page, p, "Freepointer corrupt");
		/*
		 * No choice but to zap it and thus lose the remainder
		 * of the free objects in this slab. May cause
		 * another error because the object count is now wrong.
		 */
		set_freepointer(s, p, NULL);
		return 0;
	}

	return 1;
}

static int check_slab(struct kmem_cache *s, struct page *page)
{
	int maxobj;

	VM_BUG_ON(!irqs_disabled());

	if (!PageSlab(page)) {
		slab_err(s, page, "Not a valid slab page");
		return 0;
	}

	maxobj = (PAGE_SIZE << compound_order(page)) / s->size;
	if (page->objects > maxobj) {
		slab_err(s, page, "objects %u > max %u",
			 s->name, page->objects, maxobj);
		return 0;
	}
	if (page->inuse > page->objects) {
		slab_err(s, page, "inuse %u > max %u",
			 s->name, page->inuse, page->objects);
		return 0;
	}
	/* Slab_pad_check fixes things up after itself */
	slab_pad_check(s, page);
	return 1;
}

#ifdef CONFIG_SILKWORM_SLUG
/* check if object is already on free list */
static int check_freelist(struct kmem_cache *s, struct page *page, void *search)
{
	int nr = 0;
	void *fp = page->freelist;
	void *object = NULL;

	while (fp && nr <= page->objects) {
		if (fp == search)
			return 1;
		object = fp;
		fp = get_freepointer(s, object);
		nr++;
	}

	if (s->flags & SLAB_DFREE)
	{		
		int cnr = 0;
		fp = get_cold_free_pointer_from_page(page);
		while (fp && cnr <= page->objects) 
		{
			if (fp == search)
				return 1;
			object = fp;
			fp = get_cold_pointer(s, object);
			cnr++;
		}
	}

	return search == NULL;
}
#endif

/*
 * Determine if a certain object on a page is on the freelist. Must hold the
 * slab lock to guarantee that the chains are in a consistent state.
 */
static int on_freelist(struct kmem_cache *s, struct page *page, void *search)
{
	int nr = 0;
	void *fp = page->freelist;
	void *object = NULL;
	unsigned long max_objects;

	while (fp && nr <= page->objects) {
		if (fp == search)
			return 1;
		if (!check_valid_pointer(s, page, fp)) {
			if (object) {
				object_err(s, page, object,
					   "Freechain corrupt");
				set_freepointer(s, object, NULL);
				break;
			} else {
				slab_err(s, page, "Freepointer corrupt");
				page->freelist = NULL;
				page->inuse = page->objects;
				slab_fix(s, "Freelist cleared");
				return 0;
			}
			break;
		}
		object = fp;
		fp = get_freepointer(s, object);
		nr++;
	}

	max_objects = (PAGE_SIZE << compound_order(page)) / s->size;
	if (max_objects > MAX_OBJS_PER_PAGE)
		max_objects = MAX_OBJS_PER_PAGE;

	if (page->objects != max_objects) {
		slab_err(s, page, "Wrong number of objects. Found %d but "
			 "should be %d", page->objects, max_objects);
		page->objects = max_objects;
		slab_fix(s, "Number of objects adjusted.");
	}
	if (page->inuse != page->objects - nr) {
		slab_err(s, page, "Wrong object count. Counter is %d but "
			 "counted were %d", page->inuse, page->objects - nr);
		page->inuse = page->objects - nr;
		slab_fix(s, "Object count adjusted.");
	}
	return search == NULL;
}

static void trace(struct kmem_cache *s, struct page *page, void *object,
		  int alloc)
{
	if (s->flags & SLAB_TRACE) {
		printk(KERN_INFO "TRACE %s %s 0x%p inuse=%d fp=0x%p\n",
		       s->name,
		       alloc ? "alloc" : "free",
		       object, page->inuse,
		       page->freelist);

		if (!alloc)
			print_section("Object", (void *)object, s->objsize);

#ifdef CONFIG_SILKWORM_SLUG
		if (s->flags & SLAB_DFREE)
		{
			int save_message_loglevel;
			save_message_loglevel = default_message_loglevel;
			default_message_loglevel = minimum_console_loglevel;
			print_slug(s, object);
			printk(KERN_EMERG "The following is the CURRENT Stack:\n");
			dump_stack();
			default_message_loglevel = save_message_loglevel;
		}
		else
			dump_stack();
#else
		dump_stack();
#endif
	}
}

/*
 * Tracking of fully allocated slabs for debugging purposes.
 */
static void add_full(struct kmem_cache_node *n, struct page *page)
{
	spin_lock(&n->list_lock);
	list_add(&page->lru, &n->full);
	spin_unlock(&n->list_lock);
}

static void remove_full(struct kmem_cache *s, struct page *page)
{
	struct kmem_cache_node *n;

	if (!(s->flags & SLAB_STORE_USER))
		return;

	n = get_node(s, page_to_nid(page));

	spin_lock(&n->list_lock);
	list_del(&page->lru);
	spin_unlock(&n->list_lock);
}

/* Tracking of the number of slabs for debugging purposes */
static inline unsigned long slabs_node(struct kmem_cache *s, int node)
{
	struct kmem_cache_node *n = get_node(s, node);

	return atomic_long_read(&n->nr_slabs);
}

static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
{
	return atomic_long_read(&n->nr_slabs);
}

static inline void inc_slabs_node(struct kmem_cache *s, int node, int objects)
{
	struct kmem_cache_node *n = get_node(s, node);
#ifdef CONFIG_SILKWORM_SLUG
	unsigned long x;
#endif

	/*
	 * May be called early in order to allocate a slab for the
	 * kmem_cache_node structure. Solve the chicken-egg
	 * dilemma by deferring the increment of the count during
	 * bootstrap (see early_kmem_cache_node_alloc).
	 */
	if (!NUMA_BUILD || n) {
		atomic_long_inc(&n->nr_slabs);
		atomic_long_add(objects, &n->total_objects);
#ifdef CONFIG_SILKWORM_SLUG
		x = atomic_long_read(&n->total_objects);
		if (x > s->max_objects)
			s->max_objects = x;
#endif
	}
}
static inline void dec_slabs_node(struct kmem_cache *s, int node, int objects)
{
	struct kmem_cache_node *n = get_node(s, node);

	atomic_long_dec(&n->nr_slabs);
	atomic_long_sub(objects, &n->total_objects);
}

/* Object debug checks for alloc/free paths */
static void setup_object_debug(struct kmem_cache *s, struct page *page,
			       void *object)
{
#ifdef CONFIG_SILKWORM_MLT
        MLT_book_keeping_info_t *mlt_metadata;

        mlt_metadata = get_mlt_offset(s, object);
        init_mlt_metadata(mlt_metadata);
#endif
	if (!(s->flags & (SLAB_STORE_USER|SLAB_RED_ZONE|__OBJECT_POISON)))
		return;

	init_object(s, object, 0);
	init_tracking(s, object);
}

static int alloc_debug_processing(struct kmem_cache *s, struct page *page,
				  void *object, unsigned long addr)
{		
	if (!check_slab(s, page))
		goto bad;

	if (!on_freelist(s, page, object)) {
		object_err(s, page, object, "Object already allocated");
		goto bad;
	}

	if (!check_valid_pointer(s, page, object)) {
		object_err(s, page, object, "Freelist Pointer check fails");
		goto bad;
	}

	if (!check_object(s, page, object, 0))
		goto bad;

#ifdef CONFIG_SILKWORM_SLUG
	if ((s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
	{
		void *stk_ptr;
		stk_ptr = get_slug_alloc(s, object);
		set_slug_stack(stk_ptr, object);
	}
#endif	
	/* Success perform special debug activities for allocs */
	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_ALLOC, addr);

#ifdef CONFIG_ESLUB_DEBUG   
	set_xtrack(s, object, TRACK_ALLOC, addr);
#endif	
	trace(s, page, object, 1);
	init_object(s, object, 1);
	return 1;

 bad:
#ifdef CONFIG_ESLUB_DEBUG   
	print_neigh_tracking(s, page, object);
#endif
   
	if (PageSlab(page)) {
		/*
		 * If this is a slab page then lets do the best we can
		 * to avoid issues in the future. Marking all objects
		 * as used avoids touching the remaining objects.
		 */
		slab_fix(s, "Marking all objects used");
		page->inuse = page->objects;
		page->freelist = NULL;
	}
	return 0;
}

static int free_debug_processing(struct kmem_cache *s, struct page *page,
				 void *object, unsigned long addr)
{
#ifdef CONFIG_SILKWORM_SLUG
	if ((s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
	{
		void *stk_ptr;
		stk_ptr = get_slug_free(s, object);
		set_slug_stack(stk_ptr, object);
	}
#endif
	
	if (!check_slab(s, page))
		goto fail;
	
	if (!check_valid_pointer(s, page, object)) {
		slab_err(s, page, "Invalid object pointer 0x%p", object);
		goto fail;
	}

	if (on_freelist(s, page, object)) {
		object_err(s, page, object, "Object already free");
		goto fail;
	}
	
	if (!check_object(s, page, object, 1)) {
#ifdef CONFIG_ESLUB_DEBUG	   
		print_neigh_tracking(s, page, object);
#endif	   
		return 0;
	}

	if (unlikely(s != page->slab)) {
		if (!PageSlab(page)) {
			slab_err(s, page, "Attempt to free object(0x%p) "
				 "outside of slab", object);
		} else if (!page->slab) {
			printk(KERN_ERR
			       "SLUB <none>: no slab for object 0x%p.\n",
			       object);
#ifdef CONFIG_SILKWORM_SLUG
			if (s->flags & SLAB_DFREE)
			{
				int save_message_loglevel;
				save_message_loglevel = default_message_loglevel;
				default_message_loglevel = minimum_console_loglevel;
				print_slug(s, object);
				printk(KERN_EMERG "The following is the CURRENT Stack:\n");
				dump_stack();
				default_message_loglevel = save_message_loglevel;
			}
			else
				dump_stack();
#else
			dump_stack();
#endif
		} else
			object_err(s, page, object,
				   "page slab pointer corrupt.");
		goto fail;
	}

	/* Special debug activities for freeing objects */
	if (!PageSlubFrozen(page) && !page->freelist)
		remove_full(s, page);

	if (s->flags & SLAB_STORE_USER)
		set_track(s, object, TRACK_FREE, addr);

#ifdef CONFIG_ESLUB_DEBUG
   set_xtrack(s, object, TRACK_FREE, addr);
#endif	
	trace(s, page, object, 0);
	init_object(s, object, 0);
	return 1;

	fail:
#ifdef CONFIG_ESLUB_DEBUG   
	print_neigh_tracking(s, page, object);
#endif   
	slab_fix(s, "Object at 0x%p not freed", object);
	return 0;
}

#ifdef CONFIG_SILKWORM_SLUG
extern struct kernel_symbol __start___ksymtab[];
extern struct kernel_symbol __stop___ksymtab[];

/* lookup symbol in given range of kernel_symbols */
static struct kernel_symbol *lookup_symbol(const char *name,
	struct kernel_symbol *start,
	struct kernel_symbol *stop)
{
	struct kernel_symbol *ks = start;
	for (; ks < stop; ks++)
		if (strcmp(ks->name, name) == 0)
			return ks;
	return NULL;
}
#endif
static int __init setup_slub_debug(char *str)
{
	int def_flags = DEBUG_DEFAULT_FLAGS & ~SLAB_STORE_USER;
	slub_debug = def_flags;
#ifdef CONFIG_ESLUB_DEBUG   
	eslub_debug_flags = ESLUB_XTRACK_INTERNAL;
#endif	
	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		goto out;

	if (*str == ',')
		/*
		 * No options but restriction on slabs. This means full
		 * debugging for slabs matching a pattern.
		 */
		goto check_slabs;

	if (tolower(*str) == 'o') {
		/*
		 * Avoid enabling debugging on caches if its minimum order
		 * would increase as a result.
		 */
#if defined(CONFIG_SILKWORM_MLT) || defined(CONFIG_SILKWORM_SLUG)
		disable_higher_order_debug = 0;
#else
		disable_higher_order_debug = 1;
#endif
		goto out;
	}

	slub_debug = 0;
	if (*str == '-')
		/*
		 * Switch off all debugging measures.
		 */
		goto out;

	/*
	 * Determine which debug features should be switched on
	 */
	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 'f':
			slub_debug |= SLAB_DEBUG_FREE;
			break;
		case 'z':
			slub_debug |= SLAB_RED_ZONE;
			break;
		case 'p':
			slub_debug |= SLAB_POISON;
			break;
		case 'u':
			slub_debug |= SLAB_STORE_USER;
			break;
		case 't':
			slub_debug |= SLAB_TRACE;
			break;
		case 'a':
			slub_debug |= SLAB_FAILSLAB;
			break;
#ifdef CONFIG_ESLUB_DEBUG		   
		case 'c':
			str++;
			if (*str >= '0' && *str <= '9')
				eslub_num_ctx = *str - '0';
			
			/* make it even if not */
			if (eslub_num_ctx & 0x1)
				eslub_num_ctx++;

			if(eslub_num_ctx == 0)
				eslub_debug_flags = 0;
			break;
		case 'n':
			str++;
			if (*str >= '0' && *str <= '9')
				eslub_num_neighs = *str - '0';
			
			if(eslub_num_neighs == 0)
				eslub_debug_flags = 0;
			break;
		case 'i':
			eslub_debug_flags = ESLUB_XTRACK_INTERNAL;
			slub_debug |= def_flags;
			break;
		case 'o':
			eslub_debug_flags = ESLUB_XTRACK_EXTERNAL;
			slub_debug |= def_flags;
			break;
#endif			
		default:
			printk(KERN_ERR "slub_debug option '%c' "
			       "unknown. skipped\n", *str);
		}
	}

	check_slabs:
	if (*str == ',')
		slub_debug_slabs = str + 1;
	out:
	return 1;
}

__setup("slub_debug", setup_slub_debug);



static unsigned long kmem_cache_flags(unsigned long objsize,
				      unsigned long flags, const char *name,
				      void (*ctor)(void *))
{
	/*
	 * Enable debugging if selected on the kernel commandline.
	 */
	if (slub_debug && (!slub_debug_slabs ||
			   !strncmp(slub_debug_slabs, name, strlen(slub_debug_slabs))))
		flags |= slub_debug;
#ifdef CONFIG_SILKWORM_SLUG
#ifndef CONFIG_DFREE_ON
	if (!(slub_debug & SLAB_POISON))
		flags &= ~SLAB_DFREE;	/* disable deferred free if slub_debug not enabled */
#endif
#endif

	return flags;
}
#else
static inline void setup_object_debug(struct kmem_cache *s,
				      struct page *page, void *object) {}

static inline int alloc_debug_processing(struct kmem_cache *s,
					 struct page *page, void *object, unsigned long addr) { return 0;}

static inline int free_debug_processing(struct kmem_cache *s,
					struct page *page, void *object, unsigned long addr) { return 0;}

static inline int slab_pad_check(struct kmem_cache *s, struct page *page)
{ return 1;}
static inline int check_object(struct kmem_cache *s, struct page *page,
			       void *object, int active) { return 1;}
static inline void add_full(struct kmem_cache_node *n, struct page *page) {}
static inline unsigned long kmem_cache_flags(unsigned long objsize,
					     unsigned long flags, const char *name,
					     void (*ctor)(void *))
{
	return flags;
}
#define slub_debug 0

#define disable_higher_order_debug 0
	
static inline unsigned long slabs_node(struct kmem_cache *s, int node)
{ return 0;}
static inline unsigned long node_nr_slabs(struct kmem_cache_node *n)
{ return 0;}
static inline void inc_slabs_node(struct kmem_cache *s, int node,
				  int objects) {}
static inline void dec_slabs_node(struct kmem_cache *s, int node,
				  int objects) {}
#endif

/*
 * Slab allocation and freeing
 */
static inline struct page *alloc_slab_page(gfp_t flags, int node,
					   struct kmem_cache_order_objects oo)
{
	int order = oo_order(oo);

	flags |= __GFP_NOTRACK;

	if (node == -1)
		return alloc_pages(flags, order);
	else
		return alloc_pages_node(node, flags, order);
}

static struct page *allocate_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	struct kmem_cache_order_objects oo = s->oo;
	gfp_t alloc_gfp;

	flags |= s->allocflags;

	/*
	 * Let the initial higher-order allocation fail under memory pressure
	 * so we fall-back to the minimum order allocation.
	 */
	alloc_gfp = (flags | __GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;

	page = alloc_slab_page(alloc_gfp, node, oo);
	if (unlikely(!page)) {
		oo = s->min;
		/*
		 * Allocation may have failed due to fragmentation.
		 * Try a lower order alloc if possible
		 */
		page = alloc_slab_page(flags, node, oo);
		if (!page)
			return NULL;

		stat(s, ORDER_FALLBACK);
	}

	if (kmemcheck_enabled
	    && !(s->flags & (SLAB_NOTRACK | DEBUG_DEFAULT_FLAGS))) {
		int pages = 1 << oo_order(oo);

		kmemcheck_alloc_shadow(page, oo_order(oo), flags, node);

		/*
		 * Objects from caches that have a constructor don't get
		 * cleared when they're allocated, so we need to do it here.
		 */
		if (s->ctor)
			kmemcheck_mark_uninitialized_pages(page, pages);
		else
			kmemcheck_mark_unallocated_pages(page, pages);
	}

	page->objects = oo_objects(oo);
	page->trace_page = NULL;
	mod_zone_page_state(page_zone(page),
			    (s->flags & SLAB_RECLAIM_ACCOUNT) ?
			    NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
			    1 << oo_order(oo));

	return page;
}

static void setup_object(struct kmem_cache *s, struct page *page,
			 void *object)
{
	setup_object_debug(s, page, object);
	if (unlikely(s->ctor))
		s->ctor(object);
}

static struct page *new_slab(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	void *start;
	void *last;
	void *p;

	BUG_ON(flags & GFP_SLAB_BUG_MASK);

	page = allocate_slab(s,
			     flags & (GFP_RECLAIM_MASK | GFP_CONSTRAINT_MASK), node);
	if (!page)
		goto out;

	inc_slabs_node(s, page_to_nid(page), page->objects);
#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		/* on every new slab, we will increase tmp_partial */
		atomic_long_set(&s->tmp_partial, node_nr_slabs(get_node(s, node)));
		s->tmp_partial_age = jiffies;
	}
#endif
	page->slab = s;
	page->flags |= 1 << PG_slab;
	if (s->flags & (SLAB_DEBUG_FREE | SLAB_RED_ZONE | SLAB_POISON |
			SLAB_STORE_USER | SLAB_TRACE))
		__SetPageSlubDebug(page);

#ifdef CONFIG_ESLUB_DEBUG   
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_INTERNAL)) {
		atomic_add(page->objects * XTRACK_SIZE, &s->eslub_total_mem);
		atomic_add(page->objects * XTRACK_SIZE, &eslub_total);
	}
#endif   
	start = page_address(page);

	if (unlikely(s->flags & SLAB_POISON))
		memset(start, POISON_INUSE, PAGE_SIZE << compound_order(page));

	
	last = start;
	for_each_object(p, s, start, page->objects) {
		setup_object(s, page, last);
		set_freepointer(s, last, p);
		last = p;
	}
	setup_object(s, page, last);
	set_freepointer(s, last, NULL);

	page->freelist = start;
	page->inuse = 0;
	out:
	return page;
}

#ifdef CONFIG_SILKWORM_SLUG
static void add_free(struct kmem_cache *s, struct page *page)
{
	spin_lock(&s->free_lock);
	s->nr_free++;
	list_add_tail(&page->lru, &s->free);
	spin_unlock(&s->free_lock);
}

static void remove_free(struct kmem_cache *s, struct page *page)
{
	list_del(&page->lru);
	s->nr_free--;
}
#endif

static void __free_slab(struct kmem_cache *s, struct page *page)
{
	int order = compound_order(page);
	int pages = 1 << order;
	
#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		/* hold freeing the slabs until it has cooled off on the free list */
		add_free(s, page);
		if (s->nr_free > s->dfree_min)
		{
			spin_lock(&s->free_lock);
			page = list_entry(s->free.next, struct page, lru);
			remove_free(s, page);
			spin_unlock(&s->free_lock);
		}
		else
			return;
	}

#endif
	if (unlikely(SLABDEBUG && PageSlubDebug(page))) {
		void *p;

#ifdef CONFIG_SILKWORM_SLUG
		if (likely(!slub_validate_off)) {
#endif
			slab_pad_check(s, page);
			for_each_object(p, s, page_address(page),
					page->objects)
			check_object(s, page, p, 0);
#ifdef CONFIG_SILKWORM_SLUG
		}
#endif
		__ClearPageSlubDebug(page);
	}

	kmemcheck_free_shadow(page, compound_order(page));
#ifdef CONFIG_ESLUB_DEBUG   
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_EXTERNAL) && page->trace_page) {
	   int trace_order;	   
		trace_order = compound_order(page->trace_page);
		__free_pages(page->trace_page, trace_order);
		atomic_sub(1<<trace_order, &s->eslub_total_mem);
		atomic_sub(1<<trace_order, &eslub_total);
		page->trace_page = NULL;
	}
#endif

	mod_zone_page_state(page_zone(page),
			    (s->flags & SLAB_RECLAIM_ACCOUNT) ?
			    NR_SLAB_RECLAIMABLE : NR_SLAB_UNRECLAIMABLE,
			    -pages);

	__ClearPageSlab(page);
	reset_page_mapcount(page);
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += pages;

	__free_pages(page, order);
}

static void rcu_free_slab(struct rcu_head *h)
{
	struct page *page;

	page = container_of((struct list_head *)h, struct page, lru);
	__free_slab(page->slab, page);
}

static void free_slab(struct kmem_cache *s, struct page *page)
{
	if (unlikely(s->flags & SLAB_DESTROY_BY_RCU)) {
		/*
		 * RCU free overloads the RCU head over the LRU
		 */
		struct rcu_head *head = (void *)&page->lru;

		call_rcu(head, rcu_free_slab);
	} else
		__free_slab(s, page);
}

static void discard_slab(struct kmem_cache *s, struct page *page)
{
	dec_slabs_node(s, page_to_nid(page), page->objects);
#ifdef CONFIG_ESLUB_DEBUG	   
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_INTERNAL)) {
		atomic_sub(page->objects * XTRACK_SIZE, &s->eslub_total_mem);
		atomic_sub(page->objects * XTRACK_SIZE, &eslub_total);
	}
#endif   
	free_slab(s, page);
}

/*
 * Per slab locking using the pagelock
 */
static __always_inline void slab_lock(struct page *page)
{
	bit_spin_lock(PG_locked, &page->flags);
}

static __always_inline void slab_unlock(struct page *page)
{
	__bit_spin_unlock(PG_locked, &page->flags);
}

static __always_inline int slab_trylock(struct page *page)
{
	int rc = 1;

	rc = bit_spin_trylock(PG_locked, &page->flags);
	return rc;
}

/*
 * Management of partially allocated slabs
 */
static void add_partial(struct kmem_cache_node *n,
			struct page *page, int tail)
{
	spin_lock(&n->list_lock);
	n->nr_partial++;
	if (tail)
		list_add_tail(&page->lru, &n->partial);
	else
		list_add(&page->lru, &n->partial);
	spin_unlock(&n->list_lock);
}

static void remove_partial(struct kmem_cache *s, struct page *page)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));

	spin_lock(&n->list_lock);
	list_del(&page->lru);
	n->nr_partial--;
	spin_unlock(&n->list_lock);
}

/*
 * Lock slab and remove from the partial list.
 *
 * Must hold list_lock.
 */
static inline int lock_and_freeze_slab(struct kmem_cache_node *n,
				       struct page *page)
{
	if (slab_trylock(page)) {
		list_del(&page->lru);
		n->nr_partial--;
		__SetPageSlubFrozen(page);
		return 1;
	}
	return 0;
}

/*
 * Try to allocate a partial slab from a specific node.
 */
static struct page *get_partial_node(struct kmem_cache_node *n)
{
	struct page *page;

	/*
	 * Racy check. If we mistakenly see no partial slabs then we
	 * just allocate an empty slab. If we mistakenly try to get a
	 * partial slab and there is none available then get_partials()
	 * will return NULL.
	 */
	if (!n || !n->nr_partial)
		return NULL;

	spin_lock(&n->list_lock);
	list_for_each_entry(page, &n->partial, lru)
	if (lock_and_freeze_slab(n, page))
		goto out;
	page = NULL;
	out:
	spin_unlock(&n->list_lock);
	return page;
}

/*
 * Get a page from somewhere. Search in increasing NUMA distances.
 */
static struct page *get_any_partial(struct kmem_cache *s, gfp_t flags)
{
#ifdef CONFIG_NUMA
	struct zonelist *zonelist;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(flags);
	struct page *page;

	/*
	 * The defrag ratio allows a configuration of the tradeoffs between
	 * inter node defragmentation and node local allocations. A lower
	 * defrag_ratio increases the tendency to do local allocations
	 * instead of attempting to obtain partial slabs from other nodes.
	 *
	 * If the defrag_ratio is set to 0 then kmalloc() always
	 * returns node local objects. If the ratio is higher then kmalloc()
	 * may return off node objects because partial slabs are obtained
	 * from other nodes and filled up.
	 *
	 * If /sys/kernel/slab/xx/defrag_ratio is set to 100 (which makes
	 * defrag_ratio = 1000) then every (well almost) allocation will
	 * first attempt to defrag slab caches on other nodes. This means
	 * scanning over all nodes to look for partial slabs which may be
	 * expensive if we do it every time we are trying to find a slab
	 * with available objects.
	 */
	if (!s->remote_node_defrag_ratio ||
	    get_cycles() % 1024 > s->remote_node_defrag_ratio)
		return NULL;

	zonelist = node_zonelist(slab_node(current->mempolicy), flags);
	for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {
		struct kmem_cache_node *n;

		n = get_node(s, zone_to_nid(zone));

		if (n && cpuset_zone_allowed_hardwall(zone, flags) &&
		    n->nr_partial > s->min_partial) {
			page = get_partial_node(n);
			if (page)
				return page;
		}
	}
#endif
	return NULL;
}

/*
 * Get a partial page, lock it and return it.
 */
static struct page *get_partial(struct kmem_cache *s, gfp_t flags, int node)
{
	struct page *page;
	int searchnode = (node == -1) ? numa_node_id() : node;

	page = get_partial_node(get_node(s, searchnode));
	if (page || (flags & __GFP_THISNODE))
		return page;

	return get_any_partial(s, flags);
}

/*
 * Move a page back to the lists.
 *
 * Must be called with the slab lock held.
 *
 * On exit the slab lock will have been dropped.
 */
static void unfreeze_slab(struct kmem_cache *s, struct page *page, int tail)
{
	struct kmem_cache_node *n = get_node(s, page_to_nid(page));
#ifdef CONFIG_SILKWORM_SLUG
	unsigned long tmp;
#endif

	__ClearPageSlubFrozen(page);
	if (page->inuse) {

		if (page->freelist) {
			add_partial(n, page, tail);
			stat(s, tail ? DEACTIVATE_TO_TAIL : DEACTIVATE_TO_HEAD);
		} else {
			stat(s, DEACTIVATE_FULL);
			if (SLABDEBUG && PageSlubDebug(page) &&
			    (s->flags & SLAB_STORE_USER))
				add_full(n, page);
		}
		slab_unlock(page);
	} else {
		stat(s, DEACTIVATE_EMPTY);
#ifdef CONFIG_SILKWORM_SLUG
		tmp = atomic_long_read(&s->tmp_partial);
		if (n->nr_partial < max(s->min_partial, tmp)) {
#else
		if (n->nr_partial < s->min_partial) {
#endif
			/*
			 * Adding an empty slab to the partial slabs in order
			 * to avoid page allocator overhead. This slab needs
			 * to come after the other slabs with objects in
			 * so that the others get filled first. That way the
			 * size of the partial list stays small.
			 *
			 * kmem_cache_shrink can reclaim any empty slabs from
			 * the partial list.
			 */
			add_partial(n, page, 1);
			slab_unlock(page);
		} else {
			slab_unlock(page);
			stat(s, FREE_SLAB);
			discard_slab(s, page);
		}
	}
}

/*
 * Remove the cpu slab
 */
static void deactivate_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
{
	struct page *page = c->page;
	int tail = 1;

	if (page->freelist)
		stat(s, DEACTIVATE_REMOTE_FREES);
	/*
	 * Merge cpu freelist into slab freelist. Typically we get here
	 * because both freelists are empty. So this is unlikely
	 * to occur.
	 */
#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{		
		void **object;
		void *coldfreepointer;

		coldfreepointer = get_cold_free_pointer_from_page(page);
		while (unlikely(coldfreepointer)) {
			/* Retrieve object from cpu_freelist */
			object = coldfreepointer;
			coldfreepointer = get_cold_pointer(s, coldfreepointer);
	
			/* And put onto the regular freelist */
			set_freepointer(s, object, page->freelist);
			page->freelist = object;
			page->inuse--;
		}
		set_cold_free_pointer_from_page(page, NULL);
	}
#endif

	while (unlikely(c->freelist)) {
		void **object;

#ifdef CONFIG_SILKWORM_SLUG
		if (s->flags & SLAB_DFREE)
			tail = 1;
		else 
#endif
			tail = 0;/* Hot objects. Put the slab first */

		/* Retrieve object from cpu_freelist */
		object = c->freelist;
		c->freelist = get_freepointer(s, c->freelist);

		/* And put onto the regular freelist */
		set_freepointer(s, object, page->freelist);
		page->freelist = object;
		page->inuse--;
	}
	c->page = NULL;
	unfreeze_slab(s, page, tail);
}

static inline void flush_slab(struct kmem_cache *s, struct kmem_cache_cpu *c)
{
	stat(s, CPUSLAB_FLUSH);
	slab_lock(c->page);
	deactivate_slab(s, c);
}

/*
 * Flush cpu slab.
 *
 * Called from IPI handler with interrupts disabled.
 */
static inline void __flush_cpu_slab(struct kmem_cache *s, int cpu)
{
	struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);

	if (likely(c && c->page))
		flush_slab(s, c);
}

static void flush_cpu_slab(void *d)
{
	struct kmem_cache *s = d;

	__flush_cpu_slab(s, smp_processor_id());
}

static void flush_all(struct kmem_cache *s)
{
	on_each_cpu(flush_cpu_slab, s, 1);
}

/*
 * Check if the objects in a per cpu structure fit numa
 * locality expectations.
 */
static inline int node_match(struct kmem_cache_cpu *c, int node)
{
#ifdef CONFIG_NUMA
	if (node != -1 && c->node != node)
		return 0;
#endif
	return 1;
}

static int count_free(struct page *page)
{
	return page->objects - page->inuse;
}

static unsigned long count_partial(struct kmem_cache_node *n,
				   int (*get_count)(struct page *))
{
	unsigned long flags;
	unsigned long x = 0;
	struct page *page;

	spin_lock_irqsave(&n->list_lock, flags);
	list_for_each_entry(page, &n->partial, lru)
	x += get_count(page);
	spin_unlock_irqrestore(&n->list_lock, flags);
	return x;
}

static inline unsigned long node_nr_objs(struct kmem_cache_node *n)
{
#ifdef CONFIG_SLUB_DEBUG
	return atomic_long_read(&n->total_objects);
#else
	return 0;
#endif
}

static noinline void
slab_out_of_memory(struct kmem_cache *s, gfp_t gfpflags, int nid)
{
	int node;

	printk(KERN_WARNING
	       "SLUB: Unable to allocate memory on node %d (gfp=0x%x)\n",
	       nid, gfpflags);
	printk(KERN_WARNING "  cache: %s, object size: %d, buffer size: %d, "
	       "default order: %d, min order: %d\n", s->name, s->objsize,
	       s->size, oo_order(s->oo), oo_order(s->min));

	if (oo_order(s->min) > get_order(s->objsize))
		printk(KERN_WARNING "  %s debugging increased min order, use "
		       "slub_debug=O to disable.\n", s->name);

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);
		unsigned long nr_slabs;
		unsigned long nr_objs;
		unsigned long nr_free;

		if (!n)
			continue;

		nr_free  = count_partial(n, count_free);
		nr_slabs = node_nr_slabs(n);
		nr_objs  = node_nr_objs(n);

		printk(KERN_WARNING
		       "  node %d: slabs: %ld, objs: %ld, free: %ld\n",
		       node, nr_slabs, nr_objs, nr_free);
	}
}

/*
 * Slow path. The lockless freelist is empty or we need to perform
 * debugging duties.
 *
 * Interrupts are disabled.
 *
 * Processing is still very fast if new objects have been freed to the
 * regular freelist. In that case we simply take over the regular freelist
 * as the lockless freelist and zap the regular freelist.
 *
 * If that is not working then we fall back to the partial lists. We take the
 * first element of the freelist as the object to allocate now and move the
 * rest of the freelist to the lockless freelist.
 *
 * And if we were unable to get a new slab from the partial slab lists then
 * we need to allocate a new slab. This is the slowest path since it involves
 * a call to the page allocator and the setup of a new slab.
 */
static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
			  unsigned long addr, struct kmem_cache_cpu *c)
{
	void **object;
	struct page *new;
#ifdef CONFIG_SILKWORM_SLUG
	struct kmem_cache_node *n;
	unsigned long max_partial;
#endif

	/* We handle __GFP_ZERO in the caller */
	gfpflags &= ~__GFP_ZERO;

	if (!c->page)
		goto new_slab;

	slab_lock(c->page);
	if (unlikely(!node_match(c, node)))
		goto another_slab;

	stat(s, ALLOC_REFILL);

	load_freelist:
	object = c->page->freelist;
	if (unlikely(!object))
		goto another_slab;
	if (unlikely(SLABDEBUG && PageSlubDebug(c->page)))
		goto debug;
#ifdef CONFIG_SILKWORM_SLUG
	if (c->page->slab->flags & SLAB_DFREE) 
		goto dfree;
#endif

	c->freelist = get_freepointer(s, object);
	c->page->inuse = c->page->objects;
	c->page->freelist = NULL;
	c->node = page_to_nid(c->page);
	unlock_out:
	slab_unlock(c->page);
	stat(s, ALLOC_SLOWPATH);
#ifdef CONFIG_SILKWORM_SLUG
	if (c->page->slab->flags & SLAB_DFREE) 
	{
		/* ensure a minimum number of slabs in the cache for deferred free to work better */
		n = get_node(s, node);
		max_partial = max((unsigned long)MAX_PARTIAL, s->dfree_min>>1);
		if (unlikely(n->nr_partial < max_partial))
		{
			if (gfpflags & __GFP_WAIT)
				local_irq_enable();
			new = new_slab(s, gfpflags, node);
			if (gfpflags & __GFP_WAIT)
				local_irq_disable();
			if (new)
			{
				set_cold_free_pointer_from_page(new, NULL);
				add_partial(n, new, 0);		/* put new slab in front */
			}
		}
	}
#endif
	return object;

	another_slab:
	deactivate_slab(s, c);

	new_slab:
	new = get_partial(s, gfpflags, node);
	if (new) {
		c->page = new;
		stat(s, ALLOC_FROM_PARTIAL);
#ifdef CONFIG_SILKWORM_SLUG
		if (c->page->slab->flags & SLAB_DFREE) 
		{
			void *x;
			
			x = get_cold_free_pointer_from_page(new);
			WARN_ON(x);			
			set_cold_free_pointer_from_page(new, NULL);
		}
#endif
		goto load_freelist;
	}

	if (gfpflags & __GFP_WAIT)
		local_irq_enable();

	new = new_slab(s, gfpflags, node);

	if (gfpflags & __GFP_WAIT)
		local_irq_disable();

	if (new) {
		c = __this_cpu_ptr(s->cpu_slab);
		stat(s, ALLOC_SLAB);
		if (c->page)
			flush_slab(s, c);
		slab_lock(new);
		__SetPageSlubFrozen(new);
		c->page = new;
#ifdef CONFIG_SILKWORM_SLUG
		if (c->page->slab->flags & SLAB_DFREE) 
		{
			set_cold_free_pointer_from_page(new, NULL);
		}
		
#endif
		goto load_freelist;
	}
	if (!(gfpflags & __GFP_NOWARN) && printk_ratelimit())
		slab_out_of_memory(s, gfpflags, node);
	return NULL;
	debug:
	if (!alloc_debug_processing(s, c->page, object, addr))
		goto another_slab;

#ifdef CONFIG_SILKWORM_SLUG
	dfree:
#endif
	c->page->inuse++;
	c->page->freelist = get_freepointer(s, object);
	c->node = -1;
	goto unlock_out;
}

/*
 * Inlined fastpath so that allocation functions (kmalloc, kmem_cache_alloc)
 * have the fastpath folded into their functions. So no function call
 * overhead for requests that can be satisfied on the fastpath.
 *
 * The fastpath works by first checking if the lockless freelist can be used.
 * If not then __slab_alloc is called for slow processing.
 *
 * Otherwise we can simply pick the next object from the lockless free list.
 */
static __always_inline void *slab_alloc(struct kmem_cache *s,
					gfp_t gfpflags, int node, unsigned long addr)
{
	void **object;
	struct kmem_cache_cpu *c;
	unsigned long flags;

	gfpflags &= gfp_allowed_mask;

	lockdep_trace_alloc(gfpflags);
	might_sleep_if(gfpflags & __GFP_WAIT);

	if (should_failslab(s->objsize, gfpflags, s->flags))
		return NULL;

	local_irq_save(flags);
	c = __this_cpu_ptr(s->cpu_slab);
	object = c->freelist;
	if (unlikely(!object || !node_match(c, node)))

		object = __slab_alloc(s, gfpflags, node, addr, c);

	else {
		c->freelist = get_freepointer(s, object);
		stat(s, ALLOC_FASTPATH);
	}
	local_irq_restore(flags);

#ifdef CONFIG_SILKWORM_SLUG
	if (unlikely(gfpflags & __GFP_ZERO) && object)
	{
		if ((s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			memset((void *)((unsigned long)(object) + cache_line_size()), 0, s->objsize - cache_line_size());
		else
			memset(object, 0, s->objsize);
	}
#else
	if (unlikely(gfpflags & __GFP_ZERO) && object)
		memset(object, 0, s->objsize);
#endif

	kmemcheck_slab_alloc(s, gfpflags, object, s->objsize);
	kmemleak_alloc_recursive(object, s->objsize, 1, s->flags, gfpflags);


#ifdef CONFIG_SILKWORM_SLUG
	/* shift object to maintain header */
	if (object && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
		object = (void *)((unsigned long)object + cache_line_size());
#endif
	return object;
}

void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
{
	void *ret = slab_alloc(s, gfpflags, -1, _RET_IP_);

	trace_kmem_cache_alloc(_RET_IP_, ret, s->objsize, s->size, gfpflags);

#ifdef CONFIG_SILKWORM_MLT
        if ((ret) && (mlt_km_enabled)) {
                MLT_param_t mlt_param;
                mlt_param.s = s;

#ifdef CONFIG_SILKWORM_SLUG
                if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
                        mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
                else
#endif
                        mlt_param.ptr = ret;

                MLT_kmalloc_processing(&mlt_param);
        }
#endif

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc);

#ifdef CONFIG_SILKWORM_MLT
void *kmem_cache_alloc_mlt_bypass(struct kmem_cache *s, gfp_t gfpflags)
{
        void *ret = slab_alloc(s, gfpflags, -1, _RET_IP_);

        trace_kmem_cache_alloc(_RET_IP_, ret, s->objsize, s->size, gfpflags);

        return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_mlt_bypass);
#endif

#ifdef CONFIG_SILKWORM_SLUG
void *kmem_cache_alloc_brcd(struct kmem_cache *s, gfp_t gfpflags)
{
	void *ret = slab_alloc(s, gfpflags, -1, _RET_IP_);

	trace_kmem_cache_alloc(_RET_IP_, ret, s->objsize, s->size, gfpflags);

#ifdef CONFIG_SILKWORM_MLT
	if (ret) {
		MLT_param_t mlt_param;
		mlt_param.s = s;
		
		if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
		else
			mlt_param.ptr = ret;
		
		MLT_kmalloc_processing(&mlt_param);
	}
#endif
		
	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_brcd);
#endif //CONFIG_SILKWORM_SLUG

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_notrace(struct kmem_cache *s, gfp_t gfpflags)
{
	return slab_alloc(s, gfpflags, -1, _RET_IP_);
}
EXPORT_SYMBOL(kmem_cache_alloc_notrace);
#endif

#ifdef CONFIG_NUMA
void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
{
	void *ret = slab_alloc(s, gfpflags, node, _RET_IP_);

	trace_kmem_cache_alloc_node(_RET_IP_, ret,
				    s->objsize, s->size, gfpflags, node);

#ifdef CONFIG_SILKWORM_MLT
        if ((ret) && (mlt_km_enabled)) {
                MLT_param_t mlt_param;
                mlt_param.s = s;

#ifdef CONFIG_SILKWORM_SLUG
                if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
                        mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
                else
#endif
                        mlt_param.ptr = ret;

                MLT_kmalloc_processing(&mlt_param);
        }
#endif

	return ret;
}
EXPORT_SYMBOL(kmem_cache_alloc_node);
#endif

#ifdef CONFIG_TRACING
void *kmem_cache_alloc_node_notrace(struct kmem_cache *s,
				    gfp_t gfpflags,
				    int node)
{
	return slab_alloc(s, gfpflags, node, _RET_IP_);
}
EXPORT_SYMBOL(kmem_cache_alloc_node_notrace);
#endif

/*
 * Slow patch handling. This may still be called frequently since objects
 * have a longer lifetime than the cpu slabs in most processing loads.
 *
 * So we still attempt to reduce cache line usage. Just take the slab
 * lock and free the item. If there is no additional partial page
 * handling required then we can return immediately.
 */
static void __slab_free(struct kmem_cache *s, struct page *page,
			void *x, unsigned long addr)
{
	void *prior;
	void **object = (void *)x;
#ifdef CONFIG_SILKWORM_SLUG
	struct kmem_cache_node *n = NULL;
	unsigned long tmp;
#endif

	stat(s, FREE_SLOWPATH);
	slab_lock(page);

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		/* do double free checking always */
		if (check_freelist(s, page, object)) {
			object_err(s, page, (u8 *)object, "Object already free");
			goto out_unlock;
		}
	}
#endif

	if (unlikely(SLABDEBUG && PageSlubDebug(page)))
		goto debug;

	checks_ok:
#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		if (unlikely(PageSlubFrozen(page))) {
			prior = get_cold_free_pointer_from_page(page);
			set_cold_pointer(s, object, prior);
			set_cold_free_pointer_from_page(page, object);
			prior = (void *) 0xbeef1234;
		} else {		
			prior = page->freelist;
			set_freepointer(s, object, prior);
			page->freelist = object;
			page->inuse--;
		}
	} else {
		prior = page->freelist;
		set_freepointer(s, object, prior);
		page->freelist = object;
		page->inuse--;
	}
#else 
	prior = page->freelist;
	set_freepointer(s, object, prior);
	page->freelist = object;
	page->inuse--;
#endif
	if (unlikely(PageSlubFrozen(page))) {
		stat(s, FREE_FROZEN);
		goto out_unlock;
	}

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		/* start reducing min_partial after dfree age timeout */
		if (time_after(jiffies, s->tmp_partial_age + SLUG_DFREE_TMOUT))
		{
			if (atomic_long_read(&s->tmp_partial) > s->min_partial)
				atomic_long_set(&s->tmp_partial, s->min_partial);
		}
	}

	/* only free slab if we have exceeded number of allowed partial slabs */
	n = get_node(s, page_to_nid(page));
	tmp = atomic_long_read(&s->tmp_partial);
	if (unlikely((!page->inuse) && (n->nr_partial > max(s->min_partial, tmp))))
#else
	if (unlikely(!page->inuse))
#endif
		goto slab_empty;

	/*
	 * Objects left in the slab. If it was not on the partial list before
	 * then add it.
	 */
	if (unlikely(!prior)) {
#ifdef CONFIG_SILKWORM_SLUG
		add_partial(n, page, 1);
#else
		add_partial(get_node(s, page_to_nid(page)), page, 1);
#endif
		stat(s, FREE_ADD_PARTIAL);
	}

	out_unlock:
	slab_unlock(page);
	return;

	slab_empty:
	if (prior) {
		/*
		 * Slab still on the partial list.
		 */
		remove_partial(s, page);
		stat(s, FREE_REMOVE_PARTIAL);
	}
	slab_unlock(page);
	stat(s, FREE_SLAB);
	discard_slab(s, page);
	return;

	debug:
	if (!free_debug_processing(s, page, x, addr))
		goto out_unlock;
	goto checks_ok;
}

/*
 * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
 * can perform fastpath freeing without additional function calls.
 *
 * The fastpath is only possible if we are freeing to the current cpu slab
 * of this processor. This typically the case if we have just allocated
 * the item before.
 *
 * If fastpath is not possible then fall back to __slab_free where we deal
 * with all sorts of special processing.
 */
static __always_inline void slab_free(struct kmem_cache *s,
				      struct page *page, void *x, unsigned long addr)
{
	void **object;
	struct kmem_cache_cpu *c;
	unsigned long flags;

#ifdef CONFIG_SILKWORM_SLUG
	/* shift object back over header */
	if (x && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
		x = (void *)((unsigned long)x - cache_line_size());
#endif
	object = (void *)x;
	kmemleak_free_recursive(x, s->flags);
	local_irq_save(flags);
	c = __this_cpu_ptr(s->cpu_slab);
	kmemcheck_slab_free(s, object, s->objsize);
	debug_check_no_locks_freed(object, s->objsize);
	if (!(s->flags & SLAB_DEBUG_OBJECTS))
		debug_check_no_obj_freed(object, s->objsize);
	if (likely(page == c->page && c->node >= 0)) {
		set_freepointer(s, object, c->freelist);
		c->freelist = object;
		stat(s, FREE_FASTPATH);
	} else
		__slab_free(s, page, x, addr);

	local_irq_restore(flags);
}

void kmem_cache_free(struct kmem_cache *s, void *x)
{
	struct page *page;

	page = virt_to_head_page(x);

#ifdef CONFIG_SILKWORM_MLT
	if (mlt_km_enabled)
	{
        	MLT_param_t mlt_param;
        	mlt_param.s = page->slab;
#ifdef CONFIG_SILKWORM_SLUG
        	if (x && (page->slab->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
                	mlt_param.ptr = (void *)((unsigned long)x - cache_line_size());
        	else
#endif
        	mlt_param.ptr = x;
        	MLT_kfree_processing(&mlt_param);
	}
#endif

	slab_free(s, page, x, _RET_IP_);

	trace_kmem_cache_free(_RET_IP_, x);
}
EXPORT_SYMBOL(kmem_cache_free);

#ifdef CONFIG_SILKWORM_MLT
void kmem_cache_free_mlt_bypass(struct kmem_cache *s, void *x)
{
        struct page *page;

        page = virt_to_head_page(x);

        slab_free(s, page, x, _RET_IP_);

        trace_kmem_cache_free(_RET_IP_, x);
}
EXPORT_SYMBOL(kmem_cache_free_mlt_bypass);
#endif

/* Figure out on which slab page the object resides */
static struct page *get_object_page(const void *x)
{
	struct page *page = virt_to_head_page(x);

	if (!PageSlab(page))
		return NULL;

	return page;
}

/*
 * Object placement in a slab is made very easy because we always start at
 * offset 0. If we tune the size of the object to the alignment then we can
 * get the required alignment by putting one properly sized object after
 * another.
 *
 * Notice that the allocation order determines the sizes of the per cpu
 * caches. Each processor has always one slab available for allocations.
 * Increasing the allocation order reduces the number of times that slabs
 * must be moved on and off the partial lists and is therefore a factor in
 * locking overhead.
 */

/*
 * Mininum / Maximum order of slab pages. This influences locking overhead
 * and slab fragmentation. A higher order reduces the number of partial slabs
 * and increases the number of allocations possible without having to
 * take the list_lock.
 */
static int slub_min_order;
#ifdef CONFIG_SILKWORM_SLUG
//static int slub_max_order = 4;
static int slub_max_order = PAGE_ALLOC_COSTLY_ORDER;
#else
static int slub_max_order = PAGE_ALLOC_COSTLY_ORDER;
#endif
static int slub_min_objects;

/*
 * Merge control. If this is set then no merging of slab caches will occur.
 * (Could be removed. This was introduced to pacify the merge skeptics.)
 */
#if defined(CONFIG_SILKWORM_MLT) || defined(CONFIG_SILKWORM_SLUG)
/* do not allow any caches to be merged as MLT book keeping and delayed free is stored in slub metadata */
static int slub_nomerge = 1;
#else
static int slub_nomerge;
#endif

/*
 * Calculate the order of allocation given an slab object size.
 *
 * The order of allocation has significant impact on performance and other
 * system components. Generally order 0 allocations should be preferred since
 * order 0 does not cause fragmentation in the page allocator. Larger objects
 * be problematic to put into order 0 slabs because there may be too much
 * unused space left. We go to a higher order if more than 1/16th of the slab
 * would be wasted.
 *
 * In order to reach satisfactory performance we must ensure that a minimum
 * number of objects is in one slab. Otherwise we may generate too much
 * activity on the partial lists which requires taking the list_lock. This is
 * less a concern for large slabs though which are rarely used.
 *
 * slub_max_order specifies the order where we begin to stop considering the
 * number of objects in a slab as critical. If we reach slub_max_order then
 * we try to keep the page order as low as possible. So we accept more waste
 * of space in favor of a small page order.
 *
 * Higher order allocations also allow the placement of more objects in a
 * slab and thereby reduce object handling overhead. If the user has
 * requested a higher mininum order then we start with that one instead of
 * the smallest order which will fit the object.
 */
static inline int slab_order(int size, int min_objects,
			     int max_order, int fract_leftover)
{
	int order;
	int rem;
	int min_order = slub_min_order;

	if ((PAGE_SIZE << min_order) / size > MAX_OBJS_PER_PAGE)
		return get_order(size * MAX_OBJS_PER_PAGE) - 1;

	for (order = max(min_order,
			 fls(min_objects * size - 1) - PAGE_SHIFT);
	    order <= max_order; order++) {

		unsigned long slab_size = PAGE_SIZE << order;

		if (slab_size < min_objects * size)
			continue;

		rem = slab_size % size;

		if (rem <= slab_size / fract_leftover)
			break;

	}

	return order;
}

static inline int calculate_order(int size)
{
	int order;
	int min_objects;
	int fraction;
	int max_objects;

	/*
	 * Attempt to find best configuration for a slab. This
	 * works by first attempting to generate a layout with
	 * the best configuration and backing off gradually.
	 *
	 * First we reduce the acceptable waste in a slab. Then
	 * we reduce the minimum objects required in a slab.
	 */
	min_objects = slub_min_objects;
	if (!min_objects)
		min_objects = 4 * (fls(nr_cpu_ids) + 1);
	max_objects = (PAGE_SIZE << slub_max_order)/size;
	min_objects = min(min_objects, max_objects);

	while (min_objects > 1) {
		fraction = 16;
		while (fraction >= 4) {
			order = slab_order(size, min_objects,
					   slub_max_order, fraction);
			if (order <= slub_max_order)
				return order;
			fraction /= 2;
		}
		min_objects--;
	}

	/*
	 * We were unable to place multiple objects in a slab. Now
	 * lets see if we can place a single object there.
	 */
	order = slab_order(size, 1, slub_max_order, 1);
	if (order <= slub_max_order)
		return order;

	/*
	 * Doh this slab cannot be placed using slub_max_order.
	 */
	order = slab_order(size, 1, MAX_ORDER, 1);
	if (order < MAX_ORDER)
		return order;
	return -ENOSYS;
}

/*
 * Figure out what the alignment of the objects will be.
 */
static unsigned long calculate_alignment(unsigned long flags,
					 unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
		unsigned long ralign = cache_line_size();
		while (size <= ralign / 2)
			ralign /= 2;
		align = max(align, ralign);
	}

	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

	return ALIGN(align, sizeof(void *));
}

static void
init_kmem_cache_node(struct kmem_cache_node *n, struct kmem_cache *s)
{
	n->nr_partial = 0;
	spin_lock_init(&n->list_lock);
	INIT_LIST_HEAD(&n->partial);
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_set(&n->nr_slabs, 0);
	atomic_long_set(&n->total_objects, 0);
	INIT_LIST_HEAD(&n->full);
#endif
}

static DEFINE_PER_CPU(struct kmem_cache_cpu, kmalloc_percpu[KMALLOC_CACHES]);

static inline int alloc_kmem_cache_cpus(struct kmem_cache *s, gfp_t flags)
{
	if (s < kmalloc_caches + KMALLOC_CACHES && s >= kmalloc_caches)
		/*
		 * Boot time creation of the kmalloc array. Use static per cpu data
		 * since the per cpu allocator is not available yet.
		 */
		s->cpu_slab = kmalloc_percpu + (s - kmalloc_caches);
	else
		s->cpu_slab =  alloc_percpu(struct kmem_cache_cpu);

	if (!s->cpu_slab)
		return 0;

	return 1;
}

#ifdef CONFIG_NUMA
/*
 * No kmalloc_node yet so do it by hand. We know that this is the first
 * slab on the node for this slabcache. There are no concurrent accesses
 * possible.
 *
 * Note that this function only works on the kmalloc_node_cache
 * when allocating for the kmalloc_node_cache. This is used for bootstrapping
 * memory on a fresh node that has no slab structures yet.
 */
static void early_kmem_cache_node_alloc(gfp_t gfpflags, int node)
{
	struct page *page;
	struct kmem_cache_node *n;
	unsigned long flags;

	BUG_ON(kmalloc_caches->size < sizeof(struct kmem_cache_node));

	page = new_slab(kmalloc_caches, gfpflags, node);

	BUG_ON(!page);
	if (page_to_nid(page) != node) {
		printk(KERN_ERR "SLUB: Unable to allocate memory from "
		       "node %d\n", node);
		printk(KERN_ERR "SLUB: Allocating a useless per node structure "
		       "in order to be able to continue\n");
	}

	n = page->freelist;
	BUG_ON(!n);
	page->freelist = get_freepointer(kmalloc_caches, n);
	page->inuse++;
	kmalloc_caches->node[node] = n;
#ifdef CONFIG_SLUB_DEBUG
	init_object(kmalloc_caches, n, 1);
	init_tracking(kmalloc_caches, n);
#endif
	init_kmem_cache_node(n, kmalloc_caches);
	inc_slabs_node(kmalloc_caches, node, page->objects);

	/*
	 * lockdep requires consistent irq usage for each lock
	 * so even though there cannot be a race this early in
	 * the boot sequence, we still disable irqs.
	 */
	local_irq_save(flags);
	add_partial(n, page, 0);
	local_irq_restore(flags);
}

static void free_kmem_cache_nodes(struct kmem_cache *s)
{
	int node;

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = s->node[node];
		if (n)
			kmem_cache_free(kmalloc_caches, n);
		s->node[node] = NULL;
	}
}

static int init_kmem_cache_nodes(struct kmem_cache *s, gfp_t gfpflags)
{
	int node;

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n;

		if (slab_state == DOWN) {
			early_kmem_cache_node_alloc(gfpflags, node);
			continue;
		}
		n = kmem_cache_alloc_node(kmalloc_caches,
					  gfpflags, node);

		if (!n) {
			free_kmem_cache_nodes(s);
			return 0;
		}

		s->node[node] = n;
		init_kmem_cache_node(n, s);
	}
	return 1;
}
#else
static void free_kmem_cache_nodes(struct kmem_cache *s)
{
}

static int init_kmem_cache_nodes(struct kmem_cache *s, gfp_t gfpflags)
{
	init_kmem_cache_node(&s->local_node, s);
	return 1;
}
#endif

static void set_min_partial(struct kmem_cache *s, unsigned long min)
{
	if (min < MIN_PARTIAL)
		min = MIN_PARTIAL;
#ifndef CONFIG_SILKWORM
	/* allow slab cache to grow beyond MAX_PARTIAL */
	else if (min > MAX_PARTIAL)
		min = MAX_PARTIAL;
#endif
	s->min_partial = min;
}

/*
 * calculate_sizes() determines the order and the distribution of data within
 * a slab object.
 */
static int calculate_sizes(struct kmem_cache *s, int forced_order)
{
	unsigned long flags = s->flags;
	unsigned long size = s->objsize;
	unsigned long align = s->align;
	int order;

	/*
	 * Round up object size to the next word boundary. We can only
	 * place the free pointer at word boundaries and this determines
	 * the possible location of the free pointer.
	 */
	size = ALIGN(size, sizeof(void *));

#ifdef CONFIG_SLUB_DEBUG
	/*
	 * Determine if we can poison the object itself. If the user of
	 * the slab may touch the object after free or before allocation
	 * then we should never poison the object itself.
	 */
	if ((flags & SLAB_POISON) && !(flags & SLAB_DESTROY_BY_RCU) &&
	    !s->ctor)
		s->flags |= __OBJECT_POISON;
	else
		s->flags &= ~__OBJECT_POISON;


	/*
	 * If we are Redzoning then check if there is some space between the
	 * end of the object and the free pointer. If not then add an
	 * additional word to have some bytes to store Redzone information.
	 */
	if ((flags & SLAB_RED_ZONE) && size == s->objsize)
#ifdef CONFIG_SILKWORM_SLUG
		size += cache_line_size();
#else
		size += sizeof(void *);
#endif
#endif

	/*
	 * With that we have determined the number of bytes in actual use
	 * by the object. This is the potential offset to the free pointer.
	 */
	s->inuse = size;

#ifdef CONFIG_SILKWORM_SLUG
	if (((flags & (SLAB_DESTROY_BY_RCU | SLAB_POISON | SLAB_DFREE)) || s->ctor)) 
#else
	if (((flags & (SLAB_DESTROY_BY_RCU | SLAB_POISON)) || s->ctor)) 
#endif
	{
		/*
		 * Relocate free pointer after the object if it is not
		 * permitted to overwrite the first word of the object on
		 * kmem_cache_free.
		 *
		 * This is the case if we do RCU, have a constructor or
		 * destructor or are poisoning the objects.
		 */
		s->offset = size;
		size += sizeof(void *);
	}
	
#ifdef CONFIG_SILKWORM_MLT
	size += sizeof(MLT_book_keeping_info_t);
#endif

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE)
	{
		size += 2*sizeof(void *);	/* cold free pointer and cold pointer */
		if (slub_debug & SLAB_POISON)
			size += sizeof(void *) * SLUG_STACK_SIZE * 2;	/* alloc and free stack frames */
	}
#endif

#ifdef CONFIG_SLUB_DEBUG
	if (flags & SLAB_STORE_USER)
		/*
		 * Need to store information about allocs and frees after
		 * the object.
		 */
		size += 2 * sizeof(struct track);

#ifdef CONFIG_ESLUB_DEBUG	   
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_INTERNAL)) {
		s->xtrack = size;
		size += XTRACK_SIZE;
	}
#endif	
	if (flags & SLAB_RED_ZONE)
		/*
		 * Add some empty padding so that we can catch
		 * overwrites from earlier objects rather than let
		 * tracking information or the free pointer be
		 * corrupted if a user writes before the start
		 * of the object.
		 */
#ifdef CONFIG_SILKWORM_SLUG
		size += cache_line_size();
#else
		size += sizeof(void *);
#endif
#endif

	/*
	 * Determine the alignment based on various parameters that the
	 * user specified and the dynamic determination of cache line size
	 * on bootup.
	 */
	align = calculate_alignment(flags, align, s->objsize);
	s->align = align;

	/*
	 * SLUB stores one object immediately after another beginning from
	 * offset 0. In order to align the objects we have to simply size
	 * each object to conform to the alignment.
	 */
	size = ALIGN(size, align);
	s->size = size;
	if (forced_order >= 0)
		order = forced_order;
	else
		order = calculate_order(size);

	if (order < 0)
		return 0;

	s->allocflags = 0;
	if (order)
		s->allocflags |= __GFP_COMP;

	if (s->flags & SLAB_CACHE_DMA)
		s->allocflags |= SLUB_DMA;

	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		s->allocflags |= __GFP_RECLAIMABLE;

	/*
	 * Determine the number of objects per slab
	 */
	s->oo = oo_make(order, size);
	s->min = oo_make(get_order(size), size);
	if (oo_objects(s->oo) > oo_objects(s->max))
		s->max = s->oo;

	return !!oo_objects(s->oo);

}

static int kmem_cache_open(struct kmem_cache *s, gfp_t gfpflags,
			   const char *name, size_t size,
			   size_t align, unsigned long flags,
			   void (*ctor)(void *))
{
	memset(s, 0, kmem_size);
	s->name = name;
	s->ctor = ctor;
	s->objsize = size;
	s->align = align;
	s->flags = kmem_cache_flags(size, flags, name, ctor);
#ifdef CONFIG_ESLUB_DEBUG	   
	atomic_long_set(&s->eslub_total_mem, 0);
#endif
   
#ifdef CONFIG_SILKWORM_SLUG
	/* 
	 * We want to add a header in front of the object to catch if 
	 * the user underruns the buffer. Only do this when poisoning 
	 * is enabled.
	 */
	if ((s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
		s->objsize += cache_line_size();
#endif

	if (!calculate_sizes(s, -1))
		goto error;
	if (disable_higher_order_debug) {
		/*
		 * Disable debugging flags that store metadata if the min slab
		 * order increased.
		 */
		if (get_order(s->size) > get_order(s->objsize)) {
			s->flags &= ~DEBUG_METADATA_FLAGS;
			s->offset = 0;
			if (!calculate_sizes(s, -1))
				goto error;
		}
	}

	/*
	 * The larger the object size is, the more pages we want on the partial
	 * list to avoid pounding the page allocator excessively.
	 */
	set_min_partial(s, ilog2(s->size));
	s->refcount = 1;
#ifdef CONFIG_SILKWORM_SLUG
	s->nr_free = 0;
	spin_lock_init(&s->free_lock);
	INIT_LIST_HEAD(&s->free);
	s->dfree_min = MAX_PARTIAL;
	s->max_objects = 0;
	s->tmp_partial_age = jiffies;
	atomic_long_set(&s->tmp_partial, 0);
#endif
#ifdef CONFIG_NUMA
	s->remote_node_defrag_ratio = 1000;
#endif
	if (!init_kmem_cache_nodes(s, gfpflags & ~SLUB_DMA))
		goto error;

	if (alloc_kmem_cache_cpus(s, gfpflags & ~SLUB_DMA))
		return 1;

	free_kmem_cache_nodes(s);
	error:
	if (flags & SLAB_PANIC)
		panic("Cannot create slab %s size=%lu realsize=%u "
		      "order=%u offset=%u flags=%lx\n",
		      s->name, (unsigned long)size, s->size, oo_order(s->oo),
		      s->offset, flags);
	return 0;
}

/*
 * Check if a given pointer is valid
 */
int kmem_ptr_validate(struct kmem_cache *s, const void *object)
{
	struct page *page;

	if (!kern_ptr_validate(object, s->size))
		return 0;

	page = get_object_page(object);

	if (!page || s != page->slab)
		/* No slab or wrong slab */
		return 0;

	if (!check_valid_pointer(s, page, object))
		return 0;

	/*
	 * We could also check if the object is on the slabs freelist.
	 * But this would be too expensive and it seems that the main
	 * purpose of kmem_ptr_valid() is to check if the object belongs
	 * to a certain slab.
	 */
	return 1;
}
EXPORT_SYMBOL(kmem_ptr_validate);

/*
 * Determine the size of a slab object
 */
unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->objsize;
}
EXPORT_SYMBOL(kmem_cache_size);

const char *kmem_cache_name(struct kmem_cache *s)
{
	return s->name;
}
EXPORT_SYMBOL(kmem_cache_name);

static void list_slab_objects(struct kmem_cache *s, struct page *page,
			      const char *text)
{
#ifdef CONFIG_SLUB_DEBUG
	void *addr = page_address(page);
	void *p;
	DECLARE_BITMAP(map, page->objects);

	bitmap_zero(map, page->objects);
	slab_err(s, page, "%s", text);
	slab_lock(page);
	for_each_free_object(p, s, page->freelist)
	set_bit(slab_index(p, s, addr), map);

	for_each_object(p, s, addr, page->objects) {

		if (!test_bit(slab_index(p, s, addr), map)) {
			printk(KERN_ERR "INFO: Object 0x%p @offset=%tu\n",
			       p, p - addr);
			print_tracking(s, p);
		}
	}
	slab_unlock(page);
#endif
}

/*
 * Attempt to free all partial slabs on a node.
 */
static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
{
	unsigned long flags;
	struct page *page, *h;

	spin_lock_irqsave(&n->list_lock, flags);
	list_for_each_entry_safe(page, h, &n->partial, lru) {
		if (!page->inuse) {
			list_del(&page->lru);
			discard_slab(s, page);
			n->nr_partial--;
		} else {
			list_slab_objects(s, page,
					  "Objects remaining on kmem_cache_close()");
		}
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
}

/*
 * Release all resources used by a slab cache.
 */
static inline int kmem_cache_close(struct kmem_cache *s)
{
	int node;

	flush_all(s);
	free_percpu(s->cpu_slab);
	/* Attempt to free all objects */
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		free_partial(s, n);
		if (n->nr_partial || slabs_node(s, node))
			return 1;
	}
	free_kmem_cache_nodes(s);
	return 0;
}

/*
 * Close a cache and release the kmem_cache structure
 * (must be used for caches created using kmem_cache_create)
 */
void kmem_cache_destroy(struct kmem_cache *s)
{
	down_write(&slub_lock);
	s->refcount--;
	if (!s->refcount) {
		list_del(&s->list);
		up_write(&slub_lock);
		if (kmem_cache_close(s)) {
			printk(KERN_ERR "SLUB %s: %s called for cache that "
			       "still has objects.\n", s->name, __func__);
#ifdef CONFIG_SILKWORM
			{
				int save_message_loglevel;
				save_message_loglevel = default_message_loglevel;
				default_message_loglevel = minimum_console_loglevel;
				printk(KERN_EMERG "The following is the CURRENT Stack:\n");
				dump_stack();
				default_message_loglevel = save_message_loglevel;
			}
#else
			dump_stack();
#endif
		}
		if (s->flags & SLAB_DESTROY_BY_RCU)
			rcu_barrier();
		sysfs_slab_remove(s);
	} else
		up_write(&slub_lock);
}
EXPORT_SYMBOL(kmem_cache_destroy);

/********************************************************************
 *		Kmalloc subsystem
 *******************************************************************/

struct kmem_cache kmalloc_caches[KMALLOC_CACHES] __cacheline_aligned;
EXPORT_SYMBOL(kmalloc_caches);

#ifdef CONFIG_SILKWORM_SLUG
struct kmem_cache kmalloc_brcd_caches[KMALLOC_CACHES] __cacheline_aligned;
EXPORT_SYMBOL(kmalloc_brcd_caches);
#endif

static int __init setup_slub_min_order(char *str)
{
	get_option(&str, &slub_min_order);

	return 1;
}

__setup("slub_min_order=", setup_slub_min_order);

static int __init setup_slub_max_order(char *str)
{
	get_option(&str, &slub_max_order);
	slub_max_order = min(slub_max_order, MAX_ORDER - 1);

	return 1;
}

__setup("slub_max_order=", setup_slub_max_order);

static int __init setup_slub_min_objects(char *str)
{
	get_option(&str, &slub_min_objects);

	return 1;
}

__setup("slub_min_objects=", setup_slub_min_objects);

static int __init setup_slub_nomerge(char *str)
{
	slub_nomerge = 1;
	return 1;
}

__setup("slub_nomerge", setup_slub_nomerge);

static struct kmem_cache *create_kmalloc_cache(struct kmem_cache *s,
					       const char *name, int size, gfp_t gfp_flags)
{
	unsigned int flags = 0;

	if (gfp_flags & SLUB_DMA)
		flags = SLAB_CACHE_DMA;

#ifdef CONFIG_SILKWORM_SLUG
	flags |= SLAB_DFREE;
	if (size >= 1024)
		flags |= SLAB_HWCACHE_ALIGN;
#endif
	/*
	 * This function is called with IRQs disabled during early-boot on
	 * single CPU so there's no need to take slub_lock here.
	 */
	if (!kmem_cache_open(s, gfp_flags, name, size, ARCH_KMALLOC_MINALIGN,
			     flags, NULL))
		goto panic;

	list_add(&s->list, &slab_caches);

	if (sysfs_slab_add(s))
		goto panic;
	return s;

	panic:
	panic("Creation of kmalloc slab %s size=%d failed.\n", name, size);
}

#ifdef CONFIG_ZONE_DMA
static struct kmem_cache *kmalloc_caches_dma[SLUB_PAGE_SHIFT];

static void sysfs_add_func(struct work_struct *w)
{
	struct kmem_cache *s;

	down_write(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		if (s->flags & __SYSFS_ADD_DEFERRED) {
			s->flags &= ~__SYSFS_ADD_DEFERRED;
			sysfs_slab_add(s);
		}
	}
	up_write(&slub_lock);
}

static DECLARE_WORK(sysfs_add_work, sysfs_add_func);

static noinline struct kmem_cache *dma_kmalloc_cache(int index, gfp_t flags)
{
	struct kmem_cache *s;
	char *text;
	size_t realsize;
	unsigned long slabflags;
	int i;

	s = kmalloc_caches_dma[index];
	if (s)
		return s;

	/* Dynamically create dma cache */
	if (flags & __GFP_WAIT)
		down_write(&slub_lock);
	else {
		if (!down_write_trylock(&slub_lock))
			goto out;
	}

	if (kmalloc_caches_dma[index])
		goto unlock_out;

	realsize = kmalloc_caches[index].objsize;
	text = kasprintf(flags & ~SLUB_DMA, "kmalloc_dma-%d",
			 (unsigned int)realsize);

	s = NULL;
	for (i = 0; i < KMALLOC_CACHES; i++)
		if (!kmalloc_caches[i].size)
			break;

	BUG_ON(i >= KMALLOC_CACHES);
	s = kmalloc_caches + i;

	/*
	 * Must defer sysfs creation to a workqueue because we don't know
	 * what context we are called from. Before sysfs comes up, we don't
	 * need to do anything because our sysfs initcall will start by
	 * adding all existing slabs to sysfs.
	 */
	slabflags = SLAB_CACHE_DMA|SLAB_NOTRACK;
	if (slab_state >= SYSFS)
		slabflags |= __SYSFS_ADD_DEFERRED;

#ifdef CONFIG_SILKWORM
	slabflags |= SLAB_HWCACHE_ALIGN;
#endif

	if (!text || !kmem_cache_open(s, flags, text,
				      realsize, ARCH_KMALLOC_MINALIGN, slabflags, NULL)) {
		s->size = 0;
		kfree(text);
		goto unlock_out;
	}

	list_add(&s->list, &slab_caches);
	kmalloc_caches_dma[index] = s;

	if (slab_state >= SYSFS)
		schedule_work(&sysfs_add_work);

	unlock_out:
	up_write(&slub_lock);
	out:
	return kmalloc_caches_dma[index];
}
#endif

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
static s8 size_index[24] = {
	3,  /* 8 */
	4,  /* 16 */
	5,  /* 24 */
	5,  /* 32 */
	6,  /* 40 */
	6,  /* 48 */
	6,  /* 56 */
	6,  /* 64 */
	1,  /* 72 */
	1,  /* 80 */
	1,  /* 88 */
	1,  /* 96 */
	7,  /* 104 */
	7,  /* 112 */
	7,  /* 120 */
	7,  /* 128 */
	2,  /* 136 */
	2,  /* 144 */
	2,  /* 152 */
	2,  /* 160 */
	2,  /* 168 */
	2,  /* 176 */
	2,  /* 184 */
	2   /* 192 */
};

static inline int size_index_elem(size_t bytes)
{
	return(bytes - 1) / 8;
}

static struct kmem_cache *get_slab(size_t size, gfp_t flags) 
{
	int index;

	if (size <= 192) {
		if (!size)
			return ZERO_SIZE_PTR;

		index = size_index[size_index_elem(size)];
	} else
		index = fls(size - 1);

#ifdef CONFIG_ZONE_DMA
	if (unlikely((flags & SLUB_DMA)))
		return dma_kmalloc_cache(index, flags);

#endif
	return &kmalloc_caches[index];
}

#ifdef CONFIG_SILKWORM_MLT
struct kmem_cache *get_cachep(size_t size, gfp_t flags) 
{
	return get_slab(size, flags);
}
#endif

void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;
#ifdef CONFIG_SILKWORM_MLT
	MLT_param_t mlt_param;
#endif

	if (unlikely(size > SLUB_MAX_SIZE)) {
		return kmalloc_large(size, flags);
	} else {

		s = get_slab(size, flags);

		if (unlikely(ZERO_OR_NULL_PTR(s)))
			return s;

		ret = slab_alloc(s, flags, -1, _RET_IP_);
		trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
	}

#ifdef CONFIG_SILKWORM_MLT
	if (ret) {
		mlt_param.s = s;
#ifdef CONFIG_SILKWORM_SLUG
		if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
		else
#endif
		mlt_param.ptr = ret;
		MLT_kmalloc_processing(&mlt_param);
	}
#endif


	return ret;
}
EXPORT_SYMBOL(__kmalloc);

#ifdef CONFIG_SILKWORM_SLUG
static struct kmem_cache *get_slab_brcd(size_t size, gfp_t flags) 
{
	int index;

	if (size <= 192) {
		if (!size)
			return ZERO_SIZE_PTR;

		index = size_index[size_index_elem(size)];
	} else
		index = fls(size - 1);

#ifdef CONFIG_ZONE_DMA
	if (unlikely((flags & SLUB_DMA)))
		return dma_kmalloc_cache(index, flags);

#endif
	return &kmalloc_brcd_caches[index];
}

void *__kmalloc_brcd(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;
#ifdef CONFIG_SILKWORM_MLT
	MLT_param_t mlt_param;
#endif

	if (unlikely(size > SLUB_MAX_SIZE)) {
		return kmalloc_large(size, flags);
	} else {

		s = get_slab_brcd(size, flags);

		if (unlikely(ZERO_OR_NULL_PTR(s)))
			return s;

		ret = slab_alloc(s, flags, -1, _RET_IP_);
		trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
	}

#ifdef CONFIG_SILKWORM_MLT
	if (ret) {
		mlt_param.s = s;
#ifdef CONFIG_SILKWORM_SLUG
		if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
		else
#endif
		mlt_param.ptr = ret;
		MLT_kmalloc_processing(&mlt_param);
	}
#endif


	return ret;
}
EXPORT_SYMBOL(__kmalloc_brcd);
#endif

static void *kmalloc_large_node(size_t size, gfp_t flags, int node)
{
	struct page *page;
	void *ptr = NULL;

	flags |= __GFP_COMP | __GFP_NOTRACK;
	page = alloc_pages_node(node, flags, get_order(size));
	if (page)
		ptr = page_address(page);

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
        if ((ptr) && (mlt_kl_enabled))
        {
            MLT_KL_param_t mlt_kl_param;

            memset(&mlt_kl_param, 0, sizeof(MLT_KL_param_t));
            mlt_kl_param.alloc_ptr = ptr;
            mlt_kl_param.alloc_size = PAGE_SIZE << get_order(size);
            MLT_KL_alloc_processing(&mlt_kl_param);
        }
#endif

#ifdef CONFIG_SILKWORM_MLT
        atomic_inc(&kmalloc_large_cnt);
#endif

	kmemleak_alloc(ptr, size, 1, flags);
	return ptr;

}

#ifdef CONFIG_NUMA
void *__kmalloc_node(size_t size, gfp_t flags, int node)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > SLUB_MAX_SIZE)) {
		ret = kmalloc_large_node(size, flags, node);

		trace_kmalloc_node(_RET_IP_, ret,
				   size, PAGE_SIZE << get_order(size),
				   flags, node);

		return ret;
	}

	s = get_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc(s, flags, node, _RET_IP_);

	trace_kmalloc_node(_RET_IP_, ret, size, s->size, flags, node);

	return ret;
}
EXPORT_SYMBOL(__kmalloc_node);
#endif

size_t ksize(const void *object)
{
	struct page *page;
	struct kmem_cache *s;

	if (unlikely(object == ZERO_SIZE_PTR))
		return 0;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page))) {
		WARN_ON(!PageCompound(page));
		return PAGE_SIZE << compound_order(page);
	}
	s = page->slab;

#ifdef CONFIG_SILKWORM_SLUG
	if ((s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
		return (s->objsize - cache_line_size());
#endif

#ifdef CONFIG_SLUB_DEBUG
	/*
	 * Debugging requires use of the padding between object
	 * and whatever may come after it.
	 */
	if (s->flags & (SLAB_RED_ZONE | SLAB_POISON))
		return s->objsize;

#endif

#ifdef CONFIG_SILKWORM_MLT
	/* if MLT is enabled, the book keeping is stored in the metadata */
	return s->inuse;
#endif

	/*
	 * If we have the need to store the freelist pointer
	 * back there or track user information then we can
	 * only use the space before that information.
	 */
	if (s->flags & (SLAB_DESTROY_BY_RCU | SLAB_STORE_USER))
		return s->inuse;

	/*
	 * Else we can use all the padding etc for the allocation
	 */
	return s->size;
}
EXPORT_SYMBOL(ksize);

void kfree(const void *x)
{
	struct page *page;
	void *object = (void *)x;
#ifdef CONFIG_SILKWORM_MLT
        MLT_param_t mlt_param;
#endif
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
        MLT_KL_param_t mlt_kl_param;
#endif

	trace_kfree(_RET_IP_, x);

	if (unlikely(ZERO_OR_NULL_PTR(x)))
		return;

	page = virt_to_head_page(x);
	if (unlikely(!PageSlab(page))) {
		BUG_ON(!PageCompound(page));
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
		if (mlt_kl_enabled)
		{
		    memset(&mlt_kl_param, 0, sizeof(MLT_KL_param_t));
        	    mlt_kl_param.alloc_ptr = x;
		    MLT_KL_free_processing(&mlt_kl_param);
		}
#endif

#ifdef CONFIG_SILKWORM_MLT
		atomic_dec(&kmalloc_large_cnt);
#endif

		kmemleak_free(x);
		put_page(page);
		return;
	}
#ifdef CONFIG_SILKWORM_MLT
        mlt_param.s = page->slab;
#ifdef CONFIG_SILKWORM_SLUG
	if (object && (page->slab->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
		mlt_param.ptr = (void *)((unsigned long)object - cache_line_size());
	else
#endif
        mlt_param.ptr = object;
	MLT_kfree_processing(&mlt_param);
#endif

	slab_free(page->slab, page, object, _RET_IP_);
}
EXPORT_SYMBOL(kfree);

#ifdef CONFIG_SILKWORM_MLT
void setup_mlt(char *str)
{
	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		return;

	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case '0':
			mlt_enabled = 0;
			break;
		case '1':
			mlt_enabled = 1;
			break;
		default:
			printk(KERN_ERR "mlt option '%c' "
			       "unknown. skipped\n", *str);
		}
	}

}
EXPORT_SYMBOL(mlt_enabled);

__setup("mlt", setup_mlt);

void setup_mlt_km(void)
{
	mlt_km_enabled = 1;
}
EXPORT_SYMBOL(mlt_km_enabled);

__setup("mlt_km", setup_mlt_km);

EXPORT_SYMBOL(kmalloc_large_cnt);
#endif


#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
void setup_mlt_kl(void)
{
	mlt_kl_enabled = 1;
}
EXPORT_SYMBOL(mlt_kl_enabled);

__setup("mlt_kl", setup_mlt_kl);
#endif


#ifdef CONFIG_SILKWORM_MLT
void setup_console_mlt(char *str)
{
	console_mlt = (MLT_CONSOLE_SIZE_BASIC | MLT_CONSOLE_CNT_BASIC | MLT_CONSOLE_STATS_BASIC);

	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		return;

	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 's':
			console_mlt |= MLT_CONSOLE_SIZE_DETAILED;
			break;
		case 't':
			console_mlt |= MLT_CONSOLE_CNT_DETAILED;
			break;
		case 'e':
			console_mlt |= MLT_CONSOLE_STATS_DETAILED;
			break;
		default:
			printk(KERN_ERR "console_mlt option '%c' "
			       "unknown. skipped\n", *str);
		}
	}

	return;
}
EXPORT_SYMBOL(console_mlt);

__setup("console_mlt", setup_console_mlt);
#endif

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
void setup_console_mlt_kl(char *str)
{
	console_mlt_kl = (MLT_KL_CONSOLE_SIZE_BASIC | MLT_KL_CONSOLE_CNT_BASIC |  
				MLT_KL_CONSOLE_STATS_BASIC);

	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		return;

	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 's':
			console_mlt_kl |= MLT_KL_CONSOLE_SIZE_DETAILED;
			break;
		case 't':
			console_mlt_kl |= MLT_KL_CONSOLE_CNT_DETAILED;
			break;
		case 'e':
			console_mlt_kl |= MLT_KL_CONSOLE_STATS_DETAILED;
			break;
		default:
			printk(KERN_ERR "console_mlt_kl option '%c' "
			       "unknown. skipped\n", *str);
		}
	}

}
EXPORT_SYMBOL(console_mlt_kl);

__setup("console_mlt_kl", setup_console_mlt_kl);
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
void setup_console_mlt_vm(char *str)
{
	console_mlt_vm = (MLT_VM_CONSOLE_SIZE_BASIC | MLT_VM_CONSOLE_CNT_BASIC |  
				MLT_VM_CONSOLE_STATS_BASIC);

	if (*str++ != '=' || !*str)
		/*
		 * No options specified. Switch on full debugging.
		 */
		return;

	for (; *str && *str != ','; str++) {
		switch (tolower(*str)) {
		case 's':
			console_mlt_vm |= MLT_VM_CONSOLE_SIZE_DETAILED;
			break;
		case 't':
			console_mlt_vm |= MLT_VM_CONSOLE_CNT_DETAILED;
			break;
		case 'e':
			console_mlt_vm |= MLT_VM_CONSOLE_STATS_DETAILED;
			break;
		default:
			printk(KERN_ERR "console_mlt_vm option '%c' "
			       "unknown. skipped\n", *str);
		}
	}

}
EXPORT_SYMBOL(console_mlt_vm);

__setup("console_mlt_vm", setup_console_mlt_vm);
#endif

void setup_oom_tmpdir(void)
{
        no_oom_tmpdir = 1;
}
EXPORT_SYMBOL(no_oom_tmpdir);

__setup("no_oom_tmpdir", setup_oom_tmpdir);

void setup_oom_mem(void)
{
        no_oom_mem = 1;
}
EXPORT_SYMBOL(no_oom_mem);

__setup("no_oom_mem", setup_oom_mem);

void setup_oom_task(void)
{
        no_oom_task = 1;
}
EXPORT_SYMBOL(no_oom_task);

__setup("no_oom_task", setup_oom_task);

/*
 * kmem_cache_shrink removes empty slabs from the partial lists and sorts
 * the remaining slabs by the number of items in use. The slabs with the
 * most items in use come first. New allocations will then fill those up
 * and thus they can be removed from the partial lists.
 *
 * The slabs with the least items are placed last. This results in them
 * being allocated from last increasing the chance that the last objects
 * are freed in them.
 */
int kmem_cache_shrink(struct kmem_cache *s)
{
	int node;
	int i;
	struct kmem_cache_node *n;
	struct page *page;
	struct page *t;
	int objects = oo_objects(s->max);
	struct list_head *slabs_by_inuse =
	kmalloc(sizeof(struct list_head) * objects, GFP_KERNEL);
	unsigned long flags;
#ifdef CONFIG_SILKWORM_SLUG
	unsigned long tmp = 0;
#endif

	if (!slabs_by_inuse)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		n = get_node(s, node);

		if (!n->nr_partial)
			continue;

		for (i = 0; i < objects; i++)
			INIT_LIST_HEAD(slabs_by_inuse + i);

		spin_lock_irqsave(&n->list_lock, flags);

#ifdef CONFIG_SILKWORM_SLUG
		if (s->flags & SLAB_DFREE)
		{
			/* start reducing min_partial after dfree age timeout */
			if (time_after(jiffies, s->tmp_partial_age + SLUG_DFREE_TMOUT))
			{
				if (atomic_long_read(&s->tmp_partial) > s->min_partial)
					atomic_long_set(&s->tmp_partial, s->min_partial);
			}
			tmp = atomic_long_read(&s->tmp_partial);
		}
		slub_validate_off = 1;
#endif
		/*
		 * Build lists indexed by the items in use in each slab.
		 *
		 * Note that concurrent frees may occur while we hold the
		 * list_lock. page->inuse here is the upper limit.
		 */
		list_for_each_entry_safe(page, t, &n->partial, lru) {
#ifdef CONFIG_SILKWORM_SLUG
			int cnt = 0;
			/* only allow full slabs to be freed when the number of partial pages exceed min_partial */
			if (!page->inuse && (n->nr_partial > max(s->min_partial, tmp)) && slab_trylock(page)) {
#else
			if (!page->inuse && slab_trylock(page)) {
#endif
				/*
				 * Must hold slab lock here because slab_free
				 * may have freed the last object and be
				 * waiting to release the slab.
				 */
				list_del(&page->lru);
				n->nr_partial--;
				slab_unlock(page);
#ifdef CONFIG_SILKWORM_SLUG
				if ((cnt++ % 100) == 0)
					kick_watchdog();
#endif
				discard_slab(s, page);
			} else {
				list_move(&page->lru,
					  slabs_by_inuse + page->inuse);
			}
		}

		/*
		 * Rebuild the partial list with the slabs filled up most
		 * first and the least used slabs at the end.
		 */
		for (i = objects - 1; i >= 0; i--)
			list_splice(slabs_by_inuse + i, n->partial.prev);
#ifdef CONFIG_SILKWORM_SLUG
		slub_validate_off = 0;
#endif
		spin_unlock_irqrestore(&n->list_lock, flags);
	}

	kfree(slabs_by_inuse);
	return 0;
}
EXPORT_SYMBOL(kmem_cache_shrink);

#if defined(CONFIG_NUMA) && defined(CONFIG_MEMORY_HOTPLUG)
static int slab_mem_going_offline_callback(void *arg)
{
	struct kmem_cache *s;

	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list)
	kmem_cache_shrink(s);
	up_read(&slub_lock);

	return 0;
}

static void slab_mem_offline_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int offline_node;

	offline_node = marg->status_change_nid;

	/*
	 * If the node still has available memory. we need kmem_cache_node
	 * for it yet.
	 */
	if (offline_node < 0)
		return;

	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		n = get_node(s, offline_node);
		if (n) {
			/*
			 * if n->nr_slabs > 0, slabs still exist on the node
			 * that is going down. We were unable to free them,
			 * and offline_pages() function shouldn't call this
			 * callback. So, we must fail.
			 */
			BUG_ON(slabs_node(s, offline_node));

			s->node[offline_node] = NULL;
			kmem_cache_free(kmalloc_caches, n);
		}
	}
	up_read(&slub_lock);
}

static int slab_mem_going_online_callback(void *arg)
{
	struct kmem_cache_node *n;
	struct kmem_cache *s;
	struct memory_notify *marg = arg;
	int nid = marg->status_change_nid;
	int ret = 0;

	/*
	 * If the node's memory is already available, then kmem_cache_node is
	 * already created. Nothing to do.
	 */
	if (nid < 0)
		return 0;

	/*
	 * We are bringing a node online. No memory is available yet. We must
	 * allocate a kmem_cache_node structure in order to bring the node
	 * online.
	 */
	down_read(&slub_lock);
	list_for_each_entry(s, &slab_caches, list) {
		/*
		 * XXX: kmem_cache_alloc_node will fallback to other nodes
		 *      since memory is not yet available from the node that
		 *      is brought up.
		 */
		n = kmem_cache_alloc(kmalloc_caches, GFP_KERNEL);
		if (!n) {
			ret = -ENOMEM;
			goto out;
		}
		init_kmem_cache_node(n, s);
		s->node[nid] = n;
	}
	out:
	up_read(&slub_lock);
	return ret;
}

static int slab_memory_callback(struct notifier_block *self,
				unsigned long action, void *arg)
{
	int ret = 0;

	switch (action) {
	case MEM_GOING_ONLINE:
		ret = slab_mem_going_online_callback(arg);
		break;
	case MEM_GOING_OFFLINE:
		ret = slab_mem_going_offline_callback(arg);
		break;
	case MEM_OFFLINE:
	case MEM_CANCEL_ONLINE:
		slab_mem_offline_callback(arg);
		break;
	case MEM_ONLINE:
	case MEM_CANCEL_OFFLINE:
		break;
	}
	if (ret)
		ret = notifier_from_errno(ret);
	else
		ret = NOTIFY_OK;
	return ret;
}

#endif /* CONFIG_MEMORY_HOTPLUG */

#ifdef CONFIG_ESLUB_DEBUG
static inline void init_xtrack(struct kmem_cache *s, void *object)
{
	struct xtrack *p = object + s->xtrack;
	int i;
   
	if (eslub_debug_enabled(s) && (eslub_debug_flags & ESLUB_XTRACK_INTERNAL)) {
		p->idx = 0;
		for (i = 0; i < eslub_num_ctx; i++) {
			memset(&p->track[i], 0, sizeof(struct xtrack_item));
			p->track[i].type = -1;
			p->track[i].redzone = ESLUB_POISON;
		}
	}
}
			      
static inline void store_xtrack(struct kmem_cache *s, struct xtrack *p, enum track_item alloc)
{
	if (p->track[p->idx].redzone != ESLUB_POISON) {
		slab_bug(s, "xtrack redzone for cache=%s idx=%x byte=%x overwritten",
			 s->name, p->idx, p->track[p->idx].redzone);
		dump_stack();
		return;
	}

	p->track[p->idx].type = alloc;
	p->track[p->idx].cpu = smp_processor_id();
	p->track[p->idx].pid = current->pid;
	p->track[p->idx].when = get_cycles();
	
	memset(&p->track[p->idx].stack, 0, sizeof(void *) * ESLUB_MAX_STACK_ENTRY);
	save_stack(p->track[p->idx].stack, ESLUB_MAX_STACK_ENTRY);
	
	p->idx++;
	if (p->idx == eslub_num_ctx)
		p->idx = 0;
}

static inline void set_xtrack_out(struct kmem_cache *s, void *object,
		      enum track_item alloc, unsigned long addr)
{
	struct page *page;
	int off;
	struct xtrack *p;
	int order;
	void *t;
	gfp_t flags = 0;


	page = get_object_page(object);
	if (!page->trace_page) {
		order = get_order(page->objects * XTRACK_SIZE);
		atomic_add(1<<order, &s->eslub_total_mem);
		atomic_add(1<<order, &eslub_total);
		flags = s->allocflags;
		flags |= (__GFP_NOWARN | __GFP_NORETRY) & ~__GFP_NOFAIL;

		/* printk(KERN_ERR "--- cache %s order=%d objects=%d eslub=%d flag=%x\n",
		  s->name, order, page->objects, atomic_read(&s->eslub_total_mem), s->allocflags); */
		
		if (flags & __GFP_WAIT)
			local_irq_enable();

		page->trace_page = alloc_pages(flags | __GFP_ZERO, order);
		
		if (flags & __GFP_WAIT)
			local_irq_disable();
		
		if (page->trace_page == NULL)
			return;
	}

	off = (object - page_address(page))/s->size;
	t = page_address(page->trace_page);
	p = t + (off * XTRACK_SIZE);
	store_xtrack(s, p, alloc);
}

static inline void set_xtrack_in(struct kmem_cache *s, void *object,
			  enum track_item alloc, unsigned long addr)
{
	struct xtrack *p;
	p = object + s->xtrack;
	store_xtrack(s, p, alloc);
}
	

static inline void set_xtrack(struct kmem_cache *s, void *object,
		      enum track_item alloc, unsigned long addr)
{
	if (!eslub_debug_enabled(s))
		return;

	if (eslub_debug_flags & ESLUB_XTRACK_INTERNAL)
		set_xtrack_in(s, object, alloc, addr);
	else
		set_xtrack_out(s, object, alloc, addr);
}
#endif


/********************************************************************
 *			Basic setup of slabs
 *******************************************************************/
#ifdef CONFIG_SILKWORM
static void slug_add_partial(struct kmem_cache_node *n,
			struct page *page, int tail)
{
	unsigned long flags;
	spin_lock_irqsave(&n->list_lock, flags);
	n->nr_partial++;
	if (tail)
		list_add_tail(&page->lru, &n->partial);
	else
		list_add(&page->lru, &n->partial);
	spin_unlock_irqrestore(&n->list_lock, flags);
}

void slub_prime_cache(struct kmem_cache *s)
{
	struct kmem_cache_node *n;
	struct page *new;
	unsigned long tot_slabs = 0;

	n = get_node(s, -1);
	while (n->nr_partial < s->min_partial)
	{
		new = new_slab(s, GFP_KERNEL, -1);
		if (new)
		{
#ifdef CONFIG_SILKWORM_SLUG
			set_cold_free_pointer_from_page(new, NULL);
#endif
			slug_add_partial(n, new, 1);
			tot_slabs++;
		}
	}
#ifdef CONFIG_SILKWORM_SLUG
	atomic_long_set(&s->tmp_partial, tot_slabs);
#endif
}
#endif

#ifdef CONFIG_SILKWORM_SLUG
void slub_dfree_size(struct kmem_cache *s, unsigned long min)
{
	s->min_partial = min / ((1 << oo_order(s->oo)) * PAGE_SIZE);
	s->dfree_min = s->min_partial;
}
#endif

void __init kmem_cache_init(void)
{
	int i;
	int caches = 0;

#ifdef CONFIG_NUMA
	/*
	 * Must first have the slab cache available for the allocations of the
	 * struct kmem_cache_node's. There is special bootstrap code in
	 * kmem_cache_open for slab_state == DOWN.
	 */
	create_kmalloc_cache(&kmalloc_caches[0], "kmem_cache_node",
			     sizeof(struct kmem_cache_node), GFP_NOWAIT);
	kmalloc_caches[0].refcount = -1;
	caches++;

	hotplug_memory_notifier(slab_memory_callback, SLAB_CALLBACK_PRI);
#endif

	/* Able to allocate the per node structures */
	slab_state = PARTIAL;

	/* Caches that are not of the two-to-the-power-of size */
	if (KMALLOC_MIN_SIZE <= 32) {
		create_kmalloc_cache(&kmalloc_caches[1],
				     "kmalloc-96", 96, GFP_NOWAIT);
		caches++;
	}
	if (KMALLOC_MIN_SIZE <= 64) {
		create_kmalloc_cache(&kmalloc_caches[2],
				     "kmalloc-192", 192, GFP_NOWAIT);
		caches++;
	}
	for (i = KMALLOC_SHIFT_LOW; i < SLUB_PAGE_SHIFT; i++) {
		create_kmalloc_cache(&kmalloc_caches[i],
				     "kmalloc", 1 << i, GFP_NOWAIT);
		caches++;
	}
#ifdef CONFIG_SILKWORM_SLUG
#ifndef CONFIG_DFREE_ON
	if (slub_debug & SLAB_POISON)
#endif
	{
		if (KMALLOC_MIN_SIZE <= 32) {
			create_kmalloc_cache(&kmalloc_brcd_caches[1],
					     "kmalloc_brcd-96", 96, GFP_NOWAIT);
		}

		if (KMALLOC_MIN_SIZE <= 64) {
			create_kmalloc_cache(&kmalloc_brcd_caches[2],
					     "kmalloc_brcd-192", 192, GFP_NOWAIT);
		}

		for (i = KMALLOC_SHIFT_LOW; i < SLUB_PAGE_SHIFT; i++) {
			create_kmalloc_cache(&kmalloc_brcd_caches[i],
					     "kmalloc_brcd", 1 << i, GFP_NOWAIT);
		}
	}
#endif


	/*
	 * Patch up the size_index table if we have strange large alignment
	 * requirements for the kmalloc array. This is only the case for
	 * MIPS it seems. The standard arches will not generate any code here.
	 *
	 * Largest permitted alignment is 256 bytes due to the way we
	 * handle the index determination for the smaller caches.
	 *
	 * Make sure that nothing crazy happens if someone starts tinkering
	 * around with ARCH_KMALLOC_MINALIGN
	 */
	
#ifdef CONFIG_SILKWORM_SLUG
#ifndef CONFIG_DFREE_ON
	if (slub_debug & SLAB_POISON)
#endif
	{
		for (i=1; i<KMALLOC_CACHES; i++)
		{
			slub_dfree_size(&kmalloc_brcd_caches[i], KMALLOC_PRIME_SIZE);			
			slub_dfree_size(&kmalloc_caches[i], KMALLOC_PRIME_SIZE);			
		}
	}
#endif

	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		     (KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
		int elem = size_index_elem(i);
		if (elem >= ARRAY_SIZE(size_index))
			break;
		size_index[elem] = KMALLOC_SHIFT_LOW;
	}

	if (KMALLOC_MIN_SIZE == 64) {
		/*
		 * The 96 byte size cache is not used if the alignment
		 * is 64 byte.
		 */
		for (i = 64 + 8; i <= 96; i += 8)
			size_index[size_index_elem(i)] = 7;
	} else if (KMALLOC_MIN_SIZE == 128) {
		/*
		 * The 192 byte sized cache is not used if the alignment
		 * is 128 byte. Redirect kmalloc to use the 256 byte cache
		 * instead.
		 */
		for (i = 128 + 8; i <= 192; i += 8)
			size_index[size_index_elem(i)] = 8;
	}

	slab_state = UP;

	/* Provide the correct kmalloc names now that the caches are up */
	for (i = KMALLOC_SHIFT_LOW; i < SLUB_PAGE_SHIFT; i++)
		kmalloc_caches[i]. name =
		kasprintf(GFP_NOWAIT, "kmalloc-%d", 1 << i);
#ifdef CONFIG_SILKWORM_SLUG
#ifndef CONFIG_DFREE_ON
	if (slub_debug & SLAB_POISON)
#endif
	{
		for (i = KMALLOC_SHIFT_LOW; i < SLUB_PAGE_SHIFT; i++)
			kmalloc_brcd_caches[i]. name = kasprintf(GFP_NOWAIT, "kmalloc_brcd-%d", 1 << i);
	}
#endif

#ifdef CONFIG_SMP
	register_cpu_notifier(&slab_notifier);
#endif
#ifdef CONFIG_NUMA
	kmem_size = offsetof(struct kmem_cache, node) +
		    nr_node_ids * sizeof(struct kmem_cache_node *);
#else
	kmem_size = sizeof(struct kmem_cache);
#endif

	printk(KERN_INFO
	       "SLUB 0x%x: Genslabs=%d, HWalign=%d, Order=%d-%d, MinObjects=%d,"
	       " CPUs=%d, Nodes=%d\n",
	       slub_debug, caches, cache_line_size(),
	       slub_min_order, slub_max_order, slub_min_objects,
	       nr_cpu_ids, nr_node_ids);
   
#ifdef CONFIG_ESLUB_DEBUG
	if(eslub_debug_flags)
		printk(KERN_ERR "ESLUB debug enabled flags=%x ctx=%d neigh=%d slab=%s\n",
		       eslub_debug_flags, eslub_num_ctx, eslub_num_neighs,
		       eslub_debug_slabs ? eslub_debug_slabs : "none");
#endif   
	
#ifdef CONFIG_SILKWORM_SLUG
#ifndef CONFIG_DFREE_ON
	if (slub_debug & SLAB_POISON)
#endif
	{
		// prime the caches 
		struct kmem_cache *s;
		struct kernel_symbol *ks;

		/* fill up the caches */
		printk(KERN_EMERG "SLUB: dfree enabled\n");
		printk(KERN_EMERG "PRIMING SLUB: main caches\n");
		for (i=1; i<KMALLOC_CACHES; i++)
		{
			s = &kmalloc_brcd_caches[i];
			if (s->flags & SLAB_DFREE) 
				slub_prime_cache(s);
			s = &kmalloc_caches[i];
			if (s->flags & SLAB_DFREE) 
				slub_prime_cache(s);
		}
		
		/* change the __kmalloc module export symbol to the brocade version to separate the memory allocations */
		ks = lookup_symbol("__kmalloc", __start___ksymtab, __stop___ksymtab);
		if (ks)
		{
			printk(KERN_INFO "SLUB: real __kmalloc at 0x%lx\n", (unsigned long)__kmalloc);
			printk(KERN_EMERG "SLUB: export __kmalloc at 0x%lx changed to 0x%lx\n", ks->value, (unsigned long)__kmalloc_brcd);
			ks->value = (unsigned long)__kmalloc_brcd;
		}
		ks = lookup_symbol("vmalloc", __start___ksymtab, __stop___ksymtab);
		if (ks)
		{
			printk(KERN_INFO "SLUB: real vmalloc at 0x%lx\n", (unsigned long)__kmalloc);
			printk(KERN_EMERG "SLUB: export vmalloc at 0x%lx changed to 0x%lx\n", ks->value, (unsigned long)vmalloc_brcd);
			ks->value = (unsigned long)vmalloc_brcd;
		}
		ks = lookup_symbol("vfree", __start___ksymtab, __stop___ksymtab);
		if (ks)
		{
			printk(KERN_INFO "SLUB: real vfree at 0x%lx\n", (unsigned long)__kmalloc);
			printk(KERN_EMERG "SLUB: export vfree at 0x%lx changed to 0x%lx\n", ks->value, (unsigned long)vfree_brcd);
			ks->value = (unsigned long)vfree_brcd;
		}
	}
#endif
}

void __init kmem_cache_init_late(void)
{
}

/*
 * Find a mergeable slab cache
 */
static int slab_unmergeable(struct kmem_cache *s)
{
	if (slub_nomerge || (s->flags & SLUB_NEVER_MERGE))
		return 1;

	if (s->ctor)
		return 1;

	/*
	 * We may have set a slab to be unmergeable during bootstrap.
	 */
	if (s->refcount < 0)
		return 1;

	return 0;
}

static struct kmem_cache *find_mergeable(size_t size,
					 size_t align, unsigned long flags, const char *name,
					 void (*ctor)(void *)) 
{
	struct kmem_cache *s;

	if (slub_nomerge || (flags & SLUB_NEVER_MERGE))
		return NULL;

	if (ctor)
		return NULL;

	size = ALIGN(size, sizeof(void *));
	align = calculate_alignment(flags, align, size);
	size = ALIGN(size, align);
	flags = kmem_cache_flags(size, flags, name, NULL);

	list_for_each_entry(s, &slab_caches, list) {
		if (slab_unmergeable(s))
			continue;

		if (size > s->size)
			continue;

		if ((flags & SLUB_MERGE_SAME) != (s->flags & SLUB_MERGE_SAME))
			continue;
		/*
		 * Check if alignment is compatible.
		 * Courtesy of Adrian Drzewiecki
		 */
		if ((s->size & ~(align - 1)) != s->size)
			continue;

		if (s->size - size >= sizeof(void *))
			continue;

		return s;
	}
	return NULL;
}

struct kmem_cache *kmem_cache_create(const char *name, size_t size,
		   size_t align, unsigned long flags, void (*ctor)(void *)) 
{
	struct kmem_cache *s;

	if (WARN_ON(!name))
		return NULL;

	down_write(&slub_lock);
	s = find_mergeable(size, align, flags, name, ctor);
	if (s) {
		s->refcount++;
		/*
		 * Adjust the object sizes so that we clear
		 * the complete object on kzalloc.
		 */
		s->objsize = max(s->objsize, (int)size);
		s->inuse = max_t(int, s->inuse, ALIGN(size, sizeof(void *)));
		up_write(&slub_lock);

		if (sysfs_slab_alias(s, name)) {
			down_write(&slub_lock);
			s->refcount--;
			up_write(&slub_lock);
			goto err;
		}
		return s;
	}

	s = kmalloc(kmem_size, GFP_KERNEL);
	if (s) {
		if (kmem_cache_open(s, GFP_KERNEL, name,
				    size, align, flags, ctor)) {
			list_add(&s->list, &slab_caches);
			up_write(&slub_lock);
			if (sysfs_slab_add(s)) {
				down_write(&slub_lock);
				list_del(&s->list);
				up_write(&slub_lock);
				kfree(s);
				goto err;
			}
			return s;
		}
		kfree(s);
	}
	up_write(&slub_lock);

	err:
	if (flags & SLAB_PANIC)
		panic("Cannot create slabcache %s\n", name);
	else
		s = NULL;
	return s;
}
EXPORT_SYMBOL(kmem_cache_create);

#ifdef CONFIG_SMP
/*
 * Use the cpu notifier to insure that the cpu slabs are flushed when
 * necessary.
 */
static int __cpuinit slab_cpuup_callback(struct notifier_block *nfb,
					 unsigned long action, void *hcpu)
{
	long cpu = (long)hcpu;
	struct kmem_cache *s;
	unsigned long flags;

	switch (action) {
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		down_read(&slub_lock);
		list_for_each_entry(s, &slab_caches, list) {
			local_irq_save(flags);
			__flush_cpu_slab(s, cpu);
			local_irq_restore(flags);
		}
		up_read(&slub_lock);
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata slab_notifier = {
    .notifier_call = slab_cpuup_callback
};
#endif

void *__kmalloc_track_caller(size_t size, gfp_t gfpflags, unsigned long caller)
{
	struct kmem_cache *s;
	void *ret;
#ifdef CONFIG_SILKWORM_MLT
        MLT_param_t mlt_param;
#endif

	if (unlikely(size > SLUB_MAX_SIZE)) {
		return kmalloc_large(size, gfpflags);
	} else {

		s = get_slab(size, gfpflags);

		if (unlikely(ZERO_OR_NULL_PTR(s)))
			return s;

		ret = slab_alloc(s, gfpflags, -1, caller);

		/* Honor the call site pointer we recieved. */
		trace_kmalloc(caller, ret, size, s->size, gfpflags);
	}


#ifdef CONFIG_SILKWORM_MLT
	if (ret) {
                mlt_param.s = s;
#ifdef CONFIG_SILKWORM_SLUG
		if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
		else
#endif
                mlt_param.ptr = ret;
                MLT_kmalloc_processing(&mlt_param);
	}
#endif
	return ret;
}

void *__kmalloc_node_track_caller(size_t size, gfp_t gfpflags,
				  int node, unsigned long caller)
{
	struct kmem_cache *s;
	void *ret;
#ifdef CONFIG_SILKWORM_MLT
        MLT_param_t mlt_param;

	// just to remvoe compiler warning
	s = NULL;
#endif

	if (unlikely(size > SLUB_MAX_SIZE)) {
		ret = kmalloc_large_node(size, gfpflags, node);
	} else {

		s = get_slab(size, gfpflags);

		if (unlikely(ZERO_OR_NULL_PTR(s)))
			return s;

		ret = slab_alloc(s, gfpflags, node, caller);

		/* Honor the call site pointer we recieved. */
		trace_kmalloc_node(caller, ret, size, s->size, gfpflags, node);
	}

#ifdef CONFIG_SILKWORM_MLT
	if (ret) {
                mlt_param.s = s;
#ifdef CONFIG_SILKWORM_SLUG
		if (ret && (s->flags & SLAB_DFREE) && (slub_debug & SLAB_POISON))
			mlt_param.ptr = (void *)((unsigned long)ret - cache_line_size());
		else
#endif
                mlt_param.ptr = ret;
                MLT_kmalloc_processing(&mlt_param);
	}
#endif
	return ret;
}

#ifdef CONFIG_SLUB_DEBUG
static int count_inuse(struct page *page)
{
	return page->inuse;
}

static int count_total(struct page *page)
{
	return page->objects;
}

static int validate_slab(struct kmem_cache *s, struct page *page,
			 unsigned long *map)
{
	void *p;
	void *addr = page_address(page);

	if (!check_slab(s, page) ||
	    !on_freelist(s, page, NULL))
		return 0;

	/* Now we know that a valid freelist exists */
	bitmap_zero(map, page->objects);

	for_each_free_object(p, s, page->freelist) {
		set_bit(slab_index(p, s, addr), map);
		if (!check_object(s, page, p, 0))
			return 0;
	}

	for_each_object(p, s, addr, page->objects)
	if (!test_bit(slab_index(p, s, addr), map))
		if (!check_object(s, page, p, 1))
			return 0;
	return 1;
}

static void validate_slab_slab(struct kmem_cache *s, struct page *page,
			       unsigned long *map)
{
	if (slab_trylock(page)) {
		if (likely(!PageSlubFrozen(page))) 
			validate_slab(s, page, map);
		slab_unlock(page);
	} else
		printk(KERN_INFO "SLUB %s: Skipped busy slab 0x%p\n",
		       s->name, page);

#ifndef CONFIG_SILKWORM_SLUG
	if (s->flags & DEBUG_DEFAULT_FLAGS) {
		if (!PageSlubDebug(page))
			printk(KERN_ERR "SLUB %s: SlubDebug not set "
			       "on slab 0x%p\n", s->name, page);
	} else {
		if (PageSlubDebug(page))
			printk(KERN_ERR "SLUB %s: SlubDebug set on "
			       "slab 0x%p\n", s->name, page);
	}
#endif
}
  
#ifdef CONFIG_SILKWORM
#define SLUB_MAX_VALIDATE	100000
void validate_slab_list(struct kmem_cache *s, struct kmem_cache_node *n, unsigned long *map, struct list_head *head)
{
	struct page *page;
	unsigned long flags, pos, cnt;
	struct list_head *list;

	/* 
	 * To scan the list safely, we need to hold the list lock
	 * the entire time. But if we hold the lock for too long
	 * the watchdog will fire on large caches. Instead, we'll go 
	 * through 200 at a time, release the lock, and then rescan
	 * the list skipping those we validated already. Some slabs
	 * may not be fully validated this way, but that is better than
	 * crashing or having a watchdog timeout.
	 */
	cnt = 0;
	spin_lock_irqsave(&n->list_lock, flags);
	while (cnt < SLUB_MAX_VALIDATE)
	{
		pos = 0;
		list = head->next;

		/* skip what we already done */
		while ((pos < cnt) && (list != head))
		{
			pos++;
			list = list->next;
		}

		/* continue walking the list and validating */
		while (list != head)
		{
			page = list_entry(list, struct page, lru);
			validate_slab_slab(s, page, map);
			if ((cnt++ % 200) == 0)
			{
				spin_unlock_irqrestore(&n->list_lock, flags);
				kick_watchdog();	/* allows other cpus in now */
				spin_lock_irqsave(&n->list_lock, flags);
				break;
			}
			list = list->next;
		}
		if (list == head)
			break;
	}
	spin_unlock_irqrestore(&n->list_lock, flags);
}

static int validate_slab_node(struct kmem_cache *s,
			      struct kmem_cache_node *n, unsigned long *map)
{
	validate_slab_list(s, n, map, &n->partial);

#ifdef CONFIG_SILKWORM_SLUG
	if (s->flags & SLAB_DFREE) 
		validate_slab_list(s, n, map, &s->free);
#endif
	if (!(s->flags & SLAB_STORE_USER))
		goto out;

	validate_slab_list(s, n, map, &n->full);

	out:
	return 0;
}
#else
static int validate_slab_node(struct kmem_cache *s,
			      struct kmem_cache_node *n, unsigned long *map)
{
	unsigned long count = 0;
	struct page *page;
	unsigned long flags;

	spin_lock_irqsave(&n->list_lock, flags);

	list_for_each_entry(page, &n->partial, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != n->nr_partial)
		printk(KERN_ERR "SLUB %s: %ld partial slabs counted but "
		       "counter=%ld\n", s->name, count, n->nr_partial);

	if (!(s->flags & SLAB_STORE_USER))
		goto out;

	list_for_each_entry(page, &n->full, lru) {
		validate_slab_slab(s, page, map);
		count++;
	}
	if (count != atomic_long_read(&n->nr_slabs))
		printk(KERN_ERR "SLUB: %s %ld slabs counted but "
		       "counter=%ld\n", s->name, count,
		       atomic_long_read(&n->nr_slabs));

	out:
	spin_unlock_irqrestore(&n->list_lock, flags);
	return count;
}
#endif

static long validate_slab_cache(struct kmem_cache *s)
{
	int node;
	unsigned long count = 0;
	unsigned long *map = kmalloc(BITS_TO_LONGS(oo_objects(s->max)) *
				     sizeof(unsigned long), GFP_KERNEL);

	if (!map)
		return -ENOMEM;

	flush_all(s);
	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);

		count += validate_slab_node(s, n, map);
	}
	kfree(map);
	return count;
}

#ifdef SLUB_RESILIENCY_TEST
static void resiliency_test(void)
{
	u8 *p;

	printk(KERN_ERR "SLUB resiliency testing\n");
	printk(KERN_ERR "-----------------------\n");
	printk(KERN_ERR "A. Corruption after allocation\n");

	p = kzalloc(16, GFP_KERNEL);
	p[16] = 0x12;
	printk(KERN_ERR "\n1. kmalloc-16: Clobber Redzone/next pointer"
	       " 0x12->0x%p\n\n", p + 16);

	validate_slab_cache(kmalloc_caches + 4);

	/* Hmmm... The next two are dangerous */
	p = kzalloc(32, GFP_KERNEL);
	p[32 + sizeof(void *)] = 0x34;
	printk(KERN_ERR "\n2. kmalloc-32: Clobber next pointer/next slab"
	       " 0x34 -> -0x%p\n", p);
	printk(KERN_ERR
	       "If allocated object is overwritten then not detectable\n\n");

	validate_slab_cache(kmalloc_caches + 5);
	p = kzalloc(64, GFP_KERNEL);
	p += 64 + (get_cycles() & 0xff) * sizeof(void *);
	*p = 0x56;
	printk(KERN_ERR "\n3. kmalloc-64: corrupting random byte 0x56->0x%p\n",
	       p);
	printk(KERN_ERR
	       "If allocated object is overwritten then not detectable\n\n");
	validate_slab_cache(kmalloc_caches + 6);

	printk(KERN_ERR "\nB. Corruption after free\n");
	p = kzalloc(128, GFP_KERNEL);
	kfree(p);
	*p = 0x78;
	printk(KERN_ERR "1. kmalloc-128: Clobber first word 0x78->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches + 7);

	p = kzalloc(256, GFP_KERNEL);
	kfree(p);
	p[50] = 0x9a;
	printk(KERN_ERR "\n2. kmalloc-256: Clobber 50th byte 0x9a->0x%p\n\n",
	       p);
	validate_slab_cache(kmalloc_caches + 8);

	p = kzalloc(512, GFP_KERNEL);
	kfree(p);
	p[512] = 0xab;
	printk(KERN_ERR "\n3. kmalloc-512: Clobber redzone 0xab->0x%p\n\n", p);
	validate_slab_cache(kmalloc_caches + 9);
}
#else
static void resiliency_test(void) {};
#endif

/*
 * Generate lists of code addresses where slabcache objects are allocated
 * and freed.
 */

struct location {
	unsigned long count;
	unsigned long addr;
	long long sum_time;
	long min_time;
	long max_time;
	long min_pid;
	long max_pid;
	DECLARE_BITMAP(cpus, NR_CPUS);
	nodemask_t nodes;
};

struct loc_track {
	unsigned long max;
	unsigned long count;
	struct location *loc;
};

static void free_loc_track(struct loc_track *t)
{
	if (t->max)
		free_pages((unsigned long)t->loc,
			   get_order(sizeof(struct location) * t->max));
}

static int alloc_loc_track(struct loc_track *t, unsigned long max, gfp_t flags)
{
	struct location *l;
	int order;

	order = get_order(sizeof(struct location) * max);

	l = (void *)__get_free_pages(flags, order);
	if (!l)
		return 0;

	if (t->count) {
		memcpy(l, t->loc, sizeof(struct location) * t->count);
		free_loc_track(t);
	}
	t->max = max;
	t->loc = l;
	return 1;
}

static int add_location(struct loc_track *t, struct kmem_cache *s,
			const struct track *track)
{
	long start, end, pos;
	struct location *l;
	unsigned long caddr;
	unsigned long age = jiffies - track->when;

	start = -1;
	end = t->count;

	for ( ; ; ) {
		pos = start + (end - start + 1) / 2;

		/*
		 * There is nothing at "end". If we end up there
		 * we need to add something to before end.
		 */
		if (pos == end)
			break;

		caddr = t->loc[pos].addr;
		if (track->addr == caddr) {

			l = &t->loc[pos];
			l->count++;
			if (track->when) {
				l->sum_time += age;
				if (age < l->min_time)
					l->min_time = age;
				if (age > l->max_time)
					l->max_time = age;

				if (track->pid < l->min_pid)
					l->min_pid = track->pid;
				if (track->pid > l->max_pid)
					l->max_pid = track->pid;

				cpumask_set_cpu(track->cpu,
						to_cpumask(l->cpus));
			}
			node_set(page_to_nid(virt_to_page(track)), l->nodes);
			return 1;
		}

		if (track->addr < caddr)
			end = pos;
		else
			start = pos;
	}

	/*
	 * Not found. Insert new tracking element.
	 */
	if (t->count >= t->max && !alloc_loc_track(t, 2 * t->max, GFP_ATOMIC))
		return 0;

	l = t->loc + pos;
	if (pos < t->count)
		memmove(l + 1, l,
			(t->count - pos) * sizeof(struct location));
	t->count++;
	l->count = 1;
	l->addr = track->addr;
	l->sum_time = age;
	l->min_time = age;
	l->max_time = age;
	l->min_pid = track->pid;
	l->max_pid = track->pid;
	cpumask_clear(to_cpumask(l->cpus));
	cpumask_set_cpu(track->cpu, to_cpumask(l->cpus));
	nodes_clear(l->nodes);
	node_set(page_to_nid(virt_to_page(track)), l->nodes);
	return 1;
}

static void process_slab(struct loc_track *t, struct kmem_cache *s,
			 struct page *page, enum track_item alloc)
{
	void *addr = page_address(page);
	DECLARE_BITMAP(map, page->objects);
	void *p;

	bitmap_zero(map, page->objects);
	for_each_free_object(p, s, page->freelist)
	set_bit(slab_index(p, s, addr), map);

	for_each_object(p, s, addr, page->objects)
	if (!test_bit(slab_index(p, s, addr), map))
		add_location(t, s, get_track(s, p, alloc));
}

static int list_locations(struct kmem_cache *s, char *buf,
			  enum track_item alloc)
{
	int len = 0;
	unsigned long i;
	struct loc_track t = { 0, 0, NULL};
	int node;

	if (!alloc_loc_track(&t, PAGE_SIZE / sizeof(struct location),
			     GFP_TEMPORARY))
		return sprintf(buf, "Out of memory\n");

	/* Push back cpu slabs */
	flush_all(s);

	for_each_node_state(node, N_NORMAL_MEMORY) {
		struct kmem_cache_node *n = get_node(s, node);
		unsigned long flags;
		struct page *page;

		if (!atomic_long_read(&n->nr_slabs))
			continue;

		spin_lock_irqsave(&n->list_lock, flags);
		list_for_each_entry(page, &n->partial, lru)
		process_slab(&t, s, page, alloc);
		list_for_each_entry(page, &n->full, lru)
		process_slab(&t, s, page, alloc);
		spin_unlock_irqrestore(&n->list_lock, flags);
	}

	for (i = 0; i < t.count; i++) {
		struct location *l = &t.loc[i];

		if (len > PAGE_SIZE - KSYM_SYMBOL_LEN - 100)
			break;
		len += sprintf(buf + len, "%7ld ", l->count);

		if (l->addr)
			len += sprint_symbol(buf + len, (unsigned long)l->addr);
		else
			len += sprintf(buf + len, "<not-available>");

		if (l->sum_time != l->min_time) {
			len += sprintf(buf + len, " age=%ld/%ld/%ld",
				       l->min_time,
				       (long)div_u64(l->sum_time, l->count),
				       l->max_time);
		} else
			len += sprintf(buf + len, " age=%ld",
				       l->min_time);

		if (l->min_pid != l->max_pid)
			len += sprintf(buf + len, " pid=%ld-%ld",
				       l->min_pid, l->max_pid);
		else
			len += sprintf(buf + len, " pid=%ld",
				       l->min_pid);

		if (num_online_cpus() > 1 &&
		    !cpumask_empty(to_cpumask(l->cpus)) &&
		    len < PAGE_SIZE - 60) {
			len += sprintf(buf + len, " cpus=");
			len += cpulist_scnprintf(buf + len, PAGE_SIZE - len - 50,
						 to_cpumask(l->cpus));
		}

		if (nr_online_nodes > 1 && !nodes_empty(l->nodes) &&
		    len < PAGE_SIZE - 60) {
			len += sprintf(buf + len, " nodes=");
			len += nodelist_scnprintf(buf + len, PAGE_SIZE - len - 50,
						  l->nodes);
		}

		len += sprintf(buf + len, "\n");
	}

	free_loc_track(&t);
	if (!t.count)
		len += sprintf(buf, "No data\n");
	return len;
}

enum slab_stat_type {
	SL_ALL,		/* All slabs */
	SL_PARTIAL,	/* Only partially allocated slabs */
	SL_CPU,		/* Only slabs used for cpu caches */
	SL_OBJECTS,	/* Determine allocated objects not slabs */
	SL_TOTAL	/* Determine object capacity not slabs */
};

#define SO_ALL		(1 << SL_ALL)
#define SO_PARTIAL	(1 << SL_PARTIAL)
#define SO_CPU		(1 << SL_CPU)
#define SO_OBJECTS	(1 << SL_OBJECTS)
#define SO_TOTAL	(1 << SL_TOTAL)

static ssize_t show_slab_objects(struct kmem_cache *s,
				 char *buf, unsigned long flags)
{
	unsigned long total = 0;
	int node;
	int x;
	unsigned long *nodes;
	unsigned long *per_cpu;

	nodes = kzalloc(2 * sizeof(unsigned long) * nr_node_ids, GFP_KERNEL);
	if (!nodes)
		return -ENOMEM;
	per_cpu = nodes + nr_node_ids;

	if (flags & SO_CPU) {
		int cpu;

		for_each_possible_cpu(cpu) {
			struct kmem_cache_cpu *c = per_cpu_ptr(s->cpu_slab, cpu);

			if (!c || c->node < 0)
				continue;

			if (c->page) {
				if (flags & SO_TOTAL)
					x = c->page->objects;
				else if (flags & SO_OBJECTS)
					x = c->page->inuse;
				else
					x = 1;

				total += x;
				nodes[c->node] += x;
			}
			per_cpu[c->node]++;
		}
	}

	if (flags & SO_ALL) {
		for_each_node_state(node, N_NORMAL_MEMORY) {
			struct kmem_cache_node *n = get_node(s, node);

			if (flags & SO_TOTAL)
				x = atomic_long_read(&n->total_objects);
			else if (flags & SO_OBJECTS)
				x = atomic_long_read(&n->total_objects) -
				    count_partial(n, count_free);

			else
				x = atomic_long_read(&n->nr_slabs);
			total += x;
			nodes[node] += x;
		}

	} else if (flags & SO_PARTIAL) {
		for_each_node_state(node, N_NORMAL_MEMORY) {
			struct kmem_cache_node *n = get_node(s, node);

			if (flags & SO_TOTAL)
				x = count_partial(n, count_total);
			else if (flags & SO_OBJECTS)
				x = count_partial(n, count_inuse);
			else
				x = n->nr_partial;
			total += x;
			nodes[node] += x;
		}
	}
	x = sprintf(buf, "%lu", total);
#ifdef CONFIG_NUMA
	for_each_node_state(node, N_NORMAL_MEMORY)
	if (nodes[node])
		x += sprintf(buf + x, " N%d=%lu",
			     node, nodes[node]);
#endif
	kfree(nodes);
	return x + sprintf(buf + x, "\n");
}

static int any_slab_objects(struct kmem_cache *s)
{
	int node;

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		if (atomic_long_read(&n->total_objects))
			return 1;
	}
	return 0;
}

#define to_slab_attr(n) container_of(n, struct slab_attribute, attr)
#define to_slab(n) container_of(n, struct kmem_cache, kobj);

struct slab_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kmem_cache *s, char *buf);
	ssize_t (*store)(struct kmem_cache *s, const char *x, size_t count);
};

#define SLAB_ATTR_RO(_name) \
	static struct slab_attribute _name##_attr = __ATTR_RO(_name)

#define SLAB_ATTR(_name) \
	static struct slab_attribute _name##_attr =  \
	__ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t slab_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->size);
}
SLAB_ATTR_RO(slab_size);

static ssize_t align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->align);
}
SLAB_ATTR_RO(align);

static ssize_t object_size_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->objsize);
}
SLAB_ATTR_RO(object_size);

static ssize_t objs_per_slab_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", oo_objects(s->oo));
}
SLAB_ATTR_RO(objs_per_slab);

static ssize_t order_store(struct kmem_cache *s,
			   const char *buf, size_t length)
{
	unsigned long order;
	int err;

	err = strict_strtoul(buf, 10, &order);
	if (err)
		return err;

	if (order > slub_max_order || order < slub_min_order)
		return -EINVAL;

	calculate_sizes(s, order);
	return length;
}

static ssize_t order_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", oo_order(s->oo));
}
SLAB_ATTR(order);

static ssize_t min_partial_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", s->min_partial);
}

static ssize_t min_partial_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long min;
	int err;

	err = strict_strtoul(buf, 10, &min);
	if (err)
		return err;

	set_min_partial(s, min);
	return length;
}
SLAB_ATTR(min_partial);

#ifdef CONFIG_SILKWORM_SLUG
static ssize_t dfree_min_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", s->dfree_min);
}

static ssize_t dfree_min_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long val;
	int err;

	err = strict_strtoul(buf, 10, &val);
	if (err)
		return err;

	s->dfree_min = val;
	return length;
}
SLAB_ATTR(dfree_min);

#ifdef CONFIG_ESLUB_DEBUG   
static ssize_t eslub_total_mem_show(struct kmem_cache *s, char *buf)
{
    return sprintf(buf, "%lu %lu\n", atomic_long_read(&s->eslub_total_mem), atomic_long_read(&eslub_total));
}
SLAB_ATTR_RO(eslub_total_mem);
    
static ssize_t eslub_neighs_show(struct kmem_cache *s, char *buf)
{
    return sprintf(buf, "%d\n", eslub_num_neighs);
}
    
static ssize_t eslub_neighs_store(struct kmem_cache *s, const char *buf,
				      size_t length)
{
    unsigned long val;
    int err;
    
    err = strict_strtoul(buf, 10, &val);
    if (err)
	return err;
    
    eslub_num_neighs = val;
    return length;
}
SLAB_ATTR(eslub_neighs);
    
static ssize_t eslub_contexts_show(struct kmem_cache *s, char *buf)
{
    return sprintf(buf, "%d\n", eslub_num_ctx);
}
    
static ssize_t eslub_contexts_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
    unsigned long val;
    int err;
    
    err = strict_strtoul(buf, 10, &val);
    if (err)
	return err;
    
    eslub_num_ctx = val;
    calculate_sizes(s, -1);
    return length;
}
    

SLAB_ATTR(eslub_contexts);
    
#endif

static ssize_t max_objects_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", s->max_objects);
}

static ssize_t max_objects_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long val;
	int err;

	err = strict_strtoul(buf, 10, &val);
	if (err)
		return err;

	s->max_objects = val;
	return length;
}
SLAB_ATTR(max_objects);

static ssize_t tmp_partial_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", atomic_long_read(&s->tmp_partial));
}

static ssize_t tmp_partial_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long val;
	int err;

	err = strict_strtoul(buf, 10, &val);
	if (err)
		return err;

	atomic_long_set(&s->tmp_partial, val);
	return length;
}
SLAB_ATTR(tmp_partial);

static ssize_t tmp_partial_age_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%lu\n", s->tmp_partial_age);
}

static ssize_t tmp_partial_age_store(struct kmem_cache *s, const char *buf,
				 size_t length)
{
	unsigned long val;
	int err;

	err = strict_strtoul(buf, 10, &val);
	if (err)
		return err;

	s->tmp_partial_age = val;
	return length;
}
SLAB_ATTR(tmp_partial_age);
#endif

static ssize_t ctor_show(struct kmem_cache *s, char *buf)
{
	if (s->ctor) {
		int n = sprint_symbol(buf, (unsigned long)s->ctor);

		return n + sprintf(buf + n, "\n");
	}
	return 0;
}
SLAB_ATTR_RO(ctor);

static ssize_t aliases_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->refcount - 1);
}
SLAB_ATTR_RO(aliases);

static ssize_t slabs_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL);
}
SLAB_ATTR_RO(slabs);

static ssize_t partial_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_PARTIAL);
}
SLAB_ATTR_RO(partial);

static ssize_t cpu_slabs_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_CPU);
}
SLAB_ATTR_RO(cpu_slabs);

static ssize_t objects_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL|SO_OBJECTS);
}
SLAB_ATTR_RO(objects);

static ssize_t objects_partial_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_PARTIAL|SO_OBJECTS);
}
SLAB_ATTR_RO(objects_partial);

static ssize_t total_objects_show(struct kmem_cache *s, char *buf)
{
	return show_slab_objects(s, buf, SO_ALL|SO_TOTAL);
}
SLAB_ATTR_RO(total_objects);

static ssize_t sanity_checks_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DEBUG_FREE));
}

static ssize_t sanity_checks_store(struct kmem_cache *s,
				   const char *buf, size_t length)
{
	s->flags &= ~SLAB_DEBUG_FREE;
	if (buf[0] == '1')
		s->flags |= SLAB_DEBUG_FREE;
	return length;
}
SLAB_ATTR(sanity_checks);

static ssize_t trace_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_TRACE));
}

static ssize_t trace_store(struct kmem_cache *s, const char *buf,
			   size_t length)
{
	s->flags &= ~SLAB_TRACE;
	if (buf[0] == '1')
		s->flags |= SLAB_TRACE;
	return length;
}
SLAB_ATTR(trace);

#ifdef CONFIG_FAILSLAB
static ssize_t failslab_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_FAILSLAB));
}

static ssize_t failslab_store(struct kmem_cache *s, const char *buf,
			      size_t length)
{
	s->flags &= ~SLAB_FAILSLAB;
	if (buf[0] == '1')
		s->flags |= SLAB_FAILSLAB;
	return length;
}
SLAB_ATTR(failslab);
#endif

static ssize_t reclaim_account_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RECLAIM_ACCOUNT));
}

static ssize_t reclaim_account_store(struct kmem_cache *s,
				     const char *buf, size_t length)
{
	s->flags &= ~SLAB_RECLAIM_ACCOUNT;
	if (buf[0] == '1')
		s->flags |= SLAB_RECLAIM_ACCOUNT;
	return length;
}
SLAB_ATTR(reclaim_account);

static ssize_t hwcache_align_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_HWCACHE_ALIGN));
}
SLAB_ATTR_RO(hwcache_align);

#ifdef CONFIG_ZONE_DMA
static ssize_t cache_dma_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_CACHE_DMA));
}
SLAB_ATTR_RO(cache_dma);
#endif

static ssize_t destroy_by_rcu_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_DESTROY_BY_RCU));
}
SLAB_ATTR_RO(destroy_by_rcu);

static ssize_t red_zone_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_RED_ZONE));
}

static ssize_t red_zone_store(struct kmem_cache *s,
			      const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_RED_ZONE;
	if (buf[0] == '1')
		s->flags |= SLAB_RED_ZONE;
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(red_zone);

static ssize_t poison_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_POISON));
}

static ssize_t poison_store(struct kmem_cache *s,
			    const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_POISON;
	if (buf[0] == '1')
		s->flags |= SLAB_POISON;
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(poison);

static ssize_t store_user_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", !!(s->flags & SLAB_STORE_USER));
}

static ssize_t store_user_store(struct kmem_cache *s,
				const char *buf, size_t length)
{
	if (any_slab_objects(s))
		return -EBUSY;

	s->flags &= ~SLAB_STORE_USER;
	if (buf[0] == '1')
		s->flags |= SLAB_STORE_USER;
	calculate_sizes(s, -1);
	return length;
}
SLAB_ATTR(store_user);

static ssize_t validate_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t validate_store(struct kmem_cache *s,
			      const char *buf, size_t length)
{
	int ret = -EINVAL;

	if (buf[0] == '1') {
		ret = validate_slab_cache(s);
		if (ret >= 0)
			ret = length;
	}
	return ret;
}
SLAB_ATTR(validate);

static ssize_t shrink_show(struct kmem_cache *s, char *buf)
{
	return 0;
}

static ssize_t shrink_store(struct kmem_cache *s,
			    const char *buf, size_t length)
{
	if (buf[0] == '1') {
		int rc = kmem_cache_shrink(s);

		if (rc)
			return rc;
	} else
		return -EINVAL;
	return length;
}
SLAB_ATTR(shrink);

static ssize_t alloc_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_ALLOC);
}
SLAB_ATTR_RO(alloc_calls);

static ssize_t free_calls_show(struct kmem_cache *s, char *buf)
{
	if (!(s->flags & SLAB_STORE_USER))
		return -ENOSYS;
	return list_locations(s, buf, TRACK_FREE);
}
SLAB_ATTR_RO(free_calls);

#ifdef CONFIG_NUMA
static ssize_t remote_node_defrag_ratio_show(struct kmem_cache *s, char *buf)
{
	return sprintf(buf, "%d\n", s->remote_node_defrag_ratio / 10);
}

static ssize_t remote_node_defrag_ratio_store(struct kmem_cache *s,
					      const char *buf, size_t length)
{
	unsigned long ratio;
	int err;

	err = strict_strtoul(buf, 10, &ratio);
	if (err)
		return err;

	if (ratio <= 100)
		s->remote_node_defrag_ratio = ratio * 10;

	return length;
}
SLAB_ATTR(remote_node_defrag_ratio);
#endif

#ifdef CONFIG_SLUB_STATS
static int show_stat(struct kmem_cache *s, char *buf, enum stat_item si)
{
	unsigned long sum  = 0;
	int cpu;
	int len;
	int *data = kmalloc(nr_cpu_ids * sizeof(int), GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	for_each_online_cpu(cpu) {
		unsigned x = per_cpu_ptr(s->cpu_slab, cpu)->stat[si];

		data[cpu] = x;
		sum += x;
	}

	len = sprintf(buf, "%lu", sum);

#ifdef CONFIG_SMP
	for_each_online_cpu(cpu) {
		if (data[cpu] && len < PAGE_SIZE - 20)
			len += sprintf(buf + len, " C%d=%u", cpu, data[cpu]);
	}
#endif
	kfree(data);
	return len + sprintf(buf + len, "\n");
}

static void clear_stat(struct kmem_cache *s, enum stat_item si)
{
	int cpu;

	for_each_online_cpu(cpu)
	per_cpu_ptr(s->cpu_slab, cpu)->stat[si] = 0;
}

#define STAT_ATTR(si, text) 					\
static ssize_t text##_show(struct kmem_cache *s, char *buf)	\
{								\
	return show_stat(s, buf, si);				\
}								\
static ssize_t text##_store(struct kmem_cache *s,		\
				const char *buf, size_t length)	\
{								\
	if (buf[0] != '0')					\
		return -EINVAL;					\
	clear_stat(s, si);					\
	return length;						\
}								\
SLAB_ATTR(text);						\

STAT_ATTR(ALLOC_FASTPATH, alloc_fastpath);
STAT_ATTR(ALLOC_SLOWPATH, alloc_slowpath);
STAT_ATTR(FREE_FASTPATH, free_fastpath);
STAT_ATTR(FREE_SLOWPATH, free_slowpath);
STAT_ATTR(FREE_FROZEN, free_frozen);
STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
STAT_ATTR(ALLOC_SLAB, alloc_slab);
STAT_ATTR(ALLOC_REFILL, alloc_refill);
STAT_ATTR(FREE_SLAB, free_slab);
STAT_ATTR(CPUSLAB_FLUSH, cpuslab_flush);
STAT_ATTR(DEACTIVATE_FULL, deactivate_full);
STAT_ATTR(DEACTIVATE_EMPTY, deactivate_empty);
STAT_ATTR(DEACTIVATE_TO_HEAD, deactivate_to_head);
STAT_ATTR(DEACTIVATE_TO_TAIL, deactivate_to_tail);
STAT_ATTR(DEACTIVATE_REMOTE_FREES, deactivate_remote_frees);
STAT_ATTR(ORDER_FALLBACK, order_fallback);
#endif

static struct attribute *slab_attrs[] = {
	&slab_size_attr.attr,
	&object_size_attr.attr,
	&objs_per_slab_attr.attr,
	&order_attr.attr,
	&min_partial_attr.attr,
#ifdef CONFIG_SILKWORM_SLUG
	&dfree_min_attr.attr,
	&max_objects_attr.attr,
	&tmp_partial_attr.attr,
	&tmp_partial_age_attr.attr,
#endif
	&objects_attr.attr,
	&objects_partial_attr.attr,
	&total_objects_attr.attr,
	&slabs_attr.attr,
#ifdef CONFIG_ESLUB_DEBUG   
	&eslub_total_mem_attr.attr,
    	&eslub_neighs_attr.attr,
    	&eslub_contexts_attr.attr,
#endif   
	&partial_attr.attr,
	&cpu_slabs_attr.attr,
	&ctor_attr.attr,
	&aliases_attr.attr,
	&align_attr.attr,
	&sanity_checks_attr.attr,
	&trace_attr.attr,
	&hwcache_align_attr.attr,
	&reclaim_account_attr.attr,
	&destroy_by_rcu_attr.attr,
	&red_zone_attr.attr,
	&poison_attr.attr,
	&store_user_attr.attr,
	&validate_attr.attr,
	&shrink_attr.attr,
	&alloc_calls_attr.attr,
	&free_calls_attr.attr,
#ifdef CONFIG_ZONE_DMA
	&cache_dma_attr.attr,
#endif
#ifdef CONFIG_NUMA
	&remote_node_defrag_ratio_attr.attr,
#endif
#ifdef CONFIG_SLUB_STATS
	&alloc_fastpath_attr.attr,
	&alloc_slowpath_attr.attr,
	&free_fastpath_attr.attr,
	&free_slowpath_attr.attr,
	&free_frozen_attr.attr,
	&free_add_partial_attr.attr,
	&free_remove_partial_attr.attr,
	&alloc_from_partial_attr.attr,
	&alloc_slab_attr.attr,
	&alloc_refill_attr.attr,
	&free_slab_attr.attr,
	&cpuslab_flush_attr.attr,
	&deactivate_full_attr.attr,
	&deactivate_empty_attr.attr,
	&deactivate_to_head_attr.attr,
	&deactivate_to_tail_attr.attr,
	&deactivate_remote_frees_attr.attr,
	&order_fallback_attr.attr,
#endif
#ifdef CONFIG_FAILSLAB
	&failslab_attr.attr,
#endif

	NULL
};

static struct attribute_group slab_attr_group = {
	.attrs = slab_attrs,
};

static ssize_t slab_attr_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->show)
		return -EIO;

	err = attribute->show(s, buf);

	return err;
}

static ssize_t slab_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	struct slab_attribute *attribute;
	struct kmem_cache *s;
	int err;

	attribute = to_slab_attr(attr);
	s = to_slab(kobj);

	if (!attribute->store)
		return -EIO;

	err = attribute->store(s, buf, len);

	return err;
}

static void kmem_cache_release(struct kobject *kobj)
{
	struct kmem_cache *s = to_slab(kobj);

	kfree(s);
}

static const struct sysfs_ops slab_sysfs_ops = {
	.show = slab_attr_show,
	.store = slab_attr_store,
};

static struct kobj_type slab_ktype = {
    .sysfs_ops = &slab_sysfs_ops,
    .release = kmem_cache_release
};

static int uevent_filter(struct kset *kset, struct kobject *kobj)
{
	struct kobj_type *ktype = get_ktype(kobj);

	if (ktype == &slab_ktype)
		return 1;
	return 0;
}

static const struct kset_uevent_ops slab_uevent_ops = {
	.filter = uevent_filter,
};

static struct kset *slab_kset;

#define ID_STR_LENGTH 64

/* Create a unique string id for a slab cache:
 *
 * Format	:[flags-]size
 */
static char *create_unique_id(struct kmem_cache *s)
{
	char *name = kmalloc(ID_STR_LENGTH, GFP_KERNEL);
	char *p = name;

	BUG_ON(!name);

	*p++ = ':';
	/*
	 * First flags affecting slabcache operations. We will only
	 * get here for aliasable slabs so we do not need to support
	 * too many flags. The flags here must cover all flags that
	 * are matched during merging to guarantee that the id is
	 * unique.
	 */
	if (s->flags & SLAB_CACHE_DMA)
		*p++ = 'd';
	if (s->flags & SLAB_RECLAIM_ACCOUNT)
		*p++ = 'a';
	if (s->flags & SLAB_DEBUG_FREE)
		*p++ = 'F';
	if (!(s->flags & SLAB_NOTRACK))
		*p++ = 't';
	if (p != name + 1)
		*p++ = '-';
	p += sprintf(p, "%07d", s->size);
	BUG_ON(p > name + ID_STR_LENGTH - 1);
	return name;
}

static int sysfs_slab_add(struct kmem_cache *s)
{
	int err;
	const char *name;
	int unmergeable;

	if (slab_state < SYSFS)
		/* Defer until later */
		return 0;

	unmergeable = slab_unmergeable(s);
	if (unmergeable) {
		/*
		 * Slabcache can never be merged so we can use the name proper.
		 * This is typically the case for debug situations. In that
		 * case we can catch duplicate names easily.
		 */
		sysfs_remove_link(&slab_kset->kobj, s->name);
		name = s->name;
	} else {
		/*
		 * Create a unique name for the slab as a target
		 * for the symlinks.
		 */
		name = create_unique_id(s);
	}

	s->kobj.kset = slab_kset;
	err = kobject_init_and_add(&s->kobj, &slab_ktype, NULL, name);
	if (err) {
		kobject_put(&s->kobj);
		return err;
	}

	err = sysfs_create_group(&s->kobj, &slab_attr_group);
	if (err) {
		kobject_del(&s->kobj);
		kobject_put(&s->kobj);
		return err;
	}
	kobject_uevent(&s->kobj, KOBJ_ADD);
	if (!unmergeable) {
		/* Setup first alias */
		sysfs_slab_alias(s, s->name);
		kfree(name);
	}
	return 0;
}

static void sysfs_slab_remove(struct kmem_cache *s)
{
	kobject_uevent(&s->kobj, KOBJ_REMOVE);
	kobject_del(&s->kobj);
	kobject_put(&s->kobj);
}

/*
 * Need to buffer aliases during bootup until sysfs becomes
 * available lest we lose that information.
 */
struct saved_alias {
	struct kmem_cache *s;
	const char *name;
	struct saved_alias *next;
};

static struct saved_alias *alias_list;

static int sysfs_slab_alias(struct kmem_cache *s, const char *name)
{
	struct saved_alias *al;

	if (slab_state == SYSFS) {
		/*
		 * If we have a leftover link then remove it.
		 */
		sysfs_remove_link(&slab_kset->kobj, name);
		return sysfs_create_link(&slab_kset->kobj, &s->kobj, name);
	}

	al = kmalloc(sizeof(struct saved_alias), GFP_KERNEL);
	if (!al)
		return -ENOMEM;

	al->s = s;
	al->name = name;
	al->next = alias_list;
	alias_list = al;
	return 0;
}

static int __init slab_sysfs_init(void)
{
	struct kmem_cache *s;
	int err;

	slab_kset = kset_create_and_add("slab", &slab_uevent_ops, kernel_kobj);
	if (!slab_kset) {
		printk(KERN_ERR "Cannot register slab subsystem.\n");
		return -ENOSYS;
	}

	slab_state = SYSFS;

	list_for_each_entry(s, &slab_caches, list) {
		err = sysfs_slab_add(s);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab %s"
			       " to sysfs\n", s->name);
	}

	while (alias_list) {
		struct saved_alias *al = alias_list;

		alias_list = alias_list->next;
		err = sysfs_slab_alias(al->s, al->name);
		if (err)
			printk(KERN_ERR "SLUB: Unable to add boot slab alias"
			       " %s to sysfs\n", s->name);
		kfree(al);
	}

	resiliency_test();
	return 0;
}

__initcall(slab_sysfs_init);
#endif

/*
 * The /proc/slabinfo ABI
 */
#ifdef CONFIG_SLABINFO
static void print_slabinfo_header(struct seq_file *m)
{
	seq_puts(m, "slabinfo - version: 2.1\n");
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
#ifdef CONFIG_SILKWORM_SLUG
	seq_puts(m, " : slabdata <active_slabs> <sharedavail> <nr_free> <max objs> <tmp_partial>");
#else
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	down_read(&slub_lock);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&slab_caches, *pos);
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &slab_caches, pos);
}

static void s_stop(struct seq_file *m, void *p)
{
	up_read(&slub_lock);
}

static int s_show(struct seq_file *m, void *p)
{
	unsigned long nr_partials = 0;
	unsigned long nr_slabs = 0;
	unsigned long nr_inuse = 0;
	unsigned long nr_objs = 0;
	unsigned long nr_free = 0;
	struct kmem_cache *s;
	int node;
#ifdef CONFIG_SILKWORM_SLUG
	unsigned long tmp_partial;
#endif

	s = list_entry(p, struct kmem_cache, list);

	for_each_online_node(node) {
		struct kmem_cache_node *n = get_node(s, node);

		if (!n)
			continue;

		nr_partials += n->nr_partial;
		nr_slabs += atomic_long_read(&n->nr_slabs);
		nr_objs += atomic_long_read(&n->total_objects);
		nr_free += count_partial(n, count_free);
	}

	nr_inuse = nr_objs - nr_free;
#ifdef CONFIG_SILKWORM_SLUG
	tmp_partial = atomic_long_read(&s->tmp_partial);
#endif

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d", s->name, nr_inuse,
		   nr_objs, s->size, oo_objects(s->oo),
		   (1 << oo_order(s->oo)));
	seq_printf(m, " : tunables %4u %4u %4u", 0, 0, 0);
#ifdef CONFIG_SILKWORM_SLUG
	seq_printf(m, " : slabdata %6lu %6lu %6lu %6lu %6lu", nr_slabs, 0UL, s->nr_free, s->max_objects, tmp_partial);
#else
	seq_printf(m, " : slabdata %6lu %6lu %6lu", nr_slabs, nr_slabs, 0UL);
#endif
	seq_putc(m, '\n');
	return 0;
}

static const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show,
};

static int slabinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &slabinfo_op);
}

static const struct file_operations proc_slabinfo_operations = {
	.open       = slabinfo_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = seq_release,
};

static int __init slab_proc_init(void)
{
	proc_create("slabinfo", S_IRUGO, NULL, &proc_slabinfo_operations);
	return 0;
}
module_init(slab_proc_init);
#endif /* CONFIG_SLABINFO */
