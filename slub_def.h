#ifndef _LINUX_SLUB_DEF_H
#define _LINUX_SLUB_DEF_H

/*
 * SLUB : A Slab allocator without object queues.
 *
 * (C) 2007 SGI, Christoph Lameter
 */
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/workqueue.h>
#include <linux/kobject.h>
#include <linux/kmemtrace.h>
#include <linux/kmemleak.h>
#ifdef CONFIG_SILKWORM_MLT
#include <linux/mlt_inc.h>
#endif
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
#include <linux/mlt_kl_inc.h>
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
extern int console_mlt_vm;

#define MLT_VM_CONSOLE_SIZE_BASIC       0x00000400UL  
#define MLT_VM_CONSOLE_SIZE_DETAILED    0x00000800UL 
#define MLT_VM_CONSOLE_CNT_BASIC        0x00002000UL
#define MLT_VM_CONSOLE_CNT_DETAILED     0x00004000UL  
#define MLT_VM_CONSOLE_STATS_BASIC      0x00010000UL 
#define MLT_VM_CONSOLE_STATS_DETAILED   0x00040000UL

#endif

#define CONFIG_SILKWORM_SLUG	1	/* enable deferred free */

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
extern int mlt_kl_enabled;
extern int console_mlt_kl;

#define MLT_KL_CONSOLE_SIZE_BASIC       0x00000400UL  
#define MLT_KL_CONSOLE_SIZE_DETAILED    0x00000800UL 
#define MLT_KL_CONSOLE_CNT_BASIC        0x00002000UL
#define MLT_KL_CONSOLE_CNT_DETAILED     0x00004000UL  
#define MLT_KL_CONSOLE_STATS_BASIC      0x00010000UL 
#define MLT_KL_CONSOLE_STATS_DETAILED   0x00040000UL

#endif

extern int no_oom_tmpdir, no_oom_mem, no_oom_task;

#ifdef CONFIG_SILKWORM_MLT
extern int mlt_km_enabled;
extern int console_mlt;

#define MLT_CONSOLE_SIZE_BASIC       0x00000400UL  
#define MLT_CONSOLE_SIZE_DETAILED    0x00000800UL 
#define MLT_CONSOLE_CNT_BASIC        0x00002000UL
#define MLT_CONSOLE_CNT_DETAILED     0x00004000UL  
#define MLT_CONSOLE_STATS_BASIC      0x00010000UL 
#define MLT_CONSOLE_STATS_DETAILED   0x00040000UL

#endif

enum stat_item {
	ALLOC_FASTPATH,		/* Allocation from cpu slab */
	ALLOC_SLOWPATH,		/* Allocation by getting a new cpu slab */
	FREE_FASTPATH,		/* Free to cpu slub */
	FREE_SLOWPATH,		/* Freeing not to cpu slab */
	FREE_FROZEN,		/* Freeing to frozen slab */
	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from partial list */
	ALLOC_SLAB,		/* Cpu slab acquired from page allocator */
	ALLOC_REFILL,		/* Refill cpu slab from slab freelist */
	FREE_SLAB,		/* Slab freed to the page allocator */
	CPUSLAB_FLUSH,		/* Abandoning of the cpu slab */
	DEACTIVATE_FULL,	/* Cpu slab was full when deactivated */
	DEACTIVATE_EMPTY,	/* Cpu slab was empty when deactivated */
	DEACTIVATE_TO_HEAD,	/* Cpu slab was moved to the head of partials */
	DEACTIVATE_TO_TAIL,	/* Cpu slab was moved to the tail of partials */
	DEACTIVATE_REMOTE_FREES,/* Slab contained remotely freed objects */
	ORDER_FALLBACK,		/* Number of times fallback was necessary */
	NR_SLUB_STAT_ITEMS};

struct kmem_cache_cpu {
	void **freelist;	/* Pointer to first free per cpu object */
	struct page *page;	/* The slab from which we are allocating */
	int node;		/* The node of the page (or -1 for debug) */
#ifdef CONFIG_SLUB_STATS
	unsigned stat[NR_SLUB_STAT_ITEMS];
#endif
};

struct kmem_cache_node {
	spinlock_t list_lock;	/* Protect partial list and nr_partial */
	unsigned long nr_partial;
	struct list_head partial;
#ifdef CONFIG_SLUB_DEBUG
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
#endif
};

/*
 * Word size structure that can be atomically updated or read and that
 * contains both the order and the number of objects that a slab of the
 * given order would contain.
 */
struct kmem_cache_order_objects {
	unsigned long x;
};

/*
 * Slab cache management.
 */
struct kmem_cache {
	struct kmem_cache_cpu *cpu_slab;
	/* Used for retriving partial slabs etc */
	unsigned long flags;
	int size;		/* The size of an object including meta data */
	int objsize;		/* The size of an object without meta data */
	int offset;		/* Free pointer offset. */
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	struct kmem_cache_order_objects max;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	int refcount;		/* Refcount for slab cache destroy */
	void (*ctor) (void *);
	int inuse;		/* Offset to metadata */
	int align;		/* Alignment */
	unsigned long min_partial;
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SLUB_DEBUG
	struct kobject kobj;	/* For sysfs */
#ifdef CONFIG_ESLUB_DEBUG
	int xtrack;
	atomic_long_t eslub_total_mem;
#endif
#endif



#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	int remote_node_defrag_ratio;
	struct kmem_cache_node *node[MAX_NUMNODES];
#else
	/* Avoid an extra cache line for UP */
	struct kmem_cache_node local_node;
#endif

#ifdef CONFIG_SILKWORM_SLUG
	spinlock_t free_lock;		/* Protect free list and nr_free */
	unsigned long nr_free;		/* count of slabs on the deferred slab free list */
	struct list_head free;		/* deferred slab free list */
	unsigned long dfree_min;	/* deferred free min partial */
	unsigned long max_objects; 	/* most number of objects in cache */
	atomic_long_t tmp_partial;	/* temporary min partial level to hold when number of slabs increase */
	unsigned long tmp_partial_age;	/* jiffy of last slab increase */
#endif
};

#ifdef CONFIG_SILKWORM_MLT
extern int mlt_enabled;
extern atomic_t kmalloc_large_cnt;
struct kmem_cache *get_cachep (size_t size, gfp_t flags);
static __always_inline MLT_book_keeping_info_t *get_mlt_offset(struct kmem_cache *s, void *object);
static __always_inline void init_mlt_metadata(MLT_book_keeping_info_t *);
#define obj_size_api(cachep) ((cachep)->objsize)
#endif

#ifdef CONFIG_SILKWORM
int kmem_cache_objects(struct kmem_cache *s);
#endif

/*
 * Kmalloc subsystem.
 */
#if defined(ARCH_KMALLOC_MINALIGN) && ARCH_KMALLOC_MINALIGN > 8
#define KMALLOC_MIN_SIZE ARCH_KMALLOC_MINALIGN
#else
#define KMALLOC_MIN_SIZE 8
#endif

#define KMALLOC_SHIFT_LOW ilog2(KMALLOC_MIN_SIZE)

/*
 * Maximum kmalloc object size handled by SLUB. Larger object allocations
 * are passed through to the page allocator. The page allocator "fastpath"
 * is relatively slow so we need this value sufficiently high so that
 * performance critical objects are allocated through the SLUB fastpath.
 *
 * This should be dropped to PAGE_SIZE / 2 once the page allocator
 * "fastpath" becomes competitive with the slab allocator fastpaths.
 */
#ifdef CONFIG_SILKWORM_SLUG
/* add 16K kmalloc cache */
//#define SLUB_MAX_SIZE (4 * PAGE_SIZE)
//#define SLUB_PAGE_SHIFT (PAGE_SHIFT + 3)
#define SLUB_MAX_SIZE (2 * PAGE_SIZE)
#define SLUB_PAGE_SHIFT (PAGE_SHIFT + 2)
#else
#define SLUB_MAX_SIZE (2 * PAGE_SIZE)
#define SLUB_PAGE_SHIFT (PAGE_SHIFT + 2)
#endif

#ifdef CONFIG_ZONE_DMA
#define SLUB_DMA __GFP_DMA
/* Reserve extra caches for potential DMA use */
#define KMALLOC_CACHES (2 * SLUB_PAGE_SHIFT)
#else
/* Disable DMA functionality */
#define SLUB_DMA (__force gfp_t)0
#define KMALLOC_CACHES SLUB_PAGE_SHIFT
#endif

/*
 * We keep the general caches in an array of slab caches that are used for
 * 2^x bytes of allocations.
 */
extern struct kmem_cache kmalloc_caches[KMALLOC_CACHES];

/*
 * Sorry that the following has to be that ugly but some versions of GCC
 * have trouble with constant propagation and loops.
 */
static __always_inline int kmalloc_index (size_t size)
{
	if (!size)
		return 0;

	if (size <= KMALLOC_MIN_SIZE)
		return KMALLOC_SHIFT_LOW;

	if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
		return 1;
	if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
		return 2;
	if (size <= 	   8) return 3;
	if (size <= 	  16) return 4;
	if (size <= 	  32) return 5;
	if (size <= 	  64) return 6;
	if (size <= 	 128) return 7;
	if (size <= 	 256) return 8;
	if (size <= 	 512) return 9;
	if (size <= 	1024) return 10;
	if (size <= 2 * 1024) return 11;
	if (size <= 4 * 1024) return 12;
/*
 * The following is only needed to support architectures with a larger page
 * size than 4k.
 */
	if (size <= 8   * 1024) return 13;
	if (size <= 16  * 1024) return 14;
	if (size <= 32  * 1024)	return 15;
	if (size <= 64  * 1024)	return 16;
	if (size <= 128 * 1024) return 17;
	if (size <= 256 * 1024)	return 18;
	if (size <= 512 * 1024)	return 19;
	if (size <= 1024 * 1024) return 20;
	if (size <= 2 * 1024 * 1024) return 21;
	return -1;

/*
 * What we really wanted to do and cannot do because of compiler issues is:
 *	int i;
 *	for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++)
 *		if (size <= (1 << i))
 *			return i;
 */
}

/*
 * Find the slab cache for a given combination of allocation flags and size.
 *
 * This ought to end up with a global pointer to the right cache
 * in kmalloc_caches.
 */
static __always_inline struct kmem_cache *kmalloc_slab (size_t size)
{
	int index = kmalloc_index (size);

	if (index == 0)
		return NULL;

	return &kmalloc_caches[index];
}

void *kmem_cache_alloc (struct kmem_cache *, gfp_t);
void *__kmalloc (size_t size, gfp_t flags);

#ifdef CONFIG_SILKWORM_SLUG
void *kmem_cache_alloc_brcd (struct kmem_cache *s, gfp_t);
#endif

#ifdef CONFIG_TRACING
extern void *kmem_cache_alloc_notrace (struct kmem_cache *s, gfp_t gfpflags);
#else
static __always_inline void *
kmem_cache_alloc_notrace (struct kmem_cache *s, gfp_t gfpflags)
{
	return kmem_cache_alloc (s, gfpflags);
}
#endif

static __always_inline void *kmalloc_large (size_t size, gfp_t flags)
{
	unsigned int order = get_order (size);
	void *ret = (void *) __get_free_pages (flags | __GFP_COMP, order);

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
	if (mlt_kl_enabled)
	{
	    MLT_KL_param_t mlt_kl_param;

	    memset(&mlt_kl_param, 0, sizeof(MLT_KL_param_t));
	    mlt_kl_param.alloc_ptr = ret;
	    mlt_kl_param.alloc_size = PAGE_SIZE << order;
	    MLT_KL_alloc_processing(&mlt_kl_param);
	}
#endif

#ifdef CONFIG_SILKWORM_MLT
	atomic_inc(&kmalloc_large_cnt);
#endif

	kmemleak_alloc (ret, size, 1, flags);
	trace_kmalloc (_THIS_IP_, ret, size, PAGE_SIZE << order, flags);
	kmemleak_alloc (ret, size, 1, flags);

	return ret;
}

static __always_inline void *
kmalloc (size_t size, gfp_t flags)
{
	void *ret;
#ifdef CONFIG_SILKWORM_MLT
        MLT_param_t mlt_param;
#endif

#ifdef CONFIG_SILKWORM_SLUG
	return __kmalloc (size, flags);
#endif
	if (__builtin_constant_p (size)) {
		if (size > SLUB_MAX_SIZE) {
		    return kmalloc_large (size, flags);
		}
		else {
			if (!(flags & SLUB_DMA)) {
				      struct kmem_cache *s =
					      kmalloc_slab (size);
			
				      if (!s)
					      return ZERO_SIZE_PTR;
			
				      ret = kmem_cache_alloc_notrace (s,
								      flags);
			
#ifdef CONFIG_SILKWORM_MLT
				      if ((ret) && (!mlt_km_enabled)) {
                				mlt_param.s = s;
                				mlt_param.ptr = ret;
                				MLT_kmalloc_processing(&mlt_param);
				      }
#endif
			
				      trace_kmalloc (_THIS_IP_, ret, size,
						     s->size, flags);
			
				      return ret;
			}
		}
	  }

	return __kmalloc (size, flags);
}

#ifdef CONFIG_NUMA
void *__kmalloc_node (size_t size, gfp_t flags, int node);
void *kmem_cache_alloc_node (struct kmem_cache *, gfp_t flags, int node);

#ifdef CONFIG_TRACING
extern void *kmem_cache_alloc_node_notrace (struct kmem_cache *s,
					    gfp_t gfpflags, 
					    int node);
#else
static __always_inline void *
kmem_cache_alloc_node_notrace (struct kmem_cache *s, gfp_t gfpflags, int node)
{
	return kmem_cache_alloc_node (s, gfpflags, node);
}
#endif

static __always_inline void *kmalloc_node (size_t size, gfp_t flags, int node)
{
	void *ret;

	if (__builtin_constant_p (size) &&
	    size <= SLUB_MAX_SIZE && !(flags & SLUB_DMA)) {
		  struct kmem_cache *s = kmalloc_slab (size);

		  if (!s)
			  return ZERO_SIZE_PTR;

		  ret = kmem_cache_alloc_node_notrace (s, flags, node);

		  trace_kmalloc_node (_THIS_IP_, ret,
				      size, s->size, flags, node);

		  return ret;
	}
	return __kmalloc_node (size, flags, node);
}
#endif

#ifdef CONFIG_SILKWORM_MLT

static __always_inline MLT_book_keeping_info_t *get_mlt_offset(struct kmem_cache *s, void *object)
{
	MLT_book_keeping_info_t *p;

	if (s->offset)
                p = object + s->offset + sizeof(void *);
        else
                p = object + s->inuse;
	
	return p;
}

static __always_inline void init_mlt_metadata(MLT_book_keeping_info_t *p)
{
        memset(p, 0, sizeof(MLT_book_keeping_info_t));
        p->MLT_hash_node_ptr = ZERO_SIZE_PTR;
        p->mlt_signature = MLT_PATH_SIGNATURE;

        return;
}

#endif

#endif /* _LINUX_SLUB_DEF_H */
