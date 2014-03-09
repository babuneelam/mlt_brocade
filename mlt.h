
#ifdef CONFIG_SILKWORM_MLT

//#define MLT_STRESS_TEST
//#define MAX_MLT_HASH_NODES 20000 
#ifndef MLT_STRESS_TEST
#define MLT_MAX_HASH 16384
#else
#define MLT_MAX_HASH 16
#endif

#define MAX_MLT_STK_DEPTH 30
#define MAX_MLT_WRP_STK_DEPTH 20
#define MAX_MLT_HASH_STK_DEPTH 25
#define MLT_STK_TRACE_SKIP_CNT 2
#define MAX_MLT_FUNC_NAME_LEN 300
#define MLT_MAGIC_NUM 0x73914BA3
#define MAX_MLT_DISPLAY_NODES 100
#define MLT_MAX_STATS_NODES 500
#define MLT_MAX_CACHE_NAME 100
#define MLT_BYTES_PER_KB 1024
#define MAX_INDUCED_MEMLEAKS 1000	/* TBD: decide on this value later */
#define MLT_HASH_TABLE_NODE_POOL_NAME "MLT_hash_nodes_Pool"
#define MLT_VP_TABLE_NAME "MLT_vp_pool"
#define MLT_STATS_CLEAR_PERIOD 5 /*in minutes */

/* Proc fs related macros */
#define PROC_MLT_DIR_NAME "mlt"
#define PROC_MLT_LEAK_DATA_FILE "mem_leaks"
#define PROC_MLT_DETAIL_LEAK_FILE "det_mem_leaks"
#define PROC_MLT_CONFIG_DATA "config"
#define PROC_MLT_DEBUG_CONFIG_DATA "debug_config"
#define PROC_MLT_DEBUG_DATA "debug_data"
#define PROC_MLT_STATS_DATA "stats"

/* Stats IDs */
enum {
	MLT_SUCCESS = 0,
	MLT_CORRUPTED_MAGIC_NUM,
	MLT_BAD_HASH_INDEX, 
	MLT_NULL_HASH_NODE_PTR, 
	MLT_HASH_PTR_NOT_IN_LIST,
	MLT_NO_STK_TRACE,
	MLT_ALLOC_FAILED,
	MLT_UNINITIALIZED,
	MLT_MAX_STAT,
};

char MLT_stats_names[MLT_MAX_STAT + 1][100] = {
	"Success\0",
	"MLT: Corrupt magic number found in book keeping memory\0",
	"MLT: bad hash table index found in book keeping memory \0",
	"MLT: NULL hash node pointer found in book keeping memory\0",
	"MLT: Unable to find book keeping hash ptr in MLT hash list\0",
	"MLT: No Stack Trace error \0",
	"MLT: hash node allocation failed\0",
	"MLT: uninitialized\0",
	"Max Stat\0"
};

/* MLT hash node data structure */
typedef struct MLT_hash_node {
	struct list_head MLT_hash_list_next;
	unsigned long stk_trace[MAX_MLT_HASH_STK_DEPTH];	/* kmalloc function trace *//*TBD: change unsigned long to kernel's typedefs to ensure 64-bit compliance */
	unsigned int stk_fn_hash;
	struct {
#define MLT_LOCK_BIT_BE 31	/*  the compiler lays out the bit fields as big endian */
		unsigned long bit_lock:1;
		unsigned long delete_pending:1;
		unsigned long delete_wait_count:6;
		unsigned long hash_index:16;
		unsigned long chain_len:8;
	} hash_control;
	atomic_t kmalloc_cnt;	/* count to represent the number of
				   kmallocs from this function trace */
	unsigned long size;	/* allocation size */
	atomic_t total_alloc_size;	/* allocation size */
	unsigned short hash_count;
	unsigned short stk_trace_len;
	struct list_head scheduled_for_deletion;
} MLT_hash_node_t;

/* MLT hash node data structure */
typedef struct MLT_stats_node {
	int statsID;
	unsigned long stk_trace[MAX_MLT_STK_DEPTH];	/* stk trace at the error point */
	unsigned int stk_trace_len;
#if 0				/*TBD */
	char cache_name[MLT_MAX_CACHE_NAME];
	unsigned int slab_cache_buff_size;
#endif
} MLT_stats_node_t;

typedef struct {
	struct list_head MLT_vp_list_next;
	unsigned long vp;
	MLT_hash_node_t *p_stats;
} MLT_vp_node_t;

/*Function delcarations */
static __always_inline unsigned int mlt_get_stack_trace(unsigned long *mlt_stk_trace);
static __always_inline int mlt_validate_sp(unsigned long sp, struct task_struct *p,
                       unsigned long nbytes);
#ifdef CONFIG_IRQSTACKS
static __always_inline int mlt_valid_irq_stack(unsigned long sp, struct task_struct *p,
                                  unsigned long nbytes);
#endif


static __always_inline uint32_t bob_jenkins_hash(uint32_t a)
{
	a = (a + 0x7ed55d16) + (a << 12);
	a = (a ^ 0xc761c23c) ^ (a >> 19);
	a = (a + 0x165667b1) + (a << 5);
	a = (a + 0xd3a2646c) ^ (a << 9);
	a = (a + 0xfd7046c5) + (a << 3);
	a = (a ^ 0xb55a4f09) ^ (a >> 16);
	return a;
}

static __always_inline uint32_t JSHash(char *str, unsigned int len)
{
	unsigned int hash = 1315423911;

	for (; len; len--) {
		hash ^= ((hash << 5) + (*str++) + (hash >> 2));
	}

	return hash;
}

#ifdef CONFIG_IRQSTACKS
static __always_inline int mlt_valid_irq_stack(unsigned long sp, struct task_struct *p,
                                  unsigned long nbytes)
{
        unsigned long stack_page;
        unsigned long cpu = task_cpu(p);

        /*
         * Avoid crashing if the stack has overflowed and corrupted
         * task_cpu(p), which is in the thread_info struct.
         */
        if (cpu < NR_CPUS && cpu_possible(cpu)) {
                stack_page = (unsigned long) hardirq_ctx[cpu];
                if (sp >= stack_page + sizeof(struct thread_struct)
                    && sp <= stack_page + THREAD_SIZE - nbytes)
                        return 1;

                stack_page = (unsigned long) softirq_ctx[cpu];
                if (sp >= stack_page + sizeof(struct thread_struct)
                    && sp <= stack_page + THREAD_SIZE - nbytes)
                        return 1;
        }
        return 0;
}

#else
#define mlt_valid_irq_stack(sp, p, nb)      0
#endif /* CONFIG_IRQSTACKS */

static __always_inline int mlt_validate_sp(unsigned long sp, struct task_struct *p,
                       unsigned long nbytes)
{
        unsigned long stack_page = (unsigned long)task_stack_page(p);

        if (sp >= (unsigned long)end_of_stack(p)
            && sp <= stack_page + THREAD_SIZE - nbytes)
                return 1;

        return mlt_valid_irq_stack(sp, p, nbytes);
}

static __always_inline unsigned int mlt_get_stack_trace(unsigned long *mlt_stk_trace)
{
        unsigned long sp;
        unsigned int i;

        asm("mr %0,1" : "=r" (sp));

        for (i=1; i< MLT_STK_TRACE_SKIP_CNT; i++)
        {
                if (!validate_sp(sp, current, STACK_FRAME_OVERHEAD))
                        return 0;
                sp = ((unsigned long *)sp)[0];
        }

        for (i=0; i< MAX_MLT_STK_DEPTH; i++)
        {
                if (!mlt_validate_sp(sp, current, STACK_FRAME_OVERHEAD))
                        return i;

                mlt_stk_trace[i] = ((unsigned long *)sp)[STACK_FRAME_LR_SAVE];

                sp = ((unsigned long *)sp)[0];
        }

        return MAX_MLT_STK_DEPTH;
}

#endif
