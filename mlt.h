
#ifdef CONFIG_SILKWORM_MLT

#include "mlt_common.h"

//#define MLT_STRESS_TEST
//#define MAX_MLT_HASH_NODES 20000 
#ifndef MLT_STRESS_TEST
#define MLT_MAX_HASH 16384
#else
#define MLT_MAX_HASH 16
#endif

#define MAX_MLT_WRP_STK_DEPTH 20
#define MAX_MLT_HASH_STK_DEPTH 25
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
#ifdef MLT_DEBUG
        MLT_NODE_REUSED,
        MLT_NODE_FREED,
#endif
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
#ifdef MLT_DEBUG
        "MLT: Node re-used (indicates better leverage for performance)\0",
        "MLT: Node freed\0",
#endif
	"Max Stat\0"
};

/* MLT hash node data structure */
typedef struct MLT_hash_node {
	struct list_head MLT_hash_list_next;
	unsigned long stk_trace[MAX_MLT_HASH_STK_DEPTH];	/* kmalloc function trace *//*TBD: change unsigned long to kernel's typedefs to ensure 64-bit compliance */
	unsigned int stk_fn_hash;
	atomic_t kmalloc_cnt;	/* count to represent the number of
				   kmallocs from this function trace */
	atomic_t total_alloc_size;	/* allocation size */
	unsigned short stk_trace_len;
#ifdef MLT_DEBUG
        unsigned short chain_len;
#endif
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

#endif
