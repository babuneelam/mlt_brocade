/*TBD: File header if needed */
/* Memory Leak Tracking (MLT) Module */

#ifdef CONFIG_SILKWORM_MLT

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ctype.h>
#include <linux/hardirq.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/kernel.h>
#include <include/asm/uaccess.h>
#include <linux/random.h>
#include <linux/mlt_inc.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/compat.h>
#include "mlt.h"
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/poison.h>
#include <linux/vmalloc.h>
#include <linux/lockdep.h>
#include <linux/kallsyms.h>

//#define PRINT printk(KERN_DEBUG"%s %d \r\n", __FUNCTION__, __LINE__)
#define PRINT

int 
MLT_init(void);
int MLT_dump_traces(void);

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
extern int mlt_kl_enabled;
#endif

/* Global variable definitions */
int MLT_initialized = 0;	/* No lock is used to protect this variable as the impact of not using it hazardous */
static MLT_hash_node_t *MLT_hash_table;
static MLT_hash_node_t MLT_display_nodes[MAX_MLT_DISPLAY_NODES];
static struct kmem_cache *MLT_hash_nodes_pool = NULL;
static char wrp_stk_func[MAX_MLT_WRP_STK_DEPTH][MAX_MLT_FUNC_NAME_LEN];
static unsigned int wrp_stk_fn_cnt = 0;
static atomic_t MLT_stats[MLT_MAX_STAT];
static MLT_stats_node_t MLT_detailed_stats[MLT_MAX_STATS_NODES];
static atomic_t MLT_detailed_stats_cur_index = ATOMIC_INIT(0);
static int kmalloc_cnt_sort = 0, kmalloc_size_sort=1, stk_top_skip_cnt = 0, log_detail_stats=0, 
    list_stats_in_detail = 0, max_detail_stats = 10, rollover_stats_arr = 0, 
    clear_stats_now = 0, detail_entry_index = 0, bypass_mlt=0, display_cnt=20;
static int cur_display_node_cnt = 0;

static rwlock_t mlt_hash_tbl_lock[MLT_MAX_HASH];

#define MLT_READ_LOCK(index) read_lock_irqsave(&mlt_hash_tbl_lock[index], flags)
#define MLT_READ_UNLOCK(index) read_unlock_irqrestore(&mlt_hash_tbl_lock[index], flags)
#define MLT_WRITE_LOCK(index) write_lock_irqsave(&mlt_hash_tbl_lock[index], flags)
#define MLT_WRITE_UNLOCK(index) write_unlock_irqrestore(&mlt_hash_tbl_lock[index], flags)

static atomic_t outstanding_alloc_cnt, outstanding_alloc_size;
/* If MLT_conf_buff is modified, modify even the script at 
 * /vobs/projects/springboard/fabos/src/utils/sys/mlt
 */
#ifdef MLT_DEBUG
static int kmalloc_large_allocs=0;
static char MLT_conf_buff[100] = "0 0 0 0 10 0 0 0 1 20 0";
#else
static char MLT_conf_buff[100] = "0 0 0 0 10 0 0 0 1 20";
#endif
static char MLT_conf_buff_format[] = "Format: \n"
    "    Number of kmalloc-cnt sorted entries to be displayed. < 100 expected\n"
    "    Number of top functions in stack trace to be skipped before storing in hash node \n"
    "    whether to log stats in detail \n"
    "    whether to display stats in detail \n"
    "    Number of stats entries to be displayed in detail \n"
    "    whether to roll over from the beginning when stats array is full \n"
    "    whether to clear the stats information now \n"
    "    Bypass MLT from now (Use it cautiously)\n"
    "    Number of total-allocation-size sorted entries to be displayed. < 100 expected\n"
    "    MLT output display entries (should be < 100)\n"
#ifdef MLT_DEBUG
    "    Number of kmallocs to be done to cause OOM \n"
#endif
    ;

#define MLT_PROCESS_ERROR(errCode) { \
	atomic_inc(&MLT_stats[errCode]); \
	if (log_detail_stats) \
	{ \
		MLT_log_stk_trace(errCode); \
	} \
	}

#ifdef CONFIG_SILKWORM_MLT_DEBUG
static int display_hash_table = 0, display_hash_index = 0, max_display_cnt =
    0, display_hash_collisions = 0, hash_random_events = 0, induce_leaks =
    0, alloc_units = 0, reduce_leaks = 0, dealloc_units = 0, alloc_unit_size =
    0;
	   /* TBD: set default values as macros */
static char MLT_debug_conf_buff[100] = "0 0 0 0 0 0 0 0 0 0";
static char MLT_debug_conf_buff_format[] = "Format: \n"
    "    whether to display MLT hash nodes \n"
    "    the hash index at which to display the MLT hash nodes \n"
    "    Number of hash nodes to be displayed \n"
    "    whether to display hash collision info \n"
    "    Number of random kmalloc data events to be simulated for hash distribution algorithm testing \n"
    "    Whether to induce a memory allocation \n"
    "    Number of memory allocations to be induced \n"
    "    Whether to reduce memory allocations \n"
    "    Number of memory allocations to be reduced \n"
    "    Size of each memory allocation \n";

#endif

#ifdef MLT_DEBUG
static void *MLT_induced_leaks[MAX_INDUCED_MEMLEAKS];
#endif

/* Procs fs common function prototypes */
static void *MLT_proc_start(struct seq_file *, loff_t *);
static void MLT_proc_stop(struct seq_file *, void *);
static void *MLT_proc_next(struct seq_file *, void *, loff_t *);
int mlt_garbage_collector(void *);

/* Procs fs (CLI related) function prototypes */
static int MLT_config_write(struct file *file, const char *buffer,
			    unsigned long count, void *data);
static int MLT_config_read(char *page, char **start, off_t off, int count,
			   int *eof, void *data);
static int MLT_leaks_data_open(struct inode *, struct file *);
static int MLT_leaks_data_show(struct seq_file *, void *);
static int MLT_det_leaks_data_read(char *page, char **start, off_t off,
				   int count, int *eof, void *data);
static int MLT_det_leaks_data_write(struct file *file, const char *buffer,
				    unsigned long count, void *data);
static int MLT_stats_data_open(struct inode *, struct file *);
static int MLT_stats_data_show(struct seq_file *, void *);
#ifdef CONFIG_SILKWORM_MLT_DEBUG
static int MLT_debug_data_open(struct inode *, struct file *);
static int MLT_debug_data_show(struct seq_file *, void *);
static int MLT_debug_config_write(struct file *file, const char *buffer,
				  unsigned long count, void *data);
static int MLT_debug_config_read(char *page, char **start, off_t off, int count,
				 int *eof, void *data);
#endif

/* Procs fs (CLI related) data structure declarations */
static struct file_operations proc_MLT_leaks_ops = {
	.open = MLT_leaks_data_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct seq_operations MLT_leaks_data_op = {
	.start = MLT_proc_start,
	.next = MLT_proc_next,
	.stop = MLT_proc_stop,
	.show = MLT_leaks_data_show,
};

static struct file_operations proc_MLT_stats_ops = {
	.open = MLT_stats_data_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct seq_operations MLT_stats_data_op = {
	.start = MLT_proc_start,
	.next = MLT_proc_next,
	.stop = MLT_proc_stop,
	.show = MLT_stats_data_show,
};

#ifdef CONFIG_SILKWORM_MLT_DEBUG
static int MLT_debug_data_open(struct inode *inode, struct file *file);
static int MLT_debug_data_show(struct seq_file *m, void *arg);

static struct file_operations proc_MLT_debug_data_ops = {
	.open = MLT_debug_data_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static struct seq_operations meminfra_hash_table_op = {
	.start = MLT_proc_start,
	.next = MLT_proc_next,
	.stop = MLT_proc_stop,
	.show = MLT_debug_data_show,
};
#endif

struct MLT_garbage_collection_params {
	int entries;
	unsigned short mlt_delete_wait_count;
	int sleep_interval;
};

/* miscellaneous function prototypes */
static void MLT_deinit(void);
static void MLT_log_stk_trace(int errCode);
static void MLT_add_mem_wrp_func(char *func_name);
static __always_inline unsigned int MLT_hash(unsigned long *stk_trace,
			     unsigned int stk_trace_len,
			     unsigned int *stk_fn_hash);
static void insert_sort(MLT_hash_node_t *hash_node) ;

int MLT_get_panicdump_info(void *pdHandle, unsigned int event, void *cbArg,
			   char **buff, int *len);
static char *MLT_PD_buff;
static char MLT_PD_tmp_buff[] = "MLT not enabled \r\n";
static char MLT_PD_tmp_buff1[] = "MLT not initialized\r\n";
static int MLT_PD_buff_len = 0;

EXPORT_SYMBOL(MLT_initialized);

#ifdef CONFIG_LOCKDEP
typedef struct mlt_lock_class {
        struct lock_class_key key;
} mlt_lock_class_t;

static mlt_lock_class_t lock_class;
#endif

/**************************************************************************************************************************/
/**************************************************************************************************************************/
/*                                    INIT and DEINIT FUNCTIONS                                                           */
/**************************************************************************************************************************/
/**************************************************************************************************************************/

int MLT_init()
{
	int i;
	struct proc_dir_entry *MLT_dir, *MLT_config, *MLT_leaks, *MLT_det_leaks,
	    *MLT_stats_file;
#ifdef CONFIG_SILKWORM_MLT_DEBUG
	struct proc_dir_entry *MLT_debug_config, *MLT_debug_data;
#endif
#ifdef CONFIG_LOCKDEP
	char name[20]="mlt";
#endif

	if (!mlt_enabled)
		return -1;

        /* Initialize the MLT Locks */
        for (i = 0; i < MLT_MAX_HASH; i++) {
                mlt_hash_tbl_lock[i] = RW_LOCK_UNLOCKED;
#ifdef CONFIG_LOCKDEP
		lockdep_init_map(&mlt_hash_tbl_lock[i].dep_map, name, &(lock_class.key), 0);
#endif
        }

	/* create MLT hash table */
	MLT_hash_table = kzalloc(sizeof(MLT_hash_node_t) * MLT_MAX_HASH, 0);

	printk(KERN_WARNING "%s: allocated %p for MLT hash table\n", __FUNCTION__, MLT_hash_table);

	if( unlikely(!MLT_hash_table)) {
		printk(KERN_ERR "%s: Failed to allocate MLT table\n", __FUNCTION__);
		return -1;
	}

	/* Allocate MLT panic dump buffer */
	MLT_PD_buff = kzalloc(MLT_PANIC_DUMP_BUFF_SIZE, 0);
	if( unlikely(!MLT_PD_buff)) {
		printk(KERN_ERR "%s: Failed to allocate MLT panic dump buffer \n", __FUNCTION__);
		return -1;
	}

	/* Create profs file for this module */
	MLT_dir = proc_mkdir(PROC_MLT_DIR_NAME, NULL);
	if (MLT_dir == NULL)
		return MEMINFRA_INIT_FAILURE;

	/* Create MLT configuration file */
	MLT_config = create_proc_entry(PROC_MLT_CONFIG_DATA, 0644, MLT_dir);	/* TBD: make 0644 a macro */
	if (MLT_config == NULL)
		goto bailout1;
	MLT_config->read_proc = MLT_config_read;
	MLT_config->write_proc = MLT_config_write;

	/* Create MLT memory leaks display file */
	MLT_leaks = create_proc_entry(PROC_MLT_LEAK_DATA_FILE, 0, MLT_dir);
	if (MLT_leaks == NULL)
		goto bailout2;
	MLT_leaks->proc_fops = &proc_MLT_leaks_ops;

	/* Create MLT detailed memory leaks display file */
	MLT_det_leaks =
	    create_proc_entry(PROC_MLT_DETAIL_LEAK_FILE, 0644, MLT_dir);
	if (MLT_det_leaks == NULL)
		goto bailout3;
	MLT_det_leaks->read_proc = MLT_det_leaks_data_read;
	MLT_det_leaks->write_proc = MLT_det_leaks_data_write;

	/* Create MLT stats file */
	MLT_stats_file = create_proc_entry(PROC_MLT_STATS_DATA, 0, MLT_dir);
	if (MLT_stats_file == NULL)
		goto bailout4;
	MLT_stats_file->proc_fops = &proc_MLT_stats_ops;

#ifdef CONFIG_SILKWORM_MLT_DEBUG
	/* Create MLT debug configuration file */
	MLT_debug_config = create_proc_entry(PROC_MLT_DEBUG_CONFIG_DATA, 0644, MLT_dir);	/* TBD: make 0644 a macro */
	if (MLT_debug_config == NULL)
		goto bailout5;
	MLT_debug_config->read_proc = MLT_debug_config_read;
	MLT_debug_config->write_proc = MLT_debug_config_write;

	/* Create MLT debug data display file */
	MLT_debug_data = create_proc_entry(PROC_MLT_DEBUG_DATA, 0, MLT_dir);
	if (MLT_debug_data == NULL)
		goto bailout6;
	MLT_debug_data->proc_fops = &proc_MLT_debug_data_ops;
#endif

#ifdef MLT_DEBUG
	/* Initialize the simulated leaks table */
	for (i = 0; i < MAX_INDUCED_MEMLEAKS; i++)
		MLT_induced_leaks[i] = NULL;
#endif

	/* Initialize the slab cache for MLT_hash_node_t nodes */
	MLT_hash_nodes_pool = kmem_cache_create(MLT_HASH_TABLE_NODE_POOL_NAME,
						sizeof(MLT_hash_node_t), 0,
						SLAB_HWCACHE_ALIGN, NULL);
	if (!MLT_hash_nodes_pool)
		goto bailout7;

	/* Initialize the MLT_hash_table */
	for (i = 0; i < MLT_MAX_HASH; i++) {
		INIT_LIST_HEAD(&MLT_hash_table[i].MLT_hash_list_next);
		atomic_set(&MLT_hash_table[i].kmalloc_cnt, 1);
	}

	atomic_set(&outstanding_alloc_size, 0);
	atomic_set(&outstanding_alloc_cnt, 0);

	/* Initialize the Wrap Stack functions */
	MLT_add_mem_wrp_func("__kmalloc");
	MLT_add_mem_wrp_func("__kmalloc_track_caller");
	MLT_add_mem_wrp_func("kmalloc_wrapper_dbg");
	MLT_add_mem_wrp_func("vmalloc_wrapper_dbg");
	MLT_add_mem_wrp_func("kstrdup");
	MLT_add_mem_wrp_func("kmemdup");
	MLT_add_mem_wrp_func("__alloc_skb");
	MLT_add_mem_wrp_func("kmalloc_wrapper_nodbg");
	MLT_add_mem_wrp_func("__proc_create");
	MLT_add_mem_wrp_func("kmem_cache_alloc");
	MLT_add_mem_wrp_func("kmem_cache_alloc_brcd");
	MLT_add_mem_wrp_func("kmem_cache_alloc_node");
	//MLT_add_mem_wrp_func("trace_define_field");
	//MLT_add_mem_wrp_func("event_create_dir");
	//MLT_add_mem_wrp_func("sysfs_new_dirent");

	printk(KERN_WARNING "Initialized MLT\n");
	MLT_initialized = 1;
	kthread_run(mlt_garbage_collector, NULL, "MLT garbage collector\n");
	return MEMINFRA_INIT_SUCCESS;

      bailout7:
#ifdef CONFIG_SILKWORM_MLT_DEBUG
	remove_proc_entry(PROC_MLT_DEBUG_DATA, MLT_dir);
      bailout6:
	remove_proc_entry(PROC_MLT_DEBUG_CONFIG_DATA, MLT_dir);
      bailout5:
#endif
	remove_proc_entry(PROC_MLT_STATS_DATA, MLT_dir);
      bailout4:
	remove_proc_entry(PROC_MLT_DETAIL_LEAK_FILE, MLT_dir);
      bailout3:
	remove_proc_entry(PROC_MLT_LEAK_DATA_FILE, MLT_dir);
      bailout2:
	remove_proc_entry(PROC_MLT_CONFIG_DATA, MLT_dir);
      bailout1:
	remove_proc_entry(PROC_MLT_DIR_NAME, NULL);
	return MEMINFRA_INIT_FAILURE;
}

static void MLT_deinit()
{
	/* This module is deinitialized only during system de-init. So, no de-init code is required */
}

/**************************************************************************************************************************/
/**************************************************************************************************************************/
/*                                            EXPOSED API FUNCTIONS                                                       */
/**************************************************************************************************************************/
/**************************************************************************************************************************/

void MLT_kmalloc_processing(MLT_param_t *mlt_param)
{
	unsigned long mlt_stk_trace[MAX_MLT_STK_DEPTH];
	unsigned int stk_trace_len, stk_fn_hash;
	MLT_hash_node_t *MLT_hash_node_ptr=NULL, *resuable_MLT_hash_node_ptr=NULL;;
	int found = 0;
	unsigned int copy_count;
	MLT_book_keeping_info_t *metadata;
	unsigned long flags;

	if (unlikely(!mlt_enabled))
		return;

	if (unlikely(bypass_mlt))
		return;

	if (unlikely(!MLT_initialized)) {
		MLT_PROCESS_ERROR(MLT_UNINITIALIZED);
		return;
	}

	metadata = get_mlt_offset(mlt_param->s, mlt_param->ptr);
	stk_trace_len = mlt_get_stack_trace(mlt_stk_trace);

	if (unlikely(!stk_trace_len)) {
		MLT_PROCESS_ERROR(MLT_NO_STK_TRACE);
		return;
	}

	/* copy_count = MAX(stk_trace_len - stk_top_skip_cnt, MAX_MLT_HASH_STK_DEPTH) */
	copy_count = stk_trace_len - stk_top_skip_cnt;
	copy_count =
	    copy_count <=
	    MAX_MLT_HASH_STK_DEPTH ? copy_count : MAX_MLT_HASH_STK_DEPTH;

	/* initialize meta data  */
	metadata->MLT_hash_node_ptr = ZERO_SIZE_PTR;
	metadata->mlt_signature = MLT_PATH_SIGNATURE;
	metadata->hash_index =
	    MLT_hash(mlt_stk_trace, stk_trace_len * sizeof(stk_trace_len),
		     &stk_fn_hash);
	metadata->hash_index_compl = metadata->hash_index ^ 0xFFFF;

	/* iterate the table */
	MLT_READ_LOCK(metadata->hash_index);
	MLT_hash_node_ptr = &MLT_hash_table[metadata->hash_index];
	list_for_each_entry(MLT_hash_node_ptr,
			    &MLT_hash_table[metadata->hash_index].MLT_hash_list_next,
			    MLT_hash_list_next) {
		if ((MLT_hash_node_ptr->stk_trace_len == copy_count)
		    && (MLT_hash_node_ptr->stk_fn_hash == stk_fn_hash)) {
			metadata->MLT_hash_node_ptr = (void *)MLT_hash_node_ptr;
			atomic_inc(& MLT_hash_node_ptr->kmalloc_cnt);
			atomic_add(obj_size_api(mlt_param->s), &MLT_hash_node_ptr->total_alloc_size);

			atomic_inc(&outstanding_alloc_cnt);
			atomic_add(obj_size_api(mlt_param->s), &outstanding_alloc_size);
			found = 1;
			break;
		} else if (atomic_read(&MLT_hash_node_ptr->kmalloc_cnt) == 0)
                        resuable_MLT_hash_node_ptr = MLT_hash_node_ptr;
        }

        /* Re-using any delete-pending nodes */
        if ((!found)&&(resuable_MLT_hash_node_ptr))
        {
                unsigned long *stack_trace, *save_trace;

                /* point to the node we're about to insert */
                metadata->MLT_hash_node_ptr = (void *)resuable_MLT_hash_node_ptr;

                /* Fill up the info in tracking node */
                atomic_set(&resuable_MLT_hash_node_ptr->kmalloc_cnt, 1);
                atomic_set(&resuable_MLT_hash_node_ptr->total_alloc_size, obj_size_api(mlt_param->s));

		atomic_inc(&outstanding_alloc_cnt);
		atomic_add(obj_size_api(mlt_param->s), &outstanding_alloc_size);
                resuable_MLT_hash_node_ptr->stk_trace_len = copy_count;
                /* copy stack trace */
                for (stack_trace = &mlt_stk_trace[stk_top_skip_cnt], save_trace =
                     resuable_MLT_hash_node_ptr->stk_trace; copy_count; copy_count--) {
                        *save_trace++ = *stack_trace++;
                }

                resuable_MLT_hash_node_ptr->stk_fn_hash = stk_fn_hash;
#ifdef MLT_DEBUG
                MLT_PROCESS_ERROR(MLT_NODE_REUSED);
#endif

                found = 1;
        }
        MLT_READ_UNLOCK(metadata->hash_index);

	if (!found) {
		unsigned long *stack_trace, *save_trace;
		MLT_hash_node_t *new_node;

		new_node = kmem_cache_alloc_mlt_bypass(MLT_hash_nodes_pool, GFP_ATOMIC);
		if (unlikely(!new_node)) {
			printk(KERN_WARNING
			       "%s: failed to allocate MLT_hash_node\n",
			       __FUNCTION__);
			MLT_PROCESS_ERROR(MLT_ALLOC_FAILED);
			return;
		}
		/* point to the node we're about to insert */
		metadata->MLT_hash_node_ptr = (void *)new_node;

		/* Fill up the info in tracking node */
		atomic_set(&new_node->kmalloc_cnt, 1);
		atomic_set(&new_node->total_alloc_size, obj_size_api(mlt_param->s));

		atomic_inc(&outstanding_alloc_cnt);
		atomic_add(obj_size_api(mlt_param->s), &outstanding_alloc_size);

		new_node->stk_trace_len = copy_count;
		/* copy stack trace */
		for (stack_trace =
		     &mlt_stk_trace[stk_top_skip_cnt], save_trace =
		     new_node->stk_trace; copy_count; copy_count--) {
			*save_trace++ = *stack_trace++;
		}

		new_node->stk_fn_hash = stk_fn_hash;

                MLT_WRITE_LOCK(metadata->hash_index);
				/* insert at tail; */
				list_add_tail(&new_node->MLT_hash_list_next,
					      &MLT_hash_table[metadata->hash_index].
					      MLT_hash_list_next);
#ifdef MLT_DEBUG
                MLT_hash_table[metadata->hash_index].chain_len++;
#endif
                MLT_WRITE_UNLOCK(metadata->hash_index);
	}

	return;
}

EXPORT_SYMBOL(MLT_kmalloc_processing);

#define POISON_INUSE_U32 	((POISON_INUSE<<24) + (POISON_INUSE<<16) + (POISON_INUSE<<8) + (POISON_INUSE))

void MLT_kfree_processing(MLT_param_t *mlt_param)
{
	unsigned short index, found=0;
        MLT_book_keeping_info_t *metadata;
	MLT_hash_node_t *MLT_hash_node_ptr = NULL;
	unsigned long flags;

	if (unlikely(!mlt_enabled))
		return;

	if (unlikely(bypass_mlt))
		return;

	if (unlikely(!MLT_initialized)) {
		MLT_PROCESS_ERROR(MLT_UNINITIALIZED);
		return;
	}

	metadata = get_mlt_offset(mlt_param->s, mlt_param->ptr);
	if(unlikely(metadata->mlt_signature == POISON_INUSE_U32)) {
		return;
	}

	if (unlikely(metadata->mlt_signature != MLT_PATH_SIGNATURE))
	{
		MLT_PROCESS_ERROR(MLT_CORRUPTED_MAGIC_NUM);
		return;
	}

	index = metadata->hash_index;
	if (metadata->MLT_hash_node_ptr != ZERO_SIZE_PTR)
	{
	    if ((metadata->hash_index_compl ^ index) == 0xFFFF) 
	    {
#ifdef MLT_DEBUG
		if (MLT_hash_table[index].MLT_hash_list_next.next == NULL) {
			printk
			    ("%s: metadata ptr: %p; hash node ptr: %p; index: %x; index compl: %x signature %8.8x\n",
			     __FUNCTION__, metadata,
			     metadata->MLT_hash_node_ptr, metadata->hash_index,
			     metadata->hash_index_compl,
			     (unsigned int)metadata->mlt_signature);
			BUG();

		}
#endif
                MLT_READ_LOCK(index);
                list_for_each_entry(MLT_hash_node_ptr,
                            &MLT_hash_table[index].MLT_hash_list_next,
                            MLT_hash_list_next) {
                        if (MLT_hash_node_ptr == metadata->MLT_hash_node_ptr)
                        {
                                atomic_dec(&MLT_hash_node_ptr->kmalloc_cnt);
		        atomic_sub(obj_size_api(mlt_param->s), &MLT_hash_node_ptr->total_alloc_size);

				atomic_dec(&outstanding_alloc_cnt);
		        	atomic_sub(obj_size_api(mlt_param->s), &outstanding_alloc_size);
                                found = 1;
                                break;
                        }

                }
                MLT_READ_UNLOCK(index);

		/* erase bookkeeping info */
		metadata->hash_index ^= 0xFFFF;
		metadata->mlt_signature = 0;
		metadata->MLT_hash_node_ptr = (void *)0xFFFFFFFF;
		if (!found) {
			MLT_PROCESS_ERROR(MLT_HASH_PTR_NOT_IN_LIST);
			init_mlt_metadata(metadata);
		}
	    } else {
		MLT_PROCESS_ERROR(MLT_BAD_HASH_INDEX);
		init_mlt_metadata(metadata);
	    }
	} else {
		MLT_PROCESS_ERROR(MLT_NULL_HASH_NODE_PTR);
		init_mlt_metadata(metadata);
	}

}

EXPORT_SYMBOL(MLT_kfree_processing);

/**************************************************************************************************************************/
/**************************************************************************************************************************/
/*                                           PROC FS common Functions                                              */
/**************************************************************************************************************************/
/**************************************************************************************************************************/

/**
 * This function is called at the beginning of a sequence.
 * ie, when:
 *	- the /proc file is read (first time)
 *	- after the function stop (end of sequence)
 *
 */
static void *MLT_proc_start(struct seq_file *s, loff_t * pos)
{
	static unsigned long counter = 0;

	/* beginning a new sequence ? */
	if (*pos == 0) {
		/* yes => return a non null value to begin the sequence */
		return &counter;
	} else {
		/* no => it's the end of the sequence, return end to stop reading */
		*pos = 0;
		return NULL;
	}
}

/**
 * This function is called after the beginning of a sequence.
 * It's called untill the return is NULL (this ends the sequence).
 *
 */
static void *MLT_proc_next(struct seq_file *m, void *arg, loff_t * pos)
{
	*pos = 1;
	return NULL;		/* all data is displayed in one chunk */
}

static void MLT_proc_stop(struct seq_file *sf, void *p)
{
	return;
}

/**************************************************************************************************************************/
/**************************************************************************************************************************/
/*                                           PROC FS (CLI) Functions                                              */
/**************************************************************************************************************************/
/**************************************************************************************************************************/

static int MLT_config_write(struct file *file, const char *buffer,
			    unsigned long count, void *data)
{
	char *buff, *buff1, **end_ptr = NULL;
	unsigned int i, tmp;
#ifdef MLT_DEBUG
	int m;
#endif

	if (count > 100)
		return 0;	/* TBD: convert 100 to a macro */

	copy_from_user(MLT_conf_buff, buffer, count);
	MLT_conf_buff[count] = '\0';

	buff = MLT_conf_buff;
#ifdef MLT_DEBUG
	for (i = 1; i <= 11 /* Max config entires */ ; i++) {
#else
	for (i = 1; i <= 10 /* Max config entires */ ; i++) {
#endif
		buff1 = buff;
		while (MLT_isdigit(*buff))
			buff++;
		if (*buff != '\n') {
			if (*buff == ' ')
				buff++;
			else
				return 0;
		}

		switch (i) {
		case 1:
			kmalloc_cnt_sort = simple_strtoul(buff1, end_ptr, 10);	/* TBD: replace 10 by a macro */
			break;
		case 2:
			stk_top_skip_cnt = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 3:
			log_detail_stats =
			    simple_strtoul(buff1, end_ptr, 10);
			break;
		case 4:
			list_stats_in_detail =
			    simple_strtoul(buff1, end_ptr, 10);
			break;
		case 5:
			max_detail_stats = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 6:
			rollover_stats_arr = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 7:
			clear_stats_now = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 8:
			bypass_mlt = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 9:
			kmalloc_size_sort = simple_strtoul(buff1, end_ptr, 10);
			if (kmalloc_size_sort >0)
			    kmalloc_cnt_sort =0;
			break;
		case 10:
			tmp = simple_strtoul(buff1, end_ptr, 10);	
			if (tmp > MAX_MLT_DISPLAY_NODES)
			    printk("%s %d display count should be less than 100 ", 
				__FUNCTION__, __LINE__);
			else 
			    display_cnt = tmp;
			break;
#ifdef MLT_DEBUG
                case 11:
                        kmalloc_large_allocs=0;
                        kmalloc_large_allocs = simple_strtoul(buff1, end_ptr, 10);
printk("%s %d: kmalloc_large_allocs=%d \r\n", __FUNCTION__, __LINE__, kmalloc_large_allocs);
			for (m=0; (m<kmalloc_large_allocs); m++)
                        	kmalloc(/*16384*/ 131072, GFP_KERNEL);
                        break;
#endif
		}
	}

	if (clear_stats_now) {
		/* Lock is not used to memset the following arrays, 
		   but no critical damage is expected */
		memset(&MLT_stats, 0, sizeof(MLT_stats));
		memset(&MLT_detailed_stats, 0, sizeof(MLT_detailed_stats));
		atomic_set(&MLT_detailed_stats_cur_index, 0);
		printk("stats cleared \n");
	}

	return count;
}

static int MLT_config_read(char *page, char **start, off_t off, int count,
			   int *eof, void *data)
{
	sprintf(page, "\n%s \n\n%s \n\n", MLT_conf_buff, MLT_conf_buff_format);
	*eof = 1;
	return (strlen(MLT_conf_buff) + strlen(MLT_conf_buff_format) + 4);
}

static int MLT_leaks_data_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &MLT_leaks_data_op);
}

static int MLT_leaks_data_show(struct seq_file *m, void *arg)
{
	unsigned int i, j, k, l;
	MLT_hash_node_t *MLT_hash_node;
	char tmp_str1[MAX_MLT_FUNC_NAME_LEN], *tmp_str2,
	    func_name[MAX_MLT_FUNC_NAME_LEN];
	unsigned long flags;

        if (!mlt_enabled)
        {
            seq_printf(m, "\r\nMLT not enabled. \r\n\n");
            return 0;
        }

	if (mlt_km_enabled)
	{
        	seq_printf(m, "\r\nOutstanding kmem_cache_alloc allocations tracked by MLT: %d \r\n", 
				atomic_read(&outstanding_alloc_cnt));
        	seq_printf(m, "Outstanding kmem_cache_alloc memory tracked by MLT: ");
	} else {
        	seq_printf(m, "\r\nOutstanding kmalloc allocations tracked by MLT: %d \r\n", 
				atomic_read(&outstanding_alloc_cnt));
        	seq_printf(m, "Outstanding kmalloc memory tracked by MLT: ");
	}

        if ((atomic_read(&outstanding_alloc_size)/ 1048576) > 1)
                seq_printf(m, "%6d.%d MB \r\n\n", atomic_read(&outstanding_alloc_size)/1048576,
                    get_first_digit(atomic_read(&outstanding_alloc_size)%1048576));
        else if ((atomic_read(&outstanding_alloc_size)/ 1024) > 1)
                seq_printf(m, "%6d.%d KB \r\n\n", atomic_read(&outstanding_alloc_size)/1024,
                    get_first_digit(atomic_read(&outstanding_alloc_size)%1024));
        else
                seq_printf(m, "%6d B \r\n\n", atomic_read(&outstanding_alloc_size));


        cur_display_node_cnt = 0;
	for (i = 0; i < MLT_MAX_HASH; i++) {
                MLT_READ_LOCK(i);
		list_for_each_entry(MLT_hash_node,
		 	&MLT_hash_table[i].MLT_hash_list_next, MLT_hash_list_next) 
		{
		    insert_sort(MLT_hash_node);
		}
                MLT_READ_UNLOCK(i);
	}

        if (kmalloc_size_sort)
        {
	    seq_printf(m, "Display Index   Stack Trace making the allocations"
			  "                  Total Memory allocated (Alloc Count)\r\n");
	    seq_printf(m, "-------------   ----------------------------------"
		          "                  -----------------------\r\n");
        } else {
	    seq_printf(m, "Display Index   Stack Trace making the allocations"
			  "                  Number of kmallocs made (Total Mem Allocated)\r\n");
	    seq_printf(m, "-------------   ----------------------------------"
			  "                  -------------------\r\n");
	}

	for (j = 0; j < cur_display_node_cnt; j++) {
		for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
			if (is_vmalloc_or_module_addr((void *)MLT_display_nodes[j].stk_trace[l]))
				break;
		}
		if (l == MLT_display_nodes[j].stk_trace_len) {
			for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
				memset(tmp_str1, 0, MAX_MLT_FUNC_NAME_LEN);
				memset(func_name, 0, MAX_MLT_FUNC_NAME_LEN);
				tmp_str2 = NULL;
				//strcpy(tmp_str1, MLT_display_nodes[j].stk_trace[l]);
				sprintf(tmp_str1, "%pS",
					(void *)MLT_display_nodes[j].stk_trace[l]);
				tmp_str2 = strchr(tmp_str1, '+');
				if (!tmp_str2)
					break;
				*tmp_str2 = '\0';
				strcpy(func_name, tmp_str1);

				for (k = 0; k < wrp_stk_fn_cnt; k++)
					if (!strcmp(func_name, wrp_stk_func[k]))
						break;
				if (k == wrp_stk_fn_cnt)
					break;
			}
		}

        	if (kmalloc_size_sort)
        	{
		    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
		        seq_printf(m, "%13d   %-60pS  %6d.%1d MB  (%d)\n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
			   get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576),
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
		        seq_printf(m, "%13d   %-60pS  %6d.%1d KB  (%d)\n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
			   get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024),
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    else
		        seq_printf(m, "%13d   %-60pS  %6d B  (%d)\n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].total_alloc_size),
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		} else {
		    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
		        seq_printf(m, "%13d   %-60pS  %6d (%d.%1d MB)\n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
			   get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576));
		    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
		        seq_printf(m, "%13d   %-60pS  %6d (%d.%1d KB) \n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
			   get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024));
		    else
		        seq_printf(m, "%13d   %-60pS  %6d (%1d B)\n", j + 1,
			   (void *)MLT_display_nodes[j].stk_trace[l],
			   atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   atomic_read(&MLT_display_nodes[j].total_alloc_size));
		}
	}

#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
	seq_printf(m, "\r\n\nOutstanding kmalloc_large allocations: %d \r\n\n", atomic_read(&kmalloc_large_cnt));
        if (!mlt_kl_enabled)
        {
	    seq_printf(m, "    Note: If Outstanding kmalloc_large allocations is increasing over time, there could\r\n");
	    seq_printf(m, "    be large size (> 2*PAGE_SIZE) allocations impacting available system memory.\r\n");
	    seq_printf(m, "    Please consider enabling mlt_kl in boot args \r\n");
	} else {
	    seq_printf(m, "    Note: If Outstanding kmalloc_large allocations is increasing over time, there could\r\n");
	    seq_printf(m, "    be large size (> 2*PAGE_SIZE) allocations impacting available system memory.\r\n");
	    seq_printf(m, "    check mlt_kl command output as well.\r\n");
	}
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
	seq_printf(m, "\r\nOutstanding vmalloc allocations: %d \r\n", atomic_read(&vmalloc_cnt));
	seq_printf(m, "\rOutstanding vmalloc memory: ");
        if ((atomic_read(&vmalloc_tot_size)/ 1048576) > 1)
                seq_printf(m, "%6d.%d MB \r\n", atomic_read(&vmalloc_tot_size)/1048576,
                    get_first_digit(atomic_read(&vmalloc_tot_size)%1048576));
        else if ((atomic_read(&vmalloc_tot_size)/ 1024) > 1)
                seq_printf(m, "%6d.%d KB \r\n", atomic_read(&vmalloc_tot_size)/1024,
                    get_first_digit(atomic_read(&vmalloc_tot_size)%1024));
        else
                seq_printf(m, "%6d B \r\n", atomic_read(&vmalloc_tot_size));

        if (!mlt_vm_enabled)
        {
	    seq_printf(m, "    Note: If Outstanding vmalloc allocations are increasing over time, there could\r\n");
	    seq_printf(m, "    be vmalloc allocations impacting available system memory.\r\n");
	    seq_printf(m, "    Please consider enabling mlt_vm in boot args \r\n\n");
	} else {
	    seq_printf(m, "    Note: If Outstanding vmalloc allocations are increasing over time, there could\r\n");
	    seq_printf(m, "    be vmalloc allocations impacting available system memory.\r\n");
	    seq_printf(m, "    check mlt_vm command output as well.\r\n\n");
	}
#endif

	return 0;
}

static int MLT_det_leaks_data_read(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	unsigned int k;

	count = 0;

        if (!mlt_enabled)
        {
            sprintf(page, "MLT not enabled.\r\n");
            count += strlen(page);
            *eof = 1;
            return count;
        }

	if (detail_entry_index <= 0)
	{
            sprintf(page, "Invalid detail entry index - negative numbers not allowed.\r\n");
            count += strlen(page);
            *eof = 1;
            return count;

	}

	if (detail_entry_index - 1 < cur_display_node_cnt) {
        	if (kmalloc_size_sort)
		{
		    sprintf(page, "Display Index   Stack Trace making the allocations"
				  "                 Total Memory allocated (Alloc Count)\r\n");
		    count += strlen(page);
		    sprintf(page + count, "-------------   "
			    "----------------------------------                 "
			    "-----------------------\r\n");
		    count += strlen(page + count);
		} else {
		    sprintf(page, "Display Index   Stack Trace making the allocations"
				  "                 Number of kmallocs made (Total Mem Allocated)\r\n");
		    count += strlen(page);
		    sprintf(page + count, "-------------   "
			"----------------------------------                 "
			"-----------------------\r\n");
		    count += strlen(page + count);
		}
		
        	if (kmalloc_size_sort)
		{
                    if ((atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size) / 1048576) > 1)
		        sprintf(page + count, "%13d   %-60pS %6d.%d MB (%d)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1048576,
			    get_first_digit(atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)%1048576),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt));
                    else if ((atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size) / 1024) > 1)
		        sprintf(page + count, "%13d   %-60pS %6d.%d KB (%d)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1024,
			    get_first_digit(atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)%1024),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt));
		    else
		        sprintf(page + count, "%13d   %-60pS %6d B (%d)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt));
		} else {
		    if ((atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1048576) > 1)
		        sprintf(page + count, "%13d   %-60pS %6d (%d.%d MB)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1048576,
			    get_first_digit(atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)%1048576));
		    else if ((atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1024) > 1)
		        sprintf(page + count, "%13d   %-60pS %6d (%d.%d KB)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)/1024,
			    get_first_digit(atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size)%1024));
		    else
		        sprintf(page + count, "%13d   %-60pS %6d (%d B)\n", detail_entry_index,
			    (void *)MLT_display_nodes[detail_entry_index - 1].stk_trace[0],
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].kmalloc_cnt),
			    atomic_read(&MLT_display_nodes[detail_entry_index - 1].total_alloc_size));
		}

		count += strlen(page + count);
		if (MLT_display_nodes[detail_entry_index - 1].stk_trace_len > MAX_MLT_HASH_STK_DEPTH)
		{
			sprintf(page + count, "stk_trace_len is > MAX_MLT_HASH_STK_DEPTH. Possible memory corruption\n");
			count += strlen(page + count);
		} else {
			for (k = 1;
		     	(k <
		      	MLT_display_nodes[detail_entry_index - 1].stk_trace_len);
		     	k++) {
				if ((count + 2*KSYM_SYMBOL_LEN) >= PAGE_SIZE )
				{
					printk("Page limit reached, so curtailing the output\r\n");
					break;
				}
				sprintf(page + count, "                %pS\n",
					(void *)MLT_display_nodes[detail_entry_index -
							  1].stk_trace[k]);
				count += strlen(page + count);
			}
		}
#if 0
		sprintf(page + count,
			"\n                (allocation unit size = %d \n"
			"                 total memory(in KB) allocated by this trace = %d"
			"\n\n                     pid = %d, task name = %s"
			")\n\n",
			MLT_display_nodes[detail_entry_index - 1].kmalloc_size,
			(MLT_display_nodes[detail_entry_index - 1].
			 kmalloc_size * MLT_display_nodes[detail_entry_index -
							  1].kmalloc_cnt) /
			1024);
		count += strlen(page + count);
#endif
#if 0
		MLT_display_nodes[detail_entry_index - 1].pid,
		    MLT_display_nodes[detail_entry_index - 1].task_name);
#endif
	} else {
		sprintf(page + count, "Invalid detail entry index \n");
		count += strlen(page + count);
	}
	*eof = 1;
	return count;
}

static int MLT_det_leaks_data_write(struct file *file, const char *buffer,
				    unsigned long count, void *data) {
	char buff[100], **end_ptr = NULL;

	if (count > 100)
		 return 0;	/* TBD: convert 100 to a macro */

	 copy_from_user(buff, buffer, count);
	 buff[count] = '\0';
	 detail_entry_index = simple_strtoul(buff, end_ptr, 10);	/* TBD: replace 10 by a macro */

	 return count;
} 

static int MLT_stats_data_open(struct inode *inode, struct file *file) {
	return seq_open(file, &MLT_stats_data_op);
} 

static int MLT_stats_data_show(struct seq_file *m, void *arg) {
	unsigned int i, j, k, max_ind, stats_var;

        if (!mlt_enabled) {
            seq_printf(m, "\r\nMLT not enabled. \r\n\n");
            return 0;
        }

	 stats_var = MLT_STATS_CLEAR_PERIOD;
	 seq_printf(m, "\r\n");
	 seq_printf(m, "\r\n");
	 seq_printf(m, "MLT Stats are valid if collected only after %d minutes from bootup \r\n", stats_var);
	 seq_printf(m, "In other cases such as boot time crashes etc, this info might indicate errors incorrectly \r\n");
	 seq_printf(m, "\r\n");
	 seq_printf(m, "\r\n");
	 seq_printf(m, "  Number of occurences        Stat/Error Name\r\n");
	 seq_printf(m,
		    "  ---------------------       --------------------- \r\n");
	for (i = 1; i < MLT_MAX_STAT; i++)
		 seq_printf(m, "%13d              %s \n", atomic_read(&MLT_stats[i]),
			    MLT_stats_names[i]);
	 seq_printf(m, "\n");

	if (list_stats_in_detail) {
		seq_printf(m,
			   "Detailed stats array contents (Latest occuring fisrt): \n\n");
		max_ind = atomic_read(&MLT_detailed_stats_cur_index);

		if (!max_ind)
		    return 0;

		if (max_ind >= MLT_MAX_STATS_NODES)
			max_ind = MLT_MAX_STATS_NODES -1;
			
		for (i = 0, k = max_ind - 1;
		     ((i < max_ind) && (i < max_detail_stats) && (k>0)); i++, k--) {
			seq_printf(m, "        Stats/Error Name: %s\n",
				   MLT_stats_names[MLT_detailed_stats[k].
						   statsID]);
			seq_printf(m, "        Stack Trace:\n");
			for (j = 0; (j < MLT_detailed_stats[k].stk_trace_len);
			     j++)
				seq_printf(m, "            %pS\n",
					   (void *)MLT_detailed_stats[k].
					   stk_trace[j]);
#if 0			 /*TBD*/
			if ((MLT_detailed_stats[i].statsID !=
			     MLT_NULL_PTR_INPUT)
			    || (MLT_detailed_stats[i].statsID !=
				MLT_UNINITIALIZED)
			    || (MLT_detailed_stats[i].statsID !=
				MLT_NULL_CACHE_PTR_INPUT))
				seq_printf(m, "Cache Name: %s\n",
					   MLT_stats_names[i].cache_name);
			if (MLT_detailed_stats[i].statsID ==
			    MLT_CACHE_SIZE_ERROR)
				seq_printf(m, "Cache Size: %d\n",
					   MLT_stats_names[i].
					   slab_cache_buff_size);
#endif
			seq_printf(m, "\n");
	}}

	return 0;
}

#ifdef CONFIG_SILKWORM_MLT_DEBUG

static int MLT_debug_config_write(struct file *file, const char *buffer,
				  unsigned long count, void *data) {
	char *buff, *buff1, **end_ptr = NULL;
	unsigned int i;

	if (count > 100)
		 return 0;	/* TBD: convert 100 to a macro */

	 copy_from_user(MLT_debug_conf_buff, buffer, count);
	 MLT_debug_conf_buff[count] = '\0';

	 buff = MLT_debug_conf_buff;
	for (i = 1; i <= 10 /* Max config entires */ ; i++) {
		buff1 = buff;
		while (MLT_isdigit(*buff))
			buff++;
		if (*buff != '\n') {
			if (*buff == ' ')
				buff++;
			else
				return 0;
		}

		switch (i) {
		case 1:
			display_hash_table = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 2:
			display_hash_index = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 3:
			max_display_cnt = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 4:
			display_hash_collisions =
			    simple_strtoul(buff1, end_ptr, 10);
			break;
		case 5:
			hash_random_events = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 6:
			induce_leaks = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 7:
			alloc_units = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 8:
			reduce_leaks = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 9:
			dealloc_units = simple_strtoul(buff1, end_ptr, 10);
			break;
		case 10:
			alloc_unit_size = simple_strtoul(buff1, end_ptr, 10);
			break;
		}
	}

	return count;
}

static int MLT_debug_config_read(char *page, char **start, off_t off, int count,
				 int *eof, void *data) {
	sprintf(page, "\n%s \n\n%s \n\n", MLT_debug_conf_buff,
		MLT_debug_conf_buff_format);
	*eof = 1;
	return (strlen(MLT_debug_conf_buff) +
		strlen(MLT_debug_conf_buff_format) + 4);
} 

static int MLT_debug_data_open(struct inode *inode, struct file *file) {
	return seq_open(file, &meminfra_hash_table_op);
} 

static int MLT_debug_data_show(struct seq_file *m, void *arg) {
	unsigned int i, total_entries = 0, 
	    over_collisions = 0, max_list_count=0,
	    MLT_collision_summary[10], count;
	MLT_hash_node_t *MLT_hash_node;

#if 0				/*TBD */
	if (hash_random_events) {
		simulate_record_mem_alloc();
		return 0;
	}

	if (induce_leaks && alloc_unit_size) {
		for (i = 0;
		     (i < MAX_INDUCED_MEMLEAKS) && (leak_count < alloc_units);
		     i++) {
			if (MLT_induced_leaks[i])
				i++;
			else {
				MLT_induced_leaks[i] =
				    kmalloc(alloc_unit_size, GFP_KERNEL);
				leak_count++;
			}
		}
	}

	if (reduce_leaks) {
		for (i = 0;
		     (i < MAX_INDUCED_MEMLEAKS)
		     && (deleak_count < dealloc_units); i++) {
			if (MLT_induced_leaks[i]) {
				kfree(MLT_induced_leaks[i]);
				MLT_induced_leaks[i] = NULL;
				deleak_count++;
			} else
				i++;
		}
	}

	if (display_hash_table) {
		if (display_hash_index && max_display_cnt) {
			for (i = 0, MLT_hash_node =
			     MLT_hash_table[display_hash_index - 1];
			     (MLT_hash_node) && (i < max_display_cnt);
			     MLT_hash_node = MLT_hash_node->next, i++) {
				for (k = 0; k < MLT_hash_node->stk_trace_len;
				     k++)
					seq_printf(m, "%x ",
						   MLT_hash_node->stk_trace[k]);
				seq_printf(m, "\n");
			}
			return 0;
		}
	}
#endif

	if (display_hash_collisions) {
		for (i=0; i< 10; i++)
			MLT_collision_summary[i] =0;

		for (i=0; i< MLT_MAX_HASH; i++)
		{
        		MLT_hash_node = &MLT_hash_table[i];
			count =0;
        		list_for_each_entry(MLT_hash_node,
                            		&MLT_hash_table[i].MLT_hash_list_next,
                            		MLT_hash_list_next) {
				count ++;
        		}

			if (count < 10)
				MLT_collision_summary[count]++;
			else {
				over_collisions = 1;
				if (max_list_count < count)
					max_list_count = count;
			}
			total_entries += count;
        	}

		seq_printf(m, "Hash Table Collision Data \n\n");
		seq_printf(m, "List count         Number of hash entries\n");
		seq_printf(m, "---------------    ---------------------- \n");

		for (i = 1; i < 10; i++)
			seq_printf(m, "%5d               %5d     \n", i,
				   MLT_collision_summary[i]);

		if (over_collisions)
		{
			seq_printf(m,
				   "Some Hash indices have more than 10 collisions (not displayed above)\n");
			seq_printf(m, "Max Hash list size: %d \n", max_list_count);
		}

		seq_printf(m, "\n\n Total entries in hash table = %d \n",
			   total_entries);
	}

	return 0;
}
#endif

/**************************************************************************************************************************/
/**************************************************************************************************************************/
/*                                           MISCELLANEOUS LOCAL UTILITY FUNCTIONS                                        */
/**************************************************************************************************************************/
/**************************************************************************************************************************/

static void MLT_add_mem_wrp_func(char *func_name) {
	strcpy(wrp_stk_func[wrp_stk_fn_cnt++], func_name);
} 

static void MLT_log_stk_trace(int errCode) {
	unsigned int j, tmp_ind;
	static bool first_time = 1;

	if ((errCode == MLT_SUCCESS) || (errCode == MLT_UNINITIALIZED))
		return;


	tmp_ind = atomic_inc_return(&MLT_detailed_stats_cur_index) -1;
	if (tmp_ind >= MLT_MAX_STATS_NODES) {
		atomic_dec_return(&MLT_detailed_stats_cur_index);
		return;
	}

	MLT_detailed_stats[tmp_ind].statsID = errCode;
	/* Get stack trace */
	MLT_detailed_stats[tmp_ind].stk_trace_len = 
	    mlt_get_stack_trace(MLT_detailed_stats[tmp_ind].stk_trace);

	if (first_time)
	{
	    if ((errCode == MLT_CORRUPTED_MAGIC_NUM) || 
	        (errCode == MLT_BAD_HASH_INDEX) || 
	        (errCode == MLT_NULL_HASH_NODE_PTR) || 
	        (errCode == MLT_HASH_PTR_NOT_IN_LIST)) {
		    printk("MLT Error event: %s\n", MLT_stats_names[errCode]);
		    printk("Stack Trace:\n");
		    for (j = 0;
		         (j <
		          MLT_detailed_stats[tmp_ind].
		          stk_trace_len); j++)
			    printk("            %pS\n",
			           (void *)
			           MLT_detailed_stats[tmp_ind].
			           stk_trace[j]);
		    printk("\n");
	    }
	    first_time = 0;
	}
	/* TBD: cache name & cache buffer size also to be stored */

	if ((rollover_stats_arr)
	    && (atomic_read(&MLT_detailed_stats_cur_index) >= MLT_MAX_STATS_NODES))
		atomic_set(&MLT_detailed_stats_cur_index, 0);

}

static __always_inline unsigned int MLT_hash(unsigned long *stk_trace,
			       unsigned int stk_trace_len,
			       unsigned int *stk_fn_hash) {

	/* IR: let's try this hash, followed by Bob Jenkins hash */
	*stk_fn_hash = JSHash((char *)stk_trace, stk_trace_len);
	*stk_fn_hash = bob_jenkins_hash(*stk_fn_hash);
	return (*stk_fn_hash & (MLT_MAX_HASH - 1));
} 

static void insert_sort(MLT_hash_node_t *hash_node) 
{
	int j, k, inserted =0, right_end=0;

	/* Find position of the new entry in the array */
	for (j = 0; j < cur_display_node_cnt; j++) {
                if (kmalloc_size_sort)
		{
			if (atomic_read(&MLT_display_nodes[j].total_alloc_size) <
			    atomic_read(&hash_node->total_alloc_size))
			    break;
		} else {
			if (atomic_read(&MLT_display_nodes[j].kmalloc_cnt) <
			    atomic_read(&hash_node->kmalloc_cnt))
			    break;
		}
	}
	/* If new entry is superior to existing entries, insert*/
	if (j< cur_display_node_cnt)
	{
		/* Shift the last element of the array to right */
		if (cur_display_node_cnt < display_cnt)
		{
			memcpy(&MLT_display_nodes[cur_display_node_cnt], 
			       &MLT_display_nodes[cur_display_node_cnt-1],
				sizeof(MLT_hash_node_t));
			right_end = cur_display_node_cnt-1;
			cur_display_node_cnt++;
		} else right_end = cur_display_node_cnt-1;
		/* Shift the array elements one down to accomodate the new entry,
	 	* drop last one */
		for (k=right_end; k>j; k--)
			memcpy(&MLT_display_nodes[k], &MLT_display_nodes[k-1],
			       sizeof(MLT_hash_node_t));
		/* Copy the current entry to the array */
		memcpy(&MLT_display_nodes[j], hash_node, sizeof(MLT_hash_node_t));

		inserted = 1;
	} 

        /* If new entry is inferior to existing entries & we still have space, insert */
	if ((!inserted) && (cur_display_node_cnt < display_cnt))
	{
		memcpy(&MLT_display_nodes[cur_display_node_cnt], hash_node, 
		       sizeof(MLT_hash_node_t));
		cur_display_node_cnt++;
	}
}

int mlt_garbage_collector(void *arg) {
	static unsigned int list_index;
#ifdef MLT_DEBUG
	static unsigned int max_chain_len = 0;
#endif
	struct MLT_garbage_collection_params *cp =
	    (struct MLT_garbage_collection_params *)arg;
	int entries = 8;	/* default value */
	int sleep_interval = 20;
	int stats_clear =1, time_elapsed = 0;
	unsigned long flags;

	if (cp) {
		/* get non-default parameters */
		entries = cp->entries;
		sleep_interval = cp->sleep_interval;
	}

	while (MLT_initialized) {
		int i;
		for (i = 0; i < entries;
		     i++, list_index = (list_index + 1) % MLT_MAX_HASH) {
			MLT_hash_node_t *pos, *n;
			int x = 0;

#ifdef MLT_DEBUG
			if (x > max_chain_len) {
				max_chain_len = x;
				printk
				    ("%s: deleted %d nodes at position %d, hash value = %8.8X, len = %d \n",
				     __FUNCTION__, max_chain_len, list_index,
				     MLT_hash_table[list_index].stk_fn_hash,
				     MLT_hash_table[list_index].stk_trace_len);
			}
#endif
                        MLT_WRITE_LOCK(list_index);
                        list_for_each_entry_safe(pos, n, &MLT_hash_table[list_index].
                                                 MLT_hash_list_next, MLT_hash_list_next) {
                                if (atomic_read(&pos->kmalloc_cnt) == 0)
                                {
                                        list_del(&pos->MLT_hash_list_next);
                                        kmem_cache_free_mlt_bypass(MLT_hash_nodes_pool, pos);
                                        x++;
#ifdef MLT_DEBUG
                                        MLT_hash_table[list_index].chain_len--;
                                        MLT_PROCESS_ERROR(MLT_NODE_FREED);
#endif
                                }

                        }
                        MLT_WRITE_UNLOCK(list_index);
		}
		
		/* Clear MLT Stats 5 minnutes after reboot */
		if (stats_clear)
		{
			time_elapsed += sleep_interval;
			if (time_elapsed >= MLT_STATS_CLEAR_PERIOD*60*1000 /* MLT_STATS_CLEAR_PERIOD min*/)
			{
				stats_clear = 0;
				memset(&MLT_stats, 0, sizeof(MLT_stats));
				memset(&MLT_detailed_stats, 0, sizeof(MLT_detailed_stats));
				atomic_set(&MLT_detailed_stats_cur_index, 0);
				printk(KERN_INFO "MLT stats cleared \n");
			}
		}
		
		msleep(sleep_interval);

	}

	return 0;
}
int MLT_get_panicdump_info(void *pdHandle, unsigned int event, void *cbArg,
			   char **buff, int *len) {
	unsigned int i, j, k, l, count = 0, stats_var = 0;
	char buff1[300];
	unsigned int max_ind, max_len;
	char buff2[200];
	MLT_hash_node_t *MLT_hash_node;
	char tmp_str1[MAX_MLT_FUNC_NAME_LEN], *tmp_str2,
	    func_name[MAX_MLT_FUNC_NAME_LEN];
	unsigned long flags;

	if (unlikely(!MLT_initialized))
        {
                *buff = MLT_PD_tmp_buff1;
                *len = strlen(MLT_PD_tmp_buff1);
                return 0;
        }

        if (!mlt_enabled)
        {
                *buff = MLT_PD_tmp_buff;
                *len = strlen(MLT_PD_tmp_buff);
                return 0;
        }

	/*
	 * MLT panicdump buffer region has been fill with the MLT info when
	 * system out of memory.  Otherwise get the MLT info when system panic.
	 */
	if (MLT_PD_buff_len) {
		count = MLT_PD_buff_len;
		goto mlt_pd_out;
	}

	sprintf(buff2, "MLT panic dump info exceeded allcoated buffer size");
	max_len = MLT_PANIC_DUMP_BUFF_SIZE - strlen(buff2) - 50 /* Leaving 50 more bytes safe side */;

	count = 0;
	kmalloc_size_sort = 1;

	do {
        	cur_display_node_cnt = 0;
        	for (i = 0; i < MLT_MAX_HASH; i++) {
                	MLT_READ_LOCK(i);
                	list_for_each_entry(MLT_hash_node, 
                        	&MLT_hash_table[i].MLT_hash_list_next, MLT_hash_list_next)
                	{
                    	    insert_sort(MLT_hash_node);
                	}
                	MLT_READ_UNLOCK(i);
        	}
	
		if (count+2 < max_len)
		{
			sprintf(MLT_PD_buff+count, "\n\n");
			count += 2;
		} else 
			goto buff_too_large;
	
		if (kmalloc_size_sort)
			sprintf(buff1, "Dumping Memory Leak Traces (MLT) - KMALLOC SIZE SORTED");
		else
			sprintf(buff1, "Dumping Memory Leak Traces (MLT) - KMALLOC COUNT SORTED");
	
		if ((count + strlen(buff1)) < max_len)
		{ 
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
		} else 
			goto buff_too_large;
	
		if (count+2 < max_len)
		{
			sprintf(MLT_PD_buff + count, "\n\n");
			count += 2;
		} else 
			goto buff_too_large;

        	if (kmalloc_size_sort)
        	{
	    		sprintf(buff1,"Display Index   Stack Trace making the allocations"
			  	"                  Number of kmallocs made (Total Mem Allocated)\n");
        	} else {
	    		sprintf(buff1,"Display Index   Stack Trace making the allocations"
			  	"                  Total Memory allocated (Alloc Count)\n");
		}
	
	    	if ((count + strlen(buff1)) < max_len)
	    	{ 
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
	    	} else 
			goto buff_too_large;
	
        	if (kmalloc_size_sort)
        	{
	    		sprintf(buff1,"-------------   ----------------------------------"
		          	"                  -----------------------\n");
        	} else {
	    		sprintf(buff1,"-------------   ----------------------------------"
			  	"                  -------------------\n");
		}

	    	if ((count + strlen(buff1)) < max_len)
	    	{ 
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
	    	} else 
			goto buff_too_large;
	
		for (j = 0; ((j < cur_display_node_cnt) && (j < MLT_PANIC_DUMP_DISPLAY_CNT)) ; j++) {
			for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
				if (is_vmalloc_or_module_addr((void *)MLT_display_nodes[j].stk_trace[l]))
					break;
			}
			if (l == MLT_display_nodes[j].stk_trace_len) {
				for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
					memset(tmp_str1, 0, MAX_MLT_FUNC_NAME_LEN);
					memset(func_name, 0, MAX_MLT_FUNC_NAME_LEN);
					tmp_str2 = NULL;
					//strcpy(tmp_str1, MLT_display_nodes[j].stk_trace[l]);
					sprintf(tmp_str1, "%pS",
						(void *)MLT_display_nodes[j].stk_trace[l]);
					tmp_str2 = strchr(tmp_str1, '+');
					if (!tmp_str2)
						break;
					*tmp_str2 = '\0';
					strcpy(func_name, tmp_str1);
		
					for (k = 0; k < wrp_stk_fn_cnt; k++)
						if (!strcmp(func_name, wrp_stk_func[k]))
							break;
					if (k == wrp_stk_fn_cnt)
						break;
				}
			}
	
        		if (kmalloc_size_sort)
        		{
		    	    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
		        	sprintf(buff1,"%13d   %-60pS  %6d.%1d MB  (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    	    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
		        	sprintf(buff1,"%13d   %-60pS  %6d.%1d KB  (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    	    else
		        	sprintf(buff1,"%13d   %-60pS  %6d B  (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
			} else {
		    	    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
		        	sprintf(buff1,"%13d   %-60pS  %6d (%d.%1d MB)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576));
		    	    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
		        	sprintf(buff1,"%13d   %-60pS  %6d (%d.%1d KB) \n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024));
		    	    else
		        	sprintf(buff1,"%13d   %-60pS  %6d (%1d B)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[l],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size));
			}

			if ((count + strlen(buff1)) < max_len)
			{ 
	    			sprintf(MLT_PD_buff + count, buff1);
	    			count += strlen(buff1);
			} else 
	    			goto buff_too_large;
		}
	
		if (count+2 < max_len)
		{
			sprintf(MLT_PD_buff + count, "\n\n");
			count += 2;
		} else 
			goto buff_too_large;

        	if (kmalloc_size_sort)
		{
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
			sprintf(buff1, "\r\n\nOutstanding kmalloc_large allocations: %d \r\n\n", 
				atomic_read(&kmalloc_large_cnt));
			if ((count + strlen(buff1)) < max_len)
			{ 
	    			sprintf(MLT_PD_buff + count, buff1);
	    			count += strlen(buff1);
			} else 
	    			goto buff_too_large;
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
			sprintf(buff1, "\r\nOutstanding vmalloc allocations: %d \r\n", atomic_read(&vmalloc_cnt));
			if ((count + strlen(buff1)) < max_len)
			{ 
	    			sprintf(MLT_PD_buff + count, buff1);
	    			count += strlen(buff1);
			} else 
	    			goto buff_too_large;

			sprintf(buff1, "\rOutstanding vmalloc memory: ");
			if ((count + strlen(buff1)) < max_len)
			{ 
	    			sprintf(MLT_PD_buff + count, buff1);
	    			count += strlen(buff1);
			} else 
	    			goto buff_too_large;

        		if ((atomic_read(&vmalloc_tot_size)/ 1048576) > 1)
			{
                		sprintf(buff1, "%6d.%d MB \r\n", atomic_read(&vmalloc_tot_size)/1048576,
                    		get_first_digit(atomic_read(&vmalloc_tot_size)%1048576));
				if ((count + strlen(buff1)) < max_len)
				{ 
	    				sprintf(MLT_PD_buff + count, buff1);
	    				count += strlen(buff1);
				} else 
	    				goto buff_too_large;

        		} else if ((atomic_read(&vmalloc_tot_size)/ 1024) > 1) {
			
                		sprintf(buff1, "%6d.%d KB \r\n", atomic_read(&vmalloc_tot_size)/1024,
                    		get_first_digit(atomic_read(&vmalloc_tot_size)%1024));
				if ((count + strlen(buff1)) < max_len)
				{ 
	    				sprintf(MLT_PD_buff + count, buff1);
	    				count += strlen(buff1);
				} else 
	    				goto buff_too_large;

        		} else {
                		sprintf(buff1, "%6d B \r\n", atomic_read(&vmalloc_tot_size));
				if ((count + strlen(buff1)) < max_len)
				{ 
	    				sprintf(MLT_PD_buff + count, buff1);
	    				count += strlen(buff1);
				} else 
	    				goto buff_too_large;

			}
#endif
			if (count+2 < max_len)
			{
				sprintf(MLT_PD_buff + count, "\n\n");
				count += 2;
			} else 
				goto buff_too_large;
	
		}

        	if (kmalloc_size_sort)
		{
	    		sprintf(buff1, "Display Index   Stack Trace making the allocations"
			  		"                  Number of kmallocs made (Total Mem Allocated)\n");
        	} else  {
	    		sprintf(buff1, "Display Index   Stack Trace making the allocations"
			  		"                  Total Memory allocated (Alloc Count)\n");
		}
	
		if ((count + strlen(buff1)) < max_len)
		{ 
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
		} else 
			goto buff_too_large;
	
        	if (kmalloc_size_sort)
	    		sprintf(buff1, "-------------   ----------------------------------"
		          		"                  -----------------------\n");
		else
	    		sprintf(buff1, "-------------   ----------------------------------"
			  		"                  -------------------\n");
	
		if ((count + strlen(buff1)) < max_len)
		{ 
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
		} else 
			goto buff_too_large;
	
		if (count+1 < max_len)
		{
			sprintf(MLT_PD_buff + count, "\n");
			count += 1;
		} else 
			goto buff_too_large;
	
		for (j = 0; ((j < cur_display_node_cnt) && (j < MLT_PANIC_DUMP_DISPLAY_CNT)); j++) {
	
        		if (kmalloc_size_sort)
        		{
		    	    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1048576) > 1)
		        	sprintf(buff1, "%13d   %-60pS  %6d.%d MB (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size)/1048576,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1048576),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    	    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1024) > 1)
		        	sprintf(buff1, "%13d   %-60pS  %6d.%d KB (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size)/1024,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1024),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
		    	    else 
		        	sprintf(buff1, "%13d   %-60pS  %6d B (%d)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size),
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
			} else {
		    	    if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1048576) > 1)
		        	sprintf(buff1, "%13d   %-60pS  %6d (%d.%d MB)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size)/1048576,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1048576));
		    	    else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1024) > 1)
		        	sprintf(buff1, "%13d   %-60pS  %6d (%d.%d KB)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size)/1024,
			   	get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1024));
		    	    else 
		        	sprintf(buff1, "%13d   %-60pS  %6d (%d B)\n", j + 1,
			   	(void *)MLT_display_nodes[j].stk_trace[0],
			   	atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
			   	atomic_read(&MLT_display_nodes[j].total_alloc_size));
			}
			if ((count + strlen(buff1)) < max_len)
			{ 
				sprintf(MLT_PD_buff + count, buff1);
				count += strlen(buff1);
			} else 
				goto buff_too_large;
	
			for (k = 1; (k < MLT_display_nodes[j].stk_trace_len); k++) {
				sprintf(buff1, "                %pS",
					(void *)MLT_display_nodes[j].stk_trace[k]);
	
				if ((count + strlen(buff1)) < max_len)
				{ 
					sprintf(MLT_PD_buff + count, buff1);
					count += strlen(buff1);
				} else 
					goto buff_too_large;
	
				if (count+1 < max_len)
				{
					sprintf(MLT_PD_buff + count, "\n");
					count += 1;
				} else 
					goto buff_too_large;
			}
	
			if (count+1 < max_len)
			{
				sprintf(MLT_PD_buff + count, "\n");
				count += 1;
			} else 
				goto buff_too_large;
		}
	
		if (count+2 < max_len)
		{
			sprintf(MLT_PD_buff + count, "\n\n");
			count += 2;
		} else 
			goto buff_too_large;

		if (kmalloc_size_sort) 
			kmalloc_size_sort =0;
		else 
			break;

	} while (1);


	stats_var = MLT_STATS_CLEAR_PERIOD;
	sprintf(buff1, "MLT Stats are valid if collected only after %d minutes from bootup \r\n", stats_var);
	if (count+strlen(buff1) < max_len)
	{
		sprintf(MLT_PD_buff + count, buff1);
		count += strlen(buff1);
	} else 
		goto buff_too_large;

	sprintf(buff1, "In other cases such as boot time crashes etc, this info might indicate errors incorrectly \r\n");
	if (count+strlen(buff1) < max_len)
	{
		sprintf(MLT_PD_buff + count, buff1);
		count += strlen(buff1);
	} else 
		goto buff_too_large;

	if (count+2 < max_len)
	{
		sprintf(buff1, "\n\n");
		count += 2;
	} else 
		goto buff_too_large;

	sprintf(buff1, "  Number of occurences        Stat/Error Name");
	if (count+strlen(buff1) < max_len)
	{
		sprintf(MLT_PD_buff + count, buff1);
		count += strlen(buff1);
	} else 
		goto buff_too_large;

	if (count+2 < max_len)
	{
		sprintf(MLT_PD_buff + count, "\n\n");
		count += 2;
	} else 
		goto buff_too_large;

	sprintf(buff1, "  ---------------------       --------------------- ");
	if (count+strlen(buff1) < max_len)
	{
		sprintf(MLT_PD_buff + count, buff1);
		count += strlen(buff1);
	} else 
		goto buff_too_large;

	if (count+2 < max_len)
	{
		sprintf(MLT_PD_buff + count, "\n\n");
		count += 2;
	} else 
		goto buff_too_large;

	for (i = 1; i < MLT_MAX_STAT; i++)
	{
		sprintf(buff1, "%13d              %s ", atomic_read(&MLT_stats[i]),
			    MLT_stats_names[i]);
		if (count+strlen(buff1) < max_len)
		{
			sprintf(MLT_PD_buff + count, buff1);
			count += strlen(buff1);
		} else 
			goto buff_too_large;

		if (count+1 < max_len)
		{
			sprintf(MLT_PD_buff + count, "\n");
			count += 1;
		} else 
			goto buff_too_large;
	}

	sprintf(buff1,
	   "Detailed stats array contents (Latest occuring fisrt): ");
	if (count+strlen(buff1) < max_len)
	{
		sprintf(MLT_PD_buff + count, buff1);
		count += strlen(buff1);
	} else 
		goto buff_too_large;

	if (count+2 < max_len)
	{
		sprintf(MLT_PD_buff + count, "\n\n");
		count += 2;
	} else 
		goto buff_too_large;

	max_ind = atomic_read(&MLT_detailed_stats_cur_index);

	if (!max_ind)
		goto mlt_pd_out;

	if (max_ind >= MLT_MAX_STATS_NODES)
		max_ind = MLT_MAX_STATS_NODES -1;

	for (i = 0, k = max_ind - 1;
	     ((i < max_ind) && (i < max_detail_stats) && (k>0)); i++, k--) 
	{
		if (MLT_detailed_stats[k].statsID != MLT_UNINITIALIZED) 
		{
			sprintf(buff1, "        Stats/Error Name: %s",
			   	MLT_stats_names[MLT_detailed_stats[k].statsID]);
			if (count+strlen(buff1) < max_len)
			{
				sprintf(MLT_PD_buff + count, buff1);
				count += strlen(buff1);
			} else 
				goto buff_too_large;

			if (count+1 < max_len)
			{
				sprintf(MLT_PD_buff + count, "\n");
				count += 1;
			} else 
				goto buff_too_large;

			sprintf(buff1, "        Stack Trace:");
			if (count+strlen(buff1) < max_len)
			{
				sprintf(MLT_PD_buff + count, buff1);
				count += strlen(buff1);
			} else 
				goto buff_too_large;

			if (count+1 < max_len)
			{
				sprintf(MLT_PD_buff + count, "\n");
				count += 1;
			} else 
				goto buff_too_large;

			for (j = 0; (j < MLT_detailed_stats[k].stk_trace_len); j++)
			{
				sprintf(buff1, "            %pS",
				   	(void *)MLT_detailed_stats[k].stk_trace[j]);
				if (count+strlen(buff1) < max_len)
				{
					sprintf(MLT_PD_buff + count, buff1);
					count += strlen(buff1);
				} else 
					goto buff_too_large;

				if (count+1 < max_len)
				{
					sprintf(MLT_PD_buff + count, "\n");
					count += 1;
				} else 
					goto buff_too_large;
			}

			if (count+1 < max_len)
			{
				sprintf(MLT_PD_buff + count, "\n");
				count += 1;
			} else 
				goto buff_too_large;
		}
	}

	goto mlt_pd_out;

buff_too_large:
	printk(buff2);
	sprintf(MLT_PD_buff + count, buff2);
	count += strlen(buff2);

mlt_pd_out:
	MLT_PD_buff_len = count;
	*buff = MLT_PD_buff;
	*len = count;
	return 0;

}

EXPORT_SYMBOL(MLT_get_panicdump_info);

int MLT_print_panicdump_info(void)
{
        unsigned int i, j, k, l, stats_var = 0;
        unsigned int max_ind;
        MLT_hash_node_t *MLT_hash_node;
        char tmp_str1[MAX_MLT_FUNC_NAME_LEN], *tmp_str2,
            func_name[MAX_MLT_FUNC_NAME_LEN];
	unsigned long flags;

        if (!mlt_enabled)
        {
                printk(KERN_CRIT "MLT not enabled. \r\n");
                return 0;
        }

	if (unlikely(!MLT_initialized))
        {
                printk(KERN_CRIT "\nMLT not initlialized yet.\r\n");
                return 0;
        }

        kmalloc_size_sort = 1;

        do {
                cur_display_node_cnt = 0;
                for (i = 0; i < MLT_MAX_HASH; i++) {
                	MLT_READ_LOCK(i);
                        list_for_each_entry(MLT_hash_node,
                                &MLT_hash_table[i].MLT_hash_list_next, MLT_hash_list_next)
                        {
                            insert_sort(MLT_hash_node);
                        }
                	MLT_READ_UNLOCK(i);
                }

                printk(KERN_CRIT "\n\n");

                if (kmalloc_size_sort)
                        printk(KERN_CRIT "Dumping Memory Leak Traces (MLT) - KMALLOC SIZE SORTED");
                else
                        printk(KERN_CRIT "Dumping Memory Leak Traces (MLT) - KMALLOC COUNT SORTED");

                printk(KERN_CRIT "\n\n");

                if (kmalloc_size_sort)
                {
                        printk(KERN_CRIT "Display Index   Stack Trace making the allocations"
                                "                  Number of kmallocs made (Total Mem Allocated)\n");
                } else {
                        printk(KERN_CRIT "Display Index   Stack Trace making the allocations"
                                "                  Total Memory allocated (Alloc Count)\n");
                }

                if (kmalloc_size_sort)
                {
                        printk(KERN_CRIT "-------------   ----------------------------------"
                                "                  -----------------------\n");
                } else {
                        printk(KERN_CRIT "-------------   ----------------------------------"
                                "                  -------------------\n");
                }

                for (j = 0; ((j < cur_display_node_cnt) && (j < MLT_PANIC_DUMP_DISPLAY_CNT)) ; j++) {
                        for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
                                if (is_vmalloc_or_module_addr((void *)MLT_display_nodes[j].stk_trace[l]))
                                        break;
                        }
                        if (l == MLT_display_nodes[j].stk_trace_len) {
                                for (l = 0; l < MLT_display_nodes[j].stk_trace_len; l++) {
                                        memset(tmp_str1, 0, MAX_MLT_FUNC_NAME_LEN);
                                        memset(func_name, 0, MAX_MLT_FUNC_NAME_LEN);
                                        tmp_str2 = NULL;
                                        //strcpy(tmp_str1, MLT_display_nodes[j].stk_trace[l]);
                                        sprintf(tmp_str1, "%pS",
                                                (void *)MLT_display_nodes[j].stk_trace[l]);
                                        tmp_str2 = strchr(tmp_str1, '+');
                                        if (!tmp_str2)
                                                break;
                                        *tmp_str2 = '\0';
                                        strcpy(func_name, tmp_str1);

                                        for (k = 0; k < wrp_stk_fn_cnt; k++)
                                                if (!strcmp(func_name, wrp_stk_func[k]))
                                                        break;
                                        if (k == wrp_stk_fn_cnt)
                                                break;
                                }
                        }

                        if (kmalloc_size_sort)
                        {
                            if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
                                printk(KERN_CRIT "%13d   %-60pS  %6d.%1d MB  (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                            else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
                                printk(KERN_CRIT "%13d   %-60pS  %6d.%1d KB  (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                            else
                                printk(KERN_CRIT "%13d   %-60pS  %6d B  (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                        } else {
                            if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576) > 1)
                                printk(KERN_CRIT "%13d   %-60pS  %6d (%d.%1d MB)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size) /1048576,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1048576));
                            else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024) > 1)
                                printk(KERN_CRIT "%13d   %-60pS  %6d (%d.%1d KB) \n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size) /1024,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size) %1024));
                            else
                                printk(KERN_CRIT "%13d   %-60pS  %6d (%1d B)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[l],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size));
                        }
                }

                printk(KERN_CRIT "\n\n");

		if (kmalloc_size_sort)
		{ 
#ifdef CONFIG_SILKWORM_MLT_KMALLOC_LARGE
			printk(KERN_CRIT, "\r\n\nOutstanding kmalloc_large allocations: %d \r\n\n",
			       atomic_read(&kmalloc_large_cnt));
#endif

#ifdef CONFIG_SILKWORM_MLT_VMALLOC
			printk(KERN_CRIT, "\r\nOutstanding vmalloc allocations: %d \r\n", 
			       atomic_read(&vmalloc_cnt));
			printk(KERN_CRIT, "\rOutstanding vmalloc memory: ");
        		if ((atomic_read(&vmalloc_tot_size)/ 1048576) > 1)
                		printk(KERN_CRIT, "%6d.%d MB \r\n", atomic_read(&vmalloc_tot_size)/1048576,
                    		get_first_digit(atomic_read(&vmalloc_tot_size)%1048576));
        		else if ((atomic_read(&vmalloc_tot_size)/ 1024) > 1)
                		printk(KERN_CRIT, "%6d.%d KB \r\n", atomic_read(&vmalloc_tot_size)/1024,
                    		get_first_digit(atomic_read(&vmalloc_tot_size)%1024));
        		else
                		printk(KERN_CRIT, "%6d B \r\n", atomic_read(&vmalloc_tot_size));
#endif
                	printk(KERN_CRIT "\n\n");
		}

		if (kmalloc_size_sort)
		{ 
			if (!(console_mlt & MLT_CONSOLE_SIZE_DETAILED))
			{
                        	kmalloc_size_sort =0;
				continue;
			}
		} else {
			if (!(console_mlt & MLT_CONSOLE_CNT_DETAILED))
                        	break;
		}

                if (kmalloc_size_sort)
                {
                        printk(KERN_CRIT  "Display Index   Stack Trace making the allocations"
                                        "                  Number of kmallocs made (Total Mem Allocated)\n");
                } else  {
                        printk(KERN_CRIT  "Display Index   Stack Trace making the allocations"
                                        "                  Total Memory allocated (Alloc Count)\n");
                }

                if (kmalloc_size_sort)
                        printk(KERN_CRIT  "-------------   ----------------------------------"
                                        "                  -----------------------\n");
                else
                        printk(KERN_CRIT  "-------------   ----------------------------------"
                                        "                  -------------------\n");

                printk(KERN_CRIT "\n");

                for (j = 0; ((j < cur_display_node_cnt) && (j < MLT_OOM_DETAILED_DUMP_DISPLAY_CNT)); j++) {

                        if (kmalloc_size_sort)
                        {
                            if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1048576) > 1)
                                printk(KERN_CRIT  "%13d   %-60pS  %6d.%d MB (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size)/1048576,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1048576),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                            else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1024) > 1)
                                printk(KERN_CRIT  "%13d   %-60pS  %6d.%d KB (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size)/1024,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1024),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                            else
                                printk(KERN_CRIT  "%13d   %-60pS  %6d B (%d)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].total_alloc_size),
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt));
                        } else {
                            if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1048576) > 1)
                                printk(KERN_CRIT  "%13d   %-60pS  %6d (%d.%d MB)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size)/1048576,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1048576));
                            else if ((atomic_read(&MLT_display_nodes[j].total_alloc_size) / 1024) > 1)
                                printk(KERN_CRIT  "%13d   %-60pS  %6d (%d.%d KB)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size)/1024,
                                get_first_digit(atomic_read(&MLT_display_nodes[j].total_alloc_size)%1024));
                            else
                                printk(KERN_CRIT  "%13d   %-60pS  %6d (%d B)\n", j + 1,
                                (void *)MLT_display_nodes[j].stk_trace[0],
                                atomic_read(&MLT_display_nodes[j].kmalloc_cnt),
                                atomic_read(&MLT_display_nodes[j].total_alloc_size));
                        }

                        for (k = 1; (k < MLT_display_nodes[j].stk_trace_len); k++) {
                                printk(KERN_CRIT  "                %pS\n",
                                        (void *)MLT_display_nodes[j].stk_trace[k]);
                        }

                        printk(KERN_CRIT "\n");
                }

                printk(KERN_CRIT "\n\n");

                if (kmalloc_size_sort)
                        kmalloc_size_sort =0;
                else
                        break;
        } while (1);


        stats_var = MLT_STATS_CLEAR_PERIOD;
        printk(KERN_CRIT  "MLT Stats are valid if collected only after %d minutes from bootup \r\n", stats_var);
        printk(KERN_CRIT  "In other cases such as boot time crashes etc, this info might indicate errors incorrectly \r\n\n\n");

        printk(KERN_CRIT  "  Number of occurences        Stat/Error Name\n");
        printk(KERN_CRIT  "  ---------------------       --------------------- \n\n");

        for (i = 1; i < MLT_MAX_STAT; i++)
        {
                printk(KERN_CRIT  "%13d              %s \n", atomic_read(&MLT_stats[i]),
                            MLT_stats_names[i]);
        }

	if (!(console_mlt & MLT_CONSOLE_STATS_DETAILED))
		return 0;

        max_ind = atomic_read(&MLT_detailed_stats_cur_index);

        if (!max_ind)
                return 0;

        if (max_ind >= MLT_MAX_STATS_NODES)
                max_ind = MLT_MAX_STATS_NODES -1;

        printk(KERN_CRIT 
           "Detailed stats array contents (Latest occuring fisrt): \n\n");

        for (i = 0, k = max_ind - 1;
             ((i < max_ind) && (i < max_detail_stats) && (k>0)); i++, k--)
        {
                if (MLT_detailed_stats[k].statsID != MLT_UNINITIALIZED)
                {
                        printk(KERN_CRIT  "        Stats/Error Name: %s\n",
                                MLT_stats_names[MLT_detailed_stats[k].statsID]);
                        printk(KERN_CRIT  "        Stack Trace:\n");

                        for (j = 0; (j < MLT_detailed_stats[k].stk_trace_len); j++)
                        {
                                printk(KERN_CRIT  "            %pS\n",
                                        (void *)MLT_detailed_stats[k].stk_trace[j]);
                        }

                        printk(KERN_CRIT "\n");
                }
        }

        return 0;

}

EXPORT_SYMBOL(MLT_print_panicdump_info);

module_init(MLT_init);
module_exit(MLT_deinit);

#endif
