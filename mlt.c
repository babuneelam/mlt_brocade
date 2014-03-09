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

//#define PRINT printk(KERN_DEBUG"%s %d \r\n", __FUNCTION__, __LINE__)
#define PRINT

int 
MLT_init(void);
int MLT_dump_traces(void);

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
/* If MLT_conf_buff is modified, modify even the script at 
 * /vobs/projects/springboard/fabos/src/utils/sys/mlt
 */
static char MLT_conf_buff[100] = "0 0 0 0 10 0 0 0 1 20";
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
    "    MLT output display entries (should be < 100)\n";

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
static __always_inline int get_first_digit(int num);

static int MLT_isdigit(char c);
int MLT_get_panicdump_info(void *pdHandle, unsigned int event, void *cbArg,
			   char **buff, int *len);
static char *MLT_PD_buff;
static int MLT_PD_buff_len = 0;

EXPORT_SYMBOL(MLT_initialized);

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
		INIT_LIST_HEAD(&MLT_hash_table[i].scheduled_for_deletion);
	}

	/* Initialize the Wrap Stack functions */
	MLT_add_mem_wrp_func("__kmalloc");
	MLT_add_mem_wrp_func("__kmalloc_track_caller");
	MLT_add_mem_wrp_func("kmalloc_wrapper_dbg");
	MLT_add_mem_wrp_func("vmalloc_wrapper_dbg");
	MLT_add_mem_wrp_func("kstrdup");
	MLT_add_mem_wrp_func("__alloc_skb");
	MLT_add_mem_wrp_func("kmalloc_wrapper_nodbg");
	MLT_add_mem_wrp_func("__proc_create");
	//MLT_add_mem_wrp_func("trace_define_field");
	//MLT_add_mem_wrp_func("event_create_dir");
	//MLT_add_mem_wrp_func("sysfs_new_dirent");

	printk(KERN_WARNING "Initialized MLT\n");
	MLT_initialized = 1;
#if 1
	kthread_run(mlt_garbage_collector, NULL, "MLT garbage collector\n");
#endif
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
	MLT_hash_node_t *MLT_hash_node_ptr;
	MLT_hash_node_t *tail;
	int found = 0;
	unsigned int copy_count;
	MLT_book_keeping_info_t *metadata;

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

	/* IR: iterate the table */
	MLT_hash_node_ptr = &MLT_hash_table[metadata->hash_index];
	tail = &MLT_hash_table[metadata->hash_index];
	list_for_each_entry(MLT_hash_node_ptr,
			    &MLT_hash_table[metadata->hash_index].MLT_hash_list_next,
			    MLT_hash_list_next) {
		tail = MLT_hash_node_ptr;	/* save tail, so as not to use prev pointer later */
		if ((MLT_hash_node_ptr->stk_trace_len == copy_count)
		    && (MLT_hash_node_ptr->stk_fn_hash == stk_fn_hash)) {
			metadata->MLT_hash_node_ptr = (void *)MLT_hash_node_ptr;
			atomic_inc(& MLT_hash_node_ptr->kmalloc_cnt);
			MLT_hash_node_ptr->hash_control.delete_wait_count = 0;
			atomic_add(obj_size_api(mlt_param->s), &MLT_hash_node_ptr->total_alloc_size);
			found = 1;
			break;
		}
	}

	if (!found) {
		unsigned long *stack_trace, *save_trace;
		MLT_hash_node_t *new_node;
		MLT_hash_table[metadata->hash_index].hash_count++;
		/* If a tracking node doesn't exist, create a tracking node & inset it at the appropriate hash index linked list */

		/* Allocate tracking node from slab cache; consider the flag of the allocation that we're processing */
		new_node = kmem_cache_alloc(MLT_hash_nodes_pool, GFP_ATOMIC);	/*TBD: decide on the flags - GFP_ATOMIC - later. Should we get the flags from kmalloc or can we just go with atomic always */
		if (unlikely(!new_node)) {
			printk(KERN_WARNING
			       "%s: failed to allocate MLT_hash_node\n",
			       __FUNCTION__);
			MLT_PROCESS_ERROR(MLT_ALLOC_FAILED);
			return;
		}
		/* point to the node we're about to insert */
		metadata->MLT_hash_node_ptr = new_node;

		/* Fill up the info in tracking node */
		atomic_set(&new_node->kmalloc_cnt, 1);
		new_node->hash_control.hash_index = metadata->hash_index;
		new_node->hash_control.bit_lock = 0;
		new_node->hash_control.delete_wait_count = 0;
		new_node->hash_control.delete_pending = 0;
		new_node->hash_control.chain_len = 0;
		atomic_set(&new_node->total_alloc_size, 0);

		new_node->stk_trace_len = copy_count;
		/* copy stack trace */
		for (stack_trace =
		     &mlt_stk_trace[stk_top_skip_cnt], save_trace =
		     new_node->stk_trace; copy_count; copy_count--) {
			*save_trace++ = *stack_trace++;
		}

		//new_node->hash_control.hash_index = metadata->hash_index;
		new_node->stk_fn_hash = stk_fn_hash;

		/*
		 * Insertion algorithm commence
		 * At this point:
		 * found == 0;
		 * MLT_hash_node = &MLT_hash_table[hash_index], or head of list
		 */
		while (1) {
			unsigned long flags;
			unsigned timeout = 0;

			/* IR: do we need preempt disable? */
			/* disable and save irq */
			local_irq_save(flags);

			while (test_and_set_bit
			       (MLT_LOCK_BIT_BE,
				(volatile unsigned long *)&tail->hash_control)
			       && timeout < 0x100000)
				timeout++;

			if (unlikely(timeout >= 0x100000)) {
				local_irq_restore(flags);
				kmem_cache_free(MLT_hash_nodes_pool, new_node);
				printk(KERN_ERR
				       "%s: timed out waiting on lock: hash_index=%d\n",
				       __FUNCTION__, metadata->hash_index);
				MLT_initialized = 0;	/* disable MLT */
				break;
			}
#ifdef MLT_DEBUG
			if (timeout) {
				printk("%s: lock bit contention; timeout: %d\n",
				       __FUNCTION__, timeout);
			}
#endif
			/* we have the lock now */
			/* are we still pointing to head? It is possible for multiple CPU's
			 * to race to insert an element, so another CPU could've gotten ahead
			 * of us to insert at tail, so *our* tail is no longer the tail, i.e.
			 * if something got inserted, then we have a new tail. So, verify 
			 * that head's prev still points to tail   */
			if (container_of
			    (MLT_hash_table[metadata->hash_index].MLT_hash_list_next.prev,
			     MLT_hash_node_t, MLT_hash_list_next) == tail) {
				/* insert at tail; */
				list_add_tail(&new_node->MLT_hash_list_next,
					      &MLT_hash_table[metadata->hash_index].
					      MLT_hash_list_next);

				MLT_hash_table[metadata->hash_index].hash_control.
				    chain_len++;
				/* unlock */
				clear_bit(MLT_LOCK_BIT_BE,
					  (volatile unsigned long *)&tail->
					  hash_control);

				/* restore irq */
				local_irq_restore(flags);
				break;
			}

			/* unlock */
			clear_bit(MLT_LOCK_BIT_BE,
				  (unsigned long *)&tail->hash_control);
			/* restore irq */
			local_irq_restore(flags);

			/* Search for tail again in the list */
			MLT_hash_node_ptr = tail = &MLT_hash_table[metadata->hash_index];
        		list_for_each_entry(MLT_hash_node_ptr,
                            		&MLT_hash_table[metadata->hash_index].MLT_hash_list_next,
                            		MLT_hash_list_next) {
                		tail = MLT_hash_node_ptr;       /* save tail, so as not to use prev pointer later */
                		if ((MLT_hash_node_ptr->stk_trace_len == copy_count)
                    		&& (MLT_hash_node_ptr->stk_fn_hash == stk_fn_hash)) {
                        		metadata->MLT_hash_node_ptr = (void *)MLT_hash_node_ptr;
                        		atomic_inc(& MLT_hash_node_ptr->kmalloc_cnt);
                        		MLT_hash_node_ptr->hash_control.delete_wait_count = 0;
                        		atomic_add(obj_size_api(mlt_param->s), &MLT_hash_node_ptr->total_alloc_size);
                        		found = 1;
                        		break;
                		}
        		}

			if (unlikely(found)) {
				/* free the allocation; rare case when two cpu's raced to insert the same thing */
				kmem_cache_free(MLT_hash_nodes_pool, new_node);
				break;
			}
		}
	}

	return;
}

EXPORT_SYMBOL(MLT_kmalloc_processing);

#define POISON_INUSE_U32 	((POISON_INUSE<<24) + (POISON_INUSE<<16) + (POISON_INUSE<<8) + (POISON_INUSE))

void MLT_kfree_processing(MLT_param_t *mlt_param)
{
	unsigned short index;
        MLT_book_keeping_info_t *metadata;
	MLT_hash_node_t *MLT_hash_node_ptr = NULL;

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
		struct list_head *pos;
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
		__list_for_each(pos, &MLT_hash_table[index].MLT_hash_list_next) {
			if (container_of
			    (pos, MLT_hash_node_t,
			     MLT_hash_list_next) ==
			    metadata->MLT_hash_node_ptr) {
				MLT_hash_node_ptr =
				    container_of(pos, MLT_hash_node_t,
						 MLT_hash_list_next);
				break;
			}

		}
		/* erase bookkeeping info */
		metadata->hash_index ^= 0xFFFF;
		metadata->mlt_signature = 0;
		metadata->MLT_hash_node_ptr = (void *)0xFFFFFFFF;
		if (MLT_hash_node_ptr) {
			atomic_dec(& MLT_hash_node_ptr->kmalloc_cnt);
		        atomic_sub(obj_size_api(mlt_param->s), &MLT_hash_node_ptr->total_alloc_size);

		} else {
			MLT_PROCESS_ERROR(MLT_HASH_PTR_NOT_IN_LIST);
		}
	    } else {
		MLT_PROCESS_ERROR(MLT_BAD_HASH_INDEX);
	    }
	} else {
		MLT_PROCESS_ERROR(MLT_NULL_HASH_NODE_PTR);
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

	if (count > 100)
		return 0;	/* TBD: convert 100 to a macro */

	copy_from_user(MLT_conf_buff, buffer, count);
	MLT_conf_buff[count] = '\0';

	buff = MLT_conf_buff;
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
	MLT_hash_node_t *MLT_hash_node, *n;
	char tmp_str1[MAX_MLT_FUNC_NAME_LEN], *tmp_str2,
	    func_name[MAX_MLT_FUNC_NAME_LEN];

        cur_display_node_cnt = 0;
	for (i = 0; i < MLT_MAX_HASH; i++) {
			/* IR: fix it for the new table layout */
		list_for_each_entry_safe(MLT_hash_node, n,
		 	&MLT_hash_table[i].MLT_hash_list_next, MLT_hash_list_next) 
		{
		    insert_sort(MLT_hash_node);
		}
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

	return 0;
}

static int MLT_det_leaks_data_read(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	unsigned int k;

	count = 0;

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
		for (k = 1;
		     (k <
		      MLT_display_nodes[detail_entry_index - 1].stk_trace_len);
		     k++) {
			sprintf(page + count, "                %pS\n",
				(void *)MLT_display_nodes[detail_entry_index -
							  1].stk_trace[k]);
			count += strlen(page + count);
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

static int MLT_isdigit(char c) {
	return ((c >= '0') && (c <= '9'));
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

static __always_inline int get_first_digit(int num)
{
    while (num >= 10)
       num /= 10;
    return num;
}

int mlt_garbage_collector(void *arg) {
	static unsigned int list_index;
#ifdef MLT_DEBUG
	static unsigned int max_chain_len = 0;
#endif
	struct MLT_garbage_collection_params *cp =
	    (struct MLT_garbage_collection_params *)arg;
	int entries = 8;	/* default value */
	unsigned short mlt_delete_wait_count = 4;
	int sleep_interval = 20;
	int stats_clear =1, time_elapsed = 0;
	unsigned long flags;

	if (cp) {
		/* get non-default parameters */
		entries = cp->entries;
		mlt_delete_wait_count = cp->mlt_delete_wait_count;
		sleep_interval = cp->sleep_interval;
	}

	while (MLT_initialized) {
		int i;
		for (i = 0; i < entries;
		     i++, list_index = (list_index + 1) % MLT_MAX_HASH) {
			MLT_hash_node_t *pos, *n;
			int x = 0;

			/* free entries which were scheduled for deletion */
			list_for_each_entry_safe(pos, n,
						 &MLT_hash_table[list_index].
						 scheduled_for_deletion,
						 scheduled_for_deletion) {
				BUG_ON(!pos->hash_control.delete_pending);
				list_del(&pos->scheduled_for_deletion);
				kmem_cache_free(MLT_hash_nodes_pool, pos);
				x++;
			}
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
			list_for_each_entry_safe(pos, n,
						 &MLT_hash_table[list_index].
						 MLT_hash_list_next,
						 MLT_hash_list_next) {
				/* grace period is defined as: marked for list deletion bit set and time duration > NOMINAL (seconds) */
				if (atomic_read(&pos->kmalloc_cnt) == 0
				    && pos->hash_control.delete_wait_count >=
				    mlt_delete_wait_count) {
					/* SYNC POINT: sync with the inserter */
					/* disable IRQ's */
					local_save_flags(flags);
					/* test_and_set lock bit on previous */
					if (test_and_set_bit
					    (MLT_LOCK_BIT_BE,
					     (volatile unsigned long *)&pos->
					     hash_control) != 0) {
						local_irq_restore(flags);
						continue;	/* if fail, get out */
					}

					/* do an RCU delete, which essentially by-passes the deleter, 
					   without taking it out of the list

					   [ prev  ]<-------[ deleted ]------------>[ next ]
					   | ^                                     | ^
					   | |_____________________________________| |
					   |_________________________________________|

					   ...so, the deleted can still be validly used for a while by whoever is walking the list. 
					 */
					list_del_rcu(&pos->MLT_hash_list_next);

					/* release bit lock */
					clear_bit(MLT_LOCK_BIT_BE,
						  (unsigned long *)&pos->
						  hash_control);
					pos->hash_control.delete_pending = 1;
					MLT_hash_table[list_index].hash_control.
					    chain_len--;
					local_irq_restore(flags);
					/* add it to the list of items to be freed */
					list_add_tail(&pos->
						      scheduled_for_deletion,
						      &MLT_hash_table
						      [list_index].
						      scheduled_for_deletion);
				} else if (atomic_read(&pos->kmalloc_cnt) == 0) {
					pos->hash_control.delete_wait_count++;
				}

			}
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
	MLT_hash_node_t *MLT_hash_node, *n;
	char tmp_str1[MAX_MLT_FUNC_NAME_LEN], *tmp_str2,
	    func_name[MAX_MLT_FUNC_NAME_LEN];

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
                        	/* IR: fix it for the new table layout */
                	list_for_each_entry_safe(MLT_hash_node, n,
                        	&MLT_hash_table[i].MLT_hash_list_next, MLT_hash_list_next)
                	{
                    	    insert_sort(MLT_hash_node);
                	}
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
	
		for (j = 0; ((j < cur_display_node_cnt) || (j < MLT_PANIC_DUMP_DISPLAY_CNT)); j++) {
	
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

module_init(MLT_init);
module_exit(MLT_deinit);

#endif
