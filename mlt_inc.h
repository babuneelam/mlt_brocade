
#include <linux/types.h>
#ifndef __MLT_H_
#define __MLT_H_

/* MLT book keeping memory data structure */
typedef struct MLT_book_keeping_info {
	unsigned short hash_index;
	unsigned short hash_index_compl;	/* hash_index ^ 0xFFFF */
	void *MLT_hash_node_ptr;
	unsigned long mlt_signature;
} __attribute__ ((aligned(16))) MLT_book_keeping_info_t;

typedef struct MLT_param {
	struct kmem_cache *s; 
	void *ptr;
} MLT_param_t;

#define MLT_PATH_SIGNATURE 0xFEDC0FFE
/*MemInfra function prototypes */
extern void MLT_kmalloc_processing(MLT_param_t *mlt_param);
extern void MLT_kfree_processing(MLT_param_t *mlt_param);
extern int MLT_init(void);
extern int MLT_dump_traces(void);
extern int MLT_get_panicdump_info(void *pdHandle, unsigned int event,
				  void *cbArg, char **buff, int *len);;
extern int MLT_initialized;

#define MLT_PANIC_DUMP_DISPLAY_CNT 20
#define MLT_PANIC_DUMP_BUFF_SIZE ((MLT_PANIC_DUMP_DISPLAY_CNT * 2048 *2) + 5*1024)	/*2 KB per mem leak entry + 5K for Stats */

/*Function Return Codes */
#define MEMINFRA_INIT_SUCCESS 0
#define MEMINFRA_INIT_FAILURE 1

#endif
