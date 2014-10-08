#include <inttypes.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"

#define MAX_STACK 0x800000 /* As mention in doc, limiting stack to 8 MB */

/* Contains info about pages to be loaded from executable */
struct exec_info{
	off_t offset;
	size_t read_bytes;
    size_t zero_bytes;
	struct file *f;
};

/* Supplementary page structure to hold information about pages */
struct SPT
{
	void *paddr;
	void *kaddr;
	
	/* Checks whether page is loaded in memory */ 
	bool isLoaded;
	/* page is writeable or not */
	bool writeable;
	bool is_swapped;
	bool is_mmaped; 
	bool is_file;
	bool is_pinned;
	
	struct exec_info f_info;
	int ind_swp;
	struct hash_elem helem;
};

void spt_init (struct hash *pagetable);
void spt_entry(void *upage, struct file *f, off_t offset,
				size_t read_bytes, size_t write_bytes, bool writeable);
struct SPT *spt_find (void *upage);
void spt_remove(struct hash *spt);
bool page_load(struct SPT *spt);
bool get_file(struct SPT *spt);
bool get_swap(struct SPT *spt);
bool stack_growth(void *upage);
bool invalid_stack_size(void *upage);
bool mmap_entry(void *upage, struct file *f, off_t offset,
				size_t read_bytes, size_t zero_bytes);
struct SPT *spt_find_owner(struct frame *f);