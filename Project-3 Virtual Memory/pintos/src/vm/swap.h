#include "devices/block.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <bitmap.h>

#define SWP_DSK_SECTOR   PGSIZE/BLOCK_SECTOR_SIZE
// The block where the swapped pages are read
// or written from/to
struct block *block_swp;
struct lock swap_lock; 

// A bitmap of swp_table to indicate whether 
// a page is available for swapping a page or not
struct bitmap *swp_table; 


void init_swp_tab(void);
void block_read_page(struct block *block,void *kpage, size_t index);
void swap_in(size_t index, void *kpage);
void block_write_page(struct block *block,void *kpage, size_t index);
int swap_out(void *kpage);