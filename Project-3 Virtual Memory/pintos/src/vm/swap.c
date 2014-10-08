#include "swap.h"
#include <stdint.h>

size_t swap_size;

void init_swp_tab(void){ 
	block_swp = block_get_role(BLOCK_SWAP);
	//printf("dsk sector %d\n",SWP_DSK_SECTOR);
	//printf("block size = %d\n",block_size(block_swp));
	swap_size = (block_size(block_swp)) / 8;
	//printf("Swap size is %d\n",swap_size);
	swp_table = bitmap_create(1024);
	bitmap_set_all(swp_table, false);
	lock_init(&swap_lock);
	}

int swap_out(void *kpage)
{    
    //printf("Inside swap out");
	if(!lock_held_by_current_thread(&swap_lock))
		lock_acquire(&swap_lock);
	//printf("swap size is %d\n",swap_size);
	//bool full = bitmap_all (swp_table, 0, swap_size);
	//printf("bitmap full? %d\n",full);
	//if(full)
		//printf("swap full\n");
	size_t get_index = bitmap_scan_and_flip(swp_table, 0, 1, false);
	
	//int get_index = bitmap_scan(swp_table, 0, 1, false);
	printf("index is %d\n",get_index);
	//if(get_index == 0)
	//	printf("Write data from kpage is %s\n",kpage);
	//bitmap_set_multiple (swp_table, get_index, 1, true);
	block_write_page(block_swp,kpage,get_index);
	//printf("write successful\n");
	printf("page contents %x\n",*(char *)kpage);
	return get_index;
} 

void block_write_page(struct block *block,void *kpage, size_t index){
       //printf("Inside block write");
	block_sector_t sect;
	for(sect=0; sect< 8; sect++)
	{ 
		block_write(block,index * 8 + sect, kpage + (sect * 512));
		//block_write(block,index + sect,(int*) kpage + sect * BLOCK_SECTOR_SIZE);
    }
	/*for(sect=0; sect< SWP_DSK_SECTOR; sect++)
	{ 
		block_write(block,index *SWP_DSK_SECTOR + sect,
		(uint8_t *) kpage + (sect * BLOCK_SECTOR_SIZE));
		//block_write(block,index + sect,(int*) kpage + sect * BLOCK_SECTOR_SIZE);
    } */
	if(lock_held_by_current_thread(&swap_lock))
		lock_release(&swap_lock);
}

/*block_sector_t
swap_find_free ()
{
	bool full = bitmap_all (swp_table, 0, swap_size);
	if(!full){
		block_sector_t first_free = bitmap_scan_and_flip (swp_table, 0, PGSIZE / BLOCK_SECTOR_SIZE, false);

		return first_free;
	} else {
		PANIC("SWAP is full! Memory exhausted.");
	}
}

int swap_out(void *kpage)
{
	int i;
	lock_acquire (&swap_lock);
	block_sector_t swap_addr = swap_find_free();
	for(i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++){
		block_write (block_swp, swap_addr + i, kpage + i * BLOCK_SECTOR_SIZE);
	}
	lock_release (&swap_lock);
	
	return swap_addr;
}*/

void swap_in(size_t index, void *kpage)
{   
    // Lock code
	 //printf("Inside swap in");
	if(!lock_held_by_current_thread(&swap_lock)) 
		lock_acquire(&swap_lock);
	printf("Swapped in index = %d\n",index);
	//printf("flipped not failed\n");
	block_read_page(block_swp,kpage,index);
	bitmap_flip(swp_table, index);
	//printf("block read not failed\n");
	//printf("REad data is %s\n",kpage);
	if(lock_held_by_current_thread(&swap_lock))
		lock_release(&swap_lock);	
	// release the lock here 
} 


/*void swap_in(int index, void *kpage)
{
	int i;
	lock_acquire (&swap_lock);

	for( i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++ ){
		block_read (block_swp, index + i, (int*)kpage + i * BLOCK_SECTOR_SIZE);
	}

	bitmap_set_multiple (swp_table, index, PGSIZE / BLOCK_SECTOR_SIZE, false);
	lock_release (&swap_lock);
}*/

void block_read_page(struct block *block,void *kpage, size_t index){
      //printf("Inside block read page");
 	block_sector_t sect;
	for(sect=0; sect<SWP_DSK_SECTOR; sect++)
	{ 
		//block_read(block,index + sect,
		//(int*) kpage + sect * BLOCK_SECTOR_SIZE);
		block_read(block,index *SWP_DSK_SECTOR + sect, kpage + sect * BLOCK_SECTOR_SIZE);
    } 
}

		
	