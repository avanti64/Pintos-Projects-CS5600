#include "frame.h"
#include "list.h"
#include "page.h"
#include "swap.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

/* Obtains a single free page and returns its kernel virtual
   address. This function wraps palloc_get_page() function.
   */

static struct list frames;
struct lock frame_lock;
static int count;

void init_frame(void)
{
	list_init(&frames);
	lock_init(&frame_lock);
}

void *frame_get_page(void *upage)
{
	
	//Call original page allocator function to get page from 
	// User pool.
	//printf("inside frame_get_page\n");
	
	void *kpage;
	kpage = palloc_get_page (PAL_USER);
  
    count++;
    //Add info about user page to frame table
    struct frame *f;
	f = (struct frame*)malloc(sizeof(struct frame));
	f->paddr = upage;
	//f->tid = thread_current()->tid;
	//f->pagedir = thread_current()->pagedir;
	f->owner = thread_current();
//	f->vaddr = kpage;
	
	//If returned page address is null means no more pages available
    while (kpage == NULL){
		//Evict the page to make space for new page
		if(!lock_held_by_current_thread(&frame_lock))
			lock_acquire(&frame_lock);

		kpage=evict();

		if(lock_held_by_current_thread(&frame_lock))
			lock_release(&frame_lock);
	}
	f->vaddr = kpage;

	if(!lock_held_by_current_thread(&frame_lock))
		lock_acquire(&frame_lock);
	//list_push_front(&frames,&f->elem);
	list_push_back(&frames,&f->elem);
	if(lock_held_by_current_thread(&frame_lock))
		lock_release(&frame_lock);
	return kpage;
}

void frame_free_page (void *kaddr){

	struct list_elem *cur = list_head(&frames)->next;
	if(!lock_held_by_current_thread(&frame_lock))
		lock_acquire(&frame_lock);
	while(cur->next != NULL)
	{
		struct frame *f = list_entry(cur, struct frame, elem);
		cur = cur->next;
		
		if(kaddr == f->paddr)
		{
			palloc_free_page(kaddr);
			list_remove(&f->elem);
			//free frame later
			free(f);
			break;
		}
	}
	if(lock_held_by_current_thread(&frame_lock))
		lock_release(&frame_lock);
}

void free_frames(bool isLoaded, void *upage)
{
	if(isLoaded)
	{
		struct thread *t = thread_current();
		void *kpage = pagedir_get_page(t->pagedir, upage);
		frame_free_page(kpage);
		pagedir_clear_page(t->pagedir, upage);
	}
}

		
struct frame* frame_find (void *kaddr){

	struct list_elem *cur = list_head(&frames)->next;
	
	while(cur->next != NULL)
	{
		struct frame *f = list_entry(cur, struct frame, elem);
		cur = cur->next;
		
		if(kaddr == f->paddr)
		{
			list_remove(&f->elem);
			adjust_frame_LRU(f);
			return f;
		}
	}
	
	return NULL;
}

struct frame* frame_find_upage (void *upage){

	struct list_elem *cur = list_head(&frames)->next;
	
	while(cur->next != NULL)
	{
		struct frame *f = list_entry(cur, struct frame, elem);
		cur = cur->next;
		
		if(upage == f->paddr)
		{
			//list_remove(&f->elem);
			//adjust_frame_LRU(f);
			return f;
		}
	}
	return NULL;
}

/*Returns frame virtual address given its physical address */
void *get_frame_kaddr(void *upage)
{
	struct list_elem *cur = list_head(&frames)->next;
	
	while(cur->next != NULL)
	{
		struct frame *f = list_entry(cur, struct frame, elem);
		if(upage == f->paddr)
		{
			list_remove(&f->elem);
			adjust_frame_LRU(f);
			return f->vaddr;
		}
		cur = cur->next;
	}
	
	return NULL;
}

/* insert frames at the start marking it as a most recently used */
void adjust_frame_LRU(struct frame *f)
{
	//list_push_front(&frames, &f->elem);
	list_push_back(&frames, &f->elem);
}

/* Last frame in a list is a last accessed frame
   so check frame for access and dirty bit and 
   return frame for eviction */
struct frame* LRU(void)
{
//	printf("inside page LRU\n");
	struct list_elem *last = list_end(&frames)->prev;
	//struct list_elem *last = list_begin(&frames);
	bool isAccessed, isDirty;
	//while(last != list_end(&frames))
	while(last != list_begin(&frames))
	{
		
		struct frame *f = list_entry(last, struct frame, elem);
		struct SPT *spt = spt_find(f->paddr);
		last = list_prev(last);
		//last = list_next(last);
		
		if(!spt->is_pinned)
		{
			isAccessed = pagedir_is_accessed(f->owner->pagedir, f->paddr);
			isDirty = pagedir_is_dirty(f->owner->pagedir, f->paddr);
			
			//printf("isDirty =%d and isAccessed=%d\n",isDirty,isAccessed);
			//First preference is to pages which are not accessed 
			if(!isAccessed)
			{
				//pagedir_set_accessed(f->owner->pagedir, f->paddr, false);
			//		printf("accessed page given\n");
				return f;
			}
			else
				pagedir_set_accessed(f->owner->pagedir, f->paddr, false);
			//taking dirty bit into consideration
			/*if(isAccessed && !isDirty)
			{
				printf("accessed and dirty page given\n");
				//pagedir_set_accessed(f->owner->pagedir, f->paddr, false);
				return f;
			}*/
		}
	}
	
	//If no frame is evicted then choose frame at random
	//printf("Random page given\n");
	struct list_elem *rand = list_end(&frames)->prev;
	struct frame *f = list_entry(rand, struct frame, elem);
	
	return f;
}

void *evict(void)
{
	
	//struct list_elem *last = list_end(&frames)->prev;
	struct list_elem *last = list_begin(&frames);
	bool isAccessed, isDirty;
	while(1)
	//while(last != list_begin(&frames))
	{
		if(last == list_end(&frames))
			last = list_begin(&frames);
			
		struct frame *f = list_entry(last, struct frame, elem);
		struct SPT *spt = spt_find(f->paddr);
		//last = list_prev(last);
		last = list_next(last);
		
		if(!spt->is_pinned)
		{
			isAccessed = pagedir_is_accessed(f->owner->pagedir, f->paddr);
			isDirty = pagedir_is_dirty(f->owner->pagedir, f->paddr);
			
			//First preference is to pages which are not accessed 
			if(!isAccessed)
			{
				if(spt->is_mmaped)
				{
					if(isDirty)
					{
						if(!lock_held_by_current_thread(&sync))
							lock_acquire(&sync);
							file_write_at(spt->f_info.f,spt->paddr,spt->f_info.read_bytes,spt->f_info.offset);
						if(lock_held_by_current_thread(&sync))
							lock_release(&sync);
					}
				}
				else
				{
					spt->is_swapped = true;
					spt->ind_swp = swap_out(f->vaddr);
				}
				//Page is moved from page so not loaded
				spt->isLoaded = false;
				printf("Evicted frame is %x\n",f->paddr);
				//Removing references of the page
				//printf("vaddr is %x\n",f->paddr);
				//void *frame = f->vaddr;
				pagedir_clear_page(f->owner->pagedir,spt->paddr);
				palloc_free_page(f->vaddr);
				list_remove(&f->elem);
				free(f);
		
				void *kpage = palloc_get_page(PAL_USER);
				return kpage;
			}
			else
				pagedir_set_accessed(f->owner->pagedir, f->paddr, false);
		}
	}
}	
/*void *evict(void)
{
	struct frame *f = LRU();
	//printf("inside evict\n");
	//If LRU doesn't return the frame
	if(f == NULL)
	{
		printf("f is null\n");
		return NULL;
	}
	//printf("Evicted frame is %x\n",f->paddr);
	//struct SPT *spt = spt_find(f->paddr);
	struct SPT *spt = spt_find_owner(f);
	
	if(spt == NULL){
    	printf("spt is null\n");
		return NULL;
	}
	
	//struct thread *owner = f->owner;
	bool isDirty = pagedir_is_dirty(f->owner->pagedir, f->paddr);
	
	//printf("isDirty =%d and is_swapped=%d\n",isDirty,spt->is_swapped);
	//if page is dirty then write back to file or swap
	//if(isDirty)
	//{
		
		if(spt->is_mmaped)
		{
			if(isDirty)
			{
				if(!lock_held_by_current_thread(&sync))
					lock_acquire(&sync);
				//file_seek(spt->f_info.f, spt->f_info.offset);
				//file_write(spt->f_info.f, f->vaddr, spt->f_info.offset);
				//file_write(spt->f_info.f, f->vaddr, spt->f_info.offset);
				file_write_at(spt->f_info.f,spt->paddr,spt->f_info.read_bytes,spt->f_info.offset);
				if(lock_held_by_current_thread(&sync))
					lock_release(&sync);
			}
		}
		else
		{
			spt->is_swapped = true;
      		//printf("page swapped\n");		
			spt->ind_swp = swap_out(f->vaddr);
			//printf("swapped index is %d\n",spt->ind_swp);
	//		printf("page swapped out\n");
		}
	//}

	//Page is moved from page so not loaded
	spt->isLoaded = false;
	
	//Removing references of the page
	//printf("vaddr is %x\n",f->paddr);
	pagedir_clear_page(f->owner->pagedir,spt->paddr);
	palloc_free_page(f->vaddr);
	list_remove(&f->elem);
	free(f);
	
	void *kpage = palloc_get_page(PAL_USER);
	//printf("page count %d\n",count);
	count--;
	return kpage;
}*/