#include <string.h>
#include "frame.h"
#include "page.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"	
#include "userprog/process.h"
#include "userprog/syscall.h"


static unsigned page_hash_func (const struct hash_elem *a, void *aux UNUSED);
static bool page_less_func (const struct hash_elem *a, const struct hash_elem *b,
                void *aux UNUSED);
static void spt_rem_func(struct hash_elem *e, void *aux UNUSED);


static unsigned
page_hash_func (const struct hash_elem *a, void *aux UNUSED)
{
  struct SPT *pa = hash_entry (a, struct SPT, helem);
  return hash_bytes (&pa->paddr, sizeof(pa->paddr));
}

static bool
page_less_func (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED)
{
  struct SPT *pa = hash_entry (a, struct SPT, helem);
  struct SPT *pb = hash_entry (b, struct SPT, helem);
  return pa->paddr < pb->paddr;
}

void spt_init (struct hash *pagetable) {
  hash_init (pagetable, page_hash_func, page_less_func, NULL);
}

void spt_entry(void *upage, struct file *f, off_t offset,
				size_t read_bytes, size_t zero_bytes, bool writeable)
{
	struct SPT *spt = (struct SPT *)malloc(sizeof(struct SPT));
	spt->paddr = upage;
	spt->f_info.f = f;
	spt->f_info.offset = offset;
	spt->f_info.read_bytes = read_bytes;
	spt->f_info.zero_bytes = zero_bytes;
	spt->writeable = writeable;
	spt->is_file = true;
	spt->is_swapped = false; 
	spt->is_mmaped = false;
	spt->isLoaded = false;
	spt->is_pinned = false;
	//printf("inserted upage = %x writeable = %d\n",pg_round_down(upage),writeable);
	hash_insert(&thread_current()->ptable, &spt->helem);
}

bool mmap_entry(void *upage, struct file *f, off_t offset,
				size_t read_bytes, size_t zero_bytes)
{
	struct SPT *spt = (struct SPT *)malloc(sizeof(struct SPT));
	spt->paddr = upage;
	spt->f_info.f = f;
	spt->f_info.offset = offset;
	spt->f_info.read_bytes = read_bytes;
	spt->f_info.zero_bytes = zero_bytes;
	spt->writeable = true;
	spt->is_file = false;
	spt->is_swapped = false; 
	spt->is_mmaped = true;
	spt->isLoaded = false;
	spt->is_pinned = false;
	if(spt_find(upage) != NULL)
		return false;
	hash_insert(&thread_current()->ptable, &spt->helem);
	
	return true;
}



struct SPT *spt_find (void *upage)
{
  struct SPT spt;
  spt.paddr = pg_round_down(upage);
  struct thread *t = thread_current();
  struct hash_elem *e = hash_find (&t->ptable, &spt.helem);
  if (!e)
  {
	 return NULL;
  }
  return hash_entry (e, struct SPT, helem); 
}

struct SPT *spt_find_owner(struct frame *f){
  struct SPT spt;
  spt.paddr = pg_round_down(f->paddr);
  struct thread *t = f->owner;
  struct hash_elem *e = hash_find (&t->ptable, &spt.helem);
  if (!e)
  {
	 return NULL;
  }
  return hash_entry (e, struct SPT, helem); 

}

void spt_remove(struct hash *spt)
{
	hash_destroy(spt, spt_rem_func);
}

static void spt_rem_func(struct hash_elem *e, void *aux UNUSED)
{
	struct SPT *spt = hash_entry(e, struct SPT, helem);
	free_frames(spt->isLoaded, spt->paddr);
	free(spt);
}

bool page_load(struct SPT *spt)
{
	//spt->is_pinned = true;
	//printf("inside page load\n");
	//if(spt->isLoaded)
		//return false;
		
	if(spt->is_file)
		return get_file(spt);
	else if(spt->is_mmaped)
		return get_file(spt);
	else
	{
		//if(spt->isLoaded)
			//return false;
		return get_swap(spt);
	}
}

bool get_file(struct SPT *spt)
{
	//printf("inside get_file()\n");
	//get page from user pool
	void *kpage = frame_get_page(spt->paddr);
	//void *kpage = palloc_get_page(PAL_USER);
	//printf("kapge is %x\n",kpage);
	printf("page is read from %x\n",spt->paddr);
	spt->is_pinned = true;
	if(kpage == NULL)
	{	
		//printf("kpage is null\n");
		return false;
	}
	if(spt->f_info.read_bytes > 0)
	{
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	if(file_read_at(spt->f_info.f, kpage, spt->f_info.read_bytes,
					spt->f_info.offset) != (int) spt->f_info.read_bytes)
	{
		
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		frame_free_page(kpage);
		return false;
	}
	}
	memset (kpage + spt->f_info.read_bytes, 0, spt->f_info.zero_bytes);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	/* Add the page to the process's address space. */
    if (!install_page (spt->paddr, kpage, spt->writeable)) 
    {
		//printf("install_page fail");
		frame_free_page(kpage);
        return false; 
    }
	
	//struct thread *t = thread_current ();
	
	/*if(pagedir_get_page (t->pagedir, spt->paddr) != NULL)
		printf("successfully created pde mapping \n");
	else
		printf("failed to create pde mapping \n");*/
		
	//As page is loaded marking it as a loaded
	spt->isLoaded = true;
	spt->is_pinned = false;
	return true;
}

bool get_swap(struct SPT *spt)
{
	printf("inside get_swap*********   and Index = %d\n",spt->ind_swp);
	//get page from user pool
	void *kpage = frame_get_page(spt->paddr);
	spt->is_pinned = true;
	if(kpage == NULL)
		return false;
	
	swap_in(spt->ind_swp, kpage);
	printf("page contents read%x\n",*(char *)kpage);
	//memset (kpage + spt->f_info.read_bytes, 0, spt->f_info.zero_bytes);
	/* Add the page to the process's address space. */
	if (!install_page (spt->paddr, kpage, spt->writeable)) 
    {
		frame_free_page(kpage);
        return false; 
    }
	
	//struct frame *f = frame_find_upage(spt->paddr);
	//swap_in(spt->ind_swp, kpage);
	//swap_in(spt->ind_swp, spt->addr);
	//memset (kpage + spt->f_info.read_bytes, 0, spt->f_info.zero_bytes);
	//struct frame *f;
	//f = frame_find(spt->paddr);
	
	//pagedir_set_dirty(f->owner->pagedir, f->paddr, true);
	
	/*if(pagedir_get_page (f->owner->pagedir, spt->paddr) != NULL)
		printf("successfully created pde mapping \n");
	else
		printf("failed to create pde mapping \n");*/
	//As page is loaded marking it as a loaded
	spt->isLoaded = true;
	spt->is_pinned = false;
	return true;
}	

bool invalid_stack_size(void *upage)
{
	if((size_t) (PHYS_BASE - pg_round_down(upage)) > MAX_STACK)
		return true;
	return false;
}

/* Allocates one page for the stack and makes it's entry in
   Supplementary page table */
bool stack_growth(void *upage)
{
	/* Limiting stack size to 8 MB */
	if(invalid_stack_size(upage))
		return false;
		
	struct SPT *spt = (struct SPT *)malloc(sizeof(struct SPT));
	spt->is_pinned = true;
	spt->paddr = pg_round_down(upage);
	//setting stack page as writeable and as mention in doc,
	// it should be swappable as well
	spt->writeable = true;
	spt->is_swapped = true;
	spt->is_file = false; 
	spt->is_mmaped = false;
	//As page is loaded marking it as a loaded
	spt->isLoaded = true;
	
	//get page from user pool
	void *kpage = frame_get_page(spt->paddr);
	
	if(kpage == NULL)
	{
		free(spt);
		return false;
	}
	
	/* Add the page to the process's address space. */
	if (!install_page (spt->paddr, kpage, spt->writeable)) 
    {
		free(spt);
		frame_free_page(kpage);
        return false; 
    }
	
	//if(intr_context())
		spt->is_pinned = false;
		
	struct thread *t = thread_current();
	if(hash_insert(&t->ptable, &spt->helem) == NULL)
		return true;
	else
	{
		spt->is_swapped = false;
		return false;
	}
}