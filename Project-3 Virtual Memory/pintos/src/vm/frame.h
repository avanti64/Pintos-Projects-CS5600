//Author : Sachin Doiphode and Avanti Kabra

#include "threads/thread.h"

//The frame table contains one entry for each frame that contains a user page
struct frame{
/* Physical address of a page */
void *paddr;
/* virtual address corresponding to physical address */
void *vaddr;

/* Owner of a frame*/
//tid_t tid;
//uint32_t *pagedir;                  /* Page directory. */

struct thread *owner;

/* List element to iterate over */
struct list_elem elem;
};

void init_frame(void);
void *frame_get_page(void *upage);
void frame_free_page (void *kaddr);
struct frame* frame_find (void *kaddr);
void free_frames(bool isLoaded, void *upage);
void *get_frame_kaddr(void *upage);
void *get_frame_kaddr(void *upage);
void adjust_frame_LRU(struct frame *f);
struct frame* LRU(void);
void *evict(void);
struct frame* frame_find_upage (void *upage);