#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"

struct lock buffer_cache_lock;				/* Lock on overall blocks */
struct buffer_cache cache_blocks[CACHE_SIZE]; 	/* List of cached blocks */


void filesys_cache_init (void)
{
  list_init(&filesys_cache);
  lock_init(&filesys_cache_lock);
  filesys_cache_size = 0;
  thread_create("filesys_cache_writeback", 0, thread_func_write_back, NULL);
}

void init_cache()
{
	lock_init(&buffer_cache_lock);
	int i=0;
	do
	{
		struct buffer_cache *block = &cache_blocks[i];
		init_cache_block(block);
	}while(++i < CACHE_SIZE);
}

/* Initializes individual cache block */
void init_cache_block(struct buffer_cache *block)
{
	cond_init(&block->pend_rw_req);
	cond_init(&block->writer_cond);
	lock_init(&block->cache_lock);
	block->readers = 0;
	block->writers = 0;
	block->r_waiters = 0;
	block->w_waiters = 0;
	block->disk_sector_id = UNUSED_CACHE;
	block->is_dirty = false;
	block->is_valid = false;
}

struct cache_entry* block_in_cache (block_sector_t sector)
{
  struct cache_entry *c;
  struct list_elem *e;
  for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
       e = list_next(e))
    {
      c = list_entry(e, struct cache_entry, elem);
      if (c->sector == sector)
	{
	  return c;
	}
    }
  return NULL;
}

/* get a cache block for a given sector, returns null if
   block is not cached */
struct buffer_cache* get_cache_block(block_sector_t sector, int lock_type)
{
	int i=0;
	while(i < CACHE_SIZE)
	{
		struct buffer_cache *block = &cache_blocks[i];
		if(!lock_held_by_current_thread(&block->cache_lock))
			lock_acquire(&block->cache_lock);
		//check for matching sector number
		if(block->disk_sector_id == sector)
		{
			if(lock_type == EXCLUSIVE_LOCK)
			{
				block->w_waiters += 1;

				// wait till all readers and writer finishes operations
				/*while(block->readers || block->writers || block->waiters_r)			//**************** check for waiters
				{
					cond_wait(&block->pend_rw_req, &block->cache_lock);
				}*/
				if(block->readers || block->writers || block->r_waiters)
				{
					do{
						cond_wait(&block->pend_rw_req, &block->cache_lock);
					}while(block->readers || block->writers);
				}
				block->writers++;
				block->w_waiters -= 1;
			}
			else
			{
				block->r_waiters += 1;
				if(block->writers || block->w_waiters)                 //**************** check for waiters
				{
					do{
						cond_wait(&block->writer_cond, &block->cache_lock);
					}while(block->writers);
				}
				block->r_waiters -= 1;
				block->readers++;
			}
			if(lock_held_by_current_thread(&block->cache_lock))
				lock_release(&block->cache_lock);
			return block;
		}
		i++;
		if(lock_held_by_current_thread(&block->cache_lock))
			lock_release(&block->cache_lock);
	}
	//If no free cache block found then evict
	while(true)
	{
		struct buffer_cache *block = find_empty_block(sector, lock_type);
		if(block == NULL){
			evict();
			continue;
		}
		cache_read(block);
		return block;
	}
}
struct buffer_cache *find_empty_block(block_sector_t sector_id, int access)
{
	int i=0;
	while(i < CACHE_SIZE)
	{
		struct buffer_cache *block = &cache_blocks[i];

		if(block->disk_sector_id == UNUSED_CACHE)
		{
			if(!lock_held_by_current_thread(&block->cache_lock))
				lock_acquire(&block->cache_lock);
			block->disk_sector_id = sector_id;
			block->is_valid = false;
			block->is_dirty = false;
			block->readers = 0;
			block->writers = 0;
			block->r_waiters = 0;
			block->w_waiters = 0;
			if(access == EXCLUSIVE_LOCK)
				block->writers = 1;
			else
				block->readers = 1;
			if(lock_held_by_current_thread(&block->cache_lock))
				lock_release(&block->cache_lock);

			return block;
		}
		i++;
	}
	//printf("i = %d\n",i);
	//If no empty block found, return null
	return NULL;
}

void evict()
{
	//printf("inside eviction \n");
	int i=0;
	//printf("cache size is %d\n",CACHE_SIZE);
	while(i < CACHE_SIZE)
	{
		//printf("inside eviction i =%d\n",i);
		struct buffer_cache *block = &cache_blocks[i];
		i++;
		if(!lock_held_by_current_thread(&block->cache_lock))
			lock_acquire(&block->cache_lock);
		if(block->readers || block->writers || block->r_waiters || block->w_waiters)
		{
		   if(lock_held_by_current_thread(&block->cache_lock))
				lock_release(&block->cache_lock);
		   //printf("locked\n");
		   continue;
		}
		block->writers = 1;
		if(lock_held_by_current_thread(&block->cache_lock))
			lock_release(&block->cache_lock);

		/* Write block to disk if dirty bit set */
		//printf("block->is_dirty : %d\n",block->is_dirty);
		if(block->is_dirty && block->is_valid)
		{
		   block_write(fs_device, block->disk_sector_id, &block->block);
		   block->is_dirty = false;
		}
		if(!lock_held_by_current_thread(&block->cache_lock))
			lock_acquire(&block->cache_lock);
        block->writers = 0;
        if (block->r_waiters && !block->w_waiters)
        {
           block->disk_sector_id = UNUSED_CACHE;
        }
      else
        {
          if (block->r_waiters)
            cond_broadcast (&block->writer_cond, &block->cache_lock);
          else
            cond_signal (&block->pend_rw_req, &block->cache_lock);
        }
		if(lock_held_by_current_thread(&block->cache_lock))
			lock_release (&block->cache_lock);
    }
	//printf("outside eviction \n");

	//If no block found then evict random block
	struct buffer_cache *block = &cache_blocks[10];
	if(block->is_dirty)
		{
		   block_write(fs_device, block->disk_sector_id, &block->block);
		   block->is_dirty = false;
		}
		block->disk_sector_id = UNUSED_CACHE;
}

struct cache_entry* filesys_cache_block_get (block_sector_t sector,
					     bool dirty)
{
  //if(!lock_held_by_current_thread(&sync))
	lock_acquire(&filesys_cache_lock);
  struct cache_entry *c = block_in_cache(sector);
  if (c)
    {
      c->open_cnt++;
      c->dirty |= dirty;
      c->accessed = true;
      lock_release(&filesys_cache_lock);
      return c;
    }
  c = filesys_cache_block_evict(sector, dirty);
  if (!c)
    {
      PANIC("Not enough memory for buffer cache.");
    }
  lock_release(&filesys_cache_lock);
  return c;
}

struct cache_entry* filesys_cache_block_evict (block_sector_t sector,
					       bool dirty)
{
  struct cache_entry *c;
  if (filesys_cache_size < CACHE_SIZE)
    {
      filesys_cache_size++;
      c = malloc(sizeof(struct cache_entry));
      if (!c)
	{
	  return NULL;
	}
      c->open_cnt = 0;
      list_push_back(&filesys_cache, &c->elem);
    }
  else
    {
      bool loop = true;
      while (loop)
	{
	  struct list_elem *e;
	  for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
	       e = list_next(e))
	    {
	      c = list_entry(e, struct cache_entry, elem);
	      if (c->open_cnt > 0)
		{
		  continue;
		}
	      if (c->accessed)
		{
		  c->accessed = false;
		}
	      else
		{
		  if (c->dirty)
		    {
		      block_write(fs_device, c->sector, &c->block);
		    }
		  loop = false;
		  break;
		}
	    }
	}
    }
  c->open_cnt++;
  c->sector = sector;
  block_read(fs_device, c->sector, &c->block);
  c->dirty = dirty;
  c->accessed = true;
  return c;
}

void * cache_read (struct buffer_cache *block)
{
  if(!lock_held_by_current_thread(&block->cache_lock))
	lock_acquire (&block->cache_lock);
  if(!block->is_valid)
  {
	  block_read (fs_device, block->disk_sector_id, &block->block);
	  block->is_dirty = false;
	  block->is_valid = true;
  }
  if(lock_held_by_current_thread(&block->cache_lock))
	lock_release (&block->cache_lock);
  return block->block;
}

void cache_write_back_disk()
{
	int i=0;
	while(i < CACHE_SIZE)
	{
		struct buffer_cache *block= &cache_blocks[i];
		if(!lock_held_by_current_thread(&block->cache_lock))
			lock_acquire(&block->cache_lock);

		if(block->disk_sector_id != UNUSED_CACHE)
		{
			disk_flush(block, EXCLUSIVE_LOCK);
		}
		if(lock_held_by_current_thread(&block->cache_lock))
			lock_release(&block->cache_lock);
		i++;
	}
}

void disk_flush(struct buffer_cache *block, int access)
{
	if(!lock_held_by_current_thread(&block->cache_lock))
		lock_acquire(&buffer_cache_lock);
	if(access == EXCLUSIVE_LOCK)
	{
		block->w_waiters += 1;

		// wait till all readers and writer finishes operations
		/*while(block->readers || block->writers || block->waiters_r)			//**************** check for waiters
		{
			cond_wait(&block->pend_rw_req, &block->cache_lock);
		}*/
		if(block->readers || block->writers || block->r_waiters)
		{
			do{
				cond_wait(&block->pend_rw_req, &block->cache_lock);
			}while(block->readers || block->writers);
		}
		block->writers++;
		block->w_waiters -= 1;
	}
	else
	{
		block->r_waiters += 1;
		if(block->writers || block->w_waiters)                 //**************** check for waiters
		{
			do{
				cond_wait(&block->writer_cond, &block->cache_lock);
			}while(block->writers);
		}
		block->r_waiters -= 1;
		block->readers++;
	}
	if(block->is_dirty && block->is_valid)
	{
		block_write(fs_device, block->disk_sector_id, &block->block);
	    block->is_dirty = false;
	}
	unlock_buffer_cache(block);

}
void filesys_cache_write_to_disk (bool halt)
{
  lock_acquire(&filesys_cache_lock);
  struct list_elem *next, *e = list_begin(&filesys_cache);
  while (e != list_end(&filesys_cache))
    {
      next = list_next(e);
      struct cache_entry *c = list_entry(e, struct cache_entry, elem);
      if (c->dirty)
	{
	  block_write (fs_device, c->sector, &c->block);
	  c->dirty = false;
	}
      if (halt)
	{
	  list_remove(&c->elem);
	  free(c);
	}
      e = next;
    }
  lock_release(&filesys_cache_lock);
}

void thread_func_write_back (void *aux UNUSED)
{
  while (true)
    {
      timer_sleep(WRITE_BACK_INTERVAL);
      filesys_cache_write_to_disk(false);
    }
}

void spawn_thread_read_ahead (block_sector_t sector)
{
  block_sector_t *arg = malloc(sizeof(block_sector_t));
  if (arg)
    {
      *arg = sector + 1;
      thread_create("filesys_cache_readahead", 0, thread_func_read_ahead,
      		    arg);
    }
}

void thread_func_read_ahead (void *aux)
{
  block_sector_t sector = * (block_sector_t *) aux;
  lock_acquire(&filesys_cache_lock);
  struct cache_entry *c = block_in_cache(sector);
  if (!c)
    {
      filesys_cache_block_evict(sector, false);
    }
  lock_release(&filesys_cache_lock);
  free(aux);
}

void unlock_buffer_cache (struct buffer_cache *b)
{
  if(!lock_held_by_current_thread(&b->cache_lock))
	lock_acquire (&b->cache_lock);
  if (b->readers)
    {
      if (--b->readers == 0)
        cond_signal (&b->pend_rw_req, &b->cache_lock);
    }
  else if (b->writers)
    {
      b->writers--;
      if (b->r_waiters)
        cond_broadcast (&b->writer_cond, &b->cache_lock);
      else
        cond_signal (&b->pend_rw_req, &b->cache_lock);
    }
	if(lock_held_by_current_thread(&b->cache_lock))
		lock_release (&b->cache_lock);
}

void * init_cache_block_zero(struct buffer_cache *block)
{
	memset(block->block, 0, BLOCK_SECTOR_SIZE);
	block->is_dirty = true;
	block->is_valid = true;
	//Return zeroed data
	return block->block;
}

void inode_free(block_sector_t sector)
{
	int i=0;
	while(i < CACHE_SIZE)
	{
		struct buffer_cache *block = &cache_blocks[i];
		i++;
		if(!lock_held_by_current_thread(&block->cache_lock))
			lock_acquire(&block->cache_lock);
		if(block->disk_sector_id == sector)
		{
			if(!(block->readers || block->writers || block->r_waiters || block->w_waiters))
			{
				block->disk_sector_id = UNUSED_CACHE;
				if(lock_held_by_current_thread(&block->cache_lock))
					lock_release(&block->cache_lock);
				return;
			}
			block_write(fs_device, block->disk_sector_id, &block->block);
			block->is_dirty = false;
			block->is_valid = true;
		}
		if(lock_held_by_current_thread(&block->cache_lock))
			lock_release(&block->cache_lock);
	}
}
