#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "devices/timer.h"
#include "threads/synch.h"
#include <list.h>

#define WRITE_BACK_INTERVAL 5*TIMER_FREQ
#define MAX_FILESYS_CACHE_SIZE 64

#define CACHE_SIZE 64
#define UNUSED_CACHE -1
#define EXCLUSIVE_LOCK 1
#define NON_EXCLUSIVE_LOCK 2

struct list filesys_cache;
uint32_t filesys_cache_size;
struct lock filesys_cache_lock;

struct cache_entry {
  uint8_t block[BLOCK_SECTOR_SIZE];
  block_sector_t sector;
  bool dirty;
  bool accessed;
  int open_cnt;
  struct list_elem elem;
};

struct buffer_cache
{
	block_sector_t disk_sector_id; /* sector number which is cached */
	bool is_dirty;		       /* is cache entry modified */
	bool is_valid;			/* is cache entry valid */
	int readers, r_waiters;			/* Number of of readers */
	int writers, w_waiters;			/* Number of writers */

	struct lock cache_lock;		/* Lock for this block */
	struct condition pend_rw_req;
	struct condition writer_cond;
	uint8_t block[BLOCK_SECTOR_SIZE]; /* Data to be cached */
};

void filesys_cache_init (void);
struct cache_entry *block_in_cache (block_sector_t sector);
struct cache_entry* filesys_cache_block_get (block_sector_t sector,
					     bool dirty);
struct cache_entry* filesys_cache_block_evict (block_sector_t sector,
					       bool dirty);
void filesys_cache_write_to_disk (bool halt);
void thread_func_write_back (void *aux);
void thread_func_read_ahead (void *aux);
void spawn_thread_read_ahead (block_sector_t sector);

struct buffer_cache *get_cache_block(block_sector_t sector,int);
void init_cache(void);
void init_cache_block(struct buffer_cache *block);
void * cache_read (struct buffer_cache *b);
void cache_write_back_disk(void);
void disk_flush(struct buffer_cache *block, int access);
struct buffer_cache *find_empty_block(block_sector_t sector_id, int access);
void mark_dirty(struct buffer_cache *block);
void evict(void);
void unlock_buffer_cache(struct buffer_cache *);
void inode_free(block_sector_t sector);
void * init_cache_block_zero(struct buffer_cache *block);
#endif /* filesys/cache.h */

