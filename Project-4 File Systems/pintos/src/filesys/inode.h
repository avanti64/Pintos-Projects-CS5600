#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

//#define DIRECT_BLOCKS 123
//#define INDIRECT_BLOCKS 1
//#define DOUBLE_INDIRECT_BLOCKS 1

/* We have total 125 unused pointers,
   To have faster file access we need to have more direct pointers compare to
   indirect pointers to block. So to have faster file access upto 62kb file size
   I have chosen 123 direct blocks and to support file of size upto 8MB, I am 
   taking 1 direct and 1 as a indirect pointer */
   
   
#define DIRECT_BLOCKS 120
#define INDIRECT_BLOCKS 1
#define DOUBLE_INDIRECT_BLOCKS 1
   
#define PTR_PER_BLOCK 128
//#define INODE_BLOCK_COVERAGE  (DIRECT_BLOCKS + 128 * INDIRECT_BLOCKS + 128 * 128 * DOUBLE_INDIRECT_BLOCKS)
#define INODE_DATA_COVERAGE INODE_BLOCK_COVERAGE * BLOCK_SECTOR_SIZE  /* Max File size supported */
#define DIRECT_INDEX 0
#define INDIRECT_INDEX 120
#define DOUBLE_INDIRECT_INDEX 121

#define INDIRECT_BLOCK_PTRS 128
#define INODE_BLOCK_PTRS 121

#define DIRECT_BLOCKS_COVERAGE (DIRECT_BLOCKS * BLOCK_SECTOR_SIZE)
#define INDIRECT_BLOCKS_COVERAGE (BLOCK_SECTOR_SIZE*INDIRECT_BLOCK_PTRS)
#define DOUBLE_INDIRECT_BLOCKS_COVERAGE (DOUBLE_INDIRECT_BLOCKS * BLOCK_SECTOR_SIZE)
#define INODE_BLOCK_COVERAGE  (DIRECT_BLOCKS + 128 * INDIRECT_BLOCKS + 128 * 128 * DOUBLE_INDIRECT_BLOCKS)
/* 8 megabyte file size limit */
#define MAX_FILE_SIZE 8980480

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t direct_index;				/* starting index of direct block */
    uint32_t indirect_index;            /* starting index of indirect direct block */
    uint32_t double_indirect_index;     /* starting index of double indirect block */
    bool is_Dir;                        /* if true inode represents directory */
    block_sector_t parent;              /* Parent of a given dir/file */
    block_sector_t ptr[INODE_BLOCK_PTRS];     /* Pointers to blocks */
  };
  
 /* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    off_t length;                       /* File size in bytes. */
    off_t read_length;
    size_t direct_index;
    size_t indirect_index;
    size_t double_indirect_index;
    bool is_Dir;
    block_sector_t parent;
    struct lock lock;
	struct lock deny_lock;
	int writers_no;
	struct condition no_writers;
    block_sector_t ptr[INODE_BLOCK_PTRS];  /* Pointers to blocks */
  };
  
struct bitmap;

struct indirect_block
  {
    block_sector_t ptr[INDIRECT_BLOCK_PTRS];
  };

block_sector_t calc_direct_index(const struct inode *inode, off_t pos);
block_sector_t calc_indirect_index(const struct inode *inode, off_t pos);
bool inode_alloc (struct inode_disk *disk_inode);
void inode_dealloc (struct inode *);
void inode_dealloc_indirect_block (block_sector_t *, size_t );
void inode_dealloc_double_indirect_block (block_sector_t *,
					  size_t , size_t );

block_sector_t calc_double_indirect_index(const struct inode *inode, off_t pos);
off_t inode_expand (struct inode *, off_t );
size_t grow_indirect_block (struct inode *,   size_t );
size_t grow_double_indirect_block (struct inode *,  size_t) ;
size_t grow_double_indirect_block_lvl_two (struct inode *inode,
				       size_t new_data_sectors,struct indirect_block *outer_block);
bool is_inode_dir(struct inode *inode);
int get_indirect_level(block_sector_t ptr);
struct inode* get_disk_inode_data(struct inode *inode);

void inode_init (void);
bool inode_create (block_sector_t, off_t, bool);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
bool inode_is_dir (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (struct inode *);
int inode_get_open_cnt (const struct inode *inode);
block_sector_t inode_get_parent (const struct inode *inode);
bool inode_add_parent (block_sector_t parent_sector,
		       block_sector_t child_sector);
void inode_lock (const struct inode *inode);
void inode_unlock (const struct inode *inode);

#endif /* filesys/inode.h */
