#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "filesys/free-map.h"
#include "threads/synch.h"
/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };
static struct lock lock_inode;
/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */

struct inode *
dir_create (block_sector_t sector, block_sector_t dir_parent)
{  
  struct inode *inode = inode_create(sector, true);
  if(inode !=NULL)
  {
    struct dir_entry no_entries[2];
	
	memset(no_entries, 0, sizeof no_entries);
	int size_0 = sizeof no_entries[0].name;
	int size_1 = sizeof no_entries[1].name;
	no_entries[0].inode_sector = sector;
	strlcpy(no_entries[0].name, ".", size_0);
    
	/* Set the in_use to true */
	no_entries[0].in_use = true; 
	
	/* Set the parent directory */
	no_entries[1].inode_sector = dir_parent;
	strlcpy(no_entries[1].name, "..",size_1);
	no_entries[1].in_use = true;
	int size = sizeof (no_entries);
	if(size != inode_write_at(inode, no_entries,size,0))
	{
	   inode_close(inode);
	   inode_remove(inode);
	   inode = NULL;
	}
}
return inode;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL && is_inode_dir(inode))
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);
// Add this in inode
    inode_lock (dir->inode);
  if (lookup (dir, name, &e, NULL))
  {
  // Add this inode.c
    inode_unlock (dir->inode);
    *inode = inode_open (e.inode_sector);
	}
  else
  {
    *inode = NULL;
	}

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX || strchr(name, '/'))
    return false;

  /* Check that NAME is not in use. */

    inode_lock (dir->inode);
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
 
    inode_unlock (dir->inode);
    return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;
  char char_buf[NAME_MAX+1];
  struct dir* char_dir = NULL;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if(strcmp(name, "..") == false || strcmp(name, "."))
     return success;
     // Add this in inode.c
    inode_lock (dir->inode);
  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

	if(is_inode_dir(inode))
	{
        inode_lock (inode);
	   int open_cnt;
       lock_acquire (&lock_inode);
      open_cnt = inode->open_cnt;
      lock_release (&lock_inode);
	  if(open_cnt > 1)
	  {
	   
        inode_unlock (inode);
		if(char_dir != NULL)
         dir_close(char_dir);
        inode_unlock (dir->inode);
        inode_close (inode);
        return success;
	  }
	  inode_unlock(inode);
		
	  if(dir_readdir(char_dir,char_buf) == true)
	  {
	     if(char_dir != NULL)
         dir_close(char_dir);
        inode_unlock (dir->inode);
        inode_close (inode);
        return success;
	  }
	}

	
/* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
 if(char_dir != NULL)
    dir_close(char_dir);
		 // Add in inode.c
 inode_unlock (dir->inode);
 inode_close (inode);
 return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;
 
    inode_lock (dir->inode);
  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use && strcmp(e.name, "..") && strcmp(e.name, "."))
        {
         
          inode_unlock (dir->inode);
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
    inode_unlock (dir->inode);
    return false;
}
