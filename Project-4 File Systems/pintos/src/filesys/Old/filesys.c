#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static bool name_error(struct dir *dir, struct dir **dirc, char base_name[15]);
/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  init_cache();
  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_write_back_disk();
}


static int
extract_nxt (char buf_part[NAME_MAX], const char **s_part)
{
   char *dest = buf_part;
  const char *source = *s_part;
 
   if (*source == '\0')
    return 0;
	while (*source == '/')
		source++;

  while (*source != '/' && *source != '\0') 
	{
      if (dest < buf_part + NAME_MAX)
        *dest++ = *source;
		else
        return -10;
		source++; 
    }
  *dest = '\0';
  *s_part = source;
  return 1;
}

static bool
get_dir_name (const char *name,
                       char base_name[NAME_MAX + 1],struct dir **dirc) 
{
   int check;
  struct inode *inode;
  struct dir *dir = NULL;
  const char *charac;
  char first_part[NAME_MAX + 1];
  char nxt_part[NAME_MAX + 1];
 
  if (name[0] == '/' || thread_current ()->cur_dir == NULL)
    dir = dir_open_root ();
  else
    dir = dir_reopen (thread_current ()->cur_dir);
  if (dir == NULL)
      return name_error(dir,dirc, base_name);

  charac = name;
  if (extract_nxt (first_part, &charac) <= 0)
   return  name_error(dir,dirc, base_name);

 
  while ((check = extract_nxt (nxt_part, &charac)) > 0)
    {
		printf("before dir_lookup\n");
      if (!dir_lookup (dir, first_part, &inode))
         return name_error(dir,dirc, base_name);

      dir_close (dir);
      dir = dir_open (inode);
      if (dir == NULL)
        name_error(dir,dirc, base_name);

      strlcpy (first_part, nxt_part, NAME_MAX + 1);
    }
  if (check < 0)
   return  name_error(dir,dirc, base_name);
   *dirc = dir;
  strlcpy (base_name, first_part, NAME_MAX + 1);
  return true;
}

static bool name_error(struct dir *dir, struct dir **dirc, char base_name[NAME_MAX + 1])
{
  dir_close(dir);
  *dirc = NULL;
  base_name[0] = '\0';
  return false;
 }
  
  

static struct inode *
get_inode_name (char *inode_name)
{
  if (inode_name[0] == '/' && inode_name[strspn (inode_name, "/")] == '\0') 
    {
      
      return inode_open (ROOT_DIR_SECTOR);
    }
  else 
    {
     
      char buffer_name[NAME_MAX + 1];
	   struct dir *direc;

      if (get_dir_name (inode_name,buffer_name, &direc)) 
        {
		  printf("before lookup in get_inode_name\n");
          struct inode *inode;
          dir_lookup (direc, buffer_name, &inode);
          dir_close (direc);
          return inode; 
        }
      else
        return NULL;
    }
}
/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
 return get_inode_name(name);
}
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir;
  char file_base_name[NAME_MAX + 1];
   bool success = (get_dir_name (name, file_base_name,&dir)
                  && free_map_allocate (&inode_sector));
	 if (success) 
    {


      struct inode *inode;
      if (!is_dir)
        inode = create_file (inode_sector, initial_size);
      else
		inode = dir_create (inode_sector,
                            inode_get_inumber (dir_get_inode (dir))); 
      if (inode != NULL)
        {
          success = dir_add (dir, file_base_name, inode_sector);
		  if(success == false)
           inode_remove(inode);
		   inode_close(inode);
        } else
            success = false;		
   
    }


	 free_map_release (inode_sector);
     dir_close (dir);
    // free(file_name);
     return success;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char buffer_name[NAME_MAX + 1];  
  struct dir *direc;
  bool success = direc != NULL && get_dir_name(name,buffer_name,&direc);
  
  if(success)
  {   
     dir_remove (direc, buffer_name);
     dir_close (direc);
	 return true;
  }  
   else
   return false;
  

} 
  
   

 
/* Change the current directory */


bool 
filesys_chdir(char *dir_name)
{
  struct dir *direc = dir_open(get_inode_name(dir_name));
  if(direc == NULL)
  {
     return false; 
  }
  else
  {
    struct thread* t = thread_current();
	dir_close(t->cur_dir);
	t->cur_dir = direc;
	return true;
}
}
  

/* Formats the file system. */
static void
do_format (void)
{
  
  struct inode *inode;
  printf ("Formatting file system...");
  free_map_create ();
   inode = dir_create(ROOT_DIR_SECTOR, 1);
   if(!inode)
    PANIC ("root directory creation failed");
    inode_close(inode);
  free_map_close ();
  printf ("done.\n");
}
