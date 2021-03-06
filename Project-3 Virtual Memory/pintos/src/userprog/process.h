#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "threads/synch.h"
#include "threads/thread.h"

#define PRO_NOT_LOADED 0  /* process created but not loaded */
#define PRO_LOAD_SUC 1    /* process load successful */
#define PRO_LOAD_FAIL 2	  /* process load fail */

#define FDMAX 32	      /* FD Max limit per process */
#define FDMIN 2			  /* FD Min for process, 0 & 1 are reserved */
#define MAPIDMAX 32	      /* MAPID Max limit per process */
#define MAPIDMIN 2		  /* MAPID Min for process, 0 & 1 are reserved */

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int add_mmap_file(struct file *file, void *upage);
struct open_file* get_map_file(int fd);
//Structure to hold information about list of open files
struct open_file
{
	struct file *file;		/* File pointer associated with fd */
	int fd;					/* File descriptor or mmap id of a file */
	struct list_elem file_elem;  /*List element to iterate over open file list */
	void *upage;		    /* Tracks process address space for mmap */
};

//Structure to hold information about child status
struct child{
   int cid;				/* child id mappped to thread id */
   bool exit; 			/* true means child process exited */
   struct list_elem child_elem; /* elem to iterate onto list */
   int exit_status;    /* marks exit_status of a child so that parent can refer it */
   int load_status;    /* indicate whether process loaded successfully or not */
   bool wait;          /* true means parent process is waiting on this child */
   struct semaphore sema_load; /* Declaring a struct semaphore for synchronization on load */
   struct semaphore sema_exit; /* Declaring a struct semaphore for synchronization on exit */
  };
   

bool install_page (void *upage, void *kpage, bool writable);   
struct file* get_open_file(int fd);
void close_open_files();
struct child* get_child(int tid);
void remove_children(void);
void remove_child(struct child *child);
void close_open_file(int fd);
int add_open_file(struct file *file);

#define PROCESS_FAIL -1

#endif /* userprog/process.h */
