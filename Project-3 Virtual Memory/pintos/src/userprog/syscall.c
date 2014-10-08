#include "userprog/syscall.h"
#include "devices/timer.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
//#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);


void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sync);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  ////printf ("system call!\n");
  ////printf("sys call number is %d\n",*(int *)f->esp);

  //Save esp i a thread structure, required if page fault 
  //occur for the esp
  thread_current()->esp = f->esp;
  check_and_allocate_mem(f->esp, f->esp);
  switch(*(int *)f->esp)
  {
	case SYS_HALT:
		halt();
	break;
	
	case SYS_EXIT:                   /* Terminate this process. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		int status = *(int *)(f->esp + 4);
		sys_exit(status);
		break;
	}
	
    case SYS_EXEC:                   /* Start another process. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		const char *cmd = *(char **)(f->esp + 4);
		f->eax = sys_exec(cmd);
		break;
	}
	
	case SYS_WAIT:                   /* Wait for a child process to die. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		tid_t pid = *(int *) (f->esp + 4);
		f->eax = sys_wait(pid);
		break;
	}
	
	case SYS_CREATE:                 /* Create a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 16), f->esp);
		check_and_allocate_mem((const void *)(f->esp + 20), f->esp);
		const char *file = *(char **)(f->esp + 16);
		unsigned size = *(int *) (f->esp + 20);
		f->eax = sys_create(file,size);
		break;
	}
	case SYS_REMOVE:                 /* Delete a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		const char *rem = *(char **)(f->esp + 4);
		f->eax = sys_remove(rem);
		break;
	}
	
	case SYS_OPEN:                   /* Open a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		const char *file = *(char **)(f->esp + 4);
		f->eax = sys_open(file);
		break;
	}
	
	case SYS_FILESIZE:               /* Obtain a file's size. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		int size = *(int *) (f->esp + 4);
		f->eax = sys_filesize(size);
		break;
	}
	
	case SYS_READ:                   /* Read from a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 20), f->esp);
		check_and_allocate_mem((const void *)(f->esp + 24),f->esp);
		check_and_allocate_mem((const void *)(f->esp + 28), f->esp);
		
		int fd = *(int *) (f->esp + 20);
		void *buffer = *(char **) (f->esp + 24);
		unsigned size  = *(int *) (f->esp + 28);
		f->eax = sys_read(fd,buffer,size);
		break;
	}
	
	case SYS_WRITE:                  /* Write to a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 20), f->esp);
		check_and_allocate_mem((const void *)(f->esp + 24),f->esp);
		check_and_allocate_mem((const void *)(f->esp + 28), f->esp);
		
		int fd = *(int *) (f->esp + 20);
		const void  *buffer = *(char **) (f->esp + 24);
		unsigned size  = *(int *) (f->esp + 28);
		f->eax = sys_write(fd,buffer,size);
    break;
	}
	
	case SYS_SEEK:                   /* Change position in a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 16), f->esp);
		check_and_allocate_mem((const void *)(f->esp + 20), f->esp);
		
		int fd = *(int *) (f->esp + 16);
		unsigned pos  = *(int *) (f->esp + 20);
		sys_seek(fd, pos);
		break;
	}
	
	case SYS_TELL:                   /* Report current position in a file. */
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		int fd = *(int *) (f->esp + 4);
		f->eax = sys_tell(fd);
		break;
	}
	
	case SYS_CLOSE:
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		int fd = *(int *) (f->esp + 4);
		sys_close(fd);
		break;
	}
	
	case SYS_MMAP:
	{
		check_and_allocate_mem((const void *)(f->esp + 16), f->esp);
		check_and_allocate_mem((const void *)(f->esp + 20), f->esp);
		int fd = *(int *) (f->esp + 16);
		void *addr  = *(void **) (f->esp + 20);
		f->eax = sys_mmap(fd, addr);
		break;
	}
   
	case SYS_MUNMAP:
	{
		check_and_allocate_mem((const void *)(f->esp + 4), f->esp);
		mapid_t mapping = *(mapid_t *) (f->esp + 4);
		sys_munmap(mapping);
		break;
	}
	
    default:
		thread_exit();
  }  
}

/**
 power off pintos 
 */
	
void halt(void)
{
	shutdown_power_off();
}

void sys_exit(int status)
{
	//mark exit status	
	thread_current()->child->exit_status = status;
	printf("%s: exit(%d)\n",thread_current()->name,status);
	thread_exit();
}

/**
	Runs the executable whose name is given in cmd_line, passing
	any given arguments, and returns the new process's program id (pid).
*/
tid_t sys_exec(const char *cmd)
{
	//validate cmd
//	printf("Inside process exec");
	//validate_user_ptr(cmd);
	check_and_allocate_mem(cmd, thread_current()->esp);
	
	//Exceute a given command 
	tid_t tid= process_execute(cmd);
	
	//if process did not created then return error
	if(tid == TID_ERROR)
		return PROCESS_FAIL;
	
	//get the child corresponding to tid
	struct child *child_thread = get_child(tid);
	
	// If child not found in child list,
	if(child_thread == NULL)
		return PROCESS_FAIL;
	
	//wait till child is not loaded 
	//used barrier to enforce cpu to refresh value of load
	if(child_thread->load_status == PRO_NOT_LOADED)
	{ 
		sema_down(&child_thread->sema_load);
	}
	//If child process fails to load then return -1
	if(child_thread->load_status == PRO_LOAD_FAIL)
		return PROCESS_FAIL;
	
	return tid;
}
	
int sys_wait(tid_t pid)
{
	return process_wait(pid);
}

/**
	Creates a new file and return true on success
*/
bool sys_create(const char *file, unsigned size)
{
	//verify file for bad pointer
	//validate_user_ptr(file);
	
	check_and_allocate_mem(file, thread_current()->esp);
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	
	//Check validity of file name
	if (file == NULL || strlen(file) == 0)
	{
		if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
		
	bool isCreateSucc = filesys_create(file, size);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return isCreateSucc;
}

/**
	Opens a given file and returns a valid FD on success
*/
int sys_open(const char *file_name)
{
	
	//verify file for bad pointer
	
	//validate_user_ptr(file_name);
	check_and_allocate_mem(file_name, thread_current()->esp);
	
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	//Check validity of file name
	if(file_name == NULL)
	{
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
	
	//If file name length is 0 then return fd as -1
	if(strlen(file_name) == 0)
	{
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		return -1;
	}
		
	struct file *file = filesys_open(file_name);
	if(file == NULL)
	{
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	//Add file to open file list
	int fd = add_open_file(file);
	
	//validate FD
	if(fd == -1)
	{
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	//deny file write if opened file is executable
	if(strcmp(file_name, thread_current()->name) == 0){
		file_deny_write(file);
	}
	
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);	
	return fd;
}

/**
	Returns the size, in bytes, of the file open as fd.
*/
int sys_filesize(int fd)
{
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	
	//get open file corresponding to given fd
	struct file *file = get_open_file(fd);
	
	//if file not found then return error
	if(file == NULL)
	{
		lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	int file_len = file_length(file);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return file_len;
}

int sys_read(int fd, void *buffer,unsigned size)
{

	//validate buffer for bad pointer
	//validate_user_ptr(buffer);
	check_and_allocate_mem(buffer, thread_current()->esp);
	
	//if size is zero then return 0;
	if(size == 0)
	{
		return 0;
	}
	
	//Check validity of FD
	if(fd < 0 || fd > FDMAX || fd == STDOUT_FILENO)
	{   
	    sys_exit(PROCESS_FAIL);
	}
	if(!lock_held_by_current_thread(&sync))
	  lock_acquire(&sync);
	  
	//If fd==0 means it its stdin reader
	if(fd == STDIN_FILENO)
	{	
		//char c;
		unsigned int i = 0;
		while ( i < size)
		{
			//c = input_getc();
			((char *)buffer)[i++] = input_getc();
		}
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		return i;
	}
	else
	{
		//else write to the file mention by File descriptor
		struct file *f = get_open_file(fd);
		if(f == NULL)
		{   
		     ////printf("File found null\n");
		    if(lock_held_by_current_thread(&sync))
				lock_release(&sync);
			sys_exit(PROCESS_FAIL);
		}
		int read_bytes = file_read(f, buffer, size);
		
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		return read_bytes;
	}
}

int sys_write(int fd, const void *buffer,unsigned size)
{
	
	//validate buffer for bad pointer
	//validate_user_ptr(buffer);
	check_and_allocate_mem(buffer, thread_current()->esp);
	
	//if size is zero then return 0;
	if(size == 0)
	{
		return 0;
	}
	
	//Check validity of FD
	if(fd < 0 || fd > FDMAX || fd == STDIN_FILENO)
	{
		sys_exit(PROCESS_FAIL);
	}
	
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	//If stdout = 1 means , console then write data once to it
    if(fd == STDOUT_FILENO){
		putbuf(buffer, size);
		if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		return size;
	}
	
	//else write to the file mention by File descriptor
	//get open file corresponding to given fd
	struct file *f = get_open_file(fd);
	if(f == NULL)
	{
		if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
	
	//write given buffer to file
	size_t file_size = file_write(f, buffer, size);
	
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return file_size;
}

/**
	Changes the next byte to be read or written in open file fd to position,
	expressed in bytes from the beginning of the file
*/
void sys_seek(int fd, unsigned position)
{
	
	//check the validity of a FD
	if(fd < FDMIN || fd > FDMAX)
	{
		sys_exit(PROCESS_FAIL);
	}
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	//get open file corresponding to given fd
	struct file *file = get_open_file(fd);
	
	if(file == NULL)
	{   
	    if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		return;
	}
	
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	file_seek(file, position);
}

/**
	Returns the position of the next byte to be read or written in 
	open file fd, expressed in bytes from the beginning of the file.
*/
unsigned sys_tell(int fd)
{
	//check the validity of a FD
	if(fd < FDMIN || fd > FDMAX)
	{
		sys_exit(PROCESS_FAIL);
	}
    if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	//get open file corresponding to given fd
	struct file *file = get_open_file(fd);
	
	if(file == NULL)
	{   
	    if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	unsigned offset = file_tell(file);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return offset;
}

/**
	closes file descriptor fd
*/
void sys_close(int fd)
{   
     if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	//Check validity of FD
	if(fd < 2 || fd > FDMAX)
	{   
		if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
	close_open_file(fd);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
}

/**
	Deletes the file called file. Returns true if successful, false otherwise
*/
bool sys_remove(const char *file)
{
	//validate_user_ptr(file);
	check_and_allocate_mem(file, thread_current()->esp);
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	if(file == NULL)
	{
		if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
    bool result = filesys_remove(file);
	
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return result;
}

mapid_t sys_mmap (int fd, void *addr)
{
	//check addr for 0 value
	if((int)addr == 0 || ((int)addr % PGSIZE) > 0)
		return -1;
	
	//Check validity of FD
	if(fd < 0 || fd > FDMAX || fd == STDIN_FILENO)
	{
		return PROCESS_FAIL;
	}
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	struct file *file = get_open_file(fd);
	
	if(file == NULL)
	{
		lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	//To avoid unmapping if original file closed
	struct file *mapped_file = file_reopen(file);
	
	if(mapped_file == NULL)
	{
		lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	size_t flen = file_length(mapped_file);
	
	//check length of a file
	if(flen == 0)
	{
		lock_release(&sync);
		return PROCESS_FAIL;
	}
	
	off_t offset = 0;
	int no_pages = flen / PGSIZE;
	
	//Check for odd bytes
	if(flen % PGSIZE > 0)
		no_pages++;
		
	int i,read_bytes, zero_bytes;
	struct thread * t = thread_current ();
	
	// Get the map id of the thread. If it is found to be 
   // -1 then return process fail.
	mapid_t mapping = add_mmap_file(mapped_file,addr);
	
	if(mapping == -1)
	{
			lock_release(&sync);
		    return PROCESS_FAIL;
	} 
	
	//Add mapping to spt table for lazy lode
	for(i=0; i < no_pages; i++)
	{   
		offset = i * PGSIZE;
	    if(i == no_pages - 1){
			read_bytes = flen % PGSIZE; 
		}
		else
		{
			read_bytes = PGSIZE;
		}
		zero_bytes = PGSIZE - read_bytes;
			
		//record necessary information required for lazy loading
		if(!mmap_entry(addr, mapped_file, offset,read_bytes, zero_bytes))
		{
			lock_release(&sync);
			return PROCESS_FAIL;
		}
	
		// Check to to ensure that mapped files do not 
		// overlap any other segments within the process.
		void* overlap_addition = pg_round_down(addr) + offset;
		void* validate_overlap = pagedir_get_page (t->pagedir, pg_round_down(overlap_addition));
        if(validate_overlap != 0){
			lock_release(&sync);
			return PROCESS_FAIL;
		}
		addr += PGSIZE; 
	} 
	lock_release(&sync);
	return mapping;
}
	   

void sys_munmap(mapid_t mapping)
{
    struct thread *t = thread_current();
	
	struct open_file *f = get_map_file(mapping); 
	void * upage = f->upage;
	size_t flen = file_length(f->file);
	off_t offset = 0;
	int no_pages = flen/PGSIZE;
	
	//Check for odd bytes
	if(flen % PGSIZE > 0)
		no_pages++;
	int i,read_bytes, zero_bytes;
	for(i=0; i < no_pages; i++)
	{    
	    offset = i * PGSIZE;
		void *addr = upage + i*PGSIZE;
		void *vaddr = pagedir_get_page(t->pagedir, addr);
		
		if(pg_ofs (vaddr) == 0 && pagedir_is_dirty (t->pagedir,addr))
		{
		    if(i == no_pages - 1)
				read_bytes = flen % PGSIZE; 
		
			else
				read_bytes = PGSIZE;
			if(!lock_held_by_current_thread(&sync))
				lock_acquire(&sync);
			file_write_at(f->file,addr,read_bytes,offset);
			if(lock_held_by_current_thread(&sync))
				lock_release(&sync);
		}
		pagedir_clear_page (t->pagedir,addr);
	}
		
	list_remove (&f->file_elem);
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	file_close(f->file);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	free(f);
}

/**
 Checks the validity of user pointer 
 Exits process if given address is unmapped or lies in kernel memory
 */
void validate_user_ptr(const void *ptr)
{
	//Returns error if ptr doesn't point to user address space
	if (!is_user_vaddr(ptr) || ptr  < (void *)0x08048000)
		sys_exit(PROCESS_FAIL);

	//If kernel address is unmapped then returns error
	/*void *vptr = pagedir_get_page(thread_current()->pagedir, ptr);
	
	if (vptr == NULL)
	{
		sys_exit(PROCESS_FAIL);
	}*/
}

void check_and_allocate_mem(const void *vaddr, void* esp)
{
  validate_user_ptr(vaddr);
  
  bool load = false;
  struct SPT *spt = spt_find(vaddr);
  
  if (spt != NULL)
    {
      page_load(spt);
      load = spt->isLoaded;
    }
  else if (is_valid_stack_access(esp,vaddr))
    {
      load = stack_growth((void *) vaddr);
    }
  if (!load)
    {
      sys_exit(-1);
    }
	
}

bool is_valid_stack_access (void * esp, void * address)
{
	return (address < PHYS_BASE) && (address > (void*) 0x08048000)
      && (address + 32 >= esp);
}