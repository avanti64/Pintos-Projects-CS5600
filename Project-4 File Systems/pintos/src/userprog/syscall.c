#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
static void syscall_handler (struct intr_frame *);
/*void sys_exit(int status);
int sys_write(int fd, const void *buffer,unsigned size);
struct file* get_open_file(int fd);
void sys_close(int fd);
tid_t sys_exec(const char *cmd);
void sys_seek(int fd, unsigned position);
int sys_open(const char *file_name);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned size);
int sys_filesize(int fd);
unsigned sys_tell(int fd);
int sys_read(int fd, void *buffer,unsigned size);
void validate_user_ptr(const void *ptr);*/

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&sync);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
//printf ("system call!\n");
  //printf("sys call number is %d\n",*(int *)f->esp);

  validate_user_ptr(f->esp);
  switch(*(int *)f->esp)
  {
	case SYS_HALT:
		halt();
	break;
	
	case SYS_EXIT:                   /* Terminate this process. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		int status = *(int *)(f->esp + 4);
		sys_exit(status);
		break;
	}
	
    case SYS_EXEC:                   /* Start another process. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		const char *cmd = *(char **)(f->esp + 4);
		f->eax = sys_exec(cmd);
		break;
	}
	
	case SYS_WAIT:                   /* Wait for a child process to die. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		tid_t pid = *(int *) (f->esp + 4);
		f->eax = sys_wait(pid);
		break;
	}
	
	case SYS_CREATE:                 /* Create a file. */
	{
		validate_user_ptr((const void *)(f->esp + 16));
		validate_user_ptr((const void *)(f->esp + 20));
		const char *file = *(char **)(f->esp + 16);
		unsigned size = *(int *) (f->esp + 20);
		f->eax = sys_create(file,size);
		break;
	}
	case SYS_REMOVE:                 /* Delete a file. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		const char *rem = *(char **)(f->esp + 4);
		f->eax = sys_remove(rem);
		break;
	}
	
	case SYS_OPEN:                   /* Open a file. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		const char *file = *(char **)(f->esp + 4);
		f->eax = sys_open(file);
		break;
	}
	
	case SYS_FILESIZE:               /* Obtain a file's size. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		int size = *(int *) (f->esp + 4);
		f->eax = sys_filesize(size);
		break;
	}
	
	case SYS_READ:                   /* Read from a file. */
	{
		validate_user_ptr((const void *)(f->esp + 20));
		validate_user_ptr((const void *)(f->esp + 24));
		validate_user_ptr((const void *)(f->esp + 28));
		
		int fd = *(int *) (f->esp + 20);
		void *buffer = *(char **) (f->esp + 24);
		unsigned size  = *(int *) (f->esp + 28);
		f->eax = sys_read(fd,buffer,size);
		break;
	}
	
	case SYS_WRITE:                  /* Write to a file. */
	{
		validate_user_ptr((const void *)(f->esp + 20));
		validate_user_ptr((const void *)(f->esp + 24));
		validate_user_ptr((const void *)(f->esp + 28));
		
		int fd = *(int *) (f->esp + 20);
		const void  *buffer = *(char **) (f->esp + 24);
		unsigned size  = *(int *) (f->esp + 28);
		f->eax = sys_write(fd,buffer,size);
    break;
	}
	
	case SYS_CHDIR:
	{
	   validate_user_ptr((const void *)(f->esp + 4));
	   const char *buffer = *(char **) (f->esp + 4);
	
		f->eax = sys_chdir(buffer);
		break;
	
	 }
	case SYS_MKDIR:
	{
	   	validate_user_ptr((const void *)(f->esp + 4));
		const char *buffer = *(char **) (f->esp + 4);
		f->eax = sys_mkdir(buffer);
	   
	    break;
	}
	case SYS_ISDIR:
	{
	   	validate_user_ptr((const void *)(f->esp + 4));
	    int fd = *(int *) (f->esp + 4);
		f->eax = sys_isdir(fd);
		break;
	}
	
		case SYS_READDIR:
	{
	   		validate_user_ptr((const void *)(f->esp + 16));
            validate_user_ptr((const void *)(f->esp + 20));
		    int fd = *(int *) (f->esp + 16);
		      char* name = *(char **) (f->esp + 20);
		     f->eax = sys_readdir(fd,name);
	   
	    break;
	}
	case SYS_INUMBER:
	{
	   	validate_user_ptr((const void *)(f->esp + 4));
	    int fd = *(int *) (f->esp + 4);
		f->eax = sys_inumber(fd);
	}
	 
	
	case SYS_SEEK:                   /* Change position in a file. */
	{
		validate_user_ptr((const void *)(f->esp + 16));
		validate_user_ptr((const void *)(f->esp + 20));
		int fd = *(int *) (f->esp + 16);
		unsigned pos  = *(int *) (f->esp + 20);
		sys_seek(fd, pos);
		break;
	}
	
	case SYS_TELL:                   /* Report current position in a file. */
	{
		validate_user_ptr((const void *)(f->esp + 4));
		int fd = *(int *) (f->esp + 4);
		f->eax = sys_tell(fd);
		break;
	}
	
	case SYS_CLOSE:
	{
		validate_user_ptr((const void *)(f->esp + 4));
		int fd = *(int *) (f->esp + 4);
		sys_close(fd);
		break;
	}
   
    default:
		thread_exit();
  }  
}

/**
 power off pintos 
 */
 
 
bool sys_chdir(const char* direc)
{
  return filesys_chdir(direc);
}  
void halt(void)
{
	shutdown_power_off();
}

bool sys_isdir(int fd)
{
    struct open_file *f = get_open_file_sys(fd);
		if(f == NULL)
	{
		return false;
	}
	return f->is_dir;
}

int sys_inumber(int fd)
{
  	 struct open_file *f = get_open_file_sys(fd);
	 struct inode *inode;
	 	if(f == NULL)
	{
		return PROCESS_FAIL;
	}
	if(f->is_dir)
	{
	  inode = dir_get_inode(f->dir);
	}
	else
	{
	   inode = file_get_inode(f->file);
	}
	return inode_get_inumber (inode);
}
	 
bool sys_mkdir(const char* direc)
{
   return filesys_create(direc,0, true);
 }
 
 bool sys_readdir(int fd, char* dir_name)
{   
     struct open_file *f = get_open_file_sys(fd);
	if(f == NULL)
	{
		return false;
	}
	if(!f->is_dir)
	{
	  return false;
	 }
    
     if(!dir_readdir(fd, dir_name))
	 {
	    return false;
	}
     return true;
  }
 
void sys_exit(int status)
{
	thread_current()->child->exit_status = status;
	printf("%s: exit(%d)\n",thread_current()->name,status);
	thread_exit();
}

tid_t sys_exec(const char *cmd)
{
	//validate cmd
	validate_user_ptr(cmd);
	
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

bool sys_create(const char *file, unsigned size)
{
	//verify file for bad pointer
	validate_user_ptr(file);
	
	if(!lock_held_by_current_thread(&sync))
		lock_acquire(&sync);
	
	//Check validity of file name
	if (file == NULL || strlen(file) == 0)
	{
		if(lock_held_by_current_thread(&sync))
			lock_release(&sync);
		sys_exit(PROCESS_FAIL);
	}
		
	bool isCreateSucc = filesys_create(file, size,false);
	if(lock_held_by_current_thread(&sync))
		lock_release(&sync);
	return isCreateSucc;
}

int sys_open(const char *file_name)
{
	
	//verify file for bad pointer
	
	validate_user_ptr(file_name);
	
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
	validate_user_ptr(buffer);
	
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
	validate_user_ptr(buffer);
	
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
	validate_user_ptr(file);
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

/**
 Checks the validity of user pointer 
 Exits process if given address is unmapped or lies in kernel memory
 */
void validate_user_ptr(const void *ptr)
{
	//Returns error if ptr doesn't point to user address space
	if (!is_user_vaddr(ptr) || ptr  < 0x08048000)
		sys_exit(PROCESS_FAIL);

	//If kernel address is unmapped then returns error
	void *vptr = pagedir_get_page(thread_current()->pagedir, ptr);
	
	if (vptr == NULL)
	{
		sys_exit(PROCESS_FAIL);
	}
}