#include "userprog/process.h"


//#include <inttypes.h>
//#include <stdlib.h>
#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "../filesys/off_t.h"
#include "../lib/debug.h"
#include "../lib/round.h"
#include "../lib/stdbool.h"
#include "../lib/stddef.h"
#include "../lib/stdint.h"
#include "../lib/stdio.h"
#include "../lib/string.h"
#include "../threads/flags.h"
#include "../threads/interrupt.h"
#include "../threads/malloc.h"
#include "../threads/palloc.h"
#include "../threads/thread.h"
#include "../threads/synch.h"
#include "../threads/vaddr.h"



//#include "filesys/directory.h"
#include "gdt.h"
#include "pagedir.h"
//#include "threads/init.h"
#include "tss.h"

int add_open_file(struct file *file);
/*struct file* get_open_file(int fd);
void close_open_files();
struct thread* get_child(int tid);
void remove_children(void);
void remove_child(struct thread *child);
void close_open_file(int fd);
*/



static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void push_stack(void **esp, char *file_name);
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy, *fn_copy1;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
	
  fn_copy1 = palloc_get_page (0);
  if (fn_copy1 == NULL)
    return TID_ERROR;
	
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy1, file_name, PGSIZE);
  
  char *saveptr;
 
  file_name = strtok_r( fn_copy1, " ", &saveptr);
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 


  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  //Send only filename in load function
  char *org_args, *saveptr;
  org_args = (char *) malloc(128);
  //printf("file_name = %s, len= %d\n",file_name,strlen(file_name));
  strlcpy(org_args, file_name,strlen(file_name)+1);
 // printf("before strtok_r()1\n");
  file_name = strtok_r( file_name, " ", &saveptr);



 // printf("before strtok_r()2\n");

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (file_name, &if_.eip, &if_.esp);
  struct thread* t = thread_current();

  //Changes for argument passing


  if(success)
  {
    push_stack(&if_.esp,org_args);
    t->child->load_status = PRO_LOAD_SUC;
  } 
   else{
     t->child->load_status = PRO_LOAD_FAIL;
}

 sema_up(&thread_current()->child->sema_load);

	 
	
 
  /*printf("\n\n");
  hex_dump((int) if_.esp, if_.esp, 0xc0000000 - (int)if_. esp, true);
  printf("\n\n");*/
  free(org_args);
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

static void push_stack(void **esp, char *file_name){
	//determine argc count by going over file_name
	  char *str, *saveptr,*token;
	  char *str1;
	  int argc = 0;

	  str = (char *) malloc(128);
	  strlcpy(str,file_name,strlen(file_name)+1);
	  str1 = (char *) malloc(128);
	  strlcpy(str1,file_name,strlen(file_name)+1);


      //	str = file_name;
	  int i;
	  for(i=0;;i++,str=NULL){
		  token = strtok_r(str," ",&saveptr);
		  if(token == NULL)
			  break;
		  argc++;
	  }

	//Create argv array
	 char **argv = malloc(argc * sizeof(char *));

	 //strlcpy(str,file_name,strlen(file_name));
	//str = file_name;
	 //copy args into argv
	 for(i=0;i<argc;i++,str1=NULL){
		 token = strtok_r(str1," ",&saveptr);
	  	 if(token == NULL)
	  		 break;
	  	 *esp -= strlen(token)+1;
	  	 argv[i] = *esp;
//		 printf("Putting token =%s of len=%d in stack\n",token,strlen(token)); 
	//  	 printf("*esp is =%x\n",*esp);
		 memcpy(*esp,token,strlen(token)+1);
	  }

	  //The null pointer sentinel ensures that argv[argc] is a null pointer
	  argv[argc] = 0;

	  free(str);
	  free(str1);

	  //Word align for best performance round the stack pointer down
	  //to a multiple of 4 before the first push.
	  uint8_t offset = (uint8_t)*esp % 4;
	  *esp -= offset;
	  memcpy(*esp,&argv[argc],offset);


	for(i=argc;i>=0; i--){

		*esp -= sizeof(char *);
		//printf("pushing argv addr =%x\n",argv[i]);
		memcpy(*esp, &argv[i], sizeof(char *));


	}
	//printf("pushed args in rev order\n");
	//Push address of argv, which is the last push argv[0] in stack
	char *argvAddr;
	argvAddr = *esp;
	*esp -= sizeof(char **);
	memcpy(*esp, &argvAddr, sizeof(char **));
	//printf("pushed argv base addr in stack\n");

	//Push argc onto stack
	*esp -= sizeof(int);
	memcpy(*esp, &argc, sizeof(int));
	//printf("pushed argc in tack\n");

	//push fake return address onto stack
	*esp -= sizeof(void *);
	memcpy(*esp, &argv[argc], sizeof(void *));

	//printf("pushed fake return addr in stack\n");
	free(argv);

}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
	//printf("Inside process_wait()\n");
	//struct thread *t = thread_current();
	//printf("Process wait called by %s\n",t->name);
	struct child *child = get_child(child_tid);
	//printf("get child completed\n");
	//printf("child is %s\n",child->name);
	//If no direct child then return error
	if(child == NULL)
		return PROCESS_FAIL;
	
	//If already waiting on the child then return error
	if(child->wait)
		return PROCESS_FAIL;
	
	//make wait on child true so that parent won't wait on same child
	child->wait = true;

	
	//unless child exits , keep on waiting
    if(!child->exit){
	     sema_down(&child->sema_exit);
	   }

	
	//get the exit_status of the child
	int exit_status = child->exit_status;
	
	//remove child from parent list
	remove_child(child);

	//printf("End of process_wait()\n");
	return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  
  //make exit status as true
  cur->child->exit = true;

  //printf("inside process_Exit\n");
  //Remove all children of a parent
  remove_children();









 // printf("inside process_Exit1\n");

		cur->child->exit = true; 
		sema_up(&cur->child->sema_exit);

  //remove all opened files by a process
  close_open_files();
  





  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  // printf("1/n ");
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */


  file = filesys_open (file_name);


  //file_deny_write(file);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */



  file_close (file);


  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;





      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);



      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);

          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);


      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {

          palloc_free_page (kpage);

          return false; 


        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

    }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;













  kpage = palloc_get_page (PAL_USER | PAL_ZERO);









  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);

      if (success)

        *esp = PHYS_BASE;





      else

        palloc_free_page (kpage);




    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or

   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}


/*
  Adds opened file to the list of open file to the
  open files list of process
  returns : file descriptor assigned to file
  */
int add_open_file(struct file *file)
{

	
	struct open_file *f = (struct open_file *) malloc(sizeof(struct open_file));
	struct thread *t = thread_current();

	//printf("inside add_open_file\n");
	//Limit maximum fd open per process
	if(list_size(&t->open_files) == FDMAX)
		return -1;

	
	f->fd = t->fd;
	//Increment file descriptor count of current thread

	t->fd += 1;
	f->file = file;
	list_push_back(&t->open_files, &f->file_elem);
	






















	return f->fd;
}
	
/*
  Returns the list of open files by a thread.
  returns : Structure of file
  */
struct file* get_open_file(int fd)
{
	/*struct thread *t = thread_current();
	struct list_elem *current = list_head(&t->open_files)->next;


	//printf("inside get_open_file\n");
	while(current->next != NULL)
	{
		struct open_file *of = list_entry(current, struct open_file, file_elem);
		if( fd == of->fd)
		{
			return of->file;
		}
		current = current->next;
	}







	return NULL;*/
	


	
	struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->open_files);

    while (e != list_end (&t->open_files))
    {
      next = list_next(e);
      struct open_file *of = list_entry (e, struct open_file, file_elem);
	  if( fd == of->fd)
		{
			return of->file;
		}

	  e = next;
	}
	return NULL;
}

struct open_file * get_open_file_sys(int fd)
{
	struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->open_files);

    while (e != list_end (&t->open_files))
    {
      next = list_next(e);
      struct open_file *of = list_entry (e, struct open_file, file_elem);
	  if( fd == of->fd)
		{
			return of;
		}

	  e = next;
	}
	return NULL;
}

/**
  When called closes the open file with the given fd value
 */
void close_open_file(int fd)
{
	/*struct thread *t = thread_current();
	struct list_elem *current = list_head(&t->open_files)->next;

	//printf("Inside close_open_file()\n");
	while(current->next != NULL)
	{
		struct open_file *of = list_entry(current, struct open_file, file_elem);



		//Remove file is matching fd found
		if( fd == of->fd)
		{
			file_close(of->file);
			list_remove(&of->file_elem);
			free(of);
		}
		current = current->next;
	}*/
	struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->open_files);

    while (e != list_end (&t->open_files))
    {
      next = list_next(e);
      struct open_file *of = list_entry (e, struct open_file, file_elem);
	  if( fd == of->fd)
		{
			file_close(of->file);
			list_remove(&of->file_elem);
			free(of);
		}
	  e = next;
	}
	
}

/**
  When called closes all the open files 
  by a process.
*/
void close_open_files()
{
	/*struct thread *t = thread_current();
	struct list_elem *current = list_head(&t->open_files)->next;

	printf("Inside close_open_files()\n");
	while(current->next != NULL)
	{
		struct open_file *of = list_entry(current, struct open_file, file_elem);

		printf("open file fd :%d\n",of->fd);
		file_close(of->file);
		// Remove the list elem from the list.
		printf("before list_remove\n");
		list_remove(&of->file_elem);
		printf("after list_remove\n");
		free(of);
















		

































		printf("after freeing\n");
		current = current->next;
		printf("after next \n");
	}*/
	
	struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->open_files);

    while (e != list_end (&t->open_files))
    {
      next = list_next(e);
      struct open_file *of = list_entry (e, struct open_file, file_elem);
	  file_close(of->file);
	  // Remove the list elem from the list.
	  list_remove(&of->file_elem);
	  free(of);
	  e = next;
	}	
}

/**
   Returns the child for a given thread with the given tid.
   returns : Structure of child thread
*/
struct thread* get_child(int tid)
{
	/*struct thread *t = thread_current();
	struct list_elem *current = list_head(&t->child_list)->next;
	
	while(current->next != NULL)
	{
		struct thread *cur = list_entry(current, struct thread,child_elem);

		// check if the thread id matches the thread id from the list
		if(tid == cur->tid)
			return cur;
		current = current->next;
	}
	return NULL;
	*/
	
	/*struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->child_list);

    while (e != list_end (&t->child_list))
    {
      next = list_next(e);
      struct thread *cur = list_entry(e, struct thread,child_elem);
	  if(tid == cur->tid)
			return cur;
	  e = next;
	}
	return NULL;*/
	
	
	struct thread *cur = thread_current();
	struct list_elem *e;
	
	//printf("Inside get child\n");
	for(e = list_begin(&cur->child_list); e != list_end(&cur->child_list);
	e = list_next(e))
	{
		struct child *c = list_entry(e, struct child, child_elem);
		//printf("get-child: child is  tid=%d\n",t->tid);
		if(tid == c->cid)
			return c;
	}
	return NULL;
}

/**
  When called removes all the children from the 
  child list.
 */
void remove_children(void)
{
//	printf("Inside remove_children\n");
	/*struct thread *t = thread_current();
	struct list_elem *current = list_head(&t->child_list)->next;
	
	while(current->next != NULL)
	{
		struct thread *cur = list_entry(current, struct thread, child_elem);
		
		list_remove(&cur->child_elem);
		current = current->next;
	}*/
	
	struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->child_list);
   // printf("removed children\n");
	//printf("Removed children called by :%s\n",t->name);
    while (e != list_end (&t->child_list))
    {
      next = list_next(e);
      struct child *child = list_entry(e, struct child,child_elem);
	//  printf("chlild tid = %d and name = %s\n",cur->tid,cur->name);
	  list_remove(&child->child_elem);
	  free(child);
	  e = next;
	}
}

/**
  When called removes all the children from the 
  child list.
 */

void remove_child(struct child *child)
{
    // Remove the child from the list.
	//printf("Inside remove_child\n");
	list_remove(&child->child_elem);

	//printf("******** remove success *******\n");
}

