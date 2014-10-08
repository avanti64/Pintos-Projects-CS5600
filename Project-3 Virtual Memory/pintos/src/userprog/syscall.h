#include<stdio.h>
#include "threads/thread.h"
#include <user/syscall.h>
#include <threads/synch.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

//lock primitive for syncing read/write access
struct lock sync;
void syscall_init (void);
bool sys_remove(const char *file);
void halt(void);
//int sys_write(int fd, const void *buffer,unsigned size);


void sys_exit(int status);
int sys_write(int fd, const void *buffer,unsigned size);
struct file* get_open_file(int fd);
void sys_close(int fd);
tid_t sys_exec(const char *cmd);
void sys_seek(int fd, unsigned position);
int sys_open(const char *file_name);
int sys_wait(tid_t pid);
bool sys_create(const char *file, unsigned size);
int sys_filesize(int fd);
unsigned sys_tell(int fd);
int sys_read(int fd, void *buffer,unsigned size);
void validate_user_ptr(const void *ptr);
void sys_munmap(mapid_t mapping);
mapid_t sys_mmap (int fd, void *addr);
void check_and_allocate_mem(const void *vaddr, void* esp);
bool is_valid_stack_access (void * esp, void * address);
#endif /* userprog/syscall.h */
