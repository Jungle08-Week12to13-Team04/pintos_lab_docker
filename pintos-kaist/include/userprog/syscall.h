#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stddef.h>  // size_t

typedef int off_t;  // off_t 직접 정의

void syscall_init (void);
struct lock filesys_lock; // [*]2-K: 파일 시스템 락 추가

void *sys_mmap(void *addr, size_t length, int writable, int fd, off_t offset);
void sys_munmap(void *addr);
void sys_close(int fd);

#endif /* userprog/syscall.h */
