#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);


/* [*]3-Q. lazy loading 초기화를 위해 쓰일 구조체 정의 */
struct lazy_load_arg {
    struct file *file;       // 읽을 파일 포인터
    off_t offset;            // 읽기 시작할 파일 오프셋
    size_t page_read_bytes;  // 이 페이지에서 읽을 바이트 수
    size_t page_zero_bytes;  // 이 페이지에서 0으로 채울 바이트 수
};

#endif /* userprog/process.h */
