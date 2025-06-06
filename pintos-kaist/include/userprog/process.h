#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct lazy_load_arg {
    struct file   *file;        /* 매핑할 파일 객체                */
    off_t          ofs;         /* 이 페이지를 읽을 파일 내 오프셋   */
    size_t         read_bytes;  /* 이 페이지에 읽어야 할 바이트 수  */
    size_t         zero_bytes;  /* read_bytes 이후 0으로 채울 바이트 수 */
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void argument_stack(char **parse, int count, void **rsp); //[*]3-B. 추가
#ifdef VM
bool lazy_load_segment(struct page *page, void *aux);
#endif

#endif /* userprog/process.h */
