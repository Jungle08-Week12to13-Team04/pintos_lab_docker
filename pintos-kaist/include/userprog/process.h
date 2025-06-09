#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void argument_stack(char **parse, int count, void **rsp); //[*]3-B. 추가
#ifdef VM
bool lazy_load_segment(struct page *page, void *aux);
bool setup_stack(struct intr_frame *if_);
#endif


/* 부모-자식 통신용 노드 -------- */
struct wait_status {
    struct list_elem elem;     /* 부모의 children 리스트 연결용 */
    struct semaphore  sema;    /* 자식 → 부모 종료 신호 */
    int   exit_code;           /* 자식의 exit(status) 값 */
    bool  exited;              /* 자식이 exit() 호출했는가? */
    bool  waited;              /* 부모가 이미 wait() 했는가? */
};

#endif /* userprog/process.h */
