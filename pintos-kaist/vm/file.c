/* file.c: 메모리에 매핑된 파일 객체(mmap된 객체)의 구현 */

#include "vm/vm.h"
#include "threads/vaddr.h" // [*]3-B. 추가

#include <string.h>  // [*]3-L memset, memcpy
#include <stdlib.h>  // [*]3-L  malloc, free
#include "threads/mmu.h" // [*]3-L pml4_is_dirty, pml4_set_dirty 포함됨
#include "userprog/process.h" // [*]3-L lazy_load_arg 등 선언

#define ROUND_UP(X, STEP) (((X) + (STEP) - 1) & ~((STEP) - 1))//[*]3-L


static bool file_backed_swap_in (struct page *page, void *kva);//[*]3-L
static bool file_backed_swap_out (struct page *page);//[*]3-L
static void file_backed_destroy (struct page *page);//[*]3-L

/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

extern struct list frame_table;
extern struct lock frame_tabl                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          e_lock;

/* 파일 기반 가상 메모리(file vm)의 초기화 함수 */
void
vm_file_init (void) {
}

/* 파일을 기반으로 하는 페이지(file-backed page)를 초기화합니다 */
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    struct file_page *file_page = &page->file;
    page->operations = &file_ops; // file_ops 반드시 지정!

    //이 부분이 반드시 필요;;
    file_page->aux = page->uninit.aux;

    (void)type;
    (void)kva;
    return true;
}




/* 파일로부터 내용을 읽어 페이지를 swap in 합니다 */
// [*]3-L
static bool
file_backed_swap_in (struct page *page, void *kva) {
    struct file_page *file_page = &page->file;
    struct lazy_load_arg *aux = (struct lazy_load_arg *) file_page->aux;

    struct file *file = aux->file;
    off_t ofs = aux->ofs;
    size_t read_bytes = aux->read_bytes;
    size_t zero_bytes = PGSIZE - read_bytes;

    // 파일에서 read_bytes만큼 읽어오기
    if (file_read_at(file, kva, read_bytes, ofs) != (int)read_bytes)
        return false;

    // 나머지는 0으로 채움 (zero-fill)
    memset(kva + read_bytes, 0, zero_bytes);
    return true;
}



/* 페이지의 내용을 파일에 기록(writeback)하여 swap out 합니다 */
// [*]3-L
static bool
file_backed_swap_out (struct page *page) {

	struct file_page *file_page UNUSED = &page->file;
	struct load_args_tmp* aux = page->file.aux;

	if (pml4_is_dirty(thread_current()->pml4,page->va)){
		file_seek(aux->file, aux->ofs);
		file_write(aux->file, page->va, aux->read_bytes);
		pml4_set_dirty(thread_current()->pml4, page->va, 0); //?
	} 

	pml4_clear_page(thread_current()->pml4, page->va);
	
	page->frame = NULL;

	return true;
}



/* 파일 기반 페이지를 파괴(destroy)합니다. PAGE는 호출자가 해제합니다. */
static void//[*]3-L
file_backed_destroy(struct page *page) {
	struct file_page *file_page = &page->file;
    struct lazy_load_arg *aux = (struct lazy_load_arg *) file_page->aux;
    if (aux != NULL)
		free(aux);  
}


/* mmap 작업을 수행합니다 */
void *
do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    struct file *reopen_file = file_reopen(file);
    if (reopen_file == NULL)
        return NULL;

    // 실제로 읽을 수 있는 파일의 남은 바이트 계산
    size_t file_len = file_length(reopen_file);
    size_t remain = (offset < file_len) ? (file_len - offset) : 0;
    size_t read_bytes = (remain < length) ? remain : length;
    size_t zero_bytes = ROUND_UP(length, PGSIZE) - read_bytes;

    void *va = addr;
    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = (read_bytes < PGSIZE) ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_load_arg *aux = malloc(sizeof(struct lazy_load_arg));
        aux->file = reopen_file;
        aux->ofs = offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, va, writable, lazy_load_segment, aux))
            return NULL;

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        va += PGSIZE;
        offset += page_read_bytes;
    }

    return addr;
}


/* munmap 작업을 수행합니다 */
/* file.c */

void do_munmap(void *addr) {
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(&curr->spt, addr);

    while (page != NULL) {
        struct file_page *file_page = &page->file;
        struct lazy_load_arg *aux = (struct lazy_load_arg *) file_page->aux;

        /* 1) 사용자 VA 레벨에서만 dirty 비트를 확인 */
        if (page->frame != NULL && pml4_is_dirty(curr->pml4, page->va)) {
            /* 수정된 데이터를 파일에 기록 */
            file_write_at(aux->file,
                          page->frame->kva,
                          aux->read_bytes,
                          aux->ofs);
            /* dirty 비트를 초기화 */
            pml4_set_dirty(curr->pml4, page->va, false);
        }

        /* 2) 사용자 PTE만 제거 so that future accesses will fault */
        pml4_clear_page(curr->pml4, page->va);

        /* 3) associated frame을 frame_table에서 제거하고, 물리 페이지(커널 VA) 해제 */
        if (page->frame != NULL) {
            /* a) 전역 frame_table 락을 잡고 리스트에서 제거 */
            lock_acquire(&frame_table_lock);
            list_remove(&page->frame->elem);
            lock_release(&frame_table_lock);

            /* b) 물리 페이지(커널 VA) 반환 */
            palloc_free_page(page->frame->kva);

            /* c) struct frame 객체도 free */
            free(page->frame);
            page->frame = NULL;
        }

        /* 4) SPT에서 page 객체 자체도 해제 */
        vm_dealloc_page(page);

        /* 5) 다음 페이지로 이동 (연속 매핑인 경우) */
        addr += PGSIZE;
        if (page->operations != &file_ops)
            break;
        page = spt_find_page(&curr->spt, addr);
    }
}
