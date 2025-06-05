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
static bool lazy_load_segment_a(struct page *page, void *aux);//[*]3-L

/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* 파일 기반 가상 메모리(file vm)의 초기화 함수 */
void
vm_file_init (void) {
}

/* 파일을 기반으로 하는 페이지(file-backed page)를 초기화합니다 */
bool//[*]3-L
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
    struct file_page *file_page = &page->file;
    page->operations = &file_ops; // 반드시 file_ops 지정
    (void)file_page;
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
    if (page->frame == NULL)
        return true;

    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        struct file_page *file_page = &page->file;

        //타입 캐스팅 고침
        struct lazy_load_arg *aux = (struct lazy_load_arg *) file_page->aux;
        struct file *file = aux->file;
        off_t ofs = aux->ofs;

        file_write_at(file, page->frame->kva, aux->read_bytes, ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }

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
void *//[*]3-L
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
    // 페이지 크기로 반올림
    size_t read_bytes = length;
    size_t zero_bytes = ROUND_UP(length, PGSIZE) - length;

    struct file *reopen_file = file_reopen(file); // mmap용 새 파일 핸들
    if (reopen_file == NULL)
        return NULL;

    void *va = addr;
    while (read_bytes > 0 || zero_bytes > 0) {
        // 이번 페이지에 읽어야 할 바이트 계산
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        // lazy loading을 위한 aux 구조체 준비
        struct lazy_load_arg *aux = malloc(sizeof(struct lazy_load_arg));
        aux->file = reopen_file;
        aux->ofs = offset;
        aux->read_bytes = page_read_bytes;
        aux->zero_bytes = page_zero_bytes;

        // SPT에 페이지 등록
        if (!vm_alloc_page_with_initializer(VM_FILE, va, writable, lazy_load_segment_a, aux))
            return NULL;

        // 다음 페이지로
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        va += PGSIZE;
        offset += page_read_bytes;
    }

    return addr;
}

/* munmap 작업을 수행합니다 */
void//[*]3-L
do_munmap (void *addr) {
    struct thread *curr = thread_current();
    struct page *page = spt_find_page(&curr->spt, addr);

    while (page != NULL) {
        struct file_page *file_page = &page->file;
        struct lazy_load_arg *aux = (struct lazy_load_arg *) file_page->aux;

        // dirty 플래그를 정확히 확인: 실제 pml4, frame 둘 다 dirty여야 write-back! -> ?? 일단 변경
        if (pml4_is_dirty(curr->pml4, page->va)) {
            file_write_at(aux->file, page->frame->kva, aux->read_bytes, aux->ofs); // [*]3-B. 변경

            // dirty bit 클리어
            pml4_set_dirty(curr->pml4, page->va, false);
            pml4_set_dirty(curr->pml4, page->frame->kva, false);
        }

        // SPT에서 제거 (destroy도 함께)
        vm_dealloc_page(page);
        addr += PGSIZE;
        if (page->operations != &file_ops) // [*]3-B. 추가 - munmap 범위 오버런 방지
            break;
        page = spt_find_page(&curr->spt, addr);
    }
}

//[*]3-L / [*]3-B. 전체적으로 변경
static bool
lazy_load_segment_a(struct page *page, void *aux) {

    uint8_t* kpage = (page->frame)->kva;
	uint8_t* upage = page->va;
	struct load_args_tmp* args = page->uninit.aux;
	
	file_seek(args->file, args->ofs);
	if (file_read (args->file, kpage, args->read_bytes) != (int) args->read_bytes) {
		palloc_free_page (kpage);
		return false;
	}
	memset(kpage + args->read_bytes, 0, args->zero_bytes);
	return true;
}