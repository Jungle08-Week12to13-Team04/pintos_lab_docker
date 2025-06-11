/* file.c: 메모리에 매핑된 파일 객체(mmap된 객체)의 구현 */

#include "vm/vm.h"
#include "threads/vaddr.h" // [*]3-B. 추가
#include "threads/mmu.h"

#include <string.h>  // [*]3-L memset, memcpy
#include <stdlib.h>  // [*]3-L  malloc, free
#include "threads/mmu.h" // [*]3-L pml4_is_dirty, pml4_set_dirty 포함됨
#include "userprog/process.h" // [*]3-L lazy_load_arg 등 선언

#define ROUND_UP(X, STEP) (((X) + (STEP) - 1) & ~((STEP) - 1))//[*]3-L

extern struct lock filesys_lock;  // filesys/filesys.c 에 선언된 락

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* 이 구조체는 수정하지 마십시오 */
const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

extern struct list frame_table;

/* 파일 기반 가상 메모리(file vm)의 초기화 함수 */
void
vm_file_init (void) {
}

/* 파일을 기반으로 하는 페이지(file-backed page)를 초기화합니다 */
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	struct file_page *file_page = &page->file;
    page->operations = &file_ops;
    merge_try_share(page);
    return true;
}




/* 파일로부터 내용을 읽어 페이지를 swap in 합니다 */
// [*]3-L
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
	if (page == NULL)
        return false;

    struct segment_aux *segment_aux = (struct segment_aux *)page->uninit.aux;

    struct file *file = segment_aux->file;
	off_t offset = segment_aux->offset;
    size_t page_read_bytes = segment_aux->page_read_bytes;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

	file_seek (file, offset);

    if (file_read (file, kva, page_read_bytes) != (int) page_read_bytes) {
        // palloc_free_page (kva);
        return false;
    }

    memset ((uint8_t *)kva + page_read_bytes, 0, page_zero_bytes);

    return true;
}



/* 페이지의 내용을 파일에 기록(writeback)하여 swap out 합니다 */
// [*]3-L
static bool
file_backed_swap_out (struct page *page) {

	struct file_page *file_page UNUSED = &page->file;
    if (page == NULL)
        return false;

    struct segment_aux * segment_aux = (struct segment_aux *) page->uninit.aux;

    // CHECK dirty page
    if(pml4_is_dirty(thread_current()->pml4, page->va)){
        file_write_at(segment_aux->file, page->frame->kva, segment_aux->page_read_bytes, segment_aux->offset);
        pml4_set_dirty (thread_current()->pml4, page->va, 0);
    }

    pml4_clear_page(thread_current()->pml4, page->va);

	return true;
}



/* 파일 기반 페이지를 파괴(destroy)합니다. PAGE는 호출자가 해제합니다. */
static void//[*]3-L
file_backed_destroy(struct page *page) {
    merge_delete(page); //[*]3-Q

	// mmap한 페이지가 메모리에 존재했다면 (frame이 있었다면)
	if (page->frame != NULL) {
		struct segment_aux *segment_aux = (struct segment_aux *) page->uninit.aux;

		// dirty 여부 확인 후 파일에 반영
		if (pml4_is_dirty(thread_current()->pml4, page->va)) {
			file_write_at(segment_aux->file, page->frame->kva, segment_aux->page_read_bytes, segment_aux->offset);
			pml4_set_dirty(thread_current()->pml4, page->va, 0);
		}
	}

	// aux 메모리 해제
	if (page->uninit.aux != NULL) {
		free(page->uninit.aux);
		page->uninit.aux = NULL;
	}
}


/* mmap 작업을 수행합니다 */
void *
do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
	struct file *re_file = file_reopen(file);

    void * mmap_addr = addr; 
    size_t read_bytes = length > file_length(file) ? file_length(file) : length; 
    size_t zero_bytes = PGSIZE - (read_bytes % PGSIZE); 

	while (read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = page_read_bytes == PGSIZE ? 0 : PGSIZE - page_read_bytes;

        struct segment_aux *segment_aux = (struct segment_aux*)malloc(sizeof(struct segment_aux));
        segment_aux->file = re_file;
        segment_aux->offset = offset;
        segment_aux->page_read_bytes = page_read_bytes;


		if (!vm_alloc_page_with_initializer (VM_FILE, mmap_addr, writable, lazy_load_segment, segment_aux)) {
			free(segment_aux);
			return NULL;
        }
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;

		mmap_addr += PGSIZE;
		offset += page_read_bytes;
	}
	return addr;
}

/* munmap 작업을 수행합니다 */
/* file.c */

void do_munmap(void *addr) {
	while (true) {
        struct page* page = spt_find_page(&thread_current()->spt, addr);

        if (page == NULL)
            break;

        struct segment_aux * segment_aux = (struct segment_aux *) page->uninit.aux;


        if(pml4_is_dirty(thread_current()->pml4, page->va)) {
            file_write_at(segment_aux->file, page->frame->kva, segment_aux->page_read_bytes, segment_aux->offset); 
            pml4_set_dirty (thread_current()->pml4, page->va, 0);
        }

        pml4_clear_page(thread_current()->pml4, page->va);
        addr += PGSIZE;
    }
}
