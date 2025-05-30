/* file.c: 메모리에 매핑된 파일 객체(mmap된 객체)의 구현 */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

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
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* 핸들러(handler)를 설정합니다 */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* 파일로부터 내용을 읽어 페이지를 swap in 합니다 */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* 페이지의 내용을 파일에 기록(writeback)하여 swap out 합니다 */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* 파일 기반 페이지를 파괴(destroy)합니다. PAGE는 호출자가 해제합니다. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* mmap 작업을 수행합니다 */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
}

/* munmap 작업을 수행합니다 */
void
do_munmap (void *addr) {
}
