/* anon.c: 디스크 이미지가 아닌 페이지, 즉 익명 페이지(anonymous page)의 구현 */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h" //// [*]3-B. 추가

/* 아래 줄은 수정하지 마십시오 */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* 익명 페이지에 대한 데이터를 초기화합니다 */
void
vm_anon_init (void) {
	/* TODO: swap_disk를 설정하세요. */
	swap_disk = NULL;
}

/* 파일 매핑(file mapping)을 초기화합니다 */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* 핸들러를 설정합니다 */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
    return true; // [*]3-B. 추가
}

/* swap 디스크로부터 내용을 읽어 페이지를 swap in 합니다 */
static bool
anon_swap_in (struct page *page, void *kva) {
	// struct anon_page *anon_page = &page->anon;
	memcpy(kva, page->frame->kva, PGSIZE); // [*]3-B. st 구현 전 임시 작성
    return true;
}

/* swap 디스크에 내용을 써서 페이지를 swap out 합니다 */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}

/* 익명 페이지를 파괴(destroy)합니다. PAGE는 호출자에 의해 해제됩니다. */
static void
anon_destroy (struct page *page) {
	struct anon_page *anon_page = &page->anon;
}
