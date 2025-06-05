/* anon.c: 디스크 이미지가 아닌 페이지, 즉 익명 페이지(anonymous page)의 구현 */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/vaddr.h" //// [*]3-B. 추가
#include "bitmap.h"   // [*]3-L bitmap 사용
#include "threads/synch.h" // [*]3-L 락
#include <string.h>  // [*]3-L memset, memcpy
#include <stdlib.h>  // [*]3-L  malloc, free

/* 아래 줄은 수정하지 마십시오 */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

// [*]3-B. swap table 양식 변경
struct swap_table {
	struct lock lock;              /* Mutual exclusion. */
	struct bitmap *bit_map;       /* Bitmap of free pages. */ 
};
static struct swap_table swap_table;

/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* 익명 페이지에 대한 데이터를 초기화합니다 */
// [*]3-L / [*]3-B. 전체적으로 변경
void vm_anon_init(void) {
	swap_disk = disk_get(1, 1);
	disk_sector_t swap_disk_size = disk_size(swap_disk);
	uint64_t bit_cnt = swap_disk_size/8;               
	swap_table.bit_map = bitmap_create(bit_cnt);
	ASSERT(swap_table.bit_map);

	lock_init(&swap_table.lock);
}

/* 파일 매핑(file mapping)을 초기화합니다 */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* 핸들러를 설정합니다 */
	page->operations = &anon_ops;
	struct anon_page *anon_page = &page->anon;
	anon_page->swap_idx = -1;
}

/* swap 디스크로부터 내용을 읽어 페이지를 swap in 합니다 */
// [*]3-L / [*]3-B. 전체적으로 변경
static bool anon_swap_in(struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	
	size_t swap_idx = anon_page->swap_idx;
	size_t bitmap_idx = swap_idx / 8;
	int PGSIZE_d8 = PGSIZE/8;
	for(int i = 0; i < 8; i++){
		disk_read(swap_disk, swap_idx+i, page->frame->kva + PGSIZE_d8 * i);
	}
	bitmap_set_multiple(swap_table.bit_map, bitmap_idx, 1, false);
	return true;
}


/* swap 디스크에 내용을 써서 페이지를 swap out 합니다 */
// [*]3-L / [*]3-B. 전체적으로 변경
static bool anon_swap_out(struct page *page) {
	struct anon_page *anon_page = &page->anon;

	lock_acquire (&swap_table.lock);
	size_t swap_idx = 8 * bitmap_scan_and_flip (swap_table.bit_map, 0, 1, false);
	anon_page->swap_idx = swap_idx;
	lock_release (&swap_table.lock);
	
	int PGSIZE_d8 = PGSIZE/8;
	for(int i = 0; i < 8; i++){
		disk_write(swap_disk, swap_idx+i, page->frame->kva + PGSIZE_d8 * i);
	}
	
	pml4_clear_page(thread_current()->pml4, page->va);

	page->frame = NULL;
	return true;;
}


/* 익명 페이지를 파괴(destroy)합니다. PAGE는 호출자에 의해 해제됩니다. */
// [*]3-L / [*]3-B. 전체적으로 변경
static void anon_destroy(struct page *page) {
	/* anon 페이지 파괴시 할당된 swap slot 반환 */
	struct anon_page *anon_page = &page->anon;
	if (page->frame)
		free(page->frame);
	if(page->anon.aux) 
		free(page->anon.aux);
}