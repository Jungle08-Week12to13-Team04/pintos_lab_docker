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

extern struct disk *swap_disk;// [*]3-L
extern struct bitmap *swap_table;// [*]3-L
extern struct lock swap_lock;// [*]3-L


/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* 익명 페이지에 대한 데이터를 초기화합니다 */
// [*]3-L
void vm_anon_init(void) {
	/* swap 디스크 초기화 (보통 1번 디스크 1번 파티션으로 설정) */
	swap_disk = disk_get(1, 1);
	/* 전체 swap 공간 크기: 디스크 전체 sector 수 / 한 페이지의 sector 수 */
	size_t swap_size = disk_size(swap_disk) / 8;
	swap_table = bitmap_create(swap_size);
	lock_init(&swap_lock);
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
// [*]3-L
static bool anon_swap_in(struct page *page, void *kva) {
  lock_acquire(&swap_lock);
  size_t swap_idx = page->anon.swap_slot;

  for (int i=0; i<8; i++)
    disk_read(swap_disk, swap_idx * 8 + i, kva + i*DISK_SECTOR_SIZE);

  bitmap_reset(swap_table, swap_idx);
  lock_release(&swap_lock);
  return true;
}


/* swap 디스크에 내용을 써서 페이지를 swap out 합니다 */
// [*]3-L
static bool anon_swap_out(struct page *page) {
  ASSERT(page != NULL);
  lock_acquire(&swap_lock);

  size_t swap_idx = bitmap_scan_and_flip(swap_table, 0, 1, false);
  if (swap_idx == BITMAP_ERROR)
    PANIC("Swap disk full!");

  // 디스크에 페이지 쓰기
  for (int i=0; i<8; i++)
    disk_write(swap_disk, swap_idx * 8 + i, page->frame->kva + i*DISK_SECTOR_SIZE);

  // swap 슬롯 저장
  page->anon.swap_slot = swap_idx;
  page->frame = NULL;

  lock_release(&swap_lock);
  return true;
}


/* 익명 페이지를 파괴(destroy)합니다. PAGE는 호출자에 의해 해제됩니다. */
// [*]3-L
static void anon_destroy(struct page *page) {
	/* anon 페이지 파괴시 할당된 swap slot 반환 */
	if (page->frame == NULL) {
		lock_acquire(&swap_lock);
		bitmap_reset(swap_table, page->anon.swap_slot);
		lock_release(&swap_lock);
	}
}