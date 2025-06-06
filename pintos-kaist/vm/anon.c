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

#define SECTORS_PER_PAGE 8

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
    size_t disk_sectors = disk_size(swap_disk);
    size_t swap_slot_cnt = disk_sectors / SECTORS_PER_PAGE;
    swap_table.bit_map = bitmap_create(swap_slot_cnt);
    ASSERT(swap_table.bit_map);
    lock_init(&swap_table.lock);
}

/* 파일 매핑(file mapping)을 초기화합니다 */
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    page->operations = &anon_ops;
    struct anon_page *anon_page = &page->anon;
    anon_page->swap_idx = (size_t)-1; // 아직 스왑 아님
    return true;
}

/* swap 디스크로부터 내용을 읽어 페이지를 swap in 합니다 */
// [*]3-L / [*]3-B. 전체적으로 변경
static bool anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
    size_t swap_idx = anon_page->swap_idx;

    for (int i = 0; i < SECTORS_PER_PAGE; i++) {
        disk_read(swap_disk, swap_idx * SECTORS_PER_PAGE + i, kva + DISK_SECTOR_SIZE * i);
    }
    // swap slot 반환
    lock_acquire(&swap_table.lock);
    bitmap_set(swap_table.bit_map, swap_idx, false);
    lock_release(&swap_table.lock);
    return true;
}


/* swap 디스크에 내용을 써서 페이지를 swap out 합니다 */
// [*]3-L / [*]3-B. 전체적으로 변경
static bool anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;

    lock_acquire(&swap_table.lock);
    size_t swap_idx = bitmap_scan_and_flip(swap_table.bit_map, 0, 1, false);
    if (swap_idx == BITMAP_ERROR) {
        lock_release(&swap_table.lock);
        return false; // swap 공간 부족
    }
    anon_page->swap_idx = swap_idx;
    lock_release(&swap_table.lock);

    for (int i = 0; i < SECTORS_PER_PAGE; i++) {
        disk_write(swap_disk, swap_idx * SECTORS_PER_PAGE + i, page->frame->kva + DISK_SECTOR_SIZE * i);
    }
    // PML4에서 페이지 clear 등 필요한 처리
    page->frame = NULL;
    return true;
}


/* 익명 페이지를 파괴(destroy)합니다. PAGE는 호출자에 의해 해제됩니다. */
// [*]3-L / [*]3-B. 전체적으로 변경
static void anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    // frame은 vm에서 할당/해제 책임, 여기서 free할 필요 없음(프레임 테이블이 관리)
    // aux 포인터도 익명 페이지에는 불필요
}