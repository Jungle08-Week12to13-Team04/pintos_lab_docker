/* anon.c: 디스크 이미지가 아닌 페이지, 즉 익명 페이지(anonymous page)의 구현 */

#include "vm/vm.h"
#include "devices/disk.h"

#include "threads/synch.h"//[*]3-L_이현재_0602_2230추가_어나니머스구현
#include "bitmap.h"//이현재_0602_2230추가_어나니머스구현
#include "threads/vaddr.h"//이현재_0602_2230추가_어나니머스구현

//[*]3-L_스왑 디스크, 스왑 테이블, 락 선언 및 초기화
static struct disk *swap_disk; // swap 디스크 핸들러를 저장하는 전역 변수 (swap 디스크 접근 위해 추가됨)
static struct bitmap *swap_table; // swap 슬롯 사용 여부를 관리할 비트맵 (slot 관리 위해 추가됨)
static struct lock swap_lock; // swap_table 동기화를 위한 락 (경쟁 상태 방지 위해 추가됨)


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
//[*]3-L_anongla
void
vm_anon_init (void) {
    swap_disk = disk_get(1, 1); // 스왑 디스크 획득
    swap_table = bitmap_create(disk_size(swap_disk) / 8); // 슬롯 수 = 섹터수 / 8
    lock_init(&swap_lock); // 락 초기화
}


//[*]3-L_anon 페이지 초기화
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) { // 페이지 생성될 때 호출되는 초기화
    page->operations = &anon_ops; // 이 페이지의 동작 집합을 anon_ops로 지정
    struct anon_page *anon_page = &page->anon;
    anon_page->swap_slot = BITMAP_ERROR; // 아직 swap 슬롯 없으므로 초기값 지정
    return true; // 성공적으로 초기화
}

//[*]3-L_swap 슬롯 없는 경우 zero-fill 처리
static bool
anon_swap_in (struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;

    if (anon_page->swap_slot == BITMAP_ERROR) {
        // 처음 할당된 anon 페이지 → swap 슬롯 없음 → zero-fill!
        memset(kva, 0, PGSIZE);
        return true;
    }

    // 기존처럼 swap-in (swap 슬롯에서 데이터 읽어오기)
    lock_acquire(&swap_lock);
    for (int i = 0; i < 8; i++)
        disk_read(swap_disk, anon_page->swap_slot * 8 + i, kva + i * DISK_SECTOR_SIZE);
    bitmap_flip(swap_table, anon_page->swap_slot);
    lock_release(&swap_lock);

    anon_page->swap_slot = BITMAP_ERROR;
    return true;
}


//[*]3-L_swap-out: 메모리에서 swap 영역으로 내보내는 함수, 한마디로 이빅션.
static bool
anon_swap_out (struct page *page) { // Eviction 시, 메모리 페이지를 swap 영역에 저장하는 함수 (VM 구현 위해 필요)
    struct anon_page *anon_page = &page->anon; // anon_page 메타데이터 획득

    lock_acquire(&swap_lock); // swap_table에 대한 락 획득
    size_t slot = bitmap_scan_and_flip(swap_table, 0, 1, false); // 비어있는 swap 슬롯 탐색 및 사용중 표시
    if (slot == BITMAP_ERROR) PANIC("No swap slot available!"); // 사용 가능한 슬롯 없으면 panic

    for (int i = 0; i < 8; i++) // 4KB를 8섹터에 나눠 기록
        disk_write(swap_disk, slot * 8 + i, page->frame->kva + i * DISK_SECTOR_SIZE); // 메모리 → 디스크 쓰기
    lock_release(&swap_lock); // 락 해제

    anon_page->swap_slot = slot; // anon_page에 swap 슬롯 번호 기록
    page->frame = NULL; // 이제 프레임 연결 해제 (swap-out 완료)
    return true; // 성공적으로 swap-out
}

//[*]3-L_anon_destroy: anon 페이지 파괴 시, 할당된 swap 슬롯 반환
static void
anon_destroy (struct page *page) { // 페이지 제거할 때 호출되는 cleanup 함수 (메모리 해제 + swap 슬롯 반환)
    struct anon_page *anon_page = &page->anon;
    if (anon_page->swap_slot != BITMAP_ERROR) { // 할당된 swap 슬롯 있으면
        lock_acquire(&swap_lock); // 동기화
        bitmap_flip(swap_table, anon_page->swap_slot); // 슬롯 free 상태로 바꿈
        lock_release(&swap_lock); // 락 해제
    }
}