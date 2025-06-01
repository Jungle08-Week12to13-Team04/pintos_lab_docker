/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

struct list frame_table;// 전역 Frame Table 자료구조
struct lock frame_table_lock;// 전역 Frame Table 자료구조

// 프레임 할당 함수
// frame_allocate()
// 프레임을 할당하고 Frame Table에 등록하는 함수이다.
struct frame *
frame_allocate(enum palloc_flags flags, struct page *page) {
    // 1. palloc_get_page()로 물리 프레임을 할당한다.
    void *kva = palloc_get_page(flags); // palloc_get_page는 PAL_USER로 할당
    if (kva == NULL) { // 2. 물리 프레임이 부족하면 Eviction을 시도
        kva = evict_frame(); // evict_frame()에서 프레임 확보
    }

    // 3. frame 구조체를 위한 메모리 할당
    struct frame *f = malloc(sizeof(struct frame)); // malloc으로 struct frame 공간 확보
    ASSERT(f != NULL); // 할당 실패 시 Panic 발생

    // 4. frame 구조체 필드 채우기
    f->kva = kva; // 커널 가상주소 설정
    f->page = page; // 연결된 유저 페이지
    f->pinned = false; // 기본적으로 Eviction 보호 상태 아님

    // 5. 전역 Frame Table에 추가 (락으로 보호)
    lock_acquire(&frame_table_lock); // Frame Table 보호 락 획득
    list_push_back(&frame_table, &f->elem); // Frame Table에 frame 추가
    lock_release(&frame_table_lock); // 락 해제

    // 6. 생성한 frame 반환
    return f; // 성공적으로 할당된 frame 반환
}


// frame_free()
// 이미 할당된 프레임을 해제하는 함수이다.
// Frame Table에서 제거하고, 물리 메모리도 반환하며, frame 구조체 자체도 메모리 해제한다.
void frame_free(struct frame *f) {
    // 1. 전달받은 frame 포인터가 NULL이 아닌지 확인한다.
    ASSERT(f != NULL); // NULL이면 치명적 오류로 Panic

    // 2. Frame Table에서 이 프레임을 제거하기 위해 락을 획득한다.
    lock_acquire(&frame_table_lock); // Frame Table 보호 락 획득

    // 3. Frame Table 리스트에서 프레임을 제거한다.
    list_remove(&f->elem); // 프레임 리스트에서 요소 제거

    // 4. Frame Table의 락을 해제한다.
    lock_release(&frame_table_lock); // 락 해제

    // 5. 실제로 물리 메모리(프레임의 페이지)를 반환한다.
    palloc_free_page(f->kva); // PintOS의 palloc_free_page로 페이지 반환

    // 6. frame 구조체 자체의 메모리도 해제한다.
    free(f); // malloc으로 할당했던 frame 구조체 공간 해제
}



// 프레임 Eviction 함수: 프레임이 부족할 때 하나를 선택해서 비우는 함수이다.
void *evict_frame(void) {
    // 1. Eviction 대상 프레임을 저장할 변수 선언
    struct frame *victim = NULL;

    // 2. Eviction 중에는 Frame Table에 동시 접근이 있으면 안 되므로 락을 획득한다.
    lock_acquire(&frame_table_lock);

    // 3. 프레임 테이블의 맨 처음 요소부터 순회 시작
    struct list_elem *e = list_begin(&frame_table);

    // 4. 무한 루프를 돌면서 Eviction 대상 프레임을 찾는다.
    while (true) {
        // 4-1. 리스트의 끝까지 다 돌았으면 다시 처음부터 시작한다.
        if (e == list_end(&frame_table)) {
            e = list_begin(&frame_table); // 리스트 처음으로 되돌리기
        }

        // 4-2. 리스트 요소를 frame 구조체로 변환한다.
        struct frame *f = list_entry(e, struct frame, elem);

        // 4-3. Eviction 후보 조건 검사
        //      - pinned 상태가 아니어야 함 (Eviction 보호 안되는 상태)
        //      - 실제 유저 페이지를 사용 중인 프레임이어야 함
        if (!f->pinned && f->page != NULL) {
            // TODO: 접근 비트 검사 로직을 Clock 알고리즘처럼 추가할 수 있다.
            // 예) 첫 번째 탐색에서는 accessed bit를 클리어하고 넘어감.
            // 예) 두 번째 탐색에서 accessed bit가 이미 클리어된 프레임을 Eviction 대상으로 선택.

            // 4-4. 여기서는 단순히 조건을 만족하는 첫 프레임을 victim으로 선정
            victim = f;
            break; // Eviction 대상이 결정되면 루프 탈출
        }

        // 4-5. 다음 프레임으로 이동
        e = list_next(e);
    }

    // 5. Eviction 대상이 여전히 NULL이면 치명적 오류로 Panic
    if (victim == NULL) {
        PANIC("No victim frame found!"); // Frame Table에 Eviction 가능한 프레임이 없으면 치명적 오류
    }

    // 6. Eviction 대상의 데이터를 swap-out (또는 파일에 다시 저장)
    //    victim->page의 타입에 따라 anon/file의 swap_out 구현이 호출됨
    swap_out(victim->page);

    // 7. Frame Table에서 victim 프레임을 제거
    list_remove(&victim->elem);

    // 8. victim 프레임의 커널 가상주소(kva)를 저장해둔다.
    void *kva = victim->kva;

    // 9. victim의 frame 구조체 메모리 자체를 해제
    free(victim);

    // 10. Frame Table 락을 해제
    lock_release(&frame_table_lock);

    // 11. Eviction된 프레임의 커널 가상주소를 반환
    return kva;
}




/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
	list_init(&frame_table);
	lock_init(&frame_table_lock);
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */

	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
