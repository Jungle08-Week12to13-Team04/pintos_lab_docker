/* vm.c: 가상 메모리 객체를 위한 일반적인 인터페이스. */
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"

struct list frame_table;
struct lock frame_table_lock;

/* [!] SPT 해시 관련 함수 프로토타입 선언 */
unsigned page_hash(const struct hash_elem *e, void *aux UNUSED);
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
void page_destroy(struct hash_elem *e, void *aux UNUSED);


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


/* 각 서브시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다. */
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

/* 페이지의 타입을 가져옵니다. 이 함수는 페이지가 초기화된 후 
 * 해당 페이지의 타입을 알고 싶을 때 유용합니다.
 * 이 함수는 현재 완전히 구현되어 있습니다. */

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

/* 헬퍼 함수들 */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* 초기화자(initializer)를 사용하여 대기 중인 페이지 객체를 생성합니다.
 * 페이지를 만들고 싶다면 직접 생성하지 말고,
 * 이 함수나 `vm_alloc_page`를 통해 생성해야 합니다. */
/* [*]3-Q. initializer 함수 구현 */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* TODO: 페이지를 생성하고, VM 타입에 따라 적절한 initializer를 선택한 후,
	 * TODO: uninit_new를 호출하여 "uninit" 페이지 구조체를 생성합니다.
	 * TODO: uninit_new를 호출한 후 해당 필드를 수정해야 합니다. */

	/* upage가 이미 점유되어 있는지 확인합니다. */
	if (spt_find_page (spt, upage) != NULL) /* 이미 해당 주소(upage)에 페이지가 등록되어 있다면 중복이므로 false  */
        return false;
    
    struct page *page = (struct page *)malloc(sizeof(struct page)); /* 새로운 page 동적 할당 */
    if (page == NULL) // 메모리 부족 등으로 할당이 실패하면 false 반환
        return false;
    
    /* 페이지 타입에 따라 적절한 initializer 함수 포인터 선택 */
    bool (*page_initializer)(struct page *, enum vm_type, void *) = NULL;
    switch (VM_TYPE(type)) {
        case VM_ANON:      
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        default:            /* 알 수 없는 타입일 경우 free 후 false 반환 */
            free(page);
            return false;
    }
    
    /* uninit page 초기화 수행 */
    /* -> lazy loading 시 실제 로딩될 초기화 함수(init)와 보조 인자(aux)를 포함 */
    uninit_new(page, upage, init, type, aux, page_initializer);

    /* 쓰기 가능 여부 플래그 설정 */
    page->writable = writable;

    // SPT에 삽입
    if (!spt_insert_page(spt, page)) {
        free(page);
        return false;
    }

	/* 모든 작업을 이상 없이 마친 경우 true 반환*/
    return true;
}

/* spt에서 VA를 찾아 해당 페이지를 반환합니다. 오류가 발생하면 NULL을 반환합니다. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page temp;
	temp.va = pg_round_down(va); /* 찾을 va를 페이지 단위로 정렬하기 */
	struct hash_elem *e = hash_find(&spt->spt, &temp.hash_elem); /* [*]3-Q. 임시 page를 만들어 해당 주소를 가진 entry를 hash table에서 찾음 */

	if (e != NULL){
		/* [*]3-Q. e가 NULL이 아니라면, hash entry에서 struct page로 변환해서 반환 */
		return hash_entry(e, struct page, hash_elem);
	} else {
		/* [*]3-Q. NULL일 경우, struct page가 존재하지 않음을 의미, NULL 반환 */
		return NULL ;
	}
}

/* PAGE를 유효성 검사를 거쳐 spt에 삽입합니다. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	/* [*]3-Q. hash_insert는 동일한 키가 존재할 경우 기존 요소를 반환 -> FALSE */
	return hash_insert(&spt->spt, &page->hash_elem) == NULL; 
	/* [*]3-Q. 삽입 성공 시 NULL 반환 -> TRUE */
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* 교체(eviction)될 struct frame을 가져옵니다. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* 하나의 페이지를 교체하고 해당 frame을 반환합니다.
 * 오류가 발생하면 NULL을 반환합니다. */
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc()을 통해 frame을 얻습니다. 사용 가능한 페이지가 없다면 페이지를 교체(evict)한 후 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀 메모리가 가득 찼을 때도,
 * 이 함수는 frame을 교체하여 가용 메모리를 확보합니다. */
/* [*]3-Q 사용자 풀에서 빈 frame 을 가져오거나, */
static struct frame *
vm_get_frame (void) {
    /* struct 구조체 할당*/
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    if (frame == NULL)
        return NULL;

    /* 사용자 풀에서 물리 페이지를 요청 */
    frame->kva = palloc_get_page(PAL_USER);
    if (frame->kva == NULL) { // 사용자 풀에 빈 페이지가 없다면 eviction 수행
        free(frame); // 할당한 frame 구조체 메모리 해제
        frame = vm_evict_frame(); // victim 프레임 확보 (미구현)
        if(frame == NULL)
            return NULL;
    }   else {
        list_push_back(&frame_table, &frame->frame_elem);
    }

    frame->page = NULL;  // 정상적 방법으로 frame을 확보한 경우, 초기화

	// ASSERT (frame != NULL);
	// ASSERT (frame->page == NULL);
	return frame;
}

/* 스택을 확장하는 작업. */
/* [*]3-Q */
static void
vm_stack_growth (void *addr UNUSED) {
    // 1. 일단 접근 주소를 페이지 단위로 정렬(페이지 기준으로 내림)
    void *stack_page = pg_round_down(addr);

    // 2. 최대 스택 크기 초과 방지
    if (stack_page < USER_STACK - MAX_STACK_SIZE)
        return; // 최대 크기보다 더 내려간 주소는 확장하지 않음

    // 3. 해당 페이지를 VM_ANON 타입으로 lazy allocation 요청
    // -> 현재는 데이터 없이 구조만 등록하기(실제 데이터는 fault 후 적재)
    vm_alloc_page_with_initializer(VM_ANON, stack_page, true, NULL, NULL);
}

/* 쓰기 보호(write_protected)된 페이지에서 발생한 fault를 처리합니다. */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/* [*]3-Q. 페이지 폴트 발생 시, 접근한 가상 주소가 유효한지 검사
   필요한 경우 해당 페이지를 물리 메모리에 loading */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	
	/* TODO: 해당 fault가 유효한지 확인합니다. */
	/* TODO: 여기에 코드를 작성해야 합니다. */
    
    // 일단 페이지 정렬 수행(페이지 경계 기준으로 내림) //
    void *page_va = pg_round_down(addr);

    // 1. page fault 유효성 검사 //
    // 1-1. 잘못된 주소 (빈 영역, 커널 영억, GUARD 영역을 가리킬 경우)
    if (addr == NULL)
        return false;
    if (is_kernel_vaddr(addr))
        return false;
    if (addr >= USER_STACK && addr < KERN_BASE)
        return false;

    /* 2. VA를 기반으로 SPT에서 page 찾기 */
    struct page *page = spt_find_page(spt, page_va);

    // 3. SPT에 존재하지 않을 경우 스택 확장 조건 확인.
    if (page == NULL) {
        // 3-1. 현재 rsp보다 8바이트 이하이며(push 직후)
        // 3-2. 전체 스택 크기가 최대치를 초과하지 않음.
        if (addr >= f->rsp - 8 && addr >= USER_STACK - MAX_STACK_SIZE) {
            vm_stack_growth(addr); // 스택 확장
            page = spt_find_page(spt, page_va); // 확장 후 다시 검색
            if (page == NULL) // 그 때도 없으면 false 반환
                return false;
        } else {
            return false;
        }
    }

    // 4. 쓰기 요청인데 읽기 전용 페이지일 경우
    if (write && !page->writable)
        return false;


    // 5. 이상 없을 경우 해당 페이지를 메모리에 로딩
    return vm_do_claim_page(page);
}

/* 페이지를 해제합니다.
 * 이 함수는 수정하지 마세요. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* VA에 할당된 페이지를 확보(claim)합니다. */
/* [*]3-Q. 주어진 VA를 기준으로 SPT에서 page를 찾고, 그 페이지를 실제 메모리에 loading(claim)*/
bool
vm_claim_page (void *va UNUSED) {
	/* TODO: Fill this function */
struct page *page = spt_find_page(&thread_current()->spt, va); // pst_find_page()로 va에 해당하는 page를 찾고,
    if (page == NULL)
        return false;

	return vm_do_claim_page (page); // 찾았다면 메모리에 올림
}

/* Claim the PAGE and set up the mmu. */
/* [*]3-Q. SPT에 등록된 페이지를 실제로 메모리에 load하고 VA-KVA 매핑까지 완료하는 역할*/
static bool
vm_do_claim_page (struct page *page) {
    /* 1. 프레임 확보 */
    struct frame *frame = vm_get_frame ();
    if (frame == NULL)
        return false;

	/* 2. 확보한 frame과 page를 서로 연결 */
	frame->page = page;
	page->frame = frame;

    /* 3. 보조 저장소(anon / file / swap)로부터 실제 데이터 로딩 */
    if (!swap_in(page, frame->kva))
        return false;

    /* MMU의 페이지 테이블에 VA -> KVA 매핑을 추가 */
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable))
        return false;

	return true;
}

/* 새로운 보조 페이지 테이블(supplemental page table)을 초기화합니다. */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt, page_hash, page_less, NULL);
}

/* 보조 페이지 테이블을 src에서 dst로 복사합니다. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* 보조 페이지 테이블이 보유한 자원을 해제합니다. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: 스레드가 보유한 모든 supplemental_page_table을 제거하고,
	 * TODO: 수정된 내용을 스토리지에 다시 씁니다(writeback). */
	hash_destroy(&spt->spt, page_destroy);	
}


/* [*]3-Q. SPT용 hash함수 생성 */

/* [*]3-Q. sturct page의 va 값을 바탕으로 해시값 생성 */
unsigned
page_hash(const struct hash_elem *e, void *aux UNUSED) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* [*]3-Q. 해시 테이블에서 entry를 서로 비교할 때 사용하는 함수(check for duplicate, sort)*/
bool
page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *pa = hash_entry(a, struct page, hash_elem);
    const struct page *pb = hash_entry(b, struct page, hash_elem);
    return pa->va < pb->va;
}

void
page_destroy(struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(page);
}