/* vm.c: 가상 메모리 객체를 위한 일반적인 인터페이스. */

// [*]3-B. 추가
#include "lib/kernel/hash.h" 
#include "threads/thread.h"
#include "threads/vaddr.h" 
#include "userprog/process.h" 
#include "threads/mmu.h"

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "filesys/file.h"
/* 각 서브시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다. */

struct disk *swap_disk;//[*]3-L
struct bitmap *swap_table;//[*]3-L
struct lock swap_lock;//[*]3-L

// 전역 Frame Table 리스트
struct list frame_table;


void
vm_init (void) {
  vm_anon_init ();
  vm_file_init ();

#ifdef EFILESYS
  pagecache_init ();
#endif
  register_inspect_intr ();

  list_init(&frame_table);
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
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* upage가 이미 점유되어 있는지 확인합니다. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: 페이지를 생성하고, VM 타입에 따라 적절한 initializer를 선택한 후,
		 * TODO: uninit_new를 호출하여 "uninit" 페이지 구조체를 생성합니다.
		 * TODO: uninit_new를 호출한 후 해당 필드를 수정해야 합니다. */
		/* TODO: 페이지를 spt에 삽입합니다. */
 

		// [*]3-B. 페이지 생성 후 초기화, 필드 수정 후 spt에 삽입
		
		struct page* page = (struct page*)malloc(sizeof(struct page));
		ASSERT(page);
		
		bool (*initializer)(struct page *, enum vm_type, void *);
		switch(VM_TYPE(type)){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;			
				break;
			default:
				PANIC("###### vm_alloc_page_with_initializer [unvalid type] ######");
				break;
		}

		uninit_new(page, upage, init, type, aux, initializer);

		page->writable = writable;
		page->vm_type = type;

		if(spt_insert_page(spt, page))
			return true;
	}
err:
	return false;
}

/* spt에서 VA를 찾아 해당 페이지를 반환합니다. 오류가 발생하면 NULL을 반환합니다. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL; // 나중에 사용할 임시 struct page 포인터 선언
	/* TODO: Fill this function. */

	// [*]3-B. spt에서 주어진 가상 주소 va에 해당하는 페이지 정보 찾기
	struct page temp;
	temp.va = pg_round_down(va);  // 페이지 정렬
	struct hash_elem *e = hash_find(&spt->spt_hash, &temp.hash_elem);
	if (e == NULL) return NULL;
	return hash_entry(e, struct page, hash_elem);
	// return page;
}

/* PAGE를 유효성 검사를 거쳐 spt에 삽입합니다. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	
	// [*]3-B. spt에 page를 삽입하는데, 가상주소가 spt에 존재하지 않을 경우에만 삽입
	return hash_insert(&spt->spt_hash, &page->hash_elem) == NULL ? true : false;
	
	// return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

// /* 교체(eviction)될 struct frame을 가져옵니다. */
// static struct frame *
// vm_get_victim (void) {
// 	struct frame *victim = NULL;
// 	struct thread *curr = thread_current();
//     struct list_elem *frame_e;

// 	for (frame_e = list_begin(&frame_table); frame_e != list_end(&frame_table); frame_e = list_next(frame_e)) {
//         victim = list_entry(frame_e, struct frame, frame_elem);
//         if (pml4_is_accessed(curr->pml4, victim->page->va))
//             pml4_set_accessed (curr->pml4, victim->page->va, 0); 
//         else
//             return victim;
//     }

// 	return victim;
// }

// [*]3-Q
static struct frame *
vm_get_victim (void) {                                    // Clock 알고리듬으로 희생 프레임 선택
    struct frame *victim = NULL;
    struct thread *curr = thread_current ();

    for (struct list_elem *e = list_begin (&frame_table);
         e != list_end (&frame_table);
         e = list_next (e)) {

        victim = list_entry (e, struct frame, frame_elem);

        /* 🔸 공유(ref_cnt>1) 또는 pinned 프레임은 건너뛴다 */
        if (victim->ref_cnt > 1 || victim->pinned)
            continue;

        if (pml4_is_accessed (curr->pml4, victim->page->va))
            pml4_set_accessed (curr->pml4, victim->page->va, 0);
        else
            return victim;                                // 접근 안 된 프레임 선택
    }
    return victim;                                        // fallback
}



/* 하나의 페이지를 교체하고 해당 frame을 반환합니다.
 * 오류가 발생하면 NULL을 반환합니다. */
static struct frame *
vm_evict_frame (void) {
  struct frame *victim = vm_get_victim();

	if(victim->page != NULL){
		swap_out(victim -> page);
		return victim;
	}
	return NULL;
}


/* palloc()을 통해 frame을 얻습니다. 사용 가능한 페이지가 없다면 페이지를 교체(evict)한 후 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀 메모리가 가득 찼을 때도,
 * 이 함수는 frame을 교체하여 가용 메모리를 확보합니다. */
static struct frame *
vm_get_frame (void) {

	struct frame *frame = (struct frame*)malloc(sizeof(struct frame)); 

	frame->kva = palloc_get_page(PAL_USER); 
    if(frame->kva == NULL) { 
        frame = vm_evict_frame(); 
        frame->page = NULL;

        return frame; 
    }
    list_push_back (&frame_table, &frame->frame_elem); 
    frame->page = NULL;
	frame->pinned = false; // [*]3-Q 기본은 pinned가 아님
	frame->ref_cnt = 0;  // [*]3-Q 공유 카운트 0으로 초기화
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}


// [*]3-B. 스택 확장 함수
/* 스택을 확장하는 작업. */
static void
vm_stack_growth (void *addr UNUSED) {

	addr = pg_round_down(addr);

	while(1){
		if(!spt_find_page(&thread_current()->spt,addr)){
			if (vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true)){
				vm_claim_page(addr);
				memset(addr, 0, PGSIZE);
			}
			else
				PANIC("vm_alloc_page failed in vm_stack_growth function");
		}
		else
			break;
		addr = addr + PGSIZE;
	}
}


/* 쓰기 보호(write_protected)된 페이지에서 발생한 fault를 처리합니다. */
static bool
vm_handle_wp (struct page *page UNUSED) {
}


/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;

	if(is_kernel_vaddr(addr)){
    return false;
	}

	void *rsp = is_kernel_vaddr(f->rsp) ? thread_current()->save_rsp : f->rsp;
	struct page *page = spt_find_page(spt,addr);

	if(page){
		if (page->writable == 0 && write){
			return false;
		}
		return vm_do_claim_page (page);
	}
	else{
		if(is_kernel_vaddr(f->rsp) && thread_current()->save_rsp){
			rsp = thread_current()->save_rsp;
		}

		if(user && write && addr > (USER_STACK - (1<<20)) && (int)addr >= ((int)rsp)-32 && addr < USER_STACK){
			vm_stack_growth(addr);
			return true;
		}
		return false;
	}
}

/* 페이지를 해제합니다.
 * 이 함수는 수정하지 마세요. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}


/* VA에 할당된 페이지를 확보(claim)합니다. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

    // [*]3-B. spt에서 va에 해당하는 page 찾기
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)
        return false;

	return vm_do_claim_page (page);
}

// /* Claim the PAGE and set up the mmu. */
// static bool
// vm_do_claim_page (struct page *page) {
// 	struct frame *frame = vm_get_frame ();

// 	/* Set links */
// 	frame->page = page;
// 	page->frame = frame;

// 	/* TODO: 페이지의 VA를 프레임의 PA에 매핑하기 위한 페이지 테이블 엔트리를 삽입합니다. */
// 	// [*]3-B. 가상 주소와 물리 주소를 매핑

//     struct thread *curr = thread_current();
// 	bool writable = page -> writable; 
// 	pml4_set_page(curr->pml4, page->va, frame->kva, writable); 

// 	return swap_in (page, frame->kva);
// }

// [*]3-Q
static bool
vm_do_claim_page (struct page *page) {                    // 요청한 page를 실제 물리 프레임에 매핑
    struct frame *frame;                                  // 사용할 프레임

    if (page->frame != NULL) {                            // 이미 프레임이 존재(다른 SPT가 선점) / 공유
        frame = page->frame;                              // 같은 프레임 사용
        frame->ref_cnt++;                                 // 참조 수 증가 / ref_cnt +1
    } else {                                              // 프레임이 처음 필요한 상황
        frame = vm_get_frame ();                          // 새 프레임 확보
        frame->page = page;                               // 대표 페이지 지정
        page->frame = frame;                              // 역참조
        frame->ref_cnt = 1;                               // 첫 참조
    }

    /* 현재 스레드의 페이지 테이블에 매핑 */
    if (!pml4_set_page (thread_current ()->pml4,
                        page->va, frame->kva, page->writable))
        return false;                                     // 매핑 실패 시 false

    /* 디스크/파일에서 실제 내용 불러오기 (lazy-load·swap-in) */
    return swap_in (page, frame->kva);                    // 내용 로드 후 true/false 반환
}



/* 새로운 보조 페이지 테이블(supplemental page table)을 초기화합니다. */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	// struct hash 타입의 해시 테이블 객체를 초기화
	hash_init(&spt->spt_hash, page_hash, page_less, NULL); // [*]3-B. spt 초기화
}

// /* 보조 페이지 테이블을 src에서 dst로 복사합니다. */
// bool
// supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
// 		struct supplemental_page_table *src UNUSED) {
	
// 	// [*]3-B. 추가
// 	struct thread *curr = thread_current(); 

// 	struct hash_iterator i; 
//     hash_first (&i, &src->spt_hash);
//     while (hash_next (&i)) {
//         struct page *parent_page = hash_entry (hash_cur (&i), struct page, hash_elem); 
//         enum vm_type parent_type = parent_page->operations->type; 
//         if(parent_type == VM_UNINIT){
//             if(!vm_alloc_page_with_initializer(parent_page->uninit.type, parent_page->va, \
// 				parent_page->writable, parent_page->uninit.init, parent_page->uninit.aux))
//                 return false;
// 		}
//         else { 

// 			if (parent_type & VM_MARKER_0)
// 				setup_stack(&thread_current()->tf); 

// 			else
// 				if(!vm_alloc_page(parent_type, parent_page->va, parent_page->writable)) 
// 					return false;
// 				if(!vm_claim_page(parent_page->va)) 
// 					return false;
			

//             struct page* child_page = spt_find_page(dst, parent_page->va);
//             memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE); 
// 		}
//     }
//     return true;
// }

//[*]3-Q
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
                              struct supplemental_page_table *src) {
    struct hash_iterator it;
    hash_first (&it, &src->spt_hash);

    while (hash_next (&it)) {
        struct page *p_parent = hash_entry (hash_cur (&it), struct page, hash_elem);

        /* ① UNINIT 페이지 → lazy 전략 그대로 복사 */
        if (page_get_type (p_parent) == VM_UNINIT) {
            if (!vm_alloc_page_with_initializer (p_parent->uninit.type,
                                                 p_parent->va,
                                                 p_parent->writable,
                                                 p_parent->uninit.init,
                                                 p_parent->uninit.aux))
                return false;
            continue;
        }

        /* ② 이미 프레임이 존재하는 materialized 페이지 → 프레임 공유 */
        if (!vm_alloc_page (page_get_type (p_parent),
                            p_parent->va, p_parent->writable))
            return false;

        struct page *p_child = spt_find_page (dst, p_parent->va);
        ASSERT (p_child != NULL);

        p_child->frame = p_parent->frame;                // 🔸 같은 물리 프레임
        p_parent->frame->ref_cnt++;                      // 🔸 참조 수 +1

        if (!pml4_set_page (thread_current ()->pml4,
                            p_child->va, p_child->frame->kva,
                            p_child->writable))
            return false;
    }
    return true;
}


// [*]3-B. 추가
static void
spt_destroy(struct hash_elem *e, void* aux) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    free(p);
}

/* 보조 페이지 테이블이 보유한 자원을 해제합니다. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: 스레드가 보유한 모든 supplemental_page_table을 제거하고,
	 * TODO: 수정된 내용을 스토리지에 다시 씁니다(writeback). */
	struct hash_iterator i;

	if (&spt->spt_hash == NULL)
		return;

    hash_first (&i, &spt->spt_hash);
	while (hash_next (&i)) {
        struct page *page = hash_entry (hash_cur (&i), struct page, hash_elem);

        if (page_get_type(page) == VM_FILE)
            do_munmap(page->va);
			
    }
    hash_destroy(&spt->spt_hash, spt_destroy);
}


// [*]3-B. hash_init에 필요한 함수 선언
// struct page 안에 있는 가상 주소 (va)를 해시의 기준으로 사용
// hash_bytes(&p->va, sizeof p->va): 가상 주소를 바이트 단위로 해시하여 고유한 정수 값 반환
// -> 결과적으로 가상 주소 하나당 struct page 하나를 해시 테이블에 저장
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

// [*]3-B. hash_init에 필요한 함수 선언
// 두 struct page의 va를 비교하여 정렬 순서를 판단, 해시 테이블의 충돌 해결 과정에서 사용됨
// -> 결과적으로 가상 주소 작은 순서대로 정렬
bool 
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* -------------------------[*]3-Q----------------------------
   보조: SPT에 남아 있는 모든 VA의 PTE를 지우고
        공유 프레임 ref_cnt 를 최종 정리한다.
   호출 시점: supplemental_page_table_kill() 바로 **다음**
 ------------------------------------------------------------- */
/* ==== vm/vm.c ==== */
#include "threads/mmu.h"            /* 🔸 is_user_vaddr, pml4_* helpers */

void
spt_drop_pte_mappings (struct supplemental_page_table *spt,
                       uint64_t *pml4)
{
    struct hash_iterator it;
    hash_first (&it, &spt->spt_hash);

    while (hash_next (&it)) {
        struct page *page = hash_entry (hash_cur (&it), struct page, hash_elem);

        /* ① user 영역 주소만 처리 */
        if (!is_user_vaddr (page->va))
            continue;

        /* ② 매핑이 있으면 clear & ref_cnt-- */
        if (pml4_get_page (pml4, page->va) != NULL) {
            pml4_clear_page (pml4, page->va);

            if (page->frame != NULL) {
                struct frame *f = page->frame;
                f->ref_cnt--;

	            if (f->ref_cnt == 0) {              /* 🔸 마지막 참조 */
    	            list_remove (&f->frame_elem);
        	        palloc_free_page (f->kva);
            	    free (f);
                	page->frame = NULL;             /* 🔑 더 이상 사용 금지 */
	            }
            }
        }
    }
}
