/* vm.c: 가상 메모리 객체를 위한 일반적인 인터페이스. */

// [*]3-B. 추가
#include "lib/kernel/hash.h" 
#include "threads/thread.h"
#include "threads/vaddr.h" 

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
// Frame Table 락 (concurrent access 동기화용)
struct lock frame_table_lock;

void
vm_init (void) {
  vm_anon_init ();
  vm_file_init ();
  // [*] 전역 Frame Table 초기화
  list_init(&frame_table);
  lock_init(&frame_table_lock);

#ifdef EFILESYS
  pagecache_init ();
#endif
  register_inspect_intr ();
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

/* 교체(eviction)될 struct frame을 가져옵니다. */
static struct frame *
vm_get_victim (void) {
  struct frame *victim = NULL;

  lock_acquire(&frame_table_lock);
  if (!list_empty(&frame_table)) {
    // 단순히 첫 프레임을 victim으로
    struct list_elem *e = list_pop_front(&frame_table);
    victim = list_entry(e, struct frame, elem);
  }
  lock_release(&frame_table_lock);

  return victim;
}


/* 하나의 페이지를 교체하고 해당 frame을 반환합니다.
 * 오류가 발생하면 NULL을 반환합니다. */
static struct frame *
vm_evict_frame (void) {
  struct frame *victim = vm_get_victim();

  if (victim == NULL) 
    PANIC("No victim found for eviction");

  // swap-out 실행
  if (!swap_out(victim->page)) 
    PANIC("swap_out failed!");

  return victim;
}


/* palloc()을 통해 frame을 얻습니다. 사용 가능한 페이지가 없다면 페이지를 교체(evict)한 후 반환합니다.
 * 이 함수는 항상 유효한 주소를 반환합니다. 즉, 사용자 풀 메모리가 가득 찼을 때도,
 * 이 함수는 frame을 교체하여 가용 메모리를 확보합니다. */
static struct frame *
vm_get_frame (void) {
  void *kva = palloc_get_page(PAL_USER);
  if (kva == NULL) {
    struct frame *victim = vm_evict_frame();
    kva = victim->kva;

	// [*]3-B. 추가
	if (victim->page != NULL)
        victim->page->frame = NULL;
    free(victim);
  }

  struct frame *frame = malloc(sizeof(struct frame));
  if (frame == NULL) PANIC("frame alloc failed");
  memset(frame, 0, sizeof(struct frame));
  frame->kva = kva;

  //Frame Table에 등록
  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &frame->elem);
  lock_release(&frame_table_lock);

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

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: 페이지의 VA를 프레임의 PA에 매핑하기 위한 페이지 테이블 엔트리를 삽입합니다. */
	// [*]3-B. 가상 주소와 물리 주소를 매핑
	bool writable = page->writable;

	// pml4_set_page() 실패 시 처리 추가
	if (! pml4_set_page(thread_current()->pml4, page->va, frame->kva, writable)){
		free(frame);
		return false;
	}

	return swap_in (page, frame->kva);
}

/* 새로운 보조 페이지 테이블(supplemental page table)을 초기화합니다. */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	// struct hash 타입의 해시 테이블 객체를 초기화
	hash_init(&spt->spt_hash, page_hash, page_less, NULL); // [*]3-B. spt 초기화
}

/* 보조 페이지 테이블을 src에서 dst로 복사합니다. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
	// [*]3-B. 추가
	struct hash_iterator i;
    hash_first(&i, &src->spt_hash);
    while (hash_next(&i))
    {
        // src_page 정보
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        /* 1) type이 uninit이면 */
        // if (type == VM_UNINIT)
        // { // uninit page 생성 & 초기화
        //     vm_initializer *init = src_page->uninit.init;
        //     void *src_aux = src_page->uninit.aux;

		// 	struct lazy_load_arg *src_lazy = (struct lazy_load_arg *)src_aux;
		// 	struct lazy_load_arg *copy_aux = malloc(sizeof(struct lazy_load_arg));
		// 	if (copy_aux == NULL) return false;

		// 	memcpy(copy_aux, src_lazy, sizeof(struct lazy_load_arg));

        //     // vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);

		// 	copy_aux->file = file_reopen(src_lazy->file);

		// 	if (copy_aux->file == NULL) {
		// 		free(copy_aux);
		// 		return false;
		// 	}

        //     continue;
        // }

		if (type == VM_UNINIT)
	{
		vm_initializer *init = src_page->uninit.init;
		void *src_aux = src_page->uninit.aux;

		struct lazy_load_arg *src_lazy = (struct lazy_load_arg *)src_aux;
		struct lazy_load_arg *copy_aux = malloc(sizeof(struct lazy_load_arg));
		if (copy_aux == NULL) return false;

		copy_aux->ofs = src_lazy->ofs;
		copy_aux->read_bytes = src_lazy->read_bytes;
		copy_aux->zero_bytes = src_lazy->zero_bytes;

		copy_aux->file = file_reopen(src_lazy->file);
		if (copy_aux->file == NULL) {
			free(copy_aux);
			return false;
		}

		if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, copy_aux))
			return false;

		continue;
	}


        /* 2) type이 uninit이 아니면 */
        if (!vm_alloc_page(type, upage, writable)) // uninit page 생성 & 초기화
            // init이랑 aux는 Lazy Loading에 필요함
            // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
            return false;

        // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
        if (!vm_claim_page(upage))
            return false;

        // 매핑된 프레임에 내용 로딩
        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}

// [*]3-B. 추가
void hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

/* 보조 페이지 테이블이 보유한 자원을 해제합니다. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: 스레드가 보유한 모든 supplemental_page_table을 제거하고,
	 * TODO: 수정된 내용을 스토리지에 다시 씁니다(writeback). */

	hash_clear(&spt->spt_hash, hash_page_destroy);	// [*]3-B. 추가
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