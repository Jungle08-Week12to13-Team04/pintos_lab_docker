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
#include "threads/pte.h"  // PTE_W, is_writable
/* 각 서브시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다. */

struct disk *swap_disk;//[*]3-L
struct bitmap *swap_table;//[*]3-L
struct lock swap_lock;//[*]3-L

// 전역 Frame Table 리스트
struct list frame_table; // 모든 frame 목록
// Frame Table 락 (concurrent access 동기화용)
struct lock frame_table_lock; // 동시 접근 제어

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
struct frame *vm_get_victim (void);
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
// static struct frame *
// vm_get_victim (void) {
//   struct frame *victim = NULL;

//   lock_acquire(&frame_table_lock);
//   if (!list_empty(&frame_table)) {
//     // 단순히 첫 프레임을 victim으로
//     struct list_elem *e = list_pop_front(&frame_table);
//     victim = list_entry(e, struct frame, elem);
//   }
//   lock_release(&frame_table_lock);

//   return victim;
// }


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
// static bool
// vm_handle_wp (struct page *page UNUSED) {
// }


// /* Return true on success */
// bool
// vm_try_handle_fault (struct intr_frame *f, void *addr,
//                      bool user, bool write, bool not_present UNUSED)
// {
//   struct thread *t  = thread_current ();
//   struct supplemental_page_table *spt = &t->spt;

//   if (is_kernel_vaddr (addr))
//       return false;

//   void *rsp = is_kernel_vaddr (f->rsp) ? t->save_rsp : f->rsp;
//   struct page *page = spt_find_page (spt, addr);

//   /* ───── 1. 페이지가 존재할 때 ───── */
//   if (page != NULL) {

//       /* 1-A. COW: write fault + PTE R/O */
//       if (write && !pml4_is_writable (t->pml4, page->va)) {
//           struct frame *fr = page->frame;

//           if (fr->ref_cnt > 1) {                 // 공유 프레임
//               void *new_kva = palloc_get_page (PAL_USER | PAL_ZERO);
//               if (!new_kva) return false;

//               memcpy (new_kva, fr->kva, PGSIZE);
//               fr->ref_cnt--;

//               struct frame *new_fr = frame_create (new_kva);
//               new_fr->page    = page;
//               page->frame     = new_fr;

//               pml4_set_page (t->pml4, page->va, new_kva, true);
//           } else {
//               // ref_cnt == 1 → writable 비트만 ON
//               pml4_set_page (t->pml4, page->va, fr->kva, true);
//           }
//           return true;
//       }

//       /* 1-B. lazy 페이지 materialize */
//       if (!page->writable && write)
//           return false;
//       return vm_do_claim_page (page);
//   }

//   /* ───── 2. 스택 자동 확장 ───── */
//   if (user && write &&
//       addr > (USER_STACK - (1 << 20)) &&
//       (uintptr_t)addr >= (uintptr_t)rsp - 32 &&
//       addr < USER_STACK) {
//       vm_stack_growth (addr);
//       return true;
//   }

//   return false;
// }

bool
vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present) {
	struct thread *curr = thread_current();
	struct supplemental_page_table *spt = &curr->spt;
	struct page *page = spt_find_page(spt, addr);

	// [*]1. 스택 자동 확장
	if (page == NULL) {
		void *rsp = user ? f->rsp : curr->save_rsp;
		if (user && write && is_user_vaddr(addr) &&
		    addr >= rsp - 32 &&
		    addr >= USER_STACK - (1 << 20) &&
		    addr < USER_STACK) {
			vm_stack_growth(addr);
			return true;
		}
		return false;
	}

	// [*]2. lazy load 또는 swap-in
	if (not_present) {
		return vm_claim_page(addr);
	}

	// [*]3. COW 처리
	if (write && !pml4_is_writable(curr->pml4, addr)) {
		struct frame *src_frame = page->frame;
		ASSERT(src_frame != NULL);

		if (src_frame->ref_cnt == 1) {
			pml4_set_page(curr->pml4, page->va, src_frame->kva, true);
			page->writable = true;
			return true;
		}

		// 공유 프레임이므로 새 페이지 복사
		void *new_kva = palloc_get_page(PAL_USER);
		if (new_kva == NULL)
			return false;
		memcpy(new_kva, src_frame->kva, PGSIZE);

		struct frame *new_frame = frame_create(new_kva);
		if (new_frame == NULL) {
			palloc_free_page(new_kva);  // 🔧 누수 방지
			return false;
		}

		new_frame->page = page;
		page->frame = new_frame;
		page->writable = true;

		if (!pml4_set_page(curr->pml4, page->va, new_kva, true)) {
			palloc_free_page(new_kva);  // 🔧 누수 방지
			free(new_frame);            // 🔧 frame 구조체 해제 필요 시
			return false;
		}

		ASSERT(src_frame->ref_cnt > 1);
		src_frame->ref_cnt--;
		return true;
	}

	return false;
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

static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();  // frame 받아오기
	ASSERT(frame != NULL);                 // 필수 조건 확인

	// 양방향 연결
	frame->page = page;
	page->frame = frame;

	/* 페이지의 VA를 프레임의 PA에 매핑하기 위한 페이지 테이블 엔트리를 삽입합니다. */
	bool writable = page->writable;
	if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, writable)) {
		// 매핑 실패 시 메모리 해제
		free(frame);
		return false;
	}

	// 스왑 인
	return swap_in(page, frame->kva);
}



/* 새로운 보조 페이지 테이블(supplemental page table)을 초기화합니다. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
                              struct supplemental_page_table *src,
                              struct thread *parent,
                              struct thread *child)
{
  struct hash_iterator i;
  hash_first (&i, &src->spt_hash);

  while (hash_next (&i)) {
      struct page *src_p = hash_entry (hash_cur (&i), struct page, hash_elem);
      void *uva          = src_p->va;
      bool  writable     = src_p->writable;

      /* ───── 1. 아직 materialize 되지 않은 UNINIT 페이지 ───── */
      if (VM_TYPE (src_p->vm_type) == VM_UNINIT) {
          vm_initializer *init = src_p->uninit.init;
          struct lazy_load_arg *old = src_p->uninit.aux;

          struct lazy_load_arg *aux = malloc (sizeof *aux);
          if (!aux) return false;
          *aux = *old;

          if (aux->file && !(aux->file = file_reopen (aux->file))) {
              free (aux);
              return false;
          }

          if (!vm_alloc_page_with_initializer (src_p->vm_type,
                                               uva, writable, init, aux)) {
              free (aux);
              return false;
          }

          // 🔥 반드시 메모리에 할당해야 이후 접근에서 page fault 안 남
          if (!vm_claim_page(uva))
              return false;

          continue;
      }

      /* ───── 2. materialized 페이지 → COW 공유 ───── */
      if (!vm_alloc_page (src_p->vm_type, uva, false))  // 자식은 readonly로
          return false;

      if (!vm_claim_page(uva))  // 🔥 자식도 실제 프레임 받아야 함
          return false;

      struct page *dst_p = spt_find_page (dst, uva);
      ASSERT (dst_p != NULL);

      dst_p->frame         = src_p->frame;
      src_p->frame->ref_cnt++;

      pml4_set_page (parent->pml4, uva, src_p->frame->kva, false);
      pml4_set_page (child->pml4, uva, src_p->frame->kva, false);

      dst_p->writable = writable;
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


/*---------- [*]3-Q ----------*/

// struct frame *frame_create (void *kva) {
//   struct frame *fr = malloc (sizeof *fr);
//   ASSERT (fr != NULL);

//   fr->kva     = kva;
//   fr->page    = NULL;
//   fr->ref_cnt = 1;       // 기본 참조 수 = 1
//   fr->pinned  = false;

//   lock_acquire (&frame_table_lock);
//   list_push_back (&frame_table, &fr->elem);
//   lock_release (&frame_table_lock);

//   return fr;
// }

struct frame *frame_create(void *kva) {
  struct frame *frame = malloc(sizeof(struct frame));
  if (frame == NULL) PANIC("frame alloc failed");
  memset(frame, 0, sizeof(struct frame));

  frame->kva = kva;
  frame->ref_cnt = 1;  // ✅ 명시적으로 참조 카운트 1로 초기화

  lock_acquire(&frame_table_lock);
  list_push_back(&frame_table, &frame->elem);
  lock_release(&frame_table_lock);

  return frame;
}



struct frame *vm_get_frame(void) {
  void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kva == NULL)
    kva = vm_do_eviction();

  if (kva == NULL)
    return NULL;  // 방어적 처리

  struct frame *fr = frame_create(kva);
  return fr;
}

void *
vm_do_eviction (void) {
  struct frame *victim = vm_get_victim ();
  ASSERT (victim != NULL);

  swap_out (victim->page);   // page의 내용을 디스크로 swap
  void *kva = victim->kva;

  // frame_table 에서 제거
  lock_acquire (&frame_table_lock);
  list_remove (&victim->elem);
  lock_release (&frame_table_lock);

  free (victim);
  return kva;
}

struct frame *
vm_get_victim (void) {
  lock_acquire (&frame_table_lock);
  for (struct list_elem *e = list_begin (&frame_table);
       e != list_end (&frame_table); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, elem);
    if (!f->pinned && f->ref_cnt == 1) {
      lock_release (&frame_table_lock);
      return f;
    }
  }
  lock_release (&frame_table_lock);
  PANIC ("no victim frame found");
}



/* Returns true if the PTE for upage in pml4 is writable */
bool
pml4_is_writable(uint64_t *pml4, const void *upage) {
  uint64_t *pte = pml4e_walk(pml4, (uint64_t) upage, false);
  return pte != NULL && is_writable(pte);
}


void
supplemental_page_table_init(struct supplemental_page_table *spt) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}


void frame_destroy(struct frame *f) {
    ASSERT(f != NULL);
    if (--f->ref_cnt == 0) {
        palloc_free_page(f->kva);
        free(f);
    }
}
