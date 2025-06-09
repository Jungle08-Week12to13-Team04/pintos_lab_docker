#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include "lib/kernel/hash.h" // [*]3-B. spt - hash 사용

enum vm_type {
	/* 초기화되지 않은 페이지 */
	VM_UNINIT = 0,
	/* 파일과 관련 없는 페이지, 즉 anonymous 페이지 */
	VM_ANON = 1,
	/* 파일과 관련된 페이지 */
	VM_FILE = 2,
	/* 페이지 캐시를 포함하는 페이지 (Project 4용) */
	VM_PAGE_CACHE = 3,

	/* 상태를 저장하기 위한 비트 플래그 */

	/* 추가 정보를 저장하기 위한 보조 비트 플래그 마커입니다.
 	 * 값이 int 안에 들어가기만 한다면, 더 많은 마커를 추가할 수 있습니다. */
	VM_MARKER_0 = (1 << 3),
	// VM_STACK = (1 << 3), //[*]3-B. 추가
	VM_MARKER_1 = (1 << 4),

	/* 이 값을 초과하지 마십시오. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;
struct file_page;

#define VM_TYPE(type) ((type) & 7)

/* "페이지"를 나타내는 구조체입니다.
 * 이는 일종의 "부모 클래스"이며, 네 가지 "자식 클래스"를 갖습니다.
 * 각각 uninit_page, file_page, anon_page, 그리고 page_cache(Project 4)입니다.
 * 이 구조체에 정의된 멤버는 삭제하거나 수정하지 마십시오. */
struct page {
	const struct page_operations *operations;
	void *va;              /* 사용자 공간 상의 주소 */
	struct frame *frame;   /* 프레임에 대한 역참조 포인터 */

	/* Your implementation */
	struct hash_elem hash_elem; // [*]3-B. hash 연결 list_elem
	int writable; // [*]3-B. writable 필드
	enum vm_type vm_type; // [*]3-B. 페이지 타입

	/* 타입별 데이터는 union 안에 결합되어 있습니다.
	 * 각 함수는 자동으로 현재 union 타입을 감지합니다. */
	union {
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file; //[*]3-B. 포인터 형식으로 변경 필요??
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* "프레임"을 나타내는 구조체 */
struct frame {
    void *kva; // 프레임의 커널 가상주소
    struct page *page; // 연결된 유저 페이지
    struct list_elem frame_elem; // frame_table에서 연결될 list 요소
    bool pinned; // 교체 보호 여부
	int ref_cnt; //[*]3-Q 동일 프레임을 공유하는 페이지 수  
};

// [*]3-B. 추가
struct segment_aux {
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

/* 페이지 연산을 위한 함수 테이블입니다.
 * 이는 C에서 "인터페이스"를 구현하는 한 가지 방법입니다.
 * 메서드 테이블을 구조체의 멤버에 넣고,
 * 필요할 때마다 해당 메서드를 호출하는 방식입니다. */
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

/* 현재 프로세스의 메모리 공간을 표현하는 구조체입니다.
 * 이 구조체에 대해 어떤 특정한 설계를 강제하고 싶지 않습니다.
 * 전체적인 설계는 전적으로 여러분에게 달려 있습니다. */
struct supplemental_page_table {
	struct hash spt_hash; // [*]3-B. spt - hash 사용
};

#include "threads/thread.h"
void supplemental_page_table_init (struct supplemental_page_table *spt);
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);
void supplemental_page_table_kill (struct supplemental_page_table *spt);
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);

// [*]3-B. 추가
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

#endif  /* VM_VM_H */