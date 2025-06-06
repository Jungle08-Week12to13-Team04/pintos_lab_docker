/* uninit.c: 초기화되지 않은(uninitialized) 페이지의 구현
 *
 * 모든 페이지는 처음 생성될 때 uninit 페이지로 태어납니다.
 * 첫 번째 페이지 폴트가 발생하면, 핸들러 체인이 `uninit_initialize`를 호출합니다
 * (page->operations.swap_in을 통해).
 * `uninit_initialize` 함수는 해당 페이지를 특정한 유형의 페이지 객체 
 * (anon, file, page_cache 등)로 변환하며,
 * 그 과정에서 `vm_alloc_page_with_initializer` 함수로부터 전달된 초기화 콜백을
 * 호출하여 페이지 객체를 초기화합니다.
 */

#include "vm/vm.h"
#include "vm/uninit.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* 이 구조체는 수정하지 마십시오 */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* 이 함수는 수정하지 마십시오 */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* 첫 번째 페이지 폴트 발생 시 페이지를 초기화합니다 */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* 먼저 값을 복사해 둡니다. page_initialize가 해당 값을 덮어쓸 수 있기 때문입니다. */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	/* TODO: 이 함수를 수정해야 할 수도 있습니다. */
	return uninit->page_initializer (page, uninit->type, kva) &&
		(init ? init (page, aux) : true);
}

/* uninit_page가 보유한 자원을 해제합니다. 대부분의 페이지는 다른 유형의 페이지 객체로
 * 변환되지만, 실행 도중 한 번도 참조되지 않은 페이지가 남아 있을 수 있으며,
 * 이들은 프로세스 종료 시까지 uninit 상태로 존재할 수 있습니다.
 * PAGE 자체는 호출자가 해제합니다. */
static void
uninit_destroy (struct page *page) {
	struct uninit_page *uninit UNUSED = &page->uninit;
	/* TODO: 이 함수를 구현하세요.
 	 * TODO: 할 일이 없다면 그냥 return 하세요. */
	// free(page->uninit.aux); //[*]3-B. 추가
}
