#ifndef VM_UNINIT_H
#define VM_UNINIT_H
#include "vm/vm.h"

struct page;
enum vm_type;

typedef bool vm_initializer (struct page *, void *aux);

/* 초기화되지 않은 페이지 (Uninitialized page). 
 * "지연 로딩(Lazy loading)"을 구현하기 위한 타입입니다. */
struct uninit_page {
	/* 페이지의 내용을 초기화하는 함수 포인터 */
	vm_initializer *init;
	enum vm_type type;
	void *aux;
	/* struct page를 초기화하고 물리 주소(pa)를 가상 주소(va)에 매핑합니다 */
	bool (*page_initializer) (struct page *, enum vm_type, void *kva);

	bool writable; //[*]3-L_페이지 쓰기 가능 여부
};

void uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *kva));
#endif
