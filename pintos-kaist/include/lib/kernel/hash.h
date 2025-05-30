#ifndef __LIB_KERNEL_HASH_H
#define __LIB_KERNEL_HASH_H

/* 해시 테이블.
 *
 * 이 자료구조는 Pintos 프로젝트 3의 투어에서 자세히 설명되어 있음.
 *
 * 이 구현은 체이닝을 사용하는 표준 해시 테이블입니다. 
 * 테이블에서 요소를 찾으려면 해당 데이터에 대해 해시 함수를 계산하고, 
 * 그 값을 이중 연결 리스트 배열의 인덱스로 사용한 후, 
 * 해당 리스트를 선형 탐색합니다.
 *
 * 체이닝 리스트는 동적 할당을 사용하지 않습니다. 
 * 대신 해시에 들어갈 수 있는 각 구조체는 `struct hash_elem` 멤버를 내장해야 합니다. 
 * 모든 해시 함수는 이 `hash_elem`을 기반으로 동작합니다. 
 * `hash_entry` 매크로를 사용하면 `struct hash_elem` 포인터를 
 * 그것을 포함하는 원래 구조체로 변환할 수 있습니다. 
 * 이 방식은 연결 리스트 구현과 동일한 기법이며, 
 * 자세한 설명은 lib/kernel/list.h를 참고하십시오.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "list.h"

/* Hash element. */
struct hash_elem {
	struct list_elem list_elem;
};

/* 해시 요소 HASH_ELEM에 대한 포인터를,
 * HASH_ELEM이 내장되어 있는 외부 구조체의 포인터로 변환합니다.
 * 외부 구조체의 이름 STRUCT와, hash_elem 멤버의 이름 MEMBER를 지정해야 합니다.
 * 예제는 이 파일 상단의 큰 주석을 참고하세요.
 */
#define hash_entry(HASH_ELEM, STRUCT, MEMBER)                   \
	((STRUCT *) ((uint8_t *) &(HASH_ELEM)->list_elem        \
		- offsetof (STRUCT, MEMBER.list_elem)))

/* 해시 요소 E와 보조 데이터 AUX를 이용해 해시 값을 계산하고 반환합니다. */

typedef uint64_t hash_hash_func (const struct hash_elem *e, void *aux);

/* 두 해시 요소 A와 B를 보조 데이터 AUX와 함께 비교합니다.
 * A가 B보다 작으면 true, 그렇지 않으면 false를 반환합니다.
 */
typedef bool hash_less_func (const struct hash_elem *a,
		const struct hash_elem *b,
		void *aux);

/* 해시 요소 E에 대해 보조 데이터 AUX를 기반으로 연산을 수행합니다. */

typedef void hash_action_func (struct hash_elem *e, void *aux);

/* 해시 테이블 구조체 */
struct hash {
	size_t elem_cnt;            /* Number of elements in table. */
	size_t bucket_cnt;          /* Number of buckets, a power of 2. */
	struct list *buckets;       /* Array of `bucket_cnt' lists. */
	hash_hash_func *hash;       /* Hash function. */
	hash_less_func *less;       /* Comparison function. */
	void *aux;                  /* Auxiliary data for `hash' and `less'. */
};

/* 해시 테이블 반복자 (iterator) 구조체 */
struct hash_iterator {
	struct hash *hash;          /* The hash table. */
	struct list *bucket;        /* Current bucket. */
	struct hash_elem *elem;     /* Current hash element in current bucket. */
};

/* 기본 생명 주기 함수들 (생성, 초기화, 제거 등) */
bool hash_init (struct hash *, hash_hash_func *, hash_less_func *, void *aux);
void hash_clear (struct hash *, hash_action_func *);
void hash_destroy (struct hash *, hash_action_func *);

/* 탐색, 삽입, 삭제 관련 함수 */
struct hash_elem *hash_insert (struct hash *, struct hash_elem *);
struct hash_elem *hash_replace (struct hash *, struct hash_elem *);
struct hash_elem *hash_find (struct hash *, struct hash_elem *);
struct hash_elem *hash_delete (struct hash *, struct hash_elem *);

/* 반복(iteration) 관련 함수 */
void hash_apply (struct hash *, hash_action_func *);
void hash_first (struct hash_iterator *, struct hash *);
struct hash_elem *hash_next (struct hash_iterator *);
struct hash_elem *hash_cur (struct hash_iterator *);

/* 정보 조회 함수 */
size_t hash_size (struct hash *);
bool hash_empty (struct hash *);

/* Sample hash functions. */
uint64_t hash_bytes (const void *, size_t);
uint64_t hash_string (const char *);
uint64_t hash_int (int);

#endif /* lib/kernel/hash.h */