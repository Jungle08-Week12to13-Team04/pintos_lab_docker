#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
  
	// [*]3-B. 추가
	void* padding; 
	enum vm_type type;
	struct load_args_tmp *aux;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,//[*]3-L
		struct file *file, off_t offset);
void do_munmap (void *va);//[*]3-L
#endif
