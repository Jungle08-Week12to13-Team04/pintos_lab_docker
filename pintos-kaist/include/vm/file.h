#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
    struct file *file;
    off_t ofs;
    size_t read_bytes;
    enum vm_type type;
};

const struct page_operations file_ops;


void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,//[*]3-L
		struct file *file, off_t offset);
void do_munmap (void *va);//[*]3-L
bool lazy_load_segment(struct page *page, void *aux);//[*]3-L
#endif
