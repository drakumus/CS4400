#include <unistd.h>

void mem_init(void);               
void mem_reset(void);

size_t mem_pagesize(void);
void *mem_map(size_t);
void mem_unmap(void *, size_t);
int mem_is_mapped(void *p, size_t sz);

size_t mem_heapsize(void);
