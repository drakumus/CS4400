#include <stdio.h>

extern int mm_init(void);
extern void *mm_malloc(size_t size);
extern void mm_free(void *ptr);

extern int mm_check(void);
extern int mm_can_free(void *ptr);
