/*
 * mm-naive.c - The least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by allocating a
 * new page as needed.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused.
 *
 * The heap check and free check always succeeds, because the
 * allocator doesn't depend on any of the old data.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

typedef struct {
  size_t size;
  char   allocated;
} block_header;

typedef struct {
  size_t size;
  int filler;
} block_footer;

typedef struct free_list {
  struct free_list *next;
  struct free_list *prev;
} free_list;

typedef struct chunk_header {
  struct chunk_header* prev;
  struct chunk_header* next;
  free_list* free_list_head;
  size_t size; // size of this chunk (includes header)
} chunk_header;


#define DEBUG_MODULE 0

/* always use 16-byte alignment */
#define ALIGNMENT 16

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

/* rounds up to the nearest multiple of mem_pagesize() */
#define PAGE_ALIGN(size) (((size) + (mem_pagesize()-1)) & ~(mem_pagesize()-1))

/* rounds down to the nearest multiple of mem_pagesize() */
#define ADDRESS_PAGE_START(p) ((void *)(((size_t)p) & ~(mem_pagesize()-1)))

/* minimum pages allocated per chunk */
#define PAGES_PER_CHUNK 8
#define CHUNK_SIZE (mem_pagesize() * PAGES_PER_CHUNK)

#define OVERHEAD (sizeof(block_header)+sizeof(block_footer))

#define HDRP(bp) ((char *)(bp) - sizeof(block_header))
#define FTRP(bp) ((char *)(bp)+GET_SIZE(HDRP(bp))-OVERHEAD)

#define GET_SIZE(p)  ((block_header *)(p))->size
#define GET_ALLOC(p) ((block_header *)(p))->allocated

#define PREV_BLKP(bp) ((char *)(bp)-GET_SIZE((char *)(bp)-OVERHEAD))
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))


static void* extend(size_t new_size);
static void* coalesce(void *bp);
static void  set_allocated(void *bp, size_t size);
static void print_chunk_allocations(chunk_header* chunk, int chunk_index, const char* message);
static void print_all_chunks(const char * message);
static int ptr_is_mapped(void *p, size_t len);
static int is_allocated(void *p);
static int mm_chunk_check(chunk_header* cp);
void add_to_free_list(free_list * bp);
void remove_from_free_list(free_list *bp);
void print_free_list();

chunk_header *first_chunk_header = NULL;
chunk_header *last_chunk_header = NULL;

free_list *free_list_tail = NULL;

/* 
 * mm_init - initialize the malloc package.
 */


int mm_init() {
  
  first_chunk_header = NULL;
  last_chunk_header = NULL;
  free_list_tail = NULL;

  // initialize with CHUNK_SIZE allocation
  if (!extend(CHUNK_SIZE)) {
    fprintf(stderr, "Cannot allocate via mem_map\n");
    abort();
  }

  print_chunk_allocations(first_chunk_header, 0, "mm_init()");


  return 0;
}

/* 
 * mm_malloc - Allocate size bytes of memory by using blocks from available blocks in existing chunks;
 *     create a new chunk if necessary.
 */
void* mm_malloc(size_t size)
{
  void* bp;
  size_t new_size;
  free_list* fp;
  
  // make sure size is at least enough to store the free list next and prev pointers
  if (size < sizeof(free_list))
    size = sizeof(free_list);
  new_size = ALIGN(size + OVERHEAD);

  fp = free_list_tail;
  while (fp) {
    bp = fp;
    if (GET_SIZE(HDRP(bp)) >= new_size) {
      set_allocated(bp, new_size);
      print_all_chunks("mm_malloc()");
      return bp;
    }
    fp = fp->prev;
  }

  // printf("Ran out of chunk space; allocating new chunk\n");
  bp = extend(new_size);
  if (bp) {
    set_allocated(bp, new_size);
    print_all_chunks("mm_malloc()");
  }
  return bp;
}

/*
 * mm_free - Freeing a block.
 */
void mm_free(void *bp)
{
  GET_ALLOC(HDRP(bp)) = 0;
  coalesce(bp);
  print_all_chunks("mm_free()");
}


/*
 * mm_check - Check whether the heap is ok, so that mm_malloc()
 *            and proper mm_free() calls won't crash.
 */
int mm_check()
{
  // run a series of checks (outlined in section "Heap-Check Tips") to make sure the heap is consistent
  chunk_header* cp = last_chunk_header;
  while (cp) {
    // make sure the chunk pointer is valid up to at least CHUNK_SIZE
    if (!ptr_is_mapped(cp, CHUNK_SIZE))  {
      fprintf(stderr, "invalid chunk header\n");
      return 0;
    }
    if (!mm_chunk_check(cp))
      return 0;
    cp = cp->prev;
  }
  return 1;
}

int mm_chunk_check(chunk_header* cp) {
  void* block_header_start = cp + 1;
  void* bp = block_header_start + sizeof(block_header);
  void* prev_bp;
  int allocated;

  if (!ptr_is_mapped(bp, GET_SIZE(HDRP(bp)))) {
    fprintf(stderr, "invalid block pointer\n");
    return 0;
  }
  // check if first block is consistent (this is the 0-sized block)
  if (GET_SIZE(HDRP(bp)) != OVERHEAD) {
    fprintf(stderr, "bad starting block in the chunk\n");
    return 0;
  }
  if (GET_SIZE(FTRP(bp)) != OVERHEAD) {
    fprintf(stderr, "bad starting block in the chunk\n");
    return 0;
  }
  // go past 0-sized block
  bp = NEXT_BLKP(bp);

  while (GET_SIZE(HDRP(bp)) != 0) {
    // does bp point to the mapped space?
    if (!ptr_is_mapped(bp, GET_SIZE(HDRP(bp)))) {
      fprintf(stderr, "invalid block pointer\n");
      return 0;
    }
     // check if allocated flag is correct value
    allocated = GET_ALLOC(HDRP(bp));
    if (allocated != 1 && allocated != 0)  {
      fprintf(stderr, "bad value for allocated flag\n");
      return 0;
    }

     // are block header and footer consistent?
    if (GET_SIZE(HDRP(bp)) != GET_SIZE(FTRP(bp))) {
      fprintf(stderr, "block header and footer are not consistent\n");
      return 0;
    }

     prev_bp = PREV_BLKP(bp);

    // are consecutive blocks on the free list?
    if (GET_ALLOC(HDRP(prev_bp)) == 0 && GET_ALLOC(HDRP(bp)) == 0) {
      fprintf(stderr, "consecutive blocks are free\n");
      return 0;
    }

    // are there overlapping blocks?
    if (prev_bp != bp && (GET_SIZE(HDRP(prev_bp)) + HDRP(prev_bp)) > HDRP(bp)) {
      fprintf(stderr, "overlapping blocks\n");
      return 0;
    }


  	bp = NEXT_BLKP(bp);

  }
  return 1;
}

/*
 * mm_check - Check whether freeing the given `p`, which means that
 *            calling mm_free(p) leaves the heap in an ok state.
 */
int mm_can_free(void *p)
{
  if (!GET_ALLOC(HDRP(p))) return 0;
  int can_free = is_allocated(p);
  return can_free;
}

int is_allocated_in_chunk(chunk_header* cp, void* p) {
  void* block_header_start = cp + 1;
  void* bp = block_header_start + sizeof(block_header);
  while (GET_SIZE(HDRP(bp)) != 0) {
	  if (GET_ALLOC(HDRP(bp)) && bp == p)
		  return 1;
	  bp = NEXT_BLKP(bp);
  }
  return 0;
}
int is_allocated(void *p) {
  chunk_header* cp = last_chunk_header;
  while (cp) {
	  if (is_allocated_in_chunk(cp, p))
		  return 1;
    cp = cp->prev;
  }
  return 0;
}


/* allocate a new chunk that is at least new_size, aligned to PAGE boundary */

void* extend(size_t new_size) {
  void* block_header_start;
  void* bp;
  size_t chunk_size;
  chunk_header* cp;
  size_t usable_chunk_size;
  size_t chunk_overhead;

  // chunk overhead = size of the chunk header + size of first zero-sized block + size of the sentinel block
  chunk_overhead = sizeof(chunk_header) + OVERHEAD + sizeof(block_header);
  
  new_size += chunk_overhead;
  chunk_size = PAGE_ALIGN(new_size);
   
  // Minimum of CHUNK_SIZE since we don't want to call mem_map too often
  if (chunk_size < CHUNK_SIZE)
    chunk_size = CHUNK_SIZE;

  cp = mem_map(chunk_size);
  if (cp == NULL)
    return NULL;

  // printf("requested size: %lu, extending to size: %lu\n", new_size, chunk_size);

  if (first_chunk_header == NULL) {
    cp->prev = NULL;
    cp->next = NULL;
    first_chunk_header = cp;
    last_chunk_header = cp;
  } else {
     // insert new chunk at the end of the list
    last_chunk_header->next = cp;
    cp->prev = last_chunk_header;
    cp->next = NULL;
    last_chunk_header = cp;
  }

  cp->size = chunk_size;

  block_header_start = cp + 1;
  bp = block_header_start + sizeof(block_header);

  // first block in a chunk is a 0-sized block, which is there to make PREV_BLKP work seamlessly in the Coalesce function
  GET_SIZE(HDRP(bp)) = OVERHEAD;
  GET_SIZE(FTRP(bp)) = OVERHEAD;
  GET_ALLOC(HDRP(bp)) = 1;

  // advance block pointer to the second block
  bp = (char *)bp + OVERHEAD;
  

  // usable chunk size is the allocated size - size of the chunk header - size of first zero-sized block - size of the sentinel block
  usable_chunk_size = chunk_size - chunk_overhead;
  
  GET_SIZE(HDRP(bp)) = usable_chunk_size;
  GET_SIZE(FTRP(bp)) = usable_chunk_size;
  GET_ALLOC(HDRP(bp)) = 0;

  // initialize free list
  add_to_free_list((free_list *)bp);

  // sentinel block
  GET_SIZE(HDRP(NEXT_BLKP(bp))) = 0;
  GET_ALLOC(HDRP(NEXT_BLKP(bp))) = 1;

  return bp;
}

void set_allocated(void *bp, size_t size) {
  free_list* fp = bp;
  size_t extra_size = GET_SIZE(HDRP(bp)) - size;

  if (extra_size > ALIGN(1 + OVERHEAD + sizeof(free_list))) {
    GET_SIZE(HDRP(bp)) = size;
		GET_SIZE(FTRP(bp)) = size;
    GET_ALLOC(HDRP(bp)) = 1;

    // bp was free; it is no longer free - move the free pointer to the new free block 
    // and fill the contents from the old bp (next and prev pointers of the free list node)

    remove_from_free_list(fp);

    GET_SIZE(HDRP(NEXT_BLKP(bp))) = extra_size;
		GET_SIZE(FTRP(NEXT_BLKP(bp))) = extra_size;
    GET_ALLOC(HDRP(NEXT_BLKP(bp))) = 0;

    add_to_free_list((free_list *)NEXT_BLKP(bp));

  } else {
    GET_ALLOC(HDRP(bp)) = 1;
    remove_from_free_list(fp);
  }
}

void remove_from_free_list(free_list *fp) {
  if (fp->prev) 
    fp->prev->next = fp->next;
  if (fp->next)
    fp->next->prev = fp->prev;
  if (fp == free_list_tail) {
    free_list_tail = free_list_tail->prev;
    if (free_list_tail)
      free_list_tail->next = NULL;
  }
}

void add_to_free_list(free_list *fp) {

  // add free block to the head of the free head list
  if (free_list_tail) {
    fp->next = NULL;
    fp->prev = free_list_tail;
    free_list_tail->next = fp;
    free_list_tail = fp;
  } else {
    fp->next = fp->prev = NULL;
    free_list_tail = fp;
  }
}

void *coalesce(void *bp) {
  free_list* next_fp;
  void* next_bp;
  size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(bp)));
  size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));   
  size_t size = GET_SIZE(HDRP(bp));

  if (prev_alloc && next_alloc) {              /* Case 1 */
     // nothing to do
    add_to_free_list((free_list *)bp);
  } else if (prev_alloc && !next_alloc) {     /* Case 2 */
    add_to_free_list((free_list *)bp);
     // adjust free list to kill next free node (since it is being merged with current node)
    next_bp = NEXT_BLKP(bp);
    next_fp = (free_list *)next_bp;
    remove_from_free_list(next_fp);

    size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
    GET_SIZE(HDRP(bp)) = size;
    GET_SIZE(FTRP(bp)) = size;

  } else if (!prev_alloc && next_alloc) {     /* Case 3 */

    size += GET_SIZE(HDRP(PREV_BLKP(bp)));
    GET_SIZE(FTRP(bp)) = size;
    GET_SIZE(HDRP(PREV_BLKP(bp))) = size;

    bp = PREV_BLKP(bp);

  } else {                                    /* Case 4 */
    // both prev and next nodes are free
    // adjust free list to blow away this node and next node

    next_bp = NEXT_BLKP(bp);
    next_fp = (free_list *)next_bp;
    remove_from_free_list(next_fp);

    size += (GET_SIZE(HDRP(PREV_BLKP(bp)))
            + GET_SIZE(HDRP(NEXT_BLKP(bp))));
    GET_SIZE(HDRP(PREV_BLKP(bp))) = size;
    GET_SIZE(FTRP(NEXT_BLKP(bp))) = size;

    bp = PREV_BLKP(bp);
  }
  return bp;
}

void print_free_list() {
  free_list* flp = free_list_tail;
  void* bp;

  fprintf(stderr, "free_list {\n");
  while (flp) {
    bp = flp;
    fprintf(stderr, "block(%p): size(%lu), is_allocated(%d)\n", bp, GET_SIZE(HDRP(bp)), GET_ALLOC(HDRP(bp)));
    flp = flp->prev;
  }
  fprintf(stderr, "}\n");
}

/* print the heap, one chunk at a time debugging only*/
void print_all_chunks(const char * message) {
#if DEBUG_MODULE
  chunk_header* cp = first_chunk_header;
  int chunk_index = 0;
  while (cp) {
    print_chunk_allocations(cp, chunk_index, message);
    print_free_list();
    cp = cp->next;
    chunk_index++;
  }
#endif
}

void print_chunk_allocations(chunk_header* chunk, int chunk_index, const char* message) {
#if DEBUG_MODULE
  void* block_header_start = chunk + 1;
  void* bp = block_header_start + sizeof(block_header);
  size_t size;
  int allocated;
  int block_counter = 0;

  printf("%s chunk_size(%lu)", message, chunk->size);
  printf("{\n");
  while (GET_SIZE(HDRP(bp)) != 0) {
    size = GET_SIZE(HDRP(bp));
    allocated = GET_ALLOC(HDRP(bp));
    printf("chunk_%d: block_%d (%p): block_size(%lu), is_allocated(%s)\n", chunk_index, block_counter, bp, size, allocated?"yes":"no");
    bp = NEXT_BLKP(bp);
    block_counter++;
  }
  printf("}\n");
#endif
}

int ptr_is_mapped(void *p, size_t len) {
  void *s = ADDRESS_PAGE_START(p);
  return mem_is_mapped(s, PAGE_ALIGN((p + len) - s));
}
