/*
 * mdriver.c - CS:APP Malloc Lab Driver
 * 
 * Uses a collection of trace files to tests a malloc/free/realloc
 * implementation in mm.c.
 *
 * Copyright (c) 2002, R. Bryant and D. O'Hallaron, All rights reserved.
 * May not be used, modified, or copied without permission.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <float.h>
#include <math.h>
#include <inttypes.h>
#include <time.h>

#include "mm.h"
#include "memlib.h"
#include "pagemap.h"
#include "fsecs.h"
#include "config.h"

/**********************
 * Constants and macros
 **********************/

/* Misc */
#define MAXLINE     1024 /* max string size */
#define HDRLINES       4 /* number of header lines in a trace file */
#define LINENUM(i) (i+5) /* cnvt trace request nums to linenums (origin 1) */

/* Returns true if p is ALIGNMENT-byte aligned */
#define IS_ALIGNED(p)  ((((uintptr_t)(p)) % ALIGNMENT) == 0)

/****************************** 
 * The key compound data types 
 *****************************/

/* Records the extent of each block's payload */
typedef struct range_t {
    char *lo;              /* low payload address */
    char *hi;              /* high payload address */
    struct range_t *next;  /* next list element */
} range_t;

/* Characterizes a single trace operation (allocator request) */
typedef struct {
    enum {ALLOC, FREE, REALLOC} type; /* type of request */
    int index;                        /* index for free() to use later */
    int size;                         /* byte size of alloc/realloc request */
} traceop_t;

/* Holds the information for one trace file*/
typedef struct {
    int sugg_heapsize;   /* suggested heap size (unused) */
    int num_ids;         /* number of alloc/realloc ids */
    int num_ops;         /* number of distinct requests */
    int weight;          /* weight for this trace (unused) */
    traceop_t *ops;      /* array of requests */
    char **blocks;       /* array of ptrs returned by malloc/realloc... */
    size_t *block_sizes; /* ... and a corresponding array of payload sizes */
} trace_t;

/* 
 * Holds the params to the xxx_speed functions, which are timed by fcyc. 
 * This struct is necessary because fcyc accepts only a pointer array
 * as input.
 */
typedef struct {
    trace_t *trace;  
    range_t *ranges;
} speed_t;

/* Summarizes the important stats for some malloc function on some trace */
typedef struct {
    /* defined for both libc malloc and student malloc package (mm.c) */
    double ops;      /* number of ops (malloc/free/realloc) in the trace */
    int valid;       /* was the trace processed correctly by the allocator? */
    double secs;     /* number of secs needed to run the trace */

    /* defined only for the student malloc package */
    double util;     /* overall space utilization for this trace (always 0 for libc) */

    double inst_util;     /* instanteous space utilization for this trace (always 0 for libc) */

    /* Note: secs and util are only defined if valid is true */
} stats_t; 

/********************
 * Global variables
 *******************/
int verbose = 2;        /* global flag for verbose output */
static int errors = 0;  /* number of errs found when running student malloc */
char msg[MAXLINE];      /* for whenever we need to compose an error message */

/* Directory where default tracefiles are found */
static char tracedir[MAXLINE] = TRACEDIR;

/* The filenames of the default tracefiles */
static char *default_tracefiles[] = {  
    DEFAULT_TRACEFILES, NULL
};


/********************* 
 * Function prototypes 
 *********************/

/* these functions manipulate range lists */
static int add_range(range_t **ranges, char *lo, int size, 
		     int tracenum, int opnum);
static void remove_range(range_t **ranges, char *lo);
static void clear_ranges(range_t **ranges);

/* These functions read, allocate, and free storage for traces */
static trace_t *read_trace(char *tracedir, char *filename, int fn_index);
static void free_trace(trace_t *trace);

/* Routines for evaluating the correctness and speed of libc malloc */
static int eval_libc_valid(trace_t *trace, int tracenum);
static void eval_libc_speed(void *ptr);

/* Routines for evaluating correctnes, space utilization, and speed 
   of the student's malloc package in mm.c */
static int eval_mm_valid(trace_t *trace, int tracenum, range_t **ranges, int checks, int chaos);
static double eval_mm_util(trace_t *trace, int tracenum, range_t **ranges, double *inst_ratio);
static void eval_mm_speed(void *ptr);

/* Various helper routines */
static int check(int chaos, const char *what);
static int check_free(int chaos, void *p);
static void check_post_free(int chaos, void *p);
static void mangle(void);
static void printresults(int n, stats_t *stats);
static void usage(void);
static void unix_error(char *msg);
static void malloc_error(int tracenum, int opnum, char *msg);
static void app_error(char *msg);

/**************
 * Main routine
 **************/
int main(int argc, char **argv)
{
  int i, j;
    char c;
    char **tracefiles = NULL;  /* null-terminated array of trace file names */
    int num_tracefiles = 0;    /* the number of traces in that array */
    trace_t *trace = NULL;     /* stores a single trace file in memory */
    range_t *ranges = NULL;    /* keeps track of block extents for one trace */
    range_t *d_ranges = NULL;  
    stats_t *libc_stats = NULL;/* libc stats for each trace */
    stats_t *mm_stats = NULL;  /* mm (i.e. student) stats for each trace */
    speed_t speed_params;      /* input parameters to the xx_speed routines */ 

    int run_libc = 0;    /* If set, run libc malloc (set by -l) */
    int autograder = 0;  /* If set, emit summary info for autograder (-g) */
    int checks = 1;      /* Whether to use mm_check and mm_can_free */
    int repeats = 1;     /* Number of times to try random chaos */

    /* temporaries used to compute the performance index */
    double secs, ops, util, inst_util, avg_mm_inst_util, avg_mm_util, avg_mm_throughput;
    double p1, p1i, p2, perfindex;
    int numcorrect;
  
    srandom(42);
    
    /* 
     * Read and interpret the command line arguments 
     */
    while ((c = getopt(argc, argv, "s:r:f:t:hqgaln")) != EOF) {
        switch (c) {
        case 's':
            srandom(atoi(optarg));
            break;
        case 'r':
            repeats = atoi(optarg);
            break;
        case 'n':
            checks = 0;
            break;
	case 'g': /* Generate summary info for the autograder */
	    autograder = 1;
	    break;
        case 'f': /* Use one specific trace file only (relative to curr dir) */
            num_tracefiles = 1;
            if ((tracefiles = realloc(tracefiles, 2*sizeof(char *))) == NULL)
		unix_error("ERROR: realloc failed in main");
	    strcpy(tracedir, "./"); 
            tracefiles[0] = strdup(optarg);
            tracefiles[1] = NULL;
            break;
	case 't': /* Directory where the traces are located */
	    if (num_tracefiles == 1) /* ignore if -f already encountered */
		break;
	    strcpy(tracedir, optarg);
	    if (tracedir[strlen(tracedir)-1] != '/') 
		strcat(tracedir, "/"); /* path always ends with "/" */
	    break;
        case 'l': /* Run libc malloc */
            run_libc = 1;
            break;
        case 'q': /* Skip performance breakdown */
            verbose = 0;
            break;
        case 'h': /* Print this message */
	    usage();
            exit(0);
        default:
	    usage();
            exit(1);
        }
    }
	
    /* 
     * If no -f command line arg, then use the entire set of tracefiles 
     * defined in default_traces[]
     */
    if (tracefiles == NULL) {
        tracefiles = default_tracefiles;
        num_tracefiles = sizeof(default_tracefiles) / sizeof(char *) - 1;
	printf("Using default tracefiles in %s\n", tracedir);
    }

    /* Initialize the timing package */
    init_fsecs();

    /*
     * Optionally run and evaluate the libc malloc package 
     */
    if (run_libc) {
	if (verbose > 1)
	    printf("\nTesting libc malloc\n");
	
	/* Allocate libc stats array, with one stats_t struct per tracefile */
	libc_stats = (stats_t *)calloc(num_tracefiles, sizeof(stats_t));
	if (libc_stats == NULL)
	    unix_error("libc_stats calloc in main failed");
	
	/* Evaluate the libc malloc package using the K-best scheme */
	for (i=0; i < num_tracefiles; i++) {
          trace = read_trace(tracedir, tracefiles[i], i);
	    libc_stats[i].ops = trace->num_ops;
	    if (verbose > 1)
		printf("Checking libc malloc for correctness, ");
	    libc_stats[i].valid = eval_libc_valid(trace, i);
	    if (libc_stats[i].valid) {
		speed_params.trace = trace;
		if (verbose > 1)
		    printf("and performance.\n");
		libc_stats[i].secs = fsecs(eval_libc_speed, &speed_params);
	    }
	    free_trace(trace);
	}

	/* Display the libc results in a compact table */
	if (verbose) {
	    printf("\nResults for libc malloc:\n");
	    printresults(num_tracefiles, libc_stats);
	}
    }

    /*
     * Always run and evaluate the student's mm package
     */
    if (verbose > 1)
	printf("\nTesting mm malloc\n");

    /* Allocate the mm stats array, with one stats_t struct per tracefile */
    mm_stats = (stats_t *)calloc(num_tracefiles, sizeof(stats_t));
    if (mm_stats == NULL)
	unix_error("mm_stats calloc in main failed");
    
    /* Initialize the simulated memory system in memlib.c */
    mem_init(); 

    /* Evaluate student's mm malloc package using the K-best scheme */
    for (i=0; i < num_tracefiles; i++) {
        trace = read_trace(tracedir, tracefiles[i], i);
	mm_stats[i].ops = trace->num_ops;
	if (verbose > 1) {
          printf("Checking mm_malloc for correctness, ");
          fflush(stdout);
        }
	mm_stats[i].valid = eval_mm_valid(trace, i, &ranges, checks, 0);
	if (mm_stats[i].valid) {
          if (checks && (repeats > 0)) {
            if (verbose > 1) {
              printf("defensiveness, ");
              fflush(stdout);
            }
            for (j = 0; j < repeats; j++)
              (void)eval_mm_valid(trace, i, &d_ranges, checks, 1);
          }
          
          if (verbose > 1) {
            printf("efficiency, ");
            fflush(stdout);
          }
          mm_stats[i].util = eval_mm_util(trace, i, &ranges, &mm_stats[i].inst_util);
          speed_params.trace = trace;
          speed_params.ranges = ranges;
          if (verbose > 1) {
            printf("and performance.\n");
            fflush(stdout);
          }
          mm_stats[i].secs = fsecs(eval_mm_speed, &speed_params);
	}
	free_trace(trace);
    }

    /* Display the mm results in a compact table */
    if (verbose) {
	printf("\nResults for mm malloc:\n");
	printresults(num_tracefiles, mm_stats);
	printf("\n");
    }

    /* 
     * Accumulate the aggregate statistics for the student's mm package 
     */
    secs = 0;
    ops = 0;
    util = 0;
    inst_util = 0;
    numcorrect = 0;
    for (i=0; i < num_tracefiles; i++) {
	secs += mm_stats[i].secs;
	ops += mm_stats[i].ops;
	util += mm_stats[i].util;
	inst_util += mm_stats[i].inst_util;
	if (mm_stats[i].valid)
	    numcorrect++;
    }
    avg_mm_util = util/num_tracefiles;
    avg_mm_inst_util = inst_util/num_tracefiles;

    /* 
     * Compute and print the performance index 
     */
    if (errors == 0) {
	avg_mm_throughput = ops/secs;

	p1 = UTIL_WEIGHT * avg_mm_util;
	p1i = UTIL_I_WEIGHT * avg_mm_inst_util;
	if (avg_mm_throughput > AVG_LIBC_THRUPUT) {
          p2 = (double)(1.0 - (UTIL_WEIGHT + UTIL_I_WEIGHT));
	} 
	else {
	    p2 = ((double) (1.0 - (UTIL_WEIGHT + UTIL_I_WEIGHT))) * 
		(avg_mm_throughput/AVG_LIBC_THRUPUT);
	}
	
	perfindex = (p1 + p1i + p2)*100.0;
	printf("Perf index = %.0f (util) + %.0f (util_i) + %.0f (thru) = %.0f\n",
	       p1*100, 
	       p1i*100, 
	       p2*100,
	       perfindex);
	
    }
    else { /* There were errors */
	perfindex = 0.0;
	printf("Terminated with %d errors\n", errors);
    }

    if (autograder) {
	printf("correct:%d\n", numcorrect);
	printf("perfidx:%.0f\n", perfindex);
    }

    exit(0);
}


/*****************************************************************
 * The following routines manipulate the range list, which keeps 
 * track of the extent of every allocated block payload. We use the 
 * range list to detect any overlapping allocated blocks.
 ****************************************************************/

/*
 * add_range - As directed by request opnum in trace tracenum,
 *     we've just called the student's mm_malloc to allocate a block of 
 *     size bytes at addr lo. After checking the block for correctness,
 *     we create a range struct for this block and add it to the range list. 
 */
static int add_range(range_t **ranges, char *lo, int size, 
		     int tracenum, int opnum)
{
    char *hi = lo + size - 1;
    range_t *p;
    char msg[MAXLINE];
    size_t page_size = mem_pagesize(), i;

    assert(size > 0);

    /* Payload addresses must be ALIGNMENT-byte aligned */
    if (!IS_ALIGNED(lo)) {
	sprintf(msg, "Payload address (%p) not aligned to %d bytes", 
		lo, ALIGNMENT);
        malloc_error(tracenum, opnum, msg);
        return 0;
    }
    
    /* The payload must lie on a mapped page */
    for (i = 0; i < size; i += page_size) {
      if (!pagemap_is_mapped(lo+i)) {
	sprintf(msg, "Payload (%p:%p) includes an unmapped page",
		lo, hi);
	malloc_error(tracenum, opnum, msg);
        return 0;
      }
    }
    if (!pagemap_is_mapped(lo+size-1)) {
      sprintf(msg, "Payload (%p:%p) ends at an unmapped page",
              lo, hi);
      malloc_error(tracenum, opnum, msg);
      return 0;
    }

    /* The payload must not overlap any other payloads */
    for (p = *ranges;  p != NULL;  p = p->next) {
        if ((lo >= p->lo && lo <= p-> hi) ||
            (hi >= p->lo && hi <= p->hi)) {
	    sprintf(msg, "Payload (%p:%p) overlaps another payload (%p:%p)\n",
		    lo, hi, p->lo, p->hi);
	    malloc_error(tracenum, opnum, msg);
	    return 0;
        }
    }

    /* 
     * Everything looks OK, so remember the extent of this block 
     * by creating a range struct and adding it the range list.
     */
    if ((p = (range_t *)malloc(sizeof(range_t))) == NULL)
	unix_error("malloc error in add_range");
    p->next = *ranges;
    p->lo = lo;
    p->hi = hi;
    *ranges = p;
    return 1;
}

/* 
 * remove_range - Free the range record of block whose payload starts at lo 
 */
static void remove_range(range_t **ranges, char *lo)
{
    range_t *p;
    range_t **prevpp = ranges;

    for (p = *ranges;  p != NULL; p = p->next) {
        if (p->lo == lo) {
	    *prevpp = p->next;
            free(p);
            break;
        }
        prevpp = &(p->next);
    }
}

/*
 * clear_ranges - free all of the range records for a trace 
 */
static void clear_ranges(range_t **ranges)
{
    range_t *p;
    range_t *pnext;

    for (p = *ranges;  p != NULL;  p = pnext) {
        pnext = p->next;
        free(p);
    }
    *ranges = NULL;
}


/**********************************************
 * The following routines manipulate tracefiles
 *********************************************/

/*
 * read_trace - read a trace file and store it in memory
 */
static trace_t *read_trace(char *tracedir, char *filename, int fn_index)
{
    FILE *tracefile;
    trace_t *trace;
    char type[MAXLINE];
    char path[MAXLINE];
    unsigned index, size;
    unsigned max_index = 0;
    unsigned op_index;

    if (verbose > 1)
      printf("%d Reading tracefile: %s\n", fn_index, filename);

    /* Allocate the trace record */
    if ((trace = (trace_t *) malloc(sizeof(trace_t))) == NULL)
	unix_error("malloc 1 failed in read_trance");
	
    /* Read the trace file header */
    strcpy(path, tracedir);
    strcat(path, filename);
    if ((tracefile = fopen(path, "r")) == NULL) {
	sprintf(msg, "Could not open %s in read_trace", path);
	unix_error(msg);
    }
    fscanf(tracefile, "%d", &(trace->sugg_heapsize)); /* not used */
    fscanf(tracefile, "%d", &(trace->num_ids));     
    fscanf(tracefile, "%d", &(trace->num_ops));     
    fscanf(tracefile, "%d", &(trace->weight));        /* not used */
    
    /* We'll store each request line in the trace in this array */
    if ((trace->ops = 
	 (traceop_t *)malloc(trace->num_ops * sizeof(traceop_t))) == NULL)
	unix_error("malloc 2 failed in read_trace");

    /* We'll keep an array of pointers to the allocated blocks here... */
    if ((trace->blocks = 
	 (char **)malloc(trace->num_ids * sizeof(char *))) == NULL)
	unix_error("malloc 3 failed in read_trace");

    /* ... along with the corresponding byte sizes of each block */
    if ((trace->block_sizes = 
	 (size_t *)malloc(trace->num_ids * sizeof(size_t))) == NULL)
	unix_error("malloc 4 failed in read_trace");
    
    /* read every request line in the trace file */
    index = 0;
    op_index = 0;
    while (fscanf(tracefile, "%s", type) != EOF) {
	switch(type[0]) {
	case 'a':
	    fscanf(tracefile, "%u %u", &index, &size);
	    trace->ops[op_index].type = ALLOC;
	    trace->ops[op_index].index = index;
	    trace->ops[op_index].size = size;
	    max_index = (index > max_index) ? index : max_index;
	    break;
	case 'r':
	    fscanf(tracefile, "%u %u", &index, &size);
	    trace->ops[op_index].type = REALLOC;
	    trace->ops[op_index].index = index;
	    trace->ops[op_index].size = size;
	    max_index = (index > max_index) ? index : max_index;
	    break;
	case 'f':
	    fscanf(tracefile, "%ud", &index);
	    trace->ops[op_index].type = FREE;
	    trace->ops[op_index].index = index;
	    break;
	default:
	    printf("Bogus type character (%c) in tracefile %s\n", 
		   type[0], path);
	    exit(1);
	}
	op_index++;
	
    }
    fclose(tracefile);
    assert(max_index == trace->num_ids - 1);
    assert(trace->num_ops == op_index);
    
    return trace;
}

/*
 * free_trace - Free the trace record and the three arrays it points
 *              to, all of which were allocated in read_trace().
 */
void free_trace(trace_t *trace)
{
    free(trace->ops);         /* free the three arrays... */
    free(trace->blocks);      
    free(trace->block_sizes);
    free(trace);              /* and the trace record itself... */
}

/**********************************************************************
 * The following functions evaluate the correctness, space utilization,
 * and throughput of the libc and mm malloc packages.
 **********************************************************************/

/*
 * eval_mm_valid - Check the mm malloc package for correctness
 */
static int eval_mm_valid(trace_t *trace, int tracenum, range_t **ranges, int checks, int chaos)
{
    int i, non_free_op = 0;
    int index;
    int size;
    char *newp;
    char *oldp;
    char *p;
    
    /* Reset the heap and free any records in the range list */
    clear_ranges(ranges);

    /* Call the mm package's init function */
    if (mm_init() < 0) {
	malloc_error(tracenum, 0, "mm_init failed.");
	return 0;
    }

    /* Interpret each operation in the trace in order */
    for (i = 0;  i < trace->num_ops;  i++) {
        if (checks) {
          if (trace->ops[i].type != FREE) {
            /* check that freed pointers since last alloc are
               recognized as unfreeable: */
            while (non_free_op < i) {
              check_post_free(chaos, trace->blocks[trace->ops[non_free_op].index]);
              non_free_op++;
            }
            non_free_op = i+1;
          }
        }

	index = trace->ops[i].index;
	size = trace->ops[i].size;

        switch (trace->ops[i].type) {

        case ALLOC: /* mm_malloc */

	    /* Call the student's malloc */
	    if ((p = mm_malloc(size)) == NULL) {
		malloc_error(tracenum, i, "mm_malloc failed.");
		return 0;
	    }
            if (checks && !check(chaos, "alloc"))
              return 0;
	    
	    /* 
	     * Test the range of the new block for correctness and add it 
	     * to the range list if OK. The block must be  be aligned properly,
	     * and must not overlap any currently allocated block. 
	     */ 
	    if (!chaos)
              if (add_range(ranges, p, size, tracenum, i) == 0)
		return 0;
	    
	    /* ADDED: cgw
	     * fill range with low byte of index.  This will be used later
	     * if we realloc the block and wish to make sure that the old
	     * data was copied to the new block
	     */
            if (!chaos)
              memset(p, index & 0xFF, size);

	    /* Remember region */
	    trace->blocks[index] = p;
	    trace->block_sizes[index] = size;
	    break;

        case REALLOC: /* mm_malloc + mm_free */
	    
	    /* Call the student's realloc */
	    oldp = trace->blocks[index];
	    if ((newp = mm_malloc(size)) == NULL) {
		malloc_error(tracenum, i, "mm_malloc failed.");
		return 0;
	    }
            if (checks && !check(chaos, "alloc"))
              return 0;

	    /* Remove the old region from the range list */
            if (!chaos)
              remove_range(ranges, oldp);
	    
	    /* Check new block for correctness and add it to range list */
            if (!chaos) {
              if (add_range(ranges, newp, size, tracenum, i) == 0)
		return 0;
              memset(newp, index & 0xFF, size);
            }

            if (checks && !check_free(chaos, oldp))
              return 0;
            mm_free(oldp);
            if (checks && !check(chaos, "free"))
              return 0;
            if (checks)
              check_post_free(chaos, oldp);

	    /* Remember region */
	    trace->blocks[index] = newp;
	    trace->block_sizes[index] = size;
	    break;

        case FREE: /* mm_free */
	    
	    /* Remove region from list and call student's free function */
	    p = trace->blocks[index];
            if (!chaos)
              remove_range(ranges, p);
            if (checks && !check_free(chaos, p))
              return 0;
            mm_free(p);
            if (checks && !check(chaos, "free"))
              return 0;
	    break;

	default:
	    app_error("Nonexistent request type in eval_mm_valid");
        }

    }

    mem_reset();

    /* As far as we know, this is a valid malloc package */
    return 1;
}

/* 
 * eval_mm_util - Evaluate the space utilization of the student's package
 *   The idea is to remember the high water mark "hwm" of the heap for 
 *   an optimal allocator, i.e., no gaps and no internal fragmentation.
 *   Utilization is the ratio hwm/heapsize, where heapsize is the 
 *   size of the heap in bytes after running the student's malloc 
 *   package on the trace. Note that our implementation of mem_sbrk() 
 *   doesn't allow the students to decrement the brk pointer, so brk
 *   is always the high water mark of the heap. 
 *   
 */
static double eval_mm_util(trace_t *trace, int tracenum, range_t **ranges, double *inst_ratio)
{   
    int i;
    int index;
    int size, newsize, oldsize;
    size_t max_total_size = 0, max_heap_size = 0;
    size_t heap_size = 0, total_size = 0;
    double ratio, ratio_frac, accum_ratio_frac = 1.0, accum_ratio_exp = 0.0;
    int ratio_exp;
    char *p;
    char *newp, *oldp;

    /* initialize the heap and the mm malloc package */
    if (mm_init() < 0)
	app_error("mm_init failed in eval_mm_util");

    for (i = 0;  i < trace->num_ops;  i++) {
        switch (trace->ops[i].type) {

        case ALLOC: /* mm_alloc */
	    index = trace->ops[i].index;
	    size = trace->ops[i].size;

	    if ((p = mm_malloc(size)) == NULL) 
		app_error("mm_malloc failed in eval_mm_util");
	    
	    /* Remember region and size */
	    trace->blocks[index] = p;
	    trace->block_sizes[index] = size;
	    
	    /* Keep track of current total size
	     * of all allocated blocks */
	    total_size += size;

            break;

	case REALLOC: /* mm_mealloc + mm_free */
	    index = trace->ops[i].index;
	    newsize = trace->ops[i].size;
	    oldsize = trace->block_sizes[index];

	    oldp = trace->blocks[index];
	    if ((newp = mm_malloc(newsize)) == NULL)
		app_error("mm_realloc failed in eval_mm_util");

            mm_free(oldp);

	    /* Remember region and size */
	    trace->blocks[index] = newp;
	    trace->block_sizes[index] = newsize;
	    
	    /* Keep track of current total size
	     * of all allocated blocks */
	    total_size += (newsize - oldsize);
            
	    break;

        case FREE: /* mm_free */
	    index = trace->ops[i].index;
	    size = trace->block_sizes[index];
	    p = trace->blocks[index];
	    
	    mm_free(p);
	    
	    /* Keep track of current total size
	     * of all allocated blocks */
	    total_size -= size;
	    
	    break;

	default:
	    app_error("Nonexistent request type in eval_mm_util");

        }

    	    
        /* Update statistics */
        max_total_size = ((total_size > max_total_size) ?
                          total_size
                          : max_total_size);

        heap_size = mem_heapsize();
        if (heap_size > max_heap_size)
          max_heap_size = heap_size;

        ratio = (double)(total_size + 1) / (heap_size + 1);

        ratio_frac = frexp(ratio, &ratio_exp);

        accum_ratio_frac *= ratio_frac;
        accum_ratio_exp += ratio_exp;

        accum_ratio_frac = frexp(accum_ratio_frac, &ratio_exp);
        accum_ratio_exp += ratio_exp;
        
        // printf("%ld %ld %f\n", total_size, heap_size, ratio);
    }

    mem_reset();

    ratio = accum_ratio_frac * pow(2, accum_ratio_exp / trace->num_ops);

    // printf("%ld %f\n", max_total_size, ratio);

    *inst_ratio = ratio;

    return (double)max_total_size / max_heap_size;;
}


/*
 * eval_mm_speed - This is the function that is used by fcyc()
 *    to measure the running time of the mm malloc package.
 */
static void eval_mm_speed(void *ptr)
{
    int i, index, size, newsize;
    char *p, *newp, *oldp, *block;
    trace_t *trace = ((speed_t *)ptr)->trace;

    /* Reset the heap and initialize the mm package */
    if (mm_init() < 0) 
	app_error("mm_init failed in eval_mm_speed");

    /* Interpret each trace request */
    for (i = 0;  i < trace->num_ops;  i++)
        switch (trace->ops[i].type) {

        case ALLOC: /* mm_malloc */
            index = trace->ops[i].index;
            size = trace->ops[i].size;
            if ((p = mm_malloc(size)) == NULL)
		app_error("mm_malloc error in eval_mm_speed");
            trace->blocks[index] = p;
            break;

	case REALLOC: /* mm_malloc + mm_free */
	    index = trace->ops[i].index;
            newsize = trace->ops[i].size;
	    oldp = trace->blocks[index];
            if ((newp = mm_malloc(newsize)) == NULL)
		app_error("mm_realloc error in eval_mm_speed");
            mm_free(oldp);
            trace->blocks[index] = newp;
            break;

        case FREE: /* mm_free */
            index = trace->ops[i].index;
            block = trace->blocks[index];
            mm_free(block);
            break;

	default:
	    app_error("Nonexistent request type in eval_mm_valid");
        }

    mem_reset();
}

/*
 * eval_libc_valid - We run this function to make sure that the
 *    libc malloc can run to completion on the set of traces.
 *    We'll be conservative and terminate if any libc malloc call fails.
 *
 */
static int eval_libc_valid(trace_t *trace, int tracenum)
{
    int i, newsize;
    char *p, *newp, *oldp;

    for (i = 0;  i < trace->num_ops;  i++) {
        switch (trace->ops[i].type) {

        case ALLOC: /* malloc */
	    if ((p = malloc(trace->ops[i].size)) == NULL) {
		malloc_error(tracenum, i, "libc malloc failed");
		unix_error("System message");
	    }
	    trace->blocks[trace->ops[i].index] = p;
	    break;

	case REALLOC: /* realloc */
            newsize = trace->ops[i].size;
	    oldp = trace->blocks[trace->ops[i].index];
	    if ((newp = realloc(oldp, newsize)) == NULL) {
		malloc_error(tracenum, i, "libc realloc failed");
		unix_error("System message");
	    }
	    trace->blocks[trace->ops[i].index] = newp;
	    break;
	    
        case FREE: /* free */
	    free(trace->blocks[trace->ops[i].index]);
	    break;

	default:
	    app_error("invalid operation type  in eval_libc_valid");
	}
    }

    return 1;
}

/* 
 * eval_libc_speed - This is the function that is used by fcyc() to
 *    measure the running time of the libc malloc package on the set
 *    of traces.
 */
static void eval_libc_speed(void *ptr)
{
    int i;
    int index, size, newsize;
    char *p, *newp, *oldp, *block;
    trace_t *trace = ((speed_t *)ptr)->trace;

    for (i = 0;  i < trace->num_ops;  i++) {
        switch (trace->ops[i].type) {
        case ALLOC: /* malloc */
	    index = trace->ops[i].index;
	    size = trace->ops[i].size;
	    if ((p = malloc(size)) == NULL)
		unix_error("malloc failed in eval_libc_speed");
	    trace->blocks[index] = p;
	    break;

	case REALLOC: /* realloc */
	    index = trace->ops[i].index;
	    newsize = trace->ops[i].size;
	    oldp = trace->blocks[index];
	    if ((newp = malloc(newsize)) == NULL)
		unix_error("malloc failed in eval_libc_speed\n");
            free(oldp);
	    
	    trace->blocks[index] = newp;
	    break;
	    
        case FREE: /* free */
	    index = trace->ops[i].index;
	    block = trace->blocks[index];
	    free(block);
	    break;
	}
    }
}

/*************************************
 * Some miscellaneous helper routines
 ************************************/

static int check(int chaos, const char *what)
{
  if (chaos) {
    mangle();
    if (!mm_check()) {
      mem_reset();
      return 0;
    }
  } else {
    if (!mm_check()) {
      if (!strcmp(what, "alloc"))
        app_error("mm_check failed after alloc");
      else
        app_error("mm_check failed after free");
    }
  }

  return 1;
}

static int check_free(int chaos, void *p)
{  
  if (chaos) {
    if (!mm_can_free(p)) {
      mem_reset();
      return 0;
    }
    if (mm_can_free(p + 8))
      mm_free(p+8);
    if (mm_can_free(p - 8))
      mm_free(p-8);
  } else {
    if (!mm_can_free(p)) {
      app_error("mm_can_free incorrectly claimed unfreeable");
    }
  }

  return 1;
}

static void check_post_free(int chaos, void *p)
{
  if (chaos) {
    if (mm_can_free(p)) {
      /* although p was just freed, the implementaton claims that it's
         ok to free, so... */
      mm_free(p);
    }
  } else {
    if (mm_can_free(p))
      app_error("mm_can_free incorrectly claimed freeable after free");
  }
}

static int mangle_pageno;
static size_t mangle_offset;
static size_t mangle_len;
static char mangle_v;

static void mangle_page(void *addr) {
  if (mangle_pageno == 0) {
    size_t len = mangle_len;
    size_t c = mangle_offset;
    
    while (len--) {
      ((char *)addr)[c++] = mangle_v;
    }

    mangle_pageno = random() % 16;
  } else
    mangle_pageno--;
}

static void mangle(void)
{
  /* Mangle multiple pages at the same place */
  mangle_offset = random() % mem_pagesize();
  mangle_len = random() % 8;
  if (mangle_len + mangle_offset > mem_pagesize())
    mangle_len = mem_pagesize() - mangle_offset;  
  mangle_v = random() % 256;

  mangle_pageno = random() % 16;
  pagemap_for_each(mangle_page, 0);
}

/*
 * printresults - prints a performance summary for some malloc package
 */
static void printresults(int n, stats_t *stats) 
{
    int i;
    double secs = 0;
    double ops = 0;
    double util = 0;
    double inst_util = 0;

    /* Print the individual results for each trace */
    printf("%5s%7s %5s%7s%7s%10s%6s\n", 
	   "trace", " valid", "util", "util_i", "ops", "secs", "Kops");
    for (i=0; i < n; i++) {
	if (stats[i].valid) {
	    printf("%2d%10s%5.0f%%%5.0f%%%8.0f%10.6f%6.0f\n", 
		   i,
		   "yes",
		   stats[i].util*100.0,
		   stats[i].inst_util*100.0,
		   stats[i].ops,
		   stats[i].secs,
		   (stats[i].ops/1e3)/stats[i].secs);
	    secs += stats[i].secs;
	    ops += stats[i].ops;
	    util += stats[i].util;
	    inst_util += stats[i].inst_util;
	}
	else {
	    printf("%2d%10s%6s%8s%10s%6s\n", 
		   i,
		   "no",
		   "-",
		   "-",
		   "-",
		   "-");
	}
    }

    /* Print the aggregate results for the set of traces */
    if (errors == 0) {
	printf("%12s%5.0f%%%5.0f%%%8.0f%10.6f%6.0f\n", 
	       "Total       ",
	       (util/n)*100.0,
	       (inst_util/n)*100.0,
	       ops, 
	       secs,
	       (ops/1e3)/secs);
    }
    else {
	printf("%12s%6s%6s%8s%10s%6s\n", 
	       "Total       ",
	       "-", 
	       "-", 
	       "-", 
	       "-", 
	       "-");
    }

}

/* 
 * app_error - Report an arbitrary application error
 */
void app_error(char *msg) 
{
    printf("%s\n", msg);
    exit(1);
}

/* 
 * unix_error - Report a Unix-style error
 */
void unix_error(char *msg) 
{
    printf("%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * malloc_error - Report an error returned by the mm_malloc package
 */
void malloc_error(int tracenum, int opnum, char *msg)
{
    errors++;
    printf("ERROR [trace %d, line %d]: %s\n", tracenum, LINENUM(opnum), msg);
}

/* 
 * usage - Explain the command line arguments
 */
static void usage(void) 
{
    fprintf(stderr, "Usage: mdriver [-nhvVal] [-f <file>] [-t <dir>] [-s <seed>] [-r <reps>]\n");
    fprintf(stderr, "Options\n");
    fprintf(stderr, "\t-n         Skip mm_check and mm_can_free correctness.\n");
    fprintf(stderr, "\t-f <file>  Use <file> as the trace file.\n");
    fprintf(stderr, "\t-g         Generate summary info for autograder.\n");
    fprintf(stderr, "\t-h         Print this message.\n");
    fprintf(stderr, "\t-s <seed>  Seed random-number generator for chaos.\n");
    fprintf(stderr, "\t-r <reps>  Try defenses against chaos <reps> times.\n");
    fprintf(stderr, "\t-l         Run libc malloc as well.\n");
    fprintf(stderr, "\t-t <dir>   Directory to find default traces.\n");
    fprintf(stderr, "\t-q         Quiet: not per-trace performance breakdowns.\n");
}
