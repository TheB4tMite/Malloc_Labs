/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "0u751d3r5",
    /* First member's full name */
    "TheB4tMite",
    /* First member's email address */
    "banana@banana.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define WSIZE 4
#define DSIZE 8

#define MAX(x,y) ((x) > (y) ? (x) : (y))

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// maximum possible heap size
#define MAX_HEAP getpagesize()

// extend chunk size
#define CHUNKSIZE 1024

// Pack a size and allocated bit into a word
#define PACK(size,inuse) ((size) | (inuse))

// Read and write a word at address p
#define GET(p) (*(unsigned int *)(p))
#define PUT(p,val) (*(unsigned int *)(p) = (val))

// Getting size and alloc state from a pointer
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

// Getting header and footer pointers of a block
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

// Getting next and previous block payload pointers
#define NEXTBP(bp) ((char *)bp + GET_SIZE(HDRP(bp)))
#define PREVBP(bp) ((char *)bp - GET_SIZE((bp-DSIZE)))

// Getting next and previous free block pointers
#define NFREE(bp) (*(char **)(bp + WSIZE))
#define PFREE(bp) (*(char **)(bp))

// Write a word to next and prev payload pointers
#define PUTN(bp,np) ((NFREE(bp)) = np)
#define PUTP(bp,np) ((PFREE(bp)) = np)

// Global variables
static char * heap_ptr = 0;
static char * free_list_head = 0; // Free list head pointer

// Function prototypes
static void * mm_sbrk(size_t words);
static void * mm_fit(size_t size);
static void * mm_coalesce(char * blk_ptr);
static void mm_alloc(char * blk_ptr, size_t align_size);
static void mm_insert(char * blk_ptr);
static void mm_detach(char * blk_ptr);

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void) {
    
    if ((heap_ptr = mem_sbrk(16)) != NULL) { 
        PUT(heap_ptr, 0);
        PUT(heap_ptr+4,PACK(4,1)); // Prologue header
        PUT(heap_ptr+8,PACK(4,1)); // Prologue footer
        PUT(heap_ptr+12,PACK(0,1)); // Epilogue header
        free_list_head = heap_ptr + 16;
        return 0;
    } 
    return -1;
}

/*
* mm_sbrk - extends heap when addtional memory required
*/
static void * mm_sbrk(size_t words) {

    char * blk_ptr;
    size_t align_size;
    
    align_size = words * 4;
    if (words % 2) (align_size = (words + 1)*4); // Aligning size to 8-byte boundary
    
    if (align_size < 16) align_size = 16;
    
    if ((int)(blk_ptr = mem_sbrk(align_size)) == -1) return NULL;
    
    PUT(HDRP(blk_ptr), PACK(align_size, 0)); // Chunk header
    PUT(FTRP(blk_ptr), PACK(align_size, 0)); // Chunk footer
    PUT(HDRP(NEXTBP(blk_ptr)), PACK(0, 1)); // New Epilogue header

    return mm_coalesce(blk_ptr);
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void * mm_malloc(size_t size) {

    size_t align_size;
    char * blk_ptr;

    if (size <= 0 || size > MAX_HEAP) return NULL; // Invalid size check

    if (size <= 8) {
        align_size = 16;
    } else {
        align_size = ALIGN(size) + 8;
    }

    if ((blk_ptr = (char *)mm_fit(align_size)) != NULL) { // Finding free block with suitable size
        mm_alloc(blk_ptr,align_size); // Allocating chunk in heap
        return blk_ptr; 
    }

    if ((blk_ptr = (char *)mm_sbrk(MAX(align_size,CHUNKSIZE)/4)) == NULL) { // Requesting more space if free block not found
        return NULL;
    }

    mm_alloc(blk_ptr, align_size); // Allocating chunk in heap
    return blk_ptr;
}

/*
* mm_fit - Finds free block of suitable size
*/
static void * mm_fit(size_t size) {

    char * cmp_block = free_list_head;
    char * min_block = NULL;
    
    // First-fit algorithm
    // for (cmp_block = free_list_head; ((GET_ALLOC(HDRP(cmp_block)) == 0) && (NFREE(cmp_block) != NULL)); cmp_block = NFREE(cmp_block)) {
    //     if (size <= (size_t)GET_SIZE(HDRP(cmp_block))) return cmp_block;
    // }
    // return NULL;

    // Best-fit algorithm
    while (NFREE(cmp_block) && (!GET_ALLOC(HDRP(cmp_block)))) {
        
        if (!min_block) {
            if (size <= GET_SIZE(HDRP(cmp_block))) min_block = cmp_block;
        } else {
            if (size == GET_SIZE(HDRP(min_block))) return min_block;

            if ((size < GET_SIZE(HDRP(cmp_block))) && (GET_SIZE(HDRP(min_block)) > GET_SIZE(HDRP(cmp_block))) && (min_block != cmp_block)) min_block = cmp_block;
        }    
        
        if (NFREE(cmp_block) && (NFREE(cmp_block) != free_list_head)) {
            cmp_block = NFREE(cmp_block);
        } else break;
    }
    return min_block;
}

/*
* mm_alloc - Allocates chunk and encodes chunk data within block returned by mm_fit
*/
static void mm_alloc(char * blk_ptr, size_t align_size) {

    size_t block_size = GET_SIZE(HDRP(blk_ptr));
    
    if ((block_size - align_size) >= 16) {
        PUT(HDRP(blk_ptr), PACK(align_size, 1));
        PUT(FTRP(blk_ptr), PACK(align_size, 1));
        mm_detach(blk_ptr);
        PUT(HDRP(NEXTBP(blk_ptr)), PACK(block_size - align_size, 0));
        PUT(FTRP(NEXTBP(blk_ptr)), PACK(block_size - align_size, 0));
        mm_coalesce(NEXTBP(blk_ptr));
    } else {
        PUT(HDRP(blk_ptr), PACK(block_size, 1));
        PUT(FTRP(blk_ptr), PACK(block_size, 1));
        mm_detach(blk_ptr);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void * blk_ptr) {

    size_t size;
    
    if (!blk_ptr) return;

    size = GET_SIZE(HDRP(blk_ptr));
    PUT(HDRP(blk_ptr), PACK(size,0));
    PUT(FTRP(blk_ptr), PACK(size,0));

    mm_coalesce(blk_ptr);
}

/*
* mm_coalesce - Handles coalescing adjacent free blocks
*/
static void * mm_coalesce(char * blk_ptr) {

    size_t n_alloc = GET_ALLOC(HDRP(NEXTBP(blk_ptr)));
    size_t p_alloc = ((GET_ALLOC(blk_ptr - DSIZE)) || (PREVBP(blk_ptr) == blk_ptr));
    size_t new_size = GET_SIZE(HDRP(blk_ptr));

    if (!p_alloc && n_alloc) { // Prev block is free
        blk_ptr = PREVBP(blk_ptr);
        new_size += GET_SIZE(HDRP(blk_ptr));
        mm_detach(blk_ptr);
        PUT(HDRP(blk_ptr), PACK(new_size, 0));
        PUT(FTRP(blk_ptr), PACK(new_size, 0));
    } else if (p_alloc && !n_alloc) { // Next block is free
        new_size += GET_SIZE(HDRP(NEXTBP(blk_ptr)));
        mm_detach(NEXTBP(blk_ptr));
        PUT(HDRP(blk_ptr), PACK(new_size, 0));
        PUT(FTRP(blk_ptr), PACK(new_size, 0));
    } else if (!p_alloc && !n_alloc) { // Next and Prev block are free
        new_size += (GET_SIZE(HDRP(PREVBP(blk_ptr))) + GET_SIZE(HDRP(NEXTBP(blk_ptr))));
        mm_detach(PREVBP(blk_ptr));
        mm_detach(NEXTBP(blk_ptr));
        blk_ptr = PREVBP(blk_ptr);
        PUT(HDRP(blk_ptr), PACK(new_size, 0));
        PUT(FTRP(blk_ptr), PACK(new_size, 0));
    }
    mm_insert(blk_ptr);
    return blk_ptr;
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void * mm_realloc(void * blk_ptr, size_t size) {
    
    size_t old_size = GET_SIZE(HDRP(blk_ptr));
    size_t new_size = size + 8;

    if (size < 0) {
        return NULL;
    } else if (size == 0) {
        mm_free(blk_ptr);
        return NULL;
    } else if (size > 0) {
        size_t n_alloc = GET_ALLOC(HDRP(NEXTBP(blk_ptr)));

        if (size < old_size) return blk_ptr;
        else if (!n_alloc && ((old_size + GET_SIZE(HDRP(NEXTBP(blk_ptr)))) >= new_size)) {
            mm_detach(NEXTBP(blk_ptr));
            PUT(HDRP(blk_ptr), PACK(new_size, 1));
            PUT(FTRP(blk_ptr), PACK(new_size, 1));
            return blk_ptr;
        } else {
            char * new_ptr = mm_malloc(new_size);
            mm_alloc(new_ptr, new_size);
            memcpy(new_ptr, blk_ptr, new_size);
            mm_free(blk_ptr);
            return new_ptr;
        }

    } else return NULL;
}

/*
* mm_insert - Adds prev and next pointers to a block
*/
static void mm_insert(char * blk_ptr) {
    PUTN(blk_ptr, free_list_head);
    PUTP(free_list_head, blk_ptr);
    PUTP(blk_ptr, NULL);
    free_list_head = blk_ptr;
}

/*
* mm_detach - Unlinks argument block and links adjacent blocks if needed
*/
static void mm_detach(char * blk_ptr) {
    if (PFREE(blk_ptr)) {
        PUTN(PFREE(blk_ptr),NFREE(blk_ptr));
    } else {
        free_list_head = NFREE(blk_ptr);
    }
    PUTP(NFREE(blk_ptr), PFREE(blk_ptr));
}
