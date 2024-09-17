/*
 * mm_alloc.h
 *
 * Exports a clone of the interface documented in "man 3 malloc".
 */

#pragma once

#ifndef _malloc_H_
#define _malloc_H_

#include <stdlib.h>

// #include "../pintos/src/lib/kernel/list.h"
#include "list.h"

/* list of available blocks in the heap */
struct list free_block_list = LIST_INITIALIZER(free_block_list);

/* meta of a block memory */
typedef struct block_meta {
    size_t size_; /* bytes of the block excluding meta-self */
    bool free_; /* true if the block is not allocated */
    struct list_elem elem_; /* list element */
} block_meta;

void* mm_malloc(size_t size);
void* mm_realloc(void* ptr, size_t size);
void mm_free(void* ptr);

#endif
