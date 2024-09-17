/*
 * mm_alloc.c
 */

#include "mm_alloc.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <syscall.h>

#define MIN_SIZE_ON_SBRK 4096

/**
 * get an available block from the free block list with first fit strategy
 * @param SIZE bytes of the block
 * @return address of a free block or NULL if no available free blocks in the list
*/
static void* get_free_block_from_the_list(size_t size) {
  void* available_block = NULL;
  // get free block from the list
  struct list_elem *e = NULL;
  for (e = list_begin(&free_block_list); e != list_end(&free_block_list); e = list_next(e)) {
    block_meta *b_meta = list_entry(e, block_meta, elem_);
    if (b_meta->size_ >= size) {
      available_block = (void*)((intptr_t)b_meta + sizeof (block_meta));

      // split the block if it is large enough to hold at least two blocks
      if (b_meta->size_ >= (size + sizeof (block_meta))) {

        // split the old block and insert the new block into the list after the old block
        block_meta *new_block_meta = (block_meta*)((intptr_t)b_meta + sizeof(block_meta) + size);
        new_block_meta->free_ = true;
        new_block_meta->size_ = b_meta->size_ - size - sizeof (block_meta);
        list_insert(e->next, &new_block_meta->elem_);

        // update size of old block
        b_meta->size_  = size;
        b_meta->free_ = false;
      }

      break;
    }
  }

  return available_block;
}

/**
 * create more space on the heap
 * @param SIZE the size bytes the list needs from OS and SIZE >= 0
 * @return true if the heap size is changed or false
*/
static bool create_more_space_on_the_heap(size_t size) {
  size_t real_size = size + sizeof (block_meta);
  if (real_size < MIN_SIZE_ON_SBRK) {
    real_size = MIN_SIZE_ON_SBRK;
  }
  void* prev_brk = sbrk((intptr_t)real_size);

  // insert new space into the free block list if any
  if (prev_brk != (void*)-1) {
    block_meta *new_b_meta = (block_meta*)prev_brk;
    new_b_meta->size_ = real_size - sizeof (block_meta);
    new_b_meta->free_ = true;
    list_push_back(&free_block_list, &new_b_meta->elem_);
  }
  
  return prev_brk != (void*)-1;
}

void* mm_malloc(size_t size) {
  //TODO: Implement malloc

  void* block = NULL;
  block = get_free_block_from_the_list(size);

  if (block == NULL) {
    bool success = create_more_space_on_the_heap(size);
    if (success) {
      block = get_free_block_from_the_list(size);
    }
  }

  return block;
}

void* mm_realloc(void* ptr, size_t size) {
  //TODO: Implement realloc

  void *new_block = NULL;

  if ((ptr != NULL) && (size != 0)) {
    new_block = mm_malloc(size);
    if (new_block) {
      block_meta * old_b_meta = (block_meta*)((uintptr_t)ptr - sizeof (block_meta));
      memcpy(new_block, ptr, old_b_meta->size_);
      mm_free(ptr);
    }
  }
  else if ((ptr != NULL) && (size == 0)) {
    mm_free(ptr);
    new_block = NULL;
  }
  else if ((ptr == NULL) && (size != 0)) {
    new_block = mm_malloc(size);
  }
  else if ((ptr == NULL) && (size == 0)) {
    new_block = NULL;
  }

  return new_block;
}


/**
 * coalesce consecutive free blocks in the list[START, END)
 * @param START first block in the consecutive free blocks
 * @param END next block of the last block in the consecutive free blocks
*/
static void coalesce_consecutive_free_blocks(struct list_elem *start, struct list_elem *end) {
  block_meta* new_b_meta = list_entry(start, block_meta, elem_);
  struct list_elem *next_elem = start->next;

  while (next_elem != end) {
    block_meta* b_meta = list_entry(next_elem, block_meta, elem_);
    new_b_meta->size_ += (b_meta->size_ + sizeof (block_meta));
    struct list_elem *to_be_deleted = next_elem;
    next_elem = next_elem->next;
    list_remove(to_be_deleted);
  }
}

void mm_free(void* ptr) {
  //TODO: Implement free
  if (ptr != NULL) {
    block_meta* freed_block = (block_meta*)((uintptr_t)ptr - sizeof (block_meta));
    freed_block->free_ = true;

    // coalesce consecutive free blocks if necessary
    struct list_elem *prev_start = NULL;
    for (prev_start = &freed_block->elem_; prev_start != list_rend(&free_block_list); prev_start = list_prev(prev_start)) {
      block_meta *b_meta = list_entry(prev_start, block_meta, elem_);
      if (!b_meta->free_) {
        break;
      }
    }

    struct list_elem *end = NULL;
    for (end = &freed_block->elem_; end != list_end(&free_block_list); end = list_next(end)) {
      block_meta *b_meta = list_entry(end, block_meta, elem_);
      if (!b_meta->free_) {
        break;
      }
    }
    coalesce_consecutive_free_blocks(prev_start->next, end);
  }

}
