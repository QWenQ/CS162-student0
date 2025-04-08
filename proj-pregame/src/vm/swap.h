#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "kernel/hash.h"
#include "threads/synch.h"
#include "lib/debug.h"

typedef block_sector_t block_slot_t;

void swapsys_init();
void swapsys_destroy();
block_slot_t write_data_to_swap(void* buf);
void read_data_from_swap(void* buf, block_slot_t slot_idx);

void free_swap_slot(block_slot_t slot_idx);

#endif