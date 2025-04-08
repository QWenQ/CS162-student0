#include "swap.h"

// note: index in the hash should be multiple of 8
#define SECTOR_NUMBERS_PER_SLOT 8

// lock before accessing swap system
struct lock lock_on_swap;
// ptr to swap block 
static struct block* swap_block;

// usage of array slots
static bool* swap_slots;
uint32_t swap_slot_size;

// initialize swap system
void swapsys_init() {
    lock_init(&lock_on_swap);
    // size of swap block is n-MB designated in the command line
    swap_block = block_get_role(BLOCK_SWAP);
    if (swap_block == NULL) {
        PANIC("There is no swap block!/n");
    }
    swap_slot_size = block_size(swap_block) / SECTOR_NUMBERS_PER_SLOT;
    swap_slots = (bool*)calloc(swap_slot_size, sizeof(bool));
    if (swap_slots == NULL) {
        PANIC("Initialization of swap system fails: out of memory!\n");
    }
}

// reclamin resources allocated to swap system
void swapsys_destroy() {
    free(swap_slots);
}

// write data in the frame pointed by BUF to the swap, the frame is 8-sector size
block_slot_t write_data_to_swap(void* buf) {
    lock_acquire(&lock_on_swap);
    block_slot_t slot_idx = 0;
    while (slot_idx < swap_slot_size) {
        if (swap_slots[slot_idx] == 0) {
            swap_slots[slot_idx] = 1;
            for (uint32_t offset = 0; offset < SECTOR_NUMBERS_PER_SLOT; ++offset) {
                block_sector_t sector_idx = slot_idx * SECTOR_NUMBERS_PER_SLOT + offset;
                char* start = (char*)buf + offset * BLOCK_SECTOR_SIZE;
                block_write(swap_block, sector_idx, (void*)start);
            }
            break;
        }
        ++slot_idx;
    }
    lock_release(&lock_on_swap);
    if (slot_idx >= swap_slot_size) {
        PANIC("No available swap slot!/n");
    }
    return slot_idx;
}

// read data into frame pointed by BUF from swap secotrs [SECTOR_IDX, SECTOR_IDX + 8)
void read_data_from_swap(void* buf, block_slot_t slot_idx) {
    lock_acquire(&lock_on_swap);
    ASSERT(slot_idx < swap_slot_size);
    ASSERT(swap_slots[slot_idx] == 1);

    for (uint32_t offset = 0; offset < SECTOR_NUMBERS_PER_SLOT; ++offset) {
        block_sector_t sector_idx = slot_idx * SECTOR_NUMBERS_PER_SLOT + offset;
        char* start = (char*)buf + offset * BLOCK_SECTOR_SIZE;
        block_read(swap_block, sector_idx, (void*)start);
    }

    swap_slots[slot_idx] = 0;
    lock_release(&lock_on_swap);
}

// free swap slot specified by SLOT_IDX
void free_swap_slot(block_slot_t slot_idx) {
    if (slot_idx >= swap_slot_size) return;
    lock_acquire(&lock_on_swap);
    swap_slots[slot_idx] = 0;
    lock_release(&lock_on_swap);
}