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

            block_sector_t sector_idx = slot_idx * SECTOR_NUMBERS_PER_SLOT;
            uint32_t offset = 0;
            char* start = (char*)buf;
            // // debug
            // printf("\t\t\twrite_data_to_swap() into swap: %d\n", sector_idx);
            while (offset < SECTOR_NUMBERS_PER_SLOT) {
                // // debug
                // printf("\t\t\t\tfirst byte: %d, last byte: %d\n", *start, *(start + BLOCK_SECTOR_SIZE - 1));

                sector_idx += offset;
                block_write(swap_block, sector_idx, start);
                start += BLOCK_SECTOR_SIZE;
                offset += 1;
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

    block_sector_t sector_idx = slot_idx * SECTOR_NUMBERS_PER_SLOT;
    uint32_t offset = 0;
    char* start = (char*)buf;
    // // debug
    // printf("\t\t\tread_data_from_swap() from swap: %d\n", sector_idx);
    while (offset < SECTOR_NUMBERS_PER_SLOT) {

        sector_idx += offset;
        block_read(swap_block, sector_idx, start);

        // // debug
        // printf("\t\t\t\tfirst byte: %d, last byte: %d\n", *start, *(start + BLOCK_SECTOR_SIZE - 1));

        start += BLOCK_SECTOR_SIZE;
        offset += 1;
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