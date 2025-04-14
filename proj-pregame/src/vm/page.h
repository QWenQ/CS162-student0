#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "frame.h"
#include "swap.h"
#include "hash.h"
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

typedef block_sector_t block_slot_t;

// SPT entry
struct spt_entry;

/* operations of struct spt_entry */

uint32_t spte_get_virtual_addr(struct spt_entry* spte);
bool spte_is_writable(struct spt_entry* spte);
struct file* spte_get_file(struct spt_entry* spte);
off_t spte_get_offset(struct spt_entry* spte);
size_t spte_get_size(struct spt_entry* spte);
block_slot_t spte_get_swap_index(struct spt_entry* spte);
void spte_set_swap_index(struct spt_entry* spte, block_slot_t swap_slot_idx);
void spte_swap_sema_down(struct spt_entry* spte);
void spte_swap_sema_up(struct spt_entry* spte);

/* operations of virtual memory management */

void supplemental_page_table_init(struct process* pcb, struct hash* spt);
bool allocate_page(struct process* pcb, uint8_t* vaddr, bool writable, struct file* file, off_t offset, uint32_t size);


void deallocate_all_pages(struct process* pcb);
void deallocate_page(struct process* pcb, uint8_t* vaddr);

bool allocate_frame_for_page(struct process* pcb, uint8_t* vaddr);

bool is_access_valid(struct process* pcb, uint8_t* vaddr);
bool is_page_writable(struct process* pcb, uint8_t* vaddr);
bool is_page_valid(struct process* pcb, uint8_t* vaddr);

uint32_t get_free_page_from_top(struct process* pcb);


bool pin_page(struct process* pcb, void* vaddr);

void unpin_page(struct process* pcb, void* vaddr);

#endif