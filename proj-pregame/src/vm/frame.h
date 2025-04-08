#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "page.h"
#include "swap.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include <stdbool.h>
#include "lib/string.h"

struct frame;

/* operations of frame management */

void framesys_init();

bool allocate_frame(struct process* pcb, struct spt_entry* spte);

void deallocate_frame(struct process* pcb, struct spt_entry* spte);

// return true if frame F is pinned 
bool pin_frame(struct process* pcb, struct spt_entry* spte);
// unpin frame F
void unpin_frame(struct process* pcb, struct spt_entry* spte);

#endif