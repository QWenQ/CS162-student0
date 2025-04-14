#include "page.h"
#include "threads/pte.h"

#define INVALID_SWAP_SLOT_INDEX 0xffffffff

static unsigned spt_hash_func(const struct hash_elem* e, void* aux UNUSED);
static bool spt_hash_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED);
static void spt_hash_destroy_func(struct hash_elem* e, void* aux UNUSED);


static struct spt_entry* get_spte_of_page(struct process* pcb, void* vaddr);
static void clear_dirty_page(struct hash_elem* e, void* aux);
static void free_page(struct hash_elem* e, void* aux);

static void lock_on_vm(struct process* pcb);
static void unlock_on_vm(struct process* pcb);

// entry of supplemental page table
struct spt_entry {
    uint8_t* upage_; // virtual page address;
    bool is_writable_; // true if the page is write/read
    struct file* file_; // file opened
    off_t offset_; // start in the file
    size_t size_; // data bytes in the page
    struct semaphore sema_on_swap_; // up if the data is in the swap
    block_slot_t swap_slot_idx_; // index(!= 0xffffffff) of swap slot where page data is in
    struct hash_elem h_elem_; // managed by supplemental page table
};


// return a hash value for a struct spt_entry object
static unsigned spt_hash_func(const struct hash_elem* e, void* aux UNUSED) {
    struct spt_entry* ent = hash_entry(e, struct spt_entry, h_elem_);
    return hash_int(ent->upage_);
}

// return true if paddr_ of spt_entry A preceeds B's
static bool spt_hash_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED) {
    struct spt_entry* ent_a = hash_entry(a, struct spt_entry, h_elem_);
    struct spt_entry* ent_b = hash_entry(b, struct spt_entry, h_elem_);
    return ent_a->upage_ < ent_b->upage_;
}

// deallocate memory allcoated to struct spt_entry object in the spt hash
static void spt_hash_destroy_func(struct hash_elem* e, void* aux UNUSED) {
    struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
    free(spte);
}


/* operations of struct spt_entry */

uint32_t spte_get_virtual_addr(struct spt_entry* spte) {
    return spte->upage_;
}

bool spte_is_writable(struct spt_entry* spte) {
    return spte->is_writable_;
}

struct file* spte_get_file(struct spt_entry* spte) {
    return spte->file_;
}

off_t spte_get_offset(struct spt_entry* spte) {
    return spte->offset_;
}

size_t spte_get_size(struct spt_entry* spte) {
    return spte->size_;
}

block_slot_t spte_get_swap_index(struct spt_entry* spte) {
    return spte->swap_slot_idx_;
}

void spte_set_swap_index(struct spt_entry* spte, block_slot_t swap_slot_idx) {
    spte->swap_slot_idx_ = swap_slot_idx;
}

void spte_swap_sema_down(struct spt_entry* spte) {
    sema_down(&spte->sema_on_swap_);
}

void spte_swap_sema_up(struct spt_entry* spte) {
    sema_up(&spte->sema_on_swap_);
}

/* operations of virtual memory management */


// lock pcb->lock_on_vm_
static void lock_on_vm(struct process* pcb) {
    if (!lock_held_by_current_thread(&pcb->lock_on_vm_)) {
        lock_acquire(&pcb->lock_on_vm_);
    }
}

// unlock pcb->lock_on_vm_
static void unlock_on_vm(struct process* pcb) {
    if (lock_held_by_current_thread(&pcb->lock_on_vm_)) {
        lock_release(&pcb->lock_on_vm_);
    }
}

// initialize supplemental page table
void supplemental_page_table_init(struct process* pcb ,struct hash* spt) {
    bool success = hash_init(spt, spt_hash_func, spt_hash_less_func, NULL);
    if (!success) {
        PANIC("Initialization of supplemental page table fails.\n");
    }
    spt->aux = pcb;
}

// allocate a page for VADDR, if FILE_NAME is NULL, page is anonymity type, else file type
bool allocate_page(struct process* p, uint8_t* vaddr, bool writable, struct file* file, off_t offset, uint32_t size) {
    struct spt_entry* spte = (struct spt_entry*)calloc(sizeof(struct spt_entry), 1);
    if (spte == NULL) return false;
    spte->upage_ = ((uint32_t)vaddr & PTE_ADDR);
    spte->is_writable_ = writable;
    spte->file_ = file;
    spte->offset_ = offset;
    spte->size_ = size;
    sema_init(&(spte->sema_on_swap_), 0);
    spte->swap_slot_idx_ = INVALID_SWAP_SLOT_INDEX;
    lock_on_vm(p);
    struct hash_elem* e = hash_insert(&p->spt_, &spte->h_elem_);
    unlock_on_vm(p);
    if (e != NULL) {
        free(spte);
        return false;
    }
    return true;
}


// write all dirty file pages back to disk and free swap slots
static void clear_dirty_page(struct hash_elem* e, void* aux) {
    struct process* p = (struct process*)aux;
    struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
    if (spte->swap_slot_idx_ != INVALID_SWAP_SLOT_INDEX) {
        // wait until the dirty page has been written into the swap
        spte_swap_sema_down(spte);
        // write file dirty page dirty back to the process virtual space
        if (spte->file_ && spte->size_ > 0 && pagedir_is_dirty(p->pagedir, spte->upage_)) {
            if (pagedir_get_page(p->pagedir, spte->upage_) == NULL) {
                allocate_frame_for_page(p, spte->upage_);
            }
        }
        // free swap slots occupied by dirty page
        free_swap_slot(spte->swap_slot_idx_);
        spte_set_swap_index(spte, INVALID_SWAP_SLOT_INDEX);
    }

    // write file dirty data back to file 
    if (spte->file_ && spte->size_ > 0 && pagedir_is_dirty(p->pagedir, spte->upage_)) {
        file_write_at(spte->file_, spte->upage_, spte->size_, spte->offset_);
        pagedir_set_dirty(p->pagedir, spte->upage_, false);
    }
}

// free page allocated
static void free_page(struct hash_elem* e, void* aux) {
    struct process* p = (struct process*)aux;
    struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
    // if page is present, dereference the frame referred by the page
    void* upage = spte_get_virtual_addr(spte);
    if (pagedir_get_page(p->pagedir, upage)) {
        deallocate_frame(p, spte);
        pagedir_clear_page(p->pagedir, upage);
    }
}

// clear all allocated pages in a process
void deallocate_all_pages(struct process* p) {
    hash_apply(&p->spt_, clear_dirty_page);
    hash_apply(&p->spt_, free_page);
    // destory supplemental page table
    hash_destroy(&p->spt_, spt_hash_destroy_func);
    // page table will be destroty by the caller 
}

// deallocate page pointed by UADDR in process PCB
void deallocate_page(struct process* pcb, uint8_t* upage) {
    struct spt_entry key;
    key.upage_ = upage;
    lock_on_vm(pcb);
    struct hash_elem* e = hash_delete(&pcb->spt_, &key.h_elem_);
    unlock_on_vm(pcb);
    struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
    // struct spt_entry* spte = get_spte_of_page(pcb, upage);
    if (spte) {
        clear_dirty_page(&spte->h_elem_, pcb);
        free_page(&spte->h_elem_, pcb);
    }
}


// allocate a frame; data initialization if necessary; update PTE/SPTE;
// return true if op successes
bool allocate_frame_for_page(struct process* p, uint8_t* vaddr) {
    bool success = false;
    lock_on_vm(p);
    struct spt_entry* spte = get_spte_of_page(p, vaddr);
    if (spte) {
        success = allocate_frame(p, spte);
    }
    unlock_on_vm(p);
    return success;
}

/**
 * check if VADDR is in the range of valid data
 * @param p process's pcb
 * @param vaddr virtual address accessed
 * @return true if VADDR is in the range of valid data
*/
bool is_access_valid(struct process* p, uint8_t* vaddr) {
    bool is_valid = false;
    lock_on_vm(p);
    struct hash* spt = &p->spt_;
    struct spt_entry tmp;
    tmp.upage_ = pt_no(vaddr);
    struct hash_elem* e = hash_find(spt, &tmp.h_elem_);
    if (e) {
        struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
        uint32_t idx = (uint32_t)vaddr - pt_no(vaddr);
        if (idx < spte->size_) {
            is_valid = true;
        }
    }
    unlock_on_vm(p);
    return is_valid;
}


// check if VADDR is allocated before
bool is_page_valid(struct process* pcb, uint8_t* vaddr) {
    bool is_valid = true;
    lock_on_vm(pcb);
    struct spt_entry* spte = get_spte_of_page(pcb, vaddr);
    if (spte == NULL) {
        is_valid = false;
    }
    unlock_on_vm(pcb);
    return is_valid;
}

// return true if page pointed by VADDR is writable, the caller should guarantee that the page is mapped
bool is_page_writable(struct process* pcb, uint8_t* vaddr) {
    bool is_writable = false;
    lock_on_vm(pcb);
    struct spt_entry* spte = get_spte_of_page(pcb, vaddr);
    if (spte) {
        is_writable = spte_is_writable(spte);
    }
    unlock_on_vm(pcb);
    return is_writable;
}

uint32_t get_free_page_from_top(struct process* p) {
    uint32_t start = PHYS_BASE;
    lock_on_vm(p);
    while (start > PGSIZE) {
        struct spt_entry* spte = get_spte_of_page(p, start);
        if (spte == NULL) {
            break;
        }
        start -= PGSIZE;
    }
    unlock_on_vm(p);
    return start;
}

// return a pointer to a struct spt_entry object releated to VADDR in PCB else NULL
static struct spt_entry* get_spte_of_page(struct process* pcb, void* vaddr) {
    uint32_t upage = (uint32_t)vaddr & PTE_ADDR;
    struct spt_entry key;
    key.upage_ = upage;
    struct hash_elem* e = hash_find(&pcb->spt_, &key.h_elem_);
    if (e) {
        struct spt_entry* spte = hash_entry(e, struct spt_entry, h_elem_);
        // allocate a frame and update page's SPTE
        return spte;
    }
    return NULL;
}

// pin the page pointed by VADDR to prevent its associated frame from being evicted
bool pin_page(struct process* pcb, void* vaddr) {
    // if page is not-present, allocate a new frame for the page
    // pin the page
    bool success = true;
    lock_on_vm(pcb);
    if (pagedir_get_page(pcb->pagedir, vaddr) == NULL) {
        success = allocate_frame_for_page(pcb, vaddr);
    }
    if (success) {
        struct spt_entry* spte = get_spte_of_page(pcb, vaddr);
        if (spte) {
            success = pin_frame(pcb, spte);
        }
    }
    unlock_on_vm(pcb);
    return success;
}

// unpin the page, after that, the associated frame is allowed to be evicted
void unpin_page(struct process* pcb, void* vaddr) {
    lock_on_vm(pcb);
    if (pagedir_get_page(pcb->pagedir, vaddr)) {
        struct spt_entry* spte = get_spte_of_page(pcb, vaddr);
        if (spte) {
            unpin_frame(pcb, spte);
        }
    }
    unlock_on_vm(pcb);
}