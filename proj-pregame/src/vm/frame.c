#include "frame.h"

#define INVALID_SWAP_SLOT_IDX 0XFFFFFFFF

/* meta info of a frame */
struct frame {
  uint8_t* kpage_;          // physical address of the frame, which should be multiple of page size
  int evict_cnt_;           // field used for evict algorithm
  int pin_cnt_;             // number of user pinning the frame
  struct list refs_;        // list of pte references to the current frame
  struct list_elem l_elem_; // managed by the USING_FRAMES_LIST 
};

/* sharing file(read-only) info using in SHARING_FILES_HASH */
struct sharing_info {
  struct file* file_;       // read-only file
  off_t offset_;            // start index in the file
  struct frame* frame_;     // frame shared
  struct hash_elem h_elem_; // managed by SHARING_FILES_HASH
};

/* info of a page referring to a frame, used for reverse mapping from frame to page */
struct page_ref {
    struct process* pcb_;     // process who owns the page referring the sharing frame
    struct spt_entry* spte_;  // page's supplemental page table entry
    struct list_elem l_elem_; // managed by PTE_REFS_ in struct frame
};

/* sharing functions */

static unsigned sharing_files_hash_func(const struct hash_elem* e, void* aux UNUSED);
static bool sharing_files_hash_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED);
static bool sharing_files_hash_init();
static void add_sharing_frame(struct file* file, off_t offset, struct frame* frame);
static void remove_sharing_frame(struct file* file, off_t offset);
static struct sharing_info* get_sharing(struct file* file, off_t offset);

// sharing only for read-only files 
static struct hash sharing_files_hash;


/* frame functions */

static void lock_paging();
static void unlock_paging();
static struct frame* get_from_user_pool();
static struct frame* evict();
static bool add_ref_to_sharing_frame(struct page_ref* ref);
static bool initialize_frame(struct frame* frame, struct page_ref* ref);
static bool create_a_new_frame(struct page_ref* ref);
static void clean_up_evicted_frame(struct frame* evicted_frame);
static bool reusing_frame(struct page_ref* ref);
static struct frame* search_frame_referred_by(struct process* pcb, struct spt_entry* spte);


// acquire before running Clock Algorithm
static struct lock lock_on_paging;

// list of allocated frames
static struct list using_frames_list;


// lock the LOCK_ON_PAGING
static void lock_paging() {
    if (!lock_held_by_current_thread(&lock_on_paging)) {
        lock_acquire(&lock_on_paging);
    }
}

// unlock the LOCK_ON_PAGING
static void unlock_paging() {
    if (lock_held_by_current_thread(&lock_on_paging)) {
        lock_release(&lock_on_paging);
    }
}


// return a hash value for a struct spt_entry object
static unsigned sharing_files_hash_func(const struct hash_elem* e, void* aux UNUSED) {
    struct sharing_info* info = hash_entry(e, struct sharing_info, h_elem_);
    return hash_int((uint32_t)info->file_);
}

// return true if kpage_ of spt_entry A preceeds B's
static bool sharing_files_hash_less_func(const struct hash_elem* a, const struct hash_elem* b, void* aux UNUSED) {
    struct sharing_info* info_a = hash_entry(a, struct sharing_info, h_elem_);
    struct sharing_info* info_b = hash_entry(b, struct sharing_info, h_elem_);
    return (info_a->file_ < info_b->file_) || ((info_a->file_ == info_b->file_) && (info_a->offset_ < info_b->offset_));
}

// return true if initialization of SHARING_FILES_HASH is successful
static bool sharing_files_hash_init() {
    return hash_init(&sharing_files_hash, sharing_files_hash_func, sharing_files_hash_less_func, NULL);
}

// recocd a read-only file page for sharing
static void add_sharing_frame(struct file* file, off_t offset, struct frame* frame) {
    struct sharing_info* new_info = (struct sharing_info*)malloc(sizeof(struct sharing_info));
    if (new_info == NULL) return;
    new_info->file_ = file;
    new_info->offset_ = offset;
    new_info->frame_ = frame;
    struct hash_elem* e = hash_insert(&sharing_files_hash, &(new_info->h_elem_));
    // if insertion fails, release memory resources
    if (e) {
        free(new_info);
    }
}

// remove a read-only file page
static void remove_sharing_frame(struct file* file, off_t offset) {
    struct sharing_info info_key;
    info_key.file_ = file;
    info_key.offset_ = offset;
    struct hash_elem* e = hash_delete(&sharing_files_hash, &info_key.h_elem_);
    if (e) {
        struct sharing_info* del_info = hash_entry(e, struct sharing_info, h_elem_);
        free(del_info);
    }
}

// return a pointer to struct sharing_info if it exits else return NULL
static struct sharing_info* get_sharing(struct file* file, off_t offset) {
    struct sharing_info info_key;
    info_key.file_ = file;
    info_key.offset_ = offset;
    struct hash_elem* e = hash_find(&sharing_files_hash, &info_key.h_elem_);
    if (e == NULL) return NULL;
    struct sharing_info* ret_info = hash_entry(e, struct sharing_info, h_elem_);
    return ret_info;
}

// initialization of frame manage system
void framesys_init() {
    lock_init(&lock_on_paging);
    list_init(&using_frames_list);
    if (!sharing_files_hash_init()) {
        PANIC("Initialization of sharing file system fails!\n");
    }
}

// get a free frame if possible
static struct frame* get_frame_from_user_pool() {
    uint8_t* frame_addr = palloc_get_page(PAL_USER);
    if (frame_addr == NULL) {
        return NULL;
    }
    struct frame* new_frame = (struct frame*)malloc(sizeof (struct frame));
    if (new_frame == NULL) {
        palloc_free_page(frame_addr);
        return NULL;
    }
    new_frame->kpage_ = frame_addr;
    list_init(&(new_frame->refs_));
    // add it to using frame list for evictioin
    list_push_front(&using_frames_list, &new_frame->l_elem_);
    return new_frame;
}


/* N-th Chance of Clock Algorithm(NCoCA):
    1. Clean page: N = 1; Dirty page: N = 2;
    2. algorithm: 
        OS sweeps from the start and checks accessed bit(A) and dirty bit(D):
        1. A is 1: clear the counter and accessed bit;
        2. A is 0: add the counter by 1, and if
            1. D is 0, evict the frame;
            2. D is 1 and counter equals 2, evict the frame and write the frame back to swap block;*/

// evict an using frame with N-th Chance Algorithm, whhere N = 1 for read-only file, N = 2 for Dirty page
static struct frame* evict() {
    struct frame* evicted_frame = NULL;
    // get an evicted frame

    while (!list_empty(&using_frames_list)) {
        struct list_elem* e = NULL;
        for (e = list_begin(&using_frames_list); e != list_end(&using_frames_list); e = list_next(e)) {
            struct frame* f = list_entry(e, struct frame, l_elem_);
            if (f->pin_cnt_ <= 0) {
                struct list_elem* ee = NULL;
                for (ee = list_begin(&f->refs_); ee != list_end(&f->refs_); ee = list_next(ee)) {
                    struct page_ref* ref = list_entry(ee, struct page_ref, l_elem_);
                    struct process* pcb = ref->pcb_;
                    struct spt_entry* spte = ref->spte_;
                    const void* upage = spte_get_virtual_addr(spte);
                    if (pagedir_is_accessed(pcb->pagedir, upage)) {
                        // if accessed flag is set, clear the accessed flag and N-th counter of the frame
                        pagedir_set_accessed(pcb->pagedir, upage, false);
                        f->evict_cnt_ = 0;
                    }
                    else {
                        // if accessed flag is clearing, add the N-th counter of the frame
                        ++f->evict_cnt_;
                        // check and evict if necessary
                        if (!pagedir_is_dirty(pcb->pagedir, upage) || (f->evict_cnt_ >= 2)) {
                            evicted_frame = f;
                            break;
                        }
                    }
                }
                if (evicted_frame) {
                    break;
                }
            }
        }
        // finish the loop when get an evicted frame
        if (evicted_frame) {
            break;
        }
    }

    return evicted_frame;
}

// return true if adding a new ref to a sharing frame successes
static bool add_ref_to_sharing_frame(struct page_ref* cur_ref) {
    bool success = false;
    struct process* pcb = cur_ref->pcb_;

    // a sharing page should be file page and ready-only
    struct spt_entry* spte = cur_ref->spte_;
    if (spte_is_writable(spte)) return false;
    struct file* file = spte_get_file(spte);
    if (file == NULL) return false;

    off_t offset = spte_get_offset(spte);
    struct sharing_info* info = get_sharing(file, offset);
    if (info) {
        uint32_t upage = spte_get_virtual_addr(spte);
        // add a new page reference to the frame's ref list
        pagedir_set_page(pcb->pagedir, upage, info->frame_->kpage_, false);
        list_push_front(&info->frame_->refs_, &cur_ref->l_elem_);
        success = true;
    }

    return success;
}

// initialize a frame according to the page reference
static bool initialize_frame(struct frame* frame, struct page_ref* cur_ref) {
    struct process* pcb = cur_ref->pcb_;
    struct spt_entry* spte = cur_ref->spte_;
    bool is_dirty = false;

    // update page's PTE
    uint8_t* upage = spte_get_virtual_addr(spte);
    bool is_writable = spte_is_writable(spte);
    bool success = pagedir_set_page(pcb->pagedir, upage, frame->kpage_, is_writable);
    if (!success) {
        return false;
        // PANIC("pagedir_set_page() failed!\n");
    }
    pagedir_set_dirty(pcb->pagedir, upage, is_dirty);
    // update frame's reversing mapping
    list_push_front(&frame->refs_, &cur_ref->l_elem_);

    // if the page is swap type, read data from swap slot and update page's SPTE
    block_slot_t swap_slot_idx = spte_get_swap_index(spte);
    if (swap_slot_idx != INVALID_SWAP_SLOT_IDX) {
        void* upage = spte_get_virtual_addr(spte);
        // wait until the data has been in swap slots
        spte_swap_sema_down(spte);
        read_data_from_swap(frame->kpage_, swap_slot_idx);
        spte_set_swap_index(spte, INVALID_SWAP_SLOT_IDX);
        is_dirty = true;
    }
    else {
        // if the page is file type, read data from file block
        struct file* file = spte_get_file(spte);
        if (file) {
            size_t size = spte_get_size(spte);
            off_t offset = spte_get_offset(spte);
            if (size > 0) {
                off_t read_bytes = file_read_at(file, frame->kpage_, size, offset);
                if (read_bytes != size) {
                    return false;
                }
            }
            memset(frame->kpage_ + size, 0, PGSIZE - size);
        }
    }

    return true;
}

// return true if a free frame is allocated
static bool create_a_new_frame(struct page_ref* cur_ref) {
    bool success = false;
    struct spt_entry* spte = cur_ref->spte_;
    struct file* file = spte_get_file(spte);
    bool is_writable = spte_is_writable(spte);
    struct frame* new_frame = get_frame_from_user_pool(); 
    if (new_frame) {
        success = initialize_frame(new_frame, cur_ref);
        // if page is read-only file page, add it to sharing structure
        if (success && !is_writable && file) {
            off_t offset = spte_get_offset(spte);
            add_sharing_frame(file, offset, new_frame);
        }
    }
    return success;
}

// store data of dirty frame into swap or remove the frame from sharing structure if it's sharing 
static void clean_up_evicted_frame(struct frame* frame) {
    struct list_elem* e = list_front(&frame->refs_);
    struct page_ref* ref = list_entry(e, struct page_ref, l_elem_);
    uint8_t* upage = spte_get_virtual_addr(ref->spte_);
    // if the evicted frame is dirty, write it to swap and update swap idx to its original page reference
    if (pagedir_is_dirty(ref->pcb_->pagedir, upage)) {
        block_slot_t swap_slot_idx = write_data_to_swap(frame->kpage_);
        spte_set_swap_index(ref->spte_, swap_slot_idx);
        // signal that the dirty page data has been written into swap slot
        spte_swap_sema_up(ref->spte_);
    }
    // if the evicted frame is sharing, remove it from sharing structure
    struct file* file = spte_get_file(ref->spte_);
    if (file) {
        off_t offset = spte_get_offset(ref->spte_);
        struct sharing_info* info = get_sharing(file, offset);
        if (info) {
            remove_sharing_frame(file, offset);
        }
    }

    e = NULL;
    // release evicted frame's reverse mapping
    for (e = list_begin(&frame->refs_); e != list_end(&frame->refs_); e = list_next(e)) {
        struct page_ref* cur_ref = list_entry(e, struct page_ref, l_elem_);
        uint8_t* cur_ref_upage = spte_get_virtual_addr(cur_ref->spte_);
        pagedir_clear_page(ref->pcb_->pagedir, cur_ref_upage);
    }

    e = NULL;
    // destroy evicted frame's reverse mappings
    while (!list_empty(&frame->refs_)) {
        e = list_pop_front(&frame->refs_);
        struct page_ref* cur_ref = list_entry(e, struct page_ref, l_elem_);
        free(cur_ref);
    }
}

// return true if an using frame is available
static bool reusing_frame(struct page_ref* cur_ref) {
    bool success = false;
    struct process* pcb = cur_ref->pcb_;
    struct spe_entry* spte = cur_ref->spte_;
    struct file* file = spte_get_file(spte);
    bool is_writable = spte_is_writable(spte);
    // evict a using frame
    struct frame* evicted_frame = evict();
    if (evicted_frame) {
        clean_up_evicted_frame(evicted_frame);
        // initialize the frame with new page's SPTE
        success = initialize_frame(evicted_frame, cur_ref);
        if (!success) {
            return false;
        }
        // if page is read-only file page, add it to sharing structure
        if (!is_writable && file) {
            off_t offset = spte_get_offset(spte);
            add_sharing_frame(file, offset, evicted_frame);
        }
        success = true;
    }
    return success;
}

/* return true if allocation of a frame successes */
bool allocate_frame(struct process* pcb, struct spt_entry* spte) {

    struct page_ref* cur_ref = (struct page_ref*)malloc(sizeof(struct page_ref));
    if (cur_ref == NULL) {
        return false;
    }
    cur_ref->pcb_ = pcb;
    cur_ref->spte_ = spte;

    bool allocated_success = false;

    lock_paging();

    // 1. if the page is sharing, get sharing frame from sharing_files_hash, add a new page reference to the frame’s ref list, 
    allocated_success = add_ref_to_sharing_frame(cur_ref);

    // 2. if user pool is not emtpy, get a free frame from the pool;
    if (!allocated_success) {
        allocated_success = create_a_new_frame(cur_ref);
    }
    // 3. else evict a frame from `using_frames_list` by using NCoCA;
    //      a. if the evicted frame is dirty, write it into swap;
    //      b. update original page references of the frame with `pagedir_clear_page()`;
    if (!allocated_success) {
        allocated_success = reusing_frame(cur_ref);
    }

    unlock_paging();

    if (!allocated_success) {
        free(cur_ref);
    }

    return allocated_success;
}


// return pointer to struct frame we want else NULL 
static struct frame* search_frame_referred_by(struct process* pcb, struct spt_entry* spte) {
    struct list_elem* e = NULL;
    struct frame* frame = NULL;
    for (e = list_begin(&using_frames_list); e != list_end(&using_frames_list); e = list_next(e)) {
        frame = list_entry(e, struct frame, l_elem_);
        struct list_elem* ee = NULL;
        for (ee = list_begin(&frame->refs_); ee != list_end(&frame->refs_); ee = list_next(ee)) {
            struct page_ref* ref = list_entry(ee, struct page_ref, l_elem_);
            if (ref->pcb_ == pcb && ref->spte_ == spte) {
                break;
            }
        }
        if (ee == list_end(&frame->refs_)) {
            frame = NULL;
        }
        if (frame != NULL) {
            break;
        }
    }
    return frame;
}

/* free the frame allocated to page pointed by SPTE in process PCB */
void deallocate_frame(struct process* pcb, struct spt_entry* spte) {
    lock_paging();
    struct frame* frame = search_frame_referred_by(pcb, spte);
    if (frame != NULL) {
        // remove reference from frame reference list
        struct list_elem* e = NULL;
        for (e = list_begin(&frame->refs_); e != list_end(&frame->refs_); e = list_next(e)) {
            struct page_ref* ref = list_entry(e, struct page_ref, l_elem_);
            if (ref->pcb_ == pcb && ref->spte_ == spte) {
                list_remove(e);
                free(ref);
                break;
            }
        }
        // if the frame is not referred, free the frame into user pool
        if (list_empty(&frame->refs_)) {
            // if the frame is sharing, remove it from sharing structure
            struct file* file = spte_get_file(spte);
            off_t offset = spte_get_offset(spte);
            remove_sharing_frame(file, offset);

            // free frame
            list_remove(&frame->l_elem_);
            palloc_free_page(frame->kpage_);
            free(frame);
        }
    }
    unlock_paging();
}

// return true if frame F is pinned 
bool pin_frame(struct process* pcb, struct spt_entry* spte) {
    bool success = false;
    lock_paging();
    struct frame* frame = search_frame_referred_by(pcb, spte);
    if (frame) {
        ++frame->pin_cnt_;
        success = true;
    }
    unlock_paging();
    return success;
}

// unpin frame F
void unpin_frame(struct process* pcb, struct spt_entry* spte) {
    lock_paging();
    struct frame* frame = search_frame_referred_by(pcb, spte);
    if (frame) {
        --frame->pin_cnt_;
    }
    unlock_paging();
}