#include "cache.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"
#include "lib/debug.h"
#include "filesys.h"
#include "lib/string.h"

#define BUFFER_CACHE_SIZE_LIMIT 64 // maximum capacity of buffer cache
#define INVALID_SECOTR_INDEX 0xffffffff

/* meta info of a cached sector */
struct cached_sector {
  block_sector_t sector_idx_; // index of a cached sector and key in LRU_HASH
  void* cache_addr_; // start address of a sector cache
  int pin_cnt_; // count of user being using the cache block
  bool is_dirty_; // true if cached data is modified
  bool is_initialized_; // true if initializing a newly allocated sector is done
  struct lock lock_; // lock when accessing data members
  struct condition cond_; // wait until the disk data is read into memory
  struct hash_elem h_elem_; // managed by LRU_HASH
  struct list_elem l_elem_; // managed by FREE_LIST or LRU_LIST
}; // struct cached_sector

/* operations on STRUCT CACHED_SECTOR */
static struct cached_sector* create_cached_sector(block_sector_t sec_idx);
static void destroy_cached_sector(struct cached_sector* sec);
static void set_idx_cached_sector(struct cached_sector* sec, block_sector_t idx);
static block_sector_t get_idx_cached_sector(const struct cached_sector* sec);
static void* get_addr_cached_sector(const struct cached_sector* sec);
static void pin_cached_sector(struct cached_sector* sec);
static void unpin_cached_sector(struct cached_sector* sec);
static int get_pin_cnt_cahced_sector(const struct cached_sector* sec);

/* disk IO */
static void flush_back_to_disk_cached_sector(struct cached_sector* sec);


/* fields of buffer cache */
/* lock when accessing the buffer cache */
static struct lock lock_on_buffer_cache;
/* list of unallocated buffer cache sectors */
static struct list free_list;
/* list of allocated buffer cache sectors */
static struct list lru_list;
/* hash table for cached sectors */
static struct hash lru_hash;


/* hash functions */
static unsigned buffer_cache_hash(const struct hash_elem *p_, void *aux UNUSED);
static bool buffer_cache_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);


/* operations on buffer cache */
static void lock_buffer_cache();
static void unlock_buffer_cache();
/* return a pointer to a STRUCT CACHED_SECTOR object with LRU algorithm */
static struct cached_sector* get(block_sector_t sec_idx, block_sector_t* old_sec_idx, bool* free_sec);


/* fields of write-back feature */
#define FLUSH_CYCLE_CLOCKS 1000 // flush the buffer cache every 1000 clocks
/* flush all dirty, cached data when countdown is over */
static int countdown_flush;

static void flush_if_timeout();

/****************************************************implementation***********************************************/

/* operations on STRUCT CACHED_SECTOR */
static struct cached_sector* create_cached_sector(block_sector_t sec_idx) {
    struct cached_sector* sec = (struct cached_sector*)malloc(sizeof (struct cached_sector));
    if (sec == NULL) return NULL;
    sec->cache_addr_ = malloc(BLOCK_SECTOR_SIZE);
    if (sec->cache_addr_ == NULL) {
        free(sec);
        return NULL;
    }
    sec->sector_idx_ = sec_idx;
    sec->pin_cnt_ = 0;
    sec->is_dirty_ = false;
    sec->is_initialized_ = false;
    lock_init(&sec->lock_);
    cond_init(&sec->cond_);
    return sec;
}

static void destroy_cached_sector(struct cached_sector* sec) {
    free(sec->cache_addr_);
    free(sec);
}

static void set_idx_cached_sector(struct cached_sector* sec, block_sector_t sec_idx) {
    lock_acquire(&sec->lock_);
    sec->sector_idx_ = sec_idx;
    lock_release(&sec->lock_);
}

static block_sector_t get_idx_cached_sector(const struct cached_sector* sec) {
    block_sector_t sec_idx = INVALID_SECOTR_INDEX;
    lock_acquire(&sec->lock_);
    sec_idx = sec->sector_idx_;
    lock_release(&sec->lock_);
    return sec_idx;
}

static void* get_addr_cached_sector(const struct cached_sector* sec) {
    void* cache_addr = NULL;
    lock_acquire(&sec->lock_);
    cache_addr = sec->cache_addr_;
    lock_release(&sec->lock_);
    return cache_addr;
}

static void pin_cached_sector(struct cached_sector* sec) {
    lock_acquire(&sec->lock_);
    sec->pin_cnt_++;
    lock_release(&sec->lock_);
}

static void unpin_cached_sector(struct cached_sector* sec) {
    lock_acquire(&sec->lock_);
    sec->pin_cnt_--;
    lock_release(&sec->lock_);
}

static int get_pin_cnt_cahced_sector(const struct cached_sector* sec) {
    int pin_cnt = 0;
    lock_acquire(&sec->lock_);
    pin_cnt = sec->pin_cnt_;
    lock_release(&sec->lock_);
    return pin_cnt;
}

static void flush_back_to_disk_cached_sector(struct cached_sector* sec) {
    bool success = lock_try_acquire(&sec->lock_);
    if (!success) return;
    if (sec->is_dirty_) {
        block_write(fs_device, sec->sector_idx_, sec->cache_addr_);
        sec->is_dirty_ = false;
    }
    lock_release(&sec->lock_);
}

/* hash functions */
static unsigned buffer_cache_hash (const struct hash_elem *p_, void *aux UNUSED) {
    const struct cached_sector* sec = hash_entry(p_, struct cached_sector, h_elem_);
    return hash_int(sec->sector_idx_);
}

static bool buffer_cache_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct cached_sector* sec_a = hash_entry(a_, struct cached_sector, h_elem_);
    const struct cached_sector* sec_b = hash_entry(b_, struct cached_sector, h_elem_);
    return sec_a->sector_idx_ < sec_b->sector_idx_;
}


/* operations on buffer cache */
static void lock_buffer_cache() {
    if (!lock_held_by_current_thread(&lock_on_buffer_cache)) {
        lock_acquire(&lock_on_buffer_cache);
    }
}

static void unlock_buffer_cache() {
    if (lock_held_by_current_thread(&lock_on_buffer_cache)) {
        lock_release(&lock_on_buffer_cache);
    }
}

/* return a pointer to a STRUCT CACHED_SECTOR object with LRU algorithm;
    if the sector is got by eviction, OLD_SEC_IDX should store the original sector index;
    if the sector is allocated first time, FREE_SEC should be set as true */
static struct cached_sector* get(block_sector_t sec_idx, block_sector_t* old_sec_idx, bool* free_sec) {
    struct cached_sector* sec = NULL;
    struct cached_sector key;
    key.sector_idx_ = sec_idx;
    lock_buffer_cache();

    flush_if_timeout();

    struct hash_elem* he = hash_find(&lru_hash, &key.h_elem_);
    if (he) {
        // if sector frame exists in the buffer cache
        sec = hash_entry(he, struct cached_sector, h_elem_);
        list_remove(&sec->l_elem_);
        list_push_front(&lru_list, &sec->l_elem_);
    }
    else {
        if (!list_empty(&free_list)) {
            // allocate a new sector frame from free list
            struct list_elem* le = list_pop_front(&free_list);
            sec = list_entry(le, struct cached_sector, l_elem_);
            set_idx_cached_sector(sec, sec_idx);
            hash_insert(&lru_hash, &sec->h_elem_);
            list_push_front(&lru_list, &sec->l_elem_);
            *free_sec = true;
        }
        else {
            // evict the least-recently-used sector frame from lru list
            struct list_elem* le = NULL;
            for (le = list_rbegin(&lru_list); le != list_rend(&lru_list); le = list_prev(le)) {
                sec = list_entry(le, struct cached_sector, l_elem_);
                int pin_cnt = get_pin_cnt_cahced_sector(sec);
                if (pin_cnt == 0) {
                    break;
                }
                sec = NULL;
            }
            // move evicted sector frame to the head of LRU_LIST and upate its hash info
            if (sec) {
                list_remove(&sec->l_elem_);
                list_push_front(&lru_list, &sec->l_elem_);
                hash_delete(&lru_hash, &sec->h_elem_);
                *old_sec_idx = get_idx_cached_sector(sec);
                block_write(fs_device, *old_sec_idx, sec->cache_addr_);
                set_idx_cached_sector(sec, sec_idx);
                hash_insert(&lru_hash, &sec->h_elem_);
                // old data of evicted sector should be evicted
                sec->is_initialized_ = false;
                sec->is_dirty_ = false;
            }
        }
    }
    // pin the sector frame to avoid to be evicted when being used
    if (sec) {
        pin_cached_sector(sec);
    }
    unlock_buffer_cache();
    return sec;
}

/* periodically write all dirty, cached block sectors back to disk */
static void flush_if_timeout() {
    if (countdown_flush <= 0) {
        struct list_elem* e = NULL;
        for (e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
            struct cached_sector* sec = list_entry(e, struct cached_sector, l_elem_);
            flush_back_to_disk_cached_sector(sec);
        }
    }
    // reset countdown
    countdown_flush = FLUSH_CYCLE_CLOCKS;
}


/* operations for outside work */

/* buffer cache initialization */
void buffer_cache_init() {
    lock_init(&lock_on_buffer_cache);
    list_init(&free_list);
    list_init(&lru_list);
    hash_init(&lru_hash, buffer_cache_hash, buffer_cache_less, NULL);
    for (int i = 0; i < BUFFER_CACHE_SIZE_LIMIT; ++i) {
        struct cached_sector* sec = create_cached_sector(INVALID_SECOTR_INDEX);
        list_push_front(&free_list, &sec->l_elem_);
    }
    countdown_flush = FLUSH_CYCLE_CLOCKS; 
}

/* release all resources allocated to buffer cache */
void buffer_cache_destroy() {
    while (!list_empty(&free_list)) {
        struct list_elem* e = list_pop_front(&free_list);
        struct cached_sector* sec = list_entry(e, struct cached_sector, l_elem_);
        destroy_cached_sector(sec);
    }

    while (!list_empty(&lru_list)) {
        struct list_elem* e = list_pop_front(&lru_list);
        struct cached_sector* sec = list_entry(e, struct cached_sector, l_elem_);
        destroy_cached_sector(sec);
    }
    hash_destroy(&lru_hash, NULL);
}

/* read data from sector SEC_IDX into BUFFER, 
    if READ_AHEAD is true, execute read-ahead feature if necessary */
void read_within_buffer_cache(block_sector_t sec_idx, void* buffer, int sector_ofs, size_t data_size, bool read_ahead) {
    // get the existing cache sector or allocate a new cache sector from buffer cache 
    block_sector_t old_sec_idx = INVALID_SECOTR_INDEX;
    bool free_sec = false;
    struct cached_sector* sec = get(sec_idx, &old_sec_idx, &free_sec);

    // the thread the first one executes I/O on the current cache sector
    if (free_sec || old_sec_idx != INVALID_SECOTR_INDEX) {
        lock_acquire(&sec->lock_);
        // write dirty data back to disk and reset dirty flag of cache sector allocated
        // if (sec->is_dirty_) {
        //     block_write(fs_device, old_sec_idx, sec->cache_addr_);
        //     sec->is_dirty_ = false;
        // }
        memset(sec->cache_addr_, 0, BLOCK_SECTOR_SIZE);
        // read data wanted into cache buffer
        block_read(fs_device, sec->sector_idx_, sec->cache_addr_);

        // write data in the buffer cache into BUFFER if BUFFER is not NULL,
        // which means the read operation is not read-ahead
        if (buffer) {
            memcpy(buffer, sec->cache_addr_ + sector_ofs, data_size);
        }

        // wake up threads blocked for the sector initialization
        // lock_acquire(&sec->lock_);
        sec->is_initialized_ = true;
        cond_broadcast(&sec->cond_, &sec->lock_);
        lock_release(&sec->lock_);
    }
    else {
        if (buffer) {
            // read-ahead: it sector is in the buffer cache, read its adjacent sector into buffer cache if necessary
            if (read_ahead) {
                read_within_buffer_cache(sec_idx + 1, NULL, 0, BLOCK_SECTOR_SIZE, !read_ahead);
            }

            // read the sector data into the buffer
            lock_acquire(&sec->lock_);
            while (!sec->is_initialized_) {
                cond_wait(&sec->cond_, &sec->lock_);
            }
            memcpy(buffer, sec->cache_addr_ + sector_ofs, data_size);
            lock_release(&sec->lock_);
        }
    }

    unpin_cached_sector(sec);
}

/* write data in BUFFER into sector SEC_IDX */
void write_within_buffer_cache(block_sector_t sec_idx, const void* buffer, int sector_ofs, size_t data_size) {
    // get the existing cache sector or allocate a new cache sector from buffer cache 
    block_sector_t old_sec_idx = INVALID_SECOTR_INDEX;
    bool free_sec = false;
    struct cached_sector* sec = get(sec_idx, &old_sec_idx, &free_sec);

    // the thread the first one executes I/O on the current cache sector
    if (free_sec || old_sec_idx != INVALID_SECOTR_INDEX) {
        lock_acquire(&sec->lock_);
        // write dirty data back to disk and reset dirty flag of cache sector allocated
        // if (sec->is_dirty_) {
        //     block_write(fs_device, old_sec_idx, sec->cache_addr_);
        //     sec->is_dirty_ = false;
        // }
        memset(sec->cache_addr_, 0, BLOCK_SECTOR_SIZE);
        /* If the sector contains data before or after the chunk
                we're writing, then we need to read in the sector
                first.  Otherwise we start with a sector of all zeros. */
        if (data_size < BLOCK_SECTOR_SIZE) {
            block_read(fs_device, sec->sector_idx_, sec->cache_addr_);
        }

        memcpy(sec->cache_addr_ + sector_ofs, buffer, data_size);
        sec->is_dirty_ = true;

        // wake up threads blocked for the sector initialization
        // lock_acquire(&sec->lock_);
        sec->is_initialized_ = true;
        cond_broadcast(&sec->cond_, &sec->lock_);
        lock_release(&sec->lock_);
    }
    else {
        lock_acquire(&sec->lock_);
        while (!sec->is_initialized_) {
            cond_wait(&sec->cond_, &sec->lock_);
        }
        // write the buffer data into cache sector
        memcpy(sec->cache_addr_ + sector_ofs, buffer, data_size);
        sec->is_dirty_ = true;
        lock_release(&sec->lock_);
    }

    unpin_cached_sector(sec);
}

/* flush all dirty caches back to disk when filesys_done() is called */
void flush_all_caches() {
    // there is no concurrency when flush_all_caches() is called
    struct list_elem* e = NULL;
    for (e = list_begin(&lru_list); e != list_end(&lru_list); e = list_next(e)) {
        struct cached_sector* sec = list_entry(e, struct cached_sector, l_elem_);
        if (sec->is_dirty_) {
            block_write(fs_device, sec->sector_idx_, sec->cache_addr_);
        }
    }
}

/* decrease countdown of buffer cache by one */
void buffer_cache_flush_countdown() {
    --countdown_flush;
}

