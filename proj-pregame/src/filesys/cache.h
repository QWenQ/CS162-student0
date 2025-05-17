#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"
#include "lib/stdbool.h"

void buffer_cache_init();

void buffer_cache_destroy();

void read_within_buffer_cache(block_sector_t sec_idx, void* buffer, int sector_ofs, size_t data_size, bool read_ahead);

void write_within_buffer_cache(block_sector_t sec_idx, const void* buffer, int sector_ofs, size_t data_size);

void flush_all_caches();

void buffer_cache_flush_countdown();

#endif /* filesys/cache.h*/