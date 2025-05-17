#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

/* before Project 4: in free map module, free map code should be accessed by at most one thread */
// ensure that only at most one thread at a time is accessing free map code
static struct lock lock_on_free_map;
static void free_map_lock_init();
static void lock_free_map();
static void unlock_free_map();

static void free_map_lock_init() {
  lock_init(&lock_on_free_map);
}

static void lock_free_map() {
  if (!lock_held_by_current_thread(&lock_on_free_map)) {
    lock_acquire(&lock_on_free_map);
  }
}

static void unlock_free_map() {
  if (lock_held_by_current_thread(&lock_on_free_map)) {
    lock_release(&lock_on_free_map);
  }
}

static struct file* free_map_file; /* Free map file. */
static struct bitmap* free_map;    /* Free map, one bit per sector. */

/* Initializes the free map. */
void free_map_init(void) {
  free_map_lock_init();
  free_map = bitmap_create(block_size(fs_device));
  if (free_map == NULL)
    PANIC("bitmap creation failed--file system device is too large");
  bitmap_mark(free_map, FREE_MAP_SECTOR);
  bitmap_mark(free_map, ROOT_DIR_SECTOR);
}

/* Allocates CNT consecutive sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if not enough consecutive
   sectors were available or if the free_map file could not be
   written. */
bool free_map_allocate(size_t cnt, block_sector_t* sectorp) {
  lock_free_map();
  block_sector_t sector = bitmap_scan_and_flip(free_map, 0, cnt, false);
  if (sector != BITMAP_ERROR && free_map_file != NULL && !bitmap_write(free_map, free_map_file)) {
    bitmap_set_multiple(free_map, sector, cnt, false);
    sector = BITMAP_ERROR;
  }
  if (sector != BITMAP_ERROR)
    *sectorp = sector;
  unlock_free_map();
  return sector != BITMAP_ERROR;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void free_map_release(block_sector_t sector, size_t cnt) {
  lock_free_map();
  ASSERT(bitmap_all(free_map, sector, cnt));
  bitmap_set_multiple(free_map, sector, cnt, false);
  bitmap_write(free_map, free_map_file);
  unlock_free_map();
}

/* Opens the free map file and reads it from disk. */
void free_map_open(void) {
  lock_free_map();
  free_map_file = file_open(inode_open(FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC("can't open free map");
  if (!bitmap_read(free_map, free_map_file))
    PANIC("can't read free map");
  unlock_free_map();
}

/* Writes the free map to disk and closes the free map file. */
void free_map_close(void) { 
  lock_free_map();
  file_close(free_map_file); 
  unlock_free_map();
}

/* Creates a new free map file on disk and writes the free map to
   it. */
void free_map_create(void) {
  lock_free_map();
  /* Create inode. */
  if (!inode_create(FREE_MAP_SECTOR, bitmap_file_size(free_map)))
    PANIC("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open(inode_open(FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC("can't open free map");
  if (!bitmap_write(free_map, free_map_file))
    PANIC("can't write free map");
  unlock_free_map();
}
