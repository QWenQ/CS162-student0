#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "cache.h"
#include "threads/synch.h"

/* before Project 4: File Systems, file code should be accessed by at most one thread */
// ensure that only one thread at a time is executing file system code
static struct lock lock_on_filesys;
static void file_system_lock_init();
static void lock_on_file_system();
static void unlock_on_file_system();

static void file_system_lock_init() {
  lock_init(&lock_on_filesys);
}

static void lock_on_file_system() {
  if (!lock_held_by_current_thread(&lock_on_filesys)) {
    lock_acquire(&lock_on_filesys);
  }
}

static void unlock_on_file_system() {
  if (lock_held_by_current_thread(&lock_on_filesys)) {
    lock_release(&lock_on_filesys);
  }
}




/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {

  // file system global lock initialization
  file_system_lock_init();

  // initialize buffer cache
  buffer_cache_init();

  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { 
  // close buffer cache 
  flush_all_caches();
  buffer_cache_destroy();

  free_map_close(); 
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  lock_on_file_system();
  block_sector_t inode_sector = 0;
  struct dir* dir = dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);
  unlock_on_file_system();

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  lock_on_file_system();
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  struct file* file_opened = file_open(inode);
  unlock_on_file_system();
  return file_opened;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  lock_on_file_system();
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);
  unlock_on_file_system();

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
