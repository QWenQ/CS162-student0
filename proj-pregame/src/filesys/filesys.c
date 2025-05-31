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
#include "threads/thread.h"
#include "userprog/process.h"


/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

static int get_next_part(char part[NAME_MAX + 1], const char** srcp);

static struct file* open_file_from_dir(struct dir* dir, const char* name);

static struct dir* open_dir_from_dir(struct dir* dir, const char* name);

static struct dir* open_parent_dir(const char* path, char part[NAME_MAX + 1]);

static struct file* open_file(const char* file_name);

static struct dir* open_directory(const char* dir_name);


/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* open a file with given NAME from directory DIR
   and return a pointer to STRUCT FILE if one exists, NULL otherwise.*/
static struct file* open_file_from_dir(struct dir* dir, const char* name) {
  struct inode* inode = NULL;
  // get file from DIR
  bool success = dir_get_file(dir, name, &inode);
  if (!success) {
    return NULL;
  }
  struct file* file = file_open(inode);
  return file;
}

/* open a directory with given NAME from directory DIR
   and return a pointer to STRUCT DIR if one exists, NULL otherwise.*/
static struct dir* open_dir_from_dir(struct dir* dir, const char* name) {
  struct inode* inode = NULL;
  bool success = dir_get_subdir(dir, name, &inode);
  if (!success) {
    return NULL;
  }
  struct dir* dir_opened = dir_open(inode);
  return dir_opened;
}


/* open file's parent directory with given PATH
   and return a pointer to the file's parent if the parent directory exists or a NULL pointer.
   the independent file/directory name will be stored in PART. */
static struct dir* open_parent_dir(const char* path, char part[NAME_MAX + 1]) {
  struct dir* dir = NULL;
  if (path[0] == '/') {
    // absolute: open it from root directory
    dir = dir_open_root();
  }
  else {
    // relative: open it from current working directory
    struct thread* cur_thread = thread_current();
    struct process* pcb = cur_thread->pcb;
    dir = dir_reopen(pcb->pwd_);
  }

  // reutrn NULL if no directory is avaliable
  if (dir == NULL) {
    return NULL;
  }

  char* srcp = path;

  while (true) {
    memset(part, 0, sizeof part);
    int ret = get_next_part(part, &srcp);
    // return if PART is invalid
    // return if FILE_NAME is invalid
    if (ret != 1) {
      dir_close(dir);
      return NULL;
    }
    // break if get the last file/directory name
    if (*srcp == '\0') {
      break;
    }
    struct dir* sub_dir = open_dir_from_dir(dir, part);
    dir_close(dir);
    if (sub_dir == NULL) {
      return NULL;
    }
    dir = sub_dir;
  }
  return dir;
}

/* open a file with given FILE_NAME 
   and return a pointer to STRUCT FILE if one exists, NULL otherwise.*/
static struct file* open_file(const char* file) {
  char part[NAME_MAX + 1];
  struct dir* parent_dir = open_parent_dir(file, part);
  struct file* file_opened = open_file_from_dir(parent_dir, part);
  dir_close(parent_dir);
  return file_opened;
}

/* open a directory with given DIR_NAME
   and return a pointer to STRUCT DIR if one exists, NULL otherwise.*/
static struct dir* open_directory(const char* dir_name) {
  // open root
  if ((dir_name[0] == '/') && (strlen(dir_name) == 1)) {
    return dir_open_root();
  }
  // open from root or pwd of process
  char part[NAME_MAX + 1];
  struct dir* parent_dir = open_parent_dir(dir_name, part);
  struct dir* dir = open_dir_from_dir(parent_dir, part);
  dir_close(parent_dir);
  return dir;
}




/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {

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

  /* the initial process' present working directory should be root */
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  pcb->pwd_ = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { 
  // close buffer cache 
  flush_all_caches();

  free_map_close(); 

  buffer_cache_destroy();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists, or if internal memory allocation fails. 
   IS_FILE is true when an ordinary file is added to the DIR, a directory is added otherwise. */
bool filesys_create(const char* name, off_t initial_size, bool is_file_type) {

  // block_sector_t inode_sector = 0;
  // struct dir* dir = dir_open_root();
  // bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
  //                 inode_create(inode_sector, initial_size) && dir_add(dir, name, inode_sector));
  // if (!success && inode_sector != 0)
  //   free_map_release(inode_sector, 1);
  // dir_close(dir);

  if (strlen(name) == 0) {
    return NULL;
  }
  char part[NAME_MAX + 1];
  struct dir* parent_dir = open_parent_dir(name, part);
  if (parent_dir == NULL) {
    return false;
  }

  struct inode* inode = NULL;
  bool exist = dir_lookup(parent_dir, part, &inode);
  if (exist) {
    dir_close(parent_dir);
    inode_close(inode);
    return false;
  }

  ASSERT(inode == NULL);

  block_sector_t inode_sector = 0;
  bool success = true;
  success = free_map_allocate(1, &inode_sector);
  if (!success) {
    dir_close(parent_dir);
    return false;
  }

  if (is_file_type) {
    success = inode_create(inode_sector, initial_size);
  }
  else {
    struct inode* p_inode = dir_get_inode(parent_dir);
    block_sector_t p_sector = inode_get_inumber(p_inode);
    success = dir_create(inode_sector, 2, p_sector);
  }
  if (!success) {
    free_map_release(inode_sector, 1);
    dir_close(parent_dir);
    return false;
  }
  success = dir_add(parent_dir, part, inode_sector, is_file_type);
  dir_close(parent_dir);
  if (!success) {
    free_map_release(inode_sector, 1);
    return false;
  }
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {

  // struct dir* dir = dir_open_root();
  // struct inode* inode = NULL;

  // if (dir != NULL)
  //   dir_lookup(dir, name, &inode);
  // dir_close(dir);

  // struct file* file_opened = file_open(inode);
  // return file_opened;

  if (strlen(name) == 0) {
    return NULL;
  }
  char part[NAME_MAX + 1];
  struct dir* parent_dir = open_parent_dir(name, part);
  if (parent_dir == NULL) {
    return NULL;
  }
  struct file* file = open_file_from_dir(parent_dir, part);
  dir_close(parent_dir);
  return file;

}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  // struct dir* dir = dir_open_root();
  // bool success = dir != NULL && dir_remove(dir, name);
  // dir_close(dir);

  // return success;

  if (strlen(name) == 0) {
    return NULL;
  }
  char part[NAME_MAX + 1];
  struct dir* parent_dir = open_parent_dir(name, part);
  if (parent_dir == NULL) {
    return false;
  }
  bool success = parent_dir != NULL && dir_remove(parent_dir, part);
  dir_close(parent_dir);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/* Opens the directory with the given NAME.
   Returns the new directory if successful or a null pointer otherwise.
   Fails if no directory named NAME exists, 
   or if an internal memory allocation fails. */
struct dir* filesys_open_dir(const char* name) {
  if (strlen(name) == 0) {
    return NULL;
  }
  struct dir* dir = open_directory(name);
  return dir;
}

/* Opens the ordinary file with the given NAME.
   Returns the new file if successful or a null pointer otherwise.
   Fails if no file named NAME exists, 
   or if an internal memory allocation fails. */
struct file* filesys_open_file(const char* name) {
  if (strlen(name) == 0) {
    return NULL;
  }
  struct file* file = open_file(name);
  return file;
}
