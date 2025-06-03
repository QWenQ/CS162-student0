#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

// /* On-disk inode.
//    Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// struct inode_disk {
//   block_sector_t start; /* First data sector. */
//   off_t length;         /* File size in bytes. */
//   unsigned magic;       /* Magic number. */
//   uint32_t unused[125]; /* Not used. */
// };

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct_[12]; /* Direct pointers */
  block_sector_t indirect_; /* Indirect pointer */
  block_sector_t double_indirect_; /* Double Indirect pointer */
  off_t length_; /* File size in bytes. */

  /* field for directory */
  size_t entry_cnt_; /* number of files in the directory */

  unsigned magic_;       /* Magic number. */
  uint32_t unused[111]; /* Not used. */
};


/* FFS-like inode functions */

static bool inode_resize(struct inode_disk* id, off_t size);


/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk* data_; /* pointer to Inode content. */

  /* new fields added in Project 4 File System */
  struct lock inode_lock_; /* lock before accessing inode fields */
  bool is_being_extended_; /* true when the file is being extended */
  struct condition disk_cond_; /* broadcast when extending file is done */
};


static void lock_on_inode(struct inode* id);
static void unlock_on_inode(struct inode* id);

void lock_on_inode(struct inode* id) {
  ASSERT(id != NULL);
  if (!lock_held_by_current_thread(&id->inode_lock_)) {
    lock_acquire(&id->inode_lock_);
  }
}

void unlock_on_inode(struct inode* id) {
  ASSERT(id != NULL);
  if (lock_held_by_current_thread(&id->inode_lock_)) {
    lock_release(&id->inode_lock_);
  }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  
  if (pos < inode->data_->length_) {
    block_sector_t idx = pos / BLOCK_SECTOR_SIZE;
    if (idx < 12) {
      return inode->data_->direct_[idx];
    }
    else if (idx < 140) {
      idx -= 12;
      block_sector_t buffer[128];
      read_within_buffer_cache(inode->data_->indirect_, buffer, 0, BLOCK_SECTOR_SIZE, false);
      return buffer[idx];
    }
    else {
      idx -= 140;
      block_sector_t indirects[128];
      read_within_buffer_cache(inode->data_->double_indirect_, indirects, 0, BLOCK_SECTOR_SIZE, false);
      block_sector_t indirect_idx = idx / (BLOCK_SECTOR_SIZE / sizeof(block_sector_t));
      block_sector_t directs[128];
      read_within_buffer_cache(indirects[indirect_idx], directs, 0, BLOCK_SECTOR_SIZE, false);
      return directs[idx % (BLOCK_SECTOR_SIZE / sizeof(block_sector_t))];
    }
  }
  else {
    return -1;
  }
}

static struct lock lock_on_open_inodes_list;

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { 
  lock_init(&lock_on_open_inodes_list);
  list_init(&open_inodes); 
}

// initalized file owned by DISK_INODE with LENGTH 0 bytes
static void inode_sector_init(struct inode_disk* disk_inode, off_t length) {

  // initialize memory with zeros
  static char zeros[BLOCK_SECTOR_SIZE];
  // direct
  if (length > 0) {
    for (int i = 0; i < 12; ++i) {
      if (disk_inode->direct_[i] == 0) {
        break;
      }
      size_t sec_len = BLOCK_SECTOR_SIZE;
      if (length < BLOCK_SECTOR_SIZE) {
        sec_len = length;
      }
      write_within_buffer_cache(disk_inode->direct_[i], zeros, 0, sec_len);
      length -= sec_len;
    }
  }
  // indirect
  if (length > 0) {
    block_sector_t directs[128];
    read_within_buffer_cache(disk_inode->indirect_, directs, 0, BLOCK_SECTOR_SIZE, false);
    for (int i = 0; i < 128; ++i) {
      if (directs[i] == 0) {
        break;
      }
      size_t sec_len = BLOCK_SECTOR_SIZE;
      if (length < BLOCK_SECTOR_SIZE) {
        sec_len = length;
      }
      write_within_buffer_cache(directs[i], zeros, 0, sec_len);
      length -= sec_len;
    }
  }
  // double indirect
  if (length > 0) {
    block_sector_t indirects[128];
    read_within_buffer_cache(disk_inode->double_indirect_, indirects, 0, BLOCK_SECTOR_SIZE, false);
    for (int i = 0; i < 128; ++i) {
      if (indirects[i] == 0) {
        break;
      }
      block_sector_t directs[128];
      read_within_buffer_cache(indirects[i], directs, 0, BLOCK_SECTOR_SIZE, false);
      for (int j = 0; j < 128; ++j) {
        if (directs[j] == 0) {
          break;
        }
        size_t sec_len = BLOCK_SECTOR_SIZE;
        if (length < BLOCK_SECTOR_SIZE) {
          sec_len = length;
        }
        write_within_buffer_cache(directs[j], zeros, 0, sec_len);
        length -= sec_len;
      } 
    }
  }

  // initialized block area should be LENGTH size
  ASSERT(length == 0);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails.*/
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);

  if (disk_inode != NULL) {
    if (sector != 0) {
      // initialize ordinary files disk info
      success = inode_resize(disk_inode, length);
      ASSERT(success);
      ASSERT(disk_inode->length_ == length);
      inode_sector_init(disk_inode, length);
      disk_inode->magic_ = INODE_MAGIC;
      write_within_buffer_cache(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      success = true;
    }
    else {
      // initialize free map file disk info 
      size_t sectors = bytes_to_sectors(length);
      disk_inode->length_ = length;
      disk_inode->magic_ = INODE_MAGIC;
      if (free_map_allocate(sectors, &disk_inode->direct_[0])) {
        static char zeros[BLOCK_SECTOR_SIZE];
        write_within_buffer_cache(disk_inode->direct_[0], zeros, 0, BLOCK_SECTOR_SIZE);
        write_within_buffer_cache(sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
        success = true;
      }
    }


    free(disk_inode);
    disk_inode = NULL;
  }

  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e = NULL;
  struct inode* inode = NULL;

  lock_acquire(&lock_on_open_inodes_list);
  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      break;
    }
    inode = NULL;
  }
  if (inode) {
    lock_release(&lock_on_open_inodes_list);
    return inode;
  }
  
  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL) {
    lock_release(&lock_on_open_inodes_list);
    return NULL;
  }

  inode->data_ = (struct inode_disk*)calloc(1, sizeof (struct inode_disk));
  if (inode->data_ == NULL) {
    free(inode);
    inode = NULL;
  }
  else {
    /* if inode is effective, inode should lock before unlock openned inodes list */
    lock_init(&inode->inode_lock_);
    lock_on_inode(inode);
    list_push_front(&open_inodes, &inode->elem);
  }
  lock_release(&lock_on_open_inodes_list);

  /* Initialize. */
  if (inode) {
    inode->sector = sector;
    inode->open_cnt = 1;
    inode->deny_write_cnt = 0;
    inode->removed = false;
    inode->is_being_extended_ = false;
    cond_init(&(inode->disk_cond_));
    read_within_buffer_cache(inode->sector, inode->data_, 0, BLOCK_SECTOR_SIZE, false);
    unlock_on_inode(inode);
  }

  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  struct inode* ret = inode;
  if (inode != NULL) {
    lock_on_inode(inode);
    if (inode->removed) {
      ret = NULL;
    }
    else {
      inode->open_cnt++;
    }
    unlock_on_inode(inode);
  }
  return ret;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { 
  block_sector_t inumber = 0;
  lock_on_inode(inode);
  inumber = inode->sector;
  unlock_on_inode(inode);
  return inumber;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  
  bool close = false;
  // get lock of open inodes list in avoid of openning the inode on close happenning 
  lock_acquire(&lock_on_open_inodes_list);
  lock_on_inode(inode);
  --inode->open_cnt;
  if (inode->open_cnt == 0) {
    close = true;
  }
  unlock_on_inode(inode);

  // nothing happens
  if (!close) {
    lock_release(&lock_on_open_inodes_list);
    return;
  }

  /* Release resources if this was the last opener. */

  /* Remove from inode list. */
  list_remove(&inode->elem);
  lock_release(&lock_on_open_inodes_list);

  /* Deallocate blocks if removed. */
  if (inode->removed) {
    free_map_release(inode->sector, 1);
    bool success = inode_resize(inode->data_, 0);
    ASSERT(success);
  }
  else {
    // write disk inode info back to disk
    write_within_buffer_cache(inode->sector, inode->data_, 0, sizeof *inode->data_);
  }

  free(inode->data_);
  inode->data_ = NULL;
  free(inode);
  inode = NULL;
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_on_inode(inode);
  inode->removed = true;
  unlock_on_inode(inode);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  lock_on_inode(inode);
  while (inode->sector != FREE_MAP_SECTOR && inode->is_being_extended_) {
    cond_wait(&inode->disk_cond_, &inode->inode_lock_);
  }
  // recalculate read size in avoid of out-of-bounds behavior
  if (inode->data_->length_ < offset + size) {
    size = inode->data_->length_ - offset;
  }
  unlock_on_inode(inode);


  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;

    if (chunk_size <= 0)
      break;

    bool read_ahead = size > chunk_size;
    read_within_buffer_cache(sector_idx, buffer + bytes_read, sector_ofs, chunk_size, read_ahead);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;
  
  lock_on_inode(inode);
  while (inode->sector != FREE_MAP_SECTOR && inode->is_being_extended_) {
    cond_wait(&inode->disk_cond_, &inode->inode_lock_);
  }
  // extend the file if write will be past EOF of the file
  bool resize_done = true;
  if (offset + size > inode->data_->length_) {
    inode->is_being_extended_ = true;
    resize_done = inode_resize(inode->data_, offset + size);
    ASSERT(resize_done);
  }
  if (!resize_done) {
    inode->is_being_extended_ = false;
  }
  unlock_on_inode(inode);
  if (!resize_done) {
    return 0;
  }
  
  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
    //   /* Write full sector directly to disk. */
    //   block_write(fs_device, sector_idx, buffer + bytes_written);

    // } else {
    //   /* We need a bounce buffer. */
    //   if (bounce == NULL) {
    //     bounce = malloc(BLOCK_SECTOR_SIZE);
    //     if (bounce == NULL)
    //       break;
    //   }
    //   /* If the sector contains data before or after the chunk
    //          we're writing, then we need to read in the sector
    //          first.  Otherwise we start with a sector of all zeros. */
    //   if (sector_ofs > 0 || chunk_size < sector_left)
    //     block_read(fs_device, sector_idx, bounce);
    //   else
    //     memset(bounce, 0, BLOCK_SECTOR_SIZE);
    //   memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
    //   block_write(fs_device, sector_idx, bounce);
    // }


    write_within_buffer_cache(sector_idx, buffer + bytes_written, sector_ofs, chunk_size); 

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }


  lock_on_inode(inode);

  if (inode->is_being_extended_) {
    inode->is_being_extended_ = false;
    cond_broadcast(&inode->disk_cond_, &inode->inode_lock_);
  }
  unlock_on_inode(inode);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_on_inode(inode);
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  unlock_on_inode(inode);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_on_inode(inode);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  unlock_on_inode(inode);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { 
  off_t length = 0;
  lock_on_inode(inode);
  length = inode->data_->length_;
  unlock_on_inode(inode);
  return length;
}

/* grow or shrink the inode ID based on the given SIZE */
static bool inode_resize(struct inode_disk* id, off_t size) {
    /* Handle direct pointers. */
    for (int i = 0; i < 12; i++) {
        if (size <= BLOCK_SECTOR_SIZE * i && id->direct_[i] != 0) {
            /* Shrink. */
            free_map_release(id->direct_[i], 1);
            id->direct_[i] = 0;
        } else if (size > BLOCK_SECTOR_SIZE * i && id->direct_[i] == 0) {
            /* Grow. */
            bool success = free_map_allocate(1, &id->direct_[i]);
            // handle sector allocation failures
            if (!success) {
                inode_resize(id, id->length_);
                return false;
            }
        }
    }

    /* Check if indirect pointers are needed. */
    if (id->indirect_ == 0 && size <= 12 * BLOCK_SECTOR_SIZE) {
        id->length_ = size;
        return true;
    }

    block_sector_t buffer[128];
    memset(buffer, 0, 512);
    if (id->indirect_ == 0) {
        /* Allocate indirect block. */
        bool success = free_map_allocate(1, &id->indirect_);
        // handle sector allocation failures
        if (!success) {
            inode_resize(id, id->length_);
            return false;
        }
    } else {
        /* Read in indirect block. */
        read_within_buffer_cache(id->indirect_, buffer, 0, BLOCK_SECTOR_SIZE, false);
    }

    /* Handle indirect pointers. */
    for (int i = 0; i < 128; i++) {
        if (size <= (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] != 0) {
            /* Shrink. */
            free_map_release(buffer[i], 1);
            buffer[i] = 0;
        } else if (size > (12 + i) * BLOCK_SECTOR_SIZE && buffer[i] == 0) {
            /* Grow. */
            bool success = free_map_allocate(1, &buffer[i]);
            // handle sector allocation failures
            if (!success) {
                inode_resize(id, id->length_);
                return false;
            }
        }
    }

    if (size <= 12 * BLOCK_SECTOR_SIZE) {
        /* We shrank the inode such that indirect pointers are not required. */
        free_map_release(id->indirect_, 1);
        id->indirect_ = 0;
    } else {
        /* Write the updates to the indirect block back to disk. */
        write_within_buffer_cache(id->indirect_, buffer, 0, BLOCK_SECTOR_SIZE);
    }


    /* Check if double indirect pointers are needed. */
    if (id->double_indirect_ == 0 && size <= 140 * BLOCK_SECTOR_SIZE) {
        id->length_ = size;
        return true;
    }

    memset(buffer, 0, 512);
    if (id->double_indirect_ == 0) {
        /* Allocate indirect block. */
        bool success = free_map_allocate(1, &id->double_indirect_);
        // handle sector allocation failures
        if (!success) {
            inode_resize(id, id->length_);
            return false;
        }
    } else {
        /* Read in double indirect block. */
        read_within_buffer_cache(id->double_indirect_, buffer, 0, BLOCK_SECTOR_SIZE, false);
    }

    /* Handle double indirect pointers. */
    for (int i = 0; i < 128; ++i) {
        if (size <= (140 + i * 128) * BLOCK_SECTOR_SIZE) {
          break;
        }
        block_sector_t buffer2[128];
        memset(buffer2, 0, 512);
        if (buffer[i] == 0) {
            bool success = free_map_allocate(1, &buffer[i]);
            // handle sector allocation failures
            if (!success) {
                inode_resize(id, id->length_);
                return false;
            }
        } else {
            /* Read in direct block. */
            read_within_buffer_cache(buffer[i], buffer2, 0, BLOCK_SECTOR_SIZE, false);
        }

        // handle double indirect pointers
        for (int j = 0; j < 128; ++j) {
            if (size <= (140 + i * 128 + j) * BLOCK_SECTOR_SIZE && buffer2[j] != 0) {
                /* Shrink. */
                free_map_release(buffer2[j], 1);
                buffer2[j] = 0;
            } else if (size > (140 + i * 128 + j) * BLOCK_SECTOR_SIZE && buffer2[j] == 0) {
                /* Grow. */
                bool success = free_map_allocate(1, &buffer2[j]);
                // handle sector allocation failures
                if (!success) {
                    inode_resize(id, id->length_);
                    return false;
                }
            }
        }

        if (size <= (140 + i * 128) * BLOCK_SECTOR_SIZE) {
            /* We shrank the inode such that double indirect pointers are not required. */
            free_map_release(buffer[i], 1);
            buffer[i] = 0;
        } else {
            /* Write the updates to the double indirect block back to disk. */
            write_within_buffer_cache(buffer[i], buffer2, 0, BLOCK_SECTOR_SIZE);
        }
    }

    if (size <= 140 * BLOCK_SECTOR_SIZE) {
        /* We shrank the inode such that double indirect pointers are not required. */
        free_map_release(id->double_indirect_, 1);
        id->double_indirect_ = 0;
    } else {
        /* Write the updates to the double indirect block back to disk. */
        write_within_buffer_cache(id->double_indirect_, buffer, 0, BLOCK_SECTOR_SIZE);
    }

    id->length_ = size;
    return true;
}


/* add number of files in directory pointed by INODE by 1 */
void inode_increase_cnt(struct inode* inode) {
  lock_on_inode(inode);
  inode->data_->entry_cnt_++;
  unlock_on_inode(inode);
}

/* minus number of files in directory pointed by INODE by 1 */
void inode_decrease_cnt(struct inode* inode) {
  lock_on_inode(inode);
  inode->data_->entry_cnt_--;
  unlock_on_inode(inode);
}

/* set a directory pointed by INODE as removed only when it's empty */
bool inode_set_as_removed(struct inode* inode) {
  bool removed = true;
  lock_on_inode(inode);
  if (inode->data_->entry_cnt_ <= 2) {
    inode->removed = true;
  }
  removed = inode->removed;
  unlock_on_inode(inode);
  return removed;
}
