#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "lib/string.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"

#ifdef VM
#define PF_U 0x4 /* 0: kernel, 1: user process. */
#endif

#define SIZE_OF_FPU 108 /* length of FPU is 108 bytes */

static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

static int is_legal_pointer(uint8_t* uaddr, bool read);

static int is_legal_fd(int fd);

static void exit_if_user_address_space_overflow(uint32_t* sp, int args_num);

static void string_check(const char* str);

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/**
 * check if the pointer is valid.
 * @param UADDR pointer to user space.
 * @param READ true if operation on UADDR is read, otherwise false.
 * @return -1 if the pointer is invalid or 0.
*/
static int is_legal_pointer(uint8_t* uaddr, bool read) {
  int error_code = 0;
  // invalid pointer to kenel memory space
  if ((uint32_t)uaddr >= PHYS_BASE) {
    error_code = -1;
  }
  else {
    // check if read operation is allowed
    if (read) {
      error_code = (get_user(uaddr) == -1) ? -1 : 0;
    }
    // check if write operation is allowed
    else {
      uint8_t byte = 0x1;
      error_code = put_user(uaddr, byte) ? 0 : -1;
    }
  }
  return error_code;
}

/**
 * kill process if a page fault occurs
 * @param F interrupt frame
 * @param UADDR pointer to user space.
 * @param READ true if operation on UADDR is read, otherwise false.
*/
static void exit_if_error(struct intr_frame* f, uint8_t* uaddr, bool read) {
  int error_code = is_legal_pointer(uaddr, read);
  if (error_code == -1) {
    uint32_t* args = ((uint32_t*)f->esp);
    args[0] = SYS_EXIT;
    args[1] = -1;
    syscall_handler(f);
  }
}

/**
 * check if the specified fd is valid
 * @param FD file descriptor.
 * @return 0 if FD is valid else -1.
*/
static int is_legal_fd(int fd) {
  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  if (fd >= MAX_FILES || fd < 0 || pcb->open_files_[fd] == NULL) {
    return -1;
  }
  return 0;
}

// check if there is any argument be above the top of user address space
static void exit_if_user_address_space_overflow(uint32_t* sp, int args_num) {
  bool overflow = (sp + sizeof(uint32_t) * args_num) > PHYS_BASE;
  if (overflow) {
    struct thread *cur_thread = thread_current();
    cur_thread->exit_status_ = -1;

    pthread_exit();
    NOT_REACHED();
  }

  // all stack position containning arguments should be valid 
  for (int i = 0; i < sizeof(uint32_t) * args_num; ++i) {
    if (is_legal_pointer((uint8_t*)sp + i, true) == -1) {
      struct thread *cur_thread = thread_current();
      cur_thread->exit_status_ = -1;

      pthread_exit();
      NOT_REACHED();
    }
  }
}

// check if string STR is readable on all bytes
static void string_check(const char* str) {
  char* ptr = str;
  while (true) {
    if (is_legal_pointer(ptr, true) == -1) {
      struct thread *cur_thread = thread_current();
      cur_thread->exit_status_ = -1;

      pthread_exit();
      NOT_REACHED();
    }
    if (*ptr == '\0') break;
    ++ptr;
  } 
}




/* syscall behaviours */
/********************************************************************************/
static void sys_exit(struct intr_frame* f UNUSED) {
  // signature: void exit(int status)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);

  struct thread *cur_thread = thread_current();
  cur_thread->exit_status_ = args[1];

  pthread_exit();
  NOT_REACHED();
}

static void sys_practice(struct intr_frame* f UNUSED) {
  // signature: int practice (int i)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  f->eax = args[1] + 1;
}

static void sys_halt(struct intr_frame* f UNUSED) {
  // signature: void halt (void)
  shutdown_power_off();
}

static void sys_exec(struct intr_frame* f UNUSED) {
  // signature: pid_t exec (const char *cmd_line)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  const char* cmd_line = (const char*)args[1];
  string_check(cmd_line);
  int cmd_length = strlen(cmd_line) + 1;
  f->eax = -1;
  char* buffer = (char*)calloc(cmd_length, 1);
  if (buffer) {
    strlcpy(buffer, cmd_line, cmd_length);
    f->eax = process_execute(buffer);
    free(buffer);
  }
}

static void sys_wait(struct intr_frame* f UNUSED) {
  // signature: int wait (pid_t pid)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  pid_t child_pid = (pid_t)args[1];
  f->eax = process_wait(child_pid);
}

static void sys_create(struct intr_frame* f UNUSED) {
  // signature: bool create (const char *file, unsigned initial_size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 3);
  const char* file = (const char*)args[1];
  string_check(file);
  unsigned initial_size = (unsigned)args[2];

  bool success = filesys_create(file, initial_size, true);
  f->eax = success ? 1 : 0;
}

static void sys_remove(struct intr_frame* f UNUSED) {
  // signature: bool remove (const char *file)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  const char* file_name = (const char*)args[1];
  string_check(file_name);
  
  bool success = filesys_remove(file_name);

  f->eax = success ? 1 : 0;
}

static void sys_open(struct intr_frame* f UNUSED) {
  // signature: int open(const char* file)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);

  const char* file_name = (const char*)args[1];
  string_check(file_name);
  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  lock_acquire(&(pcb->lock_on_file_));

  void* entry_opened = NULL;
  bool is_file = true;
  entry_opened = filesys_open_file(file_name);
  if (entry_opened == NULL) {
    entry_opened = filesys_open_dir(file_name);
    if (entry_opened != NULL) {
      is_file = false;
    }
  }

  if (entry_opened == NULL) {
    lock_release(&(pcb->lock_on_file_));
    f->eax = -1;
    return;
  }


  // create and initilaize a new file_info node
  struct file_info* new_info = (struct file_info*)calloc(sizeof(struct file_info), 1);
  if (new_info == NULL) {
    lock_release(&(pcb->lock_on_file_));
    if (is_file) {
      file_close((struct file*)entry_opened);
    }
    else {
      dir_close((struct dir*)entry_opened);
    }
    f->eax = -1;
    return;
  }
  int file_name_len = strlen(file_name);
  new_info->file_name_ = (char*)malloc(file_name_len + 1);
  if (new_info->file_name_ == NULL) {
    lock_release(&(pcb->lock_on_file_));
    if (is_file) {
      file_close((struct file*)entry_opened);
    }
    else {
      dir_close((struct dir*)entry_opened);
    }
    free(new_info);
    f->eax = -1;
    return;
  }
  strlcpy(new_info->file_name_, file_name, file_name_len + 1);
  new_info->is_file_ = is_file;
  new_info->entry_ = entry_opened;

  f->eax = -1;
  // rw_lock_acquire(&(pcb->file_rw_lock_), false);
  for (int i = 2; i < MAX_FILES; ++i) {
    if (pcb->open_files_[i] == NULL) {
      pcb->open_files_[i] = new_info;
      f->eax = i;
      break;
    }
  }
  // rw_lock_release(&(pcb->file_rw_lock_), false);
  lock_release(&(pcb->lock_on_file_));

  if ((int)f->eax == -1) {
    free(new_info->file_name_);
    free(new_info);
    if (is_file) {
      file_close((struct file*)entry_opened);
    }
    else {
      dir_close((struct dir*)entry_opened);
    }
  }
}

static void sys_filesize(struct intr_frame* f UNUSED) {
  // signature: int filesize (int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int fd = args[1];

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  f->eax = -1;
  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    struct file* file = (struct file*)info->entry_;
    f->eax = file_length(file);
  }
  lock_release(&(pcb->lock_on_file_));
}

static void sys_read(struct intr_frame* f UNUSED) {
  // signature: int read (int fd, void *buffer, unsigned size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 4);
  int fd = args[1];
  char* buffer = args[2];
  unsigned size = args[3];
  for (int i = 0; i < size; ++i) {
    exit_if_error(f, buffer + i, false);
  }

#ifdef VM
  struct thread* cur_thread = thread_current();
  struct process* cur_pcb = cur_thread->pcb;
  // pin_page(cur_pcb, buffer);
#endif

  // read from keyboard
  if (fd == STDIN_FILENO) {
    unsigned cnt = 0;
    while (true) {
      if (cnt >= size) {
        break;
      }
      uint8_t key = input_getc();
      buffer[cnt] = key;
      ++cnt;
      if (key == '\0') {
        break;
      }
    }
    f->eax = cnt;
    return;
  }

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  // rw_lock_acquire(&(pcb->file_rw_lock_), true);
  f->eax = -1;
  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    struct file* file = (struct file*)info->entry_;
    f->eax = file_read(file, buffer, size);
  }
  // rw_lock_release(&(pcb->file_rw_lock_), true);
  lock_release(&(pcb->lock_on_file_));
  
#ifdef VM
  unpin_page(cur_pcb, buffer);
#endif

}

static void sys_write(struct intr_frame* f UNUSED) {
  // signature: int write (int fd, const void *buffer, unsigned size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 4);
  int fd = args[1];
  char* buffer = args[2];
  unsigned size = args[3];
  for (int i = 0; i < size; ++i) {
    exit_if_error(f, buffer + i, true);
  }

#ifdef VM
  struct thread* cur_thread = thread_current();
  struct process* cur_pcb = cur_thread->pcb;
  // pin_page(cur_pcb, buffer);
#endif


  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    f->eax = size;
    return;
  }

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  f->eax = -1;
  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    struct file* file = (struct file*)info->entry_;
    f->eax = file_write(file, buffer, size);
  }
  // rw_lock_release(&(pcb->file_rw_lock_), true);
  lock_release(&(pcb->lock_on_file_));

#ifdef VM
  unpin_page(cur_pcb, buffer);
#endif

}

static void sys_seek(struct intr_frame* f UNUSED) {
  // signature: void seek (int fd, unsigned position)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 3);
  int fd = args[1];
  unsigned position = args[2];

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    struct file* file = (struct file*)info->entry_;
    file_seek(file, position);
  }
  lock_release(&(pcb->lock_on_file_));
}

static void sys_tell(struct intr_frame* f UNUSED) {
  // signature: int tell(int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int fd = args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;


  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    struct file* file = (struct file*)info->entry_;
    f->eax = file_tell(file);
  }
  lock_release(&(pcb->lock_on_file_));
}

static void sys_close(struct intr_frame* f UNUSED) {
  // signature: void close (int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int fd = args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }
  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    file_close((struct file*)info->entry_);
  }
  else {
    dir_close((struct dir*)info->entry_);
  }
  info->entry_ = NULL;
  free(info->file_name_);
  info->file_name_ = NULL;
  free(info);
  pcb->open_files_[fd] = NULL;
  lock_release(&(pcb->lock_on_file_));
}

static void sys_compute_e(struct intr_frame* f UNUSED) {
  // signature: double compute_e (int n)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int n = (int)args[1];

  // store state of fpu
  uint8_t fpu[SIZE_OF_FPU];
  asm volatile(
    "fsave %0" 
    : "=m"(*fpu) 
    : 
    : "memory"
  );

  f->eax = sys_sum_to_e(n);

  // restore state of fpu
  asm volatile(
    "frstor %0"
    :
    : "m"(*fpu)
    : "memory"
  );
}

static void sys_pt_create(struct intr_frame* f UNUSED) {
  // signature: tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 4);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  exit_if_error(f, (uint8_t*)(args + 2), true);
  exit_if_error(f, (uint8_t*)(args + 3), true);

  stub_fun sfun = (stub_fun)args[1];
  pthread_fun tfun = (pthread_fun)args[2];
  const void* tfun_arg = (void*)args[3];
  f->eax = pthread_execute(sfun, tfun, tfun_arg);
}

static void sys_pt_exit(struct intr_frame* f UNUSED) {
  // signature: void sys_pthread_exit(void) NO_RETURN;
  uint32_t* args UNUSED= ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 1);
  pthread_exit();
  NOT_REACHED();
}

static void sys_pt_join(struct intr_frame* f UNUSED) {
  // signature: tid_t sys_pthread_join(tid_t tid);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  tid_t join_tid = (tid_t)args[1];
  tid_t ret_tid = pthread_join(join_tid); 
  f->eax = ret_tid;
}

static void sys_lock_init(struct intr_frame* f UNUSED) {
  // signature: bool lock_init(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  char* lock_id_ptr = (char*)args[1];
  if (lock_id_ptr == NULL) {
    f->eax = false;
    return;
  }
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;
  if (pcb == NULL) {
    f->eax = false;
    return;
  }

  bool success = false;
  // critical section
  rw_lock_acquire(&(pcb->rw_on_locks_), false);
  for (int i = 0; i < USER_LOCK_SIZE; ++i) {
    if (pcb->locks_[i] != NULL) continue;
    pcb->locks_[i] = (struct lock*)malloc(sizeof(struct lock)); 
    if (pcb->locks_[i] == NULL) break;
    lock_init(pcb->locks_[i]);
    success = true;
    *lock_id_ptr = (char)i;
    break;
  }
  rw_lock_release(&(pcb->rw_on_locks_), false);
  f->eax = success;
}

static void sys_lock_acquire(struct intr_frame* f UNUSED) {
  // signature: void lock_acquire(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  uint8_t lock_id = *(char*)args[1];
  bool success = false;
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;

  rw_lock_acquire(&(pcb->rw_on_locks_), true);
  if ((pcb != NULL) && (pcb->locks_[lock_id] != NULL)) {
    if (!lock_held_by_current_thread(pcb->locks_[lock_id])) {
      success = lock_try_acquire(pcb->locks_[lock_id]);
      if (!success) {
        rw_lock_release(&(pcb->rw_on_locks_), true);
        lock_acquire(pcb->locks_[lock_id]);
        success = true;
      }
      else {
        rw_lock_release(&(pcb->rw_on_locks_), true);
      }
    }
  }
  f->eax = success;
}

static void sys_lock_release(struct intr_frame* f UNUSED) {
  // signature: void lock_release(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  uint8_t lock_id = *(char*)args[1];
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;

  bool success = false;
  rw_lock_acquire(&(pcb->rw_on_locks_), true);
  if ((pcb != NULL) && (pcb->locks_[lock_id] != NULL)) {
    if (lock_held_by_current_thread(pcb->locks_[lock_id])) {
      lock_release(pcb->locks_[lock_id]);
      success = true;
    }
  }
  rw_lock_release(&(pcb->rw_on_locks_), true);
  f->eax = success;
}

static void sys_sema_init(struct intr_frame* f UNUSED) {
  // signature: bool sema_init(char* sema, int val);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 3);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  uint8_t* sema_id_ptr = (uint8_t*)args[1];
  if (sema_id_ptr == NULL) {
    f->eax = false;
    return;
  }
  int val = (int)args[2];
  if (val < 0) {
    f->eax = false;
    return;
  }
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;
  if (pcb == NULL) {
    f->eax = false;
    return;
  }

  bool success = false;
  // critical section
  rw_lock_acquire(&(pcb->rw_on_semas_), false);
  for (int i = 0; i < USER_SEMAPHORE_SIZE; ++i) {
    if (pcb->semas_[i] != NULL) continue;
    pcb->semas_[i] = (struct semaphore*)malloc(sizeof(struct semaphore)); 
    if (pcb->semas_[i] == NULL) break;
    sema_init(pcb->semas_[i], val);
    *sema_id_ptr = (uint8_t)i;
    success = true;
    break;
  }
  rw_lock_release(&(pcb->rw_on_semas_), false);
  f->eax = success;
}

static void sys_sema_down(struct intr_frame* f UNUSED) {
  // signature: void sema_down(char* sema);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  uint8_t sema_id = *(uint8_t*)args[1];
  bool success = false;
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;

  rw_lock_acquire(&(pcb->rw_on_semas_), true);
  if ((pcb != NULL) && (pcb->semas_[sema_id] != NULL)) {
    success = sema_try_down(pcb->semas_[sema_id]);
    if (!success) {
      rw_lock_release(&(pcb->rw_on_semas_), true);
      sema_down(pcb->semas_[sema_id]);
      success = true;
    }
    else {
      rw_lock_release(&(pcb->rw_on_semas_), true);
    }
  }
  f->eax = success;
}

static void sys_sema_up(struct intr_frame* f UNUSED) {
  // signature: void sema_up(char* sema);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  uint8_t sema_id = *(uint8_t*)args[1];
  struct thread* current_thread = thread_current();
  struct process* pcb = current_thread->pcb;

  bool success = false;
  rw_lock_acquire(&(pcb->rw_on_semas_), true);
  if ((pcb != NULL) && (pcb->semas_[sema_id] != NULL)) {
    success = true;
    sema_up(pcb->semas_[sema_id]);
  }
  rw_lock_release(&(pcb->rw_on_semas_), true);
  f->eax = success;
}

static void sys_get_tid(struct intr_frame* f UNUSED) {
  // signature: tid_t get_tid(void);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 1);
  f->eax = thread_tid();
}

static void sys_mmap(struct intr_frame* f UNUSED) {
  // signature: mapid_t mmap(int fd, void* addr);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 3);
  int fd = (int)args[1];
  if (is_legal_fd(fd)) {
    f->eax = -1;
    return;
  }
  void* addr = (void*)args[2];
  // exit_if_error(f, addr, false);

  struct file* file = NULL;

  /* error cases */
  // 1. `addr` is not page-aligned; 2. `addr == 0`; 3. `fd == 0` or `fd == 1`;
  if ((((uint32_t)addr & PGMASK) != 0) || (addr == 0) || (fd == 0) || (fd == 1)) {
    f->eax = -1;
    return;
  }

  // 4. file open as `fd` has a length of zero bytes;
  int file_size = 0;
  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;
  bool is_file = false;
  lock_acquire(&(pcb->lock_on_file_));
  struct file_info* info = pcb->open_files_[fd];
  if (info->is_file_) {
    is_file = true;
    file = (struct file*)info->entry_;
    file_size = file_length(file);
  }
  lock_release(&(pcb->lock_on_file_));
  if (!is_file || (file_size == 0)) {
    f->eax = -1;
    return;
  }

  // 5. range of pages mapped overlaps any existing set of mapped pages;
  bool get_consecutive_memory = true;
  int page_cnt = file_size / PGSIZE;
  if ((file_size & PGMASK) != 0) {
    ++page_cnt;
  }
  for (int offset = 0; offset < page_cnt; ++offset) {
    if (is_page_valid(pcb, addr + offset * PGSIZE)) {
      get_consecutive_memory = false;
      break;
    }
  }

  if (!get_consecutive_memory) {
    f->eax = -1;
    return;
  }

  // allocate a struct mmap_entry object for the file FD and add it to the process
  struct mmap_entry* mmap_ent = (struct mmap_entry*)malloc(sizeof(struct mmap_entry));
  if (mmap_ent == NULL) {
    f->eax = -1;
    return;
  }
  mmap_ent->mapid_ = pcb->next_map_id_;
  ++pcb->next_map_id_;
  list_init(&mmap_ent->m_page_list_);
  list_push_front(&(pcb->mmap_list_), &(mmap_ent->l_elem_));


  // allocate page for the file
  for (int offset = 0; offset < page_cnt; ++offset) {
    struct mmap_page* m_page = (struct mmap_page*)malloc(sizeof(struct mmap_page));
    m_page->file_ = file_reopen(file);
    m_page->upage_ = addr + offset * PGSIZE;
    list_push_back(&mmap_ent->m_page_list_, &m_page->l_elem_);
    uint32_t size = 0;
    if (file_size >= PGSIZE) {
      size = PGSIZE;
    }
    else {
      size = file_size;
    }
    file_size -= size;
    allocate_page(pcb, m_page->upage_, true, m_page->file_, offset * PGSIZE, size);
  }

  f->eax = mmap_ent->mapid_;
}

static void sys_munmap(struct intr_frame* f UNUSED) {
  // signature: void munmap(mapid_t);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  mapid_t map_id = (mapid_t)args[1];

  // map id validation check
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  struct list_elem* e = NULL;
  struct mmap_entry* ent = NULL;
  for (e = list_begin(&pcb->mmap_list_); e != list_end(&pcb->mmap_list_); e = list_next(e)) {
    ent = list_entry(e, struct mmap_entry, l_elem_);
    if (ent->mapid_ == map_id) {
      list_remove(e);
      break;
    }
    ent = NULL;
  }

  // return if mapping doesn't exist
  if (ent == NULL) {
    f->eax = -1;
    return;
  }

  // write all memory mapped dirty page data back to file
  e = NULL;
  while (!list_empty(&ent->m_page_list_)) {
    e = list_pop_front(&ent->m_page_list_);
    struct mmap_page* m_page = list_entry(e, struct mmap_page, l_elem_);
    deallocate_page(pcb, m_page->upage_);
    file_close(m_page->file_);
    free(m_page);
  }
  free(ent);
}

static void sys_chdir(struct intr_frame* f UNUSED) {
  // signature: bool chdir(const char* dir);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  const char* dir_name = (const char*)args[1];
  size_t dir_len = strlen(dir_name);
  for (size_t i = 0; i <= dir_len; ++i) {
    exit_if_error(f, dir_name + i, true);
  }

  struct dir* dir = filesys_open_dir(dir_name);
  if (dir == NULL) {
    f->eax = false;
    return;
  }
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  dir_close(pcb->pwd_);
  pcb->pwd_ = dir;
  f->eax = true;
}

static void sys_mkdir(struct intr_frame* f UNUSED) {
  // signature: bool mkdir(const char* dir);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  const char* dir_name = (const char*)args[1];
  size_t dir_len = strlen(dir_name);
  for (size_t i = 0; i <= dir_len; ++i) {
    exit_if_error(f, dir_name + i, true);
  }

  f->eax = filesys_create(dir_name, 2, false);
}

static void sys_readdir(struct intr_frame* f UNUSED) {
  // signature: bool readdir(int fd, char name[READDIR_MAX_LEN + 1]);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 3);
  int fd = (int)args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    f->eax = false;
    return;
  }
  // pointer to a char array with (READDIR_MAX_LEN + 1) size bytes
  const char* name = (const char*)args[2];
  size_t len = strlen(name);
  for (size_t i = 0; i <= len; ++i) {
    exit_if_error(f, name + i, false);
  }

  // fd should be directory type
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  if (pcb->open_files_[fd]->is_file_) {
    f->eax = false;
    return;
  }

  // read a directory entry from fd, while [.] and [..] should not be returned by readdir.
  f->eax = true;
  struct dir* fd_dir = (struct dir*)(pcb->open_files_[fd]->entry_);
  memset(name, 0, NAME_MAX + 1);
  while (true) {
    bool success = dir_readdir(fd_dir, name);
    if (!success) {
      f->eax = false;
      break;
    }
    if (strcmp(".", name) && strcmp("..", name)) {
      break;
    }
    memset(name, 0, NAME_MAX + 1);
  }
}

static void sys_isdir(struct intr_frame* f UNUSED) {
  // signature: bool isdir(int fd);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int fd = (int)args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    f->eax = false;
    return;
  }

  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  f->eax = !pcb->open_files_[fd]->is_file_;
}

static void sys_inumber(struct intr_frame* f UNUSED) {
  // signature: int inumber(int fd);
  uint32_t* args UNUSED = ((uint32_t*)f->esp);
  exit_if_user_address_space_overflow(args, 2);
  int fd = (int)args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  struct inode* inode = NULL;
  if (pcb->open_files_[fd]->is_file_) {
    struct file* file = (struct file*)(pcb->open_files_[fd]->entry_);
    inode = file_get_inode(file);
  }
  else {
    struct dir* dir = (struct dir*)(pcb->open_files_[fd]->entry_);
    inode = dir_get_inode(dir);
  }
  f->eax = inode_get_inumber(inode);
}

/********************************************************************************/

static void syscall_handler(struct intr_frame* f UNUSED) {

#ifdef VM
  // for stack growth
  // save user stack pointer to current thread when a context switch from user to kernel occurs
  struct thread* cur_thread = thread_current();
  bool user = (f->error_code & PF_U) != 0;
  if (user) {
    cur_thread->esp_ = f->esp;
  }
#endif

  uint32_t* args = ((uint32_t*)f->esp);
  // stack pointer validation check
  exit_if_user_address_space_overflow(args, 1);
  uint32_t syscall_number = args[0];

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (syscall_number == SYS_EXIT) {
    sys_exit(f);
  }
  else if (syscall_number == SYS_PRACTICE) {
    sys_practice(f);
  }
  else if (syscall_number == SYS_HALT) {
    sys_halt(f);
  }
  else if (syscall_number == SYS_EXEC) {
    sys_exec(f);
  }
  else if (syscall_number == SYS_WAIT) {
    sys_wait(f);
  }
  else if (syscall_number == SYS_CREATE) {
    sys_create(f);
  }
  else if (syscall_number == SYS_REMOVE) {
    sys_remove(f);
  }
  else if (syscall_number == SYS_OPEN) {
    sys_open(f);
  }
  else if (syscall_number == SYS_FILESIZE) {
    sys_filesize(f);
  }
  else if (syscall_number == SYS_READ) {
    sys_read(f);
  }
  else if (syscall_number == SYS_WRITE) {
    sys_write(f);
  }
  else if (syscall_number == SYS_SEEK) {
     sys_seek(f);
  }
  else if (syscall_number == SYS_TELL) {
    sys_tell(f);
  }
  else if (syscall_number == SYS_CLOSE) {
    sys_close(f);
  }
  else if (syscall_number == SYS_COMPUTE_E) {
    sys_compute_e(f);
  }
  else if (syscall_number == SYS_PT_CREATE) {
    sys_pt_create(f);
  }
  else if (syscall_number == SYS_PT_EXIT) {
    sys_pt_exit(f);
  }
  else if (syscall_number == SYS_PT_JOIN) {
    sys_pt_join(f);
  }
  else if (syscall_number == SYS_LOCK_INIT) {
    sys_lock_init(f);
  }
  else if (syscall_number == SYS_LOCK_ACQUIRE) {
    sys_lock_acquire(f);
  }
  else if (syscall_number == SYS_LOCK_RELEASE) {
    sys_lock_release(f);
  }
  else if (syscall_number == SYS_SEMA_INIT) {
    sys_sema_init(f);
  }
  else if (syscall_number == SYS_SEMA_DOWN) {
    sys_sema_down(f);
  }
  else if (syscall_number == SYS_SEMA_UP) {
    sys_sema_up(f);
  }
  else if (syscall_number == SYS_GET_TID) {
    sys_get_tid(f);
  }
  else if (syscall_number == SYS_MMAP) {
    sys_mmap(f);
  }
  else if (syscall_number == SYS_MUNMAP) {
    sys_munmap(f);
  }
  else if (syscall_number == SYS_CHDIR) {
    sys_chdir(f);
  }
  else if (syscall_number == SYS_MKDIR) {
    sys_mkdir(f);
  }
  else if (syscall_number == SYS_READDIR) {
    sys_readdir(f);
  }
  else if (syscall_number == SYS_ISDIR) {
    sys_isdir(f);
  }
  else if (syscall_number == SYS_INUMBER) {
    sys_inumber(f);
  }
  else {
    // do nothing
  }
}
