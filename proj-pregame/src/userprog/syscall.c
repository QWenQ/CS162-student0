#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
// #include "user/syscall.h"

#define PHYS_BASE 0xc0000000 /* 3 GB. */

#define SIZE_OF_FPU 108 /* length of FPU is 108 bytes */

static int get_user(const uint8_t *uaddr);

static bool put_user(uint8_t *udst, uint8_t byte);

static int is_legal_pointer(uint8_t* uaddr, bool read);

static int is_legal_fd(int fd);

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


/* syscall behaviours */
/********************************************************************************/
void sys_exit(struct intr_frame* f UNUSED) {
  // signature: void exit(int status)
  uint32_t* args = ((uint32_t*)f->esp);
  f->eax = is_legal_pointer((uint8_t*)(args + 1), true);
  if ((int)f->eax != -1) {
    f->eax = args[1];
  }

  struct thread *cur_thread = thread_current();
  cur_thread->exit_status_ = args[1];

  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, f->eax);
  process_exit();
}

void sys_practice(struct intr_frame* f UNUSED) {
  // signature: int practice (int i)
  uint32_t* args = ((uint32_t*)f->esp);
  f->eax = is_legal_pointer((uint8_t*)(args + 1), true);
  if ((int)f->eax == -1) {
    return;
  }
  f->eax = args[1] + 1;
}

void sys_halt(struct intr_frame* f UNUSED) {
  // signature: void halt (void)
  // uint32_t* args = ((uint32_t*)f->esp);
  shutdown_power_off();
}

void sys_exec(struct intr_frame* f UNUSED) {
  // signature: pid_t exec (const char *cmd_line)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  const char* cmd_line = (const char*)args[1];
  int cmd_length = strlen(cmd_line) + 1;
  char* buffer = (char*)calloc(cmd_length, 1);
  strlcpy(buffer, cmd_line, cmd_length);
  f->eax = process_execute(buffer);
  free(buffer);
}

void sys_wait(struct intr_frame* f UNUSED) {
  // signature: int wait (pid_t pid)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  pid_t child_pid = (pid_t)args[1];
  f->eax = process_wait(child_pid);
}

void sys_create(struct intr_frame* f UNUSED) {
  // signature: bool create (const char *file, unsigned initial_size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true); 
  const char* file = (const char*)args[1];
  exit_if_error(f, (uint8_t*)file, true);
  exit_if_error(f, (uint8_t*)(args + 2), true);
  unsigned initial_size = (unsigned)args[2];

  bool success = filesys_create(file, initial_size);
  f->eax = success ? 1 : 0;
}

void sys_remove(struct intr_frame* f UNUSED) {
  // signature: bool remove (const char *file)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  const char* file_name = (const char*)args[1];
  
  bool success = filesys_remove(file_name);

  f->eax = success ? 1 : 0;
}

void sys_open(struct intr_frame* f UNUSED) {
  // signature: int open(const char* file)
  uint32_t* args = ((uint32_t*)f->esp);
  f->eax = is_legal_pointer((uint8_t*)(args + 1), true);
  if ((int)f->eax == -1) {
    return;
  }

  f->eax = is_legal_pointer((uint8_t*)args[1], true);
  if ((int)f->eax == -1) {
    args[0] = SYS_EXIT;
    args[1] = -1;
    syscall_handler(f);
  }

  const char* file = (const char*)args[1];
  struct file* open_file = filesys_open(file);
  if (open_file == NULL) {
    f->eax = -1;
    return;
  }


  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  f->eax = -1;
  // ciritical section
  rw_lock_acquire(&(pcb->file_rw_lock_), false);
  for (int i = 2; i < MAX_FILES; ++i) {
    if (pcb->open_files_[i] == NULL) {
      pcb->open_files_[i] = open_file;
      f->eax = i;
      break;
    }
  }

  rw_lock_release(&(pcb->file_rw_lock_), false);
}

void sys_filesize(struct intr_frame* f UNUSED) {
  // signature: int filesize (int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  rw_lock_acquire(&(pcb->file_rw_lock_), true);
  struct file* p_file = pcb->open_files_[fd];
  if (p_file != NULL) {
    f->eax = file_length(p_file);
  }
  rw_lock_release(&(pcb->file_rw_lock_), true);
}

void sys_read(struct intr_frame* f UNUSED) {
  // signature: int read (int fd, void *buffer, unsigned size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];
  exit_if_error(f, (uint8_t*)(args + 2), true);
  char* buffer = args[2];
  exit_if_error(f, (uint8_t*)(args + 3), true);
  unsigned size = args[3];
  exit_if_error(f, (uint8_t*)(buffer), true);
  exit_if_error(f, (uint8_t*)(buffer + size - 1), true);

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

  rw_lock_acquire(&(pcb->file_rw_lock_), true);
  struct file* p_file = pcb->open_files_[fd];
  f->eax = file_read(p_file, buffer, size);
  rw_lock_release(&(pcb->file_rw_lock_), true);
}

void sys_write(struct intr_frame* f UNUSED) {
  // signature: int write (int fd, const void *buffer, unsigned size)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];
  exit_if_error(f, (uint8_t*)(args + 2), true);
  char* buffer = args[2];
  exit_if_error(f, (uint8_t*)(args + 3), true);
  unsigned size = args[3];
  exit_if_error(f, (uint8_t*)(buffer), true);
  exit_if_error(f, (uint8_t*)(buffer + size - 1), true);


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

  rw_lock_acquire(&(pcb->file_rw_lock_), true);
  struct file* p_file = pcb->open_files_[fd];
  f->eax = file_write(p_file, buffer, size);
  rw_lock_release(&(pcb->file_rw_lock_), true);
}

void sys_seek(struct intr_frame* f UNUSED) {
  // signature: void seek (int fd, unsigned position)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];
  exit_if_error(f, (uint8_t*)(args + 2), true);
  unsigned position = args[2];

  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  rw_lock_acquire(&pcb->file_rw_lock_, true);
  struct file* p_file = pcb->open_files_[fd];
  file_seek(p_file, position);
  rw_lock_release(&pcb->file_rw_lock_, true);
}

void sys_tell(struct intr_frame* f UNUSED) {
  // signature: int tell(int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }

  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;


  rw_lock_acquire(&pcb->file_rw_lock_, true);
  struct file* p_file = pcb->open_files_[fd];
  f->eax = file_tell(p_file);
  rw_lock_release(&pcb->file_rw_lock_, true);
}

void sys_close(struct intr_frame* f UNUSED) {
  // signature: void close (int fd)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  int fd = args[1];
  f->eax = is_legal_fd(fd);
  if ((int)f->eax == -1) {
    return;
  }
  struct thread* running_thread = thread_current();
  struct process* pcb = running_thread->pcb;

  rw_lock_acquire(&pcb->file_rw_lock_, false);
  struct file* p_file = pcb->open_files_[fd];
  file_close(p_file);
  pcb->open_files_[fd] = NULL;
  rw_lock_release(&pcb->file_rw_lock_, false);
}

void sys_compute_e(struct intr_frame* f UNUSED) {
  // signature: double compute_e (int n)
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);

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

void sys_pt_create(struct intr_frame* f UNUSED) {
  // signature: tid_t sys_pthread_create(stub_fun sfun, pthread_fun tfun, const void* arg);
  uint32_t* args = ((uint32_t*)f->esp);
  exit_if_error(f, (uint8_t*)(args + 1), true);
  exit_if_error(f, (uint8_t*)(args + 2), true);
  exit_if_error(f, (uint8_t*)(args + 3), true);

  stub_fun sfun = (stub_fun)args[1];
  pthread_fun tfun = (pthread_fun)args[2];
  const void* tfun_arg = (void*)args[3];
  f->eax = pthread_execute(sfun, tfun, tfun_arg);
}

void sys_pt_exit(struct intr_frame* f UNUSED) {
  // signature: void sys_pthread_exit(void) NO_RETURN;
  uint32_t* args = ((uint32_t*)f->esp);
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  if (pcb == NULL) return;
  if (pcb->main_thread == cur_thread) {
    // main thread exits
    pthread_exit_main();
  }
  else {
    // non-main thread exits
    pthread_exit();
  }
}

void sys_pt_join(struct intr_frame* f UNUSED) {
  // signature: tid_t sys_pthread_join(tid_t tid);
  uint32_t* args = ((uint32_t*)f->esp);
  tid_t join_tid = (tid_t)args[1];
  tid_t ret_tid = pthread_join(join_tid); 
  f->eax = ret_tid;
}


void sys_lock_init(struct intr_frame* f UNUSED) {
  // signature: bool lock_init(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_lock_acquire(struct intr_frame* f UNUSED) {
  // signature: void lock_acquire(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_lock_release(struct intr_frame* f UNUSED) {
  // signature: void lock_release(char* lock);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_sema_init(struct intr_frame* f UNUSED) {
  // signature: bool sema_init(char* sema, int val);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_sema_down(struct intr_frame* f UNUSED) {
  // signature: void sema_down(char* sema);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_sema_up(struct intr_frame* f UNUSED) {
  // signature: void sema_up(char* sema);
  uint32_t* args = ((uint32_t*)f->esp);
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

void sys_get_tid(struct intr_frame* f UNUSED) {
  // signature: tid_t get_tid(void);
  uint32_t* args UNUSED= ((uint32_t*)f->esp);
  f->eax = thread_tid();
}

// template
// void sys_(struct intr_frame* f UNUSED) {
//   // signature: 
//   uint32_t* args = ((uint32_t*)f->esp);

// }

/********************************************************************************/




static void syscall_handler(struct intr_frame* f UNUSED) {
  // uint32_t* args = ((uint32_t*)f->esp);
  uint32_t syscall_number = *(uint32_t*)(f->esp);

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
  else {
    // do nothing
  }
}
