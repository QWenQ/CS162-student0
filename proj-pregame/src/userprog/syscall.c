#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdbool.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

#define PHYS_BASE 0xc0000000 /* 3 GB. */

extern struct latch_on_create_new_process {
  bool is_new_process_create_done_; /* true if work of creating a new process is done */
  bool is_creating_succeed_; /* true if new process work as expected */
  struct lock monitor_lock_; /* monitor lock */
  struct condition done_cond_; /* signaled when work of creatign a new process is done*/
} latch_on_create_new_process;

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

  if (fd >= MAX_FILES || fd < 0 || pcb->open_files[fd] == NULL) {
    return -1;
  }
  return 0;
}


static void syscall_handler(struct intr_frame* f UNUSED) {

  // syscall number check
  uint8_t* syscall_number_byte_pointer = (uint8_t*)f->esp;
  for (size_t len = 0; len < (sizeof(SYS_CHDIR) / sizeof (uint8_t)); ++len) {
    f->eax = is_legal_pointer(syscall_number_byte_pointer, true);
    if ((int)f->eax == -1) {
      return;
    }
    ++syscall_number_byte_pointer;
  }

  uint32_t* args = ((uint32_t*)f->esp);


  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    f->eax = is_legal_pointer((uint8_t*)(args + 1), true);
    if ((int)f->eax != -1) {
      f->eax = args[1];
    }

    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, f->eax);
    process_exit();
  }
  else if (args[0] == SYS_PRACTICE) {
    // signature: int practice (int i)
    f->eax = is_legal_pointer((uint8_t*)(args + 1), true);
    if ((int)f->eax == -1) {
      return;
    }
    f->eax = args[1] + 1;
  }
  else if (args[0] == SYS_HALT) {
    // signature: void halt (void)
    shutdown_power_off();
  }
  else if (args[0] == SYS_EXEC) {
    // signature: pid_t exec (const char *cmd_line)
    exit_if_error(f, (uint8_t*)(args + 1), true);
    const char* cmd_line = (const char*)args[1];

    f->eax = -1;

    // pid_t pid = process_execute(cmd_line);
    // if (pid == TID_ERROR) {
    //   return;
    // }

    // while (!latch_on_create_new_process.is_new_process_create_done_) {
    //   lock_acquire(&latch_on_create_new_process.monitor_lock_); 
    //   cond_wait(&latch_on_create_new_process.done_cond_, &latch_on_create_new_process.monitor_lock_);
    // }

    // lock_release(&latch_on_create_new_process.monitor_lock_);

    // if (latch_on_create_new_process.is_creating_succeed_) { 
    //   f->eax = pid;
    // }

  }
  else if (args[0] == SYS_WAIT) {
    // signature: int wait (pid_t pid)

  }
  else if (args[0] == SYS_CREATE) {
    // signature: bool create (const char *file, unsigned initial_size)
    exit_if_error(f, (uint8_t*)(args + 1), true); 
    const char* file = (const char*)args[1];
    exit_if_error(f, (uint8_t*)file, true);
    exit_if_error(f, (uint8_t*)(args + 2), true);
    unsigned initial_size = (unsigned)args[2];

    bool success = filesys_create(file, initial_size);
    f->eax = success ? 1 : 0;
    
  }
  else if (args[0] == SYS_REMOVE) {
    // signature: bool remove (const char *file)
    exit_if_error(f, (uint8_t*)(args + 1), true);
    const char* file = (const char*)args[1];

    bool success = filesys_remove(file);
    f->eax = success ? 1 : 0;

  }
  else if (args[0] == SYS_OPEN) {
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
    rw_lock_acquire(&(pcb->file_rw_lock), false);
    for (int i = 2; i < MAX_FILES; ++i) {
      if (pcb->open_files[i] == NULL) {
        pcb->open_files[i] = open_file;
        f->eax = i;
        break;
      }
    }

    rw_lock_release(&(pcb->file_rw_lock), false);
  }
  else if (args[0] == SYS_FILESIZE) {
    // signature: int filesize (int fd)
    exit_if_error(f, (uint8_t*)(args + 1), true);
    int fd = args[1];

    f->eax = is_legal_fd(fd);
    if ((int)f->eax == -1) {
      return;
    }

    struct thread* running_thread = thread_current();
    struct process* pcb = running_thread->pcb;

    rw_lock_acquire(&(pcb->file_rw_lock), true);
    struct file* p_file = pcb->open_files[fd];
    if (p_file != NULL) {
      f->eax = file_length(p_file);
    }
    rw_lock_release(&(pcb->file_rw_lock), true);

  }
  else if (args[0] == SYS_READ) {
    // signature: int read (int fd, void *buffer, unsigned size)
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

    rw_lock_acquire(&(pcb->file_rw_lock), true);
    struct file* p_file = pcb->open_files[fd];
    f->eax = file_read(p_file, buffer, size);
    rw_lock_release(&(pcb->file_rw_lock), true);

  }
  else if (args[0] == SYS_WRITE) {
    // signature : int write (int fd, const void *buffer, unsigned size)
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

    rw_lock_acquire(&(pcb->file_rw_lock), true);
    struct file* p_file = pcb->open_files[fd];
    f->eax = file_write(p_file, buffer, size);
    rw_lock_release(&(pcb->file_rw_lock), true);
  }
  else if (args[0] == SYS_SEEK) {
    // signature: void seek (int fd, unsigned position)
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

    rw_lock_acquire(&pcb->file_rw_lock, true);
    struct file* p_file = pcb->open_files[fd];
    file_seek(p_file, position);
    rw_lock_release(&pcb->file_rw_lock, true);

  }
  else if (args[0] == SYS_TELL) {
    // signature: int tell(int fd)
    exit_if_error(f, (uint8_t*)(args + 1), true);
    int fd = args[1];
    f->eax = is_legal_fd(fd);
    if ((int)f->eax == -1) {
      return;
    }

    struct thread* running_thread = thread_current();
    struct process* pcb = running_thread->pcb;


    rw_lock_acquire(&pcb->file_rw_lock, true);
    struct file* p_file = pcb->open_files[fd];
    f->eax = file_tell(p_file);
    rw_lock_release(&pcb->file_rw_lock, true);
  }
  else if (args[0] == SYS_CLOSE) {
    // signature: void close (int fd)
    exit_if_error(f, (uint8_t*)(args + 1), true);
    int fd = args[1];
    f->eax = is_legal_fd(fd);
    if ((int)f->eax == -1) {
      return;
    }
    struct thread* running_thread = thread_current();
    struct process* pcb = running_thread->pcb;

    rw_lock_acquire(&pcb->file_rw_lock, false);
    struct file* p_file = pcb->open_files[fd];
    file_close(p_file);
    pcb->open_files[fd] = NULL;
    rw_lock_release(&pcb->file_rw_lock, false);
  }
  else {
    // do nothing
  }
}
