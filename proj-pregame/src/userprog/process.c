#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


// static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp, void* arg);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  // main thread has no parent
  t->pcb->parent_ = NULL;

  // initialize list of child processes
  list_init(&t->pcb->children_);
  list_init(&t->pcb->child_exec_info_list_);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  char* just_file_name;
  tid_t tid;

  // sema_init(&temporary, 0);
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;

  // get length of the file name
  size_t file_name_length = 0;
  while (file_name[file_name_length] != ' ') {
    ++file_name_length;
  }
  just_file_name = (char*)malloc(file_name_length + 1);
  // just_file_name = palloc_get_page(0);
  if (just_file_name == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  memcpy(just_file_name, file_name, file_name_length);
  just_file_name[file_name_length] = '\0';

  strlcpy(fn_copy, file_name, PGSIZE);

  // pass struct process of the parent into the child
  struct thread* current_thread = thread_current();
  struct process* current_process = current_thread->pcb;
  memcpy((void*)(fn_copy + PGSIZE - sizeof(struct process*)), (const void*)&current_process, sizeof(struct process*));

  sema_init(&current_process->exec_child_done_, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(just_file_name, PRI_DEFAULT, start_process, fn_copy);

  free(just_file_name);
  
  if (tid != TID_ERROR) {
    /* parent waits until the child has done its loading */
    sema_down(&current_process->exec_child_done_);
    if (!current_process->is_child_created_success_) {
      tid = TID_ERROR;
      // palloc_free_page(fn_copy);
    }
  }
  
  return tid;
}

/* A thread function that loads a user process and starts it running. */
static void start_process(void* file_name_) {
  // file_name containing all command-line args passed to the main()
  char* file_name = (char*)file_name_;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = (struct process*)malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    memcpy((void*)&new_pcb->parent_, (const void*)(file_name_ + PGSIZE - sizeof(struct process*)), sizeof(struct process*));
    list_init(&new_pcb->children_);
    list_init(&new_pcb->child_exec_info_list_);
    
    // Initializing the open file hash array in the new pcb
    rw_lock_init(&(new_pcb->file_rw_lock_));
    new_pcb->open_files_ = calloc(sizeof(struct file*), MAX_FILES);

    // initialize user thread fields
    lock_init(&(new_pcb->lock_on_cnt_));
    cond_init(&(new_pcb->cond_on_cnt));
    new_pcb->pthread_unadded_cnt_ = 0;
    rw_lock_init(&(new_pcb->lock_on_pthreads_list_));
    list_init(&(new_pcb->pthreads_list_));

    struct pthread_meta* meta = (struct pthread_meta*)malloc(sizeof(struct pthread_meta));
    meta->thread_id_ = t->tid;
    lock_init(&(meta->p_lock_));
    cond_init(&(meta->p_cond_));
    meta->p_is_died_ = false;
    meta->p_has_been_joined_ = false;

    list_push_front(&(new_pcb->pthreads_list_), &(meta->p_elem_));

    // list_push_front(&(new_pcb->pthreads_list_), &(t->p_elem_));

    rw_lock_init(&(new_pcb->rw_on_locks_));
    rw_lock_init(&(new_pcb->rw_on_semas_));
    uint64_t* allocated_page = (uint64_t*)palloc_get_page(PAL_ZERO | PAL_ASSERT);
    new_pcb->locks_ = (struct lock*)allocated_page;
    new_pcb->semas_ = (struct semaphore*)(allocated_page + USER_LOCK_SIZE);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);
  }

  palloc_free_page(file_name);

  // update children list of the parent if the child(current) run successes
  if (success) {
    // add a new child execution info into the list in the parent
    if (new_pcb->parent_) {
      struct execution_info *child_exec_info = (struct execution_info*)malloc(sizeof(struct execution_info));
      if (child_exec_info != NULL) {
        child_exec_info->child_pid_ = new_pcb->main_thread->tid;
        sema_init(&child_exec_info->ready_to_die_, 0);

        list_push_back(&new_pcb->parent_->child_exec_info_list_, &child_exec_info->elem_);
        list_push_back(&new_pcb->parent_->children_, &new_pcb->elem_);
      }
      else {
        success = false;
      }
    }
  }

  new_pcb->parent_->is_child_created_success_ = success;
  sema_up(&new_pcb->parent_->exec_child_done_);


  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    if (pcb_to_free->executable_) {
      file_close(pcb_to_free->executable_);
    }
    free(pcb_to_free->open_files_);
    free(pcb_to_free);
  }


  /* Clean up. Exit on failure or jump to userspace */
  // palloc_free_page(file_name);
  if (!success) {
    // sema_up(&temporary);
    thread_exit();
  }



  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid UNUSED) {
  // sema_down(&temporary);
  struct thread* current_thread = thread_current();
  struct process* current_process = current_thread->pcb;

  struct list_elem *e = NULL;
  struct execution_info *child_exec_info = NULL;
  struct list *child_exec_info_list = &current_process->child_exec_info_list_;
  for (e = list_begin(child_exec_info_list); e != list_end(child_exec_info_list); e = list_next(e)) {
    child_exec_info = list_entry(e, struct execution_info, elem_);
    if (child_exec_info->child_pid_ == child_pid) {
      break;
    }
    child_exec_info = NULL;
  }

  if (child_exec_info == NULL) {
    return -1;
  }

  // wait until the child with CHILD_PID exits
  sema_down(&child_exec_info->ready_to_die_);

  int child_exit_status = child_exec_info->exit_status_;

  // delete execution info of the child
  list_remove(e);
  free(child_exec_info);

  return child_exit_status;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  // update the exit status to the parent
  struct process *cur_process = cur->pcb;
  struct process *parent = cur_process->parent_;
  if (parent) {
    struct list_elem *e = NULL;
    for (e = list_begin(&parent->child_exec_info_list_); e != list_end(&parent->child_exec_info_list_); e = list_next(e)) {
      struct execution_info *exec_info = list_entry(e, struct execution_info, elem_);
      if (exec_info->child_pid_ == cur->tid) {
        exec_info->exit_status_ = cur->exit_status_;
        sema_up(&(exec_info->ready_to_die_));
        break;
      }
    }
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* disconnect the connection between parent and its children */
  struct list_elem *e = NULL;
  for (e = list_begin(&cur->pcb->children_); e != list_end(&cur->pcb->children_); e = list_next(e)) {
    struct process *child = list_entry(e, struct process, elem_);
    // todo: should this be sychronized with other tasks?
    child->parent_ = NULL;
  }

  while (!list_empty(&cur->pcb->child_exec_info_list_)) {
    e = list_pop_front(&cur->pcb->child_exec_info_list_);
    struct execution_info *exec_info = list_entry(e, struct execution_info, elem_);
    free(exec_info);
  }

  // delete child(current process) from its parent
  if (cur->pcb->parent_) {
    struct list *children_from_parent = &cur->pcb->parent_->children_;
    for (e = list_begin(children_from_parent); e != list_end(children_from_parent); e = list_next(e)) {
      struct process *child = list_entry(e, struct process, elem_);
      if (child->main_thread->tid == cur->tid) {
        list_remove(e);
        break;
      }
    }
  }


  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;

  if (pcb_to_free->executable_) {
    file_close(pcb_to_free->executable_);
  }

  // close open files and free open file array
  for (size_t i = 2; i < MAX_FILES; ++i) {
    if (pcb_to_free->open_files_[i]) {
      file_close(pcb_to_free->open_files_[i]);
    }
  }

  // free user locks and semaphores
  for (int i = 0; i < USER_LOCK_SIZE; ++i) {
    free(pcb_to_free->locks_[i]);
    free(pcb_to_free->semas_[i]);
  }

  palloc_free_page((void*)pcb_to_free->locks_);

  free(pcb_to_free->open_files_);
  free(pcb_to_free);


  // sema_up(&temporary);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();
  
  /**
   * parse command-line arguments in the FILE_NAME argument
   * 1. break the command in to words;
   * 2. place the words at the top of the stack and store their address in right-to-left order;
   * 3. load ELF executable from real file name parsed above;
   * 4. 16-byte alignment and push address of words into the statck in right-to-left order;
   * 5. push a fake return address into the stack;
   * 
  */



  // 1. break the command line into words
  size_t command_nums = 0;
  bool new_command = true;
  size_t command_length = strlen(file_name);
  char *command_line = (char*)file_name;
  while (*command_line != '\0') {
    if (*command_line == ' ') {
      *command_line = '\0';
      new_command = true;
    }
    else {
      if (new_command) {
        ++command_nums;
        new_command = false;
      }
    }
    ++command_line;
  }

  
  // 3. load ELF executable from real file name parsed above;
  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  // record main thread's user stack address
  t->p_user_stack_addr_ = (uint8_t*)(PHYS_BASE - PGSIZE);
  
  {
    // 2. place the words at the top of the stack and store their address in right-to-left order;
    command_line = PHYS_BASE -command_length - 1; 
    memcpy(command_line, file_name, command_length + 1);

    // 0xc0000000(PHYS_BASE)
    // argv[n - 1][...]
    // ... 
    // argv[1][...]
    // argv[0][...]  file_name          char[?] 
    // stack_align                      uint8_t
    // argv[n]        0
    // ....
    // argv[1]        ...                 char*
    // argv[0]        &argv[0][...]     char*
    // argv           &argv[0]          char**
    // argc           1                 int     the address here should be like 0xXXXXXXX0 -> 16-byte alignment at this point 
    // (fake)return address 0                 void(*)()

    // 4. 16-byte alignment and push address of words into the statck in right-to-left order;
    // 4.1 16-byte alignment
    size_t stack_align_bytes = 0;
    size_t command_bytes_used_in_stack = command_length + 1 + (command_nums + 3) * sizeof(char*);
    if((command_bytes_used_in_stack % 16) != 0) {
      stack_align_bytes = 16 - (command_bytes_used_in_stack % 16);
      command_bytes_used_in_stack += stack_align_bytes;
    }
    *esp -= (command_length + stack_align_bytes + 1);
    if (stack_align_bytes != 0) {
      memset(*esp, 0, stack_align_bytes);
    }

    // 4.2 push address of words into stack in right-to-left order

    // store args' address in the local buffer
    const size_t args_nums = command_nums + 1;

    char* args_add[args_nums];

    memset(args_add, 0, args_nums * sizeof(char*));
    new_command = true;
    while (command_line != PHYS_BASE) {
      if (*command_line != '\0') {
        if (new_command) {
          args_add[command_nums] = command_line;
          --command_nums;
          new_command = false;
        }
      }
      else {
        // expect next command arg string
        new_command = true;
      }
      ++command_line;
    }

    // push args' address into the stack in the right-to-left order
    for (size_t idx = 0; idx < args_nums; ++idx) {
      *esp -= sizeof(char*);
      *(int*)(*esp) = (int)args_add[idx];
    }

    // push argv and argc into the stack
    char* argv = *esp;
    *esp -= sizeof(char*);
    *(int*)(*esp) = (int)argv;

    *esp -= sizeof(int);
    *(int*)(*esp) = args_nums - 1;

    // debug
    // printf("%p\n", *esp);
    // hex_dump(0, *esp, command_bytes_used_in_stack, true);

    // 5. push a fake return address into the stack;
    *esp -= sizeof(0);
    *(int*)(*esp) = 0;

    /* Start address. */
    *eip = (void (*)(void))ehdr.e_entry;

    success = true;
  }

  file_deny_write(file);

done:
  /* We arrive here whether the load is successful or not. */
  if (!success && file) {
    file_close(file);
    file = NULL;
  }
  struct thread *cur_thread = thread_current();
  cur_thread->pcb->executable_ = file;
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp UNUSED, void* arg) { 
  uint64_t* array = (uint64_t*)arg;
  stub_fun sfun = (stub_fun)array[0];
  pthread_fun tfun = (pthread_fun)array[1];
  void* tfun_arg = (void*)array[2];
  bool success = false;
  uint32_t start = PHYS_BASE;
  uint8_t* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL) return false;
  // allocate a new user-level stack from PYHS_BASE downwards and set the args
  while (start > PGSIZE) {
    success = install_page((uint8_t*)(start - PGSIZE), kpage, true);
    if (success) {
      struct thread* cur_thread = thread_current();
      cur_thread->p_user_stack_addr_ = (uint8_t*)(start - PGSIZE);
      // push args of SFUN
      // void _pthread_start_stub(pthread_fun fun, void* arg)
      uint32_t* sp = (uint32_t*)start;
      --sp;
      *sp = tfun_arg;
      --sp;
      *sp = tfun;
      --sp;
      *sp = NULL;
      *esp = sp;

      *eip = (void (*)(void))sfun;
      break;
    }
    start -= PGSIZE;
  }
  
  if (!success) {
    palloc_free_page(kpage);
  }
  return success; 
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf UNUSED, pthread_fun tf UNUSED, void* arg UNUSED) { 
  // if the main thread is going to die, the create behavior is forbidden
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;
  tid_t main_tid = pcb->main_thread->tid;
  struct list_elem* e = NULL;
  struct pthread_meta* meta = NULL;
  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), true);
  for (e = list_begin(&(pcb->pthreads_list_)); e != list_end(&(pcb->pthreads_list_)); e = list_next(e)) {
    meta = list_entry(e, struct pthread_meta, p_elem_);
    if (meta->thread_id_ == main_tid) break;
  }
  rw_lock_release(&(pcb->lock_on_pthreads_list_), true);
  if (e == list_end(&(pcb->pthreads_list_))) return TID_ERROR;
  bool is_process_dying = false;
  lock_acquire(&(meta->p_lock_));
  is_process_dying = meta->p_is_died_;
  lock_release(&(meta->p_lock_));
  if (is_process_dying) return TID_ERROR;
  

  int bytes = sizeof(stub_fun) + sizeof(pthread_fun) + sizeof(void*) + sizeof(struct process*);
  uint64_t* sp_args = (uint64_t*)palloc_get_page(PAL_ZERO | PAL_USER);
  if (sp_args == NULL) return TID_ERROR;
  sp_args[0] = sf;
  sp_args[1] = tf;
  sp_args[2] = arg;
  sp_args[3] = pcb;
  lock_acquire(&(pcb->lock_on_cnt_));
  ++pcb->pthread_unadded_cnt_;
  lock_release(&(pcb->lock_on_cnt_));
  tid_t tid = thread_create("", PRI_DEFAULT, start_pthread, (void*)sp_args);
  if (tid == TID_ERROR) {
    lock_acquire(&(pcb->lock_on_cnt_));
    --pcb->pthread_unadded_cnt_;
    lock_release(&(pcb->lock_on_cnt_));
  }
  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_ UNUSED) {
  // set user thread's PCB 
  struct process* pcb = (struct process*)(*((uint64_t*)exec_ + 3));
  struct thread* cur_thread = thread_current();
  cur_thread->pcb = pcb;

  // activate page directory
  process_activate();

  // struct intr_frame
  struct intr_frame if_;
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  bool success = setup_thread(&(if_.eip), &(if_.esp), exec_);
  palloc_free_page(exec_);

  if (!success) {
    pthread_exit();
    NOT_REACHED();
  }

  
  // create a meta info of new thread
  struct pthread_meta* new_meta = (struct pthread_meta*)malloc(sizeof(struct pthread_meta));
  if (new_meta == NULL) {
    pthread_exit();
    NOT_REACHED();
  }
  new_meta->thread_id_ = cur_thread->tid;
  lock_init(&(new_meta->p_lock_));
  cond_init(&(new_meta->p_cond_));
  new_meta->p_is_died_ = false;
  new_meta->p_has_been_joined_ = false;

  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), false);
  // add itself to the list of threads in the PCB
  list_push_front(&(pcb->pthreads_list_), &(new_meta->p_elem_));

  lock_acquire(&(pcb->lock_on_cnt_));
  --pcb->pthread_unadded_cnt_;
  if (pcb->pthread_unadded_cnt_ <= 0) {
    cond_broadcast(&(pcb->cond_on_cnt), &(pcb->lock_on_cnt_));
  }
  lock_release(&(pcb->lock_on_cnt_));

  rw_lock_release(&(pcb->lock_on_pthreads_list_), false);


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) { 
  struct thread* cur_thread = thread_current();
  // join self is illegal
  if (tid == cur_thread->tid) return TID_ERROR;

  struct process* pcb = cur_thread->pcb;
  if (pcb == NULL) return TID_ERROR;

  lock_acquire(&(pcb->lock_on_cnt_));
  while (pcb->pthread_unadded_cnt_ > 0) {
    cond_wait(&(pcb->cond_on_cnt), &(pcb->lock_on_cnt_));
  }
  lock_release(&(pcb->lock_on_cnt_));

  // valid join: thread was spawned in the same process and has not been waited on yet.
  struct list_elem* e = NULL;
  // struct thread* joined_thread = NULL;
  struct pthread_meta* meta = NULL;
  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), true);
  for (e = list_begin(&(pcb->pthreads_list_)); e != list_end(&(pcb->pthreads_list_)); e = list_next(e)) {
    meta = list_entry(e, struct pthread_meta, p_elem_);
    if (meta->thread_id_ == tid) {
      break;
    }
  }
  rw_lock_release(&(pcb->lock_on_pthreads_list_), true);
  if (e == list_end(&(pcb->pthreads_list_))) return TID_ERROR;

  lock_acquire(&(meta->p_lock_));
  if (!meta->p_has_been_joined_) {
    meta->p_has_been_joined_ = true;
    // wait until the joined thread is died
    while (!meta->p_is_died_) {
      cond_wait(&(meta->p_cond_), &(meta->p_lock_));
    }
  }
  else {
    tid = TID_ERROR;
  }
  lock_release(&(meta->p_lock_));

  return tid; 
}


// update current state to die state and wake up all user threads joined on it 
static void wakeUpAllWaitedThreads(void) {
  struct thread* cur_thread = thread_current();
  struct process* pcb = cur_thread->pcb;


  // deallocate its user stack
  void* kpage = pagedir_get_page(pcb->pagedir, cur_thread->p_user_stack_addr_);
  pagedir_clear_page(pcb->pagedir, cur_thread->p_user_stack_addr_);
  if (kpage != NULL) {
    palloc_free_page(kpage);
  }
  cur_thread->p_user_stack_addr_ = NULL;

  
  struct list_elem* e = NULL;
  struct pthread_meta* meta = NULL;
  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), true);
  for (e = list_begin(&(pcb->pthreads_list_)); e != list_end(&(pcb->pthreads_list_)); e = list_next(e)) {
    meta = list_entry(e, struct pthread_meta, p_elem_);
    if (meta->thread_id_ == cur_thread->tid) {
      break;
    }
  }
  rw_lock_release(&(pcb->lock_on_pthreads_list_), true);
  if (e == list_end(&(pcb->pthreads_list_))) {
    thread_exit();
    NOT_REACHED();
  };


  lock_acquire(&(meta->p_lock_));
  // update current thread's state to die
  meta->p_is_died_ = true;
  // wake up all waited threads
  cond_broadcast(&(meta->p_cond_), &(meta->p_lock_));
  lock_release(&(meta->p_lock_)); 
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  wakeUpAllWaitedThreads();
  
  thread_exit();
  NOT_REACHED();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {

  wakeUpAllWaitedThreads();

  // The main thread should wait on all threads in the process to terminate properly, before exiting itself.
  struct thread* main_thread = thread_current();
  struct process* pcb = main_thread->pcb;
  struct list_elem* e = NULL;
  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), true);
  for (e = list_begin(&(pcb->pthreads_list_)); e != list_end(&(pcb->pthreads_list_)); e = list_next(e)) {
    struct pthread_meta* meta = list_entry(e, struct pthread_meta, p_elem_);
    pthread_join(meta->thread_id_);
  }
  rw_lock_release(&(pcb->lock_on_pthreads_list_), true);

  // free all user threads' kernel stack except the main's kernel stack
  // note: at this point, all user threads but the main have been died, so no concurrency will happen
  rw_lock_acquire(&(pcb->lock_on_pthreads_list_), false);
  while (!list_empty(&(pcb->pthreads_list_))) {
    e = list_begin(&(pcb->pthreads_list_));
    list_remove(e);
    struct pthread_meta* meta = list_entry(e, struct pthread_meta, p_elem_);
    free(meta);
  }
  rw_lock_release(&(pcb->lock_on_pthreads_list_), false);

  process_exit();
}
