#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "lib/round.h"
#include "threads/pte.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

void syscall_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

/*
 * This does not check that the buffer consists of only mapped pages; it merely
 * checks the buffer exists entirely below PHYS_BASE.
 */
static void validate_buffer_in_user_region(const void* buffer, size_t length) {
  uintptr_t delta = PHYS_BASE - buffer;
  if (!is_user_vaddr(buffer) || length > delta)
    syscall_exit(-1);
}

/*
 * This does not check that the string consists of only mapped pages; it merely
 * checks the string exists entirely below PHYS_BASE.
 */
static void validate_string_in_user_region(const char* string) {
  uintptr_t delta = PHYS_BASE - (const void*)string;
  if (!is_user_vaddr(string) || strnlen(string, delta) == delta)
    syscall_exit(-1);
}

static int syscall_open(const char* filename) {
  struct thread* t = thread_current();
  if (t->open_file != NULL)
    return -1;

  t->open_file = filesys_open(filename);
  if (t->open_file == NULL)
    return -1;

  return 2;
}

static int syscall_write(int fd, void* buffer, unsigned size) {
  struct thread* t = thread_current();
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  } else if (fd != 2 || t->open_file == NULL)
    return -1;

  return (int)file_write(t->open_file, buffer, size);
}

static int syscall_read(int fd, void* buffer, unsigned size) {
  struct thread* t = thread_current();
  if (fd != 2 || t->open_file == NULL)
    return -1;

  return (int)file_read(t->open_file, buffer, size);
}

static void syscall_close(int fd) {
  struct thread* t = thread_current();
  if (fd == 2 && t->open_file != NULL) {
    file_close(t->open_file);
    t->open_file = NULL;
  }
}

/* deallocate PAGE_CNT pages start from address UPAGE */
static void deallocate_multiple_pages(void* upage, size_t page_cnt) {
  struct thread* current_thread = thread_current();
  for (size_t offset = 0; offset < page_cnt; ++offset) {
    void *upage_mapped = (void*)((uint32_t)upage + offset * PGSIZE);
    void *kpage_mapped = pagedir_get_page(current_thread->pagedir, upage_mapped);
    if (kpage_mapped != NULL) {
      palloc_free_page(kpage_mapped);
      // set pte as 0 value indicating that the page is not present
      uint32_t *pde = (uint32_t*)current_thread->pagedir + pd_no(upage_mapped);
      uint32_t *pt = pde_get_pt(*pde);
      uint32_t *pte = pt + pt_no(upage_mapped);
      *pte = 0;
    }
  }
}

static void* syscall_sbrk(intptr_t increment) {
  // homework 4 memory
  struct thread* current_thread = thread_current();

  void* previous_brk = current_thread->brk_;
  if (increment == 0) {
    return previous_brk;
  }

  void* new_brk = (void*)((intptr_t)current_thread->brk_ + increment);

  // make sure the heap is located above the process's code and other data loaded from the executable
  if ((uint32_t)new_brk < (uint32_t)current_thread->start_of_heap_) {
    return (void*)-1;
  }


  // allocate memory if positive
  if (increment > 0) {
    // size_t page_cnt = (uint32_t)new_brk / PGSIZE - (uint32_t)previous_brk / PGSIZE;
    size_t page_cnt = (ROUND_UP((uint32_t)new_brk, PGSIZE) - ROUND_UP((uint32_t)previous_brk, PGSIZE)) / PGSIZE;
    for (size_t idx = 0; idx < page_cnt; ++idx) {
      void* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
      // undo previous page allocation if the user memory pool is exhausted
      if (kpage == NULL) {
        deallocate_multiple_pages((void*)ROUND_UP((uint32_t)previous_brk, PGSIZE), idx);
        return (void*)-1;
      }

      void* upage = (void*)(ROUND_UP((uint32_t)previous_brk, PGSIZE) + idx * PGSIZE);
      // undo previous page allocation if the user address has been mapped
      if (pagedir_get_page(current_thread->pagedir, upage) != NULL) {
        deallocate_multiple_pages((void*)ROUND_UP((uint32_t)previous_brk, PGSIZE), idx + 1);
        return (void*)-1;
      }

      // map the page into a virtual address space
      bool success = pagedir_set_page(current_thread->pagedir, upage, kpage, true);
      if (!success) {
        deallocate_multiple_pages((void*)ROUND_UP((uint32_t)previous_brk, PGSIZE), idx + 1);
        return (void*)-1;
      }
    }
  }
  // deallocate memory if negative
  else {
    // size_t page_cnt = (uint32_t)previous_brk / PGSIZE - (uint32_t)new_brk / PGSIZE;
    size_t page_cnt = (ROUND_UP((uint32_t)previous_brk, PGSIZE) - ROUND_UP((uint32_t)new_brk, PGSIZE)) / PGSIZE;
    deallocate_multiple_pages((void*)ROUND_UP((uint32_t)new_brk, PGSIZE), page_cnt);
  }

  current_thread->brk_ = new_brk;
  return previous_brk;
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = (uint32_t*)f->esp;
  struct thread* t = thread_current();
  t->in_syscall = true;

  validate_buffer_in_user_region(args, sizeof(uint32_t));
  switch (args[0]) {
    case SYS_EXIT:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      syscall_exit((int)args[1]);
      break;

    case SYS_OPEN:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      validate_string_in_user_region((char*)args[1]);
      f->eax = (uint32_t)syscall_open((char*)args[1]);
      break;

    case SYS_WRITE:
      validate_buffer_in_user_region(&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[2], (unsigned)args[3]);
      f->eax = (uint32_t)syscall_write((int)args[1], (void*)args[2], (unsigned)args[3]);
      break;

    case SYS_READ:
      validate_buffer_in_user_region(&args[1], 3 * sizeof(uint32_t));
      validate_buffer_in_user_region((void*)args[2], (unsigned)args[3]);
      f->eax = (uint32_t)syscall_read((int)args[1], (void*)args[2], (unsigned)args[3]);
      break;

    case SYS_CLOSE:
      validate_buffer_in_user_region(&args[1], sizeof(uint32_t));
      syscall_close((int)args[1]);
      break;
    
    case SYS_SBRK:
      validate_buffer_in_user_region(&args[1], sizeof(intptr_t));
      f->eax = (uint32_t)syscall_sbrk((intptr_t)args[1]);
      break;

    default:
      printf("Unimplemented system call: %d\n", (int)args[0]);
      break;
  }

  t->in_syscall = false;
}
