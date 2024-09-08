#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

#define MAX_FILES 128


/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);



/* execution information */
struct execution_info {
  pid_t child_pid_; /* child process id */
  int exit_status_; /* exit status of process */
  struct semaphore ready_to_die_; /* up when the child exits */
  struct list_elem elem_; /* element of list */
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */

  /* fields for child processes */
  struct process* parent_; /* parent process */
  bool is_child_created_success_; /* true if new child is loaded successfully */
  struct semaphore exec_child_done_; /* up if loading work is  */
  struct list children_; /* children process of current process */
  struct list_elem elem_; /* element of children list */
  struct list child_exec_info_list_; /* list of children execution information */

  /* deny write for the running executable */
  struct file *executable_; /* executable of current process */ 
  

  /* fields for file descriptors */
  struct rw_lock file_rw_lock_; /* lock for fd hash array */
  struct file** open_files_; /* file hash array with MAX_FILES size */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
