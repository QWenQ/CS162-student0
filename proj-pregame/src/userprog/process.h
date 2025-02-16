#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

#define MAX_FILES 128

#define USER_LOCK_SIZE (1 << 8)
#define USER_SEMAPHORE_SIZE (1 << 8)

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);


/* metadata of user threads in the same process */
struct pthread_meta {
  tid_t thread_id_; // user thread's id

  struct lock p_lock_; // lock if visit P_HAS_BEEN_JOINED_
  struct condition p_cond_; // broadcast if the thread is going be dying
  bool p_is_died_; // true if the thread is died
  bool p_has_been_joined_; // true if other user threads join on the thread

  struct list_elem p_elem_; // manage user thread in PCB
};


/* process execution fields */
struct process_meta {
  pid_t pid_; // the pid of execution info of ower process
  pid_t parent_pid_; // ower's parent's pid
  struct lock lock_; // lock on process' state
  struct condition cond_; // wait if IS_ALIVE_ is true
  bool is_alive_; // true if the process is running
  bool has_been_waited_; // true if the process has been waited
  int exit_code_; // exit status of process
  struct list_elem p_s_elem_; // use in PROCESS_STATE_LIST
};


/* execution information */
// struct execution_info {
//   pid_t child_pid_; /* child process id */
//   int exit_status_; /* exit status of process */

//   struct semaphore ready_to_die_; /* up when the child exits */
//   struct lock lock_; /* locked before visiting IS_DIED_ */
//   struct condition cond_; /* signal all if the process is dead */
//   bool is_died_; /* true if the child is dead */

//   struct list_elem elem_; /* element of list */
// };

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
  // struct process* parent_; /* parent process */
  // bool is_child_created_success_; /* true if new child is loaded successfully */
  // struct semaphore exec_child_done_; /* up if loading work is done */
  // struct list children_; /* children process of current process */
  // struct list_elem elem_; /* element of children list */
  // struct list child_exec_info_list_; /* list of children execution information */

  /* deny write for the running executable */
  struct file *executable_; /* executable of current process */ 
  

  /* fields for file descriptors */
  struct rw_lock file_rw_lock_; /* lock for fd hash array */
  struct file** open_files_; /* file hash array with MAX_FILES size */
  
  /* user threads fields */
  struct lock lock_on_cnt_; // lock when visit PTHREAD_UNADDED_CNT_;
  struct condition cond_on_cnt; // broadcast if PTHREAD_UNADDED_CNT_ is 0;
  int pthread_unadded_cnt_; // number of user threads created but not added to the PTHREADS_LIST_ yet 

  struct rw_lock lock_on_pthreads_list_; // lock on PTHREADS_LIST_
  struct list pthreads_list_; // user threads created in the process

  struct rw_lock rw_on_locks_;
  struct lock** locks_; // 256 struct lock pointers

  struct rw_lock rw_on_semas_;
  struct semaphore** semas_; // 256 struct semaphore pointers
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
