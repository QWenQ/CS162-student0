#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* FPU */
#define SIZE_OF_FPU 108 /* length of state of FPU is 108 bytes */

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list fifo_ready_list;

// list of ready threads ordered by their priorities decreasingly
static struct list prio_ready_list = LIST_INITIALIZER(prio_ready_list);

/* multilevel feedback queue */
static struct list mlfq[PRI_MAX + 1];

/* a real number: the average number of threads ready to run over the past minute */
static fixed_point_t load_avg; 

/* number of threads either being running or ready excluding idle thread */
static int ready_and_running_threads;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread* idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread* initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame {
  void* eip;             /* Return address. */
  thread_func* function; /* Function to call. */
  void* aux;             /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4          /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

static void mlfqs_info_init(void);

static void init_thread(struct thread*, const char* name, int priority);
static bool is_thread(struct thread*) UNUSED;
static void* alloc_frame(struct thread*, size_t size);
static void schedule(void);
static void thread_enqueue(struct thread* t);
static tid_t allocate_tid(void);
void thread_switch_tail(struct thread* prev);

static void kernel_thread(thread_func*, void* aux);
static void idle(void* aux UNUSED);
static struct thread* running_thread(void);


static struct thread* next_thread_to_run(void);
static struct thread* thread_schedule_fifo(void);
static struct thread* thread_schedule_prio(void);
static struct thread* thread_schedule_fair(void);
static struct thread* thread_schedule_mlfqs(void);
static struct thread* thread_schedule_reserved(void);


static void check_if_reschedule_for_mlfqs(void);
static void update_all_threads_recent_cpu(void);
static void update_all_threads_priority(void);
static void update_load_avg(void);

/* Determines which scheduler the kernel should use.
   Controlled by the kernel command-line options
    "-sched=fifo", "-sched=prio",
    "-sched=fair". "-sched=mlfqs"
   Is equal to SCHED_FIFO by default. */
enum sched_policy active_sched_policy;

/* Selects a thread to run from the ready list according to
   some scheduling policy, and returns a pointer to it. */
typedef struct thread* scheduler_func(void);

/* Jump table for dynamically dispatching the current scheduling
   policy in use by the kernel. */
scheduler_func* scheduler_jump_table[8] = {thread_schedule_fifo,     thread_schedule_prio,
                                           thread_schedule_fair,     thread_schedule_mlfqs,
                                           thread_schedule_reserved, thread_schedule_reserved,
                                           thread_schedule_reserved, thread_schedule_reserved};


/* initialize multilevel feedback queue if THREAD_SCHEDULE_MLFQS schedule policy is on */
static void mlfqs_info_init(void) {
  if (active_sched_policy == SCHED_MLFQS) {
    for (int i = PRI_MIN; i <= PRI_MAX; ++i) {
      list_init(&mlfq[i]);
    }
    load_avg = fix_int(0);
  }
}

/* calculate thread's priority */
static void calculate_thread_priority_in_mlfqs(struct thread* t, void* aux UNUSED) {
  // priority = PRI_MAX - (1 / 4) * recent_cpu - 2 * nice;
  fixed_point_t fp_1_div_4 = fix_div(fix_int(1), fix_int(4));
  fixed_point_t fp_2 = fix_int(2);
  int new_priority = fix_round(fix_sub(fix_sub(fix_int(PRI_MAX), 
                                              fix_mul(fp_1_div_4, t->recent_cpu_)
                                              ), 
                                      fix_mul(fp_2, fix_int(t->nice_))
                                      )
                              );
  if (new_priority < PRI_MIN) {
    new_priority = PRI_MIN;
  }
  if (new_priority > PRI_MAX) {
    new_priority = PRI_MAX;
  }
  t->priority = new_priority;
}

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void) {
  ASSERT(intr_get_level() == INTR_OFF);

  lock_init(&tid_lock);
  list_init(&fifo_ready_list);
  mlfqs_info_init();
  list_init(&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread();
  init_thread(initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void) {
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init(&idle_started, 0);
  thread_create("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void) {
  struct thread* t = thread_current();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pcb != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return();
}

/* Prints thread statistics. */
void thread_print_stats(void) {
  printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks,
         user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char* name, int priority, thread_func* function, void* aux) {
  struct thread* t;
  struct kernel_thread_frame* kf;
  struct switch_entry_frame* ef;
  struct switch_threads_frame* sf;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page(PAL_ZERO);
  if (t == NULL) {
    // debug
    void;
    return TID_ERROR;
  }

  /* Initialize thread. */
  init_thread(t, name, priority);
  tid = t->tid = allocate_tid();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame(t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame(t, sizeof *ef);
  ef->eip = (void (*)(void))kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame(t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock(t);
  update_running_thread_if_prio_sche_on(t);

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void) {
  ASSERT(!intr_context());
  ASSERT(intr_get_level() == INTR_OFF);

  struct thread* cur_thread = thread_current();
  if (cur_thread != idle_thread) {
    --ready_and_running_threads;
  }

  cur_thread->status = THREAD_BLOCKED;
  // thread_current()->status = THREAD_BLOCKED;

  schedule();
}

/* insert a ready thread T into a ready list LIST ordered by thread's priority decreasingly */
static void insert_into_decreasing_list(struct list* list, struct thread* t) {
  struct list_elem* before = NULL;
  for (before = list_begin(list); before != list_end(list); before = list_next(before)) {
    struct thread* entry = list_entry(before, struct thread, elem);
    int entry_priority = get_effective_priority(entry);
    int t_priority = get_effective_priority(t); 
    if (entry_priority < t_priority) {
      break;
    }
  }

  list_insert(before, &t->elem);
}

/* Places a thread on the ready structure appropriate for the
   current active scheduling policy.
   
   This function must be called with interrupts turned off. */
static void thread_enqueue(struct thread* t) {
  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(is_thread(t));

  if (active_sched_policy == SCHED_FIFO)
    list_push_back(&fifo_ready_list, &t->elem);
  else if (active_sched_policy == SCHED_PRIO) {
    insert_into_decreasing_list(&prio_ready_list, t);
  }
  else if (active_sched_policy == SCHED_MLFQS) {
    int t_priority = get_effective_priority(t); 
    struct list* ready_list = &mlfq[t_priority];
    insert_into_decreasing_list(ready_list, t);
  }
  else
    PANIC("Unimplemented scheduling policy value: %d", active_sched_policy);
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread* t) {
  enum intr_level old_level;

  ASSERT(is_thread(t));

  old_level = intr_disable();
  ASSERT(t->status == THREAD_BLOCKED);
  thread_enqueue(t);
  t->status = THREAD_READY;
  if (t != idle_thread) {
    ++ready_and_running_threads;
  }
  intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char* thread_name(void) { return thread_current()->name; }

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread* thread_current(void) {
  struct thread* t = running_thread();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT(is_thread(t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void) { return thread_current()->tid; }

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void) {
  ASSERT(!intr_context());

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_switch_tail(). */
  intr_disable();
  list_remove(&thread_current()->allelem);
  thread_current()->status = THREAD_DYING;
  --ready_and_running_threads;
  schedule();
  NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void) {
  struct thread* cur = thread_current();
  enum intr_level old_level;

  ASSERT(!intr_context());

  old_level = intr_disable();
  if (cur != idle_thread)
    thread_enqueue(cur);
  cur->status = THREAD_READY;
  schedule();
  intr_set_level(old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void thread_foreach(thread_action_func* func, void* aux) {
  struct list_elem* e;

  ASSERT(intr_get_level() == INTR_OFF);

  for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e)) {
    struct thread* t = list_entry(e, struct thread, allelem);
    func(t, aux);
  }
}

/**
 * if new ready thread is prior than the running one, schedule the execution
 * @param t a new ready thread should be in ready list already
*/
void update_running_thread_if_prio_sche_on(struct thread* t) {
  if (active_sched_policy == SCHED_PRIO) {
    int t_priority = get_effective_priority(t);
    int cur_t_priority = thread_get_priority();
    if (t_priority > cur_t_priority) {
      thread_yield();
    }
  }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority) { 

  if (active_sched_policy == SCHED_MLFQS) return;

  struct thread* cur_thread = thread_current(); 
  cur_thread->priority = new_priority;

  // lowering thread's priority may cause the thread to immediately yield the CPU 
  // if the thread's priority is not highest after updated
  if (!list_empty(&prio_ready_list)) {
    struct thread* highest_prio_ready_thread = list_entry(list_front(&prio_ready_list), struct thread, elem);
    int cur_t_priority = thread_get_priority();
    int h_p_r_t_priority = get_effective_priority(highest_prio_ready_thread);
    if (h_p_r_t_priority > cur_t_priority) {
      thread_yield();
    }
  }
}

/* get effective priority of thread T */
int get_effective_priority(struct thread* t) {
  // return (t->donated_priority_ == -1) ? t->priority : t->donated_priority_;
  if (!list_empty(&t->donated_list_)) {
    struct list_elem* e = list_front(&t->donated_list_);
    struct donated_list_elem* donated_entry = list_entry(e, struct donated_list_elem, elem_);
    return donated_entry->donated_priority_;
  }
  return t->priority;
}

/* Returns the current thread's priority. */
int thread_get_priority(void) { 
  struct thread* cur_thread = thread_current();
  return get_effective_priority(cur_thread);
}

/* update donation PRIORITY along the donation chain associated with LOCK if the path exists */
static bool update_donated_priority_in_place(int priority, struct lock* lock) {
  ASSERT(intr_get_level() == INTR_OFF);
  bool success = false;

  struct thread* holder = lock->holder;
  struct list_elem* e = NULL;
  for (e = list_begin(&holder->donated_list_); e != list_end(&holder->donated_list_); e = list_next(e)) {
    struct donated_list_elem* donated_entry = list_entry(e, struct donated_list_elem, elem_);
    if (donated_entry->donated_lock_ == lock) {
      donated_entry->donated_priority_ = priority;
      success = true;
      break;
    }
  }
  return success;
}

/* create a new donation path for LOCK holder with new donation PRIORITY */
static void insert_new_donated_node(int priority, struct lock* lock) {
  ASSERT(intr_get_level() == INTR_OFF);
  struct thread* holder = lock->holder;

  struct donated_list_elem* new_donated_node = (struct donated_list_elem*)malloc(sizeof (struct donated_list_elem));
  new_donated_node->donated_lock_ = lock;
  new_donated_node->donated_priority_ = priority;

  struct list_elem* e = NULL;
  for (e = list_begin(&holder->donated_list_); e != list_end(&holder->donated_list_); e = list_next(e)) {
    struct donated_list_elem* donated_entry = list_entry(e, struct donated_list_elem, elem_);
    if (donated_entry->donated_priority_ < priority) {
      break;
    }
  }

  list_insert(e, &new_donated_node->elem_);
}

/* update donation PRIORITY along the donation chain associated with LOCK */
static void update_donated_priority(int priority, struct lock* lock) {
  bool success = update_donated_priority_in_place(priority, lock);
  if (!success) {
    insert_new_donated_node(priority, lock);
  }
}


/* donate PRIORITY associated with LOCK to the thread holding LOCK recursively */
void donate_priority(int priority, struct lock* lock) {
  ASSERT(intr_get_level() == INTR_OFF);
  // edge case
  // if ((lock == NULL) || (lock->holder->status != THREAD_BLOCKED)) return;
  if (lock == NULL) return;

  update_donated_priority(priority, lock);

  // update donated priority along the donation chain
  donate_priority(priority, lock->holder->blocked_on_lock_);
}

/* called after updating thread's priority and schedule if the running thread no longer has the highest priority */
static void check_if_reschedule_for_mlfqs(void) {
  struct thread* cur_thread = thread_current();
  enum intr_level old_level = intr_disable();
  for (int i = PRI_MAX; i > cur_thread->priority; --i) {
    if (!list_empty(&mlfq[i])) {
      thread_yield(); 
    }
  }
  intr_set_level(old_level);
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) { 
  /* Not yet implemented. */ 
  if (nice >= -20 && nice <= 20) {
    struct thread* cur_thread = thread_current();
    cur_thread->nice_ = nice;
    int old_priority = cur_thread->priority;
    // recalculate thread's priority
    calculate_thread_priority_in_mlfqs(cur_thread, NULL);
    // yield cpu if the thread no longer has the highest priority among the ready threads
    if (old_priority > cur_thread->priority) {
      check_if_reschedule_for_mlfqs();
    }
  }
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
  /* Not yet implemented. */
  return thread_current()->nice_;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
  /* Not yet implemented. */
  return fix_round(fix_scale(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
  /* Not yet implemented. */
  struct thread* cur_thread = thread_current();
  return fix_round(fix_scale(cur_thread->recent_cpu_, 100));
}

// update thread T's recent_cpu field
static void update_thread_recent_cpu(struct thread* t, void* aux UNUSED) {
    // recent_cpu = ((2 * load_avg) / (2 * load_avg + 1)) * recent_cpu + nice;
    t->recent_cpu_ = fix_add(fix_mul(fix_div(fix_scale(load_avg, 2), 
                                                      fix_add(fix_scale(load_avg, 2), fix_int(1))), 
                                              t->recent_cpu_), 
                                    fix_int(t->nice_));

}

/* update all threads' recent_cpu field on per second */
static void update_all_threads_recent_cpu(void) {
  thread_foreach(update_thread_recent_cpu, NULL);
}


/* update LOAD_AVG on per second */
static void update_load_avg(void) {
    // load_avg = (59 / 60) * load_avg + (1 / 60) * ready_and_running_threads;
    fixed_point_t fp_59_div_60 = fix_div(fix_int(59), fix_int(60));
    fixed_point_t fp_1_div_60 = fix_div(fix_int(1), fix_int(60));
    load_avg = fix_add(fix_mul(fp_59_div_60, load_avg), fix_mul(fp_1_div_60, fix_int(ready_and_running_threads)));
}


/* calculate thread's priority and place it in the right position of mlfq if thread is ready */
static void recalculate_priority_in_mlfqs(struct thread* t, void* aux UNUSED) {
  calculate_thread_priority_in_mlfqs(t, aux);
  if (t->status == THREAD_READY) {
    list_remove(&t->elem);
    list_push_back(&mlfq[t->priority], &t->elem);
  }
}

/* update all threads' priority on every four ticks */
static void update_all_threads_priority(void) {
  thread_foreach(recalculate_priority_in_mlfqs, NULL);
}

/* update multilevel feedback queue schdule data info during timer interrupt */
void update_mlfqs_info_if_mlfqs_on(int64_t ticks, int64_t timer_freq) {
  if (active_sched_policy == SCHED_MLFQS) {
    // called when TICKS is being updated
    ASSERT(intr_context());
    // on each timer tick
    struct thread* cur_thread = thread_current();
    cur_thread->recent_cpu_ = fix_add(cur_thread->recent_cpu_, fix_int(1));

    // update current thread's priority on every fourth clock ticks
    if (thread_ticks + 1 == TIME_SLICE) {
      update_all_threads_priority();
      if (idle_thread != NULL) {
        idle_thread->priority = PRI_MIN;
      }
    }

    // on per second
    if ((ticks % timer_freq) == 0) {
      update_load_avg();
      update_all_threads_recent_cpu();
    }
  }
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void idle(void* idle_started_ UNUSED) {
  struct semaphore* idle_started = idle_started_;
  idle_thread = thread_current();
  sema_up(idle_started);

  for (;;) {
    /* Let someone else run. */
    intr_disable();
    thread_block();

    /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
    asm volatile("sti; hlt" : : : "memory");
  }
}

/* Function used as the basis for a kernel thread. */
static void kernel_thread(thread_func* function, void* aux) {
  ASSERT(function != NULL);

  intr_enable(); /* The scheduler runs with interrupts off. */
  function(aux); /* Execute the thread function. */
  thread_exit(); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread* running_thread(void) {
  uint32_t* esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm("mov %%esp, %0" : "=g"(esp));
  return pg_round_down(esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool is_thread(struct thread* t) { return t != NULL && t->magic == THREAD_MAGIC; }

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void init_thread(struct thread* t, const char* name, int priority) {
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset(t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy(t->name, name, sizeof t->name);
  t->stack = (uint8_t*)t + PGSIZE;
  t->priority = priority;
  if (active_sched_policy == SCHED_MLFQS) {
    // calculate thread's priority with MLFQS method
    if (t == initial_thread) {
      t->nice_ = 0;
      t->recent_cpu_ = fix_int(0);
    }
    else {
      t->nice_ = thread_current()->nice_;
      t->recent_cpu_ = thread_current()->recent_cpu_;
    }
    calculate_thread_priority_in_mlfqs(t, NULL);
  }
  t->pcb = NULL;
  list_init(&t->donated_list_);
  t->blocked_on_lock_ = NULL;
  t->magic = THREAD_MAGIC;

  old_level = intr_disable();
  list_push_back(&all_list, &t->allelem);

  /* initialize user program fields */
  // default value
  t->exit_status_ = 0; 

  /* initialize user thread fields */
  t->p_user_stack_addr_ = NULL;

  intr_set_level(old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void* alloc_frame(struct thread* t, size_t size) {
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread(t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* First-in first-out scheduler */
static struct thread* thread_schedule_fifo(void) {
  if (!list_empty(&fifo_ready_list))
    return list_entry(list_pop_front(&fifo_ready_list), struct thread, elem);
  else
    return idle_thread;
}

/* Strict priority scheduler */
static struct thread* thread_schedule_prio(void) {
  // PANIC("Unimplemented scheduler policy: \"-sched=prio\"");
  struct thread* next_thread = idle_thread;

  if (!list_empty(&prio_ready_list)) {
    struct list_elem* e = list_pop_front(&prio_ready_list);
    next_thread = list_entry(e, struct thread, elem);
  }

  return next_thread;
}

/* Fair priority scheduler */
static struct thread* thread_schedule_fair(void) {
  PANIC("Unimplemented scheduler policy: \"-sched=fair\"");
}

/* Multi-level feedback queue scheduler */
static struct thread* thread_schedule_mlfqs(void) {
  // PANIC("Unimplemented scheduler policy: \"-sched=mlfqs\"");
  struct thread* next_thread = idle_thread;
  for (int i = PRI_MAX; i >= PRI_MIN; --i) {
    if (list_empty(&mlfq[i])) continue;
    struct list_elem* e = list_pop_front(&mlfq[i]);
    next_thread = list_entry(e, struct thread, elem);
    break;
  }

  return next_thread;
}

/* Not an actual scheduling policy — placeholder for empty
 * slots in the scheduler jump table. */
static struct thread* thread_schedule_reserved(void) {
  PANIC("Invalid scheduler policy value: %d", active_sched_policy);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread* next_thread_to_run(void) {
  return (scheduler_jump_table[active_sched_policy])();
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_switch() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void thread_switch_tail(struct thread* prev) {
  struct thread* cur = running_thread();

  ASSERT(intr_get_level() == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) {
    ASSERT(prev != cur);
    palloc_free_page(prev);
  }
}

/* Schedules a new thread.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_switch_tail()
   has completed. */
static void schedule(void) {
  struct thread* cur = running_thread();
  struct thread* next = next_thread_to_run();
  struct thread* prev = NULL;

  ASSERT(intr_get_level() == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread(next));

  // store state of fpu of old thread
  uint8_t fpu[SIZE_OF_FPU];
  asm volatile(
    "fsave %0" 
    : "=m"(*fpu) 
    : 
    : "memory"
  );

  if (cur != next)
    prev = switch_threads(cur, next);
  thread_switch_tail(prev);
  
  // restore state of fpu of new thread
  asm volatile(
    "frstor %0"
    :
    : "m"(*fpu)
    : "memory"
  );
}

/* Returns a tid to use for a new thread. */
static tid_t allocate_tid(void) {
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire(&tid_lock);
  tid = next_tid++;
  lock_release(&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
