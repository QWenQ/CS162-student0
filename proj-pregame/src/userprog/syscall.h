#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdio.h"
#include "threads/vaddr.h"

#ifdef VM
#include "vm/page.h"
#endif

void syscall_init(void);

#endif /* userprog/syscall.h */
