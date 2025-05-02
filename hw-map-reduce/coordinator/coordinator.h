/**
 * The MapReduce coordinator.
 */

#ifndef H1_H__
#define H1_H__
#include "../rpc/rpc.h"
#include "../lib/lib.h"
#include "../app/app.h"
#include "job.h"
#include <glib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef struct {
  /* TODO */
  int job_id_allocator_; // allocate unique job ID for every job submitted
  GList* map_work_list_;     // list of map works of all jobs
  GList* reduce_work_list_;     // list of reduce works of some job
  GHashTable* job_set_;  // set of info of jobs
} coordinator;

void coordinator_init(coordinator** coord_ptr);
#endif
