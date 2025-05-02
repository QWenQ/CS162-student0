/**
 * The MapReduce coordinator.
 */

#include "coordinator.h"

#ifndef SIG_PF
#define SIG_PF void (*)(int)
#endif


typedef struct {
  int job_id_;
  int map_task_id_;
  bool is_being_processed_;
  path file_;
  char* app_;
  int n_reduce_;
	struct {
		u_int args_len_;
		char *args_val_;
	} args_;
} map_fn_info;

typedef struct {
  int job_id_;
  int reduce_task_id_;
  bool is_being_processed_;
  char* app_;
  path output_dir_;
  int n_map_;
	struct {
		u_int args_len_;
		char *args_val_;
	} args_;
} reduce_fn_info;

typedef struct {
  int job_id_;
  int n_map_;
  char* app_;
  path output_dir_;
	struct {
		u_int args_len_;
		char *args_val_;
	} args_;
} reduce_meta;

/* work execution info of a submitted job */
typedef struct {
  int map_fns_left_;
  int reduce_fns_left_;
  reduce_meta* reduce_meta_;
} submitted_job_info;

/* Global coordinator state. */
coordinator* state;

extern void coordinator_1(struct svc_req*, SVCXPRT*);

/* Set up and run RPC server. */
int main(int argc, char** argv) {
  register SVCXPRT* transp;

  pmap_unset(COORDINATOR, COORDINATOR_V1);

  transp = svcudp_create(RPC_ANYSOCK);
  if (transp == NULL) {
    fprintf(stderr, "%s", "cannot create udp service.");
    exit(1);
  }
  if (!svc_register(transp, COORDINATOR, COORDINATOR_V1, coordinator_1, IPPROTO_UDP)) {
    fprintf(stderr, "%s", "unable to register (COORDINATOR, COORDINATOR_V1, udp).");
    exit(1);
  }

  transp = svctcp_create(RPC_ANYSOCK, 0, 0);
  if (transp == NULL) {
    fprintf(stderr, "%s", "cannot create tcp service.");
    exit(1);
  }
  if (!svc_register(transp, COORDINATOR, COORDINATOR_V1, coordinator_1, IPPROTO_TCP)) {
    fprintf(stderr, "%s", "unable to register (COORDINATOR, COORDINATOR_V1, tcp).");
    exit(1);
  }

  coordinator_init(&state);

  svc_run();
  fprintf(stderr, "%s", "svc_run returned");
  exit(1);
  /* NOTREACHED */
}

/* EXAMPLE RPC implementation. */
int* example_1_svc(int* argp, struct svc_req* rqstp) {
  static int result;

  result = *argp + 1;

  return &result;
}

/* SUBMIT_JOB RPC implementation. */
int* submit_job_1_svc(submit_job_request* argp, struct svc_req* rqstp) {
  static int result;

  printf("Received submit job request\n");

  /* TODO */
  result = -1;
  app ap = get_app(argp->app);
  if (ap.name != NULL) {
    submitted_job_info* info = (submitted_job_info*)malloc(sizeof(submitted_job_info));
    if (info) {
      info->reduce_meta_ = (reduce_meta*)malloc(sizeof (reduce_meta));
      if (info->reduce_meta_ == NULL) {
        free(info);
      }
      else {
        info->map_fns_left_ = argp->files.files_len;
        info->reduce_fns_left_ = argp->n_reduce;
        result = state->job_id_allocator_;
        state->job_id_allocator_++;
        info->reduce_meta_->job_id_ = result;
        info->reduce_meta_->n_map_ = argp->files.files_len;
        info->reduce_meta_->app_ = argp->app;
        info->reduce_meta_->output_dir_ = argp->output_dir;
        info->reduce_meta_->args_.args_len_ = argp->args.args_len;
        info->reduce_meta_->args_.args_val_ = argp->args.args_val;
        


        // add info to hash table
        g_hash_table_insert(state->job_set_, GINT_TO_POINTER(result), info);


        // add map works to list and reduce works will be added when all the job's map works are done
        for (int i = 0; i < info->map_fns_left_; ++i) {
          map_fn_info* map_info = (map_fn_info*)malloc(sizeof (map_fn_info));
          map_info->job_id_ = result;
          map_info->map_task_id_ = i;
          map_info->is_being_processed_ = false;
          map_info->file_ = argp->files.files_val[i];
          map_info->app_ = argp->app;
          map_info->n_reduce_ = argp->n_reduce;
          map_info->args_.args_len_ = argp->args.args_len;
          map_info->args_.args_val_ = argp->args.args_val;
          state->map_work_list_ = g_list_append(state->map_work_list_, map_info);
        }
      }
    }
  }


  /* Do not modify the following code. */
  /* BEGIN */
  struct stat st;
  if (stat(argp->output_dir, &st) == -1) {
    mkdirp(argp->output_dir);
  }

  return &result;
  /* END */
}

/* POLL_JOB RPC implementation. */
poll_job_reply* poll_job_1_svc(int* argp, struct svc_req* rqstp) {
  static poll_job_reply result;

  printf("Received poll job request\n");

  /* TODO */
  // initialization
  result.done = false;
  result.failed = false;
  result.invalid_job_id = false;

  submitted_job_info* info = g_hash_table_lookup(state->job_set_, GINT_TO_POINTER(*argp));
  if (info == NULL) {
    result.invalid_job_id = true;
  }
  else {
    if ((info->map_fns_left_ <= 0) && (info->reduce_fns_left_ <= 0)) {
      result.done = true;
    }
    // todo: fail case
  }



  return &result;
}

/* GET_TASK RPC implementation. */
get_task_reply* get_task_1_svc(void* argp, struct svc_req* rqstp) {
  static get_task_reply result;

  printf("Received get task request\n");
  result.file = "";
  result.output_dir = "";
  result.app = "";
  result.wait = true;
  result.args.args_len = 0;

  /* TODO */
  bool get_task = false;
  // first, check if any reduce task need to be done
  for (GList* elem = state->reduce_work_list_; elem; elem = elem->next) {
    reduce_fn_info* info = elem->data;
    if (!info->is_being_processed_) {
      result.job_id = info->job_id_;
      result.task = info->reduce_task_id_;
      result.output_dir = info->output_dir_;
      result.app = info->app_;
      result.n_map = info->n_map_;
      result.reduce = true;
      result.wait = false;
      result.args.args_len = info->args_.args_len_;
      result.args.args_val = info->args_.args_val_;

      info->is_being_processed_ = true;
      get_task = true;
      break;
    }
  }

  // second, if no reduce task, try to get map task
  if (!get_task) {
    for (GList* elem = state->map_work_list_; elem; elem = elem->next) {
      map_fn_info* info = elem->data;
      if (!info->is_being_processed_) {
        result.job_id = info->job_id_;
        result.task = info->map_task_id_;
        result.file = info->file_;
        result.app = info->app_;
        result.n_reduce = info->n_reduce_;
        result.reduce = false;
        result.wait = false;
        result.args.args_len = info->args_.args_len_;
        result.args.args_val = info->args_.args_val_;

        info->is_being_processed_ = true;
        get_task = true;
        break;
      }
    }
  }

  return &result;
}

/* FINISH_TASK RPC implementation. */
void* finish_task_1_svc(finish_task_request* argp, struct svc_req* rqstp) {
  static char* result;

  printf("Received finish task request\n");

  /* TODO */

  // handle reduce task else map task
  if (argp->reduce) {
    for (GList* elem = state->reduce_work_list_; elem; elem = elem->next) {
      reduce_fn_info* info = elem->data;
      if ((info->job_id_ == argp->job_id) && (info->reduce_task_id_ == argp->task)) {
        submitted_job_info* job_info = g_hash_table_lookup(state->job_set_, GINT_TO_POINTER(argp->job_id));
        if (argp->success) {
          job_info->reduce_fns_left_--;
          state->reduce_work_list_ = g_list_remove(state->reduce_work_list_, info);
        }
        else {
          info->is_being_processed_ = false;
        }
        break;
      }
    }
  }
  else {
    for (GList* elem = state->map_work_list_; elem; elem = elem->next) {
      map_fn_info* info = elem->data;
      if ((info->job_id_ == argp->job_id) && (info->map_task_id_ == argp->task)) {
        submitted_job_info* job_info = g_hash_table_lookup(state->job_set_, GINT_TO_POINTER(argp->job_id));
        if (argp->success) {
          job_info->map_fns_left_--;
          state->map_work_list_ = g_list_remove(state->map_work_list_, info);
        }
        else {
          info->is_being_processed_ = false;
        }
        // map tasks are done and reduce tasks should start
        if (job_info->map_fns_left_ == 0) {
          for (int i = 0; i < job_info->reduce_fns_left_; ++i) {
            reduce_fn_info* reduce_info = (reduce_fn_info*)malloc(sizeof (reduce_fn_info));
            reduce_info->job_id_ = job_info->reduce_meta_->job_id_;
            reduce_info->reduce_task_id_ = i;
            reduce_info->is_being_processed_ = false;
            reduce_info->app_ = job_info->reduce_meta_->app_;
            reduce_info->output_dir_ = job_info->reduce_meta_->output_dir_;
            reduce_info->n_map_ = job_info->reduce_meta_->n_map_;
            reduce_info->args_.args_len_ = job_info->reduce_meta_->args_.args_len_;
            reduce_info->args_.args_val_ = job_info->reduce_meta_->args_.args_val_;
            state->reduce_work_list_ = g_list_append(state->reduce_work_list_ , reduce_info);
          }
        }
        break;
      }
    }
  }


  return (void*)&result;
}

/* Initialize coordinator state. */
void coordinator_init(coordinator** coord_ptr) {
  *coord_ptr = malloc(sizeof(coordinator));

  coordinator* coord = *coord_ptr;

  /* TODO */
  // initialization of coordinator
  coord->job_id_allocator_ = 0;
  coord->map_work_list_ = NULL;
  coord->reduce_work_list_ = NULL;
  coord->job_set_ = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
}
