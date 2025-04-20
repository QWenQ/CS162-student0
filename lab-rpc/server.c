/**
 * Server binary.
 */

#include "kv_store.h"
#include <glib.h>
#include <memory.h>
#include <netinet/in.h>
#include <rpc/pmap_clnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#ifndef SIG_PF
#define SIG_PF void (*)(int)
#endif

/* TODO: Add global state. */

static void init();
static void add(const buf* key, const buf* val);
static void lookup(const buf* key, buf* result);

static GHashTable *ht;

static void init() {
  ht = g_hash_table_new(g_bytes_hash, g_bytes_equal);
}

static void add(const buf* key, const buf* val) {
  GBytes *key_g = g_bytes_new(key->buf_val, (gsize)key->buf_len); 
  GBytes *value_g = g_bytes_new(val->buf_val, (gsize)val->buf_len);
  g_hash_table_insert(ht, key_g, value_g);
}

static void lookup(const buf* key, buf* result) {
  result->buf_len = 0;
  GBytes *key_g = g_bytes_new(key->buf_val, (gsize)key->buf_len); 
  GBytes *value_g = g_hash_table_lookup(ht, key_g);

  g_bytes_unref(key_g);

  if (value_g != NULL) {
    long unsigned int len;
    const char *data = g_bytes_get_data(value_g, &len); /* Sets len = 5. */
    result->buf_val = (char*)data;
    result->buf_len = (u_int)len;
    // printf("%.*s\n", (int) len, data); /* Outputs first `len` characters of `data` ("value"). */
  }
}



extern void kvstore_1(struct svc_req *, SVCXPRT *);

/* Set up and run RPC server. */
int main(int argc, char **argv) {
  register SVCXPRT *transp;

  pmap_unset(KVSTORE, KVSTORE_V1);

  transp = svcudp_create(RPC_ANYSOCK);
  if (transp == NULL) {
    fprintf(stderr, "%s", "cannot create udp service.");
    exit(1);
  }
  if (!svc_register(transp, KVSTORE, KVSTORE_V1, kvstore_1, IPPROTO_UDP)) {
    fprintf(stderr, "%s", "unable to register (KVSTORE, KVSTORE_V1, udp).");
    exit(1);
  }

  transp = svctcp_create(RPC_ANYSOCK, 0, 0);
  if (transp == NULL) {
    fprintf(stderr, "%s", "cannot create tcp service.");
    exit(1);
  }
  if (!svc_register(transp, KVSTORE, KVSTORE_V1, kvstore_1, IPPROTO_TCP)) {
    fprintf(stderr, "%s", "unable to register (KVSTORE, KVSTORE_V1, tcp).");
    exit(1);
  }

  /* TODO: Initialize state. */
  init();

  svc_run();
  fprintf(stderr, "%s", "svc_run returned");
  exit(1);
  /* NOTREACHED */
}

/* Example server-side RPC stub. */
int *example_1_svc(int *argp, struct svc_req *rqstp) {
  static int result;

  result = *argp + 1;

  return &result;
}

/* TODO: Add additional RPC stubs. */
char** echo_1_svc(char **argp, struct svc_req *rqstp) {
  static char* str = NULL;

  str = *argp;

  return &str;
}

void *put_1_svc(put_request *argp, struct svc_req *rqstp) {
  static void *result;

  /* TODO */
  // ARGP constains a key/value pair, so its length should be 2
  if (argp) {
    add(argp->key, argp->val);
  }

  return &result;
}

buf *get_1_svc(buf *argp, struct svc_req *rqstp) {
  static buf result;

  /* TODO */
  lookup(argp, &result);

  return &result;
}
