/**
 * Client binary.
 */

#include "kv_store_client.h"

#define HOST "localhost"

CLIENT* clnt_connect(char* host) {
  CLIENT* clnt = clnt_create(host, KVSTORE, KVSTORE_V1, "udp");
  if (clnt == NULL) {
    clnt_pcreateerror(host);
    exit(1);
  }
  return clnt;
}

int example(int input) {
  CLIENT *clnt = clnt_connect(HOST);

  int ret;
  int *result;

  result = example_1(&input, clnt);
  if (result == (int *)NULL) {
    clnt_perror(clnt, "call failed");
    exit(1);
  }
  ret = *result;
  xdr_free((xdrproc_t)xdr_int, (char *)result);

  clnt_destroy(clnt);
  
  return ret;
}

char* echo(char* input) {
  CLIENT *clnt = clnt_connect(HOST);

  char* ret;

  /* TODO */
  char** result = echo_1(&input, clnt);
  if (result == (char**)NULL) {
    clnt_perror(clnt, "call failed");
    exit(1);
  }

  ret = strdup(*result);

  /* Free previous result */
  xdr_free((xdrproc_t)xdr_string, (char*)result);

  clnt_destroy(clnt);
  
  return ret;
}

void put(buf key, buf value) {
  CLIENT *clnt = clnt_connect(HOST);

  /* TODO */

  // initialize put request passed to the server
  put_request req;
  req.key = &key;
  req.val = &value;

  void* result = put_1(&req, clnt);
  if (result == NULL) {
    clnt_perror(clnt, "call failed");
    exit(1);
  }

  /* Free previous result */
  xdr_free((xdrproc_t)xdr_pointer, (char**)result);

  clnt_destroy(clnt);
}

buf* get(buf key) {
  CLIENT *clnt = clnt_connect(HOST);

  /* TODO */
  static buf ret;
  buf* result = get_1(&key, clnt);
  if (result->buf_len == 0) {
    clnt_perror(clnt, "call failed");
    exit(1);
  }

  ret.buf_len = result->buf_len;
  ret.buf_val = result->buf_val;

  /* Free previous result */
  // xdr_free((xdrproc_t)xdr_buf, (buf*)result);

  clnt_destroy(clnt);
  
  return &ret;
}
