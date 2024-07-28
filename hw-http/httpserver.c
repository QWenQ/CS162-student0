#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>
#include <stdbool.h>


#include "libhttp.h"
#include "wq.h"

/*
 * Global configuration variables.
 * You need to use these in your implementation of handle_files_request and
 * handle_proxy_request. Their values are set up in main() using the
 * command line arguments (already implemented for you).
 */
wq_t work_queue; // Only used by poolserver
int num_threads; // Only used by poolserver
int server_port; // Default value: 8000
char* server_files_directory;
char* server_proxy_hostname;
int server_proxy_port;


/**
 * servers the contents of the file to the clent
*/
void http_send_file_contents(const char *path, int clt_fd) {
  int file_fd = open(path, __O_CLOEXEC | O_RDONLY);
  // return if file can not open
  if (file_fd == -1) {
    perror("open");
    exit(errno);
  }

  // read all bytes in the open file
  while (true) {
    char buf[1024];
    int cnt = read(file_fd, buf, 1024);
    if (cnt == 0) break;
    write(clt_fd, buf, cnt);
  }
  close(file_fd);
}

/**
 * get parent directory of PATH.
 * It is the caller's reponsibility to ensure that the file stored at `path` exists.
 * return 0 if get parent directory, else return 1.
*/
int get_parent_directory(char *buf, const char *path) {
  char *last_slash = strrchr(path, '/'); 
  if (last_slash == NULL) {
    return 1;
  }
  size_t parent_len = last_slash - path;
  memcpy(buf, path, parent_len);
  buf[parent_len] = '\0';
  return 0;
}

/*
 * Serves the contents the file stored at `path` to the client socket `fd`.
 * It is the caller's reponsibility to ensure that the file stored at `path` exists.
 */
void serve_file(int fd, char* path) {

  /* TODO: PART 2 */
  /* PART 2 BEGIN */


  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(path));

  struct stat statbuf;
  memset(&statbuf, 0, sizeof statbuf);
  stat(path, &statbuf);

  char str_cnt[10];
  memset(str_cnt, '\0', sizeof str_cnt);
  snprintf(str_cnt, 9, "%ld", statbuf.st_size);

  // http_send_header(fd, "Content-Length", "0"); // TODO: change this line too
  http_send_header(fd, "Content-Length", str_cnt);

  http_end_headers(fd);

  // send file contenst to the fd
  http_send_file_contents(path, fd);
  /* PART 2 END */
}

void serve_directory(int fd, char* path) {
  // assume that PATH is a directory

  http_start_response(fd, 200);
  http_send_header(fd, "Content-Type", http_get_mime_type(".html"));
  http_end_headers(fd);

  /* TODO: PART 3 */
  /* PART 3 BEGIN */

  // TODO: Open the directory (Hint: opendir() may be useful here)

  /**
   * TODO: For each entry in the directory (Hint: look at the usage of readdir() ),
   * send a string containing a properly formatted HTML. (Hint: the http_format_href()
   * function in libhttp.c may be useful here)
   */

  DIR *dir = opendir(path);
  if (dir == NULL) {
    perror("opendir");
    exit(errno);
  }

  // find index.html in the DIR
  bool has_index_html = false;

  while (1) {
    struct dirent *dir_ent = readdir(dir);
    // iterater all entries in the DIRECTORY but not get index.html file
    if (dir_ent == NULL) {
      break;
    }

    if (strncmp(dir_ent->d_name, "index.html", 10) == 0) {
      has_index_html = true;
      break;
    }
  }

  closedir(dir);

  // if the directory contains an index.html file
  if (has_index_html) {
    char full_name[256];
    http_format_index(full_name, path);
    http_end_headers(fd);
    http_send_file_contents(full_name, fd);
  }
  // otherwise, 
  else {
    // response a HTML page containing links to all of the immedaite children of the directory,
    // as well as a link to the parent directory
    write(fd, "<!DOCTYPE html>\n<html>\n<body>\n", 30);
    DIR *dir = opendir(path);  
    while (1) {
      struct dirent *ent = readdir(dir);
      if (ent == NULL) {
        break;
      }

      char buf[256];
      http_format_href(buf, path, ent->d_name);
      write(fd, buf, strlen(buf));
    }
    // link to the parent directory
    char parent_dir[128];
    int ret = get_parent_directory(parent_dir, path);
    if (!ret) {
      char buf[256];
      http_format_href(buf, parent_dir, "");
      write(fd, buf, strlen(buf));
    }

    write(fd, "</body>\n</html>\n", 15);
    closedir(dir);
  }

  /* PART 3 END */
}

/*
 * Reads an HTTP request from client socket (fd), and writes an HTTP response
 * containing:
 *
 *   1) If user requested an existing file, respond with the file
 *   2) If user requested a directory and index.html exists in the directory,
 *      send the index.html file.
 *   3) If user requested a directory and index.html doesn't exist, send a list
 *      of files in the directory with links to each.
 *   4) Send a 404 Not Found response.
 *
 *   Closes the client socket (fd) when finished.
 */
void handle_files_request(int fd) {

  struct http_request* request = http_request_parse(fd);

  if (request == NULL || request->path[0] != '/') {
    http_start_response(fd, 400);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  if (strstr(request->path, "..") != NULL) {
    http_start_response(fd, 403);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  /* Add `./` to the beginning of the requested path */
  char* path = malloc(2 + strlen(request->path) + 1);
  path[0] = '.';
  path[1] = '/';
  memcpy(path + 2, request->path, strlen(request->path) + 1);

  /*
   * TODO: PART 2 is to serve files. If the file given by `path` exists,
   * call serve_file() on it. Else, serve a 404 Not Found error below.
   * The `stat()` syscall will be useful here.
   *
   * TODO: PART 3 is to serve both files and directories. You will need to
   * determine when to call serve_file() or serve_directory() depending
   * on `path`. Make your edits below here in this function.
   */

  /* PART 2 & 3 BEGIN */

  // check if the file given by `path` exists
  struct stat statbuf;
  memset(&statbuf, 0, sizeof statbuf);
  int stat_ret = stat(path, &statbuf);
  // if the file does not exist, serve a 404 Not Found error
  if (stat_ret == -1) {
    http_start_response(fd, 404);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(fd);
    return;
  }

  // if path refers to a regular file
  if (S_ISREG(statbuf.st_mode)) {
    serve_file(fd, path);
  }
  // if path refers to a directory
  else if (S_ISDIR(statbuf.st_mode)) {
    serve_directory(fd, path);
  }

  /* PART 2 & 3 END */

  close(fd);
  return;
}


struct FromTo {
  int from_fd_;
  int to_fd_;
};

static void *messager(void *args) {
  struct FromTo *from_to = (struct FromTo*)args;
  int from_fd = from_to->from_fd_;
  int to_fd = from_to->to_fd_;

  while (true) {
    char buf[1024];
    int bytes = read(from_fd, buf, sizeof buf);
    if (bytes == 0) break;
    bytes = write(to_fd, buf, bytes);
    if (bytes == 0) break;
  }

  pthread_exit(NULL);
}

/*
 * Opens a connection to the proxy target (hostname=server_proxy_hostname and
 * port=server_proxy_port) and relays traffic to/from the stream fd and the
 * proxy target_fd. HTTP requests from the client (fd) should be sent to the
 * proxy target (target_fd), and HTTP responses from the proxy target (target_fd)
 * should be sent to the client (fd).
 *
 *   +--------+     +------------+     +--------------+
 *   | client | <-> | httpserver | <-> | proxy target |
 *   +--------+     +------------+     +--------------+
 *
 *   Closes client socket (fd) and proxy target fd (target_fd) when finished.
 */
void handle_proxy_request(int fd) {

  /*
  * The code below does a DNS lookup of server_proxy_hostname and
  * opens a connection to it. Please do not modify.
  */
  struct sockaddr_in target_address;
  memset(&target_address, 0, sizeof(target_address));
  target_address.sin_family = AF_INET;
  target_address.sin_port = htons(server_proxy_port);

  // Use DNS to resolve the proxy target's IP address
  struct hostent* target_dns_entry = gethostbyname2(server_proxy_hostname, AF_INET);

  // Create an IPv4 TCP socket to communicate with the proxy target.
  int target_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (target_fd == -1) {
    fprintf(stderr, "Failed to create a new socket: error %d: %s\n", errno, strerror(errno));
    close(fd);
    exit(errno);
  }

  if (target_dns_entry == NULL) {
    fprintf(stderr, "Cannot find host: %s\n", server_proxy_hostname);
    close(target_fd);
    close(fd);
    exit(ENXIO);
  }

  char* dns_address = target_dns_entry->h_addr_list[0];

  // Connect to the proxy target.
  memcpy(&target_address.sin_addr, dns_address, sizeof(target_address.sin_addr));
  int connection_status =
      connect(target_fd, (struct sockaddr*)&target_address, sizeof(target_address));

  if (connection_status < 0) {
    /* Dummy request parsing, just to be compliant. */
    http_request_parse(fd);

    http_start_response(fd, 502);
    http_send_header(fd, "Content-Type", "text/html");
    http_end_headers(fd);
    close(target_fd);
    close(fd);
    return;
  }

  /* TODO: PART 4 */
  /* PART 4 BEGIN */

  // thread1 servers data from the server to the client 
  struct FromTo server_to_client;
  server_to_client.from_fd_ = target_fd;
  server_to_client.to_fd_ = fd;

  pthread_t pid1;
  pthread_create(&pid1, NULL, messager, (void*)&server_to_client);

  // thread2 servers data from the client to the server
  struct FromTo client_to_server;
  client_to_server.from_fd_ = fd;
  client_to_server.to_fd_ = target_fd;

  pthread_t pid2;
  pthread_create(&pid2, NULL, messager, (void*)&client_to_server);


  pthread_join(pid1, NULL);
  pthread_join(pid2, NULL);


  close(target_fd);
  close(fd);
  return;

  /* PART 4 END */
}

#ifdef POOLSERVER
/*
 * All worker threads will run this function until the server shutsdown.
 * Each thread should block until a new request has been received.
 * When the server accepts a new connection, a thread should be dispatched
 * to send a response to the client.
 */
void* handle_clients(void* void_request_handler) {
  void (*request_handler)(int) = (void (*)(int))void_request_handler;
  /* (Valgrind) Detach so thread frees its memory on completion, since we won't
   * be joining on it. */
  pthread_detach(pthread_self());

  /* TODO: PART 7 */
  /* PART 7 BEGIN */
  int client_socket_number;

  while (true) {
    client_socket_number = wq_pop(&work_queue);
    request_handler(client_socket_number);
  }

  pthread_exit(NULL);

  /* PART 7 END */
}

/*
 * Creates `num_threads` amount of threads. Initializes the work queue.
 */
void init_thread_pool(int num_threads, void (*request_handler)(int)) {

  /* TODO: PART 7 */
  /* PART 7 BEGIN */
  wq_init(&work_queue);
  pthread_t tid;
  for (int i = 0; i < num_threads; ++i) {
    void*(*void_request_handler)(void*) = (void*(*)(void*))request_handler;
    pthread_create(&tid, NULL, handle_clients, void_request_handler);
  }

  /* PART 7 END */
}
#endif

#ifdef THREADSERVER

struct ThreadHandlerAndArg {
  void (*request_handler)(int);
  int client_socket_number;
};

/**
 * for a non-threadpool thread using
*/
void *start_routine(void* arg) {
  struct ThreadHandlerAndArg  *handler_and_arg = (struct ThreadHandlerAndArg*)arg;
  void (*request_handler)(int) = handler_and_arg->request_handler;
  int client_socket_number = handler_and_arg->client_socket_number;
  request_handler(client_socket_number);
  free(handler_and_arg);
  pthread_exit(NULL);
  // return NULL;
}

#endif

/*
 * Opens a TCP stream socket on all interfaces with port number PORTNO. Saves
 * the fd number of the server socket in *socket_number. For each accepted
 * connection, calls request_handler with the accepted fd number.
 */
void serve_forever(int* socket_number, void (*request_handler)(int)) {

  struct sockaddr_in server_address, client_address;
  size_t client_address_length = sizeof(client_address);
  int client_socket_number;

  // Creates a socket for IPv4 and TCP.
  *socket_number = socket(PF_INET, SOCK_STREAM, 0);
  if (*socket_number == -1) {
    perror("Failed to create a new socket");
    exit(errno);
  }

  int socket_option = 1;
  if (setsockopt(*socket_number, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(socket_option)) ==
      -1) {
    perror("Failed to set socket options");
    exit(errno);
  }

  // Setup arguments for bind()
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = INADDR_ANY;
  server_address.sin_port = htons(server_port);

  /*
   * TODO: PART 1
   *
   * Given the socket created above, call bind() to give it
   * an address and a port. Then, call listen() with the socket.
   * An appropriate size of the backlog is 1024, though you may
   * play around with this value during performance testing.
   */

  /* PART 1 BEGIN */
  int bind_ret = bind(*socket_number, (const struct sockaddr*)&server_address, sizeof server_address);
  if (bind_ret == -1) {
    perror("Failed to bind the socket to the given address and port");
    exit(errno);
  }

  // int listen_ret = listen(*socket_number, 1024);
  // int listen_ret = listen(*socket_number, 100);
  int listen_ret = listen(*socket_number, 10);
  if (listen_ret == -1) {
    perror("Failed to listen");
    exit(errno);
  }

  /* PART 1 END */
  printf("Listening on port %d...\n", server_port);

#ifdef POOLSERVER
  /*
   * The thread pool is initialized *before* the server
   * begins accepting client connections.
   */
  init_thread_pool(num_threads, request_handler);
#endif

  while (1) {
    client_socket_number = accept(*socket_number, (struct sockaddr*)&client_address,
                                  (socklen_t*)&client_address_length);
    if (client_socket_number < 0) {
      perror("Error accepting socket");
      continue;
    }

    printf("Accepted connection from %s on port %d\n", inet_ntoa(client_address.sin_addr),
           client_address.sin_port);

#ifdef BASICSERVER
    /*
     * This is a single-process, single-threaded HTTP server.
     * When a client connection has been accepted, the main
     * process sends a response to the client. During this
     * time, the server does not listen and accept connections.
     * Only after a response has been sent to the client can
     * the server accept a new connection.
     */
    request_handler(client_socket_number);

#elif FORKSERVER
    /*
     * TODO: PART 5
     *
     * When a client connection has been accepted, a new
     * process is spawned. This child process will send
     * a response to the client. Afterwards, the child
     * process should exit. During this time, the parent
     * process should continue listening and accepting
     * connections.
     */

    /* PART 5 BEGIN */

    pid_t pid = fork();
    // child process
    if (pid == 0) {
      close(*socket_number);
      request_handler(client_socket_number);
      close(client_socket_number);
      exit(0);
    }
    // parent process
    else if (pid > 0) {
      close(client_socket_number);
    }
    // fork error
    else {
      perror("fork error!");
      exit(errno);
    }


    /* PART 5 END */

#elif THREADSERVER
    /*
     * TODO: PART 6
     *
     * When a client connection has been accepted, a new
     * thread is created. This thread will send a response
     * to the client. The main thread should continue
     * listening and accepting connections. The main
     * thread will NOT be joining with the new thread.
     */

    /* PART 6 BEGIN */
    struct ThreadHandlerAndArg *handler_and_arg = (struct ThreadHandlerAndArg*)malloc(sizeof(struct ThreadHandlerAndArg));
    if (!handler_and_arg) {
      perror("malloc");
      continue;
    }

    handler_and_arg->request_handler = request_handler;
    handler_and_arg->client_socket_number = client_socket_number;

    pthread_t tid;
    int ret = pthread_create(&tid, NULL, start_routine, (void*)handler_and_arg);
    if (ret) {
      perror("pthread_create");
      free(handler_and_arg);
      exit(errno);
    }

    pthread_detach(tid);

    /* PART 6 END */
#elif POOLSERVER
    /*
     * TODO: PART 7
     *
     * When a client connection has been accepted, add the
     * client's socket number to the work queue. A thread
     * in the thread pool will send a response to the client.
     */

    /* PART 7 BEGIN */

    wq_push(&work_queue, client_socket_number);

    /* PART 7 END */
#endif
  }

  shutdown(*socket_number, SHUT_RDWR);
  close(*socket_number);
}

int server_fd;
void signal_callback_handler(int signum) {
  printf("Caught signal %d: %s\n", signum, strsignal(signum));
  printf("Closing socket %d\n", server_fd);
  if (close(server_fd) < 0)
    perror("Failed to close server_fd (ignoring)\n");
  exit(0);
}

char* USAGE =
    "Usage: ./httpserver --files some_directory/ [--port 8000 --num-threads 5]\n"
    "       ./httpserver --proxy inst.eecs.berkeley.edu:80 [--port 8000 --num-threads 5]\n";

void exit_with_usage() {
  fprintf(stderr, "%s", USAGE);
  exit(EXIT_SUCCESS);
}

int main(int argc, char** argv) {
  signal(SIGINT, signal_callback_handler);
  signal(SIGPIPE, SIG_IGN);

  /* Default settings */
  server_port = 8000;
  void (*request_handler)(int) = NULL;

  int i;
  for (i = 1; i < argc; i++) {
    if (strcmp("--files", argv[i]) == 0) {
      request_handler = handle_files_request;
      server_files_directory = argv[++i];
      if (!server_files_directory) {
        fprintf(stderr, "Expected argument after --files\n");
        exit_with_usage();
      }
    } else if (strcmp("--proxy", argv[i]) == 0) {
      request_handler = handle_proxy_request;

      char* proxy_target = argv[++i];
      if (!proxy_target) {
        fprintf(stderr, "Expected argument after --proxy\n");
        exit_with_usage();
      }

      char* colon_pointer = strchr(proxy_target, ':');
      if (colon_pointer != NULL) {
        *colon_pointer = '\0';
        server_proxy_hostname = proxy_target;
        server_proxy_port = atoi(colon_pointer + 1);
      } else {
        server_proxy_hostname = proxy_target;
        server_proxy_port = 80;
      }
    } else if (strcmp("--port", argv[i]) == 0) {
      char* server_port_string = argv[++i];
      if (!server_port_string) {
        fprintf(stderr, "Expected argument after --port\n");
        exit_with_usage();
      }
      server_port = atoi(server_port_string);
    } else if (strcmp("--num-threads", argv[i]) == 0) {
      char* num_threads_str = argv[++i];
      if (!num_threads_str || (num_threads = atoi(num_threads_str)) < 1) {
        fprintf(stderr, "Expected positive integer after --num-threads\n");
        exit_with_usage();
      }
    } else if (strcmp("--help", argv[i]) == 0) {
      exit_with_usage();
    } else {
      fprintf(stderr, "Unrecognized option: %s\n", argv[i]);
      exit_with_usage();
    }
  }

  if (server_files_directory == NULL && server_proxy_hostname == NULL) {
    fprintf(stderr, "Please specify either \"--files [DIRECTORY]\" or \n"
                    "                      \"--proxy [HOSTNAME:PORT]\"\n");
    exit_with_usage();
  }

#ifdef POOLSERVER
  if (num_threads < 1) {
    fprintf(stderr, "Please specify \"--num-threads [N]\"\n");
    exit_with_usage();
  }
#endif

  chdir(server_files_directory);
  serve_forever(&server_fd, request_handler);

  return EXIT_SUCCESS;
}
