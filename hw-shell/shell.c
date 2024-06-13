#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens* tokens);
int cmd_help(struct tokens* tokens);
int cmd_pwd(struct tokens* tokens);
int cmd_cd(struct tokens* tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens* tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t* fun;
  char* cmd;
  char* doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_pwd, "pwd", "print the current working directory"},
    {cmd_cd, "cd", "change the current working directory to the target directory"},
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens* tokens) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens* tokens) { exit(0); }

// print the current working directory
int cmd_pwd(unused struct tokens *tokens) {
  const int size = 1024;
  char* buf = getcwd(NULL, size);
  if (buf == NULL) {
    printf("get current working directory failed!\n");
    return 0;
  }
  printf("%s\n", buf);
  return 1;
}

// change the current working directory to the target directory
int cmd_cd(unused struct tokens *tokens) {
  char *path = tokens_get_token(tokens, 1);
  int ret = chdir(path);
  return ret;
}


/* Looks up the built-in command, if it exists. */
int lookup(char cmd[]) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* Intialization procedures for this shell */
void init_shell() {
  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive) {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
  }
}



// int get_full_path(struct tokens *tokens, size_t file_idx) {
//   return 0;
// }


/**
 * close all pipe fds in the array
 * @param pipe_arr array of pipe fds
 * @param size size of pipe array
*/
void close_fds_of_array(int *pipe_arr[], size_t size) {
  for (size_t idx = 0; idx < size; ++idx) {
    close(pipe_arr[idx][0]);
    close(pipe_arr[idx][1]);
  }
}

/**
 * allocate memory for pipe fds with specified size and initialize them with -1 
 * @param size size of array
 * @return NULL if allocatio fails, or memory address if success
*/
int **malloc_pipe_fds_array(size_t size) {
  int **pipe_array = (int **)malloc(size * sizeof (int *));
  if (pipe_array) {
    for (size_t idx = 0; idx < size; ++idx) {
      pipe_array[idx] = (int*)malloc(2 * sizeof (int));
      if (pipe_array[idx] == NULL) {
        fprintf(stderr, "pipe_array[%ld] is NULL", idx);
      }
      else {
        pipe_array[idx][0] = -1;
        pipe_array[idx][1] = -1;
      }
    }
  }
  return pipe_array;
}

/**
 * free memory of a pipe fds array
 * @param p_to_pipe_array the pipe fds array
 * @param size size of pipe fds array
*/
void free_pipe_fds_array(int **pipe_array, size_t size) {
  if (pipe_array) {
    for (size_t idx = 0; idx < size; ++idx) {
      free(pipe_array[idx]);
    }
    free(pipe_array);
  } 
}

int main(unused int argc, unused char* argv[]) {
  init_shell();

  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin)) {
    /* Split our line into words. */
    struct tokens* tokens = tokenize(line);

    /* Find which built-in function to run. */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0) {
      cmd_table[fundex].fun(tokens);
    } else {
      /* REPLACE this to run commands as programs. */

      // the programs to be executed 
      size_t new_programs = 1;

      size_t tokens_length = tokens_get_length(tokens);
      for (size_t idx = 0; idx < tokens_length; ++idx) {
        char *token = tokens_get_token(tokens, idx);
        if (strncmp(token, "|", 1) == 0) {
          ++new_programs;
        }
      }

      int **pipe_arr = malloc_pipe_fds_array(new_programs - 1);
      // generate pipe fds array
      if (pipe_arr) {
        for (size_t idx = 0; idx < (new_programs - 1); ++idx) {
          int ret = pipe(pipe_arr[idx]);
          if (ret) {
            fprintf(stderr, "generate pipe[%ld] failed", idx);
          }
        }
      }

      // get environment variable PATH
      char *env_path = getenv("PATH");
      
      // tokens[start_idx : end_idx) for every program
      size_t start_idx = 0;
      size_t end_idx = 0;

      for (size_t program_idx = 0; program_idx < new_programs; ++program_idx) {
        size_t new_program_arg_nums = 1;
        start_idx = end_idx;
        char *tmp = tokens_get_token(tokens, end_idx);
        while ((end_idx < tokens_length) && strncmp(tmp, "|", 1)) {
          ++new_program_arg_nums;
          ++end_idx;
          tmp = tokens_get_token(tokens, end_idx);
        }

        // in which case, end_idx >= tokens_length or tokens[end_idx] contains string "|"

        pid_t pid = fork();
        // child process
        if (pid == 0) {

          // input/output redirection if pipe
          if (new_programs > 1) {

            // write output to the next program
            if (program_idx < (new_programs - 1)) {
              int ret = dup2(pipe_arr[program_idx][1], STDOUT_FILENO);
              if (ret == -1) {
                perror("output redirection failed");
              }
            }

            // read input from the previous program
            if (program_idx > 0) {
              int ret = dup2(pipe_arr[program_idx - 1][0], STDIN_FILENO); 
              if (ret == -1) {
                perror("intput redirection failed");
              }
            }


            // close all pipe fds in the array
            close_fds_of_array(pipe_arr, new_programs - 1);
          }

          close(shell_terminal);


          // get the execution path of the program
          char *path_name = tokens_get_token(tokens, start_idx);
          ++start_idx;
          // get a file name from file path
          char *file_name = strrchr(path_name, '/');
          if (file_name == NULL) {
            file_name = path_name;
          }
          else {
            ++file_name;
          }

          char *saveptr = NULL;

          // parse PATH with strtok_r
          for (char* path = env_path; ; path = NULL) {
            char *dir = strtok_r(path, ":", &saveptr);
            if (dir == NULL) {
              break;
            }
            
            // look for the target program in DIR at the first time
            char full_path[100] = {'\0'};
            // concate directory and file name to get a full access path of file
            snprintf(full_path, sizeof(full_path), "%s/%s", dir, file_name);
            FILE *file_stream = fopen(full_path, "r");
            
            // go for next path if the current one don't work
            if (file_stream == NULL) {
              continue;
            }

            fclose(file_stream);
            // parse the arguments passed to execv() and redirection if necessary
            char *argv_execv[new_program_arg_nums];
            memset(argv_execv, 0x0, sizeof argv_execv);
            size_t argv_idx = 0;
            argv_execv[argv_idx] = full_path;
            ++argv_idx;


            // parse args in the range tokens[start_idx, end_idx)
            while (start_idx < end_idx) {
              char *token = tokens_get_token(tokens, start_idx);
              if (token == NULL) {
                break;
              }

              if (strncmp(token, "<", 1) == 0) {
                ++start_idx;
                if (start_idx >= end_idx) {
                  fprintf(stderr, "error on redirection");
                  exit(1);
                }
                char *input_filename = tokens_get_token(tokens, start_idx);
                int input_file_no = open(input_filename, O_RDONLY | __O_CLOEXEC, S_IRUSR | S_IWUSR);
                if (input_file_no == -1) {
                  perror("error on input file");
                  exit(1);
                }

                int ret = dup2(input_file_no, STDIN_FILENO);
                if (ret == -1) {
                  fprintf(stderr, "error on dup syscall");
                  exit(1);
                }
              } 
              else if (strncmp(token, ">", 1) == 0) {
                ++start_idx;
                if (start_idx >= end_idx) {
                  fprintf(stderr, "error on redirection");
                  exit(1);
                }
                char *output_filename = tokens_get_token(tokens, start_idx);
                int output_file_no = open(output_filename, O_WRONLY | O_CREAT | __O_CLOEXEC, S_IRUSR | S_IWUSR);
                if (output_file_no == -1) {
                  fprintf(stderr, "error on input file");
                  exit(1);
                }

                int ret = dup2(output_file_no, STDOUT_FILENO);
                if (ret == -1) {
                  fprintf(stderr, "error on dup syscall");
                  exit(1);
                }
              }
              else {
                argv_execv[argv_idx] = tokens_get_token(tokens, start_idx);
              }
              ++start_idx;
            }

            execv(full_path, argv_execv);
            exit(0);
          }
        }
        // parent process
        else if (pid > 0) {
          // close_fds_of_array(pipe_arr, new_programs - 1);
          pid_t end_pid = wait(&pid);
          if (end_pid == -1) {
            perror("program failed!");
          }
        }
        // fork() error
        else {
          close_fds_of_array(pipe_arr, new_programs - 1);
          perror("fork() error");
        }

        // go to new range for next program to be executed
        ++end_idx;
      }

    
      close_fds_of_array(pipe_arr, new_programs - 1);
      free_pipe_fds_array(pipe_arr, new_programs - 1);
    }



/*
      pid_t pid = fork();
      if (pid == 0) {
        // child process 
        close(shell_terminal);

        char *path_name = tokens_get_token(tokens, 0);
        // get a file name from file path
        char *file_name = strrchr(path_name, '/');
        if (file_name == NULL) {
          file_name = path_name;
        }
        else {
          ++file_name;
        }

        // get environment variable PATH
        char *env_path = getenv("PATH");
        char *saveptr = NULL;

        // parse PATH with strtok_r
        for (char* path = env_path; ; path = NULL) {
          char *dir = strtok_r(path, ":", &saveptr);
          if (dir == NULL) {
            break;
          }
          
          // look for the target program in DIR at the first time
          char full_path[100] = {'\0'};
          // concate directory and file name to get a full access path of file
          snprintf(full_path, sizeof(full_path), "%s/%s", dir, file_name);
          FILE *file_stream = fopen(full_path, "r");
          if (file_stream != NULL) {
            fclose(file_stream);
            // parse the arguments passed to execv() and redirection if necessary
            size_t token_length = tokens_get_length(tokens);
            char *argv_execv[token_length + 1];
            memset(argv_execv, 0x0, sizeof argv_execv);
            argv_execv[0] = full_path;
            size_t idx = 1;
            while (idx < token_length) {
              char *token = tokens_get_token(tokens, idx);
              if (strncmp(token, "<", 1) == 0) {
                ++idx;
                if (idx >= token_length) {
                  fprintf(stderr, "error on redirection");
                  exit(1);
                }
                char *input_filename = tokens_get_token(tokens, idx);
                int input_file_no = open(input_filename, O_RDONLY | __O_CLOEXEC, S_IRUSR | S_IWUSR);
                if (input_file_no == -1) {
                  perror("error on input file");
                  exit(1);
                }

                int ret = dup2(input_file_no, STDIN_FILENO);
                if (ret == -1) {
                  fprintf(stderr, "error on dup syscall");
                  exit(1);
                }
              } 
              else if (strncmp(token, ">", 1) == 0) {
                ++idx;
                if (idx >= token_length) {
                  fprintf(stderr, "error on redirection");
                  exit(1);
                }
                char *output_filename = tokens_get_token(tokens, idx);
                int output_file_no = open(output_filename, O_WRONLY | O_CREAT | __O_CLOEXEC, S_IRUSR | S_IWUSR);
                if (output_file_no == -1) {
                  fprintf(stderr, "error on input file");
                  exit(1);
                }

                int ret = dup2(output_file_no, STDOUT_FILENO);
                if (ret == -1) {
                  fprintf(stderr, "error on dup syscall");
                  exit(1);
                }
              }
              else {
                argv_execv[idx] = tokens_get_token(tokens, idx);
              }
              ++idx;
            }

            execv(full_path, argv_execv);
            exit(0);
          }
        }
      }
      else if (pid > 0) {
        // parent process
        pid_t end_pid = wait(&pid);
        if (end_pid == -1) {
          perror("program failed!");
        }
      }
    }
*/

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}
