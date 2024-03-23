/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright © 2021 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>

#include "word_count.h"
#include "word_helpers.h"

#define MAX_WORD_LEN 64

/* Create the empty data structure. */
word_count_list_t word_counts;

void* threadFunc(void *arg) {
  // open the file
  char *file_name = (char*)arg;
  FILE *file = fopen(file_name, "r");
  if (file == NULL) {
    pthread_exit(NULL);
  }
  count_words(&word_counts, file);
  /*
  char word[100];
  //  memset(word, '\0', 100);
  //  read a word from the file at one time
  char ch;
  int len = 0;
  while (true) {
    while ((ch = getc(file)) != EOF) {
      if (isalpha(ch)) {
        word[len] = tolower(ch);
        ++len;
        if (len >= MAX_WORD_LEN) {
          break;
        }
      }
      else {
        break;
      }
    }
    // add a new word to the word list
    if (len > 1) {
      word[len] = '\0';
      add_word(&word_counts, word);
    }
    // break if all words in the file have been read
    if (ch == EOF) {
      break;
    }
    len = 0;
  }
  */

  fclose(file);
  pthread_exit(NULL);
}

/*
 * main - handle command line, spawning one thread per file.
 */
int main(int argc, char* argv[]) {
  init_words(&word_counts);

  if (argc <= 1) {
    /* Process stdin in a single thread. */
    count_words(&word_counts, stdin);
  } else {
    /* TODO */
    pthread_t thread_ids[argc];
    for (int idx = 1; idx < argc; ++idx) {
      int ret = pthread_create(&thread_ids[idx], NULL, threadFunc, (void*)argv[idx]);
      if (ret != 0) {
        pthread_exit(NULL);
      }
    }

    for (int idx = 1; idx < argc; ++idx) {
      pthread_join(thread_ids[idx], NULL);
    }
  }

  /* Output final result of all threads' work. */
  wordcount_sort(&word_counts, less_count);
  fprint_words(&word_counts, stdout);
  return 0;
}
