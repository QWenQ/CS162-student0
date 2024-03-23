/*
 * Implementation of the word_count interface using Pintos lists and pthreads.
 *
 * You may modify this file, and are expected to modify it.
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

#ifndef PINTOS_LIST
#error "PINTOS_LIST must be #define'd when compiling word_count_lp.c"
#endif

#ifndef PTHREADS
#error "PTHREADS must be #define'd when compiling word_count_lp.c"
#endif

#include "word_count.h"

void init_words(word_count_list_t* wclist) { 
  /* TODO */ 
  // call this API before starting multi-threads
  list_init(&wclist->lst);
}

size_t len_words(word_count_list_t* wclist) {
  /* TODO */
  pthread_mutex_lock(&wclist->lock); 
  size_t len = list_size(&wclist->lst);
  pthread_mutex_unlock(&wclist->lock);
  return len;
}

word_count_t* find_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  pthread_mutex_lock(&wclist->lock);
  word_count_t *wc = NULL;
  struct list_elem *it = NULL;
  for (it = list_begin(&wclist->lst); it != list_end(&wclist->lst); it = list_next(it)) {
    wc = list_entry(it, word_count_t, elem);
    if (strcmp(word, wc->word) == 0) {
      break;
    }
  }
  pthread_mutex_unlock(&wclist->lock);
  return wc;
}

word_count_t* add_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  pthread_mutex_lock(&wclist->lock);

  word_count_t *wc = NULL; 
  // check if WORD is already been in the list
  struct list_elem *it = NULL;
  for (it = list_begin(&wclist->lst); it != list_end(&wclist->lst); it = list_next(it)) {
    wc = list_entry(it, word_count_t, elem);
    if (strcmp(word, wc->word) == 0) {
      break;
    }
  }
  // WORD has already been in the list
  if (it != list_end(&wclist->lst)) {
    ++wc->count;
  }
  else {
    // WORD is a new word to be inserted
    wc = (word_count_t*)malloc(sizeof(word_count_t));
    // memory allocation succeds
    if (wc != NULL) {
      wc->count = 1;
      wc->word = word;
      struct list_elem *begin = list_begin(&wclist->lst);
      list_insert(begin, &(wc->elem));
    }
  }

  pthread_mutex_unlock(&wclist->lock);
  return wc;
}

void fprint_words(word_count_list_t* wclist, FILE* outfile) { 
  /* TODO */
  pthread_mutex_lock(&wclist->lock);
  struct list_elem *it = NULL;
  for (it = list_begin(&wclist->lst); it != list_end(&wclist->lst); it = list_next(it)) {
    word_count_t *wc = list_entry(it, word_count_t, elem);
    fprintf(outfile, "%8i\t%s\n", wc->count, wc->word);
  }
  pthread_mutex_unlock(&wclist->lock);
}

static bool less_list(const struct list_elem *a, const struct list_elem *b, void *aux) {
  if (a == NULL) {
    return false;
  }
  if (b == NULL) {
    return true;
  }
  word_count_t *wc1 = list_entry(a, word_count_t, elem);
  word_count_t *wc2 = list_entry(b, word_count_t, elem);
  return ((wc1->count < wc2->count) || (wc1->count == wc2->count && strcmp(wc1->word, wc2->word) < 0));
}

void wordcount_sort(word_count_list_t* wclist,
                    bool less(const word_count_t*, const word_count_t*)) {
  /* TODO */
  pthread_mutex_lock(&wclist->lock);
  list_sort(&wclist->lst, less_list, less);
  pthread_mutex_unlock(&wclist->lock);
}
