/*
 * Implementation of the word_count interface using Pintos lists.
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
#error "PINTOS_LIST must be #define'd when compiling word_count_l.c"
#endif

#include "word_count.h"

void init_words(word_count_list_t* wclist) { 
  /* TODO */
  list_init(wclist);
}

size_t len_words(word_count_list_t* wclist) {
  /* TODO */ 
  return list_size(wclist);
}

word_count_t* find_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  struct list_elem *it;
  for (it = list_begin(wclist); it != list_end(wclist); it = list_next(it)) {
    word_count_t *wc = list_entry(it, word_count_t, elem);
    if (strcmp(word, wc->word) == 0) {
      return wc;
    }
  }
  return NULL;
}

word_count_t* add_word(word_count_list_t* wclist, char* word) {
  /* TODO */
  word_count_t *wc = find_word(wclist, word);
  // ++count if the word has been persent
  if (wc != NULL) {
    ++wc->count;
    return wc;
  }
  // insert a new word in the head of the list
  wc = (word_count_t*)malloc(sizeof(word_count_t));
  // return NULL if memory allocation fails
  if (wc == NULL) {
    return NULL;
  }
  wc->count = 1;
  wc->word = word;
  struct list_elem *begin = list_begin(wclist);
  list_insert(begin, &(wc->elem));
  return wc;
}

void fprint_words(word_count_list_t* wclist, FILE* outfile) {
  /* TODO */
  struct list_elem *it = NULL;
  for (it = list_begin(wclist); it != list_end(wclist); it = list_next(it)) {
    word_count_t *wc = list_entry(it, word_count_t, elem);
    fprintf(outfile, "%8i\t%s\n", wc->count, wc->word);
  }
}

static bool less_list(const struct list_elem* ewc1, const struct list_elem* ewc2, void* aux) {
  /* TODO */
  if (ewc1 == NULL) {
    return false;
  }
  if (ewc2 == NULL) {
    return true;
  }
  word_count_t *wc1 = list_entry(ewc1, word_count_t, elem); 
  word_count_t *wc2 = list_entry(ewc2, word_count_t, elem); 
  return ((wc1->count < wc2->count) || (wc1->count == wc2->count && strcmp(wc1->word, wc2->word) < 0));
}

void wordcount_sort(word_count_list_t* wclist,
                    bool less(const word_count_t*, const word_count_t*)) {
  list_sort(wclist, less_list, less);
}
