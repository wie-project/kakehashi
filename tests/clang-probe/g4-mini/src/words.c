#include "words.h"

#include <string.h>

static const char *const k_tags[] = {
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
};

int words_count(void) {
    return (int)(sizeof(k_tags) / sizeof(k_tags[0]));
}

int words_index(const char *tag) {
    int n;
    int i;

    if (tag == NULL) {
        return -1;
    }
    n = words_count();
    for (i = 0; i < n; i++) {
        if (strcmp(tag, k_tags[i]) == 0) {
            return i;
        }
    }
    return -1;
}

const char *words_at(int index) {
    if (index < 0 || index >= words_count()) {
        return NULL;
    }
    return k_tags[index];
}
