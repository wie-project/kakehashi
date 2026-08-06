/* Tiny string table + lookup (exercises strlen / memcmp across TUs). */
#ifndef G4_MINI_WORDS_H
#define G4_MINI_WORDS_H

/* Number of built-in tags. */
int words_count(void);
/* Index of exact tag, or -1. */
int words_index(const char *tag);
/* Tag at index, or NULL if out of range. */
const char *words_at(int index);

#endif /* G4_MINI_WORDS_H */
