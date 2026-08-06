/* Freestanding-friendly reporting (puts / write only — no printf %). */
#ifndef G4_MINI_REPORT_H
#define G4_MINI_REPORT_H

void report_line(const char *s);
void report_kv_int(const char *key, int value);
void report_fail(const char *what);
void report_pass(const char *suite);

#endif /* G4_MINI_REPORT_H */
