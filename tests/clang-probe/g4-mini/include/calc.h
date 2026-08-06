/* Integer helpers used across translation units (G4 multi-file link probe). */
#ifndef G4_MINI_CALC_H
#define G4_MINI_CALC_H

int calc_add(int a, int b);
int calc_mul(int a, int b);
/* Fibonacci; n < 0 → 0. */
int calc_fib(int n);
/* Sum of inclusive range [lo, hi]; empty when lo > hi → 0. */
int calc_sum_range(int lo, int hi);

#endif /* G4_MINI_CALC_H */
