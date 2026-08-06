#include "calc.h"

int calc_add(int a, int b) {
    return a + b;
}

int calc_mul(int a, int b) {
    return a * b;
}

int calc_fib(int n) {
    int a;
    int b;
    int i;
    int t;

    if (n < 0) {
        return 0;
    }
    if (n == 0) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }
    a = 0;
    b = 1;
    for (i = 2; i <= n; i++) {
        t = a + b;
        a = b;
        b = t;
    }
    return b;
}

int calc_sum_range(int lo, int hi) {
    int s;
    int i;

    if (lo > hi) {
        return 0;
    }
    s = 0;
    for (i = lo; i <= hi; i++) {
        s += i;
    }
    return s;
}
