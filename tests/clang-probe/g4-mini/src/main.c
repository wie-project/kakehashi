/*
 * G4 multi-file link probe: several TUs + headers, self-check, exit 0/1.
 * Built by guest Apple clang under kh; product re-run under kh.
 */
#include "calc.h"
#include "report.h"
#include "words.h"

#include <stdio.h>
#include <string.h>

static int expect_int(const char *name, int got, int want) {
    if (got == want) {
        report_kv_int(name, got);
        return 0;
    }
    report_fail(name);
    report_kv_int("got", got);
    report_kv_int("want", want);
    return 1;
}

static int expect_cstr(const char *name, const char *got, const char *want) {
    if (got == NULL && want == NULL) {
        report_line(name);
        return 0;
    }
    if (got == NULL || want == NULL) {
        report_fail(name);
        return 1;
    }
    if (strcmp(got, want) == 0) {
        report_line(name);
        report_line(got);
        return 0;
    }
    report_fail(name);
    return 1;
}

int main(void) {
    int fails = 0;
    int idx;

    report_line("g4-mini: start");

    fails += expect_int("add", calc_add(3, 4), 7);
    fails += expect_int("mul", calc_mul(6, 7), 42);
    fails += expect_int("fib10", calc_fib(10), 55);
    fails += expect_int("sum1_10", calc_sum_range(1, 10), 55);
    fails += expect_int("sum_empty", calc_sum_range(5, 1), 0);

    fails += expect_int("words_n", words_count(), 5);
    idx = words_index("gamma");
    fails += expect_int("idx_gamma", idx, 2);
    fails += expect_int("idx_miss", words_index("zeta"), -1);
    fails += expect_cstr("at2", words_at(2), "gamma");

    if (fails != 0) {
        report_fail("g4-mini");
        report_kv_int("fails", fails);
        return 1;
    }

    report_pass("g4-mini");
    return 0;
}
