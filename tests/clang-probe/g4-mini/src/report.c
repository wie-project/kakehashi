#include "report.h"

#include <stdio.h>
#include <string.h>

/* Decimal itoa into buf; returns length. buf must hold ≥12 bytes. */
static int itoa_dec(int value, char *buf) {
    char tmp[12];
    int n;
    int i;
    int neg;
    unsigned int u;

    if (value == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return 1;
    }

    neg = value < 0;
    if (neg) {
        /* Avoid overflow on INT_MIN by casting through unsigned. */
        u = (unsigned int)(-(value + 1)) + 1u;
    } else {
        u = (unsigned int)value;
    }

    n = 0;
    while (u > 0u && n < (int)sizeof(tmp)) {
        tmp[n++] = (char)('0' + (u % 10u));
        u /= 10u;
    }

    i = 0;
    if (neg) {
        buf[i++] = '-';
    }
    while (n > 0) {
        buf[i++] = tmp[--n];
    }
    buf[i] = '\0';
    return i;
}

void report_line(const char *s) {
    if (s == NULL) {
        puts("(null)");
        return;
    }
    puts(s);
}

void report_kv_int(const char *key, int value) {
    char line[96];
    char num[16];
    size_t klen;
    size_t nlen;
    size_t i;
    size_t j;

    if (key == NULL) {
        key = "?";
    }
    klen = strlen(key);
    nlen = (size_t)itoa_dec(value, num);
    if (klen + 1u + nlen + 1u > sizeof(line)) {
        puts("report_kv_int: overflow");
        return;
    }
    i = 0;
    for (j = 0; j < klen; j++) {
        line[i++] = key[j];
    }
    line[i++] = '=';
    for (j = 0; j < nlen; j++) {
        line[i++] = num[j];
    }
    line[i] = '\0';
    puts(line);
}

void report_fail(const char *what) {
    char line[128];
    const char *prefix = "FAIL ";
    size_t plen;
    size_t wlen;
    size_t i;

    if (what == NULL) {
        what = "(unknown)";
    }
    plen = strlen(prefix);
    wlen = strlen(what);
    if (plen + wlen + 1u > sizeof(line)) {
        puts("FAIL (msg too long)");
        return;
    }
    for (i = 0; i < plen; i++) {
        line[i] = prefix[i];
    }
    for (i = 0; i < wlen; i++) {
        line[plen + i] = what[i];
    }
    line[plen + wlen] = '\0';
    puts(line);
}

void report_pass(const char *suite) {
    char line[128];
    const char *suffix = " PASS";
    size_t slen;
    size_t xlen;
    size_t i;

    if (suite == NULL) {
        suite = "suite";
    }
    slen = strlen(suite);
    xlen = strlen(suffix);
    if (slen + xlen + 1u > sizeof(line)) {
        puts("PASS");
        return;
    }
    for (i = 0; i < slen; i++) {
        line[i] = suite[i];
    }
    for (i = 0; i < xlen; i++) {
        line[slen + i] = suffix[i];
    }
    line[slen + xlen] = '\0';
    puts(line);
}
