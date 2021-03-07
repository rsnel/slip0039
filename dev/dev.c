#include "dev.h"

void fixnum_factor_show(const fixnum_factor_t *d, const char *name) {
        printf("value=%04x log2=%d pure=%d ", d->value, d->log2, d->pure);
        fixnum_show(&d->max_left_shift, "mls");
}

void fixnum_printf(const fixnum_t *f) {
        for (int nibble = (f->no_limbs<<1) - 1; nibble >= 0; nibble--) {
                putchar(charlist_dereference(&charlist_base16, fixnum_peek(f, nibble<<2, 4)));
        }
}

void fixnum_show(const fixnum_t *f, const char *name) {
        printf("%s: ", name);
        fixnum_printf(f);
        printf("\n");
}

