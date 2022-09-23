#include <string.h>
#include "dev.h"

void fixnum_divisor_show(const fixnum_divisor_t *d, const char *name) {
        printf("log2=%d pure=%d ", d->p.log2, d->p.pure);
        fixnum_show(&d->max_left_shift, "mls");
}

void fixnum_printf(const fixnum_t *f) {
	char c[2];
        for (int nibble = (f->no_limbs<<1) - 1; nibble >= 0; nibble--) {
		memset(c, 0, sizeof(c));
                wordlist_dereference(&wordlist_base16, c, sizeof(c), fixnum_peek(f, nibble<<2, 4));
		putchar(c[0]);
        }
}

void fixnum_show(const fixnum_t *f, const char *name) {
        printf("%s: ", name);
        fixnum_printf(f);
        printf("\n");
}

