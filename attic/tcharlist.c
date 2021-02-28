#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "fixnum.h"
#include "charlists.h"
#include "verbose.h"

int main(int argc, char *argv[]) {
	uint8_t limbs_a[BLOCKS], limbs_f[BLOCKS];
	verbose_init(argv[0]);
	fixnum_t a;
	fixnum_factor_t f;
	const char *code = "deadbeef";
	int decode = 0xdeadbeef;
	printf("%x %s\n", decode, code);
	fixnum_init_pattern(&a, limbs_a, BLOCKS, PATTERN_ZERO);
	fixnum_factor_init(&f, limbs_f, BLOCKS, charlist_base16.no_chars);

	const char *buf = code;
	while (*buf) {
		fixnum_mul(&a, &f);
		int idx = charlist_search(&charlist_base16, *buf);
		assert(idx != -1);
		fixnum_add_uint16(&a, idx);
		printf("idx=%d\n", idx);
		buf++;
	}
	fixnum_show(&a, "result");
}
