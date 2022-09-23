#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "dev.h"

int main(int argc, char *argv[]) {
	uint8_t limbs_a[BLOCKS], limbs_f[BLOCKS];
	verbose_init(argv[0]);
	fixnum_t a;
	const char *code = "deadbeef";
	int decode = 0xdeadbeef;
	wordlists_init();
	printf("%x %s\n", decode, code);
	fixnum_init_pattern(&a, limbs_a, BLOCKS, PATTERN_ZERO);

	const char *buf = code;
	while (*buf) {
		fixnum_mul(&a, &wordlist_base16.m);
		int idx = wordlist_search(&wordlist_base16, buf, &buf);
		assert(idx != -1);
		fixnum_add_uint16(&a, idx);
		printf("idx=%d\n", idx);
		//buf++;
	}
	fixnum_show(&a, "result");
}
