#include <stdio.h>
#include <stdlib.h>

#include "dev.h"

int main(int argc, char *argv[]) {
	uint8_t limbs_a[BLOCKS], limbs_f[BLOCKS], shift[BLOCKS], tozero[BLOCKS];
	uint16_t ret;
	wordlists_init();
	fixnum_t a;
	fixnum_multiplier16_t m;
	fixnum_divisor_t d;
	//fixnum_factor_t f;
	fixnum_scratch_t s;
	// set a to 1
	fixnum_init_uint16(&a, limbs_a, sizeof(limbs_a), 1);
	// multiply by 65536, 8 times
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_shl(&a, 16);
	fixnum_show(&a, "a");

	// set a divisor up to divide by 1000
	fixnum_multiplier16_init(&m, 1000);
	fixnum_divisor_init_from_multiplier16(&d, &m, limbs_f, sizeof(limbs_f));
	//fixnum_factor_init(&f, limbs_f, sizeof(limbs_f), 1000);
	fixnum_divisor_show(&d, "divisor");
	fixnum_scratch_init(&s, shift, sizeof(shift), tozero, sizeof(tozero));

	// now divide until we have all the digits of 16^32
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	ret = fixnum_div(&a, &d, &s, 0);
	printf("ret=%d\n", ret);
	fixnum_show(&a, "a");
	//ret = fixnum_div_factor(&a, &f, &s);
	//printf("ret=%d\n", ret);
	//fixnum_show(&a, "a");
	//ret = fixnum_div_factor(&a, &f, &s);
	//printf("ret=%d\n", ret);
	//fixnum_show(&a, "a");
	/*
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
	fixnum_show(&a, "a");
	fixnum_set_pattern(&a, PATTERN_MAX);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, 0);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
	*/
}
