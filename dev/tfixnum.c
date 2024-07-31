#include "dev.h"

static uint16_t popcnt_helper(uint8_t in) {
        uint16_t c = 0;
        for (int i = 0; i < 8; i++) {
                c += cthelp_neq(0, in);
                in &= in - 1;
        }
        return c;
}

static uint16_t popcnt_helper2(uint8_t n) {
	n = (n&0x55) + ((n>>1)&0x55);
	n = (n&0x33) + ((n>>2)&0x33);
	n = (n&0x0f) + ((n>>4)&0x0f);
	return n;
}


int main(int argc, char *argv[]) {
	uint8_t limbs_a[BLOCKS], limbs_b[BLOCKS], limbs_f[BLOCKS], limbs_sa[BLOCKS], limbs_sb[BLOCKS];
	uint16_t ret;
	fixnum_t a, b;
	fixnum_multiplier16_t m;
	fixnum_divisor_t d;
	fixnum_scratch_t s;
	fixnum_scratch_init(&s, limbs_sa, BLOCKS, limbs_sb, BLOCKS);
	codec_init();
	wordlists_init();
	fixnum_multiplier16_init(&m, 101);
	fixnum_divisor_init_from_multiplier16(&d, &m, limbs_f, BLOCKS);
	fixnum_divisor_show(&d, "divisor");
	//fixnum_factor_t f;
	//fixnum_init_uint16(&a, limbs_a, sizeof(limbs_a), 0xffff);
	fixnum_init_uint16(&a, limbs_a, sizeof(limbs_a), 1);
	fixnum_init_pattern(&b, limbs_b, sizeof(limbs_b), PATTERN_MAX);
	ret = fixnum_div(&b, &d, &s, 1);
	fixnum_show(&b, "result");
	printf("rest=%d\n", ret);
	//fixnum_sub_uint16(&b, 3);
	fixnum_divisor_init_from_fixnum(&d, &b, limbs_f, BLOCKS);
	fixnum_mul16(&b, &m);
	fixnum_show(&b, "result");
//	ret = fixnum_div(&a, &d, &s, 1);
//	fixnum_show(&a, "result");
//	printf("rest=%d\n", ret);
	//fixnum_set_uint16(&b, 3);
	//fixnum_add_uint16(&a, 1);
	//fixnum_show(&b, "b");
	//ret = fixnum_sub_fixnum(&b, &a, 0xff);
	//printf("ret=%d\n", ret);
	//fixnum_show(&b, "b");
	/*fixnum_shl(&a, 4);
	fixnum_shl(&a, 1);
	fixnum_show(&a, "a");
	fixnum_shr(&a, 4);
	fixnum_show(&a, "a");
	fixnum_shr(&a, 1);
	fixnum_show(&a, "a");*/
	//fixnum_show(&a, "a=2a");
	//fixnum_show(&b, "b");
	//rest = fixnum_div(&a, &f);
	//printf("rest = %d\n", rest);
	//fixnum_show(&a, "a");
	//printf("peek a 0,4 = %x\n", fixnum_peek(&a, 0, 4));
	//printf("peek a 4,4 = %x\n", fixnum_peek(&a, 4, 4));
	//printf("peek a 4,5 = %x\n", fixnum_peek(&a, 4, 5));
	//printf("peek a 3,10 = %x\n", fixnum_peek(&a, 3, 10));
	//printf("peek a 4,16 = %x\n", fixnum_peek(&a, 4, 16));
	//printf("peek a 7,16 = %x\n", fixnum_peek(&a, 7, 16));
	//fixnum_add_uint16(&a, 0x2e1);
	//ret = fixnum_mul(&a, &f);
	//fixnum_show(&a, "a");
	//printf("ret=%04x\n", ret);
	//printf("Hoi!\n");
	//for (int i = 1; i < 65536; i++) {
	//	printf("log2(%d)=%d\n", i, fixnum_log2_uint16(i));
	//}
	/*
	fixnum_set_pattern(&a, PATTERN_ZERO);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
	fixnum_show(&a, "a");
	fixnum_set_pattern(&a, PATTERN_MAX);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, 0);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
	*/
	/*
	for (int i = 0; i < 256; i++) {
		printf("%d %d %d\n", i, popcnt_helper(i), popcnt_helper2(i));
	}
	*/
}
