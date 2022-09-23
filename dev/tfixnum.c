#include "dev.h"

int main(int argc, char *argv[]) {
	uint8_t limbs_a[BLOCKS], /*limbs_b[BLOCKS],*/ limbs_f[BLOCKS];
	uint16_t ret;
	fixnum_t a;//, b;
	wordlists_init();
	//fixnum_factor_t f;
	//fixnum_init_uint16(&a, limbs_a, sizeof(limbs_a), 0xffff);
	fixnum_init_uint16(&a, limbs_a, sizeof(limbs_a), 1);
	//fixnum_init_pattern(&b, limbs_b, sizeof(limbs_b), PATTERN_ADD11);
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
	fixnum_set_pattern(&a, PATTERN_ZERO);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
	fixnum_show(&a, "a");
	fixnum_set_pattern(&a, PATTERN_MAX);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, 0);
	fixnum_show(&a, "a");
	fixnum_poke(&a, 1, 17, (1<<17) - 1);
}
