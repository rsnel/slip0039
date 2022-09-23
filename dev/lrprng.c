/* check if lrcipher produces nice 'permutations', yes it does! */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "dev.h"
#include "../lrcipher.h"
#include "../fixnum.h"
#include "../wordlists.h"

int main(int argc, char *argv[]) {
	lrcipher_t lr, prng;
	int rounds = 0;
	uint8_t in[16] = { };
	uint8_t comp[16] = { };
	uint8_t target[16] = { 0xc0, };
	uint8_t out[16]; 
	uint8_t max[16];
	fixnum_t i, o, m, t, c;
	wordlists_init();
	fixnum_multiplier_t mul6, mul3273;
	fixnum_multiplier_init(&mul6, 6);
	fixnum_multiplier_init(&mul3273, 3273);
	fixnum_init(&i, in, 16);
	fixnum_init(&t, target, 16);
	fixnum_init(&o, out, 16);
	fixnum_init(&c, comp, 16);
	fixnum_init_uint16(&m, max, 16, 1);
	fixnum_sub_fixnum(&c, &t, 0xff);
	for (int i = 0; i < 45; i++) fixnum_mul(&m, &mul6);
	fixnum_mul(&m, &mul3273);
	fixnum_show(&m, "max");
	fixnum_show(&i, "input");
	fixnum_show(&t, "target");
	fixnum_show(&c, "comp");
	lrcipher_init(&prng);
	lrcipher_init(&lr);
	lrcipher_add_passphrase(&lr, "0123456789abcdef", 16);
	lrcipher_finalize_passphrase(&lr, "shamir", 6, 0x0000);
	lrcipher_execute(&lr, (unsigned char*)&out, (unsigned char*)&in, 16, 1, LRCIPHER_ENCRYPT);
	fixnum_show(&o, "output");
	lrcipher_add_passphrase(&prng, out, 16);
	for (int i = 0; i < 16; i++) {
		lrcipher_t tmp = prng;
		lrcipher_finalize_passphrase(&tmp, "test", 4, i);
		lrcipher_execute(&tmp, (unsigned char*)&out, in, 16, 1, LRCIPHER_DECRYPT);
		fixnum_show(&o, "prng");
	}
	exit(0);
}
