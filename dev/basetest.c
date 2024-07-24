

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "dev.h"
#include "../base.h"

uint8_t base_scratch_space[(BLOCKS<<1)<<2];

uint8_t in1[3] = { 0x62, 0x62, 0x62 };
uint16_t out1[4];

uint8_t in2[4] = { 0xff, 0xff, 0xff, 0xff };
uint16_t out2[10];

uint8_t in3[5] = { 0x7e, 0x00, 0x00, 0x00, 0x00 };
uint16_t out3[5];

int main(int argc, char *argv[]) {
	base_scratch_t bs;
	fixnum_multiplier16_t m;

	verbose_init(argv[0]);
	fixnum_multiplier16_init(&m, 59);
	base_init_scratch(&bs, base_scratch_space, BLOCKS<<1);
	
	base_encode_buffer(out1, 4, &m, in1, 3, &bs);
	for (int i = 0; i < 4; i++) printf("out[%d]=%d\n", i, out1[i]);
	base_decode_buffer(in1, 3, &m, out1, 4);
	for (int i = 0; i < 3; i++) printf("in[%d]=%02x\n", i, in1[i]);

	fixnum_multiplier16_init(&m, 10);
	for (int i = 0; i < 4; i++) printf("in[%d]=%02x\n", i, in2[i]);
	base_encode_buffer(out2, 10, &m, in2, 4, &bs);
	for (int i = 0; i < 10; i++) printf("out[%d]=%d\n", i, out2[i]);
	base_decode_buffer(in2, 4, &m, out2, 10);
	for (int i = 0; i < 4; i++) printf("in[%d]=%02x\n", i, in2[i]);

	fixnum_multiplier16_init(&m, 1024);
	base_encode_buffer(out3, 4, &m, in3, 5, &bs);
	for (int i = 0; i < 4; i++) printf("out[%d]=%02x\n", i, out3[i]);

}

