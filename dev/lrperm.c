/* check if lrcipher produces nice 'permutations', yes it does! */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../lrcipher.h"

int main(int argc, char *argv[]) {
	lrcipher_t lr;
	int rounds = 0;
	uint16_t start =  0x7f81, in, out = 0;
	lrcipher_init(&lr);
	lrcipher_add_passphrase(&lr, "0123456789abcdef", 16);
	in = start;
	goto start;
	do {
		lrcipher_execute(&lr, (unsigned char*)&out, (unsigned char*)&in, 2, 1, LRCIPHER_ENCRYPT);
		rounds++;
		in = out;
start:
		printf("%0000d %04x\n", rounds, in);
	} while (out != start);
	exit(0);
}
