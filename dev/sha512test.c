#include "../sha512.h"
#include "../hmac.h"
#include "../pbkdf2.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void show(uint8_t *buf) {
	for (int i = 0; i < 64; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

int main(int argc, char *argv) {
	//char msg[3] = "abc";
	uint8_t stuff[64];
	struct sha512_ctx ctx;
	//sha512_init(&ctx);
	//sha512_update(&ctx, msg, 3);
	//sha512_finalize(&ctx, stuff, 64);
	//show(stuff);
	const char key[] = {
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
	};
	const char msg[8] = "Hi There";

	const char words[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	const char passphrase[] = "mnemonicTREZOR";
	//hmac(stuff, 64, key, 20, msg, 8, HASH_SHA512);
	//show(stuff);
	hash_type_t type = HASH_SHA512;
	pbkdf2(stuff, words, strlen(words), passphrase, strlen(passphrase), 2048, 64, type);
	show(stuff);

	exit(0);
}

