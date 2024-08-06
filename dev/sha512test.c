#include "../sha512.h"
#include "../hmac.h"
#include "../pbkdf2.h"
#include "../base.h"
#include "../wordlists.h"
#include "../verbose.h"
#include "../codec.h"
#include "../utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void show(uint8_t *buf) {
	for (int i = 0; i < 64; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[]) {
	base_scratch_t bs;
	char scratch[1024];
	verbose_init(argv[0]);
	codec_init();
	wordlists_init();
	base_init_scratch(&bs, scratch, 1024/4);
	//char msg[3] = "abc";
	uint8_t stuff[64];
	struct sha512_ctx ctx;
	char sha256[32];
	uint16_t bla[120] = { };
	//sha512_init(&ctx);
	//sha512_update(&ctx, msg, 3);
	//sha512_finalize(&ctx, stuff, 64);
	//show(stuff);
	char bip32[82] = { 0x04, 0x88, 0xad, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
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

	hmac(stuff, 64, "Bitcoin seed", 12, stuff, 64, type);
	show(stuff);
	memcpy(bip32 + 13, stuff + 32, 32);
	memcpy(bip32 + 46, stuff, 32);

	//hash(sha256, sizeof(sha256), bip32, 78, HASH_SHA256);
	//hash(sha256, sizeof(sha256), sha256, 32, HASH_SHA256);
	//memcpy(bip32 + 78, sha256, 4);
	hash(bip32 + 78, 4, bip32, 78, HASH_SHA256D);

	base_encode_buffer(bla, 111, &wordlist_base58.m, bip32, 82, &bs, 0);
	for (int i = 0; i < 111; i++) {
		const char *str = wordlist_base58.words[bla[i]];
		printf("%s", str); //wordlist_base58.words[bla[i]]);
		//printf("[%3d]=%d %s\n", i, bla[i], str); //wordlist_base58.words[bla[i]]);
		//printf("[%3d]=%d %s\n", i, bla[i], wordlist_base58.words[bla[i]]);
	}
	printf("\n");

	const char *xprv = "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF";
	const char *ptr = xprv;
	int index = 0;

	while (*ptr) {
		bla[index] = wordlist_search(&wordlist_base58, ptr, &ptr);
		index++;
	}
	for (int i = 0; i < 111; i++) {
		const char *str = wordlist_base58.words[bla[i]];
		printf("%s", str); //wordlist_base58.words[bla[i]]);
		//printf("[%3d]=%d %s\n", i, bla[i], str); //wordlist_base58.words[bla[i]]);
		//printf("[%3d]=%d %s\n", i, bla[i], wordlist_base58.words[bla[i]]);
	}
	printf("\n");
	base_decode_buffer(bip32, 82, &wordlist_base58.m, bla, index, 0);
	for (int i = 0; i < 82; i++) {
		printf("%02x", (uint8_t)bip32[i]);
	}

	printf("\n");


	//printf("%s\n", wordlist_base58.words[1]);

	exit(0);
}

