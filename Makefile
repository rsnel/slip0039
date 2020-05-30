CFLAGS=-Wall -g
slip0039: slip0039.c wordlist.c wordlists.h gf256.c gf256.h sha256.c sha256.h rs1024.c rs1024.h utils.h config.h lrcipher.c lrcipher.h slip0039.h utils.c pbkdf2.c pbkdf2.h hmac.c hmac.h lagrange.c lagrange.h base1024.h base1024.c digest.c digest.h verbose.h verbose.c

wordlists.c: wordlist_slip0039.txt wordlists2c.sh
	sh wordlists2c.sh wordlist_slip0039.txt > wordlists.c

clean:
	rm -f slp0039 wordlists.c

test:
	./test.sh
