LDLIBS=-lm

all: tfixnum 16tothe32 lrperm twordlist ta prob basetest wordeq lrprng probsim fakedist sha512test

fakedist:

sha512test: sha512test.c ../sha512.c ../hmac.c ../sha256.c ../hash.c ../pbkdf2.c

lrprng: lrprng.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

tfixnum: tfixnum.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

16tothe32: 16tothe32.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

lrperm: lrperm.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

twordlist: twordlist.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

ta: ta.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../hash.c ../sha512.c

wordeq: wordeq.c dev.c ../utils.c ../wordlists.c ../verbose.c ../fixnum.c ../codec.c ../shashtbl.c ../llist.c ../base.c ../sha256.c ../lrcipher.c ../pbkdf2.c ../hmac.c ../hash.c ../sha512.c

prob.c:

probsim.c:

basetest: basetest.c ../fixnum.c ../base.c ../verbose.c dev.c ../utils.c ../wordlists.c  ../codec.c ../shashtbl.c ../llist.c ../sha256.c ../lrcipher.c ../pbkdf2.c ../hmac.c ../hash.c ../sha512.c
