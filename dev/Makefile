LDLIBS=-lm

all: tfixnum 16tothe32 lrperm twordlist ta prob basetest wordeq lrprng probsim fakedist

fakedist:

lrprng: lrprng.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

tfixnum: tfixnum.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

16tothe32: 16tothe32.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

lrperm: lrperm.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

twordlist: twordlist.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

ta: ta.c dev.c ../sha256.c ../hmac.c ../pbkdf2.c ../lrcipher.c ../fixnum.c ../utils.c ../wordlists.c ../verbose.c

wordeq: wordeq.c dev.c ../utils.c ../wordlists.c ../verbose.c ../fixnum.c

prob.c:

probsim.c:

basetest: basetest.c ../fixnum.c ../base.c ../verbose.c dev.c ../utils.c ../wordlists.c
