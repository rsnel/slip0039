#!/bin/sh
# verify.sh - check that verify.py reproduces the shares created by
# slip0039 split, for every codec
. tests/lib.sh

if ! command -v python3 >/dev/null; then
	echo "verify.sh: python3 not found"
	exit 1
fi

# same NAME ARGS..., the input is in $INPUT
same() {
	NAME=$1
	shift
	A=`printf '%s' "$INPUT" | $S -q "$@" 2>&1`
	B=`printf '%s' "$INPUT" | ./verify.py "$@" 2>&1`
	if [ -n "$A" ] && [ "$A" = "$B" ]; then pass
	else
		fail "$NAME: $*"
		echo "  slip0039:  `echo "$A" | head -1`"
		echo "  verify.py: `echo "$B" | head -1`"
	fi
}

for ARGS in "0 1 1of1" "1 1 2of3" "0 2 2of3 3of5 1of1" \
	"0 3 2of2 1of1 4of7 5of5" "0 1 16of16" "--pre-may-2024 0 2 1of1 2of3"; do
	for MS in 00000000000000000000000000000000 \
		b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c \
		000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f; do
		INPUT=`input TREZOR $MS`
		same base16 split $ARGS
	done
done

# a secret in the format of a codec, made from a master secret in base16
from_hex() {
	printf 'TREZOR\n%s\n%s\n' "$SEED" "$2" | $S -q split 0 1 1of1 |
		(echo TREZOR; cat) | $S -q -c $1
}

for L in english spanish french italian portuguese czech japanese korean \
	chinese_simplified chinese_traditional; do
	INPUT=`input TREZOR "$(from_hex bip39:$L 00112233445566778899aabbccddeeff)"`
	same bip39:$L split -c bip39:$L 0 1 2of3
	INPUT=`input "" "$(from_hex bip39:$L 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)"`
	same bip39:$L split -c bip39:$L 1 1 1of1
done

LONG_CODEX32=`from_hex codex32::0lxng 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f`

while read -r CODEC SECRET; do
	INPUT=`input TREZOR "$SECRET"`
	same "$CODEC" split -c $CODEC 0 1 2of3
	same "$CODEC" split -c $CODEC --gain 0.0001 1 2 1of1 2of2
done <<EOF
bip39 LEGA WINN THAN YEAR WAVE SAUS WORT USEF LEGA WINN THAN YELL
diceware::6 a a&p a's aa aaa aaaa
diceware:dutch:7 abc hij ijk kootte buks beauté Assen
diceware:german:3 cm³ aal 0
password::20 aB3dE5gH7jK9mN1pQ3sT
password:ascii:16 a"b\c\$d%e&f(g)h*
password:lower:30 abcdefghijklmnopqrstuvwxyzabcd
numeric::6 012345
numeric::60 012345678901234567890123456789012345678901234567890123456789
totp::32 jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp
totp::26 JBSWY3DPEHPK3PXPJBSWY3DPEE
bip32::xprv xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
wif::compressed KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
wif::uncompressed 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
nostr nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5
codex32::3cash ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln
codex32::0TEST MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW
codex32::0lxng $LONG_CODEX32
EOF

summary verify
