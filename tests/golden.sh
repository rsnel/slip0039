#!/bin/sh
# golden.sh - print the shares that split makes for every codec, and what
# recover gives with the right and with wrong passphrases
#
# the output is compared to tests/golden.expected by tests/run.sh, so that
# a change to an encoding (which would make existing shares unrecoverable)
# does not go unnoticed; regenerate it only if such a change is intended
#
# usage: tests/golden.sh [SLIP0039]

S=${1:-./slip0039}
SEED="gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx"

# codec secret split-arguments
golden() {
	CODEC=$1
	SECRET=$2
	shift 2
	echo "### -c $CODEC split $*"
	OUT=`printf 'TREZOR\n%s\n%s\n' "$SEED" "$SECRET" |
		$S -q -c $CODEC split "$@"`
	echo "$OUT"
	for P in TREZOR wrong "another one" ""; do
		echo "## passphrase \"$P\""
		printf '%s\n%s\n' "$P" "$OUT" | $S -q -c $CODEC recover
	done
}

golden base16 00000000000000000000000000000000 0 1 1of1
golden base16 b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c 1 2 2of3 3of5 1of1
golden bip39 "legal winner thank year wave sausage worth useful legal winner thank yellow" 0 1 2of3
golden bip39:spanish "abuelo azul filtro arte prueba veneno adulto guion grueso enigma usar surco" 0 1 1of1
golden diceware::6 "a a&p a's aa aaa aaaa" 0 1 1of1
golden diceware:dutch:10 "kootte buks fel amanda jolige gaucho geluk kam essen lakei" 0 1 2of2
golden diceware:german:5 "0 1 2 0 1" 0 1 1of1
golden password::20 aB3dE5gH7jK9mN1pQ3sT 0 1 1of1
golden password:ascii:16 'a"b\c$d%e&f(g)h*' 0 1 1of1
golden password:lower:12 abcdefghijkl 0 1 1of1
golden password:alpha:12 abcdefGHIJKL 0 1 1of1
golden numeric::6 012345 0 1 2of3
golden totp::32 JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP 0 1 1of1
golden totp::26 "jbsw y3dp ehpk 3pxp jbsw y3dp ee" 0 1 1of1
golden bip32::xprv xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi 0 1 1of1
golden wif::compressed KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 0 1 1of1
golden wif::uncompressed 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ 0 1 1of1
golden nostr nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5 0 1 1of1
golden codex32::3cash ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln 0 1 1of1
golden codex32::0TEST MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW 0 1 1of1
golden base16 00000000000000000000000000000000 --pre-may-2024 0 2 1of1 2of3
