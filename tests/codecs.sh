#!/bin/sh
# codecs.sh - every codec: recover gives the secret that was split, and a
# wrong passphrase gives a secret of the same format
. tests/lib.sh

# roundtrip CODEC SECRET [EXPECTED [PATTERN]]: split SECRET, recover it,
# the result must be EXPECTED (default SECRET); with a wrong passphrase
# the result must match the extended regular expression PATTERN
roundtrip() {
	CODEC=$1
	SECRET=$2
	EXPECTED=${3:-$2}
	PATTERN=$4
	SHARES=`input TREZOR "$SECRET" | $S -q -c $CODEC split 0 1 2of3`
	GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q -c $CODEC`
	expect "roundtrip $CODEC" "$EXPECTED" "$GOT"
	[ -z "$PATTERN" ] && return
	for P in wrong "" "another one"; do
		GOT=`printf '%s\n%s\n' "$P" "$SHARES" | $S -q -c $CODEC`
		if printf '%s' "$GOT" | grep -Eqx "$PATTERN" &&
				[ "$GOT" != "$EXPECTED" ]; then pass
		else fail "$CODEC with passphrase \"$P\" gave \"$GOT\""; fi
	done
}

roundtrip base16 00000000000000000000000000000000 "" '[0-9a-f]{32}'
roundtrip base16 b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c "" '[0-9a-f]{64}'
roundtrip base16 "0011 2233 4455 6677 8899 AABB CCDD EEFF" 00112233445566778899aabbccddeeff
roundtrip bip39 "legal winner thank year wave sausage worth useful legal winner thank yellow" "" '([a-z]+ ){11}[a-z]+'
roundtrip bip39:english "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" "" '([a-z]+ ){23}[a-z]+'
roundtrip diceware::6 "a a&p a's aa aaa aaaa" "" '([^ ]+ ){5}[^ ]+'
roundtrip diceware:dutch:10 "kootte buks fel amanda jolige gaucho geluk kam essen lakei" "" '([^ ]+ ){9}[^ ]+'
roundtrip diceware:german:5 "0 1 2 cm³ aal" "" '([^ ]+ ){4}[^ ]+'
roundtrip password::20 aB3dE5gH7jK9mN1pQ3sT "" '[0-9A-Za-z]{20}'
roundtrip password:ascii:16 'a"b\c$d%e&f(g)h*' "" '[!-~]{16}'
roundtrip password:alpha:12 abcdefGHIJKL "" '[A-Za-z]{12}'
roundtrip password:lower:12 abcdefghijkl "" '[a-z]{12}'
roundtrip numeric::6 012345 "" '[0-9]{6}'
roundtrip numeric::4 0000 "" '[0-9]{4}'
roundtrip totp::32 JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP "" '[A-Z2-7]{32}'
roundtrip totp::32 "jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp====" JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP
roundtrip bip32::xprv xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi "" 'xprv9s21ZrQH143K[1-9A-HJ-NP-Za-km-z]{95}'
roundtrip wif::compressed KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 "" '[KL][1-9A-HJ-NP-Za-km-z]{51}'
roundtrip wif::uncompressed 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ "" '5[1-9A-HJ-NP-Za-km-z]{50}'
roundtrip nostr nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5 "" 'nsec1[02-9ac-hj-np-z]{58}'
roundtrip codex32::3cash ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln "" 'ms13cashs[02-9ac-hj-np-z]{39}'
roundtrip codex32::0TEST MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXX4NZVCA9CMCZLW MS10TESTSXXXXXXXXXXXXXXXXXXXXXXXXXYWVFUCX7RV8MK8

# every BIP39 language, from the same master secret
for L in english spanish french italian portuguese czech japanese korean \
	chinese_simplified chinese_traditional; do
	M=`input TREZOR 00112233445566778899aabbccddeeff | $S -q split 0 1 1of1 |
		(echo TREZOR; cat) | $S -c bip39:$L`
	roundtrip bip39:$L "$M"
done

# the diceware codec reports how many words fit in a master secret
SHARES=`input TREZOR "a a a" | $S -q -c diceware::3 split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q -c diceware::9 | wc -w`
expect "diceware: more words from the same master secret" 9 $GOT
fails "diceware: too many words" "at most 9 words fit" "TREZOR
$SHARES" -c diceware::10

# the shares of split are the same every time
A=`input TREZOR 00000000000000000000000000000000 | $S -q split 1 2 2of3 3of5`
B=`input TREZOR 00000000000000000000000000000000 | $S -q split 1 2 2of3 3of5`
expect "split is deterministic" "$A" "$B"

# --random-seed, the seed is printed and verify.py reproduces the shares
OUT=`printf 'TREZOR\n00000000000000000000000000000000\n' |
	$S --random-seed split 0 1 2of3 2>&1`
NEWSEED=`echo "$OUT" | sed -n 's/^slip0039:seed://p'`
expect "--random-seed: length of seed" 64 "${#NEWSEED}"
SHARES=`echo "$OUT" | grep -v '^slip0039:'`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q`
expect "--random-seed: roundtrip" 00000000000000000000000000000000 "$GOT"
if command -v python3 >/dev/null; then
	GOT=`printf 'TREZOR\n%s\n00000000000000000000000000000000\n' "$NEWSEED" |
		./verify.py 0 1 2of3`
	expect "--random-seed: verify.py" "$SHARES" "$GOT"
fi

# split tells how to recover, unless the codec is base16
OUT=`input TREZOR "0 1 2 3" | $S -c diceware:german:4 split 0 1 1of1 2>&1`
contains "recover hint" "recover with: slip0039 -c diceware:german:4 recover" "$OUT"
OUT=`input TREZOR 00000000000000000000000000000000 | $S split 0 1 1of1 2>&1`
case "$OUT" in *"recover with"*) fail "no recover hint for base16" ;; *) pass ;; esac

summary codecs
