#!/bin/sh
PLAINTEXT="4c0ad4b46fbf3ef0ce7b36d8fe5812a1"
PLAINTEXT="00000000000000000000000000000000"
PLAINTEXT="b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c"
SEED="gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx"
PASSPHRASE="TREZOR"
PENS="$PASSPHRASE\n$SEED\n"
OUT=$(echo -n "${PENS}$PLAINTEXT\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c base16
#echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39:english
#echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware:english
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware:dutch:10

OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n0000000000000000000000000000000000000000000000000000000000000000\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39:spanish
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n00000000000000000000000000000000\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware::9
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware:dutch:10

XPRV="xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n$XPRV\n" | ./slip0039 -c bip32::xprv split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip32::xprv
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip32::zprv
SEED="gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx"
for T in "password::20 aB3dE5gH7jK9mN1pQ3sT" "numeric::6 012345" \
	"totp::32 JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" \
	"wif::compressed KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617" \
	"nostr nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5" \
	"codex32::3cash ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln"; do
	set -- $T
	OUT=$(echo -n "TREZOR\n$SEED\n$2\n" | ./slip0039 -c $1 split 1 1 1of1)
	echo "TREZOR\n$OUT\n" | ./slip0039 -c $1
done
