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
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware:dutch

OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n0000000000000000000000000000000000000000000000000000000000000000\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39:spanish
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n00000000000000000000000000000000\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
OUT=$(echo -n "TREZOR\nlkjsfkjdsh\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c diceware:dutch

