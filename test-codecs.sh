#!/bin/sh
OUT=$(echo -n "TREZOR\n00000000000000000000000000000000\n" | ./slip0039 split lkjsfkjdsh 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39:english
OUT=$(echo -n "TREZOR\n7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f\n" | ./slip0039 split lkjsfkjdsh 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39
OUT=$(echo -n "TREZOR\n0000000000000000000000000000000000000000000000000000000000000000\n" | ./slip0039 split lkjsfkjdsh 1 1 1of1)
echo "TREZOR\n$OUT\n" | ./slip0039 -c bip39

