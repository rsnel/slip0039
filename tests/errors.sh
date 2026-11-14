#!/bin/sh
# errors.sh - invalid input must be refused with a clear error message
. tests/lib.sh

MS=00000000000000000000000000000000
IN=`input TREZOR $MS`

# command line
fails "group threshold 0" "group threshold must be >= 1" "$IN" split 0 0 2of3
fails "not enough groups" "not enough groups" "$IN" split 0 3 2of3 1of1
fails "iteration exponent 16" "must be <= 15" "$IN" split 16 1 1of1
fails "iteration exponent 32" "must be <= 31" "$IN" --pre-may-2024 split 32 1 1of1
fails "X > Y" "Y in group spec XofY must be >= 3" "$IN" split 0 1 3of2
fails "no of" "separated by 'of'" "$IN" split 0 1 3to5
fails "17 shares" "must be <= 16" "$IN" split 0 1 2of17
fails "unknown option" "unknown option --bogus" "$IN" --bogus
fails "unknown mode" "must be \"recover\", \"check\" or \"split\"" "$IN" spilt
fails "argument after recover" "no arguments must be given" "$IN" recover 1
fails "unknown codec" "codec bogus not available" "$IN" -c bogus
fails "codec without argument" "needs the number of words" "$IN" -c diceware
fails "codec with argument" "does not take an argument" "$IN" -c bip39:english:12
fails "unknown wordlist" "wordlist \"klingon\" not found" "$IN" -c bip39:klingon
fails "unknown bip32 version" "unknown version" "$IN" -c bip32::abcd
fails "bip32 public version" "extended public key" "$IN" -c bip32::xpub
fails "invalid gain" "invalid value" "$IN" --gain 2
fails "--random-seed with recover" "only be used with split" "$IN" --random-seed
fails "no input" "end of input while reading passphrase" "" split 0 1 1of1

# --help and --version work if the memory can not be locked
# (root can lock memory whatever the limit is, then this tests nothing)
GOT=`(ulimit -l 64 2>/dev/null; $S --help) 2>&1 | sed -n 1p`
contains "--help with a low limit of locked memory" "usage: " "$GOT"
GOT=`(ulimit -l 64 2>/dev/null; $S -c numeric::6 --version) 2>&1`
contains "--version with a low limit of locked memory" "slip0039 " "$GOT"

# master secrets
fails "base16 too short" "at least 16 bytes" "`input TREZOR 0000`" split 0 1 1of1
fails "base16 odd" "multiple of 16 bits" "`input TREZOR ${MS}00`" split 0 1 1of1
fails "base16 not hex" "character 'g' not found" "`input TREZOR ${MS%??}0g`" split 0 1 1of1
fails "bip39 checksum" "checksum does not match" "`input TREZOR "legal winner thank year wave sausage worth useful legal winner thank year"`" -c bip39 split 0 1 1of1
fails "bip39 11 words" "number of words 11 not supported" "`input TREZOR "legal winner thank year wave sausage worth useful legal winner thank"`" -c bip39 split 0 1 1of1
fails "bip39 unknown word" "word 'bogus' not found" "`input TREZOR "bogus winner thank year wave sausage worth useful legal winner thank yellow"`" -c bip39 split 0 1 1of1
fails "diceware count" "the secret has 2 words, but -c specifies 3" "`input TREZOR "a a"`" -c diceware::3 split 0 1 1of1
fails "password alphabet" "character '!' not found" "`input TREZOR "abc!"`" -c password::4 split 0 1 1of1
fails "numeric too long" "does not fit" "`input TREZOR $(printf '%0200d' 0)`" -c numeric::200 split 0 1 1of1
fails "totp bits" "unused bits" "`input TREZOR JBSWY3DPEHPK3PXPJBSWY3DPEH`" -c totp::26 split 0 1 1of1
fails "totp length" "does not encode a whole number of bytes" "$IN" -c totp::3
fails "wif type" "but -c specifies uncompressed" "`input TREZOR KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617`" -c wif::uncompressed split 0 1 1of1
fails "wif checksum" "checksum does not match" "`input TREZOR KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98618`" -c wif::compressed split 0 1 1of1
fails "bip32 version mismatch" "but -c specifies zprv" "`input TREZOR xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi`" -c bip32::zprv split 0 1 1of1
fails "nostr checksum" "checksum does not match" "`input TREZOR nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe6`" -c nostr split 0 1 1of1
fails "codex32 header" "but -c specifies 0test" "`input TREZOR ms13cashsllhdmn9m42vcsamx24zrxgs3qqjzqud4m0d6nln`" -c codex32::0test split 0 1 1of1
fails "passphrase not ASCII" "not a printable ASCII character" "`input "pässword" $MS`" split 0 1 1of1
fails "master secrets do not fit" "is too long" "`input TREZOR "$(printf '%05000d' 0)"`" split 0 1 1of1

# mnemonics
A=`split "$IN" split 0 1 2of3`
B=`split "\`input TREZOR 11111111111111111111111111111111\`" split 0 1 2of3`
A1=`echo "$A" | sed -n 1p`
A2=`echo "$A" | sed -n 2p`
A3=`echo "$A" | sed -n 3p`
B1=`echo "$B" | sed -n 1p`
B3=`echo "$B" | sed -n 3p`
fails "no mnemonics" "no mnemonics given" "TREZOR
"
fails "one share of two" "not enough shares" "TREZOR
$A1"
fails "report of missing shares" "1 more needed (line 2)" "TREZOR
$A1"
fails "same share twice" "the mnemonic on line 3 is the same share as the one on line 2" "TREZOR
$A1
$A1"
fails "extra share of another split" "the mnemonic on line 4 does not belong to the same secret as the other mnemonics of group 1" "TREZOR
$A1
$A2
$B3"
fails "share of another split" "the digest of group 1 does not match" "TREZOR
$B1
$A2"
fails "typo in a word" "checksum of mnemonic on line 2 is not valid" "TREZOR
`echo "$A1" | sed 's/ [a-z]*$/ academic/'`
$A2"
fails "unknown word" "word 'bogus' not found in the slip0039 wordlist" "TREZOR
bogus $A1"
fails "line 3 after an empty line" "on line 4" "TREZOR
$A1

bogus $A2"
fails "a short word" "word 'ac' not found" "TREZOR
`echo "$A1" | sed 's/^[a-z]*/ac/'`"
fails "a long line" "too long" "TREZOR
`printf '%05000d' 0`"

# groups: 2 of 3 groups, one group from another split with the same SEED
A=`split "$IN" split 0 2 1of1 1of1 1of1`
B=`split "\`input TREZOR 11111111111111111111111111111111\`" split 0 2 1of1 1of1 1of1`
fails "extra group of another split" "group 3 does not belong to the same master secret as the other groups" "TREZOR
`echo "$A" | sed -n 1,2p`
`echo "$B" | sed -n 3p`"
fails "group of another split" "the digest of the master secret does not match" "TREZOR
`echo "$B" | sed -n 1p`
`echo "$A" | sed -n 2p`"
GOT=`printf 'TREZOR\n%s\n' "$A" | $S 2>&1`
expect "all three groups" $MS "$GOT"

# check mode
GOT=`printf '%s\n%s\n' "$A1" "$A3" | $S check`
contains "check: complete" "the shares belong together" "$GOT"
contains "check: group" "group 1 (academic): 2 of 2 shares, complete (lines 1, 2)" "$GOT"
GOT=`printf '%s\n' "$A1" | $S check`
RC=$?
expect "check: incomplete exit status" 1 "$RC"
contains "check: incomplete" "1 more needed" "$GOT"
fails "check: extra share of another split" "does not belong" "$A1
$A2
$B3" check

summary errors
