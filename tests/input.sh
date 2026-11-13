#!/bin/sh
# input.sh - the input may be sloppy: CRLF, upper case, extra spaces, tabs,
# empty lines, no final newline, prefixes of words and other Unicode forms;
# the terminal; signals
. tests/lib.sh

MS=00000000000000000000000000000000
A=`split "\`input TREZOR $MS\`" split 0 1 2of3`
A1=`echo "$A" | sed -n 1p`
A2=`echo "$A" | sed -n 2p`

recovers() {
	GOT=`printf "$2" "$A1" "$A2" | $S -q 2>&1`
	expect "$1" $MS "$GOT"
}

recovers "plain" 'TREZOR\n%s\n%s\n'
recovers "CRLF" 'TREZOR\r\n%s\r\n%s\r\n'
recovers "no final newline" 'TREZOR\n%s\n%s'
recovers "empty lines" 'TREZOR\n\n%s\n\n\n%s\n\n'
recovers "spaces and tabs" 'TREZOR\n  %s \t\n\t%s  \n'
UPPER=`echo "$A1" | tr a-z A-Z | sed 's/ /   /g'`
GOT=`printf 'TREZOR\n%s\n%s\n' "$UPPER" "$A2" | $S -q`
expect "upper case" $MS "$GOT"
SHORT=`echo "$A1" | awk '{ for (i = 1; i <= NF; i++) printf "%s ", substr($i, 1, 4) }'`
GOT=`printf 'TREZOR\n%s\n%s\n' "$SHORT" "$A2" | $S -q`
expect "4 letter prefixes" $MS "$GOT"

# the master secret, in other forms
SHARES=`split "\`printf 'TREZOR\r\n%s\r\nLEGA WINN THAN YEAR WAVE SAUS WORT USEF LEGA WINN THAN YELL\r\n' $SEED\`" -c bip39 split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q -c bip39`
expect "bip39 prefixes, upper case, CRLF" "legal winner thank year wave sausage worth useful legal winner thank yellow" "$GOT"

# NFC input for a wordlist in NFD (spanish: a + combining acute accent)
W=`printf '\303\241baco'`
NFC=""
i=0
while [ $i -lt 23 ]; do NFC="$NFC$W "; i=$(($i+1)); done
NFC="${NFC}ancla"
SHARES=`split "\`input TREZOR "$NFC"\`" -c bip39:spanish split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q`
expect "bip39 spanish NFC" $MS$MS "$GOT"

# japanese with ordinary spaces instead of U+3000
JA=`input TREZOR 00112233445566778899aabbccddeeff | $S -q split 0 1 1of1 |
	(echo TREZOR; cat) | $S -c bip39:japanese`
U3000=`printf '\343\200\200'`
JA_SPACES=`echo "$JA" | LC_ALL=C sed "s/$U3000/ /g"`
SHARES=`split "\`input TREZOR "$JA_SPACES"\`" -c bip39:japanese split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q`
expect "bip39 japanese with spaces" 00112233445566778899aabbccddeeff "$GOT"
case "$JA" in *"$U3000"*) pass ;;
	*) fail "bip39 japanese is written with U+3000" ;; esac

# a word that occurs twice in the wordlist
SHARES=`split "\`input TREZOR "abc hij ijk kootte buks"\`" -c diceware:dutch:5 split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q -c diceware:dutch:5`
expect "diceware dutch duplicate words" "abc hij ijk kootte buks" "$GOT"

# a word that is not in NFKD in the wordlist
SHARES=`split "\`input TREZOR "cm3 aal"\`" -c diceware:german:2 split 0 1 1of1`
GOT=`printf 'TREZOR\n%s\n' "$SHARES" | $S -q -c diceware:german:2`
expect "diceware german cm3" "cm³ aal" "$GOT"

# the terminal
if command -v python3 >/dev/null; then
	OUT=`tests/terminal.py TREZOR TREZOR "$SEED" $MS $MS -- $S -q split 0 1 2of3`
	contains "tty: prompt" "passphrase (again): " "$OUT"
	contains "tty: exit status" "exit status 0" "$OUT"
	case "$OUT" in *TREZOR*|*$SEED*|*$MS*) fail "tty: echo of secrets" ;;
		*) pass ;; esac
	T1=`echo "$OUT" | grep -E '^([a-z]+ ){19}[a-z]+$' | sed -n 1p`
	T3=`echo "$OUT" | grep -E '^([a-z]+ ){19}[a-z]+$' | sed -n 3p`
	OUT=`tests/terminal.py TREZOR "$T1" "$T3" -- $S`
	contains "tty: recover stops with enough shares" "$MS
exit status 0" "$OUT"
	OUT=`tests/terminal.py TREZOR TREZR -- $S split 0 1 1of1`
	contains "tty: passphrases differ" "the passphrases do not match" "$OUT"
	OUT=`tests/terminal.py TREZOR TREZOR "" $MS $MS -- $S split 0 1 1of1`
	contains "tty: random seed" "slip0039:seed:" "$OUT"
else
	echo "input.sh: python3 not found, the terminal is not tested"
fi

# a signal wipes the secrets and kills the program with that signal
printf 'TREZOR\n%s\n%s\n' "$SEED" $MS > /tmp/slip0039-test-$$.in
$S split 15 1 1of1 < /tmp/slip0039-test-$$.in > /dev/null \
	2> /tmp/slip0039-test-$$.err &
PID=$!
sleep 1
kill -TERM $PID
wait $PID
RC=$?
expect "signal: exit status" 143 $RC
contains "signal: message" "caught signal 15" "`cat /tmp/slip0039-test-$$.err`"
rm -f /tmp/slip0039-test-$$.in /tmp/slip0039-test-$$.err

summary input
