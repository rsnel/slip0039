# lib.sh - helpers for the tests, sourced by the test scripts
#
# the tests run in the top directory of the source, with ./slip0039

S=./slip0039
SEED="gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx"
PASSED=0
FAILED=0

pass() {
	PASSED=$(($PASSED+1))
}

fail() {
	FAILED=$(($FAILED+1))
	echo "FAILED: $*"
}

# expect NAME EXPECTED ACTUAL
expect() {
	if [ "x$2" = "x$3" ]; then pass
	else
		fail "$1"
		echo "  expected: $2"
		echo "  got:      $3"
	fi
}

# contains NAME SUBSTRING TEXT
contains() {
	case "$3" in
		*"$2"*) pass ;;
		*) fail "$1"; echo "  expected to contain: $2"
			echo "  got: $3" ;;
	esac
}

# split INPUT ARGS..., prints the shares
split() {
	INPUT=$1
	shift
	printf '%s' "$INPUT" | $S -q "$@"
}

# the input of split: passphrase, seed and master secret
input() {
	printf '%s\n%s\n%s\n' "$1" "$SEED" "$2"
}

# fails NAME SUBSTRING INPUT ARGS..., the program must fail with an error
# message that contains SUBSTRING
fails() {
	NAME=$1
	SUB=$2
	INPUT=$3
	shift 3
	OUT=`printf '%s' "$INPUT" | $S "$@" 2>&1`
	RC=$?
	if [ "$RC" = "0" ]; then
		fail "$NAME (exit status 0)"
		echo "  output: $OUT"
	else contains "$NAME" "$SUB" "$OUT"; fi
}

summary() {
	echo "$1: passed $PASSED/$(($PASSED+$FAILED)) tests"
	[ "$FAILED" = "0" ]
}
