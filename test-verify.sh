#!/bin/sh
# check that verify.py reproduces the shares created by slip0039 split
SEED="gUaRlvJDNiDFTjrJfmghruaDh47Tnm9jZCnTBnFZI5axMqxxry6j3zys1Fz67kgx"
PASSED=0
COUNT=0
for ARGS in "0 1 1of1" "1 1 2of3" "0 2 2of3 3of5 1of1" \
	"0 3 2of2 1of1 4of7 5of5" "--pre-may-2024 0 2 1of1 2of3"; do
	for MS in 00000000000000000000000000000000 \
		b57d229378164c7c82e3426d0f953aa12cefcfb19b8ac9bb5a80508fa8d64c1c; do
		COUNT=$(($COUNT+1))
		INPUT="TREZOR\n$SEED\n$MS\n"
		if [ -n "`echo -n "$INPUT" | ./slip0039 -q split $ARGS`" ] &&
			[ "`echo -n "$INPUT" | ./slip0039 -q split $ARGS`" = \
			"`echo -n "$INPUT" | ./verify.py $ARGS`" ]; then
			PASSED=$(($PASSED+1))
		else
			echo "Failed: $ARGS $MS"
		fi
	done
done
echo passed "$PASSED/$COUNT" tests
