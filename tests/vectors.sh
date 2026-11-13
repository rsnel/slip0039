#!/bin/sh
# vectors.sh - run the official SLIP-0039 test vectors (and our own, from
# number 41) through slip0039 recover
. tests/lib.sh

JQ="`command -v jq`"
VECTORS=tests/vectors.json
if [ ! -x "$JQ" ]; then
	echo "vectors.sh: executable jq not found"
	exit 1
fi

COUNT=`$JQ length < "$VECTORS"`
i=0
while [ $i -lt $COUNT ]; do
	TEST=`$JQ ".[$i]" < $VECTORS`
	DESC=`echo "$TEST" | $JQ -r ".[0]"`
	MNEMONICS=`echo "$TEST" | $JQ -r ".[1] | .[]"`
	SECRET=`echo "$TEST" | $JQ -r ".[2]"`
	RESULT=`printf 'TREZOR\n%s\n' "$MNEMONICS" | $S 2>/dev/null`
	RC=$?
	if [ "$SECRET" = "" ]; then
		# an invalid set of mnemonics, recover must fail
		if [ "$RC" != "0" ]; then pass
		else fail "$DESC (should fail)"; fi
	else
		expect "$DESC" "$SECRET" "$RESULT"
	fi
	i=$(($i+1))
done

summary vectors
