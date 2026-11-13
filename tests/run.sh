#!/bin/sh
# run.sh - run all tests, in the top directory of the source after make
#
# needs jq and python3; node is optional, without it the JavaScript port
# of the website is not tested

cd "`dirname "$0"`/.." || exit 1

if [ ! -x ./slip0039 ]; then
	echo "run.sh: ./slip0039 not found, run make first"
	exit 1
fi

STATUS=0

run() {
	if ! "$@"; then STATUS=1; fi
}

run sh tests/vectors.sh
run sh tests/codecs.sh
run sh tests/errors.sh
run sh tests/input.sh 2>/dev/null
run sh tests/verify.sh

# the encodings must not change, or existing shares can not be recovered
if sh tests/golden.sh | diff tests/golden.expected - > /dev/null; then
	echo "golden: the output of all codecs is unchanged"
else
	echo "golden: FAILED, the output differs from tests/golden.expected:"
	sh tests/golden.sh | diff tests/golden.expected - | head -20
	STATUS=1
fi

if command -v node >/dev/null; then
	run node tests/js.js
else
	echo "js: node not found, doc/slip0039.js is not tested"
fi

if [ "$STATUS" = "0" ]; then echo "all tests passed"
else echo "SOME TESTS FAILED"; fi

exit $STATUS
