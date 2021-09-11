#!/bin/sh
# simple script to run the official slip0039
# test vectors through slip0039
JQ="`which jq`"
VECTORS=vectors.json
if [ ! -x $JQ ]; then
	echo "executable jq not found"
	exit 1
fi
if [ ! -r "$VECTORS" ]; then
	echo "testfile $VECTORS not found"
	exit 1
fi
COUNT=`$JQ length < "$VECTORS"`
PASSED=0
echo running $COUNT tests
for i in `seq 1 $COUNT`; do
	TEST=`$JQ .[$i-1] < $VECTORS`
	MNENOMICS=`echo $TEST | $JQ -r ".[1] | .[]"`
	SECRET=`echo $TEST | $JQ -r ".[2]"`
	echo "----------"
	echo "running test" `echo $TEST | $JQ --raw-output .[0] `
	# as we are using the Bourne shell, echo does not need
	# the -e option to interpret \n the wat we want
	RESULT=`echo "TREZOR\n$MNENOMICS" | ./slip0039 -d`
	SUCCESS=$?
	if [ "$SUCCESS" = "1" ]; 
		then if [ "$SECRET" = "" ]; then
			PASSED=$(($PASSED+1))
			echo Passed
		else
			echo Failed

		fi
	elif [ "x$RESULT" = "x$SECRET" ]; then
		PASSED=$(($PASSED+1))
		echo Passed
	else 
		echo Failed
	fi
done
echo "----------"
echo passed "$PASSED/$COUNT" tests
