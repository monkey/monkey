#!/bin/sh
TEST_FILES=`ls *.htt`
TOTAL_TESTS=`echo $TEST_FILES | wc -w`

# Server parameters file
CONFIG_FILE='__CONFIG'

LOGFILE='errors.log'

# Clear log file
:>$LOGFILE

# Should we stop at the first error? (yes | no)
STOP_AT_ERRORS=no

# httest error code for 'Connection refused'
CONN_REFUSED=111

# Enable colors in output :) (yes | no)
WITH_COLOR=yes

# httest command 
HTTEST_CMD='httest'

NTEST=1
for test_file in $TEST_FILES; do
#	echo -ne "[TEST $NTEST/$TOTAL_TESTS]\t""case: $test_file\t\t"
	printf "[%3d/%d]  %-32s  " $NTEST $TOTAL_TESTS "$test_file"

	OUTPUT=`$HTTEST_CMD "$test_file" 2>&1`
	ERRCODE=$?	

	case $ERRCODE in
		0) 
			[ $WITH_COLOR = yes ] && echo -n "[1;32m"
			echo "=> [OK]"
			[ $WITH_COLOR = yes ] && echo -n "[m"
			;;

		$CONN_REFUSED)
			echo
			echo "Connection refused... (Is monkey running?)" >&2
			exit $CONN_REFUSED
			;;

		*)
			[ $WITH_COLOR = yes ] && echo -n "[1;31m"
			echo "=> [FAILED]"
			[ $WITH_COLOR = yes ] && echo -n "[m"

			perl -e 'print "-" x 78, "\n"' >>"$LOGFILE"
			echo "$OUTPUT" >>"$LOGFILE"
			perl -e 'print "-" x 78, "\n"' >>"$LOGFILE"

			[ $STOP_AT_ERRORS = yes ] && exit 1
	esac		

	NTEST=$((NTEST+1))
done
