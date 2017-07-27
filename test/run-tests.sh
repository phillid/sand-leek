#!/bin/sh


fail()
{
	echo -e '[\e[1;31mFAIL\e[0m] '$i: $@
	exit 1
}

pass()
{
	echo -e '[\e[0;32mPASS\e[0m] '$i
}

check_expected()
{
	[ -z $1 ] && echo WARN: check_expected called with no argument
	if [ -f $1.expected ] ; then
		diff $1.expected $1.tmp >/dev/null
		if [ $? -ne 0 ] ; then
			fail "$1 didn't match expected"
		fi
	fi
}

pushd $(dirname $0) >/dev/null
EXECUTABLE="../../sand-leek"
for i in *.test ; do
	pushd ${i} >/dev/null
	( . ./run.sh ) 2>stderr.tmp >stdout.tmp
	if [ $? -ne 0 ] ; then
		fail "script had non-zero return code"
	fi

	check_expected stdout
	check_expected stderr

	pass $i

	rm std{err,out}.tmp
	popd >/dev/null
done
popd >/dev/null
