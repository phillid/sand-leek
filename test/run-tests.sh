#!/bin/bash -e

fail()
{
	echo -e '[\e[1;31mFAIL\e[0m] '"$i:" "$@"
}

pass()
{
	echo -e '[\e[0;32mPASS\e[0m] '"$i"
}

check_expected()
{
	[ -z "$1" ] && echo WARN: check_expected called with no argument
	if [ -f "$1.expected" ] ; then
		if ! diff "$1.expected" "$1.tmp" >/dev/null; then
			fail "$1 didn't match expected"
			exit 1
		fi
	fi
}

pushd "$(dirname "$0")" >/dev/null
export EXECUTABLE="../../sand-leek"
for i in *.test ; do
	pushd "${i}" >/dev/null
	if ! ( . ./run.sh ) 2>stderr.tmp >stdout.tmp; then
		fail "script had non-zero return code"
		echo "stderr:"
		cat stderr.tmp
		echo "stdout:"
		cat stdout.tmp
		exit 1
	fi

	check_expected stdout
	check_expected stderr

	pass "$i"

	rm std{err,out}.tmp
	popd >/dev/null
done
popd >/dev/null
