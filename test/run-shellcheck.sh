#!/bin/bash -ex

pushd "$(dirname "$0")"

has_error=0
while IFS= read -d $'\0' -r script ; do
	echo "$script"
	if ! shellcheck -e SC1091 "$script" ; then
		has_error=1
	fi
done < <(find .. -name '*.sh' -print0)

exit "$has_error"
