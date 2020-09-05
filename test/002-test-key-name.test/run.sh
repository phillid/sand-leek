#!/bin/bash

set -e

if hash sha1sum ; then
	SHASUM=sha1sum
else
	# fallback for Travis OSX builds. Presume perl provides it
	SHASUM=shasum
fi

key="$(mktemp)"
stderr="$(mktemp)"

# Four character search should be a < 1 second CPU burst for CI runner
${EXECUTABLE} -s site > "$key" 2>"$stderr"

mapfile -t found < <(tr '\r' '\n' < "$stderr" | grep Found | cut -d ' ' -f 3)

echo "sand-leek says it found ${found[*]}..."

# Trick adapted to py3 from https://swehack.org/viewtopic.php?f=37&p=6978
real="$( \
	openssl rsa -in "$key" -pubout -outform DER \
	| tail -c +23 \
	| $SHASUM \
	| head -c 20 \
	| python -c "import base64,sys,codecs; print(base64.b32encode(codecs.decode(sys.stdin.readline().strip('\n'), 'hex')).decode().lower())").onion"


echo "Key analysis shows it's for ${real}"

for f in "${found[@]}" ; do
	if [ "$f" == "$real" ] ; then
		echo "Found a match, I'm happy"
		rm -- "$key" "$stderr"
		exit 0
	fi
done

# fallthrough: not found
echo "Error: No match. Key file contents:"
cat "$key"
exit 1
