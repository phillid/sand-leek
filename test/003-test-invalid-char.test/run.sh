#!/bin/sh

if ${EXECUTABLE} -A -s foovalid1not ; then
	exit 1
else
	exit 0
fi
