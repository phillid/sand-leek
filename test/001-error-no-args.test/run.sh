#!/bin/sh

if ${EXECUTABLE} -A ; then
	exit 1
else
	exit 0
fi
