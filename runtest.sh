#!/bin/bash

stap ./syscall-monitor.stp -c ./test
RET=$?
if [ "$RET" -ne "0" ]; then
	echo "FAIL! Error!"
	exit 1
fi

rm -f 'parent .creat'
rm -f ./test
