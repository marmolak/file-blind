run: test
	./runtest.sh

test: test.c
	gcc -o test test.c
