CC = gcc
INCDIR  = ../../src/include

all:
	gcc -I../../src/include -fPIC -g -c -Wall dirlisting.c
	gcc -shared -Wl -o monkey-dirlisting.so dirlisting.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
