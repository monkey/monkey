CC = gcc
INCDIR  = ../../include

all:
	gcc -I../../include -fPIC -g -c -Wall dirlisting.c
	gcc -shared -Wl -o monkey-dirlisting.so dirlisting.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
