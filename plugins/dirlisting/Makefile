CC = gcc
INCDIR  = ../../src/include

all:
	gcc $(CFLAGS) -I$(INCDIR) -fPIC -g -c -Wall dirlisting.c
	gcc $(CFLAGS) -shared -Wl -o monkey-dirlisting.so dirlisting.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
