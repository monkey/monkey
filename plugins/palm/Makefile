CC = gcc
INCDIR  = ../../src/include

all:
	gcc $(CFLAGS) -DTRACE -I$(INCDIR) -fPIC -g -c -Wall palm.c cgi.c
	gcc $(CFLAGS) -DTRACE -shared -o monkey-palm.so cgi.o palm.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
