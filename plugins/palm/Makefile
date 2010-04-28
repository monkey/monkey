CC = gcc
INCDIR  = ../../src/include
SOURCES = palm.c cgi.c request.c

all:
	gcc $(CFLAGS) -DTRACE -I$(INCDIR) -fPIC -g -c -Wall $(SOURCES)
	gcc $(CFLAGS) -DTRACE -shared -o monkey-palm.so cgi.o palm.o request.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
