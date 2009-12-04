CC = gcc
INCDIR  = ../../src/include

all:
	gcc $(CFLAGS) -I$(INCDIR) -fPIC -g -c -Wall security.c
	gcc $(CFLAGS) -shared -o monkey-security.so security.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
