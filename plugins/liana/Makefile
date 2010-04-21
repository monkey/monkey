CC = gcc
INCDIR  = ../../src/include

all:
	gcc $(CFLAGS) -I$(INCDIR) -fPIC -g -c -Wall liana.c
	gcc $(CFLAGS) -shared -o monkey-liana.so liana.o -lc
clean:
	rm -rf *.o *~ *.*so*
