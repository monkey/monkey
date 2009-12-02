CC = gcc
INCDIR  = ../../src/include

all:
	gcc $(CFLAGS) -I$(INCDIR) -fPIC -g -c -Wall cheetah.c
	gcc $(CFLAGS) -shared -Wl -o monkey-cheetah.so cheetah.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
