CC = gcc
INCDIR  = ../../include

all:
	gcc -I../../include -fPIC -g -c -Wall cheetah.c
	gcc -shared -Wl -o monkey-cheetah.so cheetah.o -lc
clean:
	rm -rf *.o
	rm -rf *.*so*
