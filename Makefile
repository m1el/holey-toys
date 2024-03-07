CC = gcc
CFLAGS_EXTRA = 
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -O3

.PHONY: clean

hbas: src/hbas.c
	${CC} ${CFLAGS} ${CFLAGS_EXTRA} hbas.c -o hbas

example: hbas example.S
	./hbas < example.S > example
	xxd example

clean:
	rm -f example hbas

all:
	hbas