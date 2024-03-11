CC = gcc
CFLAGS_EXTRA = 
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -O3

.PHONY: clean build-dir hbas example

hbas: build/hbas
example: build/example.hbf

build:
	mkdir -p build

build/hbas: build src/hbas.c
	${CC} ${CFLAGS} ${CFLAGS_EXTRA} src/hbas.c -o build/hbas

build/example.hbf: build build/hbas examples/example.S
	./hbas < examples/example.S > build/example.hbf
	xxd build/example.hbf

clean:
	rm -rf build

all:
	hbas