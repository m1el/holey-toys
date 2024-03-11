CC = gcc
CFLAGS_EXTRA = 
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -O3
CLANG_FORMAT_STYLE = '{ BasedOnStyle: Google, IndentWidth: 4 }'

.PHONY: clean hbas example format check-format

hbas: build/hbas
example: build/example.hbf

format:
	clang-format --style=${CLANG_FORMAT_STYLE} -i src/*

check-format:
	clang-format --style=${CLANG_FORMAT_STYLE} -i --dry-run -Werror src/*

build:
	mkdir -p build

build/hbas: build src/hbas.c
	${CC} ${CFLAGS} ${CFLAGS_EXTRA} src/hbas.c -o build/hbas

build/example.hbf: build build/hbas examples/example.S
	./build/hbas < examples/example.S > build/example.hbf
	xxd build/example.hbf

clean:
	rm -rf build

all:
	hbas
