# Holey-bytes VM playground

This is my take on holey bytes toolchain, currently only an assembler written in C.

## Building

Run `make`, or `make CC=<your preferred C compiler> CFLAGS_EXTRA=<more flags>`

## Usage

To run the assembler, feed the input file to stdin, and the output will be in stdout.
```
./hbas --hex < input.S > output.hex
./hbas < input.S > output.bin
```