.PHONY: all clean
CC = gcc
CFLAGS = -no-pie -fno-stack-protector -ggdb

all: test

test: test.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f test
