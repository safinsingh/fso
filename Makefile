.PHONY: test

CFLAGS = -std=c11 -pthread -Wall -Werror
SOURCES = ./src/main.c
TARGET = ./bin/fso
DEFAULT_GOAL = dev
CC = clang

main:
	$(CC) -o $(TARGET) $(CFLAGS) -g $(SOURCES)

prod:
	$(CC) -o $(TARGET)  $(CFLAGS) -O2 $(SOURCES)

test:
	deno run --allow-net test/index.ts
