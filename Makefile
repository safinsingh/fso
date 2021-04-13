.PHONY: test

CFLAGS = -std=c99 -pthread -Wall -Werror
SOURCES = ./src/main.c
TARGET = ./bin/fso
DEFAULT_GOAL = dev
CC = gcc

main:
	$(CC) -o $(TARGET) $(CFLAGS) -g $(SOURCES)

prod:
	$(CC) -o $(TARGET)  $(CFLAGS) -O2 -DPROD $(SOURCES)

test:
	deno run --allow-net test/index.ts
