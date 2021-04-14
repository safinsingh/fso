.PHONY: test

CFLAGS = -std=c11 -pthread -Wall -Werror
SOURCES = ./src/main.c
TARGET = ./bin/fso
CC = clang

main:
	$(CC) -o $(TARGET) $(CFLAGS) -g $(SOURCES)

prod:
# lol
	$(CC) -o $(TARGET)  $(CFLAGS) -Ofast -march=native -ffast-math -DPROD $(SOURCES)

clean:
	[ -f $(TARGET) ] && rm $(TARGET)

run:
	$(TARGET)

test:
	bash test/test.sh
