DEFAULT_GOAL := dev
.PHONY: test

dev:
	gcc -o fso -Wno-format-security -g -std=c11 -pthread main.c
	
prod:
	gcc -o fso -Wno-format-security -std=c11 -O2 -pthread main.c

prod-silent:
	gcc -o fso -Wno-format-security -std=c11 -O2 -DQUIET -pthread main.c

test:
	make prod
	./fso &
	sleep 3 && deno run --allow-net test/index.ts
	kill -9 $(pgrep fso)
