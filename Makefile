DEFAULT_GOAL := dev

dev:
	gcc -o fso -Wno-format-security -g -std=c99 main.c
	
prod:
	gcc -o fso -Wno-format-security -std=c99 -O2 main.c

prod-silent:
	gcc -o fso -Wno-format-security -std=c99 -O2 -DQUIET main.c
