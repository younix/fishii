CC ?= cc
CFLAGS = -std=c99 -pedantic -Wall -Wextra -g

.PHONY: clean

fishii: fishii.c blowfish.c
	$(CC) $(CFLAGS) -o $@ fishii.c blowfish.c `pkg-config --cflags --libs openssl`

clean:
	rm -f fishii

graph.svg: graph.dia
	dia --export=$@ --filter=svg graph.dia
