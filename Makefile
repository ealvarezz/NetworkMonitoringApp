CFLAGS = -c -Wall -Iinclude -pedantic -Wextra

all: clean dump

dump: mydump 
	gcc -o bin/mydump build/mydump.o -lm -lpcap

create-dir:
	@mkdir -p bin
	@mkdir -p build

mydump: create-dir src/mydump.c
	gcc $(CFLAGS) -c src/mydump.c -o build/mydump.o

mydump-debug: create-dir src/mydump.c
	gcc -g -DDEBUG $(CFLAGS) -c src/mydump.c -o build/mydump.o

debug: clean mydump-debug
	gcc -o bin/mydump build/mydump.o -lm -lpcap

clean:
	rm -rf bin
	rm -rf build
