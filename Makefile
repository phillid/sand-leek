CFLAGS += -Wall -Wextra -O2
LDFLAGS += -lssl -lcrypto -lpthread

all: sand-leek sand-leek-cl

sand-leek: sand-leek.o onion_base32.o key_update.o sha1.o
	$(CC) -o $@ $^ $(LDFLAGS)

sand-leek-cl: trampoline.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f sand-leek *.o

test: all
	@./test/run-tests.sh

.PHONY: all clean test

