CFLAGS += -Wall -Wextra -O2
LDFLAGS += -lssl -lcrypto -lpthread

all: sand-leek

sand-leek.o: endian.h onion_base32.h key_update.h colour.h

sand-leek: sand-leek.o onion_base32.o key_update.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f sand-leek *.o

test: all
	@./test/run-tests.sh

.PHONY: all clean test

