CFLAGS += -Wall -Wextra -O2
LDFLAGS += -lssl -lcrypto -lpthread

all: sand-leek

sand-leek: sand-leek.o onion_base32.o key_update.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -vf sand-leek *.o

test: all
	@./test/run-tests.sh

.PHONY: all clean test

