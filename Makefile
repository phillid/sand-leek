CFLAGS += -Wall -Wextra -O2 -I/usr/include/CL
LDFLAGS += -lssl -lcrypto -lpthread -lOpenCL

all: sand-leek sand-leek-cl

sand-leek: sand-leek.o onion_base32.o key_update.o
	$(CC) -o $@ $^ $(LDFLAGS)

sand-leek-cl: sand-leek-cl.o onion_base32.o trampoline.o cl_error.o slurp.o sha1.o
	$(CC) -o $@ $^ $(LDFLAGS)

sand-leek-cl.o: sand-leek-cl.c
	$(CC) -c -o $@ $^ $(CFLAGS) -DCL_SRC_DIR=\"$(PWD)/cl/\"

clean:
	rm -f sand-leek *.o

test: all
	@./test/run-tests.sh

.PHONY: all clean test

