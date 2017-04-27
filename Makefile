CFLAGS += -O2
LDFLAGS += -lssl -lcrypto -lpthread

all: sand-leek

clean:
	rm -vf sand-leek

.PHONY: all clean

