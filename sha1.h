#include <stdio.h>
#include <string.h>
#include <stdint.h>

struct sha_data {
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint64_t len;
	size_t data_len;
	uint8_t data[64];
};
void sha_init(struct sha_data*);
void sha_update(struct sha_data*, void *, size_t);
void sha_final(unsigned char*, struct sha_data*);

