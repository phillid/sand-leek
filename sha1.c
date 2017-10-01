#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"

uint32_t h0 = 0x67452301;
uint32_t h1 = 0xEFCDAB89;
uint32_t h2 = 0x98BADCFE;
uint32_t h3 = 0x10325476;
uint32_t h4 = 0xC3D2E1F0;

#define ROL(x, shamt) ((x << shamt) | (x >> (sizeof(x)*8 - shamt)))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

void sha_chunk(uint8_t (*buf)[64], struct sha_data *sha) {
	uint32_t w[80] = {0};
	uint32_t new_a = 0;
	uint32_t a = sha->a;
	uint32_t b = sha->b;
	uint32_t c = sha->c;
	uint32_t d = sha->d;
	uint32_t e = sha->e;
	size_t i = 0;
	size_t bo = 0;

	uint32_t k[] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	for (i = 0; i < 80; i++, bo+=4) {
		w[i] = ((uint32_t)(*buf)[bo]) << 24;
		w[i] |= (*buf)[bo+1] << 16;
		w[i] |= (*buf)[bo+2] << 8;
		w[i] |= (*buf)[bo+3];
	}

	/* FIXME unroll these operations? */
	for (i = 16; i < 80; i++) {
		w[i] = ROL((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
	}

	for (i = 0; i < 20; i++) {
		new_a = ROL(a, 5) + ((b&c)|((~b)&d)) + e + w[i] + k[0];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}

	for (i = 20; i < 40; i++) {
		new_a = ROL(a, 5) + (b^c^d) + e + w[i] + k[1];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}

	for (i = 40; i < 60; i++) {
		new_a = ROL(a, 5) + ((b&c)|(b&d)|(c&d)) + e + w[i] + k[2];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}

	for (i = 60; i < 80; i++) {
		new_a = ROL(a, 5) + (b^c^d) + e + w[i] + k[3];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}
	sha->a += a;
	sha->b += b;
	sha->c += c;
	sha->d += d;
	sha->e += e;
}

void sha_init(struct sha_data *c) {
	c->a = h0;
	c->b = h1;
	c->c = h2;
	c->d = h3;
	c->e = h4;
	c->data_len = 0;
	memset(c->data, 0, sizeof(c->data));
	c->len = 0;
}

void sha_update(struct sha_data *c, void *data, size_t size) {
	size_t remaining = size;
	uint8_t *bdata = (uint8_t*)data;


	size_t count = MIN(size, 64 - c->data_len);
	memcpy(&(c->data[c->data_len]), data, count);
	c->data_len += count;
	remaining -= count;


	while (c->data_len == 64) {
		sha_chunk(&(c->data), c);
		count = MIN(remaining, 64);
		memcpy(c->data, &bdata[size-remaining], count);
		remaining -= count;
		c->data_len = count;
	}

	/* representative of all data throughput, inclusive of the buffer in
	 * the context */
	c->len += size;
}

void sha_final(unsigned char *digest, struct sha_data *c) {
	size_t i = 0;

	c->data[c->data_len++] = 0x80;

	/* Transform byte len to bit len */
	c->len *= 8;

	for (i = c->data_len; i < 64; i++)
		c->data[i] = 0;

	/* still room for the 64-bit message length at the end of this chunk? */
	if (c->data_len + 8 > 64) {
		sha_chunk(&(c->data), c);
		memset(c->data, 0, sizeof(c->data));
	}

	/* FIXME loop or leave unrolled? */
	c->data[56] = c->len >> 56;
	c->data[57] = c->len >> 48;
	c->data[58] = c->len >> 40;
	c->data[59] = c->len >> 32;
	c->data[60] = c->len >> 24;
	c->data[61] = c->len >> 16;
	c->data[62] = c->len >> 8;
	c->data[63] = c->len;

	sha_chunk(&(c->data), c);


	/* FIXME loop or leave unrolled? */
	digest[ 0] = c->a >> 24;
	digest[ 1] = c->a >> 16;
	digest[ 2] = c->a >> 8;
	digest[ 3] = c->a;

	digest[ 4] = c->b >> 24;
	digest[ 5] = c->b >> 16;
	digest[ 6] = c->b >> 8;
	digest[ 7] = c->b;

	digest[ 8] = c->c >> 24;
	digest[ 9] = c->c >> 16;
	digest[10] = c->c >> 8;
	digest[11] = c->c;

	digest[12] = c->d >> 24;
	digest[13] = c->d >> 16;
	digest[14] = c->d >> 8;
	digest[15] = c->d;

	digest[16] = c->e >> 24;
	digest[17] = c->e >> 16;
	digest[18] = c->e >> 8;
	digest[19] = c->e;
}
