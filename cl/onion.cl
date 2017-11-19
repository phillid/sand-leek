#define SHA_CHUNK_LEN 64
#define ROL(x, shamt) ((x << shamt) | (x >> (sizeof(x)*8 - shamt)))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct sha_data {
	unsigned int a;
	unsigned int b;
	unsigned int c;
	unsigned int d;
	unsigned int e;
	unsigned long len;
	unsigned long data_len;
	unsigned char data[SHA_CHUNK_LEN];
};

void memcpy(void *restrict dest, void *restrict src, int len) {
	unsigned char *dest_ = (unsigned char*)dest;
	unsigned char *src_ = (unsigned char*)src;
	int i = 0;
	for (i = 0; i < len; i++) {
		dest_[i] = src_[i];
	}
//	while (len-- >= 0) {
//		dest_[len] = src_[len];
//	}
}

void sha_chunk(unsigned char (*buf)[SHA_CHUNK_LEN], struct sha_data *sha) {
	unsigned int w[80] = {0};
	unsigned int new_a = 0;
	unsigned int a = sha->a;
	unsigned int b = sha->b;
	unsigned int c = sha->c;
	unsigned int d = sha->d;
	unsigned int e = sha->e;
	unsigned int i = 0;
	unsigned int bo = 0;

	const unsigned int k[] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	#pragma unroll
	for (i = 0; i < 80; i++, bo+=4) {
		w[i] = ((*buf)[bo]) << 24;
		w[i] |= ((*buf)[bo+1]) << 16;
		w[i] |= ((*buf)[bo+2]) << 8;
		w[i] |= ((*buf)[bo+3]);
	}

//	#pragma unroll
	for (i = 16; i < 80; i++) {
		w[i] = ROL((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
	}

//	#pragma unroll
	for (i = 0; i < 20; i++) {
		new_a = ROL(a, 5) + ((b&c)|((~b)&d)) + e + w[i] + k[0];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}

//	#pragma unroll
	for (i = 20; i < 40; i++) {
		new_a = ROL(a, 5) + (b^c^d) + e + w[i] + k[1];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}

//	#pragma unroll
	for (i = 40; i < 60; i++) {
		new_a = ROL(a, 5) + ((b&c)|(b&d)|(c&d)) + e + w[i] + k[2];
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = new_a;
	}
//	#pragma unroll
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

void sha_update(struct sha_data *c, void *data, unsigned int size) {
	unsigned int i = 0;
	size_t remaining = size;
	unsigned char *bdata = (unsigned char*)data;


	size_t count = MIN(size, SHA_CHUNK_LEN - c->data_len);
	for (i = 0; i < count; i++)
		c->data[c->data_len+i] = ((char*)data)[i];
	//memcpy(&(c->data[c->data_len]), data, count);
	c->data_len += count;
	remaining -= count;


	while (c->data_len == SHA_CHUNK_LEN) {
		sha_chunk(&(c->data), c);
		count = MIN(remaining, SHA_CHUNK_LEN);
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

	for (i = c->data_len; i < SHA_CHUNK_LEN; i++)
		c->data[i] = 0;

	/* still room for the 64-bit message length at the end of this chunk? */
	if (c->data_len + 8 > SHA_CHUNK_LEN) {
		sha_chunk(&(c->data), c);
		for (i = 0; i < SHA_CHUNK_LEN; i++)
			c->data[i] = 0;
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


// second half of hash not needed eh?
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

__kernel void fractal_gen(
	__global unsigned int *results,
	__constant struct sha_data *partial,
	__constant unsigned char *search,
	const unsigned int raw_length,
	const unsigned int bitmask)
{
	unsigned int tx = get_global_id(0);
	unsigned int ty = get_global_id(1);
	unsigned int i,j;

	struct sha_data ctx;

	/* FIXME dummy e (big-endian) */
	unsigned char e[4] = {0x1F, 0xFF, 0xFF, 0xFF};
	unsigned char digest[20];

	/* first half of e is our worker number rest is determined later */
	e[0] = ((tx >> 8) & 0xFF);

	/* if MSB is 0, then it doesn't need to be stored in the key, so violates
	 * law of sizeof(e) == 4, messing everything up */
	if (e[0] == 0) {
		return;
	}

	e[1] = tx & 0xFF;
	results[tx] = 0;

	for (i = 3; i < 65536; i+=2) {
		e[2] = (i >> 8) & 0xFF;
		e[3] = i & 0xFF;

		#pragma unroll
		for (j = 0; j < SHA_CHUNK_LEN; j++) {
			ctx.data[j] = partial->data[j];
		}
		ctx.a = partial->a;
		ctx.b = partial->b;
		ctx.c = partial->c;
		ctx.d = partial->d;
		ctx.e = partial->e;
		ctx.len = partial->len;
		ctx.data_len = partial->data_len;

		sha_update(&ctx, &e, 4);
		sha_final(&digest, &ctx);

		int all_clear = 1;
		for (j = 0; j < raw_length; j++) {
			if (search[j] != digest[j]) {
				all_clear = 0;
			}
		}
		if (all_clear == 1 && (digest[j] & bitmask) == (search[j] & bitmask)) {
			results[tx] = i;
		}
	}

	return;
}


void unused() {
/*
#define R2(w, a, b, c, d, e, i) a = ROL(a, 5) + (b^c^d) + e + w[i] + 0x6ED9EBA1; b = ROL(b, 30);

	R2(w, a, b, c, d, e, 20);
	R2(w, e, a, b, c, d, 21);
	R2(w, d, e, a, b, c, 22);
	R2(w, c, d, e, a, b, 23);
	R2(w, b, c, d, e, a, 24);
	R2(w, a, b, c, d, e, 25);
	R2(w, e, a, b, c, d, 26);
	R2(w, d, e, a, b, c, 27);
	R2(w, c, d, e, a, b, 28);
	R2(w, b, c, d, e, a, 29);
	R2(w, a, b, c, d, e, 30);
	R2(w, e, a, b, c, d, 31);
	R2(w, d, e, a, b, c, 32);
	R2(w, c, d, e, a, b, 33);
	R2(w, b, c, d, e, a, 34);
	R2(w, a, b, c, d, e, 35);
	R2(w, e, a, b, c, d, 36);
	R2(w, d, e, a, b, c, 37);
	R2(w, c, d, e, a, b, 38);
	R2(w, b, c, d, e, a, 39);*/

/*
#define R3(w, a, b, c, d, e, i) a = ROL(a, 5) + ((b&c)|(b&d)|(c&d)) + e + w[i] + 0x8F1BBCDC; b = ROL(b, 30);

	R3(w, a, b, c, d, e, 40);
	R3(w, e, a, b, c, d, 41);
	R3(w, d, e, a, b, c, 42);
	R3(w, c, d, e, a, b, 43);
	R3(w, b, c, d, e, a, 44);
	R3(w, a, b, c, d, e, 45);
	R3(w, e, a, b, c, d, 46);
	R3(w, d, e, a, b, c, 47);
	R3(w, c, d, e, a, b, 48);
	R3(w, b, c, d, e, a, 49);
	R3(w, a, b, c, d, e, 50);
	R3(w, e, a, b, c, d, 51);
	R3(w, d, e, a, b, c, 52);
	R3(w, c, d, e, a, b, 53);
	R3(w, b, c, d, e, a, 54);
	R3(w, a, b, c, d, e, 55);
	R3(w, e, a, b, c, d, 56);
	R3(w, d, e, a, b, c, 57);
	R3(w, c, d, e, a, b, 58);
	R3(w, b, c, d, e, a, 59);
*/



}
