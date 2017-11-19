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
	char data[SHA_CHUNK_LEN];
};

void sha_chunk(char (*buf)[SHA_CHUNK_LEN], struct sha_data *sha) {
	unsigned int w[80] = {0};
	unsigned int new_a = 0;
	unsigned int a = sha->a;
	unsigned int b = sha->b;
	unsigned int c = sha->c;
	unsigned int d = sha->d;
	unsigned int e = sha->e;
	unsigned int i = 0;
	unsigned int bo = 0;

	unsigned int k[] = {
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	for (i = 0; i < 80; i++, bo+=4) {
		w[i] = ((unsigned int)(*buf)[bo]) << 24;
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

void sha_update(struct sha_data *c, void *data, unsigned int size) {
	unsigned int i = 0;
	size_t remaining = size;
	char *bdata = (char*)data;


	size_t count = MIN(size, SHA_CHUNK_LEN - c->data_len);
	for (i = 0; i < count; i++)
		c->data[c->data_len+i] = ((char*)data)[i];
//	memcpy(&(c->data[c->data_len]), data, count);
	c->data_len += count;
	remaining -= count;


	while (c->data_len == SHA_CHUNK_LEN) {
		sha_chunk(&(c->data), c);
		count = MIN(remaining, SHA_CHUNK_LEN);
		//memcpy(c->data, &bdata[size-remaining], count);
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
	__global unsigned char *results,
	__constant struct sha_data *partial,
	__constant unsigned char *search,
	const unsigned int raw_length)
{
	unsigned int tx = get_global_id(0);
	unsigned int ty = get_global_id(1);
	unsigned int i;

	struct sha_data ctx;
	ctx.a = partial->a;
	ctx.b = partial->b;
	ctx.c = partial->c;
	ctx.d = partial->d;
	ctx.e = partial->e;
	ctx.len = partial->len;
	ctx.data_len = partial->data_len;
	for (i = 0; i < SHA_CHUNK_LEN; i++) {
		ctx.data[i] = partial->data[i];
	}

	/* FIXME dummy e (big-endian) */
	char e[4] = {0x1F, 0xFF, 0xFF, 0xFF};
	char digest[20];
	for (i = 0; i < 65536; i++) {
		sha_update(&ctx, &e, 4);

		sha_final(&digest, &ctx);
	}

//	buffer[(size*y)+x] = (i*255)/iterations;
	return;
}
