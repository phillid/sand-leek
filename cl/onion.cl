#define INITIAL_DATA_LEN 9
#define SHA_CHUNK_LEN 64
#define ROL(x, shamt) ((x << shamt) | (x >> (sizeof(x)*8 - shamt)))

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
	for (i = 0; i < 16; i++, bo+=4) {
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

void sha_final(unsigned char *digest, struct sha_data *c) {
	size_t i = 0;

	#pragma unroll
	for (i = INITIAL_DATA_LEN+5; i < SHA_CHUNK_LEN-8; i++)
		c->data[i] = 0;

	sha_chunk(&(c->data), c);

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
}

__kernel void key_brute(
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

	unsigned char digest[20];

	results[tx] = 0;

	/* Data area plus (useless) exponent area, and end bit */
	#pragma unroll
	for (j = 0; j < INITIAL_DATA_LEN+5; j++) {
		ctx.data[j] = partial->data[j];
	}

	#pragma unroll
	for (j = SHA_CHUNK_LEN - 8; j < SHA_CHUNK_LEN; j++) {
		ctx.data[j] = partial->data[j];
	}

	ctx.data[INITIAL_DATA_LEN] = tx >> 8;
	/* if MSB is 0, then it doesn't need to be stored in the key, so violates
	 * law of sizeof(e) == 4, messing everything up */
	if (ctx.data[INITIAL_DATA_LEN] == 0) {
		return;
	}
	ctx.data[INITIAL_DATA_LEN + 1] = tx;

	for (i = 3; i < 65536; i+=2) {
		ctx.a = partial->a;
		ctx.b = partial->b;
		ctx.c = partial->c;
		ctx.d = partial->d;
		ctx.e = partial->e;
//////////////////////////////////////////////////////////////
		ctx.data[INITIAL_DATA_LEN + 2] = i >> 8;
		ctx.data[INITIAL_DATA_LEN + 3] = i;
/////////////////////////////////////////////////////////////
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
