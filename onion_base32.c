#include <stdlib.h>
#include <string.h>

static const char base32_lookup[] = "abcdefghijklmnopqrstuvwxyz234567";

int
check_base32(char *subject) {
	size_t offset = 0;

	if ((offset = strspn(subject, base32_lookup)) != strlen(subject)) {
		return offset;
	}
	return 0;
}

/* Simple and reliable base32 algorithm - "old trusty"
 * Note: This is not a general base32 algorithm; it outputs only the
 * first 16 base32 symbols of the input buffer, using only the first
 * 20 bytes of that buffer.
 */
void
onion_base32(char output[16], unsigned char sum[20]) {
	size_t c = 0;
	int i = 0;

	for (i = 0; i < 10; i+=5) {
		output[c++] = base32_lookup[sum[i] >> 3];
		output[c++] = base32_lookup[((sum[i] & 0x07) << 2) | (sum[i+1] >> 6)];
		output[c++] = base32_lookup[(sum[i+1] >> 1) & 0x1F];
		output[c++] = base32_lookup[((sum[i+1] & 1) << 4) | (sum[i+2] >> 4)];
		output[c++] = base32_lookup[((sum[i+2] & 0x0F) << 1) | ((sum[i+3] & 0x80) >> 7)];
		output[c++] = base32_lookup[(sum[i+3] >> 2) & 0x1F];
		output[c++] = base32_lookup[((sum[i+3] & 0x03) << 3) | (sum[i+4] >> 5)];
		output[c++] = base32_lookup[sum[i+4] & 0x1F];
	}
}

#ifdef SSSE3_ONION_BASE32
#include <tmmintrin.h>

/* A slightly-parallel base32 algorithm using SSSE3
 * Note: This is not a general base32 algorithm; it outputs only the
 * first 16 base32 symbols of the input buffer, using only the first
 * 20 bytes of that buffer.
 *
 * Somewhat inspired by http://www.alfredklomp.com/programming/sse-base64/
 */
void
onion_base32_ssse3(char output[16], unsigned char sum[20]) {
	__m128i res;
	__m128i ssum;
	__m128i masklow5;
	__m128i lmask, l;
	__m128i nmask, n;

	ssum = _mm_loadu_si128((__m128i*)sum);

	/* FIXME seems a little hacky */
	masklow5 = _mm_set1_epi32(0x1F000000);
	masklow5 = _mm_slli_epi64(masklow5, 32);

	ssum = _mm_shuffle_epi8(ssum,
		_mm_setr_epi8(9,9,9,9,8,7,6,5,4,4,4,4,3,2,1,0 ));

	/* remember how I said "slightly parallel" ? */
	res = _mm_srli_epi64(ssum, 3) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 6) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 9) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 12) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 15) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 18) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 21) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);

	res |= _mm_srli_epi64(ssum, 24) & masklow5;
	masklow5 = _mm_srli_epi64(masklow5, 8);


	res = _mm_shuffle_epi8(res,
		_mm_setr_epi8(15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0));

	lmask = _mm_cmplt_epi8(res, _mm_set1_epi8(26));
	nmask = _mm_andnot_si128(lmask, _mm_cmplt_epi8(res, _mm_set1_epi8(32)));

	l = lmask & _mm_add_epi8(res, _mm_set1_epi8('a'));
	n = nmask & _mm_add_epi8(res, _mm_set1_epi8('2' - 26));

	_mm_storeu_si128((__m128i*)output, l|n);
}
#endif /* ifdef SSSE3_ONION_BASE32 */
