#include <stdlib.h>
#include <string.h>

static const char base32_lookup[] = "abcdefghijklmnopqrstuvwxyz234567";

int
check_base32(char *subject) {
	size_t offset = 0;

	if ((offset = strspn(subject, base32_lookup)) != strlen(subject)) {
		return offset;
	}
	return -1;
}

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

/* Helper function for onion_base32_dec. Decodes a single base32 character
 * into its binary equivalent
 */
static unsigned char
base32_dec_single(char b) {
	if (b >= 'a' && b <= 'z')
		return b - 'a';
	else if (b >= '2' && b <= '7')
		return b - '2' + 26;

	return 0;
}

void
onion_base32_dec(unsigned char dec[10], char base32[16])
{
	size_t c = 0;
	size_t i = 0;

	for (i = 0; i < 16; i += 8) {
		dec[c++] = base32_dec_single(base32[i]) << 3 | base32_dec_single(base32[i+1]) >> 2;
		dec[c++] = base32_dec_single(base32[i+1]) << 6 | base32_dec_single(base32[i+2]) << 1 | base32_dec_single(base32[i+3]) >> 4;
		dec[c++] = base32_dec_single(base32[i+3]) << 4 | base32_dec_single(base32[i+4]) >> 1;
		dec[c++] = base32_dec_single(base32[i+4]) << 7 | base32_dec_single(base32[i+5]) << 2 | base32_dec_single(base32[i+6]) >> 3;
		dec[c++] = base32_dec_single(base32[i+7]) | base32_dec_single(base32[i+6]) << 5;
	}
}
