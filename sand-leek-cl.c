#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

//#include <openssl/sha.h>
#include <openssl/rsa.h>

#include "onion_base32.h"
#include "trampoline.h"
//#include "sha1.h"


/* FIXME make loop internal to run(), rather than rebuilding kernel etc
 * each new key */
int run(const char *preferred_platform, unsigned char *search_raw, size_t raw_len, struct sha_data *sha)
{
	fprintf(stderr, "Building CL trampoline... ");
	if (tramp_init(preferred_platform)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Loading kernel source from file... ");
	if (tramp_load_kernel(CL_SRC_DIR"onion.cl")) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Loaded.\n");

	fprintf(stderr, "Compiling kernel source... ");
	if (tramp_compile_kernel()) {
		fprintf(stderr, "Failed:\n%s\n", tramp_get_build_log());
		return 1;
	}
	fprintf(stderr, "Compiled.\n");

	fprintf(stderr, "Setting kernel arguments... ");
	if (tramp_set_kernel_args(raw_len)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Transferring search target to device... ");
	if (tramp_copy_search(search_raw)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Transferring partial SHA work to device... ");
	if (tramp_copy_sha(sha)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Running kernel... ");
	if (tramp_run_kernel()) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

/*	char *buffer = malloc(size*size);
	if (!buffer) {
		perror("host data buffer malloc");
		return 1;
	}
	fprintf(stderr, "Reading data from device... ");
	if (tramp_copy_data((void*)&buffer, size*size)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");
*/
	fprintf(stderr, "Destroying CL trampoline... ");
	tramp_destroy();
	fprintf(stderr, "Blown to smitherines.\n");

/*	free(buffer);*/
	return 0;
}

void die_help(char *argv0)
{
	fprintf(stderr, "Syntax:\n%s [-p platform] [-s search]\n", argv0);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *search = 0;
	char *preferred_platform = NULL;
	char c = '\0';

	while ((c = getopt(argc, argv, "s:p:")) != -1) {
		switch (c) {
		case 's':
			search = optarg;
			break;
		case 'p':
			preferred_platform = optarg;
			break;
		case '?':
			die_help(argv[0]);
			return 1; /* mostly unreachable */
			break; /* unreachable */
		}
	}

	/* FIXME sanatise the input search for non-base32 chars
	 * Also investigate performance benefit from pre-unbase32-ing it
	 * like the CPU-bound version does */

	unsigned char search_raw[10];
	/* padded array of the human-readable search */
	char search_pad[16] = {0};
	strncpy(search_pad, search, sizeof(search_pad));

	/* decode desired base32 */
	onion_base32_dec(search_raw, search_pad);

	/* hangover code from sand-leek.c */
	/* bitmasks to be used to compare remainder bits */
	unsigned char bitmasks[] = {
		[1] = 0xF8, /* 5 MSB */
		[2] = 0xC0, /* 2 MSB */
		[3] = 0xFE, /* 7 MSB */
		[4] = 0xF0, /* 4 MSB */
		[5] = 0x80, /* 1 MSB */
		[6] = 0xFC, /* 6 MSB */
		[7] = 0xE0  /* 3 MSB */
	};

	/* number of whole bytes of raw hash to compare:
	 * 10 is the size of the data a full onion address covers
	 * 16 is the size of the base32-encoded onion address */
	size_t search_len = strlen(search);
	int raw_len = (search_len*10)/16;
	int bitmask = bitmasks[search_len % 8];
	/* end hangover code from sand-leek.c */

	RSA* rsa_key = NULL;
	rsa_key = RSA_new();
	if (!rsa_key) {
		fprintf(stderr, "Failed to allocate RSA key\n");
		return 1;
	}

#define EXPONENT_SIZE_BYTES 4
#define EXPONENT_MIN 0x1FFFFFFF
#define RSA_KEY_BITS 1024

	unsigned long e = EXPONENT_MIN;
	unsigned char *der_data = NULL;
	unsigned char *tmp_data = NULL;
	int der_length = 0;
	struct sha_data sha_c;
	BIGNUM *bignum_e = NULL;


	bignum_e = BN_new();
	if (!bignum_e) {
		fprintf(stderr, "Failed to allocate bignum for exponent\n");
		return 1;
	}

	e = EXPONENT_MIN;
	BN_set_word(bignum_e, e);
	if (!RSA_generate_key_ex(rsa_key, RSA_KEY_BITS, bignum_e, NULL)) {
		fprintf(stderr, "Failed to generate RSA key\n");
		return 1;
	}
	der_length = i2d_RSAPublicKey(rsa_key, NULL);
	if (der_length <= 0) {
		fprintf(stderr, "i2d failed\n");
		return 1;
	}
	der_data = malloc(der_length);
	if (!der_data) {
		fprintf(stderr, "DER data malloc failed\n");
		return 1;
	}
	tmp_data = der_data;
	if (i2d_RSAPublicKey(rsa_key, &tmp_data) != der_length) {
		fprintf(stderr, "DER formatting failed\n");
		return 1;
	}

	sha_init(&sha_c);
	sha_update(&sha_c, der_data, der_length - EXPONENT_SIZE_BYTES);
	free(der_data);


	run(preferred_platform, search_raw, raw_len, &sha_c);
	return 0;
}
