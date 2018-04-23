#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <cl.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "key_update.h"
#include "onion_base32.h"
#include "trampoline.h"
//#include "sha1.h"

/* hangover code from sand-leek.c */
/* bitmasks to be used to compare remainder bits */
unsigned char bitmasks[] = {
	[0] = 0x00,
	[1] = 0xF8, /* 5 MSB */
	[2] = 0xC0, /* 2 MSB */
	[3] = 0xFE, /* 7 MSB */
	[4] = 0xF0, /* 4 MSB */
	[5] = 0x80, /* 1 MSB */
	[6] = 0xFC, /* 6 MSB */
	[7] = 0xE0  /* 3 MSB */
};

int truffle_valid(unsigned char *search_raw, int raw_len, char bitmask, struct sha_data sha, unsigned char e[4]) {
	unsigned char digest[20] = {};
	sha_update(&sha, e, 4);
	sha_final(&digest, &sha);
	fprintf(stderr, "Need    %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x    (%d)\n",
		search_raw[0],
		search_raw[1],
		search_raw[2],
		search_raw[3],
		search_raw[4],
		search_raw[5],
		search_raw[6],
		search_raw[7],
		search_raw[8],
		search_raw[9],
		raw_len
	);
	fprintf(stderr, "GPU got %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		digest[0],
		digest[1],
		digest[2],
		digest[3],
		digest[4],
		digest[5],
		digest[6],
		digest[7],
		digest[8],
		digest[9]
	);
	return memcmp(digest, search_raw, raw_len) == 0 &&
	       (search_raw[raw_len] & bitmask) == (digest[raw_len] & bitmask);
}

double tv_delta(struct timespec *start, struct timespec *end) {
	double s_delta = end->tv_sec - start->tv_sec;
	long ns_delta = end->tv_nsec - start->tv_nsec;
	return s_delta + (double)ns_delta/1e9;
}

/* FIXME make loop internal to run(), rather than rebuilding kernel etc
 * each new key */
unsigned long run(const char *preferred_platform, unsigned char *search_raw, size_t raw_len, size_t search_len, struct sha_data *sha)
{
	struct timespec tv_start = {};
	struct timespec tv_end = {};
	int bitmask = bitmasks[search_len % 8];

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
	if (tramp_set_kernel_args(raw_len, bitmask)) {
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

	/* pre-adjust context for modofications that are common to all GPU threads */
	sha->data_len += 4;
	sha->len += 4;

	/* pre-load end-mark bit */
	sha->data[sha->data_len] = 0x80;

	sha->len *= 8;
	/* FIXME loop or leave unrolled? */
	sha->data[56] = sha->len >> 56;
	sha->data[57] = sha->len >> 48;
	sha->data[58] = sha->len >> 40;
	sha->data[59] = sha->len >> 32;
	sha->data[60] = sha->len >> 24;
	sha->data[61] = sha->len >> 16;
	sha->data[62] = sha->len >> 8;
	sha->data[63] = sha->len;


	fprintf(stderr, "Transferring partial SHA work to device (data len is at %d, len is at %d)... ", sha->data_len, sha->len);
	if (tramp_copy_sha(sha)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	/* un-adjust context for modofications that are common to all GPU threads */
	sha->len /= 8;
	sha->data_len -= 4;
	sha->len -= 4;

	fprintf(stderr, "Running kernel... ");
	clock_gettime(CLOCK_MONOTONIC, &tv_start);

/* FIXME magic */
/* 65536 kernels doing 32767 each, except if it's 00xxxxxx */
#define HASH_PER_RUN ((65536UL*32767UL) - (1<<24))
	if (tramp_run_kernel()) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	clock_gettime(CLOCK_MONOTONIC, &tv_end);

	/*FIXME*/double clock_delta = tv_delta(&tv_start, &tv_end);
	fprintf(stderr, "Done in %.2f seconds (%.3f MH/s).\n", clock_delta, (HASH_PER_RUN/clock_delta/1e6));

	/* FIXME */cl_int *buffer = malloc(4*65536);
	if (!buffer) {
		perror("host data buffer malloc");
		return 1;
	}
	fprintf(stderr, "Reading data from device... ");
	if (tramp_copy_data((void*)&buffer, 4*65536)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Analysing batch results. Successful nonces: \n");

	/* FIXME */ int i = 0;
	/* FIXME */ int count = 0;
	for (i = 0; i < 65536; i++) {
		if (buffer[i] != 0) {
			count++;
			fprintf(stderr, "%d \n", buffer[i]);
			/* FIXME */unsigned char e[4] = {};
			/* FIXME */unsigned int smalls = (unsigned int)buffer[i];
			/* FIXME */unsigned int biggies = (unsigned int)i;
			e[0] = (biggies >> 8) & 0xFF;
			e[1] = biggies & 0xFF;
			e[2] = (smalls >> 8) & 0xFF;
			e[3] = smalls & 0xFF;
			if (truffle_valid(search_raw, raw_len, bitmask, *sha, e)) {
				fprintf(stderr, "«%x %x %x %x»\n", e[0], e[1], e[2], e[3]);
				/* FIXME */unsigned long eLE = e[0] << 24 | e[1] << 16 | e[2] << 8 | e[3];
				fprintf(stderr, "Got eem: %xul!\n", eLE);
				return eLE;
			} else {
				fprintf(stderr, "GPU doesn't agree with CPU: bug or hardware fault?\n");
			}
			break;
		}
	}
	if (count == 0) {
		fprintf(stderr, "None. ");
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Destroying CL trampoline... ");
	tramp_destroy();
	fprintf(stderr, "Blown to smitherines.\n");

	free(buffer);
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

	/* number of whole bytes of raw hash to compare:
	 * 10 is the size of the data a full onion address covers
	 * 16 is the size of the base32-encoded onion address */
	size_t search_len = strlen(search);
	int raw_len = (search_len*10)/16;
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

	do {
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

		e = run(preferred_platform, search_raw, raw_len, search_len, &sha_c);
	} while (e == 0);

	BN_set_word(bignum_e, e);
fprintf(stderr, "exponent is %lx\n", e);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (BN_set_word(bignum_e, e) != 1) {
		fprintf(stderr, "BN_set_word failed\n");
		return 1;
	}
	RSA_set0_key(rsa_key, NULL, bignum_e, NULL);
	/* allocate what was freed by above function call */
	bignum_e = BN_new();
#else
	/* much tidier to be honest */
	BN_set_word(rsa_key->e, e);
#endif
	if (key_update_d(rsa_key)) {
		printf("Error updating d component of RSA key, stop.\n");
		return 1;
	}

	if (RSA_check_key(rsa_key) == 1) {
		fprintf(stderr, "Key valid\n");
		EVP_PKEY *evp_key = EVP_PKEY_new();
		if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
			fprintf(stderr, "EVP_PKEY assignment failed\n");
			return 1;
		}
		PEM_write_PrivateKey(stdout, evp_key, NULL, NULL, 0, NULL, NULL);
		EVP_PKEY_free(evp_key);
		return 1;
	} else {
		fprintf(stderr, "Key invalid:");
		ERR_print_errors_fp(stderr);
	}


	return 0;
}
