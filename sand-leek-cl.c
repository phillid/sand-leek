/* SL_WORK_THREADS kernels doing 32767 exponents each, except if it's 00xxxxxx */
#define HASH_PER_RUN ((SL_WORK_THREADS*32767UL) - (1<<24))
#define EXPONENT_MAX 0x1FFFFFFFUL
#define EXPONENT_SIZE_BYTES 4
#define RSA_KEY_BITS 1024

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <cl.h>
#include <string.h>
#include <endian.h>

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

int truffle_valid(RSA *rsa_key, const char *search, uint32_t e) {
	char onion[17] = {0};
	int der_length;
	unsigned char *der_data;
	unsigned char *tmp_data;
	uint32_t e_big_endian;
	unsigned char digest[20];
	SHA_CTX sha;

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

	e_big_endian = htobe32(e);
	SHA1_Init(&sha);
	SHA1_Update(&sha, der_data, der_length - EXPONENT_SIZE_BYTES);
	SHA1_Update(&sha, &e_big_endian, 4);
	SHA1_Final((unsigned char*)&digest, &sha);

	onion_base32(onion, (unsigned char*)&digest);
	onion[16] = '\0';

	fprintf(stderr, "GPU got %s.onion\n", onion, search);

	return strncmp(onion, search, strlen(search) - 1) == 0;
}

double tv_delta(struct timespec *start, struct timespec *end) {
	double s_delta = end->tv_sec - start->tv_sec;
	long ns_delta = end->tv_nsec - start->tv_nsec;
	return s_delta + (double)ns_delta/1e9;
}

void die_help(char *argv0)
{
	fprintf(stderr, "Syntax:\n%s [-p platform] [-s search]\n", argv0);
	exit(1);
}

int main(int argc, char **argv)
{
	char *search = NULL;
	char *preferred_platform = NULL;
	char c = '\0';
	int offset = 0;

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

	if (preferred_platform == NULL || search == NULL || strlen(search) == 0) {
		die_help(argv[0]);
	}

	if ((offset = check_base32(search)) >= 0) {
		fprintf(stderr,
			"Error: search contains non-base-32 character(s): %c\n"
			"I cannot search for something that will never occur\n",
			search[offset]
		);
		return 1;
	}

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
	struct sha_data sha_c;
	BIGNUM *bignum_e = NULL;

	bignum_e = BN_new();
	if (!bignum_e) {
		fprintf(stderr, "Failed to allocate bignum for exponent\n");
		return 1;
	}


	struct timespec tv_program_start = {0};
	struct timespec tv_start = {0};
	struct timespec tv_end = {0};
	int bitmask = bitmasks[search_len % 8];
	unsigned char *der_data = NULL;
	unsigned char *tmp_data = NULL;
	int der_length = 0;
	unsigned long e = EXPONENT_MAX;
	unsigned long key_number = 1;
	unsigned char byte_e[4] = {0};

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

	/* FIXME */cl_int *buffer = malloc(sizeof(cl_int)*SL_WORK_THREADS);

	/* FIXME check for error */
	bignum_e = BN_new();
	clock_gettime(CLOCK_MONOTONIC, &tv_program_start);
	int success = 0;
	do {
		e = EXPONENT_MAX;
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


		/* pre-adjust context for modifications that are common to all GPU threads */
		sha_c.data_len += 4;
		sha_c.len += 4;

		/* pre-load end-mark bit */
		sha_c.data[sha_c.data_len] = 0x80;

		sha_c.len *= 8;
		/* FIXME loop or leave unrolled? */
		sha_c.data[56] = sha_c.len >> 56;
		sha_c.data[57] = sha_c.len >> 48;
		sha_c.data[58] = sha_c.len >> 40;
		sha_c.data[59] = sha_c.len >> 32;
		sha_c.data[60] = sha_c.len >> 24;
		sha_c.data[61] = sha_c.len >> 16;
		sha_c.data[62] = sha_c.len >> 8;
		sha_c.data[63] = sha_c.len;


		if (tramp_copy_sha(&sha_c)) {
			fprintf(stderr, "Failed.\n");
			return 1;
		}

		/* un-adjust context for modofications that are common to all GPU threads */
		sha_c.len /= 8;
		sha_c.data_len -= 4;
		sha_c.len -= 4;

		clock_gettime(CLOCK_MONOTONIC, &tv_start);

		if (tramp_run_kernel()) {
			fprintf(stderr, "Failed.\n");
			return 1;
		}
		clock_gettime(CLOCK_MONOTONIC, &tv_end);

		/*FIXME*/double peak_delta = tv_delta(&tv_start, &tv_end);
		/*FIXME*/double total_delta = tv_delta(&tv_program_start, &tv_end);
		fprintf(stderr, "Exhausted key attempt %lu in %.2f seconds (peak %.3f MH/s, average %.3f MH/s).\r", key_number, peak_delta, (HASH_PER_RUN/peak_delta/1e6), (key_number*HASH_PER_RUN/total_delta/1e6));

		key_number++;

		if (!buffer) {
			perror("host data buffer malloc");
			return 1;
		}
		if (tramp_copy_data((void*)&buffer, sizeof(cl_int)*SL_WORK_THREADS)) {
			fprintf(stderr, "Failed.\n");
			return 1;
		}

		/* FIXME */ int i = 0;
		/* FIXME */ int count = 0;
		/* FIXME BUG: temporarily looping backwards to increase chance of using
		 * something beginning with bit '1' as our exponent to highligt bug */
		for (i = 0; i < SL_WORK_THREADS; i++) {
			if (buffer[i] != 0) {
				count++;
				/* FIXME */uint16_t smalls = (unsigned int)buffer[i];
				/* FIXME */uint16_t biggies = (unsigned int)i;
				byte_e[0] = (biggies >> 8) & 0xFF;
				byte_e[1] = biggies & 0xFF;
				byte_e[2] = (smalls >> 8) & 0xFF;
				byte_e[3] = smalls & 0xFF;
				e = (uint32_t)(byte_e[0] << 24) | (uint32_t)(byte_e[1] << 16) | (uint32_t)(byte_e[2] << 8) | (uint32_t)(byte_e[3]);

				if (truffle_valid(rsa_key, search, e)) {
					success = 1;
				} else {
					fprintf(stderr, "GPU doesn't agree with CPU: bug or hardware fault?\n");
				}
				break;
			}
		}
	} while (success == 0);

	fprintf(stderr, "Destroying CL trampoline... ");
	tramp_destroy();
	fprintf(stderr, "Blown to smitherines.\n");

	free(buffer);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	bignum_e = BN_new();
	if (BN_set_word(bignum_e, e) != 1) {
		fprintf(stderr, "BN_set_word failed\n");
		return 1;
	}
	RSA_set0_key(rsa_key, NULL, bignum_e, NULL);
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
	} else {
		fprintf(stderr, "Key invalid:");
		ERR_print_errors_fp(stderr);
	}

	return 0;
}
