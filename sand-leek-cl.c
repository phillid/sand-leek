/* FIXME magic */
/* 32768 kernels doing 32767 each, except if it's 0xxxxxxx */
#define HASH_PER_RUN ((32768UL*32767UL) - (1<<24))
#define EXPONENT_MIN 0x1FFFFFFFUL
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

int truffle_valid(unsigned char *search_raw, int raw_len, char bitmask, struct sha_data sha, unsigned char e[4]) {
	unsigned char digest[20] = {};
	sha_update(&sha, e, EXPONENT_SIZE_BYTES);
	sha_final((unsigned char*)&digest, &sha);
	fprintf(stderr, "Need    %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (first %d bytes plus bitmask %x)\n",
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
		raw_len,
		bitmask & 0xFF
	);
	fprintf(stderr, "GPU got %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (public exponent %02x %02x %02x %02x)\n",
		digest[0],
		digest[1],
		digest[2],
		digest[3],
		digest[4],
		digest[5],
		digest[6],
		digest[7],
		digest[8],
		digest[9],
		e[0], e[1], e[2], e[3]
	);
	return memcmp(digest, search_raw, raw_len) == 0 &&
	       (search_raw[raw_len] & bitmask) == (digest[raw_len] & bitmask);
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
	const char *search = NULL;
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

	if (preferred_platform == NULL || search == NULL) {
		die_help(argv[0]);
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
	struct sha_data sha_c;
	BIGNUM *bignum_e = NULL;

	bignum_e = BN_new();
	if (!bignum_e) {
		fprintf(stderr, "Failed to allocate bignum for exponent\n");
		return 1;
	}


	struct timespec tv_program_start = {};
	struct timespec tv_start = {};
	struct timespec tv_end = {};
	int bitmask = bitmasks[search_len % 8];
	unsigned char *der_data = NULL;
	unsigned char *tmp_data = NULL;
	int der_length = 0;
	unsigned long e = EXPONENT_MIN;

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

	/*FIXME*/uint32_t eBE = 0;
	/* FIXME */cl_int *buffer = malloc(4*65536);
	/* FIXME */unsigned long key_number = 1;

	/* FIXME check for error */
	bignum_e = BN_new();
	clock_gettime(CLOCK_MONOTONIC, &tv_program_start);
	do {
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


		/* pre-adjust context for modofications that are common to all GPU threads */
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
//		fprintf(stderr, "Reading data from device... ");
		if (tramp_copy_data((void*)&buffer, 4*65536)) {
			fprintf(stderr, "Failed.\n");
			return 1;
		}

		/* FIXME */ int i = 0;
		/* FIXME */ int count = 0;
		/* FIXME BUG: temporarily looping backwards to increase chance of using
		 * something beginning with bit '1' as our exponent to highligt bug */
		for (i = 65536; i >= 0; i--) {
			if (buffer[i] != 0) {
				count++;
				fprintf(stderr, "%x had %x \n", i, buffer[i]);
				/* FIXME */unsigned char byte_e[4] = {};
				/* FIXME */uint16_t smalls = (unsigned int)buffer[i];
				/* FIXME */uint16_t biggies = (unsigned int)i;
				byte_e[0] = (biggies >> 8) & 0xFF;
				byte_e[1] = biggies & 0xFF;
				byte_e[2] = (smalls >> 8) & 0xFF;
				byte_e[3] = smalls & 0xFF;

				if (truffle_valid(search_raw, raw_len, bitmask, sha_c, byte_e)) {
					eBE = byte_e[0] << 24 | byte_e[1] << 16 | byte_e[2] << 8 | byte_e[3];
				} else {
					fprintf(stderr, "GPU doesn't agree with CPU: bug or hardware fault?\n");
				}
				break;
			}
		}
	} while (eBE == 0);
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Destroying CL trampoline... ");
	tramp_destroy();
	fprintf(stderr, "Blown to smitherines.\n");

	free(buffer);





//	e = run(preferred_platform, search_raw, raw_len, search_len, &sha_c);
	e = eBE; /* FIXME */

//fprintf(stderr, "exponent is %lx\n", e);

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
		//EVP_PKEY_free(evp_key);
	} else {
		fprintf(stderr, "Key invalid:");
		ERR_print_errors_fp(stderr);
	}

	return 0;
}
