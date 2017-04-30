#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <endian.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define EXPONENT_SIZE_BYTES   4
#define EXPONENT_MIN          0x1FFFFFFF
#define EXPONENT_MAX          0xFFFFFFFF

#define RSA_KEY_BITS          1024

const static char base32_lookup[] = "abcdefghijklmnopqrstuvwxyz234567";
static char *search;
static int search_len;
sem_t working;

void
onion_sha(char output[16], unsigned char sum[20]) {
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

/* re-calculate the decryption key `d` for the given key
 * the product of e and d must be congruent to 1, and since we are messing
 * with e to generate our keys, we must re-calculate d */
int
key_update_d(RSA *rsa_key) {
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *d = NULL;
	const BIGNUM *e = NULL;
	BIGNUM *gcd = BN_secure_new();
	BIGNUM *p1 = BN_secure_new();
	BIGNUM *q1 = BN_secure_new();
	BIGNUM *p1q1 = BN_secure_new();
	BIGNUM *lambda_n = BN_secure_new();
	BIGNUM *true_d = BN_secure_new();
	BIGNUM *true_dmp1 = BN_secure_new();
	BIGNUM *true_dmq1 = BN_secure_new();
	BIGNUM *true_iqmp = BN_secure_new();
	BN_CTX *bn_ctx = BN_CTX_secure_new();

	if (!(bn_ctx && gcd && p1 && q1 && p1q1 && lambda_n && true_d &&
	    true_dmp1 && true_dmq1 && true_iqmp)) {
		perror("bignum or bignum context allocation");
		return 1;
	}

	RSA_get0_key(rsa_key, NULL, &e, &d);
	RSA_get0_factors(rsa_key, &p, &q);

	/* calculate p-1 and q-1 and their product */
	BN_sub(p1, p, BN_value_one());
	BN_sub(q1, q, BN_value_one());
	BN_mul(p1q1, p1, q1, bn_ctx);

	/* calculate LCM of p1,q1 with p1*q1/gcd(p1,q1) */
	BN_gcd(gcd, p1, q1, bn_ctx);
	BN_div(lambda_n, NULL, p1q1, gcd, bn_ctx);

	BN_mod_inverse(true_d, e, lambda_n, bn_ctx);
	BN_mod_inverse(true_iqmp, q, p, bn_ctx);
	BN_mod(true_dmp1, true_d, p1, bn_ctx);
	BN_mod(true_dmq1, true_d, q1, bn_ctx);

	/* cleanup BN structs not managed by RSA internal functions */
	BN_clear_free(gcd);
	BN_clear_free(p1);
	BN_clear_free(q1);
	BN_clear_free(p1q1);
	BN_clear_free(lambda_n);
	BN_CTX_free(bn_ctx);

	if (!RSA_set0_key(rsa_key, NULL, NULL, true_d)) {
		fprintf(stderr, "setting d failed\n");
		return 1;
	}
	if (!RSA_set0_crt_params(rsa_key, true_dmp1, true_dmq1, true_iqmp)) {
		fprintf(stderr, "setting crt params failed\n");
		return 1;
	}
	return 0;
}

void*
work(void *arg) {
	char onion[17];
	unsigned char sha[20];
	unsigned long e = EXPONENT_MIN;
	unsigned int e_big_endian = 0;
	unsigned char *der_data = NULL;
	unsigned char *tmp_data = NULL;
	ssize_t der_length = 0;
	unsigned long volatile *kilo_hashes = arg;
	unsigned long hashes = 0;
	BIGNUM *bignum_e = NULL;
	RSA *rsa_key = NULL;
	SHA_CTX sha_c;
	SHA_CTX working_sha_c;
	int sem_val = 0;

	rsa_key = RSA_new();
	if (!rsa_key) {
		fprintf(stderr, "Failed to allocate RSA key\n");
		goto STOP;
	}

	bignum_e = BN_new();
	if (!bignum_e) {
		fprintf(stderr, "Failed to allocate bignum for exponent\n");
		goto STOP;
	}

	while(sem_getvalue(&working, &sem_val) == 0 && sem_val == 0) {
		e = EXPONENT_MIN;
		BN_set_word(bignum_e, e);
		if (!RSA_generate_key_ex(rsa_key, RSA_KEY_BITS, bignum_e, NULL)) {
			fprintf(stderr, "Failed to generate RSA key\n");
			goto STOP;
		}
		der_length = i2d_RSAPublicKey(rsa_key, NULL);
		if (der_length <= 0) {
			fprintf(stderr, "i2d failed\n");
			goto STOP;
		}
		der_data = malloc(der_length);
		if (!der_data) {
			fprintf(stderr, "DER data malloc failed\n");
			goto STOP;
		}
		tmp_data = der_data;
		if (i2d_RSAPublicKey(rsa_key, &tmp_data) != der_length) {
			fprintf(stderr, "DER formatting failed\n");
			goto STOP;
		}

		/* core loop adapted from eschalot */
		SHA1_Init(&sha_c);
		SHA1_Update(&sha_c, der_data, der_length - EXPONENT_SIZE_BYTES);
		free(der_data);

		while (e < EXPONENT_MAX) {
			memcpy(&working_sha_c, &sha_c, 10*sizeof(SHA_LONG)); /* FIXME magic */
			working_sha_c.num = sha_c.num;

			e_big_endian = htobe32(e);
			SHA1_Update(&working_sha_c, &e_big_endian, EXPONENT_SIZE_BYTES);
			SHA1_Final((unsigned char*)&sha, &working_sha_c);

			onion_sha(onion, sha);
			onion[16] = '\0';

			if (hashes++ >= 1000) {
				hashes = 0;
				(*kilo_hashes)++;
				/* check if we should still be working too */
				sem_getvalue(&working, &sem_val);
				if (sem_val > 0)
					goto STOP;
			}
			if(strncmp(onion, search, search_len) == 0) {
				fprintf(stderr, "Found %s.onion\n", onion);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				if (BN_set_word(bignum_e, e) != 1) {
					fprintf(stderr, "BN_set_word failed\n");
					goto STOP;
				}
				RSA_set0_key(rsa_key, NULL, bignum_e, NULL);
				/* allocate what was freed by above function call */
				bignum_e = BN_new();
#else
				/* much tidier to be honest */
				BN_set_word(rsa_key->e, e);
#endif
				/* FIXME check for errors */
				key_update_d(rsa_key);

				if (RSA_check_key(rsa_key) == 1) {
					fprintf(stderr, "Key valid\n");
					EVP_PKEY *evp_key = EVP_PKEY_new();
					if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
						fprintf(stderr, "EVP_PKEY assignment failed\n");
						goto STOP;
					}
					PEM_write_PrivateKey(stdout, evp_key, NULL, NULL, 0, NULL, NULL);
					EVP_PKEY_free(evp_key);
					goto STOP;
				} else {
					fprintf(stderr, "Key invalid:");
					ERR_print_errors_fp(stderr);
				}
			}
			/* select next odd exponent */
			e += 2;
		}
		fprintf(stderr, "Wrap\n");
	}
STOP:
	sem_post(&working);
	return NULL;
}

void
die_usage(const char *argv0) {
	fprintf(stderr,
		"usage: %s [-t threads] -s search\n"
		"searches for keys for onion addresses beginning with `search`\n",
		argv0
		);
	exit(1);
}

int
main(int argc, char **argv) {
	int opt = '\0';
	int thread_count = 1;
	int loops = 0;
	int i = 0;
	size_t offset = 0;
	pthread_t *workers = NULL;
	unsigned long volatile *khash_count = NULL;
	unsigned long khashes = 0;

	while ((opt = getopt(argc, argv, "t:s:")) != -1) {
		switch (opt) {
		case 't':
			thread_count = atoi(optarg);
			break;
		case 's':
			search = optarg;
			break;
		}
	}

	if (thread_count <= 0) {
		die_usage(argv[0]);
	}

	if (search == NULL || strlen(search) <= 0) {
		die_usage(argv[0]);
	}

	search_len = strlen(search);

	if ((offset = strspn(search, base32_lookup)) != search_len) {
		fprintf(stderr,
			"Error: search contains non-base-32 character(s): %c\n"
			"I cannot search for something that will never occur\n",
			search[offset]
		);
		return 1;
	}

	workers = calloc(thread_count, sizeof(pthread_t));
	if (!workers) {
		perror("worker thread calloc");
		return 1;
	}

	khash_count = calloc(thread_count, sizeof(unsigned long));
	if (!khash_count) {
		perror("hash count array calloc");
		free(workers);
		return 1;
	}

	sem_init(&working, 0, 0);

	for (i = 0; i < thread_count; i++) {
		if (pthread_create(&workers[i], NULL, work, (void*)&khash_count[i])) {
			perror("pthread_create");
			return 1;
		}
	}

	/* workers started; wait on one to finish */
	loops = 0;
	while (sem_trywait(&working) && errno == EAGAIN) {
		sleep(1);
		loops++;
		khashes = 0;
		/* approximate hashes per second */
		for (i = 0; i < thread_count; i++) {
			khashes += khash_count[i];
		}
		fprintf(stderr, "Average rate: %.2f kH/s (%.2f kH/s/thread)\r",
			(double)khashes / loops,
			((double)khashes / loops) / thread_count);
	}

	/* line feed to finish off carriage return from hashrate fprintf */
	fputc('\n', stderr);

	for (i = 0; i < thread_count; i++) {
		pthread_join(workers[i], NULL);
	}

	return 0;
}

