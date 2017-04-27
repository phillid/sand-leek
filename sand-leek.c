#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>

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

void*
work(void *arg) {
	char b32[17];
	unsigned char sha[20];
	unsigned int e = 0x01FFFFFF;
	unsigned int e_be = 0;
	unsigned char *der_data = NULL;
	unsigned char *tmp_data = NULL;
	size_t der_length = 0;
	unsigned long volatile *kilo_hashes = arg;
	unsigned long hashes = 0;
	BIGNUM *be = NULL;
	RSA *rsa_key = NULL;
	SHA_CTX sha_c;
	SHA_CTX working_sha_c;

	rsa_key = RSA_new();
	if (!rsa_key) {
		fprintf(stderr, "Failed to allocate RSA key\n");
		goto STOP;
	}

	be = BN_new();
	if (!be) {
		fprintf(stderr, "Failed to allocate bignum for exponent\n");
		goto STOP;
	}

	while(1) {
		e = 0x1FFFFFFF;
		BN_set_word(be, e);
		if (!RSA_generate_key_ex(rsa_key, 1024, be, NULL)) {
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
		SHA1_Update(&sha_c, der_data, der_length - 4);
		free(der_data);
		
		e = 0x1FFFFFFF;
		BN_set_word(be, e);
		
		while (e < 0xFFFFFFFF) {

			memcpy(&working_sha_c, &sha_c, 10*sizeof(SHA_LONG)); /* FIXME magic */
			working_sha_c.num = sha_c.num;

			e_be = htobe32(e);
			SHA1_Update(&working_sha_c, &e_be, 4);
			SHA1_Final(&sha, &working_sha_c);

			onion_sha(b32, sha);
			if (hashes++ >= 1000) {
				hashes = 0;
				(*kilo_hashes)++;
			}
			b32[16] = '\0';
			if(strncmp(b32, search, search_len) == 0) {
				printf("Found %s.onion\n", b32);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				/* update the BN e with working e */
				BN_set_word(be, e);
				RSA_set0_key(rsa_key, NULL, be, NULL);
#else
				BN_set_word(rsa_key->e, e);
#endif

				EVP_PKEY *evp_key = EVP_PKEY_new();
				if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
					fprintf(stderr, "EVP_PKEY assignment failed\n");
					goto STOP;
				}
				PEM_write_PrivateKey(stdout, evp_key, NULL, NULL, 0, NULL, NULL);
				EVP_PKEY_free(evp_key);
				goto STOP;
			}
			/* select next odd exponent */
			e += 2;
		}
		printf("Wrap\n");
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
	char opt = '\0';
	int thread_count = 1;
	int i = 0;
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

	workers = calloc(thread_count, sizeof(pthread_t));
	if (!workers) {
		perror("worker thread calloc");
		return 1;
	}

	khash_count = calloc(thread_count, sizeof(unsigned long));
	if (!khash_count) {
		perror("hash count array calloc");
		return 1;
	}

	sem_init(&working, 0, 0);

	for (i = 0; i < thread_count; i++) {
		if (pthread_create(&workers[i], NULL, work, (void*)&khash_count[i])) {
			perror("pthread_create");
			return 1;
		}
	}

	int loops = 0;
	/* workers started; wait on one to finish */
	while (sem_trywait(&working) && errno == EAGAIN) {
		sleep(1);
		loops++;
		khashes = 0;
		/* approximate hashes per second */
		for (i = 0; i < thread_count; i++) {
			khashes += khash_count[i];
		}
		printf("Average rate: %.2f kH/s (%.2f kH/s/thread)\n",
			(double)khashes / loops,
			((double)khashes / loops) / thread_count);
	}

	/* FIXME signal other children to exit - use existing sema? */
//	for (i = 0; i < thread_count; i++) {
//		pthread_join(workers[i], NULL);
//	}

	return 0;
}

