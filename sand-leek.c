#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "endian.h"
#include "onion_base32.h"
#include "key_update.h"
#include "colour.h"
#include "unit_label.h"

#define VERSION "1"

#define EXPONENT_SIZE_BYTES   4
#define EXPONENT_MIN          0x1FFFFFFF
#define EXPONENT_MAX          0xFFFFFFFF

#define RSA_KEY_BITS          1024

#ifdef CLOCK_MONOTONIC
#define SL_CLOCK_SOURCE CLOCK_MONOTONIC
#else
#warning "This platform has no CLOCK_MONOTONIC, falling back on crappy CLOCK_REALTIME"
#define SL_CLOCK_SOURCE CLOCK_REALTIME
#endif

static char no_ansi_esc = 0;
static char *search;
static char search_pad[17];
static unsigned char search_raw[10];
static size_t search_len;
static int raw_len;
static char bitmask;
static volatile char working;

static const struct unit_label khash_labels[] = {
	{1000, "k" },
	{1000, "M" },
	{1000, "G" },
	{1000, "T" },
	{1000, "P" },
	{1000, "E" },
	{   0, NULL}
};

static const struct unit_label time_labels[] = {
	{    60, "second"       },
	{    60, "minute"       },
	{    24, "hour"         },
	{365.25, "day"          },
	{  1000, "year"         },
	{  1000, "thousand year"},
	{  1000, "million year" },
	{  1000, "billion year" },
	{  1000, "trillion year"},
	{     0,  NULL          }
};


/* "Bare" eprintf that does not change colour, apply prefix, etc.
 * Only directs information to the appropriate stream */
#define eprintf_bare(...) \
	fprintf(stderr, __VA_ARGS__)

/* "Bare" iprintf that does not change colour, apply prefix, etc.
 * Only directs information to the appropriate stream */
#define iprintf_bare(...) \
	fprintf(stderr, __VA_ARGS__)


#ifndef SAND_LEEK_DISABLE_COLOUR
/* "Real" eprintf, error printf. Outputs a message to stderr, prefixed and
 * coloured all fancy */
#define eprintf(format, ...) \
	iprintf_bare("%sERROR: %s" format, \
	             no_ansi_esc ? "" : COLOUR_BOLD_OFF COLOUR_RED, \
	             no_ansi_esc ? "" : COLOUR_ALL_OFF COLOUR_BOLD, \
	             ##__VA_ARGS__);

/* "Real" iprintf, information printf. Outputs a message to stderr, prefixed
 * and coloured all fancy */
#define iprintf(format, ...) \
	iprintf_bare("%sINFO: %s" format, \
	             no_ansi_esc ? "" : COLOUR_BOLD_OFF COLOUR_CYAN, \
	             no_ansi_esc ? "" : COLOUR_ALL_OFF COLOUR_BOLD, \
	             ##__VA_ARGS__);
#else /* SAND_LEEK_DISABLE_COLOUR */
#define eprintf(...) \
	iprintf_bare("ERROR: " __VA_ARGS__);

#define iprintf(...) \
	iprintf_bare("INFO: " __VA_ARGS__);
#endif /* SAND_LEEK_DISABLE_COLOUR */

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

	rsa_key = RSA_new();
	if (!rsa_key) {
		eprintf("Failed to allocate RSA key\n");
		goto STOP;
	}

	bignum_e = BN_new();
	if (!bignum_e) {
		eprintf("Failed to allocate bignum for exponent\n");
		goto STOP;
	}

	while(working) {
		e = EXPONENT_MIN;
		BN_set_word(bignum_e, e);
		if (!RSA_generate_key_ex(rsa_key, RSA_KEY_BITS, bignum_e, NULL)) {
			eprintf("Failed to generate RSA key\n");
			goto STOP;
		}
		der_length = i2d_RSAPublicKey(rsa_key, NULL);
		if (der_length <= 0) {
			eprintf("i2d failed\n");
			goto STOP;
		}
		der_data = malloc(der_length);
		if (!der_data) {
			eprintf("DER data malloc failed\n");
			goto STOP;
		}
		tmp_data = der_data;
		if (i2d_RSAPublicKey(rsa_key, &tmp_data) != der_length) {
			eprintf("DER formatting failed\n");
			goto STOP;
		}

		/* core loop adapted from eschalot */
		SHA1_Init(&sha_c);
		SHA1_Update(&sha_c, der_data, der_length - EXPONENT_SIZE_BYTES);
		free(der_data);

		while (e < EXPONENT_MAX) {
			memcpy(&working_sha_c, &sha_c, sizeof(SHA_CTX));

			e_big_endian = sl_htobe32(e);
			SHA1_Update(&working_sha_c, &e_big_endian, EXPONENT_SIZE_BYTES);
			SHA1_Final((unsigned char*)&sha, &working_sha_c);

			if (hashes++ >= 1000) {
				hashes = 0;
				(*kilo_hashes)++;
				/* check if we should still be working too */
				if (!working)
					goto STOP;
			}

			if (memcmp(sha, search_raw, raw_len) == 0) {
				/* check the remaining partial byte */
				switch (search_len) {
				case 8:
				case 16:
					/* nothing to do; already a raw byte boundary */
					break;
				default:
					if ((search_raw[raw_len] & bitmask) != (sha[raw_len] & bitmask)) {
						e += 2;
						continue;
					}
					break;
				}

				/* sanity check */
				onion_base32(onion, sha);
				onion[16] = '\0';
				if (strncmp(onion, search, search_len)) {
					eprintf(
						"BUG: Discrepancy between raw and base32 onion addresses\n"
						"Looking for %s, but the sum is %s\n"
						"Please report this to the developer\n",
						search, onion);
						continue;
				}
				iprintf_bare("\n");
				iprintf("Found %s.onion\n", onion);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				if (BN_set_word(bignum_e, e) != 1) {
					eprintf("BN_set_word failed\n");
					goto STOP;
				}
				RSA_set0_key(rsa_key, NULL, bignum_e, NULL);
				/* allocate what was freed by above function call */
				bignum_e = BN_new();
#else
				/* much tidier to be honest */
				BN_set_word(rsa_key->e, e);
#endif
				if (key_update_d(rsa_key)) {
					eprintf("Error updating d component of RSA key, stop.\n");
					goto STOP;
				}

				if (RSA_check_key(rsa_key) == 1) {
					iprintf("Key valid\n");
					EVP_PKEY *evp_key = EVP_PKEY_new();
					if (!EVP_PKEY_assign_RSA(evp_key, rsa_key)) {
						eprintf("EVP_PKEY assignment failed\n");
						goto STOP;
					}
					PEM_write_PrivateKey(stdout, evp_key, NULL, NULL, 0, NULL, NULL);
					EVP_PKEY_free(evp_key);
					goto STOP;
				} else {
					eprintf("Key invalid:");
					ERR_print_errors_fp(stderr);
				}
			}
			/* select next odd exponent */
			e += 2;
		}
	}
STOP:
	BN_free(bignum_e);
	working = 0;
	return NULL;
}

int
set_raw_params(void) {
	/* bitmasks to be used to compare remainder bits */
	static unsigned char bitmasks[] = {
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
	raw_len = (search_len*10)/16;
	bitmask = bitmasks[search_len % 8];
	return 0;
}

void
die_usage(const char *argv0) {
	fprintf(stderr,
		"usage: %s [-t threads] [-A] -s search\n"
		"Options:\n"
		"    -t threads    use `threads` worker threads (default: 1)\n"
		"    -A            disable ANSI escape sequences in stderr output\n"
		"    -s search     search for keys to onion addresses beginning with `search`\n"
		"\n",
		argv0
		);
	exit(1);
}

void nice_time(long sec, int *seconds, int *minutes, int *hours, int *days) {
	*seconds = sec % 60; sec -= *seconds; sec /= 60;
	*minutes = sec % 60; sec -= *minutes; sec /= 60;
	*hours   = sec % 24; sec -= *hours  ; sec /= 24;
	*days    = sec % 24;
}

void
monitor_progress(unsigned long volatile *khashes, int thread_count) {
	int loops = 0;
	int i = 0;
	unsigned long total_khashes = 0;
	unsigned long last_total_khashes = 0;
	double hashes_nice = 0;
	double net_khash_nice = 0;
	double net_khash_t_nice = 0;
	char *hashes_nice_unit = NULL;
	char *net_khash_nice_unit = NULL;
	char *net_khash_t_nice_unit = NULL;
	struct timespec start = {0, 0};
	struct timespec now = {0, 0};
	int seconds = 0;
	int minutes = 0;
	int hours = 0;
	int days = 0;
	long delta = 0;
	double est_khashes = 0;
	double remaining = 0;
	double remaining_abs = 0;
	char *remaining_unit = NULL;

	/* estimated khashes required for approximate certainty of finding a key */
	est_khashes = pow(32, search_len) / 1000;

	/* FIXME linux-only? Need a portable alternative or (shriek) ifdefs */
	clock_gettime(SL_CLOCK_SOURCE, &start);

	loops = 0;
	/* loop while no thread as announced work end; we don't want to
	 * trample its output on stderr */
	while (working) {
		last_total_khashes = total_khashes;
		total_khashes = 0;
		/* approximate hashes per second */
		for (i = 0; i < thread_count; i++) {
			total_khashes += khashes[i];
		}

		hashes_nice = make_unit_whatsit(khash_labels, &hashes_nice_unit, total_khashes);

		/* compute timestamp */
		clock_gettime(SL_CLOCK_SOURCE, &now);
		delta = now.tv_sec - start.tv_sec;
		nice_time(delta, &seconds, &minutes, &hours, &days);

		if (total_khashes - last_total_khashes == 0) {
			remaining = 0;
		} else {
			remaining = (est_khashes/(total_khashes-last_total_khashes)) - delta;
		}

		remaining_abs = fabs(remaining);
		remaining_abs = make_unit_whatsit(time_labels, &remaining_unit, remaining_abs);
		net_khash_nice = make_unit_whatsit(khash_labels, &net_khash_nice_unit, total_khashes - last_total_khashes);
		net_khash_t_nice = make_unit_whatsit(khash_labels, &net_khash_t_nice_unit, (double)(total_khashes - last_total_khashes) / (thread_count));

#ifndef SAND_LEEK_DISABLE_COLOUR
		if (!no_ansi_esc) {
			iprintf_bare(COLOUR_ERASE);
		}
#endif
		/* FIXME prints incorrect English e.g. "1 billion year" */
		iprintf("[%02d:%02d:%02d:%02d]: %.2f %s hashes%s. Now ~%.2f %sH/s (%.2f %sH/s/thread). Maybe %.1f %s%s %s\r",
			days, hours, minutes, seconds,
			hashes_nice, hashes_nice_unit, (hashes_nice >= 1000 ? " (!!)" : ""),
			net_khash_nice, net_khash_nice_unit,
			net_khash_t_nice, net_khash_t_nice_unit,
			remaining_abs, remaining_unit, (remaining_abs == 1.0 ? "" : "s" ),
			(remaining < 0 ? "overdue" : "left")
			);
		sleep(1);
		loops++;
	}
}

void
show_version(void) {
	printf("sand-leek "VERSION"\n");
}

int
main(int argc, char **argv) {
	int opt = '\0';
	int thread_count = 1;
	int i = 0;
	ssize_t offset = 0;
	pthread_t *workers = NULL;
	volatile unsigned long *khashes = NULL;

	while ((opt = getopt(argc, argv, "t:s:VA")) != -1) {
		switch (opt) {
		case 'V':
			show_version();
			return 0;
		case 't':
			thread_count = atoi(optarg);
			break;
		case 's':
			search = optarg;
			break;
		case 'A':
			no_ansi_esc = 1;
			break;
		case '?':
		default:
			return 1;
			break; /* unreachable */
		}
	}

	if (thread_count <= 0) {
		die_usage(argv[0]);
	}

	if (search == NULL || strlen(search) <= 0) {
		die_usage(argv[0]);
	}

	iprintf("Starting sand-leek " VERSION "\n");

	search_len = strlen(search);

	if ((offset = check_base32(search)) >= 0) {
		eprintf(
			"search contains non-base-32 character(s): %c\n"
			"I cannot search for something that will never occur\n",
			search[offset]
		);
		return 1;
	}

	if (set_raw_params()) {
		eprintf("Search string of poor length\n");
		return 1;
	}
	memset(search_pad, 0, sizeof(search_pad));
	strncpy(search_pad, search, sizeof(search_pad)-1);

	/* decode desired base32 */
	onion_base32_dec(search_raw, search_pad);

	iprintf("Searching for \"%s\"\n", search);

	workers = calloc(thread_count, sizeof(workers[0]));
	if (!workers) {
		eprintf("");
		perror("worker thread calloc");
		return 1;
	}

	khashes = calloc(thread_count, sizeof(khashes[0]));
	if (!khashes) {
		eprintf("");
		perror("hash count array calloc");
		free(workers);
		return 1;
	}

	working = 1;

	for (i = 0; i < thread_count; i++) {
		iprintf("Spawning worker thread %d/%d ... ", i + 1, thread_count);
		if (pthread_create(&workers[i], NULL, work, (void*)&khashes[i])) {
			eprintf("");
			perror("pthread_create");
			free((unsigned long*)khashes);
			free(workers);
			return 1;
		}
		iprintf_bare("Done\r");
	}
	iprintf_bare("\n");

	monitor_progress(khashes, thread_count);

	for (i = 0; i < thread_count; i++) {
		iprintf("Waiting for worker threads (%d/%d) reaped\r", i+1, thread_count);
		pthread_join(workers[i], NULL);
	}
	iprintf_bare("\n");

	free((unsigned long*)khashes);
	free(workers);
	return 0;
}

