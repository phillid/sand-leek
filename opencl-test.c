#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "trampoline.h"

int run(const char *preferred_platform, const char *search)
{
	fprintf(stderr, "Building CL trampoline... ");
	if (tramp_init(preferred_platform)) {
		fprintf(stderr, "Failed.\n");
		return 1;
	}
	fprintf(stderr, "Done.\n");

	fprintf(stderr, "Loading kernel source from file... ");
	if (tramp_load_kernel(CL_SRC_DIR"mandelbrot.cl")) {
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
	if (tramp_set_kernel_args(size, iterations)) {
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

	char *buffer = malloc(size*size);
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

	fprintf(stderr, "Destroying CL trampoline... ");
	tramp_destroy();
	fprintf(stderr, "Blown to smitherines.\n");

	printf("P5\n%d\n%d\n255\n",size,size);
	fwrite(buffer, size*size, 1, stdout);

	free(buffer);
}

void die_help(const char **argv0)
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
			size = atoi(optarg);
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
	run(preferred_platform, search);
	return 0;
}
