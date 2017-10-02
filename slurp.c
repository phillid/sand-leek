#include <stdio.h>
#include <stdlib.h>

#define BUFFER_STEP 10240

char *slurp(FILE *f, size_t *size)
{
	char *buffer = NULL;
	size_t nread = 0;

	buffer = malloc(BUFFER_STEP);
	if (!buffer) {
		perror("malloc");
		return NULL;
	}

	while (!feof(f)) {
		nread = fread(&buffer[*size], 1, BUFFER_STEP, f);
		*size += nread;
		printf("size is %d\n",*size);
		buffer = realloc(buffer, *size);
		if (!buffer) {
			perror("realloc");
			return NULL;
		}
	}
	if (ferror(f)) {
		perror("slurp/fread");
	}
	return buffer;
}
