#include "sha1.h"

int tramp_init(const char *preferred_platform);
void tramp_destroy(void);
int tramp_load_kernel(const char *filename);
char *tramp_get_build_log(void);
int tramp_compile_kernel(void);
int tramp_set_kernel_args(unsigned int raw_len, unsigned int bitmask);
int tramp_run_kernel(void);
int tramp_copy_data(void **buffer, size_t size);
int tramp_copy_sha(struct sha_data *sha);
int tramp_copy_search(unsigned char search_raw[10]);
