int tramp_init(const char *preferred_platform);
void tramp_destroy(void);
int tramp_load_kernel(const char *filename);
char *tramp_get_build_log(void);
int tramp_compile_kernel(void);
int tramp_set_kernel_args(unsigned long size, unsigned long iterations);
int tramp_run_kernel(void);
int tramp_copy_data(void **buffer, size_t size);
