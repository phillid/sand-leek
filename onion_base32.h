int check_base32(char *);
void onion_base32(char [16], unsigned char (*));

#ifdef AVX_ONION_BASE32
void onion_base32_avx(char [16], unsigned char (*));
#endif
