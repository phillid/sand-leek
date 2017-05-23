int check_base32(char *);
void onion_base32(char [16], unsigned char (*));

#ifdef __SSSE3__
void onion_base32_ssse3(char [16], unsigned char (*));
#endif
