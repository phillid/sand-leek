int check_base32(char *);
void onion_base32(char [16], unsigned char (*));
void onion_base32_dec(unsigned char [10], char[16]);

#ifdef __SSSE3__
void onion_base32_ssse3(char [16], unsigned char (*));
#endif
