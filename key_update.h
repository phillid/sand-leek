#include <openssl/rsa.h>

/* re-calculate the decryption key `d` for the given key
 * the product of e and d must be congruent to 1, and since we are messing
 * with e to generate our keys, we must re-calculate d */
int key_update_d(RSA *rsa_key);
