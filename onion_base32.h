/* Find the first instance of a character in `subject` which is not in the
 * base32 alphabet.
 * Returns the offset into `subject` of the first such character, or -1
 * if no such character exists in the string
 */
int check_base32(char *);

/* Simple and reliable base32 algorithm - "old trusty"
 * Note: This is not a general base32 algorithm; it outputs only the
 * first 16 base32 symbols of the input buffer, using only the first
 * 20 bytes of that buffer.
 */
void onion_base32(char [16], unsigned char (*));

/* Simple algorithm to decode a 16-byte base32 sequence to the 10 bytes
 * it represents, placing the result in dec */
void onion_base32_dec(unsigned char [10], char[16]);
