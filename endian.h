#ifndef SAND_LEEK_ENDIAN_H
#define SAND_LEEK_ENDIAN_H

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define sl_htobe32(x) (x)
#else
# define sl_htobe32(x) (((x & 0x000000FF) << 24) | \
                       ((x & 0xFF000000) >> 24)) | \
                       ((x & 0x0000FF00) << 8) | \
                       ((x & 0x00FF0000) >> 8)
#endif

#endif /* ifndef SAND_LEEK_ENDIAN_H */
