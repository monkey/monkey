#ifndef B64_H
#define B64_H

unsigned char *base64_encode(const unsigned char *src, size_t len,
                             size_t *out_len);
unsigned char *base64_decode(const unsigned char *src, size_t len,
                             size_t *out_len);

#endif

