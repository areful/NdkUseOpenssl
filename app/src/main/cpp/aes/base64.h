#ifndef BASE64_H
#define BASE64_H

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

char *base64Encode(const unsigned char *buffer, size_t length);

size_t base64Decode(const char *b64message, size_t length, unsigned char **buffer);

size_t calcDecodeLength(const char *b64input, size_t length);

#endif
