#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE   64u
#define SHA256_DIGEST_SIZE  32u

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[SHA256_BLOCK_SIZE];
    size_t   buf_len;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* c);
void sha256_update(sha256_ctx_t* c, const uint8_t* data, size_t len);
void sha256_final(sha256_ctx_t* c, uint8_t out[SHA256_DIGEST_SIZE]);
void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

#endif /* SHA256_H */

