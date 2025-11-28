#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "AES_CTR_ALL.h"
#include "CCM.h"

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

static int buf_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

int main(void)
{
    /* ---------- RFC 3610 Packet Vector #1 ---------- */

    /* Key */
    uint8_t key[16] = {
        0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,
        0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF
    };

    /* Nonce (13 bytes, so L=2) */
    uint8_t nonce[13] = {
        0x00,0x00,0x00,0x03,0x02,0x01,0x00,
        0xA0,0xA1,0xA2,0xA3,0xA4,0xA5
    };

    /* AAD = 첫 8바이트 헤더 */
    uint8_t aad[8] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
    };

    /* Plaintext = 나머지 23바이트 */
    uint8_t pt[23] = {
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E
    };

    size_t pt_len    = 23;
    size_t aad_len   = 8;
    size_t nonce_len = 13;
    size_t tag_len   = 8;

    uint8_t ct[23];
    uint8_t tag[16];      // tag_len=8만 사용
    uint8_t decrypted[23];

    /* RFC 3610 expected values */
    uint8_t exp_ct[23] = {
        0x58,0x8C,0x97,0x9A,0x61,0xC6,0x63,0xD2,
        0xF0,0x66,0xD0,0xC2,0xC0,0xF9,0x89,0x80,
        0x6D,0x5F,0x6B,0x61,0xDA,0xC3,0x84
    };

    uint8_t exp_tag[8] = {
        0x17,0xE8,0xD1,0x2C,0xFD,0xF9,0x26,0xE0
    };

    /* ---------- AES context init ---------- */
    aes_ctx_t ctx;
    aes_status_t st = aes_init_ctx_128(&ctx, key);
    if (st != AES_OK) {
        printf("AES init failed: %d\n", st);
        return -1;
    }

    /* ---------- CCM Encrypt ---------- */
    st = ccm_encrypt(
        &ctx,
        nonce, nonce_len,
        aad, aad_len,
        pt, pt_len,
        ct,
        tag, tag_len
    );

    if (st != AES_OK) {
        printf("CCM encrypt failed: %d\n", st);
        return -1;
    }

    print_hex("Ciphertext: ", ct, pt_len);
    print_hex("Tag       : ", tag, tag_len);

    printf("CT match  : %s\n", buf_equal(ct, exp_ct, pt_len) ? "OK" : "NG");
    printf("TAG match : %s\n", buf_equal(tag, exp_tag, tag_len) ? "OK" : "NG");

    /* ---------- CCM Decrypt & Verify ---------- */
    st = ccm_decrypt_and_verify(
        &ctx,
        nonce, nonce_len,
        aad, aad_len,
        ct, pt_len,
        tag, tag_len,
        decrypted
    );

    if (st != AES_OK) {
        printf("CCM verify failed: %d\n", st);
        return -1;
    }

    print_hex("Decrypted : ", decrypted, pt_len);

    return 0;
}
