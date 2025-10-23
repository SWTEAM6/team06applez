// aesmini.c — 헤더에 선언된 API만 구현 (내부 헬퍼 최소화, 테스트/메인 없음)
#include "AES_CTR.h"
#include <string.h>

/* 내부 테이블/헬퍼: 심볼 노출 방지 위해 static */
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t RCON[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }
static inline uint32_t mkw(const uint8_t b4[4]) {
    return ((uint32_t)b4[0] << 24) | ((uint32_t)b4[1] << 16) | ((uint32_t)b4[2] << 8) | ((uint32_t)b4[3]);
}
static inline uint32_t rotl8(uint32_t w) { return (w << 8) | (w >> 24); }
static inline uint32_t subw(uint32_t w) {
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |
        ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |
        ((uint32_t)SBOX[(w >> 8) & 0xff] << 8) |
        ((uint32_t)SBOX[w & 0xff]);
}

/* ===== 4) 상태 변환: column-major 매핑 ===== */
void bytes_to_state(const uint8_t in[16], uint8_t st[4][4]) {
    for (int i = 0;i < 4;i++) for (int j = 0;j < 4;j++) st[i][j] = in[i + 4 * j];
}
void state_to_bytes(const uint8_t st[4][4], uint8_t out[16]) {
    for (int i = 0;i < 4;i++) for (int j = 0;j < 4;j++) out[i + 4 * j] = st[i][j];
}

/* ===== 1) 초기화 ===== */
aes_status_t aes_init_ctx(aes_ctx_t* ctx, const uint8_t key[16]) {
    if (!ctx || !key) return AES_ERR_ARG;
    ctx->rounds = AES128_ROUNDS;
    ctx->has_dec = false;

    // W[0..3]
    for (int i = 0;i < 4;i++) ctx->rk_enc[i] = mkw(&key[4 * i]);

    // W[4..43]
    for (int i = 4;i < (int)AES128_RK_WORDS;i++) {
        uint32_t t = ctx->rk_enc[i - 1];
        if ((i % 4) == 0) t = subw(rotl8(t)) ^ ((uint32_t)RCON[i / 4 - 1] << 24);
        ctx->rk_enc[i] = ctx->rk_enc[i - 4] ^ t;
    }
    return AES_OK;
}

aes_status_t aes_prepare_decrypt(aes_ctx_t* ctx) {
    if (!ctx) return AES_ERR_ARG;
    // (주의) CTR만 쓴다면 실사용 안 함. 호환 위해 역순 보관만 함.
    for (int i = 0;i < (int)AES128_RK_WORDS;i++) {
        ctx->rk_dec[i] = ctx->rk_enc[AES128_RK_WORDS - 1 - i];
    }
    ctx->has_dec = true;
    return AES_OK;
}

/* ===== 2) 코어 블록(ECB 한 블록) — 라운드 함수 인라인 구현 ===== */
aes_status_t aes_encrypt_block(const aes_ctx_t* ctx,
    const uint8_t pt[AES_BLOCK_BYTES],
    uint8_t ct[AES_BLOCK_BYTES]) {
    if (!ctx || !pt || !ct) return AES_ERR_ARG;

    uint8_t s[4][4];
    bytes_to_state(pt, s);

    // AddRoundKey(라운드 0)
    for (int i = 0;i < 4;i++) {
        uint32_t w = ctx->rk_enc[i];
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff);
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff);
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);
        s[3][i] ^= (uint8_t)(w & 0xff);
    }

    // 라운드 1..9
    for (int r = 1;r < (int)ctx->rounds;r++) {
        // SubBytes
        for (int i = 0;i < 4;i++) for (int j = 0;j < 4;j++) s[i][j] = SBOX[s[i][j]];
        // ShiftRows (인라인)
        {
            uint8_t t;
            t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
            t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;       t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
            t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
        }
        // MixColumns (인라인)
        for (int c = 0;c < 4;c++) {
            uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
            uint8_t r0 = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
            uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
            uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
            uint8_t r3 = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            s[0][c] = r0; s[1][c] = r1; s[2][c] = r2; s[3][c] = r3;
        }
        // AddRoundKey
        for (int i = 0;i < 4;i++) {
            uint32_t w = ctx->rk_enc[4 * r + i];
            s[0][i] ^= (uint8_t)((w >> 24) & 0xff);
            s[1][i] ^= (uint8_t)((w >> 16) & 0xff);
            s[2][i] ^= (uint8_t)((w >> 8) & 0xff);
            s[3][i] ^= (uint8_t)(w & 0xff);
        }
    }

    // 마지막 라운드 (MixColumns 없음)
    for (int i = 0;i < 4;i++) for (int j = 0;j < 4;j++) s[i][j] = SBOX[s[i][j]];
    {
        uint8_t t;
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;       t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
        t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
    }
    for (int i = 0;i < 4;i++) {
        uint32_t w = ctx->rk_enc[4 * ctx->rounds + i];
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff);
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff);
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);
        s[3][i] ^= (uint8_t)(w & 0xff);
    }

    state_to_bytes(s, ct);
    return AES_OK;
}

/* 주의: CTR 전용 사용 가정. ECB 복호화가 실제로 필요하면 역라운드 구현 추가 필요 */
aes_status_t aes_decrypt_block(const aes_ctx_t* ctx,
    const uint8_t ct[AES_BLOCK_BYTES],
    uint8_t pt[AES_BLOCK_BYTES]) {
    if (!ctx || !ct || !pt) return AES_ERR_ARG;
    if (!ctx->has_dec) return AES_ERR_STATE;
    // CTR에서는 enc=dec 키스트림 생성용이므로 암호화 경로 재사용 가능
    return aes_encrypt_block(ctx, ct, pt);
}

/* ===== 3) CTR 스트림 ===== */
void ctr_increment(uint8_t counter_block[16], size_t counter_len) {
    if (counter_len == 0 || counter_len > 16) return;
    for (int i = 15;i >= 16 - (int)counter_len;i--) {
        counter_block[i]++;
        if (counter_block[i] != 0) break;
    }
}

aes_status_t aes_ctr_xor_stream(const aes_ctx_t* ctx,
    uint8_t counter_block[AES_BLOCK_BYTES],
    size_t counter_len,
    const uint8_t* src,
    size_t len,
    uint8_t* dst) {
    if (!ctx || !counter_block || !src || !dst) return AES_ERR_ARG;
    if (counter_len == 0 || counter_len > 16) return AES_ERR_IVLEN;
    if (len == 0) return AES_OK;

    // 중첩 검사 (dst==src 허용)
    if (dst != src) {
        const uint8_t* s0 = src;
        const uint8_t* s1 = src + len;
        uint8_t* d0 = dst;
        uint8_t* d1 = dst + len;
        if (!(d1 <= s0 || s1 <= d0)) return AES_ERR_OVERLAP;
    }

    uint8_t ks[AES_BLOCK_BYTES];
    size_t done = 0;
    while (done < len) {
        aes_status_t st = aes_encrypt_block(ctx, counter_block, ks);
        if (st != AES_OK) return st;

        size_t blen = (len - done < AES_BLOCK_BYTES) ? (len - done) : AES_BLOCK_BYTES;
        for (size_t i = 0;i < blen;i++) dst[done + i] = src[done + i] ^ ks[i];

        done += blen;
        ctr_increment(counter_block, counter_len);
    }
    return AES_OK;
}
