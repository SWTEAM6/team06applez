// CCM.c — AES-CCM (NIST SP 800-38C) using aesmini (AES core + CTR)
#include "CCM.h"
#include <string.h>

#define CCM_MIN_TAG 4u
#define CCM_MAX_TAG 16u

/* ---------- 내부 유틸 ---------- */

// 유효한 태그 길이인지 확인 (4,6,8,10,12,14,16)
static inline bool valid_tag_len(size_t t) {
    return (t >= CCM_MIN_TAG && t <= CCM_MAX_TAG && (t % 2) == 0);
}

/* B0 = Flags || Nonce || Q(message length)
   Flags bit 구성:
   [6] Adata 존재 여부, [5..3] (t-2)/2, [2..0] (L-1)
*/
static void make_B0(uint8_t B0[16],
    size_t L,
    size_t tag_len,
    const uint8_t* nonce,
    size_t nonce_len,
    size_t pt_len,
    bool has_aad)
{
    uint8_t flags = 0;
    if (has_aad) flags |= 0x40; // Adata 비트
    flags |= (uint8_t)(((tag_len - 2u) / 2u) << 3);
    flags |= (uint8_t)((L - 1u) & 0x07u);

    B0[0] = flags;
    memcpy(&B0[1], nonce, nonce_len);

    for (size_t i = 0; i < L; i++) {
        B0[15 - i] = (uint8_t)(pt_len & 0xFFu);
        pt_len >>= 8;
    }
}

/* CTR 초기 블록 생성 (Ctr0 = Flags' || Nonce || Counter)
   Flags'는 하위 3비트에 (L-1)만 포함. Counter=0이면 S0용, 1부터 메시지용 */
static void make_Ctr0(uint8_t ctr[16],
    size_t L,
    const uint8_t* nonce,
    size_t nonce_len,
    uint64_t counter_value)
{
    memset(ctr, 0, 16);
    ctr[0] = (uint8_t)((L - 1u) & 0x07u);
    memcpy(&ctr[1], nonce, nonce_len);

    for (size_t i = 0; i < L; i++) {
        ctr[15 - i] = (uint8_t)(counter_value & 0xFFu);
        counter_value >>= 8;
    }
}

/* CBC-MAC 기본 연산: Xi = AES( Xi-1 XOR block ) */
static void cbc_mac_init(uint8_t X[16]) { memset(X, 0, 16); }

static void xor_block(uint8_t dst[16], const uint8_t src[16]) {
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];
}

static aes_status_t cbc_mac_update_block(const aes_ctx_t* ctx,
    uint8_t X[16],
    const uint8_t block[16])
{
    uint8_t tmp[16];
    memcpy(tmp, X, 16);
    xor_block(tmp, block);
    return aes_encrypt_block(ctx, tmp, X);
}

/* AAD 인코딩 및 MAC 갱신 */
static aes_status_t cbc_mac_aad(const aes_ctx_t* ctx,
    uint8_t X[16],
    const uint8_t* aad, size_t aad_len)
{
    if (!aad || aad_len == 0) return AES_OK;

    uint8_t block[16];
    size_t off = 0;

    // AAD 길이에 따른 헤더 인코딩
    if (aad_len < ((size_t)1 << 16) - ((size_t)1 << 8)) {
        memset(block, 0, 16);
        block[0] = (uint8_t)((aad_len >> 8) & 0xFF);
        block[1] = (uint8_t)(aad_len & 0xFF);
        size_t chunk = (aad_len < 14) ? aad_len : 14;
        memcpy(&block[2], aad, chunk);
        off += chunk;
        aes_status_t st = cbc_mac_update_block(ctx, X, block);
        if (st != AES_OK) return st;
    }
    else if (aad_len < ((uint64_t)1 << 32)) {
        memset(block, 0, 16);
        block[0] = 0xFF; block[1] = 0xFE;
        block[2] = (uint8_t)((aad_len >> 24) & 0xFF);
        block[3] = (uint8_t)((aad_len >> 16) & 0xFF);
        block[4] = (uint8_t)((aad_len >> 8) & 0xFF);
        block[5] = (uint8_t)(aad_len & 0xFF);
        size_t chunk = (aad_len < 10) ? aad_len : 10;
        memcpy(&block[6], aad, chunk);
        off += chunk;
        aes_status_t st = cbc_mac_update_block(ctx, X, block);
        if (st != AES_OK) return st;
    }
    else {
        memset(block, 0, 16);
        block[0] = 0xFF; block[1] = 0xFF;
        uint64_t L64 = (uint64_t)aad_len;
        for (int i = 0; i < 8; i++)
            block[2 + i] = (uint8_t)((L64 >> (56 - 8 * i)) & 0xFF);
        size_t chunk = (aad_len < 6) ? aad_len : 6;
        memcpy(&block[10], aad, chunk);
        off += chunk;
        aes_status_t st = cbc_mac_update_block(ctx, X, block);
        if (st != AES_OK) return st;
    }

    // 잔여 AAD 처리
    while (off + 16 <= aad_len) {
        aes_status_t st = cbc_mac_update_block(ctx, X, &aad[off]);
        if (st != AES_OK) return st;
        off += 16;
    }
    if (off < aad_len) {
        uint8_t last[16] = { 0 };
        memcpy(last, &aad[off], aad_len - off);
        aes_status_t st = cbc_mac_update_block(ctx, X, last);
        if (st != AES_OK) return st;
    }
    return AES_OK;
}

/* 메시지(PT/CT) MAC 갱신 */
static aes_status_t cbc_mac_msg(const aes_ctx_t* ctx,
    uint8_t X[16],
    const uint8_t* msg, size_t len)
{
    size_t off = 0;
    while (off + 16 <= len) {
        aes_status_t st = cbc_mac_update_block(ctx, X, &msg[off]);
        if (st != AES_OK) return st;
        off += 16;
    }
    if (off < len) {
        uint8_t last[16] = { 0 };
        memcpy(last, &msg[off], len - off);
        aes_status_t st = cbc_mac_update_block(ctx, X, last);
        if (st != AES_OK) return st;
    }
    return AES_OK;
}

/* ---------- 공개 API ---------- */

// Nonce, Tag 길이 검사
static aes_status_t check_params(size_t nonce_len, size_t tag_len)
{
    if (nonce_len < 7 || nonce_len > 13) return AES_ERR_IVLEN;
    if (!valid_tag_len(tag_len))          return AES_ERR_ARG;
    return AES_OK;
}

/* AES-CCM 암호화 + 인증태그 생성 */
aes_status_t ccm_encrypt(
    const aes_ctx_t* ctx,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t* tag, size_t tag_len)
{
    if (!ctx || !nonce || (!pt && pt_len) || (!ct && pt_len) || !tag)
        return AES_ERR_ARG;

    aes_status_t st = check_params(nonce_len, tag_len);
    if (st != AES_OK) return st;

    const size_t L = 15u - nonce_len;  // message length field size (2~8)

    // 1. CBC-MAC 계산
    uint8_t B0[16];
    make_B0(B0, L, tag_len, nonce, nonce_len, pt_len, aad_len > 0);

    uint8_t X[16];
    cbc_mac_init(X);
    st = cbc_mac_update_block(ctx, X, B0);
    if (st != AES_OK) return st;

    st = cbc_mac_aad(ctx, X, aad, aad_len);
    if (st != AES_OK) return st;

    st = cbc_mac_msg(ctx, X, pt ? pt : (const uint8_t*)"", pt_len);
    if (st != AES_OK) return st;

    // 2. 태그 마스킹 (S0 = E(K, Ctr0), counter=0)
    uint8_t ctr0[16], S0[16];
    make_Ctr0(ctr0, L, nonce, nonce_len, 0);
    st = aes_encrypt_block(ctx, ctr0, S0);
    if (st != AES_OK) return st;

    for (size_t i = 0; i < tag_len; i++)
        tag[i] = X[i] ^ S0[i];

    // 3. CTR 암호화 (counter=1부터)
    if (pt_len > 0) {
        uint8_t ctr_start[16];
        make_Ctr0(ctr_start, L, nonce, nonce_len, 1);
        st = aes_ctr_xor_stream(ctx, ctr_start, L, pt, pt_len, ct);
        if (st != AES_OK) return st;
    }
    return AES_OK;
}

/* AES-CCM 복호화 + 인증 검증 */
aes_status_t ccm_decrypt_and_verify(
    const aes_ctx_t* ctx,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t* tag, size_t tag_len,
    uint8_t* pt)
{
    if (!ctx || !nonce || (!ct && ct_len) || (!pt && ct_len) || !tag)
        return AES_ERR_ARG;

    aes_status_t st = check_params(nonce_len, tag_len);
    if (st != AES_OK) return st;

    const size_t L = 15u - nonce_len;

    // 1. CTR 복호화 (counter=1부터)
    if (ct_len > 0) {
        uint8_t ctr_start[16];
        make_Ctr0(ctr_start, L, nonce, nonce_len, 1);
        st = aes_ctr_xor_stream(ctx, ctr_start, L, ct, ct_len, pt);
        if (st != AES_OK) return st;
    }

    // 2. CBC-MAC 재계산
    uint8_t B0[16], X[16];
    make_B0(B0, L, tag_len, nonce, nonce_len, ct_len, aad_len > 0);

    cbc_mac_init(X);
    st = cbc_mac_update_block(ctx, X, B0);
    if (st != AES_OK) return st;

    st = cbc_mac_aad(ctx, X, aad, aad_len);
    if (st != AES_OK) return st;

    st = cbc_mac_msg(ctx, X, pt ? pt : (const uint8_t*)"", ct_len);
    if (st != AES_OK) return st;

    // 3. 태그 검증
    uint8_t ctr0[16], S0[16], comp_tag[16];
    make_Ctr0(ctr0, L, nonce, nonce_len, 0);
    st = aes_encrypt_block(ctx, ctr0, S0);
    if (st != AES_OK) return st;

    for (size_t i = 0; i < tag_len; i++)
        comp_tag[i] = X[i] ^ S0[i];

    uint8_t diff = 0;
    for (size_t i = 0; i < tag_len; i++)
        diff |= (uint8_t)(comp_tag[i] ^ tag[i]);

    if (diff != 0) {
        if (pt && ct_len) memset(pt, 0, ct_len);
        return AES_ERR_STATE; // 인증 실패
    }
    return AES_OK;
}
