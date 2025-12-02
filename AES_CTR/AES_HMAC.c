// AES_HMAC.c — AES-CTR + HMAC-SHA512 (Encrypt-then-MAC)
#include "AES_HMAC.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>

// HMAC-SHA512 계산 (내부 함수)
static void hmac_sha512(const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* mac, size_t mac_len) {
    sha512_ctx_t ctx;
    uint8_t key_padded[SHA512_BLOCK_SIZE];
    uint8_t o_key_pad[SHA512_BLOCK_SIZE];
    uint8_t i_key_pad[SHA512_BLOCK_SIZE];
    uint8_t hash[SHA512_DIGEST_SIZE];

    // 키 패딩 처리
    if (key_len > SHA512_BLOCK_SIZE) {
        // 키가 블록 크기보다 크면 해시
        sha512(key, key_len, key_padded);
        memset(&key_padded[SHA512_DIGEST_SIZE], 0, SHA512_BLOCK_SIZE - SHA512_DIGEST_SIZE);
    } else {
        memcpy(key_padded, key, key_len);
        memset(&key_padded[key_len], 0, SHA512_BLOCK_SIZE - key_len);
    }

    // o_key_pad = key_padded XOR 0x5c
    // i_key_pad = key_padded XOR 0x36
    for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
        o_key_pad[i] = key_padded[i] ^ 0x5c;
        i_key_pad[i] = key_padded[i] ^ 0x36;
    }

    // HMAC = H((o_key_pad || H((i_key_pad || data))))
    // 1. 내부 해시: H(i_key_pad || data)
    sha512_init(&ctx);
    sha512_update(&ctx, i_key_pad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, hash);

    // 2. 외부 해시: H(o_key_pad || 내부 해시)
    sha512_init(&ctx);
    sha512_update(&ctx, o_key_pad, SHA512_BLOCK_SIZE);
    sha512_update(&ctx, hash, SHA512_DIGEST_SIZE);
    sha512_final(&ctx, hash);

    // MAC 길이만큼만 복사
    size_t copy_len = (mac_len < SHA512_DIGEST_SIZE) ? mac_len : SHA512_DIGEST_SIZE;
    memcpy(mac, hash, copy_len);
}

/* AES+HMAC 암호화 및 인증 태그 생성 */
aes_status_t aes_hmac_encrypt(
    const aes_ctx_t* aes_ctx,
    const uint8_t* mac_key, size_t mac_key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct,
    uint8_t* mac, size_t mac_len) {
    
    if (!aes_ctx || !mac_key || !nonce || (!pt && pt_len) || (!ct && pt_len) || !mac)
        return AES_ERR_ARG;
    
    if (mac_len == 0 || mac_len > SHA512_DIGEST_SIZE)
        return AES_ERR_ARG;
    
    // 오버플로우 검사
    if (pt_len > SIZE_MAX - aad_len)
        return AES_ERR_ARG;
    
    // 1. AES-CTR 암호화
    uint8_t counter_block[16];
    memset(counter_block, 0, 16);
    size_t nonce_copy_len = (nonce_len < 16) ? nonce_len : 16;
    memcpy(counter_block, nonce, nonce_copy_len);
    
    aes_status_t st = aes_ctr_xor_stream_bytes_in_bytes_out(aes_ctx, counter_block, nonce_len, pt, pt_len, ct);
    if (st != AES_OK) {
        // 암호화 실패 시 출력 버퍼 초기화 (보안)
        if (ct && pt_len > 0) {
            memset(ct, 0, pt_len);
        }
        return st;
    }
    
    // 2. HMAC 계산: MAC = HMAC-SHA512(mac_key, AAD || CT)
    // MAC 입력 구성: AAD (있으면) || 암호문
    size_t mac_input_len = aad_len + pt_len;
    uint8_t* mac_input = NULL;
    
    if (mac_input_len > 0) {
        mac_input = (uint8_t*)malloc(mac_input_len);
        if (!mac_input) {
            if (ct && pt_len > 0) memset(ct, 0, pt_len);
            return AES_ERR_ARG;
        }
        
        size_t offset = 0;
        if (aad && aad_len > 0) {
            memcpy(mac_input, aad, aad_len);
            offset = aad_len;
        }
        if (ct && pt_len > 0) {
            memcpy(mac_input + offset, ct, pt_len);
        }
    }
    
    hmac_sha512(mac_key, mac_key_len, mac_input ? mac_input : (const uint8_t*)"", mac_input_len, mac, mac_len);
    
    if (mac_input) {
        free(mac_input);
    }
    
    return AES_OK;
}

/* AES+HMAC 복호화 및 인증 검증 */
aes_status_t aes_hmac_decrypt_and_verify(
    const aes_ctx_t* aes_ctx,
    const uint8_t* mac_key, size_t mac_key_len,
    const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t* mac, size_t mac_len,
    uint8_t* pt) {
    
    if (!aes_ctx || !mac_key || !nonce || (!ct && ct_len) || (!pt && ct_len) || !mac)
        return AES_ERR_ARG;
    
    if (mac_len == 0 || mac_len > SHA512_DIGEST_SIZE)
        return AES_ERR_ARG;
    
    // 오버플로우 검사
    if (ct_len > SIZE_MAX - aad_len)
        return AES_ERR_ARG;
    
    // 1. MAC 검증: MAC = HMAC-SHA512(mac_key, AAD || CT)
    size_t mac_input_len = aad_len + ct_len;
    uint8_t* mac_input = NULL;
    
    if (mac_input_len > 0) {
        mac_input = (uint8_t*)malloc(mac_input_len);
        if (!mac_input) {
            if (pt && ct_len > 0) memset(pt, 0, ct_len);
            return AES_ERR_ARG;
        }
        
        size_t offset = 0;
        if (aad && aad_len > 0) {
            memcpy(mac_input, aad, aad_len);
            offset = aad_len;
        }
        if (ct && ct_len > 0) {
            memcpy(mac_input + offset, ct, ct_len);
        }
    }
    
    uint8_t computed_mac[SHA512_DIGEST_SIZE];
    hmac_sha512(mac_key, mac_key_len, mac_input ? mac_input : (const uint8_t*)"", mac_input_len, computed_mac, mac_len);
    
    if (mac_input) {
        free(mac_input);
    }
    
    // 상수 시간 비교
    uint8_t diff = 0;
    for (size_t i = 0; i < mac_len; i++) {
        diff |= (computed_mac[i] ^ mac[i]);
    }
    
    if (diff != 0) {
        // MAC 검증 실패: 평문 버퍼 초기화 (보안)
        if (pt && ct_len > 0) {
            memset(pt, 0, ct_len);
        }
        return AES_ERR_STATE;
    }
    
    // 2. AES-CTR 복호화 (MAC 검증 성공 후)
    uint8_t counter_block[16];
    memset(counter_block, 0, 16);
    size_t nonce_copy_len = (nonce_len < 16) ? nonce_len : 16;
    memcpy(counter_block, nonce, nonce_copy_len);
    
    aes_status_t st = aes_ctr_xor_stream_bytes_in_bytes_out(aes_ctx, counter_block, nonce_len, ct, ct_len, pt);
    if (st != AES_OK) {
        // 복호화 실패 시 평문 버퍼 초기화 (보안)
        if (pt && ct_len > 0) {
            memset(pt, 0, ct_len);
        }
        return st;
    }
    
    return AES_OK;
}

