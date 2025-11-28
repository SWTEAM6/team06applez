#ifndef CCM_H
#define CCM_H

#include "AES_CTR_ALL.h"   // aes_ctx_t, aes_status_t, aes_ctr_xor_stream 등 사용

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * AES-CCM (Counter with CBC-MAC)
     *  - 표준: NIST SP 800-38C
     *  - 블록 암호: AES (aes_ctx_t에 따라 128/192/256 모두 사용 가능)
     *  - Nonce: 7~13 bytes (L = 15 - nonce_len)
     *  - Tag:   4~16 bytes, 짝수 길이만 허용
     */

    /* 암호화 및 인증 태그 생성
     *  ctx        : AES 키 컨텍스트 (aes_init_ctx_128/192/256/auto 로 초기화)
     *  nonce,len  : Nonce(IV)
     *  aad,len    : Associated Data (선택, 인증만 하고 암호화 X)
     *  pt,len     : 평문 입력
     *  ct         : 암호문 출력 버퍼
     *  tag,len    : 인증 태그 출력
     */
    aes_status_t ccm_encrypt(
        const aes_ctx_t* ctx,
        const uint8_t* nonce, size_t nonce_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct,
        uint8_t* tag, size_t tag_len);

    /* 복호화 및 인증 검증
     *  - tag 검증 실패 시 pt 버퍼는 0으로 지워짐
     */
    aes_status_t ccm_decrypt_and_verify(
        const aes_ctx_t* ctx,
        const uint8_t* nonce, size_t nonce_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ct, size_t ct_len,
        const uint8_t* tag, size_t tag_len,
        uint8_t* pt);

#ifdef __cplusplus
}
#endif

#endif /* CCM_H */
