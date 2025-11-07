#ifndef CCM_H
#define CCM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "team06_lib_api.h"   // AES-128 core & CTR interface

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * AES-CCM (Counter with CBC-MAC)
     *  - 표준: NIST SP 800-38C
     *  - 지원: AES-128 기반
     *  - Nonce: 7~13 bytes (L = 15 - nonce_len)
     *  - Tag:   4~16 bytes, 짝수 길이만 허용
     */

     /* 암호화 및 인증 태그 생성
      *  ctx        : AES 키 컨텍스트
      *  nonce,len  : Nonce(IV)
      *  aad,len    : Associated Data (선택)
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
     *  tag 검증 실패 시 pt 버퍼는 0으로 지워짐
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
