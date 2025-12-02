#ifndef AES_HMAC_H  // 헤더 가드 시작
#define AES_HMAC_H  // 중복 포함 방지

#include <stddef.h>  // size_t 타입 사용
#include <stdint.h>  // 고정 크기 정수 타입 사용
#include "AES_CTR_ALL.h"  // AES 컨텍스트 및 상태 코드
#include "SHA512.h"   // SHA-512 해시 함수

#ifdef __cplusplus  // C++ 컴파일러인 경우
extern "C" {  // C 링키지 사용
#endif

    /*
     * AES-CTR + HMAC-SHA512 (Encrypt-then-MAC)
     *  - 암호화: AES-128 CTR 모드
     *  - 인증: HMAC-SHA512
     *  - 키 분리: 암호화 키와 MAC 키를 별도로 사용 (권장)
     */

    /* AES+HMAC 암호화 및 인증 태그 생성
     *  aes_ctx    : AES 암호화 컨텍스트 (암호화 키 사용)
     *  mac_key    : HMAC 키 (최소 64바이트 권장, SHA-512 블록 크기)
     *  mac_key_len: HMAC 키 길이
     *  nonce      : Nonce/IV (CTR 모드용)
     *  nonce_len  : Nonce 길이
     *  aad        : Associated Data (선택, MAC에만 포함)
     *  aad_len    : AAD 길이
     *  pt         : 평문 입력
     *  pt_len     : 평문 길이
     *  ct         : 암호문 출력 버퍼
     *  mac        : MAC 출력 버퍼 (64바이트)
     *  mac_len    : 사용할 MAC 길이 (최대 64바이트)
     */
    aes_status_t aes_hmac_encrypt(
        const aes_ctx_t* aes_ctx,
        const uint8_t* mac_key, size_t mac_key_len,
        const uint8_t* nonce, size_t nonce_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* pt, size_t pt_len,
        uint8_t* ct,
        uint8_t* mac, size_t mac_len);

    /* AES+HMAC 복호화 및 인증 검증
     *  mac 검증 실패 시 ct 버퍼는 0으로 지워짐 (보안)
     */
    aes_status_t aes_hmac_decrypt_and_verify(
        const aes_ctx_t* aes_ctx,
        const uint8_t* mac_key, size_t mac_key_len,
        const uint8_t* nonce, size_t nonce_len,
        const uint8_t* aad, size_t aad_len,
        const uint8_t* ct, size_t ct_len,
        const uint8_t* mac, size_t mac_len,
        uint8_t* pt);

#ifdef __cplusplus  // C++ 컴파일러인 경우
}  // extern "C" 블록 종료
#endif

#endif /* AES_HMAC_H */  // 헤더 가드 종료
