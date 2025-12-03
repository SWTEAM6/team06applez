#ifndef CCM_H  // 헤더 가드 시작: CCM_H가 정의되지 않았을 때만 아래 코드 포함
#define CCM_H  // CCM_H 매크로 정의하여 중복 포함 방지

#include <stddef.h>  // size_t 타입을 사용하기 위한 표준 라이브러리 포함
#include <stdint.h>  // uint8_t, uint64_t 등의 고정 크기 정수 타입 사용
#include <stdbool.h>  // bool 타입 사용을 위한 표준 라이브러리 포함
#include "team06_lib_api.h"   // AES-128 core & CTR interface - AES 암호화 및 CTR 모드 인터페이스

#ifdef __cplusplus  // C++ 컴파일러인 경우
extern "C" {  // C 링키지를 사용하여 C++에서도 C 함수로 호출 가능하도록 함
#endif

    /*
     * AES-CCM (Counter with CBC-MAC)  // AES-CCM 모드 설명 주석
     *  - 표준: NIST SP 800-38C  // NIST 표준 문서 참조
     *  - 지원: AES-128 기반  // AES-128 암호화 알고리즘 사용
     *  - Nonce: 7~13 bytes (L = 15 - nonce_len)  // Nonce 길이 제한 및 L 파라미터 설명
     *  - Tag:   4~16 bytes, 짝수 길이만 허용  // 인증 태그 길이 제한
     */

     /* 암호화 및 인증 태그 생성  // ccm_encrypt 함수 설명
      *  ctx        : AES 키 컨텍스트  // AES 암호화 컨텍스트 포인터
      *  nonce,len  : Nonce(IV)  // 초기화 벡터 및 길이
      *  aad,len    : Associated Data (선택)  // 추가 인증 데이터 (옵션)
      *  pt,len     : 평문 입력  // 평문 데이터 및 길이
      *  ct         : 암호문 출력 버퍼  // 암호문을 저장할 버퍼
      *  tag,len    : 인증 태그 출력  // 인증 태그 및 길이
      */
    aes_status_t ccm_encrypt(  // AES-CCM 암호화 함수 선언
        const aes_ctx_t* ctx,  // AES 컨텍스트 포인터 (읽기 전용)
        const uint8_t* nonce, size_t nonce_len,  // Nonce 버퍼와 길이
        const uint8_t* aad, size_t aad_len,  // 추가 인증 데이터 버퍼와 길이
        const uint8_t* pt, size_t pt_len,  // 평문 버퍼와 길이
        uint8_t* ct,  // 암호문 출력 버퍼
        uint8_t* tag, size_t tag_len);  // 인증 태그 출력 버퍼와 길이

    /* 복호화 및 인증 검증  // ccm_decrypt_and_verify 함수 설명
     *  tag 검증 실패 시 pt 버퍼는 0으로 지워짐  // 보안을 위한 메모리 초기화
     */
    aes_status_t ccm_decrypt_and_verify(  // AES-CCM 복호화 및 검증 함수 선언
        const aes_ctx_t* ctx,  // AES 컨텍스트 포인터 (읽기 전용)
        const uint8_t* nonce, size_t nonce_len,  // Nonce 버퍼와 길이
        const uint8_t* aad, size_t aad_len,  // 추가 인증 데이터 버퍼와 길이
        const uint8_t* ct, size_t ct_len,  // 암호문 버퍼와 길이
        const uint8_t* tag, size_t tag_len,  // 인증 태그 버퍼와 길이
        uint8_t* pt);  // 평문 출력 버퍼

#ifdef __cplusplus  // C++ 컴파일러인 경우
}  // extern "C" 블록 종료
#endif
#endif /* CCM_H */  // 헤더 가드 종료
