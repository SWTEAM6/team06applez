#ifndef AES_CTR_H  // 중복 방지
#define AES_CTR_H

#include <stddef.h>   // size_t와 같은 표준 타입
#include <stdint.h>   // 고정폭 정수
#include <stdbool.h>  // bool 타입

#ifdef __cplusplus  // C++에서 이 헤더를 쓸 때
extern "C" {        // 함수 이름이 망가지지 않게 C 링키지로 선언
#endif              // C++ 프로젝트에서 사용할 것을 대비해 미리 호환되도록 만드는 것

    /* ===== 공통 ===== */
#define AES_BLOCK_BYTES   16u  // AES 블록 크기(16바이트)

/* 상태코드 */
#define AES_OK            0
#define AES_ERR_ARG       1   // NULL, length=0 등 인자 오류 
#define AES_ERR_KEYLEN    2   // 허용 키 길이 아님(이 헤더는 128bit만 지원) 
#define AES_ERR_IVLEN     3   // counter_len 범위(1~16) 아님 
#define AES_ERR_OVERLAP   4   // in/out 버퍼 중첩 
#define AES_ERR_STATE     5   // 컨텍스트 상태(예: rk_dec 미준비)-CTR 불필요

    typedef int aes_status_t;  // 위 상태 코드를 담는 정수 타입

    /* ===== AES-128 전용: 라운드키 11개(44 words) ===== */
#define AES128_ROUNDS     10u  // AES-128 라운드 수(10)
#define AES128_RK_WORDS   44u  // 라운드키 총 워드 수(4x11=44)

    typedef struct {
        uint32_t rk_enc[AES128_RK_WORDS];  // 암호화용 라운드 키 저장 176B 
        uint32_t rk_dec[AES128_RK_WORDS];  // 176B (복호화용, 선택)-CTR 불필요
        uint32_t rounds;                   // 10 
        bool     has_dec;                  // rk_dec 준비 여부(True면 복호화 가능)-CTR 불필요
    } aes_ctx_t;

    /* ===== 1) 초기화 ===== */
    /* encrypt 전용 키스케줄만 준비 (기본) */
    aes_status_t aes_init_ctx(aes_ctx_t* ctx, const uint8_t key[16]);
    // 컨텍스트(ctx)에 16바이트 키로 암호화 라운드 키를 계산해 넣는다.

    /* 복호화 라운드키를 추가로 준비 (필요할 때 호출) */
    aes_status_t aes_prepare_decrypt(aes_ctx_t* ctx);
    // aes_init_ctx로 암호화 키가 준비된 상태에서, 복호화용 라운드키(rk_dec)도 만들어 둔다.
    // CTR에서는 불필요

    /* ===== 2) 코어 블록(ECB 한 블록) ===== */
    aes_status_t aes_encrypt_block(const aes_ctx_t* ctx,
        const uint8_t pt[AES_BLOCK_BYTES],
        uint8_t ct[AES_BLOCK_BYTES]);
    // 16바이트 평문(pt) 1블록을 암호화해서 16바이트 암호문(ct)로 만든다.

    /* rk_dec이 준비되어 있어야 함(has_dec=true) */
    aes_status_t aes_decrypt_block(const aes_ctx_t* ctx,
        const uint8_t ct[AES_BLOCK_BYTES],
        uint8_t pt[AES_BLOCK_BYTES]);
    // 16바이트 암호문(ct) 1블록을 복호화해서 16바이트 평문(pt)로 만든다. (복호화 키 필요)
    // CTR에서는 불필요

    /* ===== 3) CTR 스트림 ===== */
    // CTR 모드는 카운터 블록을 암호화해서 키스트림을 만들고, 평문과 XOR 하는 방식
    // Ciphertext = Plaintext + AES_encrypt(counter)
    // Plaintext = CIphertext + AES_encrypt(counter)
    // counter_block: in-place 증가; counter_len은 뒤에서부터 big-endian 증가 바이트 수[1..16]
    // dst==src 인플레이스 허용, 그 외 부분 중첩은 AES_ERR_OVERLAP 
    void ctr_increment(uint8_t counter_block[16], size_t counter_len);
    // 16바이트 카운터 블록의 맨 뒤에서 count_len 바이트를 빅엔디안 방식으로 +1 한다. 
    // in-place 증가란 새로운 배열을 만들지 않고 counter_block 자체를 수정하는 방법

    aes_status_t aes_ctr_xor_stream(const aes_ctx_t* ctx,
        uint8_t counter_block[AES_BLOCK_BYTES],
        size_t counter_len,
        const uint8_t* src,
        size_t len,
        uint8_t* dst);
    // CTR모드 스트림 처리. counter_block을 암호화해 나온 키스트림을 src와 XOR해 dst에 쓴다.
    // src: 입력된 데이터, len: 입력 길이, dst: 출력
    // 매 블록 처리 후 counter_block을 in-place로 증가. src==dst(제자리 처리)는 허용

    /* ===== 4) (선택) 상태 변환: AES는 column-major(열 우선) 매핑 ===== */
    void bytes_to_state(const uint8_t in[16], uint8_t state[4][4]);
    // 16바이트 배열을 AES 상태행렬(4x4)로 바꾼다. (열 우선 배치)
    void state_to_bytes(const uint8_t state[4][4], uint8_t out[16]);
    // AES 상태행렬(4x4)을 16 바이트 배열로 되돌린다. (열 우선 배치)

#ifdef __cplusplus  // C++에서
}                   // exter "C" 블록 끝
#endif
#endif /* AES_CTR_H */ 
