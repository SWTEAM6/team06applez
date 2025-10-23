#ifndef AESMINI_H
#define AESMINI_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    /* ===== 공통 ===== */
#define AES_BLOCK_BYTES   16u

/* 상태코드 */
#define AES_OK            0
#define AES_ERR_ARG       1   /* NULL, length=0 등 인자 오류 */
#define AES_ERR_KEYLEN    2   /* 허용 키 길이 아님(이 헤더는 128bit만 지원) */
#define AES_ERR_IVLEN     3   /* counter_len 범위(1~16) 아님 */
#define AES_ERR_OVERLAP   4   /* in/out 버퍼 중첩 */
#define AES_ERR_STATE     5   /* 컨텍스트 상태(예: rk_dec 미준비) */

    typedef int aes_status_t;

    /* ===== AES-128 전용: 라운드키 11개(44 words) ===== */
#define AES128_ROUNDS     10u
#define AES128_RK_WORDS   44u

    typedef struct {
        uint32_t rk_enc[AES128_RK_WORDS];  /* 176B */
        uint32_t rk_dec[AES128_RK_WORDS];  /* 176B (복호화용, 선택) */
        uint32_t rounds;                   /* 항상 10 */
        bool     has_dec;                  /* rk_dec 준비 여부 */
    } aes_ctx_t;

    /* ===== 1) 초기화 ===== */
    /* encrypt 전용 키스케줄만 준비 (기본) */
    aes_status_t aes_init_ctx(aes_ctx_t* ctx, const uint8_t key[16]);

    /* 복호화 라운드키를 추가로 준비 (필요할 때 호출) */
    aes_status_t aes_prepare_decrypt(aes_ctx_t* ctx);

    /* ===== 2) 코어 블록(ECB 한 블록) ===== */
    aes_status_t aes_encrypt_block(const aes_ctx_t* ctx,
        const uint8_t pt[AES_BLOCK_BYTES],
        uint8_t ct[AES_BLOCK_BYTES]);

    /* rk_dec이 준비되어 있어야 함(has_dec=true) */
    aes_status_t aes_decrypt_block(const aes_ctx_t* ctx,
        const uint8_t ct[AES_BLOCK_BYTES],
        uint8_t pt[AES_BLOCK_BYTES]);

    /* ===== 3) CTR 스트림 ===== */
    /* counter_block: in-place 증가; counter_len은 뒤에서부터 big-endian 증가 바이트 수[1..16]
       dst==src 인플레이스 허용, 그 외 부분 중첩은 AES_ERR_OVERLAP */
    void ctr_increment(uint8_t counter_block[16], size_t counter_len);

    aes_status_t aes_ctr_xor_stream(const aes_ctx_t* ctx,
        uint8_t counter_block[AES_BLOCK_BYTES],
        size_t counter_len,
        const uint8_t* src,
        size_t len,
        uint8_t* dst);

    /* ===== 4) (선택) 상태 변환: AES는 column-major(열 우선) 매핑 ===== */
    void bytes_to_state(const uint8_t in[16], uint8_t state[4][4]);
    void state_to_bytes(const uint8_t state[4][4], uint8_t out[16]);

#ifdef __cplusplus
}
#endif
#endif /* AESMINI_H */
