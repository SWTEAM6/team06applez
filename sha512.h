#ifndef SHA512_H  // 헤더 중복 방지
#define SHA512_H

#include <stddef.h>  // size_t 타입 사용을 위한 표준 라이브러리
#include <stdint.h>  // 고정 폭 정수 타입(uint8_t, uint32_t, uint64_t)

#define SHA512_BLOCK_SIZE   128u  // SHA-512 블록 처리 크기 (바이트) = 1024 비트
#define SHA512_DIGEST_SIZE  64u   // SHA-512 해시 다이제스트 크기 (바이트) = 512 비트

typedef struct {
    uint64_t state[8];                // 내부 해시 상태, 8개의 64비트 워드
    uint64_t bitlen_hi;               // 처리된 총 메시지 길이의 상위 64비트 (비트 단위)
    uint64_t bitlen_lo;               // 처리된 총 메시지 길이의 하위 64비트 (비트 단위)
    uint8_t  buf[SHA512_BLOCK_SIZE];  // 입력 데이터를 임시 저장하는 128 바이트 버퍼
    size_t   buf_len;                 // buf에 현재 채워진 바이트 수 (0~128 바이트)
} sha512_ctx_t;                       // SHA-512 컨텍스트 구조체

// sha512_init: SHA-512 컨텍스트를 초기화
// c: 초기화할 sha512_ctx_t 구조체 포인터
void sha512_init(sha512_ctx_t* c);

// sha512_update: 메시지 데이터를 SHA-512 컨텍스트에 추가하여 처리
// c: sha512_ctx_t 구조체 포인터
// data_bytes: 입력 데이터 바이트 배열 포인터
// len_bytes: 입력 데이터 길이 (바이트 단위)
void sha512_update(sha512_ctx_t* c, const uint8_t* data_bytes, size_t len_bytes);

// sha512_final: 최종 패딩을 추가하고 해시 다이제스트를 계산
// c: sha512_ctx_t 구조체 포인터
// out_digest_bytes: 64 바이트 해시 다이제스트를 저장할 출력 버퍼
void sha512_final(sha512_ctx_t* c, uint8_t out_digest_bytes[SHA512_DIGEST_SIZE]);

// sha512: 단일 호출 SHA-512 해시 계산 함수 (init -> update -> final을 한 번에 처리)
// data_bytes: 해시할 입력 데이터 바이트 배열 포인터
// len_bytes: 입력 데이터 길이 (바이트 단위)
// out_digest_bytes: 64 바이트 해시 다이제스트를 저장할 출력 버퍼
void sha512(const uint8_t* data_bytes, size_t len_bytes, uint8_t out_digest_bytes[SHA512_DIGEST_SIZE]);

#endif /* SHA512_H */