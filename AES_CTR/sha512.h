#ifndef SHA512_H  // 중복 포함 방지
#define SHA512_H

#include <stddef.h>  // size_t 타입 사용 위한 헤더
#include <stdint.h>  // 고정 폭 정수형(uint8_t, uint32_t, uint64_t)

#define SHA512_BLOCK_SIZE   128u  // SHA-512 내부 처리 블록 크기(바이트) = 1024비트
#define SHA512_DIGEST_SIZE  64u  // SHA-512 출력 해시 길이(바이트) = 512비트

typedef struct {
    uint64_t state[8];                // 내부 상태, 8개의 64비트 워드
    uint64_t bitlen_hi;               // 지금까지 처리한 총 비트 길이 상위(패딩 시 최종 길이 인코딩에 사용)
    uint64_t bitlen_lo;               // 지금까지 처리한 총 비트 길이 하위 64비트
    uint8_t  buf[SHA512_BLOCK_SIZE];  // 입력 데이터를 임시 저장하는 128바이트 버퍼
    size_t   buf_len;                 // buf에 현재 채워진 바이트 수(0~128)
} sha512_ctx_t;                       // SHA-512 스트리밍 컨텍스트(상태 보관용)

void sha512_init(sha512_ctx_t* c);  // 컨텍스트 초기화: state를 초기값(IV)로 설정, 길이/버퍼 리셋
void sha512_update(sha512_ctx_t* c, const uint8_t* data, size_t len);  // 메시지를 스트리밍으로 공급: 128바이트가 다 차면 압축 수행
void sha512_final(sha512_ctx_t* c, uint8_t out[SHA512_DIGEST_SIZE]);  // 패딩+최종 압축 후 최종 64바이트 해시값을 out 배열에 기록
void sha512(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]);  // 원샷 API: init->update->final을 한 번에 처리

#endif /* SHA512_H */