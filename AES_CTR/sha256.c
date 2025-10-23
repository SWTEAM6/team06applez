#include "sha256.h"  // SHA-256 컨텍스트/상수 정의 포함된 헤더
#include <string.h>  // memcpy 등 표준 문자열/메모리 함수

// SHA256 상수들
static const uint32_t k[64] = {    // 라운드 상수 K[t], FIPS 180-4에 정의된 64개 32비트 상수
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// 헬퍼 함수들
static uint32_t rotr(uint32_t x, int n) {  // 오른쪽 순환 회전(ROTR): 상위 n비트를 하위로 순환
    return (x >> n) | (x << (32 - n));
}

static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {  // Ch(x,y,z) = (x^y) ⊕ (~x^z)
    return (x & y) ^ (~x & z);                            // 선택 함수: x 비트에 따라 y 또는 z 선택
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {  // Maj(x,y,z) = (x^y) ⊕ (x^z) ⊕ (y^z)
    return (x & y) ^ (x & z) ^ (y & z);                    // 다수 함수: 세 비트 중 다수결
}

static uint32_t sigma0(uint32_t x) {  // Σ0(x) = ROTR2(x) ^ ROTR13(x) ^ ROTR22(x)
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t sigma1(uint32_t x) {  // Σ1(x) = ROTR6(x) ^ ROTR11(x) ^ ROTR25(x)
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t gamma0(uint32_t x) {   // σ0(x) = ROTR7(x) ^ ROTR18(x) ^ SHR3(x)
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static uint32_t gamma1(uint32_t x) {  // σ1(x) = ROTR17(x) ^ ROTR19(x) ^ SHR10(x)
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// 바이트 순서 변환 (빅 엔디안)
static void store32(uint8_t* dst, uint32_t w) {  // 32비트 정수를 빅엔디안 바이트[4]로 저장
    dst[0] = (uint8_t)(w >> 24);
    dst[1] = (uint8_t)(w >> 16);
    dst[2] = (uint8_t)(w >> 8);
    dst[3] = (uint8_t)w;
}

static uint32_t load32(const uint8_t* src) {  // 빅엔디안 바이트[4]를 32비트 정수로 로드
    return ((uint32_t)src[0] << 24) |
        ((uint32_t)src[1] << 16) |
        ((uint32_t)src[2] << 8) |
        (uint32_t)src[3];
}

// 64비트 빅엔디안 저장 (길이 인코딩용)
static void store64_be(uint8_t dst[8], uint64_t v) {
    dst[0] = (uint8_t)(v >> 56);  // 최상위 바이트 (비트 63~56)
    dst[1] = (uint8_t)(v >> 48);  // 비트 55~48
    dst[2] = (uint8_t)(v >> 40);  // 비크 47~40
    dst[3] = (uint8_t)(v >> 32);  // 비트 39~32
    dst[4] = (uint8_t)(v >> 24);  // 비트 31~24
    dst[5] = (uint8_t)(v >> 16);  // 비트 23~16
    dst[6] = (uint8_t)(v >> 8);  // 비트 15~8
    dst[7] = (uint8_t)(v);  // 최하위 바이트 (비트 7~0)
}
// -> SHA256에서는 메시지 총 길이를 64비트 빅엔디안으로 패딩 블록 끝에 저장
// 이 함수는 그 변환을 수행

// SHA256 초기화
void sha256_init(sha256_ctx_t* c) {
    // 초기 상태값 (IV): FIPS PUB 180-4에 정의된 고정 상수
    c->state[0] = 0x6a09e667;  // H0
    c->state[1] = 0xbb67ae85;  // H1
    c->state[2] = 0x3c6ef372;  // H2
    c->state[3] = 0xa54ff53a;  // H3
    c->state[4] = 0x510e527f;  // H4
    c->state[5] = 0x9b05688c;  // H5
    c->state[6] = 0x1f83d9ab;  // H6
    c->state[7] = 0x5be0cd19;  // H7

    c->bitlen = 0;             // 지금까지 처리한 총 비트 길이 초기화 
    c->buf_len = 0;            // 내부 버퍼에 저장된 데이터 길이 초기화
}
// -> SHA256 컨텍스트를 초기화
// statwe[]: 8개의 워드를 구성된 해시 상태 레지스터
// bitlen: 지금까지 입력된 데이터의 총 비트 수 (패딩 시 기록용)
// buf_len: 현재 버퍼에 쌓인 데이터의 길이 (64바이트 단위 처리용)

// SHA256 압축 함수 (공통화)
static void sha256_compress(sha256_ctx_t* c, const uint8_t* block) {
    uint32_t w[64];

    // 메시지 스케줄링: 입력 블록의 처음 16워드를 빅엔디안으로 로드
    for (int t = 0; t < 16; t++) {
        w[t] = load32(&block[t * 4]);  // 메시지 스케쥴 (64x32비트) 버퍼
    }

    // 메시지 스케쥴링: 16,,,63 워드를 이전 값들로부터 유도
    for (int t = 16; t < 64; t++) {
        w[t] = gamma1(w[t - 2])  // σ1'(x) = ROTR17 ^ ROTR19 ^ SHR10
            + w[t - 7]           // 7워드 전         
            + gamma0(w[t - 15])  // σ0'(x) = ROTR7 ^ ROTR18 ^ SHR3
            + w[t - 16];         // 16워드 전
    }

    // 작업 레지스터 초기화: 현재 state를 로컬 변수로 복사
    uint32_t a = c->state[0];
    uint32_t b = c->state[1];
    uint32_t c_val = c->state[2];  // 변수명 충돌 방지를 위해 c→c_val
    uint32_t d = c->state[3];
    uint32_t e = c->state[4];
    uint32_t f = c->state[5];
    uint32_t g = c->state[6];
    uint32_t h = c->state[7];

    // 메인 라운드: 64회 반복
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = h          // t1 = h
            + sigma1(e)          //    + Σ1(e) = ROTR6 ^ ROTR11 ^ ROTR25
            + ch(e, f, g)        //    + Ch(e,f,g) = (e&f)^(~e&g)
            + k[t]               //    + 라운드 상수 K[t]
            + w[t];              //    + 메시지 워드 w[t]
        uint32_t t2 = sigma0(a)  // t2 = Σ0(a) = ROTR2 ^ ROTR13 ^ ROTR22
            + maj(a, b, c_val);  //    + Maj(a,b,c) = (a&b)^(a&c)^(b&c)

        // 레지스터 순환 업데이트
        h = g;        // h ← g
        g = f;        // g ← f
        f = e;        // f ← e
        e = d + t1;   // e ← d + t1
        d = c_val;    // d ← c
        c_val = b;    // c ← b
        b = a;        // b ← a
        a = t1 + t2;  // a ← t1 + t2
    }

    // 중간 해시 값 업데이트
    c->state[0] += a;      // H0 ← H0 + a
    c->state[1] += b;      // H1 ← H1 + b
    c->state[2] += c_val;  // H2 ← H2 + c
    c->state[3] += d;      // H3 ← H3 + d
    c->state[4] += e;      // H4 ← H4 + e
    c->state[5] += f;      // H5 ← H5 + f
    c->state[6] += g;      // H6 ← H6 + g
    c->state[7] += h;      // H7 ← H7 + h
}

// SHA256 업데이트 (데이터 처리) — 길이 누적을 "복사한 바이트 수" 기준으로
void sha256_update(sha256_ctx_t* c, const uint8_t* data, size_t len) {
    if (!data || len == 0) return;  // 입력이 없으면 즉시 반환

    while (len > 0) {                                   // 남은 입력을 모두 소비할 때까지
        size_t space = SHA256_BLOCK_SIZE - c->buf_len;  // 내부 버퍼의 남은 공간(0..64)
        size_t take = (len < space) ? len : space;      // 이번에 복사할 바이트 수 결정

        memcpy(c->buf + c->buf_len, data, take);        // 입력 일부를 내부 버퍼에 복사
        c->buf_len += take;                             // 버퍼 채워진 길이 갱신
        data += take;                                   // 외부 포인터 전진
        len -= take;                                    // 남은 입력 길이 감소

        // 원본 입력 길이 누적 (패딩 전 총 비트 길이)
        c->bitlen += (uint64_t)take * 8;

        if (c->buf_len == SHA256_BLOCK_SIZE) {          // 버퍼가 64바이트 채워지면
            sha256_compress(c, c->buf);                 // 512비트(한 블록) 압축 수행
            c->buf_len = 0;                             // 버퍼 비우기
        }
    }
}

// SHA256 최종화 (패딩 및 최종 해시 생성) — "패딩 전 길이"를 기록
void sha256_final(sha256_ctx_t* c, uint8_t out[SHA256_DIGEST_SIZE]) {
    // 1) 0x80(패딩 시작 비트) 추가
    c->buf[c->buf_len++] = 0x80;

    // 2) 길이(8바이트)를 남기고 0 패딩
    if (c->buf_len > 56) {
        while (c->buf_len < 64) c->buf[c->buf_len++] = 0;
        sha256_compress(c, c->buf);   // 첫 패딩 블록 압축
        c->buf_len = 0;               // 새 블록 시작
    }
    while (c->buf_len < 56) c->buf[c->buf_len++] = 0;  // 3) 길이 필드 앞(56바이트)까지 0패딩

    // 4) 패딩 "전" 원본 총 비트 길이를 빅엔디안으로 기록
    store64_be(&c->buf[56], c->bitlen);  

    // 5) 마지막 블록 압축 (길이 포함)
    sha256_compress(c, c->buf);
    c->buf_len = 0;  // 내부 버퍼 정리

    // 6) 최종 해시 출력
    for (int i = 0; i < 8; ++i) {
        store32(&out[i * 4], c->state[i]);  // 각 워드를 빅엔디안으로 out[32]에 저장
    }

    // (선택) 컨텍스트 민감 데이터 지우기
    // memset(c, 0, sizeof(*c));
}

// SHA256 단일 호출 함수
void sha256(const uint8_t* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]) {
    sha256_ctx_t ctx;                // 로컬 컨텍스트
    sha256_init(&ctx);               // 초기 상태(IV) 설정
    sha256_update(&ctx, data, len);  // 전체 입력 스트리밍 처리
    sha256_final(&ctx, out);         // 패딩/마지막 압축 및 해시 출력
}