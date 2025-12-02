#include "SHA512.h"  // SHA-512 컨텍스트/상수 정의 포함된 헤더
#include <string.h>  // memcpy 등 표준 문자열/메모리 함수

// SHA-512는 데이터를 128바이트 덩어리로 자르며 처리하는 해시함수

// SHA512 상수들
static const uint64_t k[80] = {    // 라운드 상수 K[t]. 80라운드를 돌릴 때 매 라운드마다 더해주는 고정 상수들
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// 헬퍼 함수들
static uint64_t rotr(uint64_t x, int n) {  // 오른쪽 순환 회전(ROTR): 상위 n비트를 하위로 순환
    return (x >> n) | (x << (64 - n));
}

static uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {  // Choose
    return (x & y) ^ (~x & z);                            // 선택 함수: x가 1인 자리에는 y의 비트를, 0인 자리에는 z 비트를 골라 합친 것
}

static uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {  // Majority
    return (x & y) ^ (x & z) ^ (y & z);                    // 다수결 함수: 각 자리별로 다수결하여 셋 중 2개 이상이 1이면 1을 반환하는 연산
}

static uint64_t sigma0(uint64_t x) {  // Σ0(x) = ROTR28(x) ^ ROTR34(x) ^ ROTR39(x)
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);  // 서로 다른 ROTR 3개를 XOR로 합쳐서 비트를 강하게 섞음
}

static uint64_t sigma1(uint64_t x) {  // Σ1(x) = ROTR14(x) ^ ROTR18(x) ^ ROTR41(x)
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);  // 이런 회전값들은 FIPS 180-4 표준에서 고정해두었음
}

static uint64_t gamma0(uint64_t x) {   // σ0(x) = ROTR1(x) ^ ROTR8(x) ^ SHR7(x)
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);  // ROTR 2ro + 오른쪽 쉬프트를 XOR로 합친 함수
}

static uint64_t gamma1(uint64_t x) {  // σ1(x) = ROTR19(x) ^ ROTR61(x) ^ SHR6(x)
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

// 바이트 순서 변환 (빅 엔디안, 64비트)
static void store64(uint8_t* dst, uint64_t w) {  // 64비트 정수를 빅엔디안(상위바이트 먼저) 바이트[8]로 저장
    dst[0] = (uint8_t)(w >> 56);
    dst[1] = (uint8_t)(w >> 48);
    dst[2] = (uint8_t)(w >> 40);
    dst[3] = (uint8_t)(w >> 32);
    dst[4] = (uint8_t)(w >> 24);
    dst[5] = (uint8_t)(w >> 16);
    dst[6] = (uint8_t)(w >> 8);
    dst[7] = (uint8_t)(w);
}

static uint64_t load64(const uint8_t* src) {  // 빅엔디안 바이트[8]를 64비트 정수로 로드
    return ((uint64_t)src[0] << 56) |
        ((uint64_t)src[1] << 48) |
        ((uint64_t)src[2] << 40) |
        ((uint64_t)src[3] << 32) |
        ((uint64_t)src[4] << 24) |
        ((uint64_t)src[5] << 16) |
        ((uint64_t)src[6] << 8) |
        (uint64_t)src[7];
}

// SHA512 초기화
void sha512_init(sha512_ctx_t* c) {
    // 초기 상태값 (IV): FIPS PUB 180-4에 정의된 고정 상수
    c->state[0] = 0x6a09e667f3bcc908ULL;  // H0
    c->state[1] = 0xbb67ae8584caa73bULL;  // H1
    c->state[2] = 0x3c6ef372fe94f82bULL;  // H2
    c->state[3] = 0xa54ff53a5f1d36f1ULL;  // H3
    c->state[4] = 0x510e527fade682d1ULL;  // H4
    c->state[5] = 0x9b05688c2b3e6c1fULL;  // H5
    c->state[6] = 0x1f83d9abfb41bd6bULL;  // H6
    c->state[7] = 0x5be0cd19137e2179ULL;  // H7

    c->bitlen_hi = 0;          // 상위 64비트
    c->bitlen_lo = 0;          // 하위 64비트 (패딩 시 총 비트 길이 인코딩용)
    c->buf_len = 0;          // 내부 버퍼에 저장된 데이터 길이 초기화
}
// -> SHA512 컨텍스트를 초기화
// state[]: 64비트 워드 8개의 워드를 구성된 해시 상태 레지스터
// bitlen_hi: 지금까지 입력된 데이터의 총 비트 수의 상위 64비트 (총 길이를 128비트로 표현하기 위한 상위 부분)
// bitlen_lo: 지금까지 입력된 데이터의 총 비트 수의 하위 64비트
// buf_len: 현재 버퍼에 쌓인 데이터의 길이 (128바이트 단위 처리용)

// SHA512 압축 함수 (공통화)
// 내부 전용 엔진이므로 헤더에는 작성하지 않는 게 좋음
static void sha512_compress(sha512_ctx_t* c, const uint8_t* block) {
    uint64_t w[80];

    // 메시지 스케줄링: 입력 블록의 처음 16워드를 빅엔디안 워드로 로드
    for (int t = 0; t < 16; t++) {
        w[t] = load64(&block[t * 8]);  // 128바이트 블록을 8바이트씩 잘라서 W[0,,,15]에 저장
    }

    // 메시지 스케쥴링: 16,,,79 워드를 이전 값들로부터 유도
    for (int t = 16; t < 80; t++) {
        w[t] = gamma1(w[t - 2])  // σ1'(x) = ROTR19 ^ ROTR61 ^ SHR6
            + w[t - 7]           // 7워드 전         
            + gamma0(w[t - 15])  // σ0'(x) = ROTR1 ^ ROTR8 ^ SHR7
            + w[t - 16];         // 16워드 전
    }

    // 작업 레지스터 초기화: 현재 내부 상태를 로컬 변수로 복사
    uint64_t a = c->state[0];
    uint64_t b = c->state[1];
    uint64_t c_val = c->state[2];  // 변수명 충돌 방지를 위해 c → c_val
    uint64_t d = c->state[3];
    uint64_t e = c->state[4];
    uint64_t f = c->state[5];
    uint64_t g = c->state[6];
    uint64_t h = c->state[7];

    // 메인 라운드: 80회 반복
    for (int t = 0; t < 80; t++) {
        uint64_t t1 = h          // t1 = h
            + sigma1(e)          //    + Σ1(e) = ROTR14 ^ ROTR18 ^ ROTR41
            + ch(e, f, g)        //    + Ch(e,f,g) = (e&f)^(~e&g)
            + k[t]               //    + 라운드 상수 K[t]
            + w[t];              //    + 이번 라운드용 메시지 워드 w[t]
        uint64_t t2 = sigma0(a)  // t2 = Σ0(a) = ROTR28 ^ ROTR34 ^ ROTR39
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
        // 오른쪽으로 한 칸씩 밀고, t1, t2로 a와 e 위치에 새로운 값 주입
        // 이 패턴을 80번 반복하면서 입력과 상태가 비선형적으로 섞임
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
    // 이렇게 만들어진 새 상태가 다음 블록의 시작값이 됨
}

// SHA512 업데이트 (데이터 처리) — 길이 누적을 "복사한 바이트 수" 기준으로
void sha512_update(sha512_ctx_t* c, const uint8_t* data, size_t len) {
    if (!data || len == 0) return;  // 입력이 없으면 즉시 반환

    while (len > 0) {                                   // 남은 입력을 모두 소비할 때까지
        size_t space = SHA512_BLOCK_SIZE - c->buf_len;  // 내부 버퍼의 남은 공간(0..128)
        size_t take = (len < space) ? len : space;      // 이번에 복사할 바이트 수 결정
        // 남은 입력(len)이 버퍼 빈칸(space)보다 작으면 남은 입력 만큼, 크거나 같으면 버퍼 빈칸만큼 채운다.

        memcpy(c->buf + c->buf_len, data, take);        // 아직 비어 있는 버퍼의 뒤쪽에 take 바이트만큼 가져다 붙임
        c->buf_len += take;                             // 버퍼 채워진 길이 갱신
        data += take;                                   // 외부 포인터 전진
        len -= take;                                    // 남은 입력 길이 감소

        // 원본 입력 길이 누적 (패딩 전 지금까지 처리한 총 비트 길이)
        uint64_t bits = (uint64_t)take * 8;               // 바이트를 비트로 (*8)

        c->bitlen_lo += bits;                             // 하위 64비트에 더하고

        if (c->bitlen_lo < bits) {                        // 오버플로우가 발생하면
            c->bitlen_hi++;                               // 상위 64비트에 캐리 반영
        }

        if (c->buf_len == SHA512_BLOCK_SIZE) {            // 버퍼가 128바이트 채워지면
            sha512_compress(c, c->buf);                   // 1024비트(한 블록) 압축 수행
            c->buf_len = 0;                               // 버퍼 비우기
        }
    }
}

// SHA512 최종화 (패딩 및 최종 해시 생성) — "패딩 전 총 비트 길이"를 128비트(상위 64 + 하위 64)로 기록
void sha512_final(sha512_ctx_t* c, uint8_t out[SHA512_DIGEST_SIZE]) {
    // 1) 0x80(패딩 시작 비트) 추가
    c->buf[c->buf_len++] = 0x80; // 1000 0000

    // 2) 길이(16바이트)를 남기고 0 패딩(마지막 16바이트에 총 비트 길이를 넣어야하기 때문)
    if (c->buf_len > 112) {  // 만약 지금 버퍼 위치가 112을 넘어가면(= 16바이트를 넣을 자리가 부족하면)
        while (c->buf_len < 128) {
            c->buf[c->buf_len++] = 0; // 일단 0으로 채워 한 블록을 마감
        }
        sha512_compress(c, c->buf);   // 첫 패딩 블록 압축
        c->buf_len = 0;               // 새 블록 시작
        // 패딩이 두 블록을 쓸 수도 있다는 뜻
    }
    while (c->buf_len < 112) {
        c->buf[c->buf_len++] = 0;  // 3) 길이 필드 앞(112바이트)까지 0패딩
    }

    // 4) 패딩 "전" 원본 총 비트 길이를 빅엔디안으로 기록
    store64(&c->buf[112], c->bitlen_hi);     // 상위 64비트
    store64(&c->buf[120], c->bitlen_lo);     // 하위 64비트

    // 5) 마지막 블록 압축 (길이 포함)
    sha512_compress(c, c->buf);
    c->buf_len = 0;  // 내부 버퍼 정리

    // 6) 최종 해시 출력
    for (int i = 0; i < 8; ++i) {
        store64(&out[i * 8], c->state[i]);  // 내부 상태값 state[0,,,7](각 64비트)를 총 64바이트 결과로 꺼냄
        // 빅엔디안으로 내보내는 것도 표준 규정
    }

    // (선택) 컨텍스트 민감 데이터 지우기
    // memset(c, 0, sizeof(*c));
}

// SHA512 단일 호출 함수
void sha512(const uint8_t* data, size_t len, uint8_t out[SHA512_DIGEST_SIZE]) {
    sha512_ctx_t ctx;                // 로컬 컨텍스트
    sha512_init(&ctx);               // 초기 상태(IV) 설정
    sha512_update(&ctx, data, len);  // 전체 입력 스트리밍 처리
    sha512_final(&ctx, out);         // 패딩/마지막 압축 및 해시 출력
}