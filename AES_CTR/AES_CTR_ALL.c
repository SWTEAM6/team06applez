// AES_CTR_ALL.c — AES-128/192/256 모두 지원하는 CTR 모드 구현 파일
#include "AES_CTR_ALL.h"  // 이 파일에서 사용할 함수 선언과 타입 정의를 포함
#include <string.h>        // memcpy, memset 등의 문자열/메모리 함수를 사용하기 위한 표준 헤더

/* 내부 테이블/헬퍼: 심볼 노출 방지 위해 static 사용 (이 파일 내에서만 접근 가능) */
// AES S-box: SubBytes 변환과 키 스케줄링에서 사용하는 대체 테이블
// 256개의 바이트 값으로 구성되며, 각 입력 바이트(0x00~0xFF)를 고정된 출력 바이트로 매핑
// 이 테이블은 FIPS 197 표준에 정의된 AES S-box로, 비선형 변환을 제공하여 암호 강도를 높임
static const uint8_t SBOX[256] = {  // static: 이 파일 외부에서 접근 불가, const: 수정 불가
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};  // S-box 배열 정의 완료: 256개의 바이트 값

// 키 스케줄에서 사용하는 라운드 상수(10개): 각 라운드의 첫 번째 워드 생성 시 XOR되는 상수
// RCON[0]부터 RCON[9]까지: AES-128은 10라운드이므로 10개 필요
// 이 값들은 GF(2^8) 유한체에서 x^(i-1)을 나타냄 (x는 GF(2^8)의 원시 원소)
static const uint8_t RCON[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
// 각 값 설명:
// 0x01 = 1, 0x02 = 2, 0x04 = 4, 0x08 = 8, 0x10 = 16
// 0x20 = 32, 0x40 = 64, 0x80 = 128, 0x1b = 27 (GF(2^8)에서 128*2의 결과), 0x36 = 54

// GF(2^8)에서 x*2 연산: 갈루아 필드 GF(2^8)에서 값에 x(2)를 곱하는 연산
// xtime(a) = (a << 1) XOR (a의 최상위 비트가 1이면 0x1b를 XOR)
// 이는 GF(2^8)에서 x(다항식의 변수)를 곱하는 것과 같음
// 최상위 비트가 1이면 irreducible polynomial 0x11b (x^8 + x^4 + x^3 + x + 1)로 모듈로 연산
static inline uint8_t xtime(uint8_t x) {  // static inline: 이 파일 내부에서만 사용, 컴파일러가 인라인 확장 권장
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));  
    // x << 1: 왼쪽으로 1비트 시프트 (x*2와 같음)
    // x & 0x80: 최상위 비트(비트 7)가 1인지 확인
    // 최상위 비트가 1이면 0x1b를 XOR (irreducible polynomial의 하위 8비트)
    // 최상위 비트가 0이면 0x00을 XOR (변화 없음)
}

// 4 바이트를 빅엔디안으로 32비트 워드로 묶음: Make Word 함수
// 키 스케줄링에서 4개의 연속된 바이트를 하나의 32비트 워드로 변환할 때 사용
// 빅엔디안: 첫 번째 바이트가 최상위 바이트, 네 번째 바이트가 최하위 바이트
static inline uint32_t mkw(const uint8_t b4[4]) {  // b4는 4바이트 배열
    return ((uint32_t)b4[0] << 24) | ((uint32_t)b4[1] << 16) | ((uint32_t)b4[2] << 8) | ((uint32_t)b4[3]);
    // b4[0] << 24: 첫 번째 바이트를 최상위 8비트 위치로 이동 (비트 24~31)
    // b4[1] << 16: 두 번째 바이트를 중상위 8비트 위치로 이동 (비트 16~23)
    // b4[2] << 8: 세 번째 바이트를 중하위 8비트 위치로 이동 (비트 8~15)
    // b4[3]: 네 번째 바이트는 최하위 8비트 위치 (비트 0~7)
    // | 연산자로 모든 비트를 OR하여 하나의 32비트 워드로 결합
}

// 32비트 워드를 바이트 단위로 좌회전(8비트): Rotate Word 함수
// 키 스케줄링에서 RotWord 연산에 사용: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
static inline uint32_t rotl8(uint32_t w) {  // w는 32비트 워드
    return (w << 8) | (w >> 24);  
    // w << 8: 왼쪽으로 8비트 시프트 (하위 24비트가 상위로 이동)
    // w >> 24: 오른쪽으로 24비트 시프트 (상위 8비트가 하위로 이동)
    // | 연산자로 결합하여 순환 회전 효과 생성
}

// 워드의 각 바이트에 S-box 적용: Substitute Word 함수
// 키 스케줄링에서 SubWord 연산에 사용: 워드의 4개 바이트 각각에 S-box를 적용
static inline uint32_t subw(uint32_t w) {  // w는 32비트 워드
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |  // 최상위 바이트(비트 24~31)에 S-box 적용
        ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |     // 두 번째 바이트(비트 16~23)에 S-box 적용
        ((uint32_t)SBOX[(w >> 8) & 0xff] << 8) |       // 세 번째 바이트(비트 8~15)에 S-box 적용
        ((uint32_t)SBOX[w & 0xff]);                    // 최하위 바이트(비트 0~7)에 S-box 적용
    // 각 바이트를 추출하고 S-box로 치환한 후 원래 위치로 복원
}

/* ===== 상태 변환: column-major 매핑 ===== */
// 16바이트 배열을 4x4 상태 행렬로 변환: AES는 열 우선(column-major) 방식으로 저장
// in: 16바이트 입력 배열
// st: 4x4 상태 행렬 출력 (st[행][열] 형식)
void bytes_to_state(const uint8_t in[16], uint8_t st[4][4]) {  // 함수 정의
    for (int i = 0; i < 4; i++)   // i: 행 인덱스 (0~3)
        for (int j = 0; j < 4; j++)   // j: 열 인덱스 (0~3)
            st[i][j] = in[i + 4 * j];  // 열 우선 매핑: st[행 i][열 j] = in[행 i + 4*열 j]
    // 예: st[0][0] = in[0], st[1][0] = in[1], st[2][0] = in[2], st[3][0] = in[3] (첫 번째 열)
    //     st[0][1] = in[4], st[1][1] = in[5], st[2][1] = in[6], st[3][1] = in[7] (두 번째 열)
}

// 4x4 상태 행렬을 16바이트 배열로 변환: bytes_to_state의 역변환
// st: 4x4 상태 행렬 입력 (st[행][열] 형식)
// out: 16바이트 출력 배열
void state_to_bytes(const uint8_t st[4][4], uint8_t out[16]) {  // 함수 정의
    for (int i = 0; i < 4; i++)   // i: 행 인덱스 (0~3)
        for (int j = 0; j < 4; j++)   // j: 열 인덱스 (0~3)
            out[i + 4 * j] = st[i][j];  // 열 우선 매핑: out[행 i + 4*열 j] = st[행 i][열 j]
    // bytes_to_state와 동일한 매핑 규칙을 역으로 적용
}

/* ===== 키 확장: AES-128/192/256 공용 함수 ===== */
// 키 확장 알고리즘: 입력 키를 라운드 키로 확장하는 공용 함수
// key: 입력 키 배열 포인터
// Nk: 키 워드 수 (AES-128: 4, AES-192: 6, AES-256: 8)
// Nr: 라운드 수 (AES-128: 10, AES-192: 12, AES-256: 14)
// W: 출력 라운드 키 배열 (확장된 키가 저장됨)
static void expand_key_generic(const uint8_t* key, int Nk, int Nr, uint32_t* W) {  // static: 내부 함수
    int words = 4 * (Nr + 1);  // 총 워드 수 계산: 각 라운드마다 4워드, 초기 키 포함
    // AES-128: 4*(10+1) = 44워드, AES-192: 4*(12+1) = 52워드, AES-256: 4*(14+1) = 60워드
    
    // 초기 Nk 워드 입력: 입력 키를 워드 단위로 변환하여 저장
    for (int i = 0; i < Nk; i++)   // i: 0부터 Nk-1까지
        W[i] = mkw(&key[4 * i]);   // key[4*i]부터 4바이트를 빅엔디안으로 하나의 워드로 변환
    // 예: W[0] = key[0..3], W[1] = key[4..7], W[2] = key[8..11], W[3] = key[12..15] (AES-128)
    
    // 나머지 워드 확장: Nk부터 words-1까지의 워드를 생성
    for (int i = Nk; i < words; i++) {  // i: Nk부터 words-1까지
        uint32_t t = W[i - 1];  // t: 직전 워드 (임시 변수)
        
        if (i % Nk == 0) {  // 매 Nk번째 워드마다 (라운드의 첫 번째 워드)
            // 라운드 첫 워드: RotWord -> SubWord -> Rcon XOR
            // RotWord: 바이트 단위로 1바이트 왼쪽 순환 회전
            // SubWord: 각 바이트에 S-box 적용
            // Rcon XOR: 라운드 상수와 XOR
            t = subw(rotl8(t)) ^ ((uint32_t)RCON[(i / Nk) - 1] << 24);
            // rotl8(t): RotWord 연산 실행
            // subw(...): SubWord 연산 실행
            // RCON[(i / Nk) - 1] << 24: 라운드 상수를 최상위 바이트 위치로 이동 후 XOR
        } else if (Nk > 6 && (i % Nk) == 4) {  // AES-256 전용 규칙: Nk=8이고 i % 8 == 4일 때
            // AES-256 전용 규칙: i % 8 == 4이면 SubWord만 적용 (RotWord, Rcon 없음)
            t = subw(t);  // SubWord만 적용
        }
        // else: 일반적인 경우 (변환 없음, t는 직전 워드 그대로)
        
        W[i] = W[i - Nk] ^ t;  // Nk 워드 전과 XOR하여 현재 워드 생성
        // 예: AES-128에서 W[4] = W[0] ^ t, W[5] = W[1] ^ t, W[6] = W[2] ^ t, W[7] = W[3] ^ t
    }
}

/* ===== AES-128 초기화 함수 ===== */
// AES-128 컨텍스트 초기화: 16바이트 키로 AES-128 컨텍스트를 초기화
// ctx: 초기화할 AES 컨텍스트 포인터
// key: 16바이트(128비트) 키 배열
// 반환값: AES_OK (성공) 또는 AES_ERR_ARG (인자 오류)
aes_status_t aes_init_ctx_128(aes_ctx_t* ctx, const uint8_t key[16]) {  // 함수 정의
    if (!ctx || !key) return AES_ERR_ARG;  // NULL 포인터 검사: ctx나 key가 NULL이면 에러 반환
    ctx->rounds = 10;  // AES-128 라운드 수 설정: 10라운드
    ctx->key_size = AES_KEY_128;  // 키 크기 식별자 설정: AES_KEY_128 (0)
    expand_key_generic(key, 4, 10, ctx->rk_enc);  // 키 확장: Nk=4, Nr=10로 키 확장 실행
    // expand_key_generic: key를 받아서 44개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK;  // 성공 반환
}

/* ===== AES-192 초기화 함수 ===== */
// AES-192 컨텍스트 초기화: 24바이트 키로 AES-192 컨텍스트를 초기화
// ctx: 초기화할 AES 컨텍스트 포인터
// key: 24바이트(192비트) 키 배열
// 반환값: AES_OK (성공) 또는 AES_ERR_ARG (인자 오류)
aes_status_t aes_init_ctx_192(aes_ctx_t* ctx, const uint8_t key[24]) {  // 함수 정의
    if (!ctx || !key) return AES_ERR_ARG;  // NULL 포인터 검사: ctx나 key가 NULL이면 에러 반환
    ctx->rounds = 12;  // AES-192 라운드 수 설정: 12라운드
    ctx->key_size = AES_KEY_192;  // 키 크기 식별자 설정: AES_KEY_192 (1)
    expand_key_generic(key, 6, 12, ctx->rk_enc);  // 키 확장: Nk=6, Nr=12로 키 확장 실행
    // expand_key_generic: key를 받아서 52개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK;  // 성공 반환
}

/* ===== AES-256 초기화 함수 ===== */
// AES-256 컨텍스트 초기화: 32바이트 키로 AES-256 컨텍스트를 초기화
// ctx: 초기화할 AES 컨텍스트 포인터
// key: 32바이트(256비트) 키 배열
// 반환값: AES_OK (성공) 또는 AES_ERR_ARG (인자 오류)
aes_status_t aes_init_ctx_256(aes_ctx_t* ctx, const uint8_t key[32]) {  // 함수 정의
    if (!ctx || !key) return AES_ERR_ARG;  // NULL 포인터 검사: ctx나 key가 NULL이면 에러 반환
    ctx->rounds = 14;  // AES-256 라운드 수 설정: 14라운드
    ctx->key_size = AES_KEY_256;  // 키 크기 식별자 설정: AES_KEY_256 (2)
    expand_key_generic(key, 8, 14, ctx->rk_enc);  // 키 확장: Nk=8, Nr=14로 키 확장 실행
    // expand_key_generic: key를 받아서 60개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK;  // 성공 반환
}

/* ===== 키 길이 자동 감지 및 초기화 함수 ===== */
// 키 길이에 따라 자동으로 적절한 AES 버전을 선택하여 초기화
// ctx: 초기화할 AES 컨텍스트 포인터
// key: 키 배열 포인터 (길이는 key_len에 따라 결정)
// key_len: 키 길이 (바이트 단위, 16/24/32만 허용)
// 반환값: AES_OK (성공), AES_ERR_ARG (인자 오류), AES_ERR_KEYLEN (지원하지 않는 키 길이)
aes_status_t aes_init_ctx_auto(aes_ctx_t* ctx, const uint8_t* key, size_t key_len) {  // 함수 정의
    if (!ctx || !key) return AES_ERR_ARG;  // NULL 포인터 검사: ctx나 key가 NULL이면 에러 반환
    
    if (key_len == 16) {  // 키 길이가 16바이트인 경우
        return aes_init_ctx_128(ctx, key);  // AES-128로 초기화하고 결과 반환
    } else if (key_len == 24) {  // 키 길이가 24바이트인 경우
        return aes_init_ctx_192(ctx, key);  // AES-192로 초기화하고 결과 반환
    } else if (key_len == 32) {  // 키 길이가 32바이트인 경우
        return aes_init_ctx_256(ctx, key);  // AES-256로 초기화하고 결과 반환
    } else {  // 지원하지 않는 키 길이인 경우
        return AES_ERR_KEYLEN;  // 키 길이 오류 반환
    }
}

/* ===== 1블록 암호화 함수 (AES-128/192/256 공용) ===== */
// AES 블록 암호화: 16바이트 평문을 16바이트 암호문으로 변환
// 이 함수는 AES-128, AES-192, AES-256 모두 지원 (컨텍스트의 rounds 값에 따라 자동 조정)
// ctx: 초기화된 AES 컨텍스트 포인터 (라운드 수와 라운드 키가 설정되어 있어야 함)
// pt: 평문(plaintext) 16바이트 배열 입력
// ct: 암호문(ciphertext) 16바이트 배열 출력
// 반환값: AES_OK (성공) 또는 AES_ERR_ARG (인자 오류)
aes_status_t aes_encrypt_block(const aes_ctx_t* ctx,
    const uint8_t pt[AES_BLOCK_BYTES],  // 평문: AES_BLOCK_BYTES는 16
    uint8_t ct[AES_BLOCK_BYTES]) {       // 암호문: AES_BLOCK_BYTES는 16
    if (!ctx || !pt || !ct) return AES_ERR_ARG;  // NULL 포인터 검사: 모든 포인터가 NULL이 아니어야 함

    uint8_t s[4][4];  // AES 상태 행렬: 4x4 바이트 배열로 암호화 과정의 중간 상태를 저장
    bytes_to_state(pt, s);  // 평문을 상태 행렬로 변환: 16바이트 배열을 4x4 행렬로 열 우선 매핑

    // AddRoundKey(라운드 0): 초기 라운드 키를 상태에 XOR
    // 첫 번째 4워드(W[0], W[1], W[2], W[3])를 상태 행렬의 각 열에 XOR
    for (int i = 0; i < 4; i++) {  // i: 열 인덱스 (0~3)
        uint32_t w = ctx->rk_enc[i];  // w: i번째 라운드 키 워드 (W[i])
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff);  // 최상위 바이트를 추출하여 상태[0][i]에 XOR
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff);  // 두 번째 바이트를 추출하여 상태[1][i]에 XOR
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   // 세 번째 바이트를 추출하여 상태[2][i]에 XOR
        s[3][i] ^= (uint8_t)(w & 0xff);          // 최하위 바이트를 추출하여 상태[3][i]에 XOR
    }

    // 라운드 1부터 (Nr-1)까지 수행: 표준 라운드 (SubBytes, ShiftRows, MixColumns, AddRoundKey)
    for (int r = 1; r < (int)ctx->rounds; r++) {  // r: 현재 라운드 번호 (1부터 rounds-1까지)
        // SubBytes: 각 바이트를 S-box로 치환 (비선형 변환)
        for (int i = 0; i < 4; i++)   // i: 행 인덱스 (0~3)
            for (int j = 0; j < 4; j++)   // j: 열 인덱스 (0~3)
                s[i][j] = SBOX[s[i][j]];  // 각 바이트를 S-box 테이블로 치환
        // S-box 치환으로 각 바이트가 완전히 다른 값으로 대체되어 암호 강도 향상

        // ShiftRows (인라인 구현): 각 행을 왼쪽으로 순환 시프트
        // 행 0: 시프트 없음 (그대로)
        // 행 1: 1바이트 왼쪽 시프트
        // 행 2: 2바이트 왼쪽 시프트
        // 행 3: 3바이트 왼쪽 시프트 (또는 1바이트 오른쪽 시프트)
        {
            uint8_t t;  // 임시 변수: 스왑에 사용
            // 행 1: 1바이트 왼쪽 순환 시프트 [a,b,c,d] -> [b,c,d,a]
            t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
            // 행 2: 2바이트 왼쪽 순환 시프트 [a,b,c,d] -> [c,d,a,b]
            t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;       // s[2][0] <-> s[2][2] 교환
            t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;       // s[2][1] <-> s[2][3] 교환
            // 행 3: 3바이트 왼쪽 순환 시프트 [a,b,c,d] -> [d,a,b,c] (또는 1바이트 오른쪽)
            t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
        }

        // MixColumns (인라인 구현): 각 열에 선형 변환 적용 (GF(2^8)에서 행렬 곱셈)
        // 각 열을 독립적으로 변환하여 바이트 간의 선형 관계를 확산시킴
        for (int c = 0; c < 4; c++) {  // c: 열 인덱스 (0~3)
            uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];  // 열 c의 4개 바이트 저장
            // MixColumns 행렬 연산 (GF(2^8)에서):
            // [r0]   [2 3 1 1]   [a0]
            // [r1] = [1 2 3 1] * [a1]
            // [r2]   [1 1 2 3]   [a2]
            // [r3]   [3 1 1 2]   [a3]
            // xtime(x) = x*2 (GF(2^8)에서)
            uint8_t r0 = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);  // r0 = 2*a0 + 3*a1 + 1*a2 + 1*a3
            uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);  // r1 = 1*a0 + 2*a1 + 3*a2 + 1*a3
            uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));  // r2 = 1*a0 + 1*a1 + 2*a2 + 3*a3
            uint8_t r3 = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));  // r3 = 3*a0 + 1*a1 + 1*a2 + 2*a3
            s[0][c] = r0; s[1][c] = r1; s[2][c] = r2; s[3][c] = r3;  // 변환된 결과를 상태 행렬에 저장
        }
        
        // AddRoundKey: 이번 라운드의 라운드 키를 상태에 XOR
        // 라운드 r의 4워드(W[4*r], W[4*r+1], W[4*r+2], W[4*r+3])를 상태 행렬의 각 열에 XOR
        for (int i = 0; i < 4; i++) {  // i: 열 인덱스 (0~3)
            uint32_t w = ctx->rk_enc[4 * r + i];  // w: 라운드 r의 i번째 워드 (W[4*r+i])
            s[0][i] ^= (uint8_t)((w >> 24) & 0xff);  // 최상위 바이트를 추출하여 상태[0][i]에 XOR
            s[1][i] ^= (uint8_t)((w >> 16) & 0xff);  // 두 번째 바이트를 추출하여 상태[1][i]에 XOR
            s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   // 세 번째 바이트를 추출하여 상태[2][i]에 XOR
            s[3][i] ^= (uint8_t)(w & 0xff);          // 최하위 바이트를 추출하여 상태[3][i]에 XOR
        }
    }

    // 마지막 라운드(Nr): MixColumns 없이 SubBytes, ShiftRows, AddRoundKey만 수행
    // 마지막 라운드에서는 MixColumns를 생략하여 복호화 알고리즘의 대칭성 유지
    
    // SubBytes: 각 바이트를 S-box로 치환
    for (int i = 0; i < 4; i++)   // i: 행 인덱스 (0~3)
        for (int j = 0; j < 4; j++)   // j: 열 인덱스 (0~3)
            s[i][j] = SBOX[s[i][j]];  // 각 바이트를 S-box 테이블로 치환

    {
        // ShiftRows: 각 행을 왼쪽으로 순환 시프트 (라운드 1~9와 동일)
        uint8_t t;  // 임시 변수: 스왑에 사용
        // 행 1: 1바이트 왼쪽 순환 시프트
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
        // 행 2: 2바이트 왼쪽 순환 시프트
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;       // s[2][0] <-> s[2][2] 교환
        t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;       // s[2][1] <-> s[2][3] 교환
        // 행 3: 3바이트 왼쪽 순환 시프트
        t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
    }

    // AddRoundKey(마지막 라운드): 마지막 라운드 키를 상태에 XOR
    // 마지막 라운드의 4워드(W[4*Nr], W[4*Nr+1], W[4*Nr+2], W[4*Nr+3])를 상태 행렬의 각 열에 XOR
    for (int i = 0; i < 4; i++) {  // i: 열 인덱스 (0~3)
        uint32_t w = ctx->rk_enc[4 * ctx->rounds + i];  // w: 마지막 라운드의 i번째 워드 (W[4*rounds+i])
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff);  // 최상위 바이트를 추출하여 상태[0][i]에 XOR
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff);  // 두 번째 바이트를 추출하여 상태[1][i]에 XOR
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   // 세 번째 바이트를 추출하여 상태[2][i]에 XOR
        s[3][i] ^= (uint8_t)(w & 0xff);          // 최하위 바이트를 추출하여 상태[3][i]에 XOR
    }

    state_to_bytes(s, ct);  // 상태 행렬을 16바이트 배열로 변환하여 암호문에 저장
    return AES_OK;  // 성공 반환
}

/* ===== CTR 스트림 함수들 ===== */
// 카운터 증가 함수: CTR 모드에서 사용하는 카운터 블록을 증가시킴
// counter_block: 16바이트 카운터 블록 (이 함수에서 in-place로 수정됨)
// counter_len: 카운터 길이 (1~16 바이트, 맨 뒤에서부터 이 길이만큼만 증가)
// 작동 방식: 맨 뒤에서부터 counter_len 바이트만큼 big-endian 방식으로 1 증가
// 예: counter_len=4이면 인덱스 12~15의 4바이트가 하나의 32비트 big-endian 숫자로 취급되어 증가
void ctr_increment(uint8_t counter_block[16], size_t counter_len) {  // 함수 정의
    if (counter_len == 0 || counter_len > 16) return;  // 허용 범위 체크: 1~16 바이트만 허용
    // 맨 뒤부터 올리고, 넘치면(=0xFF -> 0x00) 자리올림을 왼쪽으로 전파
    for (int i = 15; i >= 16 - (int)counter_len; i--) {  // i: 맨 뒤(15)부터 카운터 시작 위치까지 역순으로
        counter_block[i]++;  // 현재 바이트를 1 증가
        if (counter_block[i] != 0) break;  // carry가 안 나면 종료 (0xFF가 아니면 더 이상 자리올림 없음)
        // counter_block[i]가 0이면 자리올림 발생: 다음 바이트로 넘어가서 계속 증가
    }
}

// CTR 모드 스트림 처리 함수: CTR 모드로 데이터를 암호화/복호화
// CTR 모드 특징: 암호화와 복호화가 동일한 연산 (XOR만 사용)이므로 같은 함수로 처리 가능
// ctx: 초기화된 AES 컨텍스트 포인터 (AES-128/192/256 모두 가능)
// counter_block: 16바이트 카운터 블록 (처리 중 in-place로 증가됨, 다음 사용을 위해 수정됨)
// counter_len: 카운터 길이 (1~16 바이트, 맨 뒤에서부터 증가할 바이트 수)
// src: 입력 데이터 포인터 (평문 또는 암호문)
// len: 처리할 데이터 길이 (바이트 단위, 임의의 길이 가능)
// dst: 출력 데이터 포인터 (암호문 또는 평문)
// 반환값: AES_OK (성공), AES_ERR_ARG (인자 오류), AES_ERR_IVLEN (카운터 길이 오류), AES_ERR_OVERLAP (버퍼 중첩)
// 주의: src==dst이면 in-place 처리 가능 (같은 버퍼에서 암복호화 가능, CTR 모드의 장점)
aes_status_t aes_ctr_xor_stream(const aes_ctx_t* ctx,
    uint8_t counter_block[AES_BLOCK_BYTES],  // 카운터 블록: AES_BLOCK_BYTES는 16
    size_t counter_len,                       // 카운터 길이: 1~16 바이트
    const uint8_t* src,                       // 입력 데이터 포인터
    size_t len,                               // 데이터 길이: 바이트 단위
    uint8_t* dst) {                           // 출력 데이터 포인터
    if (!ctx || !counter_block || !src || !dst) return AES_ERR_ARG;  // NULL 포인터 검사
    if (counter_len == 0 || counter_len > 16) return AES_ERR_IVLEN;  // 카운터 길이 범위 검사: 1~16만 허용
    if (len == 0) return AES_OK;  // 처리할 데이터가 없으면 즉시 성공 반환

    // 중첩 검사: 입력과 출력 버퍼가 부분적으로 겹치는지 확인 (dst==src는 허용)
    if (dst != src) {  // 완전히 동일한 포인터가 아닌 경우에만 중첩 검사
        const uint8_t* s0 = src;        // src 시작 주소
        const uint8_t* s1 = src + len;  // src 끝 주소 (한 칸 뒤)
        uint8_t* d0 = dst;              // dst 시작 주소
        uint8_t* d1 = dst + len;        // dst 끝 주소 (한 칸 뒤)
        // 두 구간이 겹치면 에러: 완전 동일 포인터가 아닌 부분 겹침은 금지
        // 겹침 조건: d0 < s1 && s0 < d1 (두 구간이 교차)
        // 겹치지 않음 조건: d1 <= s0 (dst가 src 앞에 있음) || s1 <= d0 (src가 dst 앞에 있음)
        if (!(d1 <= s0 || s1 <= d0)) return AES_ERR_OVERLAP;  // 부분 겹침 감지 시 오류 반환
    }
    // dst == src인 경우: in-place 처리 허용 (CTR 모드의 장점)

    uint8_t ks[AES_BLOCK_BYTES];  // 키스트림 버퍼: 카운터 블록을 암호화한 결과를 저장 (최대 16바이트)
    size_t done = 0;              // 처리된 총 바이트 수: 현재까지 처리한 데이터 길이 누적

    while (done < len) {  // 모든 데이터를 처리할 때까지 반복
        // 1) 현재 counter_block을 AES로 암호화하여 키스트림 ks 생성
        aes_status_t st = aes_encrypt_block(ctx, counter_block, ks);  // 카운터를 암호화하여 키스트림 생성
        if (st != AES_OK) return st;  // 암호화 실패 시 즉시 오류 반환

        // 2) 남은 길이를 기준으로 이번에 처리할 길이 결정 (최대 16바이트)
        size_t blen = (len - done < AES_BLOCK_BYTES) ? (len - done) : AES_BLOCK_BYTES;
        // 남은 데이터가 16바이트 미만이면 남은 길이만큼, 아니면 16바이트만큼 처리

        // 3) src의 데이터와 키스트림을 XOR하여 dst에 저장 (CTR 모드의 핵심 연산)
        for (size_t i = 0; i < blen; i++)   // i: 현재 블록 내에서의 바이트 인덱스 (0부터 blen-1까지)
            dst[done + i] = src[done + i] ^ ks[i];  // XOR 연산: 평문 ^ 키스트림 = 암호문 (또는 그 역)
        // CTR 모드는 암호화와 복호화가 동일하므로 같은 함수로 처리 가능

        // 4) 처리된 바이트 수 누적 및 카운터 증가
        done += blen;  // 처리된 바이트 수 누적: 다음 블록 처리 준비
        ctr_increment(counter_block, counter_len);  // 카운터를 big-endian 방식으로 1 증가 (in-place)
        // 다음 블록을 위해 카운터를 증가시켜 고유한 키스트림 생성
    }
    return AES_OK;  // 모든 데이터 처리 완료, 성공 반환
}

