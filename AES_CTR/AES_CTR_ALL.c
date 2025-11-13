#include "AES_CTR_ALL.h"  
#include <string.h>       

/* 내부 테이블/헬퍼: 심볼 노출 방지 위해 static 사용 (이 파일 내에서만 접근 가능) */
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
};  // AES SubBytes / 키 스케줄

// 키 스케줄에서 사용하는 라운드 상수(10개): 각 라운드의 첫 번째 워드 생성 시 XOR되는 상수
static const uint8_t RCON[10] = { 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36 };
// GF(2^8) 유한체에서 x^(i-1)을 나타냄

// GF(2^8)에서 x*2 연산: xtime(a) = (a << 1) XOR (비트가 넘치면 0x1b를 XOR)
// 최상위 비트가 1이면 irreducible polynomial 0x11b (x^8 + x^4 + x^3 + x + 1)로 모듈러 연산
static inline uint8_t xtime(uint8_t x) {  
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));  
    // x & 0x80: 최상위 비트(비트 7)가 1인지 확인
    // 최상위 비트가 1이면 0x1b를 XOR (irreducible polynomial의 하위 8비트)
    // 최상위 비트가 0이면 0x00을 XOR (변화 없음)
}

// 4 바이트를 빅엔디안으로 32비트 워드로 묶음 (키 스케줄 시작값 W[0,1,2,3] 만들 때 사용)
static inline uint32_t mkw(const uint8_t b4[4]) {  // b4는 4바이트 배열
    return ((uint32_t)b4[0] << 24) | ((uint32_t)b4[1] << 16) | ((uint32_t)b4[2] << 8) | ((uint32_t)b4[3]);
}

// 32비트 워드를 바이트 단위로 좌회전(8비트): Rotate Word 함수
// 키 스케줄링에서 RotWord 연산에 사용: [a0, a1, a2, a3] -> [a1, a2, a3, a0]
static inline uint32_t rotl8(uint32_t w) {  
    return (w << 8) | (w >> 24);  
}

// 워드의 각 바이트에 S-box 적용 
static inline uint32_t subw(uint32_t w) {  
    return ((uint32_t)SBOX[(w >> 24) & 0xff] << 24) |  
        ((uint32_t)SBOX[(w >> 16) & 0xff] << 16) |    
        ((uint32_t)SBOX[(w >> 8) & 0xff] << 8) |     
        ((uint32_t)SBOX[w & 0xff]);                   
}

/* ===== 상태 변환: column-major 매핑 ===== */
void bytes_to_state(const uint8_t in[16], uint8_t st[4][4]) {  
    for (int i = 0; i < 4; i++) 
        for (int j = 0; j < 4; j++)  
            st[i][j] = in[i + 4 * j]; 
}

void state_to_bytes(const uint8_t st[4][4], uint8_t out[16]) {  
    for (int i = 0; i < 4; i++)   
        for (int j = 0; j < 4; j++)   
            out[i + 4 * j] = st[i][j]; 
}

/* ===== 키 확장: AES-128/192/256 공용 함수 ===== */
// 입력 키를 라운드 키로 확장하는 공용 함수
// key: 입력 키 배열 포인터
// Nk: 키 워드 수 (AES-128: 4, AES-192: 6, AES-256: 8)
// Nr: 라운드 수 (AES-128: 10, AES-192: 12, AES-256: 14)
// W: 확장된 키가 저장될 워드 배열
static void expand_key_generic(const uint8_t* key, int Nk, int Nr, uint32_t* W) {  
    int words = 4 * (Nr + 1);  // 총 워드 수 계산: 각 라운드마다 4워드, 초기 키 포함
    // AES-128: 4*(10+1) = 44워드, AES-192: 4*(12+1) = 52워드, AES-256: 4*(14+1) = 60워드
    
    // 초기 Nk 워드 입력: 입력 키를 워드 단위로 변환하여 저장
    for (int i = 0; i < Nk; i++)  
        W[i] = mkw(&key[4 * i]);   // key[4*i]부터 4바이트를 빅엔디안으로 하나의 워드로 변환
    
    // Nk부터 words-1까지의 워드를 생성
    for (int i = Nk; i < words; i++) { 
        uint32_t t = W[i - 1];  // t: 직전 워드 
        
        if (i % Nk == 0) {  // 라운드의 첫 번째 워드일 때마다
            // 라운드 첫 워드: RotWord -> SubWord -> Rcon XOR
            t = subw(rotl8(t)) ^ ((uint32_t)RCON[(i / Nk) - 1] << 24);
        } else if (Nk > 6 && (i % Nk) == 4) {  // AES-256 추가 규칙: Nk=8이고 i % 8 == 4일 때
            // SubWord만 적용 (RotWord, Rcon 없음)
            t = subw(t);  
        }
        
        W[i] = W[i - Nk] ^ t;  // Nk 워드 전과 XOR하여 현재 워드 생성
    }
}

/* ===== AES-128 초기화 함수 ===== */
// ctx: 초기화할 AES 컨텍스트 포인터
// key: 16바이트(128비트) 키 배열
aes_status_t aes_init_ctx_128(aes_ctx_t* ctx, const uint8_t key[16]) {  
    if (!ctx || !key) return AES_ERR_ARG;  // NULL 검사
    ctx->rounds = 10;  // 10라운드
    ctx->key_size = AES_KEY_128;  // 키 크기 식별자 설정: AES_KEY_128 (0)
    expand_key_generic(key, 4, 10, ctx->rk_enc);  // 키 확장: Nk=4, Nr=10로 키 확장 실행
    // expand_key_generic: key를 받아서 44개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK; 
}

/* ===== AES-192 초기화 함수 ===== */
aes_status_t aes_init_ctx_192(aes_ctx_t* ctx, const uint8_t key[24]) { 
    if (!ctx || !key) return AES_ERR_ARG;  
    ctx->rounds = 12;  // 12라운드
    ctx->key_size = AES_KEY_192;  // 키 크기 식별자 설정: AES_KEY_192 (1)
    expand_key_generic(key, 6, 12, ctx->rk_enc);  // 키 확장: Nk=6, Nr=12로 키 확장 실행
    // expand_key_generic: key를 받아서 52개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK; 
}

/* ===== AES-256 초기화 함수 ===== */
aes_status_t aes_init_ctx_256(aes_ctx_t* ctx, const uint8_t key[32]) {  
    if (!ctx || !key) return AES_ERR_ARG; 
    ctx->rounds = 14;  // 14라운드
    ctx->key_size = AES_KEY_256;  // 키 크기 식별자 설정: AES_KEY_256 (2)
    expand_key_generic(key, 8, 14, ctx->rk_enc);  // 키 확장: Nk=8, Nr=14로 키 확장 실행
    // expand_key_generic: key를 받아서 60개의 워드로 확장하여 ctx->rk_enc에 저장
    return AES_OK; 
}

/* ===== 키 길이 자동 감지 및 초기화 함수 ===== */
// key_len: 키 길이 (바이트 단위, 16/24/32만 허용)
aes_status_t aes_init_ctx_auto(aes_ctx_t* ctx, const uint8_t* key, size_t key_len) {  
    if (!ctx || !key) return AES_ERR_ARG; 
   
    if (key_len == 16) {  // 16바이트 키
        return aes_init_ctx_128(ctx, key);  // AES-128로 초기화하고 결과 반환
    } else if (key_len == 24) {  // 24바이트 키
        return aes_init_ctx_192(ctx, key);  // AES-192로 초기화하고 결과 반환
    } else if (key_len == 32) {  // 32바이트 키
        return aes_init_ctx_256(ctx, key);  // AES-256로 초기화하고 결과 반환
    } else {  // 지원하지 않는 키 길이인 경우
        return AES_ERR_KEYLEN;  // 키 길이 오류
    }
}

/* ===== 블록 암호화 함수 (AES-128/192/256 공용) ===== */
// AES 블록 암호화: 16바이트 평문을 16바이트 암호문으로 변환
aes_status_t aes_encrypt_block(const aes_ctx_t* ctx,
    const uint8_t pt[AES_BLOCK_BYTES],  
    uint8_t ct[AES_BLOCK_BYTES]) {       
    if (!ctx || !pt || !ct) return AES_ERR_ARG;  // NULL 포인터 검사

    uint8_t s[4][4];  
    bytes_to_state(pt, s);  

    // AddRoundKey(라운드 0)
    // 첫 번째 4워드(W[0], W[1], W[2], W[3])를 상태 행렬의 각 열에 XOR
    for (int i = 0; i < 4; i++) { 
        uint32_t w = ctx->rk_enc[i];  
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff);  
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff); 
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   
        s[3][i] ^= (uint8_t)(w & 0xff);          
    }

    // 라운드 1부터 (Nr-1)까지 수행: 표준 라운드 (SubBytes, ShiftRows, MixColumns, AddRoundKey)
    for (int r = 1; r < (int)ctx->rounds; r++) { 
        // SubBytes: 각 바이트를 S-box로 치환 
        for (int i = 0; i < 4; i++) 
            for (int j = 0; j < 4; j++) 
                s[i][j] = SBOX[s[i][j]]; 

        // ShiftRows (인라인): 1행 좌1, 2행 좌2, 3행 좌3 회전
        {
            uint8_t t;  
            t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
            t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;    
            t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;    
            t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
        }

        // MixColumns (인라인 구현): 각 열에 선형 변환 적용 (GF(2^8)에서 행렬 곱셈)
        for (int c = 0; c < 4; c++) {  
            uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];  
            uint8_t r0 = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
            uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
            uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
            uint8_t r3 = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            s[0][c] = r0; s[1][c] = r1; s[2][c] = r2; s[3][c] = r3;  
        }
        
        // AddRoundKey: 이번 라운드의 라운드 키(4워드)를 상태 행렬의 각 열에 XOR
        for (int i = 0; i < 4; i++) {  
            uint32_t w = ctx->rk_enc[4 * r + i];  
            s[0][i] ^= (uint8_t)((w >> 24) & 0xff);
            s[1][i] ^= (uint8_t)((w >> 16) & 0xff);  
            s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   
            s[3][i] ^= (uint8_t)(w & 0xff);         
        }
    }

    // 마지막 라운드(Nr): MixColumns 없이 SubBytes, ShiftRows, AddRoundKey만 수행
    
    // SubBytes
    for (int i = 0; i < 4; i++)   
        for (int j = 0; j < 4; j++)   
            s[i][j] = SBOX[s[i][j]];  

    {
        // ShiftRows
        uint8_t t;  
        t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
        t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;    
        t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;       
        t = s[3][0]; s[3][0] = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = t;
    }

    // AddRoundKey(마지막 라운드)
    for (int i = 0; i < 4; i++) {  
        uint32_t w = ctx->rk_enc[4 * ctx->rounds + i]; // W[40,41,42,43]
        s[0][i] ^= (uint8_t)((w >> 24) & 0xff); 
        s[1][i] ^= (uint8_t)((w >> 16) & 0xff); 
        s[2][i] ^= (uint8_t)((w >> 8) & 0xff);   
        s[3][i] ^= (uint8_t)(w & 0xff);        
    }

    state_to_bytes(s, ct); 
    return AES_OK; 
}

/* ===== CTR 스트림 함수들 ===== */
// counter_len 바이트 만큼(뒤에서부터) big-endian으로 +1 (in-place 증가)
void ctr_increment(uint8_t counter_block[16], size_t counter_len) {  
    if (counter_len == 0 || counter_len > 16) return;  // 허용 범위 체크: 1~16 바이트만 허용
    // 맨 뒤부터 올리고, 넘치면(=0xFF -> 0x00) 자리올림을 왼쪽으로 전파
    for (int i = 15; i >= 16 - (int)counter_len; i--) {  
        counter_block[i]++;  // +1
        if (counter_block[i] != 0) break;  // carry가 안 나면 종료
    }
}

// CTR 모드 스트림 처리 함수: CTR 모드로 데이터를 암호화/복호화
// 주의: src==dst이면 in-place 처리 가능 (같은 버퍼에서 암복호화 가능)
aes_status_t aes_ctr_xor_stream(const aes_ctx_t* ctx,
    uint8_t counter_block[AES_BLOCK_BYTES],  
    size_t counter_len,                       
    const uint8_t* src,                       
    size_t len,                              
    uint8_t* dst) {                         
    if (!ctx || !counter_block || !src || !dst) return AES_ERR_ARG; 
    if (counter_len == 0 || counter_len > 16) return AES_ERR_IVLEN;  
    if (len == 0) return AES_OK;  

    // 중첩 검사: 입력과 출력 버퍼가 부분적으로 겹치는지 확인 (dst==src는 허용)
    if (dst != src) {  // 완전히 동일한 포인터가 아닌 경우에만 중첩 검사
        const uint8_t* s0 = src;      
        const uint8_t* s1 = src + len; 
        uint8_t* d0 = dst;              
        uint8_t* d1 = dst + len;      
        // 두 구간이 겹치면 에러: 완전 동일 포인터가 아닌 부분 겹침은 금지
        if (!(d1 <= s0 || s1 <= d0)) return AES_ERR_OVERLAP; 
    }

    uint8_t ks[AES_BLOCK_BYTES];  // 키스트림(카운터 블록을 암호화한 16바이트)
    size_t done = 0;              // 처리된 총 바이트 수

    while (done < len) {  
        // 1) 현재 counter_block을 AES로 암호화 -> 키스트림 ks 생성
        aes_status_t st = aes_encrypt_block(ctx, counter_block, ks);  
        if (st != AES_OK) return st;  

        // 2) 남은 길이를 기준으로 이번에 처리할 길이 결정 (최대 16바이트)
        size_t blen = (len - done < AES_BLOCK_BYTES) ? (len - done) : AES_BLOCK_BYTES;

        // 3) src의 데이터와 키스트림을 XOR -> dst에 저장 
        for (size_t i = 0; i < blen; i++)  
            dst[done + i] = src[done + i] ^ ks[i]; 

        // 4) 처리된 바이트 수 누적 및 카운터 증가
        done += blen; 
        ctr_increment(counter_block, counter_len);  // 카운터를 big-endian 방식으로 1 증가 (in-place)
    }
    return AES_OK;  
}

