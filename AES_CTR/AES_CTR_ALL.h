#ifndef AES_CTR_ALL_H  // 파일 중복 방지
#define AES_CTR_ALL_H 

#include <stddef.h>   // size_t와 같은 표준 타입
#include <stdint.h>   // 고정폭 정수
#include <stdbool.h>  // bool 타입

#ifdef __cplusplus  // C++ 컴파일러에서 컴파일 중인지 확인
extern "C" {        // C++에서 C 함수를 호출할 때 이름이 망가지지 않게 c 링크 지정
    // C++ 프로젝트에서 사용할 것을 대비해 미리 호환되도록 생성
#endif              

    /* ===== 공통 상수 ===== */
#define AES_BLOCK_BYTES   16u  // AES 블록 크기: (16바이트)

    /* 상태코드 */
#define AES_OK            0   // 성공
#define AES_ERR_ARG       1   // 인자 오류: NULL, length=0
#define AES_ERR_KEYLEN    2   // 키 길이 오류: 16, 24, 32 바이트만 허용
#define AES_ERR_IVLEN     3   // IV/카운터 길이 오류: counter_len  범위(1~16) 아님
#define AES_ERR_OVERLAP   4   // 버퍼 중첩 오류: 입력과 출력 버퍼가 부분적으로 겹침 (in-place 제외)
#define AES_ERR_STATE     5   // 컨텍스트 상태 오류: 컨텍스트가 올바르게 초기화되지 않음

    typedef int aes_status_t;  // 상태 코드를 담는 정수 타입: 에러 코드들 반환

    /* ===== 키 크기 상수 ===== */
#define AES_KEY_128        0   // AES-128: 16바이트(128비트) 키
#define AES_KEY_192        1   // AES-192: 24바이트(192비트) 키
#define AES_KEY_256        2   // AES-256: 32바이트(256비트) 키

    /* ===== 라운드 수: 각 AES 버전별 암호화 라운드 수 ===== */
#define AES128_ROUNDS      10u  // AES-128의 라운드 수: 10라운드
#define AES192_ROUNDS      12u  // AES-192의 라운드 수: 12라운드
#define AES256_ROUNDS      14u  // AES-256의 라운드 수: 14라운드

    /* ===== 라운드키 워드 수: 버전별 필요한 라운드키 워드(32비트) 개수 ===== */
#define AES128_RK_WORDS    44u  // AES-128: 4워드 * (10라운드 + 1) = 44워드 (라운드마다 4워드 + 초기 키 포함)
#define AES192_RK_WORDS    52u  // AES-192: 4워드 * (12라운드 + 1) = 52워드
#define AES256_RK_WORDS    60u  // AES-256: 4워드 * (14라운드 + 1) = 60워드
#define AES_MAX_RK_WORDS   60u  // 최대 워드 수: AES-256이 가장 많이 필요하므로 60워드
                                // 모든 버전의 컨텍스트에서 이 크기만큼 배열을 할당

    /* ===== AES 컨텍스트: AES 암호화에 필요한 모든 정보를 담는 구조체 ===== */
    typedef struct {
        uint32_t rk_enc[AES_MAX_RK_WORDS];  // 암호화용 라운드 키 배열: 확장된 키를 저장
        // 각 워드는 32비트이며, AES-256 기준 최대 60워드
        uint32_t rounds;                    // 라운드 수: 10(AES-128), 12(AES-192), 14(AES-256)
        int      key_size;                  // 키 크기 식별자: AES_KEY_128, AES_KEY_192, AES_KEY_256
    } aes_ctx_t;

    /* ===== 1) 초기화: 키 길이에 따라 자동으로 적절한 AES 버전 선택 ===== */
    // key: 입력 키 배열 (바이트 단위, 16/24/32 바이트만 허용)
    // key_len: 키 길이 (바이트 단위, 16=AES-128, 24=AES-192, 32=AES-256)
    // ctx: 초기화할 AES 컨텍스트 포인터
    // 반환값: AES_OK (성공), AES_ERR_ARG (인자 오류), AES_ERR_KEYLEN (지원하지 않는 키 길이)
    aes_status_t aes_init_ctx_key_bytes(aes_ctx_t* ctx, const uint8_t* key, size_t key_len);


    /* ===== 2) 코어 블록 암호화 함수 ===== */
    // 컨텍스트의 rounds 값에 따라 자동으로 적절한 라운드 수 사용
    aes_status_t aes_encrypt_block_128b_in_128b_out(const aes_ctx_t* ctx,
        const uint8_t pt[AES_BLOCK_BYTES],  // 입력: 128비트 평문 (16바이트)
        uint8_t ct[AES_BLOCK_BYTES]);       // 출력: 128비트 암호문 (16바이트)

    /* ===== 3) CTR 모드 스트림 ===== */
    // CTR 모드는 카운터 블록을 암호화해서 키스트림을 만들고, 평문과 XOR 하는 방식

    // 카운터 증가 함수: CTR 모드에서 사용하는 카운터 블록을 증가시킴
    // 맨 뒤에서부터 counter_len 바이트만큼 big-endian 방식으로 1 증가
    void ctr_increment_128b_inout(uint8_t counter_block[16], size_t counter_len);

    // CTR 모드 스트림 처리: counter_block을 암호화해 나온 키 스트림을 src와 XOR해 dst에 저장
    // 주의: src==dst(제자리 처리) 허용
    aes_status_t aes_ctr_xor_stream_bytes_in_bytes_out(const aes_ctx_t* ctx,
        uint8_t counter_block[AES_BLOCK_BYTES],  // 입력/출력: 128비트 카운터 블록 (16바이트)
        size_t counter_len,                      // 입력: 카운터 길이 (바이트 단위, 1~16)
        const uint8_t* src,                     // 입력: 평문/암호문 데이터 (바이트 단위)
        size_t len,                             // 입력: 데이터 길이 (바이트 단위)
        uint8_t* dst);                          // 출력: 암호문/평문 데이터 (바이트 단위)
    // 반환값: AES_OK (성공), AES_ERR_ARG (인자 오류), AES_ERR_IVLEN (카운터 길이 오류), AES_ERR_OVERLAP (버퍼 중첩)


    /* ===== 4) 상태 변환 ===== */
    // AES는 column-major(열 우선) 방식으로 데이터 저장

    // bytes_to_state: 128비트(16바이트) 배열을 4x4 상태 행렬로 변환
    // 변환 방식: state[i][j] = in[i + 4*j] (i는 행, j는 열)
    void bytes_128b_to_state_4x4_8b(const uint8_t in[16], uint8_t state[4][4]);

    // state_to_bytes: 4x4 상태 행렬을 128비트(16바이트) 배열로 변환
    void state_4x4_8b_to_bytes_128b(const uint8_t state[4][4], uint8_t out[16]);

#ifdef __cplusplus  // C++dptj
}                   // extern "C" 블록 끝
#endif              

#endif /* AES_CTR_ALL_H */
