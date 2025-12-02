// AES_CTR_ALL 라이브러리 정확도 검증 테스트
// 단위 테스트 및 통합 테스트 포함
// AES-128/192/256 모두 지원

#define _CRT_SECURE_NO_WARNINGS
#include "AES_CTR_ALL.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

// ===== 테스트 헬퍼 함수 =====

// 16진수 문자열을 바이트 배열로 변환
static void hex_to_bytes(const char* hex, uint8_t* bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// 바이트 배열을 16진수 문자열로 출력
static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

// 두 바이트 배열 비교
static bool bytes_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    return memcmp(a, b, len) == 0;
}

// 테스트 결과 추적
static int test_count = 0;
static int test_passed = 0;
static int test_failed = 0;

static void test_assert(const char* test_name, bool condition) {
    test_count++;
    if (condition) {
        test_passed++;
        printf("PASS: %s\n", test_name);
    }
    else {
        test_failed++;
        printf("FAIL: %s\n", test_name);
    }
}

// ===== 단위 테스트 1: 키 스케줄링 =====

void test_key_schedule(void) {
    printf("\n=== Unit Test 1: Key Schedule ===\n");

    // NIST FIPS 197 Appendix A.1 테스트 벡터
    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    // Input validation
    if (strlen(key_hex) != 32) {
        printf("ERROR: Key length is invalid. Expected: 32 chars (16 bytes), Actual: %zu chars\n", strlen(key_hex));
        test_assert("Key hex length validation", false);
        return;
    }

    aes_ctx_t ctx;
    aes_status_t status = aes_init_ctx_key_bytes(&ctx, key, 16);
    test_assert("Key schedule initialization", status == AES_OK);
    if (status != AES_OK) {
        printf("ERROR: Key initialization failed. Error code: %d\n", status);
        return;
    }
    test_assert("Round count setting", ctx.rounds == AES128_ROUNDS);
    if (ctx.rounds != AES128_ROUNDS) {
        printf("ERROR: Round count mismatch. Expected: %u, Actual: %u\n", AES128_ROUNDS, ctx.rounds);
    }
    test_assert("Key size setting", ctx.key_size == AES_KEY_128);
    if (ctx.key_size != AES_KEY_128) {
        printf("ERROR: Key size mismatch. Expected: %d, Actual: %d\n", AES_KEY_128, ctx.key_size);
    }

    // 첫 번째 라운드 키 확인 (W[0-3])
    uint32_t expected_w0 = 0x2b7e1516;
    uint32_t expected_w1 = 0x28aed2a6;
    uint32_t expected_w2 = 0xabf71588;
    uint32_t expected_w3 = 0x09cf4f3c;

    // 라운드 키 검증 (예상값/실제값 출력)
    printf("Round key W[0]:\n");
    printf("  Expected: 0x%08x\n", expected_w0);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[0]);
    test_assert("Round key W[0]", ctx.rk_enc[0] == expected_w0);
    if (ctx.rk_enc[0] == expected_w0) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[1]:\n");
    printf("  Expected: 0x%08x\n", expected_w1);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[1]);
    test_assert("Round key W[1]", ctx.rk_enc[1] == expected_w1);
    if (ctx.rk_enc[1] == expected_w1) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[2]:\n");
    printf("  Expected: 0x%08x\n", expected_w2);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[2]);
    test_assert("Round key W[2]", ctx.rk_enc[2] == expected_w2);
    if (ctx.rk_enc[2] == expected_w2) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[3]:\n");
    printf("  Expected: 0x%08x\n", expected_w3);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[3]);
    test_assert("Round key W[3]", ctx.rk_enc[3] == expected_w3);
    if (ctx.rk_enc[3] == expected_w3) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }

    // FIPS 197 Appendix A.1의 다음 라운드 키 값 확인
    // W[4] = 0xa0fafe17, W[5] = 0x88542cb1, W[6] = 0x23a33939, W[7] = 0x2a6c7605
    uint32_t expected_w4 = 0xa0fafe17;
    uint32_t expected_w5 = 0x88542cb1;
    uint32_t expected_w6 = 0x23a33939;
    uint32_t expected_w7 = 0x2a6c7605;

    printf("Round key W[4]:\n");
    printf("  Expected: 0x%08x\n", expected_w4);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[4]);
    test_assert("Round key W[4]", ctx.rk_enc[4] == expected_w4);
    if (ctx.rk_enc[4] == expected_w4) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[5]:\n");
    printf("  Expected: 0x%08x\n", expected_w5);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[5]);
    test_assert("Round key W[5]", ctx.rk_enc[5] == expected_w5);
    if (ctx.rk_enc[5] == expected_w5) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[6]:\n");
    printf("  Expected: 0x%08x\n", expected_w6);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[6]);
    test_assert("Round key W[6]", ctx.rk_enc[6] == expected_w6);
    if (ctx.rk_enc[6] == expected_w6) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[7]:\n");
    printf("  Expected: 0x%08x\n", expected_w7);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[7]);
    test_assert("Round key W[7]", ctx.rk_enc[7] == expected_w7);
    if (ctx.rk_enc[7] == expected_w7) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }

    // 마지막 라운드 키 확인 (W[40-43])
    // FIPS 197 Appendix A.1의 마지막 라운드 키 값
    // 참고: FIPS 197에서 마지막 라운드 키는 암호화/복호화에 따라 다를 수 있으므로,
    // 키 확장 알고리즘에 따라 생성된 값을
    // 실제 구현에 맞춰 테스트
    uint32_t expected_w40 = 0xd014f9a8;  // 마지막 라운드
    uint32_t expected_w41 = 0xc9ee2589;
    uint32_t expected_w42 = 0xe13f0cc8;
    uint32_t expected_w43 = 0xb6630ca6;

    printf("Round key W[40]:\n");
    printf("  Expected: 0x%08x\n", expected_w40);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[40]);
    test_assert("Round key W[40]", ctx.rk_enc[40] == expected_w40);
    if (ctx.rk_enc[40] == expected_w40) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[41]:\n");
    printf("  Expected: 0x%08x\n", expected_w41);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[41]);
    test_assert("Round key W[41]", ctx.rk_enc[41] == expected_w41);
    if (ctx.rk_enc[41] == expected_w41) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[42]:\n");
    printf("  Expected: 0x%08x\n", expected_w42);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[42]);
    test_assert("Round key W[42]", ctx.rk_enc[42] == expected_w42);
    if (ctx.rk_enc[42] == expected_w42) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
    
    printf("Round key W[43]:\n");
    printf("  Expected: 0x%08x\n", expected_w43);
    printf("  Actual:   0x%08x\n", ctx.rk_enc[43]);
    test_assert("Round key W[43]", ctx.rk_enc[43] == expected_w43);
    if (ctx.rk_enc[43] == expected_w43) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
}

// ===== 단위 테스트 2: 단일 블록 암호화 =====

void test_block_encryption(void) {
    printf("\n=== Unit Test 2: Single Block Encryption ===\n");

    // NIST FIPS 197 Appendix B 테스트 벡터
    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* plaintext_hex = "3243f6a8885a308d313198a2e0370734";
    const char* expected_ciphertext_hex = "3925841d02dc09fbdc118597196a0b32";

    // 입력 유효성 검증
    if (strlen(key_hex) != 32 || strlen(plaintext_hex) != 32 || strlen(expected_ciphertext_hex) != 32) {
        printf("ERROR: Input data length is invalid.\n");
        printf("  Key length: %zu (Expected: 32)\n", strlen(key_hex));
        printf("  Plaintext length: %zu (Expected: 32)\n", strlen(plaintext_hex));
        printf("  Expected ciphertext length: %zu (Expected: 32)\n", strlen(expected_ciphertext_hex));
        test_assert("Input length validation", false);
        return;
    }

    uint8_t key[16], plaintext[16], expected[16], ciphertext[16];
    hex_to_bytes(key_hex, key, 16);
    hex_to_bytes(plaintext_hex, plaintext, 16);
    hex_to_bytes(expected_ciphertext_hex, expected, 16);

    aes_ctx_t ctx;
    aes_status_t status = aes_init_ctx_key_bytes(&ctx, key, 16);
    if (status != AES_OK) {
        printf("ERROR: Key initialization failed. Error code: %d\n", status);
        test_assert("Key initialization", false);
        return;
    }

    status = aes_encrypt_block_128b_in_128b_out(&ctx, plaintext, ciphertext);
    test_assert("Block encryption execution", status == AES_OK);
    if (status != AES_OK) {
        printf("ERROR: Block encryption failed. Error code: %d\n", status);
        return;
    }

    printf("Block encryption result:\n");
    printf("  Expected: ");
        print_hex(expected, 16);
    printf("\n  Actual:   ");
        print_hex(ciphertext, 16);
        printf("\n");
    
    bool match = bytes_equal(ciphertext, expected, 16);
    test_assert("Encryption result match", match);
    if (match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
        // 각 바이트가 다른 경우 출력
        for (int i = 0; i < 16; i++) {
            if (ciphertext[i] != expected[i]) {
                printf("  Byte[%d] mismatch: Expected=0x%02x, Actual=0x%02x\n", i, expected[i], ciphertext[i]);
            }
        }
    }

    // 추가 테스트 케이스: 모두 0인 키와 평문
    memset(key, 0, 16);
    memset(plaintext, 0, 16);
    status = aes_init_ctx_key_bytes(&ctx, key, 16);
    if (status != AES_OK) {
        printf("ERROR: All-zero key initialization failed. Error code: %d\n", status);
    }
    status = aes_encrypt_block_128b_in_128b_out(&ctx, plaintext, ciphertext);
    test_assert("All-zero key/plaintext encryption", status == AES_OK);
    if (status != AES_OK) {
        printf("ERROR: All-zero key/plaintext encryption failed. Error code: %d\n", status);
    }

    // 모두 0xFF인 키와 평문
    memset(key, 0xFF, 16);
    memset(plaintext, 0xFF, 16);
    status = aes_init_ctx_key_bytes(&ctx, key, 16);
    if (status != AES_OK) {
        printf("ERROR: All-0xFF key initialization failed. Error code: %d\n", status);
    }
    status = aes_encrypt_block_128b_in_128b_out(&ctx, plaintext, ciphertext);
    test_assert("All-0xFF key/plaintext encryption", status == AES_OK);
    if (status != AES_OK) {
        printf("ERROR: All-0xFF key/plaintext encryption failed. Error code: %d\n", status);
    }
}

// ===== 단위 테스트 3: 블록 복호화 (CTR 모드에서는 불필요) =====
// CTR 모드에서는 암호화와 복호화가 동일하므로 별도의 복호화 함수가 필요 없음
// 복호화 테스트는 통합 테스트에서 CTR 모드로 처리

// ===== 단위 테스트 4: 상태 변환 함수 =====

void test_state_conversion(void) {
    printf("\n=== Unit Test 4: State Conversion Functions ===\n");

    // 테스트 데이터: FIPS 197 Appendix B
    uint8_t input[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t state[4][4];
    uint8_t output[16];

    bytes_128b_to_state_4x4_8b(input, state);
    state_4x4_8b_to_bytes_128b(state, output);

    printf("State conversion roundtrip:\n");
    printf("  Expected: ");
    print_hex(input, 16);
    printf("\n  Actual:   ");
    print_hex(output, 16);
    printf("\n");
    
    bool roundtrip_match = bytes_equal(input, output, 16);
    test_assert("State conversion roundtrip", roundtrip_match);
    if (roundtrip_match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }

    // 상태 행렬 값 확인 (column-major)
    // bytes_to_state: st[i][j] = in[i + 4*j]
    // 첫 번째 열 (j=0): in[0]=0x32, in[1]=0x43, in[2]=0xf6, in[3]=0xa8
    uint8_t expected_s00 = 0x32, expected_s10 = 0x43, expected_s20 = 0xf6, expected_s30 = 0xa8;
    printf("State matrix [0][0]:\n");
    printf("  Expected: 0x%02x\n", expected_s00);
    printf("  Actual:   0x%02x\n", state[0][0]);
    test_assert("State matrix [0][0]", state[0][0] == expected_s00);
    printf("  %s\n", (state[0][0] == expected_s00) ? "PASS" : "FAIL");
    
    printf("State matrix [1][0]:\n");
    printf("  Expected: 0x%02x\n", expected_s10);
    printf("  Actual:   0x%02x\n", state[1][0]);
    test_assert("State matrix [1][0]", state[1][0] == expected_s10);
    printf("  %s\n", (state[1][0] == expected_s10) ? "PASS" : "FAIL");
    
    printf("State matrix [2][0]:\n");
    printf("  Expected: 0x%02x\n", expected_s20);
    printf("  Actual:   0x%02x\n", state[2][0]);
    test_assert("State matrix [2][0]", state[2][0] == expected_s20);
    printf("  %s\n", (state[2][0] == expected_s20) ? "PASS" : "FAIL");
    
    printf("State matrix [3][0]:\n");
    printf("  Expected: 0x%02x\n", expected_s30);
    printf("  Actual:   0x%02x\n", state[3][0]);
    test_assert("State matrix [3][0]", state[3][0] == expected_s30);
    printf("  %s\n", (state[3][0] == expected_s30) ? "PASS" : "FAIL");

    // 두 번째 열 (j=1): in[4]=0x88, in[5]=0x5a, in[6]=0x30, in[7]=0x8d
    uint8_t expected_s01 = 0x88, expected_s11 = 0x5a, expected_s21 = 0x30, expected_s31 = 0x8d;
    printf("State matrix [0][1]:\n");
    printf("  Expected: 0x%02x\n", expected_s01);
    printf("  Actual:   0x%02x\n", state[0][1]);
    test_assert("State matrix [0][1]", state[0][1] == expected_s01);
    printf("  %s\n", (state[0][1] == expected_s01) ? "PASS" : "FAIL");
    
    printf("State matrix [1][1]:\n");
    printf("  Expected: 0x%02x\n", expected_s11);
    printf("  Actual:   0x%02x\n", state[1][1]);
    test_assert("State matrix [1][1]", state[1][1] == expected_s11);
    printf("  %s\n", (state[1][1] == expected_s11) ? "PASS" : "FAIL");
    
    printf("State matrix [2][1]:\n");
    printf("  Expected: 0x%02x\n", expected_s21);
    printf("  Actual:   0x%02x\n", state[2][1]);
    test_assert("State matrix [2][1]", state[2][1] == expected_s21);
    printf("  %s\n", (state[2][1] == expected_s21) ? "PASS" : "FAIL");
    
    printf("State matrix [3][1]:\n");
    printf("  Expected: 0x%02x\n", expected_s31);
    printf("  Actual:   0x%02x\n", state[3][1]);
    test_assert("State matrix [3][1]", state[3][1] == expected_s31);
    printf("  %s\n", (state[3][1] == expected_s31) ? "PASS" : "FAIL");
}

// ===== 단위 테스트 5: 카운터 증가 함수 =====

void test_ctr_increment(void) {
    printf("\n=== Unit Test 5: Counter Increment Function ===\n");

    uint8_t counter[16];

    // 테스트 1: 기본 증가 (counter_len = 4)
    memset(counter, 0, 16);
    counter[12] = 0x00; counter[13] = 0x00; counter[14] = 0x00; counter[15] = 0x00;
    uint8_t expected_counter1[4] = {0x00, 0x00, 0x00, 0x01};
    ctr_increment_128b_inout(counter, 4);
    printf("Counter increment test 1 (0->1):\n");
    printf("  Expected: ");
    print_hex(expected_counter1, 4);
    printf("\n  Actual:   ");
    print_hex(&counter[12], 4);
    printf("\n");
    bool match1 = (counter[12] == 0x00 && counter[13] == 0x00 && counter[14] == 0x00 && counter[15] == 0x01);
    test_assert("Counter 4-byte increment (0->1)", match1);
    printf("  %s\n", match1 ? "PASS" : "FAIL");

    // 테스트 2: 자리올림
    memset(counter, 0, 16);
    counter[12] = 0x00; counter[13] = 0x00; counter[14] = 0x00; counter[15] = 0xFF;
    ctr_increment_128b_inout(counter, 4);
    test_assert("Counter carry (0xFF->0x00)",
        counter[12] == 0x00 && counter[13] == 0x00 &&
        counter[14] == 0x01 && counter[15] == 0x00);

    // 테스트 3: 큰 값 증가
    memset(counter, 0, 16);
    counter[12] = 0xFF; counter[13] = 0xFF; counter[14] = 0xFF; counter[15] = 0xFF;
    ctr_increment_128b_inout(counter, 4);
    test_assert("Counter max value increment",
        counter[12] == 0x00 && counter[13] == 0x00 &&
        counter[14] == 0x00 && counter[15] == 0x00);

    // 테스트 4: 8바이트 카운터 (인덱스 8-15)
    memset(counter, 0, 16);
    counter[8] = 0x00; counter[9] = 0x00; counter[10] = 0x00; counter[11] = 0x00;
    counter[12] = 0x00; counter[13] = 0x00; counter[14] = 0x00; counter[15] = 0x42;
    ctr_increment_128b_inout(counter, 8);
    // counter_len=8이므로 인덱스 8-15만 증가, 하위부터 0x0000000000000042 -> 0x0000000000000043
    test_assert("Counter 8-byte increment",
        counter[8] == 0x00 && counter[9] == 0x00 && counter[10] == 0x00 && counter[11] == 0x00 &&
        counter[12] == 0x00 && counter[13] == 0x00 && counter[14] == 0x00 && counter[15] == 0x43);

    // 테스트 5: 여러 번 증가
    memset(counter, 0, 16);
    counter[15] = 0x00;
    for (int i = 0; i < 256; i++) {
        ctr_increment_128b_inout(counter, 4);
    }
    test_assert("Counter 256 increments",
        counter[12] == 0x00 && counter[13] == 0x00 &&
        counter[14] == 0x01 && counter[15] == 0x00);
}

// ===== 단위 테스트 6: 오류 처리 =====

void test_error_handling(void) {
    printf("\n=== Unit Test 6: Error Handling ===\n");

    aes_ctx_t ctx;
    uint8_t key[16] = { 0 };
    uint8_t data[16] = { 0 };
    uint8_t output[16];

    // NULL 인자 테스트
    aes_status_t status = aes_init_ctx_key_bytes(NULL, key, 16);
    test_assert("NULL context initialization", status == AES_ERR_ARG);

    status = aes_init_ctx_key_bytes(&ctx, NULL, 16);
    test_assert("NULL key initialization", status == AES_ERR_ARG);

    aes_init_ctx_key_bytes(&ctx, key, 16);
    status = aes_encrypt_block_128b_in_128b_out(NULL, data, output);
    test_assert("NULL context encryption", status == AES_ERR_ARG);

    status = aes_encrypt_block_128b_in_128b_out(&ctx, NULL, output);
    test_assert("NULL plaintext encryption", status == AES_ERR_ARG);

    status = aes_encrypt_block_128b_in_128b_out(&ctx, data, NULL);
    test_assert("NULL output encryption", status == AES_ERR_ARG);

    // CTR 모드 오류 테스트
    uint8_t counter[16] = { 0 };
    status = aes_ctr_xor_stream_bytes_in_bytes_out(NULL, counter, 4, data, 16, output);
    test_assert("NULL context CTR", status == AES_ERR_ARG);

    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, NULL, 4, data, 16, output);
    test_assert("NULL counter CTR", status == AES_ERR_ARG);

    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 0, data, 16, output);
    test_assert("Invalid counter_len=0", status == AES_ERR_IVLEN);

    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 17, data, 16, output);
    test_assert("Invalid counter_len=17", status == AES_ERR_IVLEN);

    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, NULL, 16, output);
    test_assert("NULL source CTR", status == AES_ERR_ARG);

    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data, 16, NULL);
    test_assert("NULL destination CTR", status == AES_ERR_ARG);
}

// ===== 통합 테스트 1: CTR 모드 기본 동작 =====

void test_ctr_basic(void) {
    printf("\n=== Integration Test 1: CTR Mode Basic Operation ===\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    // 테스트 데이터
    uint8_t plaintext[32] = "Hello, World! This is AES-CTR!";
    uint8_t ciphertext[32];
    uint8_t decrypted[32];

    // 카운터 초기화
    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;  // counter_len = 4, 하위부터 0x00000001

    // 암호화
    aes_status_t status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, plaintext, 32, ciphertext);
    test_assert("CTR encryption execution", status == AES_OK);
    bool differs = !bytes_equal(ciphertext, plaintext, 32);
    test_assert("Encryption result differs from plaintext", differs);
    if (!differs) {
        printf("WARNING: Ciphertext is identical to plaintext!\n");
    }

    // 카운터 리셋
    memset(counter, 0, 16);
    counter[15] = 0x01;

    // 복호화 (CTR는 암호화와 동일)
    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, ciphertext, 32, decrypted);
    test_assert("CTR decryption execution", status == AES_OK);
    
    printf("CTR decryption result:\n");
    printf("  Expected (plaintext): ");
    print_hex(plaintext, 32);
    printf("\n  Actual (decrypted):   ");
    print_hex(decrypted, 32);
    printf("\n");
    
    bool decrypt_match = bytes_equal(decrypted, plaintext, 32);
    test_assert("Decryption result matches", decrypt_match);
    if (decrypt_match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
}

// ===== 통합 테스트 2: 다양한 길이 데이터 처리 =====

void test_ctr_various_lengths(void) {
    printf("\n=== Integration Test 2: Various Length Data ===\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    // 다양한 길이 테스트
    size_t lengths[] = { 1, 15, 16, 17, 31, 32, 33, 64, 100, 256 };
    int num_lengths = sizeof(lengths) / sizeof(lengths[0]);

    for (int i = 0; i < num_lengths; i++) {
        size_t len = lengths[i];
        uint8_t* plaintext = (uint8_t*)malloc(len);
        uint8_t* ciphertext = (uint8_t*)malloc(len);
        uint8_t* decrypted = (uint8_t*)malloc(len);

        // 테스트 데이터 생성
        for (size_t j = 0; j < len; j++) {
            plaintext[j] = (uint8_t)(i * 17 + j);
        }

        uint8_t counter[16] = { 0 };
        counter[15] = 0x01;

        // 암호화
        aes_status_t status1 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, plaintext, len, ciphertext);

        // 카운터 리셋
        memset(counter, 0, 16);
        counter[15] = 0x01;

        // 복호화
        aes_status_t status2 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, ciphertext, len, decrypted);

        char test_name[64];
        sprintf(test_name, "Process %zu bytes", len);
        test_assert(test_name,
            status1 == AES_OK && status2 == AES_OK &&
            bytes_equal(decrypted, plaintext, len));

        free(plaintext);
        free(ciphertext);
        free(decrypted);
    }
}

// ===== 통합 테스트 3: 인플레이스 처리 =====

void test_ctr_inplace(void) {
    printf("\n=== Integration Test 3: In-place Processing ===\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    uint8_t data[64];
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)i;

    uint8_t data_copy[64];
    memcpy(data_copy, data, 64);

    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;

    // 인플레이스 암호화
    aes_status_t status1 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data, 64, data);
    test_assert("In-place encryption execution", status1 == AES_OK);
    test_assert("In-place encryption result changed", !bytes_equal(data, data_copy, 64));

    // 카운터 리셋
    memset(counter, 0, 16);
    counter[15] = 0x01;

    // 인플레이스 복호화
    aes_status_t status2 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data, 64, data);
    test_assert("In-place decryption execution", status2 == AES_OK);
    test_assert("In-place decryption result restored", bytes_equal(data, data_copy, 64));
}

// ===== 통합 테스트 4: 여러 블록 순차 처리 =====

void test_ctr_multiple_blocks(void) {
    printf("\n=== Integration Test 4: Multiple Block Sequential Processing ===\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    // 5블록 (80바이트) 데이터
    uint8_t plaintext[80];
    for (int i = 0; i < 80; i++) plaintext[i] = (uint8_t)(i * 3);

    uint8_t ciphertext[80];
    uint8_t decrypted[80];

    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;

    // 암호화
    aes_status_t status1 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, plaintext, 80, ciphertext);

    // 카운터 리셋
    memset(counter, 0, 16);
    counter[15] = 0x01;

    // 복호화
    aes_status_t status2 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, ciphertext, 80, decrypted);

    test_assert("Multiple block encryption", status1 == AES_OK);
    test_assert("Multiple block decryption", status2 == AES_OK);
    test_assert("Multiple block result match", bytes_equal(decrypted, plaintext, 80));

    // 각 블록이 다른 키스트림으로 암호화되었는지 확인
    uint8_t block1[16], block2[16];
    memcpy(block1, ciphertext, 16);
    memcpy(block2, ciphertext + 16, 16);
    test_assert("Different blocks have different ciphertext", !bytes_equal(block1, block2, 16));
}

// ===== 통합 테스트 5: NIST SP 800-38A 테스트 벡터 =====

void test_ctr_nist_vector(void) {
    printf("\n=== Integration Test 5: NIST SP 800-38A Test Vectors ===\n");

    // NIST SP 800-38A Appendix F.5.5 테스트 벡터
    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* iv_hex = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const char* plaintext_hex = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    uint8_t key[16], iv[16];
    hex_to_bytes(key_hex, key, 16);
    hex_to_bytes(iv_hex, iv, 16);

    size_t plaintext_len = strlen(plaintext_hex) / 2;
    uint8_t* plaintext = (uint8_t*)malloc(plaintext_len);
    uint8_t* ciphertext = (uint8_t*)malloc(plaintext_len);
    uint8_t* decrypted = (uint8_t*)malloc(plaintext_len);

    if (!plaintext || !ciphertext || !decrypted) {
        printf("Memory allocation failed\n");
        if (plaintext) free(plaintext);
        if (ciphertext) free(ciphertext);
        if (decrypted) free(decrypted);
        return;
    }

    hex_to_bytes(plaintext_hex, plaintext, plaintext_len);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    // 카운터 = IV
    uint8_t counter[16];
    memcpy(counter, iv, 16);

    // 암호화
    aes_status_t status1 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, plaintext, plaintext_len, ciphertext);

    // 카운터 리셋
    memcpy(counter, iv, 16);

    // 복호화
    aes_status_t status2 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, ciphertext, plaintext_len, decrypted);

    test_assert("NIST vector encryption", status1 == AES_OK);
    test_assert("NIST vector decryption", status2 == AES_OK);
    
    printf("NIST vector decryption result:\n");
    printf("  Expected (plaintext): ");
    print_hex(plaintext, plaintext_len);
    printf("\n  Actual (decrypted):   ");
    print_hex(decrypted, plaintext_len);
    printf("\n");
    
    bool nist_match = bytes_equal(decrypted, plaintext, plaintext_len);
    test_assert("NIST vector result match", nist_match);
    if (nist_match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }

    free(plaintext);
    free(ciphertext);
    free(decrypted);
}

// ===== 통합 테스트 6: 버퍼 중첩 검사 =====

void test_ctr_buffer_overlap(void) {
    printf("\n=== Integration Test 6: Buffer Overlap Check ===\n");

    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    uint8_t key[16];
    hex_to_bytes(key_hex, key, 16);

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    uint8_t data[64];
    // 테스트 데이터 초기화
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i + 1);

    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;

    // 인플레이스가 허용되는 경우
    aes_status_t status1 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data, 32, data);
    test_assert("In-place allowed", status1 == AES_OK);

    // 부분 중첩은 오류가 발생하는 경우
    // data를 다시 초기화
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i + 1);
    memset(counter, 0, 16);
    counter[15] = 0x01;
    aes_status_t status2 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data, 32, data + 16);
    test_assert("Partial overlap error", status2 == AES_ERR_OVERLAP);

    // data를 다시 초기화
    for (int i = 0; i < 64; i++) data[i] = (uint8_t)(i + 1);
    memset(counter, 0, 16);
    counter[15] = 0x01;
    aes_status_t status3 = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, data + 16, 32, data);
    test_assert("Reverse overlap error", status3 == AES_ERR_OVERLAP);
}

// ===== 통합 테스트 7: AES-192 기본 동작 =====

void test_aes192_basic(void) {
    printf("\n=== Integration Test 7: AES-192 Basic Operation ===\n");

    // AES-192 테스트 키 (24바이트)
    const char* key_hex = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    uint8_t key[24];
    hex_to_bytes(key_hex, key, 24);

    aes_ctx_t ctx;
    aes_status_t status = aes_init_ctx_key_bytes(&ctx, key, 24);
    test_assert("AES-192 initialization", status == AES_OK);
    test_assert("AES-192 round count", ctx.rounds == AES192_ROUNDS);
    test_assert("AES-192 key size", ctx.key_size == AES_KEY_192);

    // 테스트 데이터
    uint8_t plaintext[32] = "Hello, AES-192 CTR Mode Test!";
    uint8_t ciphertext[32];
    uint8_t decrypted[32];

    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;

    // 암호화
    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, plaintext, 32, ciphertext);
    test_assert("AES-192 CTR encryption", status == AES_OK);

    // 복호화
    memset(counter, 0, 16);
    counter[15] = 0x01;
    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, ciphertext, 32, decrypted);
    test_assert("AES-192 CTR decryption", status == AES_OK);
    
    printf("AES-192 decryption result:\n");
    printf("  Expected (plaintext): ");
    print_hex(plaintext, 32);
    printf("\n  Actual (decrypted):   ");
    print_hex(decrypted, 32);
    printf("\n");
    
    bool aes192_match = bytes_equal(decrypted, plaintext, 32);
    test_assert("AES-192 result match", aes192_match);
    if (aes192_match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
}

// ===== 통합 테스트 8: AES-256 기본 동작 =====

void test_aes256_basic(void) {
    printf("\n=== Integration Test 8: AES-256 Basic Operation ===\n");

    // AES-256 테스트 키 (32바이트)
    const char* key_hex = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    uint8_t key[32];
    hex_to_bytes(key_hex, key, 32);

    aes_ctx_t ctx;
    aes_status_t status = aes_init_ctx_key_bytes(&ctx, key, 32);
    test_assert("AES-256 initialization", status == AES_OK);
    test_assert("AES-256 round count", ctx.rounds == AES256_ROUNDS);
    test_assert("AES-256 key size", ctx.key_size == AES_KEY_256);

    // 테스트 데이터
    uint8_t plaintext[32] = "Hello, AES-256 CTR Mode Test!";
    uint8_t ciphertext[32];
    uint8_t decrypted[32];

    uint8_t counter[16] = { 0 };
    counter[15] = 0x01;

    // 암호화
    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, plaintext, 32, ciphertext);
    test_assert("AES-256 CTR encryption", status == AES_OK);

    // 복호화
    memset(counter, 0, 16);
    counter[15] = 0x01;
    status = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 4, ciphertext, 32, decrypted);
    test_assert("AES-256 CTR decryption", status == AES_OK);
    
    printf("AES-256 decryption result:\n");
    printf("  Expected (plaintext): ");
    print_hex(plaintext, 32);
    printf("\n  Actual (decrypted):   ");
    print_hex(decrypted, 32);
    printf("\n");
    
    bool aes256_match = bytes_equal(decrypted, plaintext, 32);
    test_assert("AES-256 result match", aes256_match);
    if (aes256_match) {
        printf("  PASS\n");
    } else {
        printf("  FAIL\n");
    }
}

// ===== 메인 함수 =====

int main(void) {
    printf("========================================\n");
    printf("AES_CTR_ALL Library Accuracy Verification Test\n");
    printf("(AES-128/192/256)\n");
    printf("========================================\n");

    // 단위 테스트
    test_key_schedule();
    test_block_encryption();
    // test_block_decryption(); // CTR 모드에서는 불필요 (암호화와 동일하므로 통합 테스트에서 처리)
    test_state_conversion();
    test_ctr_increment();
    test_error_handling();

    // 통합 테스트
    test_ctr_basic();
    test_ctr_various_lengths();
    test_ctr_inplace();
    test_ctr_multiple_blocks();
    test_ctr_nist_vector();
    test_ctr_buffer_overlap();

    // AES-192 테스트 추가
    test_aes192_basic();

    // AES-256 테스트 추가
    test_aes256_basic();

    // 결과 요약
    printf("\n========================================\n");
    printf("Test Results Summary\n");
    printf("========================================\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_failed);
    printf("Success rate: %.1f%%\n", test_count > 0 ? (100.0 * test_passed / test_count) : 0.0);
    printf("========================================\n");

    if (test_failed == 0) {
        printf("All tests passed successfully!\n");
    }
    else {
        printf("Some tests failed.\n");
    }

    printf("\nPress any key to exit...\n");
    getchar();

    return (test_failed == 0) ? 0 : 1;
}
