// AES_CTR_test.c — AES-128/192/256 및 CTR 모드 테스트 코드
#include "AES_CTR_ALL.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 테스트 벡터 출력 헬퍼
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 입력 유효성 검증 헬퍼
static int validate_test_input(const char* test_name, const void* ptr, size_t len, const char* param_name) {
    if (!ptr && len > 0) {
        printf("[ERROR] %s: %s is NULL but length is %zu\n", test_name, param_name, len);
        return 0;
    }
    if (len == 0) {
        printf("[ERROR] %s: %s length is 0\n", test_name, param_name);
        return 0;
    }
    return 1;
}

// 키 스케줄링 테스트
static int test_key_schedule(void) {
    printf("\n=== Key Schedule Test ===\n");
    
    // AES-128 테스트 키
    uint8_t key128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    if (!validate_test_input("test_key_schedule", key128, 16, "key")) {
        return 1;
    }
    
    aes_ctx_t ctx;
    aes_status_t st = aes_init_ctx_key_bytes(&ctx, key128, 16);
    if (st != AES_OK) {
        printf("[ERROR] Key schedule failed: %d\n", st);
        return 1;
    }
    
    if (ctx.rounds != AES128_ROUNDS) {
        printf("[ERROR] Expected %u rounds, got %u\n", AES128_ROUNDS, ctx.rounds);
        return 1;
    }
    
    if (ctx.key_size != AES_KEY_128) {
        printf("[ERROR] Expected AES_KEY_128, got %d\n", ctx.key_size);
        return 1;
    }
    
    printf("[OK] AES-128 key schedule test passed\n");
    
    // AES-192 테스트
    uint8_t key192[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    
    st = aes_init_ctx_key_bytes(&ctx, key192, 24);
    if (st != AES_OK) {
        printf("[ERROR] AES-192 key schedule failed: %d\n", st);
        return 1;
    }
    
    if (ctx.rounds != AES192_ROUNDS) {
        printf("[ERROR] Expected %u rounds, got %u\n", AES192_ROUNDS, ctx.rounds);
        return 1;
    }
    
    printf("[OK] AES-192 key schedule test passed\n");
    
    // AES-256 테스트
    uint8_t key256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    
    st = aes_init_ctx_key_bytes(&ctx, key256, 32);
    if (st != AES_OK) {
        printf("[ERROR] AES-256 key schedule failed: %d\n", st);
        return 1;
    }
    
    if (ctx.rounds != AES256_ROUNDS) {
        printf("[ERROR] Expected %u rounds, got %u\n", AES256_ROUNDS, ctx.rounds);
        return 1;
    }
    
    printf("[OK] AES-256 key schedule test passed\n");
    
    // 잘못된 키 길이 테스트
    uint8_t bad_key[15] = {0};
    st = aes_init_ctx_key_bytes(&ctx, bad_key, 15);
    if (st != AES_ERR_KEYLEN) {
        printf("[ERROR] Expected AES_ERR_KEYLEN for key length 15, got %d\n", st);
        return 1;
    }
    
    printf("[OK] Invalid key length test passed\n");
    
    return 0;
}

// 블록 암호화 테스트
static int test_block_encryption(void) {
    printf("\n=== Block Encryption Test ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    uint8_t pt[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    
    uint8_t expected_ct[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    if (!validate_test_input("test_block_encryption", key, 16, "key") ||
        !validate_test_input("test_block_encryption", pt, 16, "plaintext")) {
        return 1;
    }
    
    aes_ctx_t ctx;
    aes_status_t st = aes_init_ctx_key_bytes(&ctx, key, 16);
    if (st != AES_OK) {
        printf("[ERROR] Context initialization failed: %d\n", st);
        return 1;
    }
    
    uint8_t ct[16];
    st = aes_encrypt_block_128b_in_128b_out(&ctx, pt, ct);
    if (st != AES_OK) {
        printf("[ERROR] Encryption failed: %d\n", st);
        return 1;
    }
    
    if (memcmp(ct, expected_ct, 16) != 0) {
        printf("[ERROR] Ciphertext mismatch\n");
        print_hex("Expected", expected_ct, 16);
        print_hex("Got     ", ct, 16);
        return 1;
    }
    
    printf("[OK] Block encryption test passed\n");
    return 0;
}

// CTR 스트림 암호화/복호화 테스트
static int test_ctr_stream_encryption_decryption(void) {
    printf("\n=== CTR Stream Encryption/Decryption Test ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    const char* plaintext = "Hello, AES-CTR!";
    size_t pt_len = strlen(plaintext);
    
    if (!validate_test_input("test_ctr_stream", key, 16, "key") ||
        !validate_test_input("test_ctr_stream", plaintext, pt_len, "plaintext")) {
        return 1;
    }
    
    aes_ctx_t ctx;
    aes_status_t st = aes_init_ctx_key_bytes(&ctx, key, 16);
    if (st != AES_OK) {
        printf("[ERROR] Context initialization failed: %d\n", st);
        return 1;
    }
    
    uint8_t counter[16] = {0};
    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* pt_out = (uint8_t*)malloc(pt_len);
    
    if (!ct || !pt_out) {
        printf("[ERROR] Memory allocation failed\n");
        free(ct);
        free(pt_out);
        return 1;
    }
    
    // 암호화
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, (const uint8_t*)plaintext, pt_len, ct);
    if (st != AES_OK) {
        printf("[ERROR] Encryption failed: %d\n", st);
        free(ct);
        free(pt_out);
        return 1;
    }
    
    // 복호화 (카운터 리셋 필요)
    memset(counter, 0, 16);
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, ct, pt_len, pt_out);
    if (st != AES_OK) {
        printf("[ERROR] Decryption failed: %d\n", st);
        free(ct);
        free(pt_out);
        return 1;
    }
    
    if (memcmp(plaintext, pt_out, pt_len) != 0) {
        printf("[ERROR] Plaintext mismatch after decryption\n");
        free(ct);
        free(pt_out);
        return 1;
    }
    
    printf("[OK] CTR stream encryption/decryption test passed\n");
    free(ct);
    free(pt_out);
    return 0;
}

// CTR 증가 테스트
static int test_ctr_increment(void) {
    printf("\n=== CTR Increment Test ===\n");
    
    uint8_t counter[16] = {0};
    counter[15] = 0xFE;
    
    ctr_increment_128b_inout(counter, 1);
    if (counter[15] != 0xFF) {
        printf("[ERROR] Increment failed: expected 0xFF, got 0x%02x\n", counter[15]);
        return 1;
    }
    
    ctr_increment_128b_inout(counter, 1);
    if (counter[15] != 0x00 || counter[14] != 0x01) {
        printf("[ERROR] Increment overflow failed\n");
        return 1;
    }
    
    printf("[OK] CTR increment test passed\n");
    return 0;
}

// 자동 키 길이 선택 테스트
static int test_aes_init_ctx_auto_invalid_key_len(void) {
    printf("\n=== Invalid Key Length Test ===\n");
    
    aes_ctx_t ctx;
    uint8_t bad_key[15] = {0};
    
    aes_status_t st = aes_init_ctx_key_bytes(&ctx, bad_key, 15);
    if (st != AES_ERR_KEYLEN) {
        printf("[ERROR] Expected AES_ERR_KEYLEN, got %d\n", st);
        return 1;
    }
    
    printf("[OK] Invalid key length test passed\n");
    return 0;
}

// 버퍼 중첩 테스트
static int test_aes_ctr_xor_stream_overlap(void) {
    printf("\n=== Buffer Overlap Test ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);
    
    uint8_t data[32] = {0};
    uint8_t counter[16] = {0};
    
    // 부분 중첩 테스트 (실패해야 함)
    aes_status_t st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, data, 16, data + 8);
    if (st != AES_ERR_OVERLAP) {
        printf("[ERROR] Expected AES_ERR_OVERLAP, got %d\n", st);
        return 1;
    }
    
    // 인플레이스 테스트 (성공해야 함)
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, data, 16, data);
    if (st != AES_OK) {
        printf("[ERROR] In-place operation should succeed, got %d\n", st);
        return 1;
    }
    
    printf("[OK] Buffer overlap test passed\n");
    return 0;
}

// 잘못된 IV 길이 테스트
static int test_aes_ctr_xor_stream_invalid_iv_len(void) {
    printf("\n=== Invalid IV Length Test ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);
    
    uint8_t counter[16] = {0};
    uint8_t data[16] = {0};
    uint8_t out[16];
    
    // counter_len = 0 (실패해야 함)
    aes_status_t st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 0, data, 16, out);
    if (st != AES_ERR_IVLEN) {
        printf("[ERROR] Expected AES_ERR_IVLEN for counter_len=0, got %d\n", st);
        return 1;
    }
    
    // counter_len = 17 (실패해야 함)
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 17, data, 16, out);
    if (st != AES_ERR_IVLEN) {
        printf("[ERROR] Expected AES_ERR_IVLEN for counter_len=17, got %d\n", st);
        return 1;
    }
    
    printf("[OK] Invalid IV length test passed\n");
    return 0;
}

// NULL 인자 테스트
static int test_aes_ctr_xor_stream_null_args(void) {
    printf("\n=== NULL Arguments Test ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);
    
    uint8_t counter[16] = {0};
    uint8_t data[16] = {0};
    uint8_t out[16];
    
    // NULL ctx
    aes_status_t st = aes_ctr_xor_stream_bytes_in_bytes_out(NULL, counter, 16, data, 16, out);
    if (st != AES_ERR_ARG) {
        printf("[ERROR] Expected AES_ERR_ARG for NULL ctx, got %d\n", st);
        return 1;
    }
    
    // NULL counter
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, NULL, 16, data, 16, out);
    if (st != AES_ERR_ARG) {
        printf("[ERROR] Expected AES_ERR_ARG for NULL counter, got %d\n", st);
        return 1;
    }
    
    // NULL src
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, NULL, 16, out);
    if (st != AES_ERR_ARG) {
        printf("[ERROR] Expected AES_ERR_ARG for NULL src, got %d\n", st);
        return 1;
    }
    
    // NULL dst
    st = aes_ctr_xor_stream_bytes_in_bytes_out(&ctx, counter, 16, data, 16, NULL);
    if (st != AES_ERR_ARG) {
        printf("[ERROR] Expected AES_ERR_ARG for NULL dst, got %d\n", st);
        return 1;
    }
    
    printf("[OK] NULL arguments test passed\n");
    return 0;
}

int main(void) {
    printf("========================================\n");
    printf("    AES-128/192/256 & CTR Test Suite\n");
    printf("========================================\n");

    int failures = 0;
    failures += test_key_schedule();
    failures += test_block_encryption();
    failures += test_ctr_stream_encryption_decryption();
    failures += test_ctr_increment();
    failures += test_aes_init_ctx_auto_invalid_key_len();
    failures += test_aes_ctr_xor_stream_overlap();
    failures += test_aes_ctr_xor_stream_invalid_iv_len();
    failures += test_aes_ctr_xor_stream_null_args();

    printf("\n========================================\n");
    if (failures == 0) {
        printf("[OK] All tests passed!\n");
    } else {
        printf("[ERROR] %d test(s) failed\n", failures);
    }
    printf("========================================\n");

    return (failures == 0) ? 0 : 1;
}

