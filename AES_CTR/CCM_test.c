// CCM_test.c — AES-CCM 테스트 코드
#include "CCM.h"  // CCM.h가 team06_lib_api.h를 통해 AES_CTR_ALL.h를 포함함
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

// 메모리 비교 (상수 시간)
static int memcmp_const(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff;
}

// 기본 기능 테스트
static int test_ccm_basic(void) {
    printf("\n=== CCM Basic Function Test ===\n");

    // 테스트 키
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    // 테스트 데이터
    const char* plaintext = "Hello, CCM!";
    size_t pt_len = strlen(plaintext);
    uint8_t nonce[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    const uint8_t* aad = NULL;
    size_t aad_len = 0;
    size_t tag_len = 16;

    // 컨텍스트 초기화
    aes_ctx_t ctx;
    if (aes_init_ctx_key_bytes(&ctx, key, 16) != AES_OK) {
        printf("[ERROR] AES context initialization failed\n");
        return 1;
    }

    // 암호화
    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* tag = (uint8_t*)malloc(tag_len);
    if (!ct || !tag) {
        printf("[ERROR] Memory allocation failed\n");
        return 1;
    }

    printf("Plaintext: %s\n", plaintext);
    print_hex("Nonce", nonce, 12);

    aes_status_t st = ccm_encrypt(&ctx, nonce, 12, aad, aad_len,
        (const uint8_t*)plaintext, pt_len, ct, tag, tag_len);
    if (st != AES_OK) {
        printf("[ERROR] Encryption failed: %d\n", st);
        free(ct);
        free(tag);
        return 1;
    }

    print_hex("Ciphertext", ct, pt_len);
    print_hex("Tag", tag, tag_len);

    // 복호화
    uint8_t* pt = (uint8_t*)malloc(pt_len);
    if (!pt) {
        printf("[ERROR] Memory allocation failed\n");
        free(ct);
        free(tag);
        return 1;
    }

    st = ccm_decrypt_and_verify(&ctx, nonce, 12, aad, aad_len,
        ct, pt_len, tag, tag_len, pt);
    if (st != AES_OK) {
        printf("[ERROR] Decryption failed: %d\n", st);
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    // 결과 검증
    if (memcmp_const((const uint8_t*)plaintext, pt, pt_len) != 0) {
        printf("[ERROR] Plaintext mismatch\n");
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    printf("[OK] Decrypted plaintext: %.*s\n", (int)pt_len, pt);
    printf("[OK] CCM basic test passed\n");

    free(ct);
    free(tag);
    free(pt);
    return 0;
}

// AAD 포함 테스트
static int test_ccm_with_aad(void) {
    printf("\n=== CCM with AAD Test ===\n");

    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const char* plaintext = "Test with AAD";
    size_t pt_len = strlen(plaintext);
    uint8_t nonce[12] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b};
    const char* aad_str = "Additional Data";
    size_t aad_len = strlen(aad_str);
    size_t tag_len = 12;

    aes_ctx_t ctx;
    if (aes_init_ctx_key_bytes(&ctx, key, 16) != AES_OK) {
        printf("[ERROR] AES context initialization failed\n");
        return 1;
    }

    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* tag = (uint8_t*)malloc(tag_len);
    uint8_t* pt = (uint8_t*)malloc(pt_len);
    if (!ct || !tag || !pt) {
        printf("[ERROR] Memory allocation failed\n");
        return 1;
    }

    printf("Plaintext: %s\n", plaintext);
    printf("AAD: %s\n", aad_str);

    aes_status_t st = ccm_encrypt(&ctx, nonce, 12, (const uint8_t*)aad_str, aad_len,
        (const uint8_t*)plaintext, pt_len, ct, tag, tag_len);
    if (st != AES_OK) {
        printf("[ERROR] Encryption failed: %d\n", st);
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    print_hex("Ciphertext", ct, pt_len);
    print_hex("Tag", tag, tag_len);

    st = ccm_decrypt_and_verify(&ctx, nonce, 12, (const uint8_t*)aad_str, aad_len,
        ct, pt_len, tag, tag_len, pt);
    if (st != AES_OK) {
        printf("[ERROR] Decryption failed: %d\n", st);
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    if (memcmp_const((const uint8_t*)plaintext, pt, pt_len) != 0) {
        printf("[ERROR] Plaintext mismatch\n");
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    printf("[OK] Decrypted plaintext: %.*s\n", (int)pt_len, pt);
    printf("[OK] CCM with AAD test passed\n");

    free(ct);
    free(tag);
    free(pt);
    return 0;
}

// 태그 검증 실패 테스트
static int test_ccm_tag_verification_failure(void) {
    printf("\n=== CCM Tag Verification Failure Test ===\n");

    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    const char* plaintext = "Test message";
    size_t pt_len = strlen(plaintext);
    uint8_t nonce[12] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b};
    size_t tag_len = 16;

    aes_ctx_t ctx;
    if (aes_init_ctx_key_bytes(&ctx, key, 16) != AES_OK) {
        printf("[ERROR] AES context initialization failed\n");
        return 1;
    }

    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* tag = (uint8_t*)malloc(tag_len);
    uint8_t* pt = (uint8_t*)malloc(pt_len);
    if (!ct || !tag || !pt) {
        printf("[ERROR] Memory allocation failed\n");
        return 1;
    }

    // 정상 암호화
    aes_status_t st = ccm_encrypt(&ctx, nonce, 12, NULL, 0,
        (const uint8_t*)plaintext, pt_len, ct, tag, tag_len);
    if (st != AES_OK) {
        printf("[ERROR] Encryption failed\n");
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    // 태그 변조
    tag[0] ^= 0x01;

    // 복호화 시도 (실패해야 함)
    st = ccm_decrypt_and_verify(&ctx, nonce, 12, NULL, 0,
        ct, pt_len, tag, tag_len, pt);
    if (st == AES_OK) {
        printf("[ERROR] Tag verification failure not detected\n");
        free(ct);
        free(tag);
        free(pt);
        return 1;
    }

    // 평문 버퍼가 0으로 초기화되었는지 확인
    uint8_t all_zero = 1;
    for (size_t i = 0; i < pt_len; i++) {
        if (pt[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    if (!all_zero) {
        printf("[WARNING] Plaintext buffer not cleared on tag verification failure\n");
    }

    printf("[OK] Tag verification failure correctly detected\n");
    printf("[OK] CCM tag verification failure test passed\n");

    free(ct);
    free(tag);
    free(pt);
    return 0;
}

int main(void) {
    printf("========================================\n");
    printf("    AES-CCM Test Suite\n");
    printf("========================================\n");

    int failures = 0;
    failures += test_ccm_basic();
    failures += test_ccm_with_aad();
    failures += test_ccm_tag_verification_failure();

    printf("\n========================================\n");
    if (failures == 0) {
        printf("[OK] All tests passed!\n");
    } else {
        printf("[ERROR] %d test(s) failed\n", failures);
    }
    printf("========================================\n");

    return (failures == 0) ? 0 : 1;
}

