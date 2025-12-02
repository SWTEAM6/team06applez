// compare_benchmark.c — CCM vs AES+HMAC 비교 벤치마크
#include "CCM.h"      // CCM.h가 team06_lib_api.h를 통해 AES_CTR_ALL.h를 포함함
#include "AES_HMAC.h" // AES_HMAC.h가 AES_CTR_ALL.h를 포함함
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// 성능 측정 헬퍼
typedef struct {
    double encrypt_time;    // 암호화 시간 (초)
    double decrypt_time;    // 복호화 시간 (초)
    double total_time;      // 총 시간 (초)
    size_t data_size;       // 데이터 크기 (바이트)
    double throughput_mbps; // 처리량 (MB/s)
} benchmark_result_t;

// CCM 성능 측정
static benchmark_result_t benchmark_ccm(const uint8_t* key, const uint8_t* pt, size_t pt_len,
    const uint8_t* nonce, size_t nonce_len, const uint8_t* aad, size_t aad_len, size_t tag_len) {
    benchmark_result_t result = {0};
    result.data_size = pt_len;

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, key, 16);

    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* tag = (uint8_t*)malloc(tag_len);
    uint8_t* pt_out = (uint8_t*)malloc(pt_len);

    if (!ct || !tag || !pt_out) {
        free(ct);
        free(tag);
        free(pt_out);
        return result;
    }

    // 암호화 시간 측정
    clock_t start = clock();
    for (int i = 0; i < 1000; i++) {  // 1000회 반복
        ccm_encrypt(&ctx, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, tag, tag_len);
    }
    clock_t end = clock();
    result.encrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC / 1000.0;

    // 복호화 시간 측정
    start = clock();
    for (int i = 0; i < 1000; i++) {
        ccm_decrypt_and_verify(&ctx, nonce, nonce_len, aad, aad_len, ct, pt_len, tag, tag_len, pt_out);
    }
    end = clock();
    result.decrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC / 1000.0;

    result.total_time = result.encrypt_time + result.decrypt_time;
    result.throughput_mbps = (pt_len * 2.0) / (result.total_time * 1024.0 * 1024.0);  // 암호화+복호화

    free(ct);
    free(tag);
    free(pt_out);

    return result;
}

// AES+HMAC 성능 측정
static benchmark_result_t benchmark_aes_hmac(const uint8_t* aes_key, const uint8_t* mac_key, size_t mac_key_len,
    const uint8_t* pt, size_t pt_len, const uint8_t* nonce, size_t nonce_len,
    const uint8_t* aad, size_t aad_len, size_t mac_len) {
    benchmark_result_t result = {0};
    result.data_size = pt_len;

    aes_ctx_t ctx;
    aes_init_ctx_key_bytes(&ctx, aes_key, 16);

    uint8_t* ct = (uint8_t*)malloc(pt_len);
    uint8_t* mac = (uint8_t*)malloc(mac_len);
    uint8_t* pt_out = (uint8_t*)malloc(pt_len);

    if (!ct || !mac || !pt_out) {
        free(ct);
        free(mac);
        free(pt_out);
        return result;
    }

    // 암호화 시간 측정
    clock_t start = clock();
    for (int i = 0; i < 1000; i++) {
        aes_hmac_encrypt(&ctx, mac_key, mac_key_len, nonce, nonce_len, aad, aad_len, pt, pt_len, ct, mac, mac_len);
    }
    clock_t end = clock();
    result.encrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC / 1000.0;

    // 복호화 시간 측정
    start = clock();
    for (int i = 0; i < 1000; i++) {
        aes_hmac_decrypt_and_verify(&ctx, mac_key, mac_key_len, nonce, nonce_len, aad, aad_len, ct, pt_len, mac, mac_len, pt_out);
    }
    end = clock();
    result.decrypt_time = ((double)(end - start)) / CLOCKS_PER_SEC / 1000.0;

    result.total_time = result.encrypt_time + result.decrypt_time;
    result.throughput_mbps = (pt_len * 2.0) / (result.total_time * 1024.0 * 1024.0);

    free(ct);
    free(mac);
    free(pt_out);

    return result;
}

// Performance comparison output
static void print_performance_comparison(benchmark_result_t ccm, benchmark_result_t aes_hmac) {
    printf("\n========================================\n");
    printf("    Performance Comparison\n");
    printf("========================================\n");
    printf("Data Size: %zu bytes\n\n", ccm.data_size);

    printf("CCM:\n");
    printf("  Encryption Time: %.6f seconds\n", ccm.encrypt_time);
    printf("  Decryption Time: %.6f seconds\n", ccm.decrypt_time);
    printf("  Total Time:      %.6f seconds\n", ccm.total_time);
    printf("  Throughput:      %.2f MB/s\n", ccm.throughput_mbps);

    printf("\nAES+HMAC:\n");
    printf("  Encryption Time: %.6f seconds\n", aes_hmac.encrypt_time);
    printf("  Decryption Time: %.6f seconds\n", aes_hmac.decrypt_time);
    printf("  Total Time:      %.6f seconds\n", aes_hmac.total_time);
    printf("  Throughput:       %.2f MB/s\n", aes_hmac.throughput_mbps);

    printf("\nComparison:\n");
    double speedup = ccm.throughput_mbps / aes_hmac.throughput_mbps;
    if (speedup > 1.0) {
        printf("  CCM is %.2fx faster\n", speedup);
        if (ccm.data_size <= 64) {
            printf("  (Note: CCM is typically faster for small data due to single-pass processing)\n");
        }
    } else {
        printf("  AES+HMAC is %.2fx faster\n", 1.0 / speedup);
        if (ccm.data_size > 64) {
            printf("  (Note: AES+HMAC is typically faster for large data due to parallel processing capability)\n");
        }
    }
}

// Security strength analysis
static void print_security_analysis(void) {
    printf("\n========================================\n");
    printf("    Security Strength Analysis\n");
    printf("========================================\n");

    printf("CCM (AES-CCM):\n");
    printf("  Encryption Strength: 128-bit (AES-128)\n");
    printf("  Authentication Strength: 128-bit (32~128-bit depending on tag length)\n");
    printf("  Key Size:            128-bit\n");
    printf("  Nonce Size:          7~13 bytes\n");
    printf("  Standard:            NIST SP 800-38C\n");
    printf("  Advantages:\n");
    printf("    - Single key for encryption+authentication\n");
    printf("    - AEAD (Authenticated Encryption with Associated Data)\n");
    printf("    - Standardized mode\n");
    printf("  Disadvantages:\n");
    printf("    - High implementation complexity\n");
    printf("    - Sequential processing (difficult to parallelize)\n");

    printf("\nAES+HMAC:\n");
    printf("  Encryption Strength: 128-bit (AES-128)\n");
    printf("  Authentication Strength: 256~512-bit (HMAC-SHA512)\n");
    printf("  Key Size:            AES 128-bit + MAC 64 bytes or more recommended\n");
    printf("  Nonce Size:          No limit (CTR mode)\n");
    printf("  Standard:            RFC 2104 (HMAC), NIST SP 800-38A (CTR)\n");
    printf("  Advantages:\n");
    printf("    - High authentication strength (SHA-512 based)\n");
    printf("    - Key separation possible (encryption key and MAC key separate)\n");
    printf("    - Parallel processing possible (encryption and MAC independent)\n");
    printf("    - Simple implementation (combining existing libraries)\n");
    printf("  Disadvantages:\n");
    printf("    - Two keys need to be managed\n");
    printf("    - Two passes (encryption + MAC)\n");
    printf("    - Encrypt-then-MAC pattern required\n");
}

// Implementation complexity analysis
static void print_implementation_analysis(void) {
    printf("\n========================================\n");
    printf("    Implementation Complexity Analysis\n");
    printf("========================================\n");

    printf("CCM:\n");
    printf("  Complexity:     High\n");
    printf("  Code Lines:     ~277 lines (CCM.c)\n");
    printf("  Main Components:\n");
    printf("    - B0 block generation (flags, Nonce, length encoding)\n");
    printf("    - CTR block generation\n");
    printf("    - CBC-MAC calculation (including AAD encoding)\n");
    printf("    - Tag masking\n");
    printf("    - CTR encryption\n");
    printf("  Complex Parts:\n");
    printf("    - AAD length encoding (2/6/10 bytes)\n");
    printf("    - Message length field size calculation (L parameter)\n");
    printf("    - Simultaneous management of CBC-MAC and CTR mode\n");

    printf("\nAES+HMAC:\n");
    printf("  Complexity:     Medium\n");
    printf("  Code Lines:     ~200 lines (AES_HMAC.c)\n");
    printf("  Main Components:\n");
    printf("    - AES-CTR encryption (existing library)\n");
    printf("    - HMAC-SHA512 calculation (existing library)\n");
    printf("    - MAC input composition (AAD || CT)\n");
    printf("  Complex Parts:\n");
    printf("    - HMAC internal key padding handling\n");
    printf("    - MAC input format design\n");
    printf("    - Key separation management\n");

    printf("\nComparison:\n");
    printf("  CCM is more complex to implement as an integrated mode, but can be used with a single API\n");
    printf("  AES+HMAC is relatively simple as it combines existing libraries\n");
}

// Summary comparison
static void print_summary_comparison(benchmark_result_t ccm_result, benchmark_result_t aes_hmac_result) {
    printf("\n========================================\n");
    printf("    Summary Comparison\n");
    printf("========================================\n");

    // Performance comparison based on actual benchmark results
    double speedup = ccm_result.throughput_mbps / aes_hmac_result.throughput_mbps;
    const char* faster_method = (speedup > 1.0) ? "CCM" : "AES+HMAC";
    double speedup_factor = (speedup > 1.0) ? speedup : (1.0 / speedup);
    
    printf("Benchmark Results Summary:\n");
    printf("  Based on %zu bytes data size:\n", ccm_result.data_size);
    printf("  - CCM throughput:      %.2f MB/s\n", ccm_result.throughput_mbps);
    printf("  - AES+HMAC throughput: %.2f MB/s\n", aes_hmac_result.throughput_mbps);
    printf("  - %s is %.2fx faster\n\n", faster_method, speedup_factor);

    printf("Recommendations by Use Case:\n\n");

    printf("1. When performance is important:\n");
    if (speedup > 1.0) {
        printf("   -> CCM recommended (%.2fx faster in benchmark)\n", speedup);
        printf("      Note: CCM is typically faster for small data sizes (<256 bytes)\n\n");
    } else {
        printf("   -> AES+HMAC recommended (%.2fx faster in benchmark)\n", 1.0 / speedup);
        printf("      Note: AES+HMAC is typically faster for large data sizes (>=256 bytes)\n\n");
    }

    printf("2. When security strength is important:\n");
    printf("   -> AES+HMAC recommended (SHA-512 based high authentication strength)\n\n");

    printf("3. When implementation simplicity is important:\n");
    printf("   -> AES+HMAC recommended (combining existing libraries)\n\n");

    printf("4. When standard compliance is important:\n");
    printf("   -> CCM recommended (NIST standard, AEAD mode)\n\n");

    printf("5. When key management is important:\n");
    printf("   -> AES+HMAC recommended (key separation possible)\n\n");

    printf("6. When parallel processing is needed:\n");
    printf("   -> AES+HMAC recommended (encryption and MAC independent)\n\n");
}

int main(void) {
    printf("========================================\n");
    printf("    CCM vs AES+HMAC Benchmark\n");
    printf("========================================\n");

    // 테스트 데이터 준비
    uint8_t aes_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t mac_key[64];
    memset(mac_key, 0x1a, 64);

    // 다양한 크기의 테스트 데이터
    size_t test_sizes[] = {16, 64, 256, 1024, 4096};
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

    uint8_t nonce[12] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b};
    const uint8_t* aad = NULL;
    size_t aad_len = 0;

    printf("\nPerformance measurement in progress... (1000 iterations per size)\n");

    // 마지막 벤치마크 결과를 저장하기 위한 변수
    benchmark_result_t last_ccm_result = {0};
    benchmark_result_t last_aes_hmac_result = {0};

    for (size_t i = 0; i < num_sizes; i++) {
        size_t pt_len = test_sizes[i];
        uint8_t* pt = (uint8_t*)malloc(pt_len);
        if (!pt) continue;

        // 테스트 데이터 초기화
        for (size_t j = 0; j < pt_len; j++) {
            pt[j] = (uint8_t)(j & 0xFF);
        }

        printf("\n--- Data Size: %zu bytes ---\n", pt_len);

        // CCM 벤치마크
        benchmark_result_t ccm_result = benchmark_ccm(aes_key, pt, pt_len, nonce, 12, aad, aad_len, 16);

        // AES+HMAC 벤치마크
        benchmark_result_t aes_hmac_result = benchmark_aes_hmac(aes_key, mac_key, 64, pt, pt_len, nonce, 12, aad, aad_len, 32);

        // 결과 출력
        print_performance_comparison(ccm_result, aes_hmac_result);

        // 마지막 결과 저장 (summary에 사용)
        last_ccm_result = ccm_result;
        last_aes_hmac_result = aes_hmac_result;

        free(pt);
    }

    // 보안 강도 분석
    print_security_analysis();

    // 구현 난이도 분석
    print_implementation_analysis();

    // 종합 비교 (마지막 벤치마크 결과 사용)
    print_summary_comparison(last_ccm_result, last_aes_hmac_result);

    printf("\n========================================\n");
    printf("    Benchmark Complete\n");
    printf("========================================\n");

    return 0;
}

