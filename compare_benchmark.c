// compare_benchmark.c — CCM vs AES+HMAC 비교 벤치마크
#include "CCM.h"      // CCM.h가 team06_lib_api.h를 통해 AES_CTR_ALL.h를 포함함
#include "AES_HMAC.h" // AES_HMAC.h가 AES_CTR_ALL.h를 포함함
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>  // Windows 콘솔 코드 페이지 설정용
#endif

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
    benchmark_result_t result = { 0 };
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
    benchmark_result_t result = { 0 };
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
    }
    else {
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
static void print_summary_comparison(const benchmark_result_t* ccm_results, const benchmark_result_t* aes_hmac_results, size_t num_results) {
    printf("\n========================================\n");
    printf("    Summary Comparison\n");
    printf("========================================\n");

    // Analyze all benchmark results to determine which method is faster at different sizes
    printf("Benchmark Results Summary:\n\n");
    
    size_t ccm_wins = 0, aes_hmac_wins = 0;
    size_t threshold_size = 0;  // Size where AES+HMAC becomes faster (if applicable)
    
    for (size_t i = 0; i < num_results; i++) {
        double speedup = ccm_results[i].throughput_mbps / aes_hmac_results[i].throughput_mbps;
        const char* faster = (speedup > 1.0) ? "CCM" : "AES+HMAC";
        
        printf("  %zu bytes: %s is %.2fx faster\n", 
               ccm_results[i].data_size, faster, 
               (speedup > 1.0) ? speedup : (1.0 / speedup));
        
        if (speedup > 1.0) {
            ccm_wins++;
        } else {
            aes_hmac_wins++;
            // Find the threshold where AES+HMAC starts winning
            if (threshold_size == 0) {
                threshold_size = ccm_results[i].data_size;
            }
        }
    }
    
    printf("\nOverall Performance Analysis:\n");
    printf("  CCM faster at: %zu size(s)\n", ccm_wins);
    printf("  AES+HMAC faster at: %zu size(s)\n", aes_hmac_wins);
    if (threshold_size > 0) {
        printf("  AES+HMAC becomes faster starting from: %zu bytes\n", threshold_size);
    }
    
    // Determine the overall recommendation based on actual results
    const char* overall_faster = (ccm_wins > aes_hmac_wins) ? "CCM" : "AES+HMAC";
    
    printf("\nRecommendations by Use Case:\n\n");

    printf("1. When performance is important:\n");
    if (ccm_wins > aes_hmac_wins) {
        printf("   -> CCM recommended\n");
        if (threshold_size > 0) {
            printf("      CCM is faster for data sizes < %zu bytes\n", threshold_size);
            printf("      AES+HMAC becomes faster for data sizes >= %zu bytes\n", threshold_size);
        } else {
            printf("      CCM is faster across all tested data sizes\n");
        }
    } else if (aes_hmac_wins > ccm_wins) {
        printf("   -> AES+HMAC recommended\n");
        if (threshold_size > 0) {
            printf("      AES+HMAC is faster for data sizes >= %zu bytes\n", threshold_size);
        } else {
            printf("      AES+HMAC is faster across all tested data sizes\n");
        }
    } else {
        printf("   -> Both methods have similar performance\n");
        printf("      Performance varies by data size - check individual results above\n");
    }
    printf("\n");

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
#ifdef _WIN32
    // Windows 콘솔에서 UTF-8 출력 지원
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
#endif
    
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
    size_t test_sizes[] = { 16, 64, 256, 1024, 4096 };
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

    uint8_t nonce[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
    const uint8_t* aad = NULL;
    size_t aad_len = 0;

    printf("\nPerformance measurement in progress... (1000 iterations per size)\n");

    // 모든 벤치마크 결과를 저장하기 위한 배열
    benchmark_result_t* ccm_results = (benchmark_result_t*)malloc(num_sizes * sizeof(benchmark_result_t));
    benchmark_result_t* aes_hmac_results = (benchmark_result_t*)malloc(num_sizes * sizeof(benchmark_result_t));
    
    if (!ccm_results || !aes_hmac_results) {
        printf("[ERROR] Memory allocation failed for results storage\n");
        if (ccm_results) free(ccm_results);
        if (aes_hmac_results) free(aes_hmac_results);
        return 1;
    }

    for (size_t i = 0; i < num_sizes; i++) {
        size_t pt_len = test_sizes[i];
        uint8_t* pt = (uint8_t*)malloc(pt_len);
        if (!pt) continue;

        // 테스트 데이터 초기화
        for (size_t j = 0; j < pt_len; j++) {
            pt[j] = (uint8_t)(j & 0xFF);
        }

        printf("\n--- Data Size: %zu bytes ---\n", pt_len);

        // CCM 벤치마크 (태그 길이: 16바이트)
        ccm_results[i] = benchmark_ccm(aes_key, pt, pt_len, nonce, 12, aad, aad_len, 16);

        // AES+HMAC 벤치마크 (MAC 길이: 16바이트로 동일하게 설정하여 공정한 비교)
        // 참고: AES_HMAC은 내부적으로 전체 SHA-512(64바이트)를 계산하지만, mac_len만큼만 출력
        aes_hmac_results[i] = benchmark_aes_hmac(aes_key, mac_key, 64, pt, pt_len, nonce, 12, aad, aad_len, 16);

        // 결과 출력
        print_performance_comparison(ccm_results[i], aes_hmac_results[i]);

        free(pt);
    }

    // 보안 강도 분석
    print_security_analysis();

    // 구현 난이도 분석
    print_implementation_analysis();

    // 종합 비교 (모든 벤치마크 결과 사용)
    print_summary_comparison(ccm_results, aes_hmac_results, num_sizes);
    
    // 메모리 해제
    free(ccm_results);
    free(aes_hmac_results);

    printf("\n========================================\n");
    printf("    Benchmark Complete\n");
    printf("========================================\n");

    printf("\nPress any key to exit...\n");
    getchar();

    return 0;
}
