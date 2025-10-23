#define _CRT_SECURE_NO_WARNINGS
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 16진수 -> 2진수
void hex_to_bin(const char* hex_str, uint8_t* bin_arr, size_t bin_size) {
    for (size_t i = 0; i < bin_size; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bin_arr[i]);
    }
}

// 16진수 출력 함수
void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 테스트 케이스 구조체
typedef struct {
    const char* input;
    const char* expected;
} test_case_t;

// 알려진 테스트 케이스들
static const test_case_t test_cases[] = {
    {
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    }
};

int main() {
    printf("SHA256 테스트 시작\n");
    printf("==================\n\n");

    int passed = 0;
    int total = sizeof(test_cases) / sizeof(test_case_t);

    for (int i = 0; i < total; i++) {

        printf("테스트 %d: \"%s\"\n", i + 1, test_cases[i].input);

        uint8_t hash[SHA256_DIGEST_SIZE];
        sha256((const uint8_t*)test_cases[i].input, strlen(test_cases[i].input), hash);

        printf("예상값: %s\n", test_cases[i].expected);
        printf("실제값: ");
        print_hex(hash, SHA256_DIGEST_SIZE);

        uint8_t expected_bin[SHA256_DIGEST_SIZE];
        hex_to_bin(test_cases[i].expected, expected_bin, SHA256_DIGEST_SIZE);
        
        if (memcmp(hash, expected_bin, SHA256_DIGEST_SIZE) == 0) {
            printf("✓ 통과\n\n");
            passed++;
        }
        else {
            printf("✗ 실패\n\n");
        }
    }

    printf("==================\n");
    printf("테스트 결과: %d/%d 통과\n", passed, total);

    if (passed == total) {
        printf("모든 테스트가 성공적으로 통과했습니다!\n");
        return 0;
    }
    else {
        printf("일부 테스트가 실패했습니다.\n");
        return 1;
    }
}