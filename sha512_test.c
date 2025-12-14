// 만든 SHA-512 함수가 잘 작동하는지 확인하기 위해 공식 해시값과 비교하는 코드

#define _CRT_SECURE_NO_WARNINGS  // scanf, strcpy 같은 함수 쓸 때 경고 안 뜨게 함
#include "SHA512.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>  // 콘솔 코드 페이지 설정용

// 16진수 -> 2진수(바이트 배열)
// hex_str: 16진 문자열 ("ddaf35..." 같은 것)
// bin_arr: 결과를 쓸 바이트 배열
// bin_size: 바이트 배열의 길이(= 해시 출력 길이)
void hex_to_bin(const char* hex_str, uint8_t* bin_arr, size_t bin_size) {
    for (size_t i = 0; i < bin_size; i++) {
        // 2자리 16진수 -> 1바이트
        // %2hhx: 2자리 16진수를 읽어오기
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
    const char* input;     // 해시할 문자열
    const char* expected;  // 그 문자열의 공식 SHA512 해시값
} test_case_t;

// 알려진 테스트 케이스들
static const test_case_t test_cases[] = {
    {
        "",
        // SHA-512("")
        "cf83e1357eefb8bdf1542850d66d8007"
        "d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f"
        "63b931bd47417a81a538327af927da3e"
    },
    {
        "abc",
        // SHA-512("abc")
        "ddaf35a193617abacc417349ae204131"
        "12e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd"
        "454d4423643ce80e2a9ac94fa54ca49f"
    },
    {
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        // 멀티블록 입력 테스트
        "204a8fc6dda82f0a0ced7beb8e08a416"
        "57c16ef468b228a8279be331a703c335"
        "96fd15c13b1b07f9aa1d3bea57789ca0"
        "31ad85c7a71dd70354ec631238ca3445"
    },
    {
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    // 더 긴 반복 패턴 입력
    "8e959b75dae313da8cf4f72814fc143f"
    "8f7779c6eb9f7fa17299aeadb6889018"
    "501d289e4900f7e4331b99dec4b5433a"
    "c7d329eeb6dd26545e96e55b874be909"
}
};

int main(void) {
    // Windows 콘솔에서 한글 출력을 위한 코드 페이지 설정
    SetConsoleOutputCP(65001);  // UTF-8 코드 페이지
    SetConsoleCP(65001);        // 입력 코드 페이지도 UTF-8로 설정
    
    printf("SHA512 Test Start\n");
    printf("==================\n\n");

    // 통과한 테스트 케이스 개수를 셀 변수
    int passed = 0;
    // 배열의 총 바이트 크기를 요소 하나의 바이트 크기로 나눠서 길이를 구함
    int total = (int)(sizeof(test_cases) / sizeof(test_case_t));

    // 모든 테스트 케이스를 하나씩 돌면서 검사하는 루프
    for (int i = 0; i < total; i++) {

        const char* msg = test_cases[i].input;

        // 현재 몇 번째 테스트인지, 입력 문자열 출력
        printf("Test %d: \"%s\"\n", i + 1, msg);

        // SHA-512 결과를 담을 출력 범퍼
        uint8_t hash[SHA512_DIGEST_SIZE];
        // 원샷 API 호출
        sha512((const uint8_t*)msg, strlen(msg), hash);
        // 결과 해시는 hash[64]에 기록됨

        // 표준 해시값 16진 문자열로 출력
        printf("Expected: %s\n", test_cases[i].expected);
        printf("Actual:   ");
        // 계산한 해시값을 16진 문장열로 변환해 출력
        print_hex(hash, SHA512_DIGEST_SIZE);

        // 정답 해시를 바이트 배열로 변환해서 담아둘 버퍼(64B)
        uint8_t expected_bin[SHA512_DIGEST_SIZE];
        // expected_bin이라는 바이트 배열로 변환
        hex_to_bin(test_cases[i].expected, expected_bin, SHA512_DIGEST_SIZE);

        // memcmp로 바이트 단위 비교
        // 완전히 같으면 통과 출력 후 passed 1 증가
        if (memcmp(hash, expected_bin, SHA512_DIGEST_SIZE) == 0) {
            printf("PASS\n\n");
            passed++;
        }
        // 바이트가 하나라도 다르면 실패로 출력
        else {
            printf("FAIL\n\n");
        }
    }

    printf("==================\n");
    printf("Test Result: %d/%d passed\n", passed, total);

    // 전체 통과면 0을 반환
    if (passed == total) {
        printf("All tests passed successfully!\n");
    }
    // 하나라도 실패면 1을 반환
    else {
        printf("Some tests failed.\n");
    }

    // 콘솔 창이 바로 닫히지 않도록 대기
    printf("\nPress any key to exit...\n");
    getchar();
    return (passed == total) ? 0 : 1;
}