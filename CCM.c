// CCM.c — AES-CCM (NIST SP 800-38C) using aesmini (AES core + CTR)  // 파일 설명: AES-CCM 구현 파일
#include "CCM.h"  // CCM 헤더 파일 포함 (함수 선언 및 타입 정의)
#include <string.h>  // 문자열 및 메모리 조작 함수 사용 (memcpy, memset 등)

#define CCM_MIN_TAG 4u  // 최소 인증 태그 길이 정의 (4바이트)
#define CCM_MAX_TAG 16u  // 최대 인증 태그 길이 정의 (16바이트)

/* ---------- 내부 유틸 ---------- */  // 내부 유틸리티 함수 섹션 시작

// 유효한 태그 길이인지 확인 (4,6,8,10,12,14,16)  // 태그 길이 유효성 검사 함수 설명
static inline bool valid_tag_len(size_t t) {  // 인라인 함수로 정의하여 성능 최적화
    return (t >= CCM_MIN_TAG && t <= CCM_MAX_TAG && (t % 2) == 0);  // 최소값 이상, 최대값 이하, 짝수인지 확인
}

/* B0 = Flags || Nonce || Q(message length)  // B0 블록 구조 설명
   Flags bit 구성:  // 플래그 비트 구성 설명
   [6] Adata 존재 여부, [5..3] (t-2)/2, [2..0] (L-1)  // 각 비트 필드 의미
*/
static void make_B0(uint8_t B0[16],  // B0 블록 생성 함수 (16바이트 출력)
    size_t L,  // 메시지 길이 필드 크기 (2~8)
    size_t tag_len,  // 인증 태그 길이
    const uint8_t* nonce,  // Nonce 버퍼
    size_t nonce_len,  // Nonce 길이
    size_t pt_len,  // 평문 길이
    bool has_aad)  // 추가 인증 데이터 존재 여부
{
    if (!B0 || !nonce) return;  // NULL 포인터 검사
    if (L < 2 || L > 8) return;  // L 범위 검사
    if (nonce_len == 0 || nonce_len > 15) return;  // nonce_len 범위 검사 (B0[1..15] 사용 가능)
    if (nonce_len + L > 15) return;  // nonce와 길이 필드가 겹치지 않도록 검사

    uint8_t flags = 0;  // 플래그 바이트 초기화
    if (has_aad) flags |= 0x40; // Adata 비트  // 비트 6 설정 (0x40 = 01000000)
    flags |= (uint8_t)(((tag_len - 2u) / 2u) << 3);  // 비트 5~3에 태그 길이 인코딩 (3비트 시프트)
    flags |= (uint8_t)((L - 1u) & 0x07u);  // 비트 2~0에 L-1 값 저장 (하위 3비트만 사용)

    memset(B0, 0, 16);  // B0를 0으로 초기화 (안전성)
    B0[0] = flags;  // B0의 첫 번째 바이트에 플래그 저장
    memcpy(&B0[1], nonce, nonce_len);  // B0의 1번째 바이트부터 Nonce 복사

    for (size_t i = 0; i < L; i++) {  // 메시지 길이를 L바이트로 인코딩
        B0[15 - i] = (uint8_t)(pt_len & 0xFFu);  // 하위 바이트부터 역순으로 저장 (빅엔디안)
        pt_len >>= 8;  // 다음 바이트를 위해 8비트 오른쪽 시프트
    }
}

/* CTR 초기 블록 생성 (Ctr0 = Flags' || Nonce || Counter)  // CTR 블록 구조 설명
   Flags'는 하위 3비트에 (L-1)만 포함. Counter=0이면 S0용, 1부터 메시지용 */  // 플래그 및 카운터 용도 설명
static void make_Ctr0(uint8_t ctr[16],  // CTR 블록 생성 함수 (16바이트 출력)
    size_t L,  // 메시지 길이 필드 크기
    const uint8_t* nonce,  // Nonce 버퍼
    size_t nonce_len,  // Nonce 길이
    uint64_t counter_value)  // 카운터 값 (0: S0용, 1~: 메시지 암호화용)
{
    if (!ctr || !nonce) return;  // NULL 포인터 검사
    if (L < 2 || L > 8) return;  // L 범위 검사
    if (nonce_len == 0 || nonce_len > 15) return;  // nonce_len 범위 검사 (ctr[1..15] 사용 가능)
    if (nonce_len + L > 15) return;  // nonce와 카운터 필드가 겹치지 않도록 검사

    memset(ctr, 0, 16);  // CTR 블록을 0으로 초기화
    ctr[0] = (uint8_t)((L - 1u) & 0x07u);  // 첫 번째 바이트에 L-1 값 저장 (하위 3비트만)
    memcpy(&ctr[1], nonce, nonce_len);  // 1번째 바이트부터 Nonce 복사

    for (size_t i = 0; i < L; i++) {  // 카운터 값을 L바이트로 인코딩
        ctr[15 - i] = (uint8_t)(counter_value & 0xFFu);  // 하위 바이트부터 역순으로 저장
        counter_value >>= 8;  // 다음 바이트를 위해 8비트 오른쪽 시프트
    }
}

/* CBC-MAC 기본 연산: Xi = AES( Xi-1 XOR block ) */  // CBC-MAC 알고리즘 설명
static void cbc_mac_init(uint8_t X[16]) { memset(X, 0, 16); }  // CBC-MAC 상태 초기화 (0으로 설정)

static void xor_block(uint8_t dst[16], const uint8_t src[16]) {  // 두 블록을 XOR 연산하는 함수
    for (int i = 0; i < 16; i++) dst[i] ^= src[i];  // 각 바이트를 XOR 연산
}

static aes_status_t cbc_mac_update_block(const aes_ctx_t* ctx,  // CBC-MAC 블록 갱신 함수
    uint8_t X[16],  // CBC-MAC 상태 (입출력)
    const uint8_t block[16])  // 처리할 16바이트 블록
{
    if (!ctx || !X || !block) return AES_ERR_ARG;  // 포인터 유효성 검증
    uint8_t tmp[16];  // 임시 버퍼
    memcpy(tmp, X, 16);  // 현재 상태를 임시 버퍼에 복사
    xor_block(tmp, block);  // 임시 버퍼와 입력 블록을 XOR
    return aes_encrypt_block_128b_in_128b_out(ctx, tmp, X);  // XOR 결과를 AES 암호화하여 상태 업데이트
}

/* AAD 인코딩 및 MAC 갱신 */  // 추가 인증 데이터 처리 함수 설명
static aes_status_t cbc_mac_aad(const aes_ctx_t* ctx,  // AES 컨텍스트
    uint8_t X[16],  // CBC-MAC 상태 (입출력)
    const uint8_t* aad, size_t aad_len)  // 추가 인증 데이터 버퍼와 길이
{
    if (!ctx || !X) return AES_ERR_ARG;  // 컨텍스트와 상태 버퍼 검증
    if (!aad || aad_len == 0) return AES_OK;  // AAD가 없으면 즉시 반환

    uint8_t block[16];  // 16바이트 블록 버퍼
    size_t off = 0;  // 현재 처리 위치 오프셋

    // AAD 길이에 따른 헤더 인코딩  // CCM 표준에 따른 AAD 길이 인코딩
    if (aad_len < ((size_t)1 << 16) - ((size_t)1 << 8)) {  // AAD 길이가 65280 미만인 경우 (2바이트 인코딩)
        memset(block, 0, 16);  // 블록을 0으로 초기화
        block[0] = (uint8_t)((aad_len >> 8) & 0xFF);  // 상위 바이트 저장
        block[1] = (uint8_t)(aad_len & 0xFF);  // 하위 바이트 저장
        size_t chunk = (aad_len < 14) ? aad_len : 14;  // 첫 블록에 들어갈 데이터 크기 (최대 14바이트)
        memcpy(&block[2], aad, chunk);  // AAD 데이터 복사
        off += chunk;  // 오프셋 업데이트
        aes_status_t st = cbc_mac_update_block(ctx, X, block);  // MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }
    else if (aad_len < ((uint64_t)1 << 32)) {  // AAD 길이가 2^32 미만인 경우 (6바이트 인코딩)
        memset(block, 0, 16);  // 블록을 0으로 초기화
        block[0] = 0xFF; block[1] = 0xFE;  // 6바이트 인코딩 마커
        block[2] = (uint8_t)((aad_len >> 24) & 0xFF);  // 최상위 바이트
        block[3] = (uint8_t)((aad_len >> 16) & 0xFF);  // 상위 바이트
        block[4] = (uint8_t)((aad_len >> 8) & 0xFF);  // 중간 바이트
        block[5] = (uint8_t)(aad_len & 0xFF);  // 하위 바이트
        size_t chunk = (aad_len < 10) ? aad_len : 10;  // 첫 블록에 들어갈 데이터 크기 (최대 10바이트)
        memcpy(&block[6], aad, chunk);  // AAD 데이터 복사
        off += chunk;  // 오프셋 업데이트
        aes_status_t st = cbc_mac_update_block(ctx, X, block);  // MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }
    else {  // AAD 길이가 매우 큰 경우 (10바이트 인코딩)
        memset(block, 0, 16);  // 블록을 0으로 초기화
        block[0] = 0xFF; block[1] = 0xFF;  // 10바이트 인코딩 마커
        uint64_t L64 = (uint64_t)aad_len;  // 64비트로 변환
        for (int i = 0; i < 8; i++)  // 8바이트 길이 인코딩
            block[2 + i] = (uint8_t)((L64 >> (56 - 8 * i)) & 0xFF);  // 빅엔디안 형식으로 저장
        size_t chunk = (aad_len < 6) ? aad_len : 6;  // 첫 블록에 들어갈 데이터 크기 (최대 6바이트)
        memcpy(&block[10], aad, chunk);  // AAD 데이터 복사
        off += chunk;  // 오프셋 업데이트
        aes_status_t st = cbc_mac_update_block(ctx, X, block);  // MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }

    // 잔여 AAD 처리  // 첫 블록 이후 남은 AAD 데이터 처리
    while (off + 16 <= aad_len) {  // 완전한 16바이트 블록이 남아있는 동안
        aes_status_t st = cbc_mac_update_block(ctx, X, &aad[off]);  // 16바이트 블록 단위로 MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
        off += 16;  // 오프셋을 16바이트 증가
    }
    if (off < aad_len) {  // 마지막 불완전한 블록이 있는 경우
        uint8_t last[16] = { 0 };  // 마지막 블록 버퍼 (0으로 초기화)
        memcpy(last, &aad[off], aad_len - off);  // 남은 데이터 복사
        aes_status_t st = cbc_mac_update_block(ctx, X, last);  // 패딩된 블록으로 MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }
    return AES_OK;  // 성공 반환
}

/* 메시지(PT/CT) MAC 갱신 */  // 평문 또는 암호문을 이용한 MAC 갱신 함수
static aes_status_t cbc_mac_msg(const aes_ctx_t* ctx,  // AES 컨텍스트
    uint8_t X[16],  // CBC-MAC 상태 (입출력)
    const uint8_t* msg, size_t len)  // 메시지 버퍼와 길이
{
    if (!ctx || !X) return AES_ERR_ARG;  // 컨텍스트와 상태 버퍼 검증
    if (!msg && len > 0) return AES_ERR_ARG;  // 메시지 버퍼 검증
    size_t off = 0;  // 현재 처리 위치 오프셋
    while (off + 16 <= len) {  // 완전한 16바이트 블록이 남아있는 동안
        aes_status_t st = cbc_mac_update_block(ctx, X, &msg[off]);  // 16바이트 블록 단위로 MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
        off += 16;  // 오프셋을 16바이트 증가
    }
    if (off < len) {  // 마지막 불완전한 블록이 있는 경우
        uint8_t last[16] = { 0 };  // 마지막 블록 버퍼 (0으로 초기화)
        memcpy(last, &msg[off], len - off);  // 남은 데이터 복사
        aes_status_t st = cbc_mac_update_block(ctx, X, last);  // 패딩된 블록으로 MAC 갱신
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }
    return AES_OK;  // 성공 반환
}

/* ---------- 공개 API ---------- */  // 공개 API 함수 섹션 시작

// Nonce, Tag 길이 검사  // 파라미터 유효성 검사 함수
static aes_status_t check_params(size_t nonce_len, size_t tag_len)  // Nonce와 태그 길이 검증
{
    if (nonce_len < 7 || nonce_len > 13) return AES_ERR_IVLEN;  // Nonce 길이는 7~13바이트여야 함
    if (!valid_tag_len(tag_len))          return AES_ERR_ARG;  // 태그 길이가 유효하지 않으면 오류
    return AES_OK;  // 모든 검사 통과 시 성공 반환
}

/* AES-CCM 암호화 + 인증태그 생성 */  // CCM 암호화 함수 설명
aes_status_t ccm_encrypt(  // CCM 암호화 함수
    const aes_ctx_t* ctx,  // AES 컨텍스트 포인터
    const uint8_t* nonce, size_t nonce_len,  // Nonce 버퍼와 길이
    const uint8_t* aad, size_t aad_len,  // 추가 인증 데이터 버퍼와 길이
    const uint8_t* pt, size_t pt_len,  // 평문 버퍼와 길이
    uint8_t* ct,  // 암호문 출력 버퍼
    uint8_t* tag, size_t tag_len)  // 인증 태그 출력 버퍼와 길이
{
    if (!ctx || !nonce || (!pt && pt_len) || (!ct && pt_len) || !tag)  // 필수 포인터 유효성 검사
        return AES_ERR_ARG;  // 잘못된 인자 오류 반환

    aes_status_t st = check_params(nonce_len, tag_len);  // Nonce와 태그 길이 검증
    if (st != AES_OK) return st;  // 검증 실패 시 오류 반환

    const size_t L = 15u - nonce_len;  // message length field size (2~8)  // 메시지 길이 필드 크기 계산

    // 1. CBC-MAC 계산  // 인증 태그 생성을 위한 CBC-MAC 계산
    uint8_t B0[16];  // B0 블록 버퍼
    make_B0(B0, L, tag_len, nonce, nonce_len, pt_len, aad_len > 0);  // B0 블록 생성

    uint8_t X[16];  // CBC-MAC 상태 버퍼
    cbc_mac_init(X);  // MAC 상태 초기화
    st = cbc_mac_update_block(ctx, X, B0);  // B0 블록으로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    st = cbc_mac_aad(ctx, X, aad, aad_len);  // AAD로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    st = cbc_mac_msg(ctx, X, pt ? pt : (const uint8_t*)"", pt_len);  // 평문으로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    // 2. 태그 마스킹 (S0 = E(K, Ctr0), counter=0)  // CBC-MAC 결과를 마스킹하여 최종 태그 생성
    uint8_t ctr0[16], S0[16];  // CTR 블록과 암호화 결과 버퍼
    make_Ctr0(ctr0, L, nonce, nonce_len, 0);  // 카운터 0으로 CTR 블록 생성
    st = aes_encrypt_block_128b_in_128b_out(ctx, ctr0, S0);  // CTR 블록을 AES 암호화하여 S0 생성
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    for (size_t i = 0; i < tag_len; i++)  // 태그 길이만큼 반복
        tag[i] = X[i] ^ S0[i];  // MAC 결과와 S0를 XOR하여 최종 태그 생성

    // 3. CTR 암호화 (counter=1부터)  // 평문을 CTR 모드로 암호화
    if (pt_len > 0) {  // 평문이 있는 경우에만 암호화 수행
        uint8_t ctr_start[16];  // 시작 CTR 블록 버퍼
        make_Ctr0(ctr_start, L, nonce, nonce_len, 1);  // 카운터 1로 CTR 블록 생성
        st = aes_ctr_xor_stream_bytes_in_bytes_out(ctx, ctr_start, L, pt, pt_len, ct);  // CTR 모드로 스트림 암호화
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }
    return AES_OK;  // 성공 반환
}

/* AES-CCM 복호화 + 인증 검증 */  // CCM 복호화 및 검증 함수 설명
aes_status_t ccm_decrypt_and_verify(  // CCM 복호화 및 검증 함수
    const aes_ctx_t* ctx,  // AES 컨텍스트 포인터
    const uint8_t* nonce, size_t nonce_len,  // Nonce 버퍼와 길이
    const uint8_t* aad, size_t aad_len,  // 추가 인증 데이터 버퍼와 길이
    const uint8_t* ct, size_t ct_len,  // 암호문 버퍼와 길이
    const uint8_t* tag, size_t tag_len,  // 인증 태그 버퍼와 길이
    uint8_t* pt)  // 평문 출력 버퍼
{
    if (!ctx || !nonce || (!ct && ct_len) || (!pt && ct_len) || !tag)  // 필수 포인터 유효성 검사
        return AES_ERR_ARG;  // 잘못된 인자 오류 반환

    aes_status_t st = check_params(nonce_len, tag_len);  // Nonce와 태그 길이 검증
    if (st != AES_OK) return st;  // 검증 실패 시 오류 반환

    const size_t L = 15u - nonce_len;  // 메시지 길이 필드 크기 계산

    // 1. CTR 복호화 (counter=1부터)  // 암호문을 CTR 모드로 복호화
    if (ct_len > 0) {  // 암호문이 있는 경우에만 복호화 수행
        uint8_t ctr_start[16];  // 시작 CTR 블록 버퍼
        make_Ctr0(ctr_start, L, nonce, nonce_len, 1);  // 카운터 1로 CTR 블록 생성
        st = aes_ctr_xor_stream_bytes_in_bytes_out(ctx, ctr_start, L, ct, ct_len, pt);  // CTR 모드로 스트림 복호화
        if (st != AES_OK) return st;  // 오류 발생 시 반환
    }

    // 2. CBC-MAC 재계산  // 복호화된 평문으로 MAC 재계산
    uint8_t B0[16], X[16];  // B0 블록과 MAC 상태 버퍼
    make_B0(B0, L, tag_len, nonce, nonce_len, ct_len, aad_len > 0);  // B0 블록 생성 (암호문 길이 사용)

    cbc_mac_init(X);  // MAC 상태 초기화
    st = cbc_mac_update_block(ctx, X, B0);  // B0 블록으로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    st = cbc_mac_aad(ctx, X, aad, aad_len);  // AAD로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    st = cbc_mac_msg(ctx, X, pt ? pt : (const uint8_t*)"", ct_len);  // 복호화된 평문으로 MAC 갱신
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    // 3. 태그 검증  // 계산된 태그와 입력 태그 비교
    uint8_t ctr0[16], S0[16], comp_tag[16];  // CTR 블록, 암호화 결과, 계산된 태그 버퍼
    make_Ctr0(ctr0, L, nonce, nonce_len, 0);  // 카운터 0으로 CTR 블록 생성
    st = aes_encrypt_block_128b_in_128b_out(ctx, ctr0, S0);  // CTR 블록을 AES 암호화하여 S0 생성
    if (st != AES_OK) return st;  // 오류 발생 시 반환

    for (size_t i = 0; i < tag_len; i++)  // 태그 길이만큼 반복
        comp_tag[i] = X[i] ^ S0[i];  // MAC 결과와 S0를 XOR하여 계산된 태그 생성

    uint8_t diff = 0;  // 차이값 누적 변수
    for (size_t i = 0; i < tag_len; i++)  // 태그 길이만큼 반복
        diff |= (uint8_t)(comp_tag[i] ^ tag[i]);  // 각 바이트를 XOR하여 차이 누적

    if (diff != 0) {  // 태그가 일치하지 않는 경우
        if (pt && ct_len) memset(pt, 0, ct_len);  // 보안을 위해 평문 버퍼를 0으로 초기화
        return AES_ERR_STATE; // 인증 실패  // 인증 실패 오류 반환
    }
    return AES_OK;  // 성공 반환
}