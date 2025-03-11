#include "security.hpp"
#include <openssl/rand.h>
#include <cstdio>
#include <cstring>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

bool test_keywrap_128() {
    uint8_t kek[16];
    uint8_t key[32]; // 256-bit key to wrap
    uint8_t wrapped[40]; // 32 + 8 bytes
    uint8_t unwrapped[32];
    
    RAND_bytes(kek, sizeof(kek));
    RAND_bytes(key, sizeof(key));

    size_t wrapped_len;
    bool ret = KeyWrap::aesKeyWrap(SecuritySuite::aesGcm128, kek, sizeof(kek),
                                  key, sizeof(key), wrapped, &wrapped_len);
    if (!ret || wrapped_len != sizeof(key) + 8) return false;

    size_t unwrapped_len;
    ret = KeyWrap::aesKeyUnwrap(SecuritySuite::aesGcm128, kek, sizeof(kek),
                               wrapped, wrapped_len, unwrapped, &unwrapped_len);
    return ret && (unwrapped_len == sizeof(key)) && 
                  (memcmp(key, unwrapped, sizeof(key)) == 0);
}

bool test_keywrap_256() {
    uint8_t kek[32];
    uint8_t key[64]; // 512-bit key
    uint8_t wrapped[72];
    uint8_t unwrapped[64];
    
    RAND_bytes(kek, sizeof(kek));
    RAND_bytes(key, sizeof(key));

    size_t wrapped_len;
    bool ret = KeyWrap::aesKeyWrap(SecuritySuite::ecdhEcdsaAesGcm256Sha384, kek, sizeof(kek),
                                  key, sizeof(key), wrapped, &wrapped_len);
    if (!ret || wrapped_len != sizeof(key) + 8) return false;

    size_t unwrapped_len;
    ret = KeyWrap::aesKeyUnwrap(SecuritySuite::ecdhEcdsaAesGcm256Sha384, kek, sizeof(kek),
                               wrapped, wrapped_len, unwrapped, &unwrapped_len);
    return ret && (unwrapped_len == sizeof(key)) && 
                  (memcmp(key, unwrapped, sizeof(key)) == 0);
}

bool test_invalid_kek() {
    uint8_t invalid_kek[16] = {0};
    uint8_t key[16];
    uint8_t wrapped[24];
    size_t wrapped_len;
    
    // 使用错误的套件测试256-wrap
    return !KeyWrap::aesKeyWrap(SecuritySuite::ecdhEcdsaAesGcm256Sha384,
                               invalid_kek, sizeof(invalid_kek),
                               key, sizeof(key), wrapped, &wrapped_len);
}

int main() {
    printf("AES-128-WRAP test: %s\n", test_keywrap_128() ? "PASS" : "FAIL");
    printf("AES-256-WRAP test: %s\n", test_keywrap_256() ? "PASS" : "FAIL");
    printf("Invalid KEK test: %s\n", test_invalid_kek() ? "PASS" : "FAIL");
    return 0;
}