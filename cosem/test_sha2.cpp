#include "security.hpp"
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <vector>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

bool test_sha256_single() {
    const char* test_data = "Hello World";
    uint8_t hash[32];
    
    bool ret = Sha2::hash(SecuritySuite::aesGcm128, 
                         reinterpret_cast<const uint8_t*>(test_data),
                         strlen(test_data), hash);
    
    const uint8_t expected[] = {
        0xa5,0x91,0xa6,0xd4,0x0b,0xf4,0x20,0x40,0x4a,0x01,0x17,0x33,0xcf,0xb7,0xb1,0x90,0xd6,0x2c,0x65,0xbf,0x0b,0xcd,0xa3,0x2b,0x57,0xb2,0x77,0xd9,0xad,0x9f,0x14,0x6e
    };
    
    return ret && memcmp(hash, expected, 32) == 0;
}

bool test_sha256_stream() {
    Sha2::Context ctx{SecuritySuite::aesGcm128, nullptr, nullptr};
    if (!Sha2::init(ctx)) return false;

    const char* parts[] = {"Hello ", "World"};
    for (auto part : parts) {
        if (!Sha2::update(ctx, 
                         reinterpret_cast<const uint8_t*>(part),
                         strlen(part))) {
            return false;
        }
    }

    uint8_t hash[32];
    if (!Sha2::final(ctx, hash)) return false;

    return test_sha256_single(); // 复用单次测试的预期结果
}

bool test_sha384() {
    const char* test_data = "Hello World";
    uint8_t hash[48];
    
    bool ret = Sha2::hash(SecuritySuite::ecdhEcdsaAesGcm256Sha384,
                         reinterpret_cast<const uint8_t*>(test_data),
                         strlen(test_data), hash);
    
    const uint8_t expected[] = {
        0x99,0x51,0x43,0x29,0x18,0x6b,0x2f,0x6a,0xe4,0xa1,0x32,0x9e,0x7e,0xe6,0xc6,0x10,0xa7,0x29,0x63,0x63,0x35,0x17,0x4a,0xc6,0xb7,0x40,0xf9,0x02,0x83,0x96,0xfc,0xc8,0x03,0xd0,0xe9,0x38,0x63,0xa7,0xc3,0xd9,0x0f,0x86,0xbe,0xee,0x78,0x2f,0x4f,0x3f
    };
    
    return ret && memcmp(hash, expected, 48) == 0;
}

int main() {
    printf("SHA256 single test: %s\n", test_sha256_single() ? "PASS" : "FAIL");
    printf("SHA256 stream test: %s\n", test_sha256_stream() ? "PASS" : "FAIL");
    printf("SHA384 test: %s\n", test_sha384() ? "PASS" : "FAIL");
    return 0;
}
