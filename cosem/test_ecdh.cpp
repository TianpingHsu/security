#include "security.hpp"
#include <cstdio>
#include <vector>
#include <openssl/ec.h>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

bool test_key_exchange_p256() {
    // Alice生成密钥对
    uint8_t alice_priv[32], alice_pub[64];
    if (!Ecdh::generateEcKeyPair(SecuritySuite::ecdhEcdsaAesGcm128Sha256, 
                                alice_pub, alice_priv)) return false;

    // Bob生成密钥对
    uint8_t bob_priv[32], bob_pub[64];
    if (!Ecdh::generateEcKeyPair(SecuritySuite::ecdhEcdsaAesGcm128Sha256, 
                                bob_pub, bob_priv)) return false;

    // Alice计算共享密钥
    uint8_t alice_z[32];
    if (!Ecdh::computeSharedSecret(SecuritySuite::ecdhEcdsaAesGcm128Sha256, 
                                  alice_priv, bob_pub, alice_z)) return false;

    // Bob计算共享密钥
    uint8_t bob_z[32];
    if (!Ecdh::computeSharedSecret(SecuritySuite::ecdhEcdsaAesGcm128Sha256, 
                                  bob_priv, alice_pub, bob_z)) return false;

    return memcmp(alice_z, bob_z, 32) == 0;
}

bool test_sskdf_p256() {
    uint8_t shared_z[32] = {0}; // 测试用固定共享密钥
    uint8_t other_info[] = "TestSSKDF";
    uint8_t derived_key[16];

    if (!Ecdh::sskdf(SecuritySuite::ecdhEcdsaAesGcm128Sha256, 
                    shared_z, other_info, sizeof(other_info)-1, derived_key)) 
        return false;

    // 验证已知输出（需替换为实际测试向量）
    const uint8_t expected[] = {0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
                               0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
    return memcmp(derived_key, expected, 16) == 0;
}

int main() {
    printf("P-256 Key Exchange test: %s\n", test_key_exchange_p256() ? "PASS" : "FAIL");
    printf("SSKDF test: %s\n", test_sskdf_p256() ? "PASS" : "FAIL");
    return 0;
}