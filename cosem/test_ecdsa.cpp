#include "security.hpp"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <cstdio>
#include <vector>

bool test_ecdsa_sign_verify() {
    // 生成密钥对
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) return false;
    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        return false;
    }

    // 导出私钥（32字节）
    const BIGNUM* priv = EC_KEY_get0_private_key(ec_key);
    std::vector<uint8_t> privateKey(32);
    BN_bn2bin(priv, privateKey.data());

    // 导出公钥（未压缩格式04||X||Y，共65字节）
    const EC_POINT* pub = EC_KEY_get0_public_key(ec_key);
    std::vector<uint8_t> publicKey(65);
    if (EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub, 
                          POINT_CONVERSION_UNCOMPRESSED,
                          publicKey.data(), publicKey.size(),
                          nullptr) != publicKey.size()) {
        EC_KEY_free(ec_key);
        return false;
    }
    EC_KEY_free(ec_key); // 不再需要原始EC_KEY

    // === 签名流程 ===
    Ecdsa::Context sign_ctx{SecuritySuite::ecdhEcdsaAesGcm128Sha256};
    if (!Ecdsa::initSign(sign_ctx, privateKey.data())) return false;

    const char* parts[] = {"DataPart1", "DataPart2"};
    for (auto& part : parts) {
        if (!Ecdsa::signUpdate(sign_ctx, 
                             reinterpret_cast<const uint8_t*>(part),
                             strlen(part))) {
            return false;
        }
    }

    uint8_t sig[128];
    if (!Ecdsa::signFinal(sign_ctx, sig)) return false;

    // === 验证流程 ===
    Ecdsa::Context verify_ctx{SecuritySuite::ecdhEcdsaAesGcm128Sha256};
    if (!Ecdsa::initVerify(verify_ctx, publicKey.data())) return false;

    // 分段验证相同数据
    for (auto& part : parts) {
        if (!Ecdsa::verifyUpdate(verify_ctx, 
                                reinterpret_cast<const uint8_t*>(part),
                                strlen(part))) {
            return false;
        }
    }

    // 确定签名长度（P-256的ECDSA签名是64字节）
    const size_t expected_sig_len = 64;
    
    // 验证签名
    bool verify_result = Ecdsa::verifyFinal(verify_ctx, sig, expected_sig_len);

    // === 附加测试：篡改签名应失败 ===
    if (verify_result) {
        uint8_t corrupted_sig[128];
        memcpy(corrupted_sig, sig, expected_sig_len);
        corrupted_sig[0] ^= 0xFF; // 修改第一个字节
        
        Ecdsa::Context corrupt_ctx{SecuritySuite::ecdhEcdsaAesGcm128Sha256};
        if (!Ecdsa::initVerify(corrupt_ctx, publicKey.data())) return false;
        for (auto& part : parts) {
            Ecdsa::verifyUpdate(corrupt_ctx, 
                               reinterpret_cast<const uint8_t*>(part),
                               strlen(part));
        }
        bool should_fail = Ecdsa::verifyFinal(corrupt_ctx, corrupted_sig, expected_sig_len);
        verify_result = verify_result && !should_fail;
    }

    return verify_result;
}

int main() {
    printf("ECDSA Sign/Verify test: %s\n", 
          test_ecdsa_sign_verify() ? "PASS" : "FAIL");
    return 0;
}