// ecdsa.cpp
#include "crypto.hpp"
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/platform.h>

struct Ecdsa::ContextImpl {
    SecuritySuite suite;
    mbedtls_ecdsa_context ctx;
    Sha2::Context hash_ctx;
    bool is_signing = false;
};

bool Ecdsa::initSign(Context& ctx, const uint8_t* privateKey) {
    auto impl = reinterpret_cast<ContextImpl*>(&ctx);
    impl->is_signing = true;
    
    mbedtls_ecdsa_init(&impl->ctx);

    // 设置椭圆曲线
    mbedtls_ecp_group_id grp_id;
    switch (impl->suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256: 
            grp_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            grp_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        default: return false;
    }

    if (mbedtls_ecp_group_load(&impl->ctx.grp, grp_id) != 0)
        return false;

    // 导入私钥
    size_t key_len = (impl->suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? 32 : 48;
    if (mbedtls_mpi_read_binary(&impl->ctx.d, privateKey, key_len) != 0)
        return false;

    // 初始化哈希上下文
    impl->hash_ctx.suite = impl->suite;
    return Sha2::init(impl->hash_ctx);
}

bool Ecdsa::signFinal(Context& ctx, uint8_t* signature) {
    auto impl = reinterpret_cast<ContextImpl*>(&ctx);
    
    // 完成哈希计算
    uint8_t digest[64];
    size_t digest_len;
    switch (impl->suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256: digest_len = 32; break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384: digest_len = 48; break;
        default: return false;
    }
    if (!Sha2::final(impl->hash_ctx, digest)) return false;

    // 签名
    size_t sig_len;
    return mbedtls_ecdsa_write_signature(&impl->ctx, MBEDTLS_MD_SHA256, // 实际使用的哈希算法由上下文保证
                                        digest, digest_len,
                                        signature, &sig_len,
                                        mbedtls_ctr_drbg_random, nullptr) == 0;
}

bool Ecdsa::initVerify(Context& ctx, const uint8_t* publicKey) {
    auto impl = reinterpret_cast<ContextImpl*>(&ctx);
    impl->is_signing = false;

    mbedtls_ecdsa_init(&impl->ctx);

    // 设置椭圆曲线
    mbedtls_ecp_group_id grp_id;
    switch (impl->suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            grp_id = MBEDTLS_ECP_DP_SECP256R1;
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            grp_id = MBEDTLS_ECP_DP_SECP384R1;
            break;
        default: return false;
    }

    if (mbedtls_ecp_group_load(&impl->ctx.grp, grp_id) != 0)
        return false;

    // 解析公钥（格式：04||X||Y）
    size_t key_size;
    switch (grp_id) {
        case MBEDTLS_ECP_DP_SECP256R1: key_size = 65; break;  // 1 + 32*2
        case MBEDTLS_ECP_DP_SECP384R1: key_size = 97; break;  // 1 + 48*2
        default: return false;
    }

    // 验证公钥格式头（必须是未压缩格式）
    if (publicKey[0] != 0x04) return false;

    // 导入公钥坐标
    size_t coord_len = (key_size - 1) / 2;
    int ret = mbedtls_mpi_read_binary(&impl->ctx.Q.X, publicKey + 1, coord_len);
    if (ret != 0) return false;

    ret = mbedtls_mpi_read_binary(&impl->ctx.Q.Y, publicKey + 1 + coord_len, coord_len);
    if (ret != 0) return false;

    // 设置Z坐标为1
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&impl->ctx.Q.Z, 1));

    // 初始化哈希上下文
    impl->hash_ctx.suite = impl->suite;
    return Sha2::init(impl->hash_ctx);
}

bool Ecdsa::verifyUpdate(Context& ctx, const uint8_t* data, size_t len) {
    auto impl = reinterpret_cast<ContextImpl*>(&ctx);
    return Sha2::update(impl->hash_ctx, data, len);
}

bool Ecdsa::verifyFinal(Context& ctx, const uint8_t* signature, size_t sigLen) {
    auto impl = reinterpret_cast<ContextImpl*>(&ctx);

    // 完成哈希计算
    uint8_t digest[64];
    size_t digest_len;
    switch (impl->suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256: digest_len = 32; break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384: digest_len = 48; break;
        default: return false;
    }
    if (!Sha2::final(impl->hash_ctx, digest)) return false;

    // 验证签名
    return mbedtls_ecdsa_read_signature(&impl->ctx,
                                       digest, digest_len,
                                       signature, sigLen) == 0;
}

// 上下文清理函数（需要补充）
Ecdsa::Context::~Context() {
    auto impl = reinterpret_cast<ContextImpl*>(this);
    mbedtls_ecdsa_free(&impl->ctx);
}



