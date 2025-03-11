#include "security.hpp"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>

//----------------------------------------SHA2-------------------------------------------------
bool Sha2::init(Context& ctx) {
    switch(ctx.suite) {
        case SecuritySuite::aesGcm128:
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            ctx.hash_type = EVP_sha256();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            ctx.hash_type = EVP_sha384();
            break;
        default:
            return false;
    }

    ctx.evp_ctx = EVP_MD_CTX_new();
    if (!ctx.evp_ctx) return false;

    return EVP_DigestInit_ex(ctx.evp_ctx, ctx.hash_type, nullptr) == 1;
}

bool Sha2::update(Context& ctx, const std::uint8_t* data, std::size_t len) {
    return EVP_DigestUpdate(ctx.evp_ctx, data, len) == 1;
}

bool Sha2::final(Context& ctx, std::uint8_t* hash) {
    unsigned int digest_len;
    bool ret = EVP_DigestFinal_ex(ctx.evp_ctx, hash, &digest_len) == 1;
    EVP_MD_CTX_free(ctx.evp_ctx);
    ctx.evp_ctx = nullptr;
    return ret;
}

bool Sha2::hash(SecuritySuite suite, const std::uint8_t* data, std::size_t len, std::uint8_t* hash) {
    Context ctx{suite, nullptr, nullptr};
    if (!init(ctx)) return false;
    if (!update(ctx, data, len)) return false;
    return final(ctx, hash);
}


//-----------------------------------------AES-GCM--------------------------------------------------------

bool AesGcm::init(Context& ctx, const std::uint8_t* key, const std::uint8_t* iv, Mode mode) {
    const EVP_CIPHER* cipher = nullptr;
    switch(ctx.suite) {
        case SecuritySuite::aesGcm128:
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            cipher = EVP_aes_128_gcm();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            cipher = EVP_aes_256_gcm();
            break;
        default:
            return false;
    }

    // 拷贝密钥和IV
    size_t key_len = EVP_CIPHER_key_length(cipher);
    memcpy(ctx.key, key, key_len);
    memcpy(ctx.iv, iv, gcmIvLength);
    ctx.mode = mode;
    ctx.aad_processed = false;
    ctx.final_called = false;

    // 初始化上下文
    ctx.evp_ctx = EVP_CIPHER_CTX_new();
    if (!ctx.evp_ctx) return false;

    int ret = EVP_CipherInit_ex(ctx.evp_ctx, cipher, nullptr, 
                               ctx.key, ctx.iv, 
                               (mode == Mode::encrypt) ? 1 : 0);
    return ret == 1;
}

bool AesGcm::updateAad(Context& ctx, const std::uint8_t* aad, std::size_t len) {
    if (ctx.final_called || ctx.aad_processed) return false;
    
    int outlen;
    int ret = EVP_CipherUpdate(ctx.evp_ctx, nullptr, &outlen, aad, len);
    ctx.aad_processed = (ret == 1);
    return ctx.aad_processed;
}

bool AesGcm::update(Context& ctx, const std::uint8_t* data, std::size_t len, 
                   const std::uint8_t* out, std::size_t* outLen) {
    if (ctx.final_called) return false;
    
    int block_size = EVP_CIPHER_CTX_get_block_size(ctx.evp_ctx);
    *outLen = len + block_size - 1; // 预留足够的输出空间
    
    return EVP_CipherUpdate(ctx.evp_ctx, 
                           const_cast<uint8_t*>(out), 
                           reinterpret_cast<int*>(outLen), 
                           data, len) == 1;
}

bool AesGcm::final(Context& ctx, const std::uint8_t* out, std::size_t* outLen, 
                  const std::uint8_t* tag) {
    if (ctx.final_called) return false;
    
    int ret = EVP_CipherFinal_ex(ctx.evp_ctx, 
                                const_cast<uint8_t*>(out), 
                                reinterpret_cast<int*>(outLen));
    
    if (ret == 1 && ctx.mode == Mode::encrypt) {
        EVP_CIPHER_CTX_ctrl(ctx.evp_ctx, EVP_CTRL_GCM_GET_TAG, 
                           gcmTagLength, const_cast<uint8_t*>(tag));
    }
    
    ctx.final_called = true;
    EVP_CIPHER_CTX_free(ctx.evp_ctx);
    ctx.evp_ctx = nullptr;
    return ret == 1;
}

bool AesGcm::setTag(Context& ctx, const std::uint8_t* tag) {
    if (ctx.mode != Mode::decrypt) return false;
    return EVP_CIPHER_CTX_ctrl(ctx.evp_ctx, EVP_CTRL_GCM_SET_TAG, 
                              gcmTagLength, const_cast<uint8_t*>(tag)) == 1;
}

bool AesGcm::gmac(SecuritySuite suite, const std::uint8_t* key, 
                 const std::uint8_t* iv, const std::uint8_t* data, 
                 std::size_t dataLen, std::uint8_t* tag) {
    Context ctx{suite, nullptr, Mode::encrypt, {}, {}, false, false};
    if (!init(ctx, key, iv, Mode::encrypt)) return false;
    if (!updateAad(ctx, data, dataLen)) return false;
    std::size_t dummy_len;
    std::uint8_t dummy;
    return update(ctx, nullptr, 0, &dummy, &dummy_len) && final(ctx, nullptr, &dummy_len, tag);
}

bool KeyWrap::aesKeyWrap(SecuritySuite suite, const unsigned char* kek, std::size_t kekLen,
                        const unsigned char* input, std::size_t inputLen,
                        unsigned char* output, std::size_t* outputLen) {
    const EVP_CIPHER* cipher = nullptr;
    switch (suite) {
        case SecuritySuite::aesGcm128:
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            cipher = EVP_aes_128_wrap();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            cipher = EVP_aes_256_wrap();
            break;
        default:
            return false;
    }

    if (kekLen != static_cast<size_t>(EVP_CIPHER_key_length(cipher))) {
        return false;
    }

    if (inputLen % 8 != 0) { // RFC 3394 requires 64-bit blocks
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, kek, nullptr);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outl;
    ret = EVP_EncryptUpdate(ctx, output, &outl, input, inputLen);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *outputLen = outl;

    ret = EVP_EncryptFinal_ex(ctx, output + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);
    if (ret != 1) {
        return false;
    }
    *outputLen += outl;

    return true;
}

bool KeyWrap::aesKeyUnwrap(SecuritySuite suite, const unsigned char* kek, std::size_t kekLen,
                          const unsigned char* input, std::size_t inputLen,
                          unsigned char* output, std::size_t* outputLen) {
    const EVP_CIPHER* cipher = nullptr;
    switch (suite) {
        case SecuritySuite::aesGcm128:
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            cipher = EVP_aes_128_wrap();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            cipher = EVP_aes_256_wrap();
            break;
        default:
            return false;
    }

    if (kekLen != static_cast<size_t>(EVP_CIPHER_key_length(cipher))) {
        return false;
    }

    if (inputLen % 8 != 0 || inputLen < 16) { // Minimum 2 blocks
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, kek, nullptr);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    int outl;
    ret = EVP_DecryptUpdate(ctx, output, &outl, input, inputLen);
    if (ret != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    *outputLen = outl;

    ret = EVP_DecryptFinal_ex(ctx, output + outl, &outl);
    EVP_CIPHER_CTX_free(ctx);
    if (ret != 1) {
        return false;
    }
    *outputLen += outl;

    return true;
}

bool Ecdsa::initSign(Context& ctx, const std::uint8_t* privateKey) {
    // 根据套件选择曲线和摘要算法
    int nid;
    switch(ctx.suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            nid = NID_X9_62_prime256v1;
            ctx.digest = EVP_sha256();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            nid = NID_secp384r1;
            ctx.digest = EVP_sha384();
            break;
        default:
            return false;
    }

    // 从字节加载私钥
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) return false;

    BIGNUM* bn = BN_bin2bn(privateKey, EC_GROUP_get_degree(EC_KEY_get0_group(ec_key))/8, NULL);
    if (!bn || !EC_KEY_set_private_key(ec_key, bn)) {
        EC_KEY_free(ec_key);
        BN_free(bn);
        return false;
    }

    ctx.pkey = EVP_PKEY_new();
    if (!EVP_PKEY_set1_EC_KEY(ctx.pkey, ec_key)) {
        EC_KEY_free(ec_key);
        return false;
    }

    // 初始化签名上下文
    ctx.pkey_ctx = EVP_PKEY_CTX_new(ctx.pkey, nullptr);
    ctx.md_ctx = EVP_MD_CTX_new();
    
    return EVP_DigestSignInit(ctx.md_ctx, &ctx.pkey_ctx, 
                             ctx.digest, nullptr, ctx.pkey) == 1;
}

bool Ecdsa::signUpdate(Context& ctx, const std::uint8_t* data, std::size_t len) {
    return EVP_DigestSignUpdate(ctx.md_ctx, data, len) == 1;
}

bool Ecdsa::signFinal(Context& ctx, std::uint8_t* signature) {
    size_t siglen;
    if (EVP_DigestSignFinal(ctx.md_ctx, nullptr, &siglen) != 1) 
        return false;
    
    bool ret = EVP_DigestSignFinal(ctx.md_ctx, signature, &siglen) == 1;
    
    EVP_MD_CTX_free(ctx.md_ctx);
    EVP_PKEY_CTX_free(ctx.pkey_ctx);
    EVP_PKEY_free(ctx.pkey);
    return ret;
}

bool Ecdsa::initVerify(Context& ctx, const std::uint8_t* publicKey) {
    // 根据套件选择曲线和摘要算法
    int nid;
    switch(ctx.suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            nid = NID_X9_62_prime256v1;
            ctx.digest = EVP_sha256();
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            nid = NID_secp384r1;
            ctx.digest = EVP_sha384();
            break;
        default:
            return false;
    }

    // 创建EC_KEY并设置公钥
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) return false;

    // 创建椭圆曲线群结构
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (!pub_point) {
        EC_KEY_free(ec_key);
        return false;
    }

    // 解析公钥字节（假设为未压缩格式04||X||Y）
    size_t key_len = (ctx.suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? 64 : 96;
    if (EC_POINT_oct2point(group, pub_point, publicKey, key_len + 1, nullptr) != 1) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return false;
    }

    // 设置公钥到EC_KEY
    if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return false;
    }
    EC_POINT_free(pub_point);

    // 创建EVP_PKEY并关联EC_KEY
    ctx.pkey = EVP_PKEY_new();
    if (EVP_PKEY_set1_EC_KEY(ctx.pkey, ec_key) != 1) {
        EC_KEY_free(ec_key);
        return false;
    }
    EC_KEY_free(ec_key);

    // 初始化验证上下文
    ctx.md_ctx = EVP_MD_CTX_new();
    if (!ctx.md_ctx) return false;

    return EVP_DigestVerifyInit(ctx.md_ctx, &ctx.pkey_ctx, 
                               ctx.digest, nullptr, ctx.pkey) == 1;
}

bool Ecdsa::verifyUpdate(Context& ctx, const std::uint8_t* data, std::size_t len) {
    return EVP_DigestVerifyUpdate(ctx.md_ctx, data, len) == 1;
}

bool Ecdsa::verifyFinal(Context& ctx, const std::uint8_t* signature, std::size_t sigLen) {
    int ret = EVP_DigestVerifyFinal(ctx.md_ctx, signature, sigLen);
    
    EVP_MD_CTX_free(ctx.md_ctx);
    EVP_PKEY_CTX_free(ctx.pkey_ctx);
    EVP_PKEY_free(ctx.pkey);
    return ret == 1;
}

bool Ecdh::randBytes(unsigned char *buf, std::size_t len) {
    return RAND_bytes(buf, len) == 1;
}

bool Ecdh::generateEcKeyPair(SecuritySuite suite, std::uint8_t* publicKey, std::uint8_t* privateKey) {
    int nid;
    size_t priv_len, pub_len;

    switch (suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            nid = NID_X9_62_prime256v1;
            priv_len = 32;
            pub_len = 64; // 未压缩格式去掉04头
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            nid = NID_secp384r1;
            priv_len = 48;
            pub_len = 96;
            break;
        default:
            return false;
    }

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) return false;

    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        return false;
    }

    // 导出私钥
    const BIGNUM* priv = EC_KEY_get0_private_key(ec_key);
    if (BN_bn2binpad(priv, privateKey, priv_len) != priv_len) {
        EC_KEY_free(ec_key);
        return false;
    }

    // 导出公钥（去掉04头）
    const EC_POINT* pub = EC_KEY_get0_public_key(ec_key);
    if (EC_POINT_point2oct(EC_KEY_get0_group(ec_key), pub, 
                          POINT_CONVERSION_UNCOMPRESSED, 
                          publicKey, pub_len, nullptr) != pub_len + 1) {
        EC_KEY_free(ec_key);
        return false;
    }

    EC_KEY_free(ec_key);
    return true;
}

bool Ecdh::computeSharedSecret(SecuritySuite suite, const std::uint8_t* d, 
                              const std::uint8_t* Q, std::uint8_t* sharedSecretZ) {
    int nid;
    size_t secret_len;

    switch (suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            nid = NID_X9_62_prime256v1;
            secret_len = 32;
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            nid = NID_secp384r1;
            secret_len = 48;
            break;
        default:
            return false;
    }

    EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) return false;

    // 导入私钥
    BIGNUM* priv = BN_bin2bn(d, secret_len, nullptr);
    if (!EC_KEY_set_private_key(ec_key, priv)) {
        BN_free(priv);
        EC_KEY_free(ec_key);
        return false;
    }
    BN_free(priv);

    // 导入对方公钥
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    EC_POINT* pub_point = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, pub_point, Q, secret_len * 2, nullptr) != 1) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return false;
    }

    // 计算共享密钥
    int field_size = EC_GROUP_get_degree(group);
    size_t z_len = (field_size + 7) / 8;
    if (ECDH_compute_key(sharedSecretZ, z_len, pub_point, ec_key, nullptr) != z_len) {
        EC_POINT_free(pub_point);
        EC_KEY_free(ec_key);
        return false;
    }

    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    return true;
}

bool Ecdh::sskdf(SecuritySuite suite, unsigned char* sharedSecretZ, 
                unsigned char* otherInfo, std::size_t otherInfoLen, 
                unsigned char* key) {
    const EVP_MD* md;
    size_t key_len;

    switch (suite) {
        case SecuritySuite::ecdhEcdsaAesGcm128Sha256:
            md = EVP_sha256();
            key_len = 16;
            break;
        case SecuritySuite::ecdhEcdsaAesGcm256Sha384:
            md = EVP_sha384();
            key_len = 32;
            break;
        default:
            return false;
    }

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "SSKDF", nullptr);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) return false;

    OSSL_PARAM params[4] = {
        OSSL_PARAM_construct_utf8_string("digest", (char*)EVP_MD_get0_name(md), 0),
        OSSL_PARAM_construct_octet_string("secret", sharedSecretZ, key_len * 2),
        OSSL_PARAM_construct_octet_string("info", otherInfo, otherInfoLen),
        OSSL_PARAM_construct_end()
    };

    size_t out_len = key_len;
    bool ret = EVP_KDF_derive(kctx, key, out_len, params) == 1;
    EVP_KDF_CTX_free(kctx);
    return ret;
}

