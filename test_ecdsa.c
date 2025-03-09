#include "ecdsa_suite_b.h"
#include <openssl/ec.h>
#include <openssl/pem.h>

// 生成 P-256 密钥对
EVP_PKEY* generate_p256_key() {
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int main() {
    // 生成密钥对
    EVP_PKEY* pkey = generate_p256_key();
    if (!pkey) {
        printf("Failed to generate key\n");
        return 1;
    }

    // 导出私钥为 DER 格式（正确指针处理）
    unsigned char priv_key_der[1024];
    unsigned char *tmp = priv_key_der;
    int priv_key_len = i2d_PrivateKey(pkey, &tmp);
    if (priv_key_len <= 0) {
        printf("Failed to export private key\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 初始化签名上下文
    ECDSA_CTX* ctx = ecdsa_ctx_new();
    int ret = ecdsa_sign_init(ctx, priv_key_der, priv_key_len);
    if (ret != ECDSA_OK) {
        printf("Init error: %s\n", ecdsa_get_error(ctx));
        ecdsa_ctx_free(ctx);
        EVP_PKEY_free(pkey);
        return 1;
    }

    // 分步输入数据
    const char* data1 = "Hello, ";
    const char* data2 = "World!";
    ret = ecdsa_sign_update(ctx, (unsigned char*)data1, strlen(data1));
    ret |= ecdsa_sign_update(ctx, (unsigned char*)data2, strlen(data2));
    if (ret != ECDSA_OK) {
        printf("Update error: %s\n", ecdsa_get_error(ctx));
        return 1;
    }

    // 获取签名
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    ret = ecdsa_sign_final(ctx, sig, &sig_len);
    if (ret != ECDSA_OK) {
        printf("Sign error: %s\n", ecdsa_get_error(ctx));
        return 1;
    }

    printf("Signature generated (%zu bytes)\n", sig_len);
    ecdsa_ctx_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}
