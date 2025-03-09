#include "ecdsa_suite_b.h"
#include <openssl/err.h>
#include <string.h>

struct ecdsa_ctx {
    EVP_MD_CTX* md_ctx;
    EVP_PKEY* priv_key;
    char error[256];
};

ECDSA_CTX* ecdsa_ctx_new() {
    ECDSA_CTX* ctx = malloc(sizeof(ECDSA_CTX));
    if (!ctx) return NULL;
    
    memset(ctx, 0, sizeof(ECDSA_CTX));
    ctx->md_ctx = EVP_MD_CTX_new();
    if (!ctx->md_ctx) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

void ecdsa_ctx_free(ECDSA_CTX* ctx) {
    if (ctx) {
        EVP_MD_CTX_free(ctx->md_ctx);
        EVP_PKEY_free(ctx->priv_key);
        free(ctx);
    }
}

int ecdsa_sign_init(ECDSA_CTX* ctx, const unsigned char* priv_key, size_t priv_key_len) {
    // 从 DER 格式加载私钥（示例仅支持 DER 格式）
    BIO* bio = BIO_new_mem_buf(priv_key, priv_key_len);
    if (!bio) {
        snprintf(ctx->error, sizeof(ctx->error), "BIO_new_mem_buf failed");
        return ECDSA_ERR_INIT;
    }
    
    ctx->priv_key = d2i_PrivateKey_bio(bio, NULL);
    BIO_free(bio);
    
    if (!ctx->priv_key) {
        snprintf(ctx->error, sizeof(ctx->error), "Failed to load private key");
        return ECDSA_ERR_INIT;
    }
    
    // 初始化签名上下文（使用 SHA-256 哈希）
    if (EVP_DigestSignInit(ctx->md_ctx, NULL, EVP_sha256(), NULL, ctx->priv_key) != 1) {
        snprintf(ctx->error, sizeof(ctx->error), "EVP_DigestSignInit failed");
        return ECDSA_ERR_INIT;
    }
    
    return ECDSA_OK;
}

int ecdsa_sign_update(ECDSA_CTX* ctx, const unsigned char* data, size_t data_len) {
    if (EVP_DigestSignUpdate(ctx->md_ctx, data, data_len) != 1) {
        snprintf(ctx->error, sizeof(ctx->error), "EVP_DigestSignUpdate failed");
        return ECDSA_ERR_UPDATE;
    }
    return ECDSA_OK;
}

int ecdsa_sign_final(ECDSA_CTX* ctx, unsigned char* sig, size_t* sig_len) {
    if (EVP_DigestSignFinal(ctx->md_ctx, sig, sig_len) != 1) {
        snprintf(ctx->error, sizeof(ctx->error), "EVP_DigestSignFinal failed");
        return ECDSA_ERR_SIGN;
    }
    return ECDSA_OK;
}

const char* ecdsa_get_error(const ECDSA_CTX* ctx) {
    if (!ctx) return "Context is NULL";
    if (ctx->error[0] != '\0') return ctx->error;
    return "No error";
}
