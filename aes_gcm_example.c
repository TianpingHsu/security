#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 定义常量
#define KEY_SIZE 16  // AES-128 key size
#define IV_SIZE 12   // GCM recommended IV size
#define TAG_SIZE 16  // GCM tag size

// 定义上下文结构体
typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    int encrypted_len;
    int final_len;
} AES_GCM_CTX;

// 初始化AES-GCM上下文
int aes_gcm_init(AES_GCM_CTX *aes_ctx, const unsigned char *key, const unsigned char *iv) {
    if (!aes_ctx || !key || !iv) return 0;

    aes_ctx->ctx = EVP_CIPHER_CTX_new();
    if (!aes_ctx->ctx) return 0;

    memcpy(aes_ctx->key, key, KEY_SIZE);
    memcpy(aes_ctx->iv, iv, IV_SIZE);

    if (!EVP_EncryptInit_ex(aes_ctx->ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(aes_ctx->ctx);
        return 0;
    }

    if (!EVP_EncryptInit_ex(aes_ctx->ctx, NULL, NULL, aes_ctx->key, aes_ctx->iv)) {
        EVP_CIPHER_CTX_free(aes_ctx->ctx);
        return 0;
    }

    aes_ctx->encrypted_len = 0;
    aes_ctx->final_len = 0;

    return 1;
}

// 分段加密
int aes_gcm_update(AES_GCM_CTX *aes_ctx, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    if (!aes_ctx || !plaintext || !ciphertext) return 0;

    if (!EVP_EncryptUpdate(aes_ctx->ctx, ciphertext, &aes_ctx->encrypted_len, plaintext, plaintext_len)) {
        return 0;
    }

    return 1;
}

// 结束加密并生成认证标签
int aes_gcm_final(AES_GCM_CTX *aes_ctx, unsigned char *ciphertext, unsigned char *tag) {
    if (!aes_ctx || !ciphertext || !tag) return 0;

    if (!EVP_EncryptFinal_ex(aes_ctx->ctx, ciphertext + aes_ctx->encrypted_len, &aes_ctx->final_len)) {
        return 0;
    }

    if (!EVP_CIPHER_CTX_ctrl(aes_ctx->ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
        return 0;
    }

    return 1;
}

// 清理上下文
void aes_gcm_cleanup(AES_GCM_CTX *aes_ctx) {
    if (aes_ctx && aes_ctx->ctx) {
        EVP_CIPHER_CTX_free(aes_ctx->ctx);
        aes_ctx->ctx = NULL;
    }
}

// 测试代码
int main() {
    AES_GCM_CTX aes_ctx;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char plaintext[] = "This is a secret message.";
    unsigned char ciphertext[128];
    unsigned char tag[TAG_SIZE];

    // 生成随机密钥和IV
    if (!RAND_bytes(key, KEY_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
        fprintf(stderr, "Error generating random key or IV\n");
        return 1;
    }

    // 初始化AES-GCM上下文
    if (!aes_gcm_init(&aes_ctx, key, iv)) {
        fprintf(stderr, "Error initializing AES-GCM context\n");
        return 1;
    }

    // 分段加密明文
    int plaintext_len = strlen((char *)plaintext);
    int chunk_size = 10; // 每次加密10字节
    int offset = 0;

    while (offset < plaintext_len) {
        int len = (plaintext_len - offset) > chunk_size ? chunk_size : (plaintext_len - offset);
        if (!aes_gcm_update(&aes_ctx, plaintext + offset, len, ciphertext + offset)) {
            fprintf(stderr, "Error encrypting data\n");
            aes_gcm_cleanup(&aes_ctx);
            return 1;
        }
        offset += len;
    }

    // 结束加密并生成认证标签
    if (!aes_gcm_final(&aes_ctx, ciphertext, tag)) {
        fprintf(stderr, "Error finalizing encryption\n");
        aes_gcm_cleanup(&aes_ctx);
        return 1;
    }

    // 输出密文和认证标签
    printf("Ciphertext: ");
    for (int i = 0; i < plaintext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("Tag: ");
    for (int i = 0; i < TAG_SIZE; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    // 清理上下文
    aes_gcm_cleanup(&aes_ctx);

    return 0;
}
