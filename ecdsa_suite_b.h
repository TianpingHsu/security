#ifndef ECDSA_SUITE_B_H
#define ECDSA_SUITE_B_H

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stddef.h>

// 错误码定义
#define ECDSA_OK 0
#define ECDSA_ERR_INIT -1
#define ECDSA_ERR_UPDATE -2
#define ECDSA_ERR_SIGN -3
#define ECDSA_ERR_KEY -4

// 上下文结构体（不透明类型）
typedef struct ecdsa_ctx ECDSA_CTX;

// 创建/销毁上下文
ECDSA_CTX* ecdsa_ctx_new(void);
void ecdsa_ctx_free(ECDSA_CTX* ctx);

// 初始化签名（需传入私钥）
int ecdsa_sign_init(ECDSA_CTX* ctx, const unsigned char* priv_key, size_t priv_key_len);

// 分步更新数据（支持多次调用）
int ecdsa_sign_update(ECDSA_CTX* ctx, const unsigned char* data, size_t data_len);

// 完成签名，输出结果
int ecdsa_sign_final(ECDSA_CTX* ctx, unsigned char* sig, size_t* sig_len);

// 获取错误信息
const char* ecdsa_get_error(const ECDSA_CTX* ctx);

#endif
