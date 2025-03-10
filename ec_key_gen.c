#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>

void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void print_pem(BIO *bio) {
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0 && data) {
        printf("%.*s", (int)len, data);
    }
}

int generate_ec_keypair() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIO *bio_priv = NULL, *bio_pub = NULL;

    // 创建参数生成上下文
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) handle_error("无法创建PKEY上下文");

    // 初始化参数生成
    if (EVP_PKEY_paramgen_init(ctx) <= 0)
        handle_error("参数生成初始化失败");

    // 设置曲线参数（P-256）
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
        handle_error("无法设置EC曲线参数");

    // 生成参数
    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(ctx, &params) <= 0)
        handle_error("参数生成失败");

    // 创建密钥生成上下文
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(params, NULL);
    if (!key_ctx) handle_error("无法创建密钥生成上下文");

    // 初始化密钥生成
    if (EVP_PKEY_keygen_init(key_ctx) <= 0)
        handle_error("密钥生成初始化失败");

    // 生成密钥对
    if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0)
        handle_error("密钥生成失败");

    // 创建BIO对象用于输出
    bio_priv = BIO_new(BIO_s_mem());
    bio_pub = BIO_new(BIO_s_mem());
    if (!bio_priv || !bio_pub) handle_error("无法创建BIO对象");

    // 输出私钥PEM格式
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL))
        handle_error("无法写入私钥PEM");

    // 输出公钥PEM格式
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey))
        handle_error("无法写入公钥PEM");

    // 打印结果
    printf("EC-P256 Private Key:\n");
    print_pem(bio_priv);
    printf("\nEC-P256 Public Key:\n");
    print_pem(bio_pub);

    // 清理资源
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);
    BIO_free_all(bio_priv);
    BIO_free_all(bio_pub);

    return EXIT_SUCCESS;
}

int main() {
    // 初始化OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    // 生成密钥对
    if (generate_ec_keypair() != EXIT_SUCCESS) {
        handle_error("密钥对生成失败");
    }

    return EXIT_SUCCESS;
}
