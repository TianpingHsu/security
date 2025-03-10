#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>

void handle_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

void print_bn(const char *label, const BIGNUM *bn) {
    char *hex = BN_bn2hex(bn);
    printf("%s:\n%s\n", label, hex);
    OPENSSL_free(hex);
}

void print_ec_point(const EC_GROUP *group, const EC_POINT *point) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    
    if (!EC_POINT_get_affine_coordinates(group, point, x, y, NULL))
        handle_error("无法获取坐标点");
    
    print_bn("公钥 X 坐标", x);
    print_bn("公钥 Y 坐标", y);
    
    BN_free(x);
    BN_free(y);
}

int generate_and_print_ec_key() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *pub_point = NULL;
    const BIGNUM *priv_key = NULL;

    // 生成密钥对
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_paramgen_init(ctx) <= 0)
        handle_error("上下文初始化失败");

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0)
        handle_error("曲线设置失败");

    EVP_PKEY *params = NULL;
    if (EVP_PKEY_paramgen(ctx, &params) <= 0)
        handle_error("参数生成失败");

    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new(params, NULL);
    if (!key_ctx || EVP_PKEY_keygen_init(key_ctx) <= 0)
        handle_error("密钥生成初始化失败");

    if (EVP_PKEY_keygen(key_ctx, &pkey) <= 0)
        handle_error("密钥生成失败");

    // 提取底层 EC_KEY
    if (!(ec_key = EVP_PKEY_get1_EC_KEY(pkey)))
        handle_error("无法获取 EC_KEY");

    // 获取曲线参数
    group = EC_KEY_get0_group(ec_key);
    if (!group) handle_error("无法获取曲线参数");

    // 提取私钥
    priv_key = EC_KEY_get0_private_key(ec_key);
    if (!priv_key) handle_error("无法获取私钥");

    // 提取公钥点
    pub_point = EC_KEY_get0_public_key(ec_key);
    if (!pub_point) handle_error("无法获取公钥点");

    // 打印密钥信息
    print_bn("\n私钥 (标量值)", priv_key);
    print_ec_point(group, pub_point);

    // 验证密钥有效性
    if (!EC_KEY_check_key(ec_key))
        handle_error("密钥验证失败");

    // 清理资源
    EC_KEY_free(ec_key);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);

    return EXIT_SUCCESS;
}

int main() {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    return generate_and_print_ec_key();
}
