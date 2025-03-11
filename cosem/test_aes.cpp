#include "security.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

bool test_encrypt_decrypt() {
    const char* plaintext = "Secret Message";
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[12] = {0};

    // 加密
    AesGcm::Context enc_ctx{SecuritySuite::aesGcm128};
    if (!AesGcm::init(enc_ctx, key, iv, AesGcm::Mode::encrypt)) return false;
    
    uint8_t ciphertext[128];
    size_t out_len;
    if (!AesGcm::update(enc_ctx, 
                       reinterpret_cast<const uint8_t*>(plaintext),
                       strlen(plaintext),
                       ciphertext, &out_len)) return false;
    
    uint8_t tag[12];
    if (!AesGcm::final(enc_ctx, ciphertext + out_len, &out_len, tag)) return false;

    // 解密
    AesGcm::Context dec_ctx{SecuritySuite::aesGcm128};
    if (!AesGcm::init(dec_ctx, key, iv, AesGcm::Mode::decrypt)) return false;
    if (!AesGcm::setTag(dec_ctx, tag)) return false;
    
    uint8_t decrypted[128];
    size_t dec_len;
    if (!AesGcm::update(dec_ctx, ciphertext, strlen(plaintext), 
                       decrypted, &dec_len)) return false;
    
    uint8_t final_dec;
    if (!AesGcm::final(dec_ctx, &final_dec, &dec_len, nullptr)) return false;

    return memcmp(plaintext, decrypted, strlen(plaintext)) == 0;
}

bool test_gmac_auth() {
    uint8_t key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    uint8_t iv[12] = {0};
    const char* data = "Authentication Data";
    
    uint8_t tag[12];
    bool ret = AesGcm::gmac(SecuritySuite::aesGcm128, key, iv,
                           reinterpret_cast<const uint8_t*>(data),
                           strlen(data), tag);
    (void)ret;
    
    // 验证标签是否有效（需通过解密验证）
    AesGcm::Context ctx{SecuritySuite::aesGcm128};
    if (!AesGcm::init(ctx, key, iv, AesGcm::Mode::decrypt)) return false;
    if (!AesGcm::setTag(ctx, tag)) return false;
    if (!AesGcm::updateAad(ctx, reinterpret_cast<const uint8_t*>(data), strlen(data))) return false;
    std::size_t dummy_len;
    std::uint8_t dummy;
    return AesGcm::update(ctx, nullptr, 0, &dummy, &dummy_len) &&  AesGcm::final(ctx, nullptr, &dummy_len, nullptr);
}

bool test_stream_processing() {
    const char* parts[] = {"Chunk1 ", "Chunk2 ", "Chunk3"};
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    
    // 加密
    AesGcm::Context enc_ctx{SecuritySuite::aesGcm128};
    if (!AesGcm::init(enc_ctx, key, iv, AesGcm::Mode::encrypt)) return false;
    
    uint8_t ciphertext[128];
    size_t total_len = 0;
    for (auto part : parts) {
        size_t out_len;
        if (!AesGcm::update(enc_ctx, 
                           reinterpret_cast<const uint8_t*>(part),
                           strlen(part),
                           ciphertext + total_len, &out_len)) return false;
        total_len += out_len;
    }
    
    uint8_t tag[12];
    size_t final_len;
    if (!AesGcm::final(enc_ctx, ciphertext + total_len, &final_len, tag)) return false;
    total_len += final_len;

    // 解密
    AesGcm::Context dec_ctx{SecuritySuite::aesGcm128};
    if (!AesGcm::init(dec_ctx, key, iv, AesGcm::Mode::decrypt)) return false;
    if (!AesGcm::setTag(dec_ctx, tag)) return false;
    
    uint8_t decrypted[128];
    size_t dec_total = 0;
    for (size_t i = 0; i < total_len; i += 5) { // 故意分小段测试
        size_t chunk_len = (total_len - i) > 5 ? 5 : (total_len - i);
        size_t out_len;
        if (!AesGcm::update(dec_ctx, ciphertext + i, chunk_len,
                           decrypted + dec_total, &out_len)) return false;
        dec_total += out_len;
    }
    
    size_t final_dec_len;
    if (!AesGcm::final(dec_ctx, decrypted + dec_total, &final_dec_len, nullptr)) return false;
    dec_total += final_dec_len;

    return dec_total == strlen(parts[0]) + strlen(parts[1]) + strlen(parts[2]);
}

int main() {
    // printf("Encrypt/Decrypt test: %s\n", test_encrypt_decrypt() ? "PASS" : "FAIL");
    // printf("Stream processing test: %s\n", test_stream_processing() ? "PASS" : "FAIL");
    printf("GMAC auth test: %s\n", test_gmac_auth() ? "PASS" : "FAIL");
    return 0;
}
