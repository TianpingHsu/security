#include "aes.hpp"

#include <cstring>
#include <stdexcept>

namespace dev {
void Aes::activate() const {
    setIoActivate();
}

void Aes::deactivate() const {
    setIoDeactivate();
}
BspStatus Aes::setGcmContext(Func func, KeyBits keybits, u8 *key, u8 *iv, u32 ivLen)
{
    u16 bits[3] {128, 192, 256};
    
    mbedtls_gcm_init(&ctx_);
    mbedtls_gcm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key, bits[static_cast<u8>(keybits)]);

    if (iv == nullptr || ivLen != 12 || mbedtls_gcm_starts(&ctx_, static_cast<int>(func), iv, ivLen) != 0) {
        return BspStatus::err;
    }

    return BspStatus::ok;
}

BspStatus Aes::updateAad(const u8 *aad, u16 len)
{
    if (aad !=nullptr && len > 0 && mbedtls_gcm_update_ad(&ctx_, aad, len) != 0) {
        return BspStatus::err;
    }
    return BspStatus::ok;
}

BspStatus Aes::encryptAndTag(u8 *input, u32 iLen, u8 *output, bool isLastBlock, u8 *tag, u32 tagSize)
{
    size_t olen;

    if (input != nullptr && iLen > 0 && mbedtls_gcm_update(&ctx_, input, iLen, output, iLen, &olen) != 0) {
        return BspStatus::err;
    }

    if(isLastBlock){
        u8 tmp[16];
        if (mbedtls_gcm_finish(&ctx_, nullptr, 0, &olen, tmp, sizeof(tmp)) != 0) {
            return BspStatus::err;
        }
        // 处理仅加密，传入的tag为nullptr的情况
        if(tag != nullptr && tagSize == 16){
            memcpy(tag, tmp, tagSize);
        }
    }

    return BspStatus::ok;
}

BspStatus Aes::authAndDecrypt(u8 *input, u32 iLen, u8 *output, bool isLastBlock, u8 *tag, u32 tagSize)
{
    size_t olen;
    u8 checkTag[16];

    if (mbedtls_gcm_update(&ctx_, input, iLen, output, iLen, &olen) != 0) {
        return BspStatus::err;
    }

    if(isLastBlock){
        if (mbedtls_gcm_finish(&ctx_, nullptr, 0, &olen, checkTag, tagSize) != 0) {
            return BspStatus::err;
        }

        // 当传入tag为空时，不进行校验
        if(tag != nullptr && std::memcmp(tag, checkTag, tagSize) != 0){
            return BspStatus::err;
        }
    }

    return BspStatus::ok;
}

void Aes::saveContext(Context& ctx)
{
    memcpy(&ctx, &ctx_, sizeof(mbedtls_gcm_context));
}

void Aes::restoreContext(Context& ctx)
{
    memcpy(&ctx_, &ctx, sizeof(mbedtls_gcm_context));
}

BspStatus Aes::wrapKey(KeyBits keybits, u8 *kek, u8 *input, u8 iLen, u8 *output, u8 *oLen)
{
    mbedtls_aes_context ctx;
    u8 a[8];
    u8 r[32]; // Maximum block size for AES
    u8 b[16];
    size_t i, j;
    u16 bitLen[3] {128, 192, 256};

    if (iLen % 8 != 0 || iLen < 8) {
        return BspStatus::err; // Invalid input length
    }

    // Initialize AES context with the key encryption key (KEK)
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, kek, bitLen[static_cast<u8>(keybits)]);

    // Initial value of A
    memset(a, 0xA6, 8); // RFC 3394 specifies initial value of A

    // Copy plaintext into r[]
    memcpy(r, input, iLen);

    // Number of 64-bit blocks in the plaintext
    size_t n = iLen / 8;

    // Perform the wrapping operation
    for (j = 0; j <= 5; j++) { // 6 rounds as per RFC 3394
        for (i = 1; i <= n; i++) {
            // Prepare B = A | R[i]
            memcpy(b, a, 8);
            memcpy(b + 8, r + (i - 1) * 8, 8);

            // Encrypt B
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, b, b);

            // Update A and R[i]
            a[7] ^= (u8)((i + (j * n)) & 0xFF);
            memcpy(a, b, 8);
            memcpy(r + (i - 1) * 8, b + 8, 8);
        }
    }

    // Output A as the first block of ciphertext
    memcpy(output, a, 8);
    memcpy(output + 8, r, iLen);
    *oLen = iLen + 8;
    mbedtls_aes_free(&ctx);

    return BspStatus::ok;
}

BspStatus Aes::unwrapKey(KeyBits keybits, u8 *kek, u8 *input, u8 iLen, u8 *output, u8 *oLen)
{
    mbedtls_aes_context ctx;
    u8 a[8];
    u8 r[32]; // Maximum block size for AES
    u8 b[16];
    int i, j;
    u16 bitLen[3] {128, 192, 256};

    if (iLen % 8 != 0 || iLen < 16) {
        return BspStatus::err; // Invalid input length
    }

    // Initialize AES context with the key encryption key (KEK)
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, kek, bitLen[static_cast<u8>(keybits)]);

    // Copy ciphertext into a[] and r[]
    memcpy(a, input, 8);
    memcpy(r, input + 8, iLen - 8);

    // Number of 64-bit blocks in the ciphertext minus one
    size_t n = (iLen / 8) - 1;

    // Perform the unwrapping operation
    for (j = 5; j >= 0; j--) { // 6 rounds as per RFC 3394
        for (i = n; i >= 1; i--) {
            // Prepare B = A | R[i]
            memcpy(b, a, 8);
            memcpy(b + 8, r + (i - 1) * 8, 8);

            // Decrypt B
            mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, b, b);

            // Update A and R[i]
            memcpy(r + (i - 1) * 8, b + 8, 8);
            a[7] ^= (u8)((i + (j * n)) & 0xFF);
            memcpy(a, b, 8);
        }
    }

    // Check the final value of A
    u8 expected_a[8];
    memset(expected_a, 0xA6, 8); // RFC 3394 specifies final value of A
    if (memcmp(a, expected_a, 8) != 0) {
        mbedtls_aes_free(&ctx);
        return BspStatus::err; // Integrity check failed
    }

    // Output R as the plaintext
    memcpy(output, r, iLen - 8);
    *oLen = iLen - 8;

    mbedtls_aes_free(&ctx);
    return BspStatus::ok;
}

void Aes::throwException() const {
    throw std::logic_error("Aes must be activate before use");
}
}
