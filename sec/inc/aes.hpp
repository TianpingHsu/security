#pragma once

#include "minitype.hpp"
#include "utils.hpp"
#include "mock_io.hpp"

#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"

#include <array>

namespace dev {
class Aes : public MockIo {
public:
    enum class KeyBits : u8 {
        _128,
        _192,
        _256,
    };
    enum class Func : u8 {
        encrypt = MBEDTLS_GCM_ENCRYPT,
        decrypt = MBEDTLS_GCM_DECRYPT,
    };
    using Context = std::array<u8, sizeof(mbedtls_gcm_context)>;

public:
    Aes() noexcept = default;
    virtual ~Aes() noexcept = default;

    void activate() const;
    void deactivate() const;

    /**
     * Set the context for AES-GCM encryption.
     * 
     * @param func Operation mode, encrypt or decrypt
     * @param keybits Key length, determines whether to use 128, 192, or 256-bit key
     * @param key Pointer to the key data
     * @param iv Pointer to the initialization vector
     * @param ivLen Length of the initialization vector
     * @return BspStatus Return status code indicating whether the setup was successful.
     * 
     * This function initializes the AES-GCM encryption context based on the provided parameters,
     * including setting the key, initialization vector, and additional authenticated data.
     */  
    BspStatus setGcmContext(Func func, KeyBits keybits, u8 *key, u8 *iv, u32 ivLen);

    /**
     * @brief Updates the Additional Authenticated Data (AAD) for AES operations.
     * 
     * This function updates the AAD by calling the lower-level function LL_AES_update_aad.
     * It is typically used in authenticated encryption modes like GCM to include additional data 
     * that needs to be authenticated but not encrypted.
     * 
     * @param aad Pointer to the AAD byte array. Must not be null.
     * @param len Length of the AAD byte array in bytes. Must be non-negative.
     * 
     * @return BspStatus Returns BspStatus::ok if the operation succeeds, otherwise returns an error status.
     */
    BspStatus updateAad(const u8 *aad, u16 len);

    /**
     * @brief Use AES-GCM to encrypt and generate an authentication tag
     * 
     * This function is responsible for encrypting the given data block and generating an authentication tag on the last data block.
     * 
     * @param input Pointer to the input data buffer to be encrypted
     * @param iLen Length of the input data
     * @param output Pointer to the output buffer for the encrypted data
     * @param isLastBlock Flag indicating whether this is the last data block, required for multi-part encryption only
     * @param tag Pointer to the buffer for the generated authentication tag, required for multi-part encryption only
     * @param tagSize Length of the authentication tag, required for multi-part encryption only
     * @return BspStatus Return status of the operation, BspStatus::ok indicates success, BspStatus::err indicates failure
     */
    BspStatus encryptAndTag(u8 *input, u32 iLen, u8 *output, bool isLastBlock = false, u8 *tag = nullptr, u32 tagSize = 16);

    /**
     * @brief Use AES-GCM for authentication and decryption
     * 
     * This function decrypts the input data and verifies the tag using the GCM mode of the mbedtls library.
     * 
     * @param input Input ciphertext data
     * @param iLen Length of the input ciphertext
     * @param output Output buffer for the decrypted plaintext data
     * @param isLastBlock Flag indicating whether this is the last data block, used for handling large data in chunks
     * @param tag Input authentication tag, required for the last packet only; if only decrypting, this parameter is not needed.
     * @param tagSize Length of the authentication tag; if only decrypting, this parameter is not needed.
     * @return BspStatus Return status of the operation, BspStatus::ok indicates success, BspStatus::err indicates failure
     */
    BspStatus authAndDecrypt(u8 *input, u32 iLen, u8 *output, bool isLastBlock = false, u8 *tag = nullptr, u32 tagSize = 16);

    /**
     * @brief Save the current AES-GCM context
     * 
     * This function copies the AES-GCM context from the current instance to the provided context parameter (ctx).
     * 
     * @param ctx Reference to the Context object used to store the current AES-GCM context
     */
    void saveContext(Context& ctx);

    /**
     * Restore encryption context
     * 
     * This function is intended to restore the saved encryption context to the current object, allowing operations to be resumed
     * when processing needs to be interrupted and then continued.
     * 
     * @param ctx Reference to the Context object containing the encryption context to be restored
     */
    void restoreContext(Context& ctx);

    /**
     * @brief AES key wrapping function following RFC 3394 standard.
     * 
     * This function encrypts the input plaintext key (input) using the key encryption key (KEK) to produce ciphertext,
     * following the AES Key Wrap algorithm as specified in RFC 3394, including six rounds of encryption.
     * 
     * @param kek Pointer to the key encryption key (Key Encryption Key).
     * @param kekLen Length of the key encryption key (KEK) in bytes.
     * @param input Pointer to the plaintext key to be wrapped.
     * @param iLen Length of the plaintext key, must be a multiple of 8 and at least 8 bytes.
     * @param output Pointer to the buffer for storing the wrapped ciphertext.
     * @param oLen Pointer to the length of the output wrapped key.
     * @return BspStatus Return status of the operation, BspStatus::ok indicates success, BspStatus::err indicates failure.
     *         Failure reasons may include invalid input length or errors during the encryption process.
     */
    BspStatus wrapKey(KeyBits keybits, u8 *kek, u8 *input, u8 iLen, u8 *output, u8 *oLen);

    /**
     * @brief AES key unwrapping function following RFC 3394 standard.
     * 
     * This function decrypts the input wrapped key (input) using the key encryption key (KEK) to produce plaintext,
     * following the AES Key Unwrap algorithm as specified in RFC 3394, including six rounds of decryption.
     * 
     * @param kek Pointer to the key encryption key (Key Encryption Key).
     * @param kekLen Length of the key encryption key (KEK) in bytes.
     * @param input Pointer to the wrapped key to be unwrapped.
     * @param iLen Length of the wrapped key, must be a multiple of 8 and at least 16 bytes.
     * @param output Pointer to the buffer for storing the unwrapped plaintext.
     * @param oLen Pointer to the length of the output unwrapped key.
     * @return BspStatus Return status of the operation, BspStatus::ok indicates success, BspStatus::err indicates failure.
     *         Failure reasons may include invalid input length, errors during the decryption process, or integrity check failure.
     */
    BspStatus unwrapKey(KeyBits keybits, u8 *kek, u8 *input, u8 iLen, u8 *output, u8 *oLen);

private:
    mbedtls_gcm_context ctx_;
    Aes(const Aes&) = delete;
    Aes& operator=(const Aes&) = delete;
    Aes(Aes&&) = delete;
    Aes& operator=(Aes&&) = delete;
   
    void throwException() const override;
};
}
