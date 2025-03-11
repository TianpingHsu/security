#pragma once
#include <cstdint>
#include <openssl/evp.h>

/**
| Security Suite Id | Security suite name            | Authenticated encryption | Digital signature | Digital signature | Hash    | Key-transport    |
|-------------------+--------------------------------+--------------------------+-------------------+-------------------+---------+------------------|
|                 0 | AES-GCM-128                    | AES-GCM-128              | -                 | -                 | -       | AES-128 key wrap |
|                 1 | ECDH-ECDSA-AES-GCM-128-SHA-256 | AES-GCM-128              | ECDSA with P-256  | ECDH with P-256   | SHA-256 | AES-128 key wrap |
|                 2 | ECDH-ECDSA-AES-GCM-256-SHA-384 | AES-GCM-256              | ECDSA with P-384  | ECDH with P-384   | SHA-384 | AES-256 key wrap |
*/
enum class SecuritySuite: std::uint8_t {
    aesGcm128 = 0,                  //< suite 0
    ecdhEcdsaAesGcm128Sha256 = 1,   //< suite 1
    ecdhEcdsaAesGcm256Sha384 = 2,   //< suite 2
};


class Sha2 {
public:
    struct Context {
        SecuritySuite suite;
        EVP_MD_CTX* evp_ctx;
        const EVP_MD* hash_type;
    };

    /**
     * @brief initialize the context
     * @param ctx context
     * @return true if successful, false otherwise
     */
    static bool init(Context& ctx);

    /**
     * @brief update the hash with data
     * @param ctx context
     * @param data data to be hashed
     * @param len length of data to be hashed
     * @return true if successful, false otherwise
     * 
     * @note this function can be called multiple times to hash multiple data
     *       segments, the intermediate hash result is stored in the context.
     */
    static bool update(Context& ctx, const std::uint8_t* data, std::size_t len);

    /**
     * @brief finalize the hash and get the result
     * @param ctx context
     * @param hash pointer to the buffer to store the hash result
     * 
     * @note when you update all your data, you should call this function to get
     *       the final hash result.
     */
    static bool final(Context& ctx, std::uint8_t* hash);

    /**
     * @brief compute the hash of data using the specified suite
     * @param suite security suite
     * @param data data to be hashed
     * @param len length of data to be hashed
     * @param hash pointer to the buffer to store the hash result
     * @return true if successful, false otherwise
     * 
     * @note `HLS` with SHA2 will use this function
     */
    static bool hash(SecuritySuite suite, const std::uint8_t* data, std::size_t len, std::uint8_t* hash);
};

class AesGcm {
public:
    constexpr static std::uint8_t gcmIvLength = 12;
    constexpr static std::uint8_t gcmTagLength = 12;

public:
    enum class Mode: std::uint8_t {
        encrypt = 0,
        decrypt = 1,
    };

    struct Context {
        SecuritySuite suite;
        EVP_CIPHER_CTX* evp_ctx;
        Mode mode;
        uint8_t key[32];        // max length of key is 32 bytes
        uint8_t iv[12];
        bool aad_processed;
        bool final_called;
    };

    /**
     * @brief initialize the context
     * @param ctx context
     * @param key key for encryption/decryption
     * @param iv initialization vector for encryption/decryption
     * @param mode encryption or decryption mode
     * @return true if successful, false otherwise
     */
    static bool init(Context& ctx, const std::uint8_t* key, const std::uint8_t* iv, Mode mode);

    /**
     * @brief update addtional authenticated data (AAD)
     * @param ctx context
     * @param aad additional authenticated data to be added
     * @param len length of AAD to be added
     * @return true if successful, false otherwise
     * 
     * @note
     * 1. if `aad` is provided, it should be added before call `update` function.
     * 2. if only authentication is required, you can call this function repeatedly.
     */
    static bool updateAad(Context& ctx, const std::uint8_t* aad, std::size_t len);

    /**
     * @brief update the ciphertext/plaintext with data
     * @param ctx context
     * @param data data to be encrypted/decrypted
     * @param len length of data to be encrypted/decrypted
     * @param out pointer to the buffer to store the ciphertext/plaintext
     * @param outLen pointer to the length of the ciphertext/plaintext
     * @return true if successful, false otherwise
     * 
     * @note this function can be called multiple times to encrypt/decrypt multiple
     *       data segments, the intermediate result is stored in context.
     */
    static bool update(Context& ctx, const std::uint8_t* data, std::size_t len, const std::uint8_t* out, std::size_t* outLen);

    /**
     * @brief finalize the encryption/decryption and get the result
     * @param ctx context
     * @param out pointer to the buffer to store the ciphertext/plaintext
     * @param outLen pointer to the length of the ciphertext/plaintext
     * @param tag pointer to the buffer to store the authentication tag
     * @return true if successful, false otherwise
     * 
     * @note length of `tag` is fixed to 12 bytes in COSEM.
     */
    static bool final(Context& ctx, const std::uint8_t* out, std::size_t* outLen, const std::uint8_t* tag);

    /**
     * @brief set the authentication tag
     * @param ctx context
     * @param tag authentication tag to be set
     * 
     * @note this function should be called before `update` if tag exists.
     */
    static bool setTag(Context& ctx, const std::uint8_t* tag);

    /**
     * @brief get the authentication tag
     * @param ctx context
     * @param key key for encryption
     * @param iv initialization vector for encryption
     * @param data data to be authenticated
     * @param dataLen length of data to be authenticated
     * @param tag pointer to the buffer to store the authentication tag
     * @return true if successful, false otherwise
     * 
     * @note this function is only used for `HLS` with gmac authentication mechanism
     */
    static bool gmac(SecuritySuite suite, const std::uint8_t* key, const std::uint8_t* iv, const std::uint8_t* data, std::size_t dataLen, std::uint8_t* tag);
};

class KeyWrap {
public:

    /**
     * @brief wrap a key using AES key wrap algorithm
     * @param suite security suite
     * @param kek key encryption key
     * @param kekLen length of key encryption key
     * @param input key to be wrapped
     * @param inputLen length of key to be wrapped
     * @param output pointer to the buffer to store the wrapped key
     * @param outputLen pointer to the length of the wrapped key
     * @return true if successful, false otherwise
     */
    static bool aesKeyWrap(SecuritySuite suite, const unsigned char *kek, std::size_t kekLen, const unsigned char *input, std::size_t inputLen, unsigned char *output, std::size_t *outputLen);

    /**
     * @brief unwrap a key using AES key wrap algorithm
     * @param suite security suite
     * @param kek key encryption key
     * @param kekLen length of key encryption key
     * @param input key to be unwrapped
     * @param inputLen length of key to be unwrapped
     * @param output pointer to the buffer to store the unwrapped key
     * @param outputLen pointer to the length of the unwrapped key
     * @return true if successful, false otherwise
     */
    static bool aesKeyUnwrap(SecuritySuite suite, const unsigned char *kek, std::size_t kekLen, const unsigned char *input, std::size_t inputLen, unsigned char *output, std::size_t *outputLen);
};

class Ecdsa {
public:
    struct Context {
        SecuritySuite suite;
        EVP_PKEY_CTX* pkey_ctx;
        EVP_MD_CTX* md_ctx;
        EVP_PKEY* pkey;
        const EVP_MD* digest;
    };

    /**
     * @brief initialize the context for signing
     * @param ctx context
     * @param privateKey private key for signing
     * @return true if successful, false otherwise
     */
    static bool initSign(Context& ctx, const std::uint8_t* privateKey);

    /**
     * @brief update the data to be signed
     * @param ctx context
     * @param data data to be signed
     * @param len length of data to be signed
     * @return true if successful, false otherwise
     * 
     * @note this function can be called multiple times to sign multiple data segments,
     *       the intermediate signature result is stored in the context.
     */
    static bool signUpdate(Context& ctx, const std::uint8_t* data, std::size_t len);

    /**
     * @brief finalize the signing and get the signature
     * @param ctx context
     * @param signature pointer to the buffer to store the signature
     * @return true if successful, false otherwise
     * 
     */
    static bool signFinal(Context& ctx, std::uint8_t* signature);

    /**
     * @brief initialize the context for verification
     * @param ctx context
     * @param publicKey public key for verification
     * @return true if successful, false otherwise
     */
    static bool initVerify(Context& ctx, const std::uint8_t* publicKey);

    /**
     * @brief update the data to be verified
     * @param ctx context
     * @param data data to be verified
     * @param len length of data to be verified
     * @return true if successful, false otherwise
     * 
     * @note this function can be called multiple times to verify multiple data segments,
     *       the intermediate signature result is stored in the context.
     */
    static bool verifyUpdate(Context& ctx, const std::uint8_t* data, std::size_t len);

    /**
     * @brief finalize the verification and check the signature
     * @param ctx context
     * @param signature to be verified
     * @param sigLen length of signature to be verified
     * @return true if successful, false otherwise
     */
    static bool verifyFinal(Context& ctx, const std::uint8_t* signature, std::size_t sigLen);

};

class Ecdh {
public:
    /**
     * @brief generate random bytes
     * @param buf buffer to store random bytes
     * @param len length of random bytes to be generated
     * @return true if successful, false otherwise
     */
    static bool randBytes(unsigned char *buf, std::size_t len);

    /**
     * @brief generate a new EC key pair
     * @param suite security suite
     * @param publicKey buffer to store public key, includes x and y coordinates
     * @param privateKey buffer to store private key
     * @return true if successful, false otherwise
     * 
     * @note
     * if suite == ecdhEcdsaAesGcm128Sha256:
     *      len(publicKey) == 64
     *      len(privateKey) == 32
     * if suite == ecdhEcdsaAesGcm256Sha384:
     *      len(publicKey) == 96
     *      len(privateKey) == 48
     */
    static bool generateEcKeyPair(SecuritySuite suite, std::uint8_t* publicKey, std::uint8_t* privateKey);

    /**
     * @brief compute shared secret Z
     * @param suite security suite
     * @param d private key of the local device
     * @param Q public key of the remote device
     * @param sharedSecretZ buffer to store shared secret Z
     * @return true if successful, false otherwise
     * 
     * @note
     * if suite == ecdhEcdsaAesGcm128Sha256:
     *      len(d) == 32
     *      len(Q) == 64
     *      len(sharedSecretZ) == 32
     * if suite == ecdhEcdsaAesGcm256Sha384:
     *      len(d) == 48
     *      len(Q) == 96
     *      len(sharedSecretZ) == 48
     */
    static bool computeSharedSecret(SecuritySuite suite, const std::uint8_t* d, const std::uint8_t* Q, std::uint8_t* sharedSecretZ);

    /**
     * @brief single-step key derivation function (SSKDF), specified in NIST SP 800-56A Rev. 2: 2013, 5.8.1.1
     * @param suite security suite
     * @param sharedSecretZ shared secret Z
     * @param otherInfo A bit string equal to the following concatenation: `AlgorithmID || PartyUInfo || PartyVInfo`
     * @param otherInfoLen length of additional input data
     * @param key buffer to store derived key
     * @return true if successful, false otherwise
     * 
     * @note
     * if suite == ecdhEcdsaAesGcm128Sha256:
     *      len(sharedSecretZ) == 32
     *      len(key) == 16
     * if suite == ecdhEcdsaAesGcm256Sha384:
     *      len(sharedSecretZ) == 48
     *      len(key) == 32
     * 
     * the `H` function used in SSKDF is SHA-256 for suite ecdhEcdsaAesGcm128Sha256, and SHA-384 for suite ecdhEcdsaAesGcm256Sha384.
     * 
     * subfield of `otherInfo`: (check Table 25 and Table 26 of Green Book for details)
     * - `AlgorithmID`: A bit string that indicates how the derived secret keying material will be parsed
     *                  and for which algorithm(s) the derived secret keying material will be used.
     *                  When key agreement is used to agree on the GUEK and GAK, then the algorithm ID used shall be
     *                  AES-GCM-128 / AES-GCM-256. When it is used to agree on the KEK then the algorithm ID
     *                  used shall be AES-WRAP-128 / AES-WRAP-256.
     * - `PartyUInfo`: A bit string containing public information that is required by the application using
     *                 this KDF to be contributed by Party U to the key derivation process;
     * - `PartyVInfo`: A bit string containing public information that is required by the application using
     *                 this KDF to be contributed by Party V to the key derivation process;
     */
    static bool sskdf(SecuritySuite suite, unsigned char* sharedSecretZ, unsigned char* otherInfo, std::size_t otherInfoLen, unsigned char* key);
};
