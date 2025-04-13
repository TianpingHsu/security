#include "security.hpp"
#include <cstring>
#include <cassert>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

constexpr u8 maxClientRoles = 4;
SecurityMaterials securityMaterials[2][maxClientRoles] = {
    {
        {},
        {},
        {
            .suite = SecuritySuite::ecdhEcdsaAesGcm128Sha256,
            .guek = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF},
            .gbek = {0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
            .gak = {0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF},
            .kek = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            .dedk = {0},
            .encIcGuek = 0,
            .decIcGuek = 0,
            .encIcGbek = 0,
            .decIcGbek = 0,
            .encIcDedk = 0,
            .decIcDedk = 0,
        },
        {}
    },
    {
        {},
        {},
        {
            .suite = SecuritySuite::ecdhEcdsaAesGcm256Sha384,
            .guek = {0},
            .gbek = {0},
            .gak = {0},
            .kek = {0},
            .dedk = {0},
            .encIcGuek = 0,
            .decIcGuek = 0,
            .encIcGbek = 0,
            .decIcGbek = 0,
            .encIcDedk = 0,
            .decIcDedk = 0,
        },
        {}
    },
};

u8 suite1EcdsaPublicKey[suite1PublicKeyLength] = 
    {0x93,0x3A,0xCF,0x15,0xB0,0x3A,0x92,0x48,0xE0,0x29,0xB2,0x78,0x7F,0xB5,0x2A,0x0A,0xEC,0xAF,0x63,0x5F,0x07,0xC4,0x2A,0x00,0x19,0xFB,0x31,0x97,0xE3,0x8F,0x8F,0x54,
    0x9A,0x12,0x5E,0xA3,0x67,0x81,0xB0,0xCA,0x96,0xBE,0x89,0xA0,0xE1,0xFE,0x2C,0xF9,0xB7,0x36,0x1E,0xD4,0x8B,0x3C,0x5E,0x24,0x59,0x2B,0x9C,0x0F,0x4E,0xDD,0x31,0xD1};
u8 suite1EcdsaPrivateKey[suite1PrivateKeyLength] = 
    {0xAE,0x55,0x41,0x4F,0xFE,0x07,0x9F,0x9F,0xC9,0x56,0x49,0x53,0x6B,0xD1,0xC2,0xB5,0x65,0x3D,0x20,0x08,0x13,0x72,0x7E,0x07,0xD5,0x01,0xA8,0xB5,0x50,0xC6,0x92,0x07};
u8 suite1EcdsaClientPublicKey[suite1PublicKeyLength] = 
    {0xBA,0xAF,0xFD,0xE0,0x6A,0x8C,0xB1,0xC9,0xDA,0xE8,0xD9,0x40,0x23,0xC6,0x01,0xDB,0xBB,0x24,0x92,0x54,0xBA,0x22,0xED,0xD8,0x27,0xE8,0x20,0xBC,0xA2,0xBC,0xC6,0x43,
     0x62,0xFB,0xB8,0x3D,0x86,0xA8,0x2B,0x87,0xBB,0x8B,0x71,0x61,0xD2,0xAA,0xB5,0x52,0x19,0x11,0xA9,0x46,0xB9,0x7A,0x28,0x4A,0x90,0xF7,0x78,0x5C,0xD9,0x04,0x7D,0x25};

u8 suite1EcdhClientPublicKey[suite1PublicKeyLength] = 
    {0x07,0xC5,0x6D,0xE2,0xDC,0xAF,0x0F,0xD7,0x93,0xEF,0x29,0xF0,0x19,0xC8,0x9B,0x4A,0x0C,0xC1,0xE0,0x01,0xCE,0x94,0xF4,0xFF,0xBE,0x10,0xBC,0x05,0xE7,0xE6,0x6F,0x76,
     0x71,0xA1,0x3F,0xBC,0xF9,0xE6,0x62,0xB9,0x82,0x6F,0xFF,0x6A,0x69,0x38,0x54,0x6D,0x52,0x4E,0xD6,0xD3,0x40,0x5F,0x02,0x02,0x96,0xBD,0xE1,0x6B,0x04,0xF7,0xA7,0xC2};
u8 suite1EcdhPublicKey[suite1PublicKeyLength] = 
    {0xA6,0x53,0x56,0x5B,0x0E,0x06,0x07,0x0B,0xAE,0x9F,0xBE,0x14,0x0A,0x5D,0x21,0x56,0x81,0x2A,0xEE,0x2D,0xD5,0x25,0x05,0x3E,0x3E,0xFC,0x85,0x0B,0xF1,0x3B,0xFD,0xFF,
    0xCB,0x24,0x0B,0xC7,0xB7,0x7B,0xFF,0x58,0x83,0x34,0x4E,0x72,0x75,0x90,0x8D,0x22,0x87,0xBE,0xFA,0x37,0x25,0x01,0x72,0x95,0xA0,0x96,0x98,0x9D,0x23,0x38,0x29,0x0B};
u8 suite1EcdhPrivateKey[suite1PrivateKeyLength] = 
    {0xAA,0xD3,0xFD,0x07,0x32,0xE9,0x91,0xCF,0x52,0xA7,0x4C,0x66,0xC1,0xF2,0x82,0x7D,0xDC,0x53,0x52,0x2A,0x2E,0x0A,0x16,0x9D,0x7C,0x4F,0xFC,0xC0,0xFB,0x5D,0x6A,0x4D};

u8 suite2EcdsaPublicKey[suite2PublicKeyLength] = {};
u8 suite2EcdsaPrivateKey[suite2PrivateKeyLength] = {};
u8 suite2EcdsaClientPublicKey[suite2PublicKeyLength] = {};
u8 suite2EcdhClientPublicKey[suite2PublicKeyLength] = {};
u8 suite2EcdhPublicKey[suite2PublicKeyLength] = {};
u8 suite2EcdhPrivateKey[suite2PrivateKeyLength] = {};

bool Sha2::init(Sha2::Context& ctx) {
    return ctx.sha2.initContext(dev::Sha2::HashType::SHA256) == BspStatus::ok;
}

bool Sha2::update(Sha2::Context& ctx, const u8* data, std::size_t len) {
    return ctx.sha2.hash(const_cast<u8*>(data), static_cast<u32>(len), false, nullptr, 0) == BspStatus::ok;
}

bool Sha2::final(Sha2::Context& ctx, u8* hash) {
    return ctx.sha2.hash(nullptr, 0, true, hash, sha256DigestLength) == BspStatus::ok;
}

bool Sha2::hash(SecuritySuite suite, const u8* data, std::size_t len, u8* hash) {
    dev::Sha2 sha2;
    sha2.initContext(suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256 ? dev::Sha2::HashType::SHA256 : dev::Sha2::HashType::SHA384);
    return sha2.hash(const_cast<u8*>(data), static_cast<u32>(len), true, hash, suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256 ? sha256DigestLength : sha384DigestLength) == BspStatus::ok;
}

bool AesGcm::init(AesGcm::Context& ctx, const u8* key, const u8* iv, AesGcm::Mode mode) {
    return ctx.aes.setGcmContext(static_cast<dev::Aes::Func>(mode), dev::Aes::KeyBits::_128, const_cast<u8*>(key), const_cast<u8*>(iv), gcmIvLength) == BspStatus::ok;
}

bool AesGcm::updateAad(AesGcm::Context& ctx, const u8* aad, std::size_t len) {
    return ctx.aes.updateAad(aad, static_cast<u16>(len)) == BspStatus::ok;
}

bool AesGcm::update(AesGcm::Context& ctx, const u8* data, std::size_t len, u8* out, std::size_t* outLen) {
    BspStatus status = ctx.aes.encryptAndTag(const_cast<u8*>(data), static_cast<u32>(len), out, true, nullptr, 0);
    if (status != BspStatus::ok) {
        return false;
    }
    *outLen = len;
    return true;
}

bool AesGcm::final(AesGcm::Context& ctx, u8* out, std::size_t* outLen, u8* tag) {
    return ctx.aes.encryptAndTag(nullptr, 0, out, true, tag, gcmTagLength) == BspStatus::ok;
}

bool AesGcm::setTag(AesGcm::Context& ctx, const u8* tag) {
    // Placeholder for setting tag if needed
    return true;
}

bool AesGcm::gmac(SecuritySuite suite, const u8* key, const u8* iv, const u8* data, std::size_t dataLen, u8* tag) {
    dev::Aes aes;
    BspStatus status = aes.setGcmContext(dev::Aes::Func::encrypt, dev::Aes::KeyBits::_128, const_cast<u8*>(key), const_cast<u8*>(iv), gcmIvLength);
    if (status != BspStatus::ok) {
        return false;
    }
    status = aes.updateAad(data, static_cast<u16>(dataLen));
    if (status != BspStatus::ok) {
        return false;
    }
    return aes.encryptAndTag(nullptr, 0, nullptr, true, tag, gcmTagLength) == BspStatus::ok;
}

bool Ecdsa::initSign(Ecdsa::Context& ctx, u8* privateKey) {
    auto suite2 = ctx.sha2Ctx.suite == SecuritySuite::ecdhEcdsaAesGcm256Sha384;
    auto hashType = suite2 ? dev::Sha2::HashType::SHA384 : dev::Sha2::HashType::SHA256;
    auto curveType = suite2 ? dev::Ecc::CurveType::NIST_P384 : dev::Ecc::CurveType::NIST_P256;
    return ctx.sha2.init(ctx.sha2Ctx) && ctx.ecdsa.initContext(curveType, nullptr, privateKey) == BspStatus::ok;
}


bool Ecdsa::signUpdate(Ecdsa::Context& ctx, const u8* data, std::size_t len) {
    return ctx.sha2.update(ctx.sha2Ctx, data, len);
}

bool Ecdsa::signFinal(Ecdsa::Context& ctx, u8* signature, std::size_t* signatureLen) {
    u8 md[sha384DigestLength];
    ctx.sha2.final(ctx.sha2Ctx, md);
    *signatureLen = ctx.sha2Ctx.suite == SecuritySuite::ecdhEcdsaAesGcm256Sha384 ? sha384DigestLength : sha256DigestLength;
    return ctx.ecdsa.sign(md, *signatureLen, signature, signature + *signatureLen/2) == BspStatus::ok;
}

bool Ecdsa::initVerify(Ecdsa::Context& ctx, const u8* publicKey) {
    auto suite2 = ctx.sha2Ctx.suite == SecuritySuite::ecdhEcdsaAesGcm256Sha384;
    auto hashType = suite2 ? dev::Sha2::HashType::SHA384 : dev::Sha2::HashType::SHA256;
    auto curveType = suite2 ? dev::Ecc::CurveType::NIST_P384 : dev::Ecc::CurveType::NIST_P256;
    return ctx.sha2.init(ctx.sha2Ctx) && ctx.ecdsa.initContext(curveType, const_cast<u8*>(publicKey), nullptr) == BspStatus::ok;
}

bool Ecdsa::verifyUpdate(Ecdsa::Context& ctx, const u8* data, std::size_t len) {
    return ctx.sha2.update(ctx.sha2Ctx, data, len);
}

bool Ecdsa::verifyFinal(Ecdsa::Context& ctx, const u8* signature, std::size_t signatureLen) {
    u8 md[sha384DigestLength];
    ctx.sha2.final(ctx.sha2Ctx, md);
    return ctx.ecdsa.verify(md, signatureLen, const_cast<u8*>(signature), const_cast<u8*>(signature + signatureLen/2)) == BspStatus::ok;
}

bool Ecdh::randBytes(unsigned char *buf, std::size_t len) {
    // Use mbedtls to generate random bytes
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    const char *pers = "rand_bytes";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, buf, len);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret == 0;
}

bool Ecdh::generateEcKeyPair(SecuritySuite suite, u8* publicKey, u8* privateKey) {
    dev::Ecc ecc;
    dev::Ecc::CurveType curveType = (suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? dev::Ecc::CurveType::NIST_P256 : dev::Ecc::CurveType::NIST_P384;
    return ecc.generateKeyPair(curveType, publicKey, privateKey) == BspStatus::ok;
}

bool Ecdh::computeSharedSecret(SecuritySuite suite, const u8* d, const u8* Q, u8* sharedSecretZ) {
    dev::Ecdh ecdh;
    dev::Ecc::CurveType curveType = (suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? dev::Ecc::CurveType::NIST_P256 : dev::Ecc::CurveType::NIST_P384;
    ecdh.initContext(curveType);
    return ecdh.computeSharedSecret(const_cast<u8*>(Q), const_cast<u8*>(d), sharedSecretZ) == BspStatus::ok;
}

bool Ecdh::sskdf(SecuritySuite suite, unsigned char* sharedSecretZ, unsigned char* otherInfo, std::size_t otherInfoLen, unsigned char* key) {
    dev::Ecdh ecdh;
    dev::Ecdh::HashType hashType = (suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? dev::Ecdh::HashType::SHA_256 : dev::Ecdh::HashType::SHA_384;
    return ecdh.sskdf(hashType, sharedSecretZ, (suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? suite1SymmetricKeyLength : suite2SymmetricKeyLength, otherInfo, otherInfoLen, key, (suite == SecuritySuite::ecdhEcdsaAesGcm128Sha256) ? suite1SymmetricKeyLength : suite2SymmetricKeyLength) == BspStatus::ok;
}


