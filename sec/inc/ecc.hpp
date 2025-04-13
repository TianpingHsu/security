#pragma once

#include "minitype.hpp"
#include "utils.hpp"
#include <utility>
#include <string.h>
extern "C"{
    #include "mbedtls/ecp.h"
    #include "mbedtls/bignum.h"
    #include "mbedtls/entropy.h"
    #include "mbedtls/ctr_drbg.h"
}

namespace dev {
class Ecc
{
public:
    enum class CurveType : u8 {
        NIST_P256,
        NIST_P384,
        NIST_P521,
    };

public:
    Ecc(){
        const char *pers = "ecdh_keygen";
        mbedtls_ctr_drbg_init(&ctr_drbg_);
        mbedtls_entropy_init(&entropy_);
        // Seed the random number generator
        mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, (const unsigned char *)pers, strlen(pers));
    }

    ~Ecc(){
        // mbedtls_ctr_drbg_free(&ctr_drbg_);
        // mbedtls_entropy_free(&entropy_);
    }

    /**
     * Generate an ECC key pair.
     * 
     * @param curveType The type of elliptic curve to use for key generation.
     * @param publicKey The buffer to store the generated public key.
     *  LENGTH: 65 bytes for NIST_P256, 97 bytes for NIST_P384, 133 bytes for NIST_P521
     * @param privateKey The buffer to store the generated private key.
     *  LENGTH: 32 bytes for NIST_P256, 48 bytes for NIST_P384, 66 bytes for NIST_P521
     * @return BspStatus The status of the key pair generation process.
     */
    BspStatus generateKeyPair(CurveType curveType, u8* publicKey, u8* privateKey);

    /**
     * Computes the public key for a given private key using Elliptic Curve Cryptography (ECC).
     * 
     * @param curveType The type of elliptic curve to use for the computation.
     * @param privateKey The private key used to compute the public key.
     * @param publicKey The output buffer where the computed public key will be stored.
     * @return BspStatus::ok if the public key is successfully computed, otherwise BspStatus::err.
     * 
     * This function calculates the public key by performing an elliptic curve point multiplication:
     * Q = d * G, where 'd' is the private key and 'G' is the generator point of the elliptic curve.
     */
    BspStatus computePublicKey(CurveType curveType, const u8* privateKey, u8* publicKey);

    /**
     * @brief Gets the key lengths for the specified elliptic curve type.
     * 
     * This function returns a pair of values:
     * - The first value represents the length of the private key.
     * - The second value represents the length of the public key.
     * 
     * Supported curve types include NIST_P256, NIST_P384, and NIST_P521.
     * 
     * @param curveType The type of elliptic curve for which the key lengths are required.
     * @return std::pair<u8, u8> A pair containing the private key length and public key length.
     */
    std::pair<u8, u8> getKeyLen(CurveType curveType);

protected:
    mbedtls_entropy_context entropy_;
    mbedtls_ctr_drbg_context ctr_drbg_;

    mbedtls_ecp_group_id getEcpGroupId(CurveType curveType);

    BspStatus loadPrivateKey(mbedtls_mpi *d, const u8* privateKey, size_t privateKeyLen);

    BspStatus loadPublicKey(const mbedtls_ecp_group *grp, mbedtls_ecp_point *Q, const u8* publicKey, size_t publicKeyLen);
    
};
}
