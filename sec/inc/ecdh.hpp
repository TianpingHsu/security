#pragma once

#include "minitype.hpp"
#include "utils.hpp"
#include "ecc.hpp"
#include "mbedtls/ecdh.h"

namespace dev {
class Ecdh: public Ecc
{
public:
    enum class HashType : u8 {
        SHA_256,
        SHA_384,
        SHA_512,
    };

public:
    Ecdh();

    ~Ecdh();

    void activate(){}

    void deactivate(){}
   
    /**
     * Initializes the ECDH context with the specified elliptic curve.
     * 
     * @param curveType The type of elliptic curve to use for the ECDH context initialization.
     *                  Supported values are NIST_P256, NIST_P384, and NIST_P521.
     * @return BspStatus Returns BspStatus::ok if the initialization succeeds, or BspStatus::err 
     *                   if an error occurs (e.g., unsupported curve or failure to set up the context).
     */
    BspStatus initContext(CurveType curveType);

    /**
     * Computes the shared secret using Elliptic Curve Diffie-Hellman (ECDH).
     * 
     * @param curveType The type of elliptic curve to use for the computation.
     * @param peerPublicKey A byte array representing the peer's public key.
     *  LENGTH: 65 bytes for NIST_P256, 97 bytes for NIST_P384, 133 bytes for NIST_P521
     * @param privateKey A byte array representing the local private key.
     *  LENGTH: 32 bytes for NIST_P256, 48 bytes for NIST_P384, 66 bytes for NIST_P521
     * @param sharedSecret A buffer to store the resulting shared secret.
     *  LENGHTH: 32 bytes for NIST_P256, 48 bytes for NIST_P384, 66 bytes for NIST_P521
     * @return BspStatus Returns BspStatus::ok on success, or an error code otherwise.
     */
    BspStatus computeSharedSecret(u8* peerPublicKey, u8* privateKey, u8* sharedSecret);

    /**
     * Derives a key using a one-step key derivation function based on HMAC.
     *
     * @param hashType Type of the hash function to be used (SHA-256, SHA-384, SHA-512).
     * @param sharedSecret Pointer to the shared secret.
     * @param sharedSecretLen Length of the shared secret.
     * @param otherInfo Pointer to additional information to be included in the key derivation.
     * @param otherInfoLen Length of the additional information.
     * @param derivedKey Pointer to the buffer where the derived key will be stored.
     * @param derivedKeyLen Length of the derived key to be generated.
     * @return BspStatus::ok if the key derivation is successful, BspStatus::err otherwise.
     */
    BspStatus sskdf(HashType hashType, u8* sharedSecret, u8 sharedSecretLen, u8* otherInfo, u16 otherInfoLen, u8* derivedKey, u16 derivedKeyLen);
    
private:
    mbedtls_ecdh_context ctx_;
    CurveType curveType_;
};
}
