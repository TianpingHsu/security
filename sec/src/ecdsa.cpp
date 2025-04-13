#include "ecdsa.hpp"
#include <stdio.h>
#include <string.h>

namespace dev {
Ecdsa::Ecdsa()
{
    mbedtls_ecdsa_init(&ctx_);
}

Ecdsa::~Ecdsa()
{
    mbedtls_ecdsa_free(&ctx_);
}

BspStatus Ecdsa::initContext(CurveType curveType, u8* peerPublicKey, u8* privateKey)
{
    curveType_ = curveType;

    mbedtls_ecp_group_load(&ctx_.private_grp, getEcpGroupId(curveType));

    // Load the private key from a byte array into the elliptic curve point
    auto privateKeyLen = getKeyLen(curveType).first;
    if (privateKey != nullptr && loadPrivateKey(&ctx_.private_d, privateKey, privateKeyLen) != BspStatus::ok) {
        return BspStatus::err;
    }

    // Load the peer's public key from a byte array into the elliptic curve point
    auto publicKeyLen = getKeyLen(curveType).second;
    if (peerPublicKey != nullptr && loadPublicKey(&ctx_.private_grp, &ctx_.private_Q, peerPublicKey, publicKeyLen) != BspStatus::ok) {
        return BspStatus::err;
    }

    return BspStatus::ok;
}

BspStatus Ecdsa::sign(u8* hash, u32 hashLen, u8* r, u8* s)
{
    mbedtls_mpi mpi_r, mpi_s;
    size_t r_len, s_len;

    if(hashLen < getKeyLen(curveType_).first){
        return BspStatus::err;
    }

    mbedtls_mpi_init(&mpi_r);
    mbedtls_mpi_init(&mpi_s);

    // generate signature
    if (mbedtls_ecdsa_sign(&ctx_.private_grp, &mpi_r, &mpi_s, &ctx_.private_d, hash, hashLen, mbedtls_ctr_drbg_random, &ctr_drbg_) != 0) {
        printf("Failed to generate signature.\n");
        return BspStatus::err;
    }

    // convert MPI to byte arrays
    r_len = mbedtls_mpi_size(&mpi_r);
    s_len = mbedtls_mpi_size(&mpi_s);

    if (mbedtls_mpi_write_binary_le(&mpi_r, r, r_len) != 0 ||
        mbedtls_mpi_write_binary_le(&mpi_s, s, s_len) != 0) {
        printf("Failed to write r and s to byte arrays.\n");
        return BspStatus::err;
    }

    mbedtls_mpi_free(&mpi_r);
    mbedtls_mpi_free(&mpi_s);

    return BspStatus::ok;
}

BspStatus Ecdsa::verify(u8* hash, u32 hashLen, u8* r, u8* s)
{
    mbedtls_mpi mpi_r, mpi_s;
    u8 rsLen = getKeyLen(curveType_).first;

    mbedtls_mpi_init(&mpi_r);
    mbedtls_mpi_init(&mpi_s);

    if (mbedtls_mpi_read_binary_le(&mpi_r, r, rsLen) != 0 ||
        mbedtls_mpi_read_binary_le(&mpi_s, s, rsLen) != 0) {
        printf("Failed to read r and s to mpi.\n");
        return BspStatus::err;
    }

    if (mbedtls_ecdsa_verify(&ctx_.private_grp, hash, hashLen, &ctx_.private_Q, &mpi_r, &mpi_s) != 0) {
        printf("Signature verification failed.\n");
        return BspStatus::err;
    }

    return BspStatus::ok;
}
}
