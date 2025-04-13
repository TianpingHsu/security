#include "ecc.hpp"

namespace dev {

BspStatus Ecc::generateKeyPair(CurveType curveType, u8* publicKey, u8* privateKey)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);

    // Generate the key pair
    if (mbedtls_ecp_gen_key(getEcpGroupId(curveType), &keypair, mbedtls_ctr_drbg_random, &ctr_drbg_) != 0) {
        printf("Failed to generate ECC keypair\n");
        return BspStatus::err;
    }

    // Write the private key to the output buffer
    auto privateKeyLen = getKeyLen(curveType).first;
    if (mbedtls_mpi_write_binary(&keypair.private_d, privateKey, privateKeyLen) != 0) {
        return BspStatus::err;
    }

    // Write the public key to the output buffer
    size_t publicKeyLen = getKeyLen(curveType).second;
    if (mbedtls_ecp_point_write_binary(&keypair.private_grp, 
                                        &keypair.private_Q, 
                                        MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &publicKeyLen, publicKey, publicKeyLen) != 0) {
        return BspStatus::err;
    }
    mbedtls_ecp_keypair_free(&keypair);

    return BspStatus::ok;
}

BspStatus Ecc::computePublicKey(CurveType curveType, const u8* privateKey, u8* publicKey)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_group_load(&grp, getEcpGroupId(curveType));

    loadPrivateKey(&d, privateKey, getKeyLen(curveType).first);

    // Q = d * G
    mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, nullptr, nullptr);

    // Write the public key to the output buffer
    size_t publicKeyLen = getKeyLen(curveType).second;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &publicKeyLen, publicKey, publicKeyLen) != 0) {
        return BspStatus::err;
    }
    
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);

    return BspStatus::ok;
}

BspStatus Ecc::loadPrivateKey(mbedtls_mpi *d, const u8* privateKey, size_t privateKeyLen)
{
    mbedtls_mpi_init(d);
    // load mpi from byte array
    if (mbedtls_mpi_read_binary(d, privateKey, privateKeyLen) != 0) {
        return BspStatus::err;
    }

    return BspStatus::ok;
}

BspStatus Ecc::loadPublicKey(const mbedtls_ecp_group *grp, mbedtls_ecp_point *Q, const u8* publicKey, size_t publicKeyLen)
{
    if (mbedtls_ecp_point_read_binary(grp, Q, publicKey, publicKeyLen) != 0) {
        return BspStatus::err;
    }

    return BspStatus::ok;
}

mbedtls_ecp_group_id Ecc::getEcpGroupId(CurveType curveType)
{
    mbedtls_ecp_group_id groupIdList[] = {
        MBEDTLS_ECP_DP_SECP256R1, 
        MBEDTLS_ECP_DP_SECP384R1, 
        MBEDTLS_ECP_DP_SECP521R1
    };
    return groupIdList[static_cast<u8>(curveType)];
}

std::pair<u8, u8> Ecc::getKeyLen(CurveType curveType)
{
    std::pair<u8, u8> len;
    if(curveType == CurveType::NIST_P384){
        len.first = 48;
        len.second = 97;
    }
    else if(curveType == CurveType::NIST_P256){
        len.first = 32;
        len.second = 65;
    }
    else if(curveType == CurveType::NIST_P521){
        len.first = 66;
        len.second = 133;
    }

    return len;
}
}
