#include "ecdh.hpp"
#include <stdio.h>
#include "mbedtls/md.h"

namespace dev {
Ecdh::Ecdh()
{
    mbedtls_ecdh_init(&ctx_);
}

Ecdh::~Ecdh()
{
    mbedtls_ecdh_free(&ctx_);
}

BspStatus Ecdh::initContext(CurveType curveType)
{
    mbedtls_ecp_group_id grp_id = getEcpGroupId(curveType);
    if (mbedtls_ecdh_setup(&ctx_, grp_id) != 0) {
        printf("Failed to setup ECDH context.\n");
        return BspStatus::err;
    }
    curveType_ = curveType;
    
    return BspStatus::ok;
}

BspStatus Ecdh::computeSharedSecret(u8* peerPublicKey, u8* privateKey, u8* sharedSecret)
{
    // Load the peer's public key from a byte array into the elliptic curve point
    size_t peerPublicKeyLen = getKeyLen(curveType_).second;
    loadPublicKey(&ctx_.private_ctx.private_mbed_ecdh.private_grp, &ctx_.private_ctx.private_mbed_ecdh.private_Qp, peerPublicKey, peerPublicKeyLen);

    // Load the private key from a byte array into the elliptic curve point
    size_t privateKeyLen = getKeyLen(curveType_).first;
    loadPrivateKey(&ctx_.private_ctx.private_mbed_ecdh.private_d, privateKey, privateKeyLen);

    // Compute the shared secret using the local private key and the peer's public key
    size_t sharedSecretLen = privateKeyLen;
    if (mbedtls_ecdh_calc_secret(&ctx_, &sharedSecretLen, sharedSecret, sharedSecretLen, mbedtls_ctr_drbg_random, &ctr_drbg_) != 0) {
        printf("Failed to compute shared secret.\n");
        return BspStatus::err;
    }

    return BspStatus::ok;
}

BspStatus Ecdh::sskdf(HashType hashType, u8* sharedSecret, u8 sharedSecretLen, u8* otherInfo, u16 otherInfoLen, u8* derivedKey, u16 derivedKeyLen)
{
    u8 hashLenList[] {32, 48, 64};
    mbedtls_md_type_t modeList[] {MBEDTLS_MD_SHA256, MBEDTLS_MD_SHA384, MBEDTLS_MD_SHA512};
    u8 hashLen = hashLenList[static_cast<u8>(hashType)];
    u8 hash[64];   //Considering the actual application, the maximum length of the key is 64 bytes

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(modeList[static_cast<u8>(hashType)]);
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    if (mbedtls_md_setup(&md_ctx, md_info, 0) != 0) {
        return BspStatus::err;
    }

    // NIST SP 800-56A Rev. 2: 2013, 5.8.1.1
    // 1. reps =  keydatalen / hashlen. 
    // 2. If reps > (232 −1), then return an error indicator without performing the remaining actions. 
    // 3. Initialize a 32-bit, big-endian bit string counter as 0000000116 (i.e. 0x00000001). 
    // 4. If counter || Z || OtherInfo is more than max_H_inputlen bits long, 
    // then return an error indicator without performing the remaining actions. 
    // 5. For i = 1 to reps by 1, do the following: 
    // 5.1  Compute K(i) = H(counter || Z || OtherInfo). 
    // 5.2  Increment counter (modulo 232), treating it as an unsigned 32-bit integer. 
    // 6. Let K_Last be set to K(reps) if (keydatalen / hashlen) is an integer; otherwise, let K_Last 
    // be set to the (keydatalen mod hashlen) leftmost bits of K(reps). 
    // 7. Set DerivedKeyingMaterial = K(1) || K(2) || … || K(reps-1) || K_Last. 

    u32 reps = derivedKeyLen / hashLen;
    if(derivedKeyLen % hashLen != 0){
        reps += 1;
    }
    u8 tmpbuf[4];
    for(u32 counter = 1; counter <= reps; counter++){
        // Little endian -> Bit endian
        tmpbuf[0] = counter >> 24;
        tmpbuf[1] = (counter >> 16) & 0xFF;
        tmpbuf[2] = (counter >> 8) & 0xFF;
        tmpbuf[3] = counter & 0xFF;
        if (mbedtls_md_starts(&md_ctx) != 0) {
            return BspStatus::err;
        }
        if (mbedtls_md_update(&md_ctx, tmpbuf, sizeof(tmpbuf)) != 0) {
            return BspStatus::err;
        }
        if (mbedtls_md_update(&md_ctx, sharedSecret, sharedSecretLen) != 0) {
            return BspStatus::err;
        }
        if (mbedtls_md_update(&md_ctx, otherInfo, otherInfoLen) != 0) {
            return BspStatus::err;
        }
        if (mbedtls_md_finish(&md_ctx, &hash[(counter-1)*hashLen]) != 0) {
            return BspStatus::err;
        }
    }
    memcpy(derivedKey, hash, derivedKeyLen);
    mbedtls_md_free(&md_ctx);

    return BspStatus::ok;
}
}
