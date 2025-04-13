#pragma once

#include "minitype.hpp"
#include "utils.hpp"
#include "ecc.hpp"
#include "mbedtls/ecdsa.h"

namespace dev {
class Ecdsa: public Ecc
{
public:
    Ecdsa();

    ~Ecdsa();

    void activate(){}

    void deactivate(){}

    BspStatus initContext(CurveType curveType, u8* peerPublicKey, u8* privateKey);

    BspStatus sign(u8* hash, u32 hashLen, u8* r, u8* s);

    BspStatus verify(u8* hash, u32 hashLen, u8* r, u8* s);

private:
    mbedtls_ecdsa_context ctx_;
    CurveType curveType_;
};
}
