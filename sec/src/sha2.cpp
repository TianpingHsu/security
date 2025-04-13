#include "sha2.hpp"
#include <stdio.h>
#include <string.h>

namespace dev {
Sha2::Sha2()
{
    mbedtls_md_init(&ctx_);
}

Sha2::~Sha2()
{
    mbedtls_md_free(&ctx_);
}

BspStatus Sha2::initContext(HashType type)
{
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(static_cast<mbedtls_md_type_t>(type));
    if(md_info == nullptr){
        return BspStatus::err;
    }
    
    if (mbedtls_md_setup(&ctx_, md_info, 0) != 0) {
        return BspStatus::err;
    }

    if (mbedtls_md_starts(&ctx_) != 0) {
        return BspStatus::err;
    }

    return BspStatus::ok;
}

BspStatus Sha2::hash(u8* data, u32 len, bool isLast, u8* hash, u8 hashSize)
{
    if(isLast && (hash == nullptr || hashSize == 0)){
        return BspStatus::err;
    }
    if (mbedtls_md_update(&ctx_, data, len) != 0) {
        return BspStatus::err;
    }
    if(isLast){
        if (mbedtls_md_finish(&ctx_, hash) != 0) {
            return BspStatus::err;
        }
    }

    return BspStatus::ok;
}

void Sha2::saveContext(Context& ctx)
{
    memcpy(&ctx, &ctx_, sizeof(Context));
}

void Sha2::restoreContext(Context& ctx)
{
    memcpy(&ctx_, &ctx, sizeof(Context));
}
}
