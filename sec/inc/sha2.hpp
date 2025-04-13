#include "minitype.hpp"
#include "utils.hpp"
#include "mbedtls/md.h"

namespace dev {


class Sha2
{
public:
    enum class HashType{
        SHA224 = MBEDTLS_MD_SHA224,
        SHA256 = MBEDTLS_MD_SHA256,
        SHA384 = MBEDTLS_MD_SHA384,
        SHA512 = MBEDTLS_MD_SHA512,
    };
    using Context = mbedtls_md_context_t;
public:
    Sha2();

    ~Sha2();
    
    void activate(){}

    void deactivate(){}

    /**
     * Initializes the SHA2 context.
     * 
     * This function sets up the SHA2 context based on the specified hash type.
     * It uses the Mbed TLS library to configure the context for the given hash algorithm.
     * 
     * @param type The hash type (e.g., SHA-256, SHA-384, SHA-512) as defined in the HashType enumeration.
     * 
     * @return BspStatus::ok if the initialization is successful; otherwise, BspStatus::err.
     */
    BspStatus initContext(HashType type);

    /**
     * @brief Computes the SHA-2 hash for the given data block.
     * 
     * This function processes a block of data to compute its hash. If this is the last 
     * data block, it finalizes the hash computation and stores the result in the `hash` buffer.
     * 
     * @param data Pointer to the data block to be hashed.
     * @param len Length of the data block to be hashed.
     * @param isLast Flag indicating whether this is the last data block.
     * @param hash Pointer to the buffer where the final hash will be stored (only used if `isLast` is true).
     * @param hashSize Size of the `hash` buffer.
     * 
     * @return BspStatus::ok if the operation was successful, BspStatus::err otherwise.
     */
    BspStatus hash(u8* data, u32 len, bool isLast = false, u8* hash = nullptr, u8 hashSize = 0);

    void saveContext(Context& ctx);

    void restoreContext(Context& ctx);

private:
    mbedtls_md_context_t ctx_;
};
}
