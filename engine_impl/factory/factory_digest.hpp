#ifndef ENGINE_IMPL_FACTORY_DIGEST_HPP
#define ENGINE_IMPL_FACTORY_DIGEST_HPP

#include "engine_result.hpp"
#include <openssl/evp.h>

namespace engine
{

class DigestFactory
{
public:

DigestFactory() = default;
~DigestFactory() = default;

virtual EngineResult<int> Init(EVP_MD_CTX *ctx) = 0;
virtual EngineResult<int> Update(EVP_MD_CTX *ctx, const void *in, size_t len) = 0;
virtual EngineResult<int> Final(EVP_MD_CTX *ctx, unsigned char *md) = 0;
virtual EngineResult<void> Cleanup(EVP_MD_CTX *ctx) = 0;

};

}



#endif 