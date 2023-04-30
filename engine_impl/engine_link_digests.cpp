#include "engine_link.h"
#include <iostream>
#include <cstring>

#include "src/engine_factory.hpp"


/* sha256 mapping */
size_t sha256_size() { 
  return sizeof(Factory::FactoryDigest*); }

int sha256_init(struct engine_factory_instance* instance, EVP_MD_CTX *ctx) {
  
  int ok = 0;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto factory_digest = factory->GetDigest(NID_sha256);
    auto *digest = static_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    auto *dest = std::memmove(digest, factory_digest.get(), sizeof(Factory::FactoryDigest));
    if (dest != nullptr)
    {
      ok = digest->Init(ctx);
    }
  }
  return ok;
}

int sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len) {  
  auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
  return digest->Update(ctx, in, len);
}

int sha256_final(EVP_MD_CTX *ctx, unsigned char *md) {
  auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
  return digest->Final(ctx, md);
}

int sha256_cleanup(EVP_MD_CTX *ctx) { 
    auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    return digest->Cleanup(ctx);
}

/* sha384 mapping */
size_t sha384_size() { return sizeof(Factory::FactoryDigest*);  }

int sha384_init(struct engine_factory_instance* instance, EVP_MD_CTX *ctx) {
    int ok = 0;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto factory_digest = factory->GetDigest(NID_sha384);
    auto *digest = static_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    auto *dest = std::memmove(digest, factory_digest.get(), sizeof(Factory::FactoryDigest));
    if (dest != nullptr)
    {
      ok = digest->Init(ctx);
    }
  }
  return ok;
}

int sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len) {
      auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    return digest->Update(ctx, in, len);
}

int sha384_final(EVP_MD_CTX *ctx, unsigned char *md) {
      auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    return digest->Final(ctx, md);
}

int sha384_cleanup(EVP_MD_CTX *ctx) {    auto *digest = reinterpret_cast<Factory::FactoryDigest*>(EVP_MD_CTX_md_data(ctx));
    return digest->Cleanup(ctx);}