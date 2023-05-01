#include "engine_link.h"
#include "src/engine_factory.hpp"
#include <iostream>

EVP_PKEY *load_private_key(struct engine_factory_instance* instance, const char *keyfile) {
  
  EVP_PKEY *pkey = nullptr;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto pkey_loader = factory->GetPrivateKeyLoader();
    if (pkey_loader != nullptr)
    {
      pkey = pkey_loader->Load(keyfile);
    }
  }

  return pkey;
}

EVP_PKEY *load_public_key(struct engine_factory_instance* instance, const char *keyfile) {
  
  EVP_PKEY *pubkey = nullptr;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto pubkey_loader = factory->GetPublicKeyLoader();
    if (pubkey_loader != nullptr)
    {
      pubkey = pubkey_loader->Load(keyfile);
    }
  }

  return pubkey;
}
