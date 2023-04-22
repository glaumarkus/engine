#ifndef ENGINE_IMPL_FACTORY_FACTORY_PUBKEY_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_PUBKEY_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

class FactoryPubKey {
public:
  virtual EVP_PKEY *Load(const char *key_id) = 0;
};

} // namespace Factory

#endif ENGINE_IMPL_FACTORY_FACTORY_PUBKEY_HPP
