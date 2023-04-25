#ifndef ENGINE_IMPL_FACTORY_FACTORY_PKEY_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_PKEY_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

/**
 * \brief The FactoryPrivKey class is an interface to load Private Keys.
 */
class FactoryPrivKey {
public:
  /**
   * \brief Create the EVP_PKEY from the provided key_id.
   *
   * \param key_id The identifier of the key context. Can be for example the
   * path to the file in case of loading with openssl or the pkcs#11 URI string
   * to find on the PSC.
   * \return Returns pointer to EVP_PKEY on success and nullptr on failure.
   */
  virtual EVP_PKEY *Load(const char *key_id) noexcept = 0;
};

} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_FACTORY_PKEY_HPP
