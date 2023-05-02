#ifndef ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PUBKEY_HPP
#define ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PUBKEY_HPP

#include <factory/factory_pubkey.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwPubKey : public FactoryPubKey {
public:
  explicit SwPubKey() = default;
  SwPubKey(SwPubKey &) = delete;
  SwPubKey(SwPubKey &&) = delete;
  SwPubKey &operator=(SwPubKey &) = delete;
  SwPubKey &operator=(SwPubKey &&) = delete;
  ~SwPubKey() = default;

  EVP_PKEY *Load(const char *key_id) noexcept override;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PUBKEY_HPP
