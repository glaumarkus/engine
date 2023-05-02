#ifndef ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PKEY_HPP
#define ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PKEY_HPP

#include <factory/factory_pkey.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwPrivKey : public FactoryPrivKey {
public:
  explicit SwPrivKey() = default;
  SwPrivKey(SwPrivKey &) = delete;
  SwPrivKey(SwPrivKey &&) = delete;
  SwPrivKey &operator=(SwPrivKey &) = delete;
  SwPrivKey &operator=(SwPrivKey &&) = delete;
  ~SwPrivKey() = default;

  EVP_PKEY *Load(const char *key_id) noexcept override;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_ASYM_SW_PKEY_HPP
