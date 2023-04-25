#ifndef ENGINE_IMPL_FACTORY_SRC_ASYM_SW_CERT_HPP
#define ENGINE_IMPL_FACTORY_SRC_ASYM_SW_CERT_HPP

#include <factory/factory_cert.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwCertificate : public FactoryCertificate {
public:
  explicit SwCertificate() = default;
  SwCertificate(SwCertificate &) = delete;
  SwCertificate(SwCertificate &&) = delete;
  SwCertificate &operator=(SwCertificate &) = delete;
  SwCertificate &operator=(SwCertificate &&) = delete;
  ~SwCertificate() = default;

  int Load(const char *cert_id) noexcept override;
  X509 *Get() const noexcept override;

private:
  X509 *cert_ = nullptr;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_ASYM_SW_CERT_HPP
