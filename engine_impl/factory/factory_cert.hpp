#ifndef ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

/**
 * \brief The FactoryCertificate class is an interface to load Certificates.
 */
class FactoryCertificate {
public:
  /**
   * \brief Loads a certificate and private key from the specified sources.
   * \param cert_id Identification of the provided certificate. Can be an
   * absolute path for the SW implementation or a PKCS#11 URI for HW.
   * \return 1 on success, 0 on failure.
   */
  virtual int Load(const char *cert_id) noexcept = 0;

  /**
   * \brief Get a pointer to the X509 Object created by load.
   * \return certificate on succes, nullptr on failure.
   */
  virtual X509 *Get() const noexcept = 0;
};

} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP
