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
   *
   * \param engine The engine to use for loading the certificate and private
   * key.
   * \param ssl The SSL context to use for loading the certificate and
   * private key.
   * \param ca_dn The distinguished names of the CA certificates to
   * use for verifying the certificate chain.
   * \param pcert Output parameter for
   * the loaded certificate.
   * \param pkey Output parameter for the loaded private
   * key.
   * \param pother Output parameter for any additional certificates found
   * in the chain.
   * \param ui_method The user interface method to use for any
   * password prompts.
   * \param callback_data User-defined data to pass to the
   * password callback function.
   * \return 1 on success, 0 on failure.
   */
  virtual int Load(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) * ca_dn,
                   X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                   UI_METHOD *ui_method, void *callback_data) = 0;
};

} // namespace Factory

#endif ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP
