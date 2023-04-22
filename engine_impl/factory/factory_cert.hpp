#ifndef ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP
#define ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP

#include <cstdint>
#include <openssl/evp.h>

namespace Factory {

class FactoryCertificate {
public:
  virtual int Load(ENGINE *engine, SSL *ssl, STACK_OF(X509_NAME) * ca_dn,
                   X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                   UI_METHOD *ui_method, void *callback_data) = 0;
};

} // namespace Factory

#endif ENGINE_IMPL_FACTORY_FACTORY_CERT_HPP
