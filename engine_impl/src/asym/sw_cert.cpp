#include "sw_cert.hpp"
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace Factory {
namespace SoftwareImpl {

// the cert_id is expected to be an absolute path
int SwCertificate::Load(const char *cert_id) noexcept  {
  int ok = 0;
  BIO *cert_bio = BIO_new_file(cert_id, "r");
  if (cert_bio) {
    cert_ = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    if (cert_) {
      ok = 1;
    }
  }
  return ok;
}

X509 *SwCertificate::Get() const noexcept  { return cert_; }

} // namespace SoftwareImpl
} // namespace Factory
