#ifndef ENGINE_IMPL_SRC_ASYM_SW_EC_HPP
#define ENGINE_IMPL_SRC_ASYM_SW_EC_HPP

#include <factory/factory_ec.hpp>
#include <openssl/ec.h>

namespace Factory {
namespace SoftwareImpl {

class SwEc : public FactoryEC {
public:
  explicit SwEc() = default;
  SwEc(SwEc &) = delete;
  SwEc(SwEc &&) = delete;
  SwEc &operator=(SwEc &) = delete;
  SwEc &operator=(SwEc &&) = delete;
  ~SwEc() = default;

  int Init(EVP_PKEY_CTX *ctx) noexcept;
  int Cleanup(EVP_PKEY_CTX *ctx) noexcept;
  int SignInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept;
  int Sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
           EVP_MD_CTX *mctx) noexcept;
  int VerifyInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept;
  int Verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
             EVP_MD_CTX *mctx) noexcept;
  int CustomDigest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept;
  int DeriveInit(EVP_PKEY_CTX *ctx) noexcept;
  int Derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) noexcept;
  int KeygenInit(EVP_PKEY_CTX *ctx) noexcept;
  int Keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) noexcept;
  int Ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) noexcept;

  int ECDSADigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);

private:
  EVP_PKEY_CTX *ctx_{nullptr};

  // hold key for self and peer
  EC_KEY *key_{nullptr};
  EC_KEY *peer_{nullptr};

  // flag to see if sign or verify
  bool sign_{false};

  // used to store ECDSA
  ECDSA_SIG *sig_{nullptr};

  // used to store hash
  unsigned char hash_[EVP_MAX_MD_SIZE];
  unsigned int hash_size_{0};
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_SRC_ASYM_SW_EC_HPP
