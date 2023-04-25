#ifndef ENGINE_IMPL_FACTORY_SRC_CIPHERS_SW_CIPHER_CHACHA20_HPP
#define ENGINE_IMPL_FACTORY_SRC_CIPHERS_SW_CIPHER_CHACHA20_HPP

#include <factory/factory_cipher.hpp>

namespace Factory {
namespace SoftwareImpl {

class SwChaCha20 : public FactoryCipher {
public:
  explicit SwChaCha20() = default;
  SwChaCha20(SwChaCha20 &) = delete;
  SwChaCha20(SwChaCha20 &&) = delete;
  SwChaCha20 &operator=(SwChaCha20 &) = delete;
  SwChaCha20 &operator=(SwChaCha20 &&) = delete;
  ~SwChaCha20() = default;

  std::size_t ImplCtxSize() const noexcept override;
  int Init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
           const unsigned char *iv, int enc) noexcept override;
  int DoCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
               size_t inlen) noexcept override;
  int Cleanup(EVP_CIPHER_CTX *ctx) noexcept override;
  int Ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) noexcept override;

private:
  EVP_CIPHER_CTX *ctx_;
  int enc_;
};

} // namespace SoftwareImpl
} // namespace Factory

#endif // ENGINE_IMPL_FACTORY_SRC_CIPHERS_SW_CIPHER_CHACHA20_HPP
