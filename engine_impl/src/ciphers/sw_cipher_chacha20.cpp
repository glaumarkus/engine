#include "sw_cipher_chacha20.hpp"

namespace Factory {
namespace SoftwareImpl {

std::size_t SwChaCha20::ImplCtxSize() const noexcept {
  return sizeof(SwChaCha20);
}

int SwChaCha20::Init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                      const unsigned char *iv, int enc) noexcept {
  ctx_ = EVP_CIPHER_CTX_new();
  enc_ = enc;
  int ok = 0;
  // handle encryption
  if (enc_ == 1) {
    ok = EVP_EncryptInit_ex(ctx_, EVP_chacha20(), nullptr, key, iv);
  } else if (enc_ == 0) {
    ok = EVP_DecryptInit_ex(ctx_, EVP_chacha20(), nullptr, key, iv);
  } else {
  }
  return ok;
}

int SwChaCha20::DoCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inlen) noexcept {
  int ok = 0;
  int len = 0;
  if (enc_ == 1) {
    ok = EVP_EncryptUpdate(ctx_, out, &len, in, inlen);
  } else if (enc_ == 0) {
    ok = EVP_DecryptUpdate(ctx_, out, &len, in, inlen);
  } else {
  }
  return ok;
}

int SwChaCha20::Cleanup(EVP_CIPHER_CTX *ctx) noexcept {
  EVP_CIPHER_CTX_free(ctx_);
  return 1;
}

int SwChaCha20::Ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                      void *ptr) noexcept {
  return EVP_CIPHER_CTX_ctrl(ctx_, type, arg, ptr);
}

} // namespace SoftwareImpl
} // namespace Factory