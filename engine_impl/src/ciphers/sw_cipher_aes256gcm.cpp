#include "sw_cipher_aes256gcm.hpp"
#include <openssl/evp.h>

namespace Factory {
namespace SoftwareImpl {

std::size_t SwAes256Gcm::ImplCtxSize() const noexcept {
  return sizeof(SwAes256Gcm);
}

int SwAes256Gcm::Init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                      const unsigned char *iv, int enc) noexcept {
  ctx_ = EVP_CIPHER_CTX_new();
  enc_ = enc;
  int ok = 0;
  // handle encryption
  if (enc_ == 1) {
    ok = EVP_EncryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, key, iv);
  } else if (enc_ == 0) {
    ok = EVP_DecryptInit_ex(ctx_, EVP_aes_256_gcm(), nullptr, key, iv);
  } else {
  }
  return ok;
}

int SwAes256Gcm::DoCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t inlen) noexcept {
  int ok = 0;
  int len = 0;
  if (enc_ == 1) {
    ok = EVP_EncryptUpdate(ctx_, out, &len, in, inlen);
    // set size of buffer after operation
    if (ok)
    {
        ok = len;
    }

    // out is nullptr when using aad
    if (out)
    {
        if (!in_)
        {
            in_ = out;
            len_ = len;
        }
        else
        {
            len_ += len;
        }
    }
    
  } else if (enc_ == 0) {
    ok = EVP_DecryptUpdate(ctx_, out, &len, in, inlen);
    if (ok) {
      ok = len;
    }
    
    // out is nullptr
    if (out) {
      if (!in_) {
        in_ = out;
        len_ = len;
      } else {
        len_ += len;
      }
    }

  } else {
  }
  return ok;
}

int SwAes256Gcm::Cleanup(EVP_CIPHER_CTX *ctx) noexcept {
  EVP_CIPHER_CTX_free(ctx_);
  return 1;
}

int SwAes256Gcm::Ctrl(EVP_CIPHER_CTX *ctx, int type, int arg,
                      void *ptr) noexcept {
    int ok = 0;
    int len = 0;
    switch (type)
    {
        case EVP_CTRL_GCM_SET_TAG:
            ok = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_TAG, arg, ptr);
            if (ok)
            {
              ok = EVP_DecryptFinal_ex(ctx_, in_ + len_, &len);
            }
            break;
        case EVP_CTRL_GCM_GET_TAG:
            ok = EVP_EncryptFinal_ex(ctx_, in_ + len_, &len);
            if (ok)
            {
              ok = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_GET_TAG, arg, ptr);
            }
            break;
        case EVP_CTRL_GCM_SET_IVLEN:
            ok = EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_GCM_SET_IVLEN, arg, nullptr);
            break;
        default:
            break;
    }
  return ok;
}

} // namespace SoftwareImpl
} // namespace Factory