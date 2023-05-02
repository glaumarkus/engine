#include "engine_link.h"
#include <cstring>
#include <iostream>

#include "src/engine_factory.hpp"

// can set EVP_CIPHER_meth_set_impl_ctx_size
/* aes256 cbc mapping*/
size_t aes256_cbc_size() { return sizeof(Factory::FactoryCipher *); }

int aes256_cbc_init(engine_factory_instance *instance, EVP_CIPHER_CTX *ctx,
                    const unsigned char *key, const unsigned char *iv,
                    int enc) {
  int ok = 0;
  auto *factory =
      static_cast<Factory::SoftwareImpl::EngineFactory *>(instance->instance);
  if (factory != nullptr) {
    auto factory_cipher = factory->GetCipher(NID_aes_256_cbc);
    auto *cipher =
        static_cast<Factory::FactoryCipher *>(factory_cipher.release());
    EVP_CIPHER_CTX_set_app_data(ctx, cipher);
    if (cipher != nullptr) {
      ok = cipher->Init(ctx, key, iv, enc);
    }
  }
  return ok;
}

int aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->DoCipher(ctx, out, in, inlen);
}

int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->Cleanup(ctx);
}

/* chacha20 mapping*/

size_t chacha20_size() { return sizeof(Factory::FactoryCipher *); }

int chacha20_init(engine_factory_instance *instance, EVP_CIPHER_CTX *ctx,
                  const unsigned char *key, const unsigned char *iv, int enc) {
  int ok = 0;
  auto *factory =
      static_cast<Factory::SoftwareImpl::EngineFactory *>(instance->instance);
  if (factory != nullptr) {
    auto factory_cipher = factory->GetCipher(NID_chacha20);
    auto *cipher =
        static_cast<Factory::FactoryCipher *>(factory_cipher.release());
    EVP_CIPHER_CTX_set_app_data(ctx, cipher);
    if (cipher != nullptr) {
      ok = cipher->Init(ctx, key, iv, enc);
    }
  }
  return ok;
}

int chacha20_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inlen) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->DoCipher(ctx, out, in, inlen);
}

int chacha20_cleanup(EVP_CIPHER_CTX *ctx) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->Cleanup(ctx);
}

size_t aes256_gcm_size() {
  { return sizeof(Factory::FactoryCipher *); }
}

int aes256_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->Ctrl(ctx, type, arg, ptr);
}

int aes256_gcm_init(engine_factory_instance *instance, EVP_CIPHER_CTX *ctx,
                    const unsigned char *key, const unsigned char *iv,
                    int enc) {
  int ok = 0;
  auto *factory =
      static_cast<Factory::SoftwareImpl::EngineFactory *>(instance->instance);
  if (factory != nullptr) {
    auto factory_cipher = factory->GetCipher(NID_aes_256_gcm);
    auto *cipher =
        static_cast<Factory::FactoryCipher *>(factory_cipher.release());
    EVP_CIPHER_CTX_set_app_data(ctx, cipher);
    if (cipher != nullptr) {
      ok = cipher->Init(ctx, key, iv, enc);
    }
  }
  return ok;
}
int aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->DoCipher(ctx, out, in, inlen);
}
int aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher *>(
      EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->Cleanup(ctx);
}
