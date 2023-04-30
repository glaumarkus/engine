#include "engine_link.h"
#include <iostream>
#include <cstring>

#include "src/engine_factory.hpp"

// can set EVP_CIPHER_meth_set_impl_ctx_size
/* aes256 cbc mapping*/
size_t aes256_cbc_size() { 
  return sizeof(Factory::FactoryCipher*); }

int aes256_cbc_init(engine_factory_instance* instance, EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc) {
  int ok = 0;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto factory_cipher = factory->GetCipher(NID_aes_256_cbc);
    auto *cipher = static_cast<Factory::FactoryCipher*>(factory_cipher.release());
    EVP_CIPHER_CTX_set_app_data(ctx, cipher);
    if (cipher != nullptr)
    {
      ok = cipher->Init(ctx, key, iv, enc);
    }
  }
  return ok;
}

int aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher*>(EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->DoCipher(ctx, out, in, inlen);
}

int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx) {
  auto *cipher = reinterpret_cast<Factory::FactoryCipher*>(EVP_CIPHER_CTX_get_app_data(ctx));
  return cipher->Cleanup(ctx);
}

/* chacha20 mapping*/
struct chacha20_ctx {
  EVP_CIPHER_CTX *ctx;
  int enc;
};
size_t chacha20_size() { return sizeof(chacha20_ctx); }
int chacha20_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                  const unsigned char *iv, int enc) {
  chacha20_ctx *cctx = new chacha20_ctx;
  cctx->ctx = EVP_CIPHER_CTX_new();
  cctx->enc = enc;
  int ret = 0;
  if (enc == 1) {
    ret = EVP_EncryptInit_ex(cctx->ctx, EVP_chacha20(), nullptr, key, iv);
  } else {
    ret = EVP_DecryptInit_ex(cctx->ctx, EVP_chacha20(), nullptr, key, iv);
  }
  EVP_CIPHER_CTX_set_app_data(ctx, cctx);
  return ret;
}

int chacha20_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inlen) {
  chacha20_ctx *cctx = (chacha20_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  int len = 0;
  int ret = 0;

  if (cctx->enc == 1) {
    ret = EVP_EncryptUpdate(cctx->ctx, out, &len, in, inlen);
  } else {
    ret = EVP_DecryptUpdate(cctx->ctx, out, &len, in, inlen);
  }
  return ret;
}

int chacha20_cleanup(EVP_CIPHER_CTX *ctx) {
  chacha20_ctx *cctx = (chacha20_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  EVP_CIPHER_CTX_free(cctx->ctx);
  delete cctx;
  return 1;
}

struct aes256_gcm_ctx {
  EVP_CIPHER_CTX *ctx;
  int enc;
  unsigned char *data;
  int data_len;
};

int set_auth_tag(EVP_CIPHER_CTX *ctx, int size, void *ptr) {
  aes256_gcm_ctx *cctx = (aes256_gcm_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  int len = 0;
  int ok = EVP_CIPHER_CTX_ctrl(cctx->ctx, EVP_CTRL_GCM_SET_TAG, size, ptr);
  if (ok) {
    ok = EVP_DecryptFinal_ex(cctx->ctx, cctx->data, &len);
  }
  return ok;
}

int get_auth_tag(EVP_CIPHER_CTX *ctx, int size, void *ptr) {
  aes256_gcm_ctx *cctx = (aes256_gcm_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  // only calling final will generate the tag
  int len = 0;
  int ok = EVP_EncryptFinal_ex(cctx->ctx, cctx->data + cctx->data_len, &len);
  if (ok) {
    cctx->data_len += len;
    ok = EVP_CIPHER_CTX_ctrl(cctx->ctx, EVP_CTRL_GCM_GET_TAG, size, ptr);
  }
  return ok;
}

int set_iv_len(EVP_CIPHER_CTX *ctx, int size) {
  aes256_gcm_ctx *cctx = (aes256_gcm_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  return EVP_CIPHER_CTX_ctrl(cctx->ctx, EVP_CTRL_GCM_SET_IVLEN, size, nullptr);
}

int aes256_gcm_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
  printf("aes256_gcm_ctrl called\n");
  printf("Params: \n");
  printf("ctx: %p, type: %d, arg: %d, ptr: %p\n", ctx, type, arg, ptr);
  int ok = 0;
  switch (type) {
  case EVP_CTRL_GCM_SET_TAG:
    ok = set_auth_tag(ctx, arg, ptr);
    printf("EVP_CTRL_GCM_SET_TAG called \n");
    break;
  case EVP_CTRL_GCM_GET_TAG:
    ok = get_auth_tag(ctx, arg, ptr);
    printf("EVP_CTRL_GCM_GET_TAG called\n");
    break;
  case EVP_CTRL_GCM_SET_IVLEN:
    ok = set_iv_len(ctx, arg);
    printf("EVP_CTRL_GCM_SET_IVLEN called\n");
    break;
  default:
    break;
  }
  return ok;
}

int aes256_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc) {

  aes256_gcm_ctx *cctx = new aes256_gcm_ctx;
  cctx->ctx = EVP_CIPHER_CTX_new();
  cctx->enc = enc;
  int ret = 0;
  if (enc == 1) {
    ret = EVP_EncryptInit_ex(cctx->ctx, EVP_aes_256_gcm(), nullptr, key, iv);
  } else {
    ret = EVP_DecryptInit_ex(cctx->ctx, EVP_aes_256_gcm(), nullptr, key, iv);
  }
  EVP_CIPHER_CTX_set_app_data(ctx, cctx);
  return 1;
}
int aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  aes256_gcm_ctx *cctx = (aes256_gcm_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  int len = 0;
  int ret = 0;

  if (cctx->enc == 1) {
    ret = EVP_EncryptUpdate(cctx->ctx, out, &len, in, inlen);
    if (ret) {
      // set size of buffer
      ret = len;
    }
    // check if aad is provided, out will be nullptr
    // if not, then set data and len
    // in case of additional calls, dont reset the data and only add to the size
    if (out) {
      if (!cctx->data) {
        cctx->data = out;
        cctx->data_len = len;
      } else {
        cctx->data_len += len;
      }
    }

  } else {
    ret = EVP_DecryptUpdate(cctx->ctx, out, &len, in, inlen);
    if (ret) {
      // set size of buffer
      ret = len;
    }
    // check if aad is provided, out will be nullptr
    // if not, then set data and len
    // in case of additional calls, dont reset the data and only add to the size
    if (out) {
      if (!cctx->data) {
        cctx->data = out;
        cctx->data_len = len;
      } else {
        cctx->data_len += len;
      }
    }
  }
  return ret;
  return 1;
}
int aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx) {
  aes256_gcm_ctx *cctx = (aes256_gcm_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  EVP_CIPHER_CTX_free(cctx->ctx);
  delete cctx;
  return 1;
}
size_t aes256_gcm_size() { return 1; }