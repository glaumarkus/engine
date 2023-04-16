#include "engine_link.h"
#include <iostream>

/* aes256 cbc mapping*/
struct aes256_cbc_ctx {
  EVP_CIPHER_CTX *ctx;
  int enc;
};
size_t aes256_cbc_size() { return sizeof(aes256_cbc_ctx); }

int aes256_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc) {
  aes256_cbc_ctx *cctx = new aes256_cbc_ctx;
  cctx->ctx = EVP_CIPHER_CTX_new();
  cctx->enc = enc;
  int ret = 0;
  if (enc == 1) {
    ret = EVP_EncryptInit_ex(cctx->ctx, EVP_aes_256_cbc(), nullptr, key, iv);
  } else {
    ret = EVP_DecryptInit_ex(cctx->ctx, EVP_aes_256_cbc(), nullptr, key, iv);
  }
  EVP_CIPHER_CTX_set_app_data(ctx, cctx);
  return ret;
}

int aes256_cbc_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  aes256_cbc_ctx *cctx = (aes256_cbc_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  int len = 0;
  int ret = 0;

  if (cctx->enc == 1) {
    ret = EVP_EncryptUpdate(cctx->ctx, out, &len, in, inlen);
  } else {
    ret = EVP_DecryptUpdate(cctx->ctx, out, &len, in, inlen);
  }
  return ret;
}

int aes256_cbc_cleanup(EVP_CIPHER_CTX *ctx) {
  aes256_cbc_ctx *cctx = (aes256_cbc_ctx *)EVP_CIPHER_CTX_get_app_data(ctx);
  EVP_CIPHER_CTX_free(cctx->ctx);
  delete cctx;
  return 1;
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

int aes256_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                    const unsigned char *iv, int enc) {
  return 1;
}
int aes256_gcm_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inlen) {
  return 1;
}
int aes256_gcm_cleanup(EVP_CIPHER_CTX *ctx) { return 1; }
size_t aes256_gcm_size() { return 1; }