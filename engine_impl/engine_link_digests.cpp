#include "engine_link.h"
#include <iostream>

// can set data with EVP_MD_meth_set_app_datasize
struct sha256_digest_ctx {
  SHA256_CTX ctx;
};

/* sha256 mapping */
size_t sha256_size() { return sizeof(sha256_digest_ctx); }

int sha256_init(EVP_MD_CTX *ctx) {
  auto digest_ctx =
      reinterpret_cast<sha256_digest_ctx *>(EVP_MD_CTX_md_data(ctx));
  return SHA256_Init(&digest_ctx->ctx);
}

int sha256_update(EVP_MD_CTX *ctx, const void *in, size_t len) {
  auto digest_ctx =
      reinterpret_cast<sha256_digest_ctx *>(EVP_MD_CTX_md_data(ctx));
  return SHA256_Update(&digest_ctx->ctx, in, len);
}

int sha256_final(EVP_MD_CTX *ctx, unsigned char *md) {
  auto digest_ctx =
      reinterpret_cast<sha256_digest_ctx *>(EVP_MD_CTX_md_data(ctx));
  return SHA256_Final(md, &digest_ctx->ctx);
}

int sha256_cleanup(EVP_MD_CTX *ctx) { return 1; }

/* sha384 mapping */
struct sha384_digest_ctx {};

size_t sha384_size() { return sizeof(sha384_digest_ctx); }

int sha384_init(EVP_MD_CTX *ctx) {
  return EVP_DigestInit_ex(ctx, EVP_sha3_384(), nullptr);
}

int sha384_update(EVP_MD_CTX *ctx, const void *in, size_t len) {
  return EVP_DigestUpdate(ctx, in, len);
}

int sha384_final(EVP_MD_CTX *ctx, unsigned char *md) {
  unsigned int len = 0;
  return EVP_DigestFinal(ctx, md, &len);
}

int sha384_cleanup(EVP_MD_CTX *ctx) { return 1; }