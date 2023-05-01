#include "engine_link.h"
#include <string>
#include <vector>

#include "src/engine_factory.hpp"

// can be retrieved with EVP_PKEY_CTX_set_data EVP_PKEY_CTX_get_data
struct ecdsa_mapping {
  EC_KEY *ec_key;
  ECDSA_SIG *sig;
  int type;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_size;
};

static ecdsa_mapping *ecdsa_ctx = nullptr;

/* ecdsa mapping */
int ecdsa_init(engine_factory_instance* instance, EVP_PKEY_CTX *ctx) {

  int ok = 0;
  auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  if (factory != nullptr)
  {
    auto factory_ec = factory->GetEC(NID_chacha20);
    auto *ec = static_cast<Factory::FactoryEC*>(factory_ec.release());
    EVP_PKEY_CTX_set_app_data(ctx, ec);
    if (ec != nullptr)
    {
      ok = ec->Init(ctx);
    }
  }
  return ok;
}

int ecdsa_cleanup(EVP_PKEY_CTX *ctx) {
  auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  return ec->Cleanup(ctx);
}

int ecdsa_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {


  // set operation
  ecdsa_ctx->type = 1;

  // cast key
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  ecdsa_ctx->ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  // set flags
  EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);
  return 1;
}

int ecdsa_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {

  // set operation
  ecdsa_ctx->type = 0;

  // cast key
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  ecdsa_ctx->ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  // set flags
  EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);
  return 1;
}

int ecdsa_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  EVP_MD_CTX *mctx) {
  int ok = 0;
  if (sig == nullptr) {
    int sig_len = i2d_ECDSA_SIG(ecdsa_ctx->sig, nullptr);
    *siglen = (size_t)sig_len;
    ok = 1;
  } else {
    int sig_len = i2d_ECDSA_SIG(ecdsa_ctx->sig, &sig);
    *siglen = (size_t)sig_len;
    ok = 1;
  }
  return ok;
}

int ecdsa_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                    EVP_MD_CTX *mctx) {
  int ok = 0;
  if (sig != nullptr) {
    // cast to ECDSA_SIG
    ECDSA_SIG *sig_cast = d2i_ECDSA_SIG(nullptr, &sig, siglen);
    ok = ECDSA_do_verify(ecdsa_ctx->hash, ecdsa_ctx->hash_size, sig_cast,
                         ecdsa_ctx->ec_key);
  }
  return ok;
}

int ecdsa_custom_digest_update(EVP_MD_CTX *ctx, const void *data,
                               size_t count) {
  int ret = 0;

  // find the digest type
  const EVP_MD *type = EVP_MD_CTX_md(ctx);

  // get NID from type
  int nid = EVP_MD_type(type);

  // get alg from nid
  const EVP_MD *sw_type = EVP_get_digestbynid(nid);

  // create hash ctx
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

  // init hash
  ret = EVP_DigestInit_ex(mdctx, sw_type, NULL);
  if (ret != 1) {
    return ret;
  }

  // update hash
  ret = EVP_DigestUpdate(mdctx, data, count);
  if (ret != 1) {
    return ret;
  }

  // finalize hash
  ret = EVP_DigestFinal_ex(mdctx, ecdsa_ctx->hash, &ecdsa_ctx->hash_size);
  if (ret != 1) {
    return ret;
  }

  // free
  EVP_MD_CTX_free(mdctx);

  // if EVP_PKEY is used for signing, issue the sign
  if (ecdsa_ctx->type == 1) {
    ecdsa_ctx->sig = ECDSA_do_sign(ecdsa_ctx->hash, (int)ecdsa_ctx->hash_size,
                                   ecdsa_ctx->ec_key);
  }

  return ret;
}

int ecdsa_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  int ok = 0;
  if (ecdsa_ctx) {
    EVP_MD_CTX_set_update_fn(mctx, ecdsa_custom_digest_update);
    ok = 1;
  }

  return ok;
}

struct ecdh_data {
  EVP_PKEY_CTX *ctx;
  EC_KEY *key;
  EC_KEY *other_key;
};

static ecdh_data *ecdh_ctx = nullptr;

int ecdsa_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  printf("ecdsa_ctrl called\n");
  printf("Params: \n");
  printf("ctx: %p, type: %d, p1: %d, p2: %p\n", ctx, type, p1, p2);
  int ok = 1;
  switch (type) {
  case EVP_PKEY_CTRL_MD:
    break;
  case EVP_PKEY_CTRL_DIGESTINIT:
    break;
  case EVP_PKEY_EC:
    break;
  case EVP_PKEY_OP_DERIVE:
    break;
  case EVP_PKEY_CTRL_PEER_KEY:

    if (p2 == nullptr) {
      ok = 0;
      break;
    }

    if (p1 == 0) {
      // cast to key
      EVP_PKEY *peer_pub = (EVP_PKEY *)p2;

      // check if it is an EC Pub key
      if (EVP_PKEY_id(peer_pub) != EVP_PKEY_EC) {
        ok = 0;
        break;
      }
      ok = EVP_PKEY_derive_init(ecdh_ctx->ctx);
      ok = EVP_PKEY_derive_set_peer(ecdh_ctx->ctx, peer_pub);

    } else if (p1 == 1) {
      EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, nullptr, 32);
    }
    // EVP_PKEY_CTX_set_ecdh_kdf_md ??
    break;
  }

  return ok;
}

/* ecdh mapping */
int ecdh_derive_init(EVP_PKEY_CTX *ctx) {

  ecdh_ctx = new ecdh_data;
  // get key
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  ecdh_ctx->ctx = EVP_PKEY_CTX_new(pkey, nullptr);

  // set outlen
  EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, 32);

  // EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID(ctx, )
  // EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, 32);
  EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, 32);
  // EVP_PKEY_CTX_set_dh_kdf_outlen
  EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, 32);
  // EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, nullptr, 32);
  return 1;
}

int ecdh_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
  return EVP_PKEY_derive(ecdh_ctx->ctx, key, keylen);
}

int ecdh_set_peer(EC_KEY *other_key) {
  const unsigned char *key_mem = (const unsigned char *)other_key;
  ecdh_ctx->other_key = d2i_EC_PUBKEY(NULL, &key_mem, 1);
  ;
  int ret = EC_KEY_check_key(ecdh_ctx->other_key);
  return ret;
}

int ecdh_get_shared_secret() { return 1; }