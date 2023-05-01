#include "engine_link.h"
#include <string>
#include <vector>
#include "src/engine_factory.hpp"


/* ecdsa mapping */
int ec_init(engine_factory_instance* instance, EVP_PKEY_CTX *ctx) {
  
  int ok = 0;
  // auto *factory = static_cast<Factory::SoftwareImpl::EngineFactory*>(instance->instance);
  // if (instance != nullptr)
  // {
  //   auto factory_ec = factory->GetEC(NID_secp384r1);
  //   auto *ec = static_cast<Factory::FactoryEC*>(factory_ec.release());
  //   EVP_PKEY_CTX_set_app_data(ctx, ec);
  //   if (ec != nullptr)
  //   {
  //     ok = ec->Init(ctx);
  //   }

  // }
  return ok;
}

int ec_cleanup(EVP_PKEY_CTX *ctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Cleanup(ctx);
  return 0;
}

int ec_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->SignInit(ctx, mctx);
  return 0;
}

int ec_verifyctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  //  auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->VerifyInit(ctx, mctx);
  return 0;
}

int ec_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  EVP_MD_CTX *mctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Sign(ctx, sig, siglen, mctx);
  return 0;
}

int ec_verifyctx(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                    EVP_MD_CTX *mctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Verify(ctx, sig, siglen, mctx);
  return 0;
}


int ec_custom_digest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->CustomDigest(ctx, mctx);
  return 0;
}

int ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Ctrl(ctx, type, p1, p2);
  return 0;
}

/* ecdh mapping */
int ec_derive_init(EVP_PKEY_CTX *ctx) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->DeriveInit(ctx);
  return 0;
}

int ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen) {
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Derive(ctx, key, keylen);
  return 0;
}

int ec_keygen_init(EVP_PKEY_CTX *ctx)
{
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->KeygenInit(ctx);
  return 0;
}

int ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{ 
  // auto *ec = reinterpret_cast<Factory::FactoryEC*>(EVP_PKEY_CTX_get_app_data(ctx));
  // return ec->Keygen(ctx, pkey);
  return 0;
}