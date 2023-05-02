#include "sw_ec.hpp"
#include "digests/sw_digest_sha256.hpp"
#include "digests/sw_digest_sha384.hpp"
#include <cstring>
#include <memory>

namespace Factory {
namespace SoftwareImpl {

SwEc::SwEc(int nid) : nid_(nid) {}

int SwEc::Init(EVP_PKEY_CTX *ctx) noexcept { return 1; }

int SwEc::Cleanup(EVP_PKEY_CTX *ctx) noexcept {

  if (ctx_) {
    EVP_PKEY_CTX_free(ctx_);
  }

  if (sig_) {
    ECDSA_SIG_free(sig_);
  }

  return 1;
}

int SwEc::SignInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept {
  int ok = 0;
  sign_ = true;

  // cast key
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

  if (pkey) {
    // get ec key
    key_ = EVP_PKEY_get0_EC_KEY(pkey);

    // create ctx
    ctx_ = EVP_PKEY_CTX_new(pkey, nullptr);

    // set finalize flag
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);

    // set ok
    ok = 1;
  }

  return ok;
}

int SwEc::Sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
               EVP_MD_CTX *mctx) noexcept {
  int ok = 0;

  // get ecdsa signature if sign
  if (sign_) {
    sig_ = ECDSA_do_sign(sDigestStruct.hash, sDigestStruct.size, key_);
  }

  if (sig == nullptr) {
    int sig_len = i2d_ECDSA_SIG(sig_, nullptr);
    *siglen = static_cast<size_t>(sig_len);
    ok = 1;
  } else {
    int sig_len = i2d_ECDSA_SIG(sig_, &sig);
    *siglen = static_cast<size_t>(sig_len);
    ok = 1;
  }
  return ok;
}

int SwEc::VerifyInit(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept {
  int ok = 0;
  sign_ = false;

  // cast key
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

  if (pkey) {
    // get ec key
    peer_ = EVP_PKEY_get0_EC_KEY(pkey);

    // create ctx
    ctx_ = EVP_PKEY_CTX_new(pkey, nullptr);

    // set finalize flag
    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_FINALISE);

    ok = 1;
  }
  return ok;
}

int SwEc::Verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, int siglen,
                 EVP_MD_CTX *mctx) noexcept {
  int ok = 0;
  if (sig != nullptr) {
    // cast to ECDSA_SIG
    ECDSA_SIG *sig_cast = d2i_ECDSA_SIG(nullptr, &sig, siglen);
    ok = ECDSA_do_verify(sDigestStruct.hash, sDigestStruct.size, sig_cast,
                         peer_);
  }
  return ok;
}

int FindDigest(EVP_MD_CTX *ctx) noexcept {
  // find the digest type
  const EVP_MD *type = EVP_MD_CTX_md(ctx);

  // get NID from type
  int nid = EVP_MD_type(type);

  return nid;
}

int DoDigest(EVP_MD_CTX *ctx, FactoryDigest *digest, int nid, const void *data,
             size_t count) noexcept {
  int ok = 0;
  // check if implementation has been found and run through digest process
  if (digest != nullptr) {
    ok = digest->Init(ctx);
  }

  if (ok) {
    ok = digest->Update(ctx, data, count);
  }

  if (ok) {
    ok = digest->Final(ctx, sDigestStruct.hash);
  }

  if (ok) {
    sDigestStruct.size = EVP_MD_size(EVP_get_digestbynid(nid));
  }

  // free context
  EVP_MD_CTX_free(ctx);

  return ok;
}

int ECDSADigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count) {

  int nid = FindDigest(ctx);

  // init digest
  EVP_MD_CTX *ctx_f = EVP_MD_CTX_create();
  std::unique_ptr<Factory::FactoryDigest> digest{nullptr};

  // try to find implemented algorithm, can be or added later
  switch (nid) {
  case NID_sha256: {
    auto *sw_digest = new Factory::SoftwareImpl::SwSha256();
    digest = static_cast<std::unique_ptr<Factory::FactoryDigest>>(sw_digest);
    break;
  }

  case NID_sha384: {
    auto *sw_digest = new Factory::SoftwareImpl::SwSha384();
    digest = static_cast<std::unique_ptr<Factory::FactoryDigest>>(sw_digest);
    break;
  }

  default:
    break;
  }

  return DoDigest(ctx_f, digest.get(), nid, data, count);
}

int SwEc::CustomDigest(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) noexcept {
  int ok = 0;
  if (ctx_) {
    EVP_MD_CTX_set_update_fn(mctx, ECDSADigestUpdate);
    ok = 1;
  }
  return ok;
}

int SwEc::DeriveInit(EVP_PKEY_CTX *ctx) noexcept {

  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  ctx_ = EVP_PKEY_CTX_new(pkey, nullptr);
  return 1;
}

int SwEc::Derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                 size_t *keylen) noexcept {

  return EVP_PKEY_derive(ctx_, key, keylen);
}

int SwEc::KeygenInit(EVP_PKEY_CTX *ctx) noexcept { return 1; }

int SwEc::Keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) noexcept {
  key_ = EC_KEY_new_by_curve_name(nid_);
  int ok = EC_KEY_generate_key(key_);
  if (ok) {
    ok = EVP_PKEY_set1_EC_KEY(pkey, key_);
  }
  return ok;
}

int SwEc::Ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) noexcept {
  int ok = 0;
  switch (type) {
  case EVP_PKEY_CTRL_MD:
  case EVP_PKEY_CTRL_DIGESTINIT:
  case EVP_PKEY_EC:
  case EVP_PKEY_OP_DERIVE:
    ok = 1;
    break;
  case EVP_PKEY_CTRL_PEER_KEY:

    // exit if key is empty
    if (p2 == nullptr) {
      break;
    }

    // if correct type, cast
    if (p1 == 0) {
      // cast to key
      EVP_PKEY *peer_pub = static_cast<EVP_PKEY *>(p2);

      // check if it is an EC Pub key
      if (EVP_PKEY_id(peer_pub) != EVP_PKEY_EC) {
        break;
      }
      ok = EVP_PKEY_derive_init(ctx_);
      if (ok) {
        ok = EVP_PKEY_derive_set_peer(ctx_, peer_pub);
      }

    } else if (p1 == 1) {
      ok = 1;
      // not sure if required
      //   EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx, nullptr, 32);
    }
    break;
  }

  return ok;
}

} // namespace SoftwareImpl
} // namespace Factory
