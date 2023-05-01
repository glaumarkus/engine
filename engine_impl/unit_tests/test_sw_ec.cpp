/*
Testing:
- key derivation
- ecdsa sign
- ecdsa verify
- key derivation
*/
#include "asym/sw_ec.hpp"
#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <string>

#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Tests
class Test_EC : public ::testing::Test {
protected:
  void SetUp() override {}
};

// used for ECDHE
TEST_F(Test_EC, TestECGen) {
  // set seed for deterministic results
  std::vector<std::uint8_t> seed{0xff, 0xff, 0xff, 0xff};
  RAND_seed(seed.data(), seed.size());
  Factory::SoftwareImpl::SwEc ec(NID_secp384r1);

  // generate
  auto *ctx = EVP_PKEY_CTX_new(nullptr, nullptr);
  EXPECT_TRUE(ec.Init(ctx));
  int ok = 0;
  ok = ec.KeygenInit(ctx);
  EXPECT_TRUE(ok);

  EVP_PKEY *pkey = EVP_PKEY_new();
  ok = ec.Keygen(ctx, pkey);
  EXPECT_TRUE(ok);
  EXPECT_TRUE(ec.Cleanup(ctx));
}

// signing with Sha256
TEST_F(Test_EC, TestECSignSha256)
{
  int ok = 0;
  Factory::SoftwareImpl::SwEc ec(NID_secp384r1);
  EVP_PKEY *pkey = nullptr;
  EC_KEY *eckey = nullptr;

  // load key
  std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";
  FILE *fp = fopen(path_to_key.c_str(), "r");
  pkey = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
  PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
  ok = EVP_PKEY_set1_EC_KEY(pkey, eckey);
  EC_KEY_free(eckey);
  EXPECT_NE(EVP_PKEY_id(pkey), EVP_PKEY_NONE);

  // create message to sign
  std::string msg("MessageToBeSigned");

  // create 2 context
  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  EXPECT_TRUE(EVP_DigestInit_ex(mctx, EVP_sha256(), NULL));
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);

  // init call
  EXPECT_TRUE(ec.Init(ctx));

  // SignInit call
  EXPECT_TRUE(ec.SignInit(ctx, mctx));

  // set custom digest
  EXPECT_TRUE(ec.CustomDigest(ctx, mctx));

  // update digest
  EXPECT_TRUE(ec.ECDSADigestUpdate(mctx, msg.data(), msg.size()));

  // allocate memory
  std::vector<std::uint8_t> signature;
  signature.resize(102);
  std::size_t sig_size;

  // Sign call
  EXPECT_TRUE(ec.Sign(ctx, signature.data(), &sig_size, mctx));

  // Free
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_CTX_free(ctx);

  // init for verifiy
  ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  mctx = EVP_MD_CTX_new();
  EXPECT_TRUE(EVP_DigestInit_ex(mctx, EVP_sha256(), NULL));

  // init call
  EXPECT_TRUE(ec.Init(ctx));

  // SignInit call
  EXPECT_TRUE(ec.VerifyInit(ctx, mctx));

  // set custom digest
  EXPECT_TRUE(ec.CustomDigest(ctx, mctx));

  // update digest
  EXPECT_TRUE(ec.ECDSADigestUpdate(mctx, msg.data(), msg.size()));

  // Sign call
  EXPECT_TRUE(ec.Verify(ctx, signature.data(), sig_size, mctx));

  // cleanup
  EXPECT_TRUE(ec.Cleanup(ctx));

  // Free
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_CTX_free(ctx);

  // Free key
  EVP_PKEY_free(pkey);
}

// signing with Sha256
TEST_F(Test_EC, TestECSignSha384)
{
  int ok = 0;
  Factory::SoftwareImpl::SwEc ec(NID_secp384r1);
  EVP_PKEY *pkey = nullptr;
  EC_KEY *eckey = nullptr;

  // load key
  std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";
  FILE *fp = fopen(path_to_key.c_str(), "r");
  pkey = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
  PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
  ok = EVP_PKEY_set1_EC_KEY(pkey, eckey);
  EC_KEY_free(eckey);
  EXPECT_NE(EVP_PKEY_id(pkey), EVP_PKEY_NONE);

  // create message to sign
  std::string msg("MessageToBeSigned");

  // create 2 context
  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  EXPECT_TRUE(EVP_DigestInit_ex(mctx, EVP_sha384(), NULL));
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);

  // init call
  EXPECT_TRUE(ec.Init(ctx));

  // SignInit call
  EXPECT_TRUE(ec.SignInit(ctx, mctx));

  // set custom digest
  EXPECT_TRUE(ec.CustomDigest(ctx, mctx));

  // update digest
  EXPECT_TRUE(ec.ECDSADigestUpdate(mctx, msg.data(), msg.size()));

  // allocate memory
  std::vector<std::uint8_t> signature;
  signature.resize(102);
  std::size_t sig_size;

  // Sign call
  EXPECT_TRUE(ec.Sign(ctx, signature.data(), &sig_size, mctx));

  // Free
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_CTX_free(ctx);

  // init for verifiy
  mctx = EVP_MD_CTX_new();
  ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  EXPECT_TRUE(EVP_DigestInit_ex(mctx, EVP_sha384(), NULL));

  // init call
  EXPECT_TRUE(ec.Init(ctx));

  // SignInit call
  EXPECT_TRUE(ec.VerifyInit(ctx, mctx));

  // set custom digest
  EXPECT_TRUE(ec.CustomDigest(ctx, mctx));

  // update digest
  EXPECT_TRUE(ec.ECDSADigestUpdate(mctx, msg.data(), msg.size()));

  // Sign call
  EXPECT_TRUE(ec.Verify(ctx, signature.data(), sig_size, mctx));

  // cleanup
  EXPECT_TRUE(ec.Cleanup(ctx));

  // Free
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_CTX_free(ctx);

  // Free key
  EVP_PKEY_free(pkey);
}

TEST_F(Test_EC, TestECDerive)
{
  int ok = 0;
  Factory::SoftwareImpl::SwEc ec(NID_secp384r1);

  // keys
  EVP_PKEY* pkey;
  EC_KEY* eckey;
  EVP_PKEY* pubkey;
  EC_KEY* ecpkey;

  // path to keys
  std::string path_to_alice_key = "/home/glaum/engine/keys/alice_pkey.pem";
  std::string path_to_bob_pubkey = "/home/glaum/engine/keys/bob_pubkey.pem";

  // load pkey
  FILE *fp = fopen(path_to_alice_key.c_str(), "r");
  pkey = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
  PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
  ok = EVP_PKEY_set1_EC_KEY(pkey, eckey);
  EC_KEY_free(eckey);
  fclose(fp);
  EXPECT_NE(EVP_PKEY_id(pkey), EVP_PKEY_NONE);

  // load pubkey
  fp = fopen(path_to_bob_pubkey.c_str(), "r");
  pubkey = EVP_PKEY_new();
  ecpkey = EC_KEY_new_by_curve_name(NID_secp384r1);
  PEM_read_EC_PUBKEY(fp, &ecpkey, nullptr, nullptr);
  ok = EVP_PKEY_set1_EC_KEY(pubkey, ecpkey);
  EC_KEY_free(ecpkey);
  fclose(fp);
  EXPECT_NE(EVP_PKEY_id(pubkey), EVP_PKEY_NONE);

  // create ctx
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
  EXPECT_TRUE(ec.Init(ctx));

  // derive init
  EXPECT_TRUE(ec.DeriveInit(ctx));

  // set peer
  EXPECT_TRUE(ec.Ctrl(ctx, EVP_PKEY_CTRL_PEER_KEY, 0, pubkey));

  // derive
  std::vector<std::uint8_t> secret;
  std::size_t secret_size = 0;
  EXPECT_TRUE(ec.Derive(ctx, nullptr, &secret_size ));

  EXPECT_EQ(secret_size, 48);
  secret.resize(secret_size);
  EXPECT_TRUE(ec.Derive(ctx, secret.data(), &secret_size ));

  // cleanup
  EXPECT_TRUE(ec.Cleanup(ctx));
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(pubkey);

}