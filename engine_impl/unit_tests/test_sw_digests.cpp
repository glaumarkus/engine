#include <factory/factory_digest.hpp>

#include "digests/sw_digest_sha256.hpp"
#include "digests/sw_digest_sha384.hpp"

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <string>

// Tests
class Test_Digests : public ::testing::Test {
protected:
  void SetUp() override {}
};

TEST_F(Test_Digests, TestSha256) {

  std::unique_ptr<Factory::FactoryDigest> digest{nullptr};

  // create instance of sw sha 256
  auto *sw_digest = new Factory::SoftwareImpl::SwSha256();
  digest = static_cast<std::unique_ptr<Factory::FactoryDigest>>(sw_digest);

  // check if cast worked
  EXPECT_NE(digest, nullptr);

  // message to be hashed
  std::string msg("ExampleHash");

  // buffers
  std::vector<std::uint8_t> buff, buff2;
  buff.resize(EVP_MD_size(EVP_sha256()));
  buff2.resize(EVP_MD_size(EVP_sha256()));

  // do hash with factory
  int ok = 0;
  EVP_MD_CTX *ctx_f = EVP_MD_CTX_create();
  ok = digest->Init(ctx_f);
  EXPECT_TRUE(ok);
  ok = digest->Update(ctx_f, msg.c_str(), msg.size());
  EXPECT_TRUE(ok);
  ok = digest->Final(ctx_f, buff.data());
  EXPECT_TRUE(ok);
  EVP_MD_CTX_free(ctx_f);

  // do hash with sw
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EXPECT_TRUE(ok);
  ok = EVP_DigestUpdate(ctx, msg.c_str(), msg.size());
  EXPECT_TRUE(ok);
  unsigned int len = 0;
  ok = EVP_DigestFinal_ex(ctx, buff2.data(), &len);
  EXPECT_TRUE(ok);
  EVP_MD_CTX_free(ctx);

  // compare results
  EXPECT_EQ(buff, buff2);

  // cleanup
  digest.release();

  // delete
  delete sw_digest;
}

TEST_F(Test_Digests, TestSha384) {

  std::unique_ptr<Factory::FactoryDigest> digest{nullptr};

  // create instance of sw sha 256
  auto *sw_digest = new Factory::SoftwareImpl::SwSha384();
  digest = static_cast<std::unique_ptr<Factory::FactoryDigest>>(sw_digest);

  // check if cast worked
  EXPECT_NE(digest, nullptr);

  // message to be hashed
  std::string msg("ExampleHash");

  // buffers
  std::vector<std::uint8_t> buff, buff2;
  buff.resize(EVP_MD_size(EVP_sha384()));
  buff2.resize(EVP_MD_size(EVP_sha384()));

  // do hash with factory
  int ok = 0;
  EVP_MD_CTX *ctx_f = EVP_MD_CTX_create();
  ok = digest->Init(ctx_f);
  EXPECT_TRUE(ok);
  ok = digest->Update(ctx_f, msg.c_str(), msg.size());
  EXPECT_TRUE(ok);
  ok = digest->Final(ctx_f, buff.data());
  EXPECT_TRUE(ok);
  EVP_MD_CTX_free(ctx_f);

  // do hash with sw
  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  ok = EVP_DigestInit_ex(ctx, EVP_sha384(), nullptr);
  EXPECT_TRUE(ok);
  ok = EVP_DigestUpdate(ctx, msg.c_str(), msg.size());
  EXPECT_TRUE(ok);
  unsigned int len = 0;
  ok = EVP_DigestFinal_ex(ctx, buff2.data(), &len);
  EXPECT_TRUE(ok);
  EVP_MD_CTX_free(ctx);

  // compare results
  EXPECT_EQ(buff, buff2);

  // cleanup
  digest.release();

  // delete
  delete sw_digest;
}
