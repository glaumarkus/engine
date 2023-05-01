#include "src/engine_factory.hpp"

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <string>

// Tests
class Test_Factory : public ::testing::Test {
protected:
  void SetUp() override {}
};


TEST_F(Test_Factory, TestFactoryBasics) {
    auto factory = Factory::SoftwareImpl::EngineFactory();
    int ok = factory.Init();
    EXPECT_TRUE(ok);
    ok = factory.Finish();
    EXPECT_TRUE(ok);
    auto s = factory.Size();
    EXPECT_EQ(s, sizeof(Factory::SoftwareImpl::EngineFactory));
}

TEST_F(Test_Factory, TestCtrl) {
    auto factory = Factory::SoftwareImpl::EngineFactory();
    // path to cert
    std::string cert_path = "/home/glaum/engine/keys/certificate.pem";
    int ok = 0;
    ok = factory.CtrlCmd(nullptr, 13, 0, (void*)"LOAD_CERT_CTRL", nullptr);
    EXPECT_TRUE(ok);
    struct params {
      const char *cert_id;
      X509 *cert;
    };
    params p;
    p.cert_id = cert_path.c_str();
    ok = factory.CtrlCmd(nullptr, 1, 0, &p, nullptr);
    EXPECT_TRUE(ok);
    EXPECT_NE(p.cert, nullptr);
}

TEST_F(Test_Factory, TestFactoryGetters) {
    auto factory = Factory::SoftwareImpl::EngineFactory();
    auto ec = factory.GetEC(NID_secp384r1);
    EXPECT_NE(ec, nullptr);
    auto digest = factory.GetDigest(NID_sha256);
    EXPECT_NE(digest, nullptr);
    digest = factory.GetDigest(NID_sha384);
    EXPECT_NE(digest, nullptr);
    auto cipher = factory.GetCipher(NID_aes_256_cbc);
    EXPECT_NE(cipher, nullptr);
    cipher = factory.GetCipher(NID_aes_256_gcm);
    EXPECT_NE(cipher, nullptr);
    cipher = factory.GetCipher(NID_chacha20);
    EXPECT_NE(cipher, nullptr);
    auto pkey = factory.GetPrivateKeyLoader();
    EXPECT_NE(pkey, nullptr);
    auto pubkey = factory.GetPublicKeyLoader();
    EXPECT_NE(pubkey, nullptr);
}