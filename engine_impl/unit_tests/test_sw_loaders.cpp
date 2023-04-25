#include <factory/factory_cert.hpp>
#include <factory/factory_pkey.hpp>
#include <factory/factory_pubkey.hpp>

#include "asym/sw_cert.hpp"
#include "asym/sw_pkey.hpp"
#include "asym/sw_pubkey.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <functional>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

// Tests
class Test_Loaders : public ::testing::Test {
 protected:

  std::unique_ptr<Factory::FactoryCertificate> cert {nullptr};
  std::unique_ptr<Factory::FactoryPrivKey> pkey {nullptr};
  std::unique_ptr<Factory::FactoryPubKey> pubkey {nullptr};

  void SetUp() override {
  }
};

TEST_F(Test_Loaders, LoadSwCertificate)
{
    // create instance of sw certificate
    auto* cert_sw = new Factory::SoftwareImpl::SwCertificate();
    cert = static_cast<std::unique_ptr<Factory::FactoryCertificate>>(cert_sw);

    // check if casting was ok
    EXPECT_NE(cert, nullptr);

    // load a certificate 
    int ok = cert->Load("/home/glaum/engine/keys/certificate.pem");
    EXPECT_TRUE(ok);

    // check if cert is not nullptr
    EXPECT_NE(cert->Get(), nullptr);

    // load cert with software
    X509* certificate;
    BIO *cert_bio = BIO_new_file("/home/glaum/engine/keys/certificate.pem", "r");
    if (cert_bio) {
        certificate = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        if (certificate) {
        ok = 1;
        }
    }
    // check if sw loading was successful
    EXPECT_TRUE(ok);

    // compare certificates
    EXPECT_EQ(X509_cmp(certificate, cert->Get()),0);

    // application is expected to cleanup cert
    X509_free(cert->Get());
    X509_free(certificate);

    // free cert again
    cert.release();

    // and delete
    delete cert_sw;

}

TEST_F(Test_Loaders, LoadSwPrivateKey)
{

    // create instance of sw pkey
    auto* pkey_f = new Factory::SoftwareImpl::SwPrivKey();
    pkey = static_cast<std::unique_ptr<Factory::FactoryPrivKey>>(pkey_f);

    // check if casting was ok
    EXPECT_NE(pkey, nullptr);

    // load a private key
    auto pkey_ptr = pkey->Load("/home/glaum/engine/keys/alice_pkey.pem");
    EXPECT_NE(pkey_ptr, nullptr);

    // load key with software
    FILE *fp = fopen("/home/glaum/engine/keys/alice_pkey.pem", "r");
    EVP_PKEY *pkey_sw = nullptr;
    EC_KEY *ec_key = nullptr;
    ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
    EXPECT_NE(ec_key, nullptr);
    PEM_read_ECPrivateKey(fp, &ec_key, nullptr, nullptr);
    pkey_sw = EVP_PKEY_new();
    int ok = EVP_PKEY_set1_EC_KEY(pkey_sw, ec_key);
    EXPECT_TRUE(ok);
    fclose(fp);
    EC_KEY_free(ec_key);

    // compare keys
    ok = EVP_PKEY_cmp(pkey_ptr, pkey_sw);
    EXPECT_TRUE(ok);
    
    // free keys
    EVP_PKEY_free(pkey_ptr);
    EVP_PKEY_free(pkey_sw);

    // free cert again
    pkey.release();

    // and delete
    delete pkey_f;
}

TEST_F(Test_Loaders, LoadSwPublicKey)
{
    // create instance of sw pubkey
    auto* pubkey_f = new Factory::SoftwareImpl::SwPubKey();
    pubkey = static_cast<std::unique_ptr<Factory::FactoryPubKey>>(pubkey_f);

    // check if casting was ok
    EXPECT_NE(pubkey, nullptr);

    // load a public key
    auto pubkey_ptr = pubkey->Load("/home/glaum/engine/keys/alice_pubkey.pem");
    EXPECT_NE(pubkey_ptr, nullptr);

    // load key with software
    FILE *fp = fopen("/home/glaum/engine/keys/alice_pubkey.pem", "r");
    EVP_PKEY *pubkey_sw = nullptr;
    EC_KEY *ec_key = nullptr;
    ec_key = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
    EXPECT_NE(ec_key, nullptr);
    PEM_read_ECPrivateKey(fp, &ec_key, nullptr, nullptr);
    pubkey_sw = EVP_PKEY_new();
    int ok = EVP_PKEY_set1_EC_KEY(pubkey_sw, ec_key);
    EXPECT_TRUE(ok);
    fclose(fp);
    EC_KEY_free(ec_key);

    // compare keys
    ok = EVP_PKEY_cmp(pubkey_ptr, pubkey_sw);
    EXPECT_TRUE(ok);
    
    // free keys
    EVP_PKEY_free(pubkey_ptr);
    EVP_PKEY_free(pubkey_sw);

    // free cert again
    pubkey.release();

    // and delete
    delete pubkey_f;
}