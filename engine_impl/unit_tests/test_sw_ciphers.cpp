#include <factory/factory_cipher.hpp>

#include "ciphers/sw_cipher_aes256cbc.hpp"
#include "ciphers/sw_cipher_chacha20.hpp"
#include "ciphers/sw_cipher_aes256gcm.hpp"

#include <openssl/evp.h>

#include <gtest/gtest.h>

#include <fstream>
#include <functional>
#include <string>

// Tests
class Test_Ciphers : public ::testing::Test {
protected:
  void SetUp() override {}
};

TEST_F(Test_Ciphers, TestAes256Cbc) {

  std::unique_ptr<Factory::FactoryCipher> cipher{nullptr};

  // create instance of sw aes 256 cbc
  auto *sw_cipher = new Factory::SoftwareImpl::SwAes256Cbc();
  cipher = static_cast<std::unique_ptr<Factory::FactoryCipher>>(sw_cipher);

  // check if cast worked
  EXPECT_NE(cipher, nullptr);

  // message to be encrypted
  std::string plaintext(
      "This is a longer secret message that needs to be encrypted.");
  // the engine will supply already a padded string to the algorithm
  std::string plaintext_padded(
      "This is a longer secret message that needs to be encrypted.\x05\x05\x05\x05\x05");
  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  std::string iv("BBBBBBBBBBBBBBBB");

  // buffers
  std::vector<std::uint8_t> buff, buff2;
  buff.resize(plaintext_padded.size());
  buff2.resize(plaintext.size() + 16);

  // do encrypt with factory
  int ok = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 1);
  EXPECT_TRUE(ok);
  int cipher_len = 0;
  ok = cipher->DoCipher(ctx, buff.data(), (unsigned char *)plaintext_padded.data(),
                        plaintext_padded.size());
  EXPECT_TRUE(ok);
  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // do encrypt with sw
  ctx = EVP_CIPHER_CTX_new();
  ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                          (unsigned char *)key.data(),
                          (unsigned char *)iv.data());
  EXPECT_TRUE(ok);
  int len = 0;
  ok = EVP_EncryptUpdate(ctx, (unsigned char *)buff2.data(), &len,
                         (unsigned char *)plaintext.data(), plaintext.size());
  EXPECT_TRUE(ok);
  int buff2_len = len;
  ok =
      EVP_EncryptFinal_ex(ctx, (unsigned char *)buff2.data() + buff2_len, &len);
  EXPECT_TRUE(ok);
  buff2_len += len;
  buff2.resize(buff2_len);
  EVP_CIPHER_CTX_free(ctx);

  // compare encryptions
  EXPECT_EQ(buff.size(), buff2.size());
  EXPECT_EQ(buff, buff2);


  // buffer for decryption
  std::vector<std::uint8_t> buff_d;
  buff_d.resize(buff.size());

  // do decryption with factory
  ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 0);
  EXPECT_TRUE(ok);
  ok = cipher->DoCipher(ctx, buff_d.data(), (unsigned char *)buff.data(),
                        buff.size());
  EXPECT_TRUE(ok);
  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // compare again with plaintext
  int cmp = memcmp(buff_d.data(), plaintext_padded.data(), plaintext_padded.size());
  EXPECT_EQ(0, cmp);
}


TEST_F(Test_Ciphers, TestChaCha20) {

  std::unique_ptr<Factory::FactoryCipher> cipher{nullptr};

  // create instance of sw aes 256 cbc
  auto *sw_cipher = new Factory::SoftwareImpl::SwChaCha20();
  cipher = static_cast<std::unique_ptr<Factory::FactoryCipher>>(sw_cipher);

  // check if cast worked
  EXPECT_NE(cipher, nullptr);

  // message to be encrypted, chacha is a stream cipher and doesnt need padding as its blocksize is 1
  std::string plaintext(
      "This is a longer secret message that needs to be encrypted.");

  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  std::string iv("BBBBBBBBBBBBBBBB");

  // buffers
  std::vector<std::uint8_t> buff, buff2;
  buff.resize(plaintext.size());
  buff2.resize(plaintext.size() + 16);

  // do encrypt with factory
  int ok = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 1);
  EXPECT_TRUE(ok);
  int cipher_len = 0;
  ok = cipher->DoCipher(ctx, buff.data(), (unsigned char *)plaintext.data(),
                        plaintext.size());
  EXPECT_TRUE(ok);
  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // do encrypt with sw
  ctx = EVP_CIPHER_CTX_new();
  ok = EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr,
                          (unsigned char *)key.data(),
                          (unsigned char *)iv.data());
  EXPECT_TRUE(ok);
  int len = 0;
  ok = EVP_EncryptUpdate(ctx, (unsigned char *)buff2.data(), &len,
                         (unsigned char *)plaintext.data(), plaintext.size());
  EXPECT_TRUE(ok);
  int buff2_len = len;
  ok =
      EVP_EncryptFinal_ex(ctx, (unsigned char *)buff2.data() + buff2_len, &len);
  EXPECT_TRUE(ok);
  buff2_len += len;
  buff2.resize(buff2_len);
  EVP_CIPHER_CTX_free(ctx);

  // compare encryptions
  EXPECT_EQ(buff.size(), buff2.size());
  EXPECT_EQ(buff, buff2);

  // buffer for decryption
  std::vector<std::uint8_t> buff_d;
  buff_d.resize(buff.size());

  // do decryption with factory
  ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 0);
  EXPECT_TRUE(ok);
  ok = cipher->DoCipher(ctx, buff_d.data(), (unsigned char *)buff.data(),
                        buff.size());
  EXPECT_TRUE(ok);
  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // compare again with plaintext
  int cmp = memcmp(buff_d.data(), plaintext.data(), plaintext.size());
  EXPECT_EQ(0, cmp);
}

TEST_F(Test_Ciphers, TestAes256Gcm) {

  std::unique_ptr<Factory::FactoryCipher> cipher{nullptr};

  // create instance of sw aes 256 cbc
  auto *sw_cipher = new Factory::SoftwareImpl::SwAes256Gcm();
  cipher = static_cast<std::unique_ptr<Factory::FactoryCipher>>(sw_cipher);

  // check if cast worked
  EXPECT_NE(cipher, nullptr);

  // message to be encrypted, chacha is a stream cipher and doesnt need padding as its blocksize is 1
  std::string plaintext(
      "This is a longer secret message that needs to be encrypted.");

  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  std::string iv("BBBBBBBBBBBBBBBB");

  // buffers
  std::vector<std::uint8_t> buff, buff2;
  buff.resize(plaintext.size());
  buff2.resize(plaintext.size() + 16);

  // do encrypt with factory
  int ok = 0;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 1);
  EXPECT_TRUE(ok);
  int cipher_len = 0;
  ok = cipher->DoCipher(ctx, buff.data(), (unsigned char *)plaintext.data(),
                        plaintext.size());
  EXPECT_TRUE(ok);

  // get tag
  std::vector<std::uint8_t> tag;
  tag.resize(12);
  ok = cipher->Ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 12, tag.data());
  EXPECT_TRUE(ok);

  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // do encrypt with sw
  ctx = EVP_CIPHER_CTX_new();
  ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                          (unsigned char *)key.data(),
                          (unsigned char *)iv.data());
  EXPECT_TRUE(ok);
  int len = 0;
  ok = EVP_EncryptUpdate(ctx, (unsigned char *)buff2.data(), &len,
                         (unsigned char *)plaintext.data(), plaintext.size());
  EXPECT_TRUE(ok);
  int buff2_len = len;
  ok =
      EVP_EncryptFinal_ex(ctx, (unsigned char *)buff2.data() + buff2_len, &len);
  EXPECT_TRUE(ok);
  buff2_len += len;
  buff2.resize(buff2_len);

  // get tag
  std::vector<std::uint8_t> tag_sw;
  tag_sw.resize(12);
  ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 12, tag_sw.data());
  EXPECT_TRUE(ok);
  EXPECT_EQ(tag_sw, tag);

  EVP_CIPHER_CTX_free(ctx);

  // compare encryptions
  EXPECT_EQ(buff.size(), buff2.size());
  EXPECT_EQ(buff, buff2);

  // buffer for decryption
  std::vector<std::uint8_t> buff_d;
  buff_d.resize(buff.size());

  // do decryption with factory
  ctx = EVP_CIPHER_CTX_new();
  ok = cipher->Init(ctx, (unsigned char *)key.data(),
                    (unsigned char *)iv.data(), 0);
  EXPECT_TRUE(ok);
  ok = cipher->DoCipher(ctx, buff_d.data(), (unsigned char *)buff.data(),
                        buff.size());

  // set tag
  ok = cipher->Ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 12, tag.data());
  EXPECT_TRUE(ok);
  
  EXPECT_TRUE(ok);
  ok = cipher->Cleanup(ctx);
  EXPECT_TRUE(ok);
  EVP_CIPHER_CTX_free(ctx);

  // compare again with plaintext
  int cmp = memcmp(buff_d.data(), plaintext.data(), plaintext.size());
  EXPECT_EQ(0, cmp);
}