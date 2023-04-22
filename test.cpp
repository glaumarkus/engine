#include <gtest/gtest.h>
#include <openssl/engine.h>

using ::testing::Test;

ENGINE *engine = nullptr;

TEST(Test, EngineLoaded) {
  // try loading the engine
  ENGINE_load_dynamic();
  engine = ENGINE_by_id("libmbengine");
  EXPECT_TRUE(engine != nullptr);
}

TEST(Test, EngineInit) {
  ASSERT_NE(engine, nullptr);
  // initialize the engine
  EXPECT_EQ(1, ENGINE_init(engine));
}

TEST(Test, ECDHEngine) {
  int ret = 0;
  std::string path_to_alice_key = "/home/glaum/engine/keys/alice_pkey.pem";
  std::string path_to_bob_pubkey = "/home/glaum/engine/keys/bob_pubkey.pem";
  std::string path_to_bob_key = "/home/glaum/engine/keys/bob_pkey.pem";
  std::string path_to_alice_pubkey = "/home/glaum/engine/keys/alice_pubkey.pem";
  std::size_t engine_secret_len = 0;

  // load alice key
  EVP_PKEY *alice_pkey_engine = nullptr;
  alice_pkey_engine = ENGINE_load_private_key(engine, path_to_alice_key.c_str(),
                                              nullptr, nullptr);
  EXPECT_NE(alice_pkey_engine, nullptr);

  // load bob public key
  EVP_PKEY *bob_pubkey_engine = nullptr;
  bob_pubkey_engine = ENGINE_load_public_key(engine, path_to_bob_pubkey.c_str(),
                                             nullptr, nullptr);
  EXPECT_NE(bob_pubkey_engine, nullptr);

  // derive alice
  EVP_PKEY_CTX *ctx1 = EVP_PKEY_CTX_new(alice_pkey_engine, engine);
  ret = EVP_PKEY_derive_init(ctx1);
  EXPECT_EQ(ret, 1);
  ret = EVP_PKEY_derive_set_peer(ctx1, bob_pubkey_engine);
  EXPECT_EQ(ret, 1);
  ret = EVP_PKEY_derive(ctx1, nullptr, &engine_secret_len);
  std::vector<std::uint8_t> shared_secret_alice;
  shared_secret_alice.resize(engine_secret_len);
  ret = EVP_PKEY_derive(ctx1, shared_secret_alice.data(), &engine_secret_len);
  shared_secret_alice.resize(engine_secret_len);
  EXPECT_EQ(ret, 1);
  EXPECT_EQ(shared_secret_alice.size(), 48);
  EVP_PKEY_CTX_free(ctx1);

  // load bob key
  EVP_PKEY *bob_pkey_engine = nullptr;
  bob_pkey_engine = ENGINE_load_private_key(engine, path_to_bob_key.c_str(),
                                            nullptr, nullptr);
  EXPECT_NE(bob_pkey_engine, nullptr);

  // load alice public key
  EVP_PKEY *alice_pubkey_engine = nullptr;
  alice_pubkey_engine = ENGINE_load_public_key(
      engine, path_to_alice_pubkey.c_str(), nullptr, nullptr);
  EXPECT_NE(alice_pubkey_engine, nullptr);

  // derive bob
  EVP_PKEY_CTX *ctx2 = EVP_PKEY_CTX_new(bob_pkey_engine, engine);
  ret = EVP_PKEY_derive_init(ctx2);
  EXPECT_EQ(ret, 1);
  ret = EVP_PKEY_derive_set_peer(ctx2, alice_pubkey_engine);
  EXPECT_EQ(ret, 1);
  engine_secret_len = 0;
  ret = EVP_PKEY_derive(ctx2, nullptr, &engine_secret_len);
  std::vector<std::uint8_t> shared_secret_bob;
  shared_secret_bob.resize(engine_secret_len);
  ret = EVP_PKEY_derive(ctx2, shared_secret_bob.data(), &engine_secret_len);
  shared_secret_bob.resize(engine_secret_len);
  EXPECT_EQ(ret, 1);
  EXPECT_EQ(shared_secret_bob.size(), 48);
  EVP_PKEY_CTX_free(ctx2);

  // compare derived secrets
  EXPECT_EQ(shared_secret_alice, shared_secret_bob);

  // free keys
  EVP_PKEY_free(alice_pkey_engine);
  EVP_PKEY_free(bob_pkey_engine);
  EVP_PKEY_free(alice_pubkey_engine);
  EVP_PKEY_free(bob_pubkey_engine);
}

// ToDo: needs some more debugging for the Digest used so no extra digest is
// required
TEST(Test, ECDSA) {
  ASSERT_NE(engine, nullptr);

  // Setup vars
  EVP_PKEY *pkey_sw = nullptr;
  EC_KEY *eckey = nullptr;
  int ret = 0;
  std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";
  std::string path_to_pubkey = "/home/glaum/engine/keys/public_key.pem";
  size_t siglen = 0;
  std::vector<uint8_t> signature;
  std::vector<uint8_t> signature_engine;
  std::string msg("Sign this example message with EC private key");

  // Load private key with sw
  FILE *fp = fopen(path_to_key.c_str(), "r");
  pkey_sw = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
  PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
  ret = EVP_PKEY_set1_EC_KEY(pkey_sw, eckey);
  EC_KEY_free(eckey);
  EXPECT_NE(EVP_PKEY_id(pkey_sw), EVP_PKEY_NONE);

  // Check if type matches
  int type = EVP_PKEY_base_id(pkey_sw);
  EXPECT_EQ(type, EVP_PKEY_EC);

  // Sign with sw
  EVP_MD_CTX *mdctx = NULL;
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey_sw);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestSignUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestSignFinal(mdctx, NULL, &siglen);
  // resize signature
  signature.resize(siglen);
  EVP_DigestSignFinal(mdctx, (unsigned char *)signature.data(), &siglen);
  EVP_MD_CTX_free(mdctx);

  // Do verify sw sign
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), NULL, pkey_sw);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature.data(), siglen);
  EXPECT_EQ(ret, 1);
  EVP_MD_CTX_free(mdctx);

  // load key with engine
  EVP_PKEY *pkey_engine = nullptr;
  pkey_engine =
      ENGINE_load_private_key(engine, path_to_key.c_str(), nullptr, nullptr);
  EXPECT_NE(pkey_engine, nullptr);

  // Check if type matches
  type = EVP_PKEY_base_id(pkey_engine);
  EXPECT_EQ(type, EVP_PKEY_EC);

  // sign with engine
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), engine, pkey_engine);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestSignUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  signature_engine.resize(EVP_PKEY_size(pkey_engine));
  ret = EVP_DigestSignFinal(mdctx, (unsigned char *)signature_engine.data(),
                            &siglen);
  signature_engine.resize(siglen);
  EVP_MD_CTX_free(mdctx);

  // Do verify engine sign
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), NULL, pkey_sw);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature_engine.data(),
                              siglen);
  EXPECT_EQ(ret, 1);
  EVP_MD_CTX_free(mdctx);

  // Do verify of engine sign with engine
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), engine, pkey_engine);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature_engine.data(),
                              siglen);
  EXPECT_EQ(ret, 1);
  EVP_MD_CTX_free(mdctx);

  // Do verify of sw sign with engine
  mdctx = EVP_MD_CTX_new();
  ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), engine, pkey_engine);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature.data(),
                              signature.size());
  EXPECT_EQ(ret, 1);
  EVP_MD_CTX_free(mdctx);

  // load public key with engine
  EVP_PKEY *pubkey_engine = nullptr;
  pubkey_engine =
      ENGINE_load_public_key(engine, path_to_pubkey.c_str(), nullptr, nullptr);
  EXPECT_NE(pkey_engine, nullptr);

  // Check if type matches
  type = EVP_PKEY_base_id(pkey_engine);
  EXPECT_EQ(type, EVP_PKEY_EC);

  // Do verify of sw sign with public key
  mdctx = EVP_MD_CTX_new();
  ret =
      EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), engine, pubkey_engine);
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char *)msg.data(), msg.size());
  EXPECT_EQ(ret, 1);
  ret = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature.data(),
                              signature.size());
  EXPECT_EQ(ret, 1);
  EVP_MD_CTX_free(mdctx);
}

TEST(Test, LoadPrivateKey) {
  ASSERT_NE(engine, nullptr);
  EVP_PKEY *pkey_sw = nullptr;
  EC_KEY *eckey = nullptr;
  int ret = 0;
  std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";

  // Load private key with sw
  FILE *fp = fopen(path_to_key.c_str(), "r");
  pkey_sw = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
  PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
  ret = EVP_PKEY_set1_EC_KEY(pkey_sw, eckey);
  EC_KEY_free(eckey);
  EXPECT_NE(EVP_PKEY_id(pkey_sw), EVP_PKEY_NONE);

  // Load private key with engine
  EVP_PKEY *pkey_engine = nullptr;
  pkey_engine =
      ENGINE_load_private_key(engine, path_to_key.c_str(), nullptr, nullptr);
  EXPECT_NE(pkey_engine, nullptr);

  // compare the keys
  ret = EVP_PKEY_cmp(pkey_sw, pkey_engine);
  EXPECT_TRUE(ret);

  // compare the key params
  ret = EVP_PKEY_cmp_parameters(pkey_sw, pkey_engine);
  EXPECT_TRUE(ret);
}

TEST(Test, LoadPublicKey) {
  ASSERT_NE(engine, nullptr);
  EVP_PKEY *pkey_sw = nullptr;
  EC_KEY *eckey = nullptr;
  int ret = 0;
  std::string path_to_key = "/home/glaum/engine/keys/public_key.pem";

  // Load private key with sw
  FILE *fp = fopen(path_to_key.c_str(), "r");
  pkey_sw = EVP_PKEY_new();
  eckey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
  PEM_read_EC_PUBKEY(fp, &eckey, nullptr, nullptr);
  ret = EVP_PKEY_set1_EC_KEY(pkey_sw, eckey);
  EC_KEY_free(eckey);
  EXPECT_NE(EVP_PKEY_id(pkey_sw), EVP_PKEY_NONE);

  // Load private key with engine
  EVP_PKEY *pkey_engine = nullptr;
  pkey_engine =
      ENGINE_load_public_key(engine, path_to_key.c_str(), nullptr, nullptr);
  EXPECT_NE(pkey_engine, nullptr);

  // compare the keys
  ret = EVP_PKEY_cmp(pkey_sw, pkey_engine);
  EXPECT_TRUE(ret);

  // compare the key params
  ret = EVP_PKEY_cmp_parameters(pkey_sw, pkey_engine);
  EXPECT_TRUE(ret);
}

TEST(Test, LoadCertificate) {

  // path to cert
  std::string cert_path = "/home/glaum/engine/keys/certificate.pem";

  // load cert with sw
  BIO *cert_bio = BIO_new_file(cert_path.c_str(), "r");
  if (!cert_bio)
    FAIL();

  // Read the certificate from the BIO
  X509 *cert_sw = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
  if (!cert_sw)
    FAIL();

  // Free the BIO
  BIO_free(cert_bio);

  // curl does this:
  struct params {
    const char *cert_id;
    X509 *cert;
  };

  // check if engine supports LOAD_CERT_CTRL
  params p;
  p.cert_id = "/home/glaum/engine/keys/certificate.pem";
  printf("certstr: %p, addr: %p\n", p.cert_id, &p.cert_id);

  auto cmd_name = "LOAD_CERT_CTRL";
  int engine_support = ENGINE_ctrl(engine, ENGINE_CTRL_GET_CMD_FROM_NAME, 0,
                                   (void *)cmd_name, NULL);
  EXPECT_EQ(1, engine_support);

  // load the certificate from the engine
  int engine_load = ENGINE_ctrl_cmd(engine, cmd_name, 0, &p, NULL, 1);
  EXPECT_EQ(1, engine_load);

  // check if equal, strangely 0 here means same as memcmp is used
  int equal = X509_cmp(cert_sw, p.cert);
  EXPECT_EQ(equal, 0);
}

TEST(Test, Sha256) {
  ASSERT_NE(engine, nullptr);

  // example input
  std::string str("Sample input");

  std::vector<uint8_t> digest_sw;
  int digest_size_sw = 0;
  std::vector<uint8_t> digest_engine;
  int digest_size_engine = 0;

  // hash with openssl
  digest_size_sw = EVP_MD_meth_get_result_size(EVP_sha256());
  digest_sw.resize(digest_size_sw);
  unsigned int digestSize = -1;
  EVP_MD_CTX *evp_ctx;
  evp_ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(evp_ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(evp_ctx, (unsigned char *)str.data(), str.size());
  EVP_DigestFinal(evp_ctx, (unsigned char *)digest_sw.data(), &digestSize);
  EVP_MD_CTX_free(evp_ctx);

  // hash with engine
  const EVP_MD *engine_digest = ENGINE_get_digest(engine, NID_sha256);
  digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);
  digest_engine.resize(digest_size_engine);
  evp_ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(evp_ctx, EVP_sha256(), engine);
  EVP_DigestUpdate(evp_ctx, (unsigned char *)str.data(), str.size());
  EVP_DigestFinal(evp_ctx, (unsigned char *)digest_engine.data(), &digestSize);

  EXPECT_EQ(digest_size_engine, digest_size_sw);
  EXPECT_EQ(digest_sw, digest_engine);
}

TEST(Test, Sha384) {
  ASSERT_NE(engine, nullptr);

  // Example input
  std::string str("Sample input");

  std::vector<uint8_t> digest_sw;
  int digest_size_sw = 0;
  std::vector<uint8_t> digest_engine;
  int digest_size_engine = 0;

  // hash with openssl
  digest_size_sw = EVP_MD_meth_get_result_size(EVP_sha3_384());
  digest_sw.resize(digest_size_sw);
  unsigned int digestSize = -1;
  EVP_MD_CTX *evp_ctx;
  evp_ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(evp_ctx, EVP_sha3_384(), nullptr);
  EVP_DigestUpdate(evp_ctx, (unsigned char *)str.data(), str.size());
  EVP_DigestFinal(evp_ctx, (unsigned char *)digest_sw.data(), &digestSize);
  EVP_MD_CTX_free(evp_ctx);

  // hash with engine
  const EVP_MD *engine_digest = ENGINE_get_digest(engine, NID_sha3_384);
  digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);
  digest_engine.resize(digest_size_engine);
  evp_ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(evp_ctx, EVP_sha3_384(), engine);
  EVP_DigestUpdate(evp_ctx, (unsigned char *)str.data(), str.size());
  EVP_DigestFinal(evp_ctx, (unsigned char *)digest_engine.data(), &digestSize);
  EVP_MD_CTX_free(evp_ctx);

  EXPECT_EQ(digest_size_engine, digest_size_sw);
  EXPECT_EQ(digest_sw, digest_engine);
}

TEST(Test, AesCbc256) {
  ASSERT_NE(engine, nullptr);

  // plaintext
  std::string plaintext(
      "This is a longer secret message that needs to be encrypted.");

  // static key
  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  // static nonce
  std::string iv("AAAAAAAAAAAAAAAA");

  // params to check
  int sw_blocksize = EVP_CIPHER_block_size(EVP_aes_256_cbc()); /* 16 */
  int sw_keylen = EVP_CIPHER_key_length(EVP_aes_256_cbc());    /* 32 */
  int sw_ivlen = EVP_CIPHER_iv_length(EVP_aes_256_cbc());      /* 16 */

  // Encryption with Openssl
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     (unsigned char *)key.data(), (unsigned char *)iv.data());

  // Calculate output buffer size
  const int outlen = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
  std::vector<uint8_t> ciphertext(outlen);

  // Encrypt plaintext
  int ciphertext_len = 0;
  EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len,
                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                    plaintext.size());
  int final_len = 0;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &final_len);

  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len += final_len;
  ciphertext.resize(ciphertext_len);

  // Decrypt again
  std::string decrypted_sw;
  decrypted_sw.resize(ciphertext_len);
  ctx = EVP_CIPHER_CTX_new();

  // Decrypt init
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     (unsigned char *)key.data(), (unsigned char *)iv.data());
  int plaintext_len = 0;
  EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_sw.data(), &plaintext_len,
                    (unsigned char *)ciphertext.data(), ciphertext.size());
  final_len = 0;
  EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_sw.data() + plaintext_len,
                      &final_len);
  EVP_CIPHER_CTX_free(ctx);
  plaintext_len += final_len;
  decrypted_sw.resize(plaintext_len);

  // test if worked as expected
  EXPECT_EQ(decrypted_sw, plaintext);

  // check if engine has cipher
  const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_aes_256_cbc);
  ASSERT_NE(cipher, nullptr);

  // load engine cipher params
  int engine_blocksize = EVP_CIPHER_block_size(cipher); /* 16 */
  int engine_keylen = EVP_CIPHER_key_length(cipher);    /* 32 */
  int engine_ivlen = EVP_CIPHER_iv_length(cipher);      /* 16 */

  // check engine cipher params
  EXPECT_EQ(engine_blocksize, sw_blocksize);
  EXPECT_EQ(engine_keylen, sw_keylen);
  EXPECT_EQ(engine_ivlen, sw_ivlen);

  // encrypt with engine
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), engine,
                     (unsigned char *)key.data(), (unsigned char *)iv.data());

  // Calculate output buffer size
  std::vector<uint8_t> engine_ciphertext(outlen);

  // Encrypt plaintext
  ciphertext_len = 0;
  EVP_EncryptUpdate(ctx, engine_ciphertext.data(), &ciphertext_len,
                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                    plaintext.size());
  final_len = 0;
  EVP_EncryptFinal_ex(ctx, engine_ciphertext.data() + ciphertext_len,
                      &final_len);
  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len += final_len;
  engine_ciphertext.resize(ciphertext_len);

  // Check encrypted data
  EXPECT_EQ(engine_ciphertext, ciphertext);

  // Decrypt ciphertext
  std::string decrypted_engine;
  decrypted_engine.resize(ciphertext_len);
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), engine,
                     (unsigned char *)key.data(), (unsigned char *)iv.data());
  int plaintext_len_engine = 0;
  EVP_DecryptUpdate(
      ctx, (unsigned char *)decrypted_engine.data(), &plaintext_len_engine,
      (unsigned char *)engine_ciphertext.data(), engine_ciphertext.size());
  int final_len_engine = 0;
  EVP_DecryptFinal_ex(
      ctx, (unsigned char *)decrypted_engine.data() + plaintext_len_engine,
      &final_len_engine);
  EVP_CIPHER_CTX_free(ctx);
  plaintext_len_engine += final_len_engine;
  decrypted_engine.resize(plaintext_len_engine);

  // Check decrypted data
  EXPECT_EQ(plaintext_len_engine, plaintext_len);
  EXPECT_EQ(decrypted_engine, decrypted_sw);
}

TEST(Test, ChaCha20) {
  ASSERT_NE(engine, nullptr);

  // plaintext
  std::string plaintext("Encrypt this message");

  // static key
  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  // static nonce
  std::string nonce("AAAAAAAA");

  // params to check
  int sw_blocksize = EVP_CIPHER_block_size(EVP_chacha20()); /* 1 */
  int sw_keylen = EVP_CIPHER_key_length(EVP_chacha20());    /* 32 */
  int sw_ivlen = EVP_CIPHER_iv_length(EVP_chacha20());      /* 16 */

  // Encryption with Openssl
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, (unsigned char *)key.data(),
                     (unsigned char *)nonce.data());

  // Calculate output buffer size
  const int outlen = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
  std::vector<uint8_t> ciphertext(outlen);

  // Encrypt plaintext
  int ciphertext_len = 0;
  EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len,
                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                    plaintext.size());
  int final_len = 0;
  EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &final_len);

  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len += final_len;
  ciphertext.resize(ciphertext_len);

  // Decrypt again
  std::string decrypted_sw;
  decrypted_sw.resize(ciphertext_len);
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, (unsigned char *)key.data(),
                     (unsigned char *)nonce.data());
  int plaintext_len = 0;
  EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_sw.data(), &plaintext_len,
                    (unsigned char *)ciphertext.data(), ciphertext.size());
  final_len = 0;
  EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_sw.data() + plaintext_len,
                      &final_len);
  EVP_CIPHER_CTX_free(ctx);
  plaintext_len += final_len;
  decrypted_sw.resize(plaintext_len);

  // test if worked as expected
  EXPECT_EQ(decrypted_sw, plaintext);

  // check if engine has cipher
  const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_chacha20);
  ASSERT_NE(cipher, nullptr);

  // load engine cipher params
  int engine_blocksize = EVP_CIPHER_block_size(cipher); /* 16 */
  int engine_keylen = EVP_CIPHER_key_length(cipher);    /* 32 */
  int engine_ivlen = EVP_CIPHER_iv_length(cipher);      /* 16 */

  // check engine cipher params
  EXPECT_EQ(engine_blocksize, sw_blocksize);
  EXPECT_EQ(engine_keylen, sw_keylen);
  EXPECT_EQ(engine_ivlen, sw_ivlen);

  // encrypt with engine
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_chacha20(), engine, (unsigned char *)key.data(),
                     (unsigned char *)nonce.data());

  // Calculate output buffer size
  std::vector<uint8_t> engine_ciphertext(outlen);

  // Encrypt plaintext
  ciphertext_len = 0;
  EVP_EncryptUpdate(ctx, engine_ciphertext.data(), &ciphertext_len,
                    reinterpret_cast<const uint8_t *>(plaintext.data()),
                    plaintext.size());
  final_len = 0;
  EVP_EncryptFinal_ex(ctx, engine_ciphertext.data() + ciphertext_len,
                      &final_len);
  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len += final_len;
  engine_ciphertext.resize(ciphertext_len);

  // Check encrypted data
  EXPECT_EQ(engine_ciphertext, ciphertext);

  // Decrypt ciphertext
  std::string decrypted_engine;
  decrypted_engine.resize(ciphertext_len);
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_chacha20(), engine, (unsigned char *)key.data(),
                     (unsigned char *)nonce.data());
  int plaintext_len_engine = 0;
  EVP_DecryptUpdate(
      ctx, (unsigned char *)decrypted_engine.data(), &plaintext_len_engine,
      (unsigned char *)engine_ciphertext.data(), engine_ciphertext.size());
  int final_len_engine = 0;
  EVP_DecryptFinal_ex(
      ctx, (unsigned char *)decrypted_engine.data() + plaintext_len_engine,
      &final_len_engine);
  EVP_CIPHER_CTX_free(ctx);
  plaintext_len_engine += final_len_engine;
  decrypted_engine.resize(plaintext_len_engine);

  // Check decrypted data
  EXPECT_EQ(plaintext_len_engine, plaintext_len);
  EXPECT_EQ(decrypted_engine, decrypted_sw);
}

TEST(Test, Aes256GCM) {
  ASSERT_NE(engine, nullptr);

  // plaintext
  std::string plaintext(
      "This is a longer secret message that needs to be encrypted.");

  // static key
  std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  // static nonce
  std::string iv("AAAAAAAAAAAAAAAA");

  // static aad
  std::string aad("Message sent by me");

  // params to check
  int sw_blocksize = EVP_CIPHER_block_size(EVP_aes_256_gcm()); /* 16 */
  int sw_keylen = EVP_CIPHER_key_length(EVP_aes_256_gcm());    /* 32 */
  int sw_ivlen = EVP_CIPHER_iv_length(EVP_aes_256_gcm());      /* 16 */

  // return
  int ret = 0;

  // Encryption with Openssl
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           (unsigned char *)key.data(),
                           (unsigned char *)iv.data());
  EXPECT_TRUE(ret);

  // Provide aad data
  int len = 0;
  ret = EVP_EncryptUpdate(ctx, nullptr, &len, (unsigned char *)aad.data(),
                          aad.size());
  EXPECT_TRUE(ret);

  // Calculate output buffer size, no extra
  const int outlen = plaintext.size();
  std::vector<uint8_t> ciphertext(outlen);

  // Encrypt plaintext
  int ciphertext_len = 0;
  ret = EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len,
                          reinterpret_cast<const uint8_t *>(plaintext.data()),
                          plaintext.size());
  EXPECT_TRUE(ret);

  int final_len = 0;
  ret =
      EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &final_len);
  EXPECT_TRUE(ret);

  // Get the tag
  std::vector<std::uint8_t> tag;
  // retrieve tag size
  int tag_size = 12;
  tag.resize(tag_size);
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, tag.data());
  EXPECT_TRUE(ret);

  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len += final_len;
  ciphertext.resize(ciphertext_len);

  // Decrypt with sw
  std::string decrypted_sw;
  decrypted_sw.resize(ciphertext_len);
  ctx = EVP_CIPHER_CTX_new();

  // Set up the cipher algorithm and key
  ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL,
                           (unsigned char *)key.data(),
                           (unsigned char *)iv.data());
  EXPECT_TRUE(ret);

  // Set the IV length
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
  EXPECT_TRUE(ret);

  // Provide the additional authenticated data (AAD)
  ret = EVP_DecryptUpdate(ctx, NULL, &len, (unsigned char *)aad.data(),
                          aad.size());
  EXPECT_TRUE(ret);

  // Perform the decryption operation
  int plaintext_len = 0;
  ret = EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_sw.data(),
                          &plaintext_len, (unsigned char *)ciphertext.data(),
                          ciphertext.size());
  EXPECT_TRUE(ret);

  // set the tag
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size, tag.data());
  EXPECT_TRUE(ret);

  // finalize
  ret = EVP_DecryptFinal_ex(
      ctx, (unsigned char *)decrypted_sw.data() + plaintext_len, &final_len);
  EXPECT_TRUE(ret);

  decrypted_sw.resize(plaintext_len + final_len);

  EVP_CIPHER_CTX_free(ctx);
  EXPECT_EQ(decrypted_sw, plaintext);

  // check if engine has cipher
  const EVP_CIPHER *cipher = ENGINE_get_cipher(engine, NID_aes_256_gcm);
  ASSERT_NE(cipher, nullptr);

  /* ENGINE CODE */

  // load engine cipher params
  int engine_blocksize = EVP_CIPHER_block_size(cipher); /* 16 */
  int engine_keylen = EVP_CIPHER_key_length(cipher);    /* 32 */
  int engine_ivlen = EVP_CIPHER_iv_length(cipher);      /* 16 */

  // check engine cipher params
  EXPECT_EQ(engine_blocksize, sw_blocksize);
  EXPECT_EQ(engine_keylen, sw_keylen);
  EXPECT_EQ(engine_ivlen, sw_ivlen);

  // Encryption with Openssl
  ctx = EVP_CIPHER_CTX_new();
  ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), engine,
                           (unsigned char *)key.data(),
                           (unsigned char *)iv.data());
  EXPECT_TRUE(ret);

  // Provide aad data
  len = 0;
  ret = EVP_EncryptUpdate(ctx, nullptr, &len, (unsigned char *)aad.data(),
                          aad.size());
  EXPECT_TRUE(ret);

  // Calculate output buffer size, no extra
  const int outlen_en = plaintext.size();
  std::vector<uint8_t> ciphertext_en(outlen_en);

  // Encrypt plaintext
  int ciphertext_len_en = 0;
  ret = EVP_EncryptUpdate(ctx, ciphertext_en.data(), &ciphertext_len_en,
                          reinterpret_cast<const uint8_t *>(plaintext.data()),
                          plaintext.size());
  EXPECT_TRUE(ret);

  final_len = 0;
  ret = EVP_EncryptFinal_ex(ctx, ciphertext_en.data() + ciphertext_len_en,
                            &final_len);
  EXPECT_TRUE(ret);

  // Get the tag
  std::vector<std::uint8_t> tag_en;
  tag_en.resize(tag_size);
  printf("data: %p\n", tag_en.data());
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size, tag_en.data());
  EXPECT_TRUE(ret);

  // Clean up and resize output buffer
  EVP_CIPHER_CTX_free(ctx);
  ciphertext_len_en += final_len;
  ciphertext_en.resize(ciphertext_len_en);

  // check if ciphertexts are equal
  EXPECT_EQ(ciphertext_en, ciphertext);

  // Decrypt with engine
  std::string decrypted_en;
  decrypted_en.resize(ciphertext_len_en);
  ctx = EVP_CIPHER_CTX_new();

  // Set up the cipher algorithm and key
  ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), engine,
                           (unsigned char *)key.data(),
                           (unsigned char *)iv.data());
  EXPECT_TRUE(ret);

  // Set the IV length
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
  EXPECT_TRUE(ret);

  len = 0;
  // Provide the additional authenticated data (AAD)
  ret = EVP_DecryptUpdate(ctx, NULL, &len, (unsigned char *)aad.data(),
                          aad.size());
  EXPECT_TRUE(ret);

  // Perform the decryption operation
  int plaintext_len_en = 0;
  ret = EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_en.data(),
                          &plaintext_len_en, (unsigned char *)ciphertext.data(),
                          ciphertext.size());
  EXPECT_TRUE(ret);

  // set the tag
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_en.size(),
                            tag_en.data());
  EXPECT_TRUE(ret);

  // finalize
  final_len = 0;
  ret = EVP_DecryptFinal_ex(
      ctx, (unsigned char *)decrypted_en.data() + plaintext_len_en, &final_len);
  EXPECT_TRUE(ret);
  decrypted_en.resize(plaintext_len_en + final_len);

  // free
  EVP_CIPHER_CTX_free(ctx);

  // compare results
  EXPECT_EQ(decrypted_en, plaintext);
  EXPECT_EQ(decrypted_en, decrypted_sw);
}

// TEST(Test, ECDHNotWorking)
// {
//     std::string path_to_alice_key =
// "/home/glaum/engine/keys/alice_pkey.pem";
//     std::string path_to_bob_key = "/home/glaum/engine/keys/bob_pkey.pem";
//     EC_KEY* alice_pkey;
//     EC_KEY* bob_pkey;
//     int ret;
//     FILE* fp;

//     // Load alice private key with sw
//     fp = fopen(path_to_alice_key.c_str(), "r");
//     alice_pkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_ECPrivateKey(fp, &alice_pkey, nullptr, nullptr);

//     // Load bob private key with sw
//     fp = fopen(path_to_bob_key.c_str(), "r");
//     bob_pkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_ECPrivateKey(fp, &bob_pkey, nullptr, nullptr);

//     // Alice computes shared secret
//     unsigned char* alice_shared_secret = nullptr;
//     int alice_shared_secret_len = ECDH_compute_key(alice_shared_secret, 0,
//     EC_KEY_get0_public_key(bob_pkey), alice_pkey, nullptr);

//     // Bob computes shared secret
//     unsigned char* bob_shared_secret = nullptr;
//     int bob_shared_secret_len = ECDH_compute_key(bob_shared_secret, 0,
//     EC_KEY_get0_public_key(alice_pkey), bob_pkey, nullptr);

//     if (alice_shared_secret_len != bob_shared_secret_len ||
//     memcmp(alice_shared_secret, bob_shared_secret,
// alice_shared_secret_len)
//     != 0 ) {
//         // error handling
//         FAIL();
//     }

//     // Clean up memory
//     EC_KEY_free(alice_pkey);
//     EC_KEY_free(bob_pkey);

// }

// TEST(Test, ECDHProcess)
// {
//     EC_KEY* alice_pkey;
//     EC_KEY* alice_pubkey;
//     EC_KEY* bob_pkey;
//     EC_KEY* bob_pubkey;
//     int ret;
//     FILE* fp;
//     std::string path_to_alice_key =
// "/home/glaum/engine/keys/alice_pkey.pem";
//     std::string path_to_bob_key = "/home/glaum/engine/keys/bob_pkey.pem";
//     std::string path_to_alice_pubkey =
//     "/home/glaum/engine/keys/alice_pubkey.pem"; std::string
//     path_to_bob_pubkey = "/home/glaum/engine/keys/bob_pubkey.pem"; size_t
//     shared_secret_len = 32;

//     // Load alice private key with sw
//     fp = fopen(path_to_alice_key.c_str(), "r");
//     alice_pkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_ECPrivateKey(fp, &alice_pkey, nullptr, nullptr);

//     // Load bob private key with sw
//     fp = fopen(path_to_bob_key.c_str(), "r");
//     bob_pkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_ECPrivateKey(fp, &bob_pkey, nullptr, nullptr);

//     // Load alice public key with sw
//     fp = fopen(path_to_alice_pubkey.c_str(), "r");
//     alice_pubkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_EC_PUBKEY(fp, &alice_pubkey, nullptr, nullptr);

//     // Load bob public key with sw
//     fp = fopen(path_to_bob_pubkey.c_str(), "r");
//     bob_pubkey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
//     PEM_read_EC_PUBKEY(fp, &bob_pubkey, nullptr, nullptr);

//     // check keys
//     EXPECT_EQ(1, EC_KEY_check_key(alice_pkey));
//     EXPECT_EQ(1, EC_KEY_check_key(alice_pubkey));
//     EXPECT_EQ(1, EC_KEY_check_key(bob_pkey));
//     EXPECT_EQ(1, EC_KEY_check_key(bob_pubkey));

//     // pass key to EVP_PKEY
//     EVP_PKEY* alice_pevp = EVP_PKEY_new();
//     ret = EVP_PKEY_set1_EC_KEY(alice_pevp, alice_pkey);
//     EXPECT_EQ(ret, 1);

//     EVP_PKEY* bob_pevp = EVP_PKEY_new();
//     ret = EVP_PKEY_set1_EC_KEY(bob_pevp, bob_pkey);
//     EXPECT_EQ(ret, 1);

//     EVP_PKEY* alice_pubevp = EVP_PKEY_new();
//     ret = EVP_PKEY_set1_EC_KEY(alice_pubevp, alice_pubkey);
//     EXPECT_EQ(ret, 1);

//     EVP_PKEY* bob_pubevp = EVP_PKEY_new();
//     ret = EVP_PKEY_set1_EC_KEY(bob_pubevp, bob_pubkey);
//     EXPECT_EQ(ret, 1);

//     // create ctx
//     EVP_PKEY_CTX *ctx1 = EVP_PKEY_CTX_new(alice_pevp, nullptr);

//     // derive init
//     ret = EVP_PKEY_derive_init(ctx1);
//     EXPECT_EQ(ret, 1);

//     // set peer
//     ret = EVP_PKEY_derive_set_peer(ctx1, bob_pubevp);
//     EXPECT_EQ(ret, 1);

//     // derive
//     unsigned char shared_secret2[shared_secret_len];
//     ret = EVP_PKEY_derive(ctx1, shared_secret2, &shared_secret_len);
//     EXPECT_EQ(ret, 1);

//     // cleanup
//     EVP_PKEY_CTX_free(ctx1);

//     // create ctx
//     EVP_PKEY_CTX *ctx2 = EVP_PKEY_CTX_new(bob_pevp, nullptr);

//     // derive init
//     ret = EVP_PKEY_derive_init(ctx2);
//     EXPECT_EQ(ret, 1);

//     // set peer
//     ret = EVP_PKEY_derive_set_peer(ctx2, alice_pubevp);
//     EXPECT_EQ(ret, 1);

//     // derive
//     unsigned char shared_secret1[shared_secret_len];
//     ret = EVP_PKEY_derive(ctx1, shared_secret1, &shared_secret_len);
//     EXPECT_EQ(ret, 1);

//     // cleanup
//     EVP_PKEY_CTX_free(ctx2);

//     // compare derived secrets
//     EXPECT_EQ(memcmp(shared_secret1, shared_secret2, shared_secret_len),
// 0);

//     // Test cleanup
//     EVP_PKEY_free(alice_pevp);
//     EVP_PKEY_free(alice_pubevp);
//     EVP_PKEY_free(bob_pevp);
//     EVP_PKEY_free(bob_pubevp);
//     EC_KEY_free(alice_pkey);
//     EC_KEY_free(alice_pubkey);
//     EC_KEY_free(bob_pkey);
//     EC_KEY_free(bob_pubkey);
// }

// TEST(Test, EngineSetDefault) {
//   EXPECT_EQ(ENGINE_set_default(engine, ENGINE_METHOD_ALL), 1);
// }
