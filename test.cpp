#include <gtest/gtest.h>
#include <openssl/engine.h>

using ::testing::Test;


std::string base64_encode(const std::vector<std::uint8_t>& input) {
    std::string output;

    // Create a base64 filter
    BIO* b64_filter = BIO_new(BIO_f_base64());
    BIO_set_flags(b64_filter, BIO_FLAGS_BASE64_NO_NL);

    // Create a memory buffer filter
    BIO* mem_filter = BIO_new(BIO_s_mem());

    // Chain the filters together
    BIO_push(b64_filter, mem_filter);

    // Write the input data to the base64 filter
    BIO_write(b64_filter, input.data(), input.size());
    BIO_flush(b64_filter);

    // Get the output data from the memory buffer filter
    const unsigned char* data = nullptr;
    long length = BIO_get_mem_data(mem_filter, &data);
    output.assign(data, data + length);

    // Clean up the filters
    BIO_free_all(b64_filter);

    return output;
}

ENGINE* engine = nullptr;

TEST(Test, EngineLoaded) {
    // try loading the engine
    ENGINE_load_dynamic();
    engine = ENGINE_by_id("libmbengine");
    EXPECT_TRUE(engine != nullptr);
}

TEST(Test, EngineInit)
{
    ASSERT_NE(engine, nullptr);
    // initialize the engine
    EXPECT_EQ(1, ENGINE_init(engine));
}

TEST(Test, Sha256) {
    ASSERT_NE(engine, nullptr);

    // example input
    std::string str ("Sample input");

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
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_sw.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);

    // hash with engine
    const EVP_MD* engine_digest = ENGINE_get_digest(engine, NID_sha256);
    digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);
    digest_engine.resize(digest_size_engine);
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha256(), engine);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_engine.data(), &digestSize);
    
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
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_sw.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);
    
    // hash with engine
    const EVP_MD* engine_digest = ENGINE_get_digest(engine, NID_sha3_384);
    digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);
    digest_engine.resize(digest_size_engine);
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha3_384(), engine);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_engine.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);

    EXPECT_EQ(digest_size_engine, digest_size_sw);
    EXPECT_EQ(digest_sw, digest_engine);
}

TEST(Test, AesCbc256) {
    ASSERT_NE(engine, nullptr);

    // plaintext
    std::string plaintext("This is a longer secret message that needs to be encrypted.");

    // static key
    std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // static nonce
    std::string iv("AAAAAAAAAAAAAAAA");

    // params to check
    int sw_blocksize = EVP_CIPHER_block_size(EVP_aes_256_cbc());   /* 16 */
    int sw_keylen = EVP_CIPHER_key_length(EVP_aes_256_cbc());      /* 32 */
    int sw_ivlen = EVP_CIPHER_iv_length(EVP_aes_256_cbc());        /* 16 */

    // Encryption with Openssl
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), (unsigned char*)iv.data());

    // Calculate output buffer size
    const int outlen = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
    std::vector<uint8_t> ciphertext(outlen);

    // Encrypt plaintext
    int ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
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
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), (unsigned char*)iv.data());
    int plaintext_len = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_sw.data(), &plaintext_len, (unsigned char*)ciphertext.data(), ciphertext.size());
    final_len = 0;
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decrypted_sw.data() + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len += final_len;
    decrypted_sw.resize(plaintext_len);

    // test if worked as expected
    EXPECT_EQ(decrypted_sw, plaintext);

    // check if engine has cipher
    const EVP_CIPHER* cipher = ENGINE_get_cipher(engine, NID_aes_256_cbc);
    ASSERT_NE(cipher, nullptr);

    // load engine cipher params
    int engine_blocksize = EVP_CIPHER_block_size(cipher);   /* 16 */
    int engine_keylen = EVP_CIPHER_key_length(cipher);      /* 32 */
    int engine_ivlen = EVP_CIPHER_iv_length(cipher);        /* 16 */

    // check engine cipher params
    EXPECT_EQ(engine_blocksize, sw_blocksize);
    EXPECT_EQ(engine_keylen, sw_keylen);
    EXPECT_EQ(engine_ivlen, sw_ivlen);

    // encrypt with engine
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), engine, (unsigned char*)key.data(), (unsigned char*)iv.data());

    // Calculate output buffer size
    std::vector<uint8_t> engine_ciphertext(outlen);

    // Encrypt plaintext
    ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, engine_ciphertext.data(), &ciphertext_len, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    final_len = 0;
    EVP_EncryptFinal_ex(ctx, engine_ciphertext.data() + ciphertext_len, &final_len);
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
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), engine, (unsigned char*)key.data(), (unsigned char*)iv.data());
    int plaintext_len_engine = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_engine.data(), &plaintext_len_engine, (unsigned char*)engine_ciphertext.data(), engine_ciphertext.size());
    int final_len_engine = 0;
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decrypted_engine.data() + plaintext_len_engine, &final_len_engine);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len_engine += final_len_engine;
    decrypted_engine.resize(plaintext_len_engine);
    
    // Check decrypted data
    EXPECT_EQ(plaintext_len_engine, plaintext_len);
    EXPECT_EQ(decrypted_engine, decrypted_sw);
}

TEST(Test, ChaCha20)
{
    ASSERT_NE(engine, nullptr);

    // plaintext
    std::string plaintext("Encrypt this message");

    // static key
    std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // static nonce
    std::string nonce("AAAAAAAA");

    // params to check
    int sw_blocksize = EVP_CIPHER_block_size(EVP_chacha20());   /* 1 */
    int sw_keylen = EVP_CIPHER_key_length(EVP_chacha20());      /* 32 */
    int sw_ivlen = EVP_CIPHER_iv_length(EVP_chacha20());        /* 16 */

    // Encryption with Openssl
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, (unsigned char*)key.data(), (unsigned char*)nonce.data());

    // Calculate output buffer size
    const int outlen = plaintext.size() + EVP_CIPHER_CTX_block_size(ctx);
    std::vector<uint8_t> ciphertext(outlen);

    // Encrypt plaintext
    int ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
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
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), nullptr, (unsigned char*)key.data(), (unsigned char*)nonce.data());
    int plaintext_len = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_sw.data(), &plaintext_len, (unsigned char*)ciphertext.data(), ciphertext.size());
    final_len = 0;
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decrypted_sw.data() + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len += final_len;
    decrypted_sw.resize(plaintext_len);

    // test if worked as expected
    EXPECT_EQ(decrypted_sw, plaintext);

    // check if engine has cipher
    const EVP_CIPHER* cipher = ENGINE_get_cipher(engine, NID_chacha20);
    ASSERT_NE(cipher, nullptr);

    // load engine cipher params
    int engine_blocksize = EVP_CIPHER_block_size(cipher);   /* 16 */
    int engine_keylen = EVP_CIPHER_key_length(cipher);      /* 32 */
    int engine_ivlen = EVP_CIPHER_iv_length(cipher);        /* 16 */

    // check engine cipher params
    EXPECT_EQ(engine_blocksize, sw_blocksize);
    EXPECT_EQ(engine_keylen, sw_keylen);
    EXPECT_EQ(engine_ivlen, sw_ivlen);

    // encrypt with engine
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), engine, (unsigned char*)key.data(), (unsigned char*)nonce.data());

    // Calculate output buffer size
    std::vector<uint8_t> engine_ciphertext(outlen);

    // Encrypt plaintext
    ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, engine_ciphertext.data(), &ciphertext_len, reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    final_len = 0;
    EVP_EncryptFinal_ex(ctx, engine_ciphertext.data() + ciphertext_len, &final_len);
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
    EVP_DecryptInit_ex(ctx, EVP_chacha20(), engine, (unsigned char*)key.data(), (unsigned char*)nonce.data());
    int plaintext_len_engine = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_engine.data(), &plaintext_len_engine, (unsigned char*)engine_ciphertext.data(), engine_ciphertext.size());
    int final_len_engine = 0;
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decrypted_engine.data() + plaintext_len_engine, &final_len_engine);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len_engine += final_len_engine;
    decrypted_engine.resize(plaintext_len_engine);
    
    // Check decrypted data
    EXPECT_EQ(plaintext_len_engine, plaintext_len);
    EXPECT_EQ(decrypted_engine, decrypted_sw);
}

TEST(Test, LoadPrivateKey)
{
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* pkey_sw = nullptr;
    EC_KEY* eckey = nullptr;
    int ret = 0; 
    std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";
    
    // Load private key with sw
    FILE* fp = fopen(path_to_key.c_str(), "r");
    pkey_sw = EVP_PKEY_new();
    eckey = EC_KEY_new_by_curve_name(NID_brainpoolP384r1);
    PEM_read_ECPrivateKey(fp, &eckey, nullptr, nullptr);
    ret = EVP_PKEY_set1_EC_KEY(pkey_sw, eckey);
    EC_KEY_free(eckey);
    EXPECT_NE(EVP_PKEY_id(pkey_sw), EVP_PKEY_NONE);

    // Load private key with engine
    EVP_PKEY* pkey_engine = nullptr;
    pkey_engine = ENGINE_load_private_key(engine, path_to_key.c_str(), nullptr, nullptr);
    EXPECT_NE(pkey_engine, nullptr);

    // compare the keys
    ret = EVP_PKEY_cmp(pkey_sw, pkey_engine);
    EXPECT_TRUE(ret);

    // compare the key params
    ret = EVP_PKEY_cmp_parameters(pkey_sw, pkey_engine);
    EXPECT_TRUE(ret);
}

TEST(Test, Hm)
{
    ASSERT_NE(engine, nullptr);

    // Setup vars
    EVP_PKEY* pkey_sw = nullptr;
    EC_KEY* eckey = nullptr;
    int ret = 0; 
    std::string path_to_key = "/home/glaum/engine/keys/private_key.pem";
    size_t siglen = 0;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> signature_engine;
    std::string msg ("Sign this example message with EC private key");

    // Load private key with sw
    FILE* fp = fopen(path_to_key.c_str(), "r");
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
    ret = EVP_DigestSignUpdate(mdctx, (unsigned char*)msg.data(), msg.size());
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestSignFinal(mdctx, NULL, &siglen);
    // resize signature
    signature.resize(siglen);
    EVP_DigestSignFinal(mdctx, (unsigned char*)signature.data(), &siglen);
    std::cout << "Digest: " << base64_encode(signature) << std::endl;
    EVP_MD_CTX_free(mdctx);

    // different sign with sw
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)msg.data(), msg.size(), hash);
    EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey_sw);
    ECDSA_SIG *sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, ec_key);
    int sig_len = i2d_ECDSA_SIG(sig, NULL);

    // allocate memory for the binary signature
    unsigned char* sig_buf = (unsigned char*)malloc(sig_len);

    // encode the signature to binary format
    unsigned char* p = sig_buf;
    sig_len = i2d_ECDSA_SIG(sig, &p);

    // allocate and copy buffer
    std::vector<uint8_t> signature_2;
    signature_2.resize(sig_len);
    memcpy(signature_2.data(), sig_buf, sig_len);
    std::cout << "Digest: " << base64_encode(signature_2) << std::endl;

    // Do verify with different sw
    mdctx = EVP_MD_CTX_new();
    ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), NULL, pkey_sw);
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char*)msg.data(), msg.size());
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestVerifyFinal(mdctx, (unsigned char*)signature_2.data(), sig_len);
    EXPECT_EQ(ret, 1);
    EVP_MD_CTX_free(mdctx);

    // Do verify 1
    mdctx = EVP_MD_CTX_new();
    ret = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), NULL, pkey_sw);
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestVerifyUpdate(mdctx, (unsigned char*)msg.data(), msg.size());
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestVerifyFinal(mdctx, (unsigned char*)signature.data(), siglen);
    EXPECT_EQ(ret, 1);
    EVP_MD_CTX_free(mdctx);

    // load key with engine
    EVP_PKEY* pkey_engine = nullptr;
    pkey_engine = ENGINE_load_private_key(engine, path_to_key.c_str(), nullptr, nullptr);
    EXPECT_NE(pkey_engine, nullptr);

    // Check if type matches
    type = EVP_PKEY_base_id(pkey_engine);
    EXPECT_EQ(type, EVP_PKEY_EC);

    // sign with engine
    mdctx = EVP_MD_CTX_new();
    std::cout << "\n";
    
    // print memory address of key and hash evp_md
    // printf("key: %p, md: %p\n", pkey_engine, ENGINE_get_digest(engine, NID_sha256));

    ret = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), engine, pkey_engine);
    std::cout << "\n";
    EXPECT_EQ(ret, 1);
    ret = EVP_DigestSignUpdate(mdctx, (unsigned char*)msg.data(), msg.size());
    EXPECT_EQ(ret, 1);
    std::cout << "\n";

    unsigned char ss[104];
    ret = EVP_DigestSignFinal(mdctx, nullptr, &siglen);
    signature_engine.resize(104);    
    ret = EVP_DigestSignFinal(mdctx, (unsigned char*)signature_engine.data(), &siglen);
    std::cout << "Digest: " << base64_encode(signature_engine) << std::endl;

    /* not working */
    // siglen = 0;
    // ret = EVP_DigestSignFinal(mdctx, NULL, &siglen);
    // signature_engine.resize(siglen);    
    // ret = EVP_DigestSignFinal(mdctx, (unsigned char*)signature_engine.data(), &siglen);
    
    
    EVP_MD_CTX_free(mdctx);




}