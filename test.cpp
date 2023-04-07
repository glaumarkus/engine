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
    // initialize the engine
    EXPECT_EQ(1, ENGINE_init(engine));
}

TEST(Test, Sha256) {
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
    // plaintext
    std::string plaintext("This is a longer secret message that needs to be encrypted.");

    // static key
    std::string key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // static nonce
    std::string nonce("AAAAAAAAAAAAAAAA");

    // params to check
    int sw_blocksize = EVP_CIPHER_block_size(EVP_aes_256_cbc());   /* 16 */
    int sw_keylen = EVP_CIPHER_key_length(EVP_aes_256_cbc());      /* 32 */
    int sw_ivlen = EVP_CIPHER_iv_length(EVP_aes_256_cbc());        /* 16 */

    // Encryption with Openssl
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), (unsigned char*)nonce.data());

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
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char*)key.data(), (unsigned char*)nonce.data());
    int plaintext_len = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)decrypted_sw.data(), &plaintext_len, (unsigned char*)ciphertext.data(), ciphertext.size());
    final_len = 0;
    EVP_EncryptFinal_ex(ctx, (unsigned char*)decrypted_sw.data() + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len += final_len;
    decrypted_sw.resize(plaintext_len);

    // test if worked as expected
    EXPECT_EQ(decrypted_sw, plaintext);
}

TEST(Test, ChaCha20)
{
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
    EVP_EncryptFinal_ex(ctx, (unsigned char*)decrypted_sw.data() + plaintext_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    plaintext_len += final_len;
    decrypted_sw.resize(plaintext_len);

    // test if worked as expected
    EXPECT_EQ(decrypted_sw, plaintext);
}