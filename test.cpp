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
    ENGINE_load_dynamic();
    engine = ENGINE_by_id("libmbengine");
    EXPECT_TRUE(engine != nullptr);
}

TEST(Test, EngineInit)
{
    EXPECT_EQ(1, ENGINE_init(engine));
}

TEST(Test, Sha256) {
    // Hash without engine
    std::string str ("Sample input");
    std::vector<uint8_t> digest_sw;
    int digest_size_sw = 0;
    std::vector<uint8_t> digest_engine;
    int digest_size_engine = 0;

    digest_size_sw = EVP_MD_meth_get_result_size(EVP_sha256());
    digest_sw.resize(digest_size_sw);
    unsigned int digestSize = -1;
    EVP_MD_CTX *evp_ctx;
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha256(),nullptr);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_sw.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);

    const EVP_MD* engine_digest = ENGINE_get_digest(engine, NID_sha256);
    digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);

    EXPECT_EQ(digest_size_engine, digest_size_sw);

    digest_engine.resize(digest_size_engine);
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha256(), engine);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_engine.data(), &digestSize);
    
    EXPECT_EQ(digest_sw, digest_engine);
}


TEST(Test, Sha384) {

    // Hash without engine
    std::string str("Sample input");
    std::vector<uint8_t> digest_sw;
    int digest_size_sw = 0;
    std::vector<uint8_t> digest_engine;
    int digest_size_engine = 0;

    digest_size_sw = EVP_MD_meth_get_result_size(EVP_sha3_384());
    digest_sw.resize(digest_size_sw);
    unsigned int digestSize = -1;
    EVP_MD_CTX *evp_ctx;
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha3_384(), nullptr);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_sw.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);
    


    const EVP_MD* engine_digest = ENGINE_get_digest(engine, NID_sha3_384);
    digest_size_engine = EVP_MD_meth_get_result_size(engine_digest);

    EXPECT_EQ(digest_size_engine, digest_size_sw);

    digest_engine.resize(digest_size_engine);
    evp_ctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(evp_ctx, EVP_sha3_384(), engine);
    EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    EVP_DigestFinal(evp_ctx, (unsigned char*)digest_engine.data(), &digestSize);
    EVP_MD_CTX_free(evp_ctx);

    EXPECT_EQ(digest_sw, digest_engine);
}
