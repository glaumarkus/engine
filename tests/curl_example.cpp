#include <curl/curl.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include "engine_link.h"
#include <iostream>
#include <vector>

// 1. check $OPENSSL_ENGINES var: echo $OPENSSL_ENGINES. if not set, then export OPENSSL_ENGINES=/usr/local/lib/engines-1.1
// 2. copy engine sudo ln -s /home/glaum/engine/build/libmbengine.so /usr/local/lib/engines-1.1/libmbengine.so
// 3. echo $LD_LIBRARY_PATH -> export LD_LIBRARY_PATH=/usr/local/lib/engines-1.1
// 4. link sudo ln -s /home/glaum/engine/build/libmbengine.so /home/glaum/curl/openssl-1.1.1b/engines
// 5. link sudo ln -s /home/glaum/engine/build/libmbengine.so /usr/local/lib/engines-1.1
// 6. link sudo ln -s /home/glaum/engine/build/libmbengine.so /usr/lib/x86_64-linux-gnu/engines-3
// 7. link sudo ln -s /home/glaum/engine/build/libmbengine.so /home/glaum/openssl/engines
// 8. link sudo ln -s /home/glaum/engine/build/libmbengine.so /home/glaum/openssl/demos/engines
// 9. link sudo ln -s /home/glaum/engine/build/libmbengine.so /home/glaum/curl/openssl-1.1.1b/demos/engines


// void load_private_key()
// {

//     auto key = load_ec_key("/home/glaum/engine/private_key.pem");
// }

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

int main()
{

    // load_private_key();

    
    ENGINE_load_dynamic();  // Load dynamic engines
    ENGINE *engine = ENGINE_by_id("libmbengine");
    if (engine == NULL) {
        std::cout << "Engine not found\n";
        exit(0);
    }
    if (!ENGINE_init(engine)) {
        std::cout << "Engine not found\n";
        exit(0);
    }

    if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
        fprintf(stderr, "Failed to set engine as default\n");
        ENGINE_free(engine);
        exit(1);
    }

    std::string str ("Hash this");
    std::vector<uint8_t> digest;
    digest.reserve(32);
    unsigned int digestSize = -1;

    int er = ENGINE_set_default_digests(engine);

    EVP_MD_CTX *evp_ctx;
    evp_ctx = EVP_MD_CTX_create();
    er = EVP_DigestInit_ex(evp_ctx, EVP_sha256(),engine);
    er = EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    er = EVP_DigestFinal(evp_ctx, (unsigned char*)digest.data(), &digestSize);
    std::string hash_result = "1dac7205da38fc7de823435b53a5236e434fc83ab57ac69b1800ca38500256b9";


    // // load private key
    // EVP_PKEY *pkey = ENGINE_load_private_key(engine, "/home/glaum/engine/private_key.pem", NULL, NULL);
    // if (pkey == nullptr) {
    //     fprintf(stderr, "Failed to load private key\n");
    //     ERR_print_errors_fp(stderr);
    //     ENGINE_free(engine);
    //     exit(1);
    // }

    // // ecdsa
    //     // EVP_PKEY_CTX* pkctx = EVP_PKEY_CTX_new(pkey, engine);

    // EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    // std::string msg = "message to sign";


    // int ret = 0;
    // std::vector<std::uint8_t> sig;
    
    // size_t sigsize = 0;

    // // signature
    // // MGUCMQCAPTPGQFX1CjuaR7b9cbt1Lo1qsZOkIkYPKDk17UZ7NohwWV3+wNPclKNK1RdtPr0CMGCorf0aBeydsRzUXVejZKzyU7TqPm7NMCi+WXNBEtMoPC511B//tFHfO84yRu9TxAA=

    // ret = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), engine, pkey);
    // ret = EVP_DigestSign(mdctx, nullptr, &sigsize, (unsigned char*)msg.data(), msg.size());
    // sig.resize(sigsize);
    // ret = EVP_DigestSign(mdctx, (unsigned char*)sig.data(), &sigsize, (unsigned char*)msg.data(), msg.size());

    // std::cout << base64_encode(sig) << std::endl;

    // /* without engine */
    // auto private_key = load_ec_key("/home/glaum/engine/private_key.pem");
    // mdctx = EVP_MD_CTX_new();
    // ret = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, private_key);
    // ret = EVP_DigestSign(mdctx, nullptr, &sigsize, (unsigned char*)msg.data(), msg.size());
    // /* allocate memory */
    // std::vector<std::uint8_t> signature;
    // signature.resize(sigsize);
    // ret = EVP_DigestSign(mdctx, (unsigned char*)signature.data(), &sigsize, (unsigned char*)msg.data(), msg.size());

    // std::cout << base64_encode(signature) << std::endl;



    //ret = EVP_DigestSignUpdate(mdctx, msg.c_str(), msg.size());

    // size_t sig_len;
    // ret = EVP_DigestSignFinal(mdctx, NULL, &sig_len);

    // EVP_MD *md = EVP_SHA256();


    // curl_global_init(CURL_GLOBAL_DEFAULT);
    // CURL* curl;
    // CURLcode res;
    // curl = curl_easy_init();
    // const char *pEngine = "libmbengine";
    // if (curl)
    // {
    //     if(curl_easy_setopt(curl, CURLOPT_SSLENGINE, "libmbengine") != CURLE_OK) {
    //       /* load the crypto engine */
    //       fprintf(stderr, "cannot set crypto engine\n");
    //       return 1;
    //     }
    //     // Set the URL to connect to
    //     curl_easy_setopt(curl, CURLOPT_URL, "https://google.com");

    //     // Enable SSL/TLS
    //     curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

    //     // Enable mTLS with PKCS11
    //     curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "ENG");
    //     curl_easy_setopt(curl, CURLOPT_SSLCERT, "pkcs11:token=MyToken;object=MyCert");
    //     curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "ENG");
    //     curl_easy_setopt(curl, CURLOPT_SSLKEY, "pkcs11:token=MyToken;object=MyKey");

    //     // Specify the cipher suite to use
    //     curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");

    //     // Use engine
    //     curl_easy_setopt(curl, CURLOPT_SSLENGINE, "mb_engine");

    //     // Perform the request
    //     res = curl_easy_perform(curl);

    //     // Check for errors
    //     if (res != CURLE_OK)
    //         fprintf(stderr, "curl_easy_perform() failed: %s\n",
    //             curl_easy_strerror(res));

    //     // Cleanup
    //     curl_easy_cleanup(curl);
    // }
    return 0;
}
