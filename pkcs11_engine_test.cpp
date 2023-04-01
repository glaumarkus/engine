#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

// add this to be able to load engine
// sudo ln -s /home/glaum/engine/build/libmbengine.so /usr/lib/x86_64-linux-gnu/engines-3/libmbengine.so
// sudo ln -s /home/glaum/engine/build/libmbengine.so /usr/local/lib/engines-1.1/libmbengine.so

int main() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ENGINE_load_dynamic();
    ENGINE *mb_engine = ENGINE_by_id("libmbengine");

    if( mb_engine == NULL )
    {
        printf("Could not Load MB Engine!\n");
        exit(1);
    }
    printf("MB Engine successfully loaded\n");

    int init_res = ENGINE_init(mb_engine);
    printf("Engine name: %s init result : %d \n",ENGINE_get_name(mb_engine), init_res);
    
    // Hashing
    std::string str ("Hash this");
    std::vector<std::uint8_t> digest;
    digest.reserve(32);
    unsigned int digestSize = -1;

    int er = ENGINE_set_default_digests(mb_engine);

    EVP_MD_CTX *evp_ctx;
    evp_ctx = EVP_MD_CTX_create();
    er = EVP_DigestInit_ex(evp_ctx, EVP_sha256(),mb_engine);
    printf("Digest INIT %d\n",er);

    er = EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    printf("Digest Update %d\n",er);

    er = EVP_DigestFinal(evp_ctx, digest.data(), &digestSize);
    printf("Digest Final %d Digest size:%d\n",er,digestSize);

    for(int i= 0; i< digestSize; i++) {
        printf("%x", digest[i]);
    }
    printf("\n");
    EVP_MD_CTX_destroy(evp_ctx);
    // Cleanup & free
    int fin_res = ENGINE_finish(mb_engine);
    int free = ENGINE_free(mb_engine);
    return 0;
}