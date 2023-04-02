#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>

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
    
    int er = ENGINE_set_default_ciphers(mb_engine);
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();
    char text[] = "Encrypt this";
    int clen = 0;
    int flen = 0;
    unsigned char* out;
    
    char key[] = "0000000000000000";
    char iv[] = "0000000000000000";
    er = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), mb_engine, (unsigned char*)key, (unsigned char*)iv);
    er = EVP_EncryptUpdate(ctx, out, &clen, (unsigned char*)text, sizeof(text));
    er = EVP_EncryptFinal_ex(ctx, out + clen, &flen);
    EVP_CIPHER_CTX_free(ctx);

    // // Hashing
    // std::string str ("Hash this");
    // std::vector<uint8_t> digest;
    // digest.reserve(32);
    // unsigned int digestSize = -1;

    // int er = ENGINE_set_default_digests(mb_engine);

    // EVP_MD_CTX *evp_ctx;
    // evp_ctx = EVP_MD_CTX_create();
    // er = EVP_DigestInit_ex(evp_ctx, EVP_sha256(),mb_engine);
    // er = EVP_DigestUpdate(evp_ctx, (unsigned char*)str.data(), str.size());
    // er = EVP_DigestFinal(evp_ctx, (unsigned char*)digest.data(), &digestSize);
    // std::string hash_result = "1dac7205da38fc7de823435b53a5236e434fc83ab57ac69b1800ca38500256b9";

    // std::cout << "Hash1: ";
    // for(int i= 0; i< digestSize; i++) {
    //     printf("%x", digest[i]);
    // }
    // std::cout << "\n" << "Hash2: " << hash_result << "\n";

    // EVP_MD_CTX_destroy(evp_ctx);
    // Cleanup & free
    int fin_res = ENGINE_finish(mb_engine);
    int free = ENGINE_free(mb_engine);
    return 0;
}   